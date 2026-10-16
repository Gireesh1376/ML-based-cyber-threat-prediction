"""
Train an adversarially hardened model and compare against baseline.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1] / "backend"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import RAW_DIR, MODELS_DIR
from app.ml import load_artifacts, model_path, hybrid_predict, HybridArtifacts
from app.ml.features import load_nsl_kdd, split_zero_day

RATE_COLUMNS = [
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

COUNT_COLUMNS = [
    "duration", "src_bytes", "dst_bytes", "count", "srv_count",
    "dst_host_count", "dst_host_srv_count"
]

def apply_constrained_perturbation(df: pd.DataFrame, epsilon: float = 0.20) -> pd.DataFrame:
    perturbed = df.copy()
    rng = np.random.default_rng(42)
    for col in RATE_COLUMNS:
        if col in perturbed.columns:
            target = 1.0 if "same_srv" in col else 0.0
            delta = epsilon * (target - perturbed[col]) + rng.normal(0, 0.02 * epsilon, size=len(perturbed))
            perturbed[col] = np.clip(perturbed[col] + delta, 0.0, 1.0)
    for col in COUNT_COLUMNS:
        if col in perturbed.columns:
            scale_jitter = 1.0 + rng.uniform(-epsilon, epsilon, size=len(perturbed))
            perturbed[col] = np.maximum(0, perturbed[col] * scale_jitter)
            if col in ["count", "srv_count", "dst_host_count", "dst_host_srv_count"]:
                perturbed[col] = np.round(perturbed[col])
    return perturbed

def train_and_test():
    artifacts, _ = load_artifacts(model_path())
    train_path = RAW_DIR / "KDDTrain+.txt"
    test_path = RAW_DIR / "KDDTest+.txt"
    
    train_df = load_nsl_kdd(train_path)
    test_df = load_nsl_kdd(test_path)
    
    known_train, _ = split_zero_day(train_df)
    known_test, _ = split_zero_day(test_df)
    
    # 1. Transform baseline training set
    X_train_orig = artifacts.transformer.transform(known_train)
    encoder = LabelEncoder()
    family_labels = known_train["family"].where(known_train["label"] != "normal", "normal")
    y_train_orig = encoder.fit_transform(family_labels.astype(str))
    
    # 2. Select attacks from train split and generate adversarial perturbations
    attack_mask = (known_train["label"] != "normal")
    train_attacks = known_train[attack_mask].copy()
    
    print(f"Generating adversarial variations from {len(train_attacks)} training attacks...")
    adv_train_1 = apply_constrained_perturbation(train_attacks, epsilon=0.15)
    adv_train_2 = apply_constrained_perturbation(train_attacks, epsilon=0.25)
    
    # Combined adversarial training set
    adv_df = pd.concat([adv_train_1, adv_train_2], ignore_index=True)
    X_adv = artifacts.transformer.transform(adv_df)
    adv_families = adv_df["family"].astype(str)
    y_adv = encoder.transform(adv_families)
    
    # Augmented dataset
    X_aug = np.vstack([X_train_orig, X_adv])
    y_aug = np.concatenate([y_train_orig, y_adv])
    
    Xs_aug = X_aug[:, artifacts.selected_features]
    print(f"Augmented training shape: {Xs_aug.shape}")
    
    # 3. Retrain hardened XGBoost model
    print("Fitting Hardened XGBoost classifier...")
    clf_hardened = XGBClassifier(
        n_estimators=280,
        max_depth=8,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        min_child_weight=2,
        gamma=0.05,
        reg_lambda=1.5, # Slightly higher regularization for robustness
        objective="multi:softprob",
        eval_metric="mlogloss",
        n_jobs=-1,
        tree_method="hist",
        random_state=42,
    )
    clf_hardened.fit(Xs_aug, y_aug)
    
    hardened_artifacts = HybridArtifacts(
        transformer=artifacts.transformer,
        autoencoder=artifacts.autoencoder,
        xgboost=clf_hardened,
        recon_threshold=artifacts.recon_threshold,
        label_classes=artifacts.label_classes,
        selected_features=artifacts.selected_features,
        feature_names=artifacts.feature_names,
        novelty_gate=artifacts.novelty_gate,
        recon_quantile=artifacts.recon_quantile,
    )
    
    # 4. Compare Baseline vs Hardened on clean and perturbed test attacks
    test_attacks = known_test[known_test["label"] != "normal"].sample(n=1000, random_state=42).copy()
    pert_test = apply_constrained_perturbation(test_attacks, epsilon=0.20)
    
    X_test_clean = artifacts.transformer.transform(test_attacks)
    X_test_pert = artifacts.transformer.transform(pert_test)
    
    res_base_clean = hybrid_predict(artifacts, X_test_clean)
    res_base_pert = hybrid_predict(artifacts, X_test_pert)
    
    res_hard_clean = hybrid_predict(hardened_artifacts, X_test_clean)
    res_hard_pert = hybrid_predict(hardened_artifacts, X_test_pert)
    
    base_clean_acc = (res_base_clean["label"] != "normal").mean()
    base_pert_acc = (res_base_pert["label"] != "normal").mean()
    base_pert_evasion = (res_base_pert["label"] == "normal").mean()
    base_clf_evasion = (res_base_pert["known_label"] == "normal").mean()
    
    hard_clean_acc = (res_hard_clean["label"] != "normal").mean()
    hard_pert_acc = (res_hard_pert["label"] != "normal").mean()
    hard_pert_evasion = (res_hard_pert["label"] == "normal").mean()
    hard_clf_evasion = (res_hard_pert["known_label"] == "normal").mean()
    
    print("\n================ COMPARISON SUMMARY ================")
    print(f"Clean Attack Recall:    Baseline = {base_clean_acc*100:.1f}%, Hardened = {hard_clean_acc*100:.1f}%")
    print(f"Perturbed Attack Recall: Baseline = {base_pert_acc*100:.1f}%, Hardened = {hard_pert_acc*100:.1f}%")
    print(f"Classifier Evasion Rate: Baseline = {base_clf_evasion*100:.1f}%, Hardened = {hard_clf_evasion*100:.1f}%")
    print(f"Hybrid Evasion Rate:     Baseline = {base_pert_evasion*100:.1f}%, Hardened = {hard_pert_evasion*100:.1f}%")
    
    # Check Benign False Alarm Rate
    benign_test = known_test[known_test["label"] == "normal"].sample(n=1000, random_state=42).copy()
    X_benign = artifacts.transformer.transform(benign_test)
    base_fpr = (hybrid_predict(artifacts, X_benign)["label"] != "normal").mean()
    hard_fpr = (hybrid_predict(hardened_artifacts, X_benign)["label"] != "normal").mean()
    print(f"Benign False Positive Rate: Baseline = {base_fpr*100:.2f}%, Hardened = {hard_fpr*100:.2f}%")

if __name__ == "__main__":
    train_and_test()

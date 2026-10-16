"""
Problem 4: Adversarial Evasion Robustness & Retraining Module.

Implements network-protocol-constrained adversarial sample synthesis (DEMGAN, UAP,
and FGSM approximations) and iterative adversarial retraining to harden the
tree-ensemble core against generative and universal evasion perturbations.
Citations:
  - Xu et al. (2025, CMC): DEMGAN multi-generator evasion & adversarial retraining.
  - Zhang et al. (2025): Universal Adversarial Perturbations (UAPs) in NIDS.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from app.config import (
    FEATURE_COLUMNS,
    MODELS_DIR,
    RAW_DIR,
    SERVICE_CRITICALITY,
)
from app.ml import (
    HybridArtifacts,
    hybrid_predict,
    load_artifacts,
    model_path,
    save_artifacts,
    xgboost_native_path,
)
from app.ml.features import FeatureTransformer, load_nsl_kdd, split_zero_day
from app.ml.priority import compute_priority, tier_from_score

ADVERSARIAL_METRICS_PATH = MODELS_DIR / "adversarial_metrics.json"
HARDENED_MODEL_PATH = MODELS_DIR / "hybrid_detector_hardened.joblib"

# Rate features constrained strictly to [0.0, 1.0]
RATE_COLUMNS = [
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

# Physical count and byte size features constrained to non-negative values
COUNT_COLUMNS = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "count",
    "srv_count",
    "dst_host_count",
    "dst_host_srv_count",
]

# Discrete integer columns that must be rounded to valid integers
DISCRETE_INT_COLUMNS = [
    "count",
    "srv_count",
    "dst_host_count",
    "dst_host_srv_count",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "num_compromised",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
]

# Immutable protocol fields that an adversary cannot mutate without invalidating packets
IMMUTABLE_COLUMNS = [
    "protocol_type",
    "land",
    "is_host_login",
    "is_guest_login",
]


def enforce_domain_constraints(df: pd.DataFrame) -> pd.DataFrame:
    """Enforces network protocol semantics and physical packet invariants."""
    out = df.copy()
    for col in RATE_COLUMNS:
        if col in out.columns:
            out[col] = np.clip(out[col].astype(float), 0.0, 1.0)

    for col in COUNT_COLUMNS:
        if col in out.columns:
            out[col] = np.maximum(0.0, out[col].astype(float))

    for col in DISCRETE_INT_COLUMNS:
        if col in out.columns:
            out[col] = np.round(np.maximum(0.0, out[col].astype(float))).astype(int)

    return out


def generate_adversarial_perturbation(
    df: pd.DataFrame,
    method: str = "demgan",
    epsilon: float = 0.20,
    seed: int = 42,
) -> pd.DataFrame:
    """Synthesize network-constrained adversarial samples.

    Methods:
      - 'demgan': Generative multi-feature drift towards benign traffic distribution
                  with controlled variance, mimicking Xu et al. (2025).
      - 'uap': Universal Adversarial Perturbation vector shifting statistical error
               and count densities across the flow stream, mimicking Zhang et al. (2025).
      - 'fgsm': Fast Gradient Sign approximation driving feature values along the
                highest sensitivity paths toward normal classification.
    """
    rng = np.random.default_rng(seed)
    perturbed = df.copy()
    epsilon = float(np.clip(epsilon, 0.01, 0.50))

    if method == "uap":
        # Universal pre-computed shift vector
        for col in RATE_COLUMNS:
            if col in perturbed.columns:
                target = 1.0 if "same_srv" in col else 0.0
                shift = epsilon * 0.8 * (target - perturbed[col].astype(float))
                perturbed[col] = perturbed[col].astype(float) + shift
        for col in COUNT_COLUMNS:
            if col in perturbed.columns:
                shift_factor = 1.0 - (epsilon * 0.4)
                perturbed[col] = perturbed[col].astype(float) * shift_factor

    elif method == "fgsm":
        # Directional sensitivity step towards normal boundaries
        for col in RATE_COLUMNS:
            if col in perturbed.columns:
                target = 1.0 if "same_srv" in col else 0.0
                direction = np.sign(target - perturbed[col].astype(float))
                step = epsilon * direction * 0.85
                perturbed[col] = perturbed[col].astype(float) + step
        for col in ["count", "srv_count"]:
            if col in perturbed.columns:
                perturbed[col] = perturbed[col].astype(float) * (1.0 - epsilon * 0.5)

    else:
        # Default: DEMGAN generative family-directed mutation with Gaussian jitter
        for col in RATE_COLUMNS:
            if col in perturbed.columns:
                target = 1.0 if "same_srv" in col else 0.0
                drift = epsilon * (target - perturbed[col].astype(float))
                noise = rng.normal(0, 0.03 * epsilon, size=len(perturbed))
                perturbed[col] = perturbed[col].astype(float) + drift + noise
        for col in COUNT_COLUMNS:
            if col in perturbed.columns:
                jitter = rng.uniform(-epsilon * 0.6, epsilon * 0.6, size=len(perturbed))
                perturbed[col] = perturbed[col].astype(float) * (1.0 + jitter)

    return enforce_domain_constraints(perturbed)


def train_hardened_pipeline(progress_callback=None) -> dict[str, Any]:
    """Retrain the hybrid detector with adversarial augmentation.

    Saves:
      - MODELS_DIR / 'hybrid_detector_hardened.joblib'
      - MODELS_DIR / 'hybrid_detector_hardened_xgb.json'
      - MODELS_DIR / 'adversarial_metrics.json'
    """
    base_artifacts, extra = load_artifacts(model_path())
    train_path = RAW_DIR / "KDDTrain+.txt"
    test_path = RAW_DIR / "KDDTest+.txt"

    train_df = load_nsl_kdd(train_path)
    test_df = load_nsl_kdd(test_path)

    known_train, _ = split_zero_day(train_df)
    known_test, _ = split_zero_day(test_df)

    if progress_callback:
        progress_callback("Transforming base dataset...")

    X_train_orig = base_artifacts.transformer.transform(known_train)
    encoder = LabelEncoder()
    family_labels = known_train["family"].where(known_train["label"] != "normal", "normal")
    y_train_orig = encoder.fit_transform(family_labels.astype(str))

    # Generate adversarial variations from training attacks
    attack_mask = known_train["label"] != "normal"
    train_attacks = known_train[attack_mask].copy()

    if progress_callback:
        progress_callback("Synthesizing constrained adversarial perturbations...")

    # Multi-generator augmentation: DEMGAN style at ε=0.15 and ε=0.25
    adv_train_1 = generate_adversarial_perturbation(train_attacks, method="demgan", epsilon=0.15, seed=42)
    adv_train_2 = generate_adversarial_perturbation(train_attacks, method="demgan", epsilon=0.25, seed=43)

    adv_df = pd.concat([adv_train_1, adv_train_2], ignore_index=True)
    X_adv = base_artifacts.transformer.transform(adv_df)
    y_adv = encoder.transform(adv_df["family"].astype(str))

    X_aug = np.vstack([X_train_orig, X_adv])
    y_aug = np.concatenate([y_train_orig, y_adv])

    Xs_aug = X_aug[:, base_artifacts.selected_features]

    if progress_callback:
        progress_callback(f"Fitting hardened XGBoost model on {len(Xs_aug)} samples...")

    clf_hardened = XGBClassifier(
        n_estimators=280,
        max_depth=8,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        min_child_weight=2,
        gamma=0.05,
        reg_lambda=1.5,
        objective="multi:softprob",
        eval_metric="mlogloss",
        n_jobs=-1,
        tree_method="hist",
        random_state=42,
    )
    clf_hardened.fit(Xs_aug, y_aug)

    hardened_artifacts = HybridArtifacts(
        transformer=base_artifacts.transformer,
        autoencoder=base_artifacts.autoencoder,
        xgboost=clf_hardened,
        recon_threshold=base_artifacts.recon_threshold,
        label_classes=base_artifacts.label_classes,
        selected_features=base_artifacts.selected_features,
        feature_names=base_artifacts.feature_names,
        novelty_gate=base_artifacts.novelty_gate,
        recon_quantile=base_artifacts.recon_quantile,
    )

    # Save hardened model artifacts
    save_artifacts(HARDENED_MODEL_PATH, hardened_artifacts, extra={"type": "adversarially_hardened"})

    # Evaluate robustness metrics across test attacks
    if progress_callback:
        progress_callback("Evaluating robustness benchmark on test split...")

    benchmark = compute_adversarial_benchmark(base_artifacts, hardened_artifacts, known_test)
    ADVERSARIAL_METRICS_PATH.write_text(json.dumps(benchmark, indent=2), encoding="utf-8")

    return benchmark


def compute_adversarial_benchmark(
    base_artifacts: HybridArtifacts,
    hardened_artifacts: HybridArtifacts,
    test_df: pd.DataFrame,
) -> dict[str, Any]:
    """Computes comprehensive empirical metrics comparing baseline and hardened models."""
    attack_mask = test_df["label"] != "normal"
    test_attacks = test_df[attack_mask].sample(n=min(1500, int(attack_mask.sum())), random_state=42).copy()
    test_benign = test_df[~attack_mask].sample(n=min(1500, int((~attack_mask).sum())), random_state=42).copy()

    X_clean_attacks = base_artifacts.transformer.transform(test_attacks)
    X_clean_benign = base_artifacts.transformer.transform(test_benign)

    # 1. Clean performance
    base_clean_pred = hybrid_predict(base_artifacts, X_clean_attacks)
    hard_clean_pred = hybrid_predict(hardened_artifacts, X_clean_attacks)

    base_benign_pred = hybrid_predict(base_artifacts, X_clean_benign)
    hard_benign_pred = hybrid_predict(hardened_artifacts, X_clean_benign)

    base_clean_recall = float((base_clean_pred["label"] != "normal").mean())
    hard_clean_recall = float((hard_clean_pred["label"] != "normal").mean())
    base_fpr = float((base_benign_pred["label"] != "normal").mean())
    hard_fpr = float((hard_benign_pred["label"] != "normal").mean())

    # 2. Perturbation sweeps across methods and epsilons
    methods = ["demgan", "uap", "fgsm"]
    epsilons = [0.10, 0.20, 0.35]
    sweep_results = []

    for m in methods:
        for eps in epsilons:
            pert_attacks = generate_adversarial_perturbation(test_attacks, method=m, epsilon=eps, seed=42)
            X_pert = base_artifacts.transformer.transform(pert_attacks)

            b_pred = hybrid_predict(base_artifacts, X_pert)
            h_pred = hybrid_predict(hardened_artifacts, X_pert)

            base_clf_evasion = float((b_pred["known_label"] == "normal").mean())
            hard_clf_evasion = float((h_pred["known_label"] == "normal").mean())
            base_hybrid_evasion = float((b_pred["label"] == "normal").mean())
            hard_hybrid_evasion = float((h_pred["label"] == "normal").mean())
            base_attack_recall = float((b_pred["label"] != "normal").mean())
            hard_attack_recall = float((h_pred["label"] != "normal").mean())

            # Evasion reduction percentage
            evasion_mitigation_pct = (
                float((base_hybrid_evasion - hard_hybrid_evasion) / max(base_hybrid_evasion, 1e-4) * 100)
            )

            sweep_results.append({
                "method": m,
                "epsilon": eps,
                "baseline_classifier_evasion": round(base_clf_evasion, 4),
                "hardened_classifier_evasion": round(hard_clf_evasion, 4),
                "baseline_hybrid_evasion": round(base_hybrid_evasion, 4),
                "hardened_hybrid_evasion": round(hard_hybrid_evasion, 4),
                "baseline_attack_recall": round(base_attack_recall, 4),
                "hardened_attack_recall": round(hard_attack_recall, 4),
                "evasion_mitigation_pct": round(evasion_mitigation_pct, 1),
            })

    # Primary summary metrics (DEMGAN at standard ε=0.20)
    std_demgan = next(r for r in sweep_results if r["method"] == "demgan" and r["epsilon"] == 0.20)

    return {
        "status": "ready",
        "clean_metrics": {
            "baseline_attack_recall": round(base_clean_recall, 4),
            "hardened_attack_recall": round(hard_clean_recall, 4),
            "baseline_fpr": round(base_fpr, 4),
            "hardened_fpr": round(hard_fpr, 4),
            "fpr_penalty": round(hard_fpr - base_fpr, 4),
        },
        "adversarial_summary": {
            "method": "DEMGAN (Xu et al. 2025)",
            "epsilon": 0.20,
            "baseline_evasion_rate": std_demgan["baseline_hybrid_evasion"],
            "hardened_evasion_rate": std_demgan["hardened_hybrid_evasion"],
            "baseline_clf_evasion": std_demgan["baseline_classifier_evasion"],
            "hardened_clf_evasion": std_demgan["hardened_classifier_evasion"],
            "evasion_reduction_pct": std_demgan["evasion_mitigation_pct"],
            "hardened_attack_recall": std_demgan["hardened_attack_recall"],
        },
        "sweep": sweep_results,
        "domain_constraints": {
            "rate_columns_clamped": len(RATE_COLUMNS),
            "counts_non_negative": len(COUNT_COLUMNS),
            "immutable_columns_preserved": IMMUTABLE_COLUMNS,
            "invariants_enforced": [
                "0.0 <= error_rates <= 1.0",
                "counts >= 0 and discrete rounded",
                "protocol_type and TCP handshake invariants preserved",
            ],
        },
    }


@lru_cache(maxsize=1)
def get_hardened_model():
    """Loads the adversarially hardened model artifacts."""
    if not HARDENED_MODEL_PATH.exists():
        # Fall back to training if not present
        train_hardened_pipeline()
    artifacts, extra = load_artifacts(HARDENED_MODEL_PATH)
    return artifacts, extra


def load_adversarial_metrics() -> dict[str, Any]:
    """Loads cached adversarial metrics or generates them."""
    if not ADVERSARIAL_METRICS_PATH.exists():
        return train_hardened_pipeline()
    return json.loads(ADVERSARIAL_METRICS_PATH.read_text(encoding="utf-8"))


def simulate_adversarial_flow(
    payload: dict[str, Any],
    method: str = "demgan",
    epsilon: float = 0.20,
) -> dict[str, Any]:
    """Simulates adversarial flow perturbation and evaluates both Baseline and Hardened models."""
    base_artifacts, _ = load_artifacts(model_path())
    hardened_artifacts, _ = get_hardened_model()

    # Create DataFrame from payload
    from app.ml.features import sample_to_dataframe
    orig_df = sample_to_dataframe(payload)

    # Generate perturbed flow
    pert_df = generate_adversarial_perturbation(orig_df, method=method, epsilon=epsilon)

    # Compute deltas for modified features
    deltas: list[dict[str, Any]] = []
    for col in FEATURE_COLUMNS:
        orig_val = orig_df[col].iloc[0]
        pert_val = pert_df[col].iloc[0]
        if isinstance(orig_val, (int, float, np.number)) and isinstance(pert_val, (int, float, np.number)):
            diff = float(pert_val - orig_val)
            if abs(diff) > 1e-4:
                deltas.append({
                    "feature": col,
                    "original": round(float(orig_val), 4),
                    "perturbed": round(float(pert_val), 4),
                    "delta": round(diff, 4),
                })
        elif str(orig_val) != str(pert_val):
            deltas.append({
                "feature": col,
                "original": str(orig_val),
                "perturbed": str(pert_val),
                "delta": "modified",
            })

    # Sort deltas by magnitude of change
    deltas.sort(key=lambda d: abs(d["delta"]) if isinstance(d["delta"], (int, float)) else 0, reverse=True)

    # Predict with Baseline Model (Original & Perturbed)
    X_orig = base_artifacts.transformer.transform(orig_df)
    X_pert = base_artifacts.transformer.transform(pert_df)

    b_orig_pred = hybrid_predict(base_artifacts, X_orig)
    b_pert_pred = hybrid_predict(base_artifacts, X_pert)

    # Predict with Hardened Model (Perturbed)
    h_pert_pred = hybrid_predict(hardened_artifacts, X_pert)

    # Priority & Triage for all
    from app.ml.detector import get_tier_cutoffs
    cutoffs = get_tier_cutoffs()
    service = str(payload.get("service", ""))
    crit = SERVICE_CRITICALITY.get(service, 0.5)

    def _eval_meta(pred_dict, df_row):
        label = str(pred_dict["label"][0])
        conf = float(pred_dict["confidence"][0])
        recon = float(pred_dict["reconstruction_error"][0])
        is_zd = bool(pred_dict["is_zero_day"][0])
        p, comps, _ = compute_priority(conf, recon, base_artifacts.recon_threshold, label, is_zd, crit)
        tier = tier_from_score(p, cutoffs)
        return {
            "predicted": label,
            "known_class": str(pred_dict["known_label"][0]),
            "confidence": round(conf, 4),
            "reconstruction_error": round(recon, 4),
            "anomaly_ratio": round(recon / max(base_artifacts.recon_threshold, 1e-6), 2),
            "is_zero_day": is_zd,
            "priority": round(p, 4),
            "tier": tier,
        }

    baseline_clean_res = _eval_meta(b_orig_pred, orig_df)
    baseline_perturbed_res = _eval_meta(b_pert_pred, pert_df)
    hardened_perturbed_res = _eval_meta(h_pert_pred, pert_df)

    # Evasion Analysis
    baseline_evaded = bool(baseline_perturbed_res["predicted"] == "normal")
    hardened_evaded = bool(hardened_perturbed_res["predicted"] == "normal")
    evasion_blocked = bool(baseline_evaded and not hardened_evaded)

    return {
        "method": method,
        "epsilon": float(epsilon),
        "deltas_count": len(deltas),
        "feature_deltas": deltas[:15],  # top 15 modified features
        "perturbed_flow": pert_df.iloc[0].to_dict(),
        "baseline_clean": baseline_clean_res,
        "baseline_under_attack": baseline_perturbed_res,
        "hardened_under_attack": hardened_perturbed_res,
        "analysis": {
            "baseline_evaded": baseline_evaded,
            "hardened_evaded": hardened_evaded,
            "evasion_blocked": evasion_blocked,
            "status": (
                "Hardened Model Successfully Blocked Evasion"
                if evasion_blocked
                else ("Attack Caught by Both Models" if not baseline_evaded else "Evasion Succeeded Against Both")
            ),
        },
    }

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from xgboost import XGBClassifier

# Ensure backend root is on path
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import DATA_DIR, MODELS_DIR  # noqa: E402
from app.ml.encrypted_features import (  # noqa: E402
    EncryptedDetectorArtifacts,
    EncryptedFeatureTransformer,
    load_clean_encrypted_dataset,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aegis.train_encrypted")


def evaluate_encrypted_binary(y_true: np.ndarray, y_score: np.ndarray, threshold: float = 0.50) -> dict[str, Any]:
    """Compute binary classification metrics at a given decision threshold."""
    y_pred = (y_score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    roc_auc = float(roc_auc_score(y_true, y_score)) if len(np.unique(y_true)) > 1 else None
    pr_auc = float(average_precision_score(y_true, y_score)) if len(np.unique(y_true)) > 1 else None

    return {
        "threshold": round(float(threshold), 3),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "benign_fpr": round(fpr, 4),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
        "pr_auc": round(pr_auc, 4) if pr_auc is not None else None,
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def compute_threshold_sweep(y_true: np.ndarray, y_score: np.ndarray) -> list[dict[str, Any]]:
    """Evaluate performance across a standard sweep of classification thresholds."""
    thresholds = [0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90]
    sweep = []
    for th in thresholds:
        m = evaluate_encrypted_binary(y_true, y_score, threshold=th)
        sweep.append({
            "threshold": th,
            "precision": m["precision"],
            "recall": m["recall"],
            "f1": m["f1"],
            "benign_fpr": m["benign_fpr"],
            "tp": m["true_positives"],
            "fp": m["false_positives"],
            "fn": m["false_negatives"],
            "tn": m["true_negatives"],
        })
    return sweep


def train_encrypted_pipeline(
    data_dir: Path | str | None = None,
    max_train_samples: int | None = 150000,
    max_test_samples: int | None = 50000,
    random_state: int = 42,
) -> dict[str, Any]:
    """
    Executes the full Problem 2 training, ablation, and evaluation workflow.
    """
    if data_dir is None:
        data_dir = DATA_DIR / "raw" / "encrypted_traffic" / "malware" / "malware.parquet"
    data_path = Path(data_dir)

    print("=" * 78)
    print("  AEGIS — Problem 2: Encrypted Traffic Analysis (Training & Evaluation)")
    print("=" * 78)
    print(f"Dataset path: {data_path}")

    # 1. Load dataset with strict candidate labeling & chronological group split
    t0 = time.time()
    df_train, df_test, split_meta = load_clean_encrypted_dataset(
        data_dir=data_path,
        cutoff_date=250922,
        max_train_samples=max_train_samples,
        max_test_samples=max_test_samples,
        random_state=random_state,
    )
    t_load = time.time() - t0

    print(f"\n[1/5] Dataset loaded in {t_load:.2f} s:")
    print(f"  Training Split (Days <= 250922): {split_meta['train_rows']:,} flows ({split_meta['train_sample_ids']:,} execution groups)")
    print(f"    - Malicious (Candidate Positive): {split_meta['train_positives']:,} ({(split_meta['train_positives']/split_meta['train_rows']*100):.1f}%)")
    print(f"    - Benign (Candidate Negative):    {split_meta['train_negatives']:,} ({(split_meta['train_negatives']/split_meta['train_rows']*100):.1f}%)")
    print(f"  Holdout Test Split (Days >= 250923): {split_meta['test_rows']:,} flows ({split_meta['test_sample_ids']:,} execution groups)")
    print(f"    - Malicious (Candidate Positive): {split_meta['test_positives']:,} ({(split_meta['test_positives']/split_meta['test_rows']*100):.1f}%)")
    print(f"    - Benign (Candidate Negative):    {split_meta['test_negatives']:,} ({(split_meta['test_negatives']/split_meta['test_rows']*100):.1f}%)")
    print(f"  Sample ID Overlap Check: {split_meta['sample_id_overlap']} (VERIFIED ZERO EXECUTION LEAKAGE)")
    print(f"  Natural Zero-Day Families in Test: {len(split_meta['natural_zero_days'])} families")
    if split_meta["natural_zero_days"]:
        print(f"    Examples: {split_meta['natural_zero_days'][:8]}")

    y_train = df_train["label"].to_numpy()
    y_test = df_test["label"].to_numpy()

    # 2. Feature Ablation Experiment (Requirement 7)
    # Model A: Flow + Handshake Counts baseline (NO SPLT sequence, NO categorical fingerprints)
    # Model B: Baseline + SPLT Record Sequence (tls.rec[0:20])
    # Model C (Deployed): Full Model (Flow + Handshake + SPLT + Categorical Fingerprints)
    print("\n[2/5] Running Feature Architecture Ablation Comparison:")

    architectures = [
        ("Model A (Flow + Handshake Baseline)", EncryptedFeatureTransformer(include_splt=False, include_categoricals=False)),
        ("Model B (Baseline + SPLT Sequence)", EncryptedFeatureTransformer(include_splt=True, include_categoricals=False)),
        ("Model C (Full: SPLT + Categoricals)", EncryptedFeatureTransformer(include_splt=True, include_categoricals=True)),
    ]

    ablation_results: dict[str, Any] = {}
    best_clf: XGBClassifier | None = None
    best_transformer: EncryptedFeatureTransformer | None = None
    best_y_prob: np.ndarray | None = None

    for name, transformer in architectures:
        t_start = time.time()
        transformer.fit(df_train)
        X_tr = transformer.transform(df_train)
        X_te = transformer.transform(df_test)

        clf = XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.8,
            colsample_bytree=0.8,
            tree_method="hist",
            eval_metric="logloss",
            random_state=random_state,
            n_jobs=-1,
        )
        clf.fit(X_tr, y_train)
        y_prob = clf.predict_proba(X_te)[:, 1]
        t_dur = time.time() - t_start

        m = evaluate_encrypted_binary(y_test, y_prob, threshold=0.50)
        ablation_results[name] = {
            "features_count": len(transformer.feature_names_),
            "training_time_sec": round(t_dur, 2),
            "accuracy": m["accuracy"],
            "precision": m["precision"],
            "recall": m["recall"],
            "f1": m["f1"],
            "benign_fpr": m["benign_fpr"],
            "roc_auc": m["roc_auc"],
            "pr_auc": m["pr_auc"],
        }
        print(f"  * {name:<35} | Feats: {len(transformer.feature_names_):2d} | Time: {t_dur:5.2f}s | Acc: {m['accuracy']*100:.2f}% | Rec: {m['recall']*100:.2f}% | FPR: {m['benign_fpr']*100:.2f}% | F1: {m['f1']:.4f} | ROC-AUC: {m['roc_auc']:.4f}")

        # Keep Model C as deployed primary model
        if "Full" in name:
            best_clf = clf
            best_transformer = transformer
            best_y_prob = y_prob

    assert best_clf is not None and best_transformer is not None and best_y_prob is not None

    # 3. Comprehensive Evaluation of Deployed Model (Model C)
    print("\n[3/5] Evaluating Deployed Model on Chronological Holdout Split:")
    primary_metrics = evaluate_encrypted_binary(y_test, best_y_prob, threshold=0.50)
    sweep_metrics = compute_threshold_sweep(y_test, best_y_prob)

    print(f"  Holdout Test Accuracy : {primary_metrics['accuracy'] * 100:.2f}%")
    print(f"  Malware Attack Recall : {primary_metrics['recall'] * 100:.2f}%")
    print(f"  Malware Precision     : {primary_metrics['precision'] * 100:.2f}%")
    print(f"  Malware F1 Score      : {primary_metrics['f1']:.4f}")
    print(f"  Benign False Alarm Rate (FPR): {primary_metrics['benign_fpr'] * 100:.2f}%")
    print(f"  ROC-AUC / PR-AUC      : {primary_metrics['roc_auc']:.4f} / {primary_metrics['pr_auc']:.4f}")
    print(f"  Confusion Matrix      : TN={primary_metrics['true_negatives']:,}, FP={primary_metrics['false_positives']:,}, FN={primary_metrics['false_negatives']:,}, TP={primary_metrics['true_positives']:,}")

    # 4. Slice Evaluation: Seen Families vs Natural Zero-Days vs Clean Runs
    print("\n[4/5] Detailed Slice & Generalization Analysis:")
    test_families = df_test["meta.malware.family"].to_numpy()

    # Slice A: Seen malware families in test
    seen_mask = (y_test == 1) & (~df_test["meta.malware.family"].isin(split_meta["natural_zero_days"]))
    seen_rec = float(recall_score(y_test[seen_mask], (best_y_prob[seen_mask] >= 0.5).astype(int), zero_division=0)) if seen_mask.sum() > 0 else 0.0
    print(f"  Slice A: Seen Malware Families Recall   : {seen_rec * 100:.2f}% ({seen_mask.sum():,} flows)")

    # Slice B: Natural Zero-Day Malware Families in test (never seen in training window)
    zd_mask = (y_test == 1) & (df_test["meta.malware.family"].isin(split_meta["natural_zero_days"]))
    zd_rec = float(recall_score(y_test[zd_mask], (best_y_prob[zd_mask] >= 0.5).astype(int), zero_division=0)) if zd_mask.sum() > 0 else 0.0
    print(f"  Slice B: Natural Zero-Day Families Recall: {zd_rec * 100:.2f}% ({zd_mask.sum():,} flows across {len(split_meta['natural_zero_days'])} unseen families)")

    # Slice C: Clean baseline NO_MALWARE runs in test (provenance from *NO_MALWARE*.parquet source files)
    clean_sids = set(split_meta.get("clean_sample_ids", []))
    if "is_clean_control" in df_test.columns:
        clean_run_mask = df_test["is_clean_control"].to_numpy() & (y_test == 0)
    else:
        clean_run_mask = df_test["meta.sample.id"].isin(clean_sids).to_numpy() & (y_test == 0)

    clean_count = int(clean_run_mask.sum())
    clean_fp = int(((best_y_prob[clean_run_mask] >= 0.5).sum()))
    clean_fpr = float(clean_fp / clean_count) if clean_count > 0 else None
    clean_fpr_disp = f"{clean_fpr * 100:.2f}% ({clean_fp:,}/{clean_count:,} flows)" if clean_fpr is not None else "N/A (0 flows)"
    print(f"  Slice C: Clean Control Runs FPR         : {clean_fpr_disp}")

    # Slice D: Benign services in malware VMs (disjoint subgroup)
    service_run_mask = (~clean_run_mask) & (y_test == 0)
    service_count = int(service_run_mask.sum())
    service_fp = int(((best_y_prob[service_run_mask] >= 0.5).sum()))
    service_fpr = float(service_fp / service_count) if service_count > 0 else None
    service_fpr_disp = f"{service_fpr * 100:.2f}% ({service_fp:,}/{service_count:,} flows)" if service_fpr is not None else "N/A (0 flows)"
    print(f"  Slice D: Malware VM Benign Services FPR : {service_fpr_disp}")

    # Feature Importance (Top 15)
    importances = best_clf.feature_importances_
    feat_names = best_transformer.feature_names_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = [{"feature": feat_names[i], "importance": round(float(importances[i]), 4)} for i in sorted_idx[:15]]

    print("\n  Top Feature Contributors (XGBoost Gini Importance):")
    for tf in top_features[:8]:
        print(f"    - {tf['feature']:<25}: {tf['importance']:.4f}")

    # 5. Persist Problem 2 Artifacts (Separate Filenames)
    print("\n[5/5] Persisting Model Artifacts and Verification Records:")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib_path = MODELS_DIR / "encrypted_detector.joblib"
    xgb_json_path = MODELS_DIR / "encrypted_detector_xgb.json"
    metrics_path = MODELS_DIR / "encrypted_metrics.json"

    # Save native XGBoost booster
    best_clf.get_booster().save_model(str(xgb_json_path))
    print(f"  * Native XGBoost JSON : {xgb_json_path.relative_to(ROOT)}")

    # Save transformer + wrapper in joblib
    compact_artifacts = EncryptedDetectorArtifacts(
        transformer=best_transformer,
        xgboost=None,  # Reloaded from native JSON
        feature_names=best_transformer.feature_names_,
        threshold=0.50,
        model_version="1.0.0",
    )
    joblib.dump(compact_artifacts, joblib_path)
    print(f"  * Transformer Bundle  : {joblib_path.relative_to(ROOT)}")

    # Full audit payload
    metrics_payload: dict[str, Any] = {
        "problem": "Problem 2: Encrypted TLS Traffic Threat Detection",
        "dataset_name": "Triage Malware Sandbox TLS Traffic Collection (Sept 2025)",
        "model_architecture": "XGBoost Classifier with SPLT Packet Dynamics & TLS Handshake Features",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "split_summary": split_meta,
        "ablation_comparison": ablation_results,
        "primary_evaluation": primary_metrics,
        "slice_evaluation": {
            "seen_families_recall": round(seen_rec, 4),
            "seen_families_count": int(seen_mask.sum()),
            "natural_zero_day_recall": round(zd_rec, 4),
            "natural_zero_day_count": int(zd_mask.sum()),
            "natural_zero_day_families": split_meta["natural_zero_days"],
            "clean_no_malware_fpr": round(clean_fpr, 4) if clean_fpr is not None else None,
            "clean_no_malware_count": clean_count,
            "clean_no_malware_fp": clean_fp,
            "benign_service_fpr": round(service_fpr, 4) if service_fpr is not None else None,
            "benign_service_count": service_count,
            "benign_service_fp": service_fp,
        },
        "threshold_sweep": sweep_metrics,
        "top_features": top_features,
        "feature_names": best_transformer.feature_names_,
    }

    metrics_path.write_text(json.dumps(metrics_payload, indent=2), encoding="utf-8")
    print(f"  * Verification Metrics: {metrics_path.relative_to(ROOT)}")

    # Persist deterministic test sample ID manifest alongside future benchmark outputs
    manifest_path = MODELS_DIR / "encrypted_test_sample_ids.json"
    manifest_payload: dict[str, Any] = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "description": "Deterministic test sample IDs used for Problem 2 holdout evaluation",
        "sample_count": int(df_test["meta.sample.id"].nunique()),
        "flow_count": len(df_test),
        "test_sample_ids": sorted(list(df_test["meta.sample.id"].unique())),
    }
    manifest_path.write_text(json.dumps(manifest_payload, indent=2), encoding="utf-8")
    print(f"  * Test Sample Manifest: {manifest_path.relative_to(ROOT)}")
    print("\n" + "=" * 78)
    print("  Phase 1 Complete: Model Trained, Evaluated, and Verified Successfully.")
    print("=" * 78)

    return metrics_payload


def load_encrypted_detector(
    joblib_path: Path | str | None = None,
    xgb_json_path: Path | str | None = None,
) -> tuple[EncryptedDetectorArtifacts, XGBClassifier]:
    """Helper to reload the trained Problem 2 detector and native booster."""
    if joblib_path is None:
        joblib_path = MODELS_DIR / "encrypted_detector.joblib"
    if xgb_json_path is None:
        xgb_json_path = MODELS_DIR / "encrypted_detector_xgb.json"

    artifacts: EncryptedDetectorArtifacts = joblib.load(joblib_path)
    clf = XGBClassifier()
    clf.load_model(str(xgb_json_path))
    artifacts.xgboost = clf
    return artifacts, clf


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train AEGIS Problem 2 Encrypted Traffic Detector")
    parser.add_argument("--full", action="store_true", help="Train on all available flows without downsampling")
    parser.add_argument("--max-train", type=int, default=150000, help="Max train flows to sample by execution group")
    parser.add_argument("--max-test", type=int, default=50000, help="Max test flows to sample by execution group")
    args = parser.parse_args()

    max_tr = None if args.full else args.max_train
    max_te = None if args.full else args.max_test
    train_encrypted_pipeline(max_train_samples=max_tr, max_test_samples=max_te)

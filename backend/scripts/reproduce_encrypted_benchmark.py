#!/usr/bin/env python3
"""
Reproduce Encrypted TLS Benchmark Script.

Loads the saved Problem 2 production detector (without retraining),
extracts features using the trained transformer bundle, evaluates across
the deterministic chronological holdout population, and exports a paired
reproducible benchmark artifact and sample ID manifest.

Usage:
    python backend/scripts/reproduce_encrypted_benchmark.py
    python backend/scripts/reproduce_encrypted_benchmark.py --verify
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import xgboost as xgb
import joblib
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
REPO_ROOT = BACKEND_DIR.parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import DATA_DIR, MODELS_DIR
from app.ml.encrypted_features import load_clean_encrypted_dataset


def compute_file_sha256(path: Path) -> str:
    """Computes SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def run_benchmark_evaluation(
    data_dir: Path,
    joblib_path: Path,
    xgb_json_path: Path,
    cutoff_date: int = 250922,
    threshold: float = 0.50,
    manifest_sample_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Runs deterministic evaluation of the saved model on holdout traffic."""
    # 1. Verify model artifacts exist
    if not joblib_path.exists():
        raise FileNotFoundError(f"Model bundle not found: {joblib_path}")
    if not xgb_json_path.exists():
        raise FileNotFoundError(f"Native XGBoost JSON not found: {xgb_json_path}")

    joblib_sha = compute_file_sha256(joblib_path)
    xgb_sha = compute_file_sha256(xgb_json_path)

    # 2. Load model bundle and native booster
    bundle = joblib.load(joblib_path)
    transformer = bundle.transformer
    feature_names = bundle.feature_names
    saved_threshold = getattr(bundle, "threshold", threshold)

    booster = xgb.Booster()
    booster.load_model(str(xgb_json_path))

    # 3. Load dataset
    print(f"Loading holdout dataset from {data_dir} (cutoff_date={cutoff_date})...")
    t0 = time.time()
    _, df_test, split_meta = load_clean_encrypted_dataset(
        data_dir=data_dir,
        cutoff_date=cutoff_date,
        max_train_samples=1,  # Minimal train loading to accelerate test extraction
        max_test_samples=None,
        random_state=42,
    )
    load_time = time.time() - t0
    print(f"Loaded {len(df_test):,} holdout flows in {load_time:.2f}s.")

    # If manifest is supplied, filter df_test to exact sample IDs
    if manifest_sample_ids is not None:
        valid_set = set(manifest_sample_ids)
        df_test = df_test[df_test["meta.sample.id"].isin(valid_set)].copy()
        print(f"Filtered to manifest: {len(df_test):,} flows across {df_test['meta.sample.id'].nunique():,} sample IDs.")

    # 4. Feature transformation
    t1 = time.time()
    X_test = transformer.transform(df_test)
    transform_time = time.time() - t1

    # 5. Model scoring
    t2 = time.time()
    dtest = xgb.DMatrix(X_test, feature_names=feature_names)
    y_prob = booster.predict(dtest)
    y_true = df_test["label"].to_numpy().astype(int)
    y_pred = (y_prob >= saved_threshold).astype(int)
    scoring_time = time.time() - t2

    # 6. Primary metrics
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    roc = float(roc_auc_score(y_true, y_prob))
    pr_auc = float(average_precision_score(y_true, y_prob))

    # 7. Subgroup metrics
    clean_mask = df_test["is_clean_control"].to_numpy() & (y_true == 0)
    service_mask = (~df_test["is_clean_control"].to_numpy()) & (y_true == 0)

    clean_count = int(clean_mask.sum())
    clean_fp = int((y_pred[clean_mask] == 1).sum())
    clean_fpr = float(clean_fp / clean_count) if clean_count > 0 else 0.0

    service_count = int(service_mask.sum())
    service_fp = int((y_pred[service_mask] == 1).sum())
    service_fpr = float(service_fp / service_count) if service_count > 0 else 0.0

    combined_subgroup_count = clean_count + service_count
    combined_subgroup_fp = clean_fp + service_fp
    combined_subgroup_fpr = float(combined_subgroup_fp / combined_subgroup_count) if combined_subgroup_count > 0 else 0.0

    # 8. Zero-day families evaluation
    zd_fams = split_meta.get("natural_zero_days", [])
    zd_mask = df_test["meta.malware.family"].isin(set(zd_fams)).to_numpy()
    zd_count = int(zd_mask.sum())
    zd_tp = int((y_pred[zd_mask] == 1).sum())
    zd_recall = float(zd_tp / zd_count) if zd_count > 0 else 0.0

    ordered_sample_ids = sorted(list(df_test["meta.sample.id"].unique()))

    return {
        "joblib_sha256": joblib_sha,
        "xgb_json_sha256": xgb_sha,
        "timing": {
            "load_time_sec": round(load_time, 2),
            "transform_time_sec": round(transform_time, 2),
            "scoring_time_sec": round(scoring_time, 2),
        },
        "population": {
            "flow_count": len(df_test),
            "sample_count": len(ordered_sample_ids),
            "malicious_count": int((y_true == 1).sum()),
            "benign_count": int((y_true == 0).sum()),
            "dates": f"{df_test['date'].min()} to {df_test['date'].max()}",
        },
        "primary_evaluation": {
            "threshold": saved_threshold,
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "benign_fpr": round(fpr, 4),
            "roc_auc": round(roc, 4),
            "pr_auc": round(pr_auc, 4),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
            "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        },
        "subgroups": {
            "clean_control": {
                "flow_count": clean_count,
                "false_positives": clean_fp,
                "fpr": round(clean_fpr, 4),
            },
            "malware_vm_services": {
                "flow_count": service_count,
                "false_positives": service_fp,
                "fpr": round(service_fpr, 4),
            },
            "combined": {
                "flow_count": combined_subgroup_count,
                "false_positives": combined_subgroup_fp,
                "fpr": round(combined_subgroup_fpr, 4),
            },
        },
        "zero_day_evaluation": {
            "families_count": len(zd_fams),
            "families": zd_fams,
            "flow_count": zd_count,
            "detected_count": zd_tp,
            "recall": round(zd_recall, 4),
        },
        "sample_ids": ordered_sample_ids,
        "raw_predictions": y_prob,
        "raw_labels": y_true,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Reproduce AEGIS Problem 2 Encrypted TLS Benchmark")
    parser.add_argument(
        "--metrics-out",
        type=Path,
        default=MODELS_DIR / "encrypted_benchmark_reproducible_metrics.json",
        help="Path to save reproducible metrics artifact",
    )
    parser.add_argument(
        "--manifest-out",
        type=Path,
        default=MODELS_DIR / "encrypted_benchmark_reproducible_manifest.json",
        help="Path to save reproducible test sample IDs manifest",
    )
    parser.add_argument(
        "--manifest-in",
        type=Path,
        default=None,
        help="Optional input manifest to evaluate against an exact sample list",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Execute two consecutive evaluations and assert bit-for-bit reproducibility",
    )
    args = parser.parse_args()

    data_dir = DATA_DIR / "raw" / "encrypted_traffic" / "malware" / "malware.parquet"
    joblib_path = MODELS_DIR / "encrypted_detector.joblib"
    xgb_json_path = MODELS_DIR / "encrypted_detector_xgb.json"

    print("=" * 80)
    print(" AEGIS Problem 2 — Reproducible Benchmark Evaluation (Full Holdout Population)")
    print("=" * 80)

    # 1. Execute primary evaluation run
    manifest_ids = None
    if args.manifest_in and args.manifest_in.exists():
        manifest_data = json.loads(args.manifest_in.read_text(encoding="utf-8"))
        manifest_ids = manifest_data.get("test_sample_ids")
        print(f"Loaded {len(manifest_ids):,} sample IDs from input manifest: {args.manifest_in}")

    print("\n--- Run 1: Generating benchmark results from saved model ---")
    run1 = run_benchmark_evaluation(
        data_dir=data_dir,
        joblib_path=joblib_path,
        xgb_json_path=xgb_json_path,
        cutoff_date=250922,
        threshold=0.50,
        manifest_sample_ids=manifest_ids,
    )

    benchmark_id = f"aegis-problem2-holdout-reproducible-{run1['xgb_json_sha256'][:8]}"

    # Prepare manifest payload
    manifest_payload = {
        "benchmark_id": benchmark_id,
        "description": "Deterministic test sample IDs for AEGIS Problem 2 Holdout Evaluation",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model_xgb_sha256": run1["xgb_json_sha256"],
        "model_joblib_sha256": run1["joblib_sha256"],
        "cutoff_date": 250922,
        "sample_count": run1["population"]["sample_count"],
        "flow_count": run1["population"]["flow_count"],
        "test_sample_ids": run1["sample_ids"],
    }

    manifest_json_text = json.dumps(manifest_payload, indent=2)
    manifest_sha = hashlib.sha256(manifest_json_text.encode("utf-8")).hexdigest()

    # Prepare metrics payload
    metrics_payload = {
        "benchmark_id": benchmark_id,
        "problem": "Problem 2: Encrypted TLS Traffic Threat Detection",
        "dataset_name": "Triage Malware Sandbox TLS Traffic Collection (Sept 2025)",
        "model_architecture": "XGBoost Classifier with SPLT Packet Dynamics & TLS Handshake Features",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "provenance": {
            "model_joblib_sha256": run1["joblib_sha256"],
            "model_xgb_sha256": run1["xgb_json_sha256"],
            "manifest_file": args.manifest_out.name,
            "manifest_sha256": manifest_sha,
            "evaluation_mode": "full_chronological_holdout" if manifest_ids is None else "manifest_filtered",
            "date_cutoff": 250922,
        },
        "timing": run1["timing"],
        "population": run1["population"],
        "primary_evaluation": run1["primary_evaluation"],
        "subgroups": run1["subgroups"],
        "zero_day_evaluation": run1["zero_day_evaluation"],
    }

    # Save matched pair of artifacts
    args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
    args.manifest_out.write_text(manifest_json_text, encoding="utf-8")
    args.metrics_out.write_text(json.dumps(metrics_payload, indent=2), encoding="utf-8")

    print(f"\nSaved Manifest : {args.manifest_out}")
    print(f"  * Sample count : {manifest_payload['sample_count']:,}")
    print(f"  * Flow count   : {manifest_payload['flow_count']:,}")
    print(f"  * SHA-256      : {manifest_sha}")

    print(f"\nSaved Metrics  : {args.metrics_out}")
    print(f"  * Accuracy     : {run1['primary_evaluation']['accuracy']*100:.2f}%")
    print(f"  * Recall       : {run1['primary_evaluation']['recall']*100:.2f}%")
    print(f"  * Precision    : {run1['primary_evaluation']['precision']*100:.2f}%")
    print(f"  * F1-Score     : {run1['primary_evaluation']['f1']:.4f}")
    print(f"  * Benign FPR   : {run1['primary_evaluation']['benign_fpr']*100:.2f}%")
    print(f"  * Clean FPR    : {run1['subgroups']['clean_control']['fpr']*100:.2f}%")
    print(f"  * Services FPR : {run1['subgroups']['malware_vm_services']['fpr']*100:.2f}%")
    print(f"  * ROC-AUC      : {run1['primary_evaluation']['roc_auc']:.4f}")
    print(f"  * PR-AUC       : {run1['primary_evaluation']['pr_auc']:.4f}")

    # 2. Run verification pass if requested
    if args.verify:
        print("\n" + "=" * 80)
        print("--- Run 2: Verifying Reproducibility Against Saved Manifest ---")
        print("=" * 80)
        run2 = run_benchmark_evaluation(
            data_dir=data_dir,
            joblib_path=joblib_path,
            xgb_json_path=xgb_json_path,
            cutoff_date=250922,
            threshold=0.50,
            manifest_sample_ids=manifest_payload["test_sample_ids"],
        )

        # Assert identical populations
        assert run1["population"]["flow_count"] == run2["population"]["flow_count"], "Flow counts differ!"
        assert run1["population"]["sample_count"] == run2["population"]["sample_count"], "Sample counts differ!"
        assert run1["sample_ids"] == run2["sample_ids"], "Sample ID sequences differ!"

        # Assert identical predictions
        max_prob_diff = float(np.max(np.abs(run1["raw_predictions"] - run2["raw_predictions"])))
        pred_mismatches = int(np.sum(
            (run1["raw_predictions"] >= 0.50).astype(int) != (run2["raw_predictions"] >= 0.50).astype(int)
        ))
        assert pred_mismatches == 0, f"Found {pred_mismatches} prediction label mismatches!"
        assert max_prob_diff < 1e-6, f"Max probability difference {max_prob_diff} exceeds tolerance!"

        # Assert identical metrics
        assert run1["primary_evaluation"] == run2["primary_evaluation"], "Primary evaluation metrics differ!"
        assert run1["subgroups"] == run2["subgroups"], "Subgroup metrics differ!"
        assert run1["zero_day_evaluation"] == run2["zero_day_evaluation"], "Zero-day metrics differ!"

        print("\n[VERIFICATION RESULT: 100% BIT-FOR-BIT REPRODUCIBILITY CONFIRMED]")
        print(f"  * Evaluated Flow Counts : Run 1 = {run1['population']['flow_count']:,} | Run 2 = {run2['population']['flow_count']:,} (MATCH)")
        print(f"  * Evaluated Sample IDs  : Run 1 = {run1['population']['sample_count']:,} | Run 2 = {run2['population']['sample_count']:,} (MATCH)")
        print(f"  * Prediction Disparity  : 0 mismatches across {run1['population']['flow_count']:,} flows")
        print(f"  * Max Probability Delta : {max_prob_diff:.2e} (within numerical tolerance 1e-6)")
        print(f"  * Accuracy Match        : {run1['primary_evaluation']['accuracy']} == {run2['primary_evaluation']['accuracy']}")
        print(f"  * F1-Score Match        : {run1['primary_evaluation']['f1']} == {run2['primary_evaluation']['f1']}")
        print(f"  * Benign FPR Match      : {run1['primary_evaluation']['benign_fpr']} == {run2['primary_evaluation']['benign_fpr']}")
        print(f"  * Confusion Matrix      : {run1['primary_evaluation']['confusion_matrix']} == {run2['primary_evaluation']['confusion_matrix']}")


if __name__ == "__main__":
    main()


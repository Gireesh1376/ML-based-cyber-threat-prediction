from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from urllib.request import urlretrieve

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import (  # noqa: E402
    CATEGORICAL_COLUMNS,
    FEATURE_COLUMNS,
    METRICS_PATH,
    MODELS_DIR,
    NSL_KDD_TEST_URL,
    NSL_KDD_TRAIN_URL,
    RAW_DIR,
)
from app.ml.features import FeatureTransformer, load_nsl_kdd, split_zero_day  # noqa: E402
from app.ml import (  # noqa: E402
    evaluate_binary,
    evaluate_multiclass,
    hybrid_predict,
    model_path,
    save_artifacts,
    train_hybrid,
)
from app.ml.priority import (  # noqa: E402
    ASSET_UNKNOWN_FALLBACK,
    FAMILY_SEVERITY,
    PRIORITY_WEIGHTS,
    RECON_RATIO_CAP,
    annotate_alert,
    compute_priority,
    derive_tier_cutoffs,
    ranking_variants,
    tier_from_score,
)
from app.config import SERVICE_CRITICALITY  # noqa: E402


def download_dataset() -> tuple[Path, Path]:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    train_path = RAW_DIR / "KDDTrain+.txt"
    test_path = RAW_DIR / "KDDTest+.txt"
    if not train_path.exists():
        print("Downloading NSL-KDD train split...")
        urlretrieve(NSL_KDD_TRAIN_URL, train_path)
    if not test_path.exists():
        print("Downloading NSL-KDD test split...")
        urlretrieve(NSL_KDD_TEST_URL, test_path)
    return train_path, test_path


def main() -> None:
    train_path, test_path = download_dataset()
    train_df = load_nsl_kdd(train_path)
    test_df = load_nsl_kdd(test_path)

    known_train, zero_train = split_zero_day(train_df)
    _, zero_test = split_zero_day(test_df)
    unseen = pd.concat([zero_train, zero_test], ignore_index=True)

    transformer = FeatureTransformer().fit(known_train)
    X_all_train = transformer.transform(known_train)
    encoder = LabelEncoder()
    family_labels = known_train["family"].where(known_train["label"] != "normal", "normal")
    y_multi = encoder.fit_transform(family_labels.astype(str))
    y_bin = (known_train["label"] != "normal").astype(int).to_numpy()

    X_tr, X_val, y_tr, y_val, yb_tr, yb_val, idx_tr, idx_val = train_test_split(
        X_all_train,
        y_multi,
        y_bin,
        np.arange(len(known_train)),
        test_size=0.15,
        random_state=42,
        stratify=y_bin,
    )

    tuning_path = MODELS_DIR / "novelty_tuning.json"
    tuning = json.loads(tuning_path.read_text(encoding="utf-8")) if tuning_path.exists() else None
    chosen = (tuning or {}).get("chosen") or {}
    recon_q = float(chosen.get("recon_quantile", 0.95))
    gate = float(chosen.get("novelty_gate", 0.62))
    print(f"Novelty settings: recon_quantile={recon_q}, novelty_gate={gate} "
          f"({'validation-tuned' if chosen else 'legacy defaults, run app.ml.tune_novelty'})")
    artifacts = train_hybrid(X_tr, y_tr, yb_tr, transformer.feature_names,
                             recon_quantile=recon_q, novelty_gate=gate)
    artifacts.transformer = transformer
    artifacts.label_classes = encoder.classes_.tolist()

    val_pred = hybrid_predict(artifacts, X_val)
    known_attack = (np.array(artifacts.label_classes)[y_val] != "normal")
    pred_attack = (val_pred["label"] != "normal")
    attack_score = np.where(
        val_pred["label"] == "normal",
        1.0 - val_pred["confidence"],
        np.clip(val_pred["confidence"] + 0.15 * (val_pred["reconstruction_error"] / max(artifacts.recon_threshold, 1e-8)), 0, 1),
    )
    binary_metrics = evaluate_binary(known_attack.astype(int), pred_attack.astype(int), attack_score)

    val_true_labels = np.array(artifacts.label_classes)[y_val]
    val_pred_labels = np.where(val_pred["label"] == "zero_day", val_pred["known_label"], val_pred["label"])
    multi_metrics = evaluate_multiclass(
        val_true_labels,
        val_pred_labels,
        sorted(set(artifacts.label_classes)),
    )

    X_unseen = transformer.transform(unseen) if len(unseen) else np.empty((0, X_all_train.shape[1]))
    if len(unseen):
        unseen_pred = hybrid_predict(artifacts, X_unseen)
        zero_day_recall = float(unseen_pred["is_zero_day"].mean())
        unseen_detected = float((unseen_pred["label"] != "normal").mean())
        zero_day_examples = unseen.assign(
            predicted=unseen_pred["label"],
            confidence=unseen_pred["confidence"],
            reconstruction_error=unseen_pred["reconstruction_error"],
        )[["label", "family", "predicted", "confidence", "reconstruction_error"]].head(40).to_dict(orient="records")
    else:
        zero_day_recall = 0.0
        unseen_detected = 0.0
        zero_day_examples = []

    X_full_test = transformer.transform(test_df)
    test_pred = hybrid_predict(artifacts, X_full_test)
    test_true_attack = (test_df["label"] != "normal").astype(int).to_numpy()
    test_pred_attack = (test_pred["label"] != "normal").astype(int)
    test_score = np.where(
        test_pred["label"] == "normal",
        1.0 - test_pred["confidence"],
        np.clip(test_pred["confidence"], 0, 1),
    )
    test_binary = evaluate_binary(test_true_attack, test_pred_attack, test_score)

    # ---- Problem 3: composite alert prioritisation -------------------------
    # Tier cutoffs derive from the VALIDATION split only; the official test
    # split is used purely for evaluation below, keeping test numbers honest.
    # Bug-2 fix: calibration uses TRUE labels, never predicted ones.
    val_true = np.array(artifacts.label_classes)[y_val]
    true_attack_val = val_true != "normal"
    val_services = None
    if len(idx_val) and len(known_train):
        val_idx = np.asarray(idx_val)
        val_services = list(known_train["service"].iloc[val_idx])
    val_scores = _validation_priorities(
        val_pred, artifacts.recon_threshold, services=val_services
    )
    cutoffs = derive_tier_cutoffs(val_scores, true_attack_val, attack_share=0.85)

    test_priority, test_components = _priority_scores(
        test_pred,
        artifacts.recon_threshold,
        test_pred["label"],
        test_pred["is_zero_day"].astype(bool),
        services=list(test_df["service"]),
        want_components=True,
    )

    tiers = np.array([
        tier_from_score(
            float(test_priority[i]),
            cutoffs,
            None if str(test_df.iloc[i]["service"]) in SERVICE_CRITICALITY else "review",
        )
        for i in range(len(test_priority))
    ])

    priority_eval = _evaluate_prioritisation(
        scores=test_priority,
        component_scores=test_components,
        confidences=test_pred["confidence"],
        predicted_labels=test_pred["label"],
        tiers=tiers,
        true_attack=test_true_attack.astype(bool),
        true_zero_day=test_df["is_zero_day"].to_numpy(),
    )

    demo_alerts = []
    sample_idx = np.linspace(0, len(test_df) - 1, num=min(80, len(test_df)), dtype=int)
    for i in sample_idx:
        row = test_df.iloc[int(i)]
        service_name = str(row["service"])
        asset_is_known = service_name in SERVICE_CRITICALITY
        tier_floor = None if asset_is_known else "review"
        alert_tier = tier_from_score(
            float(test_priority[i]),
            cutoffs,
            tier_floor,
        )
        demo_alerts.append(
            {
                "id": f"ALT-{10000 + int(i)}",
                "src": f"10.0.{int(i) % 24}.{int(i) % 250}",
                "dst": f"172.16.{int(i) % 12}.{int(i) % 200}",
                "protocol": str(row["protocol_type"]),
                "service": str(row["service"]),
                "true_label": row["label"],
                "predicted": str(test_pred["label"][i]),
                "known_label": str(test_pred["known_label"][i]),
                "confidence": float(test_pred["confidence"][i]),
                "reconstruction_error": float(test_pred["reconstruction_error"][i]),
                "is_zero_day": bool(test_pred["is_zero_day"][i]),
                "severity": _severity(float(test_pred["confidence"][i]), bool(test_pred["is_zero_day"][i]), str(test_pred["label"][i])),
                "priority": round(float(test_priority[i]), 4),
                "tier": alert_tier,
                "priority_components": {k: round(float(test_components[k][i]), 4) for k in test_components},
                "asset_criticality": round(
                    float(SERVICE_CRITICALITY.get(service_name, ASSET_UNKNOWN_FALLBACK)), 4
                    ),
                "asset_criticality_known": asset_is_known,
                # Full raw feature payload so POST /detect/replay can re-score the
                # exact flow instead of guessing from a preset.
                "flow": {
                    col: (str(row[col]) if col in CATEGORICAL_COLUMNS else float(row[col]))
                    for col in FEATURE_COLUMNS
                },
            }
        )

    metrics = {
        "dataset": "NSL-KDD",
        "problem": "Zero-day / unknown attack detection",
        "architecture": "Autoencoder + XGBoost hybrid (Dai et al. 2024 style)",
        "train_rows": int(len(known_train)),
        "validation_rows": int(len(X_val)),
        "test_rows": int(len(test_df)),
        "unseen_zero_day_rows": int(len(unseen)),
        "held_out_labels": sorted(unseen["label"].unique().tolist()) if len(unseen) else [],
        "selected_feature_count": int(len(artifacts.selected_features)),
        "reconstruction_threshold": artifacts.recon_threshold,
        "classes": artifacts.label_classes,
        "validation_binary": binary_metrics,
        "validation_multiclass": {
            "accuracy": multi_metrics["accuracy"],
            "macro_f1": multi_metrics["macro_f1"],
            "weighted_f1": multi_metrics["weighted_f1"],
        },
        "official_test_binary": test_binary,
        "prioritisation": {
            "weights": PRIORITY_WEIGHTS,
            "weight_sum": round(sum(PRIORITY_WEIGHTS.values()), 6),
            "family_severity": FAMILY_SEVERITY,
            "asset_criticality_scale": "SERVICE_CRITICALITY map (65 NSL-KDD services), continuous [0,1], unknown -> review-floor fallback",
            "recon_ratio_cap": 20.0,
            "tier_cutoffs": cutoffs,
            "cutoffs_derived_on": "validation_split_true_labels",
            "cutoff_meaning": {"critical": f"85% of TRUE validation attacks land critical", "review": "95% of TRUE validation benign flows stay below (auto-log)"},
            "test_evaluation": priority_eval,
        },
        "zero_day": {
            "held_out_attack_detection_rate": unseen_detected,
            "flagged_as_novel_rate": zero_day_recall,
            "examples": zero_day_examples,
        },
        "feature_names": [artifacts.feature_names[i] for i in artifacts.selected_features],
        "novelty_settings": {
            "recon_quantile": recon_q,
            "novelty_gate": gate,
            "source": "validation_leave_family_out (models/novelty_tuning.json)" if chosen else "legacy defaults (test-informed)",
        },
    }

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (MODELS_DIR / "demo_alerts.json").write_text(json.dumps(demo_alerts, indent=2), encoding="utf-8")
    save_artifacts(model_path(), artifacts, {"encoder_classes": artifacts.label_classes})
    print(json.dumps({k: metrics[k] for k in ["validation_binary", "official_test_binary", "zero_day"] if k != "zero_day"}, indent=2))
    print("Zero-day held-out detection rate:", unseen_detected)
    print("Flagged as novel:", zero_day_recall)
    print("Saved", model_path())


def _priority_scores(
    pred: dict[str, np.ndarray],
    recon_threshold: float,
    labels,
    zero_day,
    services=None,
    want_components: bool = False,
):
    n = len(labels)
    conf = np.asarray(pred["confidence"], dtype=float)
    recon = np.asarray(pred["reconstruction_error"], dtype=float)
    zd = np.asarray(zero_day, dtype=bool)[:n]
    labels = np.asarray(labels)[:n]
    p_attack = np.where(labels == "normal", 1.0 - conf, conf)
    recon_term = np.minimum(recon / max(recon_threshold, 1e-9), RECON_RATIO_CAP) / RECON_RATIO_CAP
    fam = np.array([FAMILY_SEVERITY.get(str(x), 0.5) for x in labels])
    if services is not None:
        services = np.asarray(services)[:n]
        asset = np.array([SERVICE_CRITICALITY.get(str(x), ASSET_UNKNOWN_FALLBACK) for x in services])
    else:
        asset = np.full(n, ASSET_UNKNOWN_FALLBACK)
    w = PRIORITY_WEIGHTS
    components = {
        "confidence": w["confidence"] * p_attack,
        "reconstruction": w["reconstruction"] * recon_term,
        "family": w["family"] * fam,
        "asset": w["asset"] * asset,
        "zero_day_bonus": w["zero_day_bonus"] * zd.astype(float),
    }
    scores = np.minimum(sum(components.values()), 1.0)
    return (scores, components) if want_components else scores


def _validation_priorities(val_pred: dict[str, np.ndarray], recon_threshold: float, services=None) -> np.ndarray:
    """Priority scores on the validation split for cutoff calibration."""
    return _priority_scores(
        val_pred,
        recon_threshold,
        val_pred["label"],
        val_pred["is_zero_day"].astype(bool),
        services=services,
    )


def _evaluate_prioritisation(
    scores: np.ndarray,
    component_scores: dict[str, np.ndarray],
    confidences: np.ndarray,
    predicted_labels: np.ndarray,
    tiers: np.ndarray,
    true_attack: np.ndarray,
    true_zero_day: np.ndarray,
) -> dict[str, Any]:
    n = len(scores)
    critical = tiers == "critical"
    human_review = (tiers == "critical") | (tiers == "review")
    composite = {
        "attacks_in_critical": float((critical & true_attack).sum() / max(true_attack.sum(), 1)),
        "attacks_in_human_tiers": float((human_review & true_attack).sum() / max(true_attack.sum(), 1)),
        "zero_days_in_critical": float((critical & true_zero_day).sum() / max(true_zero_day.sum(), 1)),
        "zero_days_in_human_tiers": float((human_review & true_zero_day).sum() / max(true_zero_day.sum(), 1)),
        "human_review_workload": float(human_review.mean()),
        "auto_logged_share": float((tiers == "auto_log").mean()),
        # Safety of auto-logging: attacks that never reach a human tier.
        "attacks_auto_logged": int(((tiers == "auto_log") & true_attack).sum()),
        "attacks_outside_human_tiers": float(((~human_review) & true_attack).sum() / max(true_attack.sum(), 1)),
        "zero_days_outside_human_tiers": float(((~human_review) & true_zero_day).sum() / max(true_zero_day.sum(), 1)),
        "auto_logged_true_attack_count": int(((tiers == "auto_log") & true_attack).sum()),
        "tier_counts": {t: int((tiers == t).sum()) for t in ("critical", "review", "auto_log")},
    }

    # ---- Fixed queue budgets ----
    order = np.argsort(-scores, kind="stable")
    conf_order = np.argsort(-np.asarray(confidences, dtype=float), kind="stable")
    confidence_risk = np.where(
        np.asarray(predicted_labels) == "normal",
        1.0 - np.asarray(confidences, dtype=float),
        np.asarray(confidences, dtype=float),
    )
    class_aware_conf_order = np.argsort(-confidence_risk, kind="stable")
    budgets = [50, 100, 200, 500, 1000, 2000]
    budgets = [k for k in budgets if k <= n]
    fixed_queue = {}
    for k in budgets:
        top = order[:k]
        conf_top = conf_order[:k]
        class_aware_conf_top = class_aware_conf_order[:k]
        fixed_queue[f"@{k}"] = {
            "composite": _queue_metrics(top, true_attack, true_zero_day, n),
            "confidence_only": _queue_metrics(conf_top, true_attack, true_zero_day, n),
            "class_aware_confidence_only": _queue_metrics(class_aware_conf_top, true_attack, true_zero_day, n),
        }

    # ---- Ablation ladder (like-for-like: each variant renormalised) ----
    variants = ranking_variants(component_scores)
    ablation = {}
    k = int(human_review.sum())  # queue budget matched to the deployed tiering
    for name, vscores in variants.items():
        top = np.argsort(-vscores, kind="stable")[:k]
        ablation[name] = _queue_metrics(top, true_attack, true_zero_day, n)
    # Explicit with/without zero-day bonus (review 4.3 double-counting check)
    full = variants["full"]
    w = PRIORITY_WEIGHTS
    without_bonus = full - w["zero_day_bonus"] * component_scores["zero_day_bonus"]
    w_remaining = sum(w.values()) - w["zero_day_bonus"]
    without_bonus = without_bonus / w_remaining
    top_no_bonus = np.argsort(-without_bonus, kind="stable")[:k]
    ablation["full_without_zero_day_bonus"] = _queue_metrics(top_no_bonus, true_attack, true_zero_day, n)

    return {
        **composite,
        "queue_budget": int(k),
        "fixed_queue": fixed_queue,
        "ablation_at_review_queue_size": ablation,
        "confidence_baseline_matched": ablation.get("conf_only"),
        "composite_matched": ablation["full"],
    }


def _queue_metrics(top_idx: np.ndarray, true_attack: np.ndarray, true_zero_day: np.ndarray, n: int) -> dict[str, Any]:
    k = len(top_idx)
    hits = int(true_attack[top_idx].sum())
    zd_hits = int(true_zero_day[top_idx].sum())
    return {
        "k": int(k),
        "precision_at_k": hits / k if k else 0.0,
        "recall_at_k": hits / max(int(true_attack.sum()), 1),
        "zero_day_capture_at_k": zd_hits / max(int(true_zero_day.sum()), 1),
        "false_negatives_outside_queue": int(true_attack.sum()) - hits,
    }


def _severity(confidence: float, is_zero_day: bool, label: str) -> str:
    if label == "normal":
        return "info"
    if is_zero_day:
        return "critical"
    if confidence >= 0.9:
        return "high"
    if confidence >= 0.7:
        return "medium"
    return "low"


if __name__ == "__main__":
    main()

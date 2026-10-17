from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np

from app.config import ALERTS_PATH, FEATURE_COLUMNS, METRICS_PATH, SERVICE_CRITICALITY
from app.ml import hybrid_predict, load_artifacts, model_path
from app.ml.features import sample_to_dataframe
from app.ml.priority import compute_priority, tier_from_score


class DetectorNotReady(RuntimeError):
    pass


@lru_cache(maxsize=1)
def get_tier_cutoffs() -> dict[str, float]:
    """Tier cutoffs from metrics.json, falling back to validation-derived cutoffs."""
    fallback = {"critical": 0.5901, "review": 0.1364}
    if not METRICS_PATH.exists():
        return fallback
    data = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    cutoffs = (data.get("prioritisation") or {}).get("tier_cutoffs") or fallback
    return {k: float(cutoffs[k]) for k in ("critical", "review") if k in cutoffs} or fallback


DEFAULT_CUTOFFS: dict[str, float] = {"critical": 0.5901, "review": 0.1364}


@lru_cache(maxsize=1)
def get_model():
    path = model_path()
    if not path.exists():
        raise DetectorNotReady("Model has not been trained yet. Run: python -m app.ml.train")
    artifacts, extra = load_artifacts(path)
    return artifacts, extra


def load_metrics() -> dict[str, Any]:
    if not METRICS_PATH.exists():
        return {}
    return json.loads(METRICS_PATH.read_text(encoding="utf-8"))


def load_demo_alerts() -> list[dict[str, Any]]:
    if not ALERTS_PATH.exists():
        return []
    return json.loads(Path(ALERTS_PATH).read_text(encoding="utf-8"))


def predict_payload(payload: dict[str, Any]) -> dict[str, Any]:
    artifacts, _ = get_model()
    df = sample_to_dataframe(payload)
    X = artifacts.transformer.transform(df)
    result = hybrid_predict(artifacts, X)
    shap_values = _top_contributors(artifacts, X)
    anomaly_features = _anomaly_contributors(artifacts, X)
    label = str(result["label"][0])
    known = str(result["known_label"][0])
    confidence = float(result["confidence"][0])
    recon = float(result["reconstruction_error"][0])
    is_zero_day = bool(result["is_zero_day"][0])
    # Problem 3: composite priority + tier for every scored flow.
    # Asset criticality comes from the documented SERVICE_CRITICALITY map on the
    # target service; callers may override it with an explicit payload field.
    service = str(payload.get("service", ""))
    override = payload.get("asset_criticality")
    if isinstance(override, (int, float)) and 0.0 <= float(override) <= 1.0:
        asset_criticality, asset_known = float(override), True
    else:
        asset_criticality = SERVICE_CRITICALITY.get(service)
        asset_known = asset_criticality is not None
        if not asset_known:
            asset_criticality = None  # documented fallback + Review floor inside
    priority, components, dq_flags = compute_priority(
        confidence=confidence,
        reconstruction_error=recon,
        recon_threshold=artifacts.recon_threshold,
        predicted=label,
        is_zero_day=is_zero_day,
        asset_criticality=asset_criticality,
    )
    cutoffs = get_tier_cutoffs()
    tier_floor = "review" if "asset_criticality_unknown" in dq_flags else None
    tier = tier_from_score(priority, cutoffs, tier_floor)
    return {
        "predicted": label,
        "known_class": known,
        "is_zero_day": is_zero_day,
        "confidence": confidence,
        "reconstruction_error": recon,
        "threshold": artifacts.recon_threshold,
        "anomaly_ratio": recon / artifacts.recon_threshold if artifacts.recon_threshold else recon,
        "priority": round(priority, 4),
        "priority_components": {k: round(v, 4) for k, v in components.items()},
        "tier": tier,
        "tier_floor_applied": tier_floor,
        "dq_flags": dq_flags,
        "asset_criticality": round(float(asset_criticality if asset_criticality is not None else 0.5), 4),
        "asset_criticality_known": asset_known,
        "tier_reason": _tier_reason_text(priority, tier, cutoffs, tier_floor),
        "severity": _severity(confidence, is_zero_day, label),
        "rationale": _rationale(label, known, confidence, recon, artifacts.recon_threshold, is_zero_day),
        "top_features": shap_values,
        "anomaly_features": anomaly_features,
        "explanation_scope": (
            "top_features (SHAP) explain the XGBoost classifier's reading only. anomaly_features show "
            "which inputs the normal-traffic autoencoder reconstructed worst, i.e. why the flow looks "
            "anomalous. For zero_day alerts, anomaly_features is the relevant justification."
        ),
        "explanation_kind": "shap" if shap_values and _is_shap(shap_values) else "feature_importance_fallback",
        "input": {k: payload.get(k) for k in FEATURE_COLUMNS if k in payload} or payload,
    }


def _anomaly_contributors(artifacts, X: np.ndarray, top: int = 8) -> list[dict[str, Any]]:
    """Per-feature share of the autoencoder reconstruction error for ONE flow.

    reconstruction_error() = mean over features of (x - x_hat)^2, so each feature's
    share of the total is exact and sums to 1. High share = the model could not
    reproduce that feature from normal-traffic structure.
    """
    Xs = X[:, artifacts.selected_features]
    names = [artifacts.feature_names[i] for i in artifacts.selected_features]
    recon = artifacts.autoencoder.predict(Xs)
    sq = (Xs[0] - recon[0]) ** 2
    total = float(sq.sum())
    if total <= 0.0:
        return []
    order = np.argsort(sq)[::-1][:top]
    return [
        {
            "feature": names[i],
            "error_share": float(sq[i] / total),
            "value": float(Xs[0, i]),
            "reconstructed": float(recon[0, i]),
        }
        for i in order
    ]


def _is_shap(rows: list[dict[str, Any]]) -> bool:
    # The SHAP path returns signed impacts with mixed signs; the
    # feature-importance fallback returns non-negative importances only.
    return any(float(r.get("impact", 0.0)) < -1e-12 for r in rows)


def _tier_reason_text(score: float, tier: str, cutoffs: dict[str, float], tier_floor: str | None) -> str:
    if tier_floor == "review" and tier == "review" and score < cutoffs["review"]:
        return (
            f"Score {score:.3f} alone would auto-log, but the target service has no documented "
            f"asset criticality - floored to Review rather than silently assumed unimportant."
        )
    if tier == "critical":
        return f"Score {score:.3f} >= critical cutoff {cutoffs['critical']:.3f} -> Critical (immediate attention)."
    if tier == "review":
        return f"Score {score:.3f} >= review cutoff {cutoffs['review']:.3f} -> Review (analyst investigation)."
    return f"Score {score:.3f} < review cutoff {cutoffs['review']:.3f} -> Auto-logged (routine)."


def _top_contributors(artifacts, X: np.ndarray) -> list[dict[str, Any]]:
    Xs = X[:, artifacts.selected_features]
    names = [artifacts.feature_names[i] for i in artifacts.selected_features]
    try:
        import shap

        explainer = shap.TreeExplainer(artifacts.xgboost)
        values = explainer.shap_values(Xs)
        if isinstance(values, list):
            pred = int(np.argmax(artifacts.xgboost.predict_proba(Xs)[0]))
            row = np.array(values[pred][0])
        else:
            arr = np.array(values)
            if arr.ndim == 3:
                pred = int(np.argmax(artifacts.xgboost.predict_proba(Xs)[0]))
                row = arr[0, :, pred] if arr.shape[1] == len(names) else arr[pred, 0]
            else:
                row = arr[0]
        order = np.argsort(np.abs(row))[::-1][:8]
        return [
            {"feature": names[i], "impact": float(row[i]), "value": float(Xs[0, i])}
            for i in order
        ]
    except Exception:
        importances = getattr(artifacts.xgboost, "feature_importances_", np.ones(len(names)))
        order = np.argsort(importances)[::-1][:8]
        return [
            {"feature": names[i], "impact": float(importances[i]), "value": float(Xs[0, i])}
            for i in order
        ]


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


def _rationale(label, known, confidence, recon, threshold, is_zero_day) -> str:
    if is_zero_day:
        return (
            f"Traffic does not match trained attack families (XGBoost leaned {known} at "
            f"{confidence:.1%} confidence) and reconstruction error {recon:.4f} exceeds the "
            f"normal baseline threshold {threshold:.4f}. Treated as a novel / zero-day threat."
        )
    if label == "normal":
        return (
            f"Flow reconstructed within the benign autoencoder baseline "
            f"(error {recon:.4f} vs threshold {threshold:.4f}) and classified as normal "
            f"with {confidence:.1%} confidence."
        )
    return (
        f"Classified as known attack '{label}' with {confidence:.1%} confidence. "
        f"Autoencoder reconstruction error is {recon:.4f} (threshold {threshold:.4f})."
    )

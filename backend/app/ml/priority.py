from __future__ import annotations

import math
from typing import Any

import numpy as np

from app.config import ASSET_UNKNOWN_FALLBACK

# Weights sum to exactly 1.0 (Bug-1 fix). Magnitudes are a documented design
# choice validated on the validation split via the ablation in train.py; see
# metrics.json -> prioritisation.ablation for the measured deltas.
PRIORITY_WEIGHTS = {
    "confidence": 0.35,
    "reconstruction": 0.25,
    "family": 0.15,
    "asset": 0.15,
    "zero_day_bonus": 0.10,
}

assert abs(sum(PRIORITY_WEIGHTS.values()) - 1.0) < 1e-9, "weights must normalise to 1.0"

# Reconstruction-error ratio saturates at this multiple of the threshold, so a
# single wild flow cannot swamp the other signals (documented normalisation).
RECON_RATIO_CAP = 20.0

# Asset criticality considered missing. Flows with an unknown asset keep this
# neutral value but are flagged and floored to Review by the caller.

# Design-choice severity of each predicted family, tuned on validation only.
FAMILY_SEVERITY = {
    "dos": 1.00,
    "zero_day": 1.00,
    "u2r": 0.95,
    "r2l": 0.80,
    "probe": 0.70,
    "normal": 0.00,
}

TIERS = ("critical", "review", "auto_log")


def p_attack(confidence: float, predicted: str) -> float:
    """Class-aware confidence: convert top-class confidence into attack risk."""
    value = float(confidence)
    if not _finite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"confidence must be finite in [0, 1], got {confidence!r}")
    if predicted in ("normal",):
        return 1.0 - value
    return value


def reconstruct_term(reconstruction_error: float, recon_threshold: float) -> float:
    """Normalised anomaly in [0, 1] with documented saturation."""
    ratio = reconstruction_error / max(recon_threshold, 1e-9)
    return min(max(ratio, 0.0), RECON_RATIO_CAP) / RECON_RATIO_CAP


def _finite(value: Any) -> bool:
    try:
        return math.isfinite(float(value))
    except (TypeError, ValueError):
        return False


def compute_priority(
    confidence: float,
    reconstruction_error: float,
    recon_threshold: float,
    predicted: str,
    is_zero_day: bool,
    asset_criticality: float | None = None,
) -> tuple[float, dict[str, float], list[str]]:
    """Return (score in [0,1], component breakdown, data-quality flags).

    Raises ValueError for non-finite required signals (Bug-5: model-internal
    values must never be silently coerced); callers validate user-facing
    inputs before reaching here.
    """
    conf = float(confidence)
    recon = float(reconstruction_error)
    if not math.isfinite(conf) or not 0.0 <= conf <= 1.0:
        raise ValueError(f"confidence must be finite in [0, 1], got {confidence!r}")
    if not math.isfinite(recon) or recon < 0.0:
        raise ValueError(f"reconstruction_error must be finite and >= 0, got {reconstruction_error!r}")

    flags: list[str] = []
    asset = asset_criticality if asset_criticality is not None else ASSET_UNKNOWN_FALLBACK
    if float(asset) < 0.0 or float(asset) > 1.0:
        raise ValueError(f"asset_criticality must be in [0, 1], got {asset_criticality!r}")
    asset = float(asset)
    if asset_criticality is None:
        flags.append("asset_criticality_unknown")

    attack_risk = p_attack(conf, predicted)
    components = {
        "confidence": PRIORITY_WEIGHTS["confidence"] * attack_risk,
        "reconstruction": PRIORITY_WEIGHTS["reconstruction"] * reconstruct_term(recon, recon_threshold),
        "family": PRIORITY_WEIGHTS["family"] * FAMILY_SEVERITY.get(predicted, 0.5),
        "asset": PRIORITY_WEIGHTS["asset"] * asset,
        "zero_day_bonus": PRIORITY_WEIGHTS["zero_day_bonus"] * (1.0 if is_zero_day else 0.0),
    }
    score = sum(components.values())
    return min(score, 1.0), components, flags


def tier_from_score(score: float, cutoffs: dict[str, float], tier_floor: str | None = None) -> str:
    """Assign exactly one tier (Bug-3: >= boundaries, deterministic order)."""
    tier = (
        "critical"
        if score >= cutoffs["critical"]
        else "review"
        if score >= cutoffs["review"]
        else "auto_log"
    )
    if tier_floor == "review" and tier == "auto_log":
        return "review"
    return tier


def derive_tier_cutoffs(
    scores: Any,
    true_attack: Any,
    attack_share: float = 0.85,
    benign_escalation_share: float = 0.05,
) -> dict[str, float]:
    """Calibrate cutoffs on the validation split, using TRUE labels (Bug-2 fix).

    Critical: quantile of true-attack validation scores guaranteeing
    ``attack_share`` of true attacks land in Critical.
    Review: quantile of true-BENIGN validation scores so at most
    ``benign_escalation_share`` of confidently-benign traffic escalates to
    human review. Test labels are never touched here.
    """
    scores = np.asarray(scores, dtype=float)
    true_attack = np.asarray(true_attack, dtype=bool)
    if not true_attack.any():
        return {"critical": 0.5901, "review": 0.1364}
    benign_scores = scores[~true_attack]
    critical_cut = float(np.quantile(scores[true_attack], 1.0 - attack_share))
    review_cut = (
        float(np.quantile(benign_scores, 1.0 - benign_escalation_share))
        if benign_scores.size
        else 0.0
    )
    if review_cut > critical_cut:  # keep tiers monotonically separated
        review_cut = critical_cut
    return {"critical": round(critical_cut, 4), "review": round(review_cut, 4)}


def annotate_alert(
    alert: dict[str, Any],
    recon_threshold: float,
    cutoffs: dict[str, float],
    asset_criticality: float | None = None,
) -> dict[str, Any]:
    """Add priority/components/tier (+ reasons, flags) to one alert dict."""
    score, components, flags = compute_priority(
        confidence=alert["confidence"],
        reconstruction_error=alert["reconstruction_error"],
        recon_threshold=recon_threshold,
        predicted=alert["predicted"],
        is_zero_day=alert.get("is_zero_day", False),
        asset_criticality=alert.get("asset_criticality", asset_criticality),
    )
    out = dict(alert)
    tier_floor = "review" if "asset_criticality_unknown" in flags else None
    tier = tier_from_score(score, cutoffs, tier_floor)
    out["priority"] = round(score, 4)
    out["priority_components"] = {k: round(v, 4) for k, v in components.items()}
    out["tier"] = tier
    out["tier_floor_applied"] = tier_floor is not None
    out["dq_flags"] = flags
    out["tier_reason"] = _tier_reason(score, tier, cutoffs, tier_floor)
    return out


def _tier_reason(score: float, tier: str, cutoffs: dict[str, float], tier_floor: str | None) -> str:
    if tier_floor == "review" and tier == "review" and score < cutoffs["review"]:
        return (
            f"Score {score:.3f} alone would auto-log, but the target asset criticality is "
            f"unknown - floored to Review rather than silently assumed unimportant."
        )
    if tier == "critical":
        return f"Score {score:.3f} >= critical cutoff {cutoffs['critical']:.3f} -> Critical (immediate attention)."
    if tier == "review":
        return f"Score {score:.3f} >= review cutoff {cutoffs['review']:.3f} -> Review (analyst investigation)."
    return f"Score {score:.3f} < review cutoff {cutoffs['review']:.3f} -> Auto-logged (routine)."


def ranking_variants(scores: dict[str, np.ndarray]) -> dict[str, np.ndarray]:
    """Ablation ladder (Phase 6): partial score combinations, renormalised.

    Each variant keeps the final weights of its included factors, renormalised
    to sum 1.0, so comparisons are like-for-like. Variant keys:
      conf_only, conf_recon, conf_recon_family, conf_recon_family_asset, full
    """
    w = PRIORITY_WEIGHTS
    plans = {
        "conf_only": ("confidence",),
        "conf_recon": ("confidence", "reconstruction"),
        "conf_recon_family": ("confidence", "reconstruction", "family"),
        "conf_recon_family_asset": ("confidence", "reconstruction", "family", "asset"),
        "full": tuple(w),
    }
    out = {}
    for name, factors in plans.items():
        total = sum(w[f] for f in factors)
        out[name] = sum(w[f] / total * scores[f] for f in factors)
    return out

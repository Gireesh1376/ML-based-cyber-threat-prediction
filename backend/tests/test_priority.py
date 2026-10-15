"""Problem 3 unit tests: priority score range, direction, tiers, fallbacks.

Run: cd backend && ./.venv/Scripts/python -m pytest tests/test_priority.py -q
These cover the review-report Bug-1..Bug-5 fix acceptance criteria:
score range/direction, cutoff boundaries (below / at / above), unknown-asset
fallback behaviour, batch-vs-scalar parity, and tie determinism.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ml.priority import (  # noqa: E402
    ASSET_UNKNOWN_FALLBACK,
    PRIORITY_WEIGHTS,
    annotate_alert,
    compute_priority,
    derive_tier_cutoffs,
    ranking_variants,
    tier_from_score,
)

CUT = {"critical": 0.75, "review": 0.45}
SERVICE_CRITICALITY_TEST = {"ssh": 0.95, "http": 0.55, "discard": 0.35}


def score(**kwargs) -> float:
    base = dict(
        confidence=0.9,
        reconstruction_error=1.0,
        recon_threshold=1.0,
        predicted="dos",
        is_zero_day=False,
    )
    base.update(kwargs)
    value, _, _ = compute_priority(**base)
    return value


# ---- Bug-1: weights normalise, score stays in [0, 1] -----------------------

def test_weights_sum_to_one():
    assert abs(sum(PRIORITY_WEIGHTS.values()) - 1.0) < 1e-9


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(confidence=0.0, reconstruction_error=0.0, predicted="normal", is_zero_day=False),
        dict(confidence=1.0, reconstruction_error=1e6, predicted="dos", is_zero_day=True),
        dict(confidence=0.5, reconstruction_error=3.7, predicted="zero_day", is_zero_day=True),
    ],
)
def test_score_in_unit_range(kwargs):
    assert 0.0 <= score(**kwargs) <= 1.0


def test_extreme_inputs_no_saturation_ties():
    # A single wild flow must not swamp the other signals (recon capped):
    # any recon error beyond RECON_RATIO_CAP × threshold scores identically.
    s1 = score(confidence=1.0, reconstruction_error=1e6, predicted="dos")
    s2 = score(confidence=1.0, reconstruction_error=1e12, predicted="dos")
    assert s1 == s2
    # ... but it still must not rank BELOW a moderate flow.
    moderate = score(confidence=1.0, reconstruction_error=1.0, predicted="dos")
    assert s1 >= moderate


# ---- Direction tests (Phase 2 acceptance) -------------------------------

def test_direction_confidence_attack():
    assert score(confidence=0.95, predicted="dos") > score(confidence=0.55, predicted="dos")


def test_direction_confidence_benign_is_class_aware():
    # High confidence in a BENIGN prediction is LOW risk (phase 8 note).
    assert score(confidence=0.99, predicted="normal") < score(confidence=0.60, predicted="normal")


def test_direction_reconstruction():
    assert score(reconstruction_error=5.0) > score(reconstruction_error=0.1)


def test_direction_family_severity():
    assert score(predicted="dos") > score(predicted="probe")


def test_direction_zero_day_bonus():
    assert score(is_zero_day=True) > score(is_zero_day=False)


def test_direction_asset_criticality():
    hi = score(predicted="dos", asset_criticality=0.95)
    lo = score(predicted="dos", asset_criticality=0.35)
    assert hi > lo


# ---- Bug-5: missing / invalid values -------------------------------------

def test_unknown_asset_uses_documented_fallback_and_flags():
    value, comp, flags = compute_priority(
        confidence=0.9, reconstruction_error=1.0, recon_threshold=1.0,
        predicted="dos", is_zero_day=False, asset_criticality=None,
    )
    assert comp["asset"] == pytest.approx(PRIORITY_WEIGHTS["asset"] * ASSET_UNKNOWN_FALLBACK)
    assert "asset_criticality_unknown" in flags


def test_missing_confidence_raises_not_silent_low_risk():
    with pytest.raises(ValueError):
        compute_priority(
            confidence=float("nan"), reconstruction_error=1.0, recon_threshold=1.0,
            predicted="dos", is_zero_day=False,
        )


def test_confidence_out_of_range_raises():
    with pytest.raises(ValueError):
        compute_priority(
            confidence=1.4, reconstruction_error=1.0, recon_threshold=1.0,
            predicted="dos", is_zero_day=False,
        )


def test_negative_reconstruction_raises():
    with pytest.raises(ValueError):
        compute_priority(
            confidence=0.9, reconstruction_error=-1.0, recon_threshold=1.0,
            predicted="dos", is_zero_day=False,
        )


def test_unknown_family_not_lowest_but_flagged_via_get():
    # Unknown family gets neutral 0.5 severity, below dos / above normal.
    unknown = score(predicted="some_new_family")
    assert score(predicted="normal") < unknown < score(predicted="dos")


# ---- Bug-3: tier boundaries: below / at / above ---------------------------

def test_tier_boundary_exact_and_around():
    for boundary in (CUT["critical"], CUT["review"]):
        above = tier_from_score(boundary + 1e-6, CUT)
        exactly = tier_from_score(boundary, CUT)
        below = tier_from_score(boundary - 1e-6, CUT)
        assert above == exactly
        if boundary == CUT["critical"]:
            assert exactly == "critical"
            assert below != "critical"
        else:
            assert exactly == "review"
            assert below != "review"


def test_every_event_gets_exactly_one_tier():
    for s in (0.0, 0.2, CUT["review"], 0.6, CUT["critical"], 1.0):
        assert tier_from_score(s, CUT) in ("critical", "review", "auto_log")


def test_review_floor_promotes_auto_log_for_unknown_asset():
    low = score(confidence=0.1, reconstruction_error=0.0, predicted="normal")
    assert tier_from_score(low, CUT) == "auto_log"
    assert tier_from_score(low, CUT, tier_floor="review") == "review"


def test_annotate_applies_review_floor_for_unknown_asset():
    alert = {"confidence": 0.10, "reconstruction_error": 0.0,
             "predicted": "normal", "is_zero_day": False}
    out = annotate_alert(alert, recon_threshold=1.0, cutoffs=CUT)
    assert out["tier"] == "review"
    assert out["tier_floor_applied"] is True
    assert "asset_criticality_unknown" in out["dq_flags"]
    assert "unknown" in out["tier_reason"]


# ---- Ties + calibration ---------------------------------------------------

def test_equal_inputs_give_equal_scores_deterministic():
    s1 = score()
    s2 = score()
    assert s1 == s2


def test_derive_cutoffs_uses_true_labels_and_orders_tiers():
    rng = np.random.default_rng(7)
    scores = rng.random(500)
    true_attack = rng.random(500) > 0.7
    cuts = derive_tier_cutoffs(scores, true_attack, attack_share=0.85)
    assert cuts["critical"] >= cuts["review"]
    # >= attack_share of true attacks reach critical
    captured = float((scores[true_attack] >= cuts["critical"]).mean())
    assert captured >= 0.85 - 0.01


def test_ranking_variants_renormalise():
    comp = {
        "confidence": np.array([0.3]),
        "reconstruction": np.array([0.2]),
        "family": np.array([0.1]),
        "asset": np.array([0.1]),
        "zero_day_bonus": np.array([0.1]),
    }
    variants = ranking_variants(comp)
    assert variants["conf_only"][0] > 0
    assert 0 <= variants["full"][0] <= 1.0


def test_compute_priority_matches_batch_reference():
    # Scalar annotate == batch _priority_scores for identical inputs (Bug-7).
    from app.ml.train import _priority_scores  # noqa: PLC0415

    pred = {"confidence": np.array([0.9, 0.3]), "reconstruction_error": np.array([1.0, 0.2])}
    labels = np.array(["dos", "normal"])
    zd = np.array([False, False])
    services = np.array(["ssh", "discard"])
    batch, comps = _priority_scores(pred, 1.0, labels, zd, services=services, want_components=True)
    scalar_a, comp_a, _ = compute_priority(
        confidence=0.9, reconstruction_error=1.0, recon_threshold=1.0,
        predicted="dos", is_zero_day=False, asset_criticality=SERVICE_CRITICALITY_TEST["ssh"],
    )
    scalar_b, comp_b, _ = compute_priority(
        confidence=0.3, reconstruction_error=0.2, recon_threshold=1.0,
        predicted="normal", is_zero_day=False, asset_criticality=SERVICE_CRITICALITY_TEST["discard"],
    )
    assert batch[0] == pytest.approx(scalar_a, abs=1e-9)
    assert batch[1] == pytest.approx(scalar_b, abs=1e-9)
    assert comps["confidence"][1] == pytest.approx(
        PRIORITY_WEIGHTS["confidence"] * (1.0 - 0.3), abs=1e-9
    )

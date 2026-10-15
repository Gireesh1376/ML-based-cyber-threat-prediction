"""
Integration tests for POST /api/detect output consistency (cross-check A6).

These check that the detect endpoint's returned tier / priority / component
breakdown / explanation fields are internally consistent with the actual
implementation, rather than trusting that the dashboard renders them correctly.

Reproducible: uses FastAPI's in-process TestClient (Starlette test client) so
no running server or open port is required. Just:

    cd backend && python -m pytest tests/test_detect_integration.py -q

The TestClient mounts the FastAPI app directly in-process; /api/detect,
/api/alerts, and /api/detect/replay/{id} all go through the real router
logic with the trained artifacts loaded from models/.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient

# In-process test client — no network, no port, no stale-PID dependency.
# The app is imported once per process; TestClient uses it directly.
from app.main import app as _app

_CLIENT = TestClient(_app)

BENIGN_WEB = {
    "duration": 2, "protocol_type": "tcp", "service": "http", "flag": "SF",
    "src_bytes": 280, "dst_bytes": 4200, "logged_in": 1, "count": 4,
    "srv_count": 4, "same_srv_rate": 1, "dst_host_same_srv_rate": 1,
    "dst_host_count": 40, "dst_host_srv_count": 38,
}
DOS_FLOW = {
    "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "S0",
    "src_bytes": 0, "dst_bytes": 0, "logged_in": 0, "count": 180,
    "srv_count": 18, "serror_rate": 1, "srv_serror_rate": 1,
    "same_srv_rate": 0.1, "diff_srv_rate": 0.06,
    "dst_host_serror_rate": 1, "dst_host_srv_serror_rate": 1,
    "dst_host_count": 255, "dst_host_same_srv_rate": 0.05,
}
UNKNOWN_SERVICE_FLOW = {
    "duration": 2, "protocol_type": "tcp", "service": "totally_unknown_svc", "flag": "SF",
    "src_bytes": 100, "dst_bytes": 100, "logged_in": 0, "count": 1,
    "srv_count": 1, "same_srv_rate": 1, "dst_host_same_srv_rate": 1,
    "dst_host_count": 1, "dst_host_srv_count": 1,
}


def _post(payload: dict) -> dict:
    """POST /api/detect with the given flow payload, return decoded JSON."""
    resp = _CLIENT.post("/api/detect", json=payload)
    assert resp.status_code == 200, f"/api/detect returned {resp.status_code}: {resp.text}"
    return resp.json()

def _get(path: str) -> dict:
    """GET an /api/* path, return decoded JSON."""
    resp = _CLIENT.get(path)
    assert resp.status_code == 200, f"GET {path} returned {resp.status_code}: {resp.text}"
    return resp.json()


def _component_sum(det: dict) -> float:
    comp = det.get("priority_components") or {}
    return float(sum(comp.values()))


def _round4(x: float) -> float:
    return round(x, 4)


class TestDetectEndpointConsistency:
    """A6: the endpoint's tier / priority / components / explanation agree."""

    def test_endpoint_is_up(self):
        det = _post(BENIGN_WEB)
        assert det["predicted"] in ("normal", "dos", "probe", "r2l", "u2r", "zero_day")

    def test_priority_components_sum_to_priority(self):
        for name, payload in [("benign", BENIGN_WEB), ("dos", DOS_FLOW)]:
            det = _post(payload)
            comp_sum = _component_sum(det)
            assert comp_sum == pytest.approx(det["priority"], abs=1e-3), (
                f"{name}: component sum {comp_sum} != priority {det['priority']}"
            )

    def test_tier_matches_score_vs_cutoffs(self):
        from app.ml.priority import tier_from_score
        from app.ml.detector import get_tier_cutoffs

        cutoffs = get_tier_cutoffs()
        for name, payload in [("benign", BENIGN_WEB), ("dos", DOS_FLOW), ("unknown_svc", UNKNOWN_SERVICE_FLOW)]:
            det = _post(payload)
            # tier_from_score with no floor gives the raw tier from the score.
            raw_tier = tier_from_score(det["priority"], cutoffs)
            floor = det.get("tier_floor_applied")  # str or None/False
            if floor:
                # The unknown-service Review floor was applied. The final tier is
                # the max of the raw tier and the floor: a flow whose score already
                # places it in Critical keeps Critical even though the floor fired
                # (the floor is a lower bound, not an override). A flow whose raw
                # tier is auto_log gets promoted to Review.
                expected_tier = "review" if raw_tier == "auto_log" else raw_tier
                assert det["tier"] == expected_tier, (
                    f"{name}: tier {det['tier']!r} != expected (raw={raw_tier!r}, floor={floor!r}) -> {expected_tier!r}"
                )
                assert det["tier"] != "auto_log", (
                    f"{name}: unknown service must not be auto-logged; got {det['tier']!r}"
                )
            else:
                assert det["tier"] == raw_tier, (
                    f"{name}: tier {det['tier']!r} != tier_from_score({det['priority']}, cutoffs)={raw_tier!r}"
                )

    def test_tier_reason_mentions_cutoff_for_critical_review(self):
        dos = _post(DOS_FLOW)
        if dos["tier"] in ("critical", "review"):
            assert "cutoff" in dos["tier_reason"].lower(), dos["tier_reason"]

    def test_tier_reason_present_and_nonempty(self):
        for name, payload in [("benign", BENIGN_WEB), ("dos", DOS_FLOW)]:
            det = _post(payload)
            assert isinstance(det.get("tier_reason"), str) and det["tier_reason"]

    def test_explanation_kind_is_mapped(self):
        dos = _post(DOS_FLOW)
        assert dos.get("explanation_kind") in ("shap", "feature_importance_fallback")

    def test_top_features_present_when_shap(self):
        dos = _post(DOS_FLOW)
        if dos.get("explanation_kind") == "shap":
            tf = dos.get("top_features") or []
            assert isinstance(tf, list) and len(tf) >= 1
            for row in tf:
                assert isinstance(row.get("feature"), str)
                assert isinstance(row.get("impact"), (int, float))
                assert isinstance(row.get("value"), (int, float))

    def test_severity_rules(self):
        benign = _post(BENIGN_WEB)
        assert benign["severity"] == "info"  # normal -> info
        dos = _post(DOS_FLOW)
        assert dos["severity"] in ("high", "medium", "low", "critical")

    def test_asset_criticality_known_for_mapped_service(self):
        benign = _post(BENIGN_WEB)
        assert benign["asset_criticality_known"] is True
        assert 0.0 <= benign["asset_criticality"] <= 1.0

    def test_unknown_service_never_auto_logged(self):
        """Unknown service is never silently auto-logged (documented policy).

        The Review floor promotes an unknown-service flow out of auto_log IF its
        score would otherwise auto-log. If the score already lands in Review (or
        higher) the floor does not fire and tier_floor_applied may be None — that
        is correct, not a bug. The invariant we check here is the policy outcome:
        an unknown-service flow is never silently auto-logged.
        """
        det = _post(UNKNOWN_SERVICE_FLOW)
        assert det["asset_criticality_known"] is False
        assert det["tier"] != "auto_log", (
            f"unknown service must not be auto-logged; got tier={det['tier']!r}, "
            f"priority={det['priority']}, reason={det.get('tier_reason')!r}"
        )
        # If the floor did fire it is recorded; if the score already placed the
        # flow in Review (or higher) the floor is not triggered.
        if det.get("tier_floor_applied"):
            assert det["tier"] == "review"
            assert any("unknown" in f.lower() for f in (det.get("dq_flags") or []))
        else:
            # Score placed it in review/critical on its own; still flag the
            # unknown-asset data-quality issue so an operator can see why the
            # asset term is the neutral fallback.
            assert any("unknown" in f.lower() for f in (det.get("dq_flags") or []))

    def test_priority_in_unit_range(self):
        for payload in [BENIGN_WEB, DOS_FLOW, UNKNOWN_SERVICE_FLOW]:
            det = _post(payload)
            assert 0.0 <= det["priority"] <= 1.0, f"{det['priority']} not in [0,1]"

    def test_replay_returns_same_prediction_family(self):
        """/api/detect/replay/{id} reproduces a stored alert's decision family."""
        alerts = _get("/api/alerts?limit=1")
        items = alerts.get("items") or []
        if not items:
            pytest.skip("no demo alerts available")
        alert = items[0]
        replay_resp = _CLIENT.post(f"/api/detect/replay/{alert['id']}")
        assert replay_resp.status_code == 200, f"replay returned {replay_resp.status_code}"
        replay = replay_resp.json()
        assert replay.get("predicted") == alert["predicted"], (
            f"replay predicted {replay.get('predicted')} != alert {alert['predicted']}"
        )
        assert replay.get("is_zero_day") == alert.get("is_zero_day"), "is_zero_day mismatch on replay"

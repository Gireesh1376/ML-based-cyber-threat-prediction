"""
Unit & Integration tests for Problem 4: Adversarial Evasion Robustness & Retraining.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.ml.adversarial import (
    RATE_COLUMNS,
    COUNT_COLUMNS,
    IMMUTABLE_COLUMNS,
    enforce_domain_constraints,
    generate_adversarial_perturbation,
    load_adversarial_metrics,
    simulate_adversarial_flow,
)
from app.routers.detect import PRESETS

client = TestClient(app)


def test_domain_constraints_enforcement():
    """Verify rate bounds, non-negative counts, and integer rounding."""
    mock_data = pd.DataFrame([{
        "serror_rate": 1.45,       # Out of bound > 1.0
        "same_srv_rate": -0.25,     # Out of bound < 0.0
        "count": 42.7,              # Fractional count
        "src_bytes": -150.0,        # Negative bytes
        "protocol_type": "tcp",
        "land": 0,
    }])
    constrained = enforce_domain_constraints(mock_data)

    assert constrained["serror_rate"].iloc[0] == 1.0
    assert constrained["same_srv_rate"].iloc[0] == 0.0
    assert constrained["count"].iloc[0] == 43
    assert constrained["src_bytes"].iloc[0] == 0.0
    assert constrained["protocol_type"].iloc[0] == "tcp"
    assert constrained["land"].iloc[0] == 0


def test_perturbation_methods_preserve_constraints():
    """Verify all 3 perturbation methods produce valid, constrained flows."""
    from app.ml.features import sample_to_dataframe
    flow_df = sample_to_dataframe(PRESETS["known_dos"])

    for method in ["demgan", "uap", "fgsm"]:
        perturbed = generate_adversarial_perturbation(flow_df, method=method, epsilon=0.25)
        for col in RATE_COLUMNS:
            if col in perturbed.columns:
                val = float(perturbed[col].iloc[0])
                assert 0.0 <= val <= 1.0, f"{method} violated rate bound for {col}: {val}"
        for col in COUNT_COLUMNS:
            if col in perturbed.columns:
                val = float(perturbed[col].iloc[0])
                assert val >= 0.0, f"{method} violated non-negative count for {col}: {val}"
        for col in IMMUTABLE_COLUMNS:
            if col in perturbed.columns:
                assert perturbed[col].iloc[0] == flow_df[col].iloc[0], f"{method} mutated immutable {col}"


def test_simulate_adversarial_flow():
    """Verify flow simulation executes and returns structured comparative output."""
    res = simulate_adversarial_flow(PRESETS["known_dos"], method="demgan", epsilon=0.20)

    assert "baseline_clean" in res
    assert "baseline_under_attack" in res
    assert "hardened_under_attack" in res
    assert "feature_deltas" in res
    assert "analysis" in res
    assert isinstance(res["feature_deltas"], list)
    assert len(res["feature_deltas"]) > 0

    clean_pred = res["baseline_clean"]["predicted"]
    assert clean_pred != "normal", f"Known DoS should not be predicted normal: {clean_pred}"
    assert "tier" in res["hardened_under_attack"]


def test_api_metrics_endpoint():
    """Test GET /api/adversarial/metrics returns valid benchmark schema."""
    resp = client.get("/api/adversarial/metrics")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert "clean_metrics" in data
    assert "adversarial_summary" in data
    assert "sweep" in data
    assert len(data["sweep"]) >= 6
    assert data["adversarial_summary"]["evasion_reduction_pct"] > 0


def test_api_presets_endpoint():
    """Test GET /api/adversarial/presets returns presets and method metadata."""
    resp = client.get("/api/adversarial/presets")
    assert resp.status_code == 200
    data = resp.json()
    assert "presets" in data
    assert "known_dos" in data["presets"]
    assert "methods" in data
    assert "demgan" in data["methods"]
    assert "uap" in data["methods"]
    assert "fgsm" in data["methods"]


def test_api_simulate_endpoint():
    """Test POST /api/adversarial/simulate with preset and custom epsilon."""
    resp = client.post("/api/adversarial/simulate", json={
        "preset": "known_dos",
        "method": "demgan",
        "epsilon": 0.20,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["method"] == "demgan"
    assert data["epsilon"] == 0.20
    assert "analysis" in data
    assert "baseline_clean" in data
    assert "hardened_under_attack" in data

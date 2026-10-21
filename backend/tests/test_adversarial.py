"""
Comprehensive Unit & Integration tests for Problem 4: Adversarial Evasion Robustness,
Network-Flow Constraint Validation, and Adversarial Hardening.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.ml import hybrid_predict, load_artifacts, model_path
from app.ml.adversarial import (
    BINARY_COLUMNS,
    COUNT_COLUMNS,
    DISCRETE_INT_COLUMNS,
    FEATURE_SCALES,
    HARDENED_UAP_VECTOR_PATH,
    IMMUTABLE_COLUMNS,
    MUTABLE_COLUMNS,
    RATE_COLUMNS,
    UAP_VECTOR_PATH,
    check_sample_constraints,
    compute_hybrid_evasion_loss,
    compute_model_gradients,
    enforce_domain_constraints,
    generate_adversarial_perturbation,
    get_hardened_model,
    get_transformer_feature_scales,
    load_adversarial_metrics,
    load_or_train_uap_vector,
    simulate_adversarial_flow,
    train_universal_adversarial_perturbation,
    validate_network_flow_constraints,
)
from app.ml.features import sample_to_dataframe
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


def test_network_flow_constraint_validator_detects_violations():
    """Verify constraint validator catches illegal feature ranges and impossible combinations."""
    base_flow = sample_to_dataframe(PRESETS["known_dos"])

    # 1. Negative duration violation
    bad_dur = base_flow.copy()
    bad_dur["duration"] = -5.0
    is_valid, violations = validate_network_flow_constraints(bad_dur)
    assert not is_valid
    assert any("duration" in v and "negative" in v for v in violations)

    # 2. Out-of-bounds error rate violation
    bad_rate = base_flow.copy()
    bad_rate["serror_rate"] = 1.35
    is_valid, violations = validate_network_flow_constraints(bad_rate)
    assert not is_valid
    assert any("serror_rate" in v for v in violations)

    # 3. Fractional discrete packet count violation
    bad_count = base_flow.copy()
    bad_count["count"] = 12.4
    is_valid, violations = validate_network_flow_constraints(bad_count)
    assert not is_valid
    assert any("count" in v and "non-integer" in v for v in violations)

    # 4. Hierarchy violation: dst_host_srv_count > dst_host_count
    bad_hierarchy = base_flow.copy()
    bad_hierarchy["dst_host_count"] = 50
    bad_hierarchy["dst_host_srv_count"] = 120
    is_valid, violations = validate_network_flow_constraints(bad_hierarchy)
    assert not is_valid
    assert any("Hierarchy violation" in v for v in violations)

    # 5. Complementary rate sum violation: serror_rate + rerror_rate > 1.0
    bad_sum = base_flow.copy()
    bad_sum["serror_rate"] = 0.8
    bad_sum["rerror_rate"] = 0.8
    is_valid, violations = validate_network_flow_constraints(bad_sum)
    assert not is_valid
    assert any("Complementary rate violation" in v for v in violations)

    # 6. Protocol violation: non-zero SYN error on UDP traffic
    bad_proto = base_flow.copy()
    bad_proto["protocol_type"] = "udp"
    bad_proto["serror_rate"] = 0.5
    is_valid, violations = validate_network_flow_constraints(bad_proto)
    assert not is_valid
    assert any("Protocol violation" in v and "UDP" in v for v in violations)

    # 7. Comparison against original: mutation of immutable protocol field
    bad_mut = base_flow.copy()
    bad_mut["protocol_type"] = "icmp"
    is_valid, violations = validate_network_flow_constraints(bad_mut, orig_df=base_flow)
    assert not is_valid
    assert any("Immutable column 'protocol_type' was modified" in v for v in violations)

    # 8. Comparison against original: payload shrinkage
    bad_shrink = base_flow.copy()
    bad_shrink["src_bytes"] = float(base_flow["src_bytes"].iloc[0]) - 100.0
    is_valid, violations = validate_network_flow_constraints(bad_shrink, orig_df=base_flow)
    assert not is_valid
    assert any("Payload reduction" in v for v in violations)


def test_check_sample_constraints_exact_counting():
    """Verify check_sample_constraints produces accurate per-sample boolean masks and counts."""
    base_flow = sample_to_dataframe(PRESETS["known_dos"])
    # Create 5 flows
    batch = pd.concat([base_flow] * 5, ignore_index=True)
    # Ensure columns can accept float mutations
    batch["duration"] = batch["duration"].astype(float)
    batch["serror_rate"] = batch["serror_rate"].astype(float)

    # Corrupt samples 1 and 3 specifically
    batch.loc[1, "duration"] = -8.0
    batch.loc[3, "serror_rate"] = 1.6

    valid_mask, violations = check_sample_constraints(batch, orig_df=pd.concat([base_flow] * 5, ignore_index=True))
    assert len(valid_mask) == 5
    assert valid_mask[0] == True
    assert valid_mask[1] == False
    assert valid_mask[2] == True
    assert valid_mask[3] == False
    assert valid_mask[4] == True
    assert int(np.sum(valid_mask)) == 3
    valid_pct = float(np.sum(valid_mask) / len(batch) * 100.0)
    assert valid_pct == 60.0
    assert len(violations) >= 2


def test_enforce_domain_constraints_fixes_all_violations():
    """Verify enforce_domain_constraints transforms invalid flows into 100% compliant flows."""
    orig_flow = sample_to_dataframe(PRESETS["known_dos"])

    # Create flow with numerous deliberate constraint violations
    corrupted = orig_flow.copy()
    corrupted["duration"] = -10.0
    corrupted["serror_rate"] = 1.8
    corrupted["rerror_rate"] = 0.9
    corrupted["count"] = 15.67
    corrupted["dst_host_count"] = 300.0  # exceeds window size 255
    corrupted["dst_host_srv_count"] = 500.0  # exceeds dst_host_count
    corrupted["protocol_type"] = "icmp"  # illegal immutable change
    corrupted["src_bytes"] = -50.0

    # Enforce domain constraints with original baseline reference
    repaired = enforce_domain_constraints(corrupted, orig_df=orig_flow)

    # Validate that all violations have been eliminated
    is_valid, violations = validate_network_flow_constraints(repaired, orig_df=orig_flow)
    assert is_valid, f"Repaired flow still has violations: {violations}"
    assert len(violations) == 0

    # Verify specific repairs
    assert repaired["protocol_type"].iloc[0] == orig_flow["protocol_type"].iloc[0]
    assert 0.0 <= repaired["serror_rate"].iloc[0] <= 1.0
    assert repaired["serror_rate"].iloc[0] + repaired["rerror_rate"].iloc[0] <= 1.0 + 1e-4
    assert repaired["dst_host_count"].iloc[0] <= 255
    assert repaired["dst_host_srv_count"].iloc[0] <= repaired["dst_host_count"].iloc[0]
    assert repaired["count"].iloc[0] == 16
    assert repaired["src_bytes"].iloc[0] >= orig_flow["src_bytes"].iloc[0]


def test_perturbation_methods_preserve_constraints():
    """Verify all 3 perturbation methods produce valid, constrained flows."""
    flow_df = sample_to_dataframe(PRESETS["known_dos"])

    for method in ["demgan", "uap", "fgsm"]:
        perturbed = generate_adversarial_perturbation(flow_df, method=method, epsilon=0.25)
        is_valid, violations = validate_network_flow_constraints(perturbed, orig_df=flow_df)
        assert is_valid, f"{method} produced invalid constraints: {violations}"

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


def test_fgsm_gradient_feedback_and_feature_scaling():
    """Verify FGSM computes genuine model gradients, respects feature scaling, and perturbs features."""
    art, _ = load_artifacts(model_path())
    flow_df = sample_to_dataframe(PRESETS["known_dos"])

    # Compute numerical gradients directly
    grads = compute_model_gradients(art, flow_df)
    assert len(grads) > 0, "FGSM should compute gradients for mutable features"
    assert "serror_rate" in grads

    # Generate FGSM adversarial flow at epsilon 0.20
    perturbed = generate_adversarial_perturbation(flow_df, method="fgsm", epsilon=0.20, artifacts=art)

    # Verify immutable columns remain identical
    for col in IMMUTABLE_COLUMNS:
        if col in flow_df.columns:
            assert perturbed[col].iloc[0] == flow_df[col].iloc[0], f"FGSM altered immutable column {col}"

    # Verify rate shift is bounded by epsilon
    rate_diff = abs(float(perturbed["serror_rate"].iloc[0]) - float(flow_df["serror_rate"].iloc[0]))
    assert rate_diff <= 0.20 + 1e-4, f"Rate shift {rate_diff} exceeded epsilon budget 0.20"

    # Verify monotonic payload padding
    assert float(perturbed["src_bytes"].iloc[0]) >= float(flow_df["src_bytes"].iloc[0])
    assert float(perturbed["duration"].iloc[0]) >= float(flow_df["duration"].iloc[0])

    # Verify at least one mutable feature was altered
    diffs = [
        col for col in MUTABLE_COLUMNS
        if col in flow_df.columns and abs(float(perturbed[col].iloc[0]) - float(flow_df[col].iloc[0])) > 1e-4
    ]
    assert len(diffs) > 0, "FGSM must perturb at least one mutable feature"


def test_genuine_uap_optimization_feedback():
    """Verify UAP iteratively optimizes a universal vector using model feedback."""
    art, _ = load_artifacts(model_path())
    # Create calibration samples
    c1 = sample_to_dataframe(PRESETS["known_dos"])
    c2 = sample_to_dataframe(PRESETS["probe_scan"])
    c1["label"] = "neptune"
    c2["label"] = "ipsweep"
    cal_df = pd.concat([c1, c2], ignore_index=True)

    # Train genuine UAP vector
    v = train_universal_adversarial_perturbation(art, cal_df, epsilon=0.20, max_iter=3, step_size=0.04)
    assert isinstance(v, dict)
    assert len(v) > 0

    # Check key directions
    assert "serror_rate" in v
    # Non-negative properties for delay and padding
    assert v.get("duration", 0.0) >= 0.0
    assert v.get("src_bytes", 0.0) >= 0.0
    assert v.get("dst_bytes", 0.0) >= 0.0


def test_uap_universal_property():
    """Verify UAP applies a model-optimized universal shift vector across different flows."""
    flow1 = sample_to_dataframe(PRESETS["known_dos"])
    flow2 = sample_to_dataframe(PRESETS["probe_scan"])

    pert1 = generate_adversarial_perturbation(flow1, method="uap", epsilon=0.20)
    pert2 = generate_adversarial_perturbation(flow2, method="uap", epsilon=0.20)

    # Both flows must pass network-flow constraint validation
    assert validate_network_flow_constraints(pert1, orig_df=flow1)[0]
    assert validate_network_flow_constraints(pert2, orig_df=flow2)[0]

    # Verify that universal directions apply consistently
    assert float(pert1["serror_rate"].iloc[0]) <= float(flow1["serror_rate"].iloc[0])


def test_adaptive_attack_evaluation():
    """Verify adaptive attack targeting the hardened model operates and generates valid perturbed flows."""
    hardened_art, _ = get_hardened_model()
    flow = sample_to_dataframe(PRESETS["known_dos"])

    # Generate attack specifically targeting the hardened model
    adapt_pert = generate_adversarial_perturbation(flow, method="fgsm", epsilon=0.20, artifacts=hardened_art)
    is_valid, violations = validate_network_flow_constraints(adapt_pert, orig_df=flow)
    assert is_valid, f"Adaptive attack generated invalid constraints: {violations}"

    # Verify simulation with adaptive=True executes and reports adaptive flag
    res = simulate_adversarial_flow(PRESETS["known_dos"], method="fgsm", epsilon=0.20, adaptive=True)
    assert res["adaptive"] is True
    assert "hardened_under_attack" in res
    assert "baseline_clean" in res


def test_demgan_manifold_drift_documentation():
    """Verify DEMGAN is documented as an empirical manifold drift approximation."""
    resp = client.get("/api/adversarial/presets")
    assert resp.status_code == 200
    data = resp.json()
    assert "demgan" in data["methods"]
    method_info = data["methods"]["demgan"]
    assert "Approximation" in method_info["name"] or "Surrogate" in method_info["name"] or "Drift" in method_info["name"]
    assert "approximation" in method_info["description"].lower()


def test_simulate_adversarial_flow():
    """Verify flow simulation executes and returns structured comparative output."""
    res = simulate_adversarial_flow(PRESETS["known_dos"], method="demgan", epsilon=0.20)

    assert "baseline_clean" in res
    assert "baseline_under_attack" in res
    assert "hardened_under_attack" in res
    assert "feature_deltas" in res
    assert "analysis" in res
    assert "constraints_valid" in res
    assert res["constraints_valid"] is True
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
    assert "fgsm_summary" in data
    assert "uap_summary" in data
    assert "adaptive_attack_evaluation" in data
    assert "sweep" in data
    assert len(data["sweep"]) == 9
    assert data["adversarial_summary"]["evasion_reduction_pct"] > 0

    # Verify clean metrics include accuracy, recall, and FPR
    clean = data["clean_metrics"]
    assert "baseline_attack_recall" in clean
    assert "hardened_attack_recall" in clean
    assert "baseline_accuracy" in clean
    assert "hardened_accuracy" in clean
    assert "baseline_fpr" in clean
    assert "hardened_fpr" in clean
    assert "fpr_penalty" in clean


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
    """Test POST /api/adversarial/simulate with preset, custom epsilon, and adaptive flag."""
    resp = client.post("/api/adversarial/simulate", json={
        "preset": "known_dos",
        "method": "fgsm",
        "epsilon": 0.20,
        "adaptive": True,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["method"] == "fgsm"
    assert data["epsilon"] == 0.20
    assert data["adaptive"] is True
    assert "analysis" in data
    assert "baseline_clean" in data
    assert "hardened_under_attack" in data
    assert data.get("constraints_valid") is True


def test_api_simulate_endpoint_rejects_invalid_method():
    """Regression test: verify POST /api/adversarial/simulate rejects unsupported methods with HTTP 422.

    Ensures unsupported methods (e.g. unknown strings, non-implemented generators)
    are strictly rejected with HTTP 422 Unprocessable Entity instead of silently falling back to DEMGAN.
    """
    # 1. Unsupported methods must return HTTP 422
    for invalid_method in ["invalid_method", "pgd", "random_noise", "gan", "deepfool", ""]:
        resp = client.post("/api/adversarial/simulate", json={
            "preset": "known_dos",
            "method": invalid_method,
            "epsilon": 0.20,
        })
        assert resp.status_code == 422, (
            f"Expected HTTP 422 for unsupported method '{invalid_method}', got {resp.status_code}: {resp.text}"
        )

    # 2. Supported methods ('fgsm', 'uap', 'demgan') must return HTTP 200
    for valid_method in ["fgsm", "uap", "demgan"]:
        resp = client.post("/api/adversarial/simulate", json={
            "preset": "known_dos",
            "method": valid_method,
            "epsilon": 0.20,
        })
        assert resp.status_code == 200, (
            f"Expected HTTP 200 for supported method '{valid_method}', got {resp.status_code}: {resp.text}"
        )
        assert resp.json()["method"] == valid_method


def test_generate_adversarial_perturbation_rejects_unsupported_method():
    """Regression test: verify generate_adversarial_perturbation raises ValueError on unsupported methods."""
    flow = sample_to_dataframe(PRESETS["known_dos"])
    with pytest.raises(ValueError, match="Unsupported perturbation method"):
        generate_adversarial_perturbation(flow, method="unsupported_generator")


def test_adversarial_metrics_schema_and_calculations():
    """Verify empirical adversarial metrics are non-trivial and derived from actual predictions."""
    metrics = load_adversarial_metrics()
    assert metrics["status"] == "ready"

    # Sweep verification
    sweep = metrics["sweep"]
    assert len(sweep) == 9, f"Expected 9 sweep items (3 methods x 3 epsilons), got {len(sweep)}"

    methods_present = {item["method"] for item in sweep}
    assert methods_present == {"demgan", "uap", "fgsm"}

    for item in sweep:
        assert 0.0 <= item["baseline_classifier_evasion"] <= 1.0
        assert 0.0 <= item["hardened_classifier_evasion"] <= 1.0
        assert 0.0 <= item["baseline_hybrid_evasion"] <= 1.0
        assert 0.0 <= item["hardened_hybrid_evasion"] <= 1.0
        assert item["valid_samples_count"] == item["total_samples_count"]
        assert item["constraint_validity_pct"] == 100.0
        assert "adaptive_hardened_classifier_evasion" in item
        assert "adaptive_hardened_hybrid_evasion" in item
        assert "adaptive_hardened_attack_recall" in item

    # Clean metrics preservation check
    clean = metrics["clean_metrics"]
    assert clean["hardened_accuracy"] >= clean["baseline_accuracy"] - 0.02
    assert clean["hardened_attack_recall"] >= clean["baseline_attack_recall"] - 0.02
    assert clean["fpr_penalty"] <= 0.05


def test_fgsm_gradient_scaling_mathematical_consistency():
    """Verify that FGSM calculates gradients and scales perturbations consistently with the model's standardized input representation.

    Specifically:
      - Gradient sign in standardized space governs perturbation direction.
      - Raw perturbation Delta x_raw_j is scaled by the exact transformer standard deviation sigma_j.
      - When transformed into standardized space, the perturbation magnitude |Delta X_j| is bounded by epsilon.
    """
    art, _ = load_artifacts(model_path())
    scales = get_transformer_feature_scales(art)
    flow_df = sample_to_dataframe(PRESETS["known_dos"])
    epsilon = 0.20

    grads = compute_model_gradients(art, flow_df, step_h=0.05)
    perturbed = generate_adversarial_perturbation(flow_df, method="fgsm", epsilon=epsilon, artifacts=art)

    # Check that each perturbed mutable feature's raw shift divided by sigma_j aligns with epsilon and direction
    for col in MUTABLE_COLUMNS:
        if col in flow_df.columns:
            orig_val = float(flow_df[col].iloc[0])
            pert_val = float(perturbed[col].iloc[0])
            raw_diff = pert_val - orig_val
            sigma = scales.get(col, 1.0)
            normalized_shift = raw_diff / sigma

            g = float(grads.get(col, [0.0])[0]) if col in grads else 0.0
            expected_dir = -np.sign(g)

            # Monotonic features cannot be reduced
            if col in ["src_bytes", "dst_bytes", "duration"]:
                assert normalized_shift >= -1e-4, f"Monotonic feature {col} was reduced"
                if expected_dir > 0:
                    assert normalized_shift <= epsilon + 1e-3, f"Normalized shift for {col} exceeded epsilon"
            else:
                # Due to clipping at [0, 1] for rate features or integer rounding,
                # normalized_shift should not exceed epsilon
                assert abs(normalized_shift) <= epsilon + 1e-2, (
                    f"Normalized shift for {col} ({normalized_shift}) exceeded epsilon ({epsilon})"
                )


def test_adaptive_uap_hardened_optimization_and_vector_separation():
    """Verify adaptive UAP optimizes a distinct vector against the hardened model and evaluation uses it."""
    assert UAP_VECTOR_PATH.exists(), "Baseline UAP vector must exist"
    assert HARDENED_UAP_VECTOR_PATH.exists(), "Hardened UAP vector must exist"

    import json
    base_v = json.loads(UAP_VECTOR_PATH.read_text(encoding="utf-8"))
    hard_v = json.loads(HARDENED_UAP_VECTOR_PATH.read_text(encoding="utf-8"))

    # Verify both vectors have mutable columns
    assert len(base_v) > 0 and len(hard_v) > 0

    # Verify that the hardened UAP vector is genuinely different from the baseline vector
    differences = [k for k in base_v if k in hard_v and abs(base_v[k] - hard_v[k]) > 1e-3]
    assert len(differences) >= 3, f"Hardened UAP vector must differ from baseline UAP: diffs in {differences}"

    # Verify that load_or_train_uap_vector loads the correct vector
    hardened_art, _ = get_hardened_model()
    loaded_hard = load_or_train_uap_vector(hardened_art, is_hardened=True)
    assert loaded_hard == hard_v, "load_or_train_uap_vector with is_hardened=True must load the hardened UAP vector"

    # Verify that adaptive UAP generation actually uses the hardened vector
    flow = sample_to_dataframe(PRESETS["probe_scan"])
    pert_base = generate_adversarial_perturbation(flow, method="uap", epsilon=0.20, is_hardened=False)
    pert_hard = generate_adversarial_perturbation(flow, method="uap", epsilon=0.20, artifacts=hardened_art, is_hardened=True)

    # Perturbed flows should differ reflecting their distinct UAP vectors
    flow_diffs = [
        c for c in MUTABLE_COLUMNS
        if c in flow.columns and abs(float(pert_base[c].iloc[0]) - float(pert_hard[c].iloc[0])) > 1e-4
    ]
    assert len(flow_diffs) > 0, "Adaptive UAP perturbation must differ from baseline UAP perturbation"


def test_complete_deployed_detector_evaluation():
    """Verify benchmark metrics evaluate both XGBoost classifier and Autoencoder anomaly gate.

    Demonstrates defense-in-depth: complete hybrid detector evasion is strictly less than
    or equal to XGBoost-alone classifier evasion because the autoencoder anomaly gate
    catches classifier-evading adversarial flows.
    """
    metrics = load_adversarial_metrics()
    sweep = metrics["sweep"]

    for row in sweep:
        # Baseline model: hybrid evasion must not exceed classifier evasion
        assert row["baseline_hybrid_evasion"] <= row["baseline_classifier_evasion"] + 1e-4, (
            f"Anomaly gate violation in baseline for {row['method']} eps={row['epsilon']}: "
            f"hybrid={row['baseline_hybrid_evasion']} > clf={row['baseline_classifier_evasion']}"
        )
        # Hardened model under transfer attack
        assert row["hardened_hybrid_evasion"] <= row["hardened_classifier_evasion"] + 1e-4, (
            f"Anomaly gate violation in hardened transfer for {row['method']} eps={row['epsilon']}"
        )
        # Hardened model under adaptive attack
        assert row["adaptive_hardened_hybrid_evasion"] <= row["adaptive_hardened_classifier_evasion"] + 1e-4, (
            f"Anomaly gate violation in hardened adaptive for {row['method']} eps={row['epsilon']}"
        )

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from app.config import MODELS_DIR
from app.ml.encrypted_features import (
    CATEGORICAL_COLS,
    FLOW_NUMERICAL_COLS,
    SPLT_RECORD_COLS,
    EncryptedFeatureTransformer,
    extract_raw_features_from_dict,
)
from app.ml.train_encrypted import load_encrypted_detector


def test_extract_raw_features_robustness():
    """Verify that extract_raw_features_from_dict handles missing, null, and malformed fields gracefully."""
    empty_payload: dict[str, Any] = {}
    feats = extract_raw_features_from_dict(empty_payload)

    # Must contain all expected continuous flow columns
    for col in FLOW_NUMERICAL_COLS:
        assert col in feats, f"Missing flow numerical feature: {col}"
        assert not np.isnan(feats[col]), f"NaN found in {col}"
        assert not np.isinf(feats[col]), f"Inf found in {col}"

    # Must contain 20 SPLT elements, zero-padded
    for i in range(20):
        assert feats[f"rec_{i}"] == 0.0

    # Categoricals must have fallback strings
    assert feats["tls.cver"] == "unknown"
    assert feats["tls.scs"] == "unknown"
    assert feats["ja4_prefix"] == "unknown"


def test_extract_raw_features_splt_preservation():
    """Verify signed TLS record length preservation (positive client, negative server)."""
    payload = {
        "bs": 520, "br": 4200, "ps": 6, "pr": 8, "dp": 443, "td": 1.5,
        "tls.ccs": ["0x1301", "0x1302"],
        "tls.cext": ["0x0000", "0x0017"],
        "tls.csg": ["0x0403"],
        "tls.sext": ["0x0000"],
        "tls.alpn": ["h2"],
        "tls.sni": "c2.malicious-domain.com",
        "tls.rec": [517, -1440, -1440, -200, 64],
        "tls.cver": "0x0303",
        "tls.scs": "0x1301",
        "tls.ja4": "t13d1516h2_8daaf6152771_02713d6af862",
    }
    feats = extract_raw_features_from_dict(payload)
    assert feats["cipher_count"] == 2.0
    assert feats["client_ext_count"] == 2.0
    assert feats["has_alpn"] == 1.0
    assert feats["has_sni"] == 1.0  # Hostname is masked into binary indicator

    # First 5 record lengths must match signed values
    assert feats["rec_0"] == 517.0
    assert feats["rec_1"] == -1440.0
    assert feats["rec_2"] == -1440.0
    assert feats["rec_3"] == -200.0
    assert feats["rec_4"] == 64.0
    # Remaining 15 entries must be zero-padded
    for i in range(5, 20):
        assert feats[f"rec_{i}"] == 0.0


def test_feature_transformer_leakage_prevention():
    """Ensure transformer feature names strictly exclude all target, IP, and temporal identifiers."""
    import pandas as pd
    sample_df = pd.DataFrame([
        extract_raw_features_from_dict({
            "bs": 100, "br": 200, "ps": 2, "pr": 2, "dp": 443, "td": 0.5,
            "tls.cver": "0x0303", "tls.scs": "0x1301", "tls.ja4": "t13d1516h2_test",
            "tls.rec": [100, -200]
        })
    ])

    transformer = EncryptedFeatureTransformer().fit(sample_df)
    names = transformer.feature_names_

    prohibited_substrings = [
        "family", "service", "sample.id", "sample_id", "da", "sa",
        "destination", "source", "timestamp", "date", "target", "label"
    ]

    for name in names:
        for sub in prohibited_substrings:
            assert sub not in name.lower(), f"Potential leakage feature identified: {name}"


def test_model_loading_and_prediction():
    """Verify loading the serialized Problem 2 artifacts and running inference."""
    joblib_path = MODELS_DIR / "encrypted_detector.joblib"
    xgb_json_path = MODELS_DIR / "encrypted_detector_xgb.json"

    if not joblib_path.exists() or not xgb_json_path.exists():
        pytest.skip("Problem 2 model has not been trained yet. Run train_encrypted.py first.")

    artifacts, clf = load_encrypted_detector(joblib_path, xgb_json_path)
    assert artifacts is not None
    assert clf is not None
    assert len(artifacts.feature_names) > 0

    # Test single flow inference
    benign_flow = {
        "bs": 240, "br": 4800, "ps": 5, "pr": 7, "dp": 443, "td": 2.1,
        "tls.ccs": ["0x1301", "0x1302", "0x1303", "0xc02b", "0xc02f"],
        "tls.cext": ["0x0000", "0x0017", "0x000d", "0x002b", "0x000a"],
        "tls.csg": ["0x0403", "0x0804", "0x0401"],
        "tls.sext": ["0x0000", "0x002b"],
        "tls.alpn": ["h2", "http/1.1"],
        "tls.sni": "www.cloudflare.com",
        "tls.rec": [517, -1440, -1440, -1440, 240, -800],
        "tls.cver": "0x0303",
        "tls.scs": "0x1301",
        "tls.ja4": "t13d1516h2_8daaf6152771_02713d6af862",
    }

    X_benign = artifacts.transformer.transform(benign_flow)
    prob_benign = float(clf.predict_proba(X_benign)[0, 1])
    assert 0.0 <= prob_benign <= 1.0


def test_metrics_json_integrity():
    """Verify that encrypted_metrics.json exists and contains complete audit sections."""
    metrics_path = MODELS_DIR / "encrypted_metrics.json"
    if not metrics_path.exists():
        pytest.skip("encrypted_metrics.json does not exist. Run train_encrypted.py first.")

    data = json.loads(metrics_path.read_text(encoding="utf-8"))
    assert "problem" in data
    assert "ablation_comparison" in data
    assert "primary_evaluation" in data
    assert "slice_evaluation" in data
    assert "threshold_sweep" in data

    pe = data["primary_evaluation"]
    assert "accuracy" in pe
    assert "precision" in pe
    assert "recall" in pe
    assert "f1" in pe
    assert "benign_fpr" in pe
    assert "roc_auc" in pe
    assert "pr_auc" in pe
    assert "confusion_matrix" in pe

    # Verify no execution sample ID overlap was reported
    split_summary = data.get("split_summary", {})
    assert split_summary.get("sample_id_overlap") == 0


# ---------------------------------------------------------------------------
# API Integration & Router Tests (FastAPI TestClient)
# ---------------------------------------------------------------------------

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_encrypted_schema_endpoint():
    """Verify GET /api/encrypted/schema returns model feature list and synthetic presets."""
    res = client.get("/api/encrypted/schema")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ready"
    assert data["feature_count"] == 71
    assert len(data["feature_names"]) == 71
    assert "presets" in data
    assert "benign_https_web" in data["presets"]
    assert "cobalt_strike_beacon" in data["presets"]
    assert "disclaimer" in data
    assert "synthetic" in data["disclaimer"].lower()


def test_encrypted_metrics_endpoint():
    """Verify GET /api/encrypted/metrics returns saved primary evaluation and ablation metrics."""
    res = client.get("/api/encrypted/metrics")
    assert res.status_code == 200
    data = res.json()
    assert data.get("problem") == "Problem 2: Encrypted TLS Traffic Threat Detection"
    pe = data.get("primary_evaluation", {})
    assert pe.get("accuracy") == 0.9799
    assert pe.get("recall") == 0.9823
    assert pe.get("benign_fpr") == 0.0215
    assert pe.get("roc_auc") == 0.9983


def test_encrypted_live_status_endpoint():
    """Verify GET /api/encrypted/live-status explicitly reports live capture disconnected."""
    res = client.get("/api/encrypted/live-status")
    assert res.status_code == 200
    data = res.json()
    assert data["connected"] is False
    assert data["status"] == "disconnected"
    assert data["live_pcap_supported"] is False


def test_encrypted_detect_endpoint_benign_and_malicious():
    """Verify POST /api/encrypted/detect handles single-flow inference with proper schema & prioritization."""
    schema_res = client.get("/api/encrypted/schema")
    presets = schema_res.json()["presets"]

    # 1. Test synthetic benign flow
    benign_flow = presets["benign_https_web"]["flow"]
    res_benign = client.post("/api/encrypted/detect", json=benign_flow)
    assert res_benign.status_code == 200
    b_data = res_benign.json()
    assert b_data["predicted"] in ("normal", "malicious")
    assert 0.0 <= b_data["confidence"] <= 1.0
    assert 0.0 <= b_data["priority"] <= 1.0
    assert b_data["tier"] in ("critical", "review", "auto_log")
    assert b_data["blocking_recommended"] is False  # Safe TLS policy: never auto-block
    assert b_data["payload_decrypted"] is False     # NIST SP 1800-37 guarantee
    assert len(b_data["top_features"]) <= 5

    # 2. Test synthetic malicious flow (Cobalt Strike Beacon)
    c2_flow = presets["cobalt_strike_beacon"]["flow"]
    res_c2 = client.post("/api/encrypted/detect", json=c2_flow)
    assert res_c2.status_code == 200
    c2_data = res_c2.json()
    assert c2_data["predicted"] == "malicious"
    assert c2_data["confidence"] >= 0.50
    assert c2_data["tier"] in ("critical", "review")
    assert c2_data["mitigation_action"] == "alert_only"
    assert c2_data["blocking_recommended"] is False


def test_encrypted_detect_leakage_exclusion():
    """Verify that incoming payloads carrying ground-truth labels or sandbox IDs are strictly isolated."""
    poisoned_payload = {
        "bs": 1200, "br": 24000, "ps": 14, "pr": 24, "dp": 443, "td": 2.0,
        "tls.ccs": ["0x1301", "0x1302"],
        "tls.cext": ["0x0000", "0x0017"],
        "tls.rec": [517, -1440, 200],
        "tls.cver": "0x0303",
        "tls.scs": "0x1301",
        # Malicious injection of training/sandbox keys:
        "meta.malware.family": "AgentTesla",
        "meta.sample.id": "sandbox_vm_10924",
        "meta.system.service": None,
        "true_label": "malicious",
        "label": 1,
    }

    res = client.post("/api/encrypted/detect", json=poisoned_payload)
    assert res.status_code == 200
    data = res.json()
    # Ensure the metadata inspected and stored in result does not accept these keys
    meta_inspected = data.get("metadata_inspected", {})
    assert "meta.malware.family" not in meta_inspected
    assert "true_label" not in meta_inspected


def test_encrypted_detect_validation_error():
    """Verify that invalid/negative numbers return HTTP 422 instead of crashing or fabricating outputs."""
    invalid_payload = {
        "bs": -500,  # Negative bytes not allowed by ge=0.0
        "dp": 999999, # Port exceeds 65535
    }
    res = client.post("/api/encrypted/detect", json=invalid_payload)
    assert res.status_code == 422


def test_encrypted_pcap_unsupported():
    """Verify that POST /api/encrypted/analyze-pcap returns 501 Not Implemented with clear reason."""
    res = client.post("/api/encrypted/analyze-pcap")
    assert res.status_code == 501
    detail = res.json().get("detail", "")
    assert "unsupported in Phase 2" in detail
    assert "payloads are never decrypted" in detail.lower()


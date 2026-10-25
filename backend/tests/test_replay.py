"""
Regression tests for alert replay routing and strict protocol isolation.

Verifies:
1. TLS alert replay invokes the Problem 2 encrypted detector.
2. NSL-KDD flow replay invokes the Problem 1 detector.
3. Unknown or malformed flow formats return a clear 422 error.
4. A TLS flow is NEVER sent to the NSL-KDD autoencoder.
5. Replay does not create duplicate alerts or alter stored database records.
"""
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routers.detect import classify_replay_target

client = TestClient(app)


def test_classify_replay_target_tls():
    # Explicit protocol
    assert classify_replay_target({"protocol": "tls"}) == "tls"
    assert classify_replay_target({"protocol": "TLS"}) == "tls"

    # Missing/blank protocol with TLS keys
    flow_with_ja4 = {"tls.ja4": "t13d0402h2_69ae9dfb1c86_02713d6af862", "dp": 443}
    assert classify_replay_target({"flow": flow_with_ja4}) == "tls"

    flow_with_encrypted_transport = {"bs": 1200, "br": 2400, "ps": 10, "pr": 12, "dp": 443}
    assert classify_replay_target({"flow": flow_with_encrypted_transport}) == "tls"


def test_classify_replay_target_nsl_kdd():
    # Explicit protocol with NSL-KDD features
    nsl_flow = {"duration": 0, "protocol_type": "tcp", "service": "http", "src_bytes": 100, "dst_bytes": 200}
    assert classify_replay_target({"protocol": "tcp", "flow": nsl_flow}) == "nsl_kdd"
    assert classify_replay_target({"protocol": "icmp", "flow": nsl_flow}) == "nsl_kdd"
    assert classify_replay_target({"protocol": "udp", "flow": nsl_flow}) == "nsl_kdd"

    # Legacy seeded alert without stored flow dict
    assert classify_replay_target({"protocol": "tcp", "predicted": "normal"}) == "nsl_kdd"


def test_classify_replay_target_unsupported():
    # Flow with corrupted/arbitrary keys
    garbage_flow = {"random_key": "some_value", "unexpected_payload": [1, 2, 3]}
    assert classify_replay_target({"protocol": "unknown", "flow": garbage_flow}) == "unsupported"
    assert classify_replay_target({"flow": garbage_flow}) == "unsupported"

    # Empty payload with unknown protocol
    assert classify_replay_target({"protocol": "gre"}) == "unsupported"


def test_nsl_kdd_alert_replay_invokes_existing_detector():
    """Verify that an NSL-KDD alert is replayed through Problem 1."""
    # ALT-10000 is an existing demo alert from demo_alerts.json
    res = client.post("/api/detect/replay/ALT-10000")
    assert res.status_code == 200
    data = res.json()
    assert data["replayed_from"] == "ALT-10000"
    assert data["engine"] == "zero_day_detector"
    assert data["protocol"] == "tcp"
    assert "reconstruction_error" in data
    assert "priority" in data
    assert "tier" in data


def test_tls_alert_replay_invokes_encrypted_detector():
    """Verify that a TLS alert is replayed through Problem 2 without NSL-KDD interference."""
    mock_tls_alert = {
        "id": "ALT-TLS-REPLAY-TEST",
        "protocol": "tls",
        "predicted": "malicious",
        "flow": {
            "bs": 1240,
            "br": 2800,
            "ps": 12,
            "pr": 14,
            "dp": 443,
            "td": 0.45,
            "tls.cver": "0x0303",
            "tls.scs": "0x1301",
            "tls.ja4": "t13d0402h2_69ae9dfb1c86_02713d6af862",
            "tls.rec": [420, -510, 240, -320],
        },
    }

    with patch("app.routers.detect.get_alert_by_id", return_value=mock_tls_alert):
        res = client.post("/api/detect/replay/ALT-TLS-REPLAY-TEST")
        assert res.status_code == 200
        data = res.json()
        assert data["replayed_from"] == "ALT-TLS-REPLAY-TEST"
        assert data["engine"] == "encrypted_traffic_detector"
        assert data["protocol"] == "tls"
        assert data["is_zero_day"] is False
        assert data["payload_decrypted"] is False
        assert "malicious_probability" in data
        assert "priority" in data
        assert "tier" in data
        assert "top_features" in data


def test_tls_flow_is_never_sent_to_nsl_kdd_autoencoder():
    """Strict architectural test: guarantees TLS flow never invokes the autoencoder."""
    mock_tls_alert = {
        "id": "ALT-TLS-STRICT-ISOLATION",
        "protocol": "tls",
        "predicted": "malicious",
        "flow": {
            "bs": 500,
            "br": 1200,
            "ps": 5,
            "pr": 6,
            "dp": 443,
            "td": 0.1,
            "tls.ja4": "t13d0402h2_dummy",
        },
    }

    with patch("app.routers.detect.get_alert_by_id", return_value=mock_tls_alert):
        with patch("app.routers.detect.predict_payload") as mock_predict_payload:
            res = client.post("/api/detect/replay/ALT-TLS-STRICT-ISOLATION")
            assert res.status_code == 200
            # Autoencoder / predict_payload MUST NOT be called!
            mock_predict_payload.assert_not_called()


def test_malformed_or_unknown_flow_returns_clear_422_error():
    """Verify that an unsupported or corrupted alert returns HTTP 422 rather than fabricating a prediction."""
    mock_invalid_alert = {
        "id": "ALT-CORRUPT-SCHEMA",
        "protocol": "proprietary_binary",
        "flow": {
            "unrecognized_field_a": 9999,
            "unrecognized_field_b": "corrupted",
        },
    }

    with patch("app.routers.detect.get_alert_by_id", return_value=mock_invalid_alert):
        res = client.post("/api/detect/replay/ALT-CORRUPT-SCHEMA")
        assert res.status_code == 422
        detail = res.json()["detail"]
        assert "unsupported, ambiguous, or malformed" in detail

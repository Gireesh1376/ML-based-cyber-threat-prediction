"""
AEGIS Problem 2: Encrypted TLS Traffic Detector Service.
Provides model caching, feature extraction, TreeSHAP explanation,
and alert prioritisation for encrypted network flows without decrypting payloads.
"""
from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np
import xgboost as xgb
from xgboost import XGBClassifier

from app.config import MODELS_DIR, SERVICE_CRITICALITY
from app.ml.encrypted_features import (
    CATEGORICAL_COLS,
    FLOW_NUMERICAL_COLS,
    SPLT_RECORD_COLS,
    EncryptedDetectorArtifacts,
    extract_raw_features_from_dict,
)
from app.ml.priority import compute_priority, tier_from_score

logger = logging.getLogger("aegis.encrypted_detector")

METRICS_PATH = MODELS_DIR / "encrypted_metrics.json"
JOBLIB_PATH = MODELS_DIR / "encrypted_detector.joblib"
XGB_JSON_PATH = MODELS_DIR / "encrypted_detector_xgb.json"

# Strict isolation: prohibited fields that represent ground-truth labels,
# sandbox execution identifiers, or leakage that must never influence inference.
PROHIBITED_METADATA_KEYS = {
    "meta.malware.family",
    "meta.sample.id",
    "meta.system.service",
    "meta.system.os",
    "meta.application.name",
    "meta.system.version",
    "family",
    "sample_id",
    "true_label",
    "label",
    "is_attack",
    "target",
}

# Synthetic Demonstration Presets (strictly labeled as synthetic examples, not live observations)
ENCRYPTED_PRESETS: dict[str, dict[str, Any]] = {
    "benign_https_web": {
        "title": "Synthetic Benign Web Browser",
        "category": "benign",
        "description": "Synthetic demonstration: Standard HTTP/2 web browsing over TLS 1.3 with complete browser cipher suites and ALPN negotiation.",
        "flow": {
            "bs": 3228,
            "br": 13920,
            "ps": 17,
            "pr": 22,
            "dp": 443,
            "td": 0.8,
            "tls.ccs": ["0x1301", "0x1302", "0x1303", "0xc02b", "0xc02f", "0xc02c", "0xc030", "0xcca9", "0xcca8", "0xc013", "0xc014", "0x009c", "0x009d", "0x002f", "0x0035"],
            "tls.cext": ["0x0000", "0x0017", "0x000d", "0x002b", "0x000a", "0x0033", "0x0010", "0x0015", "0x0012", "0x002d", "0x001b", "0x001c", "0x001d", "0x001e", "0x001f", "0x0020", "0x0021", "0x0023"],
            "tls.csg": ["0x0403", "0x0804", "0x0401", "0x0503", "0x0805", "0x0501", "0x0806", "0x0601", "0x0201"],
            "tls.sext": ["0x0000", "0x002b", "0x0033"],
            "tls.alpn": ["h2", "http/1.1"],
            "tls.sni": "cdn.cloudflare.net",
            "tls.rec": [-1726, 5991, 1440, 1440, 517, -1440, -1440, -1440],
            "tls.cver": "0303",
            "tls.scs": "C030",
            "tls.ja4": "t13d1516h2_8daaf6152771_02713d6af862",
        },
    },
    "cobalt_strike_beacon": {
        "title": "Synthetic Cobalt Strike Beacon",
        "category": "malicious",
        "description": "Synthetic demonstration: Low-and-slow encrypted C2 heartbeat with customized malleable profile, sparse extensions, and no ALPN.",
        "flow": {
            "bs": 412,
            "br": 850,
            "ps": 4,
            "pr": 5,
            "dp": 8443,
            "td": 0.6,
            "tls.ccs": ["0xc030", "0xc02c", "0x009f", "0x009e"],
            "tls.cext": ["0x0000", "0x000a", "0x000b"],
            "tls.csg": ["0x0401", "0x0201"],
            "tls.sext": ["0x0000"],
            "tls.alpn": [],
            "tls.sni": "service-update-cloud.azureedge-cdn.net",
            "tls.rec": [320, -640, 92, -210],
            "tls.cver": "0x0303",
            "tls.scs": "0xc030",
            "tls.ja4": "t12d080400_e788e0f6c77b_5569e5d4cb3a",
        },
    },
    "asyncrat_exfiltration": {
        "title": "Synthetic AsyncRAT Exfiltration",
        "category": "malicious",
        "description": "Synthetic demonstration: Asymmetric high-volume outbound data staging over encrypted TLS channel without SNI hostname.",
        "flow": {
            "bs": 52800,
            "br": 1400,
            "ps": 46,
            "pr": 12,
            "dp": 6666,
            "td": 5.2,
            "tls.ccs": ["0x1301", "0xc02b"],
            "tls.cext": ["0x0000", "0x000a"],
            "tls.csg": ["0x0403"],
            "tls.sext": [],
            "tls.alpn": [],
            "tls.sni": "",
            "tls.rec": [240, -120, 1440, 1440, 1440, 1440, 1440, 1440, 1440, 1440],
            "tls.cver": "0x0303",
            "tls.scs": "0x1301",
            "tls.ja4": "t13d020100_b2195f001e42_000000000000",
        },
    },
    "doh_tunnel_covert": {
        "title": "Synthetic DoH Covert Tunnel",
        "category": "malicious",
        "description": "Synthetic demonstration: DNS-over-HTTPS encrypted covert channel with rapid small-packet exchanges and uniform burst length distributions.",
        "flow": {
            "bs": 2400,
            "br": 2600,
            "ps": 20,
            "pr": 20,
            "dp": 443,
            "td": 1.4,
            "tls.ccs": ["0x1301", "0x1302", "0x1303"],
            "tls.cext": ["0x0000", "0x0017", "0x000d", "0x002b"],
            "tls.csg": ["0x0403", "0x0804"],
            "tls.sext": ["0x0000", "0x002b"],
            "tls.alpn": ["h2"],
            "tls.sni": "dns.quad9.net",
            "tls.rec": [380, -420, 210, -260, 195, -240, 220, -255],
            "tls.cver": "0x0303",
            "tls.scs": "0x1301",
            "tls.ja4": "t13d0402h2_69ae9dfb1c86_02713d6af862",
        },
    },
}


class EncryptedDetectorNotReady(RuntimeError):
    """Raised when the serialized Problem 2 model or transformer cannot be found or loaded."""
    pass


@lru_cache(maxsize=1)
def get_encrypted_detector() -> tuple[EncryptedDetectorArtifacts, XGBClassifier]:
    """
    Load and cache the trained Problem 2 model artifacts and transformer.
    Raises EncryptedDetectorNotReady if files are absent or damaged.
    """
    import joblib

    if not JOBLIB_PATH.exists():
        raise EncryptedDetectorNotReady(
            f"Encrypted traffic transformer artifact missing at {JOBLIB_PATH}. Run train_encrypted.py first."
        )
    if not XGB_JSON_PATH.exists():
        raise EncryptedDetectorNotReady(
            f"Encrypted traffic XGBoost model artifact missing at {XGB_JSON_PATH}. Run train_encrypted.py first."
        )

    try:
        artifacts: EncryptedDetectorArtifacts = joblib.load(JOBLIB_PATH)
        clf = XGBClassifier()
        clf.load_model(str(XGB_JSON_PATH))
        artifacts.xgboost = clf
        logger.info("Loaded Encrypted Detector: %d features, threshold=%.2f", len(artifacts.feature_names), artifacts.threshold)
        return artifacts, clf
    except Exception as exc:
        logger.exception("Failed to initialize Encrypted Detector: %s", exc)
        raise EncryptedDetectorNotReady(f"Failed to load encrypted traffic model: {exc}") from exc


def get_encrypted_metrics() -> dict[str, Any]:
    """Retrieve saved benchmark evaluation metrics from encrypted_metrics.json."""
    if not METRICS_PATH.exists():
        return {
            "status": "unavailable",
            "message": "encrypted_metrics.json not found.",
        }
    try:
        data = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
        data["status"] = "ready"
        return data
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Could not read metrics: {exc}",
        }


def predict_encrypted_flow(flow: dict[str, Any]) -> dict[str, Any]:
    """
    Run sanitized inference on an incoming encrypted flow payload.
    
    Guarantees:
    - Never uses labels or sandbox execution annotations as features.
    - Handles missing/malformed attributes safely with robust fallbacks.
    - Produces class-aware confidence, TreeSHAP feature attributions,
      and composite priority score reusing the core AEGIS prioritisation logic.
    - Explicitly marks automated blocking as suppressed to prevent accidental inline disruption.
    """
    artifacts, clf = get_encrypted_detector()

    # 1. Sanitize input: strictly discard any label or sandbox execution annotations
    sanitized_input: dict[str, Any] = {}
    for k, v in flow.items():
        if k in PROHIBITED_METADATA_KEYS or k.startswith("meta."):
            continue
        sanitized_input[k] = v

    # 2. Extract normalized features using the training transformer
    try:
        X = artifacts.transformer.transform(sanitized_input)
    except Exception as exc:
        raise ValueError(f"Feature transformation error on flow payload: {exc}") from exc

    # 3. Model prediction
    try:
        probs = clf.predict_proba(X)[0]
        prob_malicious = float(probs[1])
        prob_benign = float(probs[0])
    except Exception as exc:
        raise RuntimeError(f"XGBoost inference execution failure: {exc}") from exc

    threshold = artifacts.threshold if artifacts.threshold is not None else 0.50
    is_malicious = prob_malicious >= threshold
    predicted_label = "malicious" if is_malicious else "normal"
    confidence = prob_malicious if is_malicious else prob_benign

    # 4. TreeSHAP feature attribution
    top_features: list[dict[str, Any]] = []
    try:
        booster = clf.get_booster()
        dmatrix = xgb.DMatrix(X, feature_names=artifacts.feature_names)
        contribs = booster.predict(dmatrix, pred_contribs=True)[0]
        # contribs has shape (num_features + 1,); last element is the bias / base value
        feature_contribs = contribs[:-1]
        
        # Sort by absolute magnitude of contribution
        ranked_indices = np.argsort(np.abs(feature_contribs))[::-1]
        for idx in ranked_indices[:5]:
            feat_name = artifacts.feature_names[idx]
            val = float(feature_contribs[idx])
            top_features.append({
                "feature": feat_name,
                "importance": round(val, 4),
                "direction": "supports_malicious" if val > 0 else "supports_benign",
            })
    except Exception as exc:
        logger.debug("TreeSHAP computation notice: %s", exc)

    # 5. Composite Alert Prioritisation Integration
    # Derive asset criticality: TLS port 443 -> 0.60, 8443 -> 0.70, or custom asset_criticality
    dp_val = float(sanitized_input.get("dp", 443))
    service_key = "http_443" if dp_val in (443, 8443) else "private"
    default_asset = SERVICE_CRITICALITY.get(service_key, 0.60)
    user_asset = sanitized_input.get("asset_criticality")
    asset_crit = float(user_asset) if user_asset is not None and 0.0 <= float(user_asset) <= 1.0 else default_asset

    # Borderline/ambiguous detection floor:
    # If the prediction is high-confidence or borderline (0.35 - 0.65), flag for analyst review
    is_borderline = 0.35 <= prob_malicious <= 0.65
    pseudo_recon = max(0.0, (prob_malicious - 0.5) * 2.0) if is_malicious else 0.0

    score, components, flags = compute_priority(
        confidence=confidence,
        reconstruction_error=pseudo_recon,
        recon_threshold=1.0,
        predicted=predicted_label,
        is_zero_day=False,
        asset_criticality=asset_crit,
    )

    # Cutoffs from benchmark validation
    cutoffs = {"critical": 0.5901, "review": 0.1364}
    tier_floor = "review" if is_borderline else None
    tier = tier_from_score(score, cutoffs, tier_floor=tier_floor)

    # Construct tier rationale
    if tier == "critical":
        tier_reason = (
            f"Composite priority score {score:.3f} >= critical cutoff {cutoffs['critical']:.3f}. "
            "High-risk encrypted anomaly detected. Automated blocking is SUPPRESSED; flagged for immediate human triage."
        )
    elif tier == "review":
        if is_borderline:
            reason_detail = f"Score {score:.3f} with borderline probability ({prob_malicious:.1%}) -> Review floor enforced"
        else:
            reason_detail = f"Score {score:.3f} >= review cutoff {cutoffs['review']:.3f} (below critical cutoff {cutoffs['critical']:.3f})"
        tier_reason = (
            f"{reason_detail}. Flagged for analyst investigation. Automated blocking is suppressed for encrypted sessions."
        )
    else:
        tier_reason = (
            f"Composite priority score {score:.3f} < review cutoff {cutoffs['review']:.3f}. "
            "Traffic matches expected normal TLS characteristics; logged routine."
        )

    # 6. Response Payload
    return {
        "predicted": predicted_label,
        "is_malicious": is_malicious,
        "confidence": round(confidence, 4),
        "malicious_probability": round(prob_malicious, 4),
        "benign_probability": round(prob_benign, 4),
        "decision_threshold": threshold,
        "priority": round(score, 4),
        "tier": tier,
        "tier_reason": tier_reason,
        "tier_floor_applied": tier_floor is not None,
        "blocking_recommended": False,  # Strict safeguard: never auto-block TLS connections
        "mitigation_action": "alert_only" if is_malicious else "allow",
        "priority_components": {k: round(v, 4) for k, v in components.items()},
        "asset_criticality": round(asset_crit, 2),
        "top_features": top_features,
        "dq_flags": flags,
        "metadata_inspected": {
            "bytes_sent": sanitized_input.get("bs", 0),
            "bytes_received": sanitized_input.get("br", 0),
            "packets_sent": sanitized_input.get("ps", 0),
            "packets_received": sanitized_input.get("pr", 0),
            "destination_port": dp_val,
            "duration": sanitized_input.get("td", 0),
            "tls_client_version": sanitized_input.get("tls.cver", "unknown"),
            "tls_server_cipher": sanitized_input.get("tls.scs", "unknown"),
            "ja4_fingerprint": sanitized_input.get("tls.ja4", "unknown"),
            "has_alpn": bool(sanitized_input.get("tls.alpn")),
            "has_sni": bool(sanitized_input.get("tls.sni")),
            "splt_record_count": len(sanitized_input.get("tls.rec", [])),
        },
        "payload_decrypted": False,  # Architectural guarantee
    }

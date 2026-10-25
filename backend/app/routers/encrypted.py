"""
AEGIS Problem 2: Encrypted Traffic Analysis API Router.
Provides endpoints for feature schema/presets, benchmark metrics,
single-connection TLS threat prediction, and alert storage.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from app.db import store_alert
from app.ml.encrypted_detector import (
    ENCRYPTED_PRESETS,
    EncryptedDetectorNotReady,
    get_encrypted_detector,
    get_encrypted_metrics,
    predict_encrypted_flow,
)
from app.ml.encrypted_features import (
    CATEGORICAL_COLS,
    FLOW_NUMERICAL_COLS,
    SPLT_RECORD_COLS,
)

logger = logging.getLogger("aegis.encrypted_router")
router = APIRouter(prefix="/encrypted", tags=["encrypted"])


class EncryptedFlowPayload(BaseModel):
    """
    Validated network flow payload representing observable TLS/QUIC connection metadata.
    Does not require or accept plaintext payloads.
    """
    # Transport Dynamics
    bs: float = Field(default=0.0, ge=0.0, description="Bytes sent (client to server)")
    br: float = Field(default=0.0, ge=0.0, description="Bytes received (server to client)")
    ps: float = Field(default=0.0, ge=0.0, description="Packets sent")
    pr: float = Field(default=0.0, ge=0.0, description="Packets received")
    td: float = Field(default=0.0, ge=0.0, description="Duration in seconds")
    dp: float = Field(default=443.0, ge=1.0, le=65535.0, description="Destination port")

    # TLS Handshake Observable Metadata
    tls_ccs: list[str] | None = Field(default=None, alias="tls.ccs", description="Offered cipher suites")
    tls_cext: list[str] | None = Field(default=None, alias="tls.cext", description="Client extension codes")
    tls_csg: list[str] | None = Field(default=None, alias="tls.csg", description="Client signature algorithms")
    tls_sext: list[str] | None = Field(default=None, alias="tls.sext", description="Server extension codes")
    tls_alpn: list[str] | None = Field(default=None, alias="tls.alpn", description="Negotiated ALPN protocols")
    tls_sni: str | None = Field(default=None, alias="tls.sni", description="Server Name Indication hostname")
    tls_cver: str | None = Field(default=None, alias="tls.cver", description="Client TLS record version")
    tls_scs: str | None = Field(default=None, alias="tls.scs", description="Server chosen cipher suite")
    tls_ja4: str | None = Field(default=None, alias="tls.ja4", description="JA4 TLS client fingerprint")

    # Sequence of Packet Length and Time (SPLT): first 20 signed TLS record lengths
    tls_rec: list[int | float] | None = Field(default=None, alias="tls.rec", description="Signed record lengths sequence")

    # Optional SOC asset context
    asset_criticality: float | None = Field(default=None, ge=0.0, le=1.0, description="Asset criticality in [0, 1]")
    src: str | None = Field(default=None, description="Source IP address")
    dst: str | None = Field(default=None, description="Destination IP address")

    model_config = ConfigDict(
        extra="allow",
        populate_by_name=True,
    )


@router.get("/schema")
def schema():
    """
    Returns the exact feature schema required by the encrypted detector,
    accompanied by synthetic demonstration presets.
    All presets are strictly labeled as synthetic examples, not live observations.
    """
    try:
        artifacts, _ = get_encrypted_detector()
        feature_count = len(artifacts.feature_names)
        feature_names = artifacts.feature_names
        status_code = "ready"
    except EncryptedDetectorNotReady as exc:
        feature_count = 71
        feature_names = []
        status_code = f"unready: {exc}"

    return {
        "status": status_code,
        "model_architecture": "Gradient-Boosted Trees (XGBoost) over Flow + Handshake + SPLT",
        "feature_count": feature_count,
        "feature_names": feature_names,
        "raw_inputs": {
            "flow_transport": FLOW_NUMERICAL_COLS,
            "splt_sequence": SPLT_RECORD_COLS,
            "protocol_fingerprints": CATEGORICAL_COLS,
        },
        "presets": ENCRYPTED_PRESETS,
        "disclaimer": "Presets are synthetic demonstration examples, not live observations.",
    }


@router.get("/metrics")
def metrics():
    """
    Returns the audited primary benchmark metrics, feature ablation comparison,
    and slice evaluation results from encrypted_metrics.json.
    These represent fixed offline benchmark evaluations on holdout data.
    """
    data = get_encrypted_metrics()
    if data.get("status") == "unavailable":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Benchmark metrics artifact encrypted_metrics.json is not yet generated.",
        )
    return data


@router.get("/live-status")
def live_status():
    """
    Reports the real-time operational status of the encrypted network ingestion pipeline.
    Live packet capture is disconnected in Phase 2; offline feature extraction and replay are supported.
    """
    return {
        "connected": False,
        "status": "disconnected",
        "mode": "synthetic_and_batch_only",
        "live_pcap_supported": False,
        "active_interface": None,
        "message": "Live network interface capture is disconnected. System is operating in demonstration and API ingestion mode.",
    }


@router.post("/detect")
def detect_flow(payload: EncryptedFlowPayload):
    """
    Classifies a single encrypted connection based on observable flow and TLS handshake metadata.
    Generates class-aware confidence, TreeSHAP attributions, composite priority score,
    and records an incident alert in Elasticsearch.
    """
    raw_dict = payload.model_dump(by_alias=True)

    try:
        result = predict_encrypted_flow(raw_dict)
    except EncryptedDetectorNotReady as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(val_err)) from val_err
    except Exception as exc:
        logger.exception("Unexpected error during encrypted traffic prediction: %s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Prediction failed: {exc}") from exc

    # Ingest prediction as an alert into Elasticsearch using the compatible schema
    alert_id = str(raw_dict.get("id") or f"ALT-TLS-{uuid4().hex[:8].upper()}")
    now_iso = datetime.now(timezone.utc).isoformat()
    dp = float(raw_dict.get("dp", 443))

    alert_doc = {
        "id": alert_id,
        "timestamp": now_iso,
        "created_at": now_iso,
        "src": str(raw_dict.get("src") or "192.168.1.105"),
        "dst": str(raw_dict.get("dst") or "104.21.48.12"),
        "protocol": "tls",
        "service": "https" if dp in (443, 8443) else f"port_{int(dp)}",
        "true_label": "unknown",  # Do not fabricate or claim ground truth
        "predicted": result["predicted"],
        "known_label": "malicious_tls" if result["is_malicious"] else "benign_tls",
        "confidence": float(result["confidence"]),
        "reconstruction_error": 0.0,
        "is_zero_day": False,
        "severity": "high" if result["is_malicious"] and result["confidence"] >= 0.85 else ("medium" if result["is_malicious"] else "low"),
        "priority": float(result["priority"]),
        "tier": result["tier"],
        "priority_components": result.get("priority_components", {}),
        "asset_criticality": float(result.get("asset_criticality", 0.6)),
        "asset_criticality_known": True,
        "tier_reason": result.get("tier_reason", ""),
        "rationale": "Observable TLS handshake & SPLT metadata inference without payload decryption.",
        "tier_floor_applied": bool(result.get("tier_floor_applied")),
        "dq_flags": result.get("dq_flags", []),
        "flow": {
            "bs": raw_dict.get("bs", 0),
            "br": raw_dict.get("br", 0),
            "ps": raw_dict.get("ps", 0),
            "pr": raw_dict.get("pr", 0),
            "dp": dp,
            "td": raw_dict.get("td", 0),
            "tls_cver": str(raw_dict.get("tls.cver") or raw_dict.get("tls_cver") or "unknown"),
            "tls_scs": str(raw_dict.get("tls.scs") or raw_dict.get("tls_scs") or "unknown"),
            "tls_ja4": str(raw_dict.get("tls.ja4") or raw_dict.get("tls_ja4") or "unknown"),
            "tls.cver": str(raw_dict.get("tls.cver") or raw_dict.get("tls_cver") or "unknown"),
            "tls.scs": str(raw_dict.get("tls.scs") or raw_dict.get("tls_scs") or "unknown"),
            "tls.ja4": str(raw_dict.get("tls.ja4") or raw_dict.get("tls_ja4") or "unknown"),
            "tls.sni": raw_dict.get("tls.sni") or raw_dict.get("tls_sni") or "",
            "tls.alpn": raw_dict.get("tls.alpn") or raw_dict.get("tls_alpn") or [],
            "tls.ccs": raw_dict.get("tls.ccs") or raw_dict.get("tls_ccs") or [],
            "tls.rec": raw_dict.get("tls.rec") or raw_dict.get("tls_rec") or [],
        },
        "top_features": result.get("top_features", []),
        "anomaly_features": [],
    }

    try:
        store_alert(alert_doc, refresh=True)
        result["id"] = alert_id
        result["saved_to_db"] = True
        result["db_status"] = "stored"
    except Exception as db_err:
        logger.warning("Could not persist encrypted alert to Elasticsearch: %s", db_err)
        result["id"] = alert_id
        result["saved_to_db"] = False
        result["db_status"] = f"offline: {db_err}"

    return result


@router.post("/analyze-pcap")
def analyze_pcap():
    """
    Explicitly documents that arbitrary PCAP live dissection is unsupported in Phase 2.
    Feature extraction requires connection-level TLS metadata (SPLT sequence, ClientHello/ServerHello
    extension counts, cipher suites). Payloads are not decrypted.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            "PCAP live packet extraction is unsupported in Phase 2. "
            "Feature extraction requires pre-extracted connection-level TLS metadata "
            "(SPLT sequence, ClientHello/ServerHello extensions, cipher suites). "
            "Live traffic capture and PCAP packet dissection are deferred to a dedicated live capture pipeline. "
            "TLS payloads are never decrypted."
        ),
    )

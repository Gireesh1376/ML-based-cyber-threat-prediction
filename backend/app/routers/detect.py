from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.config import FEATURE_COLUMNS
from app.ml.detector import DetectorNotReady, load_demo_alerts, predict_payload

router = APIRouter(tags=["detect"])


class FlowPayload(BaseModel):
    # Optional Problem-3 fields: analysts may declare the criticality of the
    # targeted asset directly (documented [0, 1] scale) or a plain-text
    # service name not present in the trained feature columns. If omitted,
    # SERVICE_CRITICALITY[service] is used, with a Review tier floor for
    # unknown assets (never silently low risk).
    asset_criticality: float | None = Field(default=None, ge=0.0, le=1.0)

    duration: float = 0
    protocol_type: str = "tcp"
    service: str = "http"
    flag: str = "SF"
    src_bytes: float = 0
    dst_bytes: float = 0
    land: int = 0
    wrong_fragment: int = 0
    urgent: int = 0
    hot: int = 0
    num_failed_logins: int = 0
    logged_in: int = 0
    num_compromised: int = 0
    root_shell: int = 0
    su_attempted: int = 0
    num_root: int = 0
    num_file_creations: int = 0
    num_shells: int = 0
    num_access_files: int = 0
    num_outbound_cmds: int = 0
    is_host_login: int = 0
    is_guest_login: int = 0
    count: float = 1
    srv_count: float = 1
    serror_rate: float = 0
    srv_serror_rate: float = 0
    rerror_rate: float = 0
    srv_rerror_rate: float = 0
    same_srv_rate: float = 1
    diff_srv_rate: float = 0
    srv_diff_host_rate: float = 0
    dst_host_count: float = 1
    dst_host_srv_count: float = 1
    dst_host_same_srv_rate: float = 1
    dst_host_diff_srv_rate: float = 0
    dst_host_same_src_port_rate: float = 0
    dst_host_srv_diff_host_rate: float = 0
    dst_host_serror_rate: float = 0
    dst_host_srv_serror_rate: float = 0
    dst_host_rerror_rate: float = 0
    dst_host_srv_rerror_rate: float = 0

    model_config = ConfigDict(extra="allow")


class BatchPayload(BaseModel):
    flows: list[dict[str, Any]] = Field(default_factory=list)


PRESETS = {
    "benign_web": {
        "duration": 2,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 280,
        "dst_bytes": 4200,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 1,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 4,
        "srv_count": 4,
        "serror_rate": 0.0,
        "srv_serror_rate": 0.0,
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": 40,
        "dst_host_srv_count": 38,
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    },
    "known_dos": {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "private",
        "flag": "S0",
        "src_bytes": 0,
        "dst_bytes": 0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 0,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 180,
        "srv_count": 18,
        "serror_rate": 1.0,
        "srv_serror_rate": 1.0,
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": 0.1,
        "diff_srv_rate": 0.06,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": 255,
        "dst_host_srv_count": 18,
        "dst_host_same_srv_rate": 0.05,
        "dst_host_diff_srv_rate": 0.07,
        "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 1.0,
        "dst_host_srv_serror_rate": 1.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    },
    "probe_scan": {
        "duration": 0,
        "protocol_type": "icmp",
        "service": "eco_i",
        "flag": "SF",
        "src_bytes": 8,
        "dst_bytes": 0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 0,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 1,
        "srv_count": 1,
        "serror_rate": 0.0,
        "srv_serror_rate": 0.0,
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": 1,
        "dst_host_srv_count": 1,
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 1.0,
        "dst_host_srv_diff_host_rate": 0.5,
        "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    },
    "zero_day_like": {
        # Calibrated against the trained model to exercise the novel-threat gate:
        # XGBoost finds no confident known family and the autoencoder reconstruction
        # error lands far above the benign baseline, so the flow is promoted to
        # zero_day instead of being forced into a known class.
        "duration": 0,
        "protocol_type": "tcp",
        "service": "tftp_u",
        "flag": "SH",
        "src_bytes": 15,
        "dst_bytes": 0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 0,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 2,
        "srv_count": 2,
        "serror_rate": 0.0,
        "srv_serror_rate": 0.0,
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": 0.5,
        "diff_srv_rate": 0.5,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": 10,
        "dst_host_srv_count": 5,
        "dst_host_same_srv_rate": 0.4,
        "dst_host_diff_srv_rate": 0.6,
        "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    },
}


@router.get("/detect/schema")
def schema():
    return {"features": FEATURE_COLUMNS, "presets": PRESETS}


@router.post("/detect")
def detect(payload: FlowPayload):
    try:
        return predict_payload(payload.model_dump())
    except DetectorNotReady as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/detect/batch")
def detect_batch(payload: BatchPayload):
    try:
        return {"results": [predict_payload(flow) for flow in payload.flows[:50]]}
    except DetectorNotReady as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/detect/replay/{alert_id}")
def replay(alert_id: str):
    alerts = load_demo_alerts()
    match = next((a for a in alerts if a["id"] == alert_id), None)
    if not match:
        raise HTTPException(status_code=404, detail="Alert not found")
    flow = match.get("flow")
    if flow:
        # Exact replay: the alert carries its full feature payload.
        result = predict_payload(dict(flow))
    else:
        # Legacy alerts without a stored payload: fall back to the closest preset.
        preset_key = "benign_web" if match["predicted"] == "normal" else "known_dos"
        if match.get("is_zero_day"):
            preset_key = "zero_day_like"
        result = predict_payload(dict(PRESETS[preset_key]))
    result["replayed_from"] = alert_id
    return result

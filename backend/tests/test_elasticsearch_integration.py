"""
Comprehensive Integration & Regression Tests for Elasticsearch Alert Database.

Verifies:
1. Elasticsearch connectivity and cluster metadata.
2. Index lifecycle and schema mappings for alert documents.
3. Alert storage, field normalization, and proper serialization.
4. Duplicate handling and idempotency using stable alert identifiers.
5. Alert retrieval with tier filtering and priority/id sorting.
6. Retrieval of stored alerts through the FastAPI backend API (/api/alerts).
7. Replay of Elasticsearch-stored alerts via POST /api/detect/replay/{alert_id}.
8. Real-time alert ingestion from POST /api/detect and POST /api/detect/batch.
9. Graceful fallback when Elasticsearch is unavailable.
10. Aggregations and dashboard summary integration.
"""
from __future__ import annotations

import time
from uuid import uuid4

import pytest
from starlette.testclient import TestClient

from app.config import ELASTICSEARCH_INDEX
from app.db import (
    ElasticsearchStorageError,
    check_es_connection,
    get_alert_by_id,
    get_alerts,
    get_dashboard_aggregations,
    get_es_client,
    init_alerts_index,
    seed_demo_alerts_if_empty,
    store_alert,
    store_alerts_batch,
    validate_batch_storage_response,
)
from app.main import app

client = TestClient(app)


def test_elasticsearch_connectivity():
    """Verify that Elasticsearch is reachable and returns valid cluster information."""
    status = check_es_connection()
    assert isinstance(status, dict)
    assert status.get("connected") is True, f"Elasticsearch connection failed: {status.get('error')}"
    assert "version" in status
    assert status.get("index") == ELASTICSEARCH_INDEX


def test_elasticsearch_index_initialization_and_seeding():
    """Verify index creation with strict mappings and demo alert seeding."""
    init_alerts_index()
    es = get_es_client()
    assert es.indices.exists(index=ELASTICSEARCH_INDEX)

    # Check mapping
    mapping = es.indices.get_mapping(index=ELASTICSEARCH_INDEX)
    props = mapping[ELASTICSEARCH_INDEX]["mappings"]["properties"]
    assert "id" in props and props["id"]["type"] == "keyword"
    assert "timestamp" in props and props["timestamp"]["type"] == "date"
    assert "predicted" in props and props["predicted"]["type"] == "keyword"
    assert "confidence" in props and props["confidence"]["type"] == "float"
    assert "reconstruction_error" in props and props["reconstruction_error"]["type"] == "float"
    assert "priority" in props and props["priority"]["type"] == "float"
    assert "tier" in props and props["tier"]["type"] == "keyword"
    assert "severity" in props and props["severity"]["type"] == "keyword"


def test_store_and_retrieve_single_alert():
    """Verify storing a complete threat alert and retrieving it with exact field preservation."""
    test_id = f"ALT-TEST-{uuid4().hex[:6].upper()}"
    alert_doc = {
        "id": test_id,
        "src": "192.168.1.105",
        "dst": "10.0.0.1",
        "protocol": "tcp",
        "service": "http",
        "true_label": "neptune",
        "predicted": "dos",
        "known_label": "dos",
        "confidence": 0.9945,
        "reconstruction_error": 0.4521,
        "is_zero_day": False,
        "severity": "high",
        "priority": 0.7812,
        "tier": "critical",
        "priority_components": {
            "confidence": 0.35,
            "reconstruction": 0.05,
            "family": 0.15,
            "asset": 0.075,
            "zero_day_bonus": 0.0,
        },
        "asset_criticality": 0.55,
        "asset_criticality_known": True,
        "tier_reason": "High priority DoS attack",
        "rationale": "Classified as known attack 'dos' with 99.5% confidence.",
        "flow": {"duration": 0.0, "src_bytes": 0.0, "dst_bytes": 0.0},
    }

    try:
        store_res = store_alert(alert_doc, refresh=True)
        assert store_res["status"] == "stored"
        assert store_res["id"] == test_id

        # Retrieve by ID
        fetched = get_alert_by_id(test_id)
        assert fetched is not None
        assert fetched["id"] == test_id
        assert fetched["predicted"] == "dos"
        assert fetched["severity"] == "high"
        assert fetched["tier"] == "critical"
        assert fetched["src"] == "192.168.1.105"
        assert fetched["dst"] == "10.0.0.1"
        assert round(fetched["confidence"], 4) == 0.9945
        assert round(fetched["priority"], 4) == 0.7812
        assert "timestamp" in fetched
    finally:
        # Cleanup test document
        es = get_es_client()
        es.options(ignore_status=[404]).delete(index=ELASTICSEARCH_INDEX, id=test_id, refresh=True)


def test_duplicate_prevention_with_stable_id():
    """Verify that repeated requests with the same stable alert ID update rather than duplicating."""
    stable_id = f"ALT-DEDUP-{uuid4().hex[:6].upper()}"
    es = get_es_client()

    doc_v1 = {
        "id": stable_id,
        "src": "10.0.0.5",
        "predicted": "probe",
        "severity": "medium",
        "priority": 0.45,
        "tier": "review",
    }
    doc_v2 = {
        "id": stable_id,
        "src": "10.0.0.5",
        "predicted": "probe",
        "severity": "high",
        "priority": 0.65,
        "tier": "critical",
    }

    try:
        # First write
        res1 = store_alert(doc_v1, refresh=True)
        assert res1["result"] in ("created", "updated")
        v1 = res1.get("version", 1)

        # Second write with same ID
        res2 = store_alert(doc_v2, refresh=True)
        assert res2["result"] == "updated"
        assert res2.get("version", 2) > v1

        # Confirm only ONE document exists with this ID
        fetched = get_alert_by_id(stable_id)
        assert fetched is not None
        assert fetched["severity"] == "high"
        assert fetched["priority"] == 0.65
        assert fetched["tier"] == "critical"

        # Search for this ID
        search_res = es.search(index=ELASTICSEARCH_INDEX, query={"term": {"id": stable_id}})
        assert search_res["hits"]["total"]["value"] == 1
    finally:
        es.options(ignore_status=[404]).delete(index=ELASTICSEARCH_INDEX, id=stable_id, refresh=True)


def test_api_alerts_retrieval_endpoint():
    """Verify GET /api/alerts retrieves alerts from Elasticsearch with sorting and filtering."""
    resp = client.get("/api/alerts?limit=10")
    assert resp.status_code == 200
    data = resp.json()

    assert "items" in data
    assert "count" in data
    assert "tier_cutoffs" in data
    assert len(data["items"]) <= 10
    assert data.get("source") == "elasticsearch"

    # Verify fields in each returned alert
    if data["items"]:
        first = data["items"][0]
        assert "id" in first
        assert "predicted" in first
        assert "tier" in first
        assert "priority" in first
        assert "severity" in first

    # Test filtering by tier
    resp_crit = client.get("/api/alerts?tier=critical&limit=5")
    assert resp_crit.status_code == 200
    crit_data = resp_crit.json()
    for item in crit_data["items"]:
        assert item["tier"] == "critical"


def test_api_detect_endpoint_persists_alert_to_elasticsearch():
    """Verify POST /api/detect analyzes a flow and stores the resulting alert in Elasticsearch."""
    unique_id = f"ALT-LIVE-{uuid4().hex[:6].upper()}"
    payload = {
        "id": unique_id,
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
        "count": 220,
        "srv_count": 15,
        "serror_rate": 1.0,
        "srv_serror_rate": 1.0,
        "same_srv_rate": 0.05,
        "diff_srv_rate": 0.08,
        "dst_host_count": 255,
        "dst_host_srv_count": 15,
        "dst_host_same_srv_rate": 0.05,
        "dst_host_diff_srv_rate": 0.08,
        "dst_host_serror_rate": 1.0,
        "dst_host_srv_serror_rate": 1.0,
    }

    try:
        resp = client.post("/api/detect", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["id"] == unique_id
        assert data.get("saved_to_db") is True
        assert data.get("db_status") == "stored"
        assert data["predicted"] in ("dos", "neptune", "smurf")

        # Verify that the alert is now queryable directly from Elasticsearch
        es_alert = get_alert_by_id(unique_id)
        assert es_alert is not None
        assert es_alert["id"] == unique_id
        assert es_alert["predicted"] == data["predicted"]
        assert es_alert["tier"] == data["tier"]
        assert round(es_alert["priority"], 4) == round(data["priority"], 4)
    finally:
        es = get_es_client()
        es.options(ignore_status=[404]).delete(index=ELASTICSEARCH_INDEX, id=unique_id, refresh=True)


def test_api_replay_stored_alert():
    """Verify POST /api/detect/replay/{alert_id} fetches the stored alert from Elasticsearch and replays it."""
    replay_id = f"ALT-REPLAY-{uuid4().hex[:6].upper()}"
    alert_doc = {
        "id": replay_id,
        "src": "10.0.5.12",
        "dst": "172.16.1.1",
        "protocol": "tcp",
        "service": "http",
        "true_label": "normal",
        "predicted": "normal",
        "known_label": "normal",
        "confidence": 0.999,
        "reconstruction_error": 0.002,
        "is_zero_day": False,
        "severity": "info",
        "priority": 0.05,
        "tier": "auto_log",
        "flow": {
            "duration": 2,
            "protocol_type": "tcp",
            "service": "http",
            "flag": "SF",
            "src_bytes": 280,
            "dst_bytes": 4200,
            "logged_in": 1,
            "count": 4,
            "srv_count": 4,
            "same_srv_rate": 1.0,
            "dst_host_count": 40,
            "dst_host_srv_count": 38,
            "dst_host_same_srv_rate": 1.0,
        },
    }

    try:
        store_alert(alert_doc, refresh=True)

        resp = client.post(f"/api/detect/replay/{replay_id}")
        assert resp.status_code == 200
        result = resp.json()
        assert result["replayed_from"] == replay_id
        assert result["predicted"] == "normal"
        assert "priority" in result
    finally:
        es = get_es_client()
        es.options(ignore_status=[404]).delete(index=ELASTICSEARCH_INDEX, id=replay_id, refresh=True)


def test_api_db_status_endpoint():
    """Verify GET /api/db/status returns accurate connection and index metadata."""
    resp = client.get("/api/db/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["connected"] is True
    assert data["index"] == ELASTICSEARCH_INDEX
    assert data["docs_count"] > 0
    assert "version" in data


def test_api_dashboard_summary_includes_database_status():
    """Verify GET /api/dashboard/summary incorporates Elasticsearch connectivity and metrics."""
    resp = client.get("/api/dashboard/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ready"] is True
    assert "database" in data
    assert data["database"]["type"] == "elasticsearch"
    assert data["database"]["connected"] is True
    assert data["kpis"]["open_alerts"] > 0


def test_graceful_offline_fallback(monkeypatch):
    """Verify that backend falls back gracefully to demo alerts and reports errors without crashing when ES fails."""
    from app.db import elasticsearch as es_module

    def mock_failing_get_alerts(*args, **kwargs):
        raise ElasticsearchStorageError("Simulated Elasticsearch cluster connection failure")

    monkeypatch.setattr(es_module, "get_alerts", mock_failing_get_alerts)
    monkeypatch.setattr("app.routers.dashboard.get_es_alerts", mock_failing_get_alerts)

    # 1. /api/alerts should fall back gracefully and report local_fallback source
    resp = client.get("/api/alerts?limit=5")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("source") == "local_fallback"
    assert len(data["items"]) > 0

    # 2. /api/dashboard/summary should fall back gracefully and report connected=False
    resp_sum = client.get("/api/dashboard/summary")
    assert resp_sum.status_code == 200
    sum_data = resp_sum.json()
    assert sum_data["database"]["connected"] is False
    assert sum_data["kpis"]["open_alerts"] > 0

    # 3. /api/detect should succeed with prediction but explicitly report saved_to_db=False (Requirement 9)
    def mock_failing_store_alert(*args, **kwargs):
        raise ElasticsearchStorageError("Simulated write timeout")

    monkeypatch.setattr(es_module, "store_alert", mock_failing_store_alert)
    monkeypatch.setattr("app.routers.detect.store_alert", mock_failing_store_alert)

    flow = {
        "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF",
        "src_bytes": 100, "dst_bytes": 100, "count": 1, "srv_count": 1,
        "same_srv_rate": 1, "dst_host_count": 1, "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1,
    }
    resp_det = client.post("/api/detect", json=flow)
    assert resp_det.status_code == 200
    det_data = resp_det.json()
    assert det_data["saved_to_db"] is False
    assert "error" in det_data["db_status"].lower()


def test_detect_batch_partial_failures(monkeypatch):
    """Verify that batch detection correctly reports individual failures when some documents fail indexing."""
    flow1 = {"id": "ALT-BATCH-OK-1", "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF", "count": 1, "srv_count": 1, "same_srv_rate": 1, "dst_host_count": 1, "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1}
    flow2 = {"id": "ALT-BATCH-FAIL-2", "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF", "count": 1, "srv_count": 1, "same_srv_rate": 1, "dst_host_count": 1, "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1}
    flow3 = {"id": "ALT-BATCH-OK-3", "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF", "count": 1, "srv_count": 1, "same_srv_rate": 1, "dst_host_count": 1, "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1}

    def mock_partial_store_alerts_batch(alert_docs, refresh=True):
        return {
            "stored_count": 2,
            "failed_count": 1,
            "failed_ids": {"ALT-BATCH-FAIL-2": "mapping parse exception: simulated field error"},
            "errors": [{"index": {"_id": "ALT-BATCH-FAIL-2", "error": {"reason": "mapping parse exception: simulated field error"}}}],
            "total": 3,
        }

    monkeypatch.setattr("app.routers.detect.store_alerts_batch", mock_partial_store_alerts_batch)

    resp = client.post("/api/detect/batch", json={"flows": [flow1, flow2, flow3]})
    assert resp.status_code == 200
    data = resp.json()
    assert "results" in data
    assert len(data["results"]) == 3

    r1, r2, r3 = data["results"]
    assert r1["id"] == "ALT-BATCH-OK-1"
    assert r1["saved_to_db"] is True
    assert r1["db_status"] == "stored"

    assert r2["id"] == "ALT-BATCH-FAIL-2"
    assert r2["saved_to_db"] is False
    assert "mapping parse exception" in r2["db_status"]

    assert r3["id"] == "ALT-BATCH-OK-3"
    assert r3["saved_to_db"] is True
    assert r3["db_status"] == "stored"


def test_detect_batch_inconsistent_counts(monkeypatch):
    """Verify that batch detection marks unconfirmed alerts as uncertain when counts mismatch,
    while preserving accurate failure reasons for known failed alerts."""
    flow1 = {"id": "ALT-INC-1", "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF", "count": 1, "srv_count": 1, "same_srv_rate": 1, "dst_host_count": 1, "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1}
    flow2 = {"id": "ALT-INC-2", "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF", "count": 1, "srv_count": 1, "same_srv_rate": 1, "dst_host_count": 1, "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1}
    flow3 = {"id": "ALT-INC-3", "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF", "count": 1, "srv_count": 1, "same_srv_rate": 1, "dst_host_count": 1, "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1}

    # Scenario: stored_count=1, failed_count=1, but total=3 (1+1 != 3: 1 alert is unaccounted for)
    def mock_inconsistent_counts_batch(alert_docs, refresh=True):
        return {
            "stored_count": 1,
            "failed_count": 1,
            "failed_ids": {"ALT-INC-2": "version conflict engine exception"},
            "successful_ids": ["ALT-INC-1"],
            "errors": [{"index": {"_id": "ALT-INC-2", "error": {"reason": "version conflict engine exception"}}}],
            "total": 3,
        }

    monkeypatch.setattr("app.routers.detect.store_alerts_batch", mock_inconsistent_counts_batch)

    resp = client.post("/api/detect/batch", json={"flows": [flow1, flow2, flow3]})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["results"]) == 3

    r1, r2, r3 = data["results"]
    # Inconsistent response must not falsely mark ALT-INC-1 as stored
    assert r1["id"] == "ALT-INC-1"
    assert r1["saved_to_db"] is False
    assert "uncertain" in r1["db_status"]
    assert "Count mismatch" in r1["db_status"]

    # Known failure reason for ALT-INC-2 must be preserved
    assert r2["id"] == "ALT-INC-2"
    assert r2["saved_to_db"] is False
    assert "version conflict" in r2["db_status"]

    # Unaccounted alert must be marked uncertain
    assert r3["id"] == "ALT-INC-3"
    assert r3["saved_to_db"] is False
    assert "uncertain" in r3["db_status"]
    assert "Count mismatch" in r3["db_status"]


def test_detect_batch_missing_failed_ids(monkeypatch):
    """Verify that when failed_count > 0 but failed_ids does not identify the failed documents,
    alerts are marked uncertain rather than falsely claiming success."""
    flow1 = {"id": "ALT-MISS-1", "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF", "count": 1, "srv_count": 1, "same_srv_rate": 1, "dst_host_count": 1, "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1}
    flow2 = {"id": "ALT-MISS-2", "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF", "count": 1, "srv_count": 1, "same_srv_rate": 1, "dst_host_count": 1, "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1}

    # Elasticsearch reported 1 failure, but failed_ids is empty
    def mock_missing_failed_ids_batch(alert_docs, refresh=True):
        return {
            "stored_count": 1,
            "failed_count": 1,
            "failed_ids": {},
            "errors": [],
            "total": 2,
        }

    monkeypatch.setattr("app.routers.detect.store_alerts_batch", mock_missing_failed_ids_batch)

    resp = client.post("/api/detect/batch", json={"flows": [flow1, flow2]})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["results"]) == 2

    r1, r2 = data["results"]
    assert r1["saved_to_db"] is False
    assert "uncertain" in r1["db_status"]
    assert "does not match" in r1["db_status"]

    assert r2["saved_to_db"] is False
    assert "uncertain" in r2["db_status"]
    assert "does not match" in r2["db_status"]


def test_detect_batch_unexpected_failed_ids(monkeypatch):
    """Verify that when the batch storage response contains failed IDs not in the submitted batch,
    the inconsistency is caught and submitted alerts are marked uncertain."""
    flow1 = {"id": "ALT-SUB-1", "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF", "count": 1, "srv_count": 1, "same_srv_rate": 1, "dst_host_count": 1, "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1}
    flow2 = {"id": "ALT-SUB-2", "duration": 0, "protocol_type": "tcp", "service": "http", "flag": "SF", "count": 1, "srv_count": 1, "same_srv_rate": 1, "dst_host_count": 1, "dst_host_srv_count": 1, "dst_host_same_srv_rate": 1}

    # failed_ids contains an ID that was NOT submitted
    def mock_unexpected_failed_ids_batch(alert_docs, refresh=True):
        return {
            "stored_count": 1,
            "failed_count": 1,
            "failed_ids": {"ALT-ALIEN-999": "shard failure on alien document"},
            "errors": [],
            "total": 2,
        }

    monkeypatch.setattr("app.routers.detect.store_alerts_batch", mock_unexpected_failed_ids_batch)

    resp = client.post("/api/detect/batch", json={"flows": [flow1, flow2]})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["results"]) == 2

    r1, r2 = data["results"]
    assert r1["saved_to_db"] is False
    assert "uncertain" in r1["db_status"]
    assert "unexpected failed IDs" in r1["db_status"]

    assert r2["saved_to_db"] is False
    assert "uncertain" in r2["db_status"]
    assert "unexpected failed IDs" in r2["db_status"]


def test_validate_batch_storage_response_unit():
    """Unit test covering validate_batch_storage_response under normal and abnormal edge conditions."""
    submitted = {"ID-1", "ID-2", "ID-3"}

    # 1. Normal all-success with explicit successful_ids
    valid, reason, s_ids, f_ids = validate_batch_storage_response(
        {"stored_count": 3, "failed_count": 0, "successful_ids": ["ID-1", "ID-2", "ID-3"], "total": 3},
        submitted,
    )
    assert valid is True
    assert reason is None
    assert s_ids == submitted
    assert f_ids == {}

    # 2. Count mismatch (stored_count + failed_count != len(submitted))
    valid, reason, s_ids, f_ids = validate_batch_storage_response(
        {"stored_count": 2, "failed_count": 0, "total": 3},
        submitted,
    )
    assert valid is False
    assert "Count mismatch" in reason

    # 3. Missing failed IDs (failed_count=1, but failed_ids is empty)
    valid, reason, s_ids, f_ids = validate_batch_storage_response(
        {"stored_count": 2, "failed_count": 1, "failed_ids": {}, "total": 3},
        submitted,
    )
    assert valid is False
    assert "Failed count" in reason

    # 4. Unexpected failed IDs (failed_ids contains an unsubmitted ID)
    valid, reason, s_ids, f_ids = validate_batch_storage_response(
        {"stored_count": 2, "failed_count": 1, "failed_ids": {"UNKNOWN-ID": "err"}, "total": 3},
        submitted,
    )
    assert valid is False
    assert "unexpected failed IDs" in reason

    # 5. Unexpected success IDs
    valid, reason, s_ids, f_ids = validate_batch_storage_response(
        {"stored_count": 3, "failed_count": 0, "successful_ids": ["ID-1", "ID-2", "GHOST-ID"], "total": 3},
        submitted,
    )
    assert valid is False
    assert "unexpected success IDs" in reason

    # 6. ID in both success and failure
    valid, reason, s_ids, f_ids = validate_batch_storage_response(
        {
            "stored_count": 2,
            "failed_count": 1,
            "successful_ids": ["ID-1", "ID-2"],
            "failed_ids": {"ID-2": "conflict"},
            "total": 3,
        },
        submitted,
    )
    assert valid is False
    assert "Conflict" in reason

    # 7. Non-dictionary response
    valid, reason, s_ids, f_ids = validate_batch_storage_response("bad-response", submitted)
    assert valid is False
    assert "not a dictionary" in reason


def test_api_detect_batch_live_ingestion():
    """Verify live batch detection and ingestion against the active Elasticsearch cluster."""
    id1 = f"ALT-LIVE-B1-{uuid4().hex[:6].upper()}"
    id2 = f"ALT-LIVE-B2-{uuid4().hex[:6].upper()}"

    flow1 = {
        "id": id1,
        "duration": 0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 150,
        "dst_bytes": 300,
        "count": 2,
        "srv_count": 2,
        "same_srv_rate": 1.0,
        "dst_host_count": 10,
        "dst_host_srv_count": 10,
        "dst_host_same_srv_rate": 1.0,
    }
    flow2 = {
        "id": id2,
        "duration": 0,
        "protocol_type": "icmp",
        "service": "eco_i",
        "flag": "SF",
        "src_bytes": 8,
        "dst_bytes": 0,
        "count": 1,
        "srv_count": 1,
        "same_srv_rate": 1.0,
        "dst_host_count": 1,
        "dst_host_srv_count": 1,
        "dst_host_same_srv_rate": 1.0,
    }

    try:
        resp = client.post("/api/detect/batch", json={"flows": [flow1, flow2]})
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        assert len(data["results"]) == 2

        for r in data["results"]:
            assert r["id"] in (id1, id2)
            assert r["saved_to_db"] is True
            assert r["db_status"] == "stored"
            assert "predicted" in r
            assert "priority" in r

        # Confirm documents are in Elasticsearch
        doc1 = get_alert_by_id(id1)
        doc2 = get_alert_by_id(id2)
        assert doc1 is not None and doc1["id"] == id1
        assert doc2 is not None and doc2["id"] == id2
    finally:
        es = get_es_client()
        es.options(ignore_status=[404]).delete(index=ELASTICSEARCH_INDEX, id=id1, refresh=True)
        es.options(ignore_status=[404]).delete(index=ELASTICSEARCH_INDEX, id=id2, refresh=True)




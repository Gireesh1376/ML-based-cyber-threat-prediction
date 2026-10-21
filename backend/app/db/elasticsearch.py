
"""
Elasticsearch Database Adapter for AEGIS Cyber-Threat Prediction.
Handles connection management, index creation with strict mappings, document
storage, deduplication, queries, aggregations, and graceful offline fallback.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any
from uuid import uuid4

from elasticsearch import ApiError, ConnectionError as ESConnectionError, Elasticsearch, NotFoundError
from elasticsearch.helpers import bulk, streaming_bulk

from app.config import (
    ALERTS_PATH,
    ELASTICSEARCH_API_KEY,
    ELASTICSEARCH_INDEX,
    ELASTICSEARCH_PASSWORD,
    ELASTICSEARCH_URL,
    ELASTICSEARCH_USER,
    ELASTICSEARCH_VERIFY_CERTS,
)

logger = logging.getLogger("aegis.db")

# ---------------------------------------------------------------------------
# Index Schema & Mappings
# ---------------------------------------------------------------------------
ALERT_INDEX_MAPPING: dict[str, Any] = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "index.mapping.total_fields.limit": 2000,
    },
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "created_at": {"type": "date"},
            "src": {"type": "keyword"},
            "dst": {"type": "keyword"},
            "protocol": {"type": "keyword"},
            "service": {"type": "keyword"},
            "true_label": {"type": "keyword"},
            "predicted": {"type": "keyword"},
            "known_label": {"type": "keyword"},
            "confidence": {"type": "float"},
            "reconstruction_error": {"type": "float"},
            "is_zero_day": {"type": "boolean"},
            "severity": {"type": "keyword"},
            "priority": {"type": "float"},
            "tier": {"type": "keyword"},
            "priority_components": {
                "type": "object",
                "dynamic": True,
            },
            "asset_criticality": {"type": "float"},
            "asset_criticality_known": {"type": "boolean"},
            "tier_reason": {"type": "text"},
            "rationale": {"type": "text"},
            "tier_floor_applied": {"type": "boolean"},
            "dq_flags": {"type": "keyword"},
            "flow": {
                "type": "object",
                "dynamic": True,
            },
            "top_features": {
                "type": "object",
                "dynamic": True,
            },
            "anomaly_features": {
                "type": "object",
                "dynamic": True,
            },
        }
    },
}


class ElasticsearchStorageError(RuntimeError):
    """Raised when an alert storage or indexing operation in Elasticsearch fails."""
    pass


# ---------------------------------------------------------------------------
# Connection Management
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def get_es_client() -> Elasticsearch:
    """Creates and caches an Elasticsearch client with timeout and auth configured."""
    kwargs: dict[str, Any] = {
        "hosts": [ELASTICSEARCH_URL],
        "request_timeout": 5.0,
        "verify_certs": ELASTICSEARCH_VERIFY_CERTS,
    }

    if ELASTICSEARCH_API_KEY:
        kwargs["api_key"] = ELASTICSEARCH_API_KEY
    elif ELASTICSEARCH_USER and ELASTICSEARCH_PASSWORD:
        kwargs["basic_auth"] = (ELASTICSEARCH_USER, ELASTICSEARCH_PASSWORD)

    return Elasticsearch(**kwargs)


def check_es_connection() -> dict[str, Any]:
    """Tests connectivity to Elasticsearch and returns status information."""
    try:
        es = get_es_client()
        info = es.info()
        index_exists = es.indices.exists(index=ELASTICSEARCH_INDEX)
        docs_count = 0
        if index_exists:
            count_res = es.count(index=ELASTICSEARCH_INDEX)
            docs_count = count_res.get("count", 0)

        return {
            "connected": True,
            "version": info.get("version", {}).get("number", "unknown"),
            "cluster_name": info.get("cluster_name", "unknown"),
            "url": ELASTICSEARCH_URL,
            "index": ELASTICSEARCH_INDEX,
            "index_exists": bool(index_exists),
            "docs_count": docs_count,
        }
    except Exception as exc:
        return {
            "connected": False,
            "error": str(exc),
            "url": ELASTICSEARCH_URL,
            "index": ELASTICSEARCH_INDEX,
            "index_exists": False,
            "docs_count": 0,
        }


# ---------------------------------------------------------------------------
# Index Management & Seeding
# ---------------------------------------------------------------------------
def init_alerts_index() -> bool:
    """Ensures the alert index exists with the configured mappings."""
    es = get_es_client()
    try:
        if not es.indices.exists(index=ELASTICSEARCH_INDEX):
            es.indices.create(index=ELASTICSEARCH_INDEX, body=ALERT_INDEX_MAPPING)
            logger.info("Created Elasticsearch index '%s' with mappings.", ELASTICSEARCH_INDEX)
            seed_demo_alerts_if_empty()
            return True
        return False
    except Exception as exc:
        logger.warning("Could not initialize Elasticsearch index '%s': %s", ELASTICSEARCH_INDEX, exc)
        return False


def seed_demo_alerts_if_empty() -> int:
    """Populates the Elasticsearch index from demo_alerts.json if empty."""
    import json
    from pathlib import Path

    if not ALERTS_PATH.exists():
        return 0

    es = get_es_client()
    try:
        if not es.indices.exists(index=ELASTICSEARCH_INDEX):
            es.indices.create(index=ELASTICSEARCH_INDEX, body=ALERT_INDEX_MAPPING)

        count = es.count(index=ELASTICSEARCH_INDEX).get("count", 0)
        if count > 0:
            return 0  # Already has documents, avoid duplicate initial seeding

        raw = json.loads(Path(ALERTS_PATH).read_text(encoding="utf-8"))
        if not isinstance(raw, list) or len(raw) == 0:
            return 0

        now_iso = datetime.now(timezone.utc).isoformat()
        actions = []
        for item in raw:
            doc = dict(item)
            alert_id = str(doc.get("id") or f"ALT-{uuid4().hex[:8].upper()}")
            doc["id"] = alert_id
            if "timestamp" not in doc:
                doc["timestamp"] = now_iso
            if "created_at" not in doc:
                doc["created_at"] = now_iso

            actions.append({
                "_index": ELASTICSEARCH_INDEX,
                "_id": alert_id,
                "_source": doc,
            })

        success, _ = bulk(es, actions, refresh=True)
        logger.info("Seeded %d demo alerts into Elasticsearch index '%s'.", success, ELASTICSEARCH_INDEX)
        return int(success)
    except Exception as exc:
        logger.warning("Failed to seed demo alerts into Elasticsearch: %s", exc)
        return 0


# ---------------------------------------------------------------------------
# Storage & Ingestion Operations
# ---------------------------------------------------------------------------
def normalize_alert_document(alert_doc: dict[str, Any]) -> dict[str, Any]:
    """Ensures consistent alert schema, stable ID, and ISO timestamp formatting."""
    doc = dict(alert_doc)
    now_iso = datetime.now(timezone.utc).isoformat()

    # Stable identifier
    if "id" not in doc or not doc["id"]:
        doc["id"] = f"ALT-{uuid4().hex[:8].upper()}"

    # Timestamps
    if "timestamp" not in doc or not doc["timestamp"]:
        doc["timestamp"] = now_iso
    elif isinstance(doc["timestamp"], datetime):
        doc["timestamp"] = doc["timestamp"].isoformat()

    if "created_at" not in doc or not doc["created_at"]:
        doc["created_at"] = now_iso

    # Defaults for network fields if omitted
    doc.setdefault("src", "10.0.0.1")
    doc.setdefault("dst", "172.16.0.1")
    doc.setdefault("protocol", "tcp")
    doc.setdefault("service", "http")

    # Numeric rounding and type normalization
    for float_field in ("confidence", "reconstruction_error", "priority", "asset_criticality"):
        if float_field in doc and doc[float_field] is not None:
            try:
                doc[float_field] = float(doc[float_field])
            except (ValueError, TypeError):
                pass

    if "is_zero_day" in doc:
        doc["is_zero_day"] = bool(doc["is_zero_day"])

    return doc


def store_alert(alert_doc: dict[str, Any], refresh: bool = False) -> dict[str, Any]:
    """Stores an alert document in Elasticsearch with idempotency and schema validation.

    Uses the document's stable 'id' as the Elasticsearch '_id', ensuring repeated
    requests for the same alert ID do not create unintended duplicates.

    Raises:
        ElasticsearchStorageError: If Elasticsearch is unreachable or returns an indexing error.
    """
    doc = normalize_alert_document(alert_doc)
    alert_id = doc["id"]

    try:
        es = get_es_client()
        # Ensure index exists
        if not es.indices.exists(index=ELASTICSEARCH_INDEX):
            es.indices.create(index=ELASTICSEARCH_INDEX, body=ALERT_INDEX_MAPPING)

        res = es.index(
            index=ELASTICSEARCH_INDEX,
            id=alert_id,
            document=doc,
            refresh=refresh,
        )

        return {
            "status": "stored",
            "id": alert_id,
            "index": ELASTICSEARCH_INDEX,
            "result": res.get("result"),
            "version": res.get("_version"),
            "alert": doc,
        }
    except (ESConnectionError, ApiError, Exception) as exc:
        logger.error("Failed to store alert '%s' in Elasticsearch: %s", alert_id, exc)
        raise ElasticsearchStorageError(f"Elasticsearch storage failed for alert '{alert_id}': {exc}") from exc


def store_alerts_batch(alert_docs: list[dict[str, Any]], refresh: bool = False) -> dict[str, Any]:
    """Batch indexes multiple alerts into Elasticsearch using streaming_bulk.

    Returns:
        Dictionary containing:
          - 'stored_count': Number of successfully indexed documents.
          - 'failed_count': Number of documents that failed indexing.
          - 'successful_ids': List of alert IDs confirmed indexed.
          - 'failed_ids': Dict of alert_id -> error reason for any failed items.
          - 'errors': Raw list of bulk errors.
          - 'total': Total documents in batch.
    """
    if not alert_docs:
        return {
            "stored_count": 0,
            "failed_count": 0,
            "successful_ids": [],
            "failed_ids": {},
            "errors": [],
            "total": 0,
        }

    normalized = [normalize_alert_document(d) for d in alert_docs]
    actions = [
        {
            "_index": ELASTICSEARCH_INDEX,
            "_id": d["id"],
            "_source": d,
        }
        for d in normalized
    ]

    try:
        es = get_es_client()
        if not es.indices.exists(index=ELASTICSEARCH_INDEX):
            es.indices.create(index=ELASTICSEARCH_INDEX, body=ALERT_INDEX_MAPPING)

        successful_ids: list[str] = []
        failed_ids: dict[str, str] = {}
        raw_errors: list[dict[str, Any]] = []

        for ok, item in streaming_bulk(es, actions, refresh=refresh, raise_on_error=False):
            action_info = next(iter(item.values())) if isinstance(item, dict) and item else {}
            doc_id = str(action_info.get("_id", ""))

            if ok:
                if doc_id:
                    successful_ids.append(doc_id)
            else:
                raw_errors.append(item)
                reason = (
                    action_info.get("error", {}).get("reason")
                    if isinstance(action_info, dict) and isinstance(action_info.get("error"), dict)
                    else str(action_info.get("error", "Indexing error"))
                )
                if doc_id:
                    failed_ids[doc_id] = str(reason)

        return {
            "stored_count": len(successful_ids),
            "failed_count": len(failed_ids),
            "successful_ids": successful_ids,
            "failed_ids": failed_ids,
            "errors": raw_errors,
            "total": len(alert_docs),
        }
    except Exception as exc:
        logger.error("Batch alert storage failed in Elasticsearch: %s", exc)
        raise ElasticsearchStorageError(f"Elasticsearch batch storage failed: {exc}") from exc


def validate_batch_storage_response(
    batch_res: Any,
    submitted_ids: set[str],
) -> tuple[bool, str | None, set[str], dict[str, str]]:
    """Validates the batch storage response against submitted alert IDs and reported counts.

    Returns:
        tuple: (is_valid, inconsistency_reason, verified_success_ids, verified_failed_ids)
    """
    if not isinstance(batch_res, dict):
        return False, "Batch storage response is not a dictionary", set(), {}

    # Extract failed_ids first so per-document failure reasons are preserved
    # even when response-level count inconsistencies are detected.
    failed_ids_raw = batch_res.get("failed_ids")
    failed_ids: dict[str, str] = {}
    if isinstance(failed_ids_raw, dict) and failed_ids_raw:
        failed_ids = {str(k): str(v) for k, v in failed_ids_raw.items()}
    elif isinstance(batch_res.get("errors"), list) and batch_res["errors"]:
        for err in batch_res["errors"]:
            if isinstance(err, dict):
                for info in err.values():
                    if isinstance(info, dict) and "_id" in info:
                        reason = (
                            info.get("error", {}).get("reason")
                            if isinstance(info.get("error"), dict)
                            else str(info.get("error", "Indexing error"))
                        )
                        failed_ids[str(info["_id"])] = str(reason)

    stored_count = batch_res.get("stored_count")
    failed_count = batch_res.get("failed_count", 0)
    reported_total = batch_res.get("total")
    total_submitted = len(submitted_ids)

    # 1. Type and bounds validation on counts
    if not isinstance(stored_count, int) or not isinstance(failed_count, int):
        return False, "Batch response missing integer stored_count or failed_count", set(), failed_ids

    if stored_count < 0 or failed_count < 0:
        return False, "Negative count in batch storage response", set(), failed_ids

    # 2. Check total and count consistency
    if reported_total is not None and reported_total != total_submitted:
        return (
            False,
            f"Reported total ({reported_total}) does not match submitted batch size ({total_submitted})",
            set(),
            failed_ids,
        )

    if stored_count + failed_count != total_submitted:
        return (
            False,
            f"Count mismatch: stored_count ({stored_count}) + failed_count ({failed_count}) != submitted ({total_submitted})",
            set(),
            failed_ids,
        )

    # 3. Failed count must match number of identified failed IDs
    if len(failed_ids) != failed_count:
        return (
            False,
            f"Failed count ({failed_count}) does not match number of failed IDs identified ({len(failed_ids)})",
            set(),
            failed_ids,
        )

    # 4. Check for unexpected failed IDs not in submitted batch
    unexpected_failed = set(failed_ids.keys()) - submitted_ids
    if unexpected_failed:
        return (
            False,
            f"Batch response contains unexpected failed IDs not in submitted batch: {unexpected_failed}",
            set(),
            failed_ids,
        )

    # 5. Extract and validate successful_ids
    raw_success = batch_res.get("successful_ids")
    if raw_success is not None and isinstance(raw_success, (list, set)):
        successful_ids = {str(i) for i in raw_success}

        # Check for unexpected success IDs
        unexpected_success = successful_ids - submitted_ids
        if unexpected_success:
            return (
                False,
                f"Batch response contains unexpected success IDs not in submitted batch: {unexpected_success}",
                set(),
                failed_ids,
            )

        # Overlap check: an ID cannot be both successful and failed
        overlap = successful_ids & set(failed_ids.keys())
        if overlap:
            return (
                False,
                f"Conflict: alert IDs reported as both succeeded and failed: {overlap}",
                set(),
                failed_ids,
            )

        # Count match
        if len(successful_ids) != stored_count:
            return (
                False,
                f"Number of verified successful IDs ({len(successful_ids)}) does not match stored_count ({stored_count})",
                set(),
                failed_ids,
            )
    else:
        # If successful_ids is not explicitly provided, derive it only if failed_ids
        # accounts for all failures and counts match
        successful_ids = submitted_ids - set(failed_ids.keys())
        if len(successful_ids) != stored_count:
            return (
                False,
                f"Derived successful count ({len(successful_ids)}) does not match stored_count ({stored_count})",
                set(),
                failed_ids,
            )

    return True, None, successful_ids, failed_ids


# ---------------------------------------------------------------------------
# Retrieval & Query Operations
# ---------------------------------------------------------------------------
def get_alerts(
    tier: str | None = None,
    sort: str = "priority",
    limit: int = 0,
) -> list[dict[str, Any]]:
    """Retrieves threat alerts from Elasticsearch with filtering and sorting.

    Args:
        tier: Optional comma-separated tier names (e.g. 'critical', 'review,auto_log')
        sort: Sort field: 'priority' (descending) or 'id' (ascending)
        limit: Max number of alerts to return (0 for default 500)
    """
    es = get_es_client()

    # Build query
    query: dict[str, Any] = {"match_all": {}}
    if tier:
        tiers = [t.strip() for t in tier.split(",") if t.strip()]
        if tiers:
            query = {"terms": {"tier": tiers}}

    # Build sort clause
    sort_clause: list[dict[str, Any]] = []
    if sort == "id":
        sort_clause.append({"id": {"order": "asc"}})
    else:
        sort_clause.append({"priority": {"order": "desc", "missing": "_last"}})
        sort_clause.append({"timestamp": {"order": "desc", "missing": "_last"}})

    size = min(limit, 500) if limit > 0 else 500

    res = es.search(
        index=ELASTICSEARCH_INDEX,
        query=query,
        sort=sort_clause,
        size=size,
    )

    hits = res.get("hits", {}).get("hits", [])
    results: list[dict[str, Any]] = []
    for h in hits:
        source = h.get("_source", {})
        if "_id" in h and "id" not in source:
            source["id"] = h["_id"]
        results.append(source)

    return results


def get_alert_by_id(alert_id: str) -> dict[str, Any] | None:
    """Retrieves a single alert by its unique identifier from Elasticsearch."""
    es = get_es_client()
    try:
        res = es.get(index=ELASTICSEARCH_INDEX, id=alert_id)
        source = res.get("_source")
        if source and "id" not in source:
            source["id"] = alert_id
        return source
    except NotFoundError:
        return None
    except Exception as exc:
        logger.warning("Error fetching alert '%s' from Elasticsearch: %s", alert_id, exc)
        return None


def get_dashboard_aggregations() -> dict[str, Any] | None:
    """Runs aggregations across the alert index for real-time dashboard KPIs."""
    es = get_es_client()
    try:
        agg_body = {
            "by_pred": {"terms": {"field": "predicted", "size": 20}},
            "by_severity": {"terms": {"field": "severity", "size": 10}},
            "by_tier": {"terms": {"field": "tier", "size": 10}},
            "threats_count": {
                "filter": {"bool": {"must_not": [{"term": {"predicted": "normal"}}]}}
            },
            "zero_days_count": {
                "filter": {"term": {"is_zero_day": True}}
            },
        }

        res = es.search(
            index=ELASTICSEARCH_INDEX,
            query={"match_all": {}},
            aggs=agg_body,
            size=0,
        )

        aggs = res.get("aggregations", {})
        by_pred = {b["key"]: b["doc_count"] for b in aggs.get("by_pred", {}).get("buckets", [])}
        by_severity = {b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])}
        by_tier = {b["key"]: b["doc_count"] for b in aggs.get("by_tier", {}).get("buckets", [])}
        threats = aggs.get("threats_count", {}).get("doc_count", 0)
        zero_days = aggs.get("zero_days_count", {}).get("doc_count", 0)
        total = res.get("hits", {}).get("total", {}).get("value", 0)

        return {
            "total_alerts": total,
            "threats": threats,
            "zero_days": zero_days,
            "by_pred": by_pred,
            "by_severity": by_severity,
            "by_tier": by_tier,
        }
    except Exception as exc:
        logger.warning("Elasticsearch aggregation query failed: %s", exc)
        return None

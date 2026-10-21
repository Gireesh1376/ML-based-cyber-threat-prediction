"""
Database module for AEGIS Cyber-Threat Prediction.
Provides Elasticsearch connectivity, index lifecycle management, and alert repository.
"""
from app.db.elasticsearch import (
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

__all__ = [
    "ElasticsearchStorageError",
    "check_es_connection",
    "get_alert_by_id",
    "get_alerts",
    "get_dashboard_aggregations",
    "get_es_client",
    "init_alerts_index",
    "seed_demo_alerts_if_empty",
    "store_alert",
    "store_alerts_batch",
    "validate_batch_storage_response",
]

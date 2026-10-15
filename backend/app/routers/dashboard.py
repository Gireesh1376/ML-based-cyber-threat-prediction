from fastapi import APIRouter, HTTPException, Query

from app.ml.detector import DetectorNotReady, get_model, get_tier_cutoffs, load_demo_alerts, load_metrics
from app.ml.priority import annotate_alert, tier_from_score

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard/summary")
def summary():
    metrics = load_metrics()
    alerts = load_demo_alerts()
    if not metrics:
        return {
            "ready": False,
            "message": "Train the hybrid detector first.",
        }
    threats = [a for a in alerts if a.get("predicted") != "normal"]
    zero_days = [a for a in alerts if a.get("is_zero_day")]
    by_pred = {}
    for a in alerts:
        by_pred[a["predicted"]] = by_pred.get(a["predicted"], 0) + 1
    by_severity = {}
    for a in threats:
        by_severity[a.get("severity", "low")] = by_severity.get(a.get("severity", "low"), 0) + 1
    val = metrics.get("validation_binary", {})
    test = metrics.get("official_test_binary", {})
    zd = metrics.get("zero_day", {})
    prio = metrics.get("prioritisation", {})
    prio_test = prio.get("test_evaluation", {})
    als = metrics.get("auto_log_safety", {})
    cutoffs = get_tier_cutoffs()
    by_tier = {"critical": 0, "review": 0, "auto_log": 0}
    for a in alerts:
        tier = a.get("tier")
        if tier is None:
            tier = tier_from_score(annotate_alert(a, metrics.get("reconstruction_threshold", 1.0), cutoffs)["priority"], cutoffs)
        by_tier[tier] = by_tier.get(tier, 0) + 1
    return {
        "ready": True,
        "problem": metrics.get("problem"),
        "architecture": metrics.get("architecture"),
        "dataset": metrics.get("dataset"),
        "kpis": {
            "validation_accuracy": val.get("accuracy"),
            "validation_f1": val.get("f1"),
            "validation_precision": val.get("precision"),
            "validation_recall": val.get("recall"),
            "validation_roc_auc": val.get("roc_auc"),
            "test_accuracy": test.get("accuracy"),
            "test_f1": test.get("f1"),
            "test_recall": test.get("recall"),
            "test_precision": test.get("precision"),
            "test_roc_auc": test.get("roc_auc"),
            "zero_day_detection_rate": zd.get("held_out_attack_detection_rate"),
            "novel_flag_rate": zd.get("flagged_as_novel_rate"),
            "open_alerts": len(threats),
            "zero_day_alerts": len(zero_days),
            "critical_tier_alerts": by_tier.get("critical", 0),
            "auto_logged_share": prio_test.get("auto_logged_share"),
        },
        "problem3": {
            "workload": {
                "human_review_workload": prio_test.get("human_review_workload"),
                "auto_logged_share": prio_test.get("auto_logged_share"),
                "tier_counts": prio_test.get("tier_counts"),
            },
            "threat_preservation": {
                "attacks_in_human_tiers": prio_test.get("attacks_in_human_tiers"),
                "attacks_outside_human_tiers": prio_test.get("attacks_outside_human_tiers"),
                "attacks_auto_logged": prio_test.get("attacks_auto_logged"),
                "zero_days_in_human_tiers": prio_test.get("zero_days_in_human_tiers"),
                "zero_days_outside_human_tiers": prio_test.get("zero_days_outside_human_tiers"),
            },
            "per_tier": (metrics.get("tier_precision") or prio.get("tier_precision") or {}).get("tiers"),
            "auto_log_safety": {
                "auto_log": als.get("auto_log", {}),
                "human_tiers": als.get("human_tiers", {}),
                "interpretation": als.get("interpretation"),
            },
            "cutoffs_derived_on": prio.get("cutoffs_derived_on"),
            "limitation": (
                "Auto-logging is not proven safe. On the official NSL-KDD test split, the auto_log tier contains "
                f"{als.get('auto_log', {}).get('attacks_in_auto_log', 0)} true attacks "
                f"({als.get('auto_log', {}).get('attacks_share_of_all_attacks', 0):.1%} of attacks) and "
                f"{als.get('auto_log', {}).get('zero_days_in_auto_log', 0)} held-out zero-days "
                f"({als.get('auto_log', {}).get('zero_days_share_of_all_zero_days', 0):.1%} of zero-days) "
                "without human review. These were misclassified as normal by both detector components, "
                "so the residual is a detection limitation, not a prioritized routing mistake."
            ),
        },
        "tier_mix": by_tier,
        "prioritisation": {
            "weights": prio.get("weights"),
            "tier_cutoffs": cutoffs,
            "cutoffs_derived_on": prio.get("cutoffs_derived_on"),
            "test_evaluation": prio_test,
        },
        "alert_mix": by_pred,
        "severity_mix": by_severity,
        "held_out_labels": metrics.get("held_out_labels", []),
        "classes": metrics.get("classes", []),
        "validation_rows": metrics.get("validation_rows"),
        "train_rows": metrics.get("train_rows"),
        "test_rows": metrics.get("test_rows"),
        "unseen_zero_day_rows": metrics.get("unseen_zero_day_rows"),
        "validation_binary": val,
        "official_test_binary": test,
        "detection_comparison": metrics.get("detection_comparison"),
        "zero_day": zd,
        "reconstruction_threshold": metrics.get("reconstruction_threshold"),
    }


@router.get("/model/metrics")
def metrics():
    data = load_metrics()
    if not data:
        raise HTTPException(status_code=404, detail="Metrics not found. Train the model first.")
    return data


@router.get("/alerts")
def alerts(
    tier: str | None = Query(default=None, description="Filter: critical | review | auto_log"),
    sort: str = Query(default="priority", description="priority | id"),
    limit: int = Query(default=0, ge=0, le=500),
):
    items = load_demo_alerts()
    cutoffs = get_tier_cutoffs()
    threshold = load_metrics().get("reconstruction_threshold", 1.0)
    # Saved alerts may predate the asset-criticality update; re-annotate any
    # alert that is missing priority OR components OR asset fields so the UI
    # always shows a complete, consistent explainability payload.
    def _needs_annotation(a: dict) -> bool:
        return (
            a.get("priority") is None
            or a.get("tier") is None
            or a.get("priority_components") is None
            or a.get("asset_criticality") is None
            or a.get("tier_reason") is None
        )

    items = [annotate_alert(a, threshold, cutoffs) if _needs_annotation(a) else a for a in items]
    if tier:
        wanted = {t.strip() for t in tier.split(",")}
        items = [a for a in items if a.get("tier") in wanted]
    if sort == "id":
        items.sort(key=lambda a: a["id"])
    else:
        items.sort(key=lambda a: a.get("priority", 0.0), reverse=True)
    if limit:
        items = items[:limit]
    return {"items": items, "count": len(items), "tier_cutoffs": cutoffs}


@router.get("/model/status")
def status():
    try:
        get_model()
        return {"ready": True}
    except DetectorNotReady as exc:
        return {"ready": False, "detail": str(exc)}

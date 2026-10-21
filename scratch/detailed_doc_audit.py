import json
import os
import sys
from collections import Counter
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, os.path.abspath("backend"))

from app.config import ALERTS_PATH, ELASTICSEARCH_INDEX
from app.db.elasticsearch import get_es_client
from app.routers.detect import PRESETS

es = get_es_client()
search_res = es.search(index=ELASTICSEARCH_INDEX, size=500)
hits = search_res.get("hits", {}).get("hits", [])
docs = [h["_source"] for h in hits]

demo_alerts = json.loads(ALERTS_PATH.read_text(encoding="utf-8")) if ALERTS_PATH.exists() else []
demo_ids = {a["id"] for a in demo_alerts if "id" in a}

# Sort docs by created_at or timestamp
docs.sort(key=lambda d: d.get("created_at") or d.get("timestamp") or "")

# Analyze the 80 demo docs
demo_docs = [d for d in docs if d.get("id") in demo_ids]
non_demo_docs = [d for d in docs if d.get("id") not in demo_ids]

print(f"Total ES docs: {len(docs)}")
print(f"Demo docs in ES: {len(demo_docs)}")
print(f"Non-demo docs in ES: {len(non_demo_docs)}")

# Let's check non-demo flows against known test flows and presets
# Known test flows from test_detect_integration.py:
BENIGN_WEB = {
    "duration": 2, "protocol_type": "tcp", "service": "http", "flag": "SF",
    "src_bytes": 280, "dst_bytes": 4200, "logged_in": 1, "count": 4,
    "srv_count": 4, "same_srv_rate": 1, "dst_host_same_srv_rate": 1,
    "dst_host_count": 40, "dst_host_srv_count": 38,
}
DOS_FLOW = {
    "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "S0",
    "src_bytes": 0, "dst_bytes": 0, "logged_in": 0, "count": 180,
    "srv_count": 18, "serror_rate": 1, "srv_serror_rate": 1,
    "same_srv_rate": 0.1, "diff_srv_rate": 0.06,
    "dst_host_serror_rate": 1, "dst_host_srv_serror_rate": 1,
    "dst_host_count": 255, "dst_host_same_srv_rate": 0.05,
}
UNKNOWN_SERVICE_FLOW = {
    "duration": 2, "protocol_type": "tcp", "service": "totally_unknown_svc", "flag": "SF",
    "src_bytes": 100, "dst_bytes": 100, "logged_in": 0, "count": 1,
    "srv_count": 1, "same_srv_rate": 1, "dst_host_same_srv_rate": 1,
    "dst_host_count": 1, "dst_host_srv_count": 1,
}

def match_flow(flow_dict):
    if not flow_dict:
        return "empty_flow"
    # Check test flows
    def matches_sub(sub):
        return all(flow_dict.get(k) == v for k, v in sub.items())
    
    if matches_sub(UNKNOWN_SERVICE_FLOW):
        return "test_unknown_service"
    if matches_sub(DOS_FLOW):
        return "test_dos_flow"
    if matches_sub(BENIGN_WEB):
        return "test_benign_web_flow"
    
    # Check studio presets
    for pname, pvals in PRESETS.items():
        if all(flow_dict.get(k) == pvals.get(k) for k in ("service", "protocol_type", "src_bytes", "count")):
            return f"preset_{pname}"
    
    return "other_flow"

flow_types = Counter()
for d in non_demo_docs:
    ft = match_flow(d.get("flow", {}))
    flow_types[ft] += 1

print("\n--- Non-Demo Flow Matches ---")
for ft, count in flow_types.most_common():
    print(f"  {ft}: {count}")

# Check where the 22-23 doc batches fit
print("\n--- Minute-by-Minute Breakdown of Non-Demo Docs ---")
batches = {}
for d in non_demo_docs:
    ts = (d.get("created_at") or d.get("timestamp") or "")[:16]
    batches.setdefault(ts, []).append(d)

for minute, bdocs in sorted(batches.items()):
    b_types = Counter(match_flow(d.get("flow", {})) for d in bdocs)
    b_tiers = Counter(d.get("tier") for d in bdocs)
    print(f"{minute} ({len(bdocs)} docs):")
    print(f"   Flows: {dict(b_types)}")
    print(f"   Tiers: {dict(b_tiers)}")

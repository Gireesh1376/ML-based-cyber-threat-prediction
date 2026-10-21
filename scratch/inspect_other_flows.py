import json
import os
import sys

# Add backend directory to path
sys.path.insert(0, os.path.abspath("backend"))

from app.config import ALERTS_PATH, ELASTICSEARCH_INDEX
from app.db.elasticsearch import get_es_client

es = get_es_client()
search_res = es.search(index=ELASTICSEARCH_INDEX, size=500)
hits = search_res.get("hits", {}).get("hits", [])
docs = [h["_source"] for h in hits]

demo_alerts = json.loads(ALERTS_PATH.read_text(encoding="utf-8")) if ALERTS_PATH.exists() else []
demo_ids = {a["id"] for a in demo_alerts if "id" in a}

non_demo_docs = [d for d in docs if d.get("id") not in demo_ids]

# Let's inspect the 4 "other_flow" docs
# from 2026-10-18T14:08 (1 doc) and 2026-10-19T11:11 (3 docs)
target_minutes = ("2026-10-18T14:08", "2026-10-19T11:11")
print("=== OTHER FLOWS DETAILS ===")
for d in non_demo_docs:
    ts = (d.get("created_at") or d.get("timestamp") or "")[:16]
    if ts in target_minutes:
        print(f"ID: {d.get('id')}, ts: {d.get('timestamp')}, pred: {d.get('predicted')}, tier: {d.get('tier')}, src: {d.get('src')}, dst: {d.get('dst')}")
        print("  Flow keys & values:", {k: d.get('flow', {}).get(k) for k in ("protocol_type", "service", "flag", "src_bytes", "dst_bytes", "count", "serror_rate")})
        print("  Rationale:", d.get("rationale"))
        print("  DQ flags:", d.get("dq_flags"))
        print()

# Also check test_elasticsearch_integration.py to see what flows it generates!

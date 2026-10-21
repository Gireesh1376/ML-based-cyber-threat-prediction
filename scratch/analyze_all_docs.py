import json
import os
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, os.path.abspath("backend"))

from app.config import ALERTS_PATH, ELASTICSEARCH_INDEX
from app.db.elasticsearch import get_es_client

es = get_es_client()
search_res = es.search(index=ELASTICSEARCH_INDEX, size=500)
hits = search_res.get("hits", {}).get("hits", [])
docs = [h["_source"] for h in hits]

# Sort docs by created_at or timestamp
docs.sort(key=lambda d: d.get("created_at") or d.get("timestamp") or "")

# Load demo alerts
demo_alerts = json.loads(ALERTS_PATH.read_text(encoding="utf-8")) if ALERTS_PATH.exists() else []
demo_id_to_alert = {a["id"]: a for a in demo_alerts if "id" in a}

print(f"Total documents retrieved: {len(docs)}")

# Inspect the 2 newest documents from today (Oct 20)
print("\n=== DOCS FROM OCT 20 ===")
oct20_docs = [d for d in docs if (d.get("created_at") or d.get("timestamp", "")).startswith("2026-10-20")]
for d in oct20_docs:
    print(f"ID: {d.get('id')}, ts: {d.get('timestamp')}, pred: {d.get('predicted')}, tier: {d.get('tier')}, src: {d.get('src')}, dst: {d.get('dst')}, service: {d.get('service')}, dq_flags: {d.get('dq_flags')}, rationale: {d.get('rationale')}")

# Group all documents into time batches
print("\n=== BATCHES BY TIMESTAMP ===")
batches = {}
for d in docs:
    ts = d.get("created_at") or d.get("timestamp") or "no-ts"
    # Group by minute
    key = ts[:16] if len(ts) >= 16 else ts
    if key not in batches:
        batches[key] = []
    batches[key].append(d)

for minute, bdocs in sorted(batches.items()):
    in_demo = sum(1 for d in bdocs if d.get("id") in demo_id_to_alert)
    tier_counts = Counter(d.get("tier") for d in bdocs)
    preds = Counter(d.get("predicted") for d in bdocs)
    print(f"Minute {minute}: {len(bdocs)} docs (in demo_alerts.json: {in_demo}, tiers: {dict(tier_counts)}, preds: {dict(preds)})")

# Check where ALT- IDs come from
# Let's inspect backend codebase for 'ALT-'

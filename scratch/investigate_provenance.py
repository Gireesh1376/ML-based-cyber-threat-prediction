import json
import os
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, os.path.abspath("backend"))

from app.config import ALERTS_PATH, ELASTICSEARCH_INDEX, ELASTICSEARCH_URL
from app.db.elasticsearch import get_es_client

# 1. Read demo_alerts.json
demo_alerts = []
if ALERTS_PATH.exists():
    demo_alerts = json.loads(ALERTS_PATH.read_text(encoding="utf-8"))
print(f"demo_alerts.json count: {len(demo_alerts)}")

demo_ids = {a.get("id") for a in demo_alerts if a.get("id")}
print(f"demo_alerts unique IDs count: {len(demo_ids)}")

# 2. Query Elasticsearch
es = get_es_client()
info = es.info()
print(f"Elasticsearch version: {info.get('version', {}).get('number')}")

count_res = es.count(index=ELASTICSEARCH_INDEX)
total_es_count = count_res.get("count", 0)
print(f"Live Elasticsearch total count in '{ELASTICSEARCH_INDEX}': {total_es_count}")

# Fetch all documents (size=500, since total is ~226)
search_res = es.search(index=ELASTICSEARCH_INDEX, size=500)
hits = search_res.get("hits", {}).get("hits", [])
print(f"Retrieved hits count: {len(hits)}")

docs = [h["_source"] for h in hits]

# Let's inspect ID formats and sources
id_patterns = Counter()
timestamps = []
created_ats = []
tiers = Counter()
predictions = Counter()
src_ips = Counter()
dst_ips = Counter()
matches_demo = 0
not_demo = []

for d in docs:
    doc_id = d.get("id", "")
    tier = d.get("tier", "unknown")
    pred = d.get("predicted", "unknown")
    tiers[tier] += 1
    predictions[pred] += 1
    src_ips[d.get("src", "unknown")] += 1
    dst_ips[d.get("dst", "unknown")] += 1

    ts = d.get("timestamp")
    ca = d.get("created_at")
    if ts:
        timestamps.append(ts)
    if ca:
        created_ats.append(ca)

    if doc_id.startswith("ALT-") and len(doc_id) == 12: # e.g. ALT-A1B2C3D4
        id_patterns["ALT-8hex"] += 1
    elif doc_id.startswith("ALT-"):
        id_patterns["ALT-other"] += 1
    elif len(doc_id) == 36 and "-" in doc_id:
        id_patterns["UUID"] += 1
    else:
        id_patterns["other"] += 1

    if doc_id in demo_ids:
        matches_demo += 1
    else:
        not_demo.append(d)

print(f"\n--- Match with demo_alerts.json ---")
print(f"Matches demo_alerts.json: {matches_demo}")
print(f"Not in demo_alerts.json: {len(not_demo)}")

print(f"\n--- ID Patterns ---")
for k, v in id_patterns.items():
    print(f"  {k}: {v}")

print(f"\n--- Tiers Breakdown in ES ---")
for k, v in tiers.items():
    print(f"  {k}: {v}")

print(f"\n--- Predictions Breakdown in ES ---")
for k, v in predictions.items():
    print(f"  {k}: {v}")

print(f"\n--- Sample Timestamps ---")
if timestamps:
    timestamps.sort()
    print(f"  Earliest timestamp: {timestamps[0]}")
    print(f"  Latest timestamp: {timestamps[-1]}")
    # Group by date/hour
    date_counts = Counter(t[:13] for t in timestamps)
    print("  Counts by hour (ISO prefix):")
    for dh, c in sorted(date_counts.items()):
        print(f"    {dh}:00 -> {c} docs")

# Check non-demo records structure
print(f"\n--- Non-Demo Records Sample (First 5) ---")
for i, d in enumerate(not_demo[:5]):
    print(f"Doc {i+1}: ID={d.get('id')}, ts={d.get('timestamp')}, created_at={d.get('created_at')}, pred={d.get('predicted')}, tier={d.get('tier')}, src={d.get('src')}, dst={d.get('dst')}, service={d.get('service')}, has_flow={'flow' in d}")

# Check non-demo ID formats
non_demo_id_patterns = Counter()
for d in not_demo:
    did = d.get("id", "")
    if len(did) == 36 and did.count("-") == 4:
        non_demo_id_patterns["UUID-v4"] += 1
    elif did.startswith("ALT-"):
        non_demo_id_patterns["ALT-prefix"] += 1
    else:
        non_demo_id_patterns[f"len-{len(did)}"] += 1
print(f"\n--- Non-Demo ID Patterns ---")
for k, v in non_demo_id_patterns.items():
    print(f"  {k}: {v}")

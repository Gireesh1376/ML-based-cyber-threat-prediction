import json
import os
import sys

# Add backend directory to path
sys.path.insert(0, os.path.abspath("backend"))

from app.config import ELASTICSEARCH_INDEX
from app.db.elasticsearch import get_es_client

es = get_es_client()
search_res = es.search(index=ELASTICSEARCH_INDEX, size=500)
hits = search_res.get("hits", {}).get("hits", [])
docs = [h["_source"] for h in hits]

# Sort docs by created_at or timestamp
docs.sort(key=lambda d: d.get("created_at") or d.get("timestamp") or "")

print(f"Total: {len(docs)}")

# Let's inspect docs 190 to 228 (1-indexed: 191 to 228)
print("--- Docs 190 to 228 ---")
for i in range(190, len(docs)):
    d = docs[i]
    ts = d.get("created_at") or d.get("timestamp")
    print(f"Doc #{i+1}: ID={d.get('id')}, ts={ts}, pred={d.get('predicted')}, tier={d.get('tier')}, svc={d.get('service')}, proto={d.get('protocol')}, src={d.get('src')}, dst={d.get('dst')}")

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

# Sort docs by created_at or timestamp
docs.sort(key=lambda d: d.get("created_at") or d.get("timestamp") or "")

oct18_docs = [d for d in docs if (d.get("created_at") or d.get("timestamp", "")).startswith("2026-10-18")]
oct19_docs = [d for d in docs if (d.get("created_at") or d.get("timestamp", "")).startswith("2026-10-19")]
oct20_docs = [d for d in docs if (d.get("created_at") or d.get("timestamp", "")).startswith("2026-10-20")]

print(f"Total documents: {len(docs)}")
print(f"Oct 18 documents: {len(oct18_docs)}")
print(f"Oct 19 documents: {len(oct19_docs)}")
print(f"Oct 20 documents: {len(oct20_docs)}")

print(f"Oct 18 + Oct 19: {len(oct18_docs) + len(oct19_docs)}")

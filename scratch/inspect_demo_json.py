import json
import os
import sys

# Add backend directory to path
sys.path.insert(0, os.path.abspath("backend"))

from app.config import ALERTS_PATH

raw = json.loads(ALERTS_PATH.read_text(encoding="utf-8"))
print(f"Total demo alerts in json: {len(raw)}")
sample = raw[0]
print("Keys in demo alert:", list(sample.keys()))
print("Sample demo alert:", json.dumps(sample, indent=2)[:500])

# Check true_labels in demo alerts
labels = [a.get("true_label") for a in raw]
from collections import Counter
print("True labels in demo alerts:", Counter(labels))

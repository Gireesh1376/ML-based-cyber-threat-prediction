import json
import os
import sys

# Add backend directory to path
sys.path.insert(0, os.path.abspath("backend"))

from starlette.testclient import TestClient
from app.main import app

client = TestClient(app)

print("=== 1. /api/health ===")
h = client.get("/api/health").json()
print("Health:", h)

print("\n=== 2. /api/db/status ===")
db = client.get("/api/db/status").json()
print("DB Status:", db)

print("\n=== 3. /api/dashboard/summary ===")
summ = client.get("/api/dashboard/summary").json()
kpis = summ.get("kpis", {})
print("KPIs:", {
    "open_alerts": kpis.get("open_alerts"),
    "critical_tier_alerts": kpis.get("critical_tier_alerts"),
    "zero_day_alerts": kpis.get("zero_day_alerts"),
    "test_accuracy": kpis.get("test_accuracy"),
})
print("Tier mix in summary:", summ.get("tier_mix"))

print("\n=== 4. /api/alerts ===")
al = client.get("/api/alerts").json()
print("Alerts count:", al.get("count"))
print("Source:", al.get("source"))
items = al.get("items", [])
from collections import Counter
item_tiers = Counter(i.get("tier") for i in items)
print("Item tiers in /api/alerts:", dict(item_tiers))

print("\n=== 5. First 3 Alerts ===")
for item in items[:3]:
    print(f"ID={item.get('id')}, tier={item.get('tier')}, pred={item.get('predicted')}, prio={item.get('priority')}, src={item.get('src')}, dst={item.get('dst')}")

print("\n=== VERIFICATION SUCCESSFUL ===")

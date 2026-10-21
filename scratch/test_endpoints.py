import sys
import os

# Add backend directory to path
sys.path.insert(0, os.path.abspath("backend"))

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

print("--- Testing /api/health ---")
r_health = client.get("/api/health")
print("Status Code:", r_health.status_code)
print("Response:", r_health.json())
assert r_health.status_code == 200
assert r_health.json()["status"] == "ok"

print("\n--- Testing /api/db/status ---")
r_db = client.get("/api/db/status")
print("Status Code:", r_db.status_code)
print("Response:", r_db.json())
assert r_db.status_code == 200
db_data = r_db.json()
assert "connected" in db_data

print("\n--- Testing /api/dashboard/summary adversarial payload ---")
r_summary = client.get("/api/dashboard/summary")
print("Status Code:", r_summary.status_code)
summary_data = r_summary.json()
print("Summary Adversarial Object:", summary_data.get("adversarial"))
assert summary_data["ready"] is True
assert "adversarial" in summary_data
assert summary_data["adversarial"]["summary"]["evasion_reduction_pct"] == 28.8
assert summary_data["adversarial"]["summary"]["baseline_evasion_rate"] == 0.1507
assert summary_data["adversarial"]["summary"]["hardened_evasion_rate"] == 0.1073

print("\n--- Testing /api/alerts live counts ---")
r_alerts = client.get("/api/alerts")
print("Status Code:", r_alerts.status_code)
alerts_data = r_alerts.json()
print("Source:", alerts_data.get("source"))
print("Alert count:", alerts_data.get("count"))
tiers = {}
for item in alerts_data.get("items", []):
    t = item.get("tier")
    tiers[t] = tiers.get(t, 0) + 1
print("Tier counts in /api/alerts:", tiers)

print("\nALL BACKEND TEST CLIENT ASSERTIONS PASSED!")

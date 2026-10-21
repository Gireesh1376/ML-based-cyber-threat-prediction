import json
import urllib.request

def test_endpoint(name, url, method="GET", data=None):
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data else {},
        method=method,
    )
    try:
        with urllib.request.urlopen(req) as resp:
            body = json.loads(resp.read().decode())
            print(f"[{name}] SUCCESS: status={resp.status}, keys={list(body.keys())[:5]}")
            return body
    except urllib.error.HTTPError as e:
        print(f"[{name}] HTTP ERROR: {e.code} - {e.read().decode()}")
    except Exception as e:
        print(f"[{name}] EXCEPTION: {e}")

h = test_endpoint("Health", "http://127.0.0.1:8000/api/health")
print("Health body:", h)

db = test_endpoint("DB Status", "http://127.0.0.1:8000/api/db/status")
print("DB body:", db)

summ = test_endpoint("Dashboard Summary", "http://127.0.0.1:8000/api/dashboard/summary")
print("Summary database:", summ.get("database") if summ else None)

al = test_endpoint("Alerts", "http://127.0.0.1:8000/api/alerts?limit=3")
print("Alerts count:", al.get("count"), "source:", al.get("source") if al else None)

det_payload = json.dumps({
    "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "S0",
    "count": 180, "srv_count": 18, "serror_rate": 1.0, "srv_serror_rate": 1.0,
}).encode()

res_det = test_endpoint("Detect Live", "http://127.0.0.1:8000/api/detect", method="POST", data=det_payload)
if res_det and "id" in res_det:
    alert_id = res_det["id"]
    print("Live Detect alert ID:", alert_id, "saved_to_db:", res_det.get("saved_to_db"), "db_status:", res_det.get("db_status"))
    rep = test_endpoint("Replay Live Alert", f"http://127.0.0.1:8000/api/detect/replay/{alert_id}", method="POST")
    print("Replayed from:", rep.get("replayed_from") if rep else None)

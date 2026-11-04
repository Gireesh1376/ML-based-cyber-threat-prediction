================================================================================
AEGIS — ML-Based Cyber Threat Prediction & Operations Platform
Setup, Configuration & Execution Guide
================================================================================

1. SETUP & CONFIGURATION
--------------------------------------------------------------------------------
PREREQUISITES:
  • Python 3.10+ (with pip)
  • Node.js 18+ (with npm)
  • (Optional) Docker & Docker Compose (for Elasticsearch)

CONFIGURATION FILES:
  1. Environment Configuration:
     The project root contains `.env.example`.
     Copy it to `.env` (or use default built-in fallbacks):
       cp .env.example .env      (Linux/macOS)
       copy .env.example .env    (Windows PowerShell / CMD)

     Default settings in `.env`:
       ELASTICSEARCH_URL=http://localhost:9200
       ELASTICSEARCH_INDEX=aegis-alerts
       BACKEND_HOST=127.0.0.1
       BACKEND_PORT=8000

  2. Database Note:
     Elasticsearch is OPTIONAL. If Elasticsearch is not running, AEGIS
     automatically operates in offline fallback mode using pre-loaded alerts
     (`demo_alerts.json`), allowing full evaluation without any external database.

DEPENDENCY INSTALLATION:
  1. Backend Dependencies:
     cd backend
     python -m venv .venv
     # Activate virtual environment:
     # Windows:      .venv\Scripts\activate
     # Linux/macOS:  source .venv/bin/activate
     pip install -r requirements.txt
     cd ..

  2. Frontend Dependencies:
     cd frontend
     npm install
     # (Optional) If npm reports any package advisory (e.g., in vite):
     #   npm audit fix
     cd ..


2. HOW TO RUN THE PROJECT
--------------------------------------------------------------------------------
Run Backend and Frontend in two separate terminals:

TERMINAL 1 (Backend API):
  cd backend
  # Ensure virtual environment is activated (.venv)
  uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

TERMINAL 2 (Frontend UI):
  cd frontend
  npm run dev

ACCESS URLS:
  • SOC Operations Dashboard: http://localhost:5173
  • Interactive API Docs:     http://localhost:8000/docs
  • Elasticsearch (optional): http://localhost:9200

ALTERNATIVE: DOCKER COMPOSE (Run entire stack in containers)
  docker compose up -d --build


3. VERIFICATION & TESTS
--------------------------------------------------------------------------------
• Run backend test suite (104 passed across 7 test suites):
    pytest
• Verify P2 Encrypted Traffic benchmark (234k flows):
    python backend/scripts/reproduce_encrypted_benchmark.py --verify
• Verify P4 Adversarial Defense benchmark:
    python backend/scripts/reproduce_adversarial_benchmark.py --verify


4. DATASET SOURCES
--------------------------------------------------------------------------------
• NSL-KDD: Included locally in `backend/data/raw/` & `Data_csv/`.
  URL: https://www.unb.ca/cic/datasets/nsl.html
• Encrypted TLS Traffic: Included locally in `backend/data/raw/encrypted_traffic/`.
  URL: https://www.stratosphereips.org/datasets-malware


6. END-TO-END SYSTEM FLOW DIAGRAM
--------------------------------------------------------------------------------

  +-----------------------+              +------------------------------+
  |  Network Flow Events  |              |   Encrypted TLS Sessions     |
  |  (NSL-KDD Benchmark)  |              |  (828k Malware / Benign Flow)|
  +-----------+-----------+              +--------------+---------------+
              |                                         |
              v                                         v
  +-----------------------+              +------------------------------+
  | Preprocessing Pipeline|              | Metadata Extractor (P2)      |
  | (48 Standard Features)|              | (71 Observable TLS Features) |
  +-----------+-----------+              +--------------+---------------+
              |                                         |
              +-------------------+---------------------+
                                  |
                                  v
  +---------------------------------------------------------------------+
  |                   AEGIS THREAT DETECTION ENGINE                     |
  |                                                                     |
  |  [P1: Zero-Day & Known]      [P2: Encrypted]      [P4: Hardening]   |
  |  +--------------------+     +---------------+    +---------------+  |
  |  | MLP Bottleneck     |     | XGBoost TLS   |    | FGSM / UAP    |  |
  |  | Reconstruction Net |     | Classifier    |    | Adversarial   |  |
  |  | (Threshold tau)    |     | (300 Trees)   |    | Robustness    |  |
  |  +---------+----------+     +-------+-------+    +-------+-------+  |
  |            |                        |                    |          |
  |            v                        v                    v          |
  |     Reconstruction            Encrypted Threat       Hardened       |
  |     Anomaly Scores            Family Inferences     Predictions     |
  +-------------------------------------+-------------------------------+
                                        |
                                        v
  +---------------------------------------------------------------------+
  |             P3: RISK TRIAGE & PRIORITISATION ENGINE                 |
  |                                                                     |
  | Priority = 0.35*Confidence + 0.25*ReconAnomaly + 0.15*FamilySeverity|
  |            + 0.15*AssetCriticality + 0.10*ZeroDayBonus              |
  |                                                                     |
  |         [Critical Tier]         [Review Tier]         [Auto-log]    |
  |           (Score >= 0.59)      (0.14 <= S < 0.59)      (Score < 0.14)|
  +-------------------------------------+-------------------------------+
                                        |
                                        v
  +---------------------------------------------------------------------+
  |                 FASTAPI BACKEND REST CONTROLLERS                    |
  |          (/api/detect, /api/encrypted, /api/adversarial)            |
  +-------------------------------------+-------------------------------+
                                        |
                     +------------------+------------------+
                     |                                     |
                     v                                     v
       +----------------------------+        +---------------------------+
       | Elasticsearch Cluster      |        | React 19 SOC Dashboard    |
       | (or demo_alerts.json       |------->| • Threat Operations       |
       |  graceful fallback)        |        | • Zero-Day & Encrypted Lab|
       +----------------------------+        | • Adversarial Cockpit     |
                                             +---------------------------+

================================================================================

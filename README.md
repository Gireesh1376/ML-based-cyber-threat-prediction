# AEGIS --- Cybersecurity Operations & Threat Detection Platform

AEGIS is a full-stack platform for detecting network threats, analysing
encrypted TLS traffic, prioritising security alerts, and evaluating
resistance to adversarial evasion.

## Project Overview

-   **Frontend:** React 19, Vite, TypeScript
-   **Backend:** FastAPI (Python)
-   **Machine learning:** XGBoost and an MLPRegressor bottleneck
    reconstruction network
-   **Alert storage:** Elasticsearch (optional), with automatic fallback
    to `demo_alerts.json`
-   **Dashboard:** SOC operations dashboard with threat detection,
    encrypted traffic analysis, alert triage, and adversarial testing

## Core Capabilities

1.  **Zero-Day & Known Threat Detection:** Hybrid XGBoost and
    reconstruction-based anomaly detection using the NSL-KDD dataset.
2.  **Encrypted TLS Threat Detection:** Analyses 71 observable traffic
    metadata features, including JA4 and packet size/direction patterns,
    without decrypting payloads.
3.  **Alert Prioritisation:** Assigns alerts to Critical, Review, and
    Auto-log tiers using a five-factor risk score: attack confidence,
    reconstruction anomaly, family severity, asset criticality, and
    zero-day indicator.
4.  **Adversarial Robustness:** Evaluates and hardens detection against
    constrained FGSM, UAP, and DEMGAN-style manifold-drift
    perturbations.

## Datasets

-   **NSL-KDD:** Used for zero-day detection, alert prioritisation, and
    adversarial robustness. Dataset files are included under
    `backend/data/raw/` and `Data_csv/`.
-   **Encrypted TLS traffic:** Used for encrypted traffic detection.
    Dataset files are included under
    `backend/data/raw/encrypted_traffic/`.

## Requirements

-   Python 3.11 or later
-   Node.js 18 or later (includes npm)
-   Docker and Docker Compose (optional; used for Elasticsearch)

## Setup

Run these commands from the project root.

### 1. Configure environment

Copy `.env.example` to `.env`:

``` powershell
copy .env.example .env
```

Default configuration:

``` env
ELASTICSEARCH_URL=http://localhost:9200
ELASTICSEARCH_INDEX=aegis-alerts
BACKEND_HOST=127.0.0.1
BACKEND_PORT=8000
```

Elasticsearch is optional. If it is unavailable, the application uses
the pre-loaded `demo_alerts.json` fallback.

### 2. Install dependencies

``` powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Install frontend dependencies

``` powershell
cd frontend
npm install
cd ..
```

## Run the Project
Open two terminals from the project root.

**Terminal 1 --- Backend**

``` powershell
.venv\Scripts\activate
cd backend
uvicorn app.main:app --reload --port 8000
```

**Terminal 2 --- Frontend**

``` powershell
cd frontend
npm run dev
```

### Option C: Docker Compose

If Docker is installed:

``` bash
docker compose up -d --build
```

## Access the Application

-   **SOC Dashboard:** http://localhost:5173
-   **Backend API:** http://localhost:8000
-   **Interactive API documentation:** http://localhost:8000/docs
-   **Elasticsearch (optional):** http://localhost:9200

## Verification

Run the backend tests from the project root:

``` bash
cd backend
python -m pytest tests -q
```

Reproduce the benchmark evaluations:

``` bash
# Encrypted TLS benchmark
python scripts/reproduce_encrypted_benchmark.py --verify

# Adversarial robustness benchmark
python scripts/reproduce_adversarial_benchmark.py
```

## Important Scope Notes

-   The current release supports offline demonstrations, preset
    simulations, and API-based flow ingestion.
-   Live network-interface packet capture is not enabled.
-   Arbitrary raw PCAP analysis is not implemented;
    `/api/encrypted/analyze-pcap` returns HTTP 501.
-   Encrypted traffic is analysed using supplied flow metadata; payloads
    are not decrypted.
-   The project is a benchmark/demo platform and is not presented as a
    fully integrated live SOC or SIEM/SOAR deployment.

## Dataset References

-   NSL-KDD: https://www.unb.ca/cic/datasets/nsl.html
-   Stratosphere Malware/TLS datasets:
    https://www.stratosphereips.org/datasets-malware

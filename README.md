# AEGIS – Cybersecurity Operations & Threat Detection Platform

AEGIS is a machine-learning-based cybersecurity platform designed to detect network threats, analyse encrypted TLS traffic, prioritise security alerts, and evaluate the robustness of detection models against adversarial evasion techniques.

The project combines a React-based security operations dashboard with a FastAPI backend and machine learning components. It brings multiple threat-analysis capabilities together in one interface, making it easier to inspect detections, review alert priorities, and run benchmark evaluations.

## Key Features

### 1. Known and Zero-Day Threat Detection
- Uses a hybrid detection approach combining **XGBoost classification** and an **MLPRegressor-based reconstruction model**.
- Uses the NSL-KDD dataset for model development and evaluation.
- Combines classification results with reconstruction-based anomaly signals to help identify potentially unfamiliar attack patterns.

### 2. Encrypted TLS Traffic Analysis
- Analyses encrypted traffic through observable flow and TLS metadata rather than decrypting packet payloads.
- Uses 71 metadata features, including JA4-related information, cipher-suite details, SNI entropy, and packet size/direction patterns.
- Supports analysis of the supplied encrypted-traffic dataset and benchmark workflow.

### 3. Intelligent Alert Prioritisation
- Calculates a risk score using five factors:
  - Attack confidence
  - Reconstruction anomaly
  - Attack-family severity
  - Asset criticality
  - Zero-day indicator
- Groups alerts into **Critical**, **Review**, and **Auto-log** tiers to support security-alert triage.

### 4. Adversarial Robustness Evaluation
- Evaluates how detection behaves under adversarial perturbations.
- Includes constrained FGSM, Universal Adversarial Perturbation (UAP), and DEMGAN-style manifold-drift experiments.
- Provides benchmark scripts for reproducing the robustness evaluations. The DEMGAN-style approach is an empirical surrogate rather than a separately trained neural GAN.

## Technology Stack

| Component | Technologies |
|---|---|
| Frontend | React 19, Vite, TypeScript |
| Backend | Python, FastAPI |
| Machine Learning | XGBoost, scikit-learn, MLPRegressor |
| Alert Storage | Elasticsearch (optional), JSON fallback |
| Data | NSL-KDD and encrypted TLS traffic datasets |

## Datasets

- **NSL-KDD:** Used for known/zero-day threat detection and related model evaluations. Dataset files are available under `backend/data/raw/` and `Data_csv/`.
- **Encrypted TLS traffic:** Used for encrypted traffic analysis. Dataset files are available under `backend/data/raw/encrypted_traffic/`.

The project uses the datasets included in the repository. Refer to the original dataset sources for further details:

- [NSL-KDD Dataset](https://www.unb.ca/cic/datasets/nsl.html)
- [Stratosphere Malware/TLS Datasets](https://www.stratosphereips.org/datasets-malware)

## Architecture at a Glance

1. The **React dashboard** provides the user interface for viewing detections, analysing encrypted traffic, reviewing alerts, and accessing adversarial evaluation features.
2. The **FastAPI backend** exposes the application endpoints and connects the interface to the analysis and machine-learning components.
3. The **ML components** process the supported datasets and traffic features to generate detection and anomaly signals.
4. The **alert-prioritisation component** combines risk factors to assign alert tiers.
5. **Elasticsearch** can be used for alert storage. If it is unavailable, the application can use the preloaded `demo_alerts.json` fallback.

## Requirements

- Python 3.11 or later
- Node.js 18 or later (includes npm)
- Docker and Docker Compose (optional; used for Elasticsearch)

## Installation and Setup

Run the following commands from the project root.

### 1. Configure environment

Copy the example environment file:

```powershell
copy .env.example .env
```

The default configuration is:

```env
ELASTICSEARCH_URL=http://localhost:9200
ELASTICSEARCH_INDEX=aegis-alerts
BACKEND_HOST=127.0.0.1
BACKEND_PORT=8000
```

Elasticsearch is optional. If it is unavailable, the application uses the preloaded `demo_alerts.json` fallback.

### 2. Install dependencies

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Install frontend dependencies

```powershell
cd frontend
npm install
cd ..
```

## Running the Application

Choose one of the following methods.

### Option A: Windows launcher
Open two terminals in the project root.

**Terminal 1 – Backend**

```powershell
.venv\Scripts\activate
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 – Frontend**

```powershell
cd frontend
npm run dev
```

### Option C: Docker Compose

If Docker is installed and configured:

```bash
docker compose up -d --build
```

## Application URLs

| Service | URL |
|---|---|
| AEGIS Dashboard | http://localhost:5173 |
| Backend API | http://localhost:8000 |
| Interactive API documentation | http://localhost:8000/docs |
| Elasticsearch (optional) | http://localhost:9200 |

## Testing and Benchmark Reproduction

Run the backend test suite from the project root:

```bash
cd backend
python -m pytest tests -q
```

To reproduce the benchmark evaluations, run the scripts from the `backend` directory:

```bash
# Encrypted TLS benchmark
python scripts/reproduce_encrypted_benchmark.py --verify

# Adversarial robustness benchmark
python scripts/reproduce_adversarial_benchmark.py
```

## Current Scope and Limitations

- The current release supports offline demonstrations, preset simulations, and API-based flow ingestion.
- Live network-interface packet capture is not enabled.
- Arbitrary raw PCAP analysis is not implemented; `/api/encrypted/analyze-pcap` currently returns HTTP 501.
- Encrypted traffic analysis uses supplied flow and TLS metadata. The application does not decrypt payloads.
- A working Elasticsearch instance is optional for the demonstration setup; the application can fall back to the provided demo alerts.
- AEGIS is a research and benchmark demonstration platform. It should not be considered a fully integrated production SOC or SIEM/SOAR deployment.

## Notes

- Keep the supplied dataset directory structure intact so the application and benchmark scripts can locate the files.
- Use the interactive API documentation at `http://localhost:8000/docs` to inspect the available backend endpoints after starting the server.
- If you encounter dependency or environment issues, verify that the required Python and Node.js versions are installed and that the commands are being run from the correct directories.

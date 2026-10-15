# Aegis — ML-Based Cyber Threat Prediction

Full-stack SOC dashboard for the academic project **ML-Based Cyber Threat Prediction**. This release implements **Problem 1: zero-day / unknown attack detection** and **Problem 3: alert prioritisation** with a hybrid Autoencoder + XGBoost pipeline in the style of Dai et al. (2024, PLOS ONE).

## Architecture

- **Frontend:** React + Vite + TypeScript, operations dashboard
- **Backend:** FastAPI
- **Detector:** StandardScaler + One-Hot features → XGBoost feature selection → MLP autoencoder on benign traffic → XGBoost known-family classifier → novel-threat gate from reconstruction error
- **Dataset:** NSL-KDD (auto-downloaded on first training run). Attack types absent from the official train split (and a configured hold-out set) are treated as zero-days

Problems 2 (encrypted traffic) and 4 (adversarial evasion) are mapped in the product roadmap but not yet built. Problem 3 (alert prioritisation) is implemented and evaluated below — composite priority, tiered triage, SHAP explanations, an unknown-service review floor, and unit tests all ship.

## Problem 3 — alert prioritisation

Every scored flow gets a composite priority in [0, 1]. Weights **sum to exactly 1.0** and the confidence term is **class-aware** (high confidence in a *benign* prediction contributes low risk):

```
priority = 0.35 * p_attack                            # confidence in the predicted class (1-c for benign)
         + 0.25 * min(recon_error / threshold, 20)/20 # reconstruction anomaly, saturated at 20×
         + 0.15 * family_severity[predicted]          # dos 1.0 · u2r 0.95 · r2l 0.80 · probe 0.70 · normal 0
         + 0.15 * asset_criticality[service]          # documented map, 78 NSL-KDD services, [0,1]
         + 0.10 * 1.0 if flagged novel/zero-day
```

- **Asset criticality** (literature-review requirement) uses the `SERVICE_CRITICALITY` map in `backend/app/config.py`: remote-access/name-resolution services score highest (ssh 0.95, remote-login services up to 1.0), web tier mid (http 0.55), discard/echo utilities lowest (0.35). **Unknown services are never silently treated as unimportant**: they get neutral 0.5 and are **floored to the Review tier** with a data-quality flag and an explanation string.
- The confidence signal counts *risk of attack*, not raw top-class probability — a benign prediction at 0.99 confidence scores near zero on this term.
- The zero-day bonus is a small additive term; the with/without ablation is reported below.

Flows are sorted into **Critical / Review / Auto-logged** tiers. Cutoffs derive **from the validation split's TRUE labels only** (`derive_tier_cutoffs`: Critical cut = score quantile capturing 85% of true-attack validation flows; Review cut = 95th percentile of true-benign validation scores, plus a monotonicity guard), so official-test numbers stay honest. Every alert carries `tier_reason`, the per-component breakdown, and data-quality flags.

## Final results (validated run: tune_novelty → train → evaluate → baselines)

All numbers below come from `metrics.json` / `baselines.json` / `novelty_tuning.json` of the final run. Novelty settings were **chosen on validation data only** (leave-family-out pseudo-zero-days `back, nmap, warezclient`; budget: benign FPR ≤ 0.05): reconstruction quantile **0.96**, novelty gate **0.9**, reconstruction threshold 0.2471. The official test split was not used to choose them. Tier cutoffs: Critical ≥ 0.590, Review ≥ 0.136.

### Detection (Problem 1)

| Metric | Value |
| --- | --- |
| Known-class validation (accuracy / F1) | 97.9% / 0.978 |
| NSL-KDD official test (accuracy / F1 / ROC-AUC) | 87.45% / 0.884 / 0.9528 |
| Held-out zero-days not classified benign | 76.4% |
| Held-out zero-days explicitly flagged `zero_day` | 49.4% |
| Zero-day screening precision / recall / F1 | 0.52 / 0.49 / 0.50 |

**Detector comparison (official test, 12 833 attacks):**

| Detector | Precision | Recall | F1 | Benign FPR | Missed attacks |
| --- | --- | --- | --- | --- | --- |
| Classifier only (XGBoost) | 0.969 | 0.650 | 0.778 | 2.8% | 4497 |
| Anomaly only (autoencoder) | 0.934 | 0.788 | 0.855 | 7.4% | 2722 |
| **Hybrid (deployed)** | 0.931 | 0.841 | 0.884 | 8.2% | 2036 |

**Baseline models (same training data; `baselines.json`):**

| Model | Precision | Recall | F1 | Benign FPR | Held-out zero-days not called benign |
| --- | --- | --- | --- | --- | --- |
| Decision Tree | 0.967 | 0.650 | 0.777 | 2.9% | 37.3% |
| Logistic Regression | 0.917 | 0.625 | 0.743 | 7.5% | 43.4% |
| Linear SVM | 0.915 | 0.612 | 0.734 | 7.5% | 39.3% |
| Random Forest | 0.968 | 0.615 | 0.752 | 2.7% | 26.7% |
| XGBoost (binary) | 0.968 | 0.659 | 0.784 | 2.8% | 40.3% |

**Reading:** the hybrid reaches recall 0.84 versus ≤ 0.66 for every supervised baseline, and detects 76% of held-out zero-days versus ≤ 43%. It pays for this with a higher benign false-positive rate (8.2% versus 2.7–7.5%). Zero-day *precision* is modest (0.52): `zero_day` is a screening signal for analyst review, not a verdict.

Per-attack-family test results are written to `metrics.json → per_family_test` by `python -m app.ml.evaluate`.

### Alert prioritisation (Problem 3)

| Tier | Flows | Attacks in tier | Precision | Benign FPR | Alerts / 1000 flows |
| --- | --- | --- | --- | --- | --- |
| critical | 10177 | 9537 | 0.937 | 6.6% | 451.43 |
| review | 1621 | 1426 | 0.880 | 2.0% | 71.9 |
| auto-log | 10746 | 1870 | 0.174 | 91.4% | 476.67 |

Human-review workload **52.3%** of flows; **85.4%** of attacks and **78.2%** of held-out zero-days reach a human tier.

**Composite vs confidence-only at the same queue size (K = 11798):** composite P@K 0.9316, zero-day capture 0.7803; confidence-only P@K 0.9313, zero-day capture 0.7752. **The composite ties confidence-only; it does not beat it.**

| Queue K | Composite P@K | Raw conf-only P@K | Class-aware conf-only P@K | Composite ZD@K | Class-aware ZD@K |
| --- | --- | --- | --- | --- | --- |
| 50 | 0.820 | 0.000 | 1.000 | 0.001 | 0.000 |
| 100 | 0.900 | 0.000 | 1.000 | 0.001 | 0.000 |
| 200 | 0.905 | 0.000 | 1.000 | 0.006 | 0.000 |
| 500 | 0.958 | 0.000 | 1.000 | 0.007 | 0.000 |
| 1000 | 0.950 | 0.000 | 1.000 | 0.083 | 0.000 |
| 2000 | 0.929 | 0.003 | 1.000 | 0.239 | 0.000 |

**Ablation at the deployed queue size:**

| Variant | P@K | Zero-day capture | FN outside queue |
| --- | --- | --- | --- |
| conf_only | 0.9313 | 0.7752 | 1846 |
| conf_recon | 0.9313 | 0.7763 | 1845 |
| conf_recon_family | 0.9313 | 0.7763 | 1845 |
| conf_recon_family_asset | 0.9316 | 0.7803 | 1842 |
| full | 0.9316 | 0.7803 | 1842 |
| full_without_zero_day_bonus | 0.9316 | 0.7803 | 1842 |

**Auto-logging safety.** 10746 flows (47.7%) are auto-logged; 1870 of them are real attacks (14.6% of all attacks) and 779 are held-out zero-days (21.8%). Every one of these attacks was predicted `normal` with high confidence and low reconstruction error, so this is a **detector blind spot, not a ranking error**: the prioritiser cannot rescue a flow both detectors confidently call benign.

**Composite priority conclusion:** it is justified as a transparent, explainable, asset- and severity-aware ordering with a documented unknown-asset policy, not as a more accurate ranker than confidence alone.

## Alignment notes (project documents vs implementation)

- **Architecture order.** The literature review describes autoencoder-first, then XGBoost. The implementation scores every flow with both models in parallel and promotes it to `zero_day` when `anomaly AND (known_label == normal OR confidence < novelty_gate)`. Same inputs and outputs, different order.
- **Autoencoder.** scikit-learn `MLPRegressor` autoencoder (not Keras); Isolation Forest is not used. Both are "and/or" options in the proposal.
- **Settings tuned without the test split.** Reconstruction quantile and novelty gate come from `app.ml.tune_novelty` (leave-family-out validation). Pseudo-zero-days differ from the real test zero-days, so the chosen values are validation-justified, not guaranteed optimal.
- **Service map.** All 78 NSL-KDD services are mapped; unknown services (callers can send any string) still fall back to 0.5 and are floored to Review. The 13 services added late use design-choice values.
- **Explanations.** `top_features` are SHAP values for the XGBoost reading. `anomaly_features` (new) give each feature's share of the autoencoder reconstruction error, which is the relevant justification for a `zero_day` alert.
- **Baselines** (Decision Tree, Logistic Regression, linear SVM, Random Forest, XGBoost) are reported above, as the proposal requires.
- **Datasets / storage.** Only NSL-KDD is used (no CICIDS2017/18). Alerts are replayed from `demo_alerts.json`; Elasticsearch, real-time capture (Scapy/PyShark) and Kafka are future work.
- **Base rate.** The NSL-KDD test split is 56.9% attacks, so alerts-per-1000-flows figures do not transfer to a real network.

## Known limitations (stated honestly)

- **Benchmark, not a live SOC.** NSL-KDD is a standard but dated benchmark; the dashboard replays test-split flows. No SIEM/SOAR integration is claimed.
- **"Zero-day" = held-out attack families**, not real-world novel exploits.
- **Confident misses.** About 14.6% of attacks (21.8% of held-out zero-days) are auto-logged because both detectors confidently call them normal. Reducing this needs a better detector or a stricter policy, and a stricter Review policy costs analyst workload.
- Detection is strongest for DoS (95%) and probe (96%) attacks. R2L attacks are detected 45% of the time and U2R 66%, which is where most of the 14.6% auto-logged attacks come from.
- **Zero-day precision is modest** (see table): treat `zero_day` as a screening signal.
- **Weights, family severities and the 85%/95% cutoff targets are design choices**, set on validation data and not optimised end-to-end.
- **Asset criticality is a static service map**; in production it would come from a CMDB. The API accepts an analyst override (`asset_criticality` in [0,1]).
- **SHAP covers the classifier only**; the autoencoder is explained by `anomaly_features`.
- **Problems 2 (encrypted traffic) and 4 (adversarial evasion) are not built.**

## Full reproduction order

```bash
cd backend
python -m app.ml.tune_novelty      # 1. validation-only choice of recon quantile + novelty gate
python -m app.ml.train             # 2. train + write metrics.json / demo_alerts.json
python -m app.ml.evaluate          # 3. detection comparison, tiers, safety audit, per-family results
python -m app.ml.baselines         # 4. DT / LR / SVM / RF / XGBoost comparison
python -m pytest tests -q
```

## Run locally

Backend (Python 3.11+):

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate  |  macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

# Train the hybrid detector (downloads NSL-KDD on first run, ~3 min on CPU)
python -m app.ml.train

# Start the API on http://localhost:8000
python -m uvicorn app.main:app --reload --port 8000
```

Frontend (Node 18+):

```bash
cd frontend
npm install
npm run dev   # http://localhost:5173, proxies /api to the backend
```

Retraining regenerates `backend/models/` (artifacts, metrics, demo alerts). The dataset is cached in `backend/data/raw/`.

> **Model format note:** the XGBoost booster is saved in its **native JSON format** (`hybrid_detector_xgb.json`), not pickled. A pickled XGBClassifier only loads under the exact xgboost version that trained it; the native format is stable across versions, so the model survives pip upgrades. The scaler, encoder, autoencoder and thresholds stay in the joblib bundle (`hybrid_detector.joblib`) and the booster is re-attached by `load_artifacts`. If the native file is missing, retraining is required.

## API

- `GET /api/health` — liveness
- `GET /api/model/status` — whether trained artifacts are loaded
- `GET /api/dashboard/summary` — KPIs, alert mix, severity mix
- `GET /api/model/metrics` — full training/evaluation metrics
- `GET /api/alerts` — priority-queue replay sample scored from the NSL-KDD test split; accepts `?tier=critical|review|auto_log` (comma-separated allowed), `?sort=priority|id`, `?limit=N`
- `GET /api/detect/schema` — feature list and lab presets
- `POST /api/detect` — score one NSL-KDD-style flow (returns `priority`, `priority_components`, `tier`)
- `POST /api/detect/batch` — score up to 50 flows
- `POST /api/detect/replay/{alert_id}` — re-score an alert's stored feature payload (exact reproduction)

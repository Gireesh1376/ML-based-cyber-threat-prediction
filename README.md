# Aegis — ML-Based Cyber Threat Prediction

Full-stack SOC dashboard for the academic project **ML-Based Cyber Threat Prediction**. This release implements **Problem 1: zero-day / unknown attack detection**, **Problem 2: encrypted TLS traffic threat detection**, **Problem 3: alert prioritisation**, and **Problem 4: adversarial evasion robustness** with a hybrid Autoencoder + XGBoost pipeline in the style of Dai et al. (2024, PLOS ONE) and Xu et al. (2025, CMC).

## Architecture

- **Frontend:** React + Vite + TypeScript, SOC operations dashboard with Zero-Day Studio, Encrypted Traffic Lab, Adversarial Defense Cockpit, and Incident Triage queue.
- **Backend:** FastAPI with modular routers for `/api/detect`, `/api/encrypted`, `/api/priority`, and `/api/adversarial`.
- **Detectors:**
  - *Problem 1 (Zero-Day):* StandardScaler + One-Hot features → XGBoost feature selection → PyTorch MLP autoencoder on benign traffic → XGBoost known-family classifier → novel-threat gate from reconstruction error.
  - *Problem 2 (Encrypted TLS):* Leakage-resistant feature transformer (71 observable features: JA4 fingerprint prefix, cipher suites, SNI entropy, and SPLT packet size/direction sequences) → XGBoost classifier (300 estimators) without decrypting payloads. Evaluated on 18,874 holdout TLS connections (ROC-AUC 0.9996, PR-AUC 0.9996, F1 0.9938).
  - *Problem 3 (Prioritisation):* Class-aware composite score ($w_a \cdot S_a + w_c \cdot C_{asset} + w_u \cdot U + w_v \cdot V - w_h \cdot H$) sorting alerts into Critical, Review, and Auto-logged tiers.
  - *Problem 4 (Adversarial Robustness):* Adversarially hardened model artifact trained against gradient-based (FGSM, PGD) and distribution (UAP, DEMGAN) perturbations under physical flow constraints.
- **Datasets:** NSL-KDD benchmark for Problem 1, 3, and 4; Stratosphere/Malware TLS Parquet benchmark for Problem 2.
- **Database:** Elasticsearch (`aegis-alerts` index) with automatic graceful fallback to `demo_alerts.json` when disconnected.

### Operational Scope and Limitations

- **Live Network Capture:** Live packet capture from network interfaces is **disconnected**. The system operates in offline demonstration, synthetic preset simulation, and API batch ingestion mode.
- **Arbitrary PCAP Dissection:** The `/api/encrypted/analyze-pcap` endpoint intentionally returns **HTTP 501 Not Implemented**. In accordance with privacy and security principles, payloads are never decrypted, and connection metadata must be supplied as flow records.

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

## Problem 4 — adversarial evasion robustness

Modern ML classifiers can be misled by input perturbations. Attackers mutate flow characteristics (such as packet arrival timing, connection durations, payload padding, and error rates) to push attack flows across the decision boundary into `normal`.

Aegis implements network-protocol-constrained adversarial sample synthesis (**Constrained FGSM**, **Universal Adversarial Perturbations / UAP**, and **DEMGAN Manifold Drift Approximation**) and iterative adversarial retraining following the methodology of Xu et al. (2025, CMC) and Zhang et al. (2025):

- **Genuine Model Feedback:**
  - **Constrained FGSM:** Implements two-sided numerical finite difference gradients of the hybrid detector's composite evasion loss, stepping mutable features in the direction of $-\text{sign}(\nabla \mathcal{L}_{\text{evasion}})$.
  - **Universal Adversarial Perturbation (UAP):** Optimizes a single universal shift vector against model predictions over training attack flows to maximize the multi-flow evasion rate under bounded perturbation budget $\|\mathbf{v}\|_\infty \le \epsilon$.
  - **DEMGAN Manifold Drift Approximation:** Generative multi-feature drift towards empirical benign traffic distributions with calibrated stochastic jitter. (Note: Evaluated as an empirical manifold-drift surrogate approximation; not a trained neural GAN generator).
- **Domain Invariants & Protocol Semantics Enforced:** Unlike computer vision perturbations, network packets are semantically coupled. All rate features (`serror_rate`, `same_srv_rate`, etc.) are strictly clamped in $[0.0, 1.0]$ with complementary sum normalization ($\text{serror} + \text{rerror} \le 1.0$), counts are discrete non-negative integers with hierarchy preservation ($\text{dst\_host\_srv\_count} \le \text{dst\_host\_count}$), UDP/ICMP traffic strictly zeroes TCP SYN error rates, and immutable protocol headers (`protocol_type`, `service`, `land`, session states) cannot be altered by packet injection.
- **Dual-Model Resilience:** The XGBoost classifier is hardened by retraining on 149,973 clean and constraint-validated adversarial samples (`hybrid_detector_hardened_xgb.json` and `hybrid_detector_hardened.joblib`). Additionally, the Autoencoder anomaly layer acts as a defense-in-depth barrier: even when an attacker lowers classifier confidence, non-standard feature variance inflates reconstruction error, catching perturbed attacks as novel/zero-day anomalies.

### Adversarial Robustness Benchmark (Official Test Set, Held-Out Split):

| Metric | Baseline Model | Hardened Retrained Model | Delta / Benefit |
| --- |:---:|:---:|:---:|
| **Clean Attack Recall** | 87.67% | **87.60%** | Zero clean degradation (-0.07% abs) |
| **Clean Binary Accuracy** | 89.80% | **89.77%** | Clean performance preserved (-0.03% abs) |
| **Benign False Alarm Rate (FPR)** | 8.07% | **8.07%** | **0.0% False Alarm Penalty** |
| **FGSM Classifier Evasion ($\epsilon = 0.20$)** | 83.13% | **14.47%** | **-68.7% abs (-82.6% relative drop)** |
| **FGSM Hybrid Evasion ($\epsilon = 0.20$)** | 18.53% | **8.20%** | **+55.8% Evasion Mitigation** |
| **UAP Classifier Evasion ($\epsilon = 0.20$)** | 90.07% | **1.73%** | **-88.3% abs (Transfer UAP neutralized)** |
| **UAP Hybrid Evasion ($\epsilon = 0.20$)** | 16.07% | **1.67%** | **+89.6% Evasion Mitigation** |
| **DEMGAN Hybrid Evasion ($\epsilon = 0.20$)** | 15.07% | **10.73%** | **+28.8% Evasion Mitigation** |
| **Adaptive FGSM Hardened Evasion** | — | **11.60%** | Evaluated directly against hardened detector |
| **Adaptive UAP Hardened Evasion** | — | **10.40%** | Hardened UAP vector against complete detector |
| **Constraint Validity Rate** | 100.0% | **100.0%** | 13,500/13,500 flows pass all network invariants |

## Alignment notes (project documents vs implementation)

- **Architecture order.** The literature review describes autoencoder-first, then XGBoost. The implementation scores every flow with both models in parallel and promotes it to `zero_day` when `anomaly AND (known_label == normal OR confidence < novelty_gate)`. Same inputs and outputs, different order.
- **Autoencoder.** scikit-learn `MLPRegressor` autoencoder (not Keras); Isolation Forest is not used. Both are "and/or" options in the proposal.
- **Settings tuned without the test split.** Reconstruction quantile and novelty gate come from `app.ml.tune_novelty` (leave-family-out validation). Pseudo-zero-days differ from the real test zero-days, so the chosen values are validation-justified, not guaranteed optimal.
- **Service map.** All 78 NSL-KDD services are mapped; unknown services (callers can send any string) still fall back to 0.5 and are floored to Review. The 13 services added late use design-choice values.
- **Explanations.** `top_features` are SHAP values for the XGBoost reading. `anomaly_features` give each feature's share of the autoencoder reconstruction error, which is the relevant justification for a `zero_day` alert.
- **Baselines** (Decision Tree, Logistic Regression, linear SVM, Random Forest, XGBoost) are reported above, as the proposal requires.
- **Problem 4 Hardening:** Retrained XGBoost on domain-constrained adversarial variants, reducing evasion by 45.9% without increasing false alarms.
- **Datasets / storage.** Only NSL-KDD is used (no CICIDS2017/18). Alerts are replayed from `demo_alerts.json`; Elasticsearch, real-time capture (Scapy/PyShark) and Kafka are future work.
- **Base rate.** The NSL-KDD test split is 56.9% attacks, so alerts-per-1000-flows figures do not transfer to a real network.

## Known limitations (stated honestly)

- **Benchmark, not a live SOC.** NSL-KDD is a standard but dated benchmark; the dashboard replays test-split flows. No SIEM/SOAR integration is claimed.
- **"Zero-day" = held-out attack families**, not real-world novel exploits.
- **Confident misses.** About 14.6% of attacks (21.8% of held-out zero-days) are auto-logged because both detectors confidently call them normal. Reducing this needs a better detector or a stricter policy, and a stricter Review policy costs analyst workload.
- Detection is strongest for DoS (95%) and probe (96%) attacks. R2L attacks are detected 45% of the time and U2R 66%, which is where most of the 14.6% auto-logged attacks come from.
- **Zero-day precision is modest** (see table): treat `zero_day` as a screening signal.
- **Adversarial evasion is a mitigation, not an absolute fix.** Retraining defends against perturbation spaces the model has been exposed to. Adversarial robustness is an ongoing arms race, and no intrusion detection model in published literature achieves 100% permanent evasion immunity.
- **Problem 2 (encrypted traffic analysis) is planned for future milestones.**

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
- `GET /api/adversarial/metrics` — empirical robustness metrics (Baseline vs. Hardened under DEMGAN/FGSM/UAP attacks)
- `GET /api/adversarial/presets` — attack flow presets (known DoS, stealthy portscan, zero-day evasion attempts)
- `POST /api/adversarial/simulate` — execute live dual-model adversarial attack simulation with domain constraint enforcement


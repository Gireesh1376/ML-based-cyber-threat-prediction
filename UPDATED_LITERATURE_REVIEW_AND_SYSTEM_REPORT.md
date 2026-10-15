# ML-Based Cyber Threat Prediction
## Updated Literature Review, System Architecture, and Empirical Validation Report

**Domain:** Cybersecurity and Machine Learning  
**Project:** ML-Based Cyber Threat Prediction  
**Authors:** Naga Gireesh Reddy, Mangali Vishnu Datta, Dwarampudi Nihar Reddy, Thalupuri Manideep Sathya  
**Academic Guide:** Mr. M. Rama Krishnam Raju  
**Institution:** Faculty of Science & Technology, The ICFAI Foundation for Higher Education, Hyderabad  

---

## 1. Introduction

Modern enterprise networks face a constantly increasing volume and sophistication of cyber threats. Traditional intrusion detection systems (IDS) relying primarily on static signature databases fail to detect previously unknown attacks and generate substantial alert fatigue for security operations center (SOC) analysts. This research and engineering project addresses these structural operational challenges by designing, implementing, and empirically evaluating a machine-learning-driven Network Intrusion Detection System.

Four critical problem areas define modern network defense research:
1. **Failure to Detect Zero-Day / Unknown Attacks:** Classifiers trained solely on known attack categories cannot identify structurally novel threats.
2. **Blind Spot in Encrypted (TLS/QUIC) Traffic:** The widespread adoption of TLS 1.3, QUIC, and Encrypted Client Hello (ECH) obstructs payload inspection without decryption proxies.
3. **Alert Fatigue from High False-Positive Rates:** High raw alert volumes force analysts to triage thousands of notifications daily, resulting in uninvestigated true attacks.
4. **Adversarial Evasion Vulnerability:** Malicious traffic can be mathematically perturbed to mislead classification models into predicting benign status.

### 1.1 Prototype Implementation Scope
While all four problem domains are formally integrated into the multi-phase program roadmap, this release delivers a fully validated, production-style working prototype for **Problem 1 (Zero-Day Attack Detection)** and **Problem 3 (Alert Prioritisation and Fatigue Mitigation)**. Problems 2 and 4 are architecturally scaffolded in the operations platform and scheduled for subsequent development phases.

---

## 2. Review of Prior Works and Studies

### 2.1 Problem 1 — Zero-Day / Unknown Attack Detection
- **Foundational Study:** Dai, Z., Por, L. Y., Chen, Y.-L., Yang, J., Ku, C. S., Alizadehsani, R., & Pławiak, P. (2024). *An intrusion detection model to detect zero-day attacks in unseen data using machine learning*. **PLOS ONE**, 19(8), e0308006.
- **Key Concepts:** Dai et al. demonstrated that combining an unsupervised anomaly detection layer (which learns normal traffic profiles) with an ensemble classifier significantly improves generalization to unobserved attack types. While Dai et al. reported accuracy figures of 99.97%–99.98% on their proprietary dataset and evaluation setup, empirical validation on standardized, standardized benchmarks (such as NSL-KDD) demonstrates that detection rates on genuinely held-out attack families must be evaluated under strict leave-family-out isolation protocols.

### 2.2 Problem 3 — Alert Prioritisation in Security Operations Centres
- **Foundational Studies:** 
  - Jalalvand, F., Chhetri, M. B., Nepal, S., & Paris, C. (2024). *Alert Prioritisation in Security Operations Centres: A Systematic Survey on Criteria and Methods*. **ACM Computing Surveys**, 57(2), Article 42.
  - Chhetri, M. B., Tariq, S., Singh, R., Jalalvand, F., Paris, C., & Nepal, S. (2024). *Towards Human-AI Teaming to Mitigate Alert Fatigue in Security Operations Centres*. **ACM Transactions on Internet Technology**, 24(3), Article 12.
- **Key Concepts:** Jalalvand et al. formalized an alert ranking taxonomy incorporating multi-criteria inputs (Alert, Asset, Analyst, Organisation, Environment). Chhetri et al. introduced the **A2C (Automated, Augmented, Collaborative)** framework, establishing that systems should not operate on uniform triage: high-confidence routine events should be automated/auto-logged, borderline events deferred to analysts with augmented context, and novel anomalies escalated for joint human-AI investigation.

---

## 3. Implemented System Architecture & Methodology

```
                   Incoming Network Flow (NSL-KDD Features)
                                      │
                   StandardScaler + One-Hot Encoding
                                      │
                      Top-48 XGBoost Feature Selection
                                      │
              ┌───────────────────────┴───────────────────────┐
              ▼                                               ▼
     Unsupervised Autoencoder                       Supervised XGBoost
    (MLPRegressor: 64-24-8-24-64)                 (Multiclass Classifier)
              │                                               │
     Reconstruction Error                           Predicted Family Label
    (Anomaly: Error > 0.2471)                        & Softmax Confidence
              │                                               │
              └───────────────────────┬───────────────────────┘
                                      │
                         Novelty Decision Gate
     [Anomaly = True] AND ([Label = Normal] OR [Confidence < 0.90])
                    ├── True  ──> Final Label: "zero_day"
                    └── False ──> Final Label: Known Family Label
                                      │
                     Composite Priority Calculation
               (Confidence + Reconstruction + Severity + Asset + ZD Bonus)
                                      │
                         Tiered Triage Assignment
              ┌───────────────────────┼───────────────────────┐
              ▼                       ▼                       ▼
           Critical                 Review                Auto-Log
      (Priority ≥ 0.590)       (Priority ≥ 0.136)     (Priority < 0.136)
      Immediate Analyst       Analyst Investigation    Automated Logging
            Queue             (+ Unknown Asset Floor)     (No Review)
```

### 3.1 Problem 1: Dual-Model Hybrid Architecture
Rather than a strict sequential pipeline, the implemented system evaluates every network flow in parallel:
1. **Unsupervised Normal-Traffic Autoencoder:** Trained exclusively on benign network traffic using a multi-layer perceptron autoencoder (`MLPRegressor` with layer architecture 64-24-8-24-64, ReLU activation, Adam optimizer). The model establishes a reconstruction error threshold ($\theta = 0.2471$, corresponding to the 96th percentile of benign reconstruction errors).
2. **Supervised Known-Family Classifier:** An `XGBClassifier` trained on known traffic classes (`normal`, `dos`, `probe`, `r2l`, `u2r`), configured with histogram-based tree optimization (`n_estimators=280`, `max_depth=8`, `learning_rate=0.08`).
3. **Novelty Decision Gate:** A flow is identified as a novel (`zero_day`) attack when:
   $$\text{reconstruction\_error} > \theta \quad \text{AND} \quad \left(\text{predicted\_label} == \text{'normal'} \;\lor\; \text{confidence} < 0.90\right)$$
   If the XGBoost model confidently classifies an anomaly as a known attack family (e.g., confident Neptune DoS with high reconstruction error), it is correctly preserved under that known family rather than falsely labelled as novel.
4. **Validation-Frozen Thresholds:** The reconstruction error quantile (0.96) and the novelty confidence gate (0.90) were derived on validation data using leave-family-out pseudo-zero-days (`back`, `nmap`, `warezclient`), ensuring the official test split remained completely untouched during hyperparameter selection.

### 3.2 Problem 3: Composite Alert Prioritisation Formula
Every scored alert receives a normalized composite priority score in the continuous range $[0, 1]$. All five constituent weights sum to exactly 1.0:

$$\text{Priority} = 0.35 \cdot p_{\text{attack}} + 0.25 \cdot R_{\text{norm}} + 0.15 \cdot S_{\text{family}} + 0.15 \cdot A_{\text{asset}} + 0.10 \cdot B_{\text{zero\_day}}$$

Where:
- $p_{\text{attack}}$: **Class-aware attack risk**. If predicted as `normal`, $p_{\text{attack}} = 1.0 - \text{confidence}$; for attack classes, $p_{\text{attack}} = \text{confidence}$. A high-confidence benign prediction scores near zero.
- $R_{\text{norm}}$: **Normalized anomaly ratio**, computed as $\min(\text{recon\_error} / \theta, 20.0) / 20.0$. Saturated at $20\times$ the threshold to prevent extreme outliers from skewing the triage queue.
- $S_{\text{family}}$: **Threat family severity** based on operational impact (`dos`: 1.00, `zero_day`: 1.00, `u2r`: 0.95, `r2l`: 0.80, `probe`: 0.70, `normal`: 0.00).
- $A_{\text{asset}}$: **Asset criticality score** from an explicit 78-service mapping (`login`/`shell`: 1.00, `ssh`: 0.95, `http`: 0.55, `echo`/`discard`: 0.35).
- $B_{\text{zero\_day}}$: **Novelty incentive bonus** (1.0 if flagged `zero_day`, 0.0 otherwise).

#### Tier Triage and Safety Floor Policy
- **Tiers:** Flows are assigned into **Critical**, **Review**, or **Auto-logged** tiers using cutoffs derived strictly from validation split true labels (Critical cutoff $= 0.5901$, Review cutoff $= 0.1364$).
- **Unknown Asset Review Floor:** Unmapped or novel service names are not assumed to be safe. They receive a neutral criticality of 0.5 and are subjected to a mandatory floor that forces them into the **Review** tier, preventing unclassified assets from ever being auto-logged.

### 3.3 Explainability Layer
To ensure operational usability, every prediction provides dual-model interpretability:
- **SHAP TreeExplainer:** Decomposes the XGBoost classification reading into signed feature impact values.
- **Anomaly Error Attribution:** Computes the exact percentage contribution of each feature to the total squared reconstruction error ($(\mathbf{x}_i - \hat{\mathbf{x}}_i)^2 / \sum (\mathbf{x} - \hat{\mathbf{x}})^2$), explicitly answering why a zero-day flow was deemed structurally abnormal.

---

## 4. Empirical Evaluation Results

All reported figures are generated from the end-to-end execution of the test suite and evaluation modules on the official NSL-KDD test set ($N = 22,544$ flows, comprising $12,833$ real attacks and $9,711$ benign flows, with $3,568$ genuinely held-out zero-day attack samples across 15 families).

### 4.1 Detection Comparison (Problem 1)

| Detector Pipeline | Attack Precision | Attack Recall | Attack F1 | Benign FPR | Missed Attacks | Zero-Day Detection Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Classifier Only (XGBoost)** | **0.969** | 0.650 | 0.778 | **2.78%** | 4,497 | 40.3% |
| **Anomaly Only (Autoencoder)** | 0.934 | 0.788 | 0.855 | 7.41% | 2,722 | 78.8% |
| **Hybrid System (Deployed)** | 0.931 | **0.841** | **0.884** | 8.18% | **2,036** | **76.4%** |

#### Comparison with Supervised Baselines (Same Training Split)
Under identical training splits, purely supervised baselines lack a novelty detection mechanism:
- **Decision Tree:** Recall 0.650, Zero-Day Detection 37.3%
- **Logistic Regression:** Recall 0.625, Zero-Day Detection 43.4%
- **Linear SVM:** Recall 0.612, Zero-Day Detection 39.3%
- **Random Forest:** Recall 0.615, Zero-Day Detection 26.7%
- **XGBoost (Binary):** Recall 0.659, Zero-Day Detection 40.3%

**Empirical Finding:** The hybrid system increases attack recall from $\le 65.9\%$ to **$84.1\%$** and raises held-out zero-day capture from $\le 43.4\%$ to **$76.4\%$**, cutting total missed attacks from 4,497 down to 2,036. The trade-off is an increase in benign false positive rate from $2.8\%$ to $8.2\%$.

#### Zero-Day Screening Specifics
On the 3,568 held-out zero-day attack instances:
- Non-normal detection rate: **76.37%** (2,725 / 3,568).
- Explicit `zero_day` flag rate: **49.41%** (1,763 / 3,568).
- Zero-day screening precision: **0.516** (F1: 0.505, FPR: 8.72%).
*Operational Interpretation:* The zero-day flag functions as an automated screening filter for analyst review, not an autonomous blocking verdict.

---

### 4.2 Alert Prioritisation and Fatigue Mitigation (Problem 3)

| Triage Tier | Flow Count | Attacks in Tier | Tier Precision | Benign FPR (Tier/All Benign) | Workload Share |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Critical Tier** | 10,177 | 9,537 | **93.71%** | 6.59% | 45.14% |
| **Review Tier** | 1,621 | 1,426 | **87.97%** | 2.01% | 7.19% |
| **Auto-Logged Tier** | 10,746 | 1,870 | 17.40% | 91.40% | 47.67% |

- **Analyst Workload Reduction:** The system auto-logs **47.67%** of network traffic, concentrating human attention on the remaining **52.33%** (11,798 flows).
- **Threat Preservation:** Human review tiers successfully capture **85.43%** of all attacks (10,963 / 12,833) and **78.17%** of held-out zero-days (2,789 / 3,568).

#### Ranking Efficacy at Review Queue Budget ($K = 11,798$)

| Ranking Method | Precision@K | Attack Recall@K | Zero-Day Capture@K | False Negatives Outside Queue |
| :--- | :---: | :---: | :---: | :---: |
| **Raw Confidence-Only** | 0.003 | 0.003 | 0.000 | 12,828 |
| **Class-Aware Confidence-Only** | 0.9313 | 0.8562 | 0.7752 | 1,846 |
| **Full Composite Priority (Deployed)** | **0.9316** | **0.8565** | **0.7803** | **1,842** |

**Empirical Finding:** At the operational queue size, the composite ranker ties class-aware confidence ranking (Precision 0.9316 vs 0.9313). The composite priority is justified not by a large statistical ranking gain, but by multi-factor transparency, asset criticality integration, and documented policy enforcement for unmapped services.

#### Auto-Logging Safety Audit
A rigorous cross-tabulation audit was conducted on the 10,746 auto-logged flows:
- **1,870 real attacks (14.57% of all attacks)** and **779 held-out zero-days (21.83% of all zero-days)** are auto-logged.
- **Root Cause Analysis:** 100% of these 1,870 auto-logged attacks had predicted label `normal`, mean confidence of $99.65\%$, and reconstruction error below the anomaly threshold ($0.0933$ vs $\theta = 0.2471$).
- **Conclusion:** This bypass is an **upstream detector blind spot** where attack traffic completely mimics normal statistical distributions. The prioritisation engine routed them consistently based on upstream detector inputs; auto-logging cannot be claimed as universally safe without recognizing this detector residual.

---

## 5. Technology Stack and Verification Status

### 5.1 Realized Software Stack
- **Backend Services:** Python 3.11+, FastAPI REST API, Uvicorn ASGI server.
- **Machine Learning Core:** Scikit-learn (`MLPRegressor`, `StandardScaler`, `OneHotEncoder`), XGBoost (`XGBClassifier`), SHAP (`TreeExplainer`).
- **Frontend SOC Dashboard:** React 18, TypeScript, Vite, Tailwind CSS, Recharts visualization library.
- **Model Persistence:** Joblib for transformer/threshold artifacts; Native XGBoost JSON (`hybrid_detector_xgb.json`) for cross-version model stability.

### 5.2 Verification Suite
The codebase has been verified with a 100% test pass rate:
- `backend/tests/test_priority.py`: 24/24 unit tests passing (verifies weight normalization, directionality, saturation caps, and tier boundaries).
- `backend/tests/test_detect_integration.py`: 12/12 in-process integration tests passing (verifies REST API schema, response consistency, and review floor enforcement).
- `backend/tests/test_anomaly_explanation.py`: 2/2 tests passing (verifies reconstruction error decomposition accuracy).
- `frontend`: TypeScript compilation (`tsc -b`) and Vite production build succeed with zero errors.

---

## 6. Summary of Adjustments from Original Proposal

1. **Architecture Order:** Shifted from sequential filtering to parallel dual-scoring with a Leave-Family-Out tuned novelty gate.
2. **Benchmark Grounding:** Replaced theoretical 99.9% claims with validated NSL-KDD results (87.45% accuracy, 84.1% attack recall, 76.4% zero-day capture, 51.6% zero-day screening precision).
3. **Data Scope:** Standardized on NSL-KDD tabular flows; deferred live packet capture (Scapy/PyShark) and secondary datasets (CICIDS) to future milestones.
4. **Fatigue Mitigation Context:** Documented that composite priority matches confidence ranking precision (0.932) while contributing asset-awareness, explainability, and a 47.7% auto-log workload reduction.
5. **Future Phases:** Retained Problem 2 (Encrypted Traffic Analysis via CNN-BiLSTM) and Problem 4 (Adversarial Robustness via DEMGAN) as mapped roadmap items.

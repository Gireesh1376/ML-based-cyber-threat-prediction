# Document corrections and demo guide (Problems 1 and 3)

All figures are from the final validated run (tune_novelty → train → evaluate → baselines).

## Part A. Wording to change in your documents

### Literature Review, Section 3.1 ("Proposed System")
Replace the sentence "an Autoencoder first learns ... and any traffic it reconstructs poorly is passed to an XGBoost/Random Forest classifier" with:

> The proposed system uses a two-model hybrid. An Autoencoder trained only on normal traffic scores every flow by reconstruction error, and an XGBoost classifier scores every flow against the known attack families. A flow is labelled a novel (zero-day) threat when its reconstruction error exceeds the normal-traffic threshold AND the classifier either reads it as normal or is not confident in a known family (confidence below the novelty gate). The reconstruction threshold and the gate were selected on validation data using leave-family-out pseudo-zero-days, never on the test split.

Replace "directly validated by Dai et al. (2024), whose equivalent hybrid reached 99.97-99.98%" with:

> Dai et al. (2024) report 99.97-99.98% accuracy for a comparable hybrid on their own dataset and setting, which supports the design direction. On the NSL-KDD benchmark used here, the implemented hybrid reaches 87.5% test accuracy with attack recall 0.84, and flags 76% of held-out unseen attack families as non-normal (49% explicitly as zero-day, precision 0.52). The datasets and protocols differ, so the figures are not directly comparable.

### Literature Review, Section 3.1 (explainability)
Replace "every flagged threat carries a human-readable justification" with:

> Every alert carries SHAP feature contributions for the classifier's reading, and, for flows flagged by the Autoencoder, a breakdown of which input features contributed most to the reconstruction error (the reason the flow looks anomalous).

### Literature Review, Section 3.3 (alert fatigue) and Project Outline, Objective 3 / Conclusion
Replace any statement that the risk ranking "reduces alert volume" or "outperforms" with:

> Alerts are ranked by a composite priority (classifier risk, reconstruction anomaly, attack-family severity, asset criticality, novelty flag) and sorted into Critical / Review / Auto-logged tiers using cutoffs derived from validation data. On the NSL-KDD test split, 52.3% of flows reach a human tier, which contain 85.4% of attacks and 78.2% of held-out zero-days. At the same queue size the composite ties a confidence-only ranker (precision 0.932 vs 0.931); its value is transparency, asset- and severity-awareness and a documented policy for unknown assets, not higher ranking accuracy. About 14.6% of attacks are auto-logged because both detectors confidently classify them as normal; this is a detector limitation, not a ranking error.

### Proposal, "Technologies Used" and Abstract
- Autoencoder: state "scikit-learn neural-network autoencoder" (Keras/TensorFlow and Isolation Forest were considered alternatives and are not used).
- "real-time", "live" traffic: state "replay of recorded NSL-KDD traffic through the detection pipeline".
- Elasticsearch, Scapy/PyShark, Kafka, Docker, Next.js: mark as "future work / not implemented in this prototype".
- Dataset: state "NSL-KDD (CICIDS2017/18 and UNSW-NB15 are future work)".
- Charts: dashboard uses Recharts; Plotly/Matplotlib are not used.

### Project Outline, Sections 3 and 4 (scope / timeline)
- Phase 2: "NSL-KDD flow features complete; TLS/handshake metadata and CICIDS datasets deferred (Problem 2)."
- Phase 3: complete. Phase 4: dashboard, SHAP and FastAPI backend complete; Elasticsearch storage deferred.
- Phase 5 (adversarial hardening, Problem 4) and the encrypted-traffic work (Problem 2): planned.
- Scope "Included" list: remove "Elasticsearch for event storage" and "CICIDS2017/2018" or move them to "Planned".

### Add to every document: a one-paragraph "Limitations" note
> NSL-KDD is a dated benchmark with a 57% attack share in the test split, so alert-volume figures do not transfer to real networks. "Zero-day" here means attack families held out of training. The zero-day flag is a screening signal (precision 0.52), not a verdict. Detection is strongest for DoS (95%) and probe (96%) attacks. R2L attacks are detected 45% of the time and U2R 66%, which is where most of the 14.6% auto-logged attacks come from.

## Part B. Final results at a glance

| Item | Value |
| --- | --- |
| NSL-KDD test accuracy / F1 / ROC-AUC | 87.45% / 0.884 / 0.953 |
| Attack recall / benign false-positive rate | 0.841 / 8.2% |
| Best supervised baseline (XGBoost binary) recall | 0.659 (zero-day detection 40%) |
| Held-out zero-days not called benign / flagged zero_day | 76.4% / 49.4% |
| Zero-day precision / recall / F1 | 0.52 / 0.49 / 0.50 |
| Human-review workload | 52.3% of flows |
| Attacks / zero-days reaching a human tier | 85.4% / 78.2% |
| Attacks / zero-days auto-logged | 14.6% / 21.8% |

## Part C. Demo script (about 8 minutes)

1. **Problem and goal (30 s).** Signature tools miss unseen attacks; analysts drown in alerts. Show the Roadmap page: Problems 1 and 3 built, 2 and 4 planned.
2. **Problem 1 design (1 min).** Autoencoder learns normal traffic; XGBoost knows attack families; a flow is "novel" when it is anomalous AND the classifier cannot name it confidently.
3. **Evidence (2 min).** Show the detector comparison and baseline tables. Key sentence: "Every supervised baseline catches 61-66% of attacks and at most 43% of unseen families. The hybrid catches 84% and 76%, at the cost of more false alarms (8.2% vs 3-7%)."
4. **Live check (2 min).** Open Zero-Day Lab. Run a known attack preset (high-confidence class, SHAP on the left). Run a held-out preset: show the zero_day label, the anomaly ratio, and the **"Why it looks anomalous"** panel.
5. **Problem 3 (2 min).** Show the priority formula, the three tiers, and the tier precision table. Send an unknown service name: it lands in Review with the data-quality explanation, never auto-logged.
6. **Honesty / Limits slide (30 s).** Composite ties confidence-only; 14.6% of attacks are confident misses; NSL-KDD limits; zero-day precision is 0.52. Detection is strongest for DoS (95%) and probe (96%) attacks. R2L attacks are detected 45% of the time and U2R 66%, which is where most of the 14.6% auto-logged attacks come from.
7. **Next steps.** Problem 4 (adversarial retraining on the same XGBoost pipeline), then Problem 2 (TLS metadata features), CICIDS datasets, Elasticsearch.

## Part D. Likely questions and honest answers

- **Why is accuracy only 87%?** The test split deliberately contains attack families absent from training; on seen families the classifier is 99.9% accurate (known-family validation; binary validation 97.9%). Unseen families are the hard case.
- **Why not just use XGBoost?** It misses 35% of attacks and 60% of unseen families; the autoencoder recovers most of them.
- **Did you tune on the test set?** No. The reconstruction quantile and novelty gate were selected on validation data with held-out pseudo-zero-days; the test split was only used for reporting. (Earlier development used the test split for exploration, which is why the thresholds were re-derived.)
- **Is the composite priority better than confidence?** No, it ties; it adds interpretable severity and asset context and a safe unknown-asset policy.
- **Why are 14.6% of attacks auto-logged?** Both detectors confidently call them normal (predicted normal, high confidence, low reconstruction error), so the ranking never sees them as risky. This is a detector blind spot; the per-family results from `evaluate.py` show which families are affected (run it and read `per_family_test`).

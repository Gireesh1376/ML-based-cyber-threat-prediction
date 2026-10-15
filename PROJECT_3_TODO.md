# Project-3 Cross-Check To-Do — Problems 1 & 3 (totally solved criterion)

Derived by mapping the team's `cross-check.txt` checklist item-by-item against the
actual codebase, then merging with the gaps found in the earlier literature-review
cross-check. Scope: validate and improve the **existing** architecture — not add
unrelated features or change the model without experimental evidence.

**Completion status (this session):** A1–A7 all completed; B1–B3 conditional/held; B4
auto-logging safety audit completed with exact counts (now reproducible via
metrics.json → auto_log_safety); B5/B6 closed as A6b/A7. **Also this session:**
reconciled the A1 detector comparison with the prior confidence-only benchmark
(confidence_baseline_matched / ablation_at_review_queue_size), corrected the
stale README ablation table to match metrics.json, and added a reproducibility
rewrite of test_detect_integration.py to use FastAPI's in-process TestClient.

**Completion criterion (from cross-check.txt):**
- Problem 1 must demonstrate detection of genuinely held-out attack families.
- Problem 3 must demonstrate the alert-prioritisation system reduces unnecessary
  analyst effort **or** improves threat capture at the same review budget.

---

## Already satisfied (verified this session)

### Problem 1
- [x] **P1.1 Unseen attack validation** — `ZERO_DAY_LABELS` (15 families) excluded from
      supervised training; held out for testing. `metrics.json`: `unseen_zero_day_rows=3568`,
      `held_out_labels` listed. Verified in `config.py` + `train.py`.
- [x] **P1.2 Anomaly detection** — Autoencoder (MLPRegressor) trained on benign traffic only;
      threshold = 95th percentile of benign reconstruction error; `hybrid_predict` flags
      `anomaly = recon > threshold`. Verified in `train.py` + `detector.py`.
- [x] **P1.4 Novelty identification** — Hybrid promotes to `zero_day` only when
      `anomaly AND (known_label == 'normal' OR confidence < 0.62)`. High-confidence
      known-family anomalies are NOT promoted. Verified in `train.py`'s `hybrid_predict`.

### Problem 3
- [x] **P3.1 Priority-score correctness (unit level)** — Weights sum to 1.0 (asserted),
      direction tests, tier-boundary tests, unknown-asset fallback + review-floor tests.
      `backend/tests/test_priority.py`: **24 passed** (re-run this session, exit 0).
- [x] **P3.2 Alert routing** — `tier_from_score` + `derive_tier_cutoffs` (validation true
      labels only) + unknown-service review floor. Deployed tiering in `metrics.json`.
- [x] **P3.5 Threat preservation** — `attacks_in_critical`, `attacks_in_human_tiers`,
      `attacks_auto_logged`, `attacks_outside_human_tiers`, `zero_days_in_*` all present.
- [x] **Section 3 "freeze thresholds before test" (in practice)** — Cutoffs derived from
      validation only; test used purely for evaluation. Verified in `train.py`.

### Dashboard / nothing-broken checks (this session)
- [x] `tsc --noEmit` on frontend: clean (exit 0) — before and after changes.
- [x] `test_priority.py`: 24/24 (exit 0) — before and after changes.
- [x] `test_detect_integration.py`: 12/12 (exit 0) — before and after changes.
- [x] `/api/alerts`, `/api/dashboard/summary`, `/api/detect` all return 200 with the
      same field contracts the frontend renders — verified by spinning up uvicorn and
      hitting the endpoints. No field removed; `explanation_kind` + `top_features` present
      on detect; `priority`/`tier`/`priority_components`/`tier_reason` present on alerts.
- [x] `api.ts` AlertItem type mismatch fixed: `priority`/`tier`/`priority_components`/
      `tier_reason`/`tier_floor_applied`/`dq_flags`/`asset_criticality`/
      `asset_criticality_known` now required (backend always returns them); frontend
      `??` fallbacks retained for safety but types now match reality.

---

## Additional corrections this session (not in the original TODO)

### Reproducibility fix — test_detect_integration.py
**Before:** hardcoded `API = "http://127.0.0.1:8001/api"` with a comment about "stale PID 4216".
**After:** uses FastAPI's in-process `TestClient` (`from starlette.testclient import TestClient`);
no network, no port, no stale-PID dependency. `pip install httpx2` is required (Starlette ≥1.7
needs it for TestClient). Run: `cd backend && python -m pytest tests/test_detect_integration.py -q`.
All 12 tests pass, in-process.

### README ablation table reconciliation
**Before:** ablation table showed conf_only R=0.8591, full R=0.8591, ZD=0.7990/0.7999, FN=1808 —
numbers that do not match any current `metrics.json` computation.
**After:** table updated to match `metrics.json → prioritisation.test_evaluation.ablation_at_review_queue_size`:
conf_only R=0.9101, ZD=0.9339, FN=1154; full R=0.8804, ZD=0.8422, FN=1535. Narrative rewritten
to honestly state that at K=12 833 the confidence-only ranker slightly outperforms the full composite,
and that the composite's advantage is only at smaller K.

---

## Tier A — Reporting/validation gaps (no model change; fills checklist holes) — ALL COMPLETED

These make the existing implementation actually satisfy the cross-check's "Expected
outcome" sections. All compute supplemental metrics from the already-trained artifacts
+ cached test data. Implemented by the new `backend/app/ml/evaluate.py` (run with
`python -m app.ml.evaluate`); results land in new `metrics.json` keys that do not
touch existing keys.

### A1 — Three-way detection comparison (classifier-only / anomaly-only / hybrid)
**Fills cross-check P1.3.** Implemented. New key `metrics.json → detection_comparison`.
Headline result (official NSL-KDD test split):

| Detector | Precision | Recall | F1 | FPR | Missed attacks |
|---|---|---|---|---|---|
| classifier_only | 0.9686 | 0.6496 | 0.7776 | 0.0278 | 4497 |
| anomaly_only | 0.9197 | 0.8081 | 0.8603 | 0.0932 | 2463 |
| hybrid | 0.9207 | 0.8533 | 0.8858 | 0.0971 | 1882 |

**Reading:** the hybrid is the right choice — it beats both single components on recall
and F1. Classifier-only has the best precision/FPR but misses 4,497 attacks (35% of
attacks); the hybrid cuts missed attacks to 1,882 while keeping precision above 0.92.
**This is the single most important table for Problem 1 and it was missing before.**

### A2 — Zero-day binary precision / FPR / F1 on held-out families
**Fills cross-check P1.5.** Implemented. New key `metrics.json → zero_day_binary`.
Result on the 3,568 held-out zero-day flows:

- Zero-day precision = 0.4695, recall = 0.4507, F1 = 0.4599, FPR = 0.0958
- True positives = 1,608; false positives = 1,817; false negatives = 1,960
- "Not classified benign" rate on held-out zero-days = 0.7946 (this is the existing
  `held_out_attack_detection_rate` — the recall-ish lens)
- Explicit `zero_day` flag rate = 0.4507 (the stricter lens)

**Honest caveat:** zero-day detection is the weaker link. Precision 0.47 means about
half of the flows the hybrid flags as `zero_day` are actually benign anomalies. This is
the honest limitation to state, not hide. FPR 0.096 is acceptable for a screening gate
but not for an automated block. **Do not claim universal zero-day detection** (per the
checklist).

### A3 — Per-tier precision and FPR for Critical / Review / auto_log
**Fills cross-check P3.3 and the "alerts per 1,000 flows" part of P3.4.** Implemented
(and corrected this session). Earlier draft mislabeled the benign-proportion-as-FPR;
the README and `metrics.json → tier_precision` now use the conventional definition:
**FPR (per tier) = benign flows routed into that tier ÷ ALL benign test flows**,
preserve **precision = attacks in tier ÷ tier size**, and keep benign proportion / FDR
as a separately named field.

New key `metrics.json → tier_precision`. Result on the 22,544-flow test set with
deployed cutoffs (Critical ≥ 0.599, Review ≥ 0.149; unknown-service Review floor applied;
9,711 benign test flows):

| Tier | Count | Precision | FPR (benign/all benign) | Benign proportion (FDR) | Alerts per 1,000 flows |
|---|---|---|---|---|---|
| critical | 10,250 | 0.9238 | 0.0804 | 0.0762 | 454.67 |
| review | 2,583 | 0.8134 | 0.0496 | 0.1866 | 114.58 |
| auto_log | 9,711 | 0.1301 | 0.8699 | 0.8699 | 430.76 |

- Human-review share = 0.5692 → **569.24 alerts per 1,000 flows** require human review.
- Critical tier: 92.4% true attacks, 8.0% of all benign traffic, 7.6% of the tier is benign.
- Review tier: 81.3% true attacks, 5.0% of all benign traffic.
- auto_log tier: 13.0% attacks by design — but it contains **1,263 true attacks (9.84% of all attacks) and 348 held-out zero-days (9.75% of all zero-days)**.

**This directly answers "does the system reduce unnecessary analyst effort while preserving
threat capture?"** Yes on effort (43.1% of flows auto-logged, 569/1,000 to human review)
and yes on capture (90.2% of attacks + 90.2% of zero-days reach a human tier) — but the
9.84% of attacks auto-logged is the residual that B4 examines. **Auto-logging is not
proven safe without evidence.**

### A4 — Cutoff sensitivity sweep on validation (corrected this session)
**Fills cross-check P3.6.** Implemented. New key `metrics.json → cutoff_sensitivity`.
Sweeps `attack_share` ∈ {0.75, 0.80, 0.85, 0.90, 0.95} × `benign_escalation_share` ∈
{0.01, 0.05, 0.10} on the validation split (107,077 rows; 49,835 attacks; 57,242 benign;
~0 held-out zero-days), applying the **same unknown-service Review-floor policy as deployed
tiering** (flows to services not in SERVICE_CRITICALITY get a Review floor — never silently
auto-logged). Reports resulting cutoffs, tier counts, human-review share, attack capture,
benign escalation, and **whether the monotonicity guard fired** (review cutoff clamped to
critical cutoff because the targeted benign-escalation share could not be achieved without
breaching the critical tier).

**Validation split contains ~0 held-out zero-day flows** (drawn from known-class training
data which excludes zero-day families by construction), so zero-day capture is **not
measurable on validation**; the sweep optimizes attack-capture vs benign-escalation only.
Zero-day behaviour is evaluated separately on the held-out test families (A1/A2).

**Deployed configuration (0.85 / 0.05) — target NOT fully achieved, honestly reported.**
The 0.85/0.05 row hits the 85% attack-capture-in-Critical target (actual 0.8499) and
99.87% attack capture in human tiers with the monotonicity guard NOT firing — but the
targeted **5% benign escalation is NOT achieved; actual benign escalation is 11.42%**. The
gap is caused by the unknown-service Review floor: flows to unmapped services are forced
into human tiers regardless of cutoff, and they dominate benign escalation. **No validation
row achieves 5% benign escalation while keeping the Review floor.**

**Monotonicity guard fired on 6 of 15 rows** (all 0.01 benign-escalation targets, plus
0.95/0.05): on those rows the targeted benign-escalation share could not be achieved at all
without breaching the critical tier, so the review cutoff was clamped and actual benign
escalation landed at the floor-driven 11.42% (or higher). These are reported explicitly in
`cutoff_sensitivity.sweep[].monotonicity_guard_fired`.

**The 0.85/0.05 configuration is retained as the best available tradeoff** that hits the
attack-capture target without firing the guard; the 5% benign-escalation target is
documented as not met on validation because of the Review-floor policy (a hard safety
constraint, not a tunable parameter here). Any future cutoff change requires re-running
the sweep and re-freezing before re-evaluating the test set.

### A5 — SHAP explanation faithfulness
**Fills cross-check P1.6.** Implemented. New key `metrics.json → shap_faithfulness`.
Result: on 200 sampled test flows, for every class, `sum_j shap[i,j,c]` equals
`booster_output[i,c] - expected_value[c]` within ~1.8e-6 (max 8.6e-6) — i.e. numerical
noise. The explainer is internally consistent with the classifier it explains.

**Honest caveat (now stated in the metric):** this is a consistency check on the
*explainer*, not a claim that the top-8 features shown in the dashboard are the true
causal drivers. That stronger claim is not supported by this check and should not be
made.

### A6 — Dashboard consistency check — COMPLETED
**Fills cross-check P3.7.** **Completed.** A backend integration test
(`tests/test_detect_integration.py`, **12 tests, all passing**) calls `/api/detect` for
representative flows and asserts the returned fields are internally consistent with the
implementation:

- `priority_components` values sum to the `priority` score (within rounding). ✓
- `tier` matches `tier_from_score(priority, cutoffs)` from the live endpoint. ✓
- `tier_reason` mentions the relevant cutoff for Critical/Review tiers. ✓
- `severity` follows the documented rules (normal→info, zero_day→critical, etc.). ✓
- Mapped services return `asset_criticality_known=True` with a value in [0,1]. ✓
- **Unknown services are never auto-logged**: the Review floor promotes them out of auto_log,
  sets `tier_floor_applied='review'` and a `dq_flags=['asset_criticality_unknown']` flag.
  ✓ (This is the test that previously failed and drove the `detector.py` fix that now
  returns `tier_floor_applied` and `dq_flags` on the endpoint.)

The test also confirms `/api/detect/replay/{id}` reproduces the stored alert's predicted
label and is_zero_day flag. The endpoint now returns `tier_floor_applied` and `dq_flags`
so the frontend and tests can see them (previously these were computed but not returned —
the integration test caught that gap).

**A6b (frontend type contract)** is NOT done: `frontend/src/api.ts` still marks
`priority?`, `tier?`, `priority_components?`, `tier_reason?`, `tier_floor_applied?`,
`dq_flags?` as optional even though the backend always returns them. That is a separate,
low-risk frontend refinement (B5), not a backend correctness issue.

### A7 — "Thresholds frozen on validation before test" methodological note — COMPLETED
**Fills cross-check Section 3.** **Completed — now stated in the README** (see the
"Threshold freezing (methodology)" paragraph in the cutoff-sensitivity section). All
cutoff selection is performed on the validation split's TRUE labels only; the official test
split is used purely for evaluation afterward and is never touched during cutoff selection,
so test numbers are unbiased by threshold choice. The deployed 0.85/0.05 configuration is
retained as the best available tradeoff; the 5% benign-escalation target is documented as
not met on validation because of the Review-floor policy.

---

## Tier B — Real improvements (code/retrain; only after Tier A experiments justify)

### B1 — Justify or tune the 0.62 novelty confidence threshold (P1.4)
**Conditional on A1/A2.** The 0.62 threshold that gates zero-day promotion is a hard-coded
heuristic. Once A1/A2 show the hybrid's zero-day behaviour, check whether 0.62 is
well-chosen: sweep it on validation (or a held-out slice) and report the effect on
zero-day precision/recall. If it matters, tune and report; if it doesn't, document that.
Small code change (one constant) + experimental justification.

### B2 — If A3 shows Critical precision is too low, adjust
**Conditional on A3.** Critical precision is 0.924 — probably fine. If a future run or a
different dataset shows Critical FPR too high, adjust the cutoff targets or add a secondary
gate. Only justified if A3 finds a problem.

### B3 — If A4's sweep finds a clearly better cutoff than 0.85/0.05, adopt + re-freeze
**Conditional on A4.** The current choice looks reasonable; the sweep is what tells you
whether to change it. If you change it, re-run `evaluate.py` (or re-run `train.py`) and
update the README to match the new numbers.

### B4 — Auto-logging safety audit (completed this session)
**Complements A3.** Exact counts from `metrics.json` + cross-tab audit (this session):

- **1,263 attacks auto-logged = 9.84% of all 12,833 attacks**.
- **348 held-out zero-days in the auto_log tier = 9.75% of all 3,568 zero-days**.
- **9,711 of 22,544 flows auto-logged = 43.08% of all flows**.
- **Human-review workload: 12,833 of 22,544 flows = 56.92%**.
- **90.16% of attacks and 90.25% of zero-days reach a human tier (Critical + Review)**.
- **Critical tier: 9,469 attacks + 2,357 zero-days; Review tier: 2,101 attacks + 863 zero-days.**

**Cross-tab finding (the key honest result):** Every single auto-logged attack (1,263/1,263)
and every auto-logged zero-day (348/348) has all of: predicted_label=`normal`, known_label=`normal`,
confidence ≥ 0.899, reconstruction_error below threshold, severity=`info`. These are **NOT
prioritization failures** — they are **detection failures** where the hybrid confidently
misclassified attacks as normal on both signals (XGBoost + autoencoder). The priority system
correctly auto-logged flows it believed were normal; the problem is upstream in detection.

0% of auto-logged attacks have anomalous reconstruction error; 0% have a confident known-family
prediction. The 9.84% residual is concentrated in exactly the cases the detector is least
equipped to catch (normal-looking traffic). **Auto-logging is not proven safe.** The 9.84%
attack / 9.75% zero-day bypass rate is a detection limitation, not a prioritization choice.
Any safety claim requires either a detection improvement or an explicit policy accepting this
rate. **Do not claim auto-logging is safe without this evidence.**

**The full cross-tab tables are now in the README** (auto-logging safety audit section).


### B5 — A6a + A6b (dashboard consistency test + type fix) — COMPLETED
- A6a: backend integration test (`tests/test_detect_integration.py`, 12 tests) — done,
  all passing.
- A6b: `api.ts` AlertItem type fix — done. `priority`/`tier`/`priority_components`/
  `tier_reason`/`tier_floor_applied`/`dq_flags`/`asset_criticality`/
  `asset_criticality_known` are now required (backend always returns them). Frontend
  `??` fallbacks retained in Alerts.tsx for safety.

Both are small, low-risk code changes now completed.

### B6 — A7 README methodological note
One paragraph. Trivial doc change.

---

## Section 3 items still open (cross-check.txt final validation)

- [x] **Compare existing Project-3 baseline with improved config, same splits.**
      The prior Project-3 benchmark (confidence-only ranker at K=12 833) is recorded in
      `metrics.json → prioritisation.test_evaluation.confidence_baseline_matched` and
      `ablation_at_review_queue_size`. The A1 detector comparison uses the same test split,
      same labels, same `ZERO_DAY_LABELS` hold-out set. The reconciliation is documented in
      the README ("Reconciliation: A1 detector comparison vs the prior confidence-only
      benchmark"). **Key honest finding:** at K=12 833 the confidence-only ranker slightly
      outperforms the full composite on both attack capture (91.01% vs 88.04%) and zero-day
      capture (93.39% vs 84.22%) — the composite's advantage is only at smaller K. The
      README ablation table was corrected to match metrics.json.
- [x] **Evaluate classifier-only, anomaly-only, hybrid.** Done by A1. ✓
- [x] **Report accuracy, precision, recall, F1, zero-day detection, FPR, alert workload.**
      Done: binary classification metrics in `official_test_binary`; zero-day
      precision/FPR/F1 in A2; alert workload (per-tier precision, FPR, per-1000) in A3;
      ranking ablation at K=50/100/200/500/1000/2000 in `fixed_queue`; full ablation at
      K=12 833 in `ablation_at_review_queue_size`; combined results table in README
      "Current results".
- [x] **Freeze final thresholds before evaluating untouched test set.** In practice done
      (A7 documents it).
- [x] **Update dashboard/report only with results reproduced by the final implementation.**
      The dashboard already reads from `metrics.json`/`demo_alerts.json` regenerated by
      `train.py`; A1–A5 and B4 add to `metrics.json` from the same artifacts. The README
      ablation table and A1/prior-benchmark reconciliation were updated to match the actual
      metrics.json numbers. ✓

---

## Recommended execution order (lowest risk first)

1. **A1–A5 are already computed** (in `metrics.json` now). Next is to surface them in the
   README so the checklist's "Expected outcome" sections are visibly satisfied. This is a
   README change only.
2. **A7 (README methodological note)** — trivial, do it with the README updates.
3. **B4 (auto-logging safety audit)** — the highest-value open honesty question; A3 now
   gives you the exact numbers. Markdown report, no code change.
4. **A6b (api.ts type fix) + A6a (consistency test)** — small code changes, do after the
   doc work so you're not mixing doc and code changes in one review.
5. **B1 (0.62 threshold justification)** — only if A1/A2 make it look worth doing.
6. **B2/B3** — only if A3/A4 find something to fix.
7. **Section 3 combined results table** — README, after everything else is in.

---

## What "totally solved" looks like after this list

**Problem 1 totally solved when:** A1 shows the hybrid beats both single components on
recall/F1 (done); A2 reports zero-day precision/FPR/F1 honestly (done, with the 0.47
precision caveat stated); A5 confirms SHAP is internally consistent (done); B1 justifies
the 0.62 gate or documents it as immaterial; the README states "held-out attack families
detected, false alarms controlled, universal zero-day detection NOT claimed."

**Problem 3 totally solved when:** A3 reports per-tier precision/FPR/per-1000 (done);
A4 justifies the 0.85/0.05 cutoffs via the sweep (done); A7 documents the freeze (trivial);
B4 audits the 9.84% auto-logged attacks and either defends or tightens; A6a/A6b close the
dashboard-consistency gap; and the README states a measurable workload reduction
(43% auto-logged, 569/1000 to human review) with the residual threat-preservation numbers
(90.2% attacks + 90.2% zero-days in human tiers) stated alongside the 9.84% auto-logged
attack residual.

**What is NOT in scope for "totally solving Problems 1 and 3":** Problem 2 (encrypted
traffic feature pipeline) and Problem 4 (adversarial retraining) are separate and remain
open regardless — they were never part of this two-problem completion criterion.

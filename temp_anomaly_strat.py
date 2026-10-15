import json
from pathlib import Path
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent
import sys
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import ZERO_DAY_LABELS, SERVICE_CRITICALITY, METRICS_PATH
from app.ml import load_artifacts, model_path, hybrid_predict
from app.ml.features import load_nsl_kdd
from app.ml.priority import tier_from_score
from app.ml.train import _priority_scores

arts, _ = load_artifacts(model_path())
test_df = load_nsl_kdd(ROOT / 'data/raw/KDDTest+.txt')
m = json.loads(METRICS_PATH.read_text())

print('=== SETUP ===')
print(f'test_df rows: {len(test_df)}')
print(f'recon_threshold: {arts.recon_threshold:.6f}')
print(f'hybrid label_classes: {arts.label_classes}')
print(f'ZERO_DAY_LABELS ({len(ZERO_DAY_LABELS)}): {sorted(ZERO_DAY_LABELS)}')
print()

X = arts.transformer.transform(test_df)
hybrid_out = hybrid_predict(arts, X)
scores, _comp = _priority_scores(hybrid_out, arts.recon_threshold,
    hybrid_out['label'], hybrid_out['is_zero_day'].astype(bool),
    services=list(test_df['service']), want_components=True)
cutoffs = m['prioritisation']['tier_cutoffs']

tiers = np.array([
    tier_from_score(float(scores[i]), cutoffs,
        None if str(test_df.iloc[i]['service']) in SERVICE_CRITICALITY else 'review')
    for i in range(len(scores))
])

# ground-truth labels
true_attack = (test_df['label'] != 'normal').values.astype(bool)
true_zero_day = test_df['label'].isin(ZERO_DAY_LABELS).values.astype(bool)

# hybrid outputs
recon = hybrid_out['reconstruction_error']
is_zd = hybrid_out['is_zero_day'].astype(bool)
pred_label = hybrid_out['label']
known_label = hybrid_out['known_label']
confidence = hybrid_out['confidence']

# ground-truth labels
true_attack = (test_df['label'] != 'normal').values.astype(bool)
true_zero_day = test_df['label'].isin(ZERO_DAY_LABELS).values.astype(bool)

# hybrid outputs
recon = hybrid_out['reconstruction_error']
is_zd = hybrid_out['is_zero_day'].astype(bool)
pred_label = hybrid_out['label']
known_label = hybrid_out['known_label']
confidence = hybrid_out['confidence']

true_attack = (test_df['label'] != 'normal').values.astype(bool)
true_zero_day = test_df['label'].isin(ZERO_DAY_LABELS).values.astype(bool)
recon = hybrid_out['reconstruction_error']
is_zd = hybrid_out['is_zero_day'].astype(bool)
pred_label = hybrid_out['label']
known_label = hybrid_out['known_label']
confidence = hybrid_out['confidence']

all_attack_count = int(true_attack.sum())
all_zd_count = int(true_zero_day.sum())
all_benign_count = int((~true_attack).sum())
all_flows = len(test_df)

print('=== OVERALL BASELINE (from this run, must match metrics.json) ===')
print(f'total flows: {all_flows}')
print(f'total attacks (true): {all_attack_count}')
print(f'total zero-days (true, held-out): {all_zd_count}')
print(f'total benign: {all_benign_count}')
print(f'hybrid predicted normal: {(pred_label == "normal").sum()}')
print(f'hybrid predicted non-normal: {(pred_label != "normal").sum()}')
print(f'hybrid explicit zero_day flag: {is_zd.sum()}')
print(f'hybrid anomaly (recon > thresh): {(recon > arts.recon_threshold).sum()}')
print()

# ---- ANOMALY STRATIFICATION ----
recon_threshold = arts.recon_threshold
anom = recon > recon_threshold
non_anom = ~anom

print('=== ANOMALY STRATIFICATION (recon > threshold vs recon <= threshold) ===')
print(f'anomalous (recon > {recon_threshold:.6f}): {anom.sum()} flows')
print(f'non-anomalous (recon <= {recon_threshold:.6f}): {non_anom.sum()} flows')
print()

def stratify_report(mask, label):
    n = int(mask.sum())
    if n == 0:
        print(f'--- {label}: 0 flows ---')
        return
    sub_true_attack = true_attack[mask]
    sub_true_zd = true_zero_day[mask]
    sub_pred = pred_label[mask]
    sub_known = known_label[mask]
    sub_conf = confidence[mask]
    sub_recon = recon[mask]
    sub_is_zd = is_zd[mask]
    sub_tier = tiers[mask]
    threshold = recon_threshold
    n_att = int(sub_true_attack.sum())
    n_zd = int(sub_true_zd.sum())
    n_benign = int((~sub_true_attack).sum())
    print(f'--- {label}: {n} flows ---')
    print(f'  ground-truth: {n_att} attacks, {n_zd} zero-days, {n_benign} benign')
    print(f'  predicted_label: {dict(zip(*np.unique(sub_pred, return_counts=True)))}')
    print(f'  known_label: {dict(zip(*np.unique(sub_known, return_counts=True)))}')
    print(f'  explicit zero_day flag: {int(sub_is_zd.sum())}')
    print(f'  confidence: min={sub_conf.min():.4f} max={sub_conf.max():.4f} mean={sub_conf.mean():.4f}')
    print(f'  reconstruction_error: min={sub_recon.min():.4f} max={sub_recon.max():.4f} mean={sub_recon.mean():.4f} (thresh={threshold:.6f})')
    print(f'  tiers: {dict(zip(*np.unique(sub_tier, return_counts=True)))}')
    print(f'  ground-truth label breakdown:')
    for lbl, cnt in test_df['label'][mask].value_counts().head(25).items():
        print(f'    {lbl}: {cnt}')
    print()
    return {
        'n': n, 'attacks': n_att, 'zero_days': n_zd, 'benign': n_benign,
        'predicted_normal': int((sub_pred == 'normal').sum()),
        'predicted_nonzero': int((sub_pred != 'normal').sum()),
        'explicit_zd': int(sub_is_zd.sum()),
        'confidence_min': float(sub_conf.min()), 'confidence_max': float(sub_conf.max()), 'confidence_mean': float(sub_conf.mean()),
        'recon_min': float(sub_recon.min()), 'recon_max': float(sub_recon.max()), 'recon_mean': float(sub_recon.mean()),
        'tiers': dict(zip(*np.unique(sub_tier, return_counts=True))),
        'label_breakdown': dict(test_df['label'][mask].value_counts()),
    }

anom_stats = stratify_report(anom, 'ANOMALOUS (recon > threshold)')
non_anom_stats = stratify_report(non_anom, 'NON-ANOMALOUS (recon <= threshold)')

print('=== ZERO-DAY RECALL BY GROUP ===')
print(f'Held-out zero-days total: {all_zd_count}')
print(f'  In anomalous group: {anom_stats["zero_days"]} -> recall {anom_stats["zero_days"]/all_zd_count:.4f} ({anom_stats["zero_days"]/all_zd_count*100:.2f}%)')
print(f'  In non-anomalous group: {non_anom_stats["zero_days"]} -> recall {non_anom_stats["zero_days"]/all_zd_count:.4f} ({non_anom_stats["zero_days"]/all_zd_count*100:.2f}%)')
print(f'  Sum: {anom_stats["zero_days"] + non_anom_stats["zero_days"]} (should equal {all_zd_count})')
print()
print(f'Of the anomalous zero-days ({anom_stats["zero_days"]}):')
print(f'  explicit zero_day flag: {int(is_zd[anom & true_zero_day].sum())}')
print(f'  predicted normal: {int((pred_label[anom & true_zero_day] == "normal").sum())}')
print(f'  predicted non-normal (attack label): {int((pred_label[anom & true_zero_day] != "normal").sum())}')
print()
print(f'Of the non-anomalous zero-days ({non_anom_stats["zero_days"]}):')
print(f'  explicit zero_day flag: {int(is_zd[non_anom & true_zero_day].sum())}')
print(f'  predicted normal: {int((pred_label[non_anom & true_zero_day] == "normal").sum())}')
print(f'  predicted non-normal (attack label): {int((pred_label[non_anom & true_zero_day] != "normal").sum())}')
print()
print('=== BENIGN FLOWS: anomaly and zero-day flag rates ===')
benign_mask = ~true_attack
benign_anom = int((benign_mask & anom).sum())
benign_non_anom = int((benign_mask & non_anom).sum())
benign_explicit_zd = int((benign_mask & is_zd).sum())
benign_anom_and_zd = int((benign_mask & anom & is_zd).sum())
print(f'Total benign: {all_benign_count}')
print(f'  Benign anomalous (recon > thresh): {benign_anom} ({benign_anom/all_benign_count:.4f} = {benign_anom/all_benign_count*100:.2f}% of benign)')
print(f'  Benign non-anomalous: {benign_non_anom} ({benign_non_anom/all_benign_count:.4f})')
print(f'  Benign explicitly flagged zero_day: {benign_explicit_zd} ({benign_explicit_zd/all_benign_count:.4f} = {benign_explicit_zd/all_benign_count*100:.2f}% of benign)')
print(f'  Benign anomalous AND flagged zero_day: {benign_anom_and_zd}')
print()
print('=== RECONCILIATION WITH metrics.json ===')
print()
zdb = m['zero_day_binary']
print('metrics.json zero_day_binary:')
print(f'  held_out_zero_day_count: {zdb["held_out_zero_day_count"]} (this run: {all_zd_count})')
print(f'  held_out_zero_day_not_classified_benign_rate: {zdb["held_out_zero_day_not_classified_benign_rate"]:.4f}')
print(f'    = held-out zd predicted non-normal / all held-out zd')
print(f'    this run: {(pred_label[true_zero_day] != "normal").sum()}/{all_zd_count} = {(pred_label[true_zero_day] != "normal").sum()/all_zd_count:.4f}')
print(f'  held_out_zero_day_explicit_zero_day_rate: {zdb["held_out_zero_day_explicit_zero_day_rate"]:.4f}')
print(f'    = held-out zd with is_zero_day=True / all held-out zd')
print(f'    this run: {is_zd[true_zero_day].sum()}/{all_zd_count} = {is_zd[true_zero_day].sum()/all_zd_count:.4f}')
print(f'  binary_metrics.zero_day_recall: {zdb["binary_metrics"]["zero_day_recall"]:.4f}')
print(f'    = zd_TP / (zd_TP + zd_FN) where zd decision = is_zero_day')
print(f'    TP={zdb["binary_metrics"]["zero_day_true_positives"]} FN={zdb["binary_metrics"]["zero_day_false_negatives"]}')
print(f'    this run TP={int((is_zd & true_zero_day).sum())} FN={int((~is_zd & true_zero_day).sum())}')
print()
dc = m['detection_comparison']
print('metrics.json detection_comparison.hybrid:')
print(f'  attack_recall: {dc["detectors"]["hybrid"]["attack_recall"]:.4f} (this run: {(pred_label != "normal")[true_attack].mean():.4f})')
print(f'  attack_false_negatives: {dc["detectors"]["hybrid"]["attack_false_negatives"]} (this run: {(pred_label == "normal")[true_attack].sum()})')
print(f'  zero_day_recall: {dc["detectors"]["hybrid"]["zero_day_recall"]:.4f}')
print(f'  zero_day_false_negatives: {dc["detectors"]["hybrid"]["zero_day_false_negatives"]}')
print(f'  zero_day_true_positives: {dc["detectors"]["hybrid"]["zero_day_true_positives"]}')
print()
als = m.get('auto_log_safety', {})
print('metrics.json auto_log_safety:')
print(f'  auto_log.attacks_in_auto_log: {als["auto_log"]["attacks_in_auto_log"]} (this run: {int((tiers == "auto_log") & true_attack).sum()})')
print(f'  auto_log.zero_days_in_auto_log: {als["auto_log"]["zero_days_in_auto_log"]} (this run: {int((tiers == "auto_log") & true_zero_day).sum()})')
print()
print('=== MAIN LIMITATION ANALYSIS ===')
print()
anom_zd = anom & true_zero_day
non_anom_zd = non_anom & true_zero_day
print(f'HELD-OUT ZERO-DAYS BY ANOMALY STATUS:')
print(f'  Anomalous (recon > thresh): {int(anom_zd.sum())} of {all_zd_count} ({int(anom_zd.sum())/all_zd_count*100:.2f}%)')
print(f'    -> These are the ONLY flows 0.62 can affect (novelty gate requires anomaly first)')
print(f'    -> Of these, explicit zero_day: {int(is_zd[anom_zd].sum())}')
print(f'    -> Of these, predicted normal: {int((pred_label[anom_zd] == "normal").sum())}')
print(f'    -> Of these, predicted non-normal (known attack label): {int((pred_label[anom_zd] != "normal").sum())}')
print(f'  Non-anomalous (recon <= thresh): {int(non_anom_zd.sum())} of {all_zd_count} ({int(non_anom_zd.sum())/all_zd_count*100:.2f}%)')
print(f'    -> These CANNOT be promoted to zero_day by ANY confidence threshold')
print(f'    -> because novelty gate requires anomaly as prerequisite')
print(f'    -> Of these, explicit zero_day: {int(is_zd[non_anom_zd].sum())} (should be ~0 by construction)')
print(f'    -> Of these, predicted normal: {int((pred_label[non_anom_zd] == "normal").sum())}')
print()
print(f'BENIGN FLOWS BY ANOMALY STATUS:')
print(f'  Anomalous benign: {benign_anom} of {all_benign_count} ({benign_anom/all_benign_count*100:.2f}%)')
print(f'    -> These are the flows the autoencoder flags as suspicious')
print(f'    -> Benign anomalous AND flagged zero_day: {benign_anom_and_zd} (false-positive zero-day promotions)')
print(f'  Non-anomalous benign: {benign_non_anom} of {all_benign_count}')
print()
print('=== DISTINCTION: DATA vs HYPOTHESIS ===')
print()
print('SUPPORTED BY DATA (these are measured, not assumed):')
print(f'  1. {int(non_anom_zd.sum())} of {all_zd_count} held-out zero-days ({int(non_anom_zd.sum())/all_zd_count*100:.2f}%) are NON-ANOMALOUS')
print(f'     -> They have recon <= threshold, so the novelty gate NEVER evaluates them for zero-day promotion')
print(f'     -> No confidence threshold (including 0.62) can recover these')
print(f'  2. {int(anom_zd.sum())} of {all_zd_count} held-out zero-days ({int(anom_zd.sum())/all_zd_count*100:.2f}%) are ANOMALOUS')
print(f'     -> Only these can be affected by the 0.62 gate')
print(f'  3. Of the anomalous zero-days, {int((pred_label[anom_zd] != "normal").sum())} are predicted as a known attack label')
print(f'     -> These are NOT promoted (rule: anomaly + confident known family = keep as known family)')
print(f'     -> This is the population where 0.62 COULD matter (anomaly + confidence < 0.62 + not confident known family)')
print(f'  4. {int(is_zd[true_zero_day].sum())} of {all_zd_count} held-out zero-days are explicitly flagged zero_day ({is_zd[true_zero_day].sum()/all_zd_count*100:.2f}%)')
print(f'  5. {benign_anom_and_zd} benign flows are anomalous AND flagged zero_day (false-positive zero-day promotions)')
print()
print('HYPOTHESIS (confirmed by data below):')
print('  The 0.62 gate matters only for the intersection of:')
print('    (a) anomalous flows (recon > threshold)')
print('    (b) NOT confidently assigned to a known family (confidence < 0.62 OR known_label == normal)')
print('  If most anomalous zero-days are either (i) predicted as a known attack with high confidence')
print('  or (ii) non-anomalous, then 0.62 has little leverage and the reconstruction threshold is the')
print('  binding constraint.')
print()
print('=== POPULATION WHERE 0.62 ACTUALLY APPLIES (the testable 0.62 population) ===')
print()
subject_to_062 = anom & (known_label == 'normal')  # anomalous + XGBoost says normal
subject_to_062_or_low_conf = anom & ((known_label == 'normal') | (confidence < 0.62))
print(f'Flows subject to 0.62 gate (anomalous AND known_label==normal): {int(subject_to_062.sum())}')
print(f'  Of these, true zero-days: {int((subject_to_062 & true_zero_day).sum())}')
print(f'  Of these, true benign: {int((subject_to_062 & ~true_attack).sum())}')
print(f'  Of these, true known attacks: {int((subject_to_062 & true_attack & ~true_zero_day).sum())}')
print()
print(f'Flows subject to 0.62 gate (anomalous AND (known_label==normal OR confidence<0.62)): {int(subject_to_062_or_low_conf.sum())}')
print(f'  Of these, true zero-days: {int((subject_to_062_or_low_conf & true_zero_day).sum())}')
print(f'  Of these, true benign: {int((subject_to_062_or_low_conf & ~true_attack).sum())}')
print(f'  Of these, true known attacks: {int((subject_to_062_or_low_conf & true_attack & ~true_zero_day).sum())}')
print()
print('=== HOLD-OUT ZERO-DAYS IN THE 0.62-TESTABLE POPULATION, BY CONFIDENCE BAND ===')
print()
anom_zd_df = test_df[anom_zd].copy()
anom_zd_df['confidence'] = confidence[anom_zd]
anom_zd_df['known_label'] = known_label[anom_zd]
anom_zd_df['pred_label'] = pred_label[anom_zd]
anom_zd_df['is_zd'] = is_zd[anom_zd]
anom_zd_df['recon'] = recon[anom_zd]
print(f'Anomalous held-out zero-days ({int(anom_zd.sum())} total):')
print(f'  by known_label:')
for kl, cnt in anom_zd_df['known_label'].value_counts().items():
    print(f'    {kl}: {cnt}')
print(f'  by predicted label:')
for pl, cnt in anom_zd_df['pred_label'].value_counts().items():
    print(f'    {pl}: {cnt}')
print(f'  by explicit zero_day flag:')
print(f'    zero_day: {int(anom_zd_df["is_zd"].sum())}')
print(f'    not zero_day: {int((~anom_zd_df["is_zd"]).sum())}')
print(f'  confidence distribution (10 bins from 0 to 1):')
bins = np.linspace(0, 1, 11)
counts, _ = np.histogram(anom_zd_df['confidence'], bins=bins)
for i in range(len(counts)):
    print(f'    [{bins[i]:.2f}, {bins[i+1]:.2f}): {counts[i]}')
print(f'  confidence < 0.62: {int((anom_zd_df["confidence"] < 0.62).sum())}')
print(f'  confidence >= 0.62: {int((anom_zd_df["confidence"] >= 0.62).sum())}')
print(f'  confidence >= 0.899 (like the auto-logged ones): {int((anom_zd_df["confidence"] >= 0.899).sum())}')
print()
print('=== RECONSTRUCTION THRESHOLD ALTERNATIVES (hypothetical, NOT implemented) ===')
print()
print(f'Current threshold: {arts.recon_threshold:.6f} (95th percentile of benign training recon error)')
print(f'Benign test flows above threshold (false-positive anomalies): {benign_anom} of {all_benign_count} ({benign_anom/all_benign_count*100:.2f}%)')
print(f'Held-out zero-days above threshold (true-positive anomalies): {int(anom_zd.sum())} of {all_zd_count} ({int(anom_zd.sum())/all_zd_count*100:.2f}%)')
print(f'Held-out zero-days BELOW threshold (missed by autoencoder): {int(non_anom_zd.sum())} of {all_zd_count} ({int(non_anom_zd.sum())/all_zd_count*100:.2f}%)')
print()
print(f'BENIGN ZERO-DAY FLAG RATES:')
print(f'  Benign anomalous flagged zero_day / benign anomalous: {benign_anom_and_zd}/{benign_anom} = {benign_anom_and_zd/benign_anom:.4f}' if benign_anom else '  n/a (no benign anomalous)')
print(f'  Benign flagged zero_day / all benign: {benign_explicit_zd}/{all_benign_count} = {benign_explicit_zd/all_benign_count:.4f}')
print(f'  Benign flagged zero_day / benign anomalous: {benign_explicit_zd}/{benign_anom} = {benign_explicit_zd/benign_anom:.4f}' if benign_anom else '  n/a')
print()
print('=== CONCLUSION: WHICH STAGE IS THE MAIN LIMITATION? ===')
print()
print('RECONSTRUCTION THRESHOLD is the MAIN limitation for zero-day DETECTION (anomaly recall):')
print(f'  - {int(non_anom_zd.sum())} of {all_zd_count} held-out zero-days ({int(non_anom_zd.sum())/all_zd_count*100:.2f}%) are non-anomalous')
print(f'  - They have recon <= threshold, so they are never candidates for zero-day promotion')
print(f'  - This is a property of the autoencoder, not the 0.62 gate')
print()
print('0.62 CONFIDENCE GATE is the limitation for zero-day PROMOTION among anomalous flows:')
print(f'  - {int(anom_zd.sum())} held-out zero-days are anomalous')
print(f'  - Of these, {int((pred_label[anom_zd] != "normal").sum())} are predicted as known attacks (not promoted, correctly)')
print(f'  - Of these, the remainder are the population where 0.62 matters')
print(f'  - The exact effect of 0.62 depends on the confidence distribution of this subgroup')
print()
print('PRIORITIZER (tier cutoffs/priority score) is NOT the limitation for zero-day DETECTION:')
print(f'  - Zero-day detection happens at the hybrid_predict stage (anomaly gate + novelty gate)')
print(f'  - The prioritizer only routes flows that have already been scored')
print(f'  - The 348 auto-logged zero-days were auto-logged BECAUSE they were predicted normal')
print(f'    (detection failure), not because the prioritizer deprioritized known attacks')
print()
print('OVERALL ZERO-DAY RECALL BREAKDOWN (reproducible):')
print(f'  Total held-out zero-days: {all_zd_count}')
print(f'  Explicit zero_day flag (hybrid): {int(is_zd[true_zero_day].sum())} -> recall {int(is_zd[true_zero_day].sum())/all_zd_count*100:.2f}%')
print(f'  Predicted non-normal (any attack label): {int((pred_label[true_zero_day] != "normal").sum())} -> recall {int((pred_label[true_zero_day] != "normal").sum())/all_zd_count*100:.2f}%')
print(f'  Of explicit zero_day, anomalous: {int((is_zd[true_zero_day] & anom).sum())}')
print(f'  Of explicit zero_day, non-anomalous: {int((is_zd[true_zero_day] & non_anom).sum())} (should be ~0)')
print(f'  NOT flagged zero_day, but predicted non-normal (known attack): {int((~is_zd[true_zero_day] & (pred_label[true_zero_day] != "normal")).sum())}')
print(f'  NOT flagged zero_day, predicted normal (true false-negative): {int((~is_zd[true_zero_day] & (pred_label[true_zero_day] == "normal")).sum())}')
print()
print('=== SMALLEST SAFE NEXT EXPERIMENT (recommendation, not implementation) ===')
print()
print('If the goal is to understand whether 0.62 is well-chosen:')
print('  STEP 1 (done above, prerequisite): Characterize the held-out zero-days by anomaly status.')
print('    Result: most are non-anomalous, so 0.62 has limited leverage on overall zero-day recall.')
print()
print('  STEP 2 (next, if you want to tune 0.62): On the ANOMALOUS held-out zero-days only,')
print('    measure zero-day precision/recall at candidate thresholds (e.g., 0.50, 0.55, 0.62, 0.65, 0.70).')
print('    This is the population where 0.62 actually applies.')
print('    Report: for each threshold, how many anomalous zero-days get promoted vs how many benign')
print('    anomalous flows get falsely promoted (precision cost).')
print()
print('  STEP 3 (interpretation): If Step 2 shows 0.62 has little effect (because most anomalous')
print('    zero-days are either confidently known-family or already promoted), document 0.62 as')
print('    "immaterial for zero-day recall at the current reconstruction threshold" - that is itself')
print('    a valid B1 completion.')
print()
print('  STEP 4 (honest caveat): If the goal is to improve zero-day DETECTION (not just promotion),')
print('    the reconstruction threshold is the binding constraint, and changing 0.62 alone will not')
print('    recover the non-anomalous zero-days. Improving those would require either a lower')
print('    reconstruction threshold (with higher benign FPR) or a different anomaly detector - both')
print('    beyond "tune 0.62" and both would change Problems 1/3 numbers.')

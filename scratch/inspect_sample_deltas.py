import sys
from pathlib import Path
sys.path.insert(0, str(Path("backend").resolve()))

import json
import numpy as np
import pandas as pd
from app.config import RAW_DIR, FEATURE_COLUMNS, SERVICE_CRITICALITY
from app.ml import load_artifacts, model_path, hybrid_predict
from app.ml.adversarial import (
    HARDENED_MODEL_PATH,
    generate_adversarial_perturbation,
    check_sample_constraints,
)
from app.ml.features import load_nsl_kdd, split_zero_day
from app.ml.priority import compute_priority, tier_from_score
from app.ml.detector import get_tier_cutoffs

base_artifacts, _ = load_artifacts(model_path())
hardened_artifacts, _ = load_artifacts(HARDENED_MODEL_PATH)

test_path = RAW_DIR / "KDDTest+.txt"
test_df = load_nsl_kdd(test_path)
known_test, _ = split_zero_day(test_df)
attack_mask = known_test["label"] != "normal"
test_attacks = known_test[attack_mask].sample(n=min(1500, int(attack_mask.sum())), random_state=42).copy()

pert = generate_adversarial_perturbation(
    test_attacks,
    method="fgsm",
    epsilon=0.20,
    seed=42,
    artifacts=base_artifacts,
    is_hardened=False,
)
X_pert = base_artifacts.transformer.transform(pert)
b_pred = hybrid_predict(base_artifacts, X_pert)
h_pred = hybrid_predict(hardened_artifacts, X_pert)

b_evaded = b_pred["label"] == "normal"
h_evaded = h_pred["label"] == "normal"
hard_caught = b_evaded & (~h_evaded)

cutoffs = get_tier_cutoffs()

for idx in np.where(hard_caught)[0][:3]:
    orig_row = test_attacks.iloc[idx]
    pert_row = pert.iloc[idx]

    # Delatas
    deltas = []
    for col in FEATURE_COLUMNS:
        ov = orig_row[col]
        pv = pert_row[col]
        if isinstance(ov, (int, float, np.number)) and isinstance(pv, (int, float, np.number)):
            diff = float(pv - ov)
            if abs(diff) > 1e-4:
                deltas.append((col, float(ov), float(pv), round(diff, 4)))
    
    crit = SERVICE_CRITICALITY.get(str(orig_row["service"]), 0.5)
    p_b, _, _ = compute_priority(float(b_pred["confidence"][idx]), float(b_pred["reconstruction_error"][idx]), base_artifacts.recon_threshold, str(b_pred["label"][idx]), bool(b_pred["is_zero_day"][idx]), crit)
    p_h, _, _ = compute_priority(float(h_pred["confidence"][idx]), float(h_pred["reconstruction_error"][idx]), base_artifacts.recon_threshold, str(h_pred["label"][idx]), bool(h_pred["is_zero_day"][idx]), crit)

    print(f"\nSample {idx} - Ground Truth: {orig_row['label']} ({orig_row['family']})")
    print(f"  Baseline: predicted={b_pred['label'][idx]}, conf={b_pred['confidence'][idx]:.4f}, tier={tier_from_score(p_b, cutoffs)}")
    print(f"  Hardened: predicted={h_pred['label'][idx]}, conf={h_pred['confidence'][idx]:.4f}, tier={tier_from_score(p_h, cutoffs)}")
    print(f"  Modified features count: {len(deltas)}")
    for d in deltas[:5]:
        print(f"    {d[0]}: {d[1]} -> {d[2]} (delta={d[3]})")

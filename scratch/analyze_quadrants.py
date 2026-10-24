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
    validate_network_flow_constraints,
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

cutoffs = get_tier_cutoffs()

for method in ["fgsm", "uap", "demgan"]:
    pert = generate_adversarial_perturbation(
        test_attacks,
        method=method,
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

    q_hard_caught = b_evaded & (~h_evaded)
    q_both_caught = (~b_evaded) & (~h_evaded)
    q_both_failed = b_evaded & h_evaded
    q_base_caught = (~b_evaded) & h_evaded

    print(f"\nMethod {method} @ eps=0.20:")
    print(f"  Hardened Caught / Base Evaded: {q_hard_caught.sum()}")
    print(f"  Both Caught: {q_both_caught.sum()}")
    print(f"  Both Failed: {q_both_failed.sum()}")
    print(f"  Base Caught / Hard Failed: {q_base_caught.sum()}")

    # Attack types in hard_caught:
    hc_labels = test_attacks.iloc[np.where(q_hard_caught)[0]]["label"].value_counts().to_dict()
    print(f"  Attack labels in Hardened Caught: {hc_labels}")

    # Attack types in both_caught:
    bc_labels = test_attacks.iloc[np.where(q_both_caught)[0]]["label"].value_counts().head(5).to_dict()
    print(f"  Top attack labels in Both Caught: {bc_labels}")

    # Attack types in both_failed:
    bf_labels = test_attacks.iloc[np.where(q_both_failed)[0]]["label"].value_counts().to_dict()
    print(f"  Attack labels in Both Failed: {bf_labels}")

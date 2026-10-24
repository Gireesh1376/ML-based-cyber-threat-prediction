import sys
from pathlib import Path
sys.path.insert(0, str(Path("backend").resolve()))

import json
import numpy as np
import pandas as pd
from app.config import RAW_DIR
from app.ml import load_artifacts, model_path, hybrid_predict
from app.ml.adversarial import (
    HARDENED_MODEL_PATH,
    generate_adversarial_perturbation,
    check_sample_constraints,
)
from app.ml.features import load_nsl_kdd, split_zero_day

base_artifacts, _ = load_artifacts(model_path())
hardened_artifacts, _ = load_artifacts(HARDENED_MODEL_PATH)

test_path = RAW_DIR / "KDDTest+.txt"
test_df = load_nsl_kdd(test_path)
known_test, _ = split_zero_day(test_df)
attack_mask = known_test["label"] != "normal"
test_attacks = known_test[attack_mask].sample(n=min(1500, int(attack_mask.sum())), random_state=42).copy()

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

    # Hybrid level
    b_evaded = b_pred["label"] == "normal"
    h_evaded = h_pred["label"] == "normal"
    hard_caught = b_evaded & (~h_evaded)

    print(f"\n================ Method: {method} ================")
    print(f"Total hard_caught: {hard_caught.sum()}")
    indices = np.where(hard_caught)[0]
    for idx in indices[:3]:
        orig_row = test_attacks.iloc[idx]
        pert_row = pert.iloc[idx]
        print(f"Sample idx {idx}:")
        print(f"  Ground truth: label={orig_row['label']}, family={orig_row['family']}")
        print(f"  Baseline pred: {b_pred['label'][idx]} (conf={b_pred['confidence'][idx]:.4f}, recon={b_pred['reconstruction_error'][idx]:.4f})")
        print(f"  Hardened pred: {h_pred['label'][idx]} (conf={h_pred['confidence'][idx]:.4f}, recon={h_pred['reconstruction_error'][idx]:.4f})")
        print(f"  Key features: service={orig_row['service']}, count={orig_row['count']}->{pert_row['count']}, serror_rate={orig_row['serror_rate']}->{pert_row['serror_rate']}")

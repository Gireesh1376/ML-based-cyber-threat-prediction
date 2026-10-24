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

print(f"Total attack samples: {len(test_attacks)}")

# Evaluate on the 3 methods at eps=0.20
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

    # Let's inspect classifier prediction vs hybrid prediction
    b_clf_norm = b_pred["known_label"] == "normal"
    h_clf_norm = h_pred["known_label"] == "normal"

    b_hyb_norm = b_pred["label"] == "normal"
    h_hyb_norm = h_pred["label"] == "normal"

    print(f"\n--- Method: {method} (eps=0.20) ---")
    print(f"Classifier Level:")
    print(f"  Baseline predicts normal (evaded): {b_clf_norm.sum()} ({b_clf_norm.mean():.4f})")
    print(f"  Hardened predicts normal (evaded): {h_clf_norm.sum()} ({h_clf_norm.mean():.4f})")
    
    # 4 quadrants at classifier level:
    # 1. Base normal, Hard attack (Hardened caught, Baseline failed)
    q_hard_caught_clf = b_clf_norm & (~h_clf_norm)
    # 2. Both attack (Both caught)
    q_both_caught_clf = (~b_clf_norm) & (~h_clf_norm)
    # 3. Both normal (Both failed)
    q_both_failed_clf = b_clf_norm & h_clf_norm
    # 4. Base attack, Hard normal (Only baseline caught)
    q_base_only_clf = (~b_clf_norm) & h_clf_norm

    print(f"  Quadrant breakdown (Classifier):")
    print(f"    Hardened caught, Baseline failed: {q_hard_caught_clf.sum()} ({q_hard_caught_clf.mean()*100:.2f}%)")
    print(f"    Both caught: {q_both_caught_clf.sum()} ({q_both_caught_clf.mean()*100:.2f}%)")
    print(f"    Both failed: {q_both_failed_clf.sum()} ({q_both_failed_clf.mean()*100:.2f}%)")
    print(f"    Baseline caught, Hardened failed: {q_base_only_clf.sum()} ({q_base_only_clf.mean()*100:.2f}%)")

    print(f"Hybrid Level (with Autoencoder Anomaly Gate):")
    print(f"  Baseline predicts normal: {b_hyb_norm.sum()} ({b_hyb_norm.mean():.4f})")
    print(f"  Hardened predicts normal: {h_hyb_norm.sum()} ({h_hyb_norm.mean():.4f})")

    q_hard_caught_hyb = b_hyb_norm & (~h_hyb_norm)
    q_both_caught_hyb = (~b_hyb_norm) & (~h_hyb_norm)
    q_both_failed_hyb = b_hyb_norm & h_hyb_norm
    q_base_only_hyb = (~b_hyb_norm) & h_hyb_norm

    print(f"  Quadrant breakdown (Hybrid):")
    print(f"    Hardened caught, Baseline failed: {q_hard_caught_hyb.sum()} ({q_hard_caught_hyb.mean()*100:.2f}%)")
    print(f"    Both caught: {q_both_caught_hyb.sum()} ({q_both_caught_hyb.mean()*100:.2f}%)")
    print(f"    Both failed: {q_both_failed_hyb.sum()} ({q_both_failed_hyb.mean()*100:.2f}%)")
    print(f"    Baseline caught, Hardened failed: {q_base_only_hyb.sum()} ({q_base_only_hyb.mean()*100:.2f}%)")

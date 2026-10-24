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
)
from app.ml.features import load_nsl_kdd, split_zero_day

base_artifacts, _ = load_artifacts(model_path())
hardened_artifacts, _ = load_artifacts(HARDENED_MODEL_PATH)

test_path = RAW_DIR / "KDDTest+.txt"
test_df = load_nsl_kdd(test_path)
known_test, _ = split_zero_day(test_df)
attack_mask = known_test["label"] != "normal"
test_attacks = known_test[attack_mask].sample(n=min(1500, int(attack_mask.sum())), random_state=42).copy()

for eps in [0.10, 0.20, 0.35]:
    for method in ["fgsm", "uap", "demgan"]:
        pert = generate_adversarial_perturbation(
            test_attacks,
            method=method,
            epsilon=eps,
            seed=42,
            artifacts=base_artifacts,
            is_hardened=False,
        )
        X_pert = base_artifacts.transformer.transform(pert)
        b_pred = hybrid_predict(base_artifacts, X_pert)
        h_pred = hybrid_predict(hardened_artifacts, X_pert)

        b_hyb_norm = b_pred["label"] == "normal"
        h_hyb_norm = h_pred["label"] == "normal"

        q_base_only_hyb = (~b_hyb_norm) & h_hyb_norm
        print(f"eps={eps} {method}: Base caught & Hardened failed = {q_base_only_hyb.sum()}")

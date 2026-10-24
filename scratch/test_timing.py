import sys
from pathlib import Path
sys.path.insert(0, str(Path("backend").resolve()))

import json
import time
from functools import lru_cache
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

t0 = time.time()
base_artifacts, _ = load_artifacts(model_path())
hardened_artifacts, _ = load_artifacts(HARDENED_MODEL_PATH)
test_path = RAW_DIR / "KDDTest+.txt"
test_df = load_nsl_kdd(test_path)
known_test, _ = split_zero_day(test_df)
attack_mask = known_test["label"] != "normal"
test_attacks = known_test[attack_mask].sample(n=min(1500, int(attack_mask.sum())), random_state=42).copy()
cutoffs = get_tier_cutoffs()
print(f"Setup loaded in {time.time() - t0:.2f}s")

t1 = time.time()
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

print(f"Evaluation finished in {time.time() - t1:.2f}s")

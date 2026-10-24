import sys
from pathlib import Path
sys.path.insert(0, str(Path("backend").resolve()))

import json
from app.config import RAW_DIR
from app.ml import load_artifacts, model_path, hybrid_predict
from app.ml.adversarial import (
    HARDENED_MODEL_PATH,
    generate_adversarial_perturbation,
    check_sample_constraints,
)
from app.ml.features import load_nsl_kdd, split_zero_day

# Let's verify how fast get_evaluation_evidence can run and structure the results
test_path = RAW_DIR / "KDDTest+.txt"
test_df = load_nsl_kdd(test_path)
known_test, _ = split_zero_day(test_df)
attack_mask = known_test["label"] != "normal"
test_attacks = known_test[attack_mask].sample(n=min(1500, int(attack_mask.sum())), random_state=42).copy()

base_artifacts, _ = load_artifacts(model_path())
hardened_artifacts, _ = load_artifacts(HARDENED_MODEL_PATH)

print("Models loaded successfully.")

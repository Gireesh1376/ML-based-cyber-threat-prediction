"""Baseline model comparison (proposal: Decision Tree, Logistic Regression, SVM, ensembles).

Trains standard supervised baselines on EXACTLY the same data the hybrid uses
(known families only, same 85/15 stratified split, seed 42) and scores them on
the official NSL-KDD test split, so they are directly comparable to
metrics.json -> detection_comparison.

Supervised baselines have no novelty mechanism, so a held-out zero-day counts
as detected only if the model calls it non-normal.

Writes backend/models/baselines.json (metrics.json is not touched).

Usage:
    cd backend
    python -m app.ml.baselines
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import MODELS_DIR, RAW_DIR  # noqa: E402
from app.ml.features import FeatureTransformer, load_nsl_kdd, split_zero_day  # noqa: E402


def _binary_report(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "missed_attacks": int(fn),
    }


def main() -> None:
    train_df = load_nsl_kdd(RAW_DIR / "KDDTrain+.txt")
    test_df = load_nsl_kdd(RAW_DIR / "KDDTest+.txt")
    known_train, _ = split_zero_day(train_df)

    transformer = FeatureTransformer().fit(known_train)
    X = transformer.transform(known_train)
    y_bin = (known_train["label"] != "normal").astype(int).to_numpy()
    X_tr, _, yb_tr, _ = train_test_split(X, y_bin, test_size=0.15, random_state=42, stratify=y_bin)

    X_test = transformer.transform(test_df)
    y_test = (test_df["label"] != "normal").astype(int).to_numpy()
    zd = test_df["is_zero_day"].to_numpy()
    families = test_df["family"].to_numpy()

    models = {
        "decision_tree": DecisionTreeClassifier(max_depth=12, random_state=42),
        "logistic_regression": LogisticRegression(max_iter=300),
        "linear_svm": LinearSVC(C=1.0, max_iter=3000, random_state=42),
        "random_forest": RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42),
    }
    try:  # XGBoost classifier on all features (no feature selection, no autoencoder)
        from xgboost import XGBClassifier

        models["xgboost_binary"] = XGBClassifier(
            n_estimators=280, max_depth=8, learning_rate=0.08, subsample=0.85,
            colsample_bytree=0.85, n_jobs=-1, tree_method="hist", random_state=42,
        )
    except Exception:  # pragma: no cover - xgboost optional here
        pass

    results = {}
    for name, model in models.items():
        model.fit(X_tr, yb_tr)
        pred = np.asarray(model.predict(X_test)).astype(int)
        report = _binary_report(y_test, pred)
        report["held_out_zero_day_detection_rate"] = float(pred[zd].mean()) if zd.any() else None
        report["recall_by_family"] = {
            fam: float(pred[(families == fam) & (y_test == 1)].mean())
            for fam in ("dos", "probe", "r2l", "u2r")
            if ((families == fam) & (y_test == 1)).any()
        }
        results[name] = report
        print(name, {k: round(v, 4) for k, v in report.items() if isinstance(v, float)})

    out = {
        "dataset": "NSL-KDD official test split",
        "test_rows": int(len(test_df)),
        "true_attacks": int(y_test.sum()),
        "held_out_zero_day_rows": int(zd.sum()),
        "setup": "Trained on known families only, same 85/15 split (seed 42) as the hybrid; all one-hot+scaled features; binary normal-vs-attack.",
        "baselines": results,
    }
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    (MODELS_DIR / "baselines.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print("Saved", MODELS_DIR / "baselines.json")


if __name__ == "__main__":
    main()

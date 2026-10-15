from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.neural_network import MLPRegressor
from xgboost import XGBClassifier

from app.config import MODELS_DIR
from app.ml.features import FeatureTransformer


@dataclass
class HybridArtifacts:
    transformer: FeatureTransformer
    autoencoder: MLPRegressor
    xgboost: XGBClassifier
    recon_threshold: float
    label_classes: list[str]
    selected_features: list[int]
    feature_names: list[str]
    novelty_gate: float = 0.62
    recon_quantile: float = 0.95


def reconstruction_error(model: MLPRegressor, X: np.ndarray) -> np.ndarray:
    reconstructed = model.predict(X)
    return np.mean((X - reconstructed) ** 2, axis=1)


def select_top_features(X: np.ndarray, y: np.ndarray, names: list[str], k: int = 48) -> list[int]:
    booster = XGBClassifier(
        n_estimators=120,
        max_depth=6,
        learning_rate=0.12,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="multi:softprob",
        eval_metric="mlogloss",
        n_jobs=-1,
        tree_method="hist",
        random_state=42,
    )
    booster.fit(X, y)
    importances = booster.feature_importances_
    k = min(k, X.shape[1])
    idx = np.argsort(importances)[::-1][:k]
    return sorted(idx.tolist())


def train_hybrid(
    X: np.ndarray,
    y: np.ndarray,
    y_binary: np.ndarray,
    feature_names: list[str],
    recon_quantile: float = 0.95,
    novelty_gate: float = 0.62,
) -> HybridArtifacts:
    selected = select_top_features(X, y, feature_names)
    Xs = X[:, selected]

    benign_mask = y_binary == 0
    benign_X = Xs[benign_mask]
    rng = np.random.default_rng(42)
    if len(benign_X) > 40000:
        pick = rng.choice(len(benign_X), size=40000, replace=False)
        benign_X = benign_X[pick]
    autoencoder = MLPRegressor(
        hidden_layer_sizes=(64, 24, 8, 24, 64),
        activation="relu",
        solver="adam",
        max_iter=25,
        random_state=42,
        early_stopping=True,
        validation_fraction=0.1,
        learning_rate_init=0.001,
    )
    autoencoder.fit(benign_X, benign_X)
    benign_err = reconstruction_error(autoencoder, Xs[benign_mask])
    # Quantile of benign reconstruction error. Default 0.95 was originally chosen
    # by looking at held-out TEST zero-days (test-informed). `app.ml.tune_novelty`
    # now selects recon_quantile and novelty_gate on validation data using
    # leave-family-out pseudo-zero-days; train.py loads them from
    # models/novelty_tuning.json when that file exists.
    recon_threshold = float(np.quantile(benign_err, recon_quantile))

    n_classes = int(np.unique(y).size)
    clf = XGBClassifier(
        n_estimators=280,
        max_depth=8,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        min_child_weight=2,
        gamma=0.05,
        reg_lambda=1.2,
        objective="multi:softprob" if n_classes > 2 else "binary:logistic",
        eval_metric="mlogloss" if n_classes > 2 else "logloss",
        n_jobs=-1,
        tree_method="hist",
        random_state=42,
    )
    clf.fit(Xs, y)
    return HybridArtifacts(
        transformer=FeatureTransformer(),
        autoencoder=autoencoder,
        xgboost=clf,
        recon_threshold=recon_threshold,
        label_classes=[],
        selected_features=selected,
        feature_names=feature_names,
        novelty_gate=novelty_gate,
        recon_quantile=recon_quantile,
    )


def hybrid_predict(
    artifacts: HybridArtifacts,
    X: np.ndarray,
) -> dict[str, np.ndarray]:
    Xs = X[:, artifacts.selected_features]
    recon = reconstruction_error(artifacts.autoencoder, Xs)
    proba = artifacts.xgboost.predict_proba(Xs)
    pred_idx = np.argmax(proba, axis=1)
    confidence = proba.max(axis=1)
    classes = np.array(artifacts.label_classes)
    pred_label = classes[pred_idx]
    anomaly = recon > artifacts.recon_threshold
    gate = float(getattr(artifacts, "novelty_gate", 0.62))
    novel = anomaly & ((pred_label == "normal") | (confidence < gate))
    # np.where (not in-place assignment): pred_label is a fixed-width unicode
    # array whose width fits "normal", so writing "zero_day" in place would
    # silently truncate it to "zero_d".
    final = np.where(novel, "zero_day", pred_label)
    return {
        "label": final,
        "known_label": pred_label,
        "confidence": confidence,
        "reconstruction_error": recon,
        "anomaly": anomaly.astype(int),
        "is_zero_day": novel.astype(int),
        "proba": proba,
    }


def evaluate_binary(y_true: np.ndarray, y_pred: np.ndarray, y_score: np.ndarray) -> dict[str, Any]:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_score)) if len(np.unique(y_true)) > 1 else None,
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }


def evaluate_multiclass(y_true: np.ndarray, y_pred: np.ndarray, labels: list[str]) -> dict[str, Any]:
    report = classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0)
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "report": report,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "labels": labels,
    }


def xgboost_native_path(model_file: Path) -> Path:
    return model_file.with_name(model_file.stem + "_xgb.json")


def save_artifacts(path: Path, artifacts: HybridArtifacts, extra: dict[str, Any]) -> None:
    """Persist artifacts with the XGBoost model in its native JSON format.

    A pickled XGBClassifier only loads in the xgboost version that trained it;
    the native format is stable across versions, so the model survives pip
    upgrades instead of crashing with a version-mismatch error. The scaler,
    one-hot encoder, autoencoder and thresholds stay in the joblib bundle;
    the booster is written separately as ``hybrid_xgb.json``.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    artifacts.xgboost.get_booster().save_model(str(xgboost_native_path(path)))
    compact = HybridArtifacts(
        transformer=artifacts.transformer,
        autoencoder=artifacts.autoencoder,
        xgboost=None,  # type: ignore[arg-type]
        recon_threshold=artifacts.recon_threshold,
        label_classes=artifacts.label_classes,
        selected_features=artifacts.selected_features,
        feature_names=artifacts.feature_names,
        novelty_gate=artifacts.novelty_gate,
        recon_quantile=artifacts.recon_quantile,
    )
    joblib.dump({"artifacts": compact, "extra": extra}, path)


def load_artifacts(path: Path) -> tuple[HybridArtifacts, dict[str, Any]]:
    payload = joblib.load(path)
    artifacts: HybridArtifacts = payload["artifacts"]
    if not getattr(artifacts, "xgboost", None):
        native = xgboost_native_path(path)
        if not native.exists():
            raise FileNotFoundError(
                f"Native XGBoost model missing: {native}. Retrain with python -m app.ml.train"
            )
        # Rebuild from the native booster: version-independent, unlike a pickle.
        clf = XGBClassifier()
        clf.load_model(str(native))
        artifacts.xgboost = clf
    return artifacts, payload.get("extra", {})


def model_path() -> Path:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    return MODELS_DIR / "hybrid_detector.joblib"

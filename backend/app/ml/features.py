from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler

from app.config import ATTACK_FAMILY, CATEGORICAL_COLUMNS, FEATURE_COLUMNS, ZERO_DAY_LABELS


def load_nsl_kdd(path) -> pd.DataFrame:
    columns = FEATURE_COLUMNS + ["label", "difficulty"]
    df = pd.read_csv(path, header=None, names=columns)
    df["label"] = df["label"].astype(str).str.rstrip(".").str.lower()
    df["family"] = df["label"].map(lambda x: ATTACK_FAMILY.get(x, "unknown"))
    df["is_zero_day"] = df["label"].isin(ZERO_DAY_LABELS)
    return df


def split_zero_day(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    known = df[~df["is_zero_day"]].copy()
    unseen = df[df["is_zero_day"]].copy()
    return known, unseen


class FeatureTransformer:
    def __init__(self) -> None:
        self.scaler = StandardScaler()
        self.onehot = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
        self.numeric_columns: list[str] = []
        self.feature_names: list[str] = []

    def fit(self, df: pd.DataFrame) -> "FeatureTransformer":
        self.numeric_columns = [c for c in FEATURE_COLUMNS if c not in CATEGORICAL_COLUMNS]
        cat = df[CATEGORICAL_COLUMNS].astype(str)
        num = df[self.numeric_columns].astype(float)
        self.onehot.fit(cat)
        encoded = self.onehot.transform(cat)
        combined = np.hstack([num.to_numpy(), encoded])
        self.scaler.fit(combined)
        cat_names = list(self.onehot.get_feature_names_out(CATEGORICAL_COLUMNS))
        self.feature_names = self.numeric_columns + cat_names
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        cat = df[CATEGORICAL_COLUMNS].astype(str)
        num = df[self.numeric_columns].astype(float)
        encoded = self.onehot.transform(cat)
        combined = np.hstack([num.to_numpy(), encoded])
        return self.scaler.transform(combined)

    def to_frame(self, X: np.ndarray) -> pd.DataFrame:
        return pd.DataFrame(X, columns=self.feature_names)


def encode_labels(series: pd.Series) -> tuple[np.ndarray, LabelEncoder]:
    encoder = LabelEncoder()
    y = encoder.fit_transform(series.astype(str))
    return y, encoder


def sample_to_dataframe(payload: dict[str, Any]) -> pd.DataFrame:
    row = {col: payload.get(col, 0) for col in FEATURE_COLUMNS}
    for col in CATEGORICAL_COLUMNS:
        row[col] = str(row[col] if row[col] not in (None, "") else "other")
    return pd.DataFrame([row])

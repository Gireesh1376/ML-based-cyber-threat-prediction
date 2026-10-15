"""The anomaly explanation must be an exact decomposition of the reconstruction error."""

from types import SimpleNamespace

import numpy as np
from sklearn.neural_network import MLPRegressor

from app.ml import reconstruction_error
from app.ml.detector import _anomaly_contributors


def _fake_artifacts(n_features: int = 12):
    rng = np.random.default_rng(0)
    X = rng.normal(size=(400, n_features))
    ae = MLPRegressor(hidden_layer_sizes=(6,), max_iter=200, random_state=0).fit(X, X)
    return SimpleNamespace(
        autoencoder=ae,
        selected_features=list(range(n_features)),
        feature_names=[f"f{i}" for i in range(n_features)],
    ), rng


def test_error_shares_are_exact_and_sorted():
    arts, rng = _fake_artifacts()
    x = rng.normal(size=(1, 12)) * 3  # deliberately off-distribution
    rows = _anomaly_contributors(arts, x, top=12)
    shares = [r["error_share"] for r in rows]
    assert abs(sum(shares) - 1.0) < 1e-9          # full list decomposes the whole error
    assert shares == sorted(shares, reverse=True)  # largest contributor first
    total = reconstruction_error(arts.autoencoder, x)[0] * 12
    sq = (x[0] - arts.autoencoder.predict(x)[0]) ** 2
    assert np.isclose(total, sq.sum())


def test_top_n_limits_rows_and_names_real_features():
    arts, rng = _fake_artifacts()
    rows = _anomaly_contributors(arts, rng.normal(size=(1, 12)), top=5)
    assert len(rows) == 5
    assert all(r["feature"] in arts.feature_names for r in rows)

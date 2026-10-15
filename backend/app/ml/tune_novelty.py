"""Select the reconstruction-error quantile and the novelty confidence gate WITHOUT touching the test split.

Problem: validation data (drawn from known-family training rows) contains no
zero-days, and the previous settings (quantile 0.95, gate 0.62) were chosen by
looking at the held-out test zero-days.

Method (leave-family-out): remove a few KNOWN attack families from KDDTrain+
entirely (default: back [dos], nmap [probe], warezclient [r2l]), train the
hybrid on everything else, then treat the removed families as pseudo-zero-days.
Sweep (recon_quantile x novelty_gate) and pick the setting that maximises
pseudo-zero-day F1 subject to a benign false-positive budget. The official test
split is never read here.

Caveat (state it in the report): pseudo-zero-days (back, nmap, warezclient)
behave differently from the test zero-days (mailbomb, apache2, ...), so the
chosen values are validated-reasonable, not guaranteed optimal for them.

Output: backend/models/novelty_tuning.json, which `python -m app.ml.train`
loads automatically.

Usage:
    cd backend
    python -m app.ml.tune_novelty [--max-fpr 0.05] [--families back nmap warezclient]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import MODELS_DIR, RAW_DIR  # noqa: E402
from app.ml import reconstruction_error, train_hybrid  # noqa: E402
from app.ml.features import FeatureTransformer, load_nsl_kdd, split_zero_day  # noqa: E402

QUANTILES = [0.90, 0.92, 0.94, 0.95, 0.96, 0.97, 0.98, 0.99]
GATES = [0.50, 0.60, 0.62, 0.70, 0.80, 0.90, 0.99]


def run(families: list[str], max_fpr: float, out_path: Path, raw_dir: Path = RAW_DIR) -> dict:
    train_df = load_nsl_kdd(raw_dir / "KDDTrain+.txt")  # test split is NOT loaded
    known, _ = split_zero_day(train_df)
    missing = [f for f in families if f not in set(known["label"])]
    if missing:
        raise SystemExit(f"Families not present in KDDTrain+ known data: {missing}")

    pseudo_mask = known["label"].isin(families).to_numpy()
    pseudo = known[pseudo_mask]
    base = known[~pseudo_mask]

    transformer = FeatureTransformer().fit(base)
    X_base = transformer.transform(base)
    encoder = LabelEncoder()
    y_multi = encoder.fit_transform(base["family"].where(base["label"] != "normal", "normal").astype(str))
    y_bin = (base["label"] != "normal").astype(int).to_numpy()
    X_tr, X_val, y_tr, y_val, yb_tr, yb_val = train_test_split(
        X_base, y_multi, y_bin, test_size=0.15, random_state=42, stratify=y_bin
    )

    arts = train_hybrid(X_tr, y_tr, yb_tr, transformer.feature_names)
    classes = np.array(encoder.classes_)
    sel = arts.selected_features

    # Benign training reconstruction errors -> threshold for any quantile (no retraining).
    benign_err = reconstruction_error(arts.autoencoder, X_tr[:, sel][yb_tr == 0])

    # Evaluation set = validation rows (benign + known attacks) + pseudo-zero-days.
    X_eval = np.vstack([X_val, transformer.transform(pseudo)])
    is_pseudo = np.concatenate([np.zeros(len(X_val), dtype=bool), np.ones(len(pseudo), dtype=bool)])
    is_benign = np.concatenate([yb_val == 0, np.zeros(len(pseudo), dtype=bool)])
    Xs = X_eval[:, sel]
    recon = reconstruction_error(arts.autoencoder, Xs)
    proba = arts.xgboost.predict_proba(Xs)
    conf = proba.max(axis=1)
    pred_normal = classes[np.argmax(proba, axis=1)] == "normal"
    is_attack = ~is_benign

    grid = []
    for q in QUANTILES:
        thr = float(np.quantile(benign_err, q))
        anomaly = recon > thr
        for gate in GATES:
            novel = anomaly & (pred_normal | (conf < gate))
            flagged = np.where(novel, True, ~pred_normal)  # final label != normal
            tp = int((novel & is_pseudo).sum())
            fp = int((novel & ~is_pseudo).sum())
            fn = int((~novel & is_pseudo).sum())
            prec = tp / (tp + fp) if tp + fp else 0.0
            rec = tp / (tp + fn) if tp + fn else 0.0
            f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
            grid.append(
                {
                    "recon_quantile": q,
                    "novelty_gate": gate,
                    "recon_threshold": thr,
                    "pseudo_zero_day_precision": round(prec, 4),
                    "pseudo_zero_day_recall": round(rec, 4),
                    "pseudo_zero_day_f1": round(f1, 4),
                    "pseudo_not_classified_benign": round(float(flagged[is_pseudo].mean()), 4),
                    "benign_false_positive_rate": round(float(flagged[is_benign].mean()), 4),
                    "attack_recall_all": round(float(flagged[is_attack].mean()), 4),
                }
            )

    feasible = [g for g in grid if g["benign_false_positive_rate"] <= max_fpr]
    pool = feasible or sorted(grid, key=lambda g: g["benign_false_positive_rate"])[:5]
    best = max(pool, key=lambda g: (g["pseudo_zero_day_f1"], g["pseudo_zero_day_recall"]))
    result = {
        "method": "leave-family-out validation; official test split not read",
        "pseudo_zero_day_families": families,
        "pseudo_zero_day_rows": int(len(pseudo)),
        "validation_rows": int(len(X_val)),
        "objective": f"max pseudo-zero-day F1 subject to benign FPR <= {max_fpr}"
        + ("" if feasible else " (NO setting met the budget; lowest-FPR settings considered)"),
        "chosen": {
            "recon_quantile": best["recon_quantile"],
            "novelty_gate": best["novelty_gate"],
            **{k: best[k] for k in best if k.startswith(("pseudo", "benign", "attack"))},
        },
        "grid": grid,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--families", nargs="+", default=["back", "nmap", "warezclient"])
    ap.add_argument("--max-fpr", type=float, default=0.05)
    ap.add_argument("--out", type=Path, default=MODELS_DIR / "novelty_tuning.json")
    args = ap.parse_args()
    res = run(args.families, args.max_fpr, args.out)
    print(json.dumps(res["chosen"], indent=2))
    print("Saved", args.out)


if __name__ == "__main__":
    main()

from __future__ import annotations

import glob
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.dataset as ds
from sklearn.base import BaseEstimator, TransformerMixin

logger = logging.getLogger("aegis.encrypted_features")

# ---------------------------------------------------------------------------
# Feature Column Definitions (Strictly Non-Leaking)
# ---------------------------------------------------------------------------

# Transport dynamics and safe structural counts (no IPs, hostnames, timestamps)
FLOW_NUMERICAL_COLS: list[str] = [
    "bs",                  # Bytes sent (client -> server)
    "br",                  # Bytes received (server -> client)
    "ps",                  # Packets sent
    "pr",                  # Packets received
    "td",                  # Duration in seconds
    "dp",                  # Destination port (e.g. 443, 8443)
    "bytes_ratio",         # bs / (br + 1)
    "pkts_ratio",          # ps / (pr + 1)
    "bytes_per_pkt_client",# bs / (ps + 1)
    "bytes_per_pkt_server",# br / (pr + 1)
    "byte_rate",           # (bs + br) / (td + 0.001)
    "pkt_rate",            # (ps + pr) / (td + 0.001)
    "cipher_count",        # ClientHello offered ciphers list length
    "client_ext_count",    # ClientHello extensions list length
    "sig_alg_count",       # Client signature algorithms list length
    "server_ext_count",    # ServerHello extensions list length
    "alpn_count",          # Negotiated ALPN count
    "has_alpn",            # Binary indicator (ALPN present)
    "has_sni",             # Binary indicator (SNI hostname present, without the name)
]

# Sequence of Packet Length and Time (SPLT): first 20 signed TLS record lengths
SPLT_RECORD_COLS: list[str] = [f"rec_{i}" for i in range(20)]

# Safe protocol categoricals
CATEGORICAL_COLS: list[str] = [
    "tls.cver",            # Client version (e.g. 0x0303)
    "tls.scs",             # Server selected cipher suite (e.g. 0x1301)
    "ja4_prefix",          # First section of JA4 fingerprint (e.g. t13d1516h2)
]


def extract_raw_features_from_dict(flow: dict[str, Any]) -> dict[str, Any]:
    """
    Extract a single sanitized feature dictionary from an incoming dictionary payload.
    Ensures safe handling of nulls, empty arrays, division-by-zero, and type coercions.
    """
    def _to_float(v: Any, default: float = 0.0) -> float:
        if v is None:
            return default
        try:
            val = float(v)
            return default if (np.isnan(val) or np.isinf(val)) else val
        except (ValueError, TypeError):
            return default

    bs = max(_to_float(flow.get("bs")), 0.0)
    br = max(_to_float(flow.get("br")), 0.0)
    ps = max(_to_float(flow.get("ps")), 0.0)
    pr = max(_to_float(flow.get("pr")), 0.0)
    td = max(_to_float(flow.get("td")), 0.0)
    dp = _to_float(flow.get("dp"), default=443.0)

    # Handshake counts
    ccs = flow.get("tls.ccs") or flow.get("tls_ccs") or flow.get("ccs") or []
    cext = flow.get("tls.cext") or flow.get("tls_cext") or flow.get("cext") or []
    csg = flow.get("tls.csg") or flow.get("tls_csg") or flow.get("csg") or []
    sext = flow.get("tls.sext") or flow.get("tls_sext") or flow.get("sext") or []
    alpn = flow.get("tls.alpn") or flow.get("tls_alpn") or flow.get("alpn") or []
    sni = flow.get("tls.sni") or flow.get("tls_sni") or flow.get("sni")

    cipher_count = float(len(ccs) if isinstance(ccs, (list, tuple, np.ndarray)) else 0)
    client_ext_count = float(len(cext) if isinstance(cext, (list, tuple, np.ndarray)) else 0)
    sig_alg_count = float(len(csg) if isinstance(csg, (list, tuple, np.ndarray)) else 0)
    server_ext_count = float(len(sext) if isinstance(sext, (list, tuple, np.ndarray)) else 0)
    alpn_count = float(len(alpn) if isinstance(alpn, (list, tuple, np.ndarray)) else 0)
    has_alpn = 1.0 if alpn_count > 0 else 0.0
    has_sni = 1.0 if (sni is not None and str(sni).strip() != "") else 0.0

    # SPLT: first 20 signed record lengths
    rec = flow.get("tls.rec") or flow.get("tls_rec") or flow.get("rec") or []
    rec_vals = [0.0] * 20
    if isinstance(rec, (list, tuple, np.ndarray)):
        for i in range(min(len(rec), 20)):
            try:
                r_val = float(rec[i])
                rec_vals[i] = 0.0 if (np.isnan(r_val) or np.isinf(r_val)) else r_val
            except (ValueError, TypeError):
                rec_vals[i] = 0.0

    # Categoricals (normalize 0x prefixes and casing for robust inference)
    cver_raw = str(flow.get("tls.cver") or flow.get("tls_cver") or flow.get("cver") or "unknown").strip()
    if cver_raw.lower() in ("", "unknown", "none"):
        cver = "unknown"
    else:
        if cver_raw.lower().startswith("0x"):
            cver_raw = cver_raw[2:]
        cver = cver_raw.upper() if cver_raw else "unknown"

    scs_raw = str(flow.get("tls.scs") or flow.get("tls_scs") or flow.get("scs") or "unknown").strip()
    if scs_raw.lower() in ("", "unknown", "none"):
        scs = "unknown"
    else:
        if scs_raw.lower().startswith("0x"):
            scs_raw = scs_raw[2:]
        scs = scs_raw.upper() if scs_raw else "unknown"

    ja4 = str(flow.get("tls.ja4") or flow.get("tls_ja4") or flow.get("ja4") or "")
    ja4_prefix = ja4.split("_")[0] if ("_" in ja4 and len(ja4.split("_")[0]) <= 12) else ("unknown" if not ja4 else ja4[:10])

    features: dict[str, Any] = {
        "bs": bs,
        "br": br,
        "ps": ps,
        "pr": pr,
        "td": td,
        "dp": dp,
        "bytes_ratio": bs / (br + 1.0),
        "pkts_ratio": ps / (pr + 1.0),
        "bytes_per_pkt_client": bs / (ps + 1.0),
        "bytes_per_pkt_server": br / (pr + 1.0),
        "byte_rate": (bs + br) / (td + 0.001),
        "pkt_rate": (ps + pr) / (td + 0.001),
        "cipher_count": cipher_count,
        "client_ext_count": client_ext_count,
        "sig_alg_count": sig_alg_count,
        "server_ext_count": server_ext_count,
        "alpn_count": alpn_count,
        "has_alpn": has_alpn,
        "has_sni": has_sni,
        "tls.cver": cver,
        "tls.scs": scs,
        "ja4_prefix": ja4_prefix,
    }
    for i in range(20):
        features[f"rec_{i}"] = rec_vals[i]

    return features


@dataclass
class EncryptedFeatureTransformer(BaseEstimator, TransformerMixin):
    """
    Leakage-resistant feature transformer for encrypted TLS/QUIC network traffic.
    Fitted exclusively on training data to prevent label and distribution leakage.
    Supports modular evaluation of metadata-only vs sequence-informed models.
    """
    include_splt: bool = True
    include_categoricals: bool = True
    top_cver_k: int = 5
    top_scs_k: int = 20
    top_ja4_k: int = 15

    # Learned parameters (populated during fit)
    medians_: dict[str, float] = field(default_factory=dict)
    means_: dict[str, float] = field(default_factory=dict)
    stds_: dict[str, float] = field(default_factory=dict)
    known_cvers_: list[str] = field(default_factory=list)
    known_scs_: list[str] = field(default_factory=list)
    known_ja4_: list[str] = field(default_factory=list)
    feature_names_: list[str] = field(default_factory=list)

    def fit(self, X: pd.DataFrame, y: Any = None) -> EncryptedFeatureTransformer:
        """Learn robust summary statistics and top categorical frequencies from training split."""
        num_cols = list(FLOW_NUMERICAL_COLS)
        if self.include_splt:
            num_cols.extend(SPLT_RECORD_COLS)

        for col in num_cols:
            if col in X.columns:
                series = pd.to_numeric(X[col], errors="coerce").fillna(0.0)
                med = float(series.median())
                mean = float(series.mean())
                std = float(series.std())
                self.medians_[col] = med
                self.means_[col] = mean
                self.stds_[col] = std if std > 1e-6 else 1.0
            else:
                self.medians_[col] = 0.0
                self.means_[col] = 0.0
                self.stds_[col] = 1.0

        names: list[str] = list(num_cols)

        if self.include_categoricals:
            # Top client versions
            if "tls.cver" in X.columns:
                cver_counts = X["tls.cver"].astype(str).value_counts()
                self.known_cvers_ = cver_counts.head(self.top_cver_k).index.tolist()
            else:
                self.known_cvers_ = []
            for cv in self.known_cvers_:
                names.append(f"cver_{cv}")
            names.append("cver_other")

            # Top server cipher suites
            if "tls.scs" in X.columns:
                scs_counts = X["tls.scs"].astype(str).value_counts()
                self.known_scs_ = scs_counts.head(self.top_scs_k).index.tolist()
            else:
                self.known_scs_ = []
            for sc in self.known_scs_:
                names.append(f"scs_{sc}")
            names.append("scs_other")

            # Top JA4 prefixes
            if "ja4_prefix" in X.columns:
                ja4_counts = X["ja4_prefix"].astype(str).value_counts()
                self.known_ja4_ = ja4_counts.head(self.top_ja4_k).index.tolist()
            else:
                self.known_ja4_ = []
            for j in self.known_ja4_:
                names.append(f"ja4_{j}")
            names.append("ja4_other")

        self.feature_names_ = names
        return self

    def transform(self, X: pd.DataFrame | list[dict[str, Any]] | dict[str, Any]) -> np.ndarray:
        """Transform arbitrary incoming flows into a normalized, sanitized feature matrix."""
        if isinstance(X, dict):
            X = [X]
        if isinstance(X, list):
            rows = [extract_raw_features_from_dict(item) if not isinstance(item, dict) or "rec_0" not in item else item for item in X]
            X = pd.DataFrame(rows)

        num_cols = list(FLOW_NUMERICAL_COLS)
        if self.include_splt:
            num_cols.extend(SPLT_RECORD_COLS)

        n_samples = len(X)
        parts: list[np.ndarray] = []

        # Numerical block
        num_arr = np.zeros((n_samples, len(num_cols)), dtype=np.float32)
        for idx, col in enumerate(num_cols):
            if col in X.columns:
                series = pd.to_numeric(X[col], errors="coerce").fillna(self.medians_.get(col, 0.0)).to_numpy()
                series = np.nan_to_num(series, nan=self.medians_.get(col, 0.0), posinf=1e6, neginf=-1e6)
            else:
                series = np.full(n_samples, self.medians_.get(col, 0.0), dtype=np.float32)

            # Robust Standardization: (X - mean) / std
            mean_val = self.means_.get(col, 0.0)
            std_val = self.stds_.get(col, 1.0)
            num_arr[:, idx] = ((series - mean_val) / std_val).astype(np.float32)

        parts.append(num_arr)

        # Categorical block (One-Hot Encoded)
        if self.include_categoricals:
            # cver
            cver_vals = X["tls.cver"].astype(str).to_numpy() if "tls.cver" in X.columns else np.full(n_samples, "unknown")
            cver_arr = np.zeros((n_samples, len(self.known_cvers_) + 1), dtype=np.float32)
            cver_matched = np.zeros(n_samples, dtype=bool)
            for k_idx, known in enumerate(self.known_cvers_):
                match = (cver_vals == known)
                cver_arr[match, k_idx] = 1.0
                cver_matched |= match
            cver_arr[~cver_matched, -1] = 1.0  # other
            parts.append(cver_arr)

            # scs
            scs_vals = X["tls.scs"].astype(str).to_numpy() if "tls.scs" in X.columns else np.full(n_samples, "unknown")
            scs_arr = np.zeros((n_samples, len(self.known_scs_) + 1), dtype=np.float32)
            scs_matched = np.zeros(n_samples, dtype=bool)
            for k_idx, known in enumerate(self.known_scs_):
                match = (scs_vals == known)
                scs_arr[match, k_idx] = 1.0
                scs_matched |= match
            scs_arr[~scs_matched, -1] = 1.0
            parts.append(scs_arr)

            # ja4_prefix
            ja4_vals = X["ja4_prefix"].astype(str).to_numpy() if "ja4_prefix" in X.columns else np.full(n_samples, "unknown")
            ja4_arr = np.zeros((n_samples, len(self.known_ja4_) + 1), dtype=np.float32)
            ja4_matched = np.zeros(n_samples, dtype=bool)
            for k_idx, known in enumerate(self.known_ja4_):
                match = (ja4_vals == known)
                ja4_arr[match, k_idx] = 1.0
                ja4_matched |= match
            ja4_arr[~ja4_matched, -1] = 1.0
            parts.append(ja4_arr)

        return np.hstack(parts)


@dataclass
class EncryptedDetectorArtifacts:
    transformer: EncryptedFeatureTransformer
    xgboost: Any | None
    feature_names: list[str]
    threshold: float = 0.50
    model_version: str = "1.0.0"


# ---------------------------------------------------------------------------
# High-Performance PyArrow Dataset Loader & Splitter
# ---------------------------------------------------------------------------

def load_clean_encrypted_dataset(
    data_dir: Path | str,
    cutoff_date: int = 250922,
    max_train_samples: int | None = 150000,
    max_test_samples: int | None = 50000,
    random_state: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, Any]]:
    """
    Stream and extract candidate supervised flows from the Parquet dataset using PyArrow.
    
    Candidate Labels (Preparation Audit Protocol):
    - Positive (1): meta.malware.family is non-null AND meta.system.service is null.
    - Negative (0): clean NO_MALWARE runs OR (meta.malware.family is null AND meta.system.service is non-null).
    - Ambiguous: Excluded (overlap of malware + service, or unattributed in infected VM).
    
    Split Strategy:
    - Grouped strictly by execution sample ID (`meta.sample.id`).
    - Chronological holdout: Train <= cutoff_date (Sep 1-22), Test > cutoff_date (Sep 23-30).
    - Sample ID overlap check: strictly 0 overlap guaranteed.
    """
    data_path = Path(data_dir)
    if not data_path.exists():
        raise FileNotFoundError(f"Encrypted traffic dataset directory not found: {data_path}")

    # 1. Discover clean baseline runs
    nm_files = glob.glob(os.path.join(str(data_path), "*NO_MALWARE*.parquet"))
    clean_sample_ids: set[str] = set()
    if nm_files:
        ds_nm = ds.dataset(nm_files, format="parquet")
        scanner_nm = ds_nm.scanner(columns=["meta.sample.id"])
        for b in scanner_nm.to_batches():
            for s in b.column("meta.sample.id").to_pylist():
                clean_sample_ids.add(s)

    clean_arr = pa.array(list(clean_sample_ids))

    # 2. PyArrow compute filter for candidate clean rows
    dataset = ds.dataset(str(data_path), format="parquet")
    filt = (
        (pc.is_valid(pc.field("meta.malware.family")) & pc.is_null(pc.field("meta.system.service")))
        | (pc.is_null(pc.field("meta.malware.family")) & pc.is_valid(pc.field("meta.system.service")))
        | (pc.is_in(pc.field("meta.sample.id"), value_set=clean_arr))
    )

    req_cols = [
        "bs", "ps", "br", "pr", "dp", "td",
        "tls.ccs", "tls.cext", "tls.csg", "tls.sext", "tls.alpn", "tls.sni",
        "tls.cver", "tls.scs", "tls.ja4", "tls.rec",
        "meta.sample.id", "meta.malware.family", "meta.system.service"
    ]

    scanner = dataset.scanner(columns=req_cols, filter=filt, batch_size=50000)

    train_batches: list[pd.DataFrame] = []
    test_batches: list[pd.DataFrame] = []

    train_sample_ids: set[str] = set()
    test_sample_ids: set[str] = set()

    for batch in scanner.to_batches():
        samps = batch.column("meta.sample.id").to_pylist()
        fams = batch.column("meta.malware.family").to_pylist()
        servs = batch.column("meta.system.service").to_pylist()

        # Vectorized L4 columns
        bs = np.nan_to_num(batch.column("bs").to_numpy(zero_copy_only=False), nan=0.0).astype(np.float32)
        br = np.nan_to_num(batch.column("br").to_numpy(zero_copy_only=False), nan=0.0).astype(np.float32)
        ps = np.nan_to_num(batch.column("ps").to_numpy(zero_copy_only=False), nan=0.0).astype(np.float32)
        pr = np.nan_to_num(batch.column("pr").to_numpy(zero_copy_only=False), nan=0.0).astype(np.float32)
        td = np.maximum(np.nan_to_num(batch.column("td").to_numpy(zero_copy_only=False), nan=0.0), 0.0).astype(np.float32)
        dp = np.nan_to_num(batch.column("dp").to_numpy(zero_copy_only=False), nan=443.0).astype(np.float32)

        # Handshake structural counts
        cipher_count = pc.list_value_length(batch.column("tls.ccs")).fill_null(0).to_numpy(zero_copy_only=False).astype(np.float32)
        client_ext_count = pc.list_value_length(batch.column("tls.cext")).fill_null(0).to_numpy(zero_copy_only=False).astype(np.float32)
        sig_alg_count = pc.list_value_length(batch.column("tls.csg")).fill_null(0).to_numpy(zero_copy_only=False).astype(np.float32)
        server_ext_count = pc.list_value_length(batch.column("tls.sext")).fill_null(0).to_numpy(zero_copy_only=False).astype(np.float32)
        alpn_count = pc.list_value_length(batch.column("tls.alpn")).fill_null(0).to_numpy(zero_copy_only=False).astype(np.float32)
        has_alpn = (alpn_count > 0).astype(np.float32)
        has_sni = pc.is_valid(batch.column("tls.sni")).to_numpy(zero_copy_only=False).astype(np.float32)

        dict_data: dict[str, Any] = {
            "bs": bs, "br": br, "ps": ps, "pr": pr, "td": td, "dp": dp,
            "bytes_ratio": bs / (br + 1.0),
            "pkts_ratio": ps / (pr + 1.0),
            "bytes_per_pkt_client": bs / (ps + 1.0),
            "bytes_per_pkt_server": br / (pr + 1.0),
            "byte_rate": (bs + br) / (td + 0.001),
            "pkt_rate": (ps + pr) / (td + 0.001),
            "cipher_count": cipher_count,
            "client_ext_count": client_ext_count,
            "sig_alg_count": sig_alg_count,
            "server_ext_count": server_ext_count,
            "alpn_count": alpn_count,
            "has_alpn": has_alpn,
            "has_sni": has_sni,
        }

        # SPLT 20 record lengths
        rec_arr = batch.column("tls.rec")
        for i in range(20):
            dict_data[f"rec_{i}"] = pc.list_element(rec_arr, i).fill_null(0).to_numpy(zero_copy_only=False).astype(np.float32)

        dict_data["tls.cver"] = batch.column("tls.cver").fill_null("unknown").to_pylist()
        dict_data["tls.scs"] = batch.column("tls.scs").fill_null("unknown").to_pylist()
        raw_ja4 = batch.column("tls.ja4").fill_null("").to_pylist()
        dict_data["ja4_prefix"] = [j.split("_")[0] if "_" in j else ("unknown" if not j else j[:10]) for j in raw_ja4]

        # Labels & metadata
        labels = [1 if (f is not None and s is None) else 0 for f, s in zip(fams, servs)]
        dict_data["label"] = np.array(labels, dtype=np.int32)
        dict_data["meta.sample.id"] = samps
        dict_data["meta.malware.family"] = [f or "benign_service" for f in fams]

        # Chronological dates
        dates = [int(s[:6]) if (len(s) >= 6 and s[:6].isdigit()) else 0 for s in samps]
        dict_data["date"] = np.array(dates, dtype=np.int32)

        df_b = pd.DataFrame(dict_data)

        # Partition into train vs test
        train_mask = df_b["date"] <= cutoff_date
        df_train_b = df_b[train_mask]
        df_test_b = df_b[~train_mask]

        if not df_train_b.empty:
            train_batches.append(df_train_b)
            train_sample_ids.update(df_train_b["meta.sample.id"].unique())
        if not df_test_b.empty:
            test_batches.append(df_test_b)
            test_sample_ids.update(df_test_b["meta.sample.id"].unique())

    df_train = pd.concat(train_batches, ignore_index=True) if train_batches else pd.DataFrame()
    df_test = pd.concat(test_batches, ignore_index=True) if test_batches else pd.DataFrame()

    # Track natural zero-day families in test
    train_fams = set(df_train["meta.malware.family"].unique()) if not df_train.empty else set()
    test_fams = set(df_test["meta.malware.family"].unique()) if not df_test.empty else set()
    natural_zero_days = (test_fams - train_fams) - {"benign_service", "none"}

    # Grouped sample-ID sampling if requested (preserves complete execution groups)
    rng = np.random.default_rng(random_state)
    if max_train_samples and len(df_train) > max_train_samples:
        all_train_samps = np.array(list(train_sample_ids))
        rng.shuffle(all_train_samps)
        selected_samps: set[str] = set()
        cur_count = 0
        samp_counts = df_train["meta.sample.id"].value_counts().to_dict()
        for sid in all_train_samps:
            selected_samps.add(sid)
            cur_count += samp_counts.get(sid, 0)
            if cur_count >= max_train_samples:
                break
        df_train = df_train[df_train["meta.sample.id"].isin(selected_samps)].copy()

    if max_test_samples and len(df_test) > max_test_samples:
        all_test_samps = np.array(list(test_sample_ids))
        rng.shuffle(all_test_samps)
        selected_test_samps: set[str] = set()
        cur_count = 0
        samp_counts_test = df_test["meta.sample.id"].value_counts().to_dict()
        for sid in all_test_samps:
            selected_test_samps.add(sid)
            cur_count += samp_counts_test.get(sid, 0)
            if cur_count >= max_test_samples:
                break
        df_test = df_test[df_test["meta.sample.id"].isin(selected_test_samps)].copy()

    overlap = set(df_train["meta.sample.id"].unique()).intersection(set(df_test["meta.sample.id"].unique()))

    meta_info: dict[str, Any] = {
        "train_rows": len(df_train),
        "test_rows": len(df_test),
        "train_sample_ids": int(df_train["meta.sample.id"].nunique()),
        "test_sample_ids": int(df_test["meta.sample.id"].nunique()),
        "sample_id_overlap": len(overlap),
        "train_positives": int((df_train["label"] == 1).sum()),
        "train_negatives": int((df_train["label"] == 0).sum()),
        "test_positives": int((df_test["label"] == 1).sum()),
        "test_negatives": int((df_test["label"] == 0).sum()),
        "train_dates": f"{df_train['date'].min()} to {df_train['date'].max()}" if not df_train.empty else "none",
        "test_dates": f"{df_test['date'].min()} to {df_test['date'].max()}" if not df_test.empty else "none",
        "natural_zero_days": sorted(list(natural_zero_days)),
    }

    return df_train, df_test, meta_info

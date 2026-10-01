"""Per-dataset causal feature extraction (the production StreamingFeatureExtractor, unchanged) + dataset loading helpers.

Labels are never read here. The onboarding boundary is derived from dataset metadata (a calendar boundary), not from any label.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path

import numpy as np
import pandas as pd

from . import common as K
from .common import C


def data_paths(did: str, data_dir=None) -> dict:
    root = Path(data_dir or K.DATA_DIR)
    if did == K.LEGACY_ID:
        return {"events": C.SAMPLE_DIR / "events.csv", "labels": C.SAMPLE_DIR / "labels.csv", "incidents": None, "meta": None}
    d = root / did
    return {"events": d / "events.csv", "labels": d / "labels.csv", "incidents": d / "incidents.json", "meta": d / "meta.json"}


def load_events4(did: str, data_dir=None) -> pd.DataFrame:
    """Same reading semantics as src.utils.load_events (the production loader)."""
    df = pd.read_csv(data_paths(did, data_dir)["events"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["command_sequence"] = df["command_sequence"].fillna("")
    return df.sort_values("timestamp").reset_index(drop=True)


def onboarding_end(did: str, ev: pd.DataFrame, data_dir=None) -> pd.Timestamp:
    if did == K.LEGACY_ID:
        return ev["timestamp"].min() + pd.Timedelta(days=K.LEGACY_ONBOARDING_DAYS)
    import json
    meta = json.load(open(data_paths(did, data_dir)["meta"], encoding="utf-8"))
    return pd.Timestamp(meta["onboarding_end"])


def compute(did: str, out_dir, data_dir=None) -> dict:
    from src.features import FEATURE_NAMES, build_feature_matrix
    t = time.time()
    ev = load_events4(did, data_dir)
    X = build_feature_matrix(ev, verbose=False)
    t_on = onboarding_end(did, ev, data_dir)
    n_onb = int((ev["timestamp"] < t_on).sum())
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    F = X[FEATURE_NAMES].to_numpy(dtype=np.float64)
    np.savez_compressed(out_dir / f"{did}.npz", event_id=ev["event_id"].to_numpy(), entity_id=ev["entity_id"].to_numpy(dtype=str),
                        entity_type=ev["entity_type"].to_numpy(dtype=str), ts_ns=ev["timestamp"].to_numpy().astype("datetime64[ns]").astype(np.int64),
                        X=F, n_onb=np.array([n_onb]))
    h = hashlib.sha256(np.ascontiguousarray(F).tobytes()).hexdigest()
    return {"dataset": did, "rows": int(len(ev)), "n_onboarding": n_onb, "n_eval": int(len(ev) - n_onb), "features_sha256": h, "seconds": round(time.time() - t, 1)}


class Loaded:
    """A dataset with its causal feature matrix (label-free)."""

    def __init__(self, did: str, feat_dir, data_dir=None):
        from src.features import FEATURE_NAMES
        z = np.load(Path(feat_dir) / f"{did}.npz", allow_pickle=False)
        self.did = did
        self.n_onb = int(z["n_onb"][0])
        self.X = pd.DataFrame(z["X"], columns=FEATURE_NAMES)
        self.X.insert(0, "event_id", z["event_id"])
        self.X.insert(1, "entity_id", z["entity_id"])
        self.X.insert(2, "entity_type", z["entity_type"])
        self.ts = pd.to_datetime(z["ts_ns"])
        self.n = len(self.X)

    @property
    def X_onb(self):
        return self.X.iloc[: self.n_onb].reset_index(drop=True)

    @property
    def X_eval(self):
        return self.X.iloc[self.n_onb:].reset_index(drop=True)


def _job(args):
    did, out_dir, data_dir = args
    return compute(did, out_dir, data_dir)


def compute_all(ids, out_dir, workers=4, data_dir=None, log=print) -> dict:
    from concurrent.futures import ProcessPoolExecutor
    res = {}
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(_job, [(d, str(out_dir), None if data_dir is None else str(data_dir)) for d in ids]):
            res[r["dataset"]] = r
            log(f"[features] {r['dataset']:13s} {r['rows']:>7,} rows ({r['n_onboarding']:,} onboarding)  {r['seconds']}s")
    return res

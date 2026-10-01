"""Dataset-scale serving evaluation: feature matrices produced through each serving boundary, and their comparison with training extraction.

Paths (canonical events -> platform payloads -> boundary -> production StreamingFeatureExtractor):
  corrected_full        EVERY event (onboarding included) through the corrected contract, entityType supplied     -> parity proof and post-fix scoring
  legacy_live           onboarding replayed canonically (as api.py warm-up does), evaluation events through the PRODUCTION boundary   -> pre-fix as served
  corrected_live_no_et  onboarding canonical, evaluation events through the corrected contract WITHOUT entityType (the platform as it is today)
Feature files are written in ML-4's npz layout so eval_ml4.features4.Loaded and the ML-4 scoring workers can read them unchanged.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path
from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd

from . import common as K
from . import parity_lib as PL
from . import platform_sim as PS
from .contract import ContractError, ServingContract
from eval_ml4 import features4 as F4
from src.features import FEATURE_NAMES, StreamingFeatureExtractor

PATHS = ("corrected_full", "legacy_live", "corrected_live_no_et")


def data_dir_of(did):
    return K.DATA_DIR if did in K.FRESH else K.ML4_DATA_DIR


def served_features_task(args):
    """(did, path, out_dir) -> summary. Writes <out_dir>/<did>.npz."""
    did, path, out_dir = args
    t = time.time()
    dd = data_dir_of(did)
    ev = F4.load_events4(did, dd)
    n_onb = int((ev["timestamp"] < F4.onboarding_end(did, ev, dd)).sum())
    tz = ZoneInfo(K.DEPLOYMENT_TZ)
    contract = ServingContract(K.DEPLOYMENT_TZ, "user")
    recs = ev.to_dict("records")
    ex = StreamingFeatureExtractor()
    rows, ets, errors = [], [], {}
    for i, r in enumerate(recs):
        if path != "corrected_full" and i < n_onb:
            e = r                                                        # warm-up history stays in the canonical representation (as api.py does)
        else:
            req = PS.to_platform_request(r, tz, "utc_z", include_entity_type=(path != "corrected_live_no_et"))
            try:
                e = PS.legacy_canonical(req) if path == "legacy_live" else contract.canonicalize(req["entityId"], req["eventType"], req["occurredAt"], req["payload"], req["eventId"]).event
            except ContractError as exc:
                errors[exc.code] = errors.get(exc.code, 0) + 1
                raise RuntimeError(f"corrected contract rejected a canonical event at row {i}: {exc}")
        f = ex.update_and_extract(e)
        rows.append([f[n] for n in FEATURE_NAMES])
        ets.append(e["entity_type"])
    X = np.array(rows, dtype=np.float64)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(out_dir / f"{did}.npz", event_id=ev["event_id"].to_numpy(), entity_id=ev["entity_id"].to_numpy(dtype=str), entity_type=np.array(ets, dtype=str),
                        ts_ns=ev["timestamp"].to_numpy().astype("datetime64[ns]").astype(np.int64), X=X, n_onb=np.array([n_onb]))
    return {"dataset": did, "path": path, "rows": int(len(ev)), "n_onboarding": n_onb, "features_sha256": hashlib.sha256(np.ascontiguousarray(X).tobytes()).hexdigest(),
            "seconds": round(time.time() - t, 1)}


def canonical_features_task(args):
    did, out_dir = args
    return F4.compute(did, out_dir, data_dir_of(did))


def compare_with_canonical(did, served_dir, canonical_dir) -> dict:
    """Feature-level parity of a served matrix against training extraction of the same dataset."""
    a = np.load(Path(canonical_dir) / f"{did}.npz")
    b = np.load(Path(served_dir) / f"{did}.npz")
    n_onb = int(a["n_onb"][0])
    c_all = PL.compare(a["X"], b["X"])
    c_live = PL.compare(a["X"][n_onb:], b["X"][n_onb:])
    et_changed = float((a["entity_type"] != b["entity_type"]).mean())
    return {"dataset": did, "rows": int(a["X"].shape[0]), "bit_identical_all_rows": c_all["bit_identical"], "within_tolerance_all_rows": c_all["within_tolerance"],
            "max_abs_diff": c_all["max_abs_diff"], "live_rows": int(a["X"].shape[0] - n_onb), "live_bit_identical": c_live["bit_identical"],
            "live_share_events_any_feature_differs": c_live["share_of_events_with_any_difference"], "live_features_differing": c_live["features_differing"],
            "live_mean_abs_diff_by_feature": {k: v["mean_abs_diff"] for k, v in c_live["per_feature"].items() if v["events_differing"] > 0},
            "share_events_with_different_entity_type": et_changed}

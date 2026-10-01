"""Shared helpers for the parity regression tests and the large-scale parity stage.

Training extraction  = StreamingFeatureExtractor over the canonical events (what build_feature_matrix does).
Serving extraction   = the SAME extractor class over the events produced by a serving boundary from the platform payloads.
For a faithful boundary the two feature streams are equal; the tolerance is documented in TOLERANCE.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.features import FEATURE_NAMES, StreamingFeatureExtractor         # noqa: E402  (production extractor, read-only)

from . import platform_sim as PS                                          # noqa: E402
from .contract import ContractError, ServingContract                      # noqa: E402

# Documented floating-point tolerance. Canonical durations have <= 6 decimals and the contract rounds seconds to 1 microsecond, so exact equality is
# expected for canonical events; the tolerance only absorbs an arbitrary platform value (a duration is a float, so 1e-9 relative is far below any
# feature resolution).
TOLERANCE = {"rtol": 1e-9, "atol": 1e-9, "expected": "bit-identical for canonical events; tolerance only for platform-supplied real-valued durations"}


def train_features(records: list) -> np.ndarray:
    ex = StreamingFeatureExtractor()
    rows = []
    for r in records:
        f = ex.update_and_extract(r)                     # exactly ONE state update per event
        rows.append([f[n] for n in FEATURE_NAMES])
    return np.array(rows, dtype=float)


def serve_features(requests: list, contract: ServingContract, legacy: bool = False):
    """Feature matrix produced through a boundary. Returns (matrix, canonical_events, errors)."""
    ex = StreamingFeatureExtractor()
    rows, evs, errs = [], [], []
    for i, rq in enumerate(requests):
        try:
            if legacy:
                ev = PS.legacy_canonical(rq)
            else:
                ev = contract.canonicalize(rq["entityId"], rq["eventType"], rq["occurredAt"], rq["payload"], rq["eventId"]).event
        except ContractError as exc:
            errs.append((i, exc.code))
            continue
        evs.append(ev)
        f = ex.update_and_extract(ev)
        rows.append([f[n] for n in FEATURE_NAMES])
    return np.array(rows, dtype=float), evs, errs


def compare(a: np.ndarray, b: np.ndarray, tol=TOLERANCE) -> dict:
    """Per-feature comparison of two aligned feature matrices."""
    if a.shape != b.shape:
        return {"comparable": False, "shape_a": list(a.shape), "shape_b": list(b.shape)}
    d = np.abs(a - b)
    scale = np.maximum(np.abs(a), np.abs(b))
    ok = d <= (tol["atol"] + tol["rtol"] * scale)
    per = {n: {"max_abs_diff": float(d[:, i].max()) if len(d) else 0.0, "events_differing": int((~ok[:, i]).sum()),
               "mean_abs_diff": float(d[:, i].mean()) if len(d) else 0.0} for i, n in enumerate(FEATURE_NAMES)}
    return {"comparable": True, "events": int(a.shape[0]), "features": int(a.shape[1]), "max_abs_diff": float(d.max()) if d.size else 0.0,
            "bit_identical": bool(np.array_equal(a, b)), "within_tolerance": bool(ok.all()),
            "features_differing": [n for n, v in per.items() if v["events_differing"] > 0], "events_with_any_difference": int((~ok).any(axis=1).sum()),
            "share_of_events_with_any_difference": float((~ok).any(axis=1).mean()) if len(ok) else 0.0, "per_feature": per}


def records_of(df: pd.DataFrame) -> list:
    return df.to_dict("records")

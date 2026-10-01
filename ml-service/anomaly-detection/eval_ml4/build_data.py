"""Build every ML-4 dataset (parallel) and the dataset manifest.

  python -m eval_ml4.build_data                       # canonical datasets -> eval_ml4/data/<id>/
  python -m eval_ml4.build_data --out <dir>           # regeneration check (run B): same content must give identical file hashes
The legacy dataset (orig42 = data/sample, produced by the production generator, seed 42) is described but never regenerated or modified.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pandas as pd

from . import common as K
from . import generator as G
from .common import C


def _gen(args):
    did, out = args
    t = time.time()
    m = G.generate_dataset(did, Path(out) / did)
    m["gen_seconds"] = round(time.time() - t, 1)
    return did, m


def legacy_meta() -> dict:
    d = C.SAMPLE_DIR
    ev = pd.read_csv(d / "events.csv", usecols=["event_id", "entity_id", "entity_type", "timestamp"])
    lab = pd.read_csv(d / "labels.csv")
    lab["attack_id"] = lab["attack_id"].fillna("")
    ts = pd.to_datetime(ev["timestamp"])
    vc = lab.label.value_counts().to_dict()
    inc = lab[lab.label.isin(C.ATTACK_TYPES)].groupby("label").attack_id.nunique().to_dict()
    return {"dataset_id": K.LEGACY_ID, "role": "DEV", "kind": "legacy", "profile": "production-generator", "seed": 42,
            "generator_version": "src/generate.py (production, unmodified)", "profile_version": "n/a", "drift_kind": None,
            "days": 30, "onboarding_days": K.LEGACY_ONBOARDING_DAYS, "events": int(len(ev)), "entities": int(ev.entity_id.nunique()),
            "entities_by_type": ev.groupby("entity_type").entity_id.nunique().to_dict(),
            "attack_events": int(sum(vc.get(t, 0) for t in C.ATTACK_TYPES)), "incidents": int(sum(inc.values())),
            "attack_types": [t for t in C.ATTACK_TYPES if vc.get(t, 0) > 0], "attack_events_by_type": {t: int(vc.get(t, 0)) for t in C.ATTACK_TYPES},
            "incidents_by_type": {t: int(inc.get(t, 0)) for t in C.ATTACK_TYPES}, "benign_drift_events": int(vc.get("benign_drift", 0)),
            "label_counts": {k: int(v) for k, v in vc.items()},
            "time_span": {"start": str(ts.min()), "end": str(ts.max()), "days": float((ts.max() - ts.min()).total_seconds() / 86400.0)},
            "chronological": bool(ts.is_monotonic_increasing), "generator_parameters": "production constants in config.py / src/generate.py (seed 42)",
            "file_sha256": {f: K.sha256_file(d / f) for f in ("events.csv", "labels.csv", "entity_profiles.json")},
            "note": "legacy dataset used by ML-1..ML-3; its ML-3 TEST labels were already read, so it is never a sealed test set"}


def build_all(out_root: Path, workers: int = 4, ids=None) -> dict:
    ids = ids or list(K.REGISTRY)
    out_root = Path(out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    metas = {}
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for did, m in ex.map(_gen, [(d, str(out_root)) for d in ids]):
            metas[did] = m
            print(f"[data] {did:13s} {m['events']:>6,} events  {m['entities']:>3} entities  {m['incidents']:>3} incidents  {m['gen_seconds']}s", flush=True)
    return metas


def manifest(metas: dict) -> dict:
    metas = dict(metas)
    metas[K.LEGACY_ID] = legacy_meta()
    schema_hash = K.sha256_file(K.ROOT / "src" / "features.py")
    from src.features import FEATURE_NAMES
    m = {"generator_version": K.GEN_VERSION, "feature_schema": {"event_schema": C.SCHEMA, "feature_names": list(FEATURE_NAMES), "feature_count": len(FEATURE_NAMES),
                                                              "features_py_sha256": schema_hash, "schema_version": "canonical-12-field / 35-feature (production, unchanged)"},
         "days": K.DAYS, "onboarding_days": K.ONBOARDING_DAYS, "roles": {d: v["role"] for d, v in metas.items()}, "datasets": metas}
    m["dataset_set_sha256"] = K.sha256_obj({d: v["file_sha256"] for d, v in metas.items()})
    return m


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(K.DATA_DIR))
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    t = time.time()
    metas = build_all(Path(a.out), a.workers)
    man = manifest(metas)
    K.write_json(Path(a.out) / "manifest.json", man)
    print(f"[data] {len(metas)} datasets in {time.time()-t:.0f}s | dataset-set sha256 {man['dataset_set_sha256']}")

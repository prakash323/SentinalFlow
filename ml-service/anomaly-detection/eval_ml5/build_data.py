"""Generate the fresh ML-5 TEST datasets with the UNCHANGED ML-4 generator (new seeds), and the manifest.

  python -m eval_ml5.build_data [--out <dir>]      (--out for the byte-identity regeneration check)
The ML-4 registry is extended in-process only (no file is modified) so generate_dataset() can be reused verbatim.
"""
from __future__ import annotations

import argparse
import json
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from . import common as K
from eval_ml4 import generator as G


def _register():
    for d, (prof, seed) in K.FRESH.items():
        K.K4.REGISTRY[d] = (prof, seed, "SEALED", "standard")


def _gen(args):
    did, out = args
    _register()
    t = time.time()
    m = G.generate_dataset(did, Path(out) / did)
    m["gen_seconds"] = round(time.time() - t, 1)
    return did, m


def build_all(out_root, workers=3) -> dict:
    out_root = Path(out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    metas = {}
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for did, m in ex.map(_gen, [(d, str(out_root)) for d in K.FRESH]):
            metas[did] = m
            print(f"[data] {did} {m['events']:,} events {m['entities']} entities {m['incidents']} incidents ({m['gen_seconds']}s)", flush=True)
    return metas


def manifest(metas: dict) -> dict:
    return {"generator_version": K.K4.GEN_VERSION, "role": "ML-5 TEST (fresh seeds)", "datasets": metas,
            "dataset_set_sha256": K.sha256_obj({d: v["file_sha256"] for d, v in metas.items()})}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(K.DATA_DIR))
    ap.add_argument("--workers", type=int, default=3)
    a = ap.parse_args()
    metas = build_all(a.out, a.workers)
    man = manifest(metas)
    K.write_json(Path(a.out) / "manifest.json", man)
    print("dataset-set sha256", man["dataset_set_sha256"])

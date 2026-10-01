"""Compare two ML-2 runs (evaluation-only): are the metrics and the raw score arrays reproducible?

    python -m eval_ml2.compare_runs A B

Metrics are compared leaf-by-leaf with EXACT equality (a float that differs in the last bit is reported, not hidden).
Wall-clock fields (latency, generation time) are excluded because they are not part of the evaluation. Raw arrays are
compared with max-abs-difference so that any CPU/library nondeterminism is quantified rather than assumed away.
"""
from __future__ import annotations

import json
import sys

import numpy as np

from . import common as K

IGNORE_PREFIXES = ("meta", "streaming_runtime", "integrity.label_vault_log")


def _walk(a, b, path, diffs, counter, tol=0.0):
    if any(path.startswith(p) for p in IGNORE_PREFIXES):
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                diffs.append({"path": f"{path}.{k}", "a": "missing" if k not in a else "present", "b": "missing" if k not in b else "present"})
                continue
            _walk(a[k], b[k], f"{path}.{k}" if path else str(k), diffs, counter, tol)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            diffs.append({"path": path, "a": f"len {len(a)}", "b": f"len {len(b)}"})
            return
        for i, (x, y) in enumerate(zip(a, b)):
            _walk(x, y, f"{path}[{i}]", diffs, counter, tol)
    else:
        counter[0] += 1
        if isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool):
            if a != b and abs(a - b) > tol:
                diffs.append({"path": path, "a": a, "b": b, "abs_diff": abs(a - b)})
        elif a != b:
            diffs.append({"path": path, "a": a, "b": b})


def compare(ra: str, rb: str) -> dict:
    da, db = K.REPORTS / "ml2_runs" / ra, K.REPORTS / "ml2_runs" / rb
    ma, mb = json.load(open(da / "metrics.json")), json.load(open(db / "metrics.json"))
    diffs, counter = [], [0]
    _walk(ma, mb, "", diffs, counter)
    # volatile-by-design fields that legitimately differ between runs
    diffs = [d for d in diffs if not d["path"].startswith("integrity.label_vault_log")]
    arrays = {}
    for fname in ("batch.npz", "stream_main.npz", "stream_heldout.npz"):
        pa, pb = da / fname, db / fname
        if not (pa.exists() and pb.exists()):
            continue
        A, B = np.load(pa, allow_pickle=False), np.load(pb, allow_pickle=False)
        rows = {}
        for k in A.files:
            if k == "latency_ms":                        # wall-clock, excluded
                continue
            x, y = A[k], B[k]
            if x.dtype.kind in "fiu" or x.dtype.kind == "b":
                d = np.abs(x.astype(float) - y.astype(float))
                rows[k] = {"shape": list(x.shape), "max_abs_diff": float(d.max()) if d.size else 0.0,
                           "n_elements_different": int((d > 0).sum()), "identical": bool(np.array_equal(x, y))}
            else:
                rows[k] = {"shape": list(x.shape), "identical": bool(np.array_equal(x, y))}
        arrays[fname] = rows
    all_identical = (not diffs) and all(r.get("identical", False) for f in arrays.values() for r in f.values())
    hb = {}
    for stage in ("batch", "stream_main", "stream_heldout", "parity", "assemble"):
        for fa, fb in ((da / f"hashes_before_{stage}.json", da / f"hashes_after_{stage}.json"),
                       (db / f"hashes_before_{stage}.json", db / f"hashes_after_{stage}.json")):
            if fa.exists() and fb.exists():
                hb[f"{fa.parent.name}/{stage}"] = json.load(open(fa)) == json.load(open(fb))
    out = {"run_a": ra, "run_b": rb, "metric_leaves_compared": counter[0], "metric_leaves_different": len(diffs),
           "first_differences": diffs[:40], "arrays": arrays, "everything_bit_identical": bool(all_identical),
           "production_hashes_unchanged_within_each_stage": hb}
    K.write_json(K.REPORTS / "ml2_runs" / f"compare_{ra}_{rb}.json", out)
    return out


if __name__ == "__main__":
    r = compare(sys.argv[1], sys.argv[2])
    print(json.dumps({k: v for k, v in r.items() if k not in ("arrays", "first_differences")}, indent=1))
    print("arrays:", {f: {k: (v.get("max_abs_diff"), v["identical"]) for k, v in rows.items()} for f, rows in r["arrays"].items()})
    print("first differences:", r["first_differences"][:10])

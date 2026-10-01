"""Exact-equality comparison of two complete ML-4 runs.  python -m eval_ml4.compare_runs A B"""
from __future__ import annotations

import json
import sys

import numpy as np

from . import common as K

VOLATILE_PREFIX = ("meta.seconds", "fit.fit_info.seconds", "verify.regeneration.seconds", "features.")   # 'features.' = per-dataset rows/hash: compared separately
VOLATILE_EXACT = {"meta.run_id", "features_note"}      # features_note = provenance of which datasets each run recomputed (different by design)


def _flat(o, path=""):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _flat(v, f"{path}.{k}" if path else str(k))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _flat(v, f"{path}[{i}]")
    else:
        yield path, o


def compare(a_id="A", b_id="B") -> dict:
    ra, rb = K.REPORTS / "ml4_runs" / a_id, K.REPORTS / "ml4_runs" / b_id
    A = json.load(open(ra / "metrics.json", encoding="utf-8"))
    B = json.load(open(rb / "metrics.json", encoding="utf-8"))
    fa, fb = dict(_flat(A)), dict(_flat(B))

    def skip(k):
        return k in VOLATILE_EXACT or k.startswith(VOLATILE_PREFIX) or k.startswith("hashes.source") or k.startswith("hashes.prediction_arrays") or k.startswith("hashes.ml4_artifact_file") \
            or k.startswith("fit.file_sha256") or k.startswith("environment")
    keys = sorted(set(fa) | set(fb))
    diffs = [k for k in keys if not skip(k) and fa.get(k) != fb.get(k)]
    only_a = [k for k in keys if not skip(k) and k in fa and k not in fb]
    only_b = [k for k in keys if not skip(k) and k in fb and k not in fa]
    shared_diffs = [k for k in diffs if k in fa and k in fb]
    prefixes = {}
    for d in diffs:
        p = ".".join(d.replace("[", ".").split(".")[:2])
        prefixes[p] = prefixes.get(p, 0) + 1
    max_num = 0.0
    for k in keys:
        if skip(k):
            continue
        x, y = fa.get(k), fb.get(k)
        if isinstance(x, (int, float)) and isinstance(y, (int, float)) and not isinstance(x, bool):
            max_num = max(max_num, abs(float(x) - float(y)))
    pa, pb = np.load(ra / "predictions.npz"), np.load(rb / "predictions.npz")
    shared_arrays = sorted(set(pa.files) & set(pb.files))
    arr = {k: bool(np.array_equal(pa[k], pb[k])) for k in shared_arrays}
    feats = {d: A["features"][d]["features_sha256"] == B["features"][d]["features_sha256"] for d in A["features"]}
    res = {"runs": [a_id, b_id], "metric_leaves_compared": len([k for k in keys if not skip(k)]), "metric_leaf_differences": len(diffs), "differing_paths": diffs[:40],
           "differing_prefixes": prefixes, "max_abs_numeric_difference": max_num, "prediction_arrays": len(arr), "prediction_arrays_identical": sum(arr.values()),
           "differences_on_shared_keys": len(shared_diffs), "shared_key_differing_paths": shared_diffs[:20], "keys_only_in_first_run": len(only_a), "keys_only_in_second_run": len(only_b),
           "prediction_arrays_only_in_first": sorted(set(pa.files) - set(pb.files))[:5], "prediction_arrays_only_in_second": sorted(set(pb.files) - set(pa.files))[:5],
           "all_predictions_identical": all(arr.values()) and set(pa.files) == set(pb.files), "feature_matrices_identical": all(feats.values()), "feature_matrices": len(feats),
           "dataset_set_identical": A["hashes"]["dataset_set"] == B["hashes"]["dataset_set"], "frozen_config_identical": A["hashes"]["frozen_config"] == B["hashes"]["frozen_config"],
           "ml4_content_hashes_identical": A["hashes"]["ml4_content"] == B["hashes"]["ml4_content"], "ml4_artifact_file_identical_bytes": A["hashes"]["ml4_artifact_file"] == B["hashes"]["ml4_artifact_file"],
           "config_identical": A["hashes"]["config"] == B["hashes"]["config"], "source_identical": A["hashes"]["source"] == B["hashes"]["source"],
           "environment_identical": {k: A["environment"].get(k) == B["environment"].get(k) for k in A["environment"]}}
    # parity report
    try:
        pa_, pb_ = json.load(open(ra / "parity_report.json", encoding="utf-8")), json.load(open(rb / "parity_report.json", encoding="utf-8"))
        qa, qb = dict(_flat(pa_)), dict(_flat(pb_))
        pd_ = [k for k in set(qa) | set(qb) if qa.get(k) != qb.get(k)]
        res["parity_report"] = {"leaves": len(set(qa) | set(qb)), "differences": len(pd_), "identical": len(pd_) == 0}
    except FileNotFoundError:
        res["parity_report"] = {"identical": None, "note": "missing"}
    res["exactly_reproducible"] = bool(res["metric_leaf_differences"] == 0 and res["all_predictions_identical"] and res["feature_matrices_identical"] and res["dataset_set_identical"]
                                       and res["frozen_config_identical"] and res["ml4_content_hashes_identical"] and (res["parity_report"]["identical"] in (True, None)))
    K.write_json(K.REPORTS / "ml4_runs" / f"compare_{a_id}_{b_id}.json", res)
    return res


if __name__ == "__main__":
    a = sys.argv[1] if len(sys.argv) > 1 else "A"
    b = sys.argv[2] if len(sys.argv) > 2 else "B"
    r = compare(a, b)
    print(json.dumps({k: r[k] for k in ("metric_leaves_compared", "metric_leaf_differences", "max_abs_numeric_difference", "prediction_arrays", "prediction_arrays_identical",
                                        "feature_matrices_identical", "dataset_set_identical", "frozen_config_identical", "ml4_content_hashes_identical",
                                        "ml4_artifact_file_identical_bytes", "parity_report", "exactly_reproducible")}, indent=2))

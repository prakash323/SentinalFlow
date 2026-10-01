"""Exact-equality comparison of two complete ML-5 runs.  python -m eval_ml5.compare_runs E F

Compares: every metric leaf, every stored prediction / tail array, the served feature-matrix hashes, the parity report, the frozen configuration and calibrator parameters
(hashes), the candidate files (hashes), and the dataset / configuration / source hashes. Wall-clock fields and the environment block are excluded as volatile.
"""
from __future__ import annotations

import json
import sys

import numpy as np

from . import common as K

VOLATILE_PREFIX = ("meta.seconds", "verify.fresh_regeneration_seconds", "candidate_manifest.created_by", "environment")
VOLATILE_EXACT = {"meta.run_id"}


def _flat(o, path=""):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _flat(v, f"{path}.{k}" if path else str(k))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _flat(v, f"{path}[{i}]")
    else:
        yield path, o


def compare(a_id="E", b_id="F") -> dict:
    ra, rb = K.REPORTS / "ml5_runs" / a_id, K.REPORTS / "ml5_runs" / b_id
    A = json.load(open(ra / "metrics.json", encoding="utf-8"))
    B = json.load(open(rb / "metrics.json", encoding="utf-8"))
    fa, fb = dict(_flat(A)), dict(_flat(B))

    def skip(k):
        return k in VOLATILE_EXACT or k.startswith(VOLATILE_PREFIX)
    keys = sorted(set(fa) | set(fb))
    diffs = [k for k in keys if not skip(k) and fa.get(k) != fb.get(k)]
    max_num = 0.0
    for k in keys:
        x, y = fa.get(k), fb.get(k)
        if not skip(k) and isinstance(x, (int, float)) and isinstance(y, (int, float)) and not isinstance(x, bool):
            max_num = max(max_num, abs(float(x) - float(y)))
    pa, pb = np.load(ra / "predictions.npz"), np.load(rb / "predictions.npz")
    shared = sorted(set(pa.files) & set(pb.files))
    arr = {k: bool(np.array_equal(pa[k], pb[k])) for k in shared}
    res = {"runs": [a_id, b_id], "metric_leaves_compared": len([k for k in keys if not skip(k)]), "metric_leaf_differences": len(diffs), "differing_paths": diffs[:40],
           "max_abs_numeric_difference": max_num, "prediction_arrays": len(arr), "prediction_arrays_identical": sum(arr.values()),
           "arrays_only_in_first": sorted(set(pa.files) - set(pb.files))[:5], "arrays_only_in_second": sorted(set(pb.files) - set(pa.files))[:5],
           "all_predictions_identical": all(arr.values()) and set(pa.files) == set(pb.files),
           "served_feature_hashes_identical": A["hashes"]["fresh_feature_hashes"] == B["hashes"]["fresh_feature_hashes"],
           "frozen_config_identical": A["hashes"]["frozen_config5"] == B["hashes"]["frozen_config5"], "calibrator_params_identical": A["hashes"]["calibrator_params"] == B["hashes"]["calibrator_params"],
           "candidate_files_identical": A["hashes"]["candidate_files"] == B["hashes"]["candidate_files"], "config_identical": A["hashes"]["config"] == B["hashes"]["config"],
           "source_identical": A["hashes"]["source"] == B["hashes"]["source"], "dataset_set_identical": A["hashes"]["fresh_dataset_set"] == B["hashes"]["fresh_dataset_set"],
           "metric_section_hashes_identical": A["hashes"]["metric_sections"] == B["hashes"]["metric_sections"],
           "thresholds_identical": A["threshold_study_test"]["universal_dev_thresholds"] == B["threshold_study_test"]["universal_dev_thresholds"]
           and A["threshold_study_dev"]["alpha_selection"] == B["threshold_study_dev"]["alpha_selection"],
           "environment_identical": {k: A["environment"].get(k) == B["environment"].get(k) for k in A["environment"]}}
    try:
        qa, qb = dict(_flat(json.load(open(ra / "parity_report.json", encoding="utf-8")))), dict(_flat(json.load(open(rb / "parity_report.json", encoding="utf-8"))))
        pd_ = [k for k in set(qa) | set(qb) if qa.get(k) != qb.get(k)]
        res["parity_report"] = {"leaves": len(set(qa) | set(qb)), "differences": len(pd_), "identical": len(pd_) == 0}
    except FileNotFoundError:
        res["parity_report"] = {"identical": None, "note": "missing"}
    res["exactly_reproducible"] = bool(res["metric_leaf_differences"] == 0 and res["all_predictions_identical"] and res["served_feature_hashes_identical"] and res["frozen_config_identical"]
                                       and res["calibrator_params_identical"] and res["candidate_files_identical"] and res["config_identical"] and res["source_identical"]
                                       and res["dataset_set_identical"] and res["parity_report"]["identical"] is True)
    K.write_json(K.REPORTS / "ml5_runs" / f"compare_{a_id}_{b_id}.json", res)
    return res


if __name__ == "__main__":
    a = sys.argv[1] if len(sys.argv) > 1 else "E"
    b = sys.argv[2] if len(sys.argv) > 2 else "F"
    r = compare(a, b)
    print(json.dumps({k: r[k] for k in ("metric_leaves_compared", "metric_leaf_differences", "max_abs_numeric_difference", "prediction_arrays", "prediction_arrays_identical",
                                        "served_feature_hashes_identical", "frozen_config_identical", "calibrator_params_identical", "candidate_files_identical", "source_identical",
                                        "parity_report", "exactly_reproducible")}, indent=2))

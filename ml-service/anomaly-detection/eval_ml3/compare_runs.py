"""Exact-equality reproducibility comparison of two complete ML-3 runs.  python -m eval_ml3.compare_runs A B"""
from __future__ import annotations

import json
import sys

import numpy as np

from . import common as K

VOLATILE = ("meta.elapsed_seconds", "meta.finished", "meta.run_id", "training.fit_info.fit_seconds")


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
    ra, rb = K.REPORTS / "ml3_runs" / a_id, K.REPORTS / "ml3_runs" / b_id
    A = json.load(open(ra / "metrics.json", encoding="utf-8"))
    B = json.load(open(rb / "metrics.json", encoding="utf-8"))
    fa, fb = dict(_flat(A)), dict(_flat(B))
    skip = lambda k: k in VOLATILE or k.startswith("hashes.candidate_artifact_files") or k.startswith("training.components_file_sha256")  # noqa: E731
    keys = sorted(set(fa) | set(fb))
    diffs = [k for k in keys if not skip(k) and fa.get(k) != fb.get(k)]
    max_num = 0.0
    for k in keys:
        if skip(k):
            continue
        x, y = fa.get(k), fb.get(k)
        if isinstance(x, (int, float)) and isinstance(y, (int, float)) and not isinstance(x, bool):
            max_num = max(max_num, abs(float(x) - float(y)))
    pa, pb = np.load(ra / "predictions.npz", allow_pickle=True), np.load(rb / "predictions.npz", allow_pickle=True)
    arr = {}
    for k in pa.files:
        x, y = pa[k], pb[k]
        exact = bool(np.array_equal(x, y))
        arr[k] = {"identical": exact, "max_abs_diff": (float(np.max(np.abs(x.astype(float) - y.astype(float)))) if (x.dtype.kind in "fiub" and len(x)) else None)}
    ca, cb = A["hashes"]["candidate_content"], B["hashes"]["candidate_content"]
    content = {k: ca[k] == cb[k] for k in ca}
    files_a, files_b = A["hashes"]["candidate_artifact_files"], B["hashes"]["candidate_artifact_files"]
    files = {k: {"identical_bytes": files_a.get(k) == files_b.get(k), "sha256_A": files_a.get(k), "sha256_B": files_b.get(k)} for k in sorted(set(files_a) | set(files_b))}
    res = {"runs": [a_id, b_id], "metric_leaves_compared": len([k for k in keys if not skip(k)]), "metric_leaf_differences": len(diffs),
           "differing_paths": diffs[:50], "max_abs_numeric_difference": max_num,
           "differing_prefixes": {pre: sum(1 for d_ in diffs if d_.startswith(pre)) for pre in sorted({".".join(d_.replace("[", ".").split(".")[:2]) for d_ in diffs})},
           "predictions": arr, "predictions_all_identical": all(v["identical"] for v in arr.values()),
           "predictions_sha256_identical": A["predictions_sha256"] == B["predictions_sha256"],
           "candidate_content_hashes_identical": content, "candidate_content_all_identical": all(content.values()),
           "candidate_classifier_content_identical": A["hashes"]["candidate_classifier_content"] == B["hashes"]["candidate_classifier_content"],
           "candidate_artifact_files": files,
           "split_manifest_identical": A["hashes"]["split_manifest"] == B["hashes"]["split_manifest"],
           "frozen_config_identical": A["hashes"]["frozen_config"] == B["hashes"]["frozen_config"],
           "source_hashes_identical": A["hashes"]["source"] == B["hashes"]["source"],
           "environment_identical": {k: A["environment"].get(k) == B["environment"].get(k) for k in A["environment"] if k != "seeds"},
           "elapsed_seconds": {a_id: A["meta"]["elapsed_seconds"], b_id: B["meta"]["elapsed_seconds"]}}
    res["exactly_reproducible"] = (res["metric_leaf_differences"] == 0 and res["predictions_all_identical"] and res["candidate_content_all_identical"]
                                   and res["candidate_classifier_content_identical"] and res["split_manifest_identical"] and res["frozen_config_identical"])
    K.write_json(K.REPORTS / "ml3_runs" / f"compare_{a_id}_{b_id}.json", res)
    return res


if __name__ == "__main__":
    a = sys.argv[1] if len(sys.argv) > 1 else "A"
    b = sys.argv[2] if len(sys.argv) > 2 else "B"
    r = compare(a, b)
    print(json.dumps({k: r[k] for k in ("metric_leaves_compared", "metric_leaf_differences", "max_abs_numeric_difference", "predictions_all_identical",
                                        "candidate_content_all_identical", "candidate_classifier_content_identical", "split_manifest_identical",
                                        "frozen_config_identical", "exactly_reproducible")}, indent=2))
    print({k: v["identical_bytes"] for k, v in r["candidate_artifact_files"].items()})

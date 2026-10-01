"""Writes reports/ml4_dataset_manifest.json (requirement 3) and the dataset/split hashes. Label-free except generator metadata counts."""
from __future__ import annotations

import json

from . import audits as AU
from . import common as K
from . import features4 as F4
from .profiles import PROFILES, get_profile


def build(run_id: str = "A") -> dict:
    man = json.load(open(K.DATA_DIR / "manifest.json", encoding="utf-8"))
    datasets = man["datasets"]
    out = {"phase": "ML-4", "generator_version": K.GEN_VERSION, "feature_schema": man["feature_schema"], "days": K.DAYS, "onboarding_days": K.ONBOARDING_DAYS,
           "dataset_set_sha256": man["dataset_set_sha256"], "study_design": {
               "roles": {"TRAIN": K.TRAIN_IDS, "VAL": K.VAL_IDS, "DEV": K.DEV_IDS, "SEALED_standard": K.SEALED_STD_IDS, "SEALED_drift": K.SEALED_DRIFT_IDS},
               "split_unit": "whole dataset (a dataset has exactly one role); attack incidents are namespaced <dataset>:<attack_id> and therefore can never cross a "
                             "train / validation / test boundary. Inside every dataset the first 14 days (20 for the legacy dataset) are attack-free onboarding.",
               "profile_families": {"TRAIN": sorted({K.REGISTRY[d][0] for d in K.TRAIN_IDS}), "VAL": sorted({K.REGISTRY[d][0] for d in K.VAL_IDS}),
                                    "SEALED_unseen_profile": sorted({K.REGISTRY[d][0] for d in K.SEALED_STD_IDS} - {K.REGISTRY[d][0] for d in K.TRAIN_IDS + K.VAL_IDS})},
               "sealed_test_kinds": {"cross_seed_of_a_TRAIN_profile": ["P0-104", "P1-202"], "cross_seed_of_a_VAL_profile": ["P2-302", "P3-402"],
                                     "unseen_profile": ["P4-501", "P4-502"]},
               "note": "sealed datasets' labels and incident registries are unreadable (eval_ml4.xfer.Vault) until the frozen config is hashed"},
           "profiles": {p: get_profile(p) for p in PROFILES}, "drift_study_base_profile": get_profile("P0", drift_study=True), "datasets": datasets}
    integ = {}
    for d, m in datasets.items():
        integ[d] = {"role": m["role"], "chronological": m["chronological"], "strictly_increasing_timestamps": m.get("strictly_increasing"),
                    **(m.get("integrity") or {"attack_events_in_onboarding": "legacy: attacks only in days 21-30 (verified in ML-1)"})}
    out["integrity_checks"] = integ
    out["class_coverage"] = AU.class_coverage(datasets)
    out["hashes"] = {"dataset_set_sha256": man["dataset_set_sha256"],
                     "split_plan_sha256": K.sha256_obj({d: {"role": m["role"], "profile": m["profile"], "seed": m["seed"],
                                                            "events_sha256": m["file_sha256"]["events.csv"], "labels_sha256": m["file_sha256"]["labels.csv"],
                                                            "incidents_sha256": m["file_sha256"].get("incidents.json")} for d, m in datasets.items()}),
                     "config_sha256": K.sha256_obj(K.ML4_CONFIG), "profiles_sha256": K.sha256_obj({p: get_profile(p) for p in PROFILES}),
                     "generator_source_sha256": {f: K.sha256_file(K.ROOT / "eval_ml4" / f) for f in ("generator.py", "profiles.py", "build_data.py")}}
    out["profile_contrast_label_free_onboarding"] = {d: AU.onboarding_contrast(d) for d in datasets}
    K.write_json(K.REPORTS / "ml4_dataset_manifest.json", out)
    return out


if __name__ == "__main__":
    o = build()
    print("manifest written:", len(o["datasets"]), "datasets |", o["hashes"])
    print({t: (v["train_incidents"], v["val_incidents"], v["sealed_test_incidents"], v["enough_independent_incidents_for_learning"]) for t, v in o["class_coverage"].items()})

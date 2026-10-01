"""Builds the machine-readable ML-5 outputs from the canonical run (E) and its twin (F).
   python -m eval_ml5.compose_json E F
Writes: reports/ml5_parity_report.json, ml5_metrics.json, ml5_thresholds.json, ml5_split_manifest.json (deterministic functions of the run outputs; nothing feeds back).
"""
from __future__ import annotations

import json
import sys

from . import common as K

# How each of the ML-4 parity mismatches (reports/ml4_parity_report.json) is resolved by the ML-5 contract, and where that is proven.
MISMATCH_RESOLUTION = [
    {"ml4_id": "P1 / V1", "mismatch": "entity_type forced to 'user' for every live event", "ml5_treatment": "ASSUMPTION (recorded): read from payload entityType; if absent, the deployment's configured default_entity_type, "
     "listed in dataQuality.assumptions; invalid value -> 422 INVALID_ENTITY_TYPE. The platform sends no entityType today: adding it to the collector contract is the real fix.",
     "tests": ["test_entity_type_not_sent_is_explicit_and_visible", "test_service_accounts", "test_edge_devices"], "residual": "with the platform as it is today (no entityType) peer-prior semantics still differ for non-user entities: measured in phase3_pre_vs_post_fix (corrected_live_no_et)"},
    {"ml4_id": "P2 / V2", "mismatch": "session duration minutes delivered into a seconds field", "ml5_treatment": "sessionDurationMinutes x 60 rounded to 1 microsecond; sessionDurationSeconds accepted as-is; both present and inconsistent -> 422 AMBIGUOUS_SESSION_DURATION; "
     "missing -> entity running mean (0 if none), recorded as degraded", "tests": ["test_units_and_tokenisation"], "residual": "none"},
    {"ml4_id": "P3 / V3", "mismatch": "commands space-separated instead of '|' tokens", "ml5_treatment": "tokenised on | whitespace , ; lower-cased, joined with '|'; a non-string/list -> 422 INVALID_COMMAND_SEQUENCE",
     "tests": ["test_units_and_tokenisation", "test_command_heavy_events"], "residual": "none"},
    {"ml4_id": "P4a / V4a", "mismatch": "live timestamps in UTC while warm-up/training is deployment wall clock (hour-of-day shifted 5.5 h)",
     "ml5_treatment": "offset-aware occurredAt converted to the deployment wall clock (ML_DEPLOYMENT_TZ REQUIRED - no silent default); naive values taken as wall clock; conversion is invertible",
     "tests": ["test_time_fields_every_timestamp_style_and_timezone"], "residual": "the deployment timezone must be configured correctly; DST-ambiguous local times are resolved deterministically"},
    {"ml4_id": "P5a / V5a", "mismatch": "missing geo_location silently accepted", "ml5_treatment": "REQUIRED: 'City|lat|lon' strictly validated; ''/'Unknown' = missing -> 422 MISSING_LOCATION; never carried forward",
     "tests": ["test_required_fields_and_validation_errors"], "residual": "collectors without geolocation cannot be scored until an explicit unknown-location policy is decided by the deployment"},
    {"ml4_id": "P5b / V5b", "mismatch": "missing device fingerprint silently accepted / carried forward", "ml5_treatment": "documented UNKNOWN marker 'unspecified' (never carried forward); recorded as degraded; scores fail-safe "
     "(fingerprint_mismatch = 1 for an unknown fingerprint of a known entity)", "tests": ["test_missing_optional_fields_are_marked_never_defaulted_benignly", "test_missing_fingerprint_is_not_carried_forward_and_is_fail_safe"], "residual": "an attacker who omits the fingerprint is treated as a mismatch, not as the entity's usual device"},
    {"ml4_id": "P5c / V5c", "mismatch": "missing authentication result defaulted to success=1, method='password' (recall 0.68 -> 0.16 silently)",
     "ml5_treatment": "auth result REQUIRED for bare LOGIN / unknown event types (422 MISSING_AUTH_RESULT); LOGIN_FAILED->0, LOGIN_SUCCESS->1 by type; post-authentication types (FILE_ACCESS, LOGOUT, ...) -> 1 as a RECORDED assumption; "
     "auth_method missing -> 'unspecified' marker", "tests": ["test_missing_auth_result"], "residual": "none for the silent-default failure; a collector that never sends loginSuccess for LOGIN events is now rejected loudly"},
    {"ml4_id": "P6 / V6", "mismatch": "live entity ids unknown to profiler / warm-up (cold start) and training-sample replay as warm-up", "ml5_treatment": "no replay of the TRAINING sample as warm-up; optional per-deployment onboarding "
     "(ML_ONBOARDING_EVENTS) warms extractor and fits the baseline; unseen entities fall back to the peer prior of their entity_type", "tests": ["test_full_scorer_risk_scores_are_identical_through_the_corrected_boundary"], "residual": "cold-start quality is a data-volume question (see the onboarding-volume study)"},
    {"ml4_id": "P7 / V7", "mismatch": "duplicate delivery updates state twice", "ml5_treatment": "eventId idempotency cache in ServingPipeline: a repeat returns the cached result and does not update state",
     "tests": ["test_duplicate_delivery_does_not_update_state_twice"], "residual": "cache is bounded (200k ids); a duplicate older than the window is scored again"},
    {"ml4_id": "P8 / V8", "mismatch": "out-of-order delivery", "ml5_treatment": "not rejected; scored and flagged in dataQuality.warnings (ML-4: rank correlation >= 0.996, the benign item)", "tests": ["test_out_of_order_is_flagged"], "residual": "state still follows arrival order"},
]


def load(run):
    return json.load(open(K.REPORTS / "ml5_runs" / run / "metrics.json", encoding="utf-8"))


def main(e_id="E", f_id="F"):
    E, F = load(e_id), load(f_id)
    cmp_ = json.load(open(K.REPORTS / "ml5_runs" / f"compare_{e_id}_{f_id}.json", encoding="utf-8"))
    par_e = json.load(open(K.REPORTS / "ml5_runs" / e_id / "parity_report.json", encoding="utf-8"))
    par_f = json.load(open(K.REPORTS / "ml5_runs" / f_id / "parity_report.json", encoding="utf-8"))
    sp = E["serving_parity_at_scale"]["paths"]
    cf = sp["corrected_full"]
    compared = {d: v for d, v in cf.items() if "bit_identical_all_rows" in v}
    parity = {
        "phase": "ML-5", "contract_version": par_e["contract_version"],
        "purpose": "Serving-parity correction at the ML feature/API boundary: identical canonical events must give identical features through training extraction and through the (corrected) serving boundary.",
        "tolerance": E["parity_unit_tests"]["tolerance"],
        "verdict": {"training_and_serving_feature_semantics_identical": bool(all(v["bit_identical_all_rows"] for v in compared.values())),
                    "datasets_compared_bit_identical": f"{sum(v['bit_identical_all_rows'] for v in compared.values())}/{len(compared)}",
                    "max_abs_feature_difference_any_dataset": max(v["max_abs_diff"] for v in compared.values()),
                    "scoring_level_parity_ml4_and_shipped": E["phase3_pre_vs_post_fix"]["corrected_full_reproduces_ML4_canonical_metrics_exactly"],
                    "unit_tests": {"run": E["parity_unit_tests"]["tests_run"], "passed": E["parity_unit_tests"]["passed"], "test_names": E["parity_unit_tests"]["test_names"]},
                    "audit_run_twice": {"runs": [e_id, f_id], "parity_reports_identical": cmp_["parity_report"]["identical"], "unit_tests_passed_in_both": E["parity_unit_tests"]["passed"] and F["parity_unit_tests"]["passed"],
                                        "served_feature_hashes_identical": cmp_["served_feature_hashes_identical"]}},
        "ml4_mismatch_resolution": MISMATCH_RESOLUTION,
        "field_policy": E["parity_unit_tests"]["field_policy"],
        "at_scale": {"corrected_full": sp["corrected_full"], "production_boundary_pre_fix_legacy_live": sp["legacy_live"], "platform_as_today_no_entityType": sp["corrected_live_no_et"]},
        "feature_hashes": E["serving_parity_at_scale"]["feature_hashes"], "canonical_fresh_hashes": E["serving_parity_at_scale"]["canonical_fresh_hashes"],
        "not_covered": ["real platform traffic (no production event capture was available or touched)", "collector-side changes (entityType, unit conventions) that require platform changes",
                        "the deployment timezone being configured correctly in a real deployment"],
    }
    K.write_json(K.REPORTS / "ml5_parity_report.json", parity)

    K.write_json(K.REPORTS / "ml5_metrics.json", {**E, "reproducibility": {k: cmp_[k] for k in cmp_ if k not in ("environment_identical",)}, "twin_run": f_id})

    ts_dev, ts_test = E["threshold_study_dev"], E["threshold_study_test"]
    thr = {"phase": "ML-5", "status": "EVALUATION RESULT - no production threshold was selected or changed. models/pipeline.joblib and its threshold (99.5023 on risk) are untouched.",
           "rule": E["freeze"]["config"]["threshold_rule"], "shipped_vehicle_rule": E["freeze"]["config"]["shipped_detector_vehicle_threshold_rule"],
           "dev": {"alpha_selection": ts_dev["alpha_selection"], "dispersion_by_alpha": ts_dev["study"]["dispersion"], "oracle_threshold_dispersion": ts_dev["study"]["oracle_threshold_dispersion"],
                   "ml4_global_threshold_dispersion": ts_dev["study"].get("ml4_global_threshold_dispersion"), "per_deployment": ts_dev["study"]["deployments"],
                   "onboarding_volume_selected_alpha": ts_dev["onboarding_volume"], "onboarding_volume_reference_alpha": ts_dev["onboarding_volume_reference_alpha"]},
           "test": {"alpha_star": ts_test["alpha_star"], "dispersion_by_alpha": ts_test["study"]["dispersion"], "oracle_threshold_dispersion": ts_test["study"]["oracle_threshold_dispersion"],
                    "ml4_global_threshold_dispersion": ts_test["study"].get("ml4_global_threshold_dispersion"), "per_deployment": ts_test["study"]["deployments"],
                    "universal_thresholds_from_DEV_tails": ts_test["universal_dev_thresholds"], "onboarding_volume_selected_alpha": ts_test["onboarding_volume"],
                    "onboarding_volume_reference_alpha": ts_test["onboarding_volume_reference_alpha"]},
           "shipped_detector_vehicle": {"dev": E["threshold_study_dev_shipped"], "test": E["threshold_study_test_shipped"]},
           "claim_policy": "No universal threshold is claimed. Threshold values, realised alert rates and F1 are reported per deployment; the deployment-specific rule is compared with pooled/universal and ML-4-global thresholds."}
    K.write_json(K.REPORTS / "ml5_thresholds.json", thr)

    m4 = json.load(open(K.REPORTS / "ml4_dataset_manifest.json", encoding="utf-8"))["datasets"]
    fm = json.load(open(K.DATA_DIR / "manifest.json", encoding="utf-8"))
    ds = {}
    for d in K.DEV_IDS + [x for x in K.K4.REGISTRY if x not in K.DEV_IDS]:
        if d == K.K4.LEGACY_ID:
            ds[d] = {"ml4_role": "DEV (legacy production-generator sample)", "ml5_role": "DEV pool (thresholds/calibration/analysis)", "seed": None, "profile": "P0-like"}
            continue
        r = K.K4.REGISTRY[d]
        if d in K.DEV_EXCLUDED_TRAIN_IDS:
            ml5 = "parity re-evaluation only; EXCLUDED from the threshold/calibration DEV pool (its onboarding fitted the ML-4 model: tails would be in-sample)"
        elif r[3] == "drift":
            ml5 = "drift carry-forward (DR-ctrl, DR-location, DR-resources); not in the threshold/calibration pool" if d in K.DRIFT_REEVAL_IDS else "not used in ML-5"
        else:
            ml5 = "DEV pool (labels were opened in ML-4, so development data in ML-5; leave-one-profile-out used for transfer)"
        ds[d] = {"ml4_role": r[2], "kind": r[3], "profile": r[0], "seed": r[1], "ml5_role": ml5, "events": m4.get(d, {}).get("events"), "file_sha256": m4.get(d, {}).get("file_sha256")}
    for d, meta in fm["datasets"].items():
        ds[d] = {"ml4_role": "n/a (generated in ML-5)", "ml5_role": "TEST - sealed until the configuration was frozen and hashed; unsealed exactly once, after freeze", "profile": meta["profile"], "seed": meta["seed"],
                 "events": meta["events"], "file_sha256": meta["file_sha256"]}
    split = {"phase": "ML-5", "protocol": "TRAIN -> VALIDATION -> FREEZE -> TEST", "ml4_model": "models/candidates/ml4/ml4_global.joblib (fitted in ML-4 on TRAIN onboarding periods; not refitted or changed in ML-5)",
             "datasets": ds, "fresh_dataset_set_sha256": fm["dataset_set_sha256"],
             "test_generation": "5 datasets, one per profile (P0..P4), seeds 711-715, generated after the design was fixed with the ML-4 generator (unchanged); labels read once after freeze",
             "test_metadata_note": "the fresh manifest contains generator-side aggregate counts (attack events / incidents); they were not used for any decision",
             "freeze": {"frozen_config5_sha256": E["freeze"]["frozen_config5_sha256"], "calibrator_params_sha256": E["freeze"]["calibrator_params_sha256"],
                        "test_datasets_unsealed_before_freeze": E["freeze"]["test_datasets_unsealed_before_freeze"], "frozen_config": E["freeze"]["config"]},
             "unseal_log": [x for x in E["integrity"]["vault_log"] if x["access"] == "unseal"], "label_access_log": E["integrity"]["vault_log"],
             "leakage_statement": "no TEST label influenced feature selection, weights, alpha, threshold rule, calibration method or parameters, or any baseline choice",
             "methodology_changes": ["TRAIN-role datasets excluded from the DEV threshold/calibration pool (decided before any ML-5 result; their tails are in-sample for the ML-4 model)"]}
    K.write_json(K.REPORTS / "ml5_split_manifest.json", split)
    print("wrote ml5_parity_report.json, ml5_metrics.json, ml5_thresholds.json, ml5_split_manifest.json")


if __name__ == "__main__":
    main(*(sys.argv[1:3] if len(sys.argv) > 2 else ["E", "F"]))

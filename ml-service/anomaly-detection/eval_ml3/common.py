"""ML-3 shared constants and helpers.

PRE-REGISTERED DECISIONS (fixed before any candidate score was inspected)
  split                 the exact ML-2 chronological protocol (asserted identical to reports/ml2_split_manifest.json)
  feature policy        see FEATURE_POLICY below
  fusion                0.1-step simplex grid on the three TRAIN-percentile signals; criterion = MACRO per-attack-type PR-AUC
                        of the fused score on VALIDATION (each attack type present in validation vs all validation negatives,
                        averaged over types, so one high-volume type such as brute force cannot decide the weights); if the
                        best is within FUSION_PARSIMONY_MARGIN of equal weights, choose equal weights. Fusion is selected with
                        a FROZEN baseline (weights do not change a frozen baseline), then the mode is selected.
  baseline mode         'frozen' unless 'ewma_guarded' beats it on the same criterion by more than MODE_MARGIN
                        (guard = an event whose fused score exceeds the whole TRAIN range never updates the baseline; this is
                        exactly what the shipped guard does, because its threshold 99.5 is only reachable by saturated events)
  operating point       F1-optimal fused threshold on VALIDATION (label-free alternatives are reported next to it)
  classifier            a class is trained only if it has >= CLASS_TRAINABLE_MIN_INCIDENTS incidents in TRAIN+VALIDATION; its
                        evaluation is called statistically meaningful only with >= CLASS_EVALUABLE_MIN_INCIDENTS incidents;
                        alerts whose top class probability < ABSTAIN_CONF are reported as UNKNOWN
"""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True

from eval_ml2 import common as K2                                   # noqa: E402  (read-only reuse)
from eval_ml2.common import (ATTACKS, C, DATA, EVAL_SEED, LabelVault, ROOT, TOPK_FRAC, env_info, load_artifact, md5_file,    # noqa: E402,F401
                             production_hashes, sha256_file, sha256_obj, to_jsonable, write_json)

REPORTS = ROOT / "reports"
CANDIDATE_DIR = ROOT / "models" / "candidates" / "ml3"
MODEL_SEED = C.RANDOM_SEED                # every learned component keeps the production seed convention (42)
ML3_SEED = 20260921                       # seed for evaluation-side resampling (bootstrap, permutation)

FUSION_GRID_STEP = 0.1
FUSION_PARSIMONY_MARGIN = 0.01
MODE_MARGIN = 0.01
CLASS_TRAINABLE_MIN_INCIDENTS = 2
CLASS_EVALUABLE_MIN_INCIDENTS = 5
ABSTAIN_CONF = C.CLASS_CONF_HIGH          # 0.65, an existing config constant; NOT tuned here
CLASSIFIER_MAX_PER_INCIDENT = K2.CLASSIFIER_MAX_PER_INCIDENT
SHIPPED_FUSION_WEIGHTS = dict(C.FUSION_WEIGHTS)     # inherited (tuned on days 21-30): reported, never assumed valid
SIGNALS = ("baseline", "iforest", "sequence")
GUARD_RISK = 100.0                         # EWMA poisoning guard: an event above the whole TRAIN score range never updates the baseline

# --------------------------------------------------------------------------------------------------------------
# Feature policy: which of the 35 production features feed the candidate's Isolation Forest, sequence autoencoder and
# classifier. The production extractor is NOT changed; the matrix always keeps all 35 columns.
# --------------------------------------------------------------------------------------------------------------
POLICY_EXCLUDED_BY_DEFINITION = {
    "entity_event_count": ("cumulative per-entity event counter = position in the stream: monotone in time by construction, so every "
                           "later window looks out-of-range relative to TRAIN (ML-1: PSI 2.44; ML-2/ML-1: 24% of test rows exceed the "
                           "TRAIN maximum). It encodes 'how long the stream has run', not behaviour.")}

KNOWN_FEATURE_PROBLEMS = [
    {"id": "P1", "features": ["is_new_city"], "problem": "dead feature: constant 0 (`city not in {city}` is always False)",
     "evidence": "ML-1 audit; re-verified on TRAIN in this run", "candidate_handling": "EXCLUDED from IF/AE/classifier (constant on TRAIN); still listed in the production baseline BOOLEAN set (contributes exactly 0)"},
    {"id": "P2", "features": ["new_resources_24h"], "problem": "dead feature: constant 0 (recent resources are always a subset of the seen set)",
     "evidence": "ML-1 audit; re-verified on TRAIN in this run", "candidate_handling": "EXCLUDED from IF/AE/classifier (constant on TRAIN); still in the production baseline CONTINUOUS set (z = 0)"},
    {"id": "P3", "features": ["resource_breadth_7d", "sensitive_ratio_7d"], "problem": "named '7d' but computed over the 24h deque",
     "evidence": "ML-1: equals the trailing-24h distinct-resource count in 400/400 sampled rows", "candidate_handling": "KEPT with the production definition (definition changes are out of scope); documented, not renamed"},
    {"id": "P4", "features": ["session_duration_zscore", "sensitive_bytes_proxy_7d"], "problem": "API boundary reads sessionDurationMinutes into a SECONDS field",
     "evidence": "ML-1/ML-2 parity: mean |Δrisk| 14.1 on 19 events", "candidate_handling": "not a training-data problem (CSV is in seconds); UNRESOLVED serving-parity blocker, recorded in the recommendation"},
    {"id": "P5", "features": ["cmd_len", "cmd_priv_count", "cmd_bigram_surprise"], "problem": "extractor splits commands on '|' but the platform sends space-separated commands",
     "evidence": "ML-1/ML-2 parity: command features change on 9/19 events", "candidate_handling": "not a training-data problem; UNRESOLVED serving-parity blocker"},
    {"id": "P6", "features": ["entity_event_count"], "problem": "non-stationary stream-position counter", "evidence": "ML-1 PSI 2.44; 24% of test rows beyond TRAIN max",
     "candidate_handling": "EXCLUDED from IF/AE/classifier by policy (see POLICY_EXCLUDED_BY_DEFINITION)"},
    {"id": "P7", "features": ["is_sensitive_resource", "sensitive_offhours_7d", "sensitive_ratio_7d", "sensitive_bytes_proxy_7d", "hour_sin", "hour_cos", "is_weekend",
                              "is_off_hours_for_entity", "offhours_count_7d", "cmd_priv_count", "distance_from_home_km", "geo_velocity_kmh", "is_new_ip_for_entity",
                              "failed_auth_5min_ip", "failed_auth_5min_entity", "ip_failure_rate_1h"],
     "problem": "generator-coupled: the generator writes attacks using the same SENSITIVE list, privileged-command set, private-vs-public IP ranges, hours and per-event random cities",
     "evidence": "ML-2 shortcut analysis (one-line raw-field rules match the detector on brute force / credential stuffing / impossible travel)",
     "candidate_handling": "KEPT (correlation is not a reason to drop a feature); their contribution is quantified by permutation in the shortcut diagnostic"},
    {"id": "P10", "features": ["fingerprint_mismatch", "auth_method_unusual"], "problem": "constant 0 on TRAIN: TRAIN contains no attacks, and the generator only produces a mismatched fingerprint / unusual auth method inside attacks, so there is no 'normal' distribution to learn",
     "evidence": "found by the pre-registered label-free rule 'constant on TRAIN' (this run); not anticipated when the policy was written (expected 3 exclusions, the rule found 5)",
     "candidate_handling": "EXCLUDED from IF/AE/classifier by the rule. CONSEQUENCE: those two signals reach the candidate only through the baseline profiler, where fingerprint_mismatch keeps its production weight 10.0 and auth_method_unusual 3.5; the IF/AE cannot see device-spoofing evidence in these flags"},
    {"id": "P9", "features": ["peer_resource_deviation", "baseline peer prior"], "problem": "api.py forces entity_type='user' for every event, so service accounts and edge devices get the wrong peer prior and peer histogram",
     "evidence": "ML-1/ML-2 parity variant V1: mean |Δrisk| 12.4", "candidate_handling": "training uses the real entity_type from the data (as the shipped training did); UNRESOLVED serving-parity blocker"},
    {"id": "P8", "features": ["fingerprint_novelty", "offhours_count_7d", "peer_resource_deviation", "resource_novelty_ratio"],
     "problem": "TRAIN->TEST distribution shift driven by cold-start transients in TRAIN (PSI 0.39-3.4)",
     "evidence": "ML-1 PSI analysis", "candidate_handling": "KEPT; fitting population unchanged for comparability with the shipped architecture; recorded as a limitation"},
]

# Groups used by the permutation shortcut diagnostic (feature-level, by generator artifact family)
SHORTCUT_GROUPS = {
    "ip (public vs private, per-IP failures)": ["is_new_ip_for_entity", "failed_auth_5min_ip", "distinct_entities_per_ip_1h", "ip_failure_rate_1h"],
    "failed authentication": ["failed_auth_5min_entity", "failed_auth_5min_ip", "ip_failure_rate_1h"],
    "hour of day / off-hours": ["hour_sin", "hour_cos", "is_weekend", "hour_zscore", "is_off_hours_for_entity", "offhours_count_7d", "sensitive_offhours_7d"],
    "location / city": ["geo_velocity_kmh", "distance_from_home_km"],
    "resource patterns": ["is_new_resource", "resource_novelty_ratio", "resource_entropy_24h", "is_sensitive_resource", "peer_resource_deviation",
                          "resource_breadth_7d", "sensitive_ratio_7d", "sensitive_bytes_proxy_7d"],
    "command patterns": ["cmd_len", "cmd_priv_count", "cmd_bigram_surprise"],
    "device fingerprint": ["fingerprint_mismatch", "fingerprint_novelty"],
    "volume / timing": ["events_last_1h", "events_last_24h", "interevent_gap_zscore", "session_duration_zscore"],
}

ML3_CONFIG = {
    "model_seed": MODEL_SEED, "ml3_seed": ML3_SEED, "fusion_grid_step": FUSION_GRID_STEP, "fusion_parsimony_margin": FUSION_PARSIMONY_MARGIN,
    "mode_margin": MODE_MARGIN, "class_trainable_min_incidents": CLASS_TRAINABLE_MIN_INCIDENTS,
    "class_evaluable_min_incidents": CLASS_EVALUABLE_MIN_INCIDENTS, "abstain_conf": ABSTAIN_CONF, "guard_risk": GUARD_RISK,
    "topk_frac": TOPK_FRAC, "seq_len": C.SEQ_LEN, "seq_fit_sample": C.SEQ_FIT_SAMPLE,
    "iforest": {"n_estimators": 200, "contamination": 0.02, "random_state": MODEL_SEED, "n_jobs": 1},
    "ae": {"hidden": 64, "epochs": 12, "lr": 1e-3, "batch": 256, "clean_fraction": 0.90},
    "policy_excluded_by_definition": list(POLICY_EXCLUDED_BY_DEFINITION), "eval_protocol": K2.EVAL_CONFIG,
}

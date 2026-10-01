"""ML-5 shared constants and the PRE-REGISTERED plan (fixed before any ML-5 result existed).

DATA ROLES
  DEV   every ML-4 standard dataset (TRAIN, VAL, DEV and the six datasets that were sealed in ML-4): their labels have been read in ML-4 and ML-4's findings
        motivated this phase, so they are DEVELOPMENT data: thresholds' alpha, the calibration method and every other choice are made on them.
        Profile-grouped cross-validation (leave-one-profile-out) is used so 'transfer' is measured on profiles the calibrator did not see.
  TEST  five FRESH datasets (new seeds, one per profile, generated after the design was fixed). Labels are unreadable until the whole configuration
        (weights, alpha, threshold rule, calibrator and its parameters) is written and hashed; unsealed exactly once.
The ML-4 global model (models/candidates/ml4) and its frozen fusion weights are used unchanged: ML-5 fits no new anomaly model.
"""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True

from eval_ml4 import common as K4                                                    # noqa: E402  (read-only reuse)
from eval_ml4.common import ATTACKS, C, ROOT, sha256_file, sha256_obj, to_jsonable, write_json     # noqa: E402,F401

REPORTS = ROOT / "reports"
DATA_DIR = ROOT / "eval_ml5" / "data"
CANDIDATE_DIR = ROOT / "models" / "candidates" / "ml5"
ML4_DATA_DIR = K4.DATA_DIR
ML4_ARTIFACT_DIR = ROOT / "models" / "candidates" / "ml4"
ML4_FEATURE_DIR = REPORTS / "ml4_runs" / "A" / "features"              # ML-4 canonical feature matrices (verified by hash against the ML-4 manifest)
ML4_RUN = REPORTS / "ml4_runs" / "C"
ML5_SEED = 20260923
DEPLOYMENT_TZ = "Asia/Kolkata"       # the wall-clock convention of the generated data (Indian/US/EU city labels are just labels; the clock is one clock)

# ---- fresh TEST datasets: (profile, seed)
FRESH = {"P0-711": ("P0", 711), "P1-712": ("P1", 712), "P2-713": ("P2", 713), "P3-714": ("P3", 714), "P4-715": ("P4", 715)}
FRESH_IDS = list(FRESH)
# ---- DEV pool = every ML-4 standard dataset, with the profile it belongs to (legacy orig42 is a P0-like dataset from the production generator)
DEV_STD_IDS = [d for d, v in K4.REGISTRY.items() if v[3] == "standard"]
DEV_PROFILE = {d: K4.REGISTRY[d][0] for d in DEV_STD_IDS}
DEV_PROFILE[K4.LEGACY_ID] = "P0"
# METHODOLOGY NOTE (decided before any ML-5 result existed): the three TRAIN-role datasets fitted the ML-4 global components on their OWN onboarding periods, so
# their onboarding-tail scores are in-sample for the isolation forest / GRU and would understate the benign score spread a genuinely new deployment shows.
# They stay in the parity re-evaluation but are EXCLUDED from the threshold/calibration DEV pool (whose tails must be out-of-sample).
DEV_EXCLUDED_TRAIN_IDS = [d for d in DEV_STD_IDS if K4.REGISTRY[d][2] == "TRAIN"]
DEV_IDS = [d for d in DEV_STD_IDS if d not in DEV_EXCLUDED_TRAIN_IDS] + [K4.LEGACY_ID]
# ML-4 sealed-standard datasets on which the serving-parity effect is measured (as in the ML-4 report)
PARITY_REEVAL_IDS = list(K4.SEALED_STD_IDS)
NO_ENTITY_TYPE_IDS = ["P0-104", "P3-402", "P4-501"]         # 'platform sends no entityType' path (the platform as it is today)
DRIFT_REEVAL_IDS = ["DR-ctrl", "DR-location", "DR-resources"]
FRESH_CANONICAL_CHECK_IDS = ["P2-713", "P3-714"]            # canonical-extraction comparison on fresh data (the other fresh sets use the serving path only)

# ---- threshold study (pre-registered)
ALPHAS = [0.001, 0.0025, 0.005, 0.01, 0.02]                 # target false-alert rate = share of benign events that raise an alert
ONBOARD_HEAD_FRACTION = 0.65                                # onboarding rows used to fit the deployment's baseline for the calibration population
ALPHA_VOLUME_REFERENCE = 0.01                                # a second, less extreme target for the onboarding-volume study
ONBOARD_SIZES = [250, 500, 1000, 2000, 5000]                # benign events available for the threshold (onboarding-volume study)
ONBOARD_DRAWS = 40
ONBOARD_OK_BAND = (0.5, 2.0)                                # realized/target false-alert-rate ratio counted as 'stable'
ONBOARD_OK_SHARE = 0.80
ALPHA_SELECTION = "maximise the mean F1 over the DEV deployments of the deployment-specific rule (alpha grid above); ties -> larger alpha"

# ---- calibration (pre-registered)
CALIB_BINS = 15
CALIB_METHODS = ["identity", "platt_raw", "isotonic_raw", "histogram_raw", "platt_deployment_normalised", "isotonic_deployment_normalised"]
CALIB_SELECTION = "lowest mean log-loss in leave-one-profile-out cross-validation on the DEV pool; must also lower the mean ECE vs identity"

ML5_CONFIG = {"ml5_seed": ML5_SEED, "deployment_tz": DEPLOYMENT_TZ, "fresh": FRESH, "dev_ids": DEV_IDS, "dev_excluded_train_ids": DEV_EXCLUDED_TRAIN_IDS, "alphas": ALPHAS, "onboard_head_fraction": ONBOARD_HEAD_FRACTION,
              "onboard_sizes": ONBOARD_SIZES, "alpha_volume_reference": ALPHA_VOLUME_REFERENCE, "onboard_draws": ONBOARD_DRAWS, "onboard_ok_band": ONBOARD_OK_BAND, "onboard_ok_share": ONBOARD_OK_SHARE,
              "alpha_selection": ALPHA_SELECTION, "calib_bins": CALIB_BINS, "calib_methods": CALIB_METHODS, "calib_selection": CALIB_SELECTION,
              "parity_reeval_ids": PARITY_REEVAL_IDS, "no_entity_type_ids": NO_ENTITY_TYPE_IDS, "drift_reeval_ids": DRIFT_REEVAL_IDS,
              "ml4_artifact": "models/candidates/ml4/ml4_global.joblib (frozen, unchanged)", "contract_version": "1.0"}

"""ML-4 shared constants and the PRE-REGISTERED plan (dataset registry, roles, rules). Fixed before any ML-4 result existed.

ROLES (a dataset has exactly one role for the whole study; an incident therefore can never cross a train/validation/test boundary)
  TRAIN    fit the global components (scaler, Isolation Forest, GRU autoencoder, score-transformation distributions)
  VAL      select fusion weights / evaluation operating points (never fits)
  DEV      dev diagnostics only (parity audit, legacy reference); labels are not sealed, nothing is selected from them
  SEALED   final test + controlled drift study; labels are physically not loaded until every configuration is frozen and hashed
Within every dataset the first ONBOARDING days are attack-free benign traffic (used to fit that dataset's per-entity baselines, exactly as
a deployment would onboard on its own history); evaluation is on the rest.
"""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True

from eval_ml3 import common as K3                                     # noqa: E402  (read-only reuse)
from eval_ml3.common import (ATTACKS, C, ROOT, md5_file, production_hashes, sha256_file, sha256_obj, to_jsonable,   # noqa: E402,F401
                             write_json)

REPORTS = ROOT / "reports"
DATA_DIR = ROOT / "eval_ml4" / "data"
CANDIDATE_DIR = ROOT / "models" / "candidates" / "ml4"
ML4_SEED = 20260922
GEN_VERSION = "ml4-gen-1.0"

DAYS = 36
ONBOARDING_DAYS = 14
TARGET_EVENTS = 60000
DRIFT_TARGET_EVENTS = 45000

# ---- dataset registry: id -> (profile, seed, role, kind)
REGISTRY = {
    "P0-101": ("P0", 101, "TRAIN", "standard"), "P0-102": ("P0", 102, "TRAIN", "standard"), "P1-201": ("P1", 201, "TRAIN", "standard"),
    "P2-301": ("P2", 301, "VAL", "standard"), "P3-401": ("P3", 401, "VAL", "standard"),
    "P0-103": ("P0", 103, "DEV", "standard"),
    "P0-104": ("P0", 104, "SEALED", "standard"), "P1-202": ("P1", 202, "SEALED", "standard"), "P2-302": ("P2", 302, "SEALED", "standard"),
    "P3-402": ("P3", 402, "SEALED", "standard"), "P4-501": ("P4", 501, "SEALED", "standard"), "P4-502": ("P4", 502, "SEALED", "standard"),
    "DR-ctrl": ("P0", 601, "SEALED", "drift"), "DR-hours": ("P0", 601, "SEALED", "drift"), "DR-resources": ("P0", 601, "SEALED", "drift"),
    "DR-location": ("P0", 601, "SEALED", "drift"), "DR-device": ("P0", 601, "SEALED", "drift"), "DR-volume": ("P0", 601, "SEALED", "drift"),
}
DRIFT_KIND = {"DR-ctrl": None, "DR-hours": "hours", "DR-resources": "resources", "DR-location": "location", "DR-device": "device", "DR-volume": "volume"}
LEGACY_ID = "orig42"          # the production generator's dataset (seed 42); read from data/sample, never regenerated or modified
LEGACY_ONBOARDING_DAYS = 20   # = the shipped model's TRAIN window (config.TRAIN_DAYS)

TRAIN_IDS = [d for d, v in REGISTRY.items() if v[2] == "TRAIN"]
VAL_IDS = [d for d, v in REGISTRY.items() if v[2] == "VAL"]
DEV_IDS = [d for d, v in REGISTRY.items() if v[2] == "DEV"] + [LEGACY_ID]
SEALED_STD_IDS = [d for d, v in REGISTRY.items() if v[2] == "SEALED" and v[3] == "standard"]
SEALED_DRIFT_IDS = [d for d, v in REGISTRY.items() if v[2] == "SEALED" and v[3] == "drift"]
SEALED_IDS = SEALED_STD_IDS + SEALED_DRIFT_IDS

# drift study phases (days): before < DRIFT_START <= during < DRIFT_END <= after
DRIFT_START, DRIFT_END = 22, 28

# ---- selection / evaluation rules (pre-registered)
FUSION_GRID_STEP = 0.1
FUSION_PARSIMONY_MARGIN = 0.01
TOPK_FRAC = 0.01
CLASS_LEARNABLE_MIN_INCIDENTS = 5          # incidents in TRAIN datasets
CLASS_LEARNABLE_MIN_PROFILES = 2           # distinct profiles among them
CLASS_EVALUABLE_MIN_VAL_INCIDENTS = 3      # incidents in VAL datasets (a different profile from TRAIN)
NEAR_DUP_QUANTILE = 0.05                   # near-duplicate = closer than the 5th percentile of within-dataset incident-pair distances

FEATURE_POLICY = K3.POLICY_EXCLUDED_BY_DEFINITION           # + 'constant on pooled TRAIN onboarding' (same rule as ML-3)
GUARD_RISK = K3.GUARD_RISK

ML4_CONFIG = {"ml4_seed": ML4_SEED, "gen_version": GEN_VERSION, "days": DAYS, "onboarding_days": ONBOARDING_DAYS, "target_events": TARGET_EVENTS,
              "drift_target_events": DRIFT_TARGET_EVENTS, "registry": REGISTRY, "drift_kind": DRIFT_KIND, "drift_window_days": [DRIFT_START, DRIFT_END],
              "legacy": {"id": LEGACY_ID, "onboarding_days": LEGACY_ONBOARDING_DAYS}, "fusion_grid_step": FUSION_GRID_STEP,
              "fusion_parsimony_margin": FUSION_PARSIMONY_MARGIN, "topk_frac": TOPK_FRAC,
              "class_learnable_min_incidents": CLASS_LEARNABLE_MIN_INCIDENTS, "class_learnable_min_profiles": CLASS_LEARNABLE_MIN_PROFILES,
              "class_evaluable_min_val_incidents": CLASS_EVALUABLE_MIN_VAL_INCIDENTS, "model": K3.ML3_CONFIG["iforest"] | {"seq_len": C.SEQ_LEN}}

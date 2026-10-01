"""Shared helpers for the ML-2 evaluation harness (evaluation-only)."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True          # never touch the project's __pycache__

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:                                     # matplotlib is not installed in the project venv. Stub it IN-PROCESS only so
    import matplotlib                    # that src.evaluate's pure-metric helpers stay importable. Nothing is installed.
except ModuleNotFoundError:
    _mpl = types.ModuleType("matplotlib")
    _mpl.use = lambda *a, **k: None
    _plt = types.ModuleType("matplotlib.pyplot")
    sys.modules["matplotlib"] = _mpl
    sys.modules["matplotlib.pyplot"] = _plt
    _mpl.pyplot = _plt

import numpy as np                       # noqa: E402
import pandas as pd                      # noqa: E402

import config as C                       # noqa: E402  (production config, read-only)

REPORTS = ROOT / "reports"
DATA = C.SAMPLE_DIR
ATTACKS = list(C.ATTACK_TYPES)

# --------------------------------------------------------------------------------------------------------------
# Pre-registered protocol constants. Fixed BEFORE any model score was inspected; see protocol.py for the rule.
# --------------------------------------------------------------------------------------------------------------
EVAL_SEED = 20260920
TRAIN_DAYS = 20            # the shipped artifact's fit window (config.TRAIN_DAYS); verified against the artifact
VAL_END_DAYS = 25          # rule: shortest window after TRAIN holding >= 1/3 of attack incidents (by first event)
HELDOUT_FRACTION = 0.30    # share of entities held out for the entity-generalisation experiment
TOPK_FRAC = 0.01           # Precision@1% / Recall@1% budget (fraction of the evaluated population)
CLASSIFIER_MAX_PER_INCIDENT = C.MAX_TRAIN_EVENTS_PER_INCIDENT   # same cap the shipped pool used (6)
SPRING_ALERT_RISK = 99.0   # Spring alert threshold 0.99 applied to anomalyScore = risk/100 (read-only reference)

EVAL_CONFIG = {
    "eval_seed": EVAL_SEED, "train_days": TRAIN_DAYS, "val_end_days": VAL_END_DAYS,
    "heldout_fraction": HELDOUT_FRACTION, "topk_frac": TOPK_FRAC,
    "classifier_max_per_incident": CLASSIFIER_MAX_PER_INCIDENT, "spring_alert_risk": SPRING_ALERT_RISK,
    "fusion_weights": dict(C.FUSION_WEIGHTS), "production_seed": C.RANDOM_SEED,
}


def md5_file(p) -> str:
    h = hashlib.md5()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_file(p) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_obj(o) -> str:
    return hashlib.sha256(json.dumps(o, sort_keys=True, default=str).encode()).hexdigest()


def production_files() -> list[Path]:
    """Every file that makes up the production scoring path + its artifact + the dataset. Hashed before/after."""
    files = [ROOT / "api.py", ROOT / "config.py", ROOT / "run_pipeline.py", ROOT / "run_realtime.py", ROOT / "app.py",
             ROOT / "models" / "pipeline.joblib", DATA / "events.csv", DATA / "labels.csv", DATA / "entity_profiles.json"]
    files += sorted((ROOT / "src").glob("*.py"))
    return files


def production_hashes() -> dict:
    return {str(p.relative_to(ROOT)).replace("\\", "/"): sha256_file(p) for p in production_files()}


def env_info() -> dict:
    import importlib
    info = {"python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine(),
            "cpu_count": os.cpu_count()}
    for mod in ("numpy", "pandas", "scipy", "sklearn", "torch", "lightgbm", "shap", "joblib", "fastapi", "pydantic"):
        try:
            info[mod] = importlib.import_module(mod).__version__
        except Exception as e:                       # noqa: BLE001
            info[mod] = f"unavailable ({type(e).__name__})"
    return info


def to_jsonable(o):
    if isinstance(o, dict):
        return {str(k): to_jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [to_jsonable(v) for v in o]
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        v = float(o)
        return None if (v != v) else v
    if isinstance(o, float):
        return None if o != o else o
    if isinstance(o, (np.bool_,)):
        return bool(o)
    if isinstance(o, np.ndarray):
        return to_jsonable(o.tolist())
    if isinstance(o, (pd.Timestamp,)):
        return o.isoformat()
    return o


def write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(to_jsonable(obj), f, indent=2, sort_keys=False)


def load_artifact():
    import warnings
    import joblib
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return joblib.load(ROOT / "models" / "pipeline.joblib")


class LabelVault:
    """Sealed labels. Tuning code only ever receives `dev_labels()` (test-period labels masked). The single final
    test evaluation calls `unseal_test()` once (a second call raises). Every other read of test-period labels goes
    through `diagnostic()` and is logged, so the manifest can enumerate exactly where held-out labels were touched."""

    def __init__(self, labels: pd.DataFrame, is_test: np.ndarray):
        self._labels = labels.reset_index(drop=True)
        self._is_test = np.asarray(is_test, dtype=bool)
        self.log: list[dict] = []
        self.test_unseals = 0

    def dev_labels(self) -> pd.DataFrame:
        d = self._labels.copy()
        d.loc[self._is_test, ["label", "attack_id"]] = [None, None]
        self.log.append({"access": "dev_labels", "test_rows_visible": 0})
        return d

    def unseal_test(self, purpose: str) -> pd.DataFrame:
        if self.test_unseals >= 1:
            raise RuntimeError("held-out test labels were already unsealed once; the final test evaluation may run once")
        self.test_unseals += 1
        self.log.append({"access": "unseal_test", "purpose": purpose})
        return self._labels.copy()

    def diagnostic(self, purpose: str) -> pd.DataFrame:
        self.log.append({"access": "diagnostic_all_labels", "purpose": purpose})
        return self._labels.copy()

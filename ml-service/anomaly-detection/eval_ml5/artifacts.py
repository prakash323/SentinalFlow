"""Candidate artifacts of ML-5 (written under a run directory; the canonical run's copy is published to models/candidates/ml5/).

Everything here is a CANDIDATE / EVALUATION ARTIFACT - NOT DEPLOYED: nothing in it is loaded by api.py, run_pipeline.py or run_realtime.py, and models/pipeline.joblib is untouched.
"""
from __future__ import annotations

import difflib
import shutil
from pathlib import Path

from . import common as K

STATUS = "CANDIDATE / EVALUATION ARTIFACT - NOT DEPLOYED. Never loaded by api.py, run_pipeline.py or run_realtime.py. models/pipeline.joblib is untouched."


def write_candidate_files(out_dir: Path, created_by: str) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    src = K.ROOT / "eval_ml5"
    shutil.copyfile(src / "contract.py", out_dir / "serving_contract.py")
    shutil.copyfile(src / "api_candidate_template.py", out_dir / "api_candidate.py")
    prod = (K.ROOT / "api.py").read_text(encoding="utf-8").splitlines(keepends=True)
    cand = (out_dir / "api_candidate.py").read_text(encoding="utf-8").splitlines(keepends=True)
    diff = "".join(difflib.unified_diff(prod, cand, fromfile="api.py (production, unchanged)", tofile="api_candidate.py (ML-5 candidate)"))
    (out_dir / "api_production_to_candidate.diff").write_text(diff, encoding="utf-8")
    (out_dir / "README.md").write_text(
        "# ML-5 candidate artifacts - NOT DEPLOYED\n\n"
        "* `serving_contract.py` - the corrected serving contract (canonical-event construction, documented field policy, ServingPipeline).\n"
        "* `api_candidate.py` - a modified copy of the production `api.py` that uses it (start with ML_DEPLOYMENT_TZ set; see the module docstring).\n"
        "* `api_production_to_candidate.diff` - the complete difference from the production `api.py` (which ML-5 did not change).\n"
        "* `frozen_config5.json`, `calibrator_params.json` - the threshold rule, alpha and the score calibrator selected on the DEV pool and frozen before any TEST label was read.\n"
        "  They are defined for the ML-4 candidate model's fused score (models/candidates/ml4), which is itself not deployed.\n\n"
        "Apply nothing here to production without review and an explicit deployment approval.\n", encoding="utf-8")
    files = {p.name: K.sha256_file(p) for p in sorted(out_dir.iterdir()) if p.is_file() and p.name != "MANIFEST.json"}
    manifest = {"status": STATUS, "created_by": created_by, "files": files, "contract_version": "1.0"}
    K.write_json(out_dir / "MANIFEST.json", manifest)
    return manifest

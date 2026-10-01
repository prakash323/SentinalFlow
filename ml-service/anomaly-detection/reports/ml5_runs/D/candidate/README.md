# ML-5 candidate artifacts - NOT DEPLOYED

* `serving_contract.py` - the corrected serving contract (canonical-event construction, documented field policy, ServingPipeline).
* `api_candidate.py` - a modified copy of the production `api.py` that uses it (start with ML_DEPLOYMENT_TZ set; see the module docstring).
* `api_production_to_candidate.diff` - the complete difference from the production `api.py` (which ML-5 did not change).
* `frozen_config5.json`, `calibrator_params.json` - the threshold rule, alpha and the score calibrator selected on the DEV pool and frozen before any TEST label was read.
  They are defined for the ML-4 candidate model's fused score (models/candidates/ml4), which is itself not deployed.

Apply nothing here to production without review and an explicit deployment approval.

# eval_ml5 — serving parity, deployment thresholds, probability calibration

Evaluation code only. **Nothing here is loaded by `api.py`, `run_pipeline.py` or `run_realtime.py`; nothing is deployed.** `models/pipeline.joblib` is untouched.

| file | purpose |
|---|---|
| `contract.py` | the corrected serving contract (canonical-event construction, documented `FIELD_POLICY`, `ContractError`, `ServingPipeline`); self-contained (stdlib + pandas) |
| `api_candidate_template.py` | candidate API that uses it (a modified copy of `api.py`; the production file is not edited) |
| `platform_sim.py` | canonical event -> the SentinelFlow envelope the platform sends; the production (pre-fix) boundary for comparison |
| `parity_lib.py`, `tests/test_contract_parity.py` | training-vs-serving feature comparison and the 19 deterministic regression tests |
| `serving_eval.py` | dataset-scale feature matrices through each boundary |
| `thresholds.py`, `calibration.py` | per-deployment threshold rule + study; calibrators + reliability / prior-shift metrics |
| `common.py` | pre-registered plan (data roles, alpha grid, methods, selection rules) |
| `build_data.py` | five fresh TEST datasets (seeds 711-715) with the unchanged ML-4 generator |
| `run.py` | orchestrator: verify -> tests -> serving -> scoring -> drift -> DEV studies -> FREEZE -> TEST -> outputs |
| `artifacts.py`, `compare_runs.py`, `compose_json.py`, `compose_md.py` | candidate files, run comparison, report writers |

## Commands

```
python -m unittest eval_ml5.tests.test_contract_parity          # parity regression suite (~30 s)
python -m eval_ml5.build_data                                    # (already generated; verified byte-identical on every run)
python -m eval_ml5.run --run-id E --workers 3 --regen            # full evaluation (~20 min); F = the twin
python -m eval_ml5.compare_runs E F
python -m eval_ml5.compose_json E F ; python -m eval_ml5.compose_md E F
```

`--dry` rehearses the TEST stage on two already-opened ML-4 datasets (no fresh label is read).

## Protocol

DEV = ML-4 standard datasets except the three TRAIN-role ones (their onboarding fitted the ML-4 model, so their tails would be in-sample) + legacy `orig42`. TEST = five fresh datasets, labels
unreadable (`Vault5`) until the configuration is frozen and hashed, then unsealed once. Fusion weights, model and features come unchanged from `models/candidates/ml4`.
Outputs: `reports/ml5_*` and `models/candidates/ml5/` (NOT DEPLOYED).

# eval_ml4 - ML-4 data and evaluation foundation

**Evaluation only.** Nothing in the production scoring path (`api.py`, `src/`, `run_*.py`, `models/pipeline.joblib`) imports this package. It never modifies `src/generate.py`;
`generator.py` is an independent, profile-parameterised generator. Datasets are written to `eval_ml4/data/`, results to `reports/ml4*`, the evaluation artifact to `models/candidates/ml4/` (NOT DEPLOYED).

## Run

From `ml-service/anomaly-detection`, with the project virtualenv:

```
python -m eval_ml4.build_data                     # 18 datasets + manifest (deterministic; re-run with --out <dir> to verify byte-identity)
python -m eval_ml4.run --run-id C --regen         # verify -> features -> fit -> dev -> FREEZE -> sealed -> drift -> audits  (checkpoints after every stage)
python -m eval_ml4.run parity --run-id A          # serving-parity audit (13 variants x 2 datasets x 2 models)
python -m eval_ml4.compare_runs C D               # exact-equality comparison of two complete runs
python -m eval_ml4.compose C D --pre A --parity A B    # writes reports/ml4_data_evaluation.md, ml4_metrics.json, ml4_dataset_manifest.json, ml4_parity_report.json
```

`--features-from A --features-recompute <ids>` reuses another run's feature cache except for the named datasets, which are recomputed and hash-compared.

## Layout

| File | Role |
|---|---|
| `common.py` | pre-registered plan: dataset registry, roles, rules, hashing |
| `profiles.py` | five generator profiles (P0 replica of production constants, P1 stealth-internal, P2 remote workforce, P3 OT/IoT, P4 burst) + drift-study base |
| `generator.py` | deterministic generator (named RNG streams; unique increasing timestamps; labels and incident registry in separate files) |
| `build_data.py` | parallel dataset build and manifest with per-file hashes |
| `features4.py` | causal feature matrices (production extractor, unchanged) |
| `xfer.py` | per-dataset label Vault, global fit, fusion selection, replay of frozen / adaptive baselines, per-dataset evaluation |
| `drift.py` | controlled frozen-vs-adaptive study (5 drift kinds, before/during/after, 6 baseline variants) |
| `audits.py` | shortcut rules, device-spoofing signals, class coverage, near-duplicate incidents, label-free profile contrast |
| `parity.py` | serving-parity variants (14) applied to live events, measured on the shipped and ML-3 models |
| `run.py` | orchestrator with sealing order and per-stage checkpoints |
| `compare_runs.py`, `compose.py`, `posthoc4.py`, `compose_manifest.py` | reproducibility comparison and report generation |

Sealed datasets' labels and incident registries cannot be read (`xfer.Vault`) until the frozen configuration is written, hashed and made read-only.

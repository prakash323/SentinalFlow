# eval_ml2 — ML-2 reproducible, leakage-safe evaluation harness

**Evaluation only.** Nothing in the production scoring path (`api.py`, `src/`, `run_*.py`, `models/`) imports this
package, and it writes only under `reports/`. It drives the production classes read-only; the unmodified
`StreamingScorer.process` is used for the streaming evaluation (instrumentation wraps methods on the harness's own
in-memory copy of the loaded artifact).

Every stage records SHA-256 hashes of every production file (source, model artifact, dataset) before and after it runs.

## Run

From `ml-service/anomaly-detection`, using the project virtualenv:

```
python -m eval_ml2.run batch    --run-id A          # frozen batch scoring of every event (label-free)
python -m eval_ml2.run stream   --run-id A --variant main      # chronological streaming, as deployed
python -m eval_ml2.run stream   --run-id A --variant heldout   # partial held-out-entity streaming
python -m eval_ml2.run parity   --run-id A          # API / feature representation checks
python -m eval_ml2.run assemble --run-id A          # metrics (decisions frozen -> test unsealed once)
# repeat with --run-id B, then:
python -m eval_ml2.compare_runs A B                 # exact-equality reproducibility comparison
python -m eval_ml2.compose A B                      # writes reports/ml2_evaluation.md, ml2_metrics.json, ml2_split_manifest.json
```

The streaming stages take ~1 h on a loaded machine (the scorer runs a GRU per event); stages are independent and can run in parallel.
Set `OMP_NUM_THREADS=1` (the runner does this by default) for single-threaded numerics.

## Layout

| File | Role |
|---|---|
| `common.py` | constants (pre-registered protocol), hashing, environment record, `LabelVault` (sealed test labels) |
| `protocol.py` | chronological TRAIN / VALIDATION / TEST split, incident purge, held-out entity selection, manifest |
| `scoring.py` | frozen batch scoring and chronological streaming (label-free) |
| `metrics.py` | every metric definition (tie-aware top-1%, operating points, per-attack, classification) |
| `classifier_eval.py` | legacy row-level CV, incident-grouped CV, chronological leakage-safe classifier evaluation |
| `parity.py` | training vs API vs streaming representation checks; warm-up scope |
| `shortcuts.py` | dataset shortcut analysis |
| `assemble.py` | orchestration with enforced label-access order |
| `compare_runs.py` | run-to-run reproducibility comparison |
| `report.py`, `report_more.py`, `findings.py`, `compose.py` | report generation (all numbers come from the metrics JSON) |

Per-run intermediates live in `reports/ml2_runs/<run-id>/`.

# AI-Powered Behavioural Anomaly Detection for Cybersecurity

Honeywell hackathon submission. An AI/ML system that learns what *normal* access
and connection behaviour looks like for every user, service account and edge
device, flags deviations in near real time, classifies the type of anomaly, and
explains itself to a SOC analyst.

Runs on **synthetic data** (generated here) and on **real public datasets**
(LANL, CERT) through the same pipeline, in both **batch** and **real-time
streaming** modes — CSV replay, a live folder watcher, a REST endpoint, and
(reviewed, not broker-tested) Kafka/MQTT adapters all feed the identical
detection pipeline, so a live, auto-refreshing SOC dashboard sits alongside
the offline batch report rather than replacing it.

---

## Quick start (VS Code)

```bash
git clone <your-repo>  &&  cd honeywell-anomaly-detection
python -m venv .venv
# Windows:  .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt

python run_pipeline.py      # 1. batch: generate -> train -> evaluate -> figures
python run_realtime.py      # 2. streaming replay with live alerts
streamlit run app.py        # 3. analyst dashboard (6 pages, incl. Live Monitor)
```

First run takes about 4-6 minutes on 99k events. In a hurry: `python run_pipeline.py --quick`.

VS Code users: press **F5** — `.vscode/launch.json` has all five run configurations pre-wired.

**Dynamic alert budget** — `config.ALERT_BUDGET = 0.01` is a default, not a
constant. Retarget it at runtime, in batch or streaming, without retraining:

```bash
python run_pipeline.py --budget 0.02       # top 2% instead of top 1%
python run_realtime.py --budget 0.015      # same idea, streaming
```

or use the dashboard's sidebar "alert budget" control, which reads the
precomputed multi-budget sweep — see `ASSUMPTIONS.md` "Dynamic alert budget".
The dashboard opens on **2%** by default (`config.DASHBOARD_DEFAULT_BUDGET`)
regardless of which budget the pipeline itself was run/calibrated at (still
1%, matching the problem statement's own stated example) — a display
default only, re-reading the same precomputed sweep, never a different
evaluation.

**Real-time input adapters** (`src/adapters.py`) — the same detection
pipeline, fed from something other than a static CSV:

```bash
# live folder watcher: drop .json / .jsonl / .csv files into a directory
python run_realtime.py --stream-source folder --watch-dir data/live_drop --serve

# REST ingestion (stdlib only, no framework dependency)
python run_realtime.py --stream-source rest --serve
curl -X POST http://127.0.0.1:8765/events -d '{"entity_id": "U0001", "timestamp": "2026-07-01T09:00:00", "resource_accessed": "/repo/api"}'

# Kafka / MQTT: interface-complete, NOT exercised against a live broker here
# (none available in this environment) -- see ASSUMPTIONS.md and FIXES.md Round 5
python run_realtime.py --stream-source kafka --kafka-topic access-events --serve
python run_realtime.py --stream-source mqtt --mqtt-topic access/events --serve
```

Any `--serve` run writes `report/live_state.json`, which the dashboard's
**Live Monitor** page (`st.fragment`, auto-refreshes every 2s) reads —
live event/alert counters, active entities, throughput, latency
percentiles, CPU/memory (via `psutil` if installed), risk distribution,
attack-type distribution, and recent alerts.

**A measured, honestly-reported gap**: streaming precision is not the same
as the batch figure above — measured directly, not estimated, and
substantially worse than "lower" implied before this pass. `--calib-events
N` (opt-in, off by default) re-calibrates the alert threshold against the
live stream's own scores instead of inheriting the batch one, which
measurably helps but does not fully close the gap. See `ASSUMPTIONS.md`
limitation 7 and `FIXES.md` Round 6 for the exact numbers, the root-cause
investigation, and the specific next experiment identified but not yet run.

---

## The two data modes you asked for

### Sample data (bundled, works offline)

`data/sample/` ships pre-generated: **99,348 events, 200 entities, 30 days,
1.15% anomalous**. Regenerate at any size:

```bash
python -m src.generate --days 30 --scale 1.0     # ~600k events
python -m src.generate --days 30 --scale 0.16    # ~99k events (shipped)
```

### Real datasets (download separately)

Adapters map real logs into the same canonical schema, so nothing downstream
changes. See `REFERENCES.md` for links and licences.

```bash
python -m src.datasets --list
python -m src.datasets --source lanl --path data/raw/lanl --out data/lanl
python run_pipeline.py --source generic --path data/lanl
```

| Source | What it gives you |
|---|---|
| `synthetic` | full control, all 6 attack types, perfect ground truth |
| `lanl` | real enterprise auth logs, 58 days, red-team labels |
| `cert` | CMU insider-threat behavioural logs, 1000 users, 17 months |
| `generic` | any CSV already in the canonical schema |

### Batch vs real-time

Both use **the exact same feature code**, so there is no train/serve skew — a
claim worth making explicitly in the deck.

| | batch (`run_pipeline.py`) | real-time (`run_realtime.py`) |
|---|---|---|
| input | whole dataframe | one event at a time |
| features | `build_feature_matrix` | `StreamingFeatureExtractor.update_and_extract` |
| fusion | rank-normalise across batch | percentile map vs stored training distribution |
| output | metrics, figures, alert queue | live alerts + latency/throughput stats |

---

## Results on the bundled sample data

| Detector | PR-AUC | Precision @1% | Recall @1% |
|---|---|---|---|
| Baseline profiler only | 0.785 | 0.862 | 0.282 |
| Isolation Forest only | 0.833 | 0.982 | 0.321 |
| Sequence autoencoder only | 0.764 | 0.997 | 0.326 |
| **Full ensemble** | **0.920** | **1.000** | **0.327** |

Incident-level detection at the top-1% analyst budget:

| Attack | Incidents | Detected |
|---|---|---|
| brute force | 5 | 5 |
| credential stuffing | 1 | 1 |
| impossible travel | 15 | 15 |
| lateral movement | 5 | 5 |
| device spoofing | 5 | 5 |
| low-and-slow exfiltration | 5 | 5 |

**36 / 36 incidents caught (100%)** at the top-1% budget
(`report/metrics.json` → `incident_budget_curve`). Device spoofing reached
5/5 in this pass via `peer_resource_deviation`, a new feature measuring how
rare a resource is *within an entity's own peer group* rather than
org-wide — evaluated with a same-seed controlled A/B, strict improvement,
zero regression on any other attack type. The alert budget itself is now a
runtime parameter (`--budget`, or the dashboard's sidebar control), not a
constant — see "Dynamic alert budget" below. Full detail: `FIXES.md`
Round 5.

False alarm rate on deliberately-planted **legitimate** drift: **0.000**.

> PR-AUC is the headline, not ROC-AUC. At a 1.15% positive rate ROC-AUC flatters
> every model. See Saito & Rehmsmeier (2015) in `REFERENCES.md`.

---

## Architecture

```
 access logs (synthetic | LANL | CERT)          live streams:
        |                                        CSV replay | folder watch |
        |                                        REST | Kafka* | MQTT*
        |                                        (src/adapters.py, one
        |                                         EventSource interface)
        v                                              |
 StreamingFeatureExtractor  <----------------------------
        |  39 leak-free behavioural features, single causal forward pass
        v
 +-------------------+-------------------+
 | baseline profiler | isolation forest  | sequence autoencoder
 | per-entity z      | global outliers   | GRU / PCA reconstruction
 +-------------------+-------------------+
        |  rank-normalised weighted fusion
        v
   risk score 0-100  ->  threshold at a RUNTIME-CONFIGURABLE budget
        |                 (default top 1%; Detector.threshold_for_budget)
        v
 attack-type classifier (flagged subset only)
        |
        v
 explainability -> reason text -> deduplicated analyst queue
        |                                     |
        v                                     v
   batch dashboard pages              Live Monitor (st.fragment,
   (Overview / Alert queue / ...)      report/live_state.json)

 * Kafka/MQTT: interface-complete, not exercised against a live broker here.
```

---

## How each requirement in the problem statement is met

| Requirement | Where | How |
|---|---|---|
| Sequential / behavioural data | `src/features.py` | per-entity streaming state, 1h/24h/7d windows, command-sequence bigrams |
| Extreme class imbalance | `src/classify.py` | detection stays **unsupervised**; the supervised classifier only ever sees the flagged subset, so it never faces 1:100 |
| Concept drift | `src/baseline.py` | EWMA profile updates + PSI monitor that raises **one** system notice instead of an alert flood |
| Baseline poisoning | `src/baseline.py` | only events **below** the alert threshold update the profile — an attacker cannot slowly teach the system to accept them |
| Explainability | `src/explain.py` | z-score decomposition + per-feature reconstruction error + SHAP, rendered as plain English; every alert also carries a concrete, attack-type-specific `recommended_action` and a MITRE ATT&CK mapping |
| Cold start | `src/baseline.py` | peer-group prior with Bayesian shrinkage `w = n/(n+k)`; low-history entities are flagged and routed to a separate queue so they cannot flood it |
| Analyst alert budget | `src/evaluate.py`, `src/detect.py` | precision/recall reported at a runtime-configurable budget (default top 1%), plus incident-level dedup so one brute-force burst is **one** alert, not 130 |
| Real-time feasibility | `src/realtime.py`, `src/adapters.py` | per-event latency/throughput measured every run; four real input adapters (CSV/folder/REST + interface-complete WebSocket/Kafka/MQTT) share one detection pipeline |
| Live analyst view | `app.py` Live Monitor page | auto-refreshing (`st.fragment`) read of `report/live_state.json`, written by any `--serve` run |

---

## Deliverables map

| Required deliverable | File |
|---|---|
| 1. Synthetic data generator + attack taxonomy | `src/generate.py`, `ASSUMPTIONS.md` |
| 2. Baseline profiling model | `src/baseline.py` |
| 3. Detection model (sequence-aware) | `src/detect.py` |
| 4. Anomaly classification | `src/classify.py` |
| 5. Explainability layer | `src/explain.py` |
| 6. Analyst-facing dashboard | `app.py` (Overview / Alert queue / Entity view / Model performance / Real-time replay / Live Monitor, one sidebar-navigated app) |
| 7. Report — assumptions, metrics, limitations | `ASSUMPTIONS.md`, `report/metrics.json` |

---

## Project layout

```
config.py              schema, constants, attack taxonomy, BUDGET_LEVELS -- single source of truth
run_pipeline.py        batch: generate -> features -> train -> evaluate -> figures (--budget)
run_realtime.py        streaming: any src/adapters.py source, --serve, --budget
app.py                 Streamlit analyst dashboard (6 pages, incl. Live Monitor)
src/generate.py        synthetic generator: profiles + 6 attacks + benign drift
src/datasets.py        LANL / CERT / generic adapters -> canonical schema
src/adapters.py        streaming input adapters: CSV / folder / REST / WebSocket / Kafka* / MQTT*
src/features.py        StreamingFeatureExtractor (leak-free, shared batch+stream)
src/baseline.py        per-entity profiles, peer priors, drift, poisoning guard
src/detect.py          IsolationForest + sequence autoencoder + fusion + threshold_for_budget
src/classify.py        attack-type classifier
src/explain.py         attribution + analyst reason strings
src/evaluate.py        PR-AUC, budget curves, incident recall, ablations, plots, shap_summary
src/realtime.py        StreamingScorer, consume() (shared by every input adapter)
data/sample/           bundled generated dataset + ground truth
report/                metrics.json, alerts.json, scored_events.csv, live_state.json
figures/               every plot the report needs
```

---

## Optional dependencies

Everything has a tested fallback, so the project runs on numpy/pandas/sklearn alone.

| Install | Get | Fallback |
|---|---|---|
| `torch` | GRU sequence autoencoder | PCA reconstruction autoencoder |
| `lightgbm` | LightGBM classifier | sklearn HistGradientBoosting |
| `shap` | per-alert SHAP values + `shap_summary.png` | z-score decomposition + feature importances |
| `faker` | nicer synthetic IDs | built-in generator |
| `psutil` | CPU/memory on the Live Monitor page | panel shows "install psutil", no fabricated numbers |
| `websockets` | `--ws-broadcast` live alert stream | that one flag is unavailable; everything else works |
| `kafka-python` / `paho-mqtt` | `--stream-source kafka` / `mqtt` | those two sources raise a clear install error; csv/folder/rest need neither |

---

## What changed in this real-time productionisation pass

On top of everything below, the most recent pass (`FIXES.md` Round 5) added
real-time streaming input adapters and a live dashboard without touching
evaluation methodology or the alert budget's default:

- **A real, previously-latent bug fixed**: `src/generate.py`'s attack
  injectors hardcoded their placement to calendar days 21-30 regardless of
  the `--days` parameter — a silent no-op at the default 30 days (so every
  number in earlier rounds was unaffected), but it broke `--quick` and any
  custom `--days` run. Fixed; verified byte-for-byte reproduction of the
  documented 99,348-event sample at the default configuration.
- **Dynamic alert budget**: `config.ALERT_BUDGET` is now a runtime
  parameter (`--budget` on both entry points, a dashboard sidebar control),
  not a constant — `Detector.threshold_for_budget()` retargets it from the
  already-stored training calibration, no retraining or leakage.
- **Streaming input adapters** (`src/adapters.py`): CSV replay, a folder
  watcher, and a REST endpoint, all tested end-to-end against the real
  trained model in this environment; WebSocket broadcast and Kafka/MQTT
  adapters are complete and interface-conformant but not exercised against
  a live broker (none available here) — see `ASSUMPTIONS.md`.
- **A live dashboard page** ("Live Monitor", auto-refreshing via
  `st.fragment`), reading `report/live_state.json` from any `--serve` run.
- **One new feature, evaluated and kept**: `peer_resource_deviation` closed
  the device-spoofing gap (incident recall 0.8 → 1.0) and brought total
  incident recall @1% budget to **36/36 (100%)**, with a same-seed
  controlled A/B showing strict improvement and zero regression. A second
  candidate, `priv_ratio_change_7d`, was tried and rejected on the same
  basis (regressed device-spoofing incident recall).
- **The real SHAP attribution path was verified for the first time** — this
  environment has `shap` and `lightgbm` installed, which the authors' own
  dev sandbox didn't; every predicted class's top SHAP feature matched its
  documented attack signature exactly. Added `figures/shap_summary.png`.
- **Streaming precision was measured, found near-zero, and partially
  fixed.** Final verification surfaced `live precision: 0/475` — checked
  directly against ground truth (not a fluke of that one run), root-caused
  to a batch-vs-streaming score-distribution mismatch, and partially
  addressed with opt-in stream-native threshold self-calibration
  (`--calib-events`). A likely second contributing cause (EWMA baseline
  drift diverging from the static batch profile over a long stream) was
  identified but not fixed this pass — see `FIXES.md` Round 6 for the full,
  honest writeup, including what still doesn't work.

Full detail, every metric table, and what was tried and rejected: `FIXES.md`
Rounds 5 and 6.

## What changed in the final submission pass

Starting point: a working pipeline and dashboard that had already been
through one review (`REVIEW_NOTES.md`), whose recommendations were written
down but not yet all applied to the shipped files. This pass actually
applies them, re-validates every metric, and adds a few small,
independently-tested improvements on top. Full detail in `FIXES.md`;
summary:

- **Dashboard rebuilt** (`app.py`): sidebar-radio navigation across five
  pages instead of `st.tabs()` (a single filter widget instead of several
  tab-scoped ones that could desync); `run_realtime.py`'s output folded in
  as a **Real-time replay** page, with a button to trigger a fresh replay
  from inside the app; every remaining raw `st.json()` dump replaced with
  formatted tables/cards; risk score now consistently rendered to 1
  decimal place everywhere (the alert-detail header still had the old
  `.0f` rounding bug that made the queue look saturated at "100"); a new
  **Overview** page leads with the side-by-side risk-distribution
  histogram (queue vs. full population) so "is this saturated?" is
  answered visually on the first screen.
- **Explainability**: every alert now carries a `recommended_action` field
  — a concrete, attack-type-specific next step for the SOC analyst, shown
  in its own tab in the Alert queue page — closing the fourth of the four
  questions an alert should answer (why flagged / why this type / which
  features / **what do I do now**).
- **Device-spoofing incident ranking**: `src/evaluate.py:incident_scores`
  now takes an optional, small (`fp_weight=0.01`, empirically swept — see
  `FIXES.md`) fingerprint-novelty persistence bonus when ranking candidate
  incidents for the analyst queue. Device-spoofing incident recall @1%
  improves 0.6 → 0.8 (3/5 → 4/5) with **zero regression** on any other
  attack type; net incident recall 34/36 → 35/36. This changes ranking
  order within the existing fixed alert budget only — it does not touch
  the evaluation methodology, the budget, or the underlying risk scores.
- **Everything else reviewed, nothing else changed.** The generator, the
  feature set, the fusion weights, the detector architecture and the
  classifier were all re-examined against the review notes and left as-is
  where no genuine improvement was found — see `FIXES.md` for what was
  considered and rejected, not just what was applied.

---

## Reproducing every number in the report

```bash
python run_pipeline.py                    # writes report/metrics.json
python run_realtime.py --limit 20000      # writes report/realtime_stats.json
```

Both are seeded (`config.RANDOM_SEED = 42`). Note: `run_pipeline.py` always
writes to the fixed `report/` / `models/` / `figures/` locations from
`config.py` regardless of `--path` (which only relocates the input
*data*) — any run of it overwrites the shipped report, including a
`--quick` smoke test. Regenerate a final run before submission if you've
been experimenting.

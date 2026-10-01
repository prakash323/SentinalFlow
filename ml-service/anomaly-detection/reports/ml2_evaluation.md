# ML-2 Reproducible Evaluation

*Scope: evaluation only. No production source, model artifact, threshold, database, Kafka topic or frontend file was changed; nothing was retrained or calibrated.
All numbers below are generated from `reports/ml2_metrics.json` by `eval_ml2/` (run `A`; run `B` reproduces it — see §12).*



## 1. Evaluation Protocol

**Purpose.** Establish a trustworthy, reproducible measurement of the CURRENT shipped model. Nothing is tuned, calibrated
or retrained in ML-2; the production scoring path, the model artifact and every threshold are untouched.

**Chronological split** (real event timestamps; no shuffling anywhere in the anomaly-detection evaluation):

| Split | Window | Role |
|---|---|---|
| TRAIN | `2026-06-01T00:00:46` → `2026-06-21T00:00:46` (days 0–20) | the exact window the shipped artifact was fitted on (verified in section 3) |
| VALIDATION | `2026-06-21T00:00:46` → `2026-06-26T00:00:46` (days 20–25) | evaluation-only decisions (an operating point, the chronological classifier) |
| TEST | `2026-06-26T00:00:46` → `2026-07-01T04:37:10` | held out from every ML-2 decision |

*Pre-registered rules* (fixed from incident-timing counts before any score was inspected): the validation window is
the **shortest window after TRAIN holding >=1/3 of attack incidents by first-event time**; an attack incident belongs to the split of its first event; events of a validation-born
incident that fall in the test period are **purged** from the TEST evaluation population (they still flow through the
stream so entity state stays causal).

**Scoring paths compared** (same events, same shipped model, same production threshold):

* **Shipped batch (legacy)** – `Detector.fuse()` rank-normalises over the scored population, then the batch `to_risk_100`.
  This is what the README and ML-1 reported. It is *transductive* (uses the evaluated population's own distribution).
* **Frozen batch** – per-signal percentile against the *stored training distributions* (== `Detector.fuse_single`,
  vectorised) with the per-event risk mapping. No test information; the only difference from streaming is the online state.
* **Streaming** – the unmodified production `StreamingScorer.process`, one event at a time in chronological order
  (state update → features → score → record → next). Warm-up uses the TRAIN window only. EWMA profile updates ON (as deployed).

**Metric definitions** (one definition each; see `eval_ml2/metrics.py`):

* *Population* = the evaluated events; *positive* = an attack event; `normal` and `benign_drift` are negatives.
* *Alert* = score ≥ operating threshold; there is **no queue and no de-duplication** anywhere in this report.
* *Precision@1% / Recall@1%* = k = floor(1% × N) highest-scored events **of the evaluated population** (no padded queue);
  precision = TP/k, recall = TP/P (so recall is capped at k/P). When events tie at the cut-off (streaming risk saturates at
  exactly 100.0) the tie-aware *expected* value and the worst/best case are reported; ranking by the continuous fused score has no ties.
* *Operating points*: **production threshold** (shipped ML decision, risk ≥ 99.5023); **Spring 0.99** (anomalyScore ≥ 0.99, read-only
  reference); **validation-derived** (evaluation-only, chosen on VALIDATION only: the 99th percentile of validation scores, and the
  F1-optimal validation threshold). Top-1% ranking performance and threshold performance are reported separately.
* *Incident detected* = ≥ 1 alert among the incident's events inside the population.

**Test discipline.** Decisions are computed from train+validation labels, frozen and hashed, and only then are held-out
labels unsealed — once (`LabelVault`; a second unseal raises). Whole-dataset *diagnostics* (legacy classifier CV, grouped CV,
shortcut analysis) are labelled DIAGNOSTIC and enumerated in the manifest; nothing in the held-out evaluation depends on them.

> **Critical caveat (read this before quoting any number).** ML-2's TEST is held out from every ML-2 decision, but the *shipped
> model's design* — fusion weights, boolean-flag weights, the feature set, the incident-ranking bonus and the production
> threshold — was tuned in earlier phases on days 21–30, which contain this TEST window (ML-1 §3). That history cannot be undone
> without new data or retraining. ML-2 numbers are therefore leakage-safe with respect to **ML-2 procedures**, not with respect to
> the model's design history; a genuinely clean test needs fresh attack instances (ML-3).

## 2. Dataset Split Manifest

Machine-readable copy: `reports/ml2_split_manifest.json`.

| Population | Events | Entities | Attack events | Attack rate | Incidents (any event) | Incidents born here | benign_drift |
|---|---|---|---|---|---|---|---|
| TRAIN | 65850 | 200 | 0 | 0.00% | 0 | 0 | 34 |
| VALIDATION | 17022 | 200 | 287 | 1.69% | 12 | 12 | 60 |
| TEST (time window) | 16476 | 200 | 734 | 4.45% | 29 | 24 | 32 |
| **TEST evaluation population** (after purge) | 16438 | 200 | 696 | 4.23% | 24 | 24 | 32 |
| Legacy days 21–30 (ML-1/README population; NOT held out) | 33498 | 200 | 1021 | 3.05% | 36 | 36 | 92 |

Per attack type:

| Attack type | VAL events | VAL incidents | TEST events | TEST incidents | All events | All incidents |
|---|---|---|---|---|---|---|
| brute_force | 196 | 2 | 424 | 3 | 620 | 5 |
| credential_stuffing | 0 | 0 | 60 | 1 | 60 | 1 |
| impossible_travel | 4 | 4 | 11 | 11 | 15 | 15 |
| lateral_movement | 31 | 1 | 124 | 4 | 155 | 5 |
| device_spoofing | 0 | 0 | 77 | 5 | 77 | 5 |
| low_slow_exfil | 56 | 5 | 0 | 0 | 94 | 5 |

Class distribution:

| Population | Class distribution (events) |
|---|---|
| train | {"normal": 65816, "benign_drift": 34} |
| validation | {"normal": 16675, "brute_force": 196, "benign_drift": 60, "low_slow_exfil": 56, "lateral_movement": 31, "impossible_travel": 4} |
| test_evaluation_population | {"normal": 15710, "brute_force": 424, "lateral_movement": 124, "device_spoofing": 77, "credential_stuffing": 60, "benign_drift": 32, "impossible_travel": 11} |

* **Purge:** 38 events of incident(s) LS000, LS001, LS002, LS003, LS004 (born in VALIDATION, running into the test
  period) are excluded from the TEST evaluation population: {"brute_force": 0, "credential_stuffing": 0, "impossible_travel": 0, "lateral_movement": 0, "device_spoofing": 0, "low_slow_exfil": 38}.
* **Held-out entities (section 9):** 60 entities (18 of them attacked in the evaluation period), seed 20260920.
* **Statistical strength.** VALIDATION holds 12 incidents and TEST holds
  24; no attack type has more than 5 incidents
  (impossible_travel has 15, each a single event), and
  credential_stuffing is ONE incident. All five low_slow_exfil incidents start in VALIDATION, so **TEST contains no low_slow_exfil incident**;
  device_spoofing and credential_stuffing have no VALIDATION incident. The dataset is a single fixed generator draw (seed 42): there is no seed variation
  and no confidence interval. **The available data cannot support a statistically strong validation set;** this is documented, not papered over.

## 3. Leakage Controls

| Stage | Allowed use | Verification / evidence |
|---|---|---|
| TRAIN (fit only) | shipped artifact fitted on exactly the TRAIN window | artifact profiler saw 65,850 events = protocol TRAIN 65,850; calibration curve rows 65,850; max |recomputed − stored| per-signal calibration: baseline 0.00e+00, iforest 0.00e+00, sequence 3.81e-06 |
| VALIDATION (decisions only) | evaluation-only operating points; chronological classifier fit | decisions from VALIDATION scores/labels only, frozen and hashed (`2f51378b7193e4b6…`) before any test label was read; classifier fitted on 52 rows from 12 validation-born incidents |
| TEST (evaluate once) | final metrics | held-out labels unsealed 1× (a second call raises); the purge removes events of validation-born incidents |
| Fusion weights / flag weights / features / ranking bonus | NOT tuned in ML-2 | inherited from the shipped model; **their historical tuning used days 21–30 (contains TEST)** — cannot be undone (see §1 caveat) |
| Production threshold (99.5023) | used as shipped | derived from the top-1% quantile of days 21–30 risk (ML-1) → **not held out from TEST**; validation-derived thresholds are reported next to it |
| Shipped classifier | not evaluated on test | trained on all 36 incidents (all test-period rows included) → no leakage-safe evaluation of the shipped classifier is possible |
| Batch fusion (shipped semantics) | reported as LEGACY | rank-normalises over the evaluated population (transductive); the leakage-safe batch path is 'frozen batch' (train-anchored) |

**Evaluation-only operating points chosen on VALIDATION** (per scoring path; applied unchanged to TEST):

| Path | Validation q99 of fused score | Validation F1-optimal fused threshold | Validation events | Validation attack events |
|---|---|---|---|---|
| shipped_batch_legacy | 0.99294 | 0.98429 | 17022 | 287 |
| frozen_batch | 0.99928 | 0.99422 | 17022 | 287 |
| streaming | 0.99928 | 0.99440 | 17022 | 287 |

**Label-access log** (every read of held-out labels, in order):

| # | Access | Purpose / hash |
|---|---|---|
| 1 | dev_labels |  |
| 2 | decisions_frozen | 2f51378b7193e4b60f67ed11ba19341102a2a5d6b604213abecb5fbc9373d52c |
| 3 | unseal_test | final held-out evaluation of frozen decisions |
| 4 | diagnostic_all_labels | classifier A/B: legacy pool rebuild + incident-grouped CV (whole-dataset incidents) |
| 5 | diagnostic_all_labels | shortcut analysis (whole dataset) |

**Other label reads outside the vault:** the batch and streaming scoring stages never read labels. The parity stage (a separate process) reads labels only to *choose* representative events (first event of each incident, plus seeded-random normal events); it evaluates nothing against them.

**Self-checks:** the vectorised fused/risk mappings equal the production single-event functions
(max |Δ| = 2.22e-16 / 0.00e+00);
the streaming `alert` flag equals `risk ≥ shipped threshold` for every event: **True**;
streaming warm-up scope = TRAIN window only (65,850 events).

## 4. Batch vs Streaming

All three columns score the **same held-out TEST population** with the **same shipped model** and the **same production threshold**. *Difference = streaming − frozen batch* (the leakage-safe comparison); *shipped batch* is the legacy protocol shown for continuity.

**held-out TEST population**

| Metric | Shipped batch (legacy) | Frozen batch | Streaming | Difference (streaming − frozen) |
|---|---|---|---|---|
| PR-AUC (deployed risk score) | 0.9347 | 0.9028 | 0.8381 | -0.0648 |
| ROC-AUC (deployed risk score) | 0.9942 | 0.9936 | 0.9813 | -0.0123 |
| PR-AUC (underlying fused score) | 0.9349 | 0.9353 | 0.8733 | -0.0620 |
| ROC-AUC (underlying fused score) | 0.9942 | 0.9942 | 0.9819 | -0.0123 |
| Alert rate @ production threshold | 0.0117 | 0.0358 | 0.0319 | -0.0039 |
| Precision @ production threshold | 1.0000 | 0.9575 | 0.9504 | -0.0071 |
| Recall @ production threshold | 0.2759 | 0.8089 | 0.7155 | -0.0934 |
| F1 @ production threshold | 0.4324 | 0.8769 | 0.8164 | -0.0606 |
| False-positive rate @ production threshold | 0.0000 | 0.0016 | 0.0017 | 0.0001 |
| False-negative rate @ production threshold | 0.7241 | 0.1911 | 0.2845 | 0.0934 |
| Precision@1% (ranked by fused, no ties) | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| Recall@1% (ranked by fused, no ties) | 0.2356 | 0.2356 | 0.2356 | 0.0000 |
| Precision@1% (deployed risk, tie-aware expected) | 1.0000 | 0.9575 | 0.9504 | -0.0071 |
| Recall@1% (deployed risk, tie-aware expected) | 0.2356 | 0.2256 | 0.2239 | -0.0017 |

**VALIDATION population**

| Metric | Shipped batch (legacy) | Frozen batch | Streaming | Difference (streaming − frozen) |
|---|---|---|---|---|
| PR-AUC (deployed risk score) | 0.8882 | 0.8205 | 0.7493 | -0.0712 |
| ROC-AUC (deployed risk score) | 0.9949 | 0.9944 | 0.9896 | -0.0047 |
| PR-AUC (underlying fused score) | 0.8887 | 0.8877 | 0.8100 | -0.0777 |
| ROC-AUC (underlying fused score) | 0.9949 | 0.9948 | 0.9900 | -0.0048 |
| Alert rate @ production threshold | 0.0084 | 0.0143 | 0.0127 | -0.0016 |
| Precision @ production threshold | 1.0000 | 0.9095 | 0.9120 | 0.0026 |
| Recall @ production threshold | 0.4983 | 0.7700 | 0.6864 | -0.0836 |
| F1 @ production threshold | 0.6651 | 0.8340 | 0.7833 | -0.0507 |
| False-positive rate @ production threshold | 0.0000 | 0.0013 | 0.0011 | -0.0002 |
| False-negative rate @ production threshold | 0.5017 | 0.2300 | 0.3136 | 0.0836 |
| Precision@1% (ranked by fused, no ties) | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| Recall@1% (ranked by fused, no ties) | 0.5923 | 0.5923 | 0.5923 | 0.0000 |
| Precision@1% (deployed risk, tie-aware expected) | 1.0000 | 0.9095 | 0.9120 | 0.0026 |
| Recall@1% (deployed risk, tie-aware expected) | 0.5923 | 0.5387 | 0.5402 | 0.0015 |

**legacy days 21–30 (ML-1 population, NOT held out)**

| Metric | Shipped batch (legacy) | Frozen batch | Streaming | Difference (streaming − frozen) |
|---|---|---|---|---|
| PR-AUC (deployed risk score) | 0.9202 | 0.8791 | 0.7935 | -0.0857 |
| ROC-AUC (deployed risk score) | 0.9947 | 0.9942 | 0.9822 | -0.0120 |
| PR-AUC (underlying fused score) | 0.9204 | 0.9204 | 0.8347 | -0.0857 |
| ROC-AUC (underlying fused score) | 0.9947 | 0.9947 | 0.9826 | -0.0120 |
| Alert rate @ production threshold | 0.0100 | 0.0252 | 0.0221 | -0.0031 |
| Precision @ production threshold | 1.0000 | 0.9443 | 0.9392 | -0.0051 |
| Recall @ production threshold | 0.3281 | 0.7806 | 0.6807 | -0.0999 |
| F1 @ production threshold | 0.4941 | 0.8547 | 0.7893 | -0.0654 |
| False-positive rate @ production threshold | 0.0000 | 0.0014 | 0.0014 | -0.0001 |
| False-negative rate @ production threshold | 0.6719 | 0.2194 | 0.3193 | 0.0999 |
| Precision@1% (ranked by fused, no ties) | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| Recall@1% (ranked by fused, no ties) | 0.3271 | 0.3271 | 0.3271 | 0.0000 |
| Precision@1% (deployed risk, tie-aware expected) | 1.0000 | 0.9443 | 0.9392 | -0.0051 |
| Recall@1% (deployed risk, tie-aware expected) | 0.3271 | 0.3089 | 0.3072 | -0.0017 |

**Score distributions on TEST (median / p90 / p95 / p99 / max):**

| Path | Score | median | p90 | p95 | p99 | max |
|---|---|---|---|---|---|---|
| shipped_batch_legacy | fused | 0.5207 | 0.9076 | 0.9641 | 0.9961 | 0.9991 |
| shipped_batch_legacy | risk | 54.2906 | 95.0374 | 98.2870 | 99.5492 | 100.0000 |
| shipped_batch_legacy | anomaly score | 0.5429 | 0.9504 | 0.9829 | 0.9955 | 1.0000 |
| frozen_batch | fused | 0.5289 | 0.9183 | 0.9745 | 1.0000 | 1.0000 |
| frozen_batch | risk | 55.5558 | 95.6244 | 98.7183 | 100.0000 | 100.0000 |
| frozen_batch | anomaly score | 0.5556 | 0.9562 | 0.9872 | 1.0000 | 1.0000 |
| streaming | fused | 0.5210 | 0.8779 | 0.9611 | 1.0000 | 1.0000 |
| streaming | risk | 54.3215 | 93.1249 | 98.1671 | 100.0000 | 100.0000 |
| streaming | anomaly score | 0.5432 | 0.9312 | 0.9817 | 1.0000 | 1.0000 |

**Streaming vs frozen batch, per event (TEST):** Spearman(fused) = 0.8768, mean |Δfused| = 0.0736, mean signed Δfused = -0.0070, events with |Δrisk| > 1: 79.9%; alerts in both = 519, streaming-only = 5, batch-only = 69.

**Feature parity (streaming vs batch matrices, 33,498 events):** max |Δ| = 0; events with any difference = 0 → the features used by the streaming evaluation are identical to the batch features.

## 5. Score Distribution

**Ceiling saturation (risk and anomalyScore = risk/100, as `api.py` returns it):**

| Path (TEST events) | N | risk = 100 | anomalyScore = 1.0 | risk > 99 | risk > 99.5 | risk > 99.9 | distinct risk values > 99.5 | share of >99.5 tied at 100 |
|---|---|---|---|---|---|---|---|---|
| shipped_batch_legacy | 16438 | 1 | 1 | 481 | 194 | 23 | 194 | 0.005 |
| frozen_batch | 16438 | 588 | 588 | 588 | 588 | 588 | 1 | 1.000 |
| streaming | 16438 | 524 | 524 | 524 | 524 | 524 | 1 | 1.000 |

**Fused score and anomaly-score thresholds (Spring's severity bands are 0.99 / 0.995 / 0.999):**

| Path (TEST) | fused ≥ 0.99 | fused ≥ 0.999 | fused ≥ 1.0 | fused max | anomaly ≥ 0.99 | anomaly ≥ 0.995 | anomaly ≥ 0.999 |
|---|---|---|---|---|---|---|---|
| shipped_batch_legacy | 491 | 3 | 0 | 0.99915 | 481 | 194 | 23 |
| frozen_batch | 600 | 447 | 160 | 1.00000 | 588 | 588 | 588 |
| streaming | 532 | 445 | 160 | 1.00000 | 524 | 524 | 524 |

**Streaming, whole evaluation period (validation + test, 33,498 events):** 740 events have risk exactly 100.0
(anomalyScore 1.0); 1 distinct risk value(s) exist above 99.5.

**Classifier confidence on streaming alerts (n = 740):** median 1.0000, p90 1.0000, p99 1.0000, max 1.0000;
593 ≥ 0.99, 553 ≥ 0.999,
542 equal 1.0 after the API's 3-decimal rounding.

*Observation only — nothing was changed or calibrated.*

## 6. Anomaly Detection Metrics

Detector only (no classifier). **Primary = streaming on the held-out TEST population.** Counts: N = 16,438 events, 696 attack events.

### Streaming (as deployed) — PRIMARY

| Operating point | Alerts | TP | FP | FN | TN | Precision | Recall | F1 | FPR | FNR | Alert rate | Incidents detected |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| production_threshold | 524 | 498 | 26 | 198 | 15716 | 0.9504 | 0.7155 | 0.8164 | 0.00165 | 0.2845 | 3.19% | 14/24 |
| spring_alert_0.99_on_anomaly_score | 524 | 498 | 26 | 198 | 15716 | 0.9504 | 0.7155 | 0.8164 | 0.00165 | 0.2845 | 3.19% | 14/24 |
| validation_q99_operating_point | 438 | 438 | 0 | 258 | 15742 | 1.0000 | 0.6293 | 0.7725 | 0.00000 | 0.3707 | 2.66% | 4/24 |
| validation_f1_optimal_operating_point | 504 | 494 | 10 | 202 | 15732 | 0.9802 | 0.7098 | 0.8233 | 0.00064 | 0.2902 | 3.07% | 12/24 |

* Ranking: PR-AUC 0.8381 / ROC-AUC 0.9813 on the deployed risk score; PR-AUC 0.8733 / ROC-AUC 0.9819 on the underlying fused score.
* **Top-1% ranking performance** (k = 164 events, NOT a queue): by fused score → Precision@1% 1.0000, Recall@1% 0.2356 (maximum possible recall 0.2356); incidents in the top 1%: 3/24.
* By deployed risk, tie-aware: cut-off score 100.000, tie group 524 events (straddles the cut-off); Precision@1% expected 0.9504 (worst 0.8415 / best 1.0000), Recall@1% expected 0.2239 (worst 0.1983 / best 0.2356).

### Frozen batch

| Operating point | Alerts | TP | FP | FN | TN | Precision | Recall | F1 | FPR | FNR | Alert rate | Incidents detected |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| production_threshold | 588 | 563 | 25 | 133 | 15717 | 0.9575 | 0.8089 | 0.8769 | 0.00159 | 0.1911 | 3.58% | 18/24 |
| spring_alert_0.99_on_anomaly_score | 588 | 563 | 25 | 133 | 15717 | 0.9575 | 0.8089 | 0.8769 | 0.00159 | 0.1911 | 3.58% | 18/24 |
| validation_q99_operating_point | 439 | 439 | 0 | 257 | 15742 | 1.0000 | 0.6307 | 0.7736 | 0.00000 | 0.3693 | 2.67% | 5/24 |
| validation_f1_optimal_operating_point | 551 | 541 | 10 | 155 | 15732 | 0.9819 | 0.7773 | 0.8677 | 0.00064 | 0.2227 | 3.35% | 14/24 |

* Ranking: PR-AUC 0.9028 / ROC-AUC 0.9936 on the deployed risk score; PR-AUC 0.9353 / ROC-AUC 0.9942 on the underlying fused score.
* **Top-1% ranking performance** (k = 164 events, NOT a queue): by fused score → Precision@1% 1.0000, Recall@1% 0.2356 (maximum possible recall 0.2356); incidents in the top 1%: 3/24.
* By deployed risk, tie-aware: cut-off score 100.000, tie group 588 events (straddles the cut-off); Precision@1% expected 0.9575 (worst 0.8476 / best 1.0000), Recall@1% expected 0.2256 (worst 0.1997 / best 0.2356).

### Shipped batch (legacy, transductive)

| Operating point | Alerts | TP | FP | FN | TN | Precision | Recall | F1 | FPR | FNR | Alert rate | Incidents detected |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| production_threshold | 192 | 192 | 0 | 504 | 15742 | 1.0000 | 0.2759 | 0.4324 | 0.00000 | 0.7241 | 1.17% | 4/24 |
| spring_alert_0.99_on_anomaly_score | 481 | 480 | 1 | 216 | 15741 | 0.9979 | 0.6897 | 0.8156 | 0.00006 | 0.3103 | 2.93% | 8/24 |
| validation_q99_operating_point | 467 | 466 | 1 | 230 | 15741 | 0.9979 | 0.6695 | 0.8014 | 0.00006 | 0.3305 | 2.84% | 6/24 |
| validation_f1_optimal_operating_point | 565 | 552 | 13 | 144 | 15729 | 0.9770 | 0.7931 | 0.8755 | 0.00083 | 0.2069 | 3.44% | 18/24 |

* Ranking: PR-AUC 0.9347 / ROC-AUC 0.9942 on the deployed risk score; PR-AUC 0.9349 / ROC-AUC 0.9942 on the underlying fused score.
* **Top-1% ranking performance** (k = 164 events, NOT a queue): by fused score → Precision@1% 1.0000, Recall@1% 0.2356 (maximum possible recall 0.2356); incidents in the top 1%: 4/24.
* By deployed risk, tie-aware: cut-off score 99.551, tie group 1 events (does not straddle the cut-off); Precision@1% expected 1.0000 (worst 1.0000 / best 1.0000), Recall@1% expected 0.2356 (worst 0.2356 / best 0.2356).

### VALIDATION population (streaming) — for context, NOT held out

| Operating point | Alerts | TP | FP | FN | TN | Precision | Recall | F1 | FPR | FNR | Alert rate | Incidents detected |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| production_threshold | 216 | 197 | 19 | 90 | 16716 | 0.9120 | 0.6864 | 0.7833 | 0.00114 | 0.3136 | 1.27% | 4/12 |
| spring_alert_0.99_on_anomaly_score | 216 | 197 | 19 | 90 | 16716 | 0.9120 | 0.6864 | 0.7833 | 0.00114 | 0.3136 | 1.27% | 4/12 |
| validation_q99_operating_point | 171 | 171 | 0 | 116 | 16735 | 1.0000 | 0.5958 | 0.7467 | 0.00000 | 0.4042 | 1.00% | 2/12 |
| validation_f1_optimal_operating_point | 200 | 197 | 3 | 90 | 16732 | 0.9850 | 0.6864 | 0.8090 | 0.00018 | 0.3136 | 1.17% | 4/12 |


## 7. Classifier Metrics

The classifier is evaluated separately from the detector. The shipped classifier is never refitted; every fit below is an in-memory scratch classifier
(same class, same hyper-parameters). **The old row-level result is kept and clearly labelled; it is not hidden.**

**Pool used by the shipped methodology (rebuilt exactly, matches the shipped classifier's stored feature means: True):**
141 rows from 36 incidents, rows per class {"lateral_movement": 30, "brute_force": 30, "low_slow_exfil": 30, "device_spoofing": 30, "impossible_travel": 15, "credential_stuffing": 6}, incidents per class {"brute_force": 5, "credential_stuffing": 1, "impossible_travel": 15, "lateral_movement": 5, "device_spoofing": 5, "low_slow_exfil": 5};
all rows in the shipped days-21–30 window: True; rows in TRAIN: 0; rows inside the ML-2 TEST population: 89.

| Methodology | Accuracy | Macro P | Macro R | Macro F1 | Weighted F1 | Rows | Classes with support |
|---|---|---|---|---|---|---|---|
| A. LEGACY row-level 5-fold CV (DIAGNOSTIC; incident leakage) | 0.986 | 0.984 | 0.983 | 0.983 | 0.986 | 141 | all 6 |
| B1. Incident-grouped leave-one-incident-out (DIAGNOSTIC) | 0.851 | 0.702 | 0.744 | 0.712 | 0.830 | 141 | all 6 |
| B2. Incident-grouped 5-fold StratifiedGroupKFold (DIAGNOSTIC) | 0.901 | 0.744 | 0.789 | 0.759 | 0.883 | 141 | all 6 |
| C. Chronological: fit on VALIDATION incidents → TEST (LEAKAGE-SAFE) | 0.565 | 0.393 | 0.401 | 0.323 | 0.637 | 696 | brute_force, credential_stuffing, impossible_travel, lateral_movement, device_spoofing |
| C'. same, restricted to classes seen in training | 0.703 | 0.706 | 0.669 | 0.590 | 0.804 | 559 | brute_force, impossible_travel, lateral_movement |

*A and B use every incident, so they compare validation methodologies on identical data; only C is a held-out result.*
Class `credential_stuffing` has one incident; in B1 it can never be learned when that incident is held out.

### Per-class results

**A. Legacy row-level CV**

| Class | Precision | Recall | F1 | Support | Predicted |
|---|---|---|---|---|---|
| brute_force | 0.968 | 1.000 | 0.984 | 30 | 31 |
| credential_stuffing | 1.000 | 1.000 | 1.000 | 6 | 6 |
| impossible_travel | 0.933 | 0.933 | 0.933 | 15 | 15 |
| lateral_movement | 1.000 | 1.000 | 1.000 | 30 | 30 |
| device_spoofing | 1.000 | 1.000 | 1.000 | 30 | 30 |
| low_slow_exfil | 1.000 | 0.967 | 0.983 | 30 | 29 |

| true \ pred | brute_force | credential_stuffing | impossible_travel | lateral_movement | device_spoofing | low_slow_exfil |
|---|---|---|---|---|---|---|
| brute_force | 30 | 0 | 0 | 0 | 0 | 0 |
| credential_stuffing | 0 | 6 | 0 | 0 | 0 | 0 |
| impossible_travel | 1 | 0 | 14 | 0 | 0 | 0 |
| lateral_movement | 0 | 0 | 0 | 30 | 0 | 0 |
| device_spoofing | 0 | 0 | 0 | 0 | 30 | 0 |
| low_slow_exfil | 0 | 0 | 1 | 0 | 0 | 29 |

**B1. Incident-grouped (leave-one-incident-out)**

| Class | Precision | Recall | F1 | Support | Predicted |
|---|---|---|---|---|---|
| brute_force | 0.900 | 0.600 | 0.720 | 30 | 20 |
| credential_stuffing | 0.000 | 0.000 | 0.000 | 6 | 0 |
| impossible_travel | 0.609 | 0.933 | 0.737 | 15 | 23 |
| lateral_movement | 0.824 | 0.933 | 0.875 | 30 | 34 |
| device_spoofing | 1.000 | 1.000 | 1.000 | 30 | 30 |
| low_slow_exfil | 0.882 | 1.000 | 0.938 | 30 | 34 |

| true \ pred | brute_force | credential_stuffing | impossible_travel | lateral_movement | device_spoofing | low_slow_exfil |
|---|---|---|---|---|---|---|
| brute_force | 18 | 0 | 6 | 6 | 0 | 0 |
| credential_stuffing | 1 | 0 | 1 | 0 | 0 | 4 |
| impossible_travel | 1 | 0 | 14 | 0 | 0 | 0 |
| lateral_movement | 0 | 0 | 2 | 28 | 0 | 0 |
| device_spoofing | 0 | 0 | 0 | 0 | 30 | 0 |
| low_slow_exfil | 0 | 0 | 0 | 0 | 0 | 30 |

**B2. Incident-grouped 5-fold**

| Class | Precision | Recall | F1 | Support | Predicted |
|---|---|---|---|---|---|
| brute_force | 0.960 | 0.800 | 0.873 | 30 | 25 |
| credential_stuffing | 0.000 | 0.000 | 0.000 | 6 | 0 |
| impossible_travel | 0.682 | 1.000 | 0.811 | 15 | 22 |
| lateral_movement | 1.000 | 0.933 | 0.966 | 30 | 28 |
| device_spoofing | 0.938 | 1.000 | 0.968 | 30 | 32 |
| low_slow_exfil | 0.882 | 1.000 | 0.938 | 30 | 34 |

**C. Chronological, leakage-safe** — trained on 52 rows ({"low_slow_exfil": 30, "brute_force": 12, "lateral_movement": 6, "impossible_travel": 4}) from
12 validation-born incidents; TEST attack events evaluated: 696.
Classes present in TEST but absent from training (recall 0 by construction): credential_stuffing, device_spoofing.

| Class | Precision | Recall | F1 | Support | Predicted |
|---|---|---|---|---|---|
| brute_force | 0.961 | 0.755 | 0.845 | 424 | 333 |
| credential_stuffing | 0.000 | 0.000 | 0.000 | 60 | 0 |
| impossible_travel | 0.050 | 0.727 | 0.094 | 11 | 160 |
| lateral_movement | 0.956 | 0.524 | 0.677 | 124 | 68 |
| device_spoofing | 0.000 | 0.000 | 0.000 | 77 | 0 |
| low_slow_exfil | 0.000 | 0.000 | 0.000 | 0 | 135 |

| true \ pred | brute_force | credential_stuffing | impossible_travel | lateral_movement | device_spoofing | low_slow_exfil |
|---|---|---|---|---|---|---|
| brute_force | 320 | 0 | 1 | 0 | 0 | 103 |
| credential_stuffing | 3 | 0 | 57 | 0 | 0 | 0 |
| impossible_travel | 1 | 0 | 8 | 0 | 0 | 2 |
| lateral_movement | 5 | 0 | 50 | 65 | 0 | 4 |
| device_spoofing | 4 | 0 | 44 | 3 | 0 | 26 |
| low_slow_exfil | 0 | 0 | 0 | 0 | 0 | 0 |

**C'. Restricted to classes the training set could know** (brute_force, impossible_travel, lateral_movement, low_slow_exfil): accuracy 0.703, macro F1 0.590, weighted F1 0.804 on 559 events.

### D. Shipped classifier on streaming alerts (TEST)

* **False alerts** (leakage-free — the shipped classifier never had a 'normal' class): 26 false alerts; predicted class {"impossible_travel": 20, "brute_force": 3, "lateral_movement": 2, "low_slow_exfil": 1};
  confidence median 0.986, p90 0.996; 24 of them at confidence ≥ 0.65 (worded "likely …" in the explanation).
* **True alerts** (498): in-sample — the classifier was trained on all 36 incidents. Confidence median 1.000; class accuracy 0.962 is **not** a performance claim.

## 8. Attack-Specific Metrics

Streaming, as deployed. *Detected* = alert at the production threshold (event level); *top-1%* = inside the population's top 1% by fused score. Precision is only meaningful for the detector as a whole (an alert cannot be attributed to a type without the classifier), so it is not split by type. No ranking of attack types is implied.

**held-out TEST population**

| Attack type | Events | Incidents | Detected (prod. thr.) | Missed | Detection rate | Incidents detected | In top 1% | Top-1% rate | Incidents in top 1% | Median risk | ROC-AUC vs negatives (fused) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| brute_force | 424 | 3 | 421 | 3 | 99.3% | 3/3 | 161 | 38.0% | 2/3 | 100.00 | 0.9999 |
| credential_stuffing | 60 | 1 | 58 | 2 | 96.7% | 1/1 | 3 | 5.0% | 1/1 | 100.00 | 0.9999 |
| impossible_travel | 11 | 11 | 9 | 2 | 81.8% | 9/11 | 0 | 0.0% | 0/11 | 100.00 | 0.9994 |
| lateral_movement | 124 | 4 | 10 | 114 | 8.1% | 1/4 | 0 | 0.0% | 0/4 | 98.13 | 0.9784 |
| device_spoofing | 77 | 5 | 0 | 77 | 0.0% | 0/5 | 0 | 0.0% | 0/5 | 92.20 | 0.8717 |
| low_slow_exfil | 0 | 0 | – | – | – | – | – | – | – | – | – |

**VALIDATION population (contains the low_slow_exfil incidents; NOT held out)**

| Attack type | Events | Incidents | Detected (prod. thr.) | Missed | Detection rate | Incidents detected | In top 1% | Top-1% rate | Incidents in top 1% | Median risk | ROC-AUC vs negatives (fused) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| brute_force | 196 | 2 | 195 | 1 | 99.5% | 2/2 | 170 | 86.7% | 2/2 | 100.00 | 1.0000 |
| credential_stuffing | 0 | 0 | – | – | – | – | – | – | – | – | – |
| impossible_travel | 4 | 4 | 2 | 2 | 50.0% | 2/4 | 0 | 0.0% | 0/4 | 99.50 | 0.9992 |
| lateral_movement | 31 | 1 | 0 | 31 | 0.0% | 0/1 | 0 | 0.0% | 0/1 | 97.78 | 0.9847 |
| device_spoofing | 0 | 0 | – | – | – | – | – | – | – | – | – |
| low_slow_exfil | 56 | 5 | 0 | 56 | 0.0% | 0/5 | 0 | 0.0% | 0/5 | 94.97 | 0.9575 |

**Score distribution per type (TEST, streaming):**

| Attack type | risk min | risk median | risk p90 | risk p99 | risk max | fused median | Alerts |
|---|---|---|---|---|---|---|---|
| brute_force | 98.07 | 100.00 | 100.00 | 100.00 | 100.00 | 1.0000 | 421 |
| credential_stuffing | 98.99 | 100.00 | 100.00 | 100.00 | 100.00 | 0.9989 | 58 |
| impossible_travel | 99.00 | 100.00 | 100.00 | 100.00 | 100.00 | 0.9957 | 9 |
| lateral_movement | 79.37 | 98.13 | 99.00 | 100.00 | 100.00 | 0.9602 | 10 |
| device_spoofing | 36.22 | 92.20 | 97.41 | 99.00 | 99.00 | 0.8655 | 0 |

**Same table, frozen batch (TEST) — detection at the production threshold:**

| Attack type | Events | Detected | Detection rate | Incidents detected | In top 1% |
|---|---|---|---|---|---|
| brute_force | 424 | 421 | 99.3% | 3/3 | 161 |
| credential_stuffing | 60 | 58 | 96.7% | 1/1 | 3 |
| impossible_travel | 11 | 10 | 90.9% | 10/11 | 0 |
| lateral_movement | 124 | 74 | 59.7% | 4/4 | 0 |
| device_spoofing | 77 | 0 | 0.0% | 0/5 | 0 |

## 9. Entity Generalization

* **A. Known-entity chronological test** = every other section of this report (all 200 entities appear in TRAIN, the model holds a profile for each).
* **B. Held-out-entity experiment (PARTIAL — read the limitation):** 60 entities (18 attacked) had their per-entity profile **removed**
  (they fall back to the `entity_type` peer prior), their training events were **excluded** from the warm-up (so their extractor history and the shared
  counters never saw them), and they are streamed cold from the start of VALIDATION.

| Group (TEST population) | Events | Attack events | PR-AUC (fused) | ROC-AUC (fused) | Alerts | TP | FP | Precision | Recall | Incidents detected |
|---|---|---|---|---|---|---|---|---|---|---|
| main_run__known_entities_(non-held-out) | 10375 | 301 | 0.7055 | 0.9627 | 162 | 151 | 11 | 0.932 | 0.502 | 9/15 |
| main_run__held_out_entities_(profile+state KNOWN to the model) | 6063 | 395 | 0.9716 | 0.9971 | 362 | 347 | 15 | 0.959 | 0.878 | 6/10 |
| heldout_run__held_out_entities_(profile+state REMOVED) | 6063 | 395 | 0.9723 | 0.9970 | 356 | 346 | 10 | 0.972 | 0.876 | 6/10 |

Normal-event risk for the held-out entities (TEST): with state known — median 52.57, p90 89.17, p99 98.75;
with state removed — median 49.20, p90 89.34, p99 98.64.

**Limitations (not a clean held-out-entity generalisation test):**

* PARTIAL held-out: the entity's own profile (per-entity mean/var/n) and extractor history were removed and its warm-up events were excluded from the shared counters.
* The GLOBAL components (Isolation Forest, sequence autoencoder, StandardScaler, calibration curves, peer priors) of the shipped artifact were fitted on all 200 entities' training traffic and cannot be un-fitted without retraining, which ML-2 forbids. This is a cold-start experiment, NOT a clean held-out-entity generalisation test.

Held-out entity IDs are listed in `reports/ml2_split_manifest.json`. Group sizes are small; treat differences as descriptive.

## 10. API/Feature Parity

Representative events (19: first event of the first incident of every type + normal user/service/device events + normal events with commands) are shown in
several representations, each processed from an identical private copy of the causal state as of just before the event, with the profiler frozen
so differences are purely representational. **V0** = training/streaming representation (the CSV row); **V1** entity_type forced to `user` (as `api.py` does);
**V2** the platform's `sessionDurationMinutes` read as seconds; **V3** the platform's space-separated `commandSequence`; **V4** the real `api._canonical_event` on a platform-style payload.
(Streaming-vs-training feature identity is measured in §4.) Not fixed in ML-2.

| Divergence vs training representation (V0) | Events | max L∞ feature diff | mean |Δrisk| | max |Δrisk| | Alert flips | Features changed (count of events) |
|---|---|---|---|---|---|---|
| V1_entity_type_user | 19 | 0.833 | 12.384 | 50.584 | 0 | peer_resource_deviation (10) |
| V2_minutes_as_seconds | 19 | 12.905 | 14.132 | 55.413 | 0 | session_duration_zscore (19) |
| V3_space_separated_commands | 19 | 5.000 | 4.836 | 29.357 | 0 | cmd_len (9), cmd_priv_count (7), cmd_bigram_surprise (7) |
| V4_full_api_path | 19 | 12.905 | 19.915 | 57.997 | 0 | session_duration_zscore (19), peer_resource_deviation (10), cmd_len (9), cmd_priv_count (7), cmd_bigram_surprise (7) |

Per event (Δ = risk under the representation − risk under V0):

| Sample | True entity_type | Label | V0 risk | Δ V1 (type→user) | Δ V2 (min→s) | Δ V3 (cmd sep.) | Δ V4 (full API) | Features changed by V4 |
|---|---|---|---|---|---|---|---|---|
| attack:low_slow_exfil | user | low_slow_exfil | 87.50 | 0.00 | 0.01 | -0.11 | -0.10 | session_duration_zscore, cmd_len |
| attack:lateral_movement | service_account | lateral_movement | 97.81 | -0.03 | -2.63 | -0.60 | -8.06 | peer_resource_deviation, session_duration_zscore, cmd_len, cmd_priv_count |
| attack:impossible_travel | user | impossible_travel | 99.00 | 0.00 | 0.00 | 0.00 | 0.00 | session_duration_zscore |
| attack:brute_force | service_account | brute_force | 100.00 | 0.00 | 0.00 | 0.00 | 0.00 | peer_resource_deviation, session_duration_zscore |
| attack:device_spoofing | service_account | device_spoofing | 98.84 | 0.07 | 0.00 | 0.00 | 0.07 | peer_resource_deviation, session_duration_zscore |
| normal:user:2 | user | normal | 93.09 | 0.00 | -15.84 | 1.50 | -1.05 | session_duration_zscore, cmd_len, cmd_priv_count, cmd_bigram_surprise |
| normal:user:3 | user | normal | 62.78 | 0.00 | 1.27 | 22.32 | 22.37 | session_duration_zscore, cmd_len, cmd_priv_count, cmd_bigram_surprise |
| normal:service_account:5 | service_account | normal | 26.77 | 38.45 | 33.09 | 0.00 | 46.00 | peer_resource_deviation, session_duration_zscore |
| normal:edge_device:9 | edge_device | normal | 31.02 | 50.58 | 55.41 | 0.00 | 57.57 | peer_resource_deviation, session_duration_zscore |
| normal:edge_device:8 | edge_device | normal | 75.65 | 5.78 | 6.93 | 0.00 | 10.01 | peer_resource_deviation, session_duration_zscore |
| normal:service_account:4 | service_account | normal | 33.67 | 46.22 | 43.28 | 0.00 | 50.44 | peer_resource_deviation, session_duration_zscore |
| normal:edge_device:7 | edge_device | normal | 34.81 | 47.09 | 55.02 | 0.00 | 57.66 | peer_resource_deviation, session_duration_zscore |
| normal:user:12 | user | normal | 77.83 | 0.00 | 0.42 | -1.31 | -0.26 | session_duration_zscore, cmd_len, cmd_priv_count, cmd_bigram_surprise |
| normal:user:0 | user | normal | 81.45 | 0.00 | 0.06 | -23.06 | -22.45 | session_duration_zscore, cmd_len, cmd_priv_count, cmd_bigram_surprise |
| attack:credential_stuffing | service_account | credential_stuffing | 98.99 | 0.00 | 0.00 | 0.00 | 0.00 | peer_resource_deviation, session_duration_zscore |
| normal:user:10 | user | normal | 39.47 | 0.00 | 0.81 | 29.36 | 30.66 | session_duration_zscore, cmd_len, cmd_bigram_surprise |
| normal:user:11 | user | normal | 92.75 | 0.00 | 0.05 | 0.93 | 0.94 | session_duration_zscore, cmd_len, cmd_priv_count, cmd_bigram_surprise |
| normal:service_account:6 | service_account | normal | 23.70 | 47.06 | 53.66 | 0.00 | 58.00 | peer_resource_deviation, session_duration_zscore |
| normal:user:1 | user | normal | 76.61 | 0.00 | 0.02 | 12.71 | 12.74 | session_duration_zscore, cmd_len, cmd_priv_count, cmd_bigram_surprise |

**Warm-up scope.** `api.py` replays all 30 days (including every attack incident) before serving; `run_realtime.py`'s replay path uses the TRAIN window only. The first event of every
incident is presented as a *new* event arriving the day after each state's last event (same clock time), so no state is fed an event from its own future. "Causal as-of" is the state the streaming
evaluation actually had at the event's own time; it is **not comparable** to the two shifted columns (different gap since the entity's last event and different window contents), so compare the TRAIN-only and all-days columns with each other. Profiler frozen. The states also differ in how much *normal* history they hold, not only attack history:

| Attack type (first event of each incident) | Incidents | Mean risk: causal as-of | Mean risk: TRAIN-only state | Mean risk: all-days state (api.py) | Alerts causal | Alerts TRAIN-only | Alerts all-days | Novelty flag fires causal | …TRAIN-only | …all-days |
|---|---|---|---|---|---|---|---|---|---|---|
| brute_force | 5 | 99.18 | 99.59 | 99.59 | 1/5 | 3/5 | 3/5 | 5/5 | 5/5 | 0/5 |
| credential_stuffing | 1 | 98.99 | 100.00 | 100.00 | 0/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 |
| impossible_travel | 15 | 99.80 | 99.80 | 99.51 | 12/15 | 12/15 | 8/15 | 15/15 | 15/15 | 4/15 |
| lateral_movement | 5 | 97.92 | 98.59 | 98.66 | 0/5 | 0/5 | 2/5 | 5/5 | 5/5 | 0/5 |
| device_spoofing | 5 | 98.93 | 99.80 | 97.65 | 0/5 | 4/5 | 0/5 | 5/5 | 5/5 | 0/5 |
| low_slow_exfil | 5 | 93.84 | 96.26 | 99.19 | 0/5 | 0/5 | 2/5 | 5/5 | 5/5 | 0/5 |

State content an all-days warm-up holds that a TRAIN-only warm-up does not: 5 extra known fingerprints over 5 entities,
784 extra known IPs over 158 entities, 123 extra known resources over 41 entities,
33,498 extra events in entity counters; entries that exist only because of attack events: {"fingerprints": 5, "ips": 67, "resources": 91}.

Code facts (verified by reading the source): api.py_entity_type: hard-coded 'user' in _canonical_event; api.py_session_duration: reads sessionDurationMinutes into session_duration (training data is in seconds); api.py_commands: reads commandSequence verbatim; features.py splits on '|'; api.py_warmup: StreamingScorer.warmup(load_events(events.csv)) = ALL events (all 30 days incl. attacks); run_realtime.py_warmup_replay_path: warm = events[ts < cut] (TRAIN window only); run_realtime.py_warmup_live_source_path: scorer.warmup(events) = ALL events; platform_simulator_payload: sessionDurationMinutes / space-separated commandSequence (frontend/src/pages/Simulator.tsx).

## 11. Dataset Shortcut Analysis

DIAGNOSTIC; the dataset is not modified. Each field below is a raw, history-free, per-event value; `ORACLE_*` fields use the generator's own entity
profile (`entity_profiles.json`), which the detector never sees. AUC strength = max(AUC, 1−AUC); per-attack columns are attack type vs normal.

| Single raw field (TEST) | AUC (attack vs rest) | brute_force | credential_s | impossible_t | lateral_move | device_spoof | low_slow_exf | best 1-threshold rule | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| log_gap_since_prev_event_s | 0.891 | 0.99 | 0.56 | 0.66 | 0.85 | 0.75 | n/a | x <= 3.258 | 0.649 | 0.614 | 0.631 |
| public_ip | 0.855 | 1.00 | 1.00 | 1.00 | 0.50 | 0.50 | n/a | x >= 1 | 0.988 | 0.711 | 0.827 |
| foreign_city | 0.855 | 1.00 | 1.00 | 1.00 | 0.50 | 0.50 | n/a | x >= 1 | 0.988 | 0.711 | 0.827 |
| ORACLE_city_differs_from_entity_home | 0.846 | 0.99 | 0.99 | 0.99 | 0.51 | 0.51 | n/a | x >= 1 | 0.629 | 0.711 | 0.668 |
| ORACLE_ip_outside_entity_pool | 0.844 | 0.99 | 0.99 | 0.99 | 0.51 | 0.51 | n/a | x >= 1 | 0.582 | 0.711 | 0.640 |
| failed_auth | 0.836 | 0.99 | 0.99 | 0.51 | 0.51 | 0.51 | n/a | x >= 1 | 0.596 | 0.693 | 0.641 |
| session_duration_s | 0.787 | 0.99 | 0.98 | 0.94 | 0.76 | 0.51 | n/a | x <= 1.2 | 0.748 | 0.542 | 0.628 |
| hour_of_day | 0.654 | 0.67 | 0.80 | 0.51 | 0.71 | 0.59 | n/a | x >= 12.07 | 0.081 | 0.881 | 0.148 |
| is_weekend | 0.637 | 0.71 | 0.67 | 0.53 | 0.64 | 0.52 | n/a | x >= 1 | 0.074 | 0.616 | 0.132 |
| ORACLE_resource_outside_role_pool | 0.588 | n/a | n/a | n/a | 1.00 | n/a | n/a | x >= 1 | 0.795 | 0.178 | 0.291 |
| command_contains_sudo | 0.570 | 0.52 | 0.52 | 0.52 | 0.98 | 0.52 | n/a | x >= 1 | 0.172 | 0.178 | 0.175 |
| off_hours_band_22_to_05 | 0.566 | 0.58 | 0.58 | 0.51 | 0.58 | 0.56 | n/a | x <= 0 | 0.049 | 0.964 | 0.093 |

**One-line rules built only from raw fields** (R4 additionally uses generator-profile data the detector never sees):

| One-line rule (TEST) | Alerts | Precision | Recall | brute_force | credential_s | impossible_t | lateral_move | device_spoof | low_slow_exf |
|---|---|---|---|---|---|---|---|---|---|
| R1: public_ip OR failed_auth | 828 | 0.598 | 0.711 | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% | – |
| R2: R1 OR foreign_city | 828 | 0.598 | 0.711 | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% | – |
| R3: R2 OR command_contains_sudo OR (sensitive_resource AND off_hours_band) | 1540 | 0.402 | 0.889 | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | – |
| R4 (uses generator profile): R3 OR fingerprint_differs_from_profile | 1617 | 0.430 | 1.000 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | – |

For comparison, what the production detector alerts on in the same population:

| Detector (streaming, production threshold, TEST) | brute_force | credential_s | impossible_t | lateral_move | device_spoof | low_slow_exf |
|---|---|---|---|---|---|---|
| detection rate | 99.3% | 96.7% | 81.8% | 8.1% | 0.0% | – |

Interpretation guide: a near-1.0 AUC or a one-line rule that flags an attack type as well as the detector means this type can be separated by a generator artifact
(e.g. attackers use public IPs while all normal traffic uses private ranges; every brute-force event is a failed authentication from a fresh random city;
low_slow_exfil is written only in 00–04 / 22–23 hours) — so high detection of that type does not by itself demonstrate behavioural generalisation.

## 12. Reproducibility

The whole evaluation (batch scoring, both streaming runs, parity, assembly) was executed **twice** as independent process trees (run A and run B, single-threaded numerics:
`OMP/MKL/OPENBLAS_NUM_THREADS=1`, `torch.set_num_threads(1)`).

| Environment | Value |
|---|---|
| python | 3.14.7 |
| platform | Windows-11-10.0.26200-SP0 |
| machine | AMD64 |
| cpu_count | 8 |
| numpy | 2.5.3 |
| pandas | 3.0.6 |
| scipy | 1.18.1 |
| sklearn | 1.9.1 |
| torch | 2.14.0+cpu |
| lightgbm | 4.7.0 |
| shap | unavailable (ModuleNotFoundError) |
| joblib | 1.6.0 |
| fastapi | 0.141.1 |
| pydantic | 2.13.5 |

* **Seeds:** {"eval_seed": 20260920, "production_seed(config.RANDOM_SEED)": 42, "lightgbm_random_state": 42, "torch": "inference only (no sampling); torch threads=1", "numeric_threads": "OMP/MKL/OPENBLAS = 1"}
* **Model artifact:** SHA-256 `381ae379ae1c5a7c3b4ac38f3df039c1b0de3268889f7df344670510de861684` (md5 `c70052a735ac63feb57553ad80b16c29`) — unchanged before/after.
* **Dataset MD5:** {"events.csv": "e0f53a92ab3490a84070a82dae876f29", "labels.csv": "3a7c6fb15bd7b8f12d5178391af918a9", "entity_profiles.json": "a6638bb4fd2d56b68b1c94cfe976bdf1"}
* **Evaluation configuration:** SHA-256 `455cce4e18c392267308ba50b1d230154edfa491656b10f975e5f15f11d92697`; frozen decisions SHA-256 `2f51378b7193e4b60f67ed11ba19341102a2a5d6b604213abecb5fbc9373d52c`.
* **Evaluation source hashes at the time the metrics were computed:** {"__init__.py": "8a565ea6ee7a\u2026", "assemble.py": "a23431246fb6\u2026", "classifier_eval.py": "3ad2afea805d\u2026", "common.py": "dc3a0634a445\u2026", "compare_runs.py": "1f481fac48ee\u2026", "compose.py": "4507daa41898\u2026", "findings.py": "b93db10f138b\u2026", "metrics.py": "300825496e6a\u2026", "parity.py": "810f4b03a6db\u2026", "protocol.py": "217a85f3e51b\u2026", "report.py": "9a41c9c2c249\u2026", "report_more.py": "2b4600dd3aeb\u2026", "run.py": "90411a4d7f85\u2026", "scoring.py": "eb0d7d1fe962\u2026", "shortcuts.py": "e36adde583da\u2026"}
* **Modules edited after the metrics were computed:** `findings.py`, `report_more.py` (the metric-producing modules `scoring`, `protocol`, `metrics`, `classifier_eval`, `parity`, `shortcuts`, `assemble`, `common`, `run` are listed as unchanged unless named here; report-rendering modules only change wording, not numbers — all numbers are read from `reports/ml2_metrics.json`).* 1.9.0 (load emits a version warning under the installed version).

**Run A vs run B.** 9,565 metric values compared with exact equality → **0 differ**.
Raw score arrays were compared element by element (max |difference|; wall-clock latency excluded). Everything bit-identical: **True**.

| File | Array | Shape | Max abs difference | Elements different | Bit-identical |
|---|---|---|---|---|---|
| batch.npz | event_id | [99348] | 0.0 | 0 | True |
| batch.npz | raw_baseline | [99348] | 0.0 | 0 | True |
| batch.npz | raw_iforest | [99348] | 0.0 | 0 | True |
| batch.npz | raw_sequence | [99348] | 0.0 | 0 | True |
| batch.npz | fused_union | [99348] | 0.0 | 0 | True |
| batch.npz | risk_union | [99348] | 0.0 | 0 | True |
| batch.npz | fused_pct | [99348] | 0.0 | 0 | True |
| batch.npz | risk_event | [99348] | 0.0 | 0 | True |
| batch.npz | lowconf | [99348] | 0.0 | 0 | True |
| batch.npz | features | [99348, 35] | 0.0 | 0 | True |
| stream_main.npz | event_id | [33498] | 0.0 | 0 | True |
| stream_main.npz | risk | [33498] | 0.0 | 0 | True |
| stream_main.npz | fused | [33498] | 0.0 | 0 | True |
| stream_main.npz | alert | [33498] | 0.0 | 0 | True |
| stream_main.npz | conf | [33498] | 0.0 | 0 | True |
| stream_main.npz | raw_baseline | [33498] | 0.0 | 0 | True |
| stream_main.npz | raw_iforest | [33498] | 0.0 | 0 | True |
| stream_main.npz | raw_sequence | [33498] | 0.0 | 0 | True |
| stream_main.npz | features | [33498, 35] | 0.0 | 0 | True |
| stream_heldout.npz | event_id | [11936] | 0.0 | 0 | True |
| stream_heldout.npz | risk | [11936] | 0.0 | 0 | True |
| stream_heldout.npz | fused | [11936] | 0.0 | 0 | True |
| stream_heldout.npz | alert | [11936] | 0.0 | 0 | True |
| stream_heldout.npz | conf | [11936] | 0.0 | 0 | True |
| stream_heldout.npz | raw_baseline | [11936] | 0.0 | 0 | True |
| stream_heldout.npz | raw_iforest | [11936] | 0.0 | 0 | True |
| stream_heldout.npz | raw_sequence | [11936] | 0.0 | 0 | True |
| stream_heldout.npz | features | [11936, 35] | 0.0 | 0 | True |

Production files hashed before and after every stage of both runs: {"A/batch": true, "B/batch": true, "A/stream_main": true, "B/stream_main": true, "A/stream_heldout": true, "B/stream_heldout": true, "A/parity": true, "B/parity": true, "A/assemble": true, "B/assemble": true}.

## 13. Findings

**F1 — Streaming and frozen-batch scoring diverge on the held-out population.** Same model, events and threshold: PR-AUC on the deployed risk score is
0.8381 streaming vs 0.9028 frozen batch (Δ -0.0648); alert rate at the production threshold
3.19% vs 3.58%; precision 0.9504 vs 0.9575; recall 0.7155 vs 0.8089;
incidents detected 14/24 vs 18/24. Per-event fused-score Spearman between the two paths is
0.8768; the features fed to both are identical (max |Δ| 0) and the model is the same artifact, so the only remaining difference between the paths is the online state
(the per-entity EWMA baseline update inside `StreamingScorer.process`). ML-2 did not re-run an EWMA-off streaming diagnostic; the ML-1 audit did, and it reproduced the frozen scores to within 0.01 risk points.

**F2 — The deployed risk/anomaly score saturates.** On the streaming path 524 of 16,438 TEST events have risk exactly 100.0 (anomalyScore 1.0) and
1 distinct risk value(s) exist above 99.5 (100.0% of all values above 99.5 are that single value). Consequently the score cannot rank alerts; the tie group straddles the top-1% cut-off
(tie-aware Precision@1% expected 0.9504, worst 0.8415, best 1.0000),
and Spring's severity bands (0.99 / 0.995 / 0.999) receive 524 / 524 / 524 events — the same number for all three, so the bands cannot discriminate. The underlying fused score is continuous (fused ≥ 1.0 for 160 events).

**F3 — Ranking performance and threshold performance are different questions.** Top-1% by fused score (k = 164, no queue): Precision@1% 1.0000,
Recall@1% 0.2356 (cap 0.2356 because k < number of attack events), incidents inside the top 1%: 3/24; attack types present in the top 1% (events): brute_force 161, credential_stuffing 3.
At the shipped production threshold: 524 alerts, TP 498, FP 26, FN 198, TN 15716 — precision 0.9504, recall 0.7155, F1 0.8164, incidents 14/24.
With the two evaluation-only VALIDATION-derived thresholds applied to TEST: q99 → precision 1.0000 / recall 0.6293 / incidents 4/24; F1-optimal → precision 0.9802 / recall 0.7098 / incidents 12/24.

**F4 — The legacy headline and the leakage-safe streaming numbers describe different things.** Shipped batch (legacy protocol, days 21–30, transductive): PR-AUC 0.9202, ROC-AUC 0.9947, production-threshold precision 1.0000 / recall 0.3281 / alert rate 1.00%.
On the held-out TEST population the same shipped model, streamed as deployed: PR-AUC 0.8381, ROC-AUC 0.9813, precision 0.9504 / recall 0.7155 / alert rate 3.19%.
Shipped batch on TEST (same population as the streaming numbers): PR-AUC 0.9347, precision 1.0000 / recall 0.2759 / alert rate 1.17%. The populations differ (TEST has 4.23% attack events vs 3.05% in days 21–30 and no low_slow_exfil), so the difference is not attributable to the scoring path alone. The same numeric threshold (99.5023) yields alert rates of 1.17% (shipped batch), 3.58% (frozen batch) and 3.19% (streaming) on the same events: the number has no path-independent meaning.

**F5 — Row-level classifier CV was inflated by incident leakage.** Same 141-row pool: legacy row-level CV macro-F1 0.983 (accuracy 0.986) vs incident-grouped leave-one-incident-out macro-F1 0.712 (accuracy 0.851).
The chronological leakage-safe experiment (fit on 52 validation-incident rows, evaluated on 696 held-out TEST events) gives macro-F1 0.323 / weighted-F1 0.637;
classes present in TEST but absent from validation (credential_stuffing, device_spoofing) cannot be predicted (recall 0 by construction). Restricted to the classes it could learn: macro-F1 0.590.

**F6 — The shipped classifier assigns an attack type, with high confidence, to false alerts.** 26 TEST false alerts: predicted classes {'impossible_travel': 20, 'brute_force': 3, 'lateral_movement': 2, 'low_slow_exfil': 1}, confidence median 0.986,
24 at ≥ 0.65 (the explanation words these "likely …"). It has no 'normal' class, so this is expected by construction, and it is leakage-free because normal events were never in its training pool.

**F7 — Attack-specific detection at the production threshold (TEST, streaming; descriptive, no ranking).** Zero events alerted: device_spoofing; partially alerted: brute_force (99.3% of events, 3/3 incidents), credential_stuffing (96.7% of events, 1/1 incidents), impossible_travel (81.8% of events, 9/11 incidents), lateral_movement (8.1% of events, 1/4 incidents);
every event alerted: none; not present in TEST: low_slow_exfil (low_slow_exfil is evaluated on VALIDATION in §8 and is not held out).

**F8 — Entity holdout (partial).** For 60 entities streamed with their profile and history removed vs known: production-threshold recall 0.876 (removed) vs 0.878 (known),
precision 0.972 vs 0.959, alerts 356 vs 362, incidents 6/10 vs 6/10. This is a cold-start experiment; the global detectors were fitted on these entities (see §9).

**F9 — API-boundary representation changes the scores.** On 19 representative events: forcing `entity_type='user'` changes `peer_resource_deviation` on 10 events (mean |Δrisk| 12.38, max 50.58);
reading minutes as seconds changes `session_duration_zscore` on 19 events (mean |Δrisk| 14.13, max 55.41);
space-separated commands change the command features on 9 events (mean |Δrisk| 4.84, max 29.36);
the full API path: mean |Δrisk| 19.92, max 58.00. Warm-up scope: see §10 (TRAIN-only vs all-days state alerts per attack type).

**F10 — Generator shortcuts.** A one-line rule on raw fields (`public_ip OR failed_auth`) flags, per attack type on TEST: brute_force 100.0%, credential_stuffing 100.0%, impossible_travel 100.0%, lateral_movement 0.0%, device_spoofing 0.0% (overall precision 0.598, recall 0.711, 828 alerts).
The production detector's per-type event detection at its threshold: brute_force 99.3%, credential_stuffing 96.7%, impossible_travel 81.8%, lateral_movement 8.1%, device_spoofing 0.0%. Types that a raw-field rule separates cleanly can be detected through generator artifacts (§11), so their detection rates do not by themselves demonstrate behavioural generalisation.

**F11 — Reproducibility.** Runs A and B were independent process trees: 9,565 metric values compared, 0 differ; raw score arrays bit-identical: True.
Production files (source, model artifact, dataset) were hashed before and after every stage of both runs: True.

## 14. Limitations

1. **Design-history contamination.** The shipped model's fusion weights, flag weights, feature set, ranking bonus and production threshold were tuned on days 21–30, which contains this TEST window. ML-2's TEST is held out from ML-2's own decisions only.
2. **Small, single-draw data.** VALIDATION has 12 incidents and 287 attack events; TEST has 24 incidents and 696 attack events; one generator seed; no confidence intervals. Per-type rates rest on 1–11 incidents.
3. **Missing coverage in TEST.** No low_slow_exfil incident (all five start in VALIDATION); credential_stuffing is a single incident; device_spoofing and credential_stuffing have no VALIDATION incident, so the chronological classifier cannot learn them.
4. **The shipped classifier cannot be evaluated leakage-safely** (it was trained on all 36 incidents). Its false-alert behaviour (D) is the only leakage-free observation.
5. **The production threshold is not held out** (derived from days 21–30). It is reported as shipped; validation-derived thresholds are evaluation-only operating points and are not proposed for production.
6. **Entity holdout is partial.** Global components of the shipped artifact saw the held-out entities; a clean test needs retraining, which ML-2 forbids.
7. **Streaming EWMA state depends on run order.** The primary streaming run passes VALIDATION then TEST continuously (as deployment would); it is one trajectory, not a distribution.
8. **Synthetic data.** All conclusions concern this generator; shortcut analysis (§11) shows several attack types are separable by generator artifacts.
9. **Wall-clock latency** depends on machine load and is excluded from the reproducibility comparison.
10. **The API parity check** presents platform-style payloads reconstructed from the simulator's conventions (seconds/60 for `sessionDurationMinutes`, space-separated commands); real platform traffic was not sampled.
11. **The environment is not pinned** (`requirements.txt` uses `>=`); the shipped artifact was pickled with scikit-learn 1.9.0 and is loaded under a newer version with a warning; `matplotlib` is absent from the project venv (stubbed in-process only; nothing was installed).

## 15. Baseline Metrics for Future Phases

Two blocks, deliberately kept apart. **ML-2 introduces no model change, so nothing here is a production improvement.**

### A. CURRENT SHIPPED MODEL under the legacy (ML-1 / README) protocol — NOT leakage-safe, kept for continuity only

| Item | Value |
|---|---|
| Protocol | ML-1 / README: days 21–30 (validation + test), transductive batch fusion, threshold and design tuned on the same window |
| PR-AUC / ROC-AUC (shipped batch) | 0.9202 / 0.9947 |
| @ production threshold: precision / recall / alert rate | 1.0000 / 0.3281 / 1.00% |
| Top-1% by fused (P@1% / R@1%) | 1.0000 / 0.3271 |
| Classifier legacy row-level CV (macro-F1) | 0.983 |

### B. LEAKAGE-SAFE EVALUATION — the numbers future model changes should be compared against

| Item | Value |
|---|---|
| Population | held-out TEST: 16,438 events, 696 attack events, 24 incidents |
| Scoring path | streaming, as deployed (EWMA on), warm-up = TRAIN window only |
| PR-AUC / ROC-AUC (deployed risk score) | 0.8381 / 0.9813 |
| PR-AUC / ROC-AUC (underlying fused score) | 0.8733 / 0.9819 |
| @ production threshold: alerts / TP / FP / FN / TN | 524 / 498 / 26 / 198 / 15716 |
| @ production threshold: precision / recall / F1 | 0.9504 / 0.7155 / 0.8164 |
| @ production threshold: FPR / FNR / alert rate | 0.00165 / 0.2845 / 3.19% |
| @ production threshold: incidents detected | 14/24 |
| Top-1% by fused (k, P@1%, R@1%) | 164, 1.0000, 0.2356 |
| Top-1% by deployed risk, tie-aware (P expected [worst,best], R expected) | 0.9504 [0.8415, 1.0000], 0.2239 |
| Validation q99 operating point: precision / recall / incidents | 1.0000 / 0.6293 / 4/24 |
| Validation F1-optimal operating point: precision / recall / incidents | 0.9802 / 0.7098 / 12/24 |
| Per-type detection at production threshold (event rate) | brute_force 99.3%, credential_stuffing 96.7%, impossible_travel 81.8%, lateral_movement 8.1%, device_spoofing 0.0% |
| Risk saturation: events at risk = 100 / distinct values > 99.5 | 524 / 1 |
| Frozen batch (same population) PR-AUC (risk) / precision / recall @ prod thr. | 0.9028 / 0.9575 / 0.8089 |
| Classifier — chronological leakage-safe (macro-F1 / weighted-F1) | 0.323 / 0.637 (classes absent from training scored 0) |
| Classifier — incident-grouped LOIO (DIAGNOSTIC; macro-F1) | 0.712 |

**How to use these.** A future change is an improvement only if it beats block B *on the same held-out TEST population and the same protocol* (`python -m eval_ml2.run …`), evaluated through the **streaming** path, with its own thresholds and
any retraining done on TRAIN/VALIDATION only (ML-3 should replace the single-draw dataset with multiple seeds and fresh attack instances). Block A must not be used as the bar.

# ML-3 Leakage-Safe Training

**Status:** implemented, run twice (plus an earlier pre-fix pair), reported. **Candidate only - not deployed.** `models/pipeline.joblib`, `api.py`, the StreamingScorer, thresholds, Spring Boot, Kafka, the frontend, the database, the dataset and the simulator are unchanged (checksums in the final report). Stopped after ML-3.

## Bottom line

* A clean training pipeline for the **same architecture** now exists (baseline profiler + Isolation Forest + GRU sequence autoencoder + fusion), fitted on TRAIN only, with fusion weights, baseline mode and the operating threshold chosen on VALIDATION and frozen (sha256 `c3bb62a11bd3c9d1`) before TEST was unsealed. Two runs reproduce every metric, every prediction and every learned parameter exactly (by content hash; the joblib file bytes are not byte-stable, section 10).
* On the held-out TEST population (16,438 events, 696 attack events, 24 incidents) the candidate reaches PR-AUC 0.9349 / ROC-AUC 0.9946; at its frozen validation-derived threshold: precision 0.9332, recall 0.8233, F1 0.8748, FPR 0.00260, 19/24 incidents detected.
* **Versus the ML-2 leakage-safe streaming baseline (the shipped model as deployed): a real improvement under the same protocol** (fused PR-AUC 0.8733 -> 0.9349; F1 at matched validation-derived thresholds 0.8233 -> 0.8748; incidents 12/24 -> 19/24).
* **But the improvement is not evidence that clean training beats the shipped model.** The shipped model scored with a frozen baseline (no EWMA) already reaches fused PR-AUC 0.9353 and F1 0.8677 on the same TEST population, i.e. the same as the candidate (0.9349, 0.8748). The gain over the deployed streaming path comes from **not letting the baseline adapt (EWMA)**, which the candidate selected on validation (0.5956 vs 0.2508 macro PR-AUC).
* Still unsolved by methodology alone: **device spoofing 0/5 incidents**, an **unreliable attack-type classifier** (unsupported classes are labelled confidently), **heavy dependence on generator artifacts** (86% of the candidate's true-positive alerts are also caught by the one-line rule 'public IP or failed auth'), and the **serving-parity blockers** found in ML-1/ML-2 (unchanged; they are not training problems).

## 1. Training Protocol

Everything below is enforced in code (`eval_ml3/run.py`), not by convention. The test-period labels are masked from every stage before the freeze (`LabelVault.dev_labels`), and the TEST events do not exist in the feature stream used for fitting and selection.

| Stage | Data it may use | What it does | Evidence in this run |
|---|---|---|---|
| 0 Protocol | event timestamps only | builds the ML-2 split; asserts it equals the published ML-2 split; writes the immutable manifest | 32 fields identical to ML-2; manifest sha256 `a393d7ee093bff63` |
| 1 Dev features | events with t < validation end (82,872 rows) | causal feature extraction on the dev prefix only | test events are not in this stream |
| 2 Fit | TRAIN rows only (65,850, 0 attacks) | baseline profile, scaler, Isolation Forest, GRU autoencoder, per-signal score distributions | components content hash `e76b175706a5b5d8` |
| 3 Select | VALIDATION rows with dev labels (test labels masked) | fusion weights, baseline mode, operating threshold, incident-grouped classifier | selection tables in sections 5-7 |
| 4 Freeze | - | candidate config written read-only and hashed | sha256 `c3bb62a11bd3c9d1`, `frozen_before_test_unseal = True` |
| 5 Test | full stream; test labels unsealed ONCE | score TEST with the frozen candidate; metrics | unseals in this process: 1; validation predictions bit-identical to stage 3; dev-prefix features identical after adding TEST events: True |
| 6 Diagnostics | all labels via `LabelVault.diagnostic` (logged) | shortcut permutation, rules, signal ablation, DS first-event analysis | post-hoc; nothing feeds back |
| 7 Engine check | no labels | candidate-style replay vs the unmodified production StreamingScorer (shipped model) | equivalent (float32 rounding only) |

**Pre-registered decisions** (written in `eval_ml3/common.py` before any candidate score was inspected; one criterion was corrected before any score was seen: the fusion criterion was changed from event-level to macro per-type PR-AUC so that brute force, which is about 60% of all attack events, cannot decide the weights):

* split = ML-2 protocol, unchanged; hyper-parameters = the shipped ones (Isolation Forest 200 trees, GRU hidden 64 / 12 epochs / lr 1e-3, window 12, fit cap 30,000 windows, cleanest 90% by baseline score, LightGBM 300 trees / lr 0.06 / 31 leaves / balanced); seed 42 as in production.
* feature rule: exclude features that are constant on TRAIN, plus the stream-position counter `entity_event_count`.
* fusion: 0.1-step simplex grid, criterion macro per-attack-type PR-AUC on VALIDATION, equal weights win if the best is within 0.01 of them.
* baseline mode: `frozen` unless `ewma_guarded` wins by more than 0.01 on the same criterion. Operating point: F1-optimal fused threshold on VALIDATION.
* classifier: trainable with >= 2 incidents, evaluation meaningful with >= 5; alerts below 0.65 class probability are UNKNOWN (the existing `CLASS_CONF_HIGH`, not tuned).

**What differs from the shipped training** (each row is a leakage or contamination source found in ML-1/ML-2):

| Item | Shipped model | ML-3 candidate |
|---|---|---|
| Fusion weights | 0.6 / 0.2 / 0.2, tuned on days 21-30 (validation + test) | 0.7 / 0.3 / 0.0, selected on VALIDATION only |
| Score calibration curve | built from batch rank-fusion, applied to percentile fusion (mismatched) | built from the same TRAIN percentile fusion that is applied at scoring time |
| Alert threshold | top-1% of the TEST risk distribution (99.5023) | F1-optimal on VALIDATION, frozen (0.989010 on the fused score) |
| Baseline at inference | EWMA adaptive (alpha 0.02, guard risk >= threshold) | `frozen` (chosen on VALIDATION) |
| Classifier pool | incidents from days 21-30 including TEST incidents | validation-born incidents only; incident-grouped validation |
| Model input features | 35 (2 dead, 1 stream-position counter, 2 constant-on-TRAIN flags) | 30 (section 3) |
| Learned components fitted on | TRAIN (verified in ML-2) | TRAIN (verified again: the checks in section 4) |

**Disclosure on TEST use.** Each run unseals TEST once. The complete pipeline has been executed four times: A and B, then C and D after an evaluation-only change to the engine-check tolerance (a 1-ULP float32 difference in the shipped model's autoencoder error made the original absolute tolerance too strict; the rule was rewritten after A/B printed it and checks the replay engine only). No candidate-affecting code, choice or threshold changed between the pairs; the frozen-config hashes and all predictions are identical across all four (section 10). Frozen-config identical A vs C: True; predictions identical A vs C: True.

## 2. Split Manifest

Full manifest: `reports/ml3_split_manifest.json` (read-only file, sha256 `a393d7ee093bff6360d85cb73529dd02a077e95ad17eb21eb35eaa8295b495b3`; event-level assignment hash `8f14a1517818d665a96ef0ec2ffa38f955d2b37a4fdc2bbf2fd35fbc3cc776d9`). It is identical to the ML-2 manifest in every compared field.

| Split | Boundary (chronological) | Rows | Entities | Attack events | Incidents born | Incidents by type |
|---|---|---|---|---|---|---|
| TRAIN | 2026-06-01T00:00:46 .. 2026-06-21T00:00:39 (t < t0+20d) | 65,850 | 200 | 0 | 0 | - |
| VALIDATION | t0+20d .. t0+25d (2026-06-26T00:00:46) | 17,022 | 200 | 287 | 12 | BF 2, IT 4, LM 1, LSE 5 |
| TEST (raw window) | t >= 2026-06-26T00:00:46 .. 2026-07-01T04:37:10 | 16,476 | 200 | 734 | 24 | - |
| TEST (evaluation population) | raw window minus purged events | 16,438 | 200 | 696 | 24 | BF 3, CS 1, IT 11, LM 4, DS 5 |

* **Purge:** an incident belongs to the split of its first event. 38 events of validation-born incidents (LS000, LS001, LS002, LS003, LS004) that fall after the validation boundary are removed from the TEST evaluation population (they stay in the stream so state is causal). Consequence: **TEST contains no low-and-slow-exfiltration incident**, and **VALIDATION contains no credential-stuffing or device-spoofing incident**.
* Allowed use: TRAIN fits (it has 0 attack events, so no label is used or needed); VALIDATION selects; TEST is unsealed once after the freeze.

## 3. Feature Set

The production extractor is unchanged and produces all 35 features for every event. The candidate's Isolation Forest, autoencoder and classifier use **30** of them (**35 -> 30, -5**). The baseline profiler keeps its production feature lists (24 continuous + 7 boolean, unchanged; dead features contribute exactly 0 there).

| Excluded feature | Why (exactly) | Rule |
|---|---|---|
| is_new_city | constant on TRAIN (dead feature) | constant on TRAIN |
| new_resources_24h | constant on TRAIN (dead feature) | constant on TRAIN |
| fingerprint_mismatch | constant 0 on TRAIN because TRAIN has no attack events - the flag only fires inside attacks (not a dead feature of the extractor) | constant on TRAIN |
| auth_method_unusual | constant 0 on TRAIN because TRAIN has no attack events - the flag only fires inside attacks (not a dead feature of the extractor) | constant on TRAIN |
| entity_event_count | cumulative per-entity event counter = position in the stream: monotone in time by construction, so every later window looks out-of-range relative to TRAIN (ML-1: PSI 2.44; ML-2/ML-1: 24% of test rows exceed the TRAIN maximum). It encodes 'how long the stream has run', not behaviour. | policy |

**Two of the five exclusions were not anticipated.** The label-free rule 'constant on TRAIN' also removed `fingerprint_mismatch` and `auth_method_unusual`: TRAIN contains no attacks and the generator only produces those flags inside attacks. The rule was fixed in advance, so it was applied as written. Consequence: the Isolation Forest and autoencoder cannot use those two flags; they reach the candidate only through the baseline profiler (weights 10.0 and 3.5 kept as in production).

**Known problems: documented, isolated, not fixed in place** (no production code changed; the candidate's handling is explicit):

| ID | Features | Problem | Candidate handling |
|---|---|---|---|
| P1 | is_new_city | dead feature: constant 0 (`city not in {city}` is always False) | EXCLUDED from IF/AE/classifier (constant on TRAIN); still listed in the production baseline BOOLEAN set (contributes exactly 0) |
| P2 | new_resources_24h | dead feature: constant 0 (recent resources are always a subset of the seen set) | EXCLUDED from IF/AE/classifier (constant on TRAIN); still in the production baseline CONTINUOUS set (z = 0) |
| P3 | resource_breadth_7d, sensitive_ratio_7d | named '7d' but computed over the 24h deque | KEPT with the production definition (definition changes are out of scope); documented, not renamed |
| P4 | session_duration_zscore, sensitive_bytes_proxy_7d | API boundary reads sessionDurationMinutes into a SECONDS field | not a training-data problem (CSV is in seconds); UNRESOLVED serving-parity blocker, recorded in the recommendation |
| P5 | cmd_len, cmd_priv_count, cmd_bigram_surprise | extractor splits commands on '|' but the platform sends space-separated commands | not a training-data problem; UNRESOLVED serving-parity blocker |
| P6 | entity_event_count | non-stationary stream-position counter | EXCLUDED from IF/AE/classifier by policy (see POLICY_EXCLUDED_BY_DEFINITION) |
| P7 | is_sensitive_resource, sensitive_offhours_7d, sensitive_ratio_7d, sensitive_bytes_proxy_7d, hour_sin, hour_cos ... | generator-coupled: the generator writes attacks using the same SENSITIVE list, privileged-command set, private-vs-public IP ranges, hours and per-event random cities | KEPT (correlation is not a reason to drop a feature); their contribution is quantified by permutation in the shortcut diagnostic |
| P8 | fingerprint_novelty, offhours_count_7d, peer_resource_deviation, resource_novelty_ratio | TRAIN->TEST distribution shift driven by cold-start transients in TRAIN (PSI 0.39-3.4) | KEPT; fitting population unchanged for comparability with the shipped architecture; recorded as a limitation |
| P9 | peer_resource_deviation, baseline peer prior | api.py forces entity_type='user' for every event, so service accounts and edge devices get the wrong peer prior and peer histogram | training uses the real entity_type from the data (as the shipped training did); UNRESOLVED serving-parity blocker |
| P10 | fingerprint_mismatch, auth_method_unusual | constant 0 on TRAIN: TRAIN contains no attacks, and the generator only produces a mismatched fingerprint / unusual auth method inside attacks, so there is no 'normal' distribution to learn | EXCLUDED from IF/AE/classifier by the rule. CONSEQUENCE: those two signals reach the candidate only through the baseline profiler, where fingerprint_mismatch keeps its production weight 10.0 and auth_method_unusual 3.5; the IF/AE cannot see device-spoofing evidence in these flags |

Largest TRAIN -> VALIDATION shifts among **all 35** (dev data only): `offhours_count_7d` PSI 3.33 (0.0% of validation rows outside the TRAIN range); `entity_event_count` PSI 2.48 (9.7% of validation rows outside the TRAIN range); `fingerprint_novelty` PSI 2.21 (0.0% of validation rows outside the TRAIN range); `peer_resource_deviation` PSI 1.90 (0.0% of validation rows outside the TRAIN range); `resource_novelty_ratio` PSI 1.35 (0.0% of validation rows outside the TRAIN range); `hour_zscore` PSI 0.04 (0.3% of validation rows outside the TRAIN range). `offhours_count_7d`, `fingerprint_novelty`, `peer_resource_deviation` and `resource_novelty_ratio` are attributed (ML-1) to cold-start transients in TRAIN (entity histories still filling), not to behavioural change; they are kept for comparability with the shipped architecture and recorded as a limitation. `entity_event_count` is excluded by policy.

## 4. Training Components

| Component | Fitted on | Settings | Learned-content hash |
|---|---|---|---|
| Baseline profiler (`BaselineProfiler`, production class) | TRAIN, 65,850 rows, 200 entities | peer prior by entity_type, shrinkage k=50, per-entity mean/variance | `9d5aba0499ec174a` |
| Feature scaler | TRAIN | StandardScaler on 30 features | `199278517fc61cb2` |
| Isolation Forest | TRAIN | 200 trees, max_samples 256, seed 42 | `b0278ee7a77ad138` |
| Sequence autoencoder (GRU, production class) | cleanest 90% of TRAIN by baseline (59,265 windows, capped to 30,000) | hidden 64, 12 epochs, window 12, seed 42, torch 1 thread | `4349b509009877db` |
| Score-transformation distributions | TRAIN raw scores of the three signals (sorted) | percentile via searchsorted | `3b80cdaab8296efb` |
| Fusion weights / mode / threshold | VALIDATION (selected), frozen | {'baseline': 0.7, 'iforest': 0.3, 'sequence': 0.0}, `frozen`, thr 0.989010 | config `c3bb62a11bd3c9d1` |
| Attack classifier (LightGBM) | VALIDATION incidents (52 rows, 12 incidents) | shipped hyper-parameters | `da45fcd37e1a95fd` |

**Sequence windows (item 5).** A window is the previous 12 events of the same entity up to and including the scored event, in timestamp order. Verified by assertion:

* TRAIN windows built from TRAIN rows only are identical to the TRAIN windows of the full dev stream: True (so no validation event can be inside a TRAIN window); the window builder is identical to `src.detect.build_sequences` on the 35 production features: True.
* **First events of every split.** TRAIN: the first 11 events of each entity have zero left-padded windows - 2,200 of 65,850 windows (3.3%); they are used for fitting as in production. VALIDATION: 0 windows contain padding, because every entity already has >= 12 events from TRAIN; 2,195 validation windows reach back into TRAIN events (warm-up history, causal). TEST: 0 padded windows; 2,172 test windows include TRAIN/VALIDATION history. No window contains an event later than the event it scores.
* Feature state is causal for the same reason: adding the TEST events to the stream leaves every dev-period feature of every dev event bit-identical (asserted for all 35 features).

**Baseline profiling (item 6).** Mode selected on VALIDATION: **`frozen`** - a *frozen* profile: fitted on TRAIN, never updated afterwards. The validation state therefore begins at the end of TRAIN (the TRAIN fit) and the test state begins at the end of VALIDATION with the same profile, so no event, in particular no test event, alters anything used to score itself or any later event. The causal-adaptive alternative (EWMA alpha 0.02, poisoning guard = an event above the whole TRAIN fused range does not update) was evaluated and lost clearly: macro per-type PR-AUC 0.2508 vs 0.5956; event-level PR-AUC 0.3899 vs 0.9178. The production EWMA behaviour is not changed. Two costs of a frozen profile: it cannot follow legitimate drift (dataset drift is small, so it was not visible here) and TRAIN scores are in-sample for the baseline (next paragraph).

**In-sample calibration caveat.** The three TRAIN score distributions are in-sample (the models saw those rows). Out-of-sample validation *negatives* sit at median TRAIN percentiles baseline 0.49, Isolation Forest 0.39, autoencoder 0.43 (0.5 would mean no in/out-of-sample gap); 0.000% of validation negatives reach the top of the TRAIN fused range. The gap is small, so it is recorded, not corrected (a correction needs cross-fitting, i.e. a new algorithm).

**Score semantics (item 10) - nothing is calibrated; the six values are kept separate in `predictions.npz`:**

| Value | Definition | Range / behaviour | Is it a probability? |
|---|---|---|---|
| raw baseline score | 0.6 x largest + 0.4 x mean of the 3 largest per-feature deviations (z-scores clipped at 6; boolean flags x their weights, up to 10) | 0 .. ~10; many ties at the ceiling | no |
| raw Isolation Forest score | -score_samples of the forest on the scaled features | unitless, higher = more isolated | no |
| raw autoencoder score | mean squared reconstruction error over all 12 steps x all features | unbounded (up to ~1.4e5 seen on the shipped model), heavy-tailed | no |
| fused score | weighted mean of the three TRAIN-percentiles, weights {'baseline': 0.7, 'iforest': 0.3, 'sequence': 0.0} | 0 .. 1; a rank score, continuous (no ties) | no |
| risk score | 99 x TRAIN-fused CDF; a value at/above the whole TRAIN range = 100 | 0 .. 100; **saturates**: 455 of 16,438 test events sit at exactly 100 | no - a percentile |
| classifier confidence | LightGBM predicted-class probability trained on a few dozen rows | 0 .. 1, uncalibrated | no - and observed to be confidently wrong (section 6) |

Because the risk score saturates, ranking and thresholds in this report use the **fused score**; `riskScore`/`anomalyScore` must not be presented as probabilities.

## 5. Fusion

**Frozen candidate weights: baseline 0.7, Isolation Forest 0.3, sequence autoencoder 0.0.** The shipped 0.6 / 0.2 / 0.2 were tuned on days 21-30 (validation + test); they are **inherited and unvalidated**, shown below for reference only.

* Selection criterion: macro per-attack-type PR-AUC of the fused score on VALIDATION (types present in validation: ['brute_force', 'impossible_travel', 'lateral_movement', 'low_slow_exfil']), frozen baseline. Grid: 66 points (step 0.1). Equal weights are not on that grid and are evaluated separately as the parsimony reference (margin 0.01).
* Result: best grid point beats equal weights by 0.1475 (> margin) so parsimony was **not** applied. Selected weights = {'baseline': 0.7, 'iforest': 0.3, 'sequence': 0.0}.

| Weights (VALIDATION, frozen baseline) | macro type PR-AUC | event PR-AUC | ROC-AUC | BF | IT | LM | LSE |
|---|---|---|---|---|---|---|---|
| selected (best on grid) | 0.5956 | 0.9178 | 0.9959 | 0.9987 | 0.4805 | 0.7049 | 0.1984 |
| equal weights (1/3 each) | 0.4481 | 0.8884 | 0.9957 | 0.9988 | 0.3404 | 0.3679 | 0.0853 |
| shipped 0.6/0.2/0.2 (inherited, unvalidated) | 0.5123 | 0.8897 | 0.9951 | 0.9991 | 0.4276 | 0.5430 | 0.0797 |

Top of the grid: (0.7, 0.3, 0.0) -> 0.5956; (0.8, 0.2, 0.0) -> 0.5862; (0.9, 0.1, 0.0) -> 0.5811; (0.6, 0.4, 0.0) -> 0.5531; (0.7, 0.2, 0.1) -> 0.5470; (0.8, 0.1, 0.1) -> 0.5413. Every top-ranked point has sequence weight 0 or 0.1.

**Consequences and honest reading.** (1) The GRU autoencoder is trained and stored but contributes **nothing** to the candidate's score (weight 0.0). (2) The evidence is thin: the criterion averages four attack types with 2 / 4 / 1 / 5 incidents (BF / IT / LM / LSE); lateral movement is one incident. (3) VALIDATION has no device-spoofing or credential-stuffing incident, so nothing in it could reward signals that see those attacks. (4) On VALIDATION alone each raw signal is weak per type and the fusion is what works (event PR-AUC baseline 0.6964, IF 0.7758, AE 0.7616, fused 0.9178).

Frozen config: `models/candidates/ml3/candidate_config.json` (sha256 `c3bb62a11bd3c9d188c08bda840f98f8829c005477903847d69010b6f0dc4fbd`), written and hashed before TEST labels were unsealed.

## 6. Classifier

Same family and hyper-parameters as the shipped classifier, fitted on **52 rows from 12 validation-born incidents** (top 6 events per incident by fused score), trained classes: brute_force, impossible_travel, low_slow_exfil. TRAIN has no attacks, so nothing else is legitimately available before TEST.

| Attack type | Training examples | Validation examples | Incidents | Training possible | Evaluation meaningful | TEST support (info) | Statement |
|---|---|---|---|---|---|---|---|
| brute_force | 12 | 12 | 2 inc. | yes | **no** | 424 ev / 3 inc. | Insufficient data for reliable classifier training/evaluation. (trained, but too few incidents to evaluate reliably) |
| credential_stuffing | 0 | 0 | 0 inc. | **no** | **no** | 60 ev / 1 inc. | Insufficient data for reliable classifier training/evaluation. (not trained: fewer than 2 incidents) |
| impossible_travel | 4 | 4 | 4 inc. | yes | **no** | 11 ev / 11 inc. | Insufficient data for reliable classifier training/evaluation. (trained, but too few incidents to evaluate reliably) |
| lateral_movement | 6 | 6 | 1 inc. | **no** | **no** | 124 ev / 4 inc. | Insufficient data for reliable classifier training/evaluation. (not trained: fewer than 2 incidents) |
| device_spoofing | 0 | 0 | 0 inc. | **no** | **no** | 77 ev / 5 inc. | Insufficient data for reliable classifier training/evaluation. (not trained: fewer than 2 incidents) |
| low_slow_exfil | 30 | 30 | 5 inc. | yes | yes | 0 ev / 0 inc. | trained and evaluable (validation only) |

TRAIN and VALIDATION examples are the same rows here (TRAIN has no attacks; validation-born incidents are both the fit set and, under leave-one-incident-out, the validation set). Nothing was resampled, augmented or synthesised for the unsupported classes.

**Incident-grouped validation (leave-one-incident-out, 11 incidents, 46 rows):** row accuracy 0.0435, macro-F1 0.2222, 42 of 46 rows abstained (UNKNOWN), 2 of 11 incidents correct by majority vote. Per class: brute_force P 0.00 / R 0.00 (support 12); impossible_travel P 1.00 / R 0.50 (support 4); low_slow_exfil P 0.00 / R 0.00 (support 30). Only low-slow-exfil has enough incidents (5) to be called evaluable, and it is the class the classifier fails on (recall 0). Compare the shipped row-level cross-validation (macro-F1 0.983) and the incident-grouped shipped result (0.712) from ML-2: incident-level generalisation from so few incidents does not work.

**Behaviour of the classification layer on TEST alerts** (frozen threshold; every alerted event is classified; UNKNOWN = confidence < 0.65):

| True type | Class trained | Alerted events | Labelled correctly | Labelled as ANOTHER class | UNKNOWN |
|---|---|---|---|---|---|
| brute_force | yes | 423 | 367 | 56 | 0 |
| credential_stuffing | no | 58 | 0 | 58 | 0 |
| impossible_travel | yes | 11 | 9 | 1 | 1 |
| lateral_movement | no | 81 | 0 | 76 | 5 |
| device_spoofing | no | 0 | - | - | - |
| low_slow_exfil | yes | 0 | - | - | - |

False-positive alerts (41): 38 were given a confident attack class and only 3 were UNKNOWN (mean confidence 0.94).

**NORMAL / UNKNOWN (item 9).** The classification layer's output space is {trained attack classes} plus UNKNOWN. There is deliberately **no NORMAL class**: normality is the anomaly detector's decision, and a normal class built from detector-selected rows would be an invented label. **Limitation, measured:** UNKNOWN by confidence does not protect against unsupported classes - 100% of credential-stuffing and 94% of lateral-movement alerts (classes never trained) were labelled as a trained class with mean confidence 0.97 / 0.88, because a closed-set model has no way to say 'none of these' and its probabilities are not calibrated. On the alerts whose true type *is* supported, the layer is right 86.6% of the time, but that is almost entirely brute force. **The candidate classifier is not fit for use** and should not replace the shipped one; the honest state is 'Insufficient data for reliable classifier training/evaluation.' for credential stuffing, lateral movement and device spoofing (untrainable), and for brute force / impossible travel (trainable but not evaluable).

## 7. Validation Results

VALIDATION drove the fusion, mode, threshold and classifier choices, so these numbers are **selection-time, optimistic** (the F1-optimal threshold was chosen on this exact population). They are shown before TEST as required.

| Population | PR-AUC (fused) | ROC-AUC | Precision@1% | Recall@1% | max possible Recall@1% |
|---|---|---|---|---|---|
| VALIDATION | 0.9178 | 0.9959 | 1.0000 | 0.5923 | 0.5923 |

| VALIDATION operating point | Precision | Recall | F1 | FPR | Alert rate | Incidents detected | TP/FP/FN |
|---|---|---|---|---|---|---|---|
| candidate F1-optimal (frozen primary) | 0.8700 | 0.8397 | 0.8546 | 0.00215 | 1.63% | 12/12 | 241/36/46 |
| candidate validation q99 (label-free) | 1.0000 | 0.5993 | 0.7495 | 0.00000 | 1.01% | 2/12 | 172/0/115 |
| shipped risk threshold 99.5023 on candidate risk (reference only) | 1.0000 | 0.6376 | 0.7787 | 0.00000 | 1.08% | 3/12 | 183/0/104 |

Precision@1% / Recall@1% use k = floor(1% x N) events by fused score (no ties, no analyst queue, no de-duplication); Recall@1% cannot exceed k / P by construction.

Per attack type at the frozen threshold (validation):

| Type | Events | Incidents | Incidents detected | Event detection | PR-AUC vs negatives | ROC-AUC vs negatives |
|---|---|---|---|---|---|---|
| brute_force | 196 | 2 | 2/2 | 99.5% | 0.9987 | 1.0000 |
| credential_stuffing | 0 | 0 | - | - | - | - |
| impossible_travel | 4 | 4 | 4/4 | 100.0% | 0.4805 | 0.9993 |
| lateral_movement | 31 | 1 | 1/1 | 80.6% | 0.7049 | 0.9988 |
| device_spoofing | 0 | 0 | - | - | - | - |
| low_slow_exfil | 56 | 5 | 5/5 | 30.4% | 0.1984 | 0.9797 |

Detected / missed incidents: 12 of 12 detected; missed none. Low-slow-exfiltration is found at the incident level (5/5) but only 30.4% of its events alert - the slow trickle is caught by a few high-scoring events.

## 8. Final Test Results

TEST was evaluated **once per run after the freeze** (`candidate_config.json` sha256 `c3bb62a11bd3c9d1`). Population: 16,438 events, 696 attack events, 24 incidents (BF 3, CS 1, IT 11, LM 4, DS 5; no LSE). Metrics are event-level; an incident is detected if any of its events alerts.

| Population | PR-AUC (fused) | ROC-AUC | Precision@1% | Recall@1% | max possible Recall@1% |
|---|---|---|---|---|---|
| TEST | 0.9349 | 0.9946 | 1.0000 | 0.2356 | 0.2356 |

On the saturating deployed-style risk score: PR-AUC 0.9333, ROC-AUC 0.9945 (455 events tied at risk 100; 1 of them negative).

| TEST operating point | Precision | Recall | F1 | FPR | Alert rate | Incidents detected | TP/FP/FN |
|---|---|---|---|---|---|---|---|
| **candidate F1-optimal (frozen primary)** | 0.9332 | 0.8233 | 0.8748 | 0.00260 | 3.74% | 19/24 | 573/41/123 |
| candidate validation q99 (label-free) | 1.0000 | 0.6264 | 0.7703 | 0.00000 | 2.65% | 6/24 | 436/0/260 |
| shipped risk threshold 99.5023 on candidate risk (reference only) | 0.9978 | 0.6523 | 0.7889 | 0.00006 | 2.77% | 8/24 | 454/1/242 |

Per attack type (frozen primary threshold):

| Type | Events | Incidents | Incidents detected | Event detection | Events in top-1% | PR-AUC vs negatives | ROC-AUC vs negatives |
|---|---|---|---|---|---|---|---|
| brute_force | 424 | 3 | 3/3 | 99.8% | 160 | 0.9992 | 1.0000 |
| credential_stuffing | 60 | 1 | 1/1 | 96.7% | 4 | 0.9538 | 0.9998 |
| impossible_travel | 11 | 11 | 11/11 | 100.0% | 0 | 0.3918 | 0.9994 |
| lateral_movement | 124 | 4 | 4/4 | 65.3% | 0 | 0.7069 | 0.9932 |
| device_spoofing | 77 | 5 | 0/5 | 0.0% | 0 | 0.0594 | 0.9621 |

**Detected:** BF001, BF003, BF004, CS000, IT000, IT001, IT002, IT006, IT007, IT008, IT009, IT010, IT012, IT013, IT014, LM000, LM001, LM002, LM003.  **Missed:** DS000, DS001, DS002, DS003, DS004.

**Device spoofing, 0/5 - what the saved predictions show (post-hoc).** `fingerprint_mismatch` fires on only 5 of 77 DS events - the first event of each of the 5 incidents (5 of 5 first events), because the spoofed fingerprint counts as already seen afterwards - so an incident is detectable essentially by its first event alone. On every DS incident the *first* event has baseline percentile 1.00 (raw baseline 8.3-8.9, above the z-score ceiling of 6, i.e. driven by a weighted boolean flag; above everything seen in TRAIN) and autoencoder percentile 0.995-1.000, but Isolation Forest percentile only 0.77-0.91 (the forest cannot see the excluded flag). With weights {'baseline': 0.7, 'iforest': 0.3, 'sequence': 0.0} the best fused score of any DS incident is 0.977, below the threshold 0.989: 0/5 incidents reach it. For reference only, the same first events would score 0.953-0.981 under the inherited 0.6/0.2/0.2 weights - also below the threshold - so the miss is **not** explained by the zero autoencoder weight alone: the Isolation Forest cannot see the excluded flags, an incident counts as detected only if some event clears the threshold, and VALIDATION contained no DS incident that could have pulled the weights or threshold toward it. The shipped model detects 0/5 as well. This is a limitation to record - not a reason to retune on TEST.

**Signal ablation on TEST (event PR-AUC / macro type PR-AUC):** baseline 0.8307 / 0.3772; iforest 0.8582 / 0.3988; sequence 0.7812 / 0.2441; fused 0.9349 / 0.6222. The fusion is far better than any single signal.

## 9. Shortcut Analysis

Question: does the candidate lean on how the synthetic generator writes attacks (public vs private IP, failed authentication, hour, city, resources, commands)? Two diagnostics on the **frozen** candidate; features are not removed because they correlate with the label.

**(a) Group permutation.** One artifact family of feature columns is shuffled jointly across the evaluated rows (2 seeds), the frozen candidate re-scores, and the loss is measured (macro type PR-AUC / event PR-AUC / recall at the frozen threshold). A big loss = the candidate uses that family; a correlated but unused family shows none.

| Family permuted | TEST d macro-PR | TEST d event-PR | TEST d recall | VAL d macro-PR | VAL d event-PR |
|---|---|---|---|---|---|
| ip (public vs private, per-IP failures) | -0.182 | -0.023 | -0.055 | -0.093 | -0.005 |
| failed authentication | -0.202 | -0.061 | -0.021 | -0.222 | -0.107 |
| hour of day / off-hours | -0.022 | -0.005 | -0.013 | -0.150 | -0.083 |
| location / city | -0.233 | -0.063 | -0.061 | -0.189 | -0.097 |
| resource patterns | -0.176 | -0.099 | -0.085 | -0.315 | -0.146 |
| command patterns | -0.095 | -0.036 | -0.046 | -0.226 | -0.061 |
| device fingerprint | -0.009 | -0.019 | +0.001 | +0.000 | -0.000 |
| volume / timing | -0.098 | -0.078 | -0.037 | -0.217 | -0.053 |
| ALL generator-artifact groups together | -0.612 | -0.888 | -0.761 | -0.591 | -0.900 |

Unpermuted: TEST macro 0.6222, event PR 0.9349, recall 0.8233; VALIDATION macro 0.5956, event PR 0.9178. Reading: the candidate depends materially on IP/failed-auth, location, resource, command and volume/timing features. The 'ALL groups together' row shuffles almost the whole feature set, so it shows only that the model uses its features, not that it uses shortcuts. The device-fingerprint family has ~0 effect because one of its two features (`fingerprint_mismatch`) is excluded and `fingerprint_novelty` is small, and hour-of-day matters little on TEST but a lot on VALIDATION (where the 5 low-slow-exfil incidents are off-hours by construction).

**(b) One-line raw-field rules vs the candidate (TEST).** R1 = public source IP OR failed authentication; R3 adds foreign city, sudo, and (sensitive resource AND 22:00-05:00). Neither uses any history, model or label.

| Rule | Rule alerts | Rule precision | Rule recall | Candidate alerts also flagged by rule | Candidate TPs also flagged | Candidate PR-AUC where rule is silent | Candidate recall where rule is silent |
|---|---|---|---|---|---|---|---|
| R1 | 828 | 0.5978 | 0.7112 | 80.8% | 85.9% | 0.5512 | 0.4030 |
| R3 | 1540 | 0.4019 | 0.8894 | 95.1% | 100.0% | 0.0699 | 0.0000 |

BF, CS and IT are flagged by R1 on **100%** of their events; LM and DS on 0%. The candidate's headline numbers are therefore dominated by attack types that the generator makes trivially separable. On the events R1 does *not* flag, the candidate keeps real signal on lateral movement (alerts on 65% of LM events) but none on device spoofing, and its recall drops to 0.40 there. R1 alone scores precision 0.5978 / recall 0.7112: the candidate's precision 0.9332 / recall 0.8233 is better, but that gain is mostly lateral movement and precision, and it is measured on a generator whose easy attacks a two-field rule already flags.

**Conclusion:** the candidate is a competent detector *of this generator's attacks*; metrics on this dataset should not be read as evidence of real-world performance. Only fresh, differently-parameterised data (ML-4) can tell the two apart.

## 10. Reproducibility

The complete pipeline (features -> fit -> select -> freeze -> test -> diagnostics -> engine check) was run **twice as the canonical pair (C, D)**, plus an earlier pair (A, B) before the engine-check tolerance fix. All single-threaded (`OMP/MKL/OPENBLAS_NUM_THREADS=1`, `torch.set_num_threads(1)`), seeds fixed.

| Comparison | Metric values compared | Differences | Max abs diff | Predictions identical | Learned content identical | Frozen config identical | Split manifest identical |
|---|---|---|---|---|---|---|---|
| C vs D (canonical) | 3086 | 0 | 0.0 | True | True | True | True |
| A vs B (pre-fix pair) | 3076 | 0 | 0.0 | True | True | True | True |
| A vs C (across the fix) | - | - | - | True | True | True | True |

(The A-vs-C row compares what the code change could not touch. The metric JSONs of A and C differ in 13 leaves, all under: engine_check.conclusion, engine_check.criterion, engine_check.max_rel_diff_raw_signals, engine_check.risk_calibration_step, hashes.source, training.window_checks.)

**Candidate artifacts:** `candidate_config.json` byte-identical; `classifier.joblib` byte-identical; `components.joblib` content-identical but **not byte-identical**. The `components.joblib` bytes differ between runs although the learned content is identical (content hashes of the profiler, scaler, forest, GRU weights, score distributions and feature list are equal, and the torch state_dict is equal). Verified cause: scikit-learn's tree node records are 64-byte structs with 57 bytes of fields, and the 7 padding bytes per node are serialised uninitialised - 175 of 200 trees differ in raw node bytes while every named field is identical; the torch object is similarly not pickled canonically. Exact byte reproduction is therefore impossible with plain joblib; **content-hash equality is the reproducibility criterion for the artifact**, and the predictions computed from it are bit-identical.

| Item | Value |
|---|---|
| Seeds | model seed 42 (as production); ML-3 diagnostic seed 20260921; ML-2 eval seed 20260920; threads 1 |
| Python / numpy / pandas / scikit-learn | 3.14.7 / 2.5.3 / 3.0.6 / 1.9.1 |
| torch / lightgbm / scipy / joblib | 2.14.0+cpu / 4.7.0 / 1.18.1 / 1.6.0 |
| Platform | Windows-11-10.0.26200-SP0 |
| Dataset sha256 | events.csv `14adfb39392b0edf95ae0862...`; labels.csv `05a8d1055f6d09ac9f581833...` |
| Split manifest sha256 | `a393d7ee093bff6360d85cb73529dd02a077e95ad17eb21eb35eaa8295b495b3` |
| ML-3 config sha256 (`ML3_CONFIG`) | `b1c018de4f5eb87856ddae3cc1a75671fd8f8e17b7b092dfab3532557aa6c082` |
| Frozen candidate config sha256 | `c3bb62a11bd3c9d188c08bda840f98f8829c005477903847d69010b6f0dc4fbd` |
| Candidate learned-content sha256 (combined) | `e76b175706a5b5d8693e9f7a52d08f3d8811c416a6832a866c5182f2818cfad9` |
| Classifier content sha256 | `da45fcd37e1a95fdfe3424b087e49607aab941396bdbe465a34d92d6bf59761e` |
| Source hashes (eval_ml3) | __init__.py `cf2565df67`; candidate.py `d874296dab`; classify3.py `78f52acbcf`; common.py `274d5f4dc2`; compare_runs.py `aa7ae5a125`; diagnostics.py `852116e302`; engine_check.py `bb116871c4`; evaluate.py `f746653975`; posthoc.py `0f1b977da8`; protocol3.py `b5c95925f2`; run.py `b9a964baa3` |
| Production model sha256 (unchanged) | `381ae379ae1c5a7c3b4ac38f3df039c1b0de3268889f7df344670510de861684` |

Note: the source hashes are those recorded by runs C and D when they finished; `compare_runs.py` gained a `differing_prefixes` summary and `compose.py` was added afterwards. Both are report/comparison code that the training and evaluation run does not execute.


**Engine check.** The candidate is evaluated with a fast causal replay instead of the ~1 h per-event `StreamingScorer`. To show the replay is the same computation, the *shipped* model was run through it and compared event by event with the unmodified StreamingScorer results recorded in ML-2 (33,498 events): features bit-identical (max diff 0.0), baseline and Isolation Forest bit-identical, autoencoder error within 9.7e-07 relative (float32 rounding: one ULP), fused within 3.0e-06, alerts 740 vs 740 with 0 mismatches -> **equivalent (float32 rounding only)**.

## 11. Comparison Against ML-2

Three things are kept separate. **SHIPPED MODEL** = the production artifact scored the way the README/ML-1 did (batch, union rank-normalised fusion; *transductive*: it ranks against the test distribution itself). **ML-2 LEAKAGE-SAFE STREAMING BASELINE** = the same artifact through the unmodified StreamingScorer (EWMA on), the deployed behaviour, warm-up on TRAIN only. **ML-3 CANDIDATE** = this phase. One extra ML-2 row is shown for attribution: the shipped artifact with a frozen baseline (ML-2 'frozen batch'). All on the identical TEST population and identical metric code.

**Ranking quality (threshold-free), TEST:**

| Model / scoring | PR-AUC (deployed risk) | PR-AUC (fused) | ROC-AUC (fused) | P@1% / R@1% |
|---|---|---|---|---|
| SHIPPED MODEL (batch, transductive) | 0.9347 | 0.9349 | 0.9942 | 1.000 / 0.236 |
| ML-2 STREAMING BASELINE (as deployed) | 0.8381 | 0.8733 | 0.9819 | 1.000 / 0.236 |
| [attribution] shipped artifact, frozen baseline | 0.9028 | 0.9353 | 0.9942 | 1.000 / 0.236 |
| **ML-3 CANDIDATE** | 0.9333 | 0.9349 | 0.9946 | 1.000 / 0.236 |

Recall@1% is identical for every model (0.2356) because 1% of the population (164 events) is smaller than the attack-event count: it is capped by k / P, not informative.

**At operating points, TEST** (like-for-like rows are the 'validation F1-optimal' rows: each model's threshold was derived on VALIDATION, none on TEST; the production threshold is the shipped model's own, tuned on the test window, and does not apply to the candidate):

| Model | Operating point | Precision | Recall | F1 | FPR | Alert rate | Incidents |
|---|---|---|---|---|---|---|---|
| SHIPPED MODEL (batch) | production threshold 99.5023 | 1.0000 | 0.2759 | 0.4324 | 0.00000 | 1.17% | 4/24 |
| SHIPPED MODEL (batch) | validation F1-optimal (ML-2) | 0.9770 | 0.7931 | 0.8755 | 0.00083 | 3.44% | 18/24 |
| ML-2 STREAMING BASELINE | production threshold 99.5023 | 0.9504 | 0.7155 | 0.8164 | 0.00165 | 3.19% | 14/24 |
| ML-2 STREAMING BASELINE | validation F1-optimal (ML-2) | 0.9802 | 0.7098 | 0.8233 | 0.00064 | 3.07% | 12/24 |
| [attribution] frozen shipped | production threshold 99.5023 | 0.9575 | 0.8089 | 0.8769 | 0.00159 | 3.58% | 18/24 |
| [attribution] frozen shipped | validation F1-optimal (ML-2) | 0.9819 | 0.7773 | 0.8677 | 0.00064 | 3.35% | 14/24 |
| **ML-3 CANDIDATE** | validation F1-optimal (frozen) | 0.9332 | 0.8233 | 0.8748 | 0.00260 | 3.74% | 19/24 |
| **ML-3 CANDIDATE** | validation q99 (label-free) | 1.0000 | 0.6264 | 0.7703 | 0.00000 | 2.65% | 6/24 |

**Per attack type - incidents detected** (each model at its own operating point: ML-2 rows at the production threshold, the only place ML-2 recorded per-type incident counts; candidate at its frozen threshold):

| Type | SHIPPED (batch) | ML-2 STREAMING | [attr.] frozen shipped | ML-3 CANDIDATE |
|---|---|---|---|---|
| brute_force | 3/3 | 3/3 | 3/3 | 3/3 |
| credential_stuffing | 1/1 | 1/1 | 1/1 | 1/1 |
| impossible_travel | 0/11 | 9/11 | 10/11 | 11/11 |
| lateral_movement | 0/4 | 1/4 | 4/4 | 4/4 |
| device_spoofing | 0/5 | 0/5 | 0/5 | 0/5 |

**Verdict.** *Against the ML-2 streaming baseline the candidate genuinely improves under the same protocol:* fused PR-AUC 0.8733 -> 0.9349 (deployed-risk scale 0.8381 -> 0.9333), recall 0.7098 -> 0.8233 at validation-derived thresholds, F1 0.8233 -> 0.8748, incidents 12 -> 19 of 24. The cost is precision (0.9802 -> 0.9332) and FPR (0.00064 -> 0.00260). At those matched thresholds the candidate raises 41 false alerts against the streaming baseline's 10; at its label-free q99 threshold it has precision 1.0000 / recall 0.6264 but detects only 6/24 incidents.
*Against the shipped model with a frozen baseline the candidate does not improve:* PR-AUC 0.9353 vs 0.9349, F1 0.8677 vs 0.8748, and per type the frozen shipped model detects IT 10/11 and LM 4/4 at its production threshold. At matched validation-derived thresholds the candidate detects more incidents than the frozen shipped model (19 vs 14 of 24) but with 41 vs 10 false alerts - a move along the same ranking (equal PR-AUC), not a better ranking; the shipped batch model at its own validation-derived threshold reaches F1 0.8755, again equal to the candidate. So the measurable gain is attributable to dropping EWMA adaptation, which ML-1 already suggested; the leakage-safe fitting itself, on this data, is worth ~0 in ranking quality. It does remove the *risk of an inflated claim*: the candidate's numbers do not depend on a test-tuned weight, threshold or calibration curve. Caveat: 24 incidents (11 of them single-event impossible travel) - differences of one or two incidents are within noise and no significance test was run.

## 12. Limitations

1. **Data.** One synthetic dataset, one seed. TRAIN has zero attacks; VALIDATION has 12 incidents and no credential-stuffing or device-spoofing incident; TEST has no low-slow-exfiltration incident and only 24 incidents (11 single-event). Every selection (weights, threshold, classifier) rests on this.
2. **TEST is not virgin.** The feature definitions, boolean flag weights, clip, shrinkage and the generator-coupled constants (sensitive-resource list, privileged commands) were, per ML-1/ML-2, designed and tuned with days 21-30 visible. ML-3 removes the *fitted* leakage (fusion weights, calibration curve, threshold, classifier pool) but inherits the design history. A truly clean test needs new data generated after the design was frozen.
3. **Generator artifacts** (section 9): 86% of the candidate's true-positive alerts are also caught by the one-line rule 'public IP or failed authentication'; BF, CS and IT are trivially separable in this data.
4. **Thin validation evidence drives the fusion.** Weights {'baseline': 0.7, 'iforest': 0.3, 'sequence': 0.0} come from 4 attack types / 12 incidents (lateral movement = 1 incident). The autoencoder gets weight 0 (device spoofing is missed under the inherited weights too, section 8); the same rule on other data could pick differently. The F1-optimal threshold is in-sample on VALIDATION (precision 0.8700 there vs 0.9332 on TEST).
5. **Feature exclusion by rule** removed two flags the generator only uses in attacks (`fingerprint_mismatch`, `auth_method_unusual`); a real system would want them modelled, which needs attack-free-but-diverse training data or a different design (out of scope: no new algorithms).
6. **Classifier** is not usable (section 6); no NORMAL class; confidence is uncalibrated and confidently wrong on unsupported classes.
7. **In-sample TRAIN score distributions** slightly shift out-of-sample percentiles (section 4); the risk score saturates on 455 test events; nothing is calibrated.
8. **Frozen baseline** cannot follow legitimate drift; drift in this dataset is small so its cost is not measured. Drift handling is untested here, not solved.
9. **Serving parity is unresolved and out of scope**: `api.py` forces `entity_type='user'`, reads minutes into a seconds field and mis-splits commands. ML-2 measured mean |Δrisk| up to 19.9 from these; the candidate inherits them if deployed through the current API.
10. **Cold-start transients in TRAIN** (PSI 1.3-3.3 on four features) are kept for architectural comparability; 3.3% of TRAIN windows are zero-padded.
11. **Post-hoc analyses** (section 8 DS explanation, section 9) read labels after the freeze; they are diagnostics, and nothing was changed because of them.

## 13. Recommendation

* **Do not deploy this candidate, do not replace `pipeline.joblib`.** It is not better than the shipped model scored with a frozen baseline, its classifier is unreliable, and device spoofing is missed.
* **Adopt the finding, not the artifact:** on the same events the deployed streaming path (EWMA-adaptive baseline) scores fused PR-AUC 0.8733 against 0.9353 with a frozen baseline, and at the production threshold detects 14 vs 18 of 24 incidents (recall 0.7155 vs 0.8089); that is the one actionable lever ML-3 measured. Any change to production is a decision for a later, explicitly approved phase.
* **Proceed to ML-4 only as data and evaluation work**, in this order: (1) generate fresh multi-seed data with attack profiles that do not share the generator's constants and with attacks present in TRAIN-like periods so TRAIN has positives or at least attack-adjacent negatives; (2) re-run this exact pipeline (it is deterministic and label-gated) as the clean test; (3) then calibration, and only then thresholds; (4) resolve the serving-parity blockers in `api.py` before any candidate is served.
* Blockers for a deployable candidate: serving-parity fixes; classifier training data (>= 5 incidents per class, incident-grouped); a device-spoofing signal (missed under both the candidate's and the inherited weights); a decision on adaptive vs frozen baselines under real drift.

---
*Generated by `eval_ml3.compose` from `reports/ml3_runs/C/metrics.json`; every number is read from JSON. Candidate artifacts: `models/candidates/ml3/` (new location). Production files: unchanged (verified in the final report).*

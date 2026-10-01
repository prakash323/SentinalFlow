# ML-4 Data and Evaluation Foundation

**Status:** implemented, run twice (plus an earlier pre-change run), reported. **Scope: data and evaluation only.** Nothing was deployed, calibrated or thresholded for production; `models/pipeline.joblib`, `api.py`, the StreamingScorer, Spring Boot, Kafka, the frontend, PostgreSQL, the simulator and `src/generate.py` are unchanged. The only artifacts are evaluation datasets (`eval_ml4/data/`), the code in `eval_ml4/`, `reports/ml4*` and `models/candidates/ml4/` (marked NOT DEPLOYED). Stopped after ML-4.

## Answers to the eight questions

**A. Does performance generalise across independent seeds? Yes, within a generator profile.** The seed-to-seed spread of PR-AUC inside a profile is at most 0.054 (per-profile table in section 6.1), against a spread of 0.376 across profiles. On the four sealed new-seed datasets the frozen model (fitted on other datasets' onboarding only) reaches PR-AUC 0.591-0.922, and over all six sealed datasets it detects 162/192 incidents (84%, 95% CI 79%-89%) at its evaluation-only threshold. Caveat: this is generalisation of a fixed generator recipe across seeds; seeds of one profile share attacker templates, so it is an optimistic estimate (section 5).

**B. Does performance generalise across materially different profiles? Only partly - it is profile-dependent, not uniform.** PR-AUC ranges from 0.591 (P1 stealth-internal) to 0.967 (P4 burst, an UNSEEN profile). Loud attacks transfer (brute force 27/27, lateral movement 25/25, credential stuffing 16/17); slow or stealthy ones do not (low-slow exfiltration 10/24; impossible travel 51/60). On the unseen profile the model detects 60/70 incidents. The evaluation thresholds do NOT transfer: the alert rate at the same fused threshold ranges from 1.1% to 8.0%. The shipped model as deployed finds only 76/192 of the same incidents.

**C. How much comes from generator shortcuts? A lot on the reference profile, less elsewhere, and never zero.** On the replica profile the trivial rule 'public IP or failed authentication' flags 100% of brute-force, stuffing and impossible-travel events and 81% of the model's true-positive alerts; on the profiles built to defeat it the share falls to 54% (P1) and 54% (P3), and on P2 the rule is useless (it flags every event; precision 0.029) yet the model keeps PR-AUC 0.843. Performance survives shortcut removal for the loud attacks and degrades where attackers behave like insiders (P1). Shuffling the IP, resource, command and volume feature families costs 0.05-0.22 macro PR-AUC each; the device-fingerprint family costs ~0 (section 7).

**D. Which attack classes have enough independent incidents for learning?** By the pre-registered count rule (>= 5 TRAIN incidents from >= 2 profiles and >= 3 VAL incidents from a different profile) all six classes pass (BF 12/7, CS 9/5, IT 30/16, LM 12/9, DS 18/15, LSE 12/8 TRAIN/VAL incidents), **but counts overstate independence**: TRAIN has only 2 profiles, and 57% of sealed impossible-travel, 36% of lateral-movement and 33% of device-spoofing incidents show an attacker behaviour that no TRAIN incident shows. No classifier was trained, no NORMAL/attack class was fabricated. The honest statement remains: 'Insufficient data for reliable classifier training/evaluation.' for every class until many more independent profiles exist.

**E. What is missing for device-spoofing detection?** The only device signal is one opaque string (`OS|MAC|protocol`). The feature `fingerprint_mismatch` fires on the FIRST event of an incident only (afterwards the spoofed value is 'known'), never on a cloned fingerprint, and it is a clean detector only because benign fingerprint changes are absent from most profiles (precision 1.000 on P0 but 0.429 on P3, where firmware refresh is benign). Cloned fingerprints are nevertheless detected (8/9 by the frozen model, including 3/4 that keep the victim's own IP) - not through device identity, which a clone copies, but through the volume/timing signature of the generator's spoofing bursts. What is missing: a device-identity signal that survives cloning and refresh - TLS client fingerprint, client-certificate identity, hardware attestation, network-attachment (port/VLAN), firmware-version telemetry - each of which must first exist in the collector (section 8). The derivable 'same fingerprint from two IPs' signal fires on 0.01%-8.0% of benign events depending on the profile (precision as a detector <= 0.076), so it is not usable alone.

**F. Frozen vs adaptive baseline under benign drift: a trade, not a winner** (section 9). At a matched pre-drift false-positive rate the adaptive baseline (EWMA alpha 0.02 with an alert-threshold guard) lowers the false-alert rate on drifted-but-benign events after the drift by 10%-70% depending on the drift kind (location drift benefits most, device drift least), at an average recall cost of 0.024 and, with no drift at all, 0.019 of PR-AUC (0.94 -> 0.92). The guard matters more than the rate: with the production-style guard (block only above the whole TRAIN range) overall PR-AUC falls to 0.68 and with no guard to 0.53, because attack bursts poison the baseline.

**G. Serving-parity issues remaining: all eight audited mismatches are unresolved** (section 4; none was compensated). The certain-for-every-event combination (entity_type + minutes-as-seconds + command separator + UTC timestamps) changes 24 of 35 features, moves the shipped model's PR-AUC from 0.835 to 0.781 and its incidents detected from 18 to 13 of 36, and the ML-3 candidate's PR-AUC from 0.930 to 0.836. The most damaging item is not a mismatch but a **silent default**: if the platform omits the authentication result, the shipped model's recall at its production threshold falls from 0.681 to 0.159 (PR-AUC 0.835 -> 0.418) with no error raised. A fresh platform deployment (V10) leaves the shipped scores only 0.58 rank-correlated with the canonical ones. Duplicate and out-of-order delivery are comparatively benign (rank correlation >= 0.996).

**H. Is the foundation strong enough to proceed to calibration? Not yet.** The data foundation is sound (18 deterministic, hashed, chronologically ordered datasets in 5 profiles, sealed-test protocol enforced in code, reproducible to the bit). But calibration would be built on (1) a score whose operating thresholds do not transfer across profiles, (2) an uncorrected serving contract that distorts the very inputs being calibrated, (3) synthetic data authored by one generator family, so 'independent' is only partly true, and (4) no device-identity or low-and-slow signal to calibrate. Section 13 gives the ordered prerequisites and the ML-5 recommendation.

## 1. Scope, protocol and what was NOT done

* **Done:** serving-parity audit (13 variants, 2 datasets, 2 models); a new profile-parameterised generator and 18 datasets in 5 profiles; a dataset manifest with hashes; whole-dataset split roles (an incident cannot cross a boundary); class coverage and near-duplicate audits; a device-spoofing signal audit; a cross-seed / cross-profile evaluation of four models; an extended shortcut audit; a controlled frozen-vs-adaptive drift study; two complete runs.
* **Not done, by instruction:** no probability calibration, no production threshold selection (the operating points below are evaluation-only, derived on the VAL datasets), no classifier training, no deployment, no change to any production file, and no compensation of the serving mismatches inside the evaluation (the main evaluation uses the training representation and says so).
* **Models evaluated on every dataset, all with the same protocol** (the dataset's own attack-free onboarding fits its per-entity baseline): `ml4` = global components fitted on the pooled onboarding of the TRAIN datasets; `ml4_local` = the same recipe fitted on the dataset's own onboarding (no transfer); `ml3` = the ML-3 candidate; `shipped` = `models/pipeline.joblib` components. Each with a frozen baseline and an adaptive EWMA baseline (not decided in advance).

## 2. Datasets and profiles

Full manifest: `reports/ml4_dataset_manifest.json` (dataset-set sha256 `0af08367cf1e6cf2d8d37dfdf0b5b755f4fbfb10eb017c9090dc31dd001cd8a4`). Generator `ml4-gen-1.0` (independent of `src/generate.py`); every dataset is 36 days, chronologically ordered with strictly increasing timestamps, written in the production 12-field schema; labels and incident ground truth are separate files. The first 14 days are attack-free onboarding.

| Dataset | Role | Profile | Seed | Events | Entities (u/s/d) | Attack events | Incidents | Incidents by type | Benign-drift events | Drift |
|---|---|---|---|---|---|---|---|---|---|---|
| P0-101 | TRAIN | P0 | 101 | 61,711 | 200 (140/40/20) | 1,128 | 31 | BF4 CS3 IT10 LM4 DS6 LSE4 | 18 | - |
| P0-102 | TRAIN | P0 | 102 | 60,881 | 200 (140/40/20) | 1,182 | 31 | BF4 CS3 IT10 LM4 DS6 LSE4 | 22 | - |
| P1-201 | TRAIN | P1 | 201 | 60,422 | 140 (100/30/10) | 517 | 31 | BF4 CS3 IT10 LM4 DS6 LSE4 | 25 | - |
| P2-301 | VAL | P2 | 301 | 61,056 | 240 (220/15/5) | 1,076 | 30 | BF4 CS3 IT10 LM4 DS5 LSE4 | 54 | - |
| P3-401 | VAL | P3 | 401 | 60,489 | 200 (30/70/100) | 704 | 30 | BF3 CS2 IT6 LM5 DS10 LSE4 | 1,427 | - |
| P0-103 | DEV | P0 | 103 | 60,875 | 200 (140/40/20) | 873 | 31 | BF4 CS3 IT10 LM4 DS6 LSE4 | 23 | - |
| P0-104 | SEALED | P0 | 104 | 61,012 | 200 (140/40/20) | 929 | 31 | BF4 CS3 IT10 LM4 DS6 LSE4 | 25 | - |
| P1-202 | SEALED | P1 | 202 | 60,774 | 140 (100/30/10) | 544 | 31 | BF4 CS3 IT10 LM4 DS6 LSE4 | 33 | - |
| P2-302 | SEALED | P2 | 302 | 60,834 | 240 (220/15/5) | 1,087 | 30 | BF4 CS3 IT10 LM4 DS5 LSE4 | 49 | - |
| P3-402 | SEALED | P3 | 402 | 60,689 | 200 (30/70/100) | 784 | 30 | BF3 CS2 IT6 LM5 DS10 LSE4 | 1,449 | - |
| P4-501 | SEALED | P4 | 501 | 63,274 | 200 (90/60/50) | 3,165 | 35 | BF6 CS3 IT12 LM4 DS6 LSE4 | 22 | - |
| P4-502 | SEALED | P4 | 502 | 63,530 | 200 (90/60/50) | 3,147 | 35 | BF6 CS3 IT12 LM4 DS6 LSE4 | 11 | - |
| DR-ctrl | SEALED | P0 | 601 | 46,894 | 140 (100/25/15) | 1,277 | 39 | BF6 CS3 IT12 LM6 DS6 LSE6 | 0 | - |
| DR-hours | SEALED | P0 | 601 | 46,894 | 140 (100/25/15) | 1,277 | 39 | BF6 CS3 IT12 LM6 DS6 LSE6 | 1,129 | hours |
| DR-resources | SEALED | P0 | 601 | 46,894 | 140 (100/25/15) | 1,277 | 39 | BF6 CS3 IT12 LM6 DS6 LSE6 | 268 | resources |
| DR-location | SEALED | P0 | 601 | 46,894 | 140 (100/25/15) | 1,277 | 39 | BF6 CS3 IT12 LM6 DS6 LSE6 | 855 | location |
| DR-device | SEALED | P0 | 601 | 46,894 | 140 (100/25/15) | 1,277 | 39 | BF6 CS3 IT12 LM6 DS6 LSE6 | 6,980 | device |
| DR-volume | SEALED | P0 | 601 | 53,108 | 140 (100/25/15) | 1,277 | 39 | BF6 CS3 IT12 LM6 DS6 LSE6 | 6,214 | volume |
| orig42 | DEV | production-generator | 42 | 99,348 | 200 (140/40/20) | 1,021 | 36 | BF5 CS1 IT15 LM5 DS5 LSE5 | 126 | - |

**How the profiles differ** (label-free, measured on each dataset's attack-free onboarding - the constants the production generator hard-codes are exactly what changes):

| Measure | orig42 | P0-101 | P1-201 | P2-301 | P3-401 | P4-501 |
|---|---|---|---|---|---|---|
| normal events from public IPs | 0.000 | 0.000 | 0.000 | 1.000 | 0.000 | 0.483 |
| failed-auth rate | 0.019 | 0.020 | 0.011 | 0.045 | 0.007 | 0.017 |
| distinct IPs / entity (median) | 6.000 | 4.000 | 2.000 | 9.000 | 1.000 | 5.000 |
| IPs shared by >1 entity | 0.012 | 0.001 | 0.018 | 0.000 | 0.100 | 0.001 |
| cities outside the production home set | 0.000 | 0.000 | 1.000 | 1.000 | 1.000 | 0.819 |
| events 22:00-05:00 | 0.163 | 0.166 | 0.159 | 0.191 | 0.260 | 0.212 |
| resources in the production vocabulary | 1.000 | 1.000 | 0.337 | 0.004 | 0.538 | 0.039 |
| hits on production SENSITIVE list | 0.040 | 0.033 | 0.040 | 0.000 | 0.000 | 0.001 |
| commands with production-privileged tokens | 0.074 | 0.065 | 0.057 | 0.000 | 0.000 | 0.034 |
| events / entity / day | 5.700 | 2.572 | 4.144 | 4.572 | 8.571 | 7.574 |

Profiles: **P0** replica of the production generator's behaviour (control); **P1** stealth-internal enterprise (attackers on internal hosts, mostly successful authentication, business hours); **P2** remote-workforce SaaS (normal users on dynamic public IPs across time zones, noisy authentication, frequent travel); **P3** OT/IoT plant (device-heavy, periodic heartbeats, shifts, NAT gateways, different vocabulary, benign firmware refresh); **P4** burst / botnet (very fast high-volume attacks, distributed stuffing, multi-hop travel, compressed exfiltration). Attack variants (spoofing: full swap / partial MAC / partial OS / protocol-only / clone; source IP kinds; success ratios; hours; durations) are parameters of the profile and are recorded per incident.

## 3. Splits, sealing and integrity

* **Roles** (fixed before any dataset existed): TRAIN P0-101, P0-102, P1-201 (fit); VAL P2-301, P3-401 (different profiles from TRAIN; fusion weights and evaluation operating points); DEV P0-103, orig42 (diagnostics; labels not sealed); SEALED test P0-104, P1-202, P2-302, P3-402, P4-501, P4-502 and drift study DR-ctrl, DR-hours, DR-resources, DR-location, DR-device, DR-volume.
* **Incident-level isolation:** the split unit is the whole dataset, so an incident (namespaced `<dataset>:<attack_id>`) can never cross a train / validation / test boundary; inside each dataset every attack event occurs after the onboarding boundary (attack events in onboarding: 0 across all 18 generated datasets, verified again after unsealing).
* **Sealing enforced in code:** `eval_ml4.xfer.Vault` refuses to open a sealed dataset's labels or incident registry until `unseal()`; the frozen config (fusion weights {'baseline': 0.9, 'iforest': 0.1, 'sequence': 0.0}, evaluation operating points, calibration curve) was written read-only and hashed (`4e9c8d80b1ad7886`) with `unsealed_datasets_before_freeze = []`; each sealed dataset was unsealed exactly once. Vault log: 48 entries in the metrics JSON.
* **Determinism check on the data:** regeneration of all datasets in this run gave byte-identical files (`True`). This check found a real bug earlier (see section 11).
* **Near-duplicate / template overlap:** see section 5 - whole-dataset splitting prevents identical incidents crossing, but two seeds of one profile still share attacker templates.

## 4. Serving-parity audit

Machine-readable: `reports/ml4_parity_report.json`. Each row transforms the LIVE events exactly as the platform / `api.py` would present them (warm-up stays in the training representation, as `api.py` does), on the legacy dataset the shipped model was built on (`orig42`; 33k live events, 36 incidents). Nothing is compensated. Models: `shipped` (as deployed: EWMA adaptive, production threshold 99.5023 on the risk score) and the ML-3 candidate. PR-AUC / recall / incidents are compared with the canonical representation on identical events.

| Variant | Mismatch | Features changed (of 35) | Mean \|change\| (all features) | Shipped: mean \|risk change\| | Shipped: rank corr. | Shipped PR-AUC | Shipped recall @ prod. threshold | Shipped incidents | ML-3 PR-AUC | ML-3 recall @ its threshold |
|---|---|---|---|---|---|---|---|---|---|---|
| V0_canonical | training representation (control) | 0 | 0.0000 | 0.00 | 1.000 | 0.835 -> 0.835 | 0.681 -> 0.681 | 18 -> 18 | 0.930 -> 0.930 | 0.825 -> 0.825 |
| V1_entity_type_forced_user | P1 entity_type := 'user' for every live event | 1 | 0.0122 | 4.18 | 0.970 | 0.835 -> 0.825 | 0.681 -> 0.672 | 18 -> 18 | 0.930 -> 0.929 | 0.825 -> 0.826 |
| V2_duration_minutes_as_seconds | P2 session duration delivered in minutes into the seconds field (seconds / 60) | 2 | 15.1934 | 4.16 | 0.937 | 0.835 -> 0.826 | 0.681 -> 0.669 | 18 -> 15 | 0.930 -> 0.920 | 0.825 -> 0.797 |
| V3_command_space_separated | P3 command separator '\|' -> ' ' | 3 | 0.0214 | 0.94 | 0.989 | 0.835 -> 0.818 | 0.681 -> 0.673 | 18 -> 18 | 0.930 -> 0.915 | 0.825 -> 0.752 |
| V4a_utc_timestamps_live_only | P4 live timestamps shifted -5.5 h (UTC) while warm-up stays naive local (api behaviour) | 19 | 1.5459 | 8.51 | 0.873 | 0.835 -> 0.814 | 0.681 -> 0.681 | 18 -> 17 | 0.930 -> 0.856 | 0.825 -> 0.851 |
| V4b_utc_all_consistent | P4 hour-of-day semantics only: EVERY timestamp shifted -5.5 h (state and live consistent) | 7 | 0.1009 | 4.04 | 0.969 | 0.835 -> 0.828 | 0.681 -> 0.683 | 18 -> 19 | 0.930 -> 0.914 | 0.825 -> 0.810 |
| V5a_missing_geo | P5 geo_location empty | 2 | 273.5676 | 26.00 | 0.720 | 0.835 -> 0.816 | 0.681 -> 0.746 | 18 -> 16 | 0.930 -> 0.930 | 0.825 -> 0.914 |
| V5b_missing_fingerprint | P5 device_fingerprint empty | 2 | 0.0010 | 2.02 | 0.979 | 0.835 -> 0.797 | 0.681 -> 0.686 | 18 -> 22 | 0.930 -> 0.901 | 0.825 -> 0.830 |
| V5c_auth_defaults | P5 auth_success := 1 and auth_method := 'password' | 4 | 0.0380 | 5.71 | 0.835 | 0.835 -> 0.418 | 0.681 -> 0.159 | 18 -> 15 | 0.930 -> 0.921 | 0.825 -> 0.792 |
| V6_unseen_entity_namespace | P6 live entity ids not known to profiler / warm-up | 21 | 31.9030 | 13.45 | 0.784 | 0.835 -> 0.826 | 0.681 -> 0.681 | 18 -> 19 | 0.930 -> 0.877 | 0.825 -> 0.808 |
| V7_duplicate_delivery_2pct | P7 2% of live events delivered twice (immediately) | 19 | 0.5097 | 1.09 | 0.996 | 0.835 -> 0.833 | 0.681 -> 0.681 | 18 -> 18 | 0.930 -> 0.930 | 0.825 -> 0.824 |
| V8_out_of_order_5pct | P8 5% of live events swapped with their successor in delivery order | 17 | 0.5818 | 0.02 | 1.000 | 0.835 -> 0.835 | 0.681 -> 0.681 | 18 -> 18 | 0.930 -> 0.930 | 0.825 -> 0.824 |
| V9_api_contract_definite | P1+P2+P3+P4a combined (the mismatches that are certain for every event) | 24 | 14.6460 | 12.12 | 0.793 | 0.835 -> 0.781 | 0.681 -> 0.668 | 18 -> 13 | 0.930 -> 0.836 | 0.825 -> 0.741 |
| V10_fresh_platform | V9 + P6 unseen entity namespace (a new platform deployment) | 29 | 47.1511 | 21.43 | 0.580 | 0.835 -> 0.776 | 0.681 -> 0.673 | 18 -> 20 | 0.930 -> 0.808 | 0.825 -> 0.754 |

Mismatch inventory (all UNRESOLVED; none is fixed here):

| ID | Mismatch (source) | Consequence |
|---|---|---|
| P1 | `api._canonical_event` sets `entity_type = 'user'` for every event | peer prior and peer-resource histogram use the wrong group for service accounts and edge devices |
| P2 | `sessionDurationMinutes` is read into the seconds field | session-duration z-score, sensitive-bytes proxy and the models' duration inputs are wrong by 60x |
| P3 | platform sends space-separated commands; the extractor splits on `\|` | every multi-token command collapses to one token: command length / privileged count / bigram surprise degrade |
| P4 | `occurredAt` is converted to UTC; the training and warm-up data are naive local time | hour-of-day, weekend and off-hours features shift by the offset; live events precede the warm-up state |
| P5 | absent optional fields default silently (geo '', fingerprint '', auth_success 1, auth_method 'password') | the corresponding attacks (travel, spoofing, brute force) become invisible without any error |
| P6 | platform entity ids are not in the profiler or the warm-up (which replays the sample data set) | every entity starts cold: peer-prior baseline and novelty features fire; the warm-up scope is irrelevant to real entities |
| P7 | `/predict` is stateful and non-idempotent; at-least-once delivery duplicates events | duplicates update the state twice |
| P8 | the extractor assumes strict time order; Kafka does not guarantee it across partitions | negative gaps and mis-ordered windows |
| P9 | hard-coded vocabularies (`SENSITIVE` resources, privileged commands) shared with the generator | quantified in section 6: profiles with different vocabularies lose those features |

## 5. Attack-class coverage and near-duplicate incidents

| Attack type | TRAIN incidents (profiles) | VAL incidents (profiles) | DEV | SEALED test | Count rule met | Distinct behaviours: TRAIN / TRAIN+VAL / sealed | Sealed incidents with behaviour unseen in TRAIN | Statement |
|---|---|---|---|---|---|---|---|---|
| brute_force | 12 (P0, P1) | 7 (P2, P3) | 9 | 63 | yes | 2 / 3 / 3 | 15% | Enough independent incidents across profiles to attempt learning (not done in ML-4). |
| credential_stuffing | 9 (P0, P1) | 5 (P2, P3) | 4 | 35 | yes | 2 / 3 / 3 | 18% | Enough independent incidents across profiles to attempt learning (not done in ML-4). |
| impossible_travel | 30 (P0, P1) | 16 (P2, P3) | 25 | 132 | yes | 2 / 3 / 4 | 57% | Enough independent incidents across profiles to attempt learning (not done in ML-4). |
| lateral_movement | 12 (P0, P1) | 9 (P2, P3) | 9 | 61 | yes | 2 / 4 / 4 | 36% | Enough independent incidents across profiles to attempt learning (not done in ML-4). |
| device_spoofing | 18 (P0, P1) | 15 (P2, P3) | 11 | 75 | yes | 3 / 5 / 6 | 33% | Enough independent incidents across profiles to attempt learning (not done in ML-4). |
| low_slow_exfil | 12 (P0, P1) | 8 (P2, P3) | 9 | 60 | yes | 2 / 2 / 2 | 0% | Enough independent incidents across profiles to attempt learning (not done in ML-4). |

The count rule is deliberately mechanical; the behaviour columns show why it is not enough. 'Behaviour' = the attacker parameters that define the incident (source-IP kind, city mode, spoof variant, foreign-resource mode, ...). Nothing was resampled, augmented or synthesised, no classifier was trained to fill a gap, and no NORMAL class exists.

**Near-duplicates.** Each sealed incident's signature (mean standardised feature vector) was compared with every TRAIN/VAL incident of the same type; 'near-duplicate' = closer than the 5th percentile of same-type distances inside the reference set.

| Sealed profile | Incidents | Near-duplicate of a TRAIN/VAL incident | Nearest neighbour is the same profile |
|---|---|---|---|
| P0 | 31 | 55% | 90% |
| P1 | 31 | 58% | 97% |
| P2 | 30 | 77% | 73% |
| P3 | 30 | 60% | 77% |
| P4 | 70 | 47% | 0% |

Seeds of a profile that was in TRAIN/VAL share templates (their nearest neighbours are almost always same-profile incidents), so cross-seed results are an optimistic estimate of generalisation; the unseen profile P4 has no same-profile neighbours by construction, and still 47% of its incidents are near-duplicates of some other profile's incident: many attack shapes are simply similar across profiles in this feature space.

## 6. Cross-seed and cross-profile generalisation

Frozen `ml4` configuration: TRAIN = P0-101, P0-102, P1-201 (onboarding only), features 31, fusion weights **0.9 baseline / 0.1 Isolation Forest / 0.0 sequence** (selected on P2-301, P3-401: mean macro per-type PR-AUC 0.568 vs equal weights 0.501 vs the shipped weights 0.511). As in ML-3, the GRU autoencoder receives weight 0 when weights are selected on held-out profiles. Evaluation-only operating points (NOT production thresholds): frozen baseline fused >= 0.98725, adaptive baseline fused >= 0.99248 (each the F1-optimum on the pooled VAL datasets for that mode).

**6.1 Threshold-free ranking (PR-AUC / ROC-AUC of the fused score), by dataset.** This is independent of every threshold:

| Sealed dataset | Kind | ml4/frozen macro type PR-AUC | ml4/frozen | ml4/adaptive | ml4_local/frozen | ml3/frozen | shipped/frozen | shipped/adaptive |
|---|---|---|---|---|---|---|---|---|
| P0-104 | new seed of TRAIN profile P0 | 0.582 | 0.922 / 0.986 | 0.875 / 0.980 | 0.920 / 0.986 | 0.916 / 0.988 | 0.912 / 0.989 | 0.870 / 0.986 |
| P1-202 | new seed of TRAIN profile P1 | 0.255 | 0.591 / 0.934 | 0.460 / 0.890 | 0.584 / 0.935 | 0.566 / 0.951 | 0.589 / 0.948 | 0.397 / 0.919 |
| P2-302 | new seed of VAL profile P2 | 0.409 | 0.843 / 0.952 | 0.768 / 0.941 | 0.841 / 0.951 | 0.839 / 0.958 | 0.829 / 0.956 | 0.786 / 0.949 |
| P3-402 | new seed of VAL profile P3 | 0.718 | 0.758 / 0.950 | 0.687 / 0.908 | 0.781 / 0.952 | 0.758 / 0.947 | 0.736 / 0.942 | 0.623 / 0.905 |
| P4-501 | UNSEEN profile P4 | 0.543 | 0.967 / 0.995 | 0.945 / 0.988 | 0.968 / 0.995 | 0.962 / 0.995 | 0.957 / 0.995 | 0.925 / 0.988 |
| P4-502 | UNSEEN profile P4 | 0.493 | 0.957 / 0.993 | 0.933 / 0.984 | 0.960 / 0.994 | 0.950 / 0.992 | 0.941 / 0.989 | 0.914 / 0.981 |

Reference (dev, not sealed - the same models on datasets used for fitting/selection/diagnostics):

| Dataset | Role | Profile | ml4/frozen | ml4/adaptive | ml3/frozen | shipped/frozen | shipped/adaptive |
|---|---|---|---|---|---|---|---|
| P2-301 | VAL | P2 | 0.841 / 0.950 | 0.764 / 0.938 | 0.832 / 0.954 | 0.818 / 0.952 | 0.777 / 0.945 |
| P3-401 | VAL | P3 | 0.783 / 0.966 | 0.600 / 0.924 | 0.786 / 0.964 | 0.695 / 0.961 | 0.551 / 0.927 |
| P0-103 | DEV | P0 | 0.929 / 0.995 | 0.886 / 0.989 | 0.924 / 0.995 | 0.928 / 0.996 | 0.887 / 0.993 |
| orig42 | DEV | legacy | 0.925 / 0.994 | 0.832 / 0.975 | 0.930 / 0.995 | 0.920 / 0.995 | 0.835 / 0.983 |
| P0-101 | TRAIN | P0 | 0.932 / 0.992 | 0.893 / 0.982 | 0.929 / 0.993 | 0.931 / 0.993 | 0.892 / 0.988 |
| P0-102 | TRAIN | P0 | 0.951 / 0.996 | 0.879 / 0.985 | 0.948 / 0.997 | 0.947 / 0.997 | 0.888 / 0.991 |
| P1-201 | TRAIN | P1 | 0.537 / 0.923 | 0.403 / 0.891 | 0.495 / 0.938 | 0.554 / 0.939 | 0.296 / 0.918 |

**Seed-to-seed spread inside each profile** (ml4/frozen PR-AUC on the evaluation period of every standard dataset of that profile):

| Profile | Datasets (role): PR-AUC | Spread (max - min) |
|---|---|---|
| P0 | P0-101 (TRAIN) 0.932; P0-102 (TRAIN) 0.951; P0-103 (DEV) 0.929; P0-104 (SEALED) 0.922 | 0.030 |
| P1 | P1-201 (TRAIN) 0.537; P1-202 (SEALED) 0.591 | 0.054 |
| P2 | P2-301 (VAL) 0.841; P2-302 (SEALED) 0.843 | 0.002 |
| P3 | P3-401 (VAL) 0.783; P3-402 (SEALED) 0.758 | 0.026 |
| P4 | P4-501 (SEALED) 0.967; P4-502 (SEALED) 0.957 | 0.011 |

Reading: (i) **dataset difficulty, not model choice, dominates** - ml4, ml4_local, ml3 and shipped are within 0.025 PR-AUC of each other on every sealed dataset; (ii) **transfer costs ~nothing in ranking**: fitting on the dataset's own onboarding instead of other datasets changes PR-AUC by -0.007 to 0.023; (iii) the frozen baseline outranks the adaptive one everywhere without drift; (iv) training on three profiles instead of the single legacy dataset (ml3 / shipped) does not improve ranking.

**6.2 Operating points (evaluation-only), per dataset.** ml4 at the thresholds transferred from VAL; ml3 at its own frozen threshold; shipped at its production threshold; last block = each model's own label-free 1% alert budget (no transferred threshold):

| Dataset | Model/mode | Precision | Recall | F1 | FPR | Alert rate | Incidents detected | Own 1% budget: P / R / incidents |
|---|---|---|---|---|---|---|---|---|
| P0-104 | ml4/frozen | 0.787 | 0.865 | 0.825 | 0.0059 | 2.71% | 29/31 | 1.000 / 0.411 / 11 |
| P0-104 | ml4/adaptive | 0.907 | 0.801 | 0.851 | 0.0021 | 2.17% | 20/31 | 1.000 / 0.411 / 11 |
| P0-104 | ml3/frozen | 0.942 | 0.805 | 0.868 | 0.0012 | 2.10% | 24/31 | 1.000 / 0.411 / 10 |
| P0-104 | shipped/adaptive | 0.977 | 0.727 | 0.833 | 0.0004 | 1.83% | 18/31 | 1.000 / 0.408 / 7 |
| P1-202 | ml4/frozen | 0.642 | 0.500 | 0.562 | 0.0041 | 1.13% | 24/31 | 0.690 / 0.474 / 23 |
| P1-202 | ml4/adaptive | 0.765 | 0.377 | 0.505 | 0.0017 | 0.72% | 12/31 | 0.594 / 0.408 / 19 |
| P1-202 | ml3/frozen | 0.847 | 0.314 | 0.458 | 0.0008 | 0.54% | 15/31 | 0.655 / 0.450 / 19 |
| P1-202 | shipped/adaptive | 0.907 | 0.197 | 0.323 | 0.0003 | 0.32% | 5/31 | 0.425 / 0.292 / 21 |
| P2-302 | ml4/frozen | 0.790 | 0.794 | 0.792 | 0.0062 | 2.89% | 23/30 | 1.000 / 0.349 / 7 |
| P2-302 | ml4/adaptive | 0.829 | 0.681 | 0.747 | 0.0042 | 2.36% | 14/30 | 1.000 / 0.348 / 7 |
| P2-302 | ml3/frozen | 0.904 | 0.712 | 0.797 | 0.0022 | 2.27% | 19/30 | 1.000 / 0.353 / 7 |
| P2-302 | shipped/adaptive | 0.954 | 0.674 | 0.790 | 0.0010 | 2.03% | 14/30 | 1.000 / 0.348 / 7 |
| P3-402 | ml4/frozen | 0.860 | 0.648 | 0.739 | 0.0023 | 1.58% | 26/30 | 0.995 / 0.476 / 20 |
| P3-402 | ml4/adaptive | 0.981 | 0.531 | 0.689 | 0.0002 | 1.13% | 23/30 | 0.995 / 0.476 / 19 |
| P3-402 | ml3/frozen | 0.996 | 0.291 | 0.450 | 0.0000 | 0.61% | 18/30 | 0.995 / 0.476 / 22 |
| P3-402 | shipped/adaptive | 0.995 | 0.240 | 0.386 | 0.0000 | 0.50% | 9/30 | 0.864 / 0.413 / 26 |
| P4-501 | ml4/frozen | 0.892 | 0.898 | 0.895 | 0.0094 | 7.99% | 30/35 | 1.000 / 0.130 / 5 |
| P4-501 | ml4/adaptive | 0.918 | 0.862 | 0.889 | 0.0067 | 7.45% | 24/35 | 1.000 / 0.130 / 5 |
| P4-501 | ml3/frozen | 0.941 | 0.830 | 0.882 | 0.0045 | 7.00% | 23/35 | 1.000 / 0.129 / 5 |
| P4-501 | shipped/adaptive | 0.977 | 0.761 | 0.855 | 0.0016 | 6.18% | 18/35 | 1.000 / 0.131 / 7 |
| P4-502 | ml4/frozen | 0.876 | 0.881 | 0.878 | 0.0105 | 7.86% | 30/35 | 1.000 / 0.129 / 6 |
| P4-502 | ml4/adaptive | 0.910 | 0.856 | 0.883 | 0.0071 | 7.36% | 22/35 | 1.000 / 0.132 / 6 |
| P4-502 | ml3/frozen | 0.934 | 0.826 | 0.877 | 0.0050 | 6.93% | 21/35 | 1.000 / 0.136 / 6 |
| P4-502 | shipped/adaptive | 0.974 | 0.775 | 0.863 | 0.0018 | 6.23% | 12/35 | 1.000 / 0.129 / 8 |

**6.3 Pooled incident detection over the six sealed datasets** (192 incidents; Wilson 95% intervals):

| Attack type | ml4/frozen | ml4/adaptive | ml3/frozen | shipped (as deployed) |
|---|---|---|---|---|
| brute_force | 27/27 (100%; 88%-100%) | 27/27 (100%; 88%-100%) | 27/27 (100%; 88%-100%) | 26/27 (96%; 82%-99%) |
| credential_stuffing | 16/17 (94%; 73%-99%) | 16/17 (94%; 73%-99%) | 16/17 (94%; 73%-99%) | 16/17 (94%; 73%-99%) |
| impossible_travel | 51/60 (85%; 74%-92%) | 43/60 (72%; 59%-81%) | 44/60 (73%; 61%-83%) | 26/60 (43%; 32%-56%) |
| lateral_movement | 25/25 (100%; 87%-100%) | 17/25 (68%; 48%-83%) | 23/25 (92%; 75%-98%) | 4/25 (16%; 6%-35%) |
| device_spoofing | 33/39 (85%; 70%-93%) | 9/39 (23%; 13%-38%) | 5/39 (13%; 6%-27%) | 3/39 (8%; 3%-20%) |
| low_slow_exfil | 10/24 (42%; 24%-61%) | 3/24 (12%; 4%-31%) | 5/24 (21%; 9%-40%) | 1/24 (4%; 1%-20%) |
| ALL | 162/192 (84%; 79%-89%) | 115/192 (60%; 53%-67%) | 120/192 (62%; 55%-69%) | 76/192 (40%; 33%-47%) |

**6.4 Per attack type and dataset (ml4/frozen): incidents detected / incidents, and event detection rate:**

| Dataset | BF | CS | IT | LM | DS | LSE |
|---|---|---|---|---|---|---|
| P0-104 | 4/4 (100%) | 3/3 (100%) | 10/10 (100%) | 4/4 (93%) | 5/6 (22%) | 3/4 (38%) |
| P1-202 | 4/4 (97%) | 2/3 (13%) | 10/10 (100%) | 4/4 (51%) | 4/6 (9%) | 0/4 (0%) |
| P2-302 | 4/4 (99%) | 3/3 (90%) | 7/10 (70%) | 4/4 (71%) | 5/5 (20%) | 0/4 (0%) |
| P3-402 | 3/3 (98%) | 2/2 (95%) | 6/6 (100%) | 5/5 (92%) | 9/10 (67%) | 1/4 (1%) |
| P4-501 | 6/6 (100%) | 3/3 (88%) | 8/12 (45%) | 4/4 (95%) | 5/6 (21%) | 4/4 (55%) |
| P4-502 | 6/6 (100%) | 3/3 (90%) | 10/12 (67%) | 4/4 (96%) | 5/6 (24%) | 2/4 (5%) |

**6.5 Which attacker behaviours are missed (ml4/frozen, pooled over sealed datasets):**

| Attack type | Behaviour (parameters) | Detected |
|---|---|---|
| credential_stuffing | ('private_internal', 'home') | 4/5 |
| impossible_travel | ('public', 'multi-hop') | 18/24 |
| impossible_travel | ('residential', 'single') | 7/10 |
| device_spoofing | ('clone', False) | 3/4 |
| device_spoofing | ('full_swap', False) | 12/15 |
| device_spoofing | ('partial_mac', False) | 3/4 |
| device_spoofing | ('protocol_only', False) | 6/7 |
| low_slow_exfil | ('mixed',) | 0/4 |
| low_slow_exfil | ('sensitive',) | 10/20 |

Per-incident tables (every incident: type, variant, events, alerts, first-alert latency, max fused score and its percentile among negatives) are in `reports/ml4_metrics.json` under `metrics.sealed_evaluation.<dataset>.<model/mode>.incident_table_at_first_threshold`.

**6.6 Signal ablation (each raw signal alone vs the fusion; event PR-AUC / macro per-type PR-AUC):**

| Dataset | Baseline alone | Isolation Forest alone | Sequence AE alone | Fused |
|---|---|---|---|---|
| P0-104 | 0.856 / 0.415 | 0.824 / 0.422 | 0.597 / 0.195 | 0.922 / 0.582 |
| P1-202 | 0.559 / 0.208 | 0.173 / 0.041 | 0.376 / 0.144 | 0.591 / 0.255 |
| P2-302 | 0.791 / 0.343 | 0.808 / 0.340 | 0.632 / 0.221 | 0.843 / 0.409 |
| P3-402 | 0.680 / 0.382 | 0.603 / 0.490 | 0.332 / 0.161 | 0.758 / 0.718 |
| P4-501 | 0.949 / 0.498 | 0.944 / 0.448 | 0.803 / 0.235 | 0.967 / 0.543 |
| P4-502 | 0.943 / 0.471 | 0.926 / 0.404 | 0.786 / 0.236 | 0.957 / 0.493 |

**6.7 The hard-coded vocabularies (P9).** The production features `is_sensitive_resource`, `sensitive_*_7d` and `cmd_priv_count` are computed against fixed lists (`config.SENSITIVE`, `{sudo, exec, delete, download}`). On P2 and P3 none of the profile's sensitive resources or privileged commands is in those lists (see the profile-contrast table: 0.000 hits), so those features are constant 0 there; on P4 20% of the sensitive resources match. The model's results on those profiles are therefore obtained with a strictly reduced feature set (an untested contributor to their lower scores; ML-4 did not add features).

## 7. Generator-shortcut audit (extended)

**7.1 Trivial raw-field rules per dataset** (sealed; R1 = public source IP OR failed authentication, RFC1918 private ranges - ML-2/ML-3 treated only 10.* and 192.168.* as private; R4 = R1 OR first-seen IP for the entity):

| Dataset | R1 precision | R1 recall | R1 FPR | R1 flag rate by attack type | Incidents the model detects where R1 never fires | Model event recall where R1 is silent | Model PR-AUC where R1 is silent | R4 precision | R4 recall |
|---|---|---|---|---|---|---|---|---|---|
| P0-104 | 0.463 | 0.703 | 0.021 | BF100% CS100% IT100% LM0% DS0% LSE0% | 12/14 | 0.554 | 0.566 | 0.300 | 0.703 |
| P1-202 | 0.322 | 0.358 | 0.011 | BF70% CS92% IT0% LM0% DS0% LSE0% | 18/24 | 0.355 | 0.410 | 0.217 | 0.384 |
| P2-302 | 0.029 | 1.000 | 1.000 | BF100% CS100% IT100% LM100% DS100% LSE100% | 0/0 | n/a | n/a | 0.029 | 1.000 |
| P3-402 | 0.578 | 0.378 | 0.006 | BF99% CS100% IT100% LM0% DS25% LSE0% | 13/17 | 0.480 | 0.586 | 0.578 | 0.378 |
| P4-501 | 0.141 | 0.930 | 0.486 | BF100% CS100% IT100% LM39% DS80% LSE71% | 3/4 | 0.622 | 0.786 | 0.141 | 0.930 |
| P4-502 | 0.134 | 0.928 | 0.507 | BF100% CS100% IT100% LM85% DS63% LSE21% | 4/6 | 0.270 | 0.396 | 0.134 | 0.928 |

**Share of the model's true-positive alerts that R1 also flags** (ml4 frozen at the evaluation threshold): P0-104 81%, P1-202 54%, P2-302 100%, P3-402 54%, P4-501 95%, P4-502 98%. (On P4, R1 flags ~52% of ALL events, so the overlap there is mostly the rule being noisy, not the model leaning on it.)

**7.2 Group permutation** (frozen ml4, one seed; change in macro per-type PR-AUC when one family of feature columns is shuffled across the evaluated rows):

| Family permuted | P0-104 (base 0.582) | P1-202 (base 0.255) | P2-302 (base 0.409) | P4-501 (base 0.543) |
|---|---|---|---|---|
| ip (public vs private, per-IP failures) | -0.195 | -0.066 | -0.097 | -0.159 |
| failed authentication | -0.098 | -0.128 | -0.105 | -0.187 |
| hour of day / off-hours | -0.029 | -0.032 | -0.041 | -0.038 |
| location / city | -0.127 | -0.024 | -0.129 | -0.091 |
| resource patterns | -0.183 | -0.223 | -0.093 | -0.148 |
| command patterns | -0.122 | -0.116 | -0.090 | -0.193 |
| device fingerprint | -0.008 | -0.006 | -0.003 | -0.005 |
| volume / timing | -0.095 | -0.118 | -0.049 | -0.120 |
| ALL generator-artifact groups together | -0.577 | -0.252 | -0.403 | -0.522 |

**7.3 Cross-generator performance:** section 6 (PR-AUC by profile). The comparison that answers 'does it survive without shortcuts': P0 (rule-visible: R1 recall 0.70, PR-AUC 0.922) vs P1 (attackers avoid the shortcuts: R1 recall 0.358, PR-AUC 0.591) and P2 (rule useless, PR-AUC 0.843).

**Verdict.** The reference-profile numbers are inflated by attacks that a two-field rule already separates (brute force, stuffing, impossible travel). The model does add real signal beyond the rule: it detects 50 of the 65 incidents on which R1 never fires; but its event-level recall on rule-silent events is only 27%-62%, and it degrades sharply on stealthy insiders (P1). Nothing in ML-4 supports claiming real-world performance.

## 8. Device-spoofing signals

**8.1 What is observable today.** One string per event (`device_fingerprint = OS|MAC|protocol`, 100% coverage). Derived features: `fingerprint_mismatch` (value not previously seen for the entity) and `fingerprint_novelty` (decaying). Measured on the sealed datasets:

| Dataset | DS events | `fingerprint_mismatch` fires: DS / benign | as a detector: precision | same-fingerprint-from-2-IPs (10 min) fires: DS / benign | benign fire rate | as a detector: precision |
|---|---|---|---|---|---|---|
| P0-104 | 81 | 6 / 0 | 1.000 | 29 / 1835 | 4.99% | 0.014 |
| P1-202 | 135 | 6 / 0 | 1.000 | 8 / 2954 | 8.02% | 0.003 |
| P2-302 | 55 | 4 / 0 | 1.000 | 13 / 1662 | 4.53% | 0.007 |
| P3-402 | 215 | 6 / 8 | 0.429 | 6 / 4 | 0.01% | 0.076 |
| P4-501 | 170 | 4 / 0 | 1.000 | 35 / 769 | 2.09% | 0.027 |
| P4-502 | 170 | 4 / 0 | 1.000 | 0 / 776 | 2.09% | 0.000 |

**8.2 Detection by spoofing variant** (pooled over the sealed datasets; incidents detected of incidents):

| Variant / attacker uses a new source IP | Incidents | ml4/frozen | ml4/adaptive | ml3 | shipped (as deployed) |
|---|---|---|---|---|---|
| clone / new IP=False | 4 | 3 | 0 | 0 | 0 |
| clone / new IP=True | 5 | 5 | 1 | 1 | 0 |
| full_swap / new IP=False | 15 | 12 | 1 | 1 | 0 |
| partial_mac / new IP=False | 4 | 3 | 0 | 0 | 0 |
| partial_os / new IP=False | 4 | 4 | 2 | 1 | 2 |
| protocol_only / new IP=False | 7 | 6 | 5 | 2 | 1 |

**8.3 Signal catalogue** (observable in real telemetry? in the current schema? generator-specific? verdict). Nothing was added to the model: a signal is only listed, never used, and anything that would need generator ground truth is marked unsuitable.

| Signal | In current schema | Observable in real telemetry | Generator-specific | Verdict |
|---|---|---|---|---|
| device_fingerprint string (OS\|MAC\|protocol) | True | yes (NAC/DHCP/EDR/agent inventory), partly spoofable | the value semantics are: exactly one stable string per entity, changed only by attacks and by explicit refresh events | available; kept as-is |
| fingerprint concurrency (same fingerprint seen from >=2 source IPs within minutes) | True | yes - derivable from (fingerprint, source_ip, timestamp) already in every event | no, but dynamic-IP / VPN users create benign concurrency | candidate (needs a benign-concurrency measurement; see coverage below) |
| TLS client fingerprint (JA3/JA4) | False | yes (Zeek/IDS/proxy), stable per client stack, spoofable by mimicry | no | candidate (requires a collector field) |
| client certificate serial / thumbprint / issuer (mTLS, 802.1X) | False | yes for managed edge devices and service accounts | no | candidate (strong for edge/service, absent for password users) |
| MAC OUI vs claimed OS/vendor | partly (MAC inside the fingerprint string) | yes at layer-2 (DHCP/NAC); modern clients randomise MAC | yes in this data (MACs are random, OUIs carry no vendor information) | unsuitable on this data; conditional in reality (fixed IoT only) |
| TCP/IP stack fingerprint (TTL, window, options) vs claimed OS | False | yes at a network sensor; unreliable behind proxies/NAT | no | candidate (noisy) |
| switch port / VLAN / AP / network segment | False | yes for wired/Wi-Fi via NAC; not for VPN/remote | no | candidate for on-premise edge/OT |
| hardware attestation / TPM measured boot / secure element | False | yes where deployed (managed fleets, modern IoT) | no | candidate (strongest, deployment-dependent) |
| firmware / build version reported by heartbeat | False | yes for edge devices; changes legitimately on updates | no | candidate (needs update-event awareness) |
| traffic cadence / inter-arrival regularity of periodic devices | partly (timestamps -> interevent_gap_zscore) | yes | yes: only the OT profile has periodic devices | candidate for periodic devices only |
| clock skew estimate | False | research-grade, needs high-resolution timestamps | n/a | unsuitable for production |
| any generator ground truth (entity_profiles.json expected fingerprint, an 'is_spoofed' flag) | False | NO - an oracle | yes | UNSUITABLE (would leak the label; never used) |

**Reading.** `fingerprint_mismatch` is precise only where benign fingerprint changes never happen (a property of most profiles, not of real fleets - P3's benign firmware refresh drops its precision); it fires on the first event only, and never on a clone. Clone detection in these data does not come from device identity: 8/9 clones were detected, including 3/4 that reuse the victim's own IP, through side effects of the generator's spoofing bursts (rapid repeated sessions at arbitrary hours). A real cloner that behaves like the victim would not leave those side effects. What real telemetry would have to add is identity evidence that a clone cannot copy and a refresh does not change: hardware/attestation or certificate identity, TLS client fingerprint, network attachment.

## 9. Frozen vs adaptive baseline under benign drift

Design: six datasets share seed 601 (profile P0, reduced size). `DR-ctrl` has no drift; each other dataset applies ONE drift kind to the same 40% of entities as a regime change ramping over days 22-28 and persisting afterwards (hours: +3.5 h working-day shift; resources: 4 new non-sensitive resources; location: relocation with a new IP pool; device: new OS / MAC; volume: +90% events). Benign events changed by the drift are labelled `benign_drift` (negative). Attacks are spread evenly before (<22), during and after (>=28). The same frozen global model and weights are used; only the baseline differs: `frozen`; adaptive EWMA with the production alpha 0.02 and an **alert-threshold guard** (an event the frozen model would alert on never updates the baseline), also alpha 0.005 and 0.08; the ML-3-style guard (`prodguard`: block only above the whole TRAIN fused range); and no guard. Operating points are the evaluation-only VAL-derived thresholds of each mode family; because the two modes use different thresholds, a **matched** comparison is also given (each variant's threshold set on its own BEFORE-drift negatives for FPR 0.5%, then applied during/after).

**9.1 Per phase at the VAL-derived thresholds** (PR-AUC / recall / FPR on benign-drift events / incident recall):

| Dataset | Baseline | before | during | after | FPR on normal (all phases) |
|---|---|---|---|---|---|
| DR-ctrl | frozen | 0.93 / 0.85 / - / 0.77 | 0.97 / 0.93 / - / 0.92 | 0.93 / 0.90 / - / 0.92 | 0.0087 |
| DR-ctrl | adaptive_a0.02 | 0.90 / 0.83 / - / 0.69 | 0.96 / 0.88 / - / 0.77 | 0.90 / 0.86 / - / 0.69 | 0.0032 |
| DR-hours | frozen | 0.93 / 0.85 / - / 0.77 | 0.97 / 0.93 / 0.009 / 0.92 | 0.93 / 0.90 / 0.010 / 1.00 | 0.0087 |
| DR-hours | adaptive_a0.02 | 0.90 / 0.83 / - / 0.69 | 0.96 / 0.88 / 0.007 / 0.77 | 0.91 / 0.86 / 0.007 / 0.69 | 0.0031 |
| DR-resources | frozen | 0.93 / 0.85 / - / 0.77 | 0.97 / 0.93 / 0.068 / 0.92 | 0.93 / 0.90 / 0.031 / 0.92 | 0.0086 |
| DR-resources | adaptive_a0.02 | 0.90 / 0.83 / - / 0.69 | 0.96 / 0.88 / 0.000 / 0.77 | 0.90 / 0.86 / 0.013 / 0.69 | 0.0032 |
| DR-location | frozen | 0.93 / 0.85 / - / 0.77 | 0.96 / 0.93 / 0.151 / 0.92 | 0.92 / 0.90 / 0.086 / 0.92 | 0.0087 |
| DR-location | adaptive_a0.02 | 0.90 / 0.83 / - / 0.69 | 0.95 / 0.88 / 0.035 / 0.77 | 0.90 / 0.86 / 0.010 / 0.69 | 0.0031 |
| DR-device | frozen | 0.93 / 0.85 / - / 0.77 | 0.96 / 0.93 / 0.020 / 0.92 | 0.93 / 0.90 / 0.022 / 0.92 | 0.0063 |
| DR-device | adaptive_a0.02 | 0.90 / 0.83 / - / 0.69 | 0.95 / 0.88 / 0.010 / 0.77 | 0.90 / 0.86 / 0.008 / 0.69 | 0.0025 |
| DR-volume | frozen | 0.93 / 0.85 / - / 0.77 | 0.96 / 0.93 / 0.012 / 0.92 | 0.91 / 0.92 / 0.039 / 1.00 | 0.0126 |
| DR-volume | adaptive_a0.02 | 0.90 / 0.83 / - / 0.69 | 0.95 / 0.88 / 0.005 / 0.77 | 0.89 / 0.86 / 0.012 / 0.69 | 0.0050 |

**9.2 Matched operating point** (threshold set per variant for FPR 0.5% on its own before-drift negatives). Recall and benign-drift FPR during / after:

| Dataset | Baseline | during: recall / FPR on benign drift / incident recall | after: recall / FPR on benign drift / incident recall |
|---|---|---|---|
| DR-ctrl | frozen | 0.931 / - / 0.92 | 0.893 / - / 0.92 |
| DR-ctrl | adaptive_a0.005 | 0.919 / - / 0.85 | 0.879 / - / 0.85 |
| DR-ctrl | adaptive_a0.02 | 0.909 / - / 0.85 | 0.870 / - / 0.77 |
| DR-ctrl | adaptive_a0.08 | 0.809 / - / 0.77 | 0.867 / - / 0.77 |
| DR-hours | frozen | 0.931 / 0.009 / 0.92 | 0.896 / 0.010 / 1.00 |
| DR-hours | adaptive_a0.005 | 0.919 / 0.009 / 0.85 | 0.879 / 0.009 / 0.85 |
| DR-hours | adaptive_a0.02 | 0.909 / 0.009 / 0.85 | 0.870 / 0.007 / 0.77 |
| DR-hours | adaptive_a0.08 | 0.809 / 0.007 / 0.77 | 0.867 / 0.010 / 0.77 |
| DR-resources | frozen | 0.931 / 0.068 / 0.92 | 0.893 / 0.031 / 0.92 |
| DR-resources | adaptive_a0.005 | 0.919 / 0.068 / 0.85 | 0.879 / 0.027 / 0.85 |
| DR-resources | adaptive_a0.02 | 0.909 / 0.068 / 0.85 | 0.870 / 0.018 / 0.77 |
| DR-resources | adaptive_a0.08 | 0.809 / 0.068 / 0.77 | 0.867 / 0.013 / 0.77 |
| DR-location | frozen | 0.931 / 0.145 / 0.92 | 0.893 / 0.082 / 0.92 |
| DR-location | adaptive_a0.005 | 0.919 / 0.128 / 0.85 | 0.879 / 0.038 / 0.85 |
| DR-location | adaptive_a0.02 | 0.909 / 0.076 / 0.85 | 0.870 / 0.025 / 0.77 |
| DR-location | adaptive_a0.08 | 0.809 / 0.070 / 0.77 | 0.867 / 0.015 / 0.77 |
| DR-device | frozen | 0.931 / 0.020 / 0.92 | 0.893 / 0.022 / 0.92 |
| DR-device | adaptive_a0.005 | 0.919 / 0.018 / 0.85 | 0.879 / 0.018 / 0.85 |
| DR-device | adaptive_a0.02 | 0.909 / 0.019 / 0.85 | 0.870 / 0.019 / 0.77 |
| DR-device | adaptive_a0.08 | 0.809 / 0.021 / 0.77 | 0.867 / 0.020 / 0.77 |
| DR-volume | frozen | 0.931 / 0.010 / 0.92 | 0.922 / 0.037 / 1.00 |
| DR-volume | adaptive_a0.005 | 0.919 / 0.012 / 0.85 | 0.882 / 0.017 / 0.92 |
| DR-volume | adaptive_a0.02 | 0.911 / 0.012 / 0.85 | 0.873 / 0.017 / 0.85 |
| DR-volume | adaptive_a0.08 | 0.809 / 0.013 / 0.77 | 0.870 / 0.027 / 0.85 |

**9.3 Reading.** At the matched pre-drift FPR the adaptive baseline (alpha 0.02) lowers the false-alert rate on drifted-but-benign events in the AFTER phase by hours 29% (1.0% -> 0.7%), resources 43% (3.1% -> 1.8%), location 70% (8.2% -> 2.5%), device 10% (2.2% -> 1.9%), volume 54% (3.7% -> 1.7%), at an average recall cost of 0.024 (during/after, all datasets). Drift kinds differ a lot: hours drift barely troubles the frozen baseline, location drift is the worst (frozen alerts on 14.5% of drifted events while the ramp is in progress), and adaptation never reaches zero. In the drift-free control the adaptive baseline still costs ranking quality and incident recall, so adaptivity is a trade, not a free improvement. The guard matters more than alpha: `prodguard` (PR-AUC 0.68) and `noguard` (0.53) collapse because attack bursts poison the baseline; alpha 0.005 / 0.02 / 0.08 give overall PR-AUC 0.94 / 0.92 / 0.86 in the control. No baseline is declared the winner: the answer depends on the relative cost of a false alert on drifted entities vs a missed low-intensity attack.

## 10. Reproducibility

Two complete runs of the whole evaluation (C, D) plus the serving-parity audit twice (A, B); an earlier full run (A) preceded the final code (section 11).

| Comparison | Metric values compared | Differences | Max abs diff | Prediction arrays identical | Feature matrices identical | Dataset set identical | Frozen config identical | Learned content identical | Exactly reproducible |
|---|---|---|---|---|---|---|---|---|---|
| C vs D (canonical) | 115534 | 0 | 0.0 | 126/126 | True | True | True | True | True |

Parity report A vs B: 2485 values compared, 0 differences (identical: True).

Earlier full run A (before the TRAIN-reference datasets and the sealed signal ablation were added to the pipeline) vs C: dataset set identical True, frozen config identical True, learned content identical True; value differences on the 93811 metric keys both runs contain: 106 (hashes.metric_sections.dev_evaluation, hashes.metric_sections.sealed_evaluation, integrity.vault_log[10].access, integrity.vault_log[10].dataset); keys only in C: 21723 (the added dev references and signal ablation); shared prediction arrays identical: 108/108.

| Item | Value |
|---|---|
| Dataset-set sha256 | `0af08367cf1e6cf2d8d37dfdf0b5b755f4fbfb10eb017c9090dc31dd001cd8a4` |
| Split-plan sha256 | `d7828053c855ff23abaa11f39c021b3a0c931b37175f5d6bc1caae330350315b` |
| ML-4 config sha256 | `2c96f334b5a877552d565d92f2df1d819f1bca2bf7e3bec90f9358505e625e1b` |
| Frozen config sha256 | `4e9c8d80b1ad78860e2547b45933b043bcf6883bd185e59bb14e70c3703376c4` |
| ml4 learned-content sha256 (combined) | `44c63dc9f9174de1abd880de09ebc624f1927965ace390407681208a9a089dea` |
| Metric-section sha256 | dev_evaluation `65a7d6d22f14`; sealed_evaluation `6adb1b35f2bb`; drift_evaluation `06c63f79d8a1`; audits `3b8c552cc1ad`; selection `48e9fbcef5bd` |
| Prediction-array hashes | 126 arrays hashed (sha256 each) in the metrics JSON |
| Feature-matrix hashes | 19 datasets (sha256 each) |
| Feature stage note | recomputed ['P0-104', 'P2-302', 'P4-501', 'DR-hours', 'P3-401', 'orig42'] (all hash-identical to run A); other datasets read from run A's cache after array-hash verification |
| Seeds | model seed 42 (production convention), ML-4 seed 20260922, dataset seeds in the registry; threads 1 |
| Environment | Python 3.14.7, numpy 2.5.3, pandas 3.0.6, scikit-learn 1.9.1, torch 2.14.0+cpu |
| Production model sha256 (unchanged) | `381ae379ae1c5a7c3b4ac38f3df039c1b0de3268889f7df344670510de861684` |

`ml4_global.joblib` is not byte-stable across runs (scikit-learn tree nodes carry uninitialised struct padding, verified in ML-3); the learned content (scaler, forest, GRU weights, score distributions, feature list) is compared by content hash instead - identical across runs: True.

## 11. Methodology changes and disclosures

* **Generator determinism bug (found and fixed before any evaluation).** A second generation of the same datasets differed in 12 of 19 `events.csv` files: the command-pool builder iterated a `set` of role names, whose order depends on Python's per-process string hash seed. Fixed with `sorted(...)`; verified by generating all datasets twice under different `PYTHONHASHSEED` values (identical dataset-set hash) and again in every run's `--regen` check. Features that had been computed on the buggy build were discarded and recomputed.
* **Adaptive-baseline guard changed after dev results, before any sealed data was read.** The first dev pass used the ML-3 guard (block only events above the whole TRAIN fused range). Under baseline-heavy weights that guard is as weak as no guard (ML-4 dev PR-AUC 0.34 vs 0.84 frozen), which would have made the frozen-vs-adaptive comparison unfair to adaptivity. The primary adaptive variant now uses the frozen model's own alert threshold as the guard; the old guard is kept as the explicit `prodguard` variant. The first-pass dev metrics are kept in `reports/ml4_runs/A/DEV_FIRST_PASS_prodguard_metrics.json`.
* **Private-IP definition corrected.** ML-2/ML-3 shortcut rules treated only 10.* and 192.168.* as private; ML-4 uses RFC1918 (adds 172.16-31.*), which matters for profiles that use 172.16.x.
* **Evaluation operating points are VAL-derived and evaluation-only.** They are not production thresholds; the label-free 1% alert budget is reported next to them. ML-3's risk mapping cannot be reproduced for the ML-3 candidate (its TRAIN fused curve was not stored), so only its fused score is evaluated.
* **Weights selected on VAL datasets of different profiles** (mean over datasets of the macro per-type PR-AUC), the ML-3 rule generalised; the ML-3 finding that the GRU autoencoder gets weight 0 recurs.
* **Feature-recompute subset.** Run A computed all 19 feature matrices; the canonical runs re-computed a stratified subset from scratch (hash-identical to A) and read the rest from A's cache after array-hash verification.
* **Group permutation** was run on 4 of the 6 sealed standard datasets (P0-104, P1-202, P2-302, P4-501) with one seed each, for time.
* **Post-hoc analyses** (matched-operating-point drift comparison, R1 share of true positives, variant coverage, near-duplicates by profile, Wilson intervals) are deterministic functions of the run outputs and the data files computed in `eval_ml4/compose.py`, after the sealed labels were unsealed; nothing feeds back.

## 12. Limitations

* All data are synthetic and come from one generator family; five profiles authored by the same hand are not five independent worlds. Independence of seeds is real; independence of profiles is partial (attack shapes recur across profiles, section 5).
* Whole-dataset splitting prevents identical incidents crossing, not shared attacker templates between two seeds of one profile (near-duplicate share above).
* Only 30-35 incidents per dataset; per-incident results have wide intervals (pooled detection 79-89%; low-slow exfiltration 24-61%). Differences of a few incidents are noise; no significance tests beyond the Wilson intervals.
* Evaluation thresholds derived on two VAL datasets do not transfer (alert rate 0.7%-8.0% across the sealed datasets); operating-point metrics are therefore secondary to the threshold-free ones. Nothing here is a production threshold.
* The main evaluation uses the training representation; real platform events reach the model through the mismatched contract of section 4, so absolute numbers are not what production would see.
* The drift study covers five single-cause regime changes on 40% of entities; real drift is mixed, gradual and non-stationary. Alpha sensitivity is three values.
* Group permutation is one seed on four datasets; the device-spoofing signal audit uses the schema's single fingerprint string and cannot test signals the collector does not provide.
* The ML-3 candidate and the shipped model are evaluated with a per-dataset onboarding profile (not their original per-entity profiles); this favours them slightly relative to deployment.
* Runs C, D and A share the same code lineage; independent re-implementation of the evaluation was not attempted.

## 13. Readiness for calibration and ML-5 recommendation

**Is the foundation strong enough to proceed to calibration? No - not yet.** What is established and what is not:

| Prerequisite | Status | Evidence |
|---|---|---|
| Deterministic, hashed, chronologically ordered multi-profile data | **met** | 18 datasets, byte-identical regeneration, dataset-set hash `0af08367cf1e6cf2` |
| Sealed-test protocol enforced in code and reproducible | **met** | Vault, frozen-before-unseal; canonical runs exactly reproducible: True |
| Performance generalises across seeds | **met** (within a profile) | PR-AUC gaps <= 0.054 |
| Performance generalises across profiles | **partly** | PR-AUC 0.591-0.967; stealth/slow attacks missed; thresholds do not transfer |
| Score semantics stable enough to calibrate | **not met** | one fused threshold gives 0.7%-8.0% alert rates across sealed datasets; risk score saturates; GRU weight 0 |
| Serving contract matches the training representation | **not met** | 8 mismatches, all unresolved; V9 changes 24 features; silent auth default drops shipped recall 0.68 -> 0.16 |
| A learnable signal for device spoofing and low-and-slow exfiltration | **not met** | first-event-only mismatch flag; low-slow 42% pooled detection |
| Independent attack classes for learning | **not met** | count rule met, behaviour coverage thin, near-duplicate templates |
| Any real-telemetry validation | **not met** | everything is synthetic |

**Recommendation on ML-5:** justified only as a *narrow, ordered* phase - not as 'calibration' in the abstract:

1. **Fix serving parity first** (entity_type, duration unit, command separator, timezone, missing-field policy, idempotency/ordering), then re-run the ML-4 parity audit as a regression test. Calibrating a score whose inputs are distorted is wasted effort.
2. **Make thresholds per-deployment, not global:** the ML-4 data show alert rates from 0.7% to 8.0% at one fused threshold; calibration has to be anchored to each deployment's own onboarding distribution (a label-free alert budget behaved consistently here) - a design study on the ML-4 datasets, before any probability calibration.
3. **Only then calibrate probabilities**, per profile family, using the multi-profile datasets, with the parity variants included as a stress set.
4. **In parallel, treat device-identity and low-and-slow as data problems, not modelling problems:** specify the collector fields (section 8), extend the generator to emit them, and re-run this exact pipeline as the clean test.
5. **Do not deploy** the ML-4 artifact, the ML-3 candidate, or any adaptive-baseline change on this evidence.

**Blockers:** the eight serving-parity mismatches; no device-identity or low-and-slow signal; thresholds that do not transfer; synthetic-only data; a classifier with no learnable class.

---
*Generated by `eval_ml4.compose` from `reports/ml4_runs/C/metrics.json`; every number is read from JSON or the data files. Candidate artifact: `models/candidates/ml4/` (NOT DEPLOYED). Production files: unchanged.*

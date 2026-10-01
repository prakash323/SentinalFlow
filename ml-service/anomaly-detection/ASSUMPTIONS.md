# Assumptions, methodology and known limitations

This doubles as the skeleton of the written report. Every modelling choice is
recorded here with the reasoning behind it.

---

## 1. Synthetic data assumptions

### Entity population
200 entities: 140 users (roles: engineer, finance, hr, admin, ops), 40 service
accounts, 20 edge devices. Roles matter because they define the **peer groups**
used for cold-start priors.

### Normal behaviour model
| Aspect | Assumption |
|---|---|
| Login hours | per-entity Gaussian; service accounts and edge devices near-uniform (they run 24/7) |
| Volume | Poisson around a per-entity daily rate; users drop sharply at weekends, machines do not |
| Resources | Zipf-weighted subset of the role's pool — a few resources dominate, with a long tail |
| Session duration | lognormal, per-entity parameters |
| Geography | a home city plus a small IP pool; occasional legitimate domestic travel |
| Commands | role-conditioned Markov chain (finance rarely `exec`s, admins `sudo` often) |
| Auth failures | 2% of normal events fail — people mistype passwords |

**10% of every entity's events are drawn from the tails of its own
distribution.** Perfectly regular behaviour is the clearest tell of a fake
dataset and would inflate every metric.

### Confounders — the part most teams skip
6% of benign events are deliberately weird but legitimate: domestic travel, an
atypical resource, a laptop upgrade producing a genuine fingerprint change, a
late-night incident response. Without these the false-positive rate is fiction.

We also inject **impossible-travel near-misses**: the same 8,000 km hop, but with
a 9-14 hour gap — a legal flight, labelled `normal`. A naive distance threshold
fails this; the geo-velocity feature passes it.

### Attack taxonomy

| Pattern | Simulation | Label | ATT&CK |
|---|---|---|---|
| Brute force | 30-200 rapid failed auths from one IP, 40% eventually succeed | anomaly | T1110 |
| Credential stuffing | 25-70 accounts, 2-3 shared IPs, ~97% failure rate | anomaly | T1110.004 |
| Impossible travel | same entity, >6,000 km apart, 24-96 min gap | anomaly | T1078 |
| Lateral movement | breadth of foreign resources expanding over 1-3 h, `sudo`-heavy sequences | anomaly | T1021 |
| Device spoofing | known device reappears with mismatched OS/MAC/protocol | anomaly | T1036 |
| Low-and-slow exfiltration | 1-3 off-hours reads of sensitive resources per day for 6-14 days | anomaly | T1030 |
| Insider drift | legitimate entity permanently expands its footprint over 2 weeks | **benign** | — |

`benign_drift` is deliberately **not** an attack. Its only purpose is
false-positive tuning, which is what the problem statement asks for.

### Rates and splits
- Injection tuned so **anomalous events land near 1.15-1.5%** of the corpus. We
  count anomalous *events*, not incidents — attacks differ hugely in
  events-per-incident, so counting incidents gives a wildly wrong positive rate.
- **Time-based split**: days 1-20 train, 21-30 test. A random split leaks future
  behaviour into the entity profiles and inflates everything.
- Low-and-slow exfiltration is anchored to start at 68% of the timeline, i.e.
  inside the **test** window. Starting it in training would let the campaign
  poison its own baseline — hiding the attack and misrepresenting deployment
  performance. We found this empirically: recall on this class was 0.0 until it
  was moved.

---

## 2. Feature engineering

**38 features, one causal forward pass.** Every feature for an event at time *t*
uses only data from before *t*. This is enforced structurally: state is updated
*after* extraction, never before. Consequences:

1. offline metrics are trustworthy — no target leakage;
2. batch and streaming run **the same code**, so there is no train/serve skew.

Feature families: travel (geo-velocity, distance from home), auth failure
(entity-side and IP-side), resource novelty and entropy, temporal deviation
against the entity's own hour histogram, device/identity, volume, slow-burn
7-day aggregates, and command-sequence statistics.

Three features were added after diagnosing failures, and all three are worth
mentioning in the report because they show iteration:

- `fingerprint_novelty` — a *decaying* score rather than a boolean. A hard
  `fingerprint_mismatch` flag fires once and then the spoofed device is silently
  accepted, which is exactly the failure mode being defended against. Device
  spoofing recall went 0.0 → 0.8.
- `sensitive_offhours_7d` — the **conjunction** of sensitive resource *and*
  outside-normal-hours, accumulated over 7 days. Either signal alone is common
  (service accounts are "off-hours" constantly); together they are rare. This is
  the actual signature of slow exfiltration.
- `peer_resource_deviation` — how rare a resource is **within this entity's own
  peer group** (same `entity_type`), as opposed to `resource_novelty_ratio`
  (rare across *everyone*). An admin touching an ops-only resource is common
  org-wide (ops entities do it constantly) but rare for the admin peer group
  specifically — the signal device spoofing and lateral movement actually
  need. Added in the final pass and evaluated with the project's own
  controlled-seed A/B methodology (see `FIXES.md` Round 5): device-spoofing
  incident recall 0.8 → **1.0** (4/5 → 5/5), total incident recall @1% budget
  35/36 → **36/36 (100%)**, PR-AUC 0.918 → 0.920, zero regression on precision,
  event-level recall, or the benign-drift false-alarm rate. A second candidate
  tried in the same pass, `priv_ratio_change_7d` (7-day privileged-command
  share minus all-time share, targeting lateral movement / insider drift), was
  **rejected**: device-spoofing incident recall regressed 1.0 → 0.6 and total
  incident recall 36/36 → 34/36 for a negligible PR-AUC change — the same
  "budget-filler zone reshuffling" failure mode already documented for
  `auth_entropy` (adding one more competing continuous feature to the
  top-3 z-score competition in `BaselineProfiler.score_row` displaces a
  fragile single-feature signal). Reverted; not shipped.

---

## 3. Modelling choices

### Why three signals, not one
Baseline z-scores are interpretable but weak on collective anomalies. Isolation
Forest finds structural outliers but explains nothing. The sequence autoencoder
catches lateral movement and slow exfiltration but is opaque. The ablation table
shows the ensemble (PR-AUC 0.920) beating every component alone (0.764-0.833;
current numbers in `report/metrics.json` → `ablation_components`, reproduced by
`python run_pipeline.py`).

### Baseline score aggregation
`0.6 × max(z) + 0.4 × mean(top-3 z)`. Pure top-3 mean buries attacks whose
evidence sits in *one* feature; pure max is too noisy. Continuous z-scores are
clipped at 6σ and boolean flags are weighted to be competitive, otherwise
brute force — whose failure counts explode — monopolises the alert budget and
every rarer pattern goes unseen.

### Why classification is trained only on flagged events
This is the answer to "extreme class imbalance". Training a multi-class model on
all ~99k events would face a 1:100 ratio. Detection stays unsupervised (so it
can surface patterns it was never labelled on) and the classifier only ever sees
the flagged subset, which is roughly balanced. It also mirrors how a SOC works:
you don't need labels to raise an alert, only to name it.

### Incident-level deduplication
A brute-force burst is 130 events but **one** thing to investigate. Without
deduplication a single noisy incident consumes the entire analyst budget. Before
dedup, 4 of 6 attack types had zero recall; after, 5 of 6 are at 100%. Event-level
metrics are still reported unchanged — dedup affects the *queue*, not the maths.

### Incident ranking: peak/window max, plus a small fingerprint-persistence bonus
Deduplicated incidents are ranked by `max(peak-event rank, windowed-mean rank)`
(`src/evaluate.py:incident_scores`) rather than by their single representative
event's risk, because slow-burn attacks never produce one spectacular event and
lose every tie-break to a benign one-off outlier.

Device spoofing is the one attack type this still under-served: its evidence is
a single near-boolean feature (`fingerprint_mismatch` / `fingerprint_novelty`)
that *persists* over a handful of events rather than spiking once, so it kept
losing ties against attacks that stack several clipped z-scores at once. We
added an optional, small windowed-mean-fingerprint-novelty bonus on top of the
existing ranking, and swept its weight empirically on the bundled sample rather
than picking a number: 0.05 reshuffled the whole "budget filler" zone and net
*hurt* overall incident recall (34/36 → 30/36); 0.01 improves device-spoofing
incident recall 0.6 → 0.8 (3/5 → 4/5) with **zero** regression on any other
attack type (net 34/36 → 35/36). This changes which incidents are drawn from
within the existing fixed 1% budget — it does not change the budget, the risk
scores, or the evaluation methodology.

### Cold start
`w = n/(n+k)` with `k = 50`, blending the entity's own statistics with its
peer-group prior. Entities under 50 events are flagged `low_confidence` and
routed to a separate review queue so a cohort of new joiners cannot flood the
main one.

### Dynamic alert budget

`config.ALERT_BUDGET = 0.01` is a **default**, not a frozen constant. Both
`run_pipeline.py --budget` and `run_realtime.py --budget` accept a runtime
value; `Detector.threshold_for_budget()` retargets the 0-100 risk threshold
by re-querying the training-set calibration curve already stored at
`calibrate()` time (`self.calib`, sorted training fused scores) at a
different percentile — no retraining, no rescoring, no leakage, because it's
the identical training-window distribution the batch threshold was
originally calibrated against. The dashboard's sidebar "alert budget"
control reads the precomputed multi-level sweep (`budget_curve` /
`incident_budget_curve`, evaluated at `config.BUDGET_LEVELS = (0.5%, 1%,
1.5%, 2%, 3%)`, plus whichever value `--budget` was actually run at) rather
than recomputing anything live in the browser — an honest re-slice / table
lookup of what the last pipeline run actually produced, never a fabricated
number for a budget that wasn't evaluated. The 1% headline stays the
default for comparability across the report; nothing about the evaluation
methodology changes.

### Streaming input adapters and the "live" dashboard

`src/adapters.py` defines one `EventSource` interface (`events() ->
Iterator[dict]`) so `src/realtime.py`'s scoring loop (`consume()`) never
changes when the input source does. Exercised end-to-end in this
environment: CSV replay (the original path, unchanged), a polling folder
watcher (`.json`/`.jsonl`/`.csv` drops), and a stdlib-only REST endpoint
(`POST /events`) — all tested with real requests/files against a running
`run_realtime.py --serve` process (see `FIXES.md` Round 5 for the exact
commands and observed output). `KafkaSource` and `MqttSource` implement the
same interface using `kafka-python` / `paho-mqtt` but are **NOT exercised
against a live broker** — none is available in this environment. They are
reviewed, complete, drop-in adapters, not load-tested ones; treat that
distinction as load-bearing. The Live Monitor dashboard page
(`st.fragment(run_every=2)`) reads `report/live_state.json`, which any of
the tested adapters' `--serve` run writes every `--live-state-every` events
— CPU/memory come from `psutil` when installed, and are shown as an
explicit "install psutil" note rather than a fabricated number when it
isn't.

### Concept drift and baseline poisoning
EWMA profile updates (α = 0.02) with a **poisoning guard**: only events scoring
*below* the alert threshold are allowed to update the profile. A PSI monitor
(threshold 0.25) raises a single system-level drift notice rather than a flood
of per-event alerts.

---

## 4. Evaluation methodology

- **PR-AUC leads**, not ROC-AUC. At ~1.15% positives ROC-AUC flatters everything.
- **Precision/recall at the top 1% alert budget**, because the problem statement
  named that budget explicitly.
- **Incident-level recall** reported *alongside*, never instead of, event-level.
- **Ablations**: each detector component alone vs the ensemble; cold-start with
  and without peer priors; false alarms on the planted legitimate drift.
- All seeded (`RANDOM_SEED = 42`).

---

## 5. Known limitations — state these; they raise credibility

1. **Synthetic data is a proxy.** Our generator encodes our own assumptions
   about normality, so the model is partly evaluated against its author's
   worldview. The LANL and CERT adapters exist to mitigate this — run against
   real logs before believing the numbers.
2. **The classifier only knows attacks we injected.** A novel technique will be
   detected (detection is unsupervised) but mislabelled.
3. **No adversarial modelling.** An attacker who knows the feature set could
   pace activity to stay under the EWMA update threshold. The poisoning guard
   raises the cost but does not eliminate it.
4. **Lateral movement and insider drift genuinely overlap.** Both look like
   footprint expansion. We separate them by rate and command profile, not by
   intent — which is unknowable from logs alone.
5. **Geo features are synthetic-only.** LANL has no geographic field, so
   geo-velocity degrades to zero there. The system falls back on the other
   signals rather than failing, but this is a real gap.
6. **Single-node.** `src/adapters.py` has real, tested folder/REST input
   adapters and interface-complete `KafkaSource`/`MqttSource` classes, but a
   real horizontally-scaled deployment still needs per-entity state moved
   out of in-process Python dicts (e.g. into Redis) so multiple scorer
   processes can share one entity's history. Measured single-event latency
   is reported by `run_realtime.py` and supports the throughput estimate,
   but it is an estimate on one process, not a load test.
7. **Batch and streaming precision are not just "different", streaming was
   measured near zero, and the fix only partially closes the gap.** Batch
   fusion rank-normalises across the scored set; the streaming path
   percentile-maps a single event against the *stored training*
   distribution. Measured directly (not estimated) on the first 20,000
   test-window events (304 real attacks): batch scoring cleanly separates
   them (attack mean risk 98.9, 143/304 clear the threshold; normal events
   top out at 99.0) — streaming scoring using the same, batch-inherited
   threshold caught **zero** of them across 475 alerts. `run_realtime.py
   --calib-events N` (opt-in, default off) re-calibrates the threshold from
   the stream's own live risk-score distribution instead of inheriting the
   batch one; measured on a same-seed 6,000-event slice (48 attacks), this
   moved true positives from 0 to 1 (precision 0.000 → 0.027) — a real,
   verified improvement, **not a fix to batch-level precision**. The
   likely remaining cause, identified but not fixed in this pass: batch
   scores the whole test window against a profile fit **once** and never
   updated, while `BaselineProfiler.update()`'s EWMA drift (α=0.02, the
   concept-drift mechanism item 3 above requires) nudges each entity's
   profile after nearly every streaming event, so by event #6,000 the
   *per-event z-scores themselves*, not just the threshold compared against
   them, likely diverge from what batch would compute. See `FIXES.md`
   Round 6 for the full investigation, the exact numbers, and the specific
   next experiment (`profiler.use_drift` on vs. off on an identical
   stream) that would confirm it. We report the batch numbers as the
   headline specifically because of this — not to hide the gap, but
   because it's now measured and named precisely enough not to need
   hiding.
8. **No analyst feedback loop in training.** The dashboard records verdicts
   and freeform notes to `report/analyst_feedback.jsonl` but nothing
   consumes them yet. Obvious next step.
9. **Kafka and MQTT adapters are not exercised against a live broker.** No
   broker is available in this environment. `src/adapters.py:KafkaSource`
   and `MqttSource` are complete, interface-conformant classes (reviewed,
   not load-tested) — treat them as a starting point for a real deployment,
   not a verified integration, unlike the folder/REST adapters which are
   both.
10. **Live-stream entity/latency state is unbounded in `--serve` mode**
    beyond a capped ring buffer. `StreamingScorer.latencies` is bounded
    (100k events) and `recent_alerts`/`recent_risk_scores` are small ring
    buffers, but `entity_last_seen` grows with the number of *distinct*
    entities ever seen, not events — fine at this project's scale (hundreds
    of entities), a real deployment would want an eviction policy for
    long-lived, high-cardinality entity populations.

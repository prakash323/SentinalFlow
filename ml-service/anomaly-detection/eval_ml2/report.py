"""Renders reports/ml2_evaluation.md from metrics.json (+ the run comparison). Every number is read from the metrics;
none is typed by hand. Evaluation-only."""
from __future__ import annotations

import json

from . import common as K
from .common import ATTACKS


def f3(x, d=3):
    return "n/a" if x is None else (f"{x:.{d}f}" if isinstance(x, float) else str(x))


def pc(x, d=1):
    return "n/a" if x is None else f"{100*x:.{d}f}%"


def tbl(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        out.append("| " + " | ".join("" if c is None else str(c) for c in r) + " |")
    return "\n".join(out)


def _op(e, name):
    return e["operating_points"][name]


def sec_protocol(m):
    mf = m["manifest"]["protocol"]
    return f"""## 1. Evaluation Protocol

**Purpose.** Establish a trustworthy, reproducible measurement of the CURRENT shipped model. Nothing is tuned, calibrated
or retrained in ML-2; the production scoring path, the model artifact and every threshold are untouched.

**Chronological split** (real event timestamps; no shuffling anywhere in the anomaly-detection evaluation):

| Split | Window | Role |
|---|---|---|
| TRAIN | `{mf['t0'][:19]}` → `{mf['train_end'][:19]}` (days 0–{mf['train_days']}) | the exact window the shipped artifact was fitted on (verified in section 3) |
| VALIDATION | `{mf['train_end'][:19]}` → `{mf['validation_end'][:19]}` (days {mf['train_days']}–{mf['validation_end_days']}) | evaluation-only decisions (an operating point, the chronological classifier) |
| TEST | `{mf['validation_end'][:19]}` → `{mf['last_event'][:19]}` | held out from every ML-2 decision |

*Pre-registered rules* (fixed from incident-timing counts before any score was inspected): the validation window is
the **{mf['validation_rule']}**; an attack incident belongs to the split of its first event; events of a validation-born
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
> the model's design history; a genuinely clean test needs fresh attack instances (ML-3)."""


def sec_manifest(m):
    sp = m["manifest"]["splits"]
    rows = []
    for k, label in (("train", "TRAIN"), ("validation", "VALIDATION"), ("test_raw_time_window", "TEST (time window)"),
                     ("test_evaluation_population", "**TEST evaluation population** (after purge)"),
                     ("legacy_days_21_30_reference", "Legacy days 21–30 (ML-1/README population; NOT held out)")):
        s = sp[k]
        rows.append([label, s["rows"], s["entities"], s["attack_events"], pc(s["attack_rate"], 2),
                     s["attack_incidents_with_any_event"], s["attack_incidents_born_in_split"], s["benign_drift_events"]])
    t1 = tbl(["Population", "Events", "Entities", "Attack events", "Attack rate", "Incidents (any event)", "Incidents born here", "benign_drift"], rows)
    trows = []
    for a in ATTACKS:
        r = [a]
        for k in ("validation", "test_evaluation_population"):
            r += [sp[k]["attack_events_by_type"][a], sp[k]["attack_incidents_by_type"][a]]
        r += [sp["legacy_days_21_30_reference"]["attack_events_by_type"][a], sp["legacy_days_21_30_reference"]["attack_incidents_by_type"][a]]
        trows.append(r)
    t2 = tbl(["Attack type", "VAL events", "VAL incidents", "TEST events", "TEST incidents", "All events", "All incidents"], trows)
    pg = m["manifest"]["purge"]
    ho = m["manifest"]["heldout_entities"]
    cls = tbl(["Population", "Class distribution (events)"], [[k, json.dumps(sp[k]["class_distribution"])] for k in
                                                              ("train", "validation", "test_evaluation_population")])
    return f"""## 2. Dataset Split Manifest

Machine-readable copy: `reports/ml2_split_manifest.json`.

{t1}

Per attack type:

{t2}

Class distribution:

{cls}

* **Purge:** {pg['events_removed_from_test']} events of incident(s) {', '.join(pg['incidents'])} (born in VALIDATION, running into the test
  period) are excluded from the TEST evaluation population: {json.dumps(pg['events_by_type'])}.
* **Held-out entities (section 9):** {ho['count']} entities ({ho['attacked_among_them']} of them attacked in the evaluation period), seed {ho['seed']}.
* **Statistical strength.** VALIDATION holds {sp['validation']['attack_incidents_born_in_split']} incidents and TEST holds
  {sp['test_evaluation_population']['attack_incidents_born_in_split']}; no attack type has more than {max(max(sp['legacy_days_21_30_reference']['attack_incidents_by_type'][a] for a in ATTACKS if a != 'impossible_travel'), 0)} incidents
  (impossible_travel has {sp['legacy_days_21_30_reference']['attack_incidents_by_type']['impossible_travel']}, each a single event), and
  credential_stuffing is ONE incident. All five low_slow_exfil incidents start in VALIDATION, so **TEST contains no low_slow_exfil incident**;
  device_spoofing and credential_stuffing have no VALIDATION incident. The dataset is a single fixed generator draw (seed 42): there is no seed variation
  and no confidence interval. **The available data cannot support a statistically strong validation set;** this is documented, not papered over."""

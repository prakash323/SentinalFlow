"""
Real-time streaming scorer.

Consumes events ONE AT A TIME, exactly as a Kafka consumer would, and emits an
alert within milliseconds. It reuses the same StreamingFeatureExtractor, the
same BaselineProfiler and the same trained models as the batch pipeline, so
there is no train/serve skew -- an important claim to be able to make.

Per event it:
  1. extracts features from streaming state          (no future data used)
  2. scores the entity baseline (with peer prior if the entity is new)
  3. scores Isolation Forest + sequence autoencoder
  4. percentile-fuses to a calibrated 0-100 risk score
  5. classifies the attack type and writes an explained alert
  6. feeds the event back into the baseline ONLY if it scored below threshold
     (poisoning guard)
  7. periodically runs a PSI drift check and raises a single system notice
     instead of a flood of per-event alerts
"""
from __future__ import annotations
from collections import defaultdict, deque, Counter
import json
import time
import numpy as np
import pandas as pd

import config as C
from src.features import StreamingFeatureExtractor, FEATURE_NAMES
from src.explain import Explainer

RECENT_ALERTS_MAXLEN = 50
ACTIVE_ENTITY_WINDOW_S = 3600.0  # "active" = seen an event in the last hour


class StreamingScorer:
    def __init__(self, profiler, detector, classifier=None, explainer=None,
                 threshold=None, budget=None, drift_every=5000,
                 calib_events=0, calib_budget=None):
        """
        `threshold` is the risk-100 alert bar to use as-is (typically the
        value baked into the trained artifact at batch-calibration time).
        `budget`, if given, takes precedence: the threshold is instead
        recomputed live from the detector's stored training calibration via
        `Detector.threshold_for_budget(budget)` -- this is what lets the
        real-time scorer retarget the analyst alert budget without
        retraining or re-scoring anything (see run_realtime.py --budget).

        `calib_events`, if > 0, opts into STREAM-NATIVE self-calibration
        (opt-in, default off -- existing behaviour and every number already
        reported for this project is unaffected unless this is explicitly
        requested): the batch/training-inherited `threshold` above is used
        as-is for the first `calib_events` live events (so nothing is ever
        silently dropped during calibration), while their risk scores are
        collected in the background; once `calib_events` have been seen, the
        threshold is replaced with the (1 - calib_budget) quantile of THOSE
        live scores, calibrated against the stream's own distribution
        instead of an inherited one. This is the fix ASSUMPTIONS.md's
        "batch and streaming scores are not numerically identical"
        limitation already names as the honest one: rank-normalised batch
        fusion and percentile-vs-training-distribution streaming fusion
        produce different absolute score distributions, so a threshold
        tuned on one can badly miscalibrate on the other over a long-running
        stream. See FIXES.md Round 6 for the measured effect.
        """
        self.extractor = StreamingFeatureExtractor()
        self.profiler = profiler
        self.detector = detector
        self.classifier = classifier
        self.explainer = explainer or Explainer(classifier)
        if budget is not None:
            self.threshold = detector.threshold_for_budget(budget)
        else:
            self.threshold = threshold if threshold is not None else 95.0
        self.budget = budget
        self._calib_remaining = int(calib_events)
        self._calib_budget = calib_budget if calib_budget is not None else \
            (budget if budget is not None else C.ALERT_BUDGET)
        self._calib_buffer = []
        self.calibrated_from_stream = False
        self.windows = defaultdict(lambda: deque(maxlen=C.SEQ_LEN))
        # Bounded so a long-running `--serve` process has flat memory use;
        # 100k events is far more than enough for stable latency percentiles.
        self.latencies = deque(maxlen=100_000)
        self.n = 0
        self.n_alerts = 0
        self.drift_every = drift_every
        self._drift_buf = []
        self.drift_notices = []
        # -- live-monitor state (src/adapters.py-fed continuous runs read
        # this via live_state(), periodically flushed to
        # report/live_state.json by run_realtime.py --serve) --
        self.entity_last_seen = {}          # entity_id -> wall-clock time.time()
        self.attack_type_counts = Counter()
        self.recent_alerts = deque(maxlen=RECENT_ALERTS_MAXLEN)
        self.recent_risk = deque(maxlen=1000)
        self.started_at = time.time()

    # ------------------------------------------------------------------
    def warmup(self, events: pd.DataFrame):
        """
        Replay the training window through the feature extractor WITHOUT
        scoring or alerting, so every entity arrives at the live window with
        the same history the batch model was fitted on.

        Skipping this is a subtle but serious bug: a cold extractor makes the
        first events of every entity look novel, and the queue fills with
        false positives that have nothing to do with the model's quality.
        """
        for ev in events.to_dict("records"):
            feat = self.extractor.update_and_extract(ev)
            self.windows[ev["entity_id"]].append(
                np.array([feat[f] for f in FEATURE_NAMES], dtype=float))
        return self

    def process(self, event: dict):
        t0 = time.perf_counter()
        feat = self.extractor.update_and_extract(event)
        vec = np.array([feat[f] for f in FEATURE_NAMES], dtype=float)

        w = self.windows[event["entity_id"]]
        w.append(vec)
        win = np.zeros((C.SEQ_LEN, len(FEATURE_NAMES)), dtype=np.float32)
        arr = np.array(w, dtype=np.float32)
        win[C.SEQ_LEN - len(arr):] = arr

        b_score, contrib, low_conf = self.profiler.score_row(
            feat, event["entity_id"], event.get("entity_type", "user"))
        raw, seq_pf = self.detector.score_single(vec, win, b_score)
        fused = self.detector.fuse_single(raw)
        risk = float(self.detector.to_risk_100(np.array([fused]))[0])

        # Stream-native self-calibration (opt-in, see __init__). The current
        # (batch-inherited) threshold keeps being used for alerting the
        # whole time -- nothing is ever silently suppressed during
        # calibration -- while these early live scores are collected in the
        # background to replace it with one tuned on the stream's own
        # distribution.
        if self._calib_remaining > 0:
            self._calib_buffer.append(risk)
            self._calib_remaining -= 1
            if self._calib_remaining == 0:
                self.threshold = float(np.quantile(
                    self._calib_buffer, 1 - self._calib_budget))
                self.calibrated_from_stream = True
                self._calib_buffer = []

        alert = None
        if risk >= self.threshold:
            if self.classifier is not None:
                row = pd.DataFrame([feat])[FEATURE_NAMES]
                pred, conf, _, _ = self.classifier.predict(row)
                pred, conf = pred[0], float(conf[0])
            else:
                pred, conf = "unclassified", 0.0
            alert = self.explainer.build_alert(event, feat, contrib, risk,
                                               pred, conf, seq_pf, low_conf)
            self.n_alerts += 1
            self.attack_type_counts[pred] += 1
            self.recent_alerts.append(alert)

        # poisoning guard lives inside profiler.update
        self.profiler.update(feat, event["entity_id"], risk, self.threshold)

        self.n += 1
        self.entity_last_seen[event["entity_id"]] = time.time()
        self.recent_risk.append(risk)
        self.latencies.append((time.perf_counter() - t0) * 1000.0)
        self._drift_buf.append(feat)
        if len(self._drift_buf) >= self.drift_every:
            rep = self.profiler.drift_report(pd.DataFrame(self._drift_buf))
            if rep["drift_detected"]:
                self.drift_notices.append({
                    "at_event": self.n,
                    "drifted_features": sorted(rep["drifted"],
                                               key=lambda k: -rep["drifted"][k])[:5],
                })
            self._drift_buf = []
        return risk, alert

    # ------------------------------------------------------------------
    def stats(self):
        lat = np.array(self.latencies) if self.latencies else np.array([0.0])
        return {
            "events_processed": self.n,
            "alerts_raised": self.n_alerts,
            "alert_rate_pct": round(100 * self.n_alerts / max(self.n, 1), 3),
            "latency_ms_median": round(float(np.median(lat)), 3),
            "latency_ms_p95": round(float(np.percentile(lat, 95)), 3),
            "latency_ms_p99": round(float(np.percentile(lat, 99)), 3),
            "throughput_events_per_sec": round(1000.0 / max(float(np.mean(lat)), 1e-6), 1),
            "drift_notices": self.drift_notices,
            "alert_budget": self.budget,
            "alert_threshold": round(self.threshold, 2),
            "calibrated_from_stream": self.calibrated_from_stream,
        }

    def live_state(self) -> dict:
        """
        A compact, JSON-safe snapshot for the dashboard's auto-refreshing
        Live Monitor page. `run_realtime.py --serve` periodically writes this
        to `report/live_state.json`; the dashboard fragment just reads it.

        Deliberately separate from `stats()` (the end-of-run summary written
        once to `report/realtime_stats.json`): this is meant to be called
        many times over a long-running process, so it stays cheap (no
        percentile recompute over the full latency history every tick) and
        carries only what a live view needs -- recent activity, not the
        full run.
        """
        now = time.time()
        active_entities = sum(1 for t in self.entity_last_seen.values()
                              if now - t <= ACTIVE_ENTITY_WINDOW_S)
        recent_lat = list(self.latencies)[-500:] or [0.0]
        cpu_pct = mem_mb = None
        try:
            import psutil
            proc = psutil.Process()
            cpu_pct = proc.cpu_percent(interval=None)
            mem_mb = round(proc.memory_info().rss / (1024 * 1024), 1)
        except Exception:
            pass
        return {
            "updated_at": now,
            "uptime_s": round(now - self.started_at, 1),
            "events_processed": self.n,
            "alerts_raised": self.n_alerts,
            "alert_budget": self.budget,
            "alert_threshold": round(self.threshold, 2),
            "calibrated_from_stream": self.calibrated_from_stream,
            "active_entities": active_entities,
            "known_entities": len(self.entity_last_seen),
            "throughput_events_per_sec": round(
                1000.0 / max(float(np.mean(recent_lat)), 1e-6), 1),
            "latency_ms_p50": round(float(np.percentile(recent_lat, 50)), 3),
            "latency_ms_p95": round(float(np.percentile(recent_lat, 95)), 3),
            "latency_ms_p99": round(float(np.percentile(recent_lat, 99)), 3),
            "cpu_percent": cpu_pct,
            "memory_mb": mem_mb,
            "recent_risk_scores": [round(float(r), 1) for r in
                                   list(self.recent_risk)[-500:]],
            "attack_type_counts": dict(self.attack_type_counts),
            "recent_alerts": list(self.recent_alerts)[-20:],
            "drift_notices": self.drift_notices[-10:],
        }


def _write_live_state(scorer: StreamingScorer, path):
    """Atomic-ish write (temp file + rename) so the dashboard never reads a
    half-written JSON file mid-tick."""
    import os
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(scorer.live_state(), fh, default=str)
    os.replace(tmp, path)


def consume(events_iter, scorer: StreamingScorer, speed: float = 0.0,
           print_alerts: bool = True, out_path=None, limit=None,
           live_state_path=None, flush_every=25, on_alert=None):
    """
    Core streaming loop: process events one at a time from ANY iterable of
    canonical-schema event dicts -- a DataFrame's records (`replay()`,
    bounded CSV replay) or a live `src/adapters.EventSource` (folder
    watcher, REST endpoint, Kafka, MQTT -- all unbounded). This is what lets
    every input mode in Part 3 share the exact same detection pipeline.

    Alerts are appended to `out_path` as JSON Lines AS THEY FIRE, not
    buffered and written once at the end -- required for an unbounded
    stream (there is no "end" to write at), and a strict improvement for
    bounded replays too (a crash mid-run doesn't lose already-fired alerts).
    `replay()` truncates `out_path` first so its own "fresh file per call"
    behaviour is unchanged.

    `on_alert(alert)`, if given, fires synchronously the moment an alert is
    built -- e.g. `run_realtime.py --ws-broadcast` uses it to push the alert
    over a WebSocket immediately instead of only at shutdown.
    """
    out_fh = open(out_path, "a", encoding="utf-8") if out_path else None
    alerts = []
    since_flush = 0
    try:
        for i, ev in enumerate(events_iter):
            if limit and i >= limit:
                break
            risk, alert = scorer.process(ev)
            if alert:
                alerts.append(alert)
                if print_alerts:
                    print(f"\n  ALERT  {alert['alert_id']}  entity={alert['entity_id']}  "
                          f"t={alert['timestamp']}")
                    print(f"  {alert['reason_text']}")
                if out_fh:
                    out_fh.write(json.dumps(alert) + "\n")
                    out_fh.flush()
                if on_alert is not None:
                    on_alert(alert)
            if speed > 0:
                time.sleep(speed)
            if print_alerts and i and i % 20000 == 0:
                print(f"  ... {i:,} events, {len(alerts)} alerts")
            since_flush += 1
            if live_state_path and since_flush >= flush_every:
                _write_live_state(scorer, live_state_path)
                since_flush = 0
    finally:
        if out_fh:
            out_fh.close()
        if live_state_path:
            _write_live_state(scorer, live_state_path)
    return alerts


def replay(events: pd.DataFrame, scorer: StreamingScorer, speed: float = 0.0,
           print_alerts: bool = True, out_path=None, limit=None,
           live_state_path=None, flush_every=25):
    """Replay a dataframe through the scorer as if it were a live stream.
    Thin wrapper around `consume()` -- unchanged behaviour for existing
    callers (`run_realtime.py`'s default CSV path)."""
    if out_path:
        open(out_path, "w").close()   # fresh file per call, as before
    return consume(events.to_dict("records"), scorer, speed=speed,
                   print_alerts=print_alerts, out_path=out_path, limit=limit,
                   live_state_path=live_state_path, flush_every=flush_every)

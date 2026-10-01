"""
Real-time streaming demo.

Default mode replays the test window through the scorer one event at a time
and prints alerts as they fire, then reports latency and throughput -- the
numbers that back up the scalability slide.

    python run_realtime.py                    # full test window, as fast as possible
    python run_realtime.py --speed 0.02       # slow enough to watch in a demo
    python run_realtime.py --limit 20000      # short run
    python run_realtime.py --budget 0.02      # retarget the alert budget live

Requires run_pipeline.py to have been run once (it loads models/pipeline.joblib).

--stream-source switches the INPUT ADAPTER (Part 3): the detection pipeline
itself never changes, only where events come from (see src/adapters.py).

    python run_realtime.py --stream-source folder --watch-dir data/live_drop --serve
    python run_realtime.py --stream-source rest --serve
        # then:  curl -X POST http://127.0.0.1:8765/events -d '{"entity_id": "U0001", ...}'
    python run_realtime.py --stream-source kafka --kafka-topic access-events --serve
        # requires kafka-python AND a reachable broker -- see src/adapters.py
    python run_realtime.py --stream-source mqtt --mqtt-topic access/events --serve
        # requires paho-mqtt AND a reachable broker -- see src/adapters.py

--serve runs indefinitely (Ctrl+C to stop) instead of stopping after one
pass, and periodically writes report/live_state.json for the dashboard's
Live Monitor page. --ws-broadcast additionally streams each alert over a
WebSocket for any connected client.
"""
from __future__ import annotations
import argparse
import json
import sys
import joblib
import numpy as np
import pandas as pd

import config as C
from src.explain import Explainer
from src.realtime import StreamingScorer, replay, consume
from src.utils import load_events

# See src/explain.py / FIXES.md for why: alert reason_text contains
# characters (sigma, em dashes) outside Windows' default cp1252 console
# codepage, which would otherwise crash a plain `python run_realtime.py`
# (no --quiet) partway through streaming, after real alerts have already
# been generated.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _load_scorer(a):
    art_path = C.MODELS / "pipeline.joblib"
    if not art_path.exists():
        raise SystemExit("No trained models found. Run:  python run_pipeline.py")
    art = joblib.load(art_path)
    kwargs = dict(budget=a.budget) if a.budget is not None else dict(threshold=art["threshold"])
    kwargs["calib_events"] = a.calib_events
    scorer = StreamingScorer(art["profiler"], art["detector"], art["classifier"],
                             Explainer(art["classifier"]), **kwargs)
    return scorer


def _warmup(scorer, events, ts, cut, a):
    if a.no_warmup:
        return
    warm = events[ts < cut]
    print(f"warming up per-entity state on {len(warm):,} training events "
          f"(no alerts raised) ...")
    scorer.warmup(warm)
    print("warm-up complete, going live\n")


def _print_stats(scorer):
    stats = scorer.stats()
    print("\n" + "=" * 72)
    print("STREAM STATISTICS")
    print("=" * 72)
    for k, v in stats.items():
        if k != "drift_notices":
            print(f"  {k:28s} {v}")
    if stats["drift_notices"]:
        print("\n  CONCEPT DRIFT NOTICES (system-level, not per-event alerts):")
        for d in stats["drift_notices"]:
            print(f"    at event {d['at_event']:,}: {', '.join(d['drifted_features'])}")
    else:
        print("\n  no concept drift detected in this window")
    return stats


# ---------------------------------------------------------------------------
# Mode 1 (default): CSV replay of the bundled/generated dataset's test window
# ---------------------------------------------------------------------------
def run_csv_replay(a):
    events = load_events(C.SAMPLE_DIR / "events.csv" if a.source == "synthetic"
                         else f"{a.path}/events.csv")
    labels = pd.read_csv(C.SAMPLE_DIR / "labels.csv" if a.source == "synthetic"
                         else f"{a.path}/labels.csv")

    ts = pd.to_datetime(events["timestamp"])
    cut = ts.min() + pd.Timedelta(days=a.train_days)
    stream = events[ts >= cut].reset_index(drop=True) if a.all else events

    scorer = _load_scorer(a)
    print(f"replaying {len(stream):,} events "
          f"(threshold = risk {scorer.threshold:.1f}, "
          f"budget = top {(scorer.budget or C.ALERT_BUDGET)*100:.1f}%)\n")
    if not a.all:
        _warmup(scorer, events, ts, cut, a)

    live_state_path = C.REPORT / "live_state.json" if a.serve else None
    if a.serve:
        print("--serve: looping the replay continuously for the live "
              "dashboard (Ctrl+C to stop) ...\n")
        alerts = []
        try:
            while True:
                alerts = replay(stream, scorer, speed=a.speed, print_alerts=not a.quiet,
                                out_path=C.REPORT / "alerts_realtime.jsonl",
                                limit=a.limit, live_state_path=live_state_path)
        except KeyboardInterrupt:
            print("\nstopped by user")
    else:
        alerts = replay(stream, scorer, speed=a.speed, print_alerts=not a.quiet,
                        out_path=C.REPORT / "alerts_realtime.jsonl", limit=a.limit)

    stats = _print_stats(scorer)
    lab = labels.set_index("event_id")["label"]
    hit = [al["event_id"] for al in alerts]
    if hit:
        truth = lab.reindex(hit)
        tp = int((~truth.isin([C.NORMAL, "benign_drift"])).sum())
        print(f"\n  live precision: {tp}/{len(hit)} = {tp/len(hit):.3f}")
    with open(C.REPORT / "realtime_stats.json", "w") as fh:
        json.dump(stats, fh, indent=2)
    print(f"\n  alerts -> {C.REPORT/'alerts_realtime.jsonl'}")
    print(f"  stats  -> {C.REPORT/'realtime_stats.json'}")


# ---------------------------------------------------------------------------
# Mode 2: live adapters (folder / rest / kafka / mqtt) -- see src/adapters.py
# ---------------------------------------------------------------------------
def run_adapter_stream(a):
    from src import adapters

    scorer = _load_scorer(a)
    print(f"stream source: {a.stream_source}  "
          f"(threshold = risk {scorer.threshold:.1f}, "
          f"budget = top {(scorer.budget or C.ALERT_BUDGET)*100:.1f}%)")

    # Live sources have no history of their own -- warm the scorer up on the
    # bundled/generated dataset's training window so entities aren't scored
    # cold from event one. Documented simplification: a genuinely fresh
    # deployment starts cold, which is exactly what src/baseline.py's
    # peer-group prior + cold-start handling is for.
    if not a.no_warmup:
        events = load_events(C.SAMPLE_DIR / "events.csv" if a.source == "synthetic"
                             else f"{a.path}/events.csv")
        ts = pd.to_datetime(events["timestamp"])
        print(f"warming up per-entity state on {len(events):,} bundled events "
              f"(no alerts raised) ...")
        scorer.warmup(events)
        print("warm-up complete, going live\n")

    kwargs = {}
    if a.stream_source == "folder":
        kwargs = dict(watch_dir=a.watch_dir, poll_interval=a.poll_interval)
    elif a.stream_source == "rest":
        kwargs = dict(host=a.host, port=a.port)
    elif a.stream_source == "kafka":
        kwargs = dict(topic=a.kafka_topic, bootstrap_servers=a.kafka_servers)
    elif a.stream_source == "mqtt":
        kwargs = dict(topic=a.mqtt_topic, host=a.mqtt_host, port=a.mqtt_port)
    source = adapters.build_source(a.stream_source, **kwargs)

    ws_sink = None
    if a.ws_broadcast:
        ws_sink = adapters.WebSocketSink(host=a.host, port=a.ws_port).start()
        print(f"WebSocket alert broadcast on ws://{a.host}:{a.ws_port}")

    if a.stream_source == "rest":
        print(f"REST ingestion listening on http://{a.host}:{a.port}/events "
              f"(POST a JSON event object or array)")
        print(f"health check: http://{a.host}:{a.port}/health\n")
    elif a.stream_source == "folder":
        print(f"watching {a.watch_dir} for new .json / .jsonl / .csv files\n")

    live_state_path = C.REPORT / "live_state.json"
    on_alert = ws_sink.broadcast if ws_sink is not None else None

    alerts = []
    try:
        alerts = consume(source.events(), scorer, print_alerts=not a.quiet,
                         out_path=C.REPORT / "alerts_realtime.jsonl",
                         limit=a.limit, live_state_path=live_state_path,
                         flush_every=a.live_state_every, on_alert=on_alert)
    except KeyboardInterrupt:
        print("\nstopped by user")
    finally:
        source.close()

    stats = _print_stats(scorer)
    with open(C.REPORT / "realtime_stats.json", "w") as fh:
        json.dump(stats, fh, indent=2)
    print(f"\n  alerts      -> {C.REPORT/'alerts_realtime.jsonl'}")
    print(f"  stats       -> {C.REPORT/'realtime_stats.json'}")
    print(f"  live state  -> {live_state_path}")


def main(a):
    print("=" * 72)
    print("REAL-TIME BEHAVIOURAL ANOMALY DETECTION -- STREAMING")
    print("=" * 72)
    if a.stream_source == "csv":
        run_csv_replay(a)
    else:
        run_adapter_stream(a)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="synthetic",
                    help="dataset source for the bundled/warm-up data "
                         "(synthetic/lanl/cert/generic) -- NOT the streaming "
                         "input adapter, see --stream-source")
    ap.add_argument("--path", default=str(C.SAMPLE_DIR))
    ap.add_argument("--train-days", type=int, default=C.TRAIN_DAYS)
    ap.add_argument("--speed", type=float, default=0.0,
                    help="seconds to sleep per event (0.02 is demo speed); "
                         "csv replay only")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--all", action="store_true", help="replay all events (csv only)")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--no-warmup", action="store_true",
                    help="skip warm-up (shows why it matters)")
    ap.add_argument("--budget", type=float, default=None,
                    help="retarget the alert threshold to this budget via "
                         "Detector.threshold_for_budget instead of using the "
                         "batch-calibrated one baked into the artifact")
    ap.add_argument("--calib-events", type=int, default=0,
                    help="opt-in stream-native self-calibration: use the "
                         "batch-inherited threshold for the first N live "
                         "events (nothing is ever suppressed), then replace "
                         "it with one tuned on those events' own risk-score "
                         "distribution. Off by default (0) -- batch and "
                         "streaming scores are not numerically identical "
                         "(ASSUMPTIONS.md), so this closes that gap when "
                         "requested. Try --calib-events 1000 or more.")

    # --- Part 3: streaming input adapters ---
    ap.add_argument("--stream-source", default="csv",
                    choices=["csv", "folder", "rest", "kafka", "mqtt"],
                    help="input adapter (src/adapters.py). 'csv' (default) is "
                         "the original bundled-dataset replay; the others are "
                         "open-ended live streams -- pair with --serve")
    ap.add_argument("--serve", action="store_true",
                    help="run indefinitely instead of stopping after one "
                         "pass (Ctrl+C to stop); required for folder/rest/"
                         "kafka/mqtt, optional for csv (loops the replay)")
    ap.add_argument("--live-state-every", type=int, default=25,
                    help="flush report/live_state.json every N events")
    ap.add_argument("--watch-dir", default=str(C.DATA / "live_drop"),
                    help="--stream-source folder: directory to watch")
    ap.add_argument("--poll-interval", type=float, default=1.0,
                    help="--stream-source folder: seconds between directory scans")
    ap.add_argument("--host", default="127.0.0.1", help="--stream-source rest: bind host")
    ap.add_argument("--port", type=int, default=8765, help="--stream-source rest: bind port")
    ap.add_argument("--kafka-topic", default="access-events")
    ap.add_argument("--kafka-servers", default="localhost:9092")
    ap.add_argument("--mqtt-topic", default="access/events")
    ap.add_argument("--mqtt-host", default="localhost")
    ap.add_argument("--mqtt-port", type=int, default=1883)
    ap.add_argument("--ws-broadcast", action="store_true",
                    help="also broadcast alerts over a WebSocket (needs the "
                         "'websockets' package)")
    ap.add_argument("--ws-port", type=int, default=8766)
    main(ap.parse_args())

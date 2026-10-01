"""
Streaming input adapters.

One `EventSource` interface so the detection pipeline (`src/realtime.py:consume`)
never changes when the input source does. Every adapter below turns its raw
input into the same canonical-schema event dict `src/features.py`'s
StreamingFeatureExtractor already consumes -- adding a new source later means
writing one more small class here, not touching detection, scoring,
explanation or the dashboard.

Exercised end-to-end in this environment: CSVReplaySource, FolderWatcherSource,
RestApiSource (see README.md "Streaming adapters" for the test commands used).

NOT exercised against a live broker: KafkaSource, MqttSource. No broker is
available in this environment. Both are complete, real adapter classes
against the same interface -- reviewed, not load-tested. Same honesty
standard the project already applies to its other optional dependencies
(torch / lightgbm / shap / faker): a clear, actionable error if the package
isn't installed, rather than silently degrading.
"""
from __future__ import annotations
import itertools
import json
import queue
import threading
import time
from abc import ABC, abstractmethod
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

import pandas as pd

_id_counter = itertools.count(1)


def normalize_event(raw: dict) -> dict:
    """
    Fill a partial/live event dict out to the canonical schema
    (`config.SCHEMA`) with safe defaults, and parse its timestamp. Every
    adapter funnels its output through this so the detection pipeline sees
    one consistent shape regardless of where the event came from.

    `entity_id` is the one field with no sensible default -- an event that
    doesn't say whose behaviour it represents can't be scored against
    anyone's baseline, so it's rejected (ValueError) rather than silently
    guessed.
    """
    if not raw.get("entity_id"):
        raise ValueError("event is missing required field 'entity_id'")
    ts = raw.get("timestamp")
    return {
        "event_id": raw.get("event_id", next(_id_counter)),
        "entity_id": str(raw["entity_id"]),
        "entity_type": raw.get("entity_type", "user"),
        "timestamp": pd.Timestamp(ts) if ts else pd.Timestamp.now(),
        "source_ip": raw.get("source_ip", ""),
        "geo_location": raw.get("geo_location", ""),
        "resource_accessed": raw.get("resource_accessed", ""),
        "auth_method": raw.get("auth_method", "password"),
        "auth_success": int(raw.get("auth_success", 1)),
        "session_duration": float(raw.get("session_duration", 0) or 0),
        "command_sequence": raw.get("command_sequence", "") or "",
        "device_fingerprint": raw.get("device_fingerprint", ""),
    }


class EventSource(ABC):
    """Everything the detection pipeline needs from an input source."""

    @abstractmethod
    def events(self) -> Iterator[dict]:
        """Yield canonical-schema event dicts, oldest first. May block
        waiting for new events (folder/REST/Kafka/MQTT) or terminate once
        the input is exhausted (CSV replay)."""
        raise NotImplementedError

    def close(self):
        pass


# ---------------------------------------------------------------------------
# CSV replay
# ---------------------------------------------------------------------------
class CSVReplaySource(EventSource):
    """Replays a canonical-schema events CSV. The default, fully-tested path
    (`run_realtime.py`'s original behaviour) -- wrapped in the same interface
    as every other source purely so it's interchangeable with them, not
    because its own behaviour needed to change."""

    def __init__(self, path, speed: float = 0.0, limit=None):
        from src.utils import load_events
        self.df = load_events(path)
        self.speed = speed
        self.limit = limit

    def events(self):
        recs = self.df.to_dict("records")
        if self.limit:
            recs = recs[: self.limit]
        for row in recs:
            yield normalize_event(row)
            if self.speed > 0:
                time.sleep(self.speed)


# ---------------------------------------------------------------------------
# Folder watcher
# ---------------------------------------------------------------------------
class FolderWatcherSource(EventSource):
    """
    Polls a directory for new `.json` / `.jsonl` / `.csv` files and turns
    each new record into a canonical-schema event. Polling (mtime + a
    processed-file marker) rather than a filesystem-events library
    (`watchdog`) keeps this dependency-free and behaves identically on
    Windows and Linux.

    A file is only read once it has stopped growing for `settle_s` seconds
    (a simple guard against reading a file mid-write), then renamed to
    `<name>.processed` so a restart doesn't reprocess it.
    """

    def __init__(self, watch_dir, poll_interval: float = 1.0,
                 settle_s: float = 0.5, stop_event: threading.Event | None = None):
        self.dir = Path(watch_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.poll_interval = poll_interval
        self.settle_s = settle_s
        self.stop_event = stop_event or threading.Event()
        self._seen: set[str] = set()

    def events(self):
        while not self.stop_event.is_set():
            for path in sorted(self.dir.glob("*")):
                if path.suffix not in (".json", ".jsonl", ".csv"):
                    continue
                if path.name in self._seen:
                    continue
                try:
                    if time.time() - path.stat().st_mtime < self.settle_s:
                        continue  # still being written -- try again next tick
                except FileNotFoundError:
                    continue
                self._seen.add(path.name)
                yield from self._read_file(path)
                self._mark_processed(path)
            time.sleep(self.poll_interval)

    @staticmethod
    def _read_file(path: Path):
        if path.suffix == ".csv":
            for row in pd.read_csv(path).to_dict("records"):
                try:
                    yield normalize_event(row)
                except ValueError:
                    continue
            return
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return
        records = json.loads(text) if text.startswith("[") else \
            [json.loads(line) for line in text.splitlines() if line.strip()]
        for row in records:
            try:
                yield normalize_event(row)
            except ValueError:
                continue

    @staticmethod
    def _mark_processed(path: Path):
        try:
            path.rename(path.with_suffix(path.suffix + ".processed"))
        except OSError:
            pass  # already moved/removed by something else -- not fatal


# ---------------------------------------------------------------------------
# REST endpoint
# ---------------------------------------------------------------------------
class RestApiSource(EventSource):
    """
    stdlib-only ingestion endpoint -- no FastAPI/Flask dependency. POST a
    single JSON event object, or a JSON array of them, to `/events`:

        curl -X POST http://127.0.0.1:8765/events \\
             -H "Content-Type: application/json" \\
             -d '{"entity_id": "U0001", "timestamp": "2026-07-01T09:00:00", ...}'

    `GET /health` returns 200 once the server is up. Runs the HTTP server on
    a background thread; `events()` drains the internal thread-safe queue.
    """

    def __init__(self, host="127.0.0.1", port=8765,
                 stop_event: threading.Event | None = None):
        self.host, self.port = host, port
        self.queue: "queue.Queue[dict]" = queue.Queue()
        self.stop_event = stop_event or threading.Event()
        self._server = None
        self._thread = None

    def start(self):
        q = self.queue

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path != "/events":
                    self.send_response(404); self.end_headers(); return
                try:
                    length = int(self.headers.get("Content-Length", 0))
                    body = json.loads(self.rfile.read(length) or b"{}")
                    records = body if isinstance(body, list) else [body]
                    for r in records:
                        q.put(r)
                    self.send_response(202)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"queued": len(records)}).encode())
                except Exception as e:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(e)}).encode())

            def do_GET(self):
                if self.path == "/health":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"status": "ok"}')
                else:
                    self.send_response(404); self.end_headers()

            def log_message(self, fmt, *args):
                pass  # the pipeline has its own event/alert logging

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def events(self):
        if self._server is None:
            self.start()
        while not self.stop_event.is_set():
            try:
                raw = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                yield normalize_event(raw)
            except ValueError:
                continue  # malformed event (no entity_id) -- drop, don't crash the stream

    def close(self):
        self.stop_event.set()
        if self._server:
            self._server.shutdown()


# ---------------------------------------------------------------------------
# WebSocket alert broadcaster (a sink, not a source)
# ---------------------------------------------------------------------------
class WebSocketSink:
    """
    Broadcasts each alert, as it fires, to any connected WebSocket client
    (a second live view, or a test client). Requires the `websockets`
    package; raises a clear error at construction if it isn't installed
    rather than silently doing nothing.
    """

    def __init__(self, host="127.0.0.1", port=8766):
        try:
            import websockets  # noqa: F401
        except ImportError as e:
            raise ImportError(
                "WebSocketSink needs the 'websockets' package: "
                "pip install websockets") from e
        self.host, self.port = host, port
        self._clients: set = set()
        self._loop = None
        self._thread = None

    def start(self):
        import asyncio
        import websockets

        async def handler(ws):
            self._clients.add(ws)
            try:
                async for _ in ws:      # broadcast-only; ignore inbound traffic
                    pass
            finally:
                self._clients.discard(ws)

        async def _serve():
            async with websockets.serve(handler, self.host, self.port):
                await asyncio.Future()  # run until the thread is killed

        def _run():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(_serve())

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        time.sleep(0.2)  # let the loop come up before the first broadcast() call
        return self

    def broadcast(self, alert: dict):
        if self._loop is None or not self._clients:
            return
        import asyncio
        payload = json.dumps(alert, default=str)

        async def _send():
            dead = []
            for ws in list(self._clients):
                try:
                    await ws.send(payload)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self._clients.discard(ws)

        asyncio.run_coroutine_threadsafe(_send(), self._loop)


# ---------------------------------------------------------------------------
# Kafka / MQTT -- pluggable interfaces, NOT exercised against a live broker
# ---------------------------------------------------------------------------
class KafkaSource(EventSource):
    """
    Consumes canonical-schema events from a Kafka topic (one JSON object per
    message). Requires `kafka-python` and a reachable broker.

    NOT EXERCISED AGAINST A LIVE BROKER in this environment -- none is
    available here. Implements the same `EventSource` interface as every
    other adapter, so it is a drop-in `--source kafka` once a broker exists;
    treat it as reviewed, not load-tested.
    """

    def __init__(self, topic: str, bootstrap_servers="localhost:9092",
                 stop_event: threading.Event | None = None, **kafka_kwargs):
        try:
            from kafka import KafkaConsumer
        except ImportError as e:
            raise ImportError(
                "KafkaSource needs the 'kafka-python' package: "
                "pip install kafka-python") from e
        self.stop_event = stop_event or threading.Event()
        self._consumer = KafkaConsumer(
            topic, bootstrap_servers=bootstrap_servers,
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            consumer_timeout_ms=500, **kafka_kwargs)

    def events(self):
        while not self.stop_event.is_set():
            for msg in self._consumer:
                try:
                    yield normalize_event(msg.value)
                except ValueError:
                    continue
                if self.stop_event.is_set():
                    return
            # consumer_timeout_ms elapsed with no new message -- loop back
            # around so stop_event gets re-checked instead of blocking forever.

    def close(self):
        self.stop_event.set()
        self._consumer.close()


class MqttSource(EventSource):
    """
    Subscribes to an MQTT topic (one JSON event per message payload).
    Requires `paho-mqtt` and a reachable broker.

    NOT EXERCISED AGAINST A LIVE BROKER in this environment -- same caveat
    as `KafkaSource` above.
    """

    def __init__(self, topic: str, host="localhost", port=1883,
                 stop_event: threading.Event | None = None):
        try:
            import paho.mqtt.client as mqtt
        except ImportError as e:
            raise ImportError(
                "MqttSource needs the 'paho-mqtt' package: "
                "pip install paho-mqtt") from e
        self.stop_event = stop_event or threading.Event()
        self._queue: "queue.Queue[dict]" = queue.Queue()
        self._client = mqtt.Client()

        def _on_message(_client, _userdata, msg):
            try:
                self._queue.put(json.loads(msg.payload.decode("utf-8")))
            except Exception:
                pass

        self._client.on_message = _on_message
        self._client.connect(host, port)
        self._client.subscribe(topic)
        self._client.loop_start()

    def events(self):
        while not self.stop_event.is_set():
            try:
                raw = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                yield normalize_event(raw)
            except ValueError:
                continue

    def close(self):
        self.stop_event.set()
        self._client.loop_stop()
        self._client.disconnect()


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
def build_source(name: str, **kwargs) -> EventSource:
    """Dispatch by name -- what `run_realtime.py --source` uses. Keeping the
    mapping in one place is what "plug in a new source without touching the
    detection pipeline" means in practice: add a class above, add one line
    here, done."""
    registry = {
        "csv": CSVReplaySource,
        "folder": FolderWatcherSource,
        "rest": RestApiSource,
        "kafka": KafkaSource,
        "mqtt": MqttSource,
    }
    if name not in registry:
        raise ValueError(f"unknown source '{name}', choose from {sorted(registry)}")
    return registry[name](**kwargs)

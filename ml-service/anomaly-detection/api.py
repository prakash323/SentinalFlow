"""
SentinelFlow ML HTTP service.

This adapter keeps the trained anomaly-detection project in Python and exposes
one small API for the Spring Boot platform.

Run:
    python run_pipeline.py --quick   # only needed if models/pipeline.joblib is missing
    python api.py

Endpoint:
    POST /predict
    GET  /health
"""
from __future__ import annotations

import hashlib
import json
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import uvicorn

import config as C
from src.explain import Explainer
from src.realtime import StreamingScorer
from src.utils import load_events

SCORER: StreamingScorer | None = None
LOAD_ERROR: str | None = None


class EventRequest(BaseModel):
    eventId: str
    entityId: str
    eventType: str
    eventVersion: str = "v1"
    occurredAt: str
    source: str = "sentinel-flow"
    payload: dict[str, Any] = Field(default_factory=dict)


def _stable_numeric_id(event_id: str) -> int:
    # The ML project expects a numeric event_id internally. SentinelFlow keeps
    # the original string eventId in the response.
    digest = hashlib.sha256(event_id.encode("utf-8")).hexdigest()
    return int(digest[:12], 16)


def _to_bool_int(value: Any, default: int = 1) -> int:
    if isinstance(value, bool):
        return int(value)
    if value is None:
        return default
    if isinstance(value, str):
        return 0 if value.lower() in {"false", "0", "fail", "failed", "failure"} else 1
    return int(bool(value))


def _to_naive_timestamp(value: str) -> pd.Timestamp:
    # The training/warm-up data (data/sample/events.csv) and every internal
    # profiler/extractor timestamp are timezone-naive. SentinelFlow sends
    # occurredAt as an ISO-8601 string WITH an offset/Z (Jackson's default
    # for OffsetDateTime), which pd.Timestamp parses as timezone-AWARE -
    # subtracting that from a naive stored timestamp (interevent gap,
    # geo-velocity time delta) raises "Cannot subtract tz-naive and
    # tz-aware datetime-like objects". Converting to UTC and dropping the
    # tzinfo keeps the absolute instant correct while matching the
    # convention every other timestamp in this project already uses.
    ts = pd.Timestamp(value)
    if ts.tzinfo is not None:
        ts = ts.tz_convert("UTC").tz_localize(None)
    return ts


def _canonical_event(req: EventRequest) -> dict[str, Any]:
    p = req.payload or {}
    event_type = req.eventType.upper()

    # Map SentinelFlow's event envelope into the ML model's canonical schema.
    success = p.get("loginSuccess", p.get("success", None))
    if success is None:
        success = 0 if event_type in {"LOGIN_FAILED", "AUTH_FAILURE"} else 1

    ip = p.get("ip", p.get("sourceIp", p.get("source_ip", ""))) or ""
    location = p.get("location", p.get("geoLocation", p.get("geo_location", ""))) or ""
    resource = p.get("resource", p.get("fileName", p.get("endpoint", ""))) or ""

    action = p.get("action", "")
    if action and not resource:
        resource = str(action)

    auth_method = p.get("authMethod", p.get("auth_method", "password")) or "password"
    session_duration = p.get(
        "sessionDurationMinutes",
        p.get("session_duration", 0),
    ) or 0

    command = p.get("commandSequence", p.get("command_sequence", "")) or ""
    device = p.get(
        "deviceFingerprint",
        p.get("device_fingerprint", ""),
    ) or ""

    # A transaction amount can be represented as a resource/context signal.
    if event_type == "TRANSACTION" and not resource:
        resource = "transaction"

    return {
        "event_id": _stable_numeric_id(req.eventId),
        "entity_id": req.entityId,
        "entity_type": "user",
        "timestamp": _to_naive_timestamp(req.occurredAt),
        "source_ip": str(ip),
        "geo_location": str(location),
        "resource_accessed": str(resource),
        "auth_method": str(auth_method),
        "auth_success": _to_bool_int(success),
        "session_duration": float(session_duration),
        "command_sequence": str(command),
        "device_fingerprint": str(device),
    }


def _load_scorer() -> StreamingScorer:
    artifact_path = C.MODELS / "pipeline.joblib"
    if not artifact_path.exists():
        raise RuntimeError(
            f"Missing {artifact_path}. Run `python run_pipeline.py --quick` first."
        )

    artifact = joblib.load(artifact_path)
    scorer = StreamingScorer(
        artifact["profiler"],
        artifact["detector"],
        artifact.get("classifier"),
        Explainer(artifact.get("classifier")),
        threshold=artifact.get("threshold"),
    )

    # Warm the stateful feature extractor so the first live event is not scored
    # from a completely cold state.
    sample_path = C.SAMPLE_DIR / "events.csv"
    if sample_path.exists():
        try:
            events = load_events(sample_path)
            scorer.warmup(events)
        except Exception as exc:
            print(f"WARNING: ML warm-up skipped: {exc}")

    return scorer


def _load_in_background() -> None:
    # Loading + warming replays ~100k events and takes a couple of minutes.
    # Doing it off the main thread lets the HTTP server come up immediately, so
    # /health can say "warming" (rather than the port simply refusing
    # connections) and /predict can answer a clear 503 until the model is ready.
    global SCORER, LOAD_ERROR
    try:
        SCORER = _load_scorer()
        print("SentinelFlow ML service ready", flush=True)
    except Exception as exc:  # noqa: BLE001 - surfaced through /health
        LOAD_ERROR = str(exc)
        print(f"ERROR: ML service failed to load: {exc}", flush=True)


@asynccontextmanager
async def lifespan(_: FastAPI):
    threading.Thread(target=_load_in_background, name="ml-loader", daemon=True).start()
    yield


APP = FastAPI(title="SentinelFlow ML Service", version="1.0.0", lifespan=lifespan)


@APP.get("/health")
def health() -> dict[str, Any]:
    # Always HTTP 200 so a liveness probe passes while warming; consumers that
    # need a *ready* model check status == "ok".
    if LOAD_ERROR:
        return {"status": "error", "ready": False, "service": "sentinelflow-ml", "detail": LOAD_ERROR}
    if SCORER is None:
        return {"status": "warming", "ready": False, "service": "sentinelflow-ml"}
    return {"status": "ok", "ready": True, "service": "sentinelflow-ml"}


@APP.post("/predict")
def predict(req: EventRequest) -> dict[str, Any]:
    if SCORER is None:
        raise HTTPException(
            status_code=503,
            detail=f"ML scorer failed to load: {LOAD_ERROR}" if LOAD_ERROR else "ML scorer is still warming up",
        )

    try:
        event = _canonical_event(req)
        risk, alert = SCORER.process(event)

        result: dict[str, Any] = {
            "eventId": req.eventId,
            "entityId": req.entityId,
            "anomalyScore": round(float(risk) / 100.0, 6),
            "riskScore": round(float(risk), 3),
            "confidence": None,
            "decision": "ANOMALOUS" if alert else "NORMAL",
            "modelName": "behavioral-anomaly-ensemble",
            "modelVersion": "pipeline-joblib",
            "attackType": None,
            "reason": None,
            "factors": [],
        }

        if alert:
            result["confidence"] = alert.get("class_confidence")
            result["attackType"] = alert.get("predicted_class")
            result["reason"] = alert.get("reason_text")
            result["factors"] = [
                f.get("meaning", f.get("feature", ""))
                for f in alert.get("top_factors", [])
            ]

        return result

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


if __name__ == "__main__":
    # 0.0.0.0 is IPv4-only. On Windows "localhost" resolves to ::1 first and
    # each request pays a ~2 s connect fallback delay, so clients should use
    # 127.0.0.1 (the backend's default ML_SERVICE_URL already does).
    uvicorn.run("api:APP", host="0.0.0.0", port=8000, reload=False)

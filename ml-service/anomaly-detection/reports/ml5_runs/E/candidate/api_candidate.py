"""SentinelFlow ML HTTP service - CANDIDATE with the corrected serving contract (ML-5).   ***  NOT DEPLOYED  ***

A modified copy of the production api.py. The production api.py is NOT changed by ML-5; apply this only after review and approval.
Differences from production (each traces to a documented ML-4 parity mismatch):
  P1 entity_type   read from the payload; absent -> ML_DEFAULT_ENTITY_TYPE (explicit deployment setting), recorded in `dataQuality.assumptions`
  P2 units         sessionDurationMinutes x 60 -> seconds
  P3 commands      space/comma/pipe separated -> canonical '|' tokens
  P4 time          occurredAt converted to the deployment wall clock (ML_DEPLOYMENT_TZ is REQUIRED; there is no silent default)
  P5 missing data  required fields -> HTTP 422 with a machine-readable code; optional fields -> explicit 'unspecified' markers + `dataQuality.degraded`;
                   a missing authentication result is never read as success
  P6 cold start    no replay of the TRAINING sample as warm-up; optional per-deployment onboarding (ML_ONBOARDING_EVENTS) warms the extractor and fits the baseline
  P7 duplicates    an eventId that was already processed returns the cached result and does not update state again
  P8 ordering      out-of-order events are scored and flagged (`dataQuality.warnings`)
Environment: ML_DEPLOYMENT_TZ (required, e.g. 'Asia/Kolkata' or '+05:30'), ML_DEFAULT_ENTITY_TYPE (default 'user'), ML_ONBOARDING_EVENTS (optional canonical CSV).
"""
from __future__ import annotations

import os
import sys
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("ML_PROJECT_ROOT", HERE.parents[2])).resolve()   # the anomaly-detection project root (config.py, src/, models/)
for p in (str(ROOT), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import joblib                                                            # noqa: E402
import uvicorn                                                           # noqa: E402
from fastapi import FastAPI, HTTPException                               # noqa: E402
from pydantic import BaseModel, Field                                    # noqa: E402

import config as C                                                       # noqa: E402
from serving_contract import ContractError, ServingContract, ServingPipeline    # noqa: E402
from src.explain import Explainer                                        # noqa: E402
from src.realtime import StreamingScorer                                 # noqa: E402

PIPELINE: ServingPipeline | None = None
LOAD_ERROR: str | None = None


class EventRequest(BaseModel):
    eventId: str
    entityId: str
    eventType: str
    eventVersion: str = "v1"
    occurredAt: str
    source: str = "sentinel-flow"
    payload: dict[str, Any] = Field(default_factory=dict)


def _build_pipeline() -> ServingPipeline:
    tz = os.environ.get("ML_DEPLOYMENT_TZ", "").strip()
    if not tz:
        raise RuntimeError("ML_DEPLOYMENT_TZ is required: training timestamps are deployment wall-clock time and the platform sends UTC")
    contract = ServingContract(tz, os.environ.get("ML_DEFAULT_ENTITY_TYPE", "user"))
    artifact = joblib.load(C.MODELS / "pipeline.joblib")
    profiler, detector = artifact["profiler"], artifact["detector"]
    onboarding = os.environ.get("ML_ONBOARDING_EVENTS", "").strip()
    scorer = StreamingScorer(profiler, detector, artifact.get("classifier"), Explainer(artifact.get("classifier")), threshold=artifact.get("threshold"))
    if onboarding:
        from src.baseline import BaselineProfiler
        from src.features import build_feature_matrix
        from src.utils import load_events
        events = load_events(Path(onboarding))                            # canonical, attack-free deployment history
        scorer.profiler = BaselineProfiler().fit(build_feature_matrix(events, verbose=False))
        scorer.warmup(events)
    else:
        print("WARNING: no ML_ONBOARDING_EVENTS: every entity starts cold (peer prior only) until it has history", flush=True)
    return ServingPipeline(contract, scorer)


def _load_in_background() -> None:
    global PIPELINE, LOAD_ERROR
    try:
        PIPELINE = _build_pipeline()
        print("SentinelFlow ML service (serving contract v1.0) ready", flush=True)
    except Exception as exc:                                              # noqa: BLE001
        LOAD_ERROR = str(exc)
        print(f"ERROR: ML service failed to load: {exc}", flush=True)


@asynccontextmanager
async def lifespan(_: FastAPI):
    threading.Thread(target=_load_in_background, name="ml-loader", daemon=True).start()
    yield


APP = FastAPI(title="SentinelFlow ML Service (candidate, serving contract v1.0)", version="1.1.0-candidate", lifespan=lifespan)


@APP.get("/health")
def health() -> dict[str, Any]:
    if LOAD_ERROR:
        return {"status": "error", "ready": False, "service": "sentinelflow-ml", "detail": LOAD_ERROR}
    if PIPELINE is None:
        return {"status": "warming", "ready": False, "service": "sentinelflow-ml"}
    return {"status": "ok", "ready": True, "service": "sentinelflow-ml"}


@APP.post("/predict")
def predict(req: EventRequest) -> dict[str, Any]:
    if PIPELINE is None:
        raise HTTPException(status_code=503, detail=f"ML scorer failed to load: {LOAD_ERROR}" if LOAD_ERROR else "ML scorer is still warming up")
    try:
        out = PIPELINE.handle(req.model_dump())
    except ContractError as exc:                                           # a controlled prediction error: the event cannot be mapped without guessing
        raise HTTPException(status_code=422, detail=exc.as_dict()) from exc
    except Exception as exc:                                               # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    risk = out["riskScore"]
    result: dict[str, Any] = {
        "eventId": out["eventId"], "entityId": out["entityId"], "anomalyScore": round(float(risk) / 100.0, 6), "riskScore": risk, "confidence": None,
        "decision": "ANOMALOUS" if out["alerted"] else "NORMAL", "modelName": "behavioral-anomaly-ensemble", "modelVersion": "pipeline-joblib",
        "attackType": None, "reason": None, "factors": [], "dataQuality": out["dataQuality"], "duplicate": out["duplicate"]}
    alert = out.get("alert")
    if alert:                                                              # same mapping as the production api.py
        result["confidence"] = alert.get("class_confidence")
        result["attackType"] = alert.get("predicted_class")
        result["reason"] = alert.get("reason_text")
        result["factors"] = [f.get("meaning", f.get("feature", "")) for f in alert.get("top_factors", [])]
    return result


if __name__ == "__main__":
    uvicorn.run("api_candidate:APP", host="127.0.0.1", port=8000, reload=False)

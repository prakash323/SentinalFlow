"""Platform simulation: canonical event -> the SentinelFlow envelope the platform actually sends, and the PRODUCTION (pre-fix) boundary for comparison.

The payload shape is taken from the platform's own simulator (frontend/src/pages/Simulator.tsx, CreateEvent.tsx): payload keys ip, location ('City|lat|lon'),
loginSuccess (boolean), authMethod, resource, sessionDurationMinutes, commandSequence (SPACE-separated), deviceFingerprint; occurredAt is
JavaScript toISOString() i.e. UTC with 'Z'. The platform sends NO entityType today (`include_entity_type=False` reproduces that).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def to_platform_request(ev: dict, tz, style: str = "utc_z", include_entity_type: bool = True, event_type: str = "FILE_ACCESS",
                        drop: tuple = (), event_id: str | None = None) -> dict:
    """`ev` = a canonical event (naive deployment wall-clock timestamp). `tz` = the deployment's tzinfo. `drop` = payload keys to omit."""
    ts = pd.Timestamp(ev["timestamp"]).tz_localize(tz)
    if style == "utc_z":
        occurred = ts.tz_convert("UTC").isoformat().replace("+00:00", "Z")
    elif style == "local_offset":
        occurred = ts.isoformat()
    elif style == "naive_local":
        occurred = pd.Timestamp(ev["timestamp"]).isoformat()
    else:
        raise ValueError(style)
    cmd = ev.get("command_sequence") or ""
    payload = {"ip": ev["source_ip"], "location": ev["geo_location"], "resource": ev["resource_accessed"], "authMethod": ev["auth_method"],
               "loginSuccess": bool(int(ev["auth_success"])), "sessionDurationMinutes": float(ev["session_duration"]) / 60.0,
               "commandSequence": " ".join(t for t in str(cmd).split("|") if t), "deviceFingerprint": ev["device_fingerprint"]}
    if include_entity_type:
        payload["entityType"] = ev["entity_type"]
    for k in drop:
        payload.pop(k, None)
    return {"eventId": str(event_id if event_id is not None else ev["event_id"]), "entityId": ev["entity_id"], "eventType": event_type, "eventVersion": "v1",
            "occurredAt": occurred, "source": "simulator", "payload": payload}


def legacy_canonical(req: dict) -> dict:
    """The production boundary as it is today (api._canonical_event). Importing `api` has no side effects (no server, no model load)."""
    import api
    # model_construct skips pydantic validation (the values are already valid strings/dicts); _canonical_event itself is the unmodified production function
    return api._canonical_event(api.EventRequest.model_construct(**{k: req[k] for k in ("eventId", "entityId", "eventType", "eventVersion", "occurredAt", "source", "payload") if k in req}))

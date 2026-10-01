"""SentinelFlow serving contract v1.0  -  CANDIDATE, NOT DEPLOYED.

Maps a platform event (the SentinelFlow envelope: eventId, entityId, eventType, occurredAt, payload{...}) to the CANONICAL 12-field event the models were
trained on, explicitly and reversibly. Self-contained (stdlib + pandas): this exact file is copied next to the candidate API.

Design rules
  * Every canonical field has exactly ONE documented treatment: REQUIRED (a missing/invalid value raises ContractError -> HTTP 422), or a documented
    UNKNOWN marker, or a documented ASSUMPTION that is recorded in the response. Nothing is defaulted silently.
  * Missing security-relevant information is NEVER converted into a benign value and NEVER carried forward from history (carrying a fingerprint or a
    location forward would let an attacker hide by omission).
  * Units and representations are made explicit: minutes -> seconds, UTC/offset timestamps -> the deployment's wall clock, space/comma-separated
    commands -> the canonical '|' token string, upper/lower-case normalised.
  * The canonical event contract (config.SCHEMA) is unchanged.

The training data are naive WALL-CLOCK timestamps of the deployment. The platform sends UTC ('Z', JavaScript toISOString()). The deployment timezone is
therefore a REQUIRED setting (no silent default).
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import timedelta, timezone
from typing import Any

import pandas as pd

CONTRACT_VERSION = "1.0"
VALID_ENTITY_TYPES = ("user", "service_account", "edge_device")
_ENTITY_ALIASES = {"service": "service_account", "serviceaccount": "service_account", "service-account": "service_account",
                   "device": "edge_device", "edge": "edge_device", "edgedevice": "edge_device", "edge-device": "edge_device"}
# event types whose bare occurrence IS an authentication attempt: an explicit result is REQUIRED (unless the type itself encodes it)
AUTH_ATTEMPT_TYPES = {"LOGIN", "LOGIN_ATTEMPT", "AUTH", "AUTHENTICATION", "SIGN_IN", "SIGNIN"}
AUTH_FAILED_TYPES = {"LOGIN_FAILED", "LOGIN_FAILURE", "AUTH_FAILURE", "AUTH_FAILED"}
AUTH_SUCCESS_TYPES = {"LOGIN_SUCCESS", "AUTH_SUCCESS"}
# event types that can only happen inside an already-authenticated session: success = 1 is a documented, recorded assumption
POST_AUTH_TYPES = {"LOGOUT", "FILE_ACCESS", "TRANSACTION", "RESOURCE_ACCESS", "COMMAND", "API_CALL"}
# event types for which the accessed resource is not an attribute of the event: an explicit marker replaces it
RESOURCELESS_TYPES = AUTH_ATTEMPT_TYPES | AUTH_FAILED_TYPES | AUTH_SUCCESS_TYPES | {"LOGOUT"}
UNSPECIFIED = "unspecified"      # documented UNKNOWN marker for auth_method / device_fingerprint (never a benign look-alike, never carried forward)

FIELD_POLICY = [
    {"canonical_field": "entity_id", "platform_keys": ["entityId"], "policy": "REQUIRED", "error": "MISSING_ENTITY_ID"},
    {"canonical_field": "timestamp", "platform_keys": ["occurredAt"], "policy": "REQUIRED",
     "rule": "ISO-8601; offset-aware values are converted to the deployment wall clock and made naive; naive values are taken as deployment wall clock",
     "error": "INVALID_TIMESTAMP / MISSING_TIMESTAMP"},
    {"canonical_field": "entity_type", "platform_keys": ["entityType", "entity_type"], "policy": "ASSUMPTION",
     "rule": "valid = user | service_account | edge_device (+aliases). Absent -> the deployment's configured default_entity_type, recorded in `assumptions`. Invalid -> error",
     "error": "INVALID_ENTITY_TYPE"},
    {"canonical_field": "source_ip", "platform_keys": ["ip", "sourceIp", "source_ip"], "policy": "REQUIRED", "rule": "valid IPv4/IPv6",
     "error": "MISSING_SOURCE_IP / INVALID_SOURCE_IP"},
    {"canonical_field": "geo_location", "platform_keys": ["location", "geoLocation", "geo_location"], "policy": "REQUIRED",
     "rule": "'City|lat|lon' with lat in [-90,90], lon in [-180,180]; ''/'Unknown' count as missing; never carried forward",
     "error": "MISSING_LOCATION / INVALID_LOCATION"},
    {"canonical_field": "resource_accessed", "platform_keys": ["resource", "fileName", "endpoint"], "policy": "REQUIRED (access events) / MARKER (auth events)",
     "rule": "LOGIN/LOGOUT-type events without a resource get the marker 'event:<type>'; any other event type must carry one", "error": "MISSING_RESOURCE"},
    {"canonical_field": "auth_method", "platform_keys": ["authMethod", "auth_method"], "policy": "UNKNOWN MARKER",
     "rule": "lower-cased; absent -> 'unspecified' (recorded as degraded); never carried forward", "error": None},
    {"canonical_field": "auth_success", "platform_keys": ["loginSuccess", "success", "auth_success"], "policy": "REQUIRED (auth events) / ASSUMPTION (post-auth events)",
     "rule": "strict boolean parse. Absent: LOGIN_FAILED-type -> 0, LOGIN_SUCCESS-type -> 1, post-authentication types (FILE_ACCESS, LOGOUT, ...) -> 1 recorded as an "
             "assumption, bare LOGIN / unknown event types -> error (a missing authentication result is never read as success)",
     "error": "MISSING_AUTH_RESULT / INVALID_AUTH_RESULT"},
    {"canonical_field": "session_duration", "platform_keys": ["sessionDurationMinutes (x60)", "sessionDurationSeconds", "session_duration"], "policy": "NEUTRAL VALUE",
     "rule": "minutes converted to seconds (rounded to 1 microsecond); both units present -> error; negative/non-finite -> error; absent -> the entity's running mean "
             "(0 with no history), recorded as degraded",
     "error": "INVALID_SESSION_DURATION / AMBIGUOUS_SESSION_DURATION"},
    {"canonical_field": "command_sequence", "platform_keys": ["commandSequence", "command_sequence"], "policy": "OPTIONAL (empty is valid)",
     "rule": "list or string; split on '|', whitespace, ',' ';'; lower-cased; joined with '|'", "error": "INVALID_COMMAND_SEQUENCE"},
    {"canonical_field": "device_fingerprint", "platform_keys": ["deviceFingerprint", "device_fingerprint"], "policy": "UNKNOWN MARKER",
     "rule": "absent -> 'unspecified' (a NEW value for the entity: fail-safe, recorded as degraded); never carried forward", "error": None},
]


class ContractError(Exception):
    """A controlled prediction error: the event cannot be mapped to a valid canonical event without guessing."""

    def __init__(self, code: str, field_name: str, message: str):
        super().__init__(f"{code}: {field_name}: {message}")
        self.code, self.field, self.message = code, field_name, message

    def as_dict(self) -> dict:
        return {"code": self.code, "field": self.field, "message": self.message, "contract_version": CONTRACT_VERSION}


@dataclass
class CanonicalResult:
    event: dict
    assumptions: list = field(default_factory=list)      # documented assumptions applied (e.g. entity_type=user)
    degraded: list = field(default_factory=list)         # fields that were unavailable: the detectors that depend on them are inactive/neutral
    warnings: list = field(default_factory=list)

    def quality(self) -> dict:
        return {"contract_version": CONTRACT_VERSION, "assumptions": list(self.assumptions), "degraded": list(self.degraded), "warnings": list(self.warnings)}


class ContractState:
    """The only state the contract keeps: per-entity last timestamp (order flag) and running duration mean (neutral value for a missing duration)."""

    def __init__(self):
        self.last_ts: dict = {}
        self.dur_n: dict = {}
        self.dur_sum: dict = {}

    def mean_duration(self, entity_id: str) -> float:
        n = self.dur_n.get(entity_id, 0)
        return self.dur_sum.get(entity_id, 0.0) / n if n else 0.0

    def update(self, entity_id: str, ts, duration: float):
        self.last_ts[entity_id] = ts
        self.dur_n[entity_id] = self.dur_n.get(entity_id, 0) + 1
        self.dur_sum[entity_id] = self.dur_sum.get(entity_id, 0.0) + duration


def _first(d: dict, keys):
    for k in keys:
        if k in d and d[k] is not None:
            return k, d[k]
    return None, None


def parse_timezone(spec: str):
    """'+05:30' / '-08:00' / 'UTC' fixed offsets, or an IANA name ('Asia/Kolkata')."""
    s = str(spec).strip()
    if s.upper() in ("UTC", "Z"):
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d{1,2}):?(\d{2})", s)
    if m:
        sign = 1 if m.group(1) == "+" else -1
        return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))
    from zoneinfo import ZoneInfo
    return ZoneInfo(s)


def _bool(v, field_name="auth_success") -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)) and not isinstance(v, bool) and v in (0, 1):
        return bool(v)
    if isinstance(v, str):
        t = v.strip().lower()
        if t in ("true", "1", "success", "succeeded", "ok", "yes"):
            return True
        if t in ("false", "0", "failure", "failed", "fail", "no"):
            return False
    raise ContractError("INVALID_AUTH_RESULT", field_name, f"cannot read {v!r} as a boolean authentication result")


def _stable_numeric_id(event_id: str) -> int:
    return int(hashlib.sha256(str(event_id).encode("utf-8")).hexdigest()[:12], 16)


class ServingContract:
    def __init__(self, deployment_timezone: str, default_entity_type: str = "user"):
        if not deployment_timezone:
            raise ValueError("deployment_timezone is REQUIRED: the training timestamps are deployment wall-clock time and the platform sends UTC")
        if default_entity_type not in VALID_ENTITY_TYPES:
            raise ValueError(f"default_entity_type must be one of {VALID_ENTITY_TYPES}")
        self.tz = parse_timezone(deployment_timezone)
        self.tz_spec = deployment_timezone
        self.default_entity_type = default_entity_type
        self.state = ContractState()

    # ------------------------------------------------------------------------------------------------------------
    def canonicalize(self, entity_id, event_type, occurred_at, payload: dict | None, event_id: str = "", update_state: bool = True) -> CanonicalResult:
        p = dict(payload or {})
        assume, degraded, warn = [], [], []
        if entity_id is None or str(entity_id).strip() == "":
            raise ContractError("MISSING_ENTITY_ID", "entityId", "entityId is required")
        entity_id = str(entity_id).strip()
        etype = str(event_type or "").strip().upper()

        # ---- timestamp -> deployment wall clock (naive)
        if occurred_at is None or str(occurred_at).strip() == "":
            raise ContractError("MISSING_TIMESTAMP", "occurredAt", "occurredAt is required")
        try:
            ts = pd.Timestamp(occurred_at)
            if pd.isna(ts):
                raise ValueError("NaT")
        except Exception as exc:                                        # noqa: BLE001
            raise ContractError("INVALID_TIMESTAMP", "occurredAt", f"cannot parse {occurred_at!r} as an ISO-8601 timestamp ({exc})") from exc
        if ts.tzinfo is not None:
            ts = ts.tz_convert(self.tz).tz_localize(None)
        last = self.state.last_ts.get(entity_id)
        if last is not None and ts < last:
            warn.append(f"out_of_order:{(last - ts).total_seconds():.3f}s_before_last_event_of_entity")

        # ---- entity type
        _, et = _first(p, ("entityType", "entity_type"))
        if et is None or str(et).strip() == "":
            entity_type = self.default_entity_type
            assume.append(f"entity_type={entity_type} (deployment default; the platform did not send entityType)")
        else:
            t = str(et).strip().lower()
            t = _ENTITY_ALIASES.get(t, t)
            if t not in VALID_ENTITY_TYPES:
                raise ContractError("INVALID_ENTITY_TYPE", "entityType", f"{et!r} is not one of {VALID_ENTITY_TYPES}")
            entity_type = t

        # ---- source ip (required)
        _, ip = _first(p, ("ip", "sourceIp", "source_ip"))
        if ip is None or str(ip).strip() == "":
            raise ContractError("MISSING_SOURCE_IP", "ip", "a source IP is required")
        try:
            ipaddress.ip_address(str(ip).strip())
        except ValueError as exc:
            raise ContractError("INVALID_SOURCE_IP", "ip", f"{ip!r} is not an IP address") from exc
        ip = str(ip).strip()

        # ---- location (required, strict)
        _, loc = _first(p, ("location", "geoLocation", "geo_location"))
        if loc is None or str(loc).strip() == "" or str(loc).strip().lower() == "unknown":
            raise ContractError("MISSING_LOCATION", "location", "a location 'City|lat|lon' is required (it is not carried forward from history)")
        loc = str(loc).strip()
        parts = loc.split("|")
        try:
            if len(parts) != 3 or not parts[0].strip():
                raise ValueError("expected City|lat|lon")
            lat, lon = float(parts[1]), float(parts[2])
            if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0) or math.isnan(lat) or math.isnan(lon):
                raise ValueError("coordinates out of range")
        except ValueError as exc:
            raise ContractError("INVALID_LOCATION", "location", f"{loc!r}: {exc}") from exc

        # ---- resource
        _, res = _first(p, ("resource", "fileName", "endpoint"))
        res = None if res is None or str(res).strip() == "" else str(res).strip()
        if res is None:
            if etype in RESOURCELESS_TYPES:
                res = f"event:{etype.lower()}"
            else:
                raise ContractError("MISSING_RESOURCE", "resource", f"event type {etype or '<none>'} must carry a resource / fileName / endpoint")

        # ---- authentication result
        _, ok = _first(p, ("loginSuccess", "success", "auth_success"))
        if ok is not None:
            auth_success = 1 if _bool(ok) else 0
        elif etype in AUTH_FAILED_TYPES:
            auth_success = 0
        elif etype in AUTH_SUCCESS_TYPES:
            auth_success = 1
        elif etype in POST_AUTH_TYPES:
            auth_success = 1
            assume.append(f"auth_success=1 (event type {etype} occurs inside an authenticated session)")
        else:
            raise ContractError("MISSING_AUTH_RESULT", "loginSuccess",
                                f"event type {etype or '<none>'} needs an explicit authentication result; a missing result is never read as success")

        # ---- auth method
        _, am = _first(p, ("authMethod", "auth_method"))
        if am is None or str(am).strip() == "":
            auth_method = UNSPECIFIED
            degraded.append("auth_method")
        else:
            auth_method = str(am).strip().lower()

        # ---- session duration (seconds)
        km, minutes = _first(p, ("sessionDurationMinutes", "session_duration_minutes"))
        ks, seconds = _first(p, ("sessionDurationSeconds", "session_duration_seconds", "session_duration"))
        if km is not None and ks is not None:
            raise ContractError("AMBIGUOUS_SESSION_DURATION", km, f"both {km} and {ks} were sent; send one unit")
        dur = None
        if km is not None or ks is not None:
            raw = minutes if km is not None else seconds
            try:
                if isinstance(raw, bool):
                    raise ValueError("boolean")
                v = float(raw)
                if not math.isfinite(v) or v < 0:
                    raise ValueError("must be finite and >= 0")
            except (TypeError, ValueError) as exc:
                raise ContractError("INVALID_SESSION_DURATION", km or ks, f"{raw!r}: {exc}") from exc
            dur = round(v * 60.0, 6) if km is not None else v
        else:
            dur = self.state.mean_duration(entity_id)
            degraded.append("session_duration")

        # ---- commands
        _, cmd = _first(p, ("commandSequence", "command_sequence"))
        if cmd is None:
            command_sequence = ""
        elif isinstance(cmd, (list, tuple)):
            command_sequence = "|".join(t for t in (str(x).strip().lower() for x in cmd) if t)
        elif isinstance(cmd, str):
            command_sequence = "|".join(t for t in re.split(r"[|\s,;]+", cmd.strip().lower()) if t)
        else:
            raise ContractError("INVALID_COMMAND_SEQUENCE", "commandSequence", f"expected a list or a string, got {type(cmd).__name__}")

        # ---- device fingerprint
        _, fp = _first(p, ("deviceFingerprint", "device_fingerprint"))
        if fp is None or str(fp).strip() == "":
            fingerprint = UNSPECIFIED
            degraded.append("device_fingerprint")
        else:
            fingerprint = str(fp).strip()

        event = {"event_id": _stable_numeric_id(event_id), "entity_id": entity_id, "entity_type": entity_type, "timestamp": ts, "source_ip": ip,
                 "geo_location": loc, "resource_accessed": res, "auth_method": auth_method, "auth_success": auth_success, "session_duration": float(dur),
                 "command_sequence": command_sequence, "device_fingerprint": fingerprint}
        if update_state:
            self.state.update(entity_id, ts, float(dur) if "session_duration" not in degraded else self.state.mean_duration(entity_id))
        return CanonicalResult(event, assume, degraded, warn)


class ServingPipeline:
    """Boundary + scorer wrapper used by the candidate API. `scorer` is duck-typed (production StreamingScorer): .process(event) -> (risk, alert)."""

    def __init__(self, contract: ServingContract, scorer, max_seen_event_ids: int = 200_000):
        self.contract, self.scorer = contract, scorer
        self._seen: OrderedDict = OrderedDict()
        self._max = max_seen_event_ids

    def handle(self, req: dict) -> dict:
        eid = str(req.get("eventId") or "")
        if eid and eid in self._seen:                                   # at-least-once delivery: a duplicate must not update state twice
            out = dict(self._seen[eid])
            out["duplicate"] = True
            return out
        res = self.contract.canonicalize(req.get("entityId"), req.get("eventType"), req.get("occurredAt"), req.get("payload"), eid)
        risk, alert = self.scorer.process(res.event)
        out = {"eventId": eid, "entityId": res.event["entity_id"], "riskScore": round(float(risk), 3), "alerted": bool(alert), "alert": alert,
               "dataQuality": res.quality(), "duplicate": False}
        if eid:
            self._seen[eid] = out
            if len(self._seen) > self._max:
                self._seen.popitem(last=False)
        return out

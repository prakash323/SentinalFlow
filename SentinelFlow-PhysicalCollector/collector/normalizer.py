"""
normalizer.py
Converts a SessionEvent (raw physical telemetry) into the canonical
SentinelFlow event envelope - UNCHANGED shape, per the approved decision:

    eventId, entityId, eventType, eventVersion, occurredAt, source, payload

Payload keys reuse the existing simulator's own naming exactly where the
same concept applies (see
SentinelFlow-Python-Simulator-9.2/simulator/event_generator.py,
_login_payload / _logout_payload):

    LOGIN  payload keys used here: loginSuccess, ip (if available)
    LOGOUT payload keys used here: sessionDurationMinutes, ip (if available)

`location` (part of the simulator's LOGIN payload) is never included -
this phase has no geo-IP lookup (would require an external network call,
out of scope) and there is no genuine location to report for a local
session. Fields this physical source cannot honestly determine are
OMITTED from payload, matching the existing project's own convention:
the simulator's payload builders already omit keys that don't apply to a
given event (e.g. LOGIN never sends sessionDurationMinutes), and the ML
adapter (ml-service/anomaly-detection/api.py:_canonical_event) already
defaults a missing key rather than requiring it - nothing new is invented
to fill a gap.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from config import SOURCE, EVENT_VERSION
from session_poller import SessionEvent
from process_poller import ProcessEvent
from network_poller import NetworkConnectionEvent


def iso_utc(epoch_seconds: float) -> str:
    """Same format as the simulator's own iso_utc(): ISO-8601 UTC, no
    microseconds, 'Z' suffix - e.g. 2026-09-30T08:15:30Z."""
    dt = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).replace(microsecond=0)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def new_event_id() -> str:
    """Unique by construction across collector restarts: wall-clock
    milliseconds + a random suffix, never a pure in-process counter.

    This collector is a long-running process observing one-off real
    events (not a scenario "run" like the simulator), so there is no
    counter to reset between runs in the first place - the exact failure
    mode fixed in the simulator (see SentinelFlow-Python-Simulator-9.2
    config.py Config.run_id) cannot recur here by design.
    """
    millis = int(datetime.now(tz=timezone.utc).timestamp() * 1000)
    return f"EV-PHYS-{millis}-{uuid.uuid4().hex[:6]}"


def build_login_event(session: SessionEvent, entity_id: str) -> Dict[str, Any]:
    """LOGIN canonical event.

    Available from this physical source:
      - loginSuccess: always True. Session polling can only observe a
        session that IS active; a failed local login attempt produces no
        session and is invisible to this mechanism - it is not fabricated
        as a separate event.
      - ip: only if psutil reports a genuine remote host for this session
        (session.host). On this project's own dev machine this is None
        for the local interactive session (verified, not assumed) - most
        real runs will omit ip entirely, which is the honest outcome.
      - username: from SessionEvent.username, already collected by
        session_poller.py for its own internal dedup key - no new
        psutil.users() call, no new cost. Event Correlation Foundation
        (Option A): this is what lets a consumer match a LOGIN to later
        PROCESS_START events for the same username; it does not by
        itself establish a precise session boundary (see the phase
        report's known limitations - e.g. the same username logging in
        twice is not disambiguated by username alone).

    Never included: location (no geo-IP lookup performed in this phase).
    """
    payload: Dict[str, Any] = {"loginSuccess": True}
    if session.host:
        payload["ip"] = session.host
    if session.username:
        payload["username"] = session.username

    return {
        "eventId": new_event_id(),
        "entityId": entity_id,
        "eventType": "LOGIN",
        "eventVersion": EVENT_VERSION,
        "occurredAt": iso_utc(session.started_epoch),
        "source": SOURCE,
        "payload": payload,
    }


def build_logout_event(session: SessionEvent, entity_id: str) -> Dict[str, Any]:
    """LOGOUT canonical event.

    sessionDurationMinutes is a genuine measurement: the real OS-reported
    session start time subtracted from the moment this collector observed
    the session end (poll granularity is the only imprecision, and it is
    bounded by --poll-interval, not invented). ip follows the same rule
    as build_login_event.
    """
    duration_minutes = max(
        0.0,
        (session.observed_epoch - session.started_epoch) / 60.0,
    )

    payload: Dict[str, Any] = {
        "sessionDurationMinutes": round(duration_minutes, 2),
    }
    if session.host:
        payload["ip"] = session.host

    return {
        "eventId": new_event_id(),
        "entityId": entity_id,
        "eventType": "LOGOUT",
        "eventVersion": EVENT_VERSION,
        "occurredAt": iso_utc(session.observed_epoch),
        "source": SOURCE,
        "payload": payload,
    }


def build_event(session: SessionEvent, entity_id: str) -> Dict[str, Any]:
    if session.kind == "LOGIN":
        return build_login_event(session, entity_id)
    if session.kind == "LOGOUT":
        return build_logout_event(session, entity_id)
    raise ValueError(f"Unknown session event kind: {session.kind}")


def build_process_start_event(process: ProcessEvent, entity_id: str) -> Dict[str, Any]:
    """PROCESS_START canonical event (Physical Telemetry P2).

    occurredAt uses the process's REAL create_time - the same pattern
    build_login_event uses the real session start time - not "now",
    since detection may lag the actual start by up to
    --process-poll-interval.

    Fields included only when genuinely available, never fabricated:
      - processName / parentPid / username: from the cheap bulk poll
        (see process_poller.py) - username is None for a handful of
        protected system processes (verified empirically, e.g.
        csrss.exe), in which case it is simply omitted here.
      - executablePath: only when the targeted per-process lookup in
        process_poller.py succeeded. A process that exited between
        detection and that lookup yields executable_path=None here,
        which is omitted - not replaced with a placeholder.

    Never included, by design, in this or any other event this
    collector builds: cmdline (command-line arguments) - see
    process_poller.py's module docstring and README "What is
    intentionally not collected". This function has no cmdline field to
    even omit-if-missing; it is simply never part of ProcessEvent.
    """
    payload: Dict[str, Any] = {"pid": process.pid}

    if process.name:
        payload["processName"] = process.name
    if process.ppid is not None:
        payload["parentPid"] = process.ppid
    if process.username:
        payload["username"] = process.username
    if process.executable_path:
        payload["executablePath"] = process.executable_path

    return {
        "eventId": new_event_id(),
        "entityId": entity_id,
        "eventType": "PROCESS_START",
        "eventVersion": EVENT_VERSION,
        "occurredAt": iso_utc(process.create_time),
        "source": SOURCE,
        "payload": payload,
    }


def build_network_connection_event(
    connection: NetworkConnectionEvent,
    entity_id: str,
    now_epoch: Optional[float] = None,
) -> Dict[str, Any]:
    """NETWORK_CONNECTION canonical event (Physical Telemetry P3).

    `now_epoch` (Collector 2.0) lets the caller supply the detection
    instant instead of reading the wall clock here. It changes nothing at
    runtime - the pipeline passes the same real time.time() value - but
    it is what makes the deterministic simulated-time stress test
    possible without patching the clock globally. Omitted/None keeps the
    original behavior exactly.

    occurredAt is the moment this collector DETECTED the connection, not
    a fabricated "connection start time" - unlike a process, psutil's
    connection table carries no equivalent of create_time, so there is
    no genuine historical instant to report instead (see
    network_poller.py's module docstring for the full reasoning, and the
    same documented limitation).

    Payload fields, all only when genuinely available:
      - protocol / localAddress / localPort / remoteAddress / remotePort
        / status: read directly from the OS connection table.
      - pid: the owning process id, when psutil reports one (every
        ESTABLISHED connection had a real, non-zero pid in the P3 audit's
        empirical testing on this machine - TIME_WAIT connections were
        the ones missing it, and those are excluded from scope entirely).
      - processName: only when the targeted psutil.Process(pid).name()
        lookup in network_poller.py succeeded. Omitted, never
        fabricated, if the owning process already exited (or, in the
        rarer PID-reuse case, if the lookup itself still fails for some
        other reason) before this lookup ran.
      - processCreateTime: Event Correlation Foundation (Option A) - the
        OWNING PROCESS's real create_time, read from the same
        psutil.Process handle already opened for processName (no new
        expensive lookup - see network_poller.py's
        _resolve_process_info). This is NOT this connection's own start
        time (psutil exposes no such field for connections); it exists
        so a consumer can match it against a PROCESS_START event's own
        (pid, create_time) identity and tell whether they really
        describe the same process, or a later, unrelated process that
        reused the same pid. Formatted with the same iso_utc() used for
        every other timestamp in this codebase, so it can be compared
        directly against PROCESS_START.occurredAt as a string. Omitted,
        never fabricated, whenever the lookup did not succeed.

    Never included: packet contents, DNS contents, HTTP/TLS internals,
    command lines, credentials/tokens/secrets - none of these are
    exposed by psutil's connection table in the first place, so there is
    nothing to deliberately strip; this collector simply never asks the
    OS for any of them.
    """
    payload: Dict[str, Any] = {
        "protocol": connection.protocol,
        "localAddress": connection.local_address,
        "localPort": connection.local_port,
        "remoteAddress": connection.remote_address,
        "remotePort": connection.remote_port,
        "status": connection.status,
    }
    if connection.pid:
        payload["pid"] = connection.pid
    if connection.process_name:
        payload["processName"] = connection.process_name
    if connection.process_create_time:
        payload["processCreateTime"] = iso_utc(connection.process_create_time)

    return {
        "eventId": new_event_id(),
        "entityId": entity_id,
        "eventType": "NETWORK_CONNECTION",
        "eventVersion": EVENT_VERSION,
        "occurredAt": iso_utc(
            now_epoch if now_epoch is not None else datetime.now(tz=timezone.utc).timestamp()
        ),
        "source": SOURCE,
        "payload": payload,
    }

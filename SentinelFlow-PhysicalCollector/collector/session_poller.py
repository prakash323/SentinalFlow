"""
session_poller.py
Polls the local machine's active login sessions and yields SessionEvent
objects for genuine login/logout transitions.

Uses psutil.users() - a normal, cross-platform, non-admin mechanism
(WTS session enumeration on Windows). Chosen explicitly because the task
requires NOT depending on the Windows Security Event Log (event IDs
4624/4634/4688), which needs an elevated audit-policy change this phase
intentionally avoids.

Verified empirically on the actual development machine (2026-09-30,
Windows 11): psutil.users() returns exactly one local interactive
session with terminal=None, host=None, pid=None, and a real
`started` epoch timestamp. That is the genuine ceiling of what this
mechanism can see on this platform - `host`/`terminal` are read as-is
and simply omitted downstream when None (see normalizer.py); nothing is
inferred or invented to fill the gap.

Sessions are identified by (username, started) rather than a session id,
because psutil does not report a stable per-session id on every platform
(pid is None here) - and (username, started) already uniquely identifies
one real login instant, which is the property this poller actually needs.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

import psutil

logger = logging.getLogger("sentinelflow.collector.session_poller")


@dataclass(frozen=True)
class _SessionKey:
    name: str
    started: float


@dataclass(frozen=True)
class SessionEvent:
    kind: str  # "LOGIN" or "LOGOUT"
    username: str
    started_epoch: float  # real OS-reported login time (both LOGIN and LOGOUT)
    observed_epoch: float  # when THIS collector observed the transition
    host: Optional[str]  # psutil-reported remote host/ip, if any (usually None)
    terminal: Optional[str]  # psutil-reported terminal/session name, if any


def _snapshot() -> Dict[_SessionKey, "psutil._common.suser"]:
    sessions: Dict[_SessionKey, "psutil._common.suser"] = {}
    for u in psutil.users():
        sessions[_SessionKey(name=u.name, started=u.started)] = u
    return sessions


def _to_event(kind: str, u, now: float) -> SessionEvent:
    return SessionEvent(
        kind=kind,
        username=u.name,
        started_epoch=u.started,
        observed_epoch=now,
        host=u.host or None,
        terminal=u.terminal or None,
    )


class SessionPoller:
    """Stateful poller. Call poll_once() repeatedly (e.g. in a loop with a
    sleep between calls); each call returns the SessionEvent list for
    transitions since the *previous* call.

    The very first call establishes a baseline and reports every
    already-active session as a LOGIN. This is a deliberate, documented
    choice, not a fabrication: `started_epoch` on that event is still the
    real OS-reported login time (which may be well before the collector
    itself started) - the collector is simply reporting a login it
    discovered rather than one it watched happen live. See README.md.
    """

    def __init__(
        self,
        snapshot_fn: Optional[Callable[[], Dict[_SessionKey, object]]] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """snapshot_fn/clock (Collector 2.0) exist so the deterministic
        long-run stress test can drive this poller from a fake session
        table and a fake clock. Both default to the real implementations,
        so runtime behavior is unchanged."""
        self._known: Dict[_SessionKey, "psutil._common.suser"] = {}
        self._initialized = False
        self._snapshot_fn = snapshot_fn or _snapshot
        self._clock = clock

    @property
    def tracked_count(self) -> int:
        """How many sessions this poller currently remembers. Bounded by
        the number of real active sessions: _known is REPLACED by the
        current snapshot on every poll (see PHASE Q)."""
        return len(self._known)

    def poll_once(self) -> List[SessionEvent]:
        current = self._snapshot_fn()
        now = self._clock()
        events: List[SessionEvent] = []

        if not self._initialized:
            for u in current.values():
                events.append(_to_event("LOGIN", u, now))
            self._known = current
            self._initialized = True
            logger.info(
                "Baseline session snapshot taken: %d active session(s)",
                len(current),
            )
            return events

        for key, u in current.items():
            if key not in self._known:
                events.append(_to_event("LOGIN", u, now))

        for key, u in self._known.items():
            if key not in current:
                events.append(_to_event("LOGOUT", u, now))

        self._known = current
        return events

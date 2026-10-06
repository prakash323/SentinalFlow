"""
process_poller.py
Polls the local machine's running processes and yields ProcessEvent
objects for processes that started AFTER this poller's baseline was
established.

DELIBERATELY DIFFERENT from SessionPoller's first-call behavior:
SessionPoller reports every already-active session as a LOGIN on its
first poll, because a currently-active session is genuinely true right
now. Reporting every already-running process the same way would be
misleading - most system/OS processes have been running since boot, not
"just now" - and would flood Kafka/Postgres with a one-time burst of
PROCESS_START events at every collector restart that carries no real
security signal. So the first poll_once() call here establishes a
SILENT baseline and returns an empty list; only processes that appear
strictly after that baseline are ever reported.

Process identity is (pid, create_time), not pid alone. Windows (like
every OS) reuses PIDs after a process exits. A reused PID will have a
different create_time from the process that previously held it, so it
is correctly treated as a distinct process - never confused with, or
silently merged into, the earlier one.

Two-phase field cost (measured empirically on the actual development
machine during this phase's audit, not assumed):
  - psutil.process_iter(['pid','name','ppid','create_time','username'])
    over ~300 processes: ~40ms.
  - Adding 'exe' (executable path) to that SAME bulk call: ~3,100ms for
    the same ~300 processes - isolated and confirmed as the expensive
    field (each path resolution is a separate expensive OS call).
Therefore the bulk/cheap poll used for new-process DETECTION never
requests 'exe'. executablePath is looked up afterward with one targeted,
bounded psutil.Process(pid).exe() call per genuinely NEW process only -
cost stays proportional to how many processes actually just started,
not to the size of the whole process table.

cmdline is never requested or read anywhere in this module - not
merely left out of the payload, but never fetched from the OS at all.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set

import psutil

logger = logging.getLogger("sentinelflow.collector.process_poller")

# Deliberately excludes 'cmdline' - see module docstring and README
# "What is intentionally not collected". Deliberately excludes 'exe' -
# see module docstring for the measured cost that justifies the
# separate targeted lookup below.
_BULK_FIELDS = ["pid", "name", "ppid", "create_time", "username"]


@dataclass(frozen=True)
class ProcessKey:
    pid: int
    create_time: float


@dataclass(frozen=True)
class ProcessEvent:
    pid: int
    name: Optional[str]
    ppid: Optional[int]
    create_time: float
    username: Optional[str]
    executable_path: Optional[str]  # None when unavailable - never fabricated


def _snapshot() -> Dict[ProcessKey, dict]:
    current: Dict[ProcessKey, dict] = {}
    for p in psutil.process_iter(_BULK_FIELDS):
        try:
            info = p.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Process exited mid-enumeration, or is inaccessible - skip
            # rather than guess at its fields.
            continue

        pid = info.get("pid")
        create_time = info.get("create_time")
        if pid is None or create_time is None:
            continue

        current[ProcessKey(pid=pid, create_time=create_time)] = info
    return current


def _lookup_executable_path(pid: int) -> Optional[str]:
    """Targeted, single-process lookup - called only for newly detected
    processes (see ProcessPoller.poll_once), never for the whole table."""
    try:
        exe = psutil.Process(pid).exe()
        return exe or None
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        # The process may have already exited between detection and this
        # lookup - a real, benign race, not an error. Omit, never
        # fabricate a path.
        return None


class ProcessPoller:
    """Stateful poller. The FIRST poll_once() call establishes a silent
    baseline of already-running processes and returns an EMPTY list.
    Every subsequent call returns one ProcessEvent per process whose
    (pid, create_time) key was not present in the previous snapshot."""

    def __init__(
        self,
        snapshot_fn: Optional[Callable[[], Dict[ProcessKey, dict]]] = None,
        executable_lookup: Optional[Callable[[int], Optional[str]]] = None,
    ) -> None:
        """snapshot_fn/executable_lookup (Collector 2.0) exist so the
        deterministic long-run stress test can drive this poller from a
        fake process table without patching psutil globally. Both default
        to the real psutil-backed implementations above, so runtime
        behavior is unchanged."""
        self._known: Set[ProcessKey] = set()
        self._initialized = False
        self._snapshot_fn = snapshot_fn or _snapshot
        self._executable_lookup = executable_lookup or _lookup_executable_path

    @property
    def tracked_count(self) -> int:
        """How many processes this poller currently remembers. Bounded by
        the size of the real process table: _known is REPLACED by the
        current snapshot on every poll, never appended to, so it can
        never accumulate historical processes (see PHASE Q)."""
        return len(self._known)

    def poll_once(self) -> List[ProcessEvent]:
        current = self._snapshot_fn()

        if not self._initialized:
            self._known = set(current.keys())
            self._initialized = True
            logger.info(
                "Baseline process snapshot taken: %d running process(es) - "
                "none reported as PROCESS_START (pre-existing, not new)",
                len(current),
            )
            return []

        new_keys = [key for key in current if key not in self._known]
        events: List[ProcessEvent] = []

        for key in new_keys:
            info = current[key]
            events.append(ProcessEvent(
                pid=key.pid,
                name=info.get("name") or None,
                ppid=info.get("ppid"),
                create_time=key.create_time,
                username=info.get("username") or None,
                executable_path=self._executable_lookup(key.pid),
            ))

        self._known = set(current.keys())
        return events

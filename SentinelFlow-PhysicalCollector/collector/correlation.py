"""
correlation.py
A bounded process-metadata cache used to enrich NETWORK_CONNECTION events
whose owning process has already exited.

WHY (PHASE G): the backend's NEW_PROCESS_EXTERNAL_CONNECTION rule
(DeterministicRuleService.evaluateNewProcessExternalConnection) correlates
a NETWORK_CONNECTION to a PROCESS_START by the exact pair

    NETWORK_CONNECTION.payload.pid           == PROCESS_START.payload.pid
    NETWORK_CONNECTION.payload.processCreateTime == PROCESS_START.occurredAt   (exact string)

If network_poller's live psutil lookup fails - which is precisely what
happens for a short-lived process that connects and exits, the most
interesting case for that rule - processCreateTime is omitted and the
correlation can never fire. This cache remembers what the PROCESS WORKER
already observed for that pid moments earlier and fills the gap from real,
previously-observed data.

It is still only ever TELEMETRY ENRICHMENT. No rule, no scoring, no alert
is evaluated here; detection stays entirely in the backend.

SAFETY RULES (the reason this is not simply "look up the pid"):

  1. The cache is consulted ONLY when the live psutil lookup produced
     nothing at all. Live truth always wins.
  2. An entry is used only within correlation_ttl_seconds (default 300s).
     This both bounds memory and bounds the PID-reuse window: the OS can
     hand pid 8420 to an unrelated process after the original exits, and
     a stale entry would then mislabel that connection. 300s also matches
     the backend rule's own 5-minute recency window, so an entry older
     than that could not produce a correlation anyway.
  3. An entry is dropped the moment the process worker observes a
     DIFFERENT create_time for the same pid - that is a definitive
     signal the pid was reused, so the old metadata is wrong.
  4. Values are copied out; callers never mutate cache state.

BOUNDING (PHASE Q): max_entries with oldest-first eviction plus the TTL.
A machine with heavy process churn cannot make this grow - the cache is
capped at correlation_max_entries (default 2000) regardless of how many
processes start over a 24-hour run.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class ProcessMetadata:
    """Exactly the fields a NETWORK_CONNECTION event can carry about its
    owning process - nothing is cached that could not be published."""
    pid: int
    name: Optional[str]
    create_time: float
    observed_at: float


class ProcessMetadataCache:
    """Bounded, TTL'd pid -> last-observed process metadata."""

    def __init__(
        self,
        ttl_seconds: float,
        max_entries: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        if max_entries <= 0:
            raise ValueError("max_entries must be > 0")

        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: "OrderedDict[int, ProcessMetadata]" = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def record(self, pid: int, name: Optional[str], create_time: float) -> None:
        """Called by the process worker for every genuinely new process."""
        if pid is None or create_time is None:
            return
        with self._lock:
            now = self._clock()
            self._expire_locked(now)
            # Re-insert at the end so the ordering stays newest-last for
            # oldest-first eviction, and so a re-observed pid is fresh.
            self._entries.pop(pid, None)
            self._entries[pid] = ProcessMetadata(
                pid=pid, name=name, create_time=create_time, observed_at=now
            )
            self._evict_locked()

    def lookup(self, pid: Optional[int]) -> Optional[ProcessMetadata]:
        """The last metadata observed for this pid, or None if unknown or
        older than the TTL. Never returns an expired entry even if
        expiry has not been swept yet."""
        if not pid:
            return None
        with self._lock:
            now = self._clock()
            self._expire_locked(now)
            entry = self._entries.get(pid)
            if entry is None:
                self._misses += 1
                return None
            if now - entry.observed_at > self._ttl:
                self._entries.pop(pid, None)
                self._misses += 1
                return None
            self._hits += 1
            return entry

    def invalidate(self, pid: int) -> None:
        """Forget a pid (used when the process worker sees the same pid
        with a different create_time - i.e. the pid was reused)."""
        with self._lock:
            self._entries.pop(pid, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def max_entries(self) -> int:
        return self._max_entries

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "size": len(self._entries),
                "max_entries": self._max_entries,
                "ttl_seconds": self._ttl,
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
            }

    def _expire_locked(self, now: float) -> None:
        cutoff = now - self._ttl
        while self._entries:
            pid, entry = next(iter(self._entries.items()))
            if entry.observed_at > cutoff:
                break
            self._entries.popitem(last=False)

    def _evict_locked(self) -> None:
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)
            self._evictions += 1

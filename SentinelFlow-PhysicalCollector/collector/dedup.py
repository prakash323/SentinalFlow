"""
dedup.py
A bounded, TTL'd "have I already seen this?" cache.

Why this exists at all, given the pollers already diff their own
snapshots: the pollers' diffs are correct only as long as a poller's
in-memory previous snapshot survives. In Collector 2.0 a telemetry worker
can be restarted by the supervisor after a crash, and a worker's poller
is re-baselined at the moment of a restart. This cache is the second,
independent layer that guarantees the same real-world observation is
never published twice, regardless of what happened to a poller's own
state - which matters because the backend ledger deduplicates on eventId,
and a re-observed event would get a NEW eventId.

Bounding (PHASE I / PHASE Q): this is explicitly NOT a `set()` that grows
forever.

  - TTL: an entry older than ttl_seconds is forgotten. Re-seeing the same
    observation after the TTL is treated as new, which is the correct
    trade-off for telemetry - a "new" duplicate is a small annoyance, a
    cache that never forgets is an unbounded leak.
  - Max size: when full, the OLDEST entry is evicted (insertion-ordered
    OrderedDict, popitem(last=False)). Oldest-first matches the TTL's own
    semantics - the entry that was going to expire soonest anyway.

Expiry is lazy plus amortized: every seen() call drops expired entries
from the front of the ordered dict (they are necessarily the oldest), so
there is no timer thread and no scan of the whole structure.

Thread safety: one lock. Several telemetry workers call seen()
concurrently through the shared pipeline.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Callable, Hashable


class BoundedDedupCache:
    """Remembers keys for a bounded time and in a bounded quantity."""

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
        self._entries: "OrderedDict[Hashable, float]" = OrderedDict()
        self._hits = 0
        self._evictions = 0
        self._expirations = 0

    def seen(self, key: Hashable) -> bool:
        """True if this key was recorded within the TTL. Records the key
        either way, so the caller does not need a second call. Returning
        True means "suppress this as a duplicate"."""
        with self._lock:
            now = self._clock()
            self._expire_locked(now)

            if key in self._entries:
                self._hits += 1
                # Deliberately NOT refreshed: a connection that persists
                # across many polls must eventually be reportable again
                # rather than being suppressed forever by its own repeats.
                return True

            self._entries[key] = now
            self._evict_locked()
            return False

    def contains(self, key: Hashable) -> bool:
        """Read-only "is this key currently remembered?" - unlike seen(),
        this records nothing. Exists so a caller (or a test) can inspect
        the cache without mutating it."""
        with self._lock:
            now = self._clock()
            entry = self._entries.get(key)
            return entry is not None and entry > now - self._ttl

    def discard(self, key: Hashable) -> None:
        """Forget a key explicitly (used when a tracked thing demonstrably
        went away, so its genuine next appearance is reportable)."""
        with self._lock:
            self._entries.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

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
                "duplicate_hits": self._hits,
                "evictions": self._evictions,
                "expirations": self._expirations,
            }

    def _expire_locked(self, now: float) -> None:
        cutoff = now - self._ttl
        # Insertion-ordered: everything expired is at the front, so this
        # stops at the first live entry instead of scanning the dict.
        while self._entries:
            key, inserted_at = next(iter(self._entries.items()))
            if inserted_at > cutoff:
                break
            self._entries.popitem(last=False)
            self._expirations += 1

    def _evict_locked(self) -> None:
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)
            self._evictions += 1

"""
event_queue.py
The one central bounded queue between the telemetry workers and the Kafka
publisher (PHASE J).

Why not queue.Queue: the required overflow policy is "accept the newest
observation, drop the oldest queued one" with a counter, and Queue offers
only block-forever or raise-Full. Blocking is explicitly wrong here -
a Kafka outage must never freeze the telemetry workers (which would stop
the collector from observing the host at all, the single worst failure
mode for a security agent). Raising Full would push the same decision
into every caller. A deque with a Condition gives exactly the semantics
needed in ~80 lines, with no new dependency.

OVERFLOW POLICY: DROP OLDEST.
A full queue means Kafka has been unreachable long enough to accumulate
queue_max_size events. At that point the newest observations are the ones
worth keeping: they describe what the host is doing NOW, which is what an
analyst responding to an incident needs, whereas the oldest queued event
describes something that happened at least a full outage ago. This also
matches the behavior kafka_producer.py already shipped for its own
pending buffer, so the two layers do not contradict each other. Every
drop is counted and reported through health (never silently discarded).

FIFO otherwise: events are published in observation order, which keeps
the backend's time-ordered correlation (PROCESS_START before the
NETWORK_CONNECTION that references it) intact in the normal case.

requeue_front() exists for one specific case: the publisher took an event
off the queue and the send failed. Putting it back at the FRONT preserves
ordering rather than reshuffling it behind newer events.
"""
from __future__ import annotations

import threading
from collections import deque
from typing import Any, Deque, Dict, List, Optional


class BoundedEventQueue:
    """Thread-safe, bounded, FIFO, drop-oldest-on-overflow event queue."""

    def __init__(self, max_size: int) -> None:
        if max_size <= 0:
            raise ValueError("max_size must be > 0")
        self._max_size = max_size
        self._items: Deque[Dict[str, Any]] = deque()
        self._condition = threading.Condition()
        self._closed = False
        self._total_enqueued = 0
        self._total_dequeued = 0
        self._dropped = 0
        self._max_depth = 0

    # -- producer side -----------------------------------------------------

    def put(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Enqueue one event. Never blocks, never raises for a full queue.

        Returns the event that was DROPPED to make room (None when
        nothing had to be dropped), so the caller can log/count it.
        Returns None and ignores the event if the queue is closed - after
        shutdown has begun, no new telemetry is accepted."""
        with self._condition:
            if self._closed:
                return None

            dropped: Optional[Dict[str, Any]] = None
            if len(self._items) >= self._max_size:
                dropped = self._items.popleft()
                self._dropped += 1

            self._items.append(event)
            self._total_enqueued += 1
            if len(self._items) > self._max_depth:
                self._max_depth = len(self._items)
            self._condition.notify()
            return dropped

    def requeue_front(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Put an event the publisher could not send back at the FRONT, so
        ordering is preserved. Obeys the same bound; if the queue filled
        up meanwhile, the newest TAIL item is dropped instead of this one
        - the event being requeued is older, and dropping it here would
        silently reorder the stream.

        Unlike put(), this is accepted even after close(): the event was
        already accepted once and is merely being handed back, so
        rejecting it here would lose events during the shutdown drain."""
        with self._condition:
            dropped: Optional[Dict[str, Any]] = None
            if len(self._items) >= self._max_size:
                dropped = self._items.pop()
                self._dropped += 1

            self._items.appendleft(event)
            if len(self._items) > self._max_depth:
                self._max_depth = len(self._items)
            self._condition.notify()
            return dropped

    # -- consumer side -----------------------------------------------------

    def get(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """One event, or None if the queue stayed empty for `timeout`
        seconds (or was closed and drained)."""
        batch = self.get_batch(1, timeout=timeout)
        return batch[0] if batch else None

    def get_batch(self, max_items: int, timeout: Optional[float] = None) -> List[Dict[str, Any]]:
        """Up to max_items events, waiting up to `timeout` for the first
        one. Batching lets the publisher amortize its send loop without
        ever holding events back: whatever is already queued is taken,
        and it never waits for a batch to "fill up"."""
        if max_items <= 0:
            return []
        with self._condition:
            if not self._items and not self._closed and timeout != 0:
                self._condition.wait(timeout)

            taken: List[Dict[str, Any]] = []
            while self._items and len(taken) < max_items:
                taken.append(self._items.popleft())
            self._total_dequeued += len(taken)
            return taken

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        """Stop accepting new events and wake every waiter. Already-queued
        events stay queued so the publisher can still drain them within
        the shutdown budget."""
        with self._condition:
            self._closed = True
            self._condition.notify_all()

    @property
    def closed(self) -> bool:
        with self._condition:
            return self._closed

    # -- metrics -----------------------------------------------------------

    def __len__(self) -> int:
        with self._condition:
            return len(self._items)

    @property
    def depth(self) -> int:
        return len(self)

    @property
    def capacity(self) -> int:
        return self._max_size

    @property
    def fill_ratio(self) -> float:
        with self._condition:
            return len(self._items) / self._max_size

    @property
    def dropped_count(self) -> int:
        with self._condition:
            return self._dropped

    @property
    def stats(self) -> Dict[str, int]:
        with self._condition:
            return {
                "depth": len(self._items),
                "capacity": self._max_size,
                "max_depth": self._max_depth,
                "total_enqueued": self._total_enqueued,
                "total_dequeued": self._total_dequeued,
                "dropped": self._dropped,
            }

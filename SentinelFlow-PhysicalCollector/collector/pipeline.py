"""
pipeline.py
The one common event pipeline every telemetry source converges into
(PHASE H):

    raw observation
        -> correlation enrichment (network only)
        -> deduplication          (bounded, TTL'd - dedup.py)
        -> normalization          (the EXISTING normalizer.py, unchanged)
        -> validation             (envelope contract)
        -> bounded queue          (event_queue.py)

No poller and no worker publishes to Kafka itself. They produce raw
observations; this pipeline is the only thing that turns an observation
into a canonical SentinelFlow event, and the only thing that puts one on
the queue.

ORDER NOTE - why deduplication happens BEFORE normalization: normalizer
.new_event_id() mints a fresh random eventId on every call, so two
normalizations of the same observation are not comparable to each other.
Deduplication therefore keys off the observation's own real-world
identity (see DEDUP KEYS below), which is stable by construction, and
runs first - which also avoids minting an eventId that would be thrown
away.

DEDUP KEYS (PHASE I) - each is the identity the OS itself gives the
thing being observed, never a hash of the whole event:

  PROCESS_START      ("PROCESS_START", pid, create_time)
      The same (pid, create_time) pair process_poller.py already uses as
      process identity. create_time is what makes a reused PID a
      different process rather than a duplicate of the old one.

  NETWORK_CONNECTION ("NETWORK_CONNECTION", protocol, localAddress,
                      localPort, remoteAddress, remotePort, pid)
      The 6-tuple network_poller.py already uses. `status` is
      deliberately excluded: a tracked connection's status can change
      (ESTABLISHED -> CLOSE_WAIT) without it being a new connection.
      Documented limitation, unchanged from 1.x: the connection table has
      no create_time equivalent, so an exact repeat of the same 6-tuple
      after the original closed is indistinguishable from it persisting.

  LOGIN / LOGOUT     (kind, username, started_epoch)
      One real login instant per (username, started) pair - the identity
      session_poller.py already uses, extended with `kind` so the LOGOUT
      of a session is not suppressed as a duplicate of its LOGIN.

VALIDATION rejects an event rather than publishing something the backend
would reject or, worse, silently mis-handle. The envelope contract comes
from the backend's own KafkaEvent record and
EventProcessingService.validate: eventId, entityId, eventType and
occurredAt are required; eventVersion/source/payload complete the
envelope the simulator and this collector have always sent.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Callable, Dict, Optional, Tuple

from correlation import ProcessMetadataCache
from dedup import BoundedDedupCache
from event_queue import BoundedEventQueue
from health import HealthRegistry
from logging_utils import RateLimitedLogger
from network_poller import NetworkConnectionEvent
from normalizer import (
    build_event,
    build_network_connection_event,
    build_process_start_event,
)
from process_poller import ProcessEvent
from session_poller import SessionEvent

logger = logging.getLogger("sentinelflow.collector.pipeline")

# The only event types this collector is contractually allowed to emit.
# PROCESS_END is deliberately absent - see README "PROCESS_END".
KNOWN_EVENT_TYPES = frozenset({"LOGIN", "LOGOUT", "PROCESS_START", "NETWORK_CONNECTION"})

_REQUIRED_ENVELOPE_KEYS = ("eventId", "entityId", "eventType", "eventVersion", "occurredAt", "source", "payload")

# Same shape normalizer.iso_utc() produces and the backend parses.
_ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# Mirrors EventKafkaProducer.MAX_EVENT_BYTES on the backend side: an
# event larger than this would be refused downstream, so it is refused
# here instead of being queued and retried forever.
MAX_EVENT_BYTES = 512 * 1024

# Log a warning once the queue passes this fill ratio (rate-limited).
QUEUE_PRESSURE_RATIO = 0.8


class EventValidationError(ValueError):
    """An event that must not be published."""


class EventPipeline:
    """Shared by every telemetry worker. Thread-safe: its own state is the
    dedup cache, the correlation cache and the queue, all of which are
    individually locked, and the health registry, which is too."""

    def __init__(
        self,
        entity_id: str,
        queue: BoundedEventQueue,
        dedup_cache: BoundedDedupCache,
        health: HealthRegistry,
        process_cache: Optional[ProcessMetadataCache] = None,
        rate_limited_logger: Optional[RateLimitedLogger] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._entity_id = entity_id
        self._queue = queue
        self._dedup = dedup_cache
        self._health = health
        self._process_cache = process_cache
        self._rate_logger = rate_limited_logger or RateLimitedLogger(logger)
        self._clock = clock

    # -- main entry point ---------------------------------------------------

    def submit(self, observation: Any) -> Optional[Dict[str, Any]]:
        """Run one raw observation through the whole pipeline.

        Returns the canonical event that was queued, or None if it was
        deduplicated, rejected by validation, or the queue was closed.
        Never raises for a bad observation - a single malformed reading
        must not take down the worker that produced it."""
        self._health.mark_event_generated()

        try:
            key = dedup_key(observation)
        except Exception:
            logger.exception("Could not derive a deduplication key - dropping observation")
            self._health.mark_event_invalid()
            return None

        if self._dedup.seen(key):
            self._health.mark_event_deduplicated()
            logger.debug("Duplicate observation suppressed key=%s", key)
            return None

        observation = self._enrich(observation)

        try:
            event = self._normalize(observation)
        except Exception:
            logger.exception("Normalization failed - dropping observation")
            self._health.mark_event_invalid()
            return None
        self._health.mark_event_normalized()

        try:
            validate_event(event)
        except EventValidationError as error:
            # eventId/eventType only - never the payload body.
            logger.error(
                "Invalid event rejected eventId=%s eventType=%s reason=%s",
                event.get("eventId"), event.get("eventType"), error,
            )
            self._health.mark_event_invalid()
            return None
        self._health.mark_event_validated()

        self._enqueue(event)
        return event

    # -- stages -------------------------------------------------------------

    def _enrich(self, observation: Any) -> Any:
        """PHASE G: fill a NETWORK_CONNECTION's missing owning-process
        metadata from what the process worker already observed.

        Only ever fills gaps - a live psutil answer is never overwritten -
        and only from a cache entry inside its TTL. See correlation.py for
        the full safety rules and the PID-reuse reasoning."""
        if self._process_cache is None or not isinstance(observation, NetworkConnectionEvent):
            return observation
        if observation.process_create_time is not None and observation.process_name is not None:
            return observation

        cached = self._process_cache.lookup(observation.pid)
        if cached is None:
            return observation

        # If the live lookup DID report a create_time and it disagrees
        # with the cache, the pid was reused - the cached name belongs to
        # a different process and must not be attached.
        if (
            observation.process_create_time is not None
            and observation.process_create_time != cached.create_time
        ):
            return observation

        enriched = NetworkConnectionEvent(
            protocol=observation.protocol,
            local_address=observation.local_address,
            local_port=observation.local_port,
            remote_address=observation.remote_address,
            remote_port=observation.remote_port,
            status=observation.status,
            pid=observation.pid,
            process_name=observation.process_name or cached.name,
            process_create_time=(
                observation.process_create_time
                if observation.process_create_time is not None
                else cached.create_time
            ),
        )
        logger.debug(
            "Correlated connection pid=%s with cached process metadata", observation.pid
        )
        return enriched

    def _normalize(self, observation: Any) -> Dict[str, Any]:
        if isinstance(observation, ProcessEvent):
            return build_process_start_event(observation, self._entity_id)
        if isinstance(observation, NetworkConnectionEvent):
            return build_network_connection_event(
                observation, self._entity_id, now_epoch=self._clock()
            )
        if isinstance(observation, SessionEvent):
            return build_event(observation, self._entity_id)
        raise TypeError(f"Unsupported observation type: {type(observation).__name__}")

    def _enqueue(self, event: Dict[str, Any]) -> None:
        if self._queue.closed:
            logger.debug(
                "Queue closed during shutdown - event not accepted eventId=%s",
                event.get("eventId"),
            )
            return

        dropped = self._queue.put(event)
        self._health.mark_event_enqueued()
        depth = self._queue.depth
        self._health.record_queue_depth(depth)

        if dropped is not None:
            self._health.mark_event_dropped()
            self._rate_logger.warning(
                "queue-overflow",
                "Event queue full (%d) - dropped the oldest queued event "
                "eventId=%s eventType=%s to make room for a newer observation",
                self._queue.capacity, dropped.get("eventId"), dropped.get("eventType"),
            )
        elif depth >= self._queue.capacity * QUEUE_PRESSURE_RATIO:
            self._rate_logger.warning(
                "queue-pressure",
                "Event queue at %.0f%% capacity (%d/%d) - Kafka may be slow or unavailable",
                100.0 * depth / self._queue.capacity, depth, self._queue.capacity,
            )


# -- deduplication keys -----------------------------------------------------


def dedup_key(observation: Any) -> Tuple:
    """The real-world identity of an observation. See this module's
    docstring for why each key is shaped the way it is."""
    if isinstance(observation, ProcessEvent):
        return ("PROCESS_START", observation.pid, observation.create_time)

    if isinstance(observation, NetworkConnectionEvent):
        return (
            "NETWORK_CONNECTION",
            observation.protocol,
            observation.local_address,
            observation.local_port,
            observation.remote_address,
            observation.remote_port,
            observation.pid,
        )

    if isinstance(observation, SessionEvent):
        return (observation.kind, observation.username, observation.started_epoch)

    raise TypeError(f"Unsupported observation type: {type(observation).__name__}")


# -- validation --------------------------------------------------------------


def validate_event(event: Any) -> None:
    """Raise EventValidationError unless this is a publishable canonical
    SentinelFlow event. Mirrors the backend's own requirements
    (EventProcessingService.validate + KafkaEvent) rather than inventing
    a stricter or looser contract."""
    if not isinstance(event, dict):
        raise EventValidationError(f"event must be a dict, got {type(event).__name__}")

    for key in _REQUIRED_ENVELOPE_KEYS:
        if key not in event:
            raise EventValidationError(f"missing required envelope key '{key}'")

    for key in ("eventId", "entityId", "eventType", "eventVersion", "source"):
        value = event[key]
        if not isinstance(value, str) or not value.strip():
            raise EventValidationError(f"'{key}' must be a non-empty string")

    event_type = event["eventType"]
    if event_type not in KNOWN_EVENT_TYPES:
        raise EventValidationError(
            f"unknown eventType '{event_type}' - this collector only emits "
            f"{sorted(KNOWN_EVENT_TYPES)}"
        )

    occurred_at = event["occurredAt"]
    if not isinstance(occurred_at, str) or not _ISO_UTC.match(occurred_at):
        raise EventValidationError(
            f"'occurredAt' must be ISO-8601 UTC like 2026-01-31T12:00:00Z (got {occurred_at!r})"
        )

    payload = event["payload"]
    if not isinstance(payload, dict):
        raise EventValidationError(f"'payload' must be an object, got {type(payload).__name__}")

    try:
        encoded = json.dumps(event)
    except (TypeError, ValueError) as error:
        raise EventValidationError(f"event is not JSON-serializable: {error}") from error

    size = len(encoded.encode("utf-8"))
    if size > MAX_EVENT_BYTES:
        raise EventValidationError(
            f"serialized event is {size} bytes, above the {MAX_EVENT_BYTES}-byte limit "
            "the backend producer enforces"
        )


__all__ = [
    "EventPipeline",
    "EventValidationError",
    "KNOWN_EVENT_TYPES",
    "MAX_EVENT_BYTES",
    "dedup_key",
    "validate_event",
]

"""
logging_utils.py
Structured-logging helpers for a process that runs for hours (PHASE O/X).

Two problems this solves:

1. Repetitive warnings. "Kafka unavailable" or "queue at 80% capacity"
   is useful once a minute and useless 600 times a minute - and on a
   long-running agent, log spam is itself a resource problem (disk, and
   the operator's attention). RateLimitedLogger emits the first
   occurrence immediately, then at most one per interval, and says how
   many it suppressed when it next speaks.

2. Logging configuration. configure_logging() is the single place that
   decides level/format/handlers, so main.py and the tests cannot drift.

Deliberately NOT included: any logging of event payload bodies. The
collector logs eventId/eventType/entityId/pid-shaped operational
metadata only. This matters because a NETWORK_CONNECTION payload carries
real remote IP addresses (see README "Privacy").
"""
from __future__ import annotations

import logging
import sys
import threading
import time
from typing import Callable, Dict, Optional


def configure_logging(level: int, log_file: Optional[str] = None) -> None:
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
        force=True,
    )

    # kafka-python logs its connection/metadata/selector lifecycle at INFO
    # and emits several lines per broker interaction. On a collector that
    # runs for hours that is pure noise around the handful of lines that
    # actually matter, and it buries the heartbeat. Its WARNING/ERROR
    # records - the ones that mean something is wrong - still come
    # through, and --verbose (DEBUG) still gives the full client detail
    # when troubleshooting a broker problem.
    logging.getLogger("kafka").setLevel(
        level if level <= logging.DEBUG else logging.WARNING
    )


class RateLimitedLogger:
    """Wraps a logger and throttles repeated messages per key.

    Keys are caller-chosen short strings ("kafka-down", "queue-pressure"),
    NOT the formatted message - so a message whose text varies (it
    usually embeds a changing count) is still correctly recognised as
    "the same recurring condition". The key table is tiny and fixed: keys
    come from a handful of literals in the source, never from telemetry
    data, so it cannot grow with event volume.
    """

    def __init__(
        self,
        logger: logging.Logger,
        interval_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._logger = logger
        self._interval = interval_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._last_emitted: Dict[str, float] = {}
        self._suppressed: Dict[str, int] = {}

    def warning(self, key: str, message: str, *args) -> None:
        self._log(logging.WARNING, key, message, *args)

    def error(self, key: str, message: str, *args) -> None:
        self._log(logging.ERROR, key, message, *args)

    def info(self, key: str, message: str, *args) -> None:
        self._log(logging.INFO, key, message, *args)

    def reset(self, key: str) -> None:
        """Forget a key's throttle state, so the next occurrence of a
        condition that has genuinely cleared and come back is reported
        immediately rather than swallowed by a stale window."""
        with self._lock:
            self._last_emitted.pop(key, None)
            self._suppressed.pop(key, None)

    def _log(self, level: int, key: str, message: str, *args) -> None:
        with self._lock:
            now = self._clock()
            last = self._last_emitted.get(key)
            if last is not None and (now - last) < self._interval:
                self._suppressed[key] = self._suppressed.get(key, 0) + 1
                return
            suppressed = self._suppressed.pop(key, 0)
            self._last_emitted[key] = now

        if suppressed:
            message = message + " (%d similar message(s) suppressed in the last %.0fs)"
            args = args + (suppressed, self._interval)
        self._logger.log(level, message, *args)

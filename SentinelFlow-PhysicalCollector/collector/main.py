"""
main.py
CLI entry point for the SentinelFlow physical telemetry collector.

Usage (see README.md for the full manual demo):

    python collector\\main.py
    python collector\\main.py --entity-id HOST-MYMACHINE --poll-interval 3 --verbose

This file is deliberately thin. It does four things and nothing else:

    1. parse + validate configuration (config.py - fails fast and loudly
       on bad input, before any thread or socket exists)
    2. configure logging (logging_utils.py)
    3. install SIGINT/SIGTERM handlers that only set an Event
    4. start CollectorApp, block in its heartbeat loop, then stop it

All of the actual architecture - workers, supervision, pipeline, queue,
publisher - lives in app.py and the modules it composes, so it is
testable without running this file.

SIGNAL HANDLING: the handler does the minimum legal amount of work (set
a flag) and returns. Doing real shutdown work inside a signal handler is
how a Python process ends up with a half-joined thread and a Kafka
producer that never flushed. The first Ctrl+C requests a graceful
shutdown with a bounded drain; a second one cuts the drain short.

Requires the collector's entityId to already be registered in
SentinelFlow via POST /api/v1/entities (ADMIN) BEFORE the collector is
started - this collector does not create entities itself.
"""
from __future__ import annotations

import logging
import signal
import sys

from app import CollectorApp
from config import Config, ConfigError, parse_args
from logging_utils import configure_logging

logger = logging.getLogger("sentinelflow.collector")


def _install_signal_handlers(app: CollectorApp) -> None:
    def handle(signum, _frame) -> None:
        logger.info("Shutdown signal received (%s)", signum)
        app.request_stop()

    for signal_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        # SIGBREAK is Windows-only; SIGTERM behaves differently across
        # platforms. Install whatever this platform actually has instead
        # of assuming, and never fail startup over a missing signal.
        sig = getattr(signal, signal_name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, handle)
        except (ValueError, OSError, RuntimeError):
            logger.debug("Could not install a handler for %s on this platform", signal_name)


def main(argv=None) -> int:
    try:
        config: Config = parse_args(argv)
    except ConfigError as error:
        # Logging is not configured yet - this must still be visible.
        print(f"Invalid collector configuration: {error}", file=sys.stderr)
        return 2

    configure_logging(config.effective_log_level(), config.log_file)

    app = CollectorApp(config)
    _install_signal_handlers(app)

    try:
        app.start()
        app.run()
    except Exception:
        logger.exception("Collector failed - shutting down")
        app.stop()
        return 1

    result = app.stop()
    logger.info("Collector stopped")
    return 0 if not result.get("stuck_workers") else 1


if __name__ == "__main__":
    sys.exit(main())

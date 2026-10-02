"""
main.py
CLI entry point for the SentinelFlow physical telemetry collector.

Usage (see README.md for the full manual demo):

    python main.py
    python main.py --entity-id HOST-MYMACHINE --poll-interval 3 --process-poll-interval 15 --verbose

Requires the collector's entityId to already be registered in
SentinelFlow via POST /api/v1/entities (ADMIN) BEFORE the collector is
started - this collector does not create entities itself. The existing
pipeline (EventProcessingLedgerService.persistOrLoad) will create the
Event row on demand, but still requires the referenced Entity to already
exist; there is no analogous safe auto-create for entities in the
current project, so none is added here.

Runs three independent pollers on independent cadences (session/LOGIN-
LOGOUT, process/PROCESS_START, network/NETWORK_CONNECTION - see
session_poller.py, process_poller.py, network_poller.py) rather than one
combined loop, because each phase gave its poller its own interval for
its own reason: process detection's targeted executablePath lookups are
measurably more expensive than session polling (P2), while network
polling is cheap but defaults longer specifically to bound EVENT VOLUME,
not CPU cost (P3). All three share the single base 0.1s tick already
used for responsive shutdown handling - a poller only actually runs when
its own interval has elapsed. Still no threads/asyncio/scheduler
framework - three plain "next due" timestamps checked each tick, exactly
the same pattern P2 introduced for two.
"""
from __future__ import annotations

import logging
import signal
import sys
import time

from config import Config, parse_args
from kafka_producer import EventPublisher
from normalizer import build_event, build_network_connection_event, build_process_start_event
from network_poller import NetworkPoller
from process_poller import ProcessPoller
from session_poller import SessionPoller

logger = logging.getLogger("sentinelflow.collector")

_shutdown = False

_TICK_SECONDS = 0.1


def _handle_signal(signum, frame) -> None:
    global _shutdown
    logger.info("Shutdown signal received (%s) - finishing current cycle then exiting", signum)
    _shutdown = True


def _configure_logging(verbose: bool, log_file) -> None:
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
        force=True,
    )


def _poll_and_publish_sessions(
    poller: SessionPoller,
    publisher: EventPublisher,
    entity_id: str,
) -> None:
    try:
        session_events = poller.poll_once()
    except Exception:
        logger.exception("Session poll failed")
        return

    for session_event in session_events:
        try:
            canonical = build_event(session_event, entity_id)
            logger.info(
                "Session transition detected kind=%s username=%s "
                "-> canonical eventType=%s eventId=%s",
                session_event.kind,
                session_event.username,
                canonical["eventType"],
                canonical["eventId"],
            )
            publisher.publish(canonical)
        except Exception:
            logger.exception(
                "Failed to normalize/publish session event kind=%s username=%s",
                session_event.kind,
                session_event.username,
            )


def _poll_and_publish_processes(
    poller: ProcessPoller,
    publisher: EventPublisher,
    entity_id: str,
) -> None:
    try:
        process_events = poller.poll_once()
    except Exception:
        logger.exception("Process poll failed")
        return

    for process_event in process_events:
        try:
            canonical = build_process_start_event(process_event, entity_id)
            logger.info(
                "New process detected pid=%s name=%s "
                "-> canonical eventType=%s eventId=%s",
                process_event.pid,
                process_event.name,
                canonical["eventType"],
                canonical["eventId"],
            )
            publisher.publish(canonical)
        except Exception:
            logger.exception(
                "Failed to normalize/publish process event pid=%s",
                process_event.pid,
            )


def _poll_and_publish_network(
    poller: NetworkPoller,
    publisher: EventPublisher,
    entity_id: str,
) -> None:
    try:
        connection_events = poller.poll_once()
    except Exception:
        logger.exception("Network poll failed")
        return

    for connection_event in connection_events:
        try:
            canonical = build_network_connection_event(connection_event, entity_id)
            logger.info(
                "New connection detected pid=%s remote=%s:%s "
                "-> canonical eventType=%s eventId=%s",
                connection_event.pid,
                connection_event.remote_address,
                connection_event.remote_port,
                canonical["eventType"],
                canonical["eventId"],
            )
            publisher.publish(canonical)
        except Exception:
            logger.exception(
                "Failed to normalize/publish network event pid=%s",
                connection_event.pid,
            )


def main(argv=None) -> int:
    global _shutdown
    _shutdown = False

    config: Config = parse_args(argv)
    _configure_logging(config.verbose, config.log_file)

    logger.info(
        "SentinelFlow physical telemetry collector starting "
        "entityId=%s topic=%s bootstrap=%s pollIntervalSeconds=%.1f "
        "processPollIntervalSeconds=%.1f networkPollIntervalSeconds=%.1f",
        config.entity_id,
        config.topic,
        config.kafka_bootstrap_servers,
        config.poll_interval_seconds,
        config.process_poll_interval_seconds,
        config.network_poll_interval_seconds,
    )
    logger.info(
        "REQUIRED: entityId '%s' must already be registered via "
        "POST /api/v1/entities before published events will be accepted "
        "by the SentinelFlow pipeline (see README.md).",
        config.entity_id,
    )

    session_poller = SessionPoller()
    process_poller = ProcessPoller()
    network_poller = NetworkPoller()
    publisher = EventPublisher(config.kafka_bootstrap_servers, config.topic)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    next_session_poll_at = 0.0
    next_process_poll_at = 0.0
    next_network_poll_at = 0.0

    try:
        while not _shutdown:
            now = time.monotonic()

            if now >= next_session_poll_at:
                _poll_and_publish_sessions(session_poller, publisher, config.entity_id)
                next_session_poll_at = now + config.poll_interval_seconds

            if now >= next_process_poll_at:
                _poll_and_publish_processes(process_poller, publisher, config.entity_id)
                next_process_poll_at = now + config.process_poll_interval_seconds

            if now >= next_network_poll_at:
                _poll_and_publish_network(network_poller, publisher, config.entity_id)
                next_network_poll_at = now + config.network_poll_interval_seconds

            # Re-send events queued during a broker outage (no-op otherwise).
            publisher.retry_pending()

            time.sleep(_TICK_SECONDS)
    finally:
        publisher.close()
        logger.info("Collector stopped")

    return 0


if __name__ == "__main__":
    sys.exit(main())

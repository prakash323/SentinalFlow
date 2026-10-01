"""
config.py
Configuration for the SentinelFlow physical telemetry collector.

Canonical envelope constants (SOURCE, EVENT_VERSION) and defaults
(Kafka topic/bootstrap) deliberately mirror the existing platform exactly
- see backend/backend/src/main/java/com/anomaly/platform/kafka/KafkaTopics.java
(topic "raw.events.v1") and application.yml (bootstrap-servers default
"localhost:9094"), and the simulator's own eventVersion "v1"
(SentinelFlow-Python-Simulator-9.2/simulator/event_generator.py).
"""
from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from typing import Optional

from host_identity import default_entity_id

# Per approved decision: physical events are identified with their own
# source literal. The simulator's "python-simulator" is NOT touched.
SOURCE = "physical-collector"
EVENT_VERSION = "v1"

# Same topic and default bootstrap address the existing Spring Boot
# consumer already listens on - no second topic, no new serialization.
DEFAULT_TOPIC = "raw.events.v1"
DEFAULT_KAFKA_BOOTSTRAP_SERVERS = "localhost:9094"

DEFAULT_POLL_INTERVAL_SECONDS = 5.0

# Process Telemetry (P2) phase: a separate, longer default than the
# session poll interval, specifically because the exe/executablePath
# lookup used only for newly-detected processes is not free - see
# process_poller.py's module docstring for the measured cost that
# justifies this default (bulk pid/name/ppid/create_time/username
# enumeration itself is cheap regardless of interval).
DEFAULT_PROCESS_POLL_INTERVAL_SECONDS = 15.0

# Network Telemetry (P3) phase: net_connections() itself is cheap
# (~1.4ms for ~200 connections, measured empirically during the P3
# audit) - this default is chosen to bound EVENT VOLUME, not CPU cost.
# See network_poller.py.
DEFAULT_NETWORK_POLL_INTERVAL_SECONDS = 30.0


@dataclass
class Config:
    entity_id: str
    kafka_bootstrap_servers: str = DEFAULT_KAFKA_BOOTSTRAP_SERVERS
    topic: str = DEFAULT_TOPIC
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS
    process_poll_interval_seconds: float = DEFAULT_PROCESS_POLL_INTERVAL_SECONDS
    network_poll_interval_seconds: float = DEFAULT_NETWORK_POLL_INTERVAL_SECONDS
    verbose: bool = False
    log_file: Optional[str] = None


def parse_args(argv=None) -> Config:
    parser = argparse.ArgumentParser(
        prog="collector.main",
        description=(
            "SentinelFlow physical host login/logout telemetry collector. "
            "Publishes canonical SentinelFlow events directly to the "
            "existing raw event Kafka topic - see README.md."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--entity-id",
        type=str,
        default=None,
        help=(
            "Override the collector's entityId. Defaults to a stable id "
            "derived from this machine's hostname (HOST-<hostname>, see "
            "host_identity.py). This entityId MUST already be registered "
            "in SentinelFlow (POST /api/v1/entities) before published "
            "events will be accepted - the collector does not create "
            "entities itself."
        ),
    )
    parser.add_argument(
        "--kafka-bootstrap-servers",
        type=str,
        default=None,
        help="Kafka bootstrap servers (defaults to the same address Spring Boot uses).",
    )
    parser.add_argument(
        "--topic",
        type=str,
        default=DEFAULT_TOPIC,
        help="Kafka topic. Must match the existing raw event topic - do not change unless the platform's topic changes.",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL_SECONDS,
        help="Seconds between local session snapshots.",
    )
    parser.add_argument(
        "--process-poll-interval",
        type=float,
        default=None,
        help=(
            "Seconds between local process snapshots (PROCESS_START "
            "detection). Independent of --poll-interval - see "
            "process_poller.py for why this defaults higher."
        ),
    )
    parser.add_argument(
        "--network-poll-interval",
        type=float,
        default=None,
        help=(
            "Seconds between local network-connection snapshots "
            "(NETWORK_CONNECTION detection). Independent of --poll-interval "
            "and --process-poll-interval - chosen to bound event volume, "
            "not CPU cost (net_connections() itself is cheap - see "
            "network_poller.py)."
        ),
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug-level logging.")
    parser.add_argument("--log-file", type=str, default=None, help="Also write logs to this file.")

    args = parser.parse_args(argv)

    entity_id = (
        args.entity_id
        or os.environ.get("COLLECTOR_ENTITY_ID")
        or default_entity_id()
    )

    kafka_bootstrap_servers = (
        args.kafka_bootstrap_servers
        or os.environ.get("KAFKA_BOOTSTRAP_SERVERS")
        or DEFAULT_KAFKA_BOOTSTRAP_SERVERS
    )

    process_poll_interval_seconds = args.process_poll_interval
    if process_poll_interval_seconds is None:
        env_value = os.environ.get("PROCESS_POLL_INTERVAL_SECONDS")
        process_poll_interval_seconds = (
            float(env_value) if env_value else DEFAULT_PROCESS_POLL_INTERVAL_SECONDS
        )

    network_poll_interval_seconds = args.network_poll_interval
    if network_poll_interval_seconds is None:
        env_value = os.environ.get("NETWORK_POLL_INTERVAL_SECONDS")
        network_poll_interval_seconds = (
            float(env_value) if env_value else DEFAULT_NETWORK_POLL_INTERVAL_SECONDS
        )

    return Config(
        entity_id=entity_id,
        kafka_bootstrap_servers=kafka_bootstrap_servers,
        topic=args.topic,
        poll_interval_seconds=args.poll_interval,
        process_poll_interval_seconds=process_poll_interval_seconds,
        network_poll_interval_seconds=network_poll_interval_seconds,
        verbose=args.verbose,
        log_file=args.log_file,
    )

"""
config.py
Configuration for the SentinelFlow physical telemetry collector.

Canonical envelope constants (SOURCE, EVENT_VERSION) and defaults
(Kafka topic/bootstrap) deliberately mirror the existing platform exactly
- see backend/backend/src/main/java/com/anomaly/platform/kafka/KafkaTopics.java
(topic "raw.events.v1") and application.yml (bootstrap-servers default
"localhost:9094"), and the simulator's own eventVersion "v1"
(SentinelFlow-Python-Simulator-9.2/simulator/event_generator.py).

Collector 2.0: every runtime knob of the continuous agent (queue bounds,
dedup bounds, retry/backoff, restart backoff, shutdown budget, heartbeat)
is settable from the environment OR the command line, with safe defaults,
and is validated at startup. Nobody has to edit Python source to run this.

Resolution order for every setting (first non-empty wins):

    1. command-line flag
    2. environment variable (the documented name, then the legacy name
       where one already existed before 2.0)
    3. the default constant in this module

Invalid configuration raises ConfigError BEFORE any thread, poller or
Kafka producer is created - a collector that would misbehave for hours
must fail in the first second instead.

Secrets: this collector has none (no credentials are read, held or
logged). The bootstrap address is logged because it is operational
topology, not a secret.
"""
from __future__ import annotations

import argparse
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Optional

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

# --- Collector 2.0 continuous-operation defaults -------------------------

# One central bounded queue between telemetry workers and the Kafka
# publisher. 5000 canonical events is roughly 2-3 MB of JSON-shaped dicts
# at this project's real event sizes (a few hundred bytes each) - large
# enough to ride out a multi-minute broker outage at the measured event
# rates (see README "Event volume"), small enough that a pathological
# event storm can never exhaust the host's memory.
DEFAULT_QUEUE_MAX_SIZE = 5000

# Kafka retry/backoff. These are the values this project already shipped
# and that the existing producer tests encode (5s -> 10s -> 20s ... 60s);
# "existing project conventions" outrank an arbitrary new ladder, and
# both ends are configurable anyway.
DEFAULT_KAFKA_RETRY_BASE_DELAY_SECONDS = 5.0
DEFAULT_KAFKA_RETRY_MAX_DELAY_SECONDS = 60.0

# The publisher's own small in-flight buffer. With the central queue in
# front of it (the publisher stops draining while it is backing off) this
# normally holds 0-1 events; it exists only so a failure mid-batch cannot
# lose the event it was holding.
DEFAULT_KAFKA_MAX_PENDING_EVENTS = 1000

# Pipeline-level duplicate suppression. One hour covers "the same
# observation seen again after a worker restart re-baselined its poller";
# 10000 entries covers an hour of events at well above the measured
# busy-machine rate (~1,700/hour).
DEFAULT_DEDUP_TTL_SECONDS = 3600.0
DEFAULT_DEDUP_MAX_ENTRIES = 10000

# Process metadata retained for process/network correlation. Deliberately
# SHORT: it exists to enrich a connection opened by a process that has
# already exited, and the backend's own NEW_PROCESS_EXTERNAL_CONNECTION
# rule only looks back 5 minutes anyway. A short TTL also bounds the
# PID-reuse risk inherent in any pid-keyed cache (see correlation.py).
DEFAULT_CORRELATION_TTL_SECONDS = 300.0
DEFAULT_CORRELATION_MAX_ENTRIES = 2000

# Graceful shutdown budget: how long the publisher may keep draining the
# queue after Ctrl+C before the collector exits regardless.
DEFAULT_SHUTDOWN_TIMEOUT_SECONDS = 15.0

# Worker restart backoff (supervisor).
DEFAULT_WORKER_RESTART_BASE_DELAY_SECONDS = 1.0
DEFAULT_WORKER_RESTART_MAX_DELAY_SECONDS = 30.0

# How long a restarted worker must stay healthy before its restart
# backoff is reset to the base delay.
DEFAULT_WORKER_HEALTHY_RESET_SECONDS = 120.0

# Periodic one-line operational summary instead of per-poll chatter.
DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 60.0

DEFAULT_LOG_LEVEL = "INFO"

_VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class ConfigError(ValueError):
    """Raised for invalid configuration. Fails startup early and clearly
    rather than letting a long-running agent misbehave for hours."""


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

    queue_max_size: int = DEFAULT_QUEUE_MAX_SIZE
    kafka_retry_base_delay_seconds: float = DEFAULT_KAFKA_RETRY_BASE_DELAY_SECONDS
    kafka_retry_max_delay_seconds: float = DEFAULT_KAFKA_RETRY_MAX_DELAY_SECONDS
    kafka_max_pending_events: int = DEFAULT_KAFKA_MAX_PENDING_EVENTS
    dedup_ttl_seconds: float = DEFAULT_DEDUP_TTL_SECONDS
    dedup_max_entries: int = DEFAULT_DEDUP_MAX_ENTRIES
    correlation_ttl_seconds: float = DEFAULT_CORRELATION_TTL_SECONDS
    correlation_max_entries: int = DEFAULT_CORRELATION_MAX_ENTRIES
    shutdown_timeout_seconds: float = DEFAULT_SHUTDOWN_TIMEOUT_SECONDS
    worker_restart_base_delay_seconds: float = DEFAULT_WORKER_RESTART_BASE_DELAY_SECONDS
    worker_restart_max_delay_seconds: float = DEFAULT_WORKER_RESTART_MAX_DELAY_SECONDS
    worker_healthy_reset_seconds: float = DEFAULT_WORKER_HEALTHY_RESET_SECONDS
    heartbeat_interval_seconds: float = DEFAULT_HEARTBEAT_INTERVAL_SECONDS
    log_level: str = DEFAULT_LOG_LEVEL

    def effective_log_level(self) -> int:
        """--verbose stays supported (it predates LOG_LEVEL) and simply
        wins when set, so existing muscle memory keeps working."""
        if self.verbose:
            return logging.DEBUG
        return getattr(logging, self.log_level, logging.INFO)

    def validate(self) -> "Config":
        """Reject anything that would make a long-running agent misbehave.
        Called by parse_args(); call it directly when building a Config
        programmatically."""
        if not self.entity_id or not self.entity_id.strip():
            raise ConfigError("entity_id must be a non-empty string")
        if not self.kafka_bootstrap_servers or not self.kafka_bootstrap_servers.strip():
            raise ConfigError("kafka_bootstrap_servers must be a non-empty string")
        if not self.topic or not self.topic.strip():
            raise ConfigError("topic must be a non-empty string")

        _require_positive("poll_interval_seconds", self.poll_interval_seconds)
        _require_positive("process_poll_interval_seconds", self.process_poll_interval_seconds)
        _require_positive("network_poll_interval_seconds", self.network_poll_interval_seconds)
        _require_positive("kafka_retry_base_delay_seconds", self.kafka_retry_base_delay_seconds)
        _require_positive("kafka_retry_max_delay_seconds", self.kafka_retry_max_delay_seconds)
        _require_positive("dedup_ttl_seconds", self.dedup_ttl_seconds)
        _require_positive("correlation_ttl_seconds", self.correlation_ttl_seconds)
        _require_positive("worker_restart_base_delay_seconds", self.worker_restart_base_delay_seconds)
        _require_positive("worker_restart_max_delay_seconds", self.worker_restart_max_delay_seconds)
        _require_positive("heartbeat_interval_seconds", self.heartbeat_interval_seconds)
        _require_non_negative("shutdown_timeout_seconds", self.shutdown_timeout_seconds)
        _require_non_negative("worker_healthy_reset_seconds", self.worker_healthy_reset_seconds)

        _require_positive_int("queue_max_size", self.queue_max_size)
        _require_positive_int("kafka_max_pending_events", self.kafka_max_pending_events)
        _require_positive_int("dedup_max_entries", self.dedup_max_entries)
        _require_positive_int("correlation_max_entries", self.correlation_max_entries)

        if self.kafka_retry_max_delay_seconds < self.kafka_retry_base_delay_seconds:
            raise ConfigError(
                "kafka_retry_max_delay_seconds (%s) must be >= "
                "kafka_retry_base_delay_seconds (%s)"
                % (self.kafka_retry_max_delay_seconds, self.kafka_retry_base_delay_seconds)
            )
        if self.worker_restart_max_delay_seconds < self.worker_restart_base_delay_seconds:
            raise ConfigError(
                "worker_restart_max_delay_seconds (%s) must be >= "
                "worker_restart_base_delay_seconds (%s)"
                % (self.worker_restart_max_delay_seconds, self.worker_restart_base_delay_seconds)
            )

        self.log_level = str(self.log_level).upper()
        if self.log_level not in _VALID_LOG_LEVELS:
            raise ConfigError(
                "log_level must be one of %s (got %r)" % (", ".join(_VALID_LOG_LEVELS), self.log_level)
            )

        return self


def _require_positive(name: str, value: Any) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ConfigError(f"{name} must be a number (got {value!r})")
    if value != value or value <= 0:  # NaN or non-positive
        raise ConfigError(f"{name} must be > 0 (got {value!r})")


def _require_non_negative(name: str, value: Any) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ConfigError(f"{name} must be a number (got {value!r})")
    if value != value or value < 0:
        raise ConfigError(f"{name} must be >= 0 (got {value!r})")


def _require_positive_int(name: str, value: Any) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{name} must be an integer (got {value!r})")
    if value <= 0:
        raise ConfigError(f"{name} must be > 0 (got {value!r})")


def _env(*names: str) -> Optional[str]:
    """First non-empty value among these environment variable names.
    Several names are accepted where 2.0's documented name differs from a
    name this project already used before 2.0 - renaming a variable
    someone may already have in a .bat/.env file is not worth it."""
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip() != "":
            return value.strip()
    return None


def _resolve(
    cli_value: Any,
    env_names: tuple,
    default: Any,
    converter: Callable[[str], Any],
    setting_name: str,
) -> Any:
    if cli_value is not None:
        return cli_value
    raw = _env(*env_names)
    if raw is None:
        return default
    try:
        return converter(raw)
    except (TypeError, ValueError) as error:
        raise ConfigError(
            f"{setting_name}: environment value {raw!r} is not valid ({error})"
        ) from error


def _to_int(raw: str) -> int:
    # Reject "5.5" rather than silently truncating a size/count setting.
    return int(raw)


def parse_args(argv=None) -> Config:
    parser = argparse.ArgumentParser(
        prog="collector.main",
        description=(
            "SentinelFlow physical host telemetry collector (2.0). Runs "
            "continuously as a small endpoint agent: supervised process, "
            "network and session workers feed one bounded queue that a "
            "dedicated Kafka publisher drains into the existing raw event "
            "topic - see README.md."
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
        default=None,
        help="Kafka topic. Must match the existing raw event topic - do not change unless the platform's topic changes.",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=None,
        help="Seconds between local session snapshots (SESSION_POLL_INTERVAL).",
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
    parser.add_argument(
        "--queue-max-size",
        type=int,
        default=None,
        help="Maximum events held in the central bounded queue before the oldest is dropped.",
    )
    parser.add_argument(
        "--kafka-retry-base-delay",
        type=float,
        default=None,
        help="First Kafka retry delay after a publish failure (doubles up to --kafka-retry-max-delay).",
    )
    parser.add_argument(
        "--kafka-retry-max-delay",
        type=float,
        default=None,
        help="Upper bound on the Kafka retry backoff.",
    )
    parser.add_argument(
        "--dedup-ttl",
        type=float,
        default=None,
        help="Seconds a pipeline deduplication key is remembered.",
    )
    parser.add_argument(
        "--dedup-max-entries",
        type=int,
        default=None,
        help="Maximum deduplication keys retained (oldest evicted first).",
    )
    parser.add_argument(
        "--shutdown-timeout",
        type=float,
        default=None,
        help="Seconds the publisher may keep draining the queue during shutdown.",
    )
    parser.add_argument(
        "--worker-restart-base-delay",
        type=float,
        default=None,
        help="First delay before a crashed telemetry worker is restarted (doubles up to the max).",
    )
    parser.add_argument(
        "--worker-restart-max-delay",
        type=float,
        default=None,
        help="Upper bound on the worker restart backoff.",
    )
    parser.add_argument(
        "--heartbeat-interval",
        type=float,
        default=None,
        help="Seconds between periodic one-line collector health summaries.",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        help="DEBUG/INFO/WARNING/ERROR/CRITICAL (LOG_LEVEL). --verbose overrides this to DEBUG.",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug-level logging.")
    parser.add_argument("--log-file", type=str, default=None, help="Also write logs to this file.")

    args = parser.parse_args(argv)

    entity_id = args.entity_id or _env("COLLECTOR_ENTITY_ID") or default_entity_id()

    config = Config(
        entity_id=entity_id,
        kafka_bootstrap_servers=_resolve(
            args.kafka_bootstrap_servers, ("KAFKA_BOOTSTRAP_SERVERS",),
            DEFAULT_KAFKA_BOOTSTRAP_SERVERS, str, "kafka_bootstrap_servers",
        ),
        topic=_resolve(
            args.topic, ("KAFKA_TOPIC",), DEFAULT_TOPIC, str, "topic",
        ),
        poll_interval_seconds=_resolve(
            args.poll_interval,
            ("SESSION_POLL_INTERVAL", "SESSION_POLL_INTERVAL_SECONDS"),
            DEFAULT_POLL_INTERVAL_SECONDS, float, "poll_interval_seconds",
        ),
        process_poll_interval_seconds=_resolve(
            args.process_poll_interval,
            ("PROCESS_POLL_INTERVAL", "PROCESS_POLL_INTERVAL_SECONDS"),
            DEFAULT_PROCESS_POLL_INTERVAL_SECONDS, float, "process_poll_interval_seconds",
        ),
        network_poll_interval_seconds=_resolve(
            args.network_poll_interval,
            ("NETWORK_POLL_INTERVAL", "NETWORK_POLL_INTERVAL_SECONDS"),
            DEFAULT_NETWORK_POLL_INTERVAL_SECONDS, float, "network_poll_interval_seconds",
        ),
        queue_max_size=_resolve(
            args.queue_max_size, ("QUEUE_MAX_SIZE",),
            DEFAULT_QUEUE_MAX_SIZE, _to_int, "queue_max_size",
        ),
        kafka_retry_base_delay_seconds=_resolve(
            args.kafka_retry_base_delay, ("KAFKA_RETRY_BASE_DELAY",),
            DEFAULT_KAFKA_RETRY_BASE_DELAY_SECONDS, float, "kafka_retry_base_delay_seconds",
        ),
        kafka_retry_max_delay_seconds=_resolve(
            args.kafka_retry_max_delay, ("KAFKA_RETRY_MAX_DELAY",),
            DEFAULT_KAFKA_RETRY_MAX_DELAY_SECONDS, float, "kafka_retry_max_delay_seconds",
        ),
        kafka_max_pending_events=_resolve(
            None, ("KAFKA_MAX_PENDING_EVENTS",),
            DEFAULT_KAFKA_MAX_PENDING_EVENTS, _to_int, "kafka_max_pending_events",
        ),
        dedup_ttl_seconds=_resolve(
            args.dedup_ttl, ("DEDUP_TTL_SECONDS",),
            DEFAULT_DEDUP_TTL_SECONDS, float, "dedup_ttl_seconds",
        ),
        dedup_max_entries=_resolve(
            args.dedup_max_entries, ("DEDUP_MAX_ENTRIES",),
            DEFAULT_DEDUP_MAX_ENTRIES, _to_int, "dedup_max_entries",
        ),
        correlation_ttl_seconds=_resolve(
            None, ("CORRELATION_TTL_SECONDS",),
            DEFAULT_CORRELATION_TTL_SECONDS, float, "correlation_ttl_seconds",
        ),
        correlation_max_entries=_resolve(
            None, ("CORRELATION_MAX_ENTRIES",),
            DEFAULT_CORRELATION_MAX_ENTRIES, _to_int, "correlation_max_entries",
        ),
        shutdown_timeout_seconds=_resolve(
            args.shutdown_timeout, ("SHUTDOWN_TIMEOUT_SECONDS",),
            DEFAULT_SHUTDOWN_TIMEOUT_SECONDS, float, "shutdown_timeout_seconds",
        ),
        worker_restart_base_delay_seconds=_resolve(
            args.worker_restart_base_delay, ("WORKER_RESTART_BASE_DELAY",),
            DEFAULT_WORKER_RESTART_BASE_DELAY_SECONDS, float, "worker_restart_base_delay_seconds",
        ),
        worker_restart_max_delay_seconds=_resolve(
            args.worker_restart_max_delay, ("WORKER_RESTART_MAX_DELAY",),
            DEFAULT_WORKER_RESTART_MAX_DELAY_SECONDS, float, "worker_restart_max_delay_seconds",
        ),
        worker_healthy_reset_seconds=_resolve(
            None, ("WORKER_HEALTHY_RESET_SECONDS",),
            DEFAULT_WORKER_HEALTHY_RESET_SECONDS, float, "worker_healthy_reset_seconds",
        ),
        heartbeat_interval_seconds=_resolve(
            args.heartbeat_interval, ("HEARTBEAT_INTERVAL_SECONDS",),
            DEFAULT_HEARTBEAT_INTERVAL_SECONDS, float, "heartbeat_interval_seconds",
        ),
        log_level=_resolve(
            args.log_level, ("LOG_LEVEL",), DEFAULT_LOG_LEVEL, str, "log_level",
        ),
        verbose=args.verbose,
        log_file=args.log_file or _env("LOG_FILE"),
    )

    return config.validate()

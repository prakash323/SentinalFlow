#!/usr/bin/env python3
"""
simulator.py
SentinelFlow Python Event Simulator -- entry point.

Generates synthetic security events per the configured scenario and POSTs
them to the Spring Boot event API (POST /api/v1/events), matching the
CreateEventRequest contract exactly. See README.md for usage.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

from config import Config, DEFAULT_USERS, VALID_SCENARIOS
from entities import build_entity_pool
from event_generator import reset_event_id_counter, validate_event_contract
from http_client import EventClient
from scenarios import generate_stream

logger = logging.getLogger("sentinelflow.simulator")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv=None) -> Config:
    parser = argparse.ArgumentParser(
        prog="simulator.py",
        description="SentinelFlow synthetic security-event generator.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--events", type=int, default=100, help="Number of events to generate")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between sends")
    parser.add_argument(
        "--scenario",
        type=str,
        default="mixed",
        choices=sorted(VALID_SCENARIOS),
        help="Behavior scenario to simulate",
    )
    parser.add_argument("--base-url", type=str, default="http://localhost:8080", help="Backend base URL")
    parser.add_argument(
        "--users",
        type=str,
        default=None,
        help="Comma-separated entity IDs (default: USER-001..USER-010)",
    )
    parser.add_argument("--seed", type=int, default=None, help="RNG seed for reproducible runs")
    parser.add_argument("--dry-run", action="store_true", help="Generate events but don't send them")
    parser.add_argument(
        "--historical-days", type=int, default=3, help="Days of history to spread events across (historical scenario)"
    )
    parser.add_argument(
        "--burst-window-seconds", type=int, default=60, help="Window to cluster timestamps in (burst scenario)"
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="HTTP request timeout (seconds)")
    parser.add_argument("--max-retries", type=int, default=3, help="HTTP retries on transient failure")
    parser.add_argument("--jitter", type=float, default=0.15, help="Fractional jitter applied to --interval")
    parser.add_argument("--output-file", type=str, default=None, help="Write every generated event to this JSONL file")
    parser.add_argument("--log-file", type=str, default=None, help="Write logs to this file in addition to stdout")
    parser.add_argument("--verbose", action="store_true", help="Enable debug-level logging")

    args = parser.parse_args(argv)

    users = DEFAULT_USERS if args.users is None else [u.strip() for u in args.users.split(",") if u.strip()]

    config = Config(
        events=args.events,
        interval=args.interval,
        scenario=args.scenario,
        base_url=args.base_url,
        users=users,
        seed=args.seed,
        dry_run=args.dry_run,
        historical_days=args.historical_days,
        burst_window_seconds=args.burst_window_seconds,
        timeout=args.timeout,
        max_retries=args.max_retries,
        jitter=args.jitter,
        output_file=args.output_file,
        log_file=args.log_file,
        verbose=args.verbose,
    )
    config.validate()
    return config


def setup_logging(config: Config) -> None:
    level = logging.DEBUG if config.verbose else logging.INFO
    handlers = [logging.StreamHandler(sys.stdout)]
    if config.log_file:
        handlers.append(logging.FileHandler(config.log_file))

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
    )


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run(config: Config) -> int:
    setup_logging(config)
    rng = config.make_rng()
    reset_event_id_counter(1)

    logger.info(
        "Starting run: scenario=%s events=%d interval=%.2fs target=%s dry_run=%s seed=%s",
        config.scenario, config.events, config.interval, config.events_url, config.dry_run, config.seed,
    )

    entity_pool = build_entity_pool(config.users, rng)
    logger.debug(
        "Entity pool: %s",
        {eid: p.profile_type for eid, p in entity_pool.items()},
    )

    stream = generate_stream(config, entity_pool, rng)
    logger.info("Planned %d events", len(stream))

    client = EventClient(
        base_url=config.base_url,
        timeout=config.timeout,
        max_retries=config.max_retries,
        dry_run=config.dry_run,
    )

    output_fh = open(config.output_file, "w", encoding="utf-8") if config.output_file else None

    sent_ok = 0
    sent_fail = 0
    by_type: Counter = Counter()
    by_scenario: Counter = Counter()
    future_timestamps = 0
    duplicate_ids = 0
    seen_ids = set()
    oldest_timestamp = None
    newest_timestamp = None
    interrupted = False

    try:
        for idx, gen_event in enumerate(stream, start=1):
            event = gen_event.event
            validate_event_contract(event)

            if event["eventId"] in seen_ids:
                duplicate_ids += 1
                raise ValueError(f"Duplicate eventId generated: {event["eventId"]}")
            seen_ids.add(event["eventId"])

            occurred = datetime.fromisoformat(event["occurredAt"].replace("Z", "+00:00"))
            if occurred > datetime.now(timezone.utc):
                future_timestamps += 1
                raise ValueError(f"Future occurredAt generated: {event["occurredAt"]}")
            oldest_timestamp = occurred if oldest_timestamp is None else min(oldest_timestamp, occurred)
            newest_timestamp = occurred if newest_timestamp is None else max(newest_timestamp, occurred)

            result = client.send_event(config.events_url, event)

            by_type[event["eventType"]] += 1
            by_scenario[gen_event.scenario] += 1

            if output_fh:
                output_fh.write(json.dumps(event) + "\n")

            if result.ok:
                sent_ok += 1
                status_desc = "DRY-RUN" if result.dry_run else f"HTTP {result.status_code}"
                logger.info(
                    "[%d/%d] OK   %-16s %-10s %s (%s)",
                    idx, len(stream), event["eventType"], event["entityId"], status_desc, gen_event.scenario,
                )
            else:
                sent_fail += 1
                logger.warning(
                    "[%d/%d] FAIL %-16s %-10s %s (%s)",
                    idx, len(stream), event["eventType"], event["entityId"], result.error, gen_event.scenario,
                )

            if idx < len(stream) and config.interval > 0:
                sleep_for = _jittered(config.interval, config.jitter, rng)
                time.sleep(sleep_for)

    except KeyboardInterrupt:
        interrupted = True
        logger.warning("Interrupted by user -- stopping after %d/%d events", sent_ok + sent_fail, len(stream))

    finally:
        client.close()
        if output_fh:
            output_fh.close()

    _print_summary(
        config, sent_ok, sent_fail, by_type, by_scenario, interrupted,
        future_timestamps, duplicate_ids, oldest_timestamp, newest_timestamp,
    )

    return 1 if sent_fail > 0 and not config.dry_run else 0


def _jittered(interval: float, jitter_fraction: float, rng: random.Random) -> float:
    if jitter_fraction <= 0:
        return interval
    delta = interval * jitter_fraction
    return max(0.0, interval + rng.uniform(-delta, delta))


def _print_summary(config, ok, fail, by_type, by_scenario, interrupted, future_timestamps=0, duplicate_ids=0, oldest_timestamp=None, newest_timestamp=None) -> None:
    total = ok + fail
    lines = [
        "",
        "=" * 60,
        "SentinelFlow Simulator -- Run Summary",
        "=" * 60,
        f"Scenario:        {config.scenario}",
        f"Target:          {config.events_url}",
        f"Mode:            {'DRY RUN (no HTTP calls made)' if config.dry_run else 'LIVE'}",
        f"Events sent:     {total} ({ok} ok, {fail} failed)",
        f"Future timestamps:{future_timestamps}",
        f"Duplicate IDs:   {duplicate_ids}",
    ]
    if interrupted:
        lines.append("Status:          INTERRUPTED (Ctrl+C)")
    if oldest_timestamp is not None:
        lines.append(f"Oldest occurredAt:{oldest_timestamp.isoformat().replace("+00:00", "Z")}")
        lines.append(f"Newest occurredAt:{newest_timestamp.isoformat().replace("+00:00", "Z")}")
    if config.seed is not None:
        lines.append(f"Seed:            {config.seed} (rerun with --seed {config.seed} to reproduce)")
    if config.output_file:
        lines.append(f"Events written:  {config.output_file}")

    lines.append("")
    lines.append("By event type:")
    for etype, count in by_type.most_common():
        lines.append(f"  {etype:<18} {count}")

    lines.append("")
    lines.append("By scenario tag:")
    for scen, count in by_scenario.most_common():
        lines.append(f"  {scen:<18} {count}")

    lines.append("=" * 60)
    summary = "\n".join(lines)

    # Print directly (not via logger) so the summary is clean regardless
    # of log level/formatting.
    print(summary)


def main(argv: Optional[list] = None) -> int:
    try:
        config = parse_args(argv)
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    return run(config)


if __name__ == "__main__":
    sys.exit(main())

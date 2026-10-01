"""
Scenario definitions and event-stream generation for SentinelFlow.

The simulator generates correlated security-event sequences and assigns
occurredAt timestamps that are guaranteed to be <= the generation time in
live mode. Sequence timing is generated backwards from an anchor near now,
then the final stream is sorted chronologically before sending.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple

from config import Config, MIXED_SCENARIO_WEIGHTS
from entities import pick_entity_for_scenario
from event_generator import GeneratedEvent, build_event, weighted_event_type

Step = Tuple[str, str]
PlanStep = Tuple[str, str, str, int]  # event_type, outcome, scenario_tag, run_id

SEQUENCES: Dict[str, List[Step]] = {
    "normal": [
        ("LOGIN", "normal"),
        ("API_ACCESS", "normal"),
        ("API_ACCESS", "normal"),
        ("FILE_ACCESS", "normal"),
        ("LOGOUT", "normal"),
    ],
    "suspicious": [
        ("LOGIN", "failure"),
        ("LOGIN", "failure"),
        ("LOGIN", "failure"),
        ("PASSWORD_CHANGE", "sensitive"),
        ("TRANSACTION", "sensitive"),
    ],
    "high": [
        ("LOGIN", "failure"),
        ("LOGIN", "failure"),
        ("PASSWORD_CHANGE", "sensitive"),
        ("API_ACCESS", "sensitive"),
        ("FILE_ACCESS", "sensitive"),
    ],
    "critical": [
        ("LOGIN", "failure"),
        ("LOGIN", "failure"),
        ("LOGIN", "failure"),
        ("PASSWORD_CHANGE", "high_value"),
        ("API_ACCESS", "high_value"),
        ("FILE_ACCESS", "high_value"),
        ("TRANSACTION", "high_value"),
    ],
}

_STEP_GAP_RANGE = (5, 45)
# Live events are allowed to be a little behind the current clock. The
# sequence duration is added backwards from this anchor, never forwards.
_LIVE_ANCHOR_MAX_AGE_SECONDS = 30


def _resolve_mixed_step(rng: random.Random) -> str:
    scenarios = list(MIXED_SCENARIO_WEIGHTS.keys())
    weights = list(MIXED_SCENARIO_WEIGHTS.values())
    return rng.choices(scenarios, weights=weights, k=1)[0]


def _add_sequence_plan(
    plan: List[PlanStep],
    scenario: str,
    remaining: int,
    run_id: int,
) -> int:
    sequence = SEQUENCES[scenario]
    count = min(len(sequence), remaining)
    for event_type, outcome in sequence[:count]:
        plan.append((event_type, outcome, scenario, run_id))
    return count


def _plan_steps(config: Config, rng: random.Random) -> List[PlanStep]:
    plan: List[PlanStep] = []
    remaining = config.events
    run_id = 0

    if config.scenario in SEQUENCES:
        while remaining > 0:
            run_id += 1
            used = _add_sequence_plan(plan, config.scenario, remaining, run_id)
            remaining -= used

    elif config.scenario == "mixed":
        while remaining > 0:
            run_id += 1
            chosen = _resolve_mixed_step(rng)
            used = _add_sequence_plan(plan, chosen, remaining, run_id)
            plan[-used:] = [
                (etype, outcome, "mixed", run_id)
                for etype, outcome, _, _ in plan[-used:]
            ]
            remaining -= used

    elif config.scenario == "burst":
        run_id += 1
        for _ in range(remaining):
            etype = weighted_event_type(rng)
            outcome = "normal" if rng.random() > 0.05 else "failure"
            plan.append((etype, outcome, "burst", run_id))
            run_id += 1

    elif config.scenario == "historical":
        while remaining > 0:
            run_id += 1
            chosen = _resolve_mixed_step(rng)
            used = _add_sequence_plan(plan, chosen, remaining, run_id)
            plan[-used:] = [
                (etype, outcome, "historical", run_id)
                for etype, outcome, _, _ in plan[-used:]
            ]
            remaining -= used

    else:
        raise ValueError(f"Unknown scenario: {config.scenario}")

    return plan[: config.events]


def _sequence_timestamps(
    length: int,
    anchor: datetime,
    rng: random.Random,
) -> List[datetime]:
    """Create strictly non-decreasing timestamps ending at anchor.

    The anchor is never in the future. Gaps are generated backwards so the
    complete sequence remains in the past relative to generation time.
    """
    if length <= 0:
        return []

    gaps = [rng.randint(*_STEP_GAP_RANGE) for _ in range(max(0, length - 1))]
    total_gap = sum(gaps)
    start = anchor - timedelta(seconds=total_gap)

    timestamps = [start]
    current = start
    for gap in gaps:
        current += timedelta(seconds=gap)
        timestamps.append(current)
    return timestamps


def _historical_sequence_timestamps(
    length: int,
    anchor: datetime,
    rng: random.Random,
) -> List[datetime]:
    """Create a sequence in the past, preserving temporal order."""
    return _sequence_timestamps(length, anchor, rng)


def _build_sequence_runs(
    plan: List[PlanStep],
    config: Config,
    now: datetime,
    rng: random.Random,
) -> List[Tuple[int, int, List[datetime]]]:
    """Return (start, end, timestamps) for every sequence run."""
    runs: List[Tuple[int, int, List[datetime]]] = []
    i = 0
    total = len(plan)

    while i < total:
        run_id = plan[i][3]
        j = i + 1
        while j < total and plan[j][3] == run_id:
            j += 1

        scenario = plan[i][2]
        length = j - i

        if scenario == "burst":
            # Burst events are independent, handled individually later.
            runs.append((i, j, []))
        elif scenario == "historical":
            span = max(1, config.historical_days) * 24 * 3600
            age = rng.uniform(0, span)
            anchor = now - timedelta(seconds=age)
            runs.append((i, j, _historical_sequence_timestamps(length, anchor, rng)))
        else:
            # Pick an anchor in the past and build the sequence backwards.
            anchor_age = rng.uniform(0, _LIVE_ANCHOR_MAX_AGE_SECONDS)
            anchor = now - timedelta(seconds=anchor_age)
            runs.append((i, j, _sequence_timestamps(length, anchor, rng)))

        i = j

    return runs


def generate_stream(
    config: Config,
    entity_pool: dict,
    rng: random.Random,
) -> List[GeneratedEvent]:
    """Generate a complete stream with safe, scenario-aware timestamps."""
    plan = _plan_steps(config, rng)
    now = datetime.now(timezone.utc)
    events: List[GeneratedEvent] = []

    for start, end, timestamps in _build_sequence_runs(plan, config, now, rng):
        scenario_tag = plan[start][2]
        entity = pick_entity_for_scenario(entity_pool, scenario_tag, rng)

        for offset, index in enumerate(range(start, end)):
            event_type, outcome, scenario, _ = plan[index]

            if scenario == "burst":
                age = rng.uniform(0, config.burst_window_seconds)
                occurred_at = now - timedelta(seconds=age)
                entity = pick_entity_for_scenario(entity_pool, scenario, rng)
            else:
                occurred_at = timestamps[offset]

            # Defensive invariant: no generated live/historical event may
            # ever be in the future relative to generation time.
            if occurred_at > now:
                occurred_at = now

            events.append(
                build_event(
                    entity=entity,
                    event_type=event_type,
                    occurred_at=occurred_at,
                    rng=rng,
                    outcome=outcome,
                    scenario=scenario,
                )
            )

    # Chronological send order makes the simulator behave like a normal
    # event source and makes eventId ordering intuitive.
    events.sort(key=lambda e: e.event["occurredAt"])
    events = events[: config.events]

    # Assign IDs after sorting so the first transmitted event is always
    # <run_id>-000001. The run_id segment (generated once per invocation,
    # see Config.run_id) is what makes IDs unique ACROSS separate runs
    # against the same backend; the numeric suffix is still a plain
    # per-run sequential counter, identical in spirit to before.
    for n, ge in enumerate(events, start=1):
        ge.event["eventId"] = f"EV-SIM-{config.run_id}-{n:06d}"

    # Final invariant check after serialization/ordering.
    generation_now = datetime.now(timezone.utc)
    for ge in events:
        timestamp = datetime.fromisoformat(ge.event["occurredAt"].replace("Z", "+00:00"))
        if timestamp > generation_now:
            raise RuntimeError(f"Generated future occurredAt: {ge.event['occurredAt']}")

    return events

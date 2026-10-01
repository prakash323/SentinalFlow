"""
config.py
Central configuration for the SentinelFlow event simulator.

Holds the Config dataclass built from CLI args, plus shared constants
(event type weights, entity pools, HTTP defaults) so other modules don't
hard-code magic numbers.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Event type weights (Section 11 of the spec)
# ---------------------------------------------------------------------------
EVENT_TYPE_WEIGHTS = {
    "LOGIN": 30,
    "API_ACCESS": 25,
    "FILE_ACCESS": 15,
    "TRANSACTION": 15,
    "LOGOUT": 10,
    "PASSWORD_CHANGE": 5,
}

# Scenario mix for the "mixed" scenario (Section 7)
MIXED_SCENARIO_WEIGHTS = {
    "normal": 70,
    "suspicious": 20,
    "high": 8,
    "critical": 2,
}

VALID_SCENARIOS = {
    "normal",
    "suspicious",
    "high",
    "critical",
    "mixed",
    "burst",
    "historical",
}

DEFAULT_USERS = [f"USER-{i:03d}" for i in range(1, 11)]  # USER-001..USER-010
DEFAULT_SERVICE_ACCOUNTS = ["SVC-001", "SVC-002"]

DEFAULT_BASE_URL = "http://localhost:8080"
EVENTS_ENDPOINT = "/api/v1/events"

DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_FACTOR = 0.5


@dataclass
class Config:
    """Resolved, validated configuration for a single simulator run."""

    events: int = 100
    interval: float = 2.0
    scenario: str = "mixed"
    base_url: str = DEFAULT_BASE_URL
    users: List[str] = field(default_factory=lambda: list(DEFAULT_USERS))
    seed: Optional[int] = None
    dry_run: bool = False
    historical_days: int = 3
    burst_window_seconds: int = 60
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    max_retries: int = DEFAULT_MAX_RETRIES
    output_file: Optional[str] = None
    log_file: Optional[str] = None
    verbose: bool = False
    jitter: float = 0.15  # +/- fraction of `interval` used to jitter send timing

    # Generated once per simulator invocation (not from --seed, deliberately
    # - two --seed-matched runs must still get different eventIds, or the
    # whole point of this field is defeated). Folded into every eventId in
    # this run (see scenarios.generate_stream) so repeated runs against the
    # same backend never collide on the DB's unique eventId constraint,
    # while IDs within one run stay sequential/deterministic.
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])

    @property
    def events_url(self) -> str:
        return self.base_url.rstrip("/") + EVENTS_ENDPOINT

    def validate(self) -> None:
        errors = []
        if self.events <= 0:
            errors.append("--events must be a positive integer")
        if self.interval < 0:
            errors.append("--interval cannot be negative")
        if self.scenario not in VALID_SCENARIOS:
            errors.append(
                f"--scenario '{self.scenario}' is invalid. "
                f"Choose from: {', '.join(sorted(VALID_SCENARIOS))}"
            )
        if not self.users:
            errors.append("--users cannot be empty")
        if self.timeout <= 0:
            errors.append("--timeout must be positive")
        if self.max_retries < 0:
            errors.append("--max-retries cannot be negative")
        if not (0 <= self.jitter < 1):
            errors.append("--jitter must be in [0, 1)")
        if errors:
            raise ValueError("Invalid configuration:\n  - " + "\n  - ".join(errors))

    def make_rng(self) -> random.Random:
        """Dedicated RNG instance so we never touch the global random state
        (keeps behavior reproducible even if other libs call random.*)."""
        return random.Random(self.seed)

"""
event_generator.py
Builds individual events that conform to the existing Spring Boot
CreateEventRequest contract (Section 3/4 of the spec).

Each event type has a payload builder that takes the entity profile and an
"outcome" hint (normal / failure / sensitive / high_value) so correlated
fields move together instead of being randomized independently
(Section 11).
"""

from __future__ import annotations

import itertools
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional

from config import EVENT_TYPE_WEIGHTS
from entities import EntityProfile

EVENT_VERSION = "v1"
SOURCE = "python-simulator"

_id_counter = itertools.count(1)


def reset_event_id_counter(start: int = 1) -> None:
    global _id_counter
    _id_counter = itertools.count(start)


def next_event_id() -> str:
    return f"EV-SIM-{next(_id_counter):06d}"


def iso_utc(dt: datetime) -> str:
    """Format as ISO-8601 UTC with a trailing 'Z', matching the contract
    example exactly (no microseconds, no +00:00)."""
    dt = dt.astimezone(timezone.utc).replace(microsecond=0)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def weighted_event_type(rng: random.Random) -> str:
    types = list(EVENT_TYPE_WEIGHTS.keys())
    weights = list(EVENT_TYPE_WEIGHTS.values())
    return rng.choices(types, weights=weights, k=1)[0]


# ---------------------------------------------------------------------------
# Payload builders -- one per event type
# ---------------------------------------------------------------------------

def _login_payload(entity: EntityProfile, rng: random.Random, outcome: str) -> Dict:
    failure = outcome in ("failure", "sensitive", "high_value")
    unfamiliar = outcome in ("sensitive", "high_value") or (
        outcome == "failure" and rng.random() < 0.6
    )
    ip = entity.unfamiliar_ip(rng) if unfamiliar else entity.familiar_ip(rng)
    location = entity.unfamiliar_location(rng) if unfamiliar else entity.familiar_location(rng)
    return {
        "ip": ip,
        "location": location,
        "loginSuccess": not failure,
    }


def _logout_payload(entity: EntityProfile, rng: random.Random, outcome: str) -> Dict:
    ip = entity.familiar_ip(rng)
    # Compromised/attack sessions tend to be short (smash and grab) or
    # unusually long (data exfiltration); normal sessions are mid-range.
    if outcome in ("sensitive", "high_value"):
        duration = rng.choice([rng.randint(1, 4), rng.randint(120, 240)])
    else:
        duration = rng.randint(5, 90)
    return {"ip": ip, "sessionDurationMinutes": duration}


def _api_access_payload(entity: EntityProfile, rng: random.Random, outcome: str) -> Dict:
    if entity.profile_type == "service_account":
        endpoints = ["/api/v1/events", "/api/v1/reports", "/api/v1/sync"]
    else:
        endpoints = ["/api/v1/events", "/api/v1/profile", "/api/v1/dashboard"]

    sensitive_endpoints = ["/api/v1/admin/users", "/api/v1/export", "/api/v1/audit-logs"]
    methods = ["GET", "GET", "GET", "POST"]  # GET-weighted for normal traffic

    if outcome in ("sensitive", "high_value"):
        endpoint = rng.choice(sensitive_endpoints)
        method = rng.choice(["GET", "POST", "DELETE"])
        status = rng.choice([200, 403, 401])
        ip = entity.unfamiliar_ip(rng) if outcome == "high_value" else entity.familiar_ip(rng)
    else:
        endpoint = rng.choice(endpoints)
        method = rng.choice(methods)
        status = 200
        ip = entity.familiar_ip(rng)

    return {"ip": ip, "method": method, "endpoint": endpoint, "statusCode": status}


def _file_access_payload(entity: EntityProfile, rng: random.Random, outcome: str) -> Dict:
    normal_files = ["report.pdf", "notes.docx", "invoice.xlsx", "readme.md"]
    sensitive_files = ["employee_pii.xlsx", "customer_db_export.csv", "salary_data.xlsx"]

    if outcome in ("sensitive", "high_value"):
        filename = rng.choice(sensitive_files)
        action = rng.choice(["READ", "DOWNLOAD", "COPY"])
        sensitive = True
        ip = entity.unfamiliar_ip(rng) if outcome == "high_value" else entity.familiar_ip(rng)
    else:
        filename = rng.choice(normal_files)
        action = rng.choice(["READ", "WRITE"])
        sensitive = False
        ip = entity.familiar_ip(rng)

    return {"ip": ip, "fileName": filename, "action": action, "sensitive": sensitive}


def _password_change_payload(entity: EntityProfile, rng: random.Random, outcome: str) -> Dict:
    unfamiliar = outcome in ("sensitive", "high_value")
    ip = entity.unfamiliar_ip(rng) if unfamiliar else entity.familiar_ip(rng)
    location = entity.unfamiliar_location(rng) if unfamiliar else entity.familiar_location(rng)
    # An attacker resetting credentials almost always succeeds (that's the
    # point of the attack); legitimate users occasionally mistype/cancel.
    success = True if outcome in ("sensitive", "high_value") else rng.random() > 0.05
    return {"ip": ip, "location": location, "success": success}


def _transaction_payload(entity: EntityProfile, rng: random.Random, outcome: str) -> Dict:
    if outcome == "high_value":
        amount = round(rng.uniform(50000, 250000), 2)
    elif outcome == "sensitive":
        amount = round(rng.uniform(5000, 50000), 2)
    else:
        amount = round(rng.uniform(50, 5000), 2)

    currency = rng.choice(["INR", "USD", "EUR"]) if outcome == "normal" else "INR"
    success = outcome not in ("failure",)
    return {
        "ip": entity.familiar_ip(rng) if outcome == "normal" else entity.unfamiliar_ip(rng),
        "amount": amount,
        "currency": currency,
        "loginSuccess": success,
    }


PAYLOAD_BUILDERS = {
    "LOGIN": _login_payload,
    "LOGOUT": _logout_payload,
    "API_ACCESS": _api_access_payload,
    "FILE_ACCESS": _file_access_payload,
    "PASSWORD_CHANGE": _password_change_payload,
    "TRANSACTION": _transaction_payload,
}


@dataclass
class GeneratedEvent:
    event: Dict
    scenario: str
    entity_type: str


def build_event(
    entity: EntityProfile,
    event_type: str,
    occurred_at: datetime,
    rng: random.Random,
    outcome: str = "normal",
    scenario: str = "normal",
) -> GeneratedEvent:
    """Build one fully-formed event dict matching the CreateEventRequest
    contract, tagging it with scenario/entity metadata for run summaries
    (metadata stays out of the actual `event` payload sent to the API)."""
    builder = PAYLOAD_BUILDERS.get(event_type)
    if builder is None:
        raise ValueError(f"Unknown event type: {event_type}")

    payload = builder(entity, rng, outcome)

    event = {
        "eventId": next_event_id(),
        "entityId": entity.entity_id,
        "eventType": event_type,
        "eventVersion": EVENT_VERSION,
        "occurredAt": iso_utc(occurred_at),
        "source": SOURCE,
        "payload": payload,
    }
    return GeneratedEvent(event=event, scenario=scenario, entity_type=entity.profile_type)


def validate_event_contract(event: Dict) -> None:
    """Validate the outgoing event against the Spring Boot request contract."""
    required = {
        "eventId": str,
        "entityId": str,
        "eventType": str,
        "eventVersion": str,
        "occurredAt": str,
        "source": str,
        "payload": dict,
    }

    missing = [key for key in required if key not in event]
    if missing:
        raise ValueError(f"Event missing required fields: {', '.join(missing)}")

    wrong_types = [
        f"{key} expected {expected.__name__}"
        for key, expected in required.items()
        if not isinstance(event[key], expected)
    ]
    if wrong_types:
        raise ValueError("Invalid event contract: " + "; ".join(wrong_types))

    if not event["eventId"].strip():
        raise ValueError("eventId cannot be empty")
    if not event["entityId"].strip():
        raise ValueError("entityId cannot be empty")
    if not event["eventType"].strip():
        raise ValueError("eventType cannot be empty")

    try:
        datetime.fromisoformat(event["occurredAt"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid occurredAt: {event['occurredAt']}") from exc

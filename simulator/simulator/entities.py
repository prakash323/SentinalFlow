"""
entities.py
Entity profile modeling (Section 10 of the spec).

Improvement over the base spec: profiles are generated once per run and
carry their own IP/location pools so that correlated fields (Section 11 --
"do not independently randomize fields that should logically correlate")
stay consistent for a given user across the whole event stream. A
compromised user's "known" IP still looks like their normal IP; their
anomalous events use a distinct IP/location drawn from a separate pool.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import List


PROFILE_TYPES = ["normal", "remote", "risky", "compromised", "service_account"]

# Weighted so most users are boring, a minority are risky/compromised --
# mirrors a realistic population instead of an even split.
PROFILE_WEIGHTS = {
    "normal": 55,
    "remote": 20,
    "risky": 15,
    "compromised": 5,
    "service_account": 5,
}

LOCATIONS = ["India", "USA", "UK", "Germany", "Singapore", "Brazil", "UAE", "Japan"]
UNFAMILIAR_LOCATIONS = ["Russia", "Nigeria", "North Korea", "Unknown"]


def _random_ip(rng: random.Random, private: bool = True) -> str:
    if private:
        return f"10.10.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


@dataclass
class EntityProfile:
    entity_id: str
    profile_type: str
    home_ip: str
    home_location: str
    known_ips: List[str] = field(default_factory=list)
    known_locations: List[str] = field(default_factory=list)

    def familiar_ip(self, rng: random.Random) -> str:
        return rng.choice(self.known_ips)

    def familiar_location(self, rng: random.Random) -> str:
        return rng.choice(self.known_locations)

    def unfamiliar_ip(self, rng: random.Random) -> str:
        return _random_ip(rng, private=False)

    def unfamiliar_location(self, rng: random.Random) -> str:
        return rng.choice(UNFAMILIAR_LOCATIONS)


def build_entity_pool(user_ids: List[str], rng: random.Random) -> dict:
    """Assign each configured user id a behavioral profile.

    Returns a dict: entity_id -> EntityProfile
    """
    types = list(PROFILE_WEIGHTS.keys())
    weights = list(PROFILE_WEIGHTS.values())
    pool = {}

    for uid in user_ids:
        # Service accounts are identified by naming convention if present,
        # otherwise assigned probabilistically like any other profile.
        if uid.startswith("SVC-"):
            profile_type = "service_account"
        else:
            profile_type = rng.choices(types, weights=weights, k=1)[0]

        home_ip = _random_ip(rng)
        home_location = rng.choice(LOCATIONS)

        known_ips = [home_ip]
        known_locations = [home_location]

        if profile_type == "remote":
            # Several legitimate known locations/IPs -- a traveling user.
            extra = rng.randint(1, 3)
            known_ips += [_random_ip(rng) for _ in range(extra)]
            known_locations += rng.sample(
                [loc for loc in LOCATIONS if loc != home_location],
                k=min(extra, len(LOCATIONS) - 1),
            )
        elif profile_type == "service_account":
            # Service accounts don't "travel" -- one stable IP/location.
            pass

        pool[uid] = EntityProfile(
            entity_id=uid,
            profile_type=profile_type,
            home_ip=home_ip,
            home_location=home_location,
            known_ips=known_ips,
            known_locations=known_locations,
        )

    return pool


def pick_entity_for_scenario(pool: dict, scenario: str, rng: random.Random) -> EntityProfile:
    """Bias entity selection toward profiles that make sense for a scenario.

    E.g. 'critical' scenarios preferentially (not exclusively) pick
    'compromised' or 'risky' profiles so the generated behavior lines up
    with the entity's baseline -- avoids a 'normal' user having a wildly
    out-of-character event with no other context.
    """
    all_entities = list(pool.values())

    preference = {
        "normal": ["normal", "remote", "service_account"],
        "suspicious": ["risky", "remote", "normal"],
        "high": ["risky", "compromised"],
        "critical": ["compromised", "risky"],
        "burst": ["service_account", "normal"],
        "historical": ["normal", "remote", "risky"],
    }.get(scenario, PROFILE_TYPES)

    preferred = [e for e in all_entities if e.profile_type in preference]
    candidates = preferred if preferred else all_entities
    return rng.choice(candidates)

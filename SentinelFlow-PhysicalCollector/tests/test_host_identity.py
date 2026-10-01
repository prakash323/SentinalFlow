"""Test C (stable entityId)."""
from host_identity import default_entity_id, stable_hostname


def test_default_entity_id_is_deterministic_across_calls():
    first = default_entity_id()
    second = default_entity_id()
    assert first == second


def test_default_entity_id_is_deterministic_across_fresh_derivations():
    # Simulates two separate collector process startups on the same
    # machine: nothing here is seeded by time/randomness, so it must be
    # identical every time, unlike the pre-fix simulator's eventId
    # counter reset bug.
    values = {default_entity_id() for _ in range(5)}
    assert len(values) == 1


def test_default_entity_id_format():
    entity_id = default_entity_id()
    assert entity_id == f"HOST-{stable_hostname().upper()}"
    assert entity_id.startswith("HOST-")

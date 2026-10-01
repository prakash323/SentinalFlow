"""
Tests A, B, D, E, F, G, H, I, J from the approved test list:
  A. physical login event -> canonical event
  B. physical logout event -> canonical event
  D. eventId uniqueness
  E. timestamp format
  F. source = physical-collector
  G. eventVersion = v1
  H. missing optional telemetry fields
  I. JSON serialization
  J. simulator-compatible payload field names
"""
import json
import re

import pytest

from normalizer import (
    build_event,
    build_login_event,
    build_logout_event,
    build_network_connection_event,
    build_process_start_event,
    iso_utc,
    new_event_id,
)
from network_poller import NetworkConnectionEvent
from process_poller import ProcessEvent
from session_poller import SessionEvent

ENTITY_ID = "HOST-TESTMACHINE"

# The simulator's own payload key vocabulary for these event types
# (SentinelFlow-Python-Simulator-9.2/simulator/event_generator.py
# _login_payload / _logout_payload) - the physical collector must never
# introduce a key outside this set for these two event types.
SIMULATOR_LOGIN_KEYS = {"ip", "location", "loginSuccess"}
SIMULATOR_LOGOUT_KEYS = {"ip", "sessionDurationMinutes"}

ISO_UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _session(kind: str, started: float, observed: float, host=None, terminal=None, username="praka") -> SessionEvent:
    return SessionEvent(
        kind=kind,
        username=username,
        started_epoch=started,
        observed_epoch=observed,
        host=host,
        terminal=terminal,
    )


# ---------------------------------------------------------------------------
# A. physical login event -> canonical event
# ---------------------------------------------------------------------------

def test_login_event_has_canonical_envelope():
    session = _session("LOGIN", started=1_800_000_000.0, observed=1_800_000_000.0)
    event = build_login_event(session, ENTITY_ID)

    assert set(event.keys()) == {
        "eventId", "entityId", "eventType", "eventVersion",
        "occurredAt", "source", "payload",
    }
    assert event["entityId"] == ENTITY_ID
    assert event["eventType"] == "LOGIN"
    assert event["payload"]["loginSuccess"] is True


def test_build_event_dispatches_login():
    # Each call generates a fresh, unique eventId by design (see test D
    # below) - compare everything else and check the id's own shape
    # separately, rather than expecting two independent calls' eventIds
    # to match.
    session = _session("LOGIN", started=1_800_000_000.0, observed=1_800_000_000.0)
    dispatched = build_event(session, ENTITY_ID)
    direct = build_login_event(session, ENTITY_ID)

    assert dispatched["eventId"].startswith("EV-PHYS-")
    assert direct["eventId"].startswith("EV-PHYS-")
    dispatched.pop("eventId")
    direct.pop("eventId")
    assert dispatched == direct


# ---------------------------------------------------------------------------
# B. physical logout event -> canonical event
# ---------------------------------------------------------------------------

def test_logout_event_has_canonical_envelope():
    session = _session("LOGOUT", started=1_800_000_000.0, observed=1_800_000_600.0)
    event = build_logout_event(session, ENTITY_ID)

    assert event["eventType"] == "LOGOUT"
    assert event["entityId"] == ENTITY_ID
    assert "sessionDurationMinutes" in event["payload"]


def test_logout_session_duration_is_a_real_measurement():
    # 600 seconds = 10 minutes, computed from real started/observed epochs.
    session = _session("LOGOUT", started=1_800_000_000.0, observed=1_800_000_600.0)
    event = build_logout_event(session, ENTITY_ID)
    assert event["payload"]["sessionDurationMinutes"] == pytest.approx(10.0)


def test_logout_duration_never_negative():
    # Defensive: observed before started should never happen, but must
    # never produce a negative "duration" if clocks are ever inconsistent.
    session = _session("LOGOUT", started=1_800_000_100.0, observed=1_800_000_000.0)
    event = build_logout_event(session, ENTITY_ID)
    assert event["payload"]["sessionDurationMinutes"] >= 0.0


def test_build_event_dispatches_logout():
    # Same reasoning as test_build_event_dispatches_login above.
    session = _session("LOGOUT", started=1_800_000_000.0, observed=1_800_000_600.0)
    dispatched = build_event(session, ENTITY_ID)
    direct = build_logout_event(session, ENTITY_ID)

    assert dispatched["eventId"].startswith("EV-PHYS-")
    assert direct["eventId"].startswith("EV-PHYS-")
    dispatched.pop("eventId")
    direct.pop("eventId")
    assert dispatched == direct


def test_build_event_rejects_unknown_kind():
    session = _session("RENEWAL", started=1.0, observed=2.0)
    with pytest.raises(ValueError):
        build_event(session, ENTITY_ID)


# ---------------------------------------------------------------------------
# D. eventId uniqueness
# ---------------------------------------------------------------------------

def test_event_id_unique_across_many_calls():
    ids = {new_event_id() for _ in range(500)}
    assert len(ids) == 500


def test_event_id_unique_across_login_and_logout_builds():
    login_session = _session("LOGIN", started=1_800_000_000.0, observed=1_800_000_000.0)
    logout_session = _session("LOGOUT", started=1_800_000_000.0, observed=1_800_000_600.0)

    ids = {build_event(login_session, ENTITY_ID)["eventId"] for _ in range(50)}
    ids |= {build_event(logout_session, ENTITY_ID)["eventId"] for _ in range(50)}
    assert len(ids) == 100


def test_event_ids_do_not_collide_across_separate_batches():
    # Unlike the pre-fix simulator bug (counter reset to 1 on every
    # process start), new_event_id() has no counter to reset in the first
    # place - two independently generated batches must never collide.
    first_batch = {new_event_id() for _ in range(200)}
    second_batch = {new_event_id() for _ in range(200)}
    assert first_batch.isdisjoint(second_batch)


# ---------------------------------------------------------------------------
# E. timestamp format
# ---------------------------------------------------------------------------

def test_iso_utc_format_matches_simulator_convention():
    formatted = iso_utc(1_800_000_000.0)
    assert ISO_UTC_PATTERN.match(formatted), formatted


def test_login_occurred_at_uses_real_session_start_time():
    session = _session("LOGIN", started=1_800_000_000.0, observed=1_800_000_555.0)
    event = build_login_event(session, ENTITY_ID)
    assert event["occurredAt"] == iso_utc(1_800_000_000.0)


def test_logout_occurred_at_uses_observed_time():
    session = _session("LOGOUT", started=1_800_000_000.0, observed=1_800_000_600.0)
    event = build_logout_event(session, ENTITY_ID)
    assert event["occurredAt"] == iso_utc(1_800_000_600.0)


# ---------------------------------------------------------------------------
# F. source = physical-collector
# ---------------------------------------------------------------------------

def test_login_source_is_physical_collector():
    session = _session("LOGIN", started=1.0, observed=1.0)
    assert build_login_event(session, ENTITY_ID)["source"] == "physical-collector"


def test_logout_source_is_physical_collector():
    session = _session("LOGOUT", started=1.0, observed=2.0)
    assert build_logout_event(session, ENTITY_ID)["source"] == "physical-collector"


# ---------------------------------------------------------------------------
# G. eventVersion = v1
# ---------------------------------------------------------------------------

def test_login_event_version_is_v1():
    session = _session("LOGIN", started=1.0, observed=1.0)
    assert build_login_event(session, ENTITY_ID)["eventVersion"] == "v1"


def test_logout_event_version_is_v1():
    session = _session("LOGOUT", started=1.0, observed=2.0)
    assert build_logout_event(session, ENTITY_ID)["eventVersion"] == "v1"


# ---------------------------------------------------------------------------
# H. missing optional telemetry fields (never fabricated)
# ---------------------------------------------------------------------------

def test_login_omits_ip_when_host_not_available():
    session = _session("LOGIN", started=1.0, observed=1.0, host=None)
    event = build_login_event(session, ENTITY_ID)
    assert "ip" not in event["payload"]


def test_login_includes_ip_only_when_genuinely_available():
    session = _session("LOGIN", started=1.0, observed=1.0, host="10.0.0.5")
    event = build_login_event(session, ENTITY_ID)
    assert event["payload"]["ip"] == "10.0.0.5"


def test_login_never_includes_location():
    # No geo-IP lookup performed in this phase - location must never
    # appear, not even as null/"unknown".
    session = _session("LOGIN", started=1.0, observed=1.0, host="10.0.0.5")
    event = build_login_event(session, ENTITY_ID)
    assert "location" not in event["payload"]


# ---------------------------------------------------------------------------
# Event Correlation Foundation (Option A): LOGIN.username
# ---------------------------------------------------------------------------

def test_login_includes_username_when_present():
    session = _session("LOGIN", started=1.0, observed=1.0, username="alice")
    event = build_login_event(session, ENTITY_ID)
    assert event["payload"]["username"] == "alice"


def test_login_omits_username_when_blank():
    # SessionEvent.username is populated from psutil.users() and is not
    # expected to ever be blank in practice, but the same omission
    # convention as every other optional field (ip/location/etc.) must
    # still hold rather than sending an empty string.
    session = _session("LOGIN", started=1.0, observed=1.0, username="")
    event = build_login_event(session, ENTITY_ID)
    assert "username" not in event["payload"]


def test_login_username_does_not_disturb_existing_fields():
    session = _session("LOGIN", started=1.0, observed=1.0, host="10.0.0.5", username="alice")
    event = build_login_event(session, ENTITY_ID)
    assert event["payload"] == {"loginSuccess": True, "ip": "10.0.0.5", "username": "alice"}


def test_two_logins_with_different_usernames_are_independently_correct():
    session_a = _session("LOGIN", started=1.0, observed=1.0, username="alice")
    session_b = _session("LOGIN", started=1.0, observed=1.0, username="bob")

    event_a = build_login_event(session_a, ENTITY_ID)
    event_b = build_login_event(session_b, ENTITY_ID)

    assert event_a["payload"]["username"] == "alice"
    assert event_b["payload"]["username"] == "bob"


def test_collector_restart_may_repeat_enriched_login_for_the_same_session():
    # Documents existing, unchanged P1 behavior rather than trying to
    # eliminate it: a fresh SessionPoller (modeling a collector restart)
    # re-reports the same still-active session as a new LOGIN with a new
    # eventId, now also carrying the same username both times.
    session = _session("LOGIN", started=1000.0, observed=1000.0, username="praka")

    first = build_login_event(session, ENTITY_ID)
    second = build_login_event(session, ENTITY_ID)

    assert first["eventId"] != second["eventId"]
    assert first["occurredAt"] == second["occurredAt"]
    assert first["payload"]["username"] == second["payload"]["username"] == "praka"


def test_logout_omits_ip_when_host_not_available():
    session = _session("LOGOUT", started=1.0, observed=2.0, host=None)
    event = build_logout_event(session, ENTITY_ID)
    assert "ip" not in event["payload"]


def test_no_field_is_ever_set_to_a_placeholder_string():
    # Guard against a future edit accidentally introducing a fabricated
    # "unknown"/"not_provided" literal instead of omitting the key.
    session = _session("LOGIN", started=1.0, observed=1.0, host=None)
    event = build_login_event(session, ENTITY_ID)
    forbidden = {"unknown", "not_provided", "n/a", "none", "null"}
    for value in event["payload"].values():
        if isinstance(value, str):
            assert value.lower() not in forbidden


# ---------------------------------------------------------------------------
# I. JSON serialization
# ---------------------------------------------------------------------------

def test_login_event_is_json_serializable_and_round_trips():
    session = _session("LOGIN", started=1_800_000_000.0, observed=1_800_000_000.0, host="10.0.0.5")
    event = build_login_event(session, ENTITY_ID)

    encoded = json.dumps(event)
    decoded = json.loads(encoded)

    assert decoded == event


def test_logout_event_is_json_serializable_and_round_trips():
    session = _session("LOGOUT", started=1_800_000_000.0, observed=1_800_000_600.0)
    event = build_logout_event(session, ENTITY_ID)

    encoded = json.dumps(event)
    decoded = json.loads(encoded)

    assert decoded == event


# ---------------------------------------------------------------------------
# J. simulator-compatible payload field names
# ---------------------------------------------------------------------------

def test_login_payload_keys_are_subset_of_simulator_vocabulary_plus_approved_additions():
    # `username` is a deliberate, approved physical-only addition (Event
    # Correlation Foundation) that the simulator's own _login_payload
    # does not send - SIMULATOR_LOGIN_KEYS itself is left unchanged so it
    # still accurately reflects what the simulator emits.
    session = _session("LOGIN", started=1.0, observed=1.0, host="10.0.0.5")
    event = build_login_event(session, ENTITY_ID)
    assert set(event["payload"].keys()) <= SIMULATOR_LOGIN_KEYS | {"username"}


def test_logout_payload_keys_are_subset_of_simulator_vocabulary():
    session = _session("LOGOUT", started=1.0, observed=61.0, host="10.0.0.5")
    event = build_logout_event(session, ENTITY_ID)
    assert set(event["payload"].keys()) <= SIMULATOR_LOGOUT_KEYS


def test_login_success_type_matches_simulator_convention():
    # Simulator's own _login_payload sends loginSuccess as a real bool,
    # not a string/int - keep the same type.
    session = _session("LOGIN", started=1.0, observed=1.0)
    event = build_login_event(session, ENTITY_ID)
    assert isinstance(event["payload"]["loginSuccess"], bool)


# ---------------------------------------------------------------------------
# Physical Telemetry P2: PROCESS_START canonical event
# Covers approved test items 6 (missing executablePath omitted), 7
# (cmdline/secrets never emitted), plus the same envelope/format/id
# guarantees LOGIN/LOGOUT already have (E, F, G, I).
# ---------------------------------------------------------------------------

_FORBIDDEN_PAYLOAD_KEYS = {
    "cmdline", "commandLine", "command_line", "args", "environ",
    "environment", "password", "token", "secret", "apiKey", "api_key",
}


def _process(pid=1234, name="notepad.exe", ppid=1000, create_time=1_800_000_000.0,
             username="LAPTOP\\praka", executable_path="C:\\Windows\\notepad.exe"):
    return ProcessEvent(
        pid=pid, name=name, ppid=ppid, create_time=create_time,
        username=username, executable_path=executable_path,
    )


def test_process_start_event_has_canonical_envelope():
    event = build_process_start_event(_process(), ENTITY_ID)

    assert set(event.keys()) == {
        "eventId", "entityId", "eventType", "eventVersion",
        "occurredAt", "source", "payload",
    }
    assert event["entityId"] == ENTITY_ID
    assert event["eventType"] == "PROCESS_START"
    assert event["eventVersion"] == "v1"
    assert event["source"] == "physical-collector"


def test_process_start_occurred_at_uses_real_process_create_time():
    process = _process(create_time=1_800_000_000.0)
    event = build_process_start_event(process, ENTITY_ID)
    assert event["occurredAt"] == iso_utc(1_800_000_000.0)


def test_process_start_payload_includes_all_available_fields():
    event = build_process_start_event(_process(), ENTITY_ID)
    payload = event["payload"]

    assert payload["pid"] == 1234
    assert payload["processName"] == "notepad.exe"
    assert payload["parentPid"] == 1000
    assert payload["username"] == "LAPTOP\\praka"
    assert payload["executablePath"] == "C:\\Windows\\notepad.exe"


def test_process_start_missing_executable_path_is_omitted_not_fabricated():
    process = _process(executable_path=None)
    event = build_process_start_event(process, ENTITY_ID)
    assert "executablePath" not in event["payload"]


def test_process_start_missing_username_is_omitted_not_fabricated():
    process = _process(username=None)
    event = build_process_start_event(process, ENTITY_ID)
    assert "username" not in event["payload"]


def test_process_start_missing_name_is_omitted_not_fabricated():
    process = _process(name=None)
    event = build_process_start_event(process, ENTITY_ID)
    assert "processName" not in event["payload"]


def test_process_start_ppid_zero_is_still_included():
    # ppid=0 is a legitimate value (root-level process) - must not be
    # dropped by a falsy check the way an empty string/None is.
    process = _process(ppid=0)
    event = build_process_start_event(process, ENTITY_ID)
    assert event["payload"]["parentPid"] == 0


def test_process_start_never_emits_cmdline_or_other_sensitive_keys():
    event = build_process_start_event(_process(), ENTITY_ID)
    assert set(event["payload"].keys()).isdisjoint(_FORBIDDEN_PAYLOAD_KEYS)


def test_process_start_event_id_is_unique_and_prefixed():
    ids = {build_process_start_event(_process(pid=n), ENTITY_ID)["eventId"] for n in range(50)}
    assert len(ids) == 50
    assert all(i.startswith("EV-PHYS-") for i in ids)


def test_process_start_event_is_json_serializable_and_round_trips():
    event = build_process_start_event(_process(), ENTITY_ID)
    assert json.loads(json.dumps(event)) == event


def test_process_start_pid_is_always_present_even_with_no_other_fields():
    process = _process(name=None, ppid=None, username=None, executable_path=None)
    event = build_process_start_event(process, ENTITY_ID)
    assert event["payload"] == {"pid": 1234}


# ---------------------------------------------------------------------------
# Physical Telemetry P3: NETWORK_CONNECTION canonical event
# ---------------------------------------------------------------------------

def _network_connection(protocol="TCP", local_address="192.168.1.2", local_port=50000,
                         remote_address="93.184.216.34", remote_port=443,
                         status="ESTABLISHED", pid=1234, process_name="chrome.exe",
                         process_create_time=1_800_000_000.0):
    return NetworkConnectionEvent(
        protocol=protocol, local_address=local_address, local_port=local_port,
        remote_address=remote_address, remote_port=remote_port, status=status,
        pid=pid, process_name=process_name, process_create_time=process_create_time,
    )


def test_network_connection_event_has_canonical_envelope():
    event = build_network_connection_event(_network_connection(), ENTITY_ID)

    assert set(event.keys()) == {
        "eventId", "entityId", "eventType", "eventVersion",
        "occurredAt", "source", "payload",
    }
    assert event["entityId"] == ENTITY_ID
    assert event["eventType"] == "NETWORK_CONNECTION"
    assert event["eventVersion"] == "v1"
    assert event["source"] == "physical-collector"


def test_network_connection_payload_includes_all_available_fields():
    event = build_network_connection_event(_network_connection(), ENTITY_ID)
    payload = event["payload"]

    assert payload["protocol"] == "TCP"
    assert payload["localAddress"] == "192.168.1.2"
    assert payload["localPort"] == 50000
    assert payload["remoteAddress"] == "93.184.216.34"
    assert payload["remotePort"] == 443
    assert payload["status"] == "ESTABLISHED"
    assert payload["pid"] == 1234
    assert payload["processName"] == "chrome.exe"
    assert payload["processCreateTime"] == iso_utc(1_800_000_000.0)


def test_network_connection_missing_process_name_is_omitted_not_fabricated():
    connection = _network_connection(process_name=None)
    event = build_network_connection_event(connection, ENTITY_ID)
    assert "processName" not in event["payload"]


def test_network_connection_missing_pid_is_omitted_not_fabricated():
    connection = _network_connection(pid=None, process_name=None, process_create_time=None)
    event = build_network_connection_event(connection, ENTITY_ID)
    assert "pid" not in event["payload"]
    assert "processName" not in event["payload"]
    assert "processCreateTime" not in event["payload"]


# ---------------------------------------------------------------------------
# Event Correlation Foundation (Option A): NETWORK_CONNECTION.processCreateTime
# ---------------------------------------------------------------------------

def test_network_connection_process_create_time_omitted_when_unavailable():
    connection = _network_connection(process_create_time=None)
    event = build_network_connection_event(connection, ENTITY_ID)
    assert "processCreateTime" not in event["payload"]


def test_network_connection_process_create_time_formatted_as_iso_utc():
    connection = _network_connection(process_create_time=1_800_000_500.0)
    event = build_network_connection_event(connection, ENTITY_ID)
    assert event["payload"]["processCreateTime"] == iso_utc(1_800_000_500.0)
    assert ISO_UTC_PATTERN.match(event["payload"]["processCreateTime"])


def test_pid_reuse_process_start_and_network_connection_create_times_differ():
    # The core Event Correlation Foundation scenario: PROCESS_START
    # (pid=A, create_time=X) and a LATER, UNRELATED process that reused
    # the same pid=A owning a NETWORK_CONNECTION (processCreateTime=Y).
    # X != Y must be visible to a consumer so these are never treated as
    # the same process merely because they share a pid - this phase only
    # exposes the fact, it draws no conclusion from it (see report).
    pid = 5555
    process_start = _process(pid=pid, create_time=1_800_000_000.0)
    stale_network_connection = _network_connection(pid=pid, process_create_time=1_800_005_000.0)

    process_event = build_process_start_event(process_start, ENTITY_ID)
    network_event = build_network_connection_event(stale_network_connection, ENTITY_ID)

    process_create_time_from_start = process_event["occurredAt"]
    process_create_time_from_network = network_event["payload"]["processCreateTime"]

    assert process_event["payload"]["pid"] == network_event["payload"]["pid"] == pid
    assert process_create_time_from_start != process_create_time_from_network


def test_network_connection_occurred_at_is_valid_iso_utc_format():
    event = build_network_connection_event(_network_connection(), ENTITY_ID)
    assert ISO_UTC_PATTERN.match(event["occurredAt"])


def test_network_connection_event_is_json_serializable_and_round_trips():
    event = build_network_connection_event(_network_connection(), ENTITY_ID)
    assert json.loads(json.dumps(event)) == event


def test_network_connection_event_id_is_unique_and_prefixed():
    ids = {
        build_network_connection_event(_network_connection(local_port=50000 + n), ENTITY_ID)["eventId"]
        for n in range(50)
    }
    assert len(ids) == 50
    assert all(i.startswith("EV-PHYS-") for i in ids)


def test_network_connection_never_emits_sensitive_or_packet_level_keys():
    event = build_network_connection_event(_network_connection(), ENTITY_ID)
    forbidden = {
        "cmdline", "packet", "payload_bytes", "dns", "http_body",
        "tls_key", "password", "token", "secret", "cookie",
    }
    assert set(event["payload"].keys()).isdisjoint(forbidden)

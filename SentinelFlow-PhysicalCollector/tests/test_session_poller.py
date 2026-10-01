"""
Verifies the login/logout diffing logic against a mocked psutil.users(),
independent of whatever real sessions happen to be active on the machine
running the test suite.
"""
from collections import namedtuple

import session_poller

_FakeUser = namedtuple("_FakeUser", ["name", "terminal", "host", "started", "pid"])


def _patch_users(monkeypatch, users):
    monkeypatch.setattr(session_poller.psutil, "users", lambda: users)


def test_first_poll_reports_every_active_session_as_login(monkeypatch):
    _patch_users(monkeypatch, [
        _FakeUser(name="praka", terminal=None, host=None, started=1000.0, pid=None),
    ])

    poller = session_poller.SessionPoller()
    events = poller.poll_once()

    assert len(events) == 1
    assert events[0].kind == "LOGIN"
    assert events[0].username == "praka"
    assert events[0].started_epoch == 1000.0


def test_second_poll_with_no_change_reports_nothing(monkeypatch):
    _patch_users(monkeypatch, [
        _FakeUser(name="praka", terminal=None, host=None, started=1000.0, pid=None),
    ])
    poller = session_poller.SessionPoller()
    poller.poll_once()

    events = poller.poll_once()
    assert events == []


def test_new_session_appearing_is_reported_as_login(monkeypatch):
    _patch_users(monkeypatch, [
        _FakeUser(name="praka", terminal=None, host=None, started=1000.0, pid=None),
    ])
    poller = session_poller.SessionPoller()
    poller.poll_once()

    _patch_users(monkeypatch, [
        _FakeUser(name="praka", terminal=None, host=None, started=1000.0, pid=None),
        _FakeUser(name="alice", terminal=None, host="10.0.0.9", started=2000.0, pid=None),
    ])
    events = poller.poll_once()

    assert len(events) == 1
    assert events[0].kind == "LOGIN"
    assert events[0].username == "alice"
    assert events[0].host == "10.0.0.9"


def test_session_disappearing_is_reported_as_logout(monkeypatch):
    _patch_users(monkeypatch, [
        _FakeUser(name="praka", terminal=None, host=None, started=1000.0, pid=None),
    ])
    poller = session_poller.SessionPoller()
    poller.poll_once()

    _patch_users(monkeypatch, [])
    events = poller.poll_once()

    assert len(events) == 1
    assert events[0].kind == "LOGOUT"
    assert events[0].username == "praka"
    assert events[0].started_epoch == 1000.0


def test_same_user_relogging_in_is_a_distinct_session(monkeypatch):
    # Same username, different started timestamp = a genuinely different
    # login instant, not a duplicate of the earlier session.
    _patch_users(monkeypatch, [
        _FakeUser(name="praka", terminal=None, host=None, started=1000.0, pid=None),
    ])
    poller = session_poller.SessionPoller()
    poller.poll_once()

    _patch_users(monkeypatch, [])
    poller.poll_once()  # logout

    _patch_users(monkeypatch, [
        _FakeUser(name="praka", terminal=None, host=None, started=5000.0, pid=None),
    ])
    events = poller.poll_once()

    assert len(events) == 1
    assert events[0].kind == "LOGIN"
    assert events[0].started_epoch == 5000.0


def test_two_different_usernames_on_the_same_host_remain_distinct(monkeypatch):
    # Event Correlation Foundation: username is what a consumer would
    # match LOGIN against PROCESS_START on - two concurrent sessions by
    # different users must never be conflated into one.
    _patch_users(monkeypatch, [
        _FakeUser(name="alice", terminal=None, host=None, started=1000.0, pid=None),
        _FakeUser(name="bob", terminal=None, host=None, started=1000.0, pid=None),
    ])

    poller = session_poller.SessionPoller()
    events = poller.poll_once()

    usernames = {e.username for e in events}
    assert usernames == {"alice", "bob"}
    assert len(events) == 2


def test_empty_terminal_and_host_are_normalized_to_none(monkeypatch):
    _patch_users(monkeypatch, [
        _FakeUser(name="praka", terminal="", host="", started=1000.0, pid=None),
    ])
    poller = session_poller.SessionPoller()
    events = poller.poll_once()

    assert events[0].terminal is None
    assert events[0].host is None

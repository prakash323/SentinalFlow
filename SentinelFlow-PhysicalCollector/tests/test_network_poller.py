"""
Verifies the ESTABLISHED-only, non-loopback, new-connection diffing
logic against a mocked psutil, independent of whatever real connections
exist on the machine running the test suite.

Covers approved test items: ESTABLISHED filtering, LISTEN exclusion,
TIME_WAIT exclusion, loopback exclusion, private/LAN retention, new
connection detection, persistent connection deduplication, connection
disappearance/reappearance, PID reuse (graceful name resolution),
missing processName, missing endpoint metadata, startup baseline.
"""
from collections import namedtuple
from unittest.mock import MagicMock

import network_poller

_addr = namedtuple("addr", ["ip", "port"])
_FakeConn = namedtuple("_FakeConn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])

TCP = 1
UDP = 2


def _conn(local_ip="192.168.1.2", local_port=50000, remote_ip="93.184.216.34",
          remote_port=443, status="ESTABLISHED", pid=1234, conn_type=TCP,
          has_remote=True):
    return _FakeConn(
        fd=-1, family=2, type=conn_type,
        laddr=_addr(ip=local_ip, port=local_port),
        raddr=_addr(ip=remote_ip, port=remote_port) if has_remote else (),
        status=status, pid=pid,
    )


def _patch_connections(monkeypatch, conns):
    monkeypatch.setattr(network_poller.psutil, "net_connections", lambda kind: list(conns))


def _patch_name_lookup(monkeypatch, name_by_pid: dict, create_time_by_pid: dict = None):
    """Mocks psutil.Process(pid) for the targeted per-connection lookup.
    name_by_pid controls .name(). create_time_by_pid controls
    .create_time() independently (defaults to a fixed real-looking value
    for every pid that also has a name, so existing callers that only
    pass name_by_pid keep working unchanged) - this lets a test model
    the two lookups succeeding/failing independently of each other."""
    if create_time_by_pid is None:
        create_time_by_pid = {pid: 1_700_000_000.0 + pid for pid in name_by_pid}

    process_class = MagicMock()

    def make_process(pid):
        instance = MagicMock()

        if pid in name_by_pid:
            instance.name.return_value = name_by_pid[pid]
        else:
            instance.name.side_effect = network_poller.psutil.NoSuchProcess(pid)

        if pid in create_time_by_pid:
            instance.create_time.return_value = create_time_by_pid[pid]
        else:
            instance.create_time.side_effect = network_poller.psutil.NoSuchProcess(pid)

        return instance

    process_class.side_effect = make_process
    monkeypatch.setattr(network_poller.psutil, "Process", process_class)
    return process_class


# ---------------------------------------------------------------------------
# Startup baseline
# ---------------------------------------------------------------------------

def test_first_poll_establishes_baseline_and_reports_nothing(monkeypatch):
    _patch_connections(monkeypatch, [_conn(remote_port=443), _conn(local_port=50001, remote_port=80)])
    _patch_name_lookup(monkeypatch, {})

    poller = network_poller.NetworkPoller()
    events = poller.poll_once()

    assert events == []


# ---------------------------------------------------------------------------
# ESTABLISHED filtering / LISTEN exclusion / TIME_WAIT exclusion
# ---------------------------------------------------------------------------

def test_listen_sockets_are_never_reported(monkeypatch):
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()  # empty baseline

    _patch_connections(monkeypatch, [_conn(status="LISTEN", has_remote=False, pid=999)])
    _patch_name_lookup(monkeypatch, {})
    events = poller.poll_once()

    assert events == []


def test_time_wait_connections_are_never_reported(monkeypatch):
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    # TIME_WAIT connections were confirmed during the audit to always
    # report pid=0 on this platform - modeled here for realism.
    _patch_connections(monkeypatch, [_conn(status="TIME_WAIT", pid=0)])
    _patch_name_lookup(monkeypatch, {})
    events = poller.poll_once()

    assert events == []


def test_udp_none_status_connections_are_never_reported(monkeypatch):
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    _patch_connections(monkeypatch, [_conn(status="NONE", conn_type=UDP, has_remote=False, pid=500)])
    _patch_name_lookup(monkeypatch, {})
    events = poller.poll_once()

    assert events == []


# ---------------------------------------------------------------------------
# Loopback exclusion / private-LAN retention
# ---------------------------------------------------------------------------

def test_loopback_remote_ipv4_is_excluded(monkeypatch):
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    _patch_connections(monkeypatch, [_conn(remote_ip="127.0.0.1", remote_port=5432)])
    _patch_name_lookup(monkeypatch, {})
    events = poller.poll_once()

    assert events == []


def test_loopback_remote_ipv6_is_excluded(monkeypatch):
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    _patch_connections(monkeypatch, [_conn(remote_ip="::1", remote_port=9094)])
    _patch_name_lookup(monkeypatch, {})
    events = poller.poll_once()

    assert events == []


def test_private_lan_remote_address_is_retained_not_excluded(monkeypatch):
    # Explicit design decision: keep private/LAN addresses eligible - do
    # not restrict telemetry to public Internet connections.
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    _patch_connections(monkeypatch, [_conn(remote_ip="192.168.1.50", remote_port=445, pid=42)])
    _patch_name_lookup(monkeypatch, {42: "smbclient.exe"})
    events = poller.poll_once()

    assert len(events) == 1
    assert events[0].remote_address == "192.168.1.50"


def test_connection_missing_remote_endpoint_is_excluded(monkeypatch):
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    _patch_connections(monkeypatch, [_conn(status="ESTABLISHED", has_remote=False)])
    _patch_name_lookup(monkeypatch, {})
    events = poller.poll_once()

    assert events == []


# ---------------------------------------------------------------------------
# New connection detection / persistent connection deduplication
# ---------------------------------------------------------------------------

def test_new_established_connection_after_baseline_produces_exactly_one_event(monkeypatch):
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    _patch_connections(monkeypatch, [_conn(remote_ip="93.184.216.34", remote_port=443, pid=1234)])
    _patch_name_lookup(monkeypatch, {1234: "chrome.exe"})
    events = poller.poll_once()

    assert len(events) == 1
    assert events[0].remote_address == "93.184.216.34"
    assert events[0].remote_port == 443
    assert events[0].process_name == "chrome.exe"


def test_persistent_connection_is_not_reported_again(monkeypatch):
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    conn = _conn(remote_ip="93.184.216.34", remote_port=443, pid=1234)
    _patch_connections(monkeypatch, [conn])
    _patch_name_lookup(monkeypatch, {1234: "chrome.exe"})
    first = poller.poll_once()
    assert len(first) == 1

    # Same connection still present on the next poll - must not repeat.
    second = poller.poll_once()
    assert second == []


def test_status_change_alone_does_not_produce_a_new_event(monkeypatch):
    # Identity deliberately excludes status - a tracked connection
    # transitioning e.g. ESTABLISHED -> CLOSE_WAIT is not itself a "new"
    # connection. (CLOSE_WAIT itself would be filtered pre-diff anyway,
    # so this models the boundary case of the SAME 5-tuple+pid persisting
    # while only status metadata would have differed.)
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    conn = _conn(remote_ip="93.184.216.34", remote_port=443, pid=1234, status="ESTABLISHED")
    _patch_connections(monkeypatch, [conn])
    _patch_name_lookup(monkeypatch, {1234: "chrome.exe"})
    poller.poll_once()

    # Re-poll with an identical identity - no duplicate.
    events = poller.poll_once()
    assert events == []


# ---------------------------------------------------------------------------
# Connection disappearance / reappearance
# ---------------------------------------------------------------------------

def test_connection_disappearing_then_reappearing_is_reported_again(monkeypatch):
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    conn = _conn(remote_ip="93.184.216.34", remote_port=443, pid=1234)
    _patch_connections(monkeypatch, [conn])
    _patch_name_lookup(monkeypatch, {1234: "chrome.exe"})
    first = poller.poll_once()
    assert len(first) == 1

    _patch_connections(monkeypatch, [])
    poller.poll_once()  # connection closes

    _patch_connections(monkeypatch, [conn])
    second = poller.poll_once()

    assert len(second) == 1


# ---------------------------------------------------------------------------
# PID reuse / missing processName (graceful failure)
# ---------------------------------------------------------------------------

def test_missing_process_name_is_omitted_not_fabricated(monkeypatch):
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    _patch_connections(monkeypatch, [_conn(pid=7777)])
    _patch_name_lookup(monkeypatch, {})  # 7777 not resolvable -> NoSuchProcess
    events = poller.poll_once()

    assert len(events) == 1
    assert events[0].process_name is None


def test_zero_pid_yields_no_process_name_lookup_attempt(monkeypatch):
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    _patch_connections(monkeypatch, [_conn(pid=0)])
    process_class = _patch_name_lookup(monkeypatch, {})
    events = poller.poll_once()

    assert len(events) == 1
    assert events[0].pid is None
    assert events[0].process_name is None
    process_class.assert_not_called()


# ---------------------------------------------------------------------------
# Event Correlation Foundation (Option A): processCreateTime
# ---------------------------------------------------------------------------

def test_process_create_time_included_when_pid_resolves_successfully(monkeypatch):
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    _patch_connections(monkeypatch, [_conn(pid=1234)])
    _patch_name_lookup(monkeypatch, {1234: "chrome.exe"}, {1234: 1_800_000_000.0})
    events = poller.poll_once()

    assert len(events) == 1
    assert events[0].process_create_time == 1_800_000_000.0


def test_process_create_time_omitted_when_pid_unavailable(monkeypatch):
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    _patch_connections(monkeypatch, [_conn(pid=0)])
    _patch_name_lookup(monkeypatch, {})
    events = poller.poll_once()

    assert len(events) == 1
    assert events[0].process_create_time is None


def test_process_create_time_omitted_when_process_lookup_fails(monkeypatch):
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    _patch_connections(monkeypatch, [_conn(pid=8888)])
    _patch_name_lookup(monkeypatch, {})  # 8888 not resolvable at all -> NoSuchProcess
    events = poller.poll_once()

    assert len(events) == 1
    assert events[0].process_name is None
    assert events[0].process_create_time is None


def test_process_create_time_omitted_independently_when_only_that_lookup_fails(monkeypatch):
    # Models a process object that resolves .name() successfully but
    # whose .create_time() call fails (e.g. the process exits between
    # the two reads) - each field must be independently omittable.
    _patch_connections(monkeypatch, [])
    poller = network_poller.NetworkPoller()
    poller.poll_once()

    _patch_connections(monkeypatch, [_conn(pid=4242)])
    _patch_name_lookup(monkeypatch, {4242: "flaky.exe"}, create_time_by_pid={})
    events = poller.poll_once()

    assert len(events) == 1
    assert events[0].process_name == "flaky.exe"
    assert events[0].process_create_time is None

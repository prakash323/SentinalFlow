"""
Verifies the new-process diffing logic against a mocked psutil, and the
targeted executablePath lookup, independent of whatever processes
happen to be running on the machine executing the test suite.

Covers approved test items 1-5:
  1. Initial startup produces no historical process flood.
  2. New process produces exactly one PROCESS_START (event, via
     poll_once returning exactly one ProcessEvent).
  3. Repeated polling does not duplicate it.
  4. Process exit + new process with same PID but different create_time
     is treated as a new process (PID reuse).
  5. Targeted executable lookup is used only for newly detected
     processes.
"""
from collections import namedtuple
from unittest.mock import MagicMock

import process_poller

_FakeProcInfo = namedtuple("_FakeProcInfo", ["pid", "name", "ppid", "create_time", "username"])


class _FakeIterProcess:
    """Stand-in for the psutil.Process objects process_iter() yields -
    only .info is used by _snapshot()."""
    def __init__(self, info: dict):
        self.info = info


def _patch_process_iter(monkeypatch, infos):
    fakes = [_FakeIterProcess(info._asdict()) for info in infos]
    monkeypatch.setattr(process_poller.psutil, "process_iter", lambda fields: iter(fakes))


def _patch_exe_lookup(monkeypatch, exe_by_pid: dict):
    """Mocks psutil.Process(pid).exe() for the targeted lookup, and
    returns the mock so tests can assert call counts/args."""
    process_class = MagicMock()

    def make_process(pid):
        instance = MagicMock()
        if pid in exe_by_pid:
            instance.exe.return_value = exe_by_pid[pid]
        else:
            instance.exe.side_effect = process_poller.psutil.NoSuchProcess(pid)
        return instance

    process_class.side_effect = make_process
    monkeypatch.setattr(process_poller.psutil, "Process", process_class)
    return process_class


def _info(pid, name="proc.exe", ppid=1, create_time=1000.0, username="host\\user"):
    return _FakeProcInfo(pid=pid, name=name, ppid=ppid, create_time=create_time, username=username)


# ---------------------------------------------------------------------------
# 1. Initial startup produces no historical process flood
# ---------------------------------------------------------------------------

def test_first_poll_establishes_baseline_and_reports_nothing(monkeypatch):
    _patch_process_iter(monkeypatch, [_info(100), _info(200), _info(300)])
    _patch_exe_lookup(monkeypatch, {})

    poller = process_poller.ProcessPoller()
    events = poller.poll_once()

    assert events == []


def test_first_poll_never_performs_targeted_exe_lookups(monkeypatch):
    _patch_process_iter(monkeypatch, [_info(100), _info(200)])
    process_class = _patch_exe_lookup(monkeypatch, {100: "C:\\a.exe", 200: "C:\\b.exe"})

    poller = process_poller.ProcessPoller()
    poller.poll_once()

    process_class.assert_not_called()


# ---------------------------------------------------------------------------
# 2. New process produces exactly one PROCESS_START (event)
# ---------------------------------------------------------------------------

def test_new_process_after_baseline_produces_exactly_one_event(monkeypatch):
    _patch_process_iter(monkeypatch, [_info(100)])
    _patch_exe_lookup(monkeypatch, {})
    poller = process_poller.ProcessPoller()
    poller.poll_once()  # baseline

    _patch_process_iter(monkeypatch, [_info(100), _info(200, name="new.exe")])
    _patch_exe_lookup(monkeypatch, {200: "C:\\Windows\\new.exe"})

    events = poller.poll_once()

    assert len(events) == 1
    assert events[0].pid == 200
    assert events[0].name == "new.exe"
    assert events[0].executable_path == "C:\\Windows\\new.exe"


# ---------------------------------------------------------------------------
# 3. Repeated polling does not duplicate it
# ---------------------------------------------------------------------------

def test_repeated_poll_with_no_change_reports_nothing(monkeypatch):
    _patch_process_iter(monkeypatch, [_info(100)])
    _patch_exe_lookup(monkeypatch, {})
    poller = process_poller.ProcessPoller()
    poller.poll_once()  # baseline

    _patch_process_iter(monkeypatch, [_info(100), _info(200)])
    _patch_exe_lookup(monkeypatch, {200: "C:\\new.exe"})
    first = poller.poll_once()
    assert len(first) == 1

    # Same snapshot again - the new process from the previous poll must
    # not be reported a second time.
    second = poller.poll_once()
    assert second == []


# ---------------------------------------------------------------------------
# 4. PID reuse: same pid, different create_time -> treated as new
# ---------------------------------------------------------------------------

def test_pid_reuse_with_different_create_time_is_a_new_process(monkeypatch):
    _patch_process_iter(monkeypatch, [_info(100, create_time=1000.0)])
    _patch_exe_lookup(monkeypatch, {})
    poller = process_poller.ProcessPoller()
    poller.poll_once()  # baseline: pid 100 @ t=1000.0 known

    # pid 100 exits, then a DIFFERENT process is later assigned the same
    # pid by the OS - it has a different create_time.
    _patch_process_iter(monkeypatch, [])
    poller.poll_once()  # pid 100 disappears (no LOGOUT-style event for processes - fine, out of scope)

    _patch_process_iter(monkeypatch, [_info(100, create_time=5000.0, name="reused.exe")])
    _patch_exe_lookup(monkeypatch, {100: "C:\\reused.exe"})
    events = poller.poll_once()

    assert len(events) == 1
    assert events[0].pid == 100
    assert events[0].create_time == 5000.0
    assert events[0].name == "reused.exe"


def test_same_pid_same_create_time_is_never_reported_twice(monkeypatch):
    _patch_process_iter(monkeypatch, [_info(100, create_time=1000.0)])
    _patch_exe_lookup(monkeypatch, {})
    poller = process_poller.ProcessPoller()
    poller.poll_once()

    _patch_process_iter(monkeypatch, [_info(100, create_time=1000.0), _info(200, create_time=1000.0)])
    _patch_exe_lookup(monkeypatch, {200: "C:\\x.exe"})
    poller.poll_once()

    # Same (pid, create_time) pairs again - no new events.
    events = poller.poll_once()
    assert events == []


# ---------------------------------------------------------------------------
# 5. Targeted executable lookup is used only for newly detected processes
# ---------------------------------------------------------------------------

def test_exe_lookup_called_only_for_new_pids_not_the_whole_table(monkeypatch):
    _patch_process_iter(monkeypatch, [_info(100), _info(200), _info(300)])
    _patch_exe_lookup(monkeypatch, {})
    poller = process_poller.ProcessPoller()
    poller.poll_once()  # baseline: 100, 200, 300 known, no lookups

    _patch_process_iter(monkeypatch, [_info(100), _info(200), _info(300), _info(400)])
    process_class = _patch_exe_lookup(monkeypatch, {400: "C:\\only-new.exe"})

    events = poller.poll_once()

    assert len(events) == 1
    process_class.assert_called_once_with(400)


# ---------------------------------------------------------------------------
# 6. Missing executablePath omitted, not fabricated (poller-level)
# ---------------------------------------------------------------------------

def test_exe_lookup_failure_yields_none_not_a_placeholder(monkeypatch):
    _patch_process_iter(monkeypatch, [])
    poller = process_poller.ProcessPoller()
    poller.poll_once()  # empty baseline

    _patch_process_iter(monkeypatch, [_info(500)])
    _patch_exe_lookup(monkeypatch, {})  # 500 not in the map -> NoSuchProcess raised

    events = poller.poll_once()

    assert len(events) == 1
    assert events[0].executable_path is None

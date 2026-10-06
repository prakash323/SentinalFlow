"""
Process-metadata cache tests (PHASE S item 15, PHASE Q bounding).

This cache is what lets a NETWORK_CONNECTION event carry
processName/processCreateTime for a process that has already exited -
the case the backend's NEW_PROCESS_EXTERNAL_CONNECTION rule cares about
most and the case psutil cannot answer live.
"""
import pytest

from correlation import ProcessMetadataCache
from fakes import VirtualClock


def _cache(ttl=300.0, max_entries=10, clock=None):
    return ProcessMetadataCache(ttl_seconds=ttl, max_entries=max_entries, clock=clock or VirtualClock())


def test_records_and_returns_process_metadata():
    cache = _cache()
    cache.record(pid=8420, name="powershell.exe", create_time=1_700_000_000.0)

    entry = cache.lookup(8420)
    assert entry is not None
    assert entry.pid == 8420
    assert entry.name == "powershell.exe"
    assert entry.create_time == 1_700_000_000.0


def test_unknown_pid_returns_none():
    assert _cache().lookup(999) is None


@pytest.mark.parametrize("pid", [None, 0])
def test_missing_or_zero_pid_is_never_looked_up(pid):
    cache = _cache()
    cache.record(pid=0, name="x", create_time=1.0)
    assert cache.lookup(pid) is None


def test_entry_expires_after_the_ttl():
    clock = VirtualClock()
    cache = _cache(ttl=300.0, clock=clock)
    cache.record(pid=1, name="a.exe", create_time=10.0)

    clock.advance(299)
    assert cache.lookup(1) is not None

    clock.advance(2)
    assert cache.lookup(1) is None, "past the TTL - too old to risk a PID-reuse mislabel"


def test_re_recording_the_same_pid_replaces_the_metadata():
    # This is how PID reuse is invalidated: the new process has a
    # different create_time, and the old metadata must not survive.
    cache = _cache()
    cache.record(pid=8420, name="old.exe", create_time=100.0)
    cache.record(pid=8420, name="new.exe", create_time=200.0)

    entry = cache.lookup(8420)
    assert entry.name == "new.exe"
    assert entry.create_time == 200.0


def test_invalidate_forgets_a_pid():
    cache = _cache()
    cache.record(pid=5, name="a.exe", create_time=1.0)
    cache.invalidate(5)
    assert cache.lookup(5) is None


def test_cache_never_exceeds_max_entries():
    cache = _cache(ttl=10_000.0, max_entries=25)

    for pid in range(5000):
        cache.record(pid=pid, name=f"p{pid}.exe", create_time=float(pid))

    assert len(cache) == 25
    assert cache.stats["evictions"] == 4975


def test_eviction_drops_the_oldest_observation_first():
    cache = _cache(ttl=10_000.0, max_entries=2)
    cache.record(pid=1, name="a", create_time=1.0)
    cache.record(pid=2, name="b", create_time=2.0)
    cache.record(pid=3, name="c", create_time=3.0)

    assert cache.lookup(1) is None
    assert cache.lookup(2) is not None
    assert cache.lookup(3) is not None


def test_expired_entries_are_swept_on_access():
    clock = VirtualClock()
    cache = _cache(ttl=10.0, max_entries=1000, clock=clock)

    for pid in range(100):
        cache.record(pid=pid, name="p.exe", create_time=1.0)
    assert len(cache) == 100

    clock.advance(11)
    cache.record(pid=9999, name="fresh.exe", create_time=1.0)
    assert len(cache) == 1


def test_record_ignores_incomplete_observations():
    cache = _cache()
    cache.record(pid=None, name="x", create_time=1.0)
    cache.record(pid=1, name="x", create_time=None)
    assert len(cache) == 0


@pytest.mark.parametrize("ttl,max_entries", [(0, 10), (10, 0)])
def test_invalid_bounds_are_rejected(ttl, max_entries):
    with pytest.raises(ValueError):
        ProcessMetadataCache(ttl_seconds=ttl, max_entries=max_entries)


def test_stats_expose_bounds_and_hit_rate():
    cache = _cache(max_entries=4)
    cache.record(pid=1, name="a", create_time=1.0)
    cache.lookup(1)
    cache.lookup(2)

    stats = cache.stats
    assert stats["max_entries"] == 4
    assert stats["hits"] == 1
    assert stats["misses"] == 1

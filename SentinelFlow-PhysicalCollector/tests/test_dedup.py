"""
Bounded deduplication cache tests (PHASE S items 7/12/13/14/52).

These are the tests that prove the collector cannot leak memory through
its "have I seen this?" state over a long run - the specific failure the
dedup.py module docstring calls out ("do not create a set() that grows
forever").
"""
import pytest

from dedup import BoundedDedupCache
from fakes import VirtualClock


def _cache(ttl=100.0, max_entries=10, clock=None):
    return BoundedDedupCache(ttl_seconds=ttl, max_entries=max_entries, clock=clock or VirtualClock())


def test_first_sighting_is_not_a_duplicate_and_the_second_is():
    cache = _cache()
    assert cache.seen("a") is False
    assert cache.seen("a") is True


def test_different_keys_do_not_interfere():
    cache = _cache()
    assert cache.seen(("PROCESS_START", 1, 10.0)) is False
    assert cache.seen(("PROCESS_START", 1, 11.0)) is False  # same pid, new create_time
    assert cache.seen(("PROCESS_START", 1, 10.0)) is True


def test_an_entry_expires_after_its_ttl():
    clock = VirtualClock()
    cache = _cache(ttl=100.0, clock=clock)

    assert cache.seen("a") is False
    clock.advance(99)
    assert cache.seen("a") is True, "still inside the TTL"

    clock.advance(2)
    assert cache.seen("a") is False, "past the TTL - reportable again"


def test_a_duplicate_hit_does_not_refresh_the_ttl():
    # Otherwise a connection re-observed every poll would be suppressed
    # forever, which is a different bug from the one dedup solves.
    clock = VirtualClock()
    cache = _cache(ttl=100.0, clock=clock)
    cache.seen("a")

    for _ in range(9):
        clock.advance(10)
        cache.seen("a")

    clock.advance(11)
    assert cache.seen("a") is False


def test_expired_entries_are_removed_not_merely_ignored():
    clock = VirtualClock()
    cache = _cache(ttl=10.0, max_entries=1000, clock=clock)

    for n in range(100):
        cache.seen(f"key-{n}")
    assert len(cache) == 100

    clock.advance(11)
    cache.seen("trigger-the-sweep")
    assert len(cache) == 1, "every expired entry was physically dropped"


def test_cache_never_exceeds_max_entries():
    cache = _cache(ttl=10_000.0, max_entries=50)

    for n in range(5000):
        cache.seen(f"key-{n}")

    assert len(cache) == 50
    assert cache.stats["evictions"] == 4950


def test_eviction_drops_the_oldest_entry_first():
    cache = _cache(ttl=10_000.0, max_entries=3)

    for key in ("a", "b", "c"):
        cache.seen(key)
    cache.seen("d")  # evicts "a"

    # contains() is read-only - asserting with seen() would re-insert the
    # evicted key and evict the next one mid-assertion.
    assert cache.contains("a") is False, "oldest was evicted"
    assert cache.contains("b") is True
    assert cache.contains("c") is True
    assert cache.contains("d") is True


def test_contains_does_not_record_the_key():
    cache = _cache()
    assert cache.contains("a") is False
    assert len(cache) == 0
    assert cache.seen("a") is False, "contains() must not have recorded it"


def test_contains_reports_false_for_an_expired_entry():
    clock = VirtualClock()
    cache = _cache(ttl=10.0, clock=clock)
    cache.seen("a")
    assert cache.contains("a") is True
    clock.advance(11)
    assert cache.contains("a") is False


def test_discard_forgets_a_key_immediately():
    cache = _cache()
    cache.seen("a")
    cache.discard("a")
    assert cache.seen("a") is False


def test_clear_empties_the_cache():
    cache = _cache()
    cache.seen("a")
    cache.clear()
    assert len(cache) == 0


def test_stats_report_bounds_and_activity():
    cache = _cache(ttl=100.0, max_entries=2)
    cache.seen("a")
    cache.seen("a")
    cache.seen("b")
    cache.seen("c")  # evicts "a"

    stats = cache.stats
    assert stats["max_entries"] == 2
    assert stats["size"] == 2
    assert stats["duplicate_hits"] == 1
    assert stats["evictions"] == 1


@pytest.mark.parametrize("ttl,max_entries", [(0, 10), (-1, 10), (10, 0), (10, -1)])
def test_invalid_bounds_are_rejected_at_construction(ttl, max_entries):
    with pytest.raises(ValueError):
        BoundedDedupCache(ttl_seconds=ttl, max_entries=max_entries)


def test_is_thread_safe_under_concurrent_access():
    import threading

    cache = _cache(ttl=10_000.0, max_entries=10_000)
    errors = []

    def hammer(offset):
        try:
            for n in range(500):
                cache.seen(f"key-{offset}-{n}")
        except Exception as error:  # pragma: no cover - a failure is the signal
            errors.append(error)

    threads = [threading.Thread(target=hammer, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert not errors
    assert len(cache) == 4000, "every distinct key recorded exactly once"

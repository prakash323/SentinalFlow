"""
Bounded event queue tests (PHASE S items 24-29, 53).

The queue is the single place where the collector decides what to do
when Kafka cannot keep up, so its overflow policy (drop OLDEST, keep the
newest security observations) and its counters are tested explicitly
rather than assumed.
"""
import threading

import pytest

from event_queue import BoundedEventQueue


def _event(n):
    return {"eventId": f"EV-{n}", "eventType": "PROCESS_START"}


# --------------------------------------------------------------------------
# 24/25. enqueue + dequeue
# --------------------------------------------------------------------------

def test_enqueue_then_dequeue_is_fifo():
    queue = BoundedEventQueue(max_size=10)
    for n in range(3):
        assert queue.put(_event(n)) is None

    assert queue.get(timeout=0)["eventId"] == "EV-0"
    assert queue.get(timeout=0)["eventId"] == "EV-1"
    assert queue.get(timeout=0)["eventId"] == "EV-2"


def test_get_on_an_empty_queue_returns_none_without_blocking_forever():
    queue = BoundedEventQueue(max_size=10)
    assert queue.get(timeout=0.01) is None


def test_get_batch_takes_what_is_available_without_waiting_to_fill():
    queue = BoundedEventQueue(max_size=10)
    queue.put(_event(1))
    queue.put(_event(2))

    batch = queue.get_batch(50, timeout=0)
    assert [e["eventId"] for e in batch] == ["EV-1", "EV-2"]


def test_get_batch_respects_its_maximum():
    queue = BoundedEventQueue(max_size=10)
    for n in range(5):
        queue.put(_event(n))

    assert len(queue.get_batch(2, timeout=0)) == 2
    assert queue.depth == 3


def test_get_batch_of_zero_is_a_no_op():
    queue = BoundedEventQueue(max_size=10)
    queue.put(_event(1))
    assert queue.get_batch(0, timeout=0) == []
    assert queue.depth == 1


# --------------------------------------------------------------------------
# 26/27. bounded capacity + overflow behavior
# --------------------------------------------------------------------------

def test_depth_never_exceeds_capacity():
    queue = BoundedEventQueue(max_size=5)
    for n in range(1000):
        queue.put(_event(n))

    assert queue.depth == 5
    assert len(queue) == 5


def test_overflow_drops_the_oldest_and_keeps_the_newest():
    queue = BoundedEventQueue(max_size=3)
    for n in range(5):
        queue.put(_event(n))

    remaining = [e["eventId"] for e in queue.get_batch(10, timeout=0)]
    assert remaining == ["EV-2", "EV-3", "EV-4"]


def test_put_returns_the_dropped_event_so_the_caller_can_log_it():
    queue = BoundedEventQueue(max_size=1)
    assert queue.put(_event(1)) is None
    dropped = queue.put(_event(2))
    assert dropped is not None and dropped["eventId"] == "EV-1"


def test_put_never_blocks_when_full():
    # The whole point: a dead broker must not freeze the telemetry
    # workers. A blocking put would hang this test.
    queue = BoundedEventQueue(max_size=1)
    finished = threading.Event()

    def fill():
        for n in range(100):
            queue.put(_event(n))
        finished.set()

    thread = threading.Thread(target=fill, daemon=True)
    thread.start()
    assert finished.wait(timeout=5), "put() blocked on a full queue"
    thread.join(timeout=5)


def test_requeue_front_preserves_publication_order():
    queue = BoundedEventQueue(max_size=10)
    queue.put(_event(2))
    queue.requeue_front(_event(1))

    assert [e["eventId"] for e in queue.get_batch(10, timeout=0)] == ["EV-1", "EV-2"]


def test_requeue_front_on_a_full_queue_drops_the_newest_instead():
    # The requeued event is OLDER than everything queued; dropping it
    # would silently reorder the stream.
    queue = BoundedEventQueue(max_size=2)
    queue.put(_event(5))
    queue.put(_event(6))

    dropped = queue.requeue_front(_event(4))

    assert dropped["eventId"] == "EV-6"
    assert [e["eventId"] for e in queue.get_batch(10, timeout=0)] == ["EV-4", "EV-5"]


# --------------------------------------------------------------------------
# 28. metrics
# --------------------------------------------------------------------------

def test_metrics_track_depth_peak_throughput_and_drops():
    queue = BoundedEventQueue(max_size=3)
    for n in range(6):
        queue.put(_event(n))
    queue.get_batch(2, timeout=0)

    stats = queue.stats
    assert stats["capacity"] == 3
    assert stats["depth"] == 1
    assert stats["max_depth"] == 3
    assert stats["total_enqueued"] == 6
    assert stats["total_dequeued"] == 2
    assert stats["dropped"] == 3
    assert queue.dropped_count == 3


def test_fill_ratio_reports_pressure():
    queue = BoundedEventQueue(max_size=4)
    queue.put(_event(1))
    queue.put(_event(2))
    assert queue.fill_ratio == pytest.approx(0.5)


# --------------------------------------------------------------------------
# 29. shutdown behavior
# --------------------------------------------------------------------------

def test_closed_queue_rejects_new_telemetry_but_keeps_what_is_queued():
    queue = BoundedEventQueue(max_size=10)
    queue.put(_event(1))
    queue.close()

    assert queue.put(_event(2)) is None
    assert queue.closed is True
    assert queue.depth == 1, "already-queued events survive for the shutdown drain"
    assert queue.get(timeout=0)["eventId"] == "EV-1"


def test_requeue_is_still_accepted_after_close():
    # During the shutdown drain the publisher may have to hand an event
    # back; rejecting it there would lose it.
    queue = BoundedEventQueue(max_size=10)
    queue.close()
    assert queue.requeue_front(_event(1)) is None
    assert queue.depth == 1


def test_close_wakes_a_blocked_consumer():
    queue = BoundedEventQueue(max_size=10)
    woke = threading.Event()

    def consume():
        queue.get_batch(1, timeout=30)
        woke.set()

    thread = threading.Thread(target=consume, daemon=True)
    thread.start()
    queue.close()

    assert woke.wait(timeout=5), "close() did not wake the waiting consumer"
    thread.join(timeout=5)


def test_a_waiting_consumer_is_woken_by_a_new_event():
    queue = BoundedEventQueue(max_size=10)
    received = []

    def consume():
        received.extend(queue.get_batch(1, timeout=30))

    thread = threading.Thread(target=consume, daemon=True)
    thread.start()
    queue.put(_event(7))
    thread.join(timeout=5)

    assert [e["eventId"] for e in received] == ["EV-7"]


@pytest.mark.parametrize("bad_size", [0, -1])
def test_invalid_capacity_is_rejected(bad_size):
    with pytest.raises(ValueError):
        BoundedEventQueue(max_size=bad_size)


def test_concurrent_producers_and_one_consumer_lose_nothing():
    queue = BoundedEventQueue(max_size=10_000)
    consumed = []
    stop = threading.Event()

    def produce(offset):
        for n in range(250):
            queue.put(_event(f"{offset}-{n}"))

    def consume():
        while not stop.is_set() or queue.depth:
            consumed.extend(queue.get_batch(100, timeout=0.05))

    consumer = threading.Thread(target=consume, daemon=True)
    consumer.start()
    producers = [threading.Thread(target=produce, args=(i,)) for i in range(4)]
    for p in producers:
        p.start()
    for p in producers:
        p.join(timeout=10)
    stop.set()
    consumer.join(timeout=10)

    assert len(consumed) == 1000
    assert len({e["eventId"] for e in consumed}) == 1000

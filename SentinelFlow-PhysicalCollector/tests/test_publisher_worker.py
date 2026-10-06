"""
Kafka publisher worker tests (PHASE S items 30-36).

These drive the REAL EventPublisher (real pending buffer, real bounded
exponential backoff, real health reporting) with only
kafka.KafkaProducer faked, and step the worker's real _iteration()
synchronously against a virtual clock. No broker, no sleeping.
"""
import pytest

from event_queue import BoundedEventQueue
from fakes import FakeKafkaProducer, NonSleepingEvent, VirtualClock
from health import DEGRADED, RUNNING, HealthRegistry
from kafka_producer import EventPublisher
from publisher_worker import PublisherWorker

TOPIC = "raw.events.v1"


def _event(n, event_type="PROCESS_START"):
    return {
        "eventId": f"EV-PHYS-{n}-aaaaaa",
        "entityId": "HOST-TEST",
        "eventType": event_type,
        "eventVersion": "v1",
        "occurredAt": "2027-01-15T08:00:00Z",
        "source": "physical-collector",
        "payload": {"pid": n},
    }


class Harness:
    def __init__(self, queue_size=1000, retry_base=5.0, retry_max=60.0, available=True):
        self.clock = VirtualClock()
        self.producer = FakeKafkaProducer(available=available)
        self.queue = BoundedEventQueue(max_size=queue_size)
        self.health = HealthRegistry(clock=self.clock)
        self.health.set_queue_capacity(queue_size)
        self.publisher = EventPublisher(
            bootstrap_servers="fake:9094", topic=TOPIC, clock=self.clock,
            retry_base_delay=retry_base, retry_max_delay=retry_max,
            health=self.health, producer_factory=lambda **kwargs: self.producer,
        )
        self.worker = PublisherWorker(
            queue=self.queue, publisher=self.publisher, health=self.health,
            queue_wait_seconds=0,  # never block on the queue in tests
        )
        self.stop = NonSleepingEvent()

    def step(self, times=1):
        for _ in range(times):
            self.worker._iteration(self.stop)

    def enqueue(self, *events):
        for event in events:
            self.queue.put(event)


@pytest.fixture
def harness():
    return Harness()


# --------------------------------------------------------------------------
# 30. successful publish
# --------------------------------------------------------------------------

def test_a_queued_event_is_published_and_removed_from_the_queue(harness):
    harness.enqueue(_event(1))
    harness.step()

    assert harness.producer.published_keys == ["EV-PHYS-1-aaaaaa"]
    assert harness.queue.depth == 0
    assert harness.health.snapshot()["events"]["published"] == 1
    assert harness.health.snapshot()["kafka"]["state"] == RUNNING


def test_events_are_published_in_queue_order(harness):
    harness.enqueue(*[_event(n) for n in range(10)])
    harness.step()

    assert harness.producer.published_keys == [f"EV-PHYS-{n}-aaaaaa" for n in range(10)]


def test_the_wire_format_is_the_existing_json_string_keyed_by_event_id(harness):
    import json

    harness.enqueue(_event(1))
    harness.step()

    key, value = harness.producer.records[0]
    assert key == "EV-PHYS-1-aaaaaa"
    assert json.loads(value) == _event(1)


def test_an_empty_queue_is_a_cheap_no_op(harness):
    harness.step(times=5)
    assert harness.producer.send_attempts == 0


def test_one_producer_is_reused_for_every_event(harness):
    created = []

    publisher = EventPublisher(
        "fake:9094", TOPIC, clock=harness.clock,
        producer_factory=lambda **kwargs: created.append(1) or harness.producer,
    )
    for n in range(20):
        publisher.publish(_event(n))

    assert len(created) == 1, "never one producer per event"


# --------------------------------------------------------------------------
# 31/32/33. temporary failure, retry, exponential backoff
# --------------------------------------------------------------------------

def test_a_failed_publish_does_not_lose_the_event(harness):
    harness.producer.go_down()
    harness.enqueue(_event(1))
    harness.step()

    assert harness.publisher.pending_count == 1
    assert harness.health.snapshot()["kafka"]["state"] == DEGRADED
    assert harness.health.snapshot()["events"]["failed"] == 1


def test_the_publisher_stops_draining_the_queue_while_backing_off(harness):
    # This is what makes the CENTRAL queue the outage buffer rather than
    # the producer's small pending buffer.
    harness.producer.go_down()
    harness.enqueue(*[_event(n) for n in range(100)])

    harness.step(times=20)

    assert harness.publisher.pending_count == 1, "only the in-flight event is held"
    assert harness.queue.depth == 99, "everything else stays in the bounded queue"
    assert harness.producer.send_attempts == 1, "no retry storm"


def test_backoff_grows_exponentially_and_is_capped():
    harness = Harness(retry_base=1.0, retry_max=8.0)
    harness.producer.go_down()
    harness.enqueue(_event(1))

    delays = []
    for _ in range(6):
        harness.step()
        delays.append(harness.publisher.seconds_until_retry())
        harness.clock.advance(harness.publisher.seconds_until_retry())

    assert delays == [1.0, 2.0, 4.0, 8.0, 8.0, 8.0]


def test_no_send_is_attempted_before_the_backoff_expires(harness):
    harness.producer.go_down()
    harness.enqueue(_event(1))
    harness.step()
    assert harness.producer.send_attempts == 1

    harness.clock.advance(4)  # base delay is 5s
    harness.step(times=10)
    assert harness.producer.send_attempts == 1

    harness.clock.advance(2)
    harness.step()
    assert harness.producer.send_attempts == 2


def test_retries_are_counted_in_health(harness):
    harness.producer.go_down()
    harness.enqueue(_event(1))
    harness.step()

    for _ in range(3):
        harness.clock.advance(120)
        harness.step()

    assert harness.health.snapshot()["kafka"]["retry_count"] == 3


# --------------------------------------------------------------------------
# 34/35. recovery and queue drain
# --------------------------------------------------------------------------

def test_the_queue_drains_in_order_after_the_broker_returns(harness):
    harness.producer.go_down()
    harness.enqueue(*[_event(n) for n in range(30)])
    harness.step()
    assert harness.queue.depth == 29

    harness.producer.come_back()
    harness.clock.advance(60)
    for _ in range(5):
        harness.step()

    assert harness.queue.depth == 0
    assert harness.publisher.pending_count == 0
    assert harness.producer.published_keys == [f"EV-PHYS-{n}-aaaaaa" for n in range(30)]


def test_recovery_restores_kafka_health(harness):
    harness.producer.go_down()
    harness.enqueue(_event(1))
    harness.step()
    assert harness.health.snapshot()["kafka"]["state"] == DEGRADED

    harness.producer.come_back()
    harness.clock.advance(60)
    harness.step()

    kafka = harness.health.snapshot()["kafka"]
    assert kafka["state"] == RUNNING
    assert kafka["consecutive_failures"] == 0


def test_draining_is_paced_rather_than_dumped_in_one_burst():
    harness = Harness(queue_size=10_000)
    harness.producer.go_down()
    harness.enqueue(*[_event(n) for n in range(500)])
    harness.step()

    harness.producer.come_back()
    harness.clock.advance(60)
    harness.step()  # exactly one iteration

    published = len(harness.producer.published_keys)
    assert 0 < published <= 51, "one batch (+ the held pending event) per iteration"
    assert harness.queue.depth > 0


def test_multiple_outages_and_recoveries_all_recover(harness):
    for cycle in range(4):
        harness.producer.go_down()
        harness.enqueue(*[_event(f"{cycle}-{n}") for n in range(5)])
        harness.step(times=3)

        harness.producer.come_back()
        harness.clock.advance(120)
        harness.step(times=3)

        assert harness.queue.depth == 0, f"cycle {cycle} did not drain"
        assert harness.publisher.pending_count == 0

    assert len(harness.producer.published_keys) == 20
    assert harness.health.snapshot()["kafka"]["state"] == RUNNING


def test_a_mid_batch_failure_requeues_the_rest_in_order(harness):
    harness.enqueue(*[_event(n) for n in range(5)])

    original_send = harness.producer.send
    calls = {"n": 0}

    def send(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 3:
            harness.producer.go_down()
        return original_send(*args, **kwargs)

    harness.producer.send = send
    harness.step()

    # 0 and 1 went out; 2 is held by the publisher; 3 and 4 went back to
    # the FRONT of the queue in order.
    assert harness.producer.published_keys == ["EV-PHYS-0-aaaaaa", "EV-PHYS-1-aaaaaa"]
    assert harness.publisher.pending_count == 1
    assert [e["eventId"] for e in harness.queue.get_batch(10, timeout=0)] == [
        "EV-PHYS-3-aaaaaa", "EV-PHYS-4-aaaaaa",
    ]


# --------------------------------------------------------------------------
# 36. permanent failure behavior
# --------------------------------------------------------------------------

def test_a_permanently_dead_broker_never_blocks_or_crashes_the_worker():
    harness = Harness(queue_size=100, available=False)

    for n in range(1000):
        harness.queue.put(_event(n))
        harness.step()
        harness.clock.advance(1)

    assert harness.queue.depth == 100, "queue stayed bounded"
    assert harness.publisher.pending_count <= 1
    # 1000 enqueued, 100 still queued, 1 held in flight by the publisher
    # -> 899 dropped by the drop-oldest overflow policy, all counted.
    assert harness.queue.dropped_count == 899
    assert harness.health.snapshot()["kafka"]["state"] == DEGRADED
    # Backoff capped, so the number of attempts is tiny next to 1000 events.
    assert harness.producer.send_attempts < 50


def test_an_unserializable_event_is_refused_before_it_is_queued(harness):
    import pytest as _pytest

    with _pytest.raises(TypeError):
        harness.publisher.publish({"eventId": "EV-X", "payload": object()})
    assert harness.publisher.pending_count == 0


def test_a_non_kafka_exception_is_treated_as_a_transient_failure(harness):
    def explode(*args, **kwargs):
        raise OSError("socket closed by peer")

    harness.producer.send = explode
    harness.enqueue(_event(1))
    harness.step()

    assert harness.publisher.pending_count == 1, "event retained, worker alive"
    assert harness.health.snapshot()["kafka"]["state"] == DEGRADED


# --------------------------------------------------------------------------
# Lazy connect: starting with no broker at all
# --------------------------------------------------------------------------

def test_the_worker_keeps_retrying_a_producer_that_cannot_be_created():
    clock = VirtualClock()
    health = HealthRegistry(clock=clock)
    queue = BoundedEventQueue(max_size=10)
    attempts = {"n": 0}

    def failing_factory():
        attempts["n"] += 1
        raise OSError("NoBrokersAvailable")

    worker = PublisherWorker(
        queue=queue, publisher=None, health=health, publisher_factory=failing_factory,
        connect_retry_base_seconds=1.0, connect_retry_max_seconds=4.0, queue_wait_seconds=0,
    )
    stop = NonSleepingEvent()

    # _ensure_publisher loops until stop; make stop fire after a few tries.
    class StopAfter(NonSleepingEvent):
        def wait(self, timeout=None):
            if attempts["n"] >= 3:
                self.set()
            return self.is_set()

    assert worker._ensure_publisher(StopAfter()) is False
    assert attempts["n"] == 3
    assert health.snapshot()["kafka"]["state"] == DEGRADED
    assert stop.is_set() is False


def test_the_worker_connects_lazily_once_the_broker_is_reachable():
    clock = VirtualClock()
    health = HealthRegistry(clock=clock)
    queue = BoundedEventQueue(max_size=10)
    producer = FakeKafkaProducer()
    attempts = {"n": 0}

    def factory():
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise OSError("NoBrokersAvailable")
        return EventPublisher(
            "fake:9094", TOPIC, clock=clock, health=health,
            producer_factory=lambda **kwargs: producer,
        )

    worker = PublisherWorker(
        queue=queue, publisher=None, health=health, publisher_factory=factory,
        connect_retry_base_seconds=1.0, connect_retry_max_seconds=4.0, queue_wait_seconds=0,
    )
    stop = NonSleepingEvent()

    assert worker._ensure_publisher(stop) is True
    assert attempts["n"] == 3

    queue.put(_event(1))
    worker._iteration(stop)
    assert producer.published_keys == ["EV-PHYS-1-aaaaaa"]


def test_a_publisher_worker_needs_a_publisher_or_a_factory():
    with pytest.raises(ValueError):
        PublisherWorker(
            queue=BoundedEventQueue(max_size=1), publisher=None,
            health=HealthRegistry(), publisher_factory=None,
        )


# --------------------------------------------------------------------------
# Shutdown drain
# --------------------------------------------------------------------------

def test_drain_publishes_everything_still_queued(harness):
    harness.enqueue(*[_event(n) for n in range(120)])
    harness.queue.close()

    remaining = harness.worker.drain(deadline_seconds=30, stop_event=harness.stop)

    assert remaining == 0
    assert len(harness.producer.published_keys) == 120


def test_drain_reports_what_it_could_not_publish(harness):
    harness.producer.go_down()
    harness.enqueue(*[_event(n) for n in range(10)])
    harness.queue.close()

    remaining = harness.worker.drain(deadline_seconds=0, stop_event=harness.stop)

    assert remaining == 10, "the fact is reported, never silently discarded"


def test_drain_does_not_wait_out_a_backoff_longer_than_its_budget(harness):
    harness.producer.go_down()
    harness.enqueue(_event(1))
    harness.step()  # fails -> 5s backoff

    harness.worker.drain(deadline_seconds=1, stop_event=harness.stop)

    assert harness.producer.send_attempts == 1, "no extra attempt inside the backoff"


def test_drain_is_a_no_op_when_the_publisher_never_connected():
    queue = BoundedEventQueue(max_size=10)
    queue.put(_event(1))
    worker = PublisherWorker(
        queue=queue, publisher=None, health=HealthRegistry(),
        publisher_factory=lambda: None, queue_wait_seconds=0,
    )
    assert worker.drain(deadline_seconds=5, stop_event=NonSleepingEvent()) == 1


# --------------------------------------------------------------------------
# Producer close semantics
# --------------------------------------------------------------------------

def test_close_makes_a_final_attempt_then_flushes_and_closes(harness):
    harness.producer.go_down()
    harness.publisher.publish(_event(1))

    harness.producer.come_back()
    harness.publisher.close()

    assert harness.publisher.pending_count == 0
    assert harness.producer.published_keys == ["EV-PHYS-1-aaaaaa"]
    assert harness.producer.flush_calls == 1
    assert harness.producer.close_calls == 1


def test_close_is_idempotent(harness):
    harness.publisher.close()
    harness.publisher.close()

    assert harness.producer.close_calls == 1, "no duplicate producer close"


def test_close_survives_a_producer_that_raises_on_flush(harness):
    def explode(timeout=None):
        raise OSError("already closed")

    harness.producer.flush = explode
    harness.publisher.close()  # must not raise
    assert harness.producer.close_calls == 1

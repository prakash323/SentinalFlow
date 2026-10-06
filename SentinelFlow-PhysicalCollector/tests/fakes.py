"""
fakes.py
Shared deterministic test doubles.

Design rule for everything in here: fake the OUTERMOST boundary only.

  - FakeKafkaProducer replaces kafka.KafkaProducer, so the real
    EventPublisher (its real queueing, real backoff, real health
    reporting) is exercised in tests rather than mocked out.
  - FakeProcessSource/FakeNetworkSource/FakeSessionSource replace the
    psutil snapshot functions, so the real pollers' real diffing logic
    runs against a table the test controls.
  - VirtualClock replaces time.monotonic/time.time so nothing sleeps.

Nothing here touches a real broker, a real process table, real
connections or real credentials.
"""
from __future__ import annotations

import threading
from collections import namedtuple
from typing import Dict, List, Optional, Tuple

from kafka.errors import KafkaError

from network_poller import ConnectionKey
from process_poller import ProcessKey

FakeUser = namedtuple("FakeUser", ["name", "terminal", "host", "started", "pid"])
FakeAddr = namedtuple("FakeAddr", ["ip", "port"])
FakeConn = namedtuple("FakeConn", ["fd", "family", "type", "laddr", "raddr", "status", "pid"])


class VirtualClock:
    """A monotonic clock the test advances by hand. Also usable as the
    wall clock - start() is a plausible epoch so iso_utc() produces
    real-looking timestamps."""

    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self._now = start
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self._now

    @property
    def now(self) -> float:
        return self()

    def advance(self, seconds: float) -> float:
        with self._lock:
            self._now += seconds
            return self._now


class NonSleepingEvent:
    """A stand-in for threading.Event whose wait() never blocks.

    Lets a worker's or the publisher's real loop code be stepped
    synchronously. The simulation's own loop owns time, so a wait() here
    must not consume any real time."""

    def __init__(self) -> None:
        self._set = False

    def is_set(self) -> bool:
        return self._set

    def set(self) -> None:
        self._set = True

    def clear(self) -> None:
        self._set = False

    def wait(self, timeout: Optional[float] = None) -> bool:
        return self._set


class VirtualStopEvent(NonSleepingEvent):
    """NonSleepingEvent that ADVANCES a VirtualClock instead of sleeping.

    This is what makes a worker's real run() loop testable with no real
    delay: the loop's "sleep until the next poll is due" becomes "jump
    the virtual clock forward to when the next poll is due". A loop that
    spins instead of waiting would therefore not advance time, which is
    exactly the bug this double would expose."""

    def __init__(self, clock: VirtualClock) -> None:
        super().__init__()
        self._clock = clock

    def wait(self, timeout: Optional[float] = None) -> bool:
        if not self._set and timeout:
            self._clock.advance(timeout)
        return self._set


class FakeRecordMetadata:
    def __init__(self, partition: int = 0, offset: int = 0) -> None:
        self.partition = partition
        self.offset = offset


class FakeFuture:
    def __init__(self, metadata: FakeRecordMetadata) -> None:
        self._metadata = metadata

    def get(self, timeout=None) -> FakeRecordMetadata:
        return self._metadata


class FakeKafkaProducer:
    """Replaces kafka.KafkaProducer. `available` toggles a broker outage;
    `fail_after` makes it start failing once N records are accepted."""

    def __init__(self, available: bool = True, **kwargs) -> None:
        self.kwargs = kwargs
        self.available = available
        self.records: List[Tuple[str, str]] = []
        self.flush_calls = 0
        self.close_calls = 0
        self.send_attempts = 0
        self._offset = 0

    def send(self, topic, key=None, value=None):
        self.send_attempts += 1
        if not self.available:
            raise KafkaError("fake broker unavailable")
        self.records.append((key, value))
        self._offset += 1
        return FakeFuture(FakeRecordMetadata(partition=0, offset=self._offset))

    def flush(self, timeout=None) -> None:
        self.flush_calls += 1

    def close(self, timeout=None) -> None:
        self.close_calls += 1

    # -- test helpers -------------------------------------------------------

    @property
    def published_keys(self) -> List[str]:
        return [key for key, _value in self.records]

    def go_down(self) -> None:
        self.available = False

    def come_back(self) -> None:
        self.available = True


class FakeProcessSource:
    """A controllable process table in the shape ProcessPoller._snapshot
    returns: {ProcessKey: info-dict}."""

    def __init__(self) -> None:
        self._table: Dict[ProcessKey, dict] = {}
        self.snapshot_calls = 0
        self.raise_next: Optional[BaseException] = None
        self.always_raise: Optional[BaseException] = None

    def add(self, pid: int, name: str = "proc.exe", ppid: int = 4,
            create_time: float = 1000.0, username: str = "HOST\\user") -> ProcessKey:
        key = ProcessKey(pid=pid, create_time=create_time)
        self._table[key] = {
            "pid": pid, "name": name, "ppid": ppid,
            "create_time": create_time, "username": username,
        }
        return key

    def remove(self, pid: int, create_time: Optional[float] = None) -> None:
        for key in list(self._table):
            if key.pid == pid and (create_time is None or key.create_time == create_time):
                del self._table[key]

    def clear(self) -> None:
        self._table.clear()

    def __len__(self) -> int:
        return len(self._table)

    def snapshot(self) -> Dict[ProcessKey, dict]:
        self.snapshot_calls += 1
        if self.always_raise is not None:
            raise self.always_raise
        if self.raise_next is not None:
            error, self.raise_next = self.raise_next, None
            raise error
        return dict(self._table)

    def executable_lookup(self, pid: int) -> Optional[str]:
        return f"C:\\fake\\{pid}.exe"


class FakeNetworkSource:
    """A controllable connection table in the shape
    NetworkPoller._snapshot returns: {ConnectionKey: conn}."""

    def __init__(self) -> None:
        self._table: Dict[ConnectionKey, FakeConn] = {}
        self.snapshot_calls = 0
        self.raise_next: Optional[BaseException] = None
        self.always_raise: Optional[BaseException] = None
        self.process_info: Dict[int, Tuple[Optional[str], Optional[float]]] = {}

    def add(self, pid: int = 1234, local_ip: str = "192.168.1.2", local_port: int = 50000,
            remote_ip: str = "93.184.216.34", remote_port: int = 443,
            protocol: str = "TCP", status: str = "ESTABLISHED") -> ConnectionKey:
        key: ConnectionKey = (protocol, local_ip, local_port, remote_ip, remote_port, pid)
        self._table[key] = FakeConn(
            fd=-1, family=2, type=1 if protocol == "TCP" else 2,
            laddr=FakeAddr(local_ip, local_port),
            raddr=FakeAddr(remote_ip, remote_port),
            status=status, pid=pid,
        )
        return key

    def remove(self, key: ConnectionKey) -> None:
        self._table.pop(key, None)

    def clear(self) -> None:
        self._table.clear()

    def __len__(self) -> int:
        return len(self._table)

    def snapshot(self) -> Dict[ConnectionKey, FakeConn]:
        self.snapshot_calls += 1
        if self.always_raise is not None:
            raise self.always_raise
        if self.raise_next is not None:
            error, self.raise_next = self.raise_next, None
            raise error
        return dict(self._table)

    def lookup(self, pid: Optional[int]) -> Tuple[Optional[str], Optional[float]]:
        if not pid:
            return None, None
        return self.process_info.get(pid, (None, None))


class FakeSessionSource:
    """A controllable session table in the shape SessionPoller._snapshot
    returns: {_SessionKey: user}."""

    def __init__(self) -> None:
        self._users: Dict[tuple, FakeUser] = {}
        self.snapshot_calls = 0
        self.raise_next: Optional[BaseException] = None
        self.always_raise: Optional[BaseException] = None

    def login(self, name: str = "praka", started: float = 900.0,
              host: Optional[str] = None, terminal: Optional[str] = None) -> tuple:
        from session_poller import _SessionKey
        key = _SessionKey(name=name, started=started)
        self._users[key] = FakeUser(name=name, terminal=terminal, host=host,
                                    started=started, pid=None)
        return key

    def logout(self, name: str, started: float) -> None:
        from session_poller import _SessionKey
        self._users.pop(_SessionKey(name=name, started=started), None)

    def __len__(self) -> int:
        return len(self._users)

    def snapshot(self) -> Dict[tuple, FakeUser]:
        self.snapshot_calls += 1
        if self.always_raise is not None:
            raise self.always_raise
        if self.raise_next is not None:
            error, self.raise_next = self.raise_next, None
            raise error
        return dict(self._users)

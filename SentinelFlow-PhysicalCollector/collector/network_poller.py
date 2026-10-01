"""
network_poller.py
Polls the local machine's ESTABLISHED network connections and yields
NetworkConnectionEvent objects for connections that are both genuinely
new since the previous poll AND not loopback-to-loopback local service
chatter.

SCOPE (per the P3 audit and approved design - NOT the full connection
table):
  - ESTABLISHED only. LISTEN sockets are long-lived standing
    configuration, not "activity" - excluded. TIME_WAIT connections were
    empirically confirmed during the audit to always have pid=0 on this
    platform, making them both low-value and unreliable to identify -
    excluded.
  - Non-loopback remote address only. A connection whose remote address
    is 127.0.0.0/8 or ::1 is local-machine-to-itself traffic (observed
    during the audit: e.g. Docker's backend talking to its own Postgres/
    Kafka containers on 127.0.0.1) - excluded as noise, not as a privacy
    measure. Private/LAN addresses (10.x, 192.168.x, etc.) are NOT
    loopback and ARE kept, per explicit design decision - this collector
    does not restrict itself to public-Internet connections.

Like ProcessPoller (P2), the FIRST poll_once() call establishes a
SILENT baseline and returns nothing - an already-established connection
at collector startup is exactly as unhelpful to report as an
already-running process was (see process_poller.py's docstring for the
same reasoning applied to processes). Only connections that first appear
after that baseline are ever reported. A collector restart re-establishes
the baseline silently and does not replay existing connections.

Connection identity is (protocol, localAddress, localPort, remoteAddress,
remotePort, pid) - deliberately NOT including status, since a tracked
connection's status can legitimately change between polls (e.g.
ESTABLISHED -> CLOSE_WAIT) without that being a new connection. This
identity has a real, documented limitation (see "Known limitations" in
README.md): psutil's connection table carries no equivalent of a
process's create_time, so there is no way to distinguish a genuinely new
connection from a coincidental exact repeat of the same 6-tuple after
the original one closed. This was investigated during the audit and
accepted as the correct trade-off for this phase, not an oversight.

Collection cost (measured empirically during the P3 audit, not
assumed): psutil.net_connections(kind='inet') costs ~1.4ms for ~200
connections on this development machine - dramatically cheaper than
P2's exe lookup. --network-poll-interval therefore exists to bound EVENT
VOLUME, not CPU cost (a light 3-request test burst produced 7 new
ESTABLISHED connections in ~15 seconds on this single machine - see the
phase report for the full extrapolation).
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import psutil

logger = logging.getLogger("sentinelflow.collector.network_poller")

ConnectionKey = Tuple[str, str, int, str, int, int]


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        # Malformed/unexpected address string - treat conservatively as
        # not loopback rather than silently dropping a real connection.
        return False


def _protocol_for(conn_type) -> str:
    if conn_type == 1:  # socket.SOCK_STREAM
        return "TCP"
    if conn_type == 2:  # socket.SOCK_DGRAM
        return "UDP"
    return str(conn_type)


@dataclass(frozen=True)
class NetworkConnectionEvent:
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    status: str
    pid: Optional[int]
    process_name: Optional[str]
    # Event Correlation Foundation (Option A): the OWNING PROCESS's real
    # create_time, as reported by the OS at the moment this connection
    # was detected - NOT this connection's own start time (psutil's
    # connection table has no such field - see the module docstring's
    # "Connection identity" note, unchanged by this addition). This lets
    # a consumer match against PROCESS_START's own (pid, create_time)
    # identity to tell whether the process that owns this connection is
    # really the same process a PROCESS_START event reported earlier, or
    # a later, unrelated process that happened to reuse the same pid.
    process_create_time: Optional[float]


def _resolve_process_info(pid: Optional[int]) -> Tuple[Optional[str], Optional[float]]:
    """Targeted, single-process lookup - called only for newly detected
    connections (see NetworkPoller.poll_once), never for the whole
    connection table. Resolves both processName and processCreateTime
    from the SAME psutil.Process handle - reading create_time costs
    nothing extra beyond the name read already performed here (P2's own
    measured cost breakdown: only exe()/path resolution was expensive,
    not create_time - no new expensive lookup is introduced)."""
    if not pid:
        return None, None

    try:
        process = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None, None

    name: Optional[str] = None
    create_time: Optional[float] = None

    try:
        name = process.name() or None
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        # The process may have exited, or (rarely, on this platform, per
        # the P3 audit) the pid may since have been reused by an
        # unrelated process - either way, omit rather than fabricate.
        pass

    try:
        create_time = process.create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    return name, create_time


def _snapshot() -> Dict[ConnectionKey, "psutil._common.sconn"]:
    current: Dict[ConnectionKey, "psutil._common.sconn"] = {}

    for c in psutil.net_connections(kind="inet"):
        if c.status != "ESTABLISHED":
            continue
        if not c.raddr:
            continue
        if _is_loopback(c.raddr.ip):
            continue

        key: ConnectionKey = (
            _protocol_for(c.type),
            c.laddr.ip,
            c.laddr.port,
            c.raddr.ip,
            c.raddr.port,
            c.pid or 0,
        )
        current[key] = c

    return current


class NetworkPoller:
    """Stateful poller. The FIRST poll_once() call establishes a silent
    baseline of already-ESTABLISHED (non-loopback-remote) connections and
    returns an EMPTY list. Every subsequent call returns one
    NetworkConnectionEvent per connection identity that was not present
    in the previous snapshot."""

    def __init__(self) -> None:
        self._known: Set[ConnectionKey] = set()
        self._initialized = False

    def poll_once(self) -> List[NetworkConnectionEvent]:
        current = _snapshot()

        if not self._initialized:
            self._known = set(current.keys())
            self._initialized = True
            logger.info(
                "Baseline network snapshot taken: %d established "
                "non-loopback connection(s) - none reported as "
                "NETWORK_CONNECTION (pre-existing, not new)",
                len(current),
            )
            return []

        new_keys = [key for key in current if key not in self._known]
        events: List[NetworkConnectionEvent] = []

        for key in new_keys:
            conn = current[key]
            pid = conn.pid or None
            process_name, process_create_time = _resolve_process_info(pid)
            events.append(NetworkConnectionEvent(
                protocol=key[0],
                local_address=key[1],
                local_port=key[2],
                remote_address=key[3],
                remote_port=key[4],
                status=conn.status,
                pid=pid,
                process_name=process_name,
                process_create_time=process_create_time,
            ))

        self._known = set(current.keys())
        return events

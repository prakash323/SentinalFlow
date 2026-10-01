"""
host_identity.py
Derives a stable, deterministic, non-secret entityId for this machine.

Derivation: "HOST-<hostname>" (uppercased OS hostname via
socket.gethostname()). Deliberately simple:

  - Deterministic across collector restarts on the same machine, which is
    the actual requirement here - not "globally collision-proof forever".
    A pure random id (e.g. uuid4() generated at each startup) would fail
    this immediately, which is exactly what this module exists to avoid.
  - Contains no secrets, credentials, or user-identifying data beyond the
    machine's own network name (the same name already visible to anyone
    on the local network, in Windows System settings, etc).
  - Matches the existing simulator's simple "NAME-suffix" entity id style
    (USER-001, SVC-001) rather than inventing a new convention.

Known, documented limitation (not solved here - see final report): if two
different physical machines in the same deployment happen to share an OS
hostname, they collapse to the same entityId. This phase targets a single
demo machine, so a hardware-level disambiguator (e.g. a MAC-address hash
or the Windows registry MachineGuid) is intentionally left out rather
than adding cross-platform/permission complexity this phase does not
need. --entity-id (see config.py) is the escape hatch if this ever
matters for a specific deployment.
"""
from __future__ import annotations

import socket


def stable_hostname() -> str:
    """The OS-reported hostname. Stable across process restarts; changes
    only if the machine itself is renamed (a deliberate admin action, not
    something this collector should try to detect or compensate for)."""
    return socket.gethostname()


def default_entity_id() -> str:
    """The collector's default entityId when --entity-id / COLLECTOR_ENTITY_ID
    is not supplied. See module docstring for the derivation and its
    documented limitation."""
    return f"HOST-{stable_hostname().upper()}"

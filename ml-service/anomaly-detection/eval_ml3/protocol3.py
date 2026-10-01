"""ML-3 split protocol: the EXACT ML-2 chronological protocol, plus an immutable per-run split manifest.

The split is not re-derived or re-tuned. eval_ml2.protocol.build() is used unchanged and its result is asserted equal to
the published ML-2 manifest (boundaries, per-split counts, incident homes, purge). The manifest written here adds an
event-level assignment hash so any later change to the split (even a single row) is detected.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat

import numpy as np
import pandas as pd

from . import common as K
from eval_ml2 import protocol as P2


def build():
    p = P2.build()
    ts = pd.to_datetime(p.events["timestamp"])
    assert ts.is_monotonic_increasing, "events must be in strict chronological order (the protocol and every causal step rely on it)"
    return p


def assignment_hash(p) -> str:
    h = hashlib.sha256()
    ids = p.events["event_id"].to_numpy()
    for i in range(len(ids)):
        h.update(f"{ids[i]}|{p.split[i]}|{int(p.purged[i])}\n".encode())
    return h.hexdigest()


def assert_matches_ml2(p) -> dict:
    """Return the comparison; raise if the ML-3 split differs from the published ML-2 split in any recorded field."""
    ml2 = json.load(open(K.REPORTS / "ml2_split_manifest.json", encoding="utf-8"))
    mine = P2.manifest(p, P2.heldout_entities(p))
    checks = {}
    for k in ("t0", "train_end", "validation_end", "last_event", "train_days", "validation_end_days"):
        checks[f"protocol.{k}"] = ml2["protocol"][k] == mine["protocol"][k]
    for s in ("train", "validation", "test_raw_time_window", "test_evaluation_population"):
        for f in ("rows", "attack_events", "attack_incidents_born_in_split", "attack_incidents_by_type", "attack_events_by_type", "entities"):
            checks[f"splits.{s}.{f}"] = ml2["splits"][s][f] == mine["splits"][s][f]
    checks["purge"] = ml2["purge"] == mine["purge"]
    checks["incidents_by_home_split"] = ml2["incidents_by_home_split"] == mine["incidents_by_home_split"]
    ok = all(checks.values())
    if not ok:
        raise AssertionError({k: v for k, v in checks.items() if not v})
    return {"identical_to_ml2": ok, "fields_compared": len(checks), "ml2_manifest_sha256": K.sha256_file(K.REPORTS / "ml2_split_manifest.json")}


def manifest(p, cmp_ml2: dict) -> dict:
    m = P2.manifest(p, [])
    m.pop("heldout_entities", None)                       # entity holdout belongs to ML-2 only
    m["ml3"] = {
        "immutable": True,
        "assignment_sha256": assignment_hash(p),
        "assignment_definition": "sha256 over lines 'event_id|split|purged' for every event in chronological order",
        "events": int(len(p.events)),
        "identical_to_ml2": cmp_ml2,
        "dataset_sha256": {"events.csv": K.sha256_file(K.DATA / "events.csv"), "labels.csv": K.sha256_file(K.DATA / "labels.csv")},
        "allowed_use": {
            "TRAIN": "fit every learned component (baseline profile, scaler, Isolation Forest, sequence autoencoder, score-transformation "
                     "distributions). Contains 0 attack events, so no label is used or needed.",
            "VALIDATION": "model selection only: fusion weights, baseline mode, operating threshold, classifier fit and its grouped CV. "
                          "Labels of validation-period rows are used here.",
            "TEST": "final evaluation, unsealed exactly once after every configuration is frozen and hashed. Test-period labels are masked "
                    "from all earlier code (LabelVault.dev_labels).",
        },
        "incident_home": {a: s for a, s in sorted(p.incident_home.items())},
    }
    return m


def write_immutable(path, m) -> str:
    path = os.fspath(path)
    if os.path.exists(path):
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    K.write_json(path, m)
    os.chmod(path, stat.S_IREAD)
    return K.sha256_file(path)

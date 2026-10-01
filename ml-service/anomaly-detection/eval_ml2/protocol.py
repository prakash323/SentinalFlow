"""Chronological TRAIN / VALIDATION / TEST protocol (evaluation-only).

Pre-registered rules (fixed before any model score was inspected; they use incident *timing counts* only):

  TRAIN       t <  t0 + 20 d      the exact window the shipped artifact was fitted on (verified in run.py against the
                                  artifact's stored calibration curves and per-entity counts).
  VALIDATION  t0+20 d <= t < t0+25 d
              25 d = the shortest window after TRAIN that contains >= 1/3 (12 of 36) of the attack incidents,
              counted by each incident's first event. Used for tuning-style decisions only (an evaluation-only
              operating point, and the chronological classifier fit).
  TEST        t >= t0 + 25 d      held out from every ML-2 decision.

Incident purge: an attack incident belongs to the split of its FIRST event. Events of a validation-born incident that
fall after the boundary are removed from the TEST *evaluation population* (they still flow through the stream, so
entity state stays causal). Otherwise a classifier/threshold decision made on validation would have seen the same
incident as the test rows. benign_drift (a negative class) is not purged.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from . import common as K
from .common import ATTACKS, C


@dataclass
class Protocol:
    events: pd.DataFrame          # canonical events, chronological, LABEL-FREE
    labels: pd.DataFrame          # aligned label/attack_id (sealed by LabelVault in the assemble stage)
    t0: pd.Timestamp
    t_train_end: pd.Timestamp
    t_val_end: pd.Timestamp
    t_end: pd.Timestamp
    split: np.ndarray             # 'train' | 'validation' | 'test'  (by timestamp)
    purged: np.ndarray           # bool: test-period attack events belonging to validation-born incidents
    incident_home: dict           # attack_id -> 'train'|'validation'|'test' (split of the incident's first event)

    @property
    def m_train(self):
        return self.split == "train"

    @property
    def m_val(self):
        return self.split == "validation"

    @property
    def m_test_raw(self):
        return self.split == "test"

    @property
    def m_test(self):
        """PRIMARY held-out evaluation population: test period minus purged straddling-incident events."""
        return (self.split == "test") & ~self.purged

    @property
    def m_legacy(self):
        """ML-1 / README population (days 21-30 = validation + unpurged test). Reference only, NOT held out."""
        return self.split != "train"


def build() -> Protocol:
    from src.utils import load_events
    events = load_events(K.DATA / "events.csv")
    labels = pd.read_csv(K.DATA / "labels.csv").set_index("event_id").loc[events.event_id].reset_index()
    labels["attack_id"] = labels["attack_id"].fillna("")
    ts = pd.to_datetime(events["timestamp"])
    t0 = ts.min()
    t_tr = t0 + pd.Timedelta(days=K.TRAIN_DAYS)
    t_va = t0 + pd.Timedelta(days=K.VAL_END_DAYS)
    split = np.where(ts < t_tr, "train", np.where(ts < t_va, "validation", "test"))

    lab = labels["label"].to_numpy()
    aid = labels["attack_id"].to_numpy()
    is_atk = np.isin(lab, ATTACKS)
    home = {}
    for a in np.unique(aid[is_atk]):
        first_i = np.where(aid == a)[0].min()            # events are chronological, so min index = first event
        home[a] = split[first_i]
    purged = np.zeros(len(events), dtype=bool)
    for i in np.where(is_atk & (split == "test"))[0]:
        if home[aid[i]] != "test":
            purged[i] = True
    return Protocol(events=events, labels=labels, t0=t0, t_train_end=t_tr, t_val_end=t_va, t_end=ts.max(),
                    split=split, purged=purged, incident_home=home)


def heldout_entities(p: Protocol) -> list[str]:
    """Deterministic 30% entity holdout, stratified by whether the entity is ever attacked in the eval period."""
    lab = p.labels["label"].to_numpy()
    ent = p.events["entity_id"].to_numpy()
    attacked = sorted(set(ent[np.isin(lab, ATTACKS) & (p.split != "train")]))
    others = sorted(set(ent) - set(attacked))
    rng = np.random.default_rng(K.EVAL_SEED)
    pick = list(rng.choice(attacked, int(round(K.HELDOUT_FRACTION * len(attacked))), replace=False))
    pick += list(rng.choice(others, int(round(K.HELDOUT_FRACTION * len(others))), replace=False))
    return sorted(pick)


def _pop_stats(p: Protocol, mask: np.ndarray) -> dict:
    lab = p.labels["label"].to_numpy()[mask]
    aid = p.labels["attack_id"].to_numpy()[mask]
    ent = p.events["entity_id"].to_numpy()[mask]
    ts = pd.to_datetime(p.events["timestamp"])[mask]
    is_atk = np.isin(lab, ATTACKS)
    inc_any = sorted(set(aid[is_atk]))
    home_here = [a for a in inc_any if p.incident_home[a] in _home_names(p, mask)]
    return {
        "rows": int(mask.sum()),
        "start": ts.min().isoformat() if mask.any() else None,
        "end": ts.max().isoformat() if mask.any() else None,
        "entities": int(len(set(ent))),
        "attack_events": int(is_atk.sum()),
        "attack_rate": float(is_atk.mean()) if mask.any() else None,
        "attack_incidents_with_any_event": len(inc_any),
        "attack_incidents_born_in_split": len(home_here),
        "benign_drift_events": int((lab == "benign_drift").sum()),
        "class_distribution": {k: int(v) for k, v in pd.Series(lab).value_counts().items()},
        "attack_incidents_by_type": {t: int(len({a for a, l in zip(aid[is_atk], lab[is_atk]) if l == t})) for t in ATTACKS},
        "attack_events_by_type": {t: int((lab == t).sum()) for t in ATTACKS},
    }


def _home_names(p, mask):
    names = set(p.split[mask])
    return names


def manifest(p: Protocol, held: list[str]) -> dict:
    ent = p.events["entity_id"].to_numpy()
    lab = p.labels["label"].to_numpy()
    n_atk_inc = len(p.incident_home)
    by_home = pd.Series(list(p.incident_home.values())).value_counts().to_dict()
    purge_incidents = sorted({p.labels["attack_id"].iloc[i] for i in np.where(p.purged)[0]})
    m = {
        "protocol": {
            "type": "chronological (actual event timestamps, no shuffling)",
            "t0": p.t0.isoformat(), "train_end": p.t_train_end.isoformat(),
            "validation_end": p.t_val_end.isoformat(), "last_event": p.t_end.isoformat(),
            "train_days": K.TRAIN_DAYS, "validation_end_days": K.VAL_END_DAYS,
            "validation_rule": "shortest window after TRAIN holding >=1/3 of attack incidents by first-event time",
            "incident_home_rule": "an incident belongs to the split of its first event",
            "purge_rule": "events of validation-born incidents that fall in the test period are excluded from the TEST "
                          "evaluation population (they remain in the stream so entity state stays causal)",
        },
        "splits": {
            "train": _pop_stats(p, p.m_train),
            "validation": _pop_stats(p, p.m_val),
            "test_raw_time_window": _pop_stats(p, p.m_test_raw),
            "test_evaluation_population": _pop_stats(p, p.m_test),
            "legacy_days_21_30_reference": _pop_stats(p, p.m_legacy),
        },
        "incidents_total": n_atk_inc,
        "incidents_by_home_split": by_home,
        "purge": {"events_removed_from_test": int(p.purged.sum()), "incidents": purge_incidents,
                  "events_by_type": {t: int(((lab == t) & p.purged).sum()) for t in ATTACKS}},
        "heldout_entities": {"count": len(held), "fraction": K.HELDOUT_FRACTION, "seed": K.EVAL_SEED, "ids": held,
                             "attacked_among_them": int(len({e for e, l, s in zip(ent, lab, p.split)
                                                              if e in set(held) and l in ATTACKS and s != 'train'}))},
    }
    return m

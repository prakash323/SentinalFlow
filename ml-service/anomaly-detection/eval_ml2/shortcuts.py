"""Dataset shortcut analysis (DIAGNOSTIC, evaluation-only). The dataset is NOT modified.

Question: can attack labels be predicted from a SINGLE raw field (or a one-line rule) that reflects how the synthetic
generator writes attacks rather than genuine behavioural deviation? If so, high detection metrics may partly measure the
generator, not the model.

Each shortcut is a per-event value computed from raw event fields only (no history, no model). Three of them use the
generator's own entity profile (entity_profiles.json: role, home city, IP pool, device fingerprint). The detector has NO
access to that file, so those are 'generator-oracle' shortcuts: they show what the generator's design would allow, not what
the model uses.

For every shortcut we report ROC-AUC (attack vs non-attack), per-attack-type ROC-AUC (vs normal), and the best single
threshold's precision/recall/F1. Then one-line combination rules are scored per attack type on the held-out TEST
population and compared with what the production alert threshold detects.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from . import common as K
from .common import ATTACKS, C


def shortcut_frame(p) -> pd.DataFrame:
    ev = p.events
    prof = pd.read_json(K.DATA / "entity_profiles.json").set_index("entity_id")
    ent = ev["entity_id"]
    ts = pd.to_datetime(ev["timestamp"])
    city = ev["geo_location"].fillna("").str.split("|").str[0]
    df = pd.DataFrame(index=ev.index)
    ip = ev["source_ip"].fillna("")
    df["public_ip"] = (~ip.str.startswith(("10.", "192.168."))).astype(float)
    hour = ts.dt.hour + ts.dt.minute / 60.0
    df["hour_of_day"] = hour
    df["off_hours_band_22_to_05"] = ((hour >= 22) | (hour < 5)).astype(float)
    df["is_weekend"] = (ts.dt.weekday >= 5).astype(float)
    df["failed_auth"] = (ev["auth_success"] == 0).astype(float)
    df["session_duration_s"] = ev["session_duration"].astype(float)
    cmd = ev["command_sequence"].fillna("")
    df["has_command"] = (cmd != "").astype(float)
    df["command_contains_sudo"] = cmd.str.contains("sudo").astype(float)
    df["command_len"] = cmd.apply(lambda s: len([t for t in s.split("|") if t])).astype(float)
    df["foreign_city"] = (~city.isin(C.HOME_CITIES)).astype(float)
    df["sensitive_resource"] = ev["resource_accessed"].isin(C.SENSITIVE).astype(float)
    gap = ts.groupby(ent).diff().dt.total_seconds()
    df["log_gap_since_prev_event_s"] = np.log1p(gap.fillna(gap.median()).clip(lower=0))
    # generator-oracle shortcuts (need entity_profiles.json - not available to the detector)
    home = ent.map(prof["home_city"])
    role = ent.map(prof["role"])
    pools = ent.map(prof["ip_pool"])
    fp_expected = (ent.map(prof["os"]) + "|" + ent.map(prof["mac"]) + "|" + ent.map(prof["protocol"]))
    df["ORACLE_city_differs_from_entity_home"] = (city != home).astype(float)
    df["ORACLE_resource_outside_role_pool"] = [float(r not in C.RESOURCES[ro]) for r, ro in zip(ev["resource_accessed"], role)]
    df["ORACLE_ip_outside_entity_pool"] = [float(i not in pl) for i, pl in zip(ip, pools)]
    df["ORACLE_fingerprint_differs_from_profile"] = (ev["device_fingerprint"] != fp_expected).astype(float)
    df["after_train_period"] = (ts >= p.t_train_end).astype(float)          # attack timing: no attack exists before day 20
    return df


def _best_stump(y, x):
    """Best single-threshold rule (either direction) by F1. Returns precision/recall/F1 and the rule."""
    xs = np.asarray(x, dtype=float)
    uniq = np.unique(xs)
    cand = uniq if len(uniq) <= 60 else np.unique(np.quantile(xs, np.linspace(0.01, 0.99, 99)))
    best = (0.0, None)
    P = int(y.sum())
    for thr in cand:
        for direction in (">=", "<="):
            pred = xs >= thr if direction == ">=" else xs <= thr
            tp = int((pred & (y == 1)).sum())
            fp = int((pred & (y == 0)).sum())
            if tp == 0:
                continue
            pr, rc = tp / (tp + fp), tp / P
            f1 = 2 * pr * rc / (pr + rc)
            if f1 > best[0]:
                best = (f1, {"rule": f"x {direction} {thr:.4g}", "precision": pr, "recall": rc, "f1": f1, "alerts": tp + fp})
    return best[1]


def analyse(p, labels, prod_detected_by_type=None) -> dict:
    """`labels` = whole-dataset labels (DIAGNOSTIC access, logged by the caller)."""
    df = shortcut_frame(p)
    lab = labels["label"].to_numpy()
    out = {"note": "DIAGNOSTIC. Single raw-field shortcuts; ORACLE_* use generator profile data the detector never sees."}
    pops = {"TEST_evaluation_population": p.m_test, "attack_period_days_21_30": p.m_legacy,
            "whole_dataset_all_days": np.ones(len(lab), dtype=bool)}
    table = {}
    for pname, mask in pops.items():
        y = np.isin(lab[mask], ATTACKS).astype(int)
        rows = {}
        for col in df.columns:
            x = df.loc[mask, col].to_numpy()
            if y.sum() == 0 or np.ptp(x) == 0:
                continue
            auc = roc_auc_score(y, x)
            per = {}
            for t in ATTACKS:
                m2 = mask & np.isin(lab, [t, "normal"])
                yy = (lab[m2] == t).astype(int)
                xx = df.loc[m2, col].to_numpy()
                per[t] = float(max(roc_auc_score(yy, xx), 1 - roc_auc_score(yy, xx))) if yy.sum() and np.ptp(xx) > 0 else None
            rows[col] = {"auc_attack_vs_rest": float(auc), "auc_strength": float(max(auc, 1 - auc)),
                         "per_attack_auc_strength": per, "best_single_threshold_rule": _best_stump(y, x)}
        table[pname] = rows
    out["single_field"] = table

    # ---- one-line combination rules on the held-out TEST population and the attack period
    rules = {
        "R1: public_ip OR failed_auth": (df.public_ip > 0) | (df.failed_auth > 0),
        "R2: R1 OR foreign_city": (df.public_ip > 0) | (df.failed_auth > 0) | (df.foreign_city > 0),
        "R3: R2 OR command_contains_sudo OR (sensitive_resource AND off_hours_band)":
            (df.public_ip > 0) | (df.failed_auth > 0) | (df.foreign_city > 0) | (df.command_contains_sudo > 0)
            | ((df.sensitive_resource > 0) & (df.off_hours_band_22_to_05 > 0)),
        "R4 (uses generator profile): R3 OR fingerprint_differs_from_profile":
            (df.public_ip > 0) | (df.failed_auth > 0) | (df.foreign_city > 0) | (df.command_contains_sudo > 0)
            | ((df.sensitive_resource > 0) & (df.off_hours_band_22_to_05 > 0)) | (df.ORACLE_fingerprint_differs_from_profile > 0),
    }
    rr = {}
    for pname in ("TEST_evaluation_population", "attack_period_days_21_30"):
        mask = pops[pname]
        y = np.isin(lab[mask], ATTACKS).astype(int)
        rr[pname] = {}
        for rname, r in rules.items():
            pred = r.to_numpy()[mask]
            tp = int((pred & (y == 1)).sum())
            fp = int((pred & (y == 0)).sum())
            per = {}
            for t in ATTACKS:
                m2 = lab[mask] == t
                per[t] = {"events": int(m2.sum()), "flagged": int(pred[m2].sum()),
                          "rate": float(pred[m2].mean()) if m2.any() else None}
            rr[pname][rname] = {"alerts": int(pred.sum()), "tp": tp, "fp": fp,
                                "precision": tp / max(tp + fp, 1), "recall": tp / max(int(y.sum()), 1), "per_attack": per}
    out["one_line_rules"] = rr
    return out

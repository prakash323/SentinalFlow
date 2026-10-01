"""ML-4 post-hoc analyses used by the report. Deterministic functions of (run outputs, data files); read labels only AFTER the run has unsealed them.
Lives next to compose (eval_ml4/posthoc4.py once both canonical runs have finished)."""
from __future__ import annotations

import json
import math

import numpy as np
import pandas as pd

from eval_ml4 import audits as AU
from eval_ml4 import common as K
from eval_ml4 import drift as DR
from eval_ml4 import features4 as F4
from eval_ml2 import metrics as M2
from eval_ml3 import evaluate as EV

ATT = list(K.ATTACKS)


def wilson(k, n, z=1.96):
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def pooled_incident_detection(S: dict, key: str, ids=None) -> dict:
    """Pooled over datasets: per attack type, incidents detected at the model's first operating point, with a Wilson 95% interval."""
    out = {}
    for t in ATT:
        k = n = 0
        for did, r in S.items():
            if ids and did not in ids:
                continue
            for row in r[key]["incident_table_at_first_threshold"]["rows"]:
                if row["type"] == t:
                    n += 1
                    k += int(row["detected"])
        lo, hi = wilson(k, n)
        out[t] = {"detected": k, "incidents": n, "rate": (k / n) if n else None, "ci95": [lo, hi]}
    k = sum(v["detected"] for v in out.values())
    n = sum(v["incidents"] for v in out.values())
    lo, hi = wilson(k, n)
    out["ALL"] = {"detected": k, "incidents": n, "rate": k / n, "ci95": [lo, hi]}
    return out


BEHAVIOUR_KEYS = {"brute_force": ("src", "city"), "credential_stuffing": ("src", "city"), "impossible_travel": ("src2", "hops"),
                  "lateral_movement": ("foreign", "cmd", "ip"), "device_spoofing": ("variant", "new_ip"), "low_slow_exfil": ("res",)}


def _inc(did):
    return json.load(open(F4.data_paths(did)["incidents"], encoding="utf-8"))


def _sig(i):
    ks = BEHAVIOUR_KEYS[i["type"]]
    vals = []
    for k in ks:
        v = i.get(k)
        vals.append(("multi-hop" if (k == "hops" and isinstance(v, (int, float)) and v > 1) else ("single" if k == "hops" else v)))
    return tuple(vals)


def variant_coverage() -> dict:
    """Behavioural-variant coverage: how many SEALED-test incidents show a behaviour signature that no TRAIN (or TRAIN+VAL) incident shows. Counts alone
    overstate independence: incidents of one profile share a template."""
    seen_train, seen_dev = {t: set() for t in ATT}, {t: set() for t in ATT}
    for did in K.TRAIN_IDS:
        for i in _inc(did):
            seen_train[i["type"]].add(_sig(i))
            seen_dev[i["type"]].add(_sig(i))
    for did in K.VAL_IDS:
        for i in _inc(did):
            seen_dev[i["type"]].add(_sig(i))
    out = {}
    for t in ATT:
        tot = un_tr = un_dev = 0
        sig_test = set()
        for did in K.SEALED_STD_IDS:
            for i in _inc(did):
                if i["type"] != t:
                    continue
                tot += 1
                s = _sig(i)
                sig_test.add(s)
                un_tr += s not in seen_train[t]
                un_dev += s not in seen_dev[t]
        out[t] = {"sealed_incidents": tot, "distinct_behaviours_in_train": len(seen_train[t]), "distinct_behaviours_in_train_plus_val": len(seen_dev[t]),
                  "distinct_behaviours_in_sealed_test": len(sig_test), "sealed_incidents_with_behaviour_unseen_in_train": un_tr,
                  "sealed_incidents_with_behaviour_unseen_in_train_or_val": un_dev,
                  "unseen_in_train_share": (un_tr / tot) if tot else None, "unseen_in_train_or_val_share": (un_dev / tot) if tot else None}
    return out


def near_dup_by_profile(A: dict) -> dict:
    nd = A.get("near_duplicates", {}).get("per_type", {})
    out = {}
    for t, v in nd.items():
        for r in v.get("rows", []):
            b = out.setdefault(r["test_profile"], {"incidents": 0, "near_duplicate": 0, "same_profile_neighbour": 0})
            b["incidents"] += 1
            b["near_duplicate"] += int(r["near_duplicate"])
            b["same_profile_neighbour"] += int(r["same_profile_neighbour"])
    for p, b in out.items():
        b["near_duplicate_share"] = b["near_duplicate"] / b["incidents"]
        b["same_profile_neighbour_share"] = b["same_profile_neighbour"] / b["incidents"]
    return out


def ds_detection_by_variant(S: dict, keys=("ml4/frozen", "ml4/adaptive", "ml3/frozen", "shipped/adaptive")) -> dict:
    out = {}
    for did, r in S.items():
        for key in keys:
            for row in r[key]["incident_table_at_first_threshold"]["rows"]:
                if row["type"] != "device_spoofing":
                    continue
                g = out.setdefault((row.get("variant"), bool(row.get("new_ip"))), {"incidents": 0, **{k: 0 for k in keys}})
                if key == keys[0]:
                    g["incidents"] += 1
                g[key] += int(row["detected"])
    return {f"{v} / new IP={n}": g for (v, n), g in sorted(out.items(), key=lambda kv: str(kv[0]))}


def behaviour_detection(S: dict, key="ml4/frozen") -> dict:
    """Detection of ml4 by behaviour variant, pooled over sealed standard datasets (which attacker behaviours are missed)."""
    out = {}
    for did, r in S.items():
        for row in r[key]["incident_table_at_first_threshold"]["rows"]:
            t = row["type"]
            sig = _sig({**row})
            g = out.setdefault(t, {}).setdefault(str(sig), {"incidents": 0, "detected": 0})
            g["incidents"] += 1
            g["detected"] += int(row["detected"])
    return out


def rule_share_of_true_positives(run_dir, S, cfg, ids) -> dict:
    """Share of the model's TRUE-POSITIVE alerts (ml4 frozen at the transferred threshold) that the trivial rule R1 also flags, per dataset."""
    P = np.load(run_dir / "predictions.npz")
    thr = cfg["thresholds"]["frozen"]["f1_optimal"]
    out = {}
    for did in ids:
        f = P[f"sealed__ml4__frozen__{did}"]
        ev = F4.load_events4(did)
        n_onb = int((ev["timestamp"] < F4.onboarding_end(did, ev)).sum())
        sd = AU.shortcut_frame(ev, n_onb).iloc[n_onb:].reset_index(drop=True)
        lab = pd.read_csv(F4.data_paths(did)["labels"]).set_index("event_id").iloc[n_onb:]
        y = EV.is_attack(lab["label"].to_numpy(dtype=object)).astype(bool)
        alert = f >= thr
        r1 = ((sd.public_ip > 0) | (sd.failed_auth > 0)).to_numpy()
        tp = alert & y
        out[did] = {"true_positive_alerts": int(tp.sum()), "share_also_flagged_by_R1": float(r1[tp].mean()) if tp.any() else None,
                    "R1_flags_share_of_all_events": float(r1.mean())}
    return out


def drift_matched(run_dir, cfg) -> dict:
    """Frozen vs adaptive at a MATCHED operating point: every variant's threshold is set on its own BEFORE-drift negatives so that FPR(before) = 0.5%, then
    the same threshold is applied during and after the drift. This removes the threshold-choice confound of comparing two modes at different thresholds."""
    P = np.load(run_dir / "predictions.npz")
    feat_man = json.load(open(run_dir / "features_manifest.json", encoding="utf-8"))["datasets"]
    out = {}
    for did in K.SEALED_DRIFT_IDS:
        n_onb = feat_man[did]["n_onboarding"]
        ev = F4.load_events4(did)
        day = ((pd.to_datetime(ev["timestamp"]).iloc[n_onb:] - pd.Timestamp("2026-06-01")).dt.total_seconds() / 86400.0).to_numpy()
        lab = pd.read_csv(F4.data_paths(did)["labels"]).set_index("event_id").iloc[n_onb:]
        labels = lab["label"].to_numpy(dtype=object)
        aid = lab["attack_id"].to_numpy(dtype=object)
        ph = DR.phase_of(day)
        incs = _inc(did)
        y = EV.is_attack(labels).astype(int)
        neg = y == 0
        out[did] = {}
        for name, _, _ in DR.VARIANTS:
            f = P[f"drift__{did}__fused__{name}"]
            b_neg = f[(ph == "before") & neg]
            thr = float(np.quantile(b_neg, 1 - 0.005))
            alert = f >= thr
            row = {"threshold": thr}
            for p in DR.PHASES:
                m = ph == p
                yy = y[m]
                bd = labels[m] == "benign_drift"
                nrm = labels[m] == "normal"
                inc_ids = [i["attack_id"] for i in incs if i.get("period") == p]
                det = sum(bool(alert[aid == a].any()) for a in inc_ids)
                row[p] = {"recall": float(alert[m][yy == 1].mean()) if (yy == 1).any() else None, "fpr_normal": float(alert[m][nrm].mean()) if nrm.any() else None,
                          "fpr_benign_drift": float(alert[m][bd].mean()) if bd.any() else None, "incident_recall": (det / len(inc_ids)) if inc_ids else None,
                          "incidents": len(inc_ids), "alert_rate": float(alert[m].mean())}
            out[did][name] = row
    return out

"""Controlled frozen-vs-adaptive baseline evaluation under benign drift (requirement 9).

Design (pre-registered): six datasets share seed 601 and profile P0 at reduced size; DR-ctrl has no drift, each other dataset applies ONE drift kind
(hours / resources / location / device / volume) to the same 40% of entities as a regime change ramping over days 22-28 and persisting afterwards.
Benign events changed by the drift are labelled benign_drift (a NEGATIVE class). Attacks are spread evenly over before (<22) / during (22-28) / after (>=28).
Variants scored with the SAME frozen global model and weights, differing only in the baseline:
  frozen              TRAIN-time profile, never updated
  adaptive_a0.005 / adaptive_a0.02 (production alpha) / adaptive_a0.08   EWMA with the production poisoning guard
  adaptive_a0.02_noguard   the same without the guard (diagnostic: shows what the guard protects against)
Nothing here decides which baseline is better in advance; every number is reported per drift kind and per phase, paired against DR-ctrl.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from . import common as K
from . import features4 as F4
from . import xfer as X
from .common import ATTACKS
from eval_ml2 import metrics as M2
from eval_ml3 import evaluate as EV

# (name, alpha, guard) with guard in {None (frozen), "alert", "prod", "none"}:
#   alert = an event the frozen model would ALERT on never updates the baseline (production design intent)
#   prod  = only an event above the whole TRAIN fused range is blocked (the ML-3 / shipped-threshold-99.5 semantics; weak under baseline-heavy weights)
#   none  = no guard
VARIANTS = [("frozen", None, None), ("adaptive_a0.005", 0.005, "alert"), ("adaptive_a0.02", 0.02, "alert"), ("adaptive_a0.08", 0.08, "alert"),
            ("adaptive_a0.02_prodguard", 0.02, "prod"), ("adaptive_a0.02_noguard", 0.02, "none")]
PHASES = ["before", "during", "after"]


def phase_of(day: np.ndarray) -> np.ndarray:
    return np.where(day < K.DRIFT_START, "before", np.where(day < K.DRIFT_END, "during", "after"))


def score_dataset(did, model, cfg, feat_dir, data_dir=None) -> dict:
    """Label-free: signals + every variant's fused array for the evaluation rows of one drift dataset."""
    import torch
    torch.set_num_threads(1)
    L = F4.Loaded(did, feat_dir, data_dir)
    sig = X.signals("ml4", model, L)
    w = cfg["fusion_weights"]
    calib_fused = np.asarray(cfg["calib_fused"])
    out = {"event_id": L.X_eval["event_id"].to_numpy(), "day": ((L.ts[L.n_onb:] - pd.Timestamp("2026-06-01")).total_seconds() / 86400.0).to_numpy(),
           "ts_ns": L.ts[L.n_onb:].asi8, "b_frozen": sig["b_frozen"], "iso": sig["iso"], "seq": sig["seq"]}
    for name, alpha, guard in VARIANTS:
        mode = "frozen" if name == "frozen" else "adaptive"
        level = {"alert": cfg["guard_alert_threshold"], "prod": cfg["fused_max"], "none": float("inf"), None: float("inf")}[guard]
        r = X.replay_modes("ml4", model, L, sig, w, level, calib_fused, alpha=alpha, modes=(mode,))[mode]
        out[f"fused__{name}"] = r["fused"]
        out[f"b__{name}"] = r["b"]
        if "guarded" in r:
            out[f"guarded__{name}"] = r["guarded"]
    return out


def evaluate(did, arrs, lab, incidents, thresholds_by_mode) -> dict:
    """arrs: output of score_dataset; lab: labels for the evaluation rows (DataFrame indexed by event_id)."""
    L = lab.loc[arrs["event_id"]]
    labels = L["label"].to_numpy(dtype=object)
    aid = L["attack_id"].to_numpy(dtype=object)
    ph = phase_of(arrs["day"])
    affected = set(pd.Series(aid[labels == "benign_drift"]).unique()) if (labels == "benign_drift").any() else set()
    res = {"dataset": did, "events": int(len(labels)), "phase_events": {p: int((ph == p).sum()) for p in PHASES}, "variants": {}}
    for name, _, _ in VARIANTS:
        fused = arrs[f"fused__{name}"]
        mode = "frozen" if name == "frozen" else "adaptive"
        thr = thresholds_by_mode[mode]
        v = {"threshold": thr, "overall": {}, "phases": {}}
        alert = fused >= thr
        y = EV.is_attack(labels).astype(int)
        v["overall"] = {**M2.rank_metrics(y, fused), **{k: M2.operating_point(y, alert)[k] for k in ("precision", "recall", "f1", "false_positive_rate", "alert_rate", "tp", "fp", "fn")},
                        "macro_type_pr_auc": EV.macro_type_prauc(labels, fused)["macro_pr_auc"]}
        for p in PHASES:
            m = ph == p
            yy = y[m]
            op = M2.operating_point(yy, alert[m])
            neg_n = np.isin(labels[m], ("normal",))
            bd = labels[m] == "benign_drift"
            inc_ids = [i["attack_id"] for i in incidents if i.get("period") == p]
            det = [i for i in inc_ids if alert[np.asarray(aid) == i].any()] if inc_ids else []
            v["phases"][p] = {**M2.rank_metrics(yy, fused[m]), "events": int(m.sum()), "attack_events": int(yy.sum()),
                              "precision": op["precision"], "recall": op["recall"], "f1": op["f1"], "false_positive_rate": op["false_positive_rate"],
                              "alert_rate": op["alert_rate"], "fp": op["fp"],
                              "fpr_on_normal": float(alert[m][neg_n].mean()) if neg_n.any() else None,
                              "fpr_on_benign_drift": float(alert[m][bd].mean()) if bd.any() else None, "benign_drift_events": int(bd.sum()),
                              "incidents": len(inc_ids), "incidents_detected": len(det),
                              "incident_recall": (len(det) / len(inc_ids)) if inc_ids else None,
                              "macro_type_pr_auc": EV.macro_type_prauc(labels[m], fused[m])["macro_pr_auc"]}
        # drifted entities vs the rest, in the AFTER phase (regime persists)
        ent_dr = np.isin(aid, list(affected)) & (labels == "benign_drift")
        v["benign_drift_fpr_all_phases"] = float(alert[labels == "benign_drift"].mean()) if (labels == "benign_drift").any() else None
        v["normal_fpr_all_phases"] = float(alert[labels == "normal"].mean())
        if f"guarded__{name}" in arrs:
            v["updates_blocked_by_guard"] = int(arrs[f"guarded__{name}"].sum())
        res["variants"][name] = v
    return res


def paired_effects(results: dict) -> dict:
    """Effect of each drift kind = (drift dataset) - (DR-ctrl), per variant and phase, for the metrics that matter."""
    ctrl = results["DR-ctrl"]
    out = {}
    for did, r in results.items():
        if did == "DR-ctrl":
            continue
        out[did] = {}
        for name, v in r["variants"].items():
            row = {}
            for p in PHASES:
                a, b = v["phases"][p], ctrl["variants"][name]["phases"][p]
                row[p] = {m: (a[m] - b[m]) if (a.get(m) is not None and b.get(m) is not None) else None
                          for m in ("pr_auc", "recall", "precision", "false_positive_rate", "alert_rate", "incident_recall", "macro_type_pr_auc")}
            out[did][name] = row
    return out

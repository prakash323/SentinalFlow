"""Deployment-specific operating thresholds (Phase 4).

A DEPLOYMENT is a dataset (profile + seed). Its calibration population is its own attack-free ONBOARDING TAIL: the last (1 - ONBOARD_HEAD_FRACTION) of its
onboarding rows, scored out-of-sample (the per-entity baseline is fitted on the head only). Nothing else is used to set its threshold:
    t_d(alpha) = the (1 - alpha) quantile of the tail's fused scores           alpha = target false-alert rate (an operational parameter)
Universal comparators: the ML-4 evaluation threshold, and a threshold pooled from the OTHER deployments' tails (leave-one-out).
Labels are used only to EVALUATE a threshold on a deployment's evaluation period, and (for the reference 'oracle') to show how much an ideal threshold varies.
"""
from __future__ import annotations

import numpy as np

from . import common as K
from eval_ml3 import evaluate as EV
from eval_ml2 import metrics as M2


def rule_threshold(tail: np.ndarray, alpha: float) -> float:
    return float(np.quantile(np.asarray(tail, float), 1.0 - alpha, method="higher"))


def evaluate_threshold(fused, labels, aid, thr) -> dict:
    y = EV.is_attack(labels).astype(int)
    alert = np.asarray(fused) >= thr
    op = M2.operating_point(y, alert)
    inc = M2.incident_detection(alert, np.asarray(aid, dtype=object), y.astype(bool))
    return {"threshold": float(thr), "alert_rate": op["alert_rate"], "false_positive_rate": op["false_positive_rate"], "precision": op["precision"], "recall": op["recall"],
            "f1": op["f1"], "tp": op["tp"], "fp": op["fp"], "fn": op["fn"], "incidents": inc["incidents"], "incidents_detected": inc["detected"],
            "incident_recall": inc["detected"] / inc["incidents"] if inc["incidents"] else None}


def oracle_f1(fused, labels) -> dict:
    """LABEL-USING reference (the F1-optimal threshold of the evaluated period itself): shows how much an ideal threshold varies. Not selectable in practice."""
    y = EV.is_attack(labels).astype(int)
    r = EV.f1_optimal_threshold(y, fused)
    return {"threshold": r["threshold"], "f1": r["f1"], "precision": r["precision"], "recall": r["recall"]}


def dispersion(values) -> dict:
    v = np.asarray([x for x in values if x is not None], float)
    return {"n": int(len(v)), "min": float(v.min()), "max": float(v.max()), "mean": float(v.mean()), "sd": float(v.std(ddof=1)) if len(v) > 1 else 0.0,
            "cv": float(v.std(ddof=1) / v.mean()) if len(v) > 1 and v.mean() != 0 else None, "range": float(v.max() - v.min()), "median": float(np.median(v))}


def study(data: dict, alphas=K.ALPHAS, ml4_threshold: float | None = None) -> dict:
    """data: did -> {tail, fused, labels, aid, profile}. Returns per-deployment rows for every rule plus the cross-deployment dispersion."""
    ids = list(data)
    out = {"alphas": list(alphas), "deployments": {}, "dispersion": {}, "selection": {}}
    for d in ids:
        r = data[d]
        row = {"profile": r["profile"], "onboarding_tail_events": int(len(r["tail"])), "eval_events": int(len(r["fused"])), "attack_rate": float(EV.is_attack(r["labels"]).mean()),
               "per_alpha": {}, "oracle": oracle_f1(r["fused"], r["labels"])}
        others = np.concatenate([data[o]["tail"] for o in ids if o != d]) if len(ids) > 1 else r["tail"]
        for a in alphas:
            t_own = rule_threshold(r["tail"], a)
            t_uni = rule_threshold(others, a)
            row["per_alpha"][str(a)] = {"deployment_specific": evaluate_threshold(r["fused"], r["labels"], r["aid"], t_own),
                                        "universal_pooled_from_other_deployments": evaluate_threshold(r["fused"], r["labels"], r["aid"], t_uni)}
        if ml4_threshold is not None:
            row["ml4_global_threshold"] = evaluate_threshold(r["fused"], r["labels"], r["aid"], ml4_threshold)
        out["deployments"][d] = row
    for a in alphas:
        k = str(a)
        own = [out["deployments"][d]["per_alpha"][k]["deployment_specific"] for d in ids]
        uni = [out["deployments"][d]["per_alpha"][k]["universal_pooled_from_other_deployments"] for d in ids]
        out["dispersion"][k] = {
            "threshold_value_deployment_specific": dispersion([x["threshold"] for x in own]),
            "realized_fpr_over_target_deployment_specific": dispersion([x["false_positive_rate"] / a for x in own]),
            "realized_fpr_over_target_universal": dispersion([x["false_positive_rate"] / a for x in uni]),
            "alert_rate_deployment_specific": dispersion([x["alert_rate"] for x in own]), "alert_rate_universal": dispersion([x["alert_rate"] for x in uni]),
            "f1_deployment_specific": dispersion([x["f1"] for x in own]), "f1_universal": dispersion([x["f1"] for x in uni]),
            "recall_deployment_specific": dispersion([x["recall"] for x in own]), "precision_deployment_specific": dispersion([x["precision"] for x in own]),
            "incident_recall_deployment_specific": dispersion([x["incident_recall"] for x in own]),
            "share_within_band_deployment_specific": float(np.mean([K.ONBOARD_OK_BAND[0] <= x["false_positive_rate"] / a <= K.ONBOARD_OK_BAND[1] for x in own])),
            "share_within_band_universal": float(np.mean([K.ONBOARD_OK_BAND[0] <= x["false_positive_rate"] / a <= K.ONBOARD_OK_BAND[1] for x in uni]))}
    out["oracle_threshold_dispersion"] = dispersion([out["deployments"][d]["oracle"]["threshold"] for d in ids])
    if ml4_threshold is not None:
        m = [out["deployments"][d]["ml4_global_threshold"] for d in ids]
        out["ml4_global_threshold_dispersion"] = {"threshold": ml4_threshold, "alert_rate": dispersion([x["alert_rate"] for x in m]), "false_positive_rate": dispersion([x["false_positive_rate"] for x in m]),
                                                  "f1": dispersion([x["f1"] for x in m])}
    return out


def select_alpha(dev_study: dict) -> dict:
    """Pre-registered rule (K.ALPHA_SELECTION): the alpha with the highest mean F1 of the deployment-specific rule over the DEV deployments; ties -> larger alpha."""
    scores = {a: dev_study["dispersion"][str(a)]["f1_deployment_specific"]["mean"] for a in dev_study["alphas"]}
    best = max(scores.values())
    alpha = max(a for a, s in scores.items() if abs(s - best) < 1e-12)
    return {"rule": K.ALPHA_SELECTION, "mean_f1_by_alpha": {str(a): s for a, s in scores.items()}, "selected_alpha": alpha}


def onboarding_volume_study(data: dict, alpha: float, sizes=K.ONBOARD_SIZES, draws=K.ONBOARD_DRAWS, seed=K.ML5_SEED) -> dict:
    """How many benign onboarding events are needed for a stable deployment threshold? For each deployment and each size k: draw k benign tail events at random
    (seeded), set the threshold at the (1 - alpha) quantile, and measure the realized false-alert rate on the evaluation period."""
    out = {"alpha": alpha, "sizes": list(sizes), "per_deployment": {}, "pooled": {}}
    rng = np.random.default_rng(seed)
    pool = {k: [] for k in sizes}
    for d, r in data.items():
        y = EV.is_attack(r["labels"]).astype(int)
        neg = r["fused"][y == 0]
        tail = np.asarray(r["tail"], float)
        row = {}
        for k in sizes:
            if k > len(tail):
                row[str(k)] = {"available": False, "tail_events": int(len(tail))}
                continue
            ratios = []
            for _ in range(draws):
                sub = tail[rng.choice(len(tail), size=k, replace=False)]
                t = rule_threshold(sub, alpha)
                ratios.append(float((neg >= t).mean()) / alpha)
            ratios = np.array(ratios)
            row[str(k)] = {"available": True, "median_ratio": float(np.median(ratios)), "p10": float(np.quantile(ratios, 0.1)), "p90": float(np.quantile(ratios, 0.9)),
                           "share_within_band": float(np.mean((ratios >= K.ONBOARD_OK_BAND[0]) & (ratios <= K.ONBOARD_OK_BAND[1])))}
            pool[k].append(row[str(k)]["share_within_band"])
        out["per_deployment"][d] = row
    for k in sizes:
        if pool[k]:
            out["pooled"][str(k)] = {"deployments": len(pool[k]), "mean_share_within_band": float(np.mean(pool[k])), "min_share_within_band": float(np.min(pool[k]))}
    ok = [k for k in sizes if str(k) in out["pooled"] and out["pooled"][str(k)]["min_share_within_band"] >= K.ONBOARD_OK_SHARE]
    out["minimum_size_meeting_criterion"] = min(ok) if ok else None
    out["criterion"] = (f"in at least {int(K.ONBOARD_OK_SHARE * 100)}% of random onboarding draws the realized false-alert rate is within "
                        f"{K.ONBOARD_OK_BAND[0]}x-{K.ONBOARD_OK_BAND[1]}x of the target, for EVERY deployment")
    return out

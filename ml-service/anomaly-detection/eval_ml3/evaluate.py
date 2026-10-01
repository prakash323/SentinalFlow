"""ML-3 evaluation helpers. Metric definitions are the ML-2 ones (eval_ml2.metrics, imported unchanged) so that candidate,
ML-2 streaming baseline and shipped-model numbers are computed identically. Added here: the macro per-type selection
criterion, the validation-only F1-optimal threshold and a population evaluator.
"""
from __future__ import annotations

import numpy as np

from . import common as K
from .common import ATTACKS
from eval_ml2 import metrics as M2

NEGATIVE = ("normal", "benign_drift")


def is_attack(labels) -> np.ndarray:
    return np.isin(np.asarray(labels, dtype=object), ATTACKS)


def macro_type_prauc(labels, score) -> dict:
    """Selection criterion. For every attack type present: PR-AUC of (that type) vs all NEGATIVE events of the population
    (other attack types excluded), then the unweighted mean over the types present. One high-volume type cannot decide it."""
    labels = np.asarray(labels, dtype=object)
    score = np.asarray(score, dtype=float)
    neg = np.isin(labels, NEGATIVE)
    per = {}
    for t in ATTACKS:
        m = labels == t
        if not m.any():
            continue
        mm = m | neg
        per[t] = M2.rank_metrics((labels[mm] == t).astype(int), score[mm])["pr_auc"]
    vals = [v for v in per.values() if v is not None]
    return {"macro_pr_auc": float(np.mean(vals)) if vals else None, "per_type_pr_auc": per, "types": sorted(per)}


def f1_optimal_threshold(y, score) -> dict:
    """Threshold t (alert iff score >= t) maximising event-level F1 on the given population. Ties in F1 -> the highest threshold."""
    y = np.asarray(y).astype(int)
    s = np.asarray(score, dtype=float)
    order = np.argsort(-s, kind="stable")
    ss, yy = s[order], y[order]
    tp = np.cumsum(yy)
    k = np.arange(1, len(ss) + 1)
    P = int(yy.sum())
    prec = tp / k
    rec = tp / max(P, 1)
    f1 = np.where(prec + rec > 0, 2 * prec * rec / np.maximum(prec + rec, 1e-300), 0.0)
    valid = np.r_[ss[:-1] != ss[1:], True]                       # only cut between distinct scores
    f1 = np.where(valid, f1, -1.0)
    j = int(np.argmax(f1))
    return {"threshold": float(ss[j]), "f1": float(f1[j]), "alerts": int(k[j]), "precision": float(prec[j]), "recall": float(rec[j])}


def operating(labels, aid, alert) -> dict:
    y = is_attack(labels).astype(int)
    a = np.asarray(alert, dtype=bool)
    op = M2.operating_point(y, a)
    inc = M2.incident_detection(a, np.asarray(aid, dtype=object), is_attack(labels))
    op["incidents"] = inc["incidents"]
    op["incidents_detected"] = inc["detected"]
    op["incidents_missed"] = inc["missed_ids"]
    op["incidents_detected_ids"] = inc["detected_ids"]
    return op


def per_attack_table(labels, aid, fused, alert, topk_mask) -> dict:
    labels = np.asarray(labels, dtype=object)
    aid = np.asarray(aid, dtype=object)
    y = is_attack(labels).astype(int)
    neg = np.isin(labels, NEGATIVE)
    out = {}
    for t in ATTACKS:
        m = labels == t
        row = {"events": int(m.sum()), "incidents": int(len(set(aid[m]) - {""}))}
        if m.any():
            mm = m | neg
            rm = M2.rank_metrics((labels[mm] == t).astype(int), np.asarray(fused)[mm])
            inc = M2.incident_detection(alert, aid, m)
            inc_top = M2.incident_detection(topk_mask, aid, m)
            row.update({"alerted_events": int(alert[m].sum()), "event_detection_rate": float(alert[m].mean()),
                        "incidents_detected": inc["detected"], "incident_detection_rate": inc["detected"] / max(row["incidents"], 1),
                        "detected_incident_ids": inc["detected_ids"], "missed_incident_ids": inc["missed_ids"],
                        "events_in_top_1pct": int(topk_mask[m].sum()), "incidents_detected_in_top_1pct": inc_top["detected"],
                        "roc_auc_vs_negatives": rm["roc_auc"], "pr_auc_vs_negatives": rm["pr_auc"],
                        "fused_dist": M2.dist(np.asarray(fused)[m])})
        out[t] = row
    return out


def evaluate_population(name, labels, aid, fused, risk, thresholds: dict, extra_alerts: dict | None = None) -> dict:
    """`thresholds`: name -> ('fused'|'risk', value). Returns the full metric block for one population."""
    labels = np.asarray(labels, dtype=object)
    aid = np.asarray(aid, dtype=object)
    fused = np.asarray(fused, dtype=float)
    risk = np.asarray(risk, dtype=float)
    y = is_attack(labels).astype(int)
    out = {"population": name, "events": int(len(y)), "attack_events": int(y.sum()), "attack_rate": float(y.mean()),
           "incidents": int(len(set(aid[y == 1]) - {""}))}
    out["ranking_fused"] = M2.rank_metrics(y, fused)
    out["ranking_risk"] = M2.rank_metrics(y, risk)
    tk = M2.top_k(y, fused, K.TOPK_FRAC)
    out["top_1pct_by_fused"] = tk
    out["top_1pct_by_risk"] = M2.top_k(y, risk, K.TOPK_FRAC)
    k = tk["k"]
    top_mask = np.zeros(len(y), dtype=bool)
    top_mask[np.argsort(-fused, kind="stable")[:k]] = True
    out["fused_dist"] = M2.dist(fused)
    out["risk_dist"] = M2.dist(risk)
    out["macro_type_pr_auc_fused"] = macro_type_prauc(labels, fused)
    ops = {}
    for nm, (kind, v) in thresholds.items():
        a = (fused if kind == "fused" else risk) >= v
        o = operating(labels, aid, a)
        o["threshold_kind"], o["threshold_value"] = kind, float(v)
        o["per_attack"] = per_attack_table(labels, aid, fused, a, top_mask)
        ops[nm] = o
    out["operating_points"] = ops
    out["saturation"] = M2.saturation(risk, fused)
    neg = np.isin(labels, NEGATIVE)
    out["negatives_at_or_above_train_fused_max"] = int((risk[neg] >= 100.0).sum())
    return out

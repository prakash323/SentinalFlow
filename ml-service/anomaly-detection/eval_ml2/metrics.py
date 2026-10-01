"""Metric definitions for ML-2 (evaluation-only). Every metric is defined here once.

POPULATION   the set of evaluated events (e.g. TEST). N = its size, P = number of positive (attack) events.
POSITIVE     an attack event (brute_force, credential_stuffing, impossible_travel, lateral_movement, device_spoofing,
             low_slow_exfil). normal and benign_drift are NEGATIVE (benign_drift is legitimate behaviour).
ALERT        score >= operating threshold (an event-level decision; there is no queue and no de-duplication).

Precision@1% / Recall@1%   k = floor(0.01 * N) events with the highest score IN THE POPULATION; precision = TP_k / k,
             recall = TP_k / P. NO padded analyst queue, no incident de-duplication. When several events tie at the
             cut-off score (streaming risk saturates at exactly 100.0) the metric is reported three ways:
               expected  = TP expected under a uniformly random tie-break inside the tie group,
               lower/upper = the worst/best case tie-break.
             Ranking by the continuous fused score (pre-mapping) has no ties and is reported separately.
Incident detected   >=1 alert among the incident's events inside the population.
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score


def _safe(f, *a):
    try:
        return float(f(*a))
    except ValueError:
        return None


def rank_metrics(y, score) -> dict:
    y = np.asarray(y).astype(int)
    if y.sum() == 0 or y.sum() == len(y):
        return {"pr_auc": None, "roc_auc": None}
    return {"pr_auc": _safe(average_precision_score, y, score), "roc_auc": _safe(roc_auc_score, y, score)}


def operating_point(y, alert) -> dict:
    y = np.asarray(y).astype(int)
    a = np.asarray(alert).astype(bool)
    tp = int((a & (y == 1)).sum())
    fp = int((a & (y == 0)).sum())
    fn = int((~a & (y == 1)).sum())
    tn = int((~a & (y == 0)).sum())
    P, N = tp + fn, len(y)
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / P if P else None
    f1 = (2 * prec * rec / (prec + rec)) if (prec is not None and rec is not None and (prec + rec) > 0) else (0.0 if P else None)
    return {"events": N, "attack_events": P, "alerts": tp + fp, "alert_rate": (tp + fp) / N if N else None,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": prec, "recall": rec, "f1": f1,
            "false_positive_rate": fp / (fp + tn) if (fp + tn) else None,
            "false_negative_rate": fn / P if P else None}


def top_k(y, score, frac=0.01) -> dict:
    """Tie-aware Precision@k / Recall@k with k = floor(frac * N). See module docstring."""
    y = np.asarray(y).astype(int)
    s = np.asarray(score, dtype=float)
    N, P = len(y), int(y.sum())
    k = max(1, int(np.floor(frac * N)))
    order = np.argsort(-s, kind="stable")
    cut = s[order[k - 1]]
    above = s > cut
    tie = s == cut
    n_above = int(above.sum())
    slots = k - n_above                                # how many tie-group members fit in the top-k
    tie_n = int(tie.sum())
    tp_above = int(y[above].sum())
    tie_pos = int(y[tie].sum())
    exp_tp = tp_above + (tie_pos * slots / tie_n if tie_n else 0.0)
    lo = tp_above + max(0, slots - (tie_n - tie_pos))   # worst case: negatives fill the slots first
    hi = tp_above + min(slots, tie_pos)                 # best case: positives fill the slots first
    return {"k": k, "events": N, "attack_events": P, "cutoff_score": float(cut), "tie_group_size": tie_n,
            "tie_slots_used": int(slots), "tie_straddles_cutoff": bool(tie_n > slots),
            "tp_expected": float(exp_tp), "tp_lower": int(lo), "tp_upper": int(hi),
            "precision_expected": exp_tp / k, "precision_lower": lo / k, "precision_upper": hi / k,
            "recall_expected": exp_tp / P if P else None, "recall_lower": lo / P if P else None,
            "recall_upper": hi / P if P else None,
            "max_possible_recall": min(k, P) / P if P else None}


def dist(x) -> dict:
    x = np.asarray(x, dtype=float)
    if len(x) == 0:
        return {"n": 0}
    return {"n": int(len(x)), "min": float(x.min()), "median": float(np.median(x)),
            "p90": float(np.quantile(x, .90)), "p95": float(np.quantile(x, .95)),
            "p99": float(np.quantile(x, .99)), "max": float(x.max())}


def saturation(risk, fused=None, conf=None) -> dict:
    """Counts of values at/above the ceilings, on the risk (0-100), anomalyScore (=risk/100, API-rounded) and fused scales."""
    r = np.asarray(risk, dtype=float)
    a = np.round(r / 100.0, 6)                          # exactly what api.py returns as anomalyScore
    out = {"n": int(len(r)),
           "risk_eq_100": int((r >= 100.0).sum()), "anomaly_eq_1_0": int((a >= 1.0).sum()),
           "risk_gt_99": int((r > 99.0).sum()), "risk_ge_99": int((r >= 99.0).sum()),
           "risk_gt_99_5": int((r > 99.5).sum()), "risk_gt_99_9": int((r > 99.9).sum()),
           "anomaly_ge_0_99": int((a >= 0.99).sum()), "anomaly_ge_0_995": int((a >= 0.995).sum()),
           "anomaly_ge_0_999": int((a >= 0.999).sum()),
           "distinct_risk_values_above_99_5": int(len(np.unique(np.round(r[r > 99.5], 9)))),
           "share_of_high_scores_tied_at_max": float(((r >= 100.0).sum() / max((r > 99.5).sum(), 1)))}
    if fused is not None:
        f = np.asarray(fused, dtype=float)
        out.update({"fused_ge_0_99": int((f >= 0.99).sum()), "fused_ge_0_999": int((f >= 0.999).sum()),
                    "fused_eq_1_0": int((f >= 1.0).sum()), "fused_max": float(f.max())})
    if conf is not None and len(conf):
        c = np.asarray(conf, dtype=float)
        out.update({"classifier_conf_n": int(len(c)), "classifier_conf_ge_0_99": int((c >= 0.99).sum()),
                    "classifier_conf_ge_0_999": int((c >= 0.999).sum()),
                    "classifier_conf_api_rounded_eq_1_0": int((np.round(c, 3) >= 1.0).sum())})
    return out


def incident_detection(alert, aid, is_pos) -> dict:
    """Detected incidents = incidents with >=1 alert. `aid` may contain '' for non-incident rows."""
    a = np.asarray(alert).astype(bool)
    aid = np.asarray(aid)
    pos = np.asarray(is_pos).astype(bool)
    ids = sorted(set(aid[pos]) - {""})
    hit = [i for i in ids if a[aid == i].any()]
    return {"incidents": len(ids), "detected": len(hit), "detected_ids": hit,
            "missed_ids": sorted(set(ids) - set(hit))}


def per_attack(labels, aid, risk, fused, alert, topk_mask, y_bin) -> dict:
    """Per-attack-type table on one population. `topk_mask` = events inside the population's top-1% (by fused)."""
    labels = np.asarray(labels)
    out = {}
    neg = (y_bin == 0)
    for t in ["brute_force", "credential_stuffing", "impossible_travel", "lateral_movement", "device_spoofing", "low_slow_exfil"]:
        m = labels == t
        n = int(m.sum())
        row = {"events": n, "incidents": int(len(set(np.asarray(aid)[m]) - {""}))}
        if n == 0:
            out[t] = row
            continue
        a_m = alert[m]
        tk = topk_mask[m]
        # ranking quality of this type against the population's negatives (independent of any threshold)
        mm = m | neg
        rm = rank_metrics((labels[mm] == t).astype(int), fused[mm])
        rr = rank_metrics((labels[mm] == t).astype(int), risk[mm])
        inc_thr = incident_detection(alert, np.asarray(aid), m)
        inc_top = incident_detection(topk_mask, np.asarray(aid), m)
        row.update({
            "detected_events_at_production_threshold": int(a_m.sum()),
            "missed_events_at_production_threshold": int((~a_m).sum()),
            "detection_rate_at_production_threshold": float(a_m.mean()),
            "alerts": int(a_m.sum()),
            "incidents_detected_at_production_threshold": inc_thr["detected"],
            "detected_events_in_top_1pct": int(tk.sum()),
            "missed_events_in_top_1pct": int((~tk).sum()),
            "detection_rate_in_top_1pct": float(tk.mean()),
            "incidents_detected_in_top_1pct": inc_top["detected"],
            "risk_dist": dist(risk[m]), "fused_dist": dist(fused[m]),
            "median_risk": float(np.median(risk[m])), "median_anomaly_score": float(np.median(risk[m]) / 100.0),
            "roc_auc_vs_negatives_fused": rm["roc_auc"], "pr_auc_vs_negatives_fused": rm["pr_auc"],
            "roc_auc_vs_negatives_risk": rr["roc_auc"],
        })
        out[t] = row
    return out


def classification_metrics(y_true, y_pred, labels) -> dict:
    """Multi-class metrics. Macro averages are over classes that have support (>=1 true row) in y_true; a class with
    support that is never predicted contributes precision 0 / recall 0 (it is NOT silently dropped)."""
    from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
    y_true = np.asarray(y_true, dtype=object)
    y_pred = np.asarray(y_pred, dtype=object)
    labels = list(labels)
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    present = [i for i, n in enumerate(s) if n > 0]
    per = {labels[i]: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]), "support": int(s[i]),
                       "predicted": int((y_pred == labels[i]).sum())} for i in range(len(labels))}
    w = np.array([s[i] for i in present], dtype=float)
    weighted_f1 = float((f[present] * w).sum() / w.sum()) if w.sum() else None
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    return {"n": int(len(y_true)), "accuracy": float((y_true == y_pred).mean()) if len(y_true) else None,
            "macro_precision": float(p[present].mean()) if present else None,
            "macro_recall": float(r[present].mean()) if present else None,
            "macro_f1": float(f[present].mean()) if present else None,
            "weighted_f1": weighted_f1,
            "classes_with_support": [labels[i] for i in present],
            "classes_never_predicted_despite_support": [labels[i] for i in present if per[labels[i]]["predicted"] == 0],
            "per_class": per, "labels": labels, "confusion_matrix": cm.tolist()}

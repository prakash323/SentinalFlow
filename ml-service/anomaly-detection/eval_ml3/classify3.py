"""ML-3 attack-type classifier (candidate). Same model family and hyper-parameters as the shipped AttackClassifier (LightGBM,
300 trees, lr 0.06, 31 leaves, balanced class weights, seed 42), on the candidate's explicit feature list.

Leakage rules
  * fitted ONLY on labelled events that exist before TEST (validation-born incidents; TRAIN has no attacks);
  * pool = the top CLASSIFIER_MAX_PER_INCIDENT events of each incident by frozen fused score (the shipped pool rule);
  * incident-grouped validation: no incident contributes rows to both the fit and the held-out side (leave-one-incident-out);
  * a class is TRAINED only with >= CLASS_TRAINABLE_MIN_INCIDENTS incidents and its evaluation is called meaningful only with
    >= CLASS_EVALUABLE_MIN_INCIDENTS incidents. Nothing is fabricated or re-sampled for the unsupported classes.

Classification layer output space = {trained attack classes} U {UNKNOWN}. UNKNOWN = the top class probability is below
ABSTAIN_CONF (the existing config constant CLASS_CONF_HIGH, not tuned). There is deliberately NO 'normal' class: normality is
the anomaly detector's job, and a synthetic normal class built from detector-selected rows would be an invented label.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from . import common as K
from .common import ATTACKS, C
from eval_ml2 import metrics as M2

UNKNOWN = "UNKNOWN"
INSUFFICIENT = "Insufficient data for reliable classifier training/evaluation."


def build_pool(labels, aid, fused, is_val, k=K.CLASSIFIER_MAX_PER_INCIDENT) -> pd.DataFrame:
    """Rows = index positions (into the full event arrays). Only validation-period rows of validation-born incidents."""
    labels = np.asarray(labels, dtype=object)
    aid = np.asarray(aid, dtype=object)
    rows = []
    for a in sorted(set(aid[is_val & np.isin(labels, ATTACKS)])):
        idx = np.where(is_val & (aid == a))[0]
        top = idx[np.argsort(-fused[idx], kind="stable")[:k]]
        for i in top:
            rows.append({"idx": int(i), "attack_id": a, "label": labels[i]})
    return pd.DataFrame(rows)


def class_support(pool: pd.DataFrame) -> dict:
    out = {}
    for t in ATTACKS:
        sub = pool[pool.label == t] if len(pool) else pool
        n_inc = int(sub.attack_id.nunique()) if len(sub) else 0
        trainable = n_inc >= K.CLASS_TRAINABLE_MIN_INCIDENTS
        evaluable = n_inc >= K.CLASS_EVALUABLE_MIN_INCIDENTS
        out[t] = {"training_examples": int(len(sub)), "training_incidents": n_inc, "validation_examples": int(len(sub)),
                  "validation_incidents": n_inc, "training_possible": bool(trainable), "evaluation_statistically_meaningful": bool(evaluable),
                  "note": ("" if evaluable else INSUFFICIENT + (" (trained, but too few incidents to evaluate reliably)" if trainable
                                                                   else " (not trained: fewer than %d incidents)" % K.CLASS_TRAINABLE_MIN_INCIDENTS))}
    return out


def _new_lgbm():
    import lightgbm as lgb
    return lgb.LGBMClassifier(n_estimators=300, learning_rate=0.06, num_leaves=31, class_weight="balanced",
                              random_state=C.RANDOM_SEED, verbose=-1, n_jobs=1)


def fit(F: np.ndarray, y: np.ndarray):
    m = _new_lgbm()
    m.fit(F, y)
    return m


def predict_abstain(model, F: np.ndarray):
    proba = model.predict_proba(F)
    classes = list(model.classes_)
    top = proba.argmax(axis=1)
    conf = proba.max(axis=1)
    pred = np.array([classes[i] if conf[j] >= K.ABSTAIN_CONF else UNKNOWN for j, i in enumerate(top)], dtype=object)
    raw = np.array([classes[i] for i in top], dtype=object)
    return pred, conf, raw, proba


def grouped_cv(F_pool: np.ndarray, pool: pd.DataFrame, trainable: list[str]) -> dict:
    """Leave-one-incident-out over the trainable classes. Every held-out incident is predicted by a model that never saw any of
    its rows. Reports row-level and incident-level (majority vote of the incident's held-out rows) results."""
    sub = pool[pool.label.isin(trainable)].reset_index(drop=True)
    F = F_pool[pool.label.isin(trainable).to_numpy()]
    y = sub.label.to_numpy(dtype=object)
    inc = sub.attack_id.to_numpy(dtype=object)
    pred = np.empty(len(y), dtype=object)
    conf = np.zeros(len(y))
    for a in sorted(set(inc)):
        te = inc == a
        tr = ~te
        if len(set(y[tr])) < 2:
            pred[te], conf[te] = UNKNOWN, 0.0
            continue
        mod = fit(F[tr], y[tr])
        p, c, _, _ = predict_abstain(mod, F[te])
        pred[te], conf[te] = p, c
    labels = sorted(trainable) + [UNKNOWN]
    row = M2.classification_metrics(y, pred, labels)
    inc_pred = {}
    for a in sorted(set(inc)):
        v = pd.Series(pred[inc == a]).value_counts()
        inc_pred[a] = {"true": str(y[inc == a][0]), "predicted_majority": str(v.index[0]), "rows": int((inc == a).sum()),
                       "correct_rows": int((pred[inc == a] == y[inc == a]).sum()), "unknown_rows": int((pred[inc == a] == UNKNOWN).sum())}
    inc_correct = sum(1 for v in inc_pred.values() if v["true"] == v["predicted_majority"])
    return {"rows": int(len(y)), "incidents": len(inc_pred), "row_level": row, "incident_level": inc_pred,
            "incidents_correct_by_majority": inc_correct, "unknown_rows": int((pred == UNKNOWN).sum()),
            "mean_confidence": float(conf.mean()) if len(conf) else None,
            "protocol": "leave-one-incident-out; no incident has rows on both sides of any fit/predict split"}


def layer_on_alerts(pred, conf, labels, alert, trained_classes) -> dict:
    """Behaviour of the classification layer on the alerts of a population (after the anomaly detector alerts).
    For each TRUE type: how many alerted events were labelled correctly / as another supported class / UNKNOWN.
    False-positive alerts (true label normal / benign_drift): how many were given a confident attack class."""
    labels = np.asarray(labels, dtype=object)
    a = np.asarray(alert, dtype=bool)
    out = {"trained_classes": sorted(trained_classes), "per_true_type": {}, "false_positive_alerts": {}}
    for t in ATTACKS:
        m = a & (labels == t)
        n = int(m.sum())
        row = {"alerted_events": n, "class_supported": t in trained_classes}
        if n:
            p = pred[m]
            row.update({"predicted_correctly": int((p == t).sum()), "predicted_other_class": int(((p != t) & (p != UNKNOWN)).sum()),
                        "predicted_unknown": int((p == UNKNOWN).sum()),
                        "prediction_counts": {str(k): int(v) for k, v in pd.Series(p).value_counts().items()},
                        "mean_confidence": float(np.mean(conf[m]))})
            if t not in trained_classes:
                row["abstained_correctly_share"] = float((p == UNKNOWN).mean())
                row["mislabelled_as_supported_class_share"] = float((p != UNKNOWN).mean())
        out["per_true_type"][t] = row
    fp = a & np.isin(labels, ("normal", "benign_drift"))
    if fp.any():
        p = pred[fp]
        out["false_positive_alerts"] = {"alerts": int(fp.sum()), "predicted_unknown": int((p == UNKNOWN).sum()),
                                        "predicted_a_class": int((p != UNKNOWN).sum()),
                                        "prediction_counts": {str(k): int(v) for k, v in pd.Series(p).value_counts().items()},
                                        "mean_confidence": float(np.mean(conf[fp]))}
    tp = a & np.isin(labels, ATTACKS)
    sup = tp & np.isin(labels, list(trained_classes))
    if sup.any():
        out["on_supported_true_positives"] = M2.classification_metrics(labels[sup], pred[sup], sorted(trained_classes) + [UNKNOWN])
    return out

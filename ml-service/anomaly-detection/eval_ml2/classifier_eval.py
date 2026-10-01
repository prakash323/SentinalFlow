"""Attack-type classifier evaluation (evaluation-only). The shipped classifier is never modified or refitted; all fits
below are SCRATCH classifiers (same class, same hyper-parameters, via the production AttackClassifier) held in memory.

A. LEGACY row-level CV (DIAGNOSTIC)      the methodology behind the shipped numbers: pool = up to 6 highest-risk events
                                         of each incident the shipped pipeline's alert queue caught, StratifiedKFold over
                                         ROWS. Rows of one incident land in both train and validation folds.
B. INCIDENT-GROUPED CV (DIAGNOSTIC)      same pool, but no incident ever appears on both sides of a fold
                                         (leave-one-incident-out, and 5-fold StratifiedGroupKFold).
                                         A and B use ALL incidents (including test-period ones), so they are
                                         methodology comparisons, not held-out test results.
C. CHRONOLOGICAL held-out (LEAKAGE-SAFE) fit ONLY on validation-born incidents (<=6 events each) using dev labels, then
                                         evaluated ONCE on every attack event of the held-out TEST population. Classes
                                         absent from validation cannot be learned; their recall is 0 by construction.
D. Shipped classifier on streaming alerts  FALSE alerts carry no label leakage (the shipped classifier never had a
                                         'normal' class); TRUE alerts are in-sample (it was trained on all 36 incidents)
                                         and are NOT reported as performance.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from . import common as K
from .common import ATTACKS
from .metrics import classification_metrics, dist


def _fit(X, y):
    from src.classify import AttackClassifier
    return AttackClassifier(verbose=False).fit(X, y, compute_importance=False)


def legacy_pool(p, batch, FN, labels):
    """Rebuild the shipped classifier's training pool exactly as run_pipeline.py does (functions reused from src.evaluate).
    `labels` = the whole-dataset label frame (a DIAGNOSTIC access, logged by the caller)."""
    from src import evaluate as ev
    events = p.events
    X = pd.DataFrame(batch["features"], columns=FN)
    X.insert(0, "event_id", events["event_id"].to_numpy())
    X.insert(1, "entity_id", events["entity_id"].to_numpy())
    X["label"] = labels["label"].to_numpy()
    X["attack_id"] = labels["attack_id"].to_numpy()
    risk = np.asarray(batch["risk_union"])
    te = p.m_legacy                                                   # days 21-30 (the shipped 'test' window)
    ranked = ev.deduplicate_alerts(np.where(te)[0], events.entity_id, events.timestamp, risk)
    inc = ev.incident_scores(ranked, events.entity_id, events.timestamp, risk,
                             fp_novelty=X["fingerprint_novelty"].to_numpy(dtype=float))
    ranked = ranked[np.argsort(-inc)]
    n_slots = max(1, int(te.sum() * 0.01))
    order = ranked[:n_slots]
    qmask = np.zeros(len(X), dtype=bool)
    qmask[order] = True
    detected = set(X.loc[qmask & (X["attack_id"] != ""), "attack_id"].unique())
    pool = ev.classifier_training_pool(X, risk, detected)
    return X.iloc[pool].reset_index(drop=True), pool, {"queue_slots": int(n_slots), "incidents_detected_by_queue": len(detected)}


def _grouped_predict(Xf, yf, groups, mode):
    from sklearn.model_selection import LeaveOneGroupOut, StratifiedGroupKFold
    pred = np.empty(len(yf), dtype=object)
    if mode == "loio":
        splits = LeaveOneGroupOut().split(Xf, yf, groups)
    else:
        splits = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=K.C.RANDOM_SEED).split(Xf, yf, groups)
    for tr, te in splits:
        if len(set(yf[tr])) < 2:
            pred[te] = yf[tr][0]
            continue
        m = _fit(Xf.iloc[tr], yf[tr])
        pred[te] = m.predict(Xf.iloc[te])[0]
    return pred


def diagnostics_legacy_vs_grouped(p, batch, FN, diag_labels, art_clf, log=print):
    """A + B (DIAGNOSTIC, whole-dataset incidents; not held-out results)."""
    from src.classify import AttackClassifier
    out = {}
    Xf, pool, meta = legacy_pool(p, batch, FN, diag_labels)
    yf = Xf["label"].to_numpy()
    groups = Xf["attack_id"].to_numpy()
    out["pool"] = {"rows": int(len(Xf)), "incidents": int(len(set(groups))),
                   "rows_per_class": {k: int(v) for k, v in pd.Series(yf).value_counts().items()},
                   "incidents_per_class": {t: int(len(set(groups[yf == t]))) for t in ATTACKS},
                   "all_rows_in_shipped_test_window": bool(p.m_legacy[pool].all()), "rows_in_train_window": int(p.m_train[pool].sum()),
                   "rows_in_ml2_test_population": int(p.m_test[pool].sum()), **meta}
    F = Xf[FN].to_numpy(dtype=float)
    out["pool"]["matches_shipped_classifier_feature_means"] = bool(
        np.allclose(np.nanmean(F, axis=0), art_clf.feat_mean_, rtol=1e-5, atol=1e-6))
    cv = AttackClassifier(verbose=False).cross_validate(Xf, yf)                 # the shipped methodology, verbatim
    out["A_legacy_row_level_cv"] = {"label": "DIAGNOSTIC / LEGACY: StratifiedKFold over ROWS (incident leakage across folds)",
                                    "folds": int(min(5, pd.Series(yf).value_counts().min())),
                                    **classification_metrics(cv["y_true"], cv["y_pred"], ATTACKS)}
    loio = _grouped_predict(Xf, yf, groups, "loio")
    out["B1_incident_grouped_loio"] = {"label": "DIAGNOSTIC: leave-one-incident-out (no incident on both sides of any fold)",
                                       **classification_metrics(yf, loio, ATTACKS)}
    sgk = _grouped_predict(Xf, yf, groups, "sgkf")
    out["B2_incident_grouped_5fold"] = {"label": "DIAGNOSTIC: StratifiedGroupKFold(5, shuffle, seed 42) by incident",
                                        **classification_metrics(yf, sgk, ATTACKS)}
    log("[classifier] A/B done")
    return out


def _stream_frames(p, stream_main, FN):
    sid = stream_main["event_id"]
    fused = np.full(len(p.events), np.nan)
    fused[sid] = stream_main["fused"]
    feats = pd.DataFrame(np.full((len(p.events), len(FN)), np.nan), columns=FN)
    feats.iloc[sid] = stream_main["features"]
    return sid, fused, feats


def fit_chronological(p, stream_main, FN, dev_labels):
    """C, step 1 (a DECISION): fit ONLY on validation-born incidents. Uses dev labels (test rows masked)."""
    sid, fused, feats = _stream_frames(p, stream_main, FN)
    dl = dev_labels["label"].to_numpy()
    da = dev_labels["attack_id"].to_numpy()
    val_atk = np.where(p.m_val & np.isin(dl, ATTACKS))[0]
    keep = []
    for a in sorted(set(da[val_atk])):
        rows = val_atk[da[val_atk] == a]
        rows = rows[np.argsort(-fused[rows], kind="stable")][:K.CLASSIFIER_MAX_PER_INCIDENT]
        keep += list(rows)
    keep = np.array(sorted(keep), dtype=int)
    yv = dl[keep]
    clf = _fit(feats.iloc[keep], yv)
    decisions = {"classifier_train_rows": int(len(keep)), "classifier_train_event_ids": [int(x) for x in keep],
                 "classifier_train_incidents": sorted(set(da[keep])), "classifier_train_classes": sorted(set(yv)),
                 "classifier_train_rows_per_class": {k: int(v) for k, v in pd.Series(yv).value_counts().items()}}
    return clf, decisions


def evaluate_chronological(p, stream_main, FN, clf, decisions, test_labels):
    """C, step 2 (final evaluation): called ONCE, after the decisions are frozen and the held-out labels unsealed."""
    sid, fused, feats = _stream_frames(p, stream_main, FN)
    tl = test_labels["label"].to_numpy()
    yv_classes = set(decisions["classifier_train_classes"])
    idx = np.where(p.m_test & np.isin(tl, ATTACKS))[0]
    pr = clf.predict(feats.iloc[idx])
    yt = tl[idx]
    cm = classification_metrics(yt, pr[0], ATTACKS)
    cm["mean_max_probability"] = float(np.mean(pr[1]))
    cm["classes_absent_from_training_but_present_in_test"] = sorted(set(yt) - yv_classes)
    cm["note"] = ("fit ONLY on validation-born incidents; a class absent from validation cannot be predicted, so its "
                  "recall is 0 by construction (a data limitation, not a model result)")
    known = [t for t in ATTACKS if t in yv_classes]
    mk = np.isin(yt, known)
    return {"label": "LEAKAGE-SAFE: fit on validation incidents, evaluated once on held-out TEST events",
            "training": decisions, **cm,
            "restricted_to_classes_seen_in_training": {"classes": known,
                                                       **classification_metrics(yt[mk], pr[0][mk], known)}}


def shipped_classifier_on_alerts(p, stream_main, test_labels):
    """D. Shipped classifier's behaviour on streaming alerts inside the held-out TEST population."""
    sid = stream_main["event_id"]
    n = len(p.events)
    alert = np.zeros(n, dtype=bool)
    alert[sid] = stream_main["alert"]
    conf = np.full(n, np.nan)
    conf[sid] = stream_main["conf"]
    pred_s = np.full(n, "", dtype=object)
    pred_s[sid] = stream_main["pred"]
    tl = test_labels["label"].to_numpy()
    is_atk = np.isin(tl, ATTACKS)
    fp = p.m_test & alert & ~is_atk
    tp = p.m_test & alert & is_atk
    return {
        "label": "shipped classifier (trained on all 36 incidents): FALSE alerts are leakage-free; TRUE alerts are in-sample",
        "false_alerts": int(fp.sum()),
        "false_alert_predicted_class": {k: int(v) for k, v in pd.Series(pred_s[fp]).value_counts().items()},
        "false_alert_confidence": dist(conf[fp]) if fp.any() else {"n": 0},
        "false_alerts_with_confidence_ge_0_65_shown_as_likely": int((conf[fp] >= K.C.CLASS_CONF_HIGH).sum()) if fp.any() else 0,
        "true_alerts": int(tp.sum()),
        "true_alert_confidence_IN_SAMPLE": dist(conf[tp]) if tp.any() else {"n": 0},
        "true_alert_class_accuracy_IN_SAMPLE_not_a_performance_claim":
            float((pred_s[tp] == tl[tp]).mean()) if tp.any() else None,
    }

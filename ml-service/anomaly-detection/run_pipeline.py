"""
End-to-end batch pipeline. One command produces every artifact the report needs.

    python run_pipeline.py                       # synthetic sample data
    python run_pipeline.py --source lanl --path data/lanl
    python run_pipeline.py --quick               # fast smoke test

Outputs:
    data/sample/{events,labels}.csv     generated logs + ground truth
    models/*.joblib                     trained artifacts (reused by realtime + app)
    report/metrics.json                 every number in the report
    report/alerts.json                  ranked, explained alert queue
    figures/*.png                       all plots
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
import joblib
import numpy as np
import pandas as pd

# Windows consoles default to the cp1252 codepage, which cannot encode
# characters this project's own explanation text uses (sigma, em dashes,
# arrows). Without this, a run that reaches the very last print statement
# after everything else succeeded -- alerts written, models trained -- can
# still crash with UnicodeEncodeError and never reach the evaluation/figure/
# persist steps below it. Reconfiguring stdout is harmless on platforms
# that are already UTF-8.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import config as C
from src import datasets, evaluate as ev
from src.baseline import BaselineProfiler, CONTINUOUS
from src.classify import AttackClassifier
from src.detect import Detector
from src.explain import Explainer
from src.features import build_feature_matrix, FEATURE_NAMES
from src.utils import load_events


def time_split(X: pd.DataFrame, train_days=C.TRAIN_DAYS):
    ts = pd.to_datetime(X["timestamp"])
    cut = ts.min() + pd.Timedelta(days=train_days)
    return (ts < cut).to_numpy(), (ts >= cut).to_numpy()


def main(args):
    print("=" * 72)
    print("AI-POWERED BEHAVIOURAL ANOMALY DETECTION -- BATCH PIPELINE")
    print("=" * 72)

    # ---------------------------------------------------------------- data
    if args.source == "synthetic":
        p = Path(args.path)
        if args.regenerate or not (p / "events.csv").exists():
            from src.generate import generate
            generate(days=args.days, out_dir=p, scale=args.scale)
        events = load_events(p / "events.csv")
        labels = pd.read_csv(p / "labels.csv")
    else:
        events, labels = datasets.load(args.source, args.path)
    labels = labels.set_index("event_id").loc[events.event_id].reset_index()
    print(f"\n[1/9] data: {len(events):,} events, "
          f"{events.entity_id.nunique()} entities")

    # ------------------------------------------------------------ features
    print("[2/9] features (single causal forward pass, leak-free) ...")
    X = build_feature_matrix(events)
    X["label"] = labels["label"].values
    X["attack_id"] = labels["attack_id"].fillna("").values
    tr, te = time_split(X, args.train_days)
    print(f"      train {tr.sum():,} | test {te.sum():,} "
          f"(time-based split, no random shuffling)")

    # ------------------------------------------------------------ baseline
    print("[3/9] per-entity baseline profiles (+ peer priors, shrinkage) ...")
    prof = BaselineProfiler(use_peer_prior=not args.no_peer_prior,
                            use_drift=not args.no_drift)
    prof.fit(X[tr])
    b_tr, _, _ = prof.score_frame(X[tr])
    b_all, contribs, lowconf = prof.score_frame(X)

    # ------------------------------------------------------------ detector
    print("[4/9] detector: IsolationForest + sequence autoencoder ...")
    det = Detector(use_sequence=not args.no_sequence).fit(X[tr], b_tr)
    raw = det.raw_scores(X, b_all)
    raw_tr = {k: v[tr] for k, v in raw.items() if k != "sequence_per_feature"}
    det.fit_calibrators(raw_tr)
    fused = det.fuse({k: v for k, v in raw.items() if k != "sequence_per_feature"})
    det.calibrate(fused[tr])
    risk = det.to_risk_100(fused)
    budget = args.budget
    thr = det.set_threshold(risk[te], budget)
    print(f"      alert threshold @ top {budget*100:.1f}% = risk {thr:.1f}")

    # ------------------------------------------------------------- alert queue
    # Built BEFORE the classifier: the training pool below needs to know
    # which incidents actually made it into the queue, so the queue has to
    # exist first. (This also doesn't need the classifier at all -- queueing
    # is purely risk-based dedup.)
    print("[5/9] ranked alert queue (incident-level dedup + incident scoring) ...")
    n_slots = max(1, int(te.sum() * budget))
    ranked = ev.deduplicate_alerts(np.where(te)[0], events.entity_id,
                                   events.timestamp, risk)
    # Re-rank the deduplicated incidents on incident-level evidence rather
    # than the single representative event's risk -- see
    # src/evaluate.py:incident_scores. Slow-burn attacks (low-and-slow
    # exfil, lateral movement) have no single spectacular event and were
    # losing every tie-break to one-off benign outliers.
    inc_score = ev.incident_scores(ranked, events.entity_id, events.timestamp, risk,
                                   fp_novelty=X["fingerprint_novelty"].to_numpy(dtype=float))
    ranked = ranked[np.argsort(-inc_score)]
    # n_slots (1% of raw events) is a BUDGET CEILING, not a promise that
    # many genuine high-confidence incidents exist. Only ~38 deduplicated
    # incidents in this run actually clear the calibrated alert threshold
    # `thr` -- the rest of the budget is filled from the normal
    # population's long statistical tail (risk 99.2-99.9, just under the
    # ceiling). Cutting the queue off AT `thr` loses real incidents too,
    # though: several attack types (device spoofing, low-and-slow exfil)
    # only ever produce one or two moderately-elevated events per
    # incident, never a risk-100 spike, so a hard cutoff there would
    # silently drop them from the classifier's training data again -- the
    # exact problem `classifier_training_pool` exists to avoid. So: keep
    # the full budget (needed so every attack type gets seen at least
    # once), but tag each alert with whether it actually cleared the
    # calibrated bar, so the queue's real composition is visible instead
    # of hidden behind one "it's an alert" bucket.
    order = ranked[:n_slots]
    queue_mask = np.zeros(len(X), dtype=bool)
    queue_mask[order] = True
    cleared_threshold = risk >= thr
    n_cleared = int(cleared_threshold[order].sum())
    print(f"      {len(ranked):,} incidents after dedup -> queue of {len(order)} "
          f"({n_cleared} clear the risk-{thr:.0f} threshold outright, "
          f"{len(order) - n_cleared} fill the remaining budget from lower-risk "
          f"incidents so rarer attack types are still represented)")

    # ---------------------------------------------------------- classifier
    print("[6/9] attack-type classifier (detected incidents, capped per "
          "incident so a bursty attack can't crowd out a rare one; "
          "'normal' is never a trainable label) ...")
    flagged = risk >= thr
    detected_incident_ids = set(
        X.loc[queue_mask & (X["attack_id"] != ""), "attack_id"].unique())
    train_idx = ev.classifier_training_pool(X, risk, detected_incident_ids)
    Xf, yf = X.iloc[train_idx], X.iloc[train_idx]["label"].to_numpy()
    clf, cv = None, None
    if len(set(yf)) >= 2 and len(Xf) >= 20:
        clf = AttackClassifier().fit(Xf, yf)
        cv = clf.cross_validate(Xf, yf)
        if cv:
            print(cv["report_text"])
        missing = [a for a in C.ATTACK_TYPES if a not in set(yf)]
        if missing:
            print(f"      NOTE: no detected incidents for {missing} in this "
                  f"run -- the classifier cannot predict a class it has "
                  f"never seen a training example of.")
    else:
        print("      too few detected incidents to train a classifier")

    # ------------------------------------------------------------- alerts
    print("[7/9] explanations for the queued alerts ...")
    # Materialise (build full explanations for) enough of the ranked queue
    # to cover the WIDEST budget level the dashboard's sidebar control
    # offers (config.BUDGET_LEVELS), not just n_slots (the budget THIS run
    # was generated at) -- so widening the budget in the dashboard shows a
    # genuine, fully-explained queue instead of the "not enough alerts were
    # generated, re-run the pipeline" note for every level except the
    # default. This is purely additive: `order` / `queue_mask` above (which
    # drive every evaluation metric, the classifier's training pool, and
    # `detected_incident_ids`) are computed from `n_slots` alone and are
    # completely unaffected by how many EXTRA rows get explained here.
    n_materialize = min(
        max(n_slots, int(te.sum() * max(C.BUDGET_LEVELS))), args.max_alerts)
    order_alerts = ranked[:n_materialize]
    expl = Explainer(clf)
    alerts = []
    for i in order_alerts:
        ev_row = events.iloc[i].to_dict()
        feat = {f: X.iloc[i][f] for f in FEATURE_NAMES}
        if clf is not None:
            pred, conf, _, _ = clf.predict(X.iloc[[i]])
            pred, conf = pred[0], float(conf[0])
        else:
            pred, conf = "unclassified", 0.0
        alerts.append(expl.build_alert(
            ev_row, feat, contribs[i], risk[i], pred, conf,
            raw["sequence_per_feature"][i], bool(lowconf[i]),
            cleared_threshold=bool(cleared_threshold[i])))
    ev.save_json(alerts, C.REPORT / "alerts.json")
    print(f"      {len(alerts)} alerts written")
    if alerts:
        print("\n      --- top alert ---")
        print("      " + alerts[0]["reason_text"][:400])

    # --------------------------------------------------------- evaluation
    print("\n[8/9] evaluation ...")
    y = ev.binary_labels(X["label"])
    res = {"overall": ev.core_metrics(y[te], risk[te], budget)}
    res["overall"]["alert_budget_used"] = budget
    print(json.dumps(res["overall"], indent=2))

    par = ev.per_attack_recall(X.loc[te, "label"], risk[te], budget)
    res["per_attack"] = par.to_dict("records")
    print(f"\n      per-attack detection, RAW EVENT ranking @ top {budget*100:.1f}%:")
    print("      (brute force emits 620 events and fills the raw-event budget,")
    print("       so every other type reads ~0 here -- see the queue view below)")
    print(par.to_string(index=False))

    parq = ev.per_attack_recall_queue(X["label"], queue_mask)
    res["per_attack_queue"] = parq.to_dict("records")
    print("\n      per-attack presence in the DEDUPLICATED ANALYST QUEUE "
          "(what an analyst actually reviews):")
    print(parq.to_string(index=False))

    inc = ev.incident_recall(X["label"], X["attack_id"], queue_mask)
    res["incident_recall"] = inc.to_dict("records")
    if len(inc):
        print(f"\n      incident-level detection @ top {budget*100:.1f}% "
              "(did we catch the attack at all?):")
        print(inc.to_string(index=False))

    # The chosen --budget is folded into the sweep (not just the fixed
    # defaults) so the dashboard's dynamic budget control always has an
    # exact precomputed row for whatever value was actually used to build
    # this run's alert queue, not just the standard levels.
    swept_budgets = tuple(sorted(set(C.BUDGET_LEVELS) | {budget}))
    ibc = ev.incident_budget_curve(ranked, X["label"], X["attack_id"],
                                   len(X), int(te.sum()), budgets=swept_budgets)
    res["incident_budget_curve"] = ibc.to_dict("records")
    print("\n      incident recall vs analyst budget "
          "(alert CARDS opened, INCIDENTS caught):")
    print(ibc.to_string(index=False))

    bc = ev.budget_curve(y[te], risk[te], budgets=swept_budgets)
    res["budget_curve"] = bc.to_dict("records")

    # ablations -------------------------------------------------------
    print("\n      ablations ...")
    ablations = [
        {"model": "baseline profiler only", "risk": raw["baseline"]},
        {"model": "isolation forest only", "risk": raw["iforest"]},
        {"model": "sequence AE only", "risk": raw["sequence"]},
        {"model": "full ensemble", "risk": fused},
    ]
    comp = []
    for a in ablations:
        m = ev.core_metrics(y[te], a["risk"][te], budget)
        comp.append({"model": a["model"], "pr_auc": m["pr_auc"],
                     "precision_at_budget": m["precision_at_budget"],
                     "recall_at_budget": m["recall_at_budget"]})
        print(f"        {a['model']:26s} PR-AUC {m['pr_auc']:.3f}  "
              f"P@{budget*100:.1f}% {m['precision_at_budget']:.3f}  "
              f"R@{budget*100:.1f}% {m['recall_at_budget']:.3f}")
    res["ablation_components"] = comp

    # cold start -------------------------------------------------------
    cold = lowconf & te
    if cold.sum() > 20:
        res["cold_start"] = {
            "n_cold_events": int(cold.sum()),
            "with_peer_prior": ev.core_metrics(y[cold], risk[cold], budget),
        }
        p2 = BaselineProfiler(use_peer_prior=False).fit(X[tr])
        b2, _, _ = p2.score_frame(X)
        res["cold_start"]["without_peer_prior"] = ev.core_metrics(y[cold], b2[cold], budget)
        print(f"        cold-start PR-AUC  with prior "
              f"{res['cold_start']['with_peer_prior']['pr_auc']:.3f}  "
              f"vs without {res['cold_start']['without_peer_prior']['pr_auc']:.3f}")

    # drift ------------------------------------------------------------
    drift = prof.drift_report(X[te])
    res["drift"] = {"detected": drift["drift_detected"],
                    "top_drifted": sorted(drift["drifted"],
                                          key=lambda k: -drift["drifted"][k])[:6],
                    "psi": {k: round(v, 3) for k, v in drift["psi"].items()}}
    dm = X.loc[te, "label"] == "benign_drift"
    if dm.sum() > 0:
        fl = risk[te] >= thr
        res["drift"]["benign_drift_false_alarm_rate"] = round(
            float((fl & dm.to_numpy()).sum() / dm.sum()), 4)
        print(f"        benign-drift false alarm rate: "
              f"{res['drift']['benign_drift_false_alarm_rate']:.3f}")

    if cv:
        res["classification"] = {
            "macro_f1": round(cv["report"]["macro avg"]["f1-score"], 4),
            "accuracy": round(cv["report"]["accuracy"], 4),
            "per_class": {k: v for k, v in cv["report"].items()
                          if isinstance(v, dict)},
        }

    # ------------------------------------------------------------ figures
    print("\n[9/9] figures ...")
    ev.plot_pr(y[te], risk[te], C.FIGURES / "pr_curve.png",
               "Anomaly detection (test window)")
    ev.plot_roc(y[te], risk[te], C.FIGURES / "roc_curve.png",
                "Anomaly detection (test window)")
    ev.plot_budget_curve(bc, C.FIGURES / "alert_budget_curve.png")
    ev.plot_model_comparison(comp, C.FIGURES / "ablation_components.png")
    ev.plot_feature_separation(
        X, X["label"],
        ["geo_velocity_kmh", "failed_auth_5min_ip", "new_resources_24h",
         "fingerprint_mismatch", "offhours_count_7d", "resource_breadth_7d"],
        C.FIGURES / "feature_separation.png")
    if cv:
        ev.plot_confusion(cv["confusion"], cv["labels"],
                          C.FIGURES / "confusion_matrix.png")
    if clf is not None:
        fi = clf.feature_importance()
        if fi:
            ev.plot_feature_importance(fi, C.FIGURES / "feature_importance.png")
            res.setdefault("classification", {})["feature_importance"] = \
                {k: round(float(v), 4) for k, v in list(fi.items())[:15]}
        has_shap = ev.plot_shap_summary(clf, Xf, C.FIGURES / "shap_summary.png")
        print(f"      SHAP summary figure: {'written' if has_shap else 'skipped (shap not installed)'}")
    ev.plot_risk_distribution(risk[order], risk[te],
                              C.FIGURES / "risk_distribution.png")
    print(f"      -> {C.FIGURES}")

    # ----------------------------------------------------------- persist
    joblib.dump({"profiler": prof, "detector": det, "classifier": clf,
                 "threshold": thr}, C.MODELS / "pipeline.joblib")
    scored = pd.DataFrame({
        "event_id": events.event_id, "entity_id": events.entity_id,
        "timestamp": events.timestamp, "risk_score": risk,
        "label": X["label"], "is_test": te, "low_confidence": lowconf,
        "flagged": flagged})
    scored.to_csv(C.REPORT / "scored_events.csv", index=False)
    ev.save_json(res, C.REPORT / "metrics.json")
    print(f"\nDONE. metrics -> {C.REPORT/'metrics.json'}")
    print(f"      alerts  -> {C.REPORT/'alerts.json'}")
    print(f"      models  -> {C.MODELS/'pipeline.joblib'}")
    print("\nNext:  streamlit run app.py        (analyst dashboard)")
    print("       python run_realtime.py     (streaming demo)")
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="synthetic",
                    choices=["synthetic", "lanl", "cert", "generic"])
    ap.add_argument("--path", default=str(C.SAMPLE_DIR))
    ap.add_argument("--days", type=int, default=C.N_DAYS)
    ap.add_argument("--train-days", type=int, default=C.TRAIN_DAYS)
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--regenerate", action="store_true")
    ap.add_argument("--quick", action="store_true", help="small fast run")
    ap.add_argument("--budget", type=float, default=C.ALERT_BUDGET,
                    help="analyst alert budget as a fraction of events, e.g. "
                         "0.01 = top 1%% (default: config.ALERT_BUDGET). Runtime "
                         "parameter, not a code constant -- see Detector."
                         "threshold_for_budget.")
    ap.add_argument("--max-alerts", type=int, default=1200,
                    help="cap on how many ranked incidents get full "
                         "explanations built (alerts.json rows). Raised "
                         "from the original 500 so the dashboard's dynamic "
                         "alert-budget control (up to config.BUDGET_LEVELS's "
                         "3%%, ~1000 slots on the bundled sample) has a "
                         "materialised, fully-explained row for every "
                         "budget level by default, not just the one this "
                         "run was generated at.")
    ap.add_argument("--no-sequence", action="store_true")
    ap.add_argument("--no-peer-prior", action="store_true")
    ap.add_argument("--no-drift", action="store_true")
    a = ap.parse_args()
    if a.quick:
        a.scale, a.days, a.train_days, a.regenerate = 0.25, 20, 13, True
    main(a)

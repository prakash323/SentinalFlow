"""Sections 3-12 of the ML-2 report (evaluation-only). Numbers are read from metrics.json."""
from __future__ import annotations

import json

from . import common as K
from .common import ATTACKS
from .report import f3, pc, tbl


def sec_leakage(m):
    integ = m["integrity"]
    ti = integ["train_window_is_the_shipped_fit_window"]
    fr = integ["frozen_decisions"]
    vlog = integ["label_vault_log"]
    log_rows = [[i + 1, v.get("access"), v.get("purpose", v.get("sha256", ""))] for i, v in enumerate(vlog)]
    sigdiff = ti["sig_calib_max_abs_diff_vs_recomputed_train"]
    ops = fr["operating_points"]
    rows = [
        ["TRAIN (fit only)", "shipped artifact fitted on exactly the TRAIN window",
         f"artifact profiler saw {ti['artifact_profiler_training_events']:,} events = protocol TRAIN {ti['protocol_train_events']:,}; calibration curve rows "
         f"{ti['artifact_calibration_rows']:,}; max |recomputed − stored| per-signal calibration: "
         f"baseline {sigdiff['baseline']:.2e}, iforest {sigdiff['iforest']:.2e}, sequence {sigdiff['sequence']:.2e}"],
        ["VALIDATION (decisions only)", "evaluation-only operating points; chronological classifier fit",
         f"decisions from VALIDATION scores/labels only, frozen and hashed (`{integ['decisions_sha256'][:16]}…`) before any test label was read; "
         f"classifier fitted on {fr['chronological_classifier']['classifier_train_rows']} rows from {len(fr['chronological_classifier']['classifier_train_incidents'])} validation-born incidents"],
        ["TEST (evaluate once)", "final metrics",
         f"held-out labels unsealed {integ['test_unseal_count']}× (a second call raises); the purge removes events of validation-born incidents"],
        ["Fusion weights / flag weights / features / ranking bonus", "NOT tuned in ML-2",
         "inherited from the shipped model; **their historical tuning used days 21–30 (contains TEST)** — cannot be undone (see §1 caveat)"],
        ["Production threshold (99.5023)", "used as shipped",
         "derived from the top-1% quantile of days 21–30 risk (ML-1) → **not held out from TEST**; validation-derived thresholds are reported next to it"],
        ["Shipped classifier", "not evaluated on test",
         "trained on all 36 incidents (all test-period rows included) → no leakage-safe evaluation of the shipped classifier is possible"],
        ["Batch fusion (shipped semantics)", "reported as LEGACY",
         "rank-normalises over the evaluated population (transductive); the leakage-safe batch path is 'frozen batch' (train-anchored)"],
    ]
    return f"""## 3. Leakage Controls

{tbl(['Stage', 'Allowed use', 'Verification / evidence'], rows)}

**Evaluation-only operating points chosen on VALIDATION** (per scoring path; applied unchanged to TEST):

{tbl(['Path', 'Validation q99 of fused score', 'Validation F1-optimal fused threshold', 'Validation events', 'Validation attack events'],
      [[k, f3(v['validation_q99_fused'], 5), f3(v['validation_f1_optimal_fused'], 5), v['validation_events'], v['validation_attack_events']] for k, v in ops.items()])}

**Label-access log** (every read of held-out labels, in order):

{tbl(['#', 'Access', 'Purpose / hash'], log_rows)}

**Other label reads outside the vault:** the batch and streaming scoring stages never read labels. The parity stage (a separate process) reads labels only to *choose* representative events (first event of each incident, plus seeded-random normal events); it evaluates nothing against them.

**Self-checks:** the vectorised fused/risk mappings equal the production single-event functions
(max |Δ| = {integ['vectorised_mappings_vs_production_functions']['vectorised_fuse_vs_fuse_single_max_abs_diff']:.2e} / {integ['vectorised_mappings_vs_production_functions']['vectorised_risk_vs_to_risk_100_max_abs_diff']:.2e});
the streaming `alert` flag equals `risk ≥ shipped threshold` for every event: **{integ['streaming_alert_flag_equals_risk_ge_shipped_threshold']}**;
streaming warm-up scope = {integ['streaming_warmup']['scope']} ({integ['streaming_warmup']['warm_events']:,} events)."""


def sec_batch_stream(m):
    bs = m["batch_vs_streaming"]
    out = ["## 4. Batch vs Streaming", "",
           "All three columns score the **same held-out TEST population** with the **same shipped model** and the **same production threshold**. "
           "*Difference = streaming − frozen batch* (the leakage-safe comparison); *shipped batch* is the legacy protocol shown for continuity.", ""]
    for pname, title in (("TEST", "held-out TEST population"), ("VALIDATION", "VALIDATION population"),
                         ("LEGACY_days_21_30_not_held_out", "legacy days 21–30 (ML-1 population, NOT held out)")):
        rows = []
        for r in bs["comparison_tables"][pname]:
            rows.append([r["metric"], f3(r["shipped_batch_legacy"], 4), f3(r["frozen_batch"], 4), f3(r["streaming"], 4),
                         f3(r["difference_streaming_minus_frozen_batch"], 4)])
        out += [f"**{title}**", "", tbl(["Metric", "Shipped batch (legacy)", "Frozen batch", "Streaming", "Difference (streaming − frozen)"], rows), ""]
    te = m["anomaly_detection"]["TEST"]
    srows = []
    for s in ("shipped_batch_legacy", "frozen_batch", "streaming"):
        for sc, key in (("fused", "fused"), ("risk", "risk"), ("anomaly score", "anomaly_score")):
            d = te[s]["score_distribution"][key]
            srows.append([s, sc, f3(d["median"], 4), f3(d["p90"], 4), f3(d["p95"], 4), f3(d["p99"], 4), f3(d["max"], 4)])
    rel = bs["score_relation_on_TEST"]
    fp = bs["feature_parity_stream_vs_batch"]
    out += ["**Score distributions on TEST (median / p90 / p95 / p99 / max):**", "",
            tbl(["Path", "Score", "median", "p90", "p95", "p99", "max"], srows), "",
            f"**Streaming vs frozen batch, per event (TEST):** Spearman(fused) = {f3(rel['spearman_fused_stream_vs_frozen_batch'], 4)}, "
            f"mean |Δfused| = {f3(rel['mean_abs_fused_difference'], 4)}, mean signed Δfused = {f3(rel['mean_signed_fused_difference_stream_minus_batch'], 4)}, "
            f"events with |Δrisk| > 1: {pc(rel['share_events_abs_risk_diff_gt_1'])}; alerts in both = {rel['alerts_both']}, streaming-only = {rel['alerts_stream_only']}, "
            f"batch-only = {rel['alerts_batch_only']}.", "",
            f"**Feature parity (streaming vs batch matrices, {fp['events_compared']:,} events):** max |Δ| = {fp['max_abs_feature_difference']:.3g}; "
            f"events with any difference = {fp['events_with_any_difference']} → the features used by the streaming evaluation are "
            f"{'identical to' if fp['max_abs_feature_difference'] == 0 else 'NOT identical to'} the batch features."]
    return "\n".join(out)


def sec_scores(m):
    sd = m["score_distribution"]
    rows = []
    for s, d in sd["TEST"].items():
        sat = d["saturation"]
        rows.append([s, sat["n"], sat["risk_eq_100"], sat["anomaly_eq_1_0"], sat["risk_gt_99"], sat["risk_gt_99_5"], sat["risk_gt_99_9"],
                     sat["distinct_risk_values_above_99_5"], f3(sat["share_of_high_scores_tied_at_max"], 3)])
    t1 = tbl(["Path (TEST events)", "N", "risk = 100", "anomalyScore = 1.0", "risk > 99", "risk > 99.5", "risk > 99.9",
              "distinct risk values > 99.5", "share of >99.5 tied at 100"], rows)
    fr = []
    for s, d in sd["TEST"].items():
        sat = d["saturation"]
        fr.append([s, sat["fused_ge_0_99"], sat["fused_ge_0_999"], sat["fused_eq_1_0"], f3(sat["fused_max"], 5),
                   sat["anomaly_ge_0_99"], sat["anomaly_ge_0_995"], sat["anomaly_ge_0_999"]])
    t2 = tbl(["Path (TEST)", "fused ≥ 0.99", "fused ≥ 0.999", "fused ≥ 1.0", "fused max", "anomaly ≥ 0.99", "anomaly ≥ 0.995", "anomaly ≥ 0.999"], fr)
    al = sd["streaming_all_evaluation_period_val_plus_test"]
    sat = al["saturation"]
    cd = al["classifier_confidence_on_alerts"]
    return f"""## 5. Score Distribution

**Ceiling saturation (risk and anomalyScore = risk/100, as `api.py` returns it):**

{t1}

**Fused score and anomaly-score thresholds (Spring's severity bands are 0.99 / 0.995 / 0.999):**

{t2}

**Streaming, whole evaluation period (validation + test, {sat['n']:,} events):** {sat['risk_eq_100']} events have risk exactly 100.0
(anomalyScore 1.0); {sat['distinct_risk_values_above_99_5']} distinct risk value(s) exist above 99.5.

**Classifier confidence on streaming alerts (n = {cd.get('n', 0)}):** median {f3(cd.get('median'), 4)}, p90 {f3(cd.get('p90'), 4)}, p99 {f3(cd.get('p99'), 4)}, max {f3(cd.get('max'), 4)};
{sat.get('classifier_conf_ge_0_99', 'n/a')} ≥ 0.99, {sat.get('classifier_conf_ge_0_999', 'n/a')} ≥ 0.999,
{sat.get('classifier_conf_api_rounded_eq_1_0', 'n/a')} equal 1.0 after the API's 3-decimal rounding.

*Observation only — nothing was changed or calibrated.*"""


def _op_row(name, o):
    return [name, o["alerts"], o["tp"], o["fp"], o["fn"], o["tn"], f3(o["precision"], 4), f3(o["recall"], 4), f3(o["f1"], 4),
            f3(o["false_positive_rate"], 5), f3(o["false_negative_rate"], 4), pc(o["alert_rate"], 2),
            f"{o['incidents']['detected']}/{o['incidents']['incidents']}"]


def sec_anomaly(m):
    te = m["anomaly_detection"]["TEST"]
    out = ["## 6. Anomaly Detection Metrics", "",
           "Detector only (no classifier). **Primary = streaming on the held-out TEST population.** Counts: "
           f"N = {te['streaming']['events']:,} events, {te['streaming']['attack_events']:,} attack events.", ""]
    hdr = ["Operating point", "Alerts", "TP", "FP", "FN", "TN", "Precision", "Recall", "F1", "FPR", "FNR", "Alert rate", "Incidents detected"]
    for s, title in (("streaming", "Streaming (as deployed) — PRIMARY"), ("frozen_batch", "Frozen batch"), ("shipped_batch_legacy", "Shipped batch (legacy, transductive)")):
        e = te[s]
        rows = [_op_row(n, e["operating_points"][n]) for n in e["operating_points"]]
        rk, rf = e["ranking_on_deployed_risk_score"], e["ranking_on_underlying_fused_score"]
        t1 = e["top_1pct_by_fused_score_no_ties"]
        t2 = e["top_1pct_by_deployed_risk_tie_aware"]
        out += [f"### {title}", "", tbl(hdr, rows), "",
                f"* Ranking: PR-AUC {f3(rk['pr_auc'], 4)} / ROC-AUC {f3(rk['roc_auc'], 4)} on the deployed risk score; "
                f"PR-AUC {f3(rf['pr_auc'], 4)} / ROC-AUC {f3(rf['roc_auc'], 4)} on the underlying fused score.",
                f"* **Top-1% ranking performance** (k = {t1['k']} events, NOT a queue): by fused score → Precision@1% {f3(t1['precision'], 4)}, Recall@1% {f3(t1['recall'], 4)} "
                f"(maximum possible recall {f3(t1['max_possible_recall'], 4)}); incidents in the top 1%: {t1['incidents']['detected']}/{t1['incidents']['incidents']}.",
                f"* By deployed risk, tie-aware: cut-off score {f3(t2['cutoff_score'], 3)}, tie group {t2['tie_group_size']} events "
                f"({'straddles the cut-off' if t2['tie_straddles_cutoff'] else 'does not straddle the cut-off'}); "
                f"Precision@1% expected {f3(t2['precision_expected'], 4)} (worst {f3(t2['precision_lower'], 4)} / best {f3(t2['precision_upper'], 4)}), "
                f"Recall@1% expected {f3(t2['recall_expected'], 4)} (worst {f3(t2['recall_lower'], 4)} / best {f3(t2['recall_upper'], 4)}).", ""]
    va = m["anomaly_detection"]["VALIDATION"]["streaming"]
    out += ["### VALIDATION population (streaming) — for context, NOT held out", "",
            tbl(hdr, [_op_row(n, va["operating_points"][n]) for n in va["operating_points"]]), ""]
    return "\n".join(out)


def _cls_row(name, r):
    return [name, f3(r["accuracy"], 3), f3(r["macro_precision"], 3), f3(r["macro_recall"], 3), f3(r["macro_f1"], 3), f3(r["weighted_f1"], 3),
            r["n"], ", ".join(r["classes_with_support"]) if len(r["classes_with_support"]) < 6 else "all 6"]


def _per_class(r):
    return tbl(["Class", "Precision", "Recall", "F1", "Support", "Predicted"],
               [[c, f3(v["precision"], 3), f3(v["recall"], 3), f3(v["f1"], 3), v["support"], v["predicted"]] for c, v in r["per_class"].items()])


def _cm(r):
    labs = r["labels"]
    return tbl(["true \\ pred"] + labs, [[labs[i]] + r["confusion_matrix"][i] for i in range(len(labs))])


def sec_classifier(m):
    c = m["classifier"]
    ab, cc, d = c["A_and_B_diagnostics"], c["C_chronological_leakage_safe"], c["D_shipped_classifier_on_streaming_alerts"]
    A, B1, B2 = ab["A_legacy_row_level_cv"], ab["B1_incident_grouped_loio"], ab["B2_incident_grouped_5fold"]
    pool = ab["pool"]
    rest = cc["restricted_to_classes_seen_in_training"]
    head = ["Methodology", "Accuracy", "Macro P", "Macro R", "Macro F1", "Weighted F1", "Rows", "Classes with support"]
    summary = tbl(head, [_cls_row("A. LEGACY row-level 5-fold CV (DIAGNOSTIC; incident leakage)", A),
                         _cls_row("B1. Incident-grouped leave-one-incident-out (DIAGNOSTIC)", B1),
                         _cls_row("B2. Incident-grouped 5-fold StratifiedGroupKFold (DIAGNOSTIC)", B2),
                         _cls_row("C. Chronological: fit on VALIDATION incidents → TEST (LEAKAGE-SAFE)", cc),
                         _cls_row("C'. same, restricted to classes seen in training", rest)])
    fpd = d["false_alert_predicted_class"]
    return f"""## 7. Classifier Metrics

The classifier is evaluated separately from the detector. The shipped classifier is never refitted; every fit below is an in-memory scratch classifier
(same class, same hyper-parameters). **The old row-level result is kept and clearly labelled; it is not hidden.**

**Pool used by the shipped methodology (rebuilt exactly, matches the shipped classifier's stored feature means: {pool['matches_shipped_classifier_feature_means']}):**
{pool['rows']} rows from {pool['incidents']} incidents, rows per class {json.dumps(pool['rows_per_class'])}, incidents per class {json.dumps(pool['incidents_per_class'])};
all rows in the shipped days-21–30 window: {pool['all_rows_in_shipped_test_window']}; rows in TRAIN: {pool['rows_in_train_window']}; rows inside the ML-2 TEST population: {pool['rows_in_ml2_test_population']}.

{summary}

*A and B use every incident, so they compare validation methodologies on identical data; only C is a held-out result.*
Class `credential_stuffing` has one incident; in B1 it can never be learned when that incident is held out.

### Per-class results

**A. Legacy row-level CV**

{_per_class(A)}

{_cm(A)}

**B1. Incident-grouped (leave-one-incident-out)**

{_per_class(B1)}

{_cm(B1)}

**B2. Incident-grouped 5-fold**

{_per_class(B2)}

**C. Chronological, leakage-safe** — trained on {cc['training']['classifier_train_rows']} rows ({json.dumps(cc['training']['classifier_train_rows_per_class'])}) from
{len(cc['training']['classifier_train_incidents'])} validation-born incidents; TEST attack events evaluated: {cc['n']}.
Classes present in TEST but absent from training (recall 0 by construction): {', '.join(cc['classes_absent_from_training_but_present_in_test']) or 'none'}.

{_per_class(cc)}

{_cm(cc)}

**C'. Restricted to classes the training set could know** ({', '.join(rest['classes'])}): accuracy {f3(rest['accuracy'], 3)}, macro F1 {f3(rest['macro_f1'], 3)}, weighted F1 {f3(rest['weighted_f1'], 3)} on {rest['n']} events.

### D. Shipped classifier on streaming alerts (TEST)

* **False alerts** (leakage-free — the shipped classifier never had a 'normal' class): {d['false_alerts']} false alerts; predicted class {json.dumps(fpd)};
  confidence median {f3(d['false_alert_confidence'].get('median'), 3)}, p90 {f3(d['false_alert_confidence'].get('p90'), 3)}; {d['false_alerts_with_confidence_ge_0_65_shown_as_likely']} of them at confidence ≥ 0.65 (worded "likely …" in the explanation).
* **True alerts** ({d['true_alerts']}): in-sample — the classifier was trained on all 36 incidents. Confidence median {f3(d['true_alert_confidence_IN_SAMPLE'].get('median'), 3)}; class accuracy {f3(d['true_alert_class_accuracy_IN_SAMPLE_not_a_performance_claim'], 3)} is **not** a performance claim."""


def sec_attack(m):
    out = ["## 8. Attack-Specific Metrics", "",
           "Streaming, as deployed. *Detected* = alert at the production threshold (event level); *top-1%* = inside the population's top 1% by fused score. "
           "Precision is only meaningful for the detector as a whole (an alert cannot be attributed to a type without the classifier), so it is not split by type. "
           "No ranking of attack types is implied.", ""]
    for pname, title in (("TEST", "held-out TEST population"), ("VALIDATION", "VALIDATION population (contains the low_slow_exfil incidents; NOT held out)")):
        pa = m["anomaly_detection"][pname]["streaming"]["per_attack"]
        rows = []
        for a in ATTACKS:
            r = pa[a]
            if r["events"] == 0:
                rows.append([a, 0, 0] + ["–"] * 9)
                continue
            rows.append([a, r["events"], r["incidents"], r["detected_events_at_production_threshold"], r["missed_events_at_production_threshold"],
                         pc(r["detection_rate_at_production_threshold"]), f"{r['incidents_detected_at_production_threshold']}/{r['incidents']}",
                         r["detected_events_in_top_1pct"], pc(r["detection_rate_in_top_1pct"]), f"{r['incidents_detected_in_top_1pct']}/{r['incidents']}",
                         f3(r["median_risk"], 2), f3(r["roc_auc_vs_negatives_fused"], 4)])
        out += [f"**{title}**", "", tbl(["Attack type", "Events", "Incidents", "Detected (prod. thr.)", "Missed", "Detection rate", "Incidents detected",
                                          "In top 1%", "Top-1% rate", "Incidents in top 1%", "Median risk", "ROC-AUC vs negatives (fused)"], rows), ""]
    pa = m["anomaly_detection"]["TEST"]["streaming"]["per_attack"]
    drows = []
    for a in ATTACKS:
        r = pa[a]
        if r["events"] == 0:
            continue
        drows.append([a, f3(r["risk_dist"]["min"], 2), f3(r["risk_dist"]["median"], 2), f3(r["risk_dist"]["p90"], 2), f3(r["risk_dist"]["p99"], 2), f3(r["risk_dist"]["max"], 2),
                      f3(r["fused_dist"]["median"], 4), r["alerts"]])
    out += ["**Score distribution per type (TEST, streaming):**", "", tbl(["Attack type", "risk min", "risk median", "risk p90", "risk p99", "risk max", "fused median", "Alerts"], drows), "",
            "**Same table, frozen batch (TEST) — detection at the production threshold:**", ""]
    pb = m["anomaly_detection"]["TEST"]["frozen_batch"]["per_attack"]
    out += [tbl(["Attack type", "Events", "Detected", "Detection rate", "Incidents detected", "In top 1%"],
                [[a, pb[a]["events"], pb[a].get("detected_events_at_production_threshold", "–"), pc(pb[a].get("detection_rate_at_production_threshold")),
                  f"{pb[a].get('incidents_detected_at_production_threshold', '–')}/{pb[a]['incidents']}", pb[a].get("detected_events_in_top_1pct", "–")]
                 for a in ATTACKS if pb[a]["events"]])]
    return "\n".join(out)


def sec_entity(m):
    e = m["entity_generalization"]
    if not e.get("available"):
        return "## 9. Entity Generalization\n\nHeld-out-entity run not available."
    rows = []
    for nm, r in e["results"].items():
        op = r["operating_points"]["production_threshold"]
        rk = r["ranking_on_underlying_fused_score"]
        rows.append([nm, r["events"], r["attack_events"], f3(rk["pr_auc"], 4), f3(rk["roc_auc"], 4), op["alerts"], op["tp"], op["fp"],
                     f3(op["precision"], 3), f3(op["recall"], 3), f"{op['incidents']['detected']}/{op['incidents']['incidents']}"])
    t = tbl(["Group (TEST population)", "Events", "Attack events", "PR-AUC (fused)", "ROC-AUC (fused)", "Alerts", "TP", "FP", "Precision", "Recall", "Incidents detected"], rows)
    nr = e["normal_event_risk_held_out_entities"]
    return f"""## 9. Entity Generalization

* **A. Known-entity chronological test** = every other section of this report (all 200 entities appear in TRAIN, the model holds a profile for each).
* **B. Held-out-entity experiment (PARTIAL — read the limitation):** {e['heldout_entity_count']} entities ({e['attacked_heldout_entities']} attacked) had their per-entity profile **removed**
  (they fall back to the `entity_type` peer prior), their training events were **excluded** from the warm-up (so their extractor history and the shared
  counters never saw them), and they are streamed cold from the start of VALIDATION.

{t}

Normal-event risk for the held-out entities (TEST): with state known — median {f3(nr['with_state_known'].get('median'), 2)}, p90 {f3(nr['with_state_known'].get('p90'), 2)}, p99 {f3(nr['with_state_known'].get('p99'), 2)};
with state removed — median {f3(nr['with_state_removed'].get('median'), 2)}, p90 {f3(nr['with_state_removed'].get('p90'), 2)}, p99 {f3(nr['with_state_removed'].get('p99'), 2)}.

**Limitations (not a clean held-out-entity generalisation test):**

{chr(10).join('* ' + x for x in e['limitations'])}

Held-out entity IDs are listed in `reports/ml2_split_manifest.json`. Group sizes are small; treat differences as descriptive."""


def sec_parity(m):
    p = m.get("api_feature_parity")
    if not p:
        return "## 10. API/Feature Parity\n\nParity stage not available."
    vs = p["variant_summary"]
    rows = []
    for v, s in vs.items():
        fc = ", ".join(f"{k} ({n})" for k, n in sorted(s["features_changed_counts"].items(), key=lambda t: -t[1])[:8]) or "none"
        rows.append([v, s["samples"], s["max_linf"] if s["max_linf"] == 0 else f3(s["max_linf"], 3), f3(s["mean_abs_risk_delta"], 3), f3(s["max_abs_risk_delta"], 3),
                     s["alert_flips_at_production_threshold"], fc])
    t1 = tbl(["Divergence vs training representation (V0)", "Events", "max L∞ feature diff", "mean |Δrisk|", "max |Δrisk|", "Alert flips", "Features changed (count of events)"], rows)
    ex = []
    for r in p["representative_events"]:
        if r["label"] in ATTACKS or r["sample"].startswith("normal:edge_device:6") or True:
            v1, v2, v3, v4 = (r["V1_entity_type_user"], r["V2_minutes_as_seconds"], r["V3_space_separated_commands"], r["V4_full_api_path"])
            ex.append([r["sample"], r["true_entity_type"], r["label"], f3(r["V0_risk"], 2), f3(v1["risk_delta"], 2), f3(v2["risk_delta"], 2), f3(v3["risk_delta"], 2), f3(v4["risk_delta"], 2),
                       ", ".join(v4["features_changed"][:6]) or "none"])
    t2 = tbl(["Sample", "True entity_type", "Label", "V0 risk", "Δ V1 (type→user)", "Δ V2 (min→s)", "Δ V3 (cmd sep.)", "Δ V4 (full API)", "Features changed by V4"], ex)
    ws = p["warmup_scope"]
    wrows = [[t, v["incidents"], f3(v["mean_risk_causal"], 2), f3(v["mean_risk_train_only"], 2), f3(v["mean_risk_all_days"], 2),
              f"{v['alerts_causal']}/{v['incidents']}", f"{v['alerts_train_only']}/{v['incidents']}", f"{v['alerts_all_days']}/{v['incidents']}",
              f"{v['novelty_fires_causal']}/{v['incidents']}", f"{v['novelty_fires_train_only']}/{v['incidents']}", f"{v['novelty_fires_all_days']}/{v['incidents']}"]
             for t, v in ws["by_type"].items()]
    t3 = tbl(["Attack type (first event of each incident)", "Incidents", "Mean risk: causal as-of", "Mean risk: TRAIN-only state", "Mean risk: all-days state (api.py)",
              "Alerts causal", "Alerts TRAIN-only", "Alerts all-days", "Novelty flag fires causal", "…TRAIN-only", "…all-days"], wrows)
    sc = ws["state_content_difference"]
    cf = p["code_facts"]
    return f"""## 10. API/Feature Parity

Representative events ({p['sample_size']}: first event of the first incident of every type + normal user/service/device events + normal events with commands) are shown in
several representations, each processed from an identical private copy of the causal state as of just before the event, with the profiler frozen
so differences are purely representational. **V0** = training/streaming representation (the CSV row); **V1** entity_type forced to `user` (as `api.py` does);
**V2** the platform's `sessionDurationMinutes` read as seconds; **V3** the platform's space-separated `commandSequence`; **V4** the real `api._canonical_event` on a platform-style payload.
(Streaming-vs-training feature identity is measured in §4.) Not fixed in ML-2.

{t1}

Per event (Δ = risk under the representation − risk under V0):

{t2}

**Warm-up scope.** `api.py` replays all 30 days (including every attack incident) before serving; `run_realtime.py`'s replay path uses the TRAIN window only. The first event of every
incident is presented as a *new* event arriving the day after each state's last event (same clock time), so no state is fed an event from its own future. "Causal as-of" is the state the streaming
evaluation actually had at the event's own time; it is **not comparable** to the two shifted columns (different gap since the entity's last event and different window contents), so compare the TRAIN-only and all-days columns with each other. Profiler frozen. The states also differ in how much *normal* history they hold, not only attack history:

{t3}

State content an all-days warm-up holds that a TRAIN-only warm-up does not: {sc['extra_fingerprints']} extra known fingerprints over {sc['entities_with_more_known_fingerprints']} entities,
{sc['extra_ips']} extra known IPs over {sc['entities_with_more_known_ips']} entities, {sc['extra_resources']} extra known resources over {sc['entities_with_more_known_resources']} entities,
{sc['extra_events_in_entity_counters']:,} extra events in entity counters; entries that exist only because of attack events: {json.dumps(sc['entries_that_exist_only_because_of_attack_events'])}.

Code facts (verified by reading the source): {'; '.join(f'{k}: {v}' for k, v in cf.items())}."""


def sec_shortcuts(m):
    s = m["dataset_shortcuts"]
    sf = s["single_field"]["TEST_evaluation_population"]
    rows = []
    for col, r in sorted(sf.items(), key=lambda t: -t[1]["auc_strength"])[:12]:
        best = r["best_single_threshold_rule"] or {}
        rows.append([col, f3(r["auc_strength"], 3)] + [f3(r["per_attack_auc_strength"].get(a), 2) for a in ATTACKS] +
                    [best.get("rule", ""), f3(best.get("precision"), 3), f3(best.get("recall"), 3), f3(best.get("f1"), 3)])
    t1 = tbl(["Single raw field (TEST)", "AUC (attack vs rest)"] + [f"{a[:12]}" for a in ATTACKS] + ["best 1-threshold rule", "precision", "recall", "F1"], rows)
    rr = s["one_line_rules"]["TEST_evaluation_population"]
    rrows = []
    for name, r in rr.items():
        rrows.append([name, r["alerts"], f3(r["precision"], 3), f3(r["recall"], 3)] + [pc(r["per_attack"][a]["rate"]) if r["per_attack"][a]["events"] else "–" for a in ATTACKS])
    t2 = tbl(["One-line rule (TEST)", "Alerts", "Precision", "Recall"] + [a[:12] for a in ATTACKS], rrows)
    te = m["anomaly_detection"]["TEST"]["streaming"]["per_attack"]
    det = tbl(["Detector (streaming, production threshold, TEST)"] + [a[:12] for a in ATTACKS],
              [["detection rate"] + [pc(te[a]["detection_rate_at_production_threshold"]) if te[a]["events"] else "–" for a in ATTACKS]])
    return f"""## 11. Dataset Shortcut Analysis

DIAGNOSTIC; the dataset is not modified. Each field below is a raw, history-free, per-event value; `ORACLE_*` fields use the generator's own entity
profile (`entity_profiles.json`), which the detector never sees. AUC strength = max(AUC, 1−AUC); per-attack columns are attack type vs normal.

{t1}

**One-line rules built only from raw fields** (R4 additionally uses generator-profile data the detector never sees):

{t2}

For comparison, what the production detector alerts on in the same population:

{det}

Interpretation guide: a near-1.0 AUC or a one-line rule that flags an attack type as well as the detector means this type can be separated by a generator artifact
(e.g. attackers use public IPs while all normal traffic uses private ranges; every brute-force event is a failed authentication from a fresh random city;
low_slow_exfil is written only in 00–04 / 22–23 hours) — so high detection of that type does not by itself demonstrate behavioural generalisation."""


def sec_repro(m, cmp=None):
    r = m["reproducibility"]
    env = r["environment"]
    rows = [[k, v] for k, v in env.items()]
    cur = {f.name: K.sha256_file(f) for f in sorted((K.ROOT / "eval_ml2").glob("*.py"))}
    chg = sorted(n for n in cur if cur[n] != r["eval_source_sha256"].get(n))
    CHANGED_TXT = ", ".join(f"`{n}`" for n in chg) if chg else "none"
    text = f"""## 12. Reproducibility

The whole evaluation (batch scoring, both streaming runs, parity, assembly) was executed **twice** as independent process trees (run A and run B, single-threaded numerics:
`OMP/MKL/OPENBLAS_NUM_THREADS=1`, `torch.set_num_threads(1)`).

{tbl(['Environment', 'Value'], rows)}

* **Seeds:** {json.dumps(r['seeds'])}
* **Model artifact:** SHA-256 `{r['model_artifact_sha256']}` (md5 `{r['model_artifact_md5']}`) — unchanged before/after.
* **Dataset MD5:** {json.dumps(r['dataset_md5'])}
* **Evaluation configuration:** SHA-256 `{r['eval_config_sha256']}`; frozen decisions SHA-256 `{r['decisions_sha256']}`.
* **Evaluation source hashes at the time the metrics were computed:** {json.dumps({k: v[:12] + '…' for k, v in r['eval_source_sha256'].items()})}
* **Modules edited after the metrics were computed:** {CHANGED_TXT} (the metric-producing modules `scoring`, `protocol`, `metrics`, `classifier_eval`, `parity`, `shortcuts`, `assemble`, `common`, `run` are listed as unchanged unless named here; report-rendering modules only change wording, not numbers — all numbers are read from `reports/ml2_metrics.json`).* {r['shipped_artifact_pickled_with_sklearn']}."""
    if cmp:
        arr = cmp["arrays"]
        arows = []
        for f, rows_ in arr.items():
            for k, v in rows_.items():
                if "max_abs_diff" in v:
                    arows.append([f, k, v["shape"], v["max_abs_diff"], v["n_elements_different"], v["identical"]])
        text += f"""

**Run A vs run B.** {cmp['metric_leaves_compared']:,} metric values compared with exact equality → **{cmp['metric_leaves_different']} differ**.
Raw score arrays were compared element by element (max |difference|; wall-clock latency excluded). Everything bit-identical: **{cmp['everything_bit_identical']}**.

{tbl(['File', 'Array', 'Shape', 'Max abs difference', 'Elements different', 'Bit-identical'], arows)}

Production files hashed before and after every stage of both runs: {json.dumps(cmp['production_hashes_unchanged_within_each_stage'])}."""
        if cmp["first_differences"]:
            text += "\n\nFirst differences: " + json.dumps(cmp["first_differences"][:10])
    return text

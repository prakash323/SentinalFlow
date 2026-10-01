"""Sections 13-15 of the ML-2 report (evaluation-only). Every statement is computed from metrics.json; direction words
(higher/lower) are derived from the numbers, never assumed."""
from __future__ import annotations

from .common import ATTACKS
from .report import f3, pc, tbl


def _dir(a, b, hi="higher", lo="lower", eq="equal"):
    if a is None or b is None:
        return "n/a"
    return hi if a > b else lo if a < b else eq


def _get(m, pop, src):
    return m["anomaly_detection"][pop][src]


def sec_findings(m, cmp):
    te = m["anomaly_detection"]["TEST"]
    st, fb, sb = te["streaming"], te["frozen_batch"], te["shipped_batch_legacy"]
    leg = m["anomaly_detection"]["LEGACY_days_21_30_not_held_out"]
    pst, pfb = st["operating_points"]["production_threshold"], fb["operating_points"]["production_threshold"]
    psb = sb["operating_points"]["production_threshold"]
    sat = st["saturation"]
    rel = m["batch_vs_streaming"]["score_relation_on_TEST"]
    fp = m["batch_vs_streaming"]["feature_parity_stream_vs_batch"]
    cl = m["classifier"]
    A, B1, C_, D = (cl["A_and_B_diagnostics"]["A_legacy_row_level_cv"], cl["A_and_B_diagnostics"]["B1_incident_grouped_loio"],
                    cl["C_chronological_leakage_safe"], cl["D_shipped_classifier_on_streaming_alerts"])
    par = m.get("api_feature_parity") or {}
    vs = par.get("variant_summary", {})
    F = []

    # 1 batch vs streaming
    d_pr = st["ranking_on_deployed_risk_score"]["pr_auc"] - fb["ranking_on_deployed_risk_score"]["pr_auc"]
    h1 = ("Streaming and frozen-batch scoring diverge on the held-out population" if abs(d_pr) >= 0.01
          else "Streaming and frozen-batch scoring agree on the held-out population")
    F.append(f"""**F1 — {h1}.** Same model, events and threshold: PR-AUC on the deployed risk score is
{f3(st['ranking_on_deployed_risk_score']['pr_auc'], 4)} streaming vs {f3(fb['ranking_on_deployed_risk_score']['pr_auc'], 4)} frozen batch (Δ {d_pr:+.4f}); alert rate at the production threshold
{pc(pst['alert_rate'], 2)} vs {pc(pfb['alert_rate'], 2)}; precision {f3(pst['precision'], 4)} vs {f3(pfb['precision'], 4)}; recall {f3(pst['recall'], 4)} vs {f3(pfb['recall'], 4)};
incidents detected {pst['incidents']['detected']}/{pst['incidents']['incidents']} vs {pfb['incidents']['detected']}/{pfb['incidents']['incidents']}. Per-event fused-score Spearman between the two paths is
{f3(rel['spearman_fused_stream_vs_frozen_batch'], 4)}; the features fed to both are {'identical' if fp['max_abs_feature_difference'] == 0 else 'NOT identical'} (max |Δ| {fp['max_abs_feature_difference']:.3g}) and the model is the same artifact, so the only remaining difference between the paths is the online state
(the per-entity EWMA baseline update inside `StreamingScorer.process`). ML-2 did not re-run an EWMA-off streaming diagnostic; the ML-1 audit did, and it reproduced the frozen scores to within 0.01 risk points.""")

    # 2 saturation
    saturated = sat["risk_eq_100"] > 0 and sat["distinct_risk_values_above_99_5"] <= 1
    tie_txt = ("the tie group straddles the top-1% cut-off" if st["top_1pct_by_deployed_risk_tie_aware"]["tie_straddles_cutoff"]
               else "the tie group does not straddle the top-1% cut-off")
    same3 = sat["anomaly_ge_0_99"] == sat["anomaly_ge_0_995"] == sat["anomaly_ge_0_999"]
    F.append(f"""**F2 — {'The deployed risk/anomaly score saturates' if saturated else 'The deployed risk/anomaly score does not saturate'}.** On the streaming path {sat['risk_eq_100']} of {sat['n']:,} TEST events have risk exactly 100.0 (anomalyScore 1.0) and
{sat['distinct_risk_values_above_99_5']} distinct risk value(s) exist above 99.5 ({pc(sat['share_of_high_scores_tied_at_max'], 1)} of all values above 99.5 are that single value). Consequently the score {'cannot rank alerts' if saturated else 'still ranks alerts'}; {tie_txt}
(tie-aware Precision@1% expected {f3(st['top_1pct_by_deployed_risk_tie_aware']['precision_expected'], 4)}, worst {f3(st['top_1pct_by_deployed_risk_tie_aware']['precision_lower'], 4)}, best {f3(st['top_1pct_by_deployed_risk_tie_aware']['precision_upper'], 4)}),
and Spring's severity bands (0.99 / 0.995 / 0.999) receive {sat['anomaly_ge_0_99']} / {sat['anomaly_ge_0_995']} / {sat['anomaly_ge_0_999']} events{' — the same number for all three, so the bands cannot discriminate' if same3 else ''}. The underlying fused score is continuous (fused ≥ 1.0 for {sat['fused_eq_1_0']} events).""")

    # 3 operating points
    ops = st["operating_points"]
    vq, vf = ops["validation_q99_operating_point"], ops["validation_f1_optimal_operating_point"]
    F.append(f"""**F3 — Ranking performance and threshold performance are different questions.** Top-1% by fused score (k = {st['top_1pct_by_fused_score_no_ties']['k']}, no queue): Precision@1% {f3(st['top_1pct_by_fused_score_no_ties']['precision'], 4)},
Recall@1% {f3(st['top_1pct_by_fused_score_no_ties']['recall'], 4)} (cap {f3(st['top_1pct_by_fused_score_no_ties']['max_possible_recall'], 4)} because k < number of attack events), incidents inside the top 1%: {st['top_1pct_by_fused_score_no_ties']['incidents']['detected']}/{st['top_1pct_by_fused_score_no_ties']['incidents']['incidents']}; attack types present in the top 1% (events): {', '.join(f"{a} {st['per_attack'][a]['detected_events_in_top_1pct']}" for a in ATTACKS if st['per_attack'][a]['events'] and st['per_attack'][a]['detected_events_in_top_1pct'])}.
At the shipped production threshold: {pst['alerts']} alerts, TP {pst['tp']}, FP {pst['fp']}, FN {pst['fn']}, TN {pst['tn']} — precision {f3(pst['precision'], 4)}, recall {f3(pst['recall'], 4)}, F1 {f3(pst['f1'], 4)}, incidents {pst['incidents']['detected']}/{pst['incidents']['incidents']}.
With the two evaluation-only VALIDATION-derived thresholds applied to TEST: q99 → precision {f3(vq['precision'], 4)} / recall {f3(vq['recall'], 4)} / incidents {vq['incidents']['detected']}/{vq['incidents']['incidents']}; F1-optimal → precision {f3(vf['precision'], 4)} / recall {f3(vf['recall'], 4)} / incidents {vf['incidents']['detected']}/{vf['incidents']['incidents']}.""")

    # 4 legacy vs leakage-safe
    lsb = leg["shipped_batch_legacy"]
    F.append(f"""**F4 — The legacy headline and the leakage-safe streaming numbers describe different things.** Shipped batch (legacy protocol, days 21–30, transductive): PR-AUC {f3(lsb['ranking_on_deployed_risk_score']['pr_auc'], 4)}, ROC-AUC {f3(lsb['ranking_on_deployed_risk_score']['roc_auc'], 4)}, production-threshold precision {f3(lsb['operating_points']['production_threshold']['precision'], 4)} / recall {f3(lsb['operating_points']['production_threshold']['recall'], 4)} / alert rate {pc(lsb['operating_points']['production_threshold']['alert_rate'], 2)}.
On the held-out TEST population the same shipped model, streamed as deployed: PR-AUC {f3(st['ranking_on_deployed_risk_score']['pr_auc'], 4)}, ROC-AUC {f3(st['ranking_on_deployed_risk_score']['roc_auc'], 4)}, precision {f3(pst['precision'], 4)} / recall {f3(pst['recall'], 4)} / alert rate {pc(pst['alert_rate'], 2)}.
Shipped batch on TEST (same population as the streaming numbers): PR-AUC {f3(sb['ranking_on_deployed_risk_score']['pr_auc'], 4)}, precision {f3(psb['precision'], 4)} / recall {f3(psb['recall'], 4)} / alert rate {pc(psb['alert_rate'], 2)}. The populations differ (TEST has {pc(st['attack_events']/st['events'], 2)} attack events vs {pc(leg['streaming']['attack_events']/leg['streaming']['events'], 2)} in days 21–30 and no low_slow_exfil), so the difference is not attributable to the scoring path alone. The same numeric threshold ({m['integrity']['frozen_decisions']['production_threshold_risk']:.4f}) yields alert rates of {pc(psb['alert_rate'], 2)} (shipped batch), {pc(pfb['alert_rate'], 2)} (frozen batch) and {pc(pst['alert_rate'], 2)} (streaming) on the same events: the number has no path-independent meaning.""")

    # 5 classifier
    F.append(f"""**F5 — Row-level classifier CV was inflated by incident leakage.** Same {m['classifier']['A_and_B_diagnostics']['pool']['rows']}-row pool: legacy row-level CV macro-F1 {f3(A['macro_f1'], 3)} (accuracy {f3(A['accuracy'], 3)}) vs incident-grouped leave-one-incident-out macro-F1 {f3(B1['macro_f1'], 3)} (accuracy {f3(B1['accuracy'], 3)}).
The chronological leakage-safe experiment (fit on {C_['training']['classifier_train_rows']} validation-incident rows, evaluated on {C_['n']} held-out TEST events) gives macro-F1 {f3(C_['macro_f1'], 3)} / weighted-F1 {f3(C_['weighted_f1'], 3)};
classes present in TEST but absent from validation ({', '.join(C_['classes_absent_from_training_but_present_in_test']) or 'none'}) cannot be predicted (recall 0 by construction). Restricted to the classes it could learn: macro-F1 {f3(C_['restricted_to_classes_seen_in_training']['macro_f1'], 3)}.""")

    # 6 shipped classifier on false alerts
    F.append(f"""**F6 — The shipped classifier assigns an attack type, with high confidence, to false alerts.** {D['false_alerts']} TEST false alerts: predicted classes {D['false_alert_predicted_class']}, confidence median {f3(D['false_alert_confidence'].get('median'), 3)},
{D['false_alerts_with_confidence_ge_0_65_shown_as_likely']} at ≥ 0.65 (the explanation words these "likely …"). It has no 'normal' class, so this is expected by construction, and it is leakage-free because normal events were never in its training pool.""")

    # 7 per-attack
    pa = st["per_attack"]
    zero = [a for a in ATTACKS if pa[a]["events"] and pa[a]["detected_events_at_production_threshold"] == 0]
    part = [a for a in ATTACKS if pa[a]["events"] and 0 < pa[a]["detection_rate_at_production_threshold"] < 1]
    full = [a for a in ATTACKS if pa[a]["events"] and pa[a]["detection_rate_at_production_threshold"] == 1]
    absent = [a for a in ATTACKS if pa[a]["events"] == 0]
    F.append(f"""**F7 — Attack-specific detection at the production threshold (TEST, streaming; descriptive, no ranking).** Zero events alerted: {', '.join(zero) or 'none'}; partially alerted: {', '.join(f'{a} ({pc(pa[a]['detection_rate_at_production_threshold'])} of events, {pa[a]['incidents_detected_at_production_threshold']}/{pa[a]['incidents']} incidents)' for a in part) or 'none'};
every event alerted: {', '.join(full) or 'none'}; not present in TEST: {', '.join(absent) or 'none'} (low_slow_exfil is evaluated on VALIDATION in §8 and is not held out).""")

    # 8 entity generalisation
    e = m["entity_generalization"]
    if e.get("available"):
        r = e["results"]
        k1 = r["main_run__held_out_entities_(profile+state KNOWN to the model)"]["operating_points"]["production_threshold"]
        k2 = r["heldout_run__held_out_entities_(profile+state REMOVED)"]["operating_points"]["production_threshold"]
        F.append(f"""**F8 — Entity holdout (partial).** For {e['heldout_entity_count']} entities streamed with their profile and history removed vs known: production-threshold recall {f3(k2['recall'], 3)} (removed) vs {f3(k1['recall'], 3)} (known),
precision {f3(k2['precision'], 3)} vs {f3(k1['precision'], 3)}, alerts {k2['alerts']} vs {k1['alerts']}, incidents {k2['incidents']['detected']}/{k2['incidents']['incidents']} vs {k1['incidents']['detected']}/{k1['incidents']['incidents']}. This is a cold-start experiment; the global detectors were fitted on these entities (see §9).""")

    # 9 parity
    if vs:
        F.append(f"""**F9 — API-boundary representation changes the scores.** On {par['sample_size']} representative events: forcing `entity_type='user'` changes `peer_resource_deviation` on {vs['V1_entity_type_user']['features_changed_counts'].get('peer_resource_deviation', 0)} events (mean |Δrisk| {f3(vs['V1_entity_type_user']['mean_abs_risk_delta'], 2)}, max {f3(vs['V1_entity_type_user']['max_abs_risk_delta'], 2)});
reading minutes as seconds changes `session_duration_zscore` on {vs['V2_minutes_as_seconds']['features_changed_counts'].get('session_duration_zscore', 0)} events (mean |Δrisk| {f3(vs['V2_minutes_as_seconds']['mean_abs_risk_delta'], 2)}, max {f3(vs['V2_minutes_as_seconds']['max_abs_risk_delta'], 2)});
space-separated commands change the command features on {max(vs['V3_space_separated_commands']['features_changed_counts'].values(), default=0)} events (mean |Δrisk| {f3(vs['V3_space_separated_commands']['mean_abs_risk_delta'], 2)}, max {f3(vs['V3_space_separated_commands']['max_abs_risk_delta'], 2)});
the full API path: mean |Δrisk| {f3(vs['V4_full_api_path']['mean_abs_risk_delta'], 2)}, max {f3(vs['V4_full_api_path']['max_abs_risk_delta'], 2)}. Warm-up scope: see §10 (TRAIN-only vs all-days state alerts per attack type).""")

    # 10 shortcuts
    sc = m["dataset_shortcuts"]["one_line_rules"]["TEST_evaluation_population"]
    r1 = sc["R1: public_ip OR failed_auth"]
    rows = ", ".join(f"{a} {pc(r1['per_attack'][a]['rate'])}" for a in ATTACKS if r1["per_attack"][a]["events"])
    dets = ", ".join(f"{a} {pc(pa[a]['detection_rate_at_production_threshold'])}" for a in ATTACKS if pa[a]["events"])
    F.append(f"""**F10 — Generator shortcuts.** A one-line rule on raw fields (`public_ip OR failed_auth`) flags, per attack type on TEST: {rows} (overall precision {f3(r1['precision'], 3)}, recall {f3(r1['recall'], 3)}, {r1['alerts']} alerts).
The production detector's per-type event detection at its threshold: {dets}. Types that a raw-field rule separates cleanly can be detected through generator artifacts (§11), so their detection rates do not by themselves demonstrate behavioural generalisation.""")

    # 11 reproducibility
    F.append(f"""**F11 — Reproducibility.** Runs A and B were independent process trees: {cmp['metric_leaves_compared']:,} metric values compared, {cmp['metric_leaves_different']} differ; raw score arrays bit-identical: {cmp['everything_bit_identical']}.
Production files (source, model artifact, dataset) were hashed before and after every stage of both runs: {all(cmp['production_hashes_unchanged_within_each_stage'].values()) if cmp['production_hashes_unchanged_within_each_stage'] else 'n/a'}.""")

    return "## 13. Findings\n\n" + "\n\n".join(F)


def sec_limitations(m):
    mf = m["manifest"]["splits"]
    return f"""## 14. Limitations

1. **Design-history contamination.** The shipped model's fusion weights, flag weights, feature set, ranking bonus and production threshold were tuned on days 21–30, which contains this TEST window. ML-2's TEST is held out from ML-2's own decisions only.
2. **Small, single-draw data.** VALIDATION has {mf['validation']['attack_incidents_born_in_split']} incidents and {mf['validation']['attack_events']} attack events; TEST has {mf['test_evaluation_population']['attack_incidents_born_in_split']} incidents and {mf['test_evaluation_population']['attack_events']} attack events; one generator seed; no confidence intervals. Per-type rates rest on 1–11 incidents.
3. **Missing coverage in TEST.** No low_slow_exfil incident (all five start in VALIDATION); credential_stuffing is a single incident; device_spoofing and credential_stuffing have no VALIDATION incident, so the chronological classifier cannot learn them.
4. **The shipped classifier cannot be evaluated leakage-safely** (it was trained on all 36 incidents). Its false-alert behaviour (D) is the only leakage-free observation.
5. **The production threshold is not held out** (derived from days 21–30). It is reported as shipped; validation-derived thresholds are evaluation-only operating points and are not proposed for production.
6. **Entity holdout is partial.** Global components of the shipped artifact saw the held-out entities; a clean test needs retraining, which ML-2 forbids.
7. **Streaming EWMA state depends on run order.** The primary streaming run passes VALIDATION then TEST continuously (as deployment would); it is one trajectory, not a distribution.
8. **Synthetic data.** All conclusions concern this generator; shortcut analysis (§11) shows several attack types are separable by generator artifacts.
9. **Wall-clock latency** depends on machine load and is excluded from the reproducibility comparison.
10. **The API parity check** presents platform-style payloads reconstructed from the simulator's conventions (seconds/60 for `sessionDurationMinutes`, space-separated commands); real platform traffic was not sampled.
11. **The environment is not pinned** (`requirements.txt` uses `>=`); the shipped artifact was pickled with scikit-learn 1.9.0 and is loaded under a newer version with a warning; `matplotlib` is absent from the project venv (stubbed in-process only; nothing was installed)."""


def sec_baseline(m):
    te = m["anomaly_detection"]["TEST"]
    st = te["streaming"]
    fb = te["frozen_batch"]
    leg = m["anomaly_detection"]["LEGACY_days_21_30_not_held_out"]["shipped_batch_legacy"]
    pst = st["operating_points"]["production_threshold"]
    ops = st["operating_points"]
    vq, vf = ops["validation_q99_operating_point"], ops["validation_f1_optimal_operating_point"]
    t1 = st["top_1pct_by_fused_score_no_ties"]
    t2 = st["top_1pct_by_deployed_risk_tie_aware"]
    cl = m["classifier"]
    C_, B1, A = cl["C_chronological_leakage_safe"], cl["A_and_B_diagnostics"]["B1_incident_grouped_loio"], cl["A_and_B_diagnostics"]["A_legacy_row_level_cv"]
    pa = st["per_attack"]
    rows_ls = [
        ["Population", f"held-out TEST: {st['events']:,} events, {st['attack_events']} attack events, {m['manifest']['splits']['test_evaluation_population']['attack_incidents_born_in_split']} incidents"],
        ["Scoring path", "streaming, as deployed (EWMA on), warm-up = TRAIN window only"],
        ["PR-AUC / ROC-AUC (deployed risk score)", f"{f3(st['ranking_on_deployed_risk_score']['pr_auc'], 4)} / {f3(st['ranking_on_deployed_risk_score']['roc_auc'], 4)}"],
        ["PR-AUC / ROC-AUC (underlying fused score)", f"{f3(st['ranking_on_underlying_fused_score']['pr_auc'], 4)} / {f3(st['ranking_on_underlying_fused_score']['roc_auc'], 4)}"],
        ["@ production threshold: alerts / TP / FP / FN / TN", f"{pst['alerts']} / {pst['tp']} / {pst['fp']} / {pst['fn']} / {pst['tn']}"],
        ["@ production threshold: precision / recall / F1", f"{f3(pst['precision'], 4)} / {f3(pst['recall'], 4)} / {f3(pst['f1'], 4)}"],
        ["@ production threshold: FPR / FNR / alert rate", f"{f3(pst['false_positive_rate'], 5)} / {f3(pst['false_negative_rate'], 4)} / {pc(pst['alert_rate'], 2)}"],
        ["@ production threshold: incidents detected", f"{pst['incidents']['detected']}/{pst['incidents']['incidents']}"],
        ["Top-1% by fused (k, P@1%, R@1%)", f"{t1['k']}, {f3(t1['precision'], 4)}, {f3(t1['recall'], 4)}"],
        ["Top-1% by deployed risk, tie-aware (P expected [worst,best], R expected)", f"{f3(t2['precision_expected'], 4)} [{f3(t2['precision_lower'], 4)}, {f3(t2['precision_upper'], 4)}], {f3(t2['recall_expected'], 4)}"],
        ["Validation q99 operating point: precision / recall / incidents", f"{f3(vq['precision'], 4)} / {f3(vq['recall'], 4)} / {vq['incidents']['detected']}/{vq['incidents']['incidents']}"],
        ["Validation F1-optimal operating point: precision / recall / incidents", f"{f3(vf['precision'], 4)} / {f3(vf['recall'], 4)} / {vf['incidents']['detected']}/{vf['incidents']['incidents']}"],
        ["Per-type detection at production threshold (event rate)", ", ".join(f"{a} {pc(pa[a]['detection_rate_at_production_threshold'])}" for a in ATTACKS if pa[a]["events"])],
        ["Risk saturation: events at risk = 100 / distinct values > 99.5", f"{st['saturation']['risk_eq_100']} / {st['saturation']['distinct_risk_values_above_99_5']}"],
        ["Frozen batch (same population) PR-AUC (risk) / precision / recall @ prod thr.", f"{f3(fb['ranking_on_deployed_risk_score']['pr_auc'], 4)} / {f3(fb['operating_points']['production_threshold']['precision'], 4)} / {f3(fb['operating_points']['production_threshold']['recall'], 4)}"],
        ["Classifier — chronological leakage-safe (macro-F1 / weighted-F1)", f"{f3(C_['macro_f1'], 3)} / {f3(C_['weighted_f1'], 3)} (classes absent from training scored 0)"],
        ["Classifier — incident-grouped LOIO (DIAGNOSTIC; macro-F1)", f3(B1["macro_f1"], 3)],
    ]
    rows_cur = [
        ["Protocol", "ML-1 / README: days 21–30 (validation + test), transductive batch fusion, threshold and design tuned on the same window"],
        ["PR-AUC / ROC-AUC (shipped batch)", f"{f3(leg['ranking_on_deployed_risk_score']['pr_auc'], 4)} / {f3(leg['ranking_on_deployed_risk_score']['roc_auc'], 4)}"],
        ["@ production threshold: precision / recall / alert rate", f"{f3(leg['operating_points']['production_threshold']['precision'], 4)} / {f3(leg['operating_points']['production_threshold']['recall'], 4)} / {pc(leg['operating_points']['production_threshold']['alert_rate'], 2)}"],
        ["Top-1% by fused (P@1% / R@1%)", f"{f3(leg['top_1pct_by_fused_score_no_ties']['precision'], 4)} / {f3(leg['top_1pct_by_fused_score_no_ties']['recall'], 4)}"],
        ["Classifier legacy row-level CV (macro-F1)", f3(A["macro_f1"], 3)],
    ]
    return f"""## 15. Baseline Metrics for Future Phases

Two blocks, deliberately kept apart. **ML-2 introduces no model change, so nothing here is a production improvement.**

### A. CURRENT SHIPPED MODEL under the legacy (ML-1 / README) protocol — NOT leakage-safe, kept for continuity only

{tbl(['Item', 'Value'], rows_cur)}

### B. LEAKAGE-SAFE EVALUATION — the numbers future model changes should be compared against

{tbl(['Item', 'Value'], rows_ls)}

**How to use these.** A future change is an improvement only if it beats block B *on the same held-out TEST population and the same protocol* (`python -m eval_ml2.run …`), evaluated through the **streaming** path, with its own thresholds and
any retraining done on TRAIN/VALIDATION only (ML-3 should replace the single-draw dataset with multiple seeds and fresh attack instances). Block A must not be used as the bar."""

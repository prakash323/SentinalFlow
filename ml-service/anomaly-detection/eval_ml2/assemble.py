"""Assemble stage (evaluation-only): turns the label-free score files into the ML-2 metrics.

ORDER OF OPERATIONS (enforced by LabelVault, recorded in the output):
  1. DEV STAGE   decisions are computed from TRAIN+VALIDATION labels only (test-period labels are masked):
                   - evaluation-only operating points from validation scores,
                   - the chronological classifier (fit on validation-born incidents).
  2. FREEZE      the decisions are serialised and hashed BEFORE any held-out label is read.
  3. UNSEAL      the held-out TEST labels are unsealed exactly once (a second call raises).
  4. FINAL EVAL  every held-out TEST metric is computed from the frozen decisions and the label-free scores.
  5. DIAGNOSTICS whole-dataset analyses (legacy classifier CV, incident-grouped CV, shortcut analysis, parity sample
                 selection) read labels through LabelVault.diagnostic() and are listed in the manifest. Nothing in
                 (1)-(4) depends on them.
"""
from __future__ import annotations

import time

import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_curve

from . import classifier_eval as CE
from . import common as K
from . import metrics as M
from . import shortcuts as SC
from .common import ATTACKS, C
from .protocol import Protocol, heldout_entities, manifest


def _npz(path):
    d = np.load(path, allow_pickle=False)
    return {k: d[k] for k in d.files}


def _full(N, ids, arr, fill=np.nan, dtype=float):
    a = np.full(N, fill, dtype=dtype)
    a[ids] = arr
    return a


def _pop_eval(src, mask, y_all, lab_all, aid_all, thr_prod, extra):
    risk, fused, alert = src["risk"][mask], src["fused"][mask], src["alert"][mask]
    y, lab, aid = y_all[mask], lab_all[mask], aid_all[mask]
    tk = M.top_k(y, fused, K.TOPK_FRAC)
    order = np.argsort(-fused, kind="stable")[: tk["k"]]
    topmask = np.zeros(len(y), dtype=bool)
    topmask[order] = True
    res = {
        "events": int(len(y)), "attack_events": int(y.sum()),
        "ranking_on_deployed_risk_score": M.rank_metrics(y, risk),
        "ranking_on_underlying_fused_score": M.rank_metrics(y, fused),
        "top_1pct_by_fused_score_no_ties": {**tk, "precision": tk["precision_expected"], "recall": tk["recall_expected"],
                                             "incidents": M.incident_detection(topmask, aid, y)},
        "top_1pct_by_deployed_risk_tie_aware": M.top_k(y, risk, K.TOPK_FRAC),
        "score_distribution": {"fused": M.dist(fused), "risk": M.dist(risk), "anomaly_score": M.dist(risk / 100.0)},
        "saturation": M.saturation(risk, fused),
        "operating_points": {},
    }
    ops = {"production_threshold": alert,
           "spring_alert_0.99_on_anomaly_score": risk >= K.SPRING_ALERT_RISK}
    for name, t in extra.items():
        ops[name] = fused >= t
    for name, a in ops.items():
        res["operating_points"][name] = {**M.operating_point(y, a), "incidents": M.incident_detection(a, aid, y)}
    res["per_attack"] = M.per_attack(lab, aid, risk, fused, alert, topmask, y)
    return res


def _cmp_rows(pop):
    """Batch vs streaming table rows for one population dict {source -> eval}."""
    def g(r, path):
        for k in path:
            r = r[k]
        return r
    rows = [
        ("PR-AUC (deployed risk score)", ["ranking_on_deployed_risk_score", "pr_auc"]),
        ("ROC-AUC (deployed risk score)", ["ranking_on_deployed_risk_score", "roc_auc"]),
        ("PR-AUC (underlying fused score)", ["ranking_on_underlying_fused_score", "pr_auc"]),
        ("ROC-AUC (underlying fused score)", ["ranking_on_underlying_fused_score", "roc_auc"]),
        ("Alert rate @ production threshold", ["operating_points", "production_threshold", "alert_rate"]),
        ("Precision @ production threshold", ["operating_points", "production_threshold", "precision"]),
        ("Recall @ production threshold", ["operating_points", "production_threshold", "recall"]),
        ("F1 @ production threshold", ["operating_points", "production_threshold", "f1"]),
        ("False-positive rate @ production threshold", ["operating_points", "production_threshold", "false_positive_rate"]),
        ("False-negative rate @ production threshold", ["operating_points", "production_threshold", "false_negative_rate"]),
        ("Precision@1% (ranked by fused, no ties)", ["top_1pct_by_fused_score_no_ties", "precision"]),
        ("Recall@1% (ranked by fused, no ties)", ["top_1pct_by_fused_score_no_ties", "recall"]),
        ("Precision@1% (deployed risk, tie-aware expected)", ["top_1pct_by_deployed_risk_tie_aware", "precision_expected"]),
        ("Recall@1% (deployed risk, tie-aware expected)", ["top_1pct_by_deployed_risk_tie_aware", "recall_expected"]),
    ]
    out = []
    for name, path in rows:
        vals = {s: g(pop[s], path) for s in pop}
        b, s_ = vals.get("frozen_batch"), vals.get("streaming")
        out.append({"metric": name, **vals, "difference_streaming_minus_frozen_batch":
                    (s_ - b) if (b is not None and s_ is not None) else None})
    return out


def assemble(p: Protocol, out_dir, log=print):
    t_start = time.time()
    from src.features import FEATURE_NAMES as FN
    art = K.load_artifact()
    thr = float(art["threshold"])
    N = len(p.events)
    assert (p.events["event_id"].to_numpy() == np.arange(N)).all(), "event_id must equal row index"

    batch = _npz(out_dir / "batch.npz")
    sm = _npz(out_dir / "stream_main.npz")
    has_held = (out_dir / "stream_heldout.npz").exists()
    sh = _npz(out_dir / "stream_heldout.npz") if has_held else None
    batch_checks = __import__("json").load(open(out_dir / "batch_checks.json"))
    stats_main = __import__("json").load(open(out_dir / "stream_main_stats.json"))
    stats_held = __import__("json").load(open(out_dir / "stream_heldout_stats.json")) if has_held else None
    parity = __import__("json").load(open(out_dir / "parity.json")) if (out_dir / "parity.json").exists() else None

    sid = sm["event_id"]
    stream_alert_matches_threshold = bool(np.all(sm["alert"] == (sm["risk"] >= thr)))
    sources = {
        "shipped_batch_legacy": {"risk": batch["risk_union"], "fused": batch["fused_union"], "alert": batch["risk_union"] >= thr},
        "frozen_batch": {"risk": batch["risk_event"], "fused": batch["fused_pct"], "alert": batch["risk_event"] >= thr},
        "streaming": {"risk": _full(N, sid, sm["risk"]), "fused": _full(N, sid, sm["fused"]),
                      "alert": _full(N, sid, sm["alert"], False, bool)},
    }

    vault = K.LabelVault(p.labels, is_test=p.m_test_raw)

    # ============================ 1. DEV STAGE (no held-out labels) ============================
    dev = vault.dev_labels()
    dev_lab = dev["label"].to_numpy()
    yv = np.isin(dev_lab[p.m_val], ATTACKS).astype(int)
    op_points = {}
    for name, s in sources.items():
        fv = s["fused"][p.m_val]
        q99 = float(np.quantile(fv, 0.99))
        prc, rcl, ths = precision_recall_curve(yv, fv)
        f1 = 2 * prc * rcl / np.maximum(prc + rcl, 1e-12)
        best = float(ths[int(np.argmax(f1[:-1]))])
        op_points[name] = {"validation_q99_fused": q99, "validation_f1_optimal_fused": best,
                           "validation_events": int(p.m_val.sum()), "validation_attack_events": int(yv.sum())}
    clf_c, clf_dec = CE.fit_chronological(p, sm, FN, dev)
    frozen = {"production_threshold_risk": thr, "spring_alert_risk": K.SPRING_ALERT_RISK, "operating_points": op_points,
              "chronological_classifier": clf_dec, "eval_config": K.EVAL_CONFIG}
    decisions_hash = K.sha256_obj(frozen)
    vault.log.append({"access": "decisions_frozen", "sha256": decisions_hash})
    log(f"[assemble] decisions frozen ({decisions_hash[:12]}); unsealing held-out test labels")

    # ============================ 3. UNSEAL (once) ============================
    full_labels = vault.unseal_test("final held-out evaluation of frozen decisions")
    lab_all = full_labels["label"].to_numpy()
    aid_all = full_labels["attack_id"].to_numpy()
    y_all = np.isin(lab_all, ATTACKS).astype(int)

    # ============================ 4. FINAL EVALUATION ============================
    pops = {"TEST": p.m_test, "VALIDATION": p.m_val, "LEGACY_days_21_30_not_held_out": p.m_legacy}
    ev = {}
    for pname, mask in pops.items():
        ev[pname] = {}
        for sname, s in sources.items():
            extra = {"validation_q99_operating_point": op_points[sname]["validation_q99_fused"],
                     "validation_f1_optimal_operating_point": op_points[sname]["validation_f1_optimal_fused"]}
            ev[pname][sname] = _pop_eval(s, mask, y_all, lab_all, aid_all, thr, extra)
    comparison = {pname: _cmp_rows(ev[pname]) for pname in pops}

    # score relation between paths on the held-out population
    m = p.m_test
    sb, ss = sources["frozen_batch"], sources["streaming"]
    relation = {
        "spearman_fused_stream_vs_frozen_batch": float(pd.Series(ss["fused"][m]).corr(pd.Series(sb["fused"][m]), method="spearman")),
        "mean_abs_fused_difference": float(np.mean(np.abs(ss["fused"][m] - sb["fused"][m]))),
        "mean_signed_fused_difference_stream_minus_batch": float(np.mean(ss["fused"][m] - sb["fused"][m])),
        "share_events_abs_risk_diff_gt_1": float(np.mean(np.abs(ss["risk"][m] - sb["risk"][m]) > 1.0)),
        "alerts_both": int((ss["alert"][m] & sb["alert"][m]).sum()), "alerts_stream_only": int((ss["alert"][m] & ~sb["alert"][m]).sum()),
        "alerts_batch_only": int((~ss["alert"][m] & sb["alert"][m]).sum()),
    }
    # features: streaming vs batch matrices for the same events
    fdiff = np.abs(sm["features"] - batch["features"][sid])
    feat_parity = {"events_compared": int(len(sid)), "max_abs_feature_difference": float(fdiff.max()),
                   "events_with_any_difference": int((fdiff.max(axis=1) > 1e-9).sum()),
                   "stream_alert_flag_equals_risk_ge_threshold": stream_alert_matches_threshold}

    # score distribution incl. classifier confidence on streaming alerts (held-out population)
    stream_conf = sm["conf"][sm["alert"]]
    dist_section = {
        "TEST": {s: {"fused": ev["TEST"][s]["score_distribution"]["fused"], "risk": ev["TEST"][s]["score_distribution"]["risk"],
                     "anomaly_score": ev["TEST"][s]["score_distribution"]["anomaly_score"], "saturation": ev["TEST"][s]["saturation"]}
                 for s in sources},
        "streaming_all_evaluation_period_val_plus_test": {"saturation": M.saturation(sm["risk"], sm["fused"], stream_conf),
                                                          "classifier_confidence_on_alerts": M.dist(stream_conf)},
    }

    # ---------------- entity generalisation ----------------
    ent_sec = {"available": has_held}
    if has_held:
        held = set(stats_held["heldout_entities"])
        is_h = p.events["entity_id"].isin(held).to_numpy()
        hid = sh["event_id"]
        held_src = {"risk": _full(N, hid, sh["risk"]), "fused": _full(N, hid, sh["fused"]),
                    "alert": _full(N, hid, sh["alert"], False, bool)}
        parts = {"main_run__known_entities_(non-held-out)": (sources["streaming"], p.m_test & ~is_h),
                 "main_run__held_out_entities_(profile+state KNOWN to the model)": (sources["streaming"], p.m_test & is_h),
                 "heldout_run__held_out_entities_(profile+state REMOVED)": (held_src, p.m_test & is_h)}
        ent_sec.update({"heldout_entity_count": len(held), "attacked_heldout_entities": int(len({e for e, l, s in zip(
            p.events["entity_id"], lab_all, p.split) if e in held and l in ATTACKS and s != "train"})),
            "population": "TEST (held-out) population", "results": {}})
        for nm, (src, mk) in parts.items():
            extra = {"validation_q99_operating_point": op_points["streaming"]["validation_q99_fused"]}
            ent_sec["results"][nm] = _pop_eval(src, mk, y_all, lab_all, aid_all, thr, extra)
        mk = p.m_test & is_h & (lab_all == "normal")
        ent_sec["normal_event_risk_held_out_entities"] = {
            "with_state_known": M.dist(sources["streaming"]["risk"][mk]), "with_state_removed": M.dist(held_src["risk"][mk])}
        ent_sec["limitations"] = [
            "PARTIAL held-out: the entity's own profile (per-entity mean/var/n) and extractor history were removed and its "
            "warm-up events were excluded from the shared counters.",
            "The GLOBAL components (Isolation Forest, sequence autoencoder, StandardScaler, calibration curves, peer priors) of the "
            "shipped artifact were fitted on all 200 entities' training traffic and cannot be un-fitted without retraining, which "
            "ML-2 forbids. This is a cold-start experiment, NOT a clean held-out-entity generalisation test."]
        ent_sec["heldout_entity_ids"] = sorted(held)

    # ============================ 5. DIAGNOSTICS (logged label reads) ============================
    diag_labels = vault.diagnostic("classifier A/B: legacy pool rebuild + incident-grouped CV (whole-dataset incidents)")
    clf_ab = CE.diagnostics_legacy_vs_grouped(p, batch, FN, diag_labels, art["classifier"], log=log)
    clf_c_eval = CE.evaluate_chronological(p, sm, FN, clf_c, clf_dec, full_labels)
    clf_d = CE.shipped_classifier_on_alerts(p, sm, full_labels)
    vault.diagnostic("shortcut analysis (whole dataset)")
    shortcuts = SC.analyse(p, diag_labels)
    log("[assemble] classifier + shortcut analyses done")

    # streaming latency / drift
    lat = sm["latency_ms"]
    streaming_runtime = {"latency_ms": M.dist(lat), "events_scored": int(len(lat)),
                         "note": "wall-clock; depends on machine load and is NOT part of the reproducibility comparison",
                         "drift_notices": stats_main.get("drift_notices")}

    # ---------------- reproducibility record ----------------
    repro = {"eval_config": K.EVAL_CONFIG, "eval_config_sha256": K.sha256_obj(K.EVAL_CONFIG),
             "decisions_sha256": decisions_hash, "environment": K.env_info(),
             "model_artifact_sha256": K.sha256_file(K.ROOT / "models" / "pipeline.joblib"),
             "model_artifact_md5": K.md5_file(K.ROOT / "models" / "pipeline.joblib"),
             "dataset_md5": {f: K.md5_file(K.DATA / f) for f in ("events.csv", "labels.csv", "entity_profiles.json")},
             "eval_source_sha256": {f.name: K.sha256_file(f) for f in sorted((K.ROOT / "eval_ml2").glob("*.py"))},
             "seeds": {"eval_seed": K.EVAL_SEED, "production_seed(config.RANDOM_SEED)": C.RANDOM_SEED,
                       "lightgbm_random_state": C.RANDOM_SEED, "torch": "inference only (no sampling); torch threads=1",
                       "numeric_threads": "OMP/MKL/OPENBLAS = 1"},
             "shipped_artifact_pickled_with_sklearn": "1.9.0 (load emits a version warning under the installed version)"}

    metrics = {
        "meta": {"generated_seconds": round(time.time() - t_start, 1), "run_dir": out_dir.name},
        "manifest": manifest(p, heldout_entities(p)),
        "integrity": {
            "label_vault_log": vault.log, "test_unseal_count": vault.test_unseals,
            "decisions_frozen_before_unseal": True, "decisions_sha256": decisions_hash,
            "train_window_is_the_shipped_fit_window": batch_checks["train_integrity"],
            "vectorised_mappings_vs_production_functions": {k: v for k, v in batch_checks.items() if k != "train_integrity"},
            "streaming_alert_flag_equals_risk_ge_shipped_threshold": stream_alert_matches_threshold,
            "streaming_warmup": {"warm_events": stats_main["warm_events"], "scope": "TRAIN window only",
                                 "profiler_ewma_updates": "ON (as deployed)"},
            "frozen_decisions": frozen,
        },
        "batch_vs_streaming": {"comparison_tables": comparison, "score_relation_on_TEST": relation, "feature_parity_stream_vs_batch": feat_parity},
        "score_distribution": dist_section,
        "anomaly_detection": ev,
        "classifier": {"A_and_B_diagnostics": clf_ab, "C_chronological_leakage_safe": clf_c_eval,
                       "D_shipped_classifier_on_streaming_alerts": clf_d},
        "entity_generalization": ent_sec,
        "api_feature_parity": parity,
        "dataset_shortcuts": shortcuts,
        "streaming_runtime": streaming_runtime,
        "reproducibility": repro,
    }
    K.write_json(out_dir / "metrics.json", metrics)
    log(f"[assemble] wrote metrics.json in {time.time()-t_start:.0f}s")
    return metrics

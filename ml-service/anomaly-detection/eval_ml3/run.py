"""ML-3 runner: one complete, self-contained training + evaluation run.  python -m eval_ml3.run --run-id A

ORDER (label access is enforced by construction, not by convention):
  0  hash every production file; build the ML-2 split; assert it equals the published ML-2 split; write the immutable manifest
  1  features on the DEV stream only (events with t < validation end; TEST events do not exist for stages 1-4)
  2  FIT every learned component on TRAIN rows only; save candidate components
  3  SELECT on VALIDATION with dev labels (test-period labels are masked): fusion weights, baseline mode, operating threshold,
     classifier (incident-grouped)
  4  FREEZE: write + hash the candidate config (read-only)
  5  TEST: features on the full stream, prefix-equality check vs the dev stream, TEST scored with the frozen candidate,
     test labels unsealed exactly ONCE, metrics
  6  POST-HOC diagnostics (shortcut permutation, rules, signal ablation) - logged, never fed back
  7  engine check (my causal replay == the unmodified production StreamingScorer, on the shipped model; label-free)
  8  hash every production file again
"""
from __future__ import annotations

import os

for _v in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
    os.environ[_v] = "1"
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

import argparse                                  # noqa: E402
import copy                                      # noqa: E402
import hashlib                                   # noqa: E402
import json                                      # noqa: E402
import stat                                      # noqa: E402
import sys                                       # noqa: E402
import time                                      # noqa: E402

import joblib                                    # noqa: E402
import numpy as np                               # noqa: E402
import pandas as pd                              # noqa: E402

from . import candidate as CD                    # noqa: E402
from . import classify3 as CL                    # noqa: E402
from . import common as K                        # noqa: E402
from . import diagnostics as DG                  # noqa: E402
from . import evaluate as EV                     # noqa: E402
from . import protocol3 as P3                    # noqa: E402
from .common import ATTACKS, C                   # noqa: E402

from eval_ml2 import metrics as M2               # noqa: E402
from src.features import FEATURE_NAMES, build_feature_matrix    # noqa: E402


def _log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def arrays_hash(d: dict) -> dict:
    return {k: hashlib.sha256(np.ascontiguousarray(v).tobytes()).hexdigest() for k, v in d.items()}


def source_hashes() -> dict:
    root = K.ROOT / "eval_ml3"
    return {f"eval_ml3/{p.name}": K.sha256_file(p) for p in sorted(root.glob("*.py"))}


def _ro(path):
    os.chmod(path, stat.S_IREAD)


def run(run_id: str, skip_diagnostics=False, skip_engine=False):
    t_all = time.time()
    out = K.REPORTS / "ml3_runs" / run_id
    cand_dir = out / "candidate"
    out.mkdir(parents=True, exist_ok=True)
    cand_dir.mkdir(parents=True, exist_ok=True)
    import torch
    torch.set_num_threads(1)
    M: dict = {"meta": {"run_id": run_id, "phase": "ML-3", "eval_config": K.ML3_CONFIG}}

    # ------------------------------------------------------------------ 0. integrity + protocol
    before = K.production_hashes()
    K.write_json(out / "hashes_before.json", before)
    p = P3.build()
    cmp2 = P3.assert_matches_ml2(p)
    man = P3.manifest(p, cmp2)
    man_path = out / "split_manifest.json"
    h_man = P3.write_immutable(man_path, man)
    _log(f"split == ML-2 split ({cmp2['fields_compared']} fields); assignment sha256 {man['ml3']['assignment_sha256'][:16]}; manifest {h_man[:16]}")
    vault = K.LabelVault(p.labels, p.m_test_raw)
    dev = vault.dev_labels()
    lab_dev = dev["label"].to_numpy(dtype=object)                  # test-period rows are None
    aid_dev = dev["attack_id"].to_numpy(dtype=object)
    n_all = len(p.events)
    is_dev = ~p.m_test_raw
    n_dev = int(is_dev.sum())
    assert is_dev[:n_dev].all() and not is_dev[n_dev:].any(), "dev rows must be a chronological prefix"
    ntr = int(p.m_train.sum())
    nva = int(p.m_val.sum())
    assert ntr + nva == n_dev
    M["split"] = {"train_rows": ntr, "validation_rows": nva, "test_raw_rows": n_all - n_dev, "test_population_rows": int(p.m_test.sum()),
                  "manifest_sha256": h_man, "assignment_sha256": man["ml3"]["assignment_sha256"], "identical_to_ml2": cmp2}

    # ------------------------------------------------------------------ 1. dev features (TEST events are not in this stream)
    t = time.time()
    X_dev = build_feature_matrix(p.events.iloc[:n_dev], verbose=False)
    _log(f"dev features {X_dev.shape} ({time.time()-t:.0f}s)")
    Xtr = X_dev.iloc[:ntr].reset_index(drop=True)
    Xva = X_dev.iloc[ntr:].reset_index(drop=True)

    # ------------------------------------------------------------------ 2. FIT on TRAIN only
    fs = CD.select_features(Xtr)
    feats = fs["model_features"]
    _log(f"feature policy: {fs['production_feature_count']} -> {fs['model_feature_count']}; excluded {fs['excluded']}")
    shift = CD.feature_shift_table(Xtr, Xva)
    m, b_tr, iso_tr, seq_tr = CD.fit(Xtr, feats, _log)

    # window / causality checks
    S_dev = CD.build_sequences_cols(X_dev, feats)
    S_tr = CD.build_sequences_cols(Xtr, feats)
    prev = CD.window_index(X_dev["entity_id"].to_numpy())
    F32 = X_dev[feats].to_numpy(dtype=np.float32)
    from src.detect import build_sequences as prod_build_sequences
    S_prod = prod_build_sequences(X_dev.iloc[:6000])
    S_mine35 = CD.build_sequences_cols(X_dev.iloc[:6000], list(FEATURE_NAMES))
    win_checks = {
        "train_windows_identical_when_built_from_train_rows_only_vs_full_dev_stream": bool(np.array_equal(S_dev[:ntr], S_tr)),
        "vectorised_window_index_identical_to_loop": bool(np.array_equal(CD.windows_from(F32, prev, np.arange(n_dev)), S_dev)),
        "candidate_window_builder_identical_to_production_build_sequences_on_35_features": bool(np.array_equal(S_prod, S_mine35)),
        "validation_windows_that_contain_zero_padding": int(CD._padded(X_dev)[ntr:].sum()),
        "train_windows_that_contain_zero_padding": int(CD._padded(X_dev)[:ntr].sum()),
        "train_windows": ntr,
        "validation_windows_that_include_train_history": int(((prev[ntr:] >= 0) & (prev[ntr:] < ntr)).any(axis=1).sum()),
    }
    assert win_checks["train_windows_identical_when_built_from_train_rows_only_vs_full_dev_stream"]
    assert win_checks["vectorised_window_index_identical_to_loop"] and win_checks["candidate_window_builder_identical_to_production_build_sequences_on_35_features"]
    _log(f"window checks {win_checks}")

    comp_path = cand_dir / "components.joblib"
    joblib.dump({"features": m.features, "profiler": m.profiler, "scaler": m.scaler, "iforest": m.iforest, "seq_ae": m.seq_ae,
                 "sig_calib": m.sig_calib, "note": "ML-3 candidate components fitted on TRAIN only; NOT the production model"}, comp_path)
    chash = CD.content_hashes(m)
    M["training"] = {"fit_info": m.fit_info, "content_hashes": chash, "components_file_sha256": K.sha256_file(comp_path),
                     "feature_set": fs, "feature_shift_train_vs_validation": shift, "window_checks": win_checks,
                     "trained_on": {"rows": ntr, "period": [man["splits"]["train"]["start"], man["splits"]["train"]["end"]],
                                    "attack_events_in_train": man["splits"]["train"]["attack_events"]}}

    # ------------------------------------------------------------------ 3. SELECT on VALIDATION (dev labels only)
    iso_va, seq_va = CD.iso_seq(m, Xva, S_dev[ntr:])
    lab_va = lab_dev[ntr:n_dev]
    aid_va = aid_dev[ntr:n_dev]
    assert all(l is not None for l in lab_va)
    y_va = EV.is_attack(lab_va).astype(int)
    calib = m.sig_calib
    prof_train_state = copy.deepcopy(m.profiler)                # the TRAIN-end baseline state, kept pristine
    w_eq = {k: 1 / 3 for k in K.SIGNALS}
    b_frozen, _, _ = CD.replay(copy.deepcopy(prof_train_state), Xva, iso_va, seq_va, calib, w_eq, np.inf, False)
    P = {"baseline": CD.pct(calib, "baseline", b_frozen), "iforest": CD.pct(calib, "iforest", iso_va), "sequence": CD.pct(calib, "sequence", seq_va)}
    grid = []
    for wb, wi, ws in CD.simplex_grid():
        f = (wb * P["baseline"] + wi * P["iforest"] + ws * P["sequence"])
        mt = EV.macro_type_prauc(lab_va, f)
        rk = M2.rank_metrics(y_va, f)
        grid.append({"w": {"baseline": wb, "iforest": wi, "sequence": ws}, "macro_type_pr_auc": mt["macro_pr_auc"], "per_type_pr_auc": mt["per_type_pr_auc"],
                     "event_pr_auc": rk["pr_auc"], "roc_auc": rk["roc_auc"]})
    # equal weights are not on a 0.1 grid; evaluate them explicitly
    f_eq = (P["baseline"] + P["iforest"] + P["sequence"]) / 3
    eq_mt = EV.macro_type_prauc(lab_va, f_eq)
    eq_rk = M2.rank_metrics(y_va, f_eq)
    eq_row = {"w": w_eq, "macro_type_pr_auc": eq_mt["macro_pr_auc"], "per_type_pr_auc": eq_mt["per_type_pr_auc"], "event_pr_auc": eq_rk["pr_auc"], "roc_auc": eq_rk["roc_auc"]}
    best = max(grid, key=lambda g: (g["macro_type_pr_auc"], 0))          # first maximum in grid order (deterministic)
    parsimony = best["macro_type_pr_auc"] - eq_row["macro_type_pr_auc"] <= K.FUSION_PARSIMONY_MARGIN
    chosen = eq_row if parsimony else best
    w = dict(chosen["w"])
    shipped_row = next(g for g in grid if all(abs(g["w"][k] - K.SHIPPED_FUSION_WEIGHTS[k]) < 1e-9 for k in K.SIGNALS))
    fusion_sel = {"criterion": "macro per-attack-type PR-AUC of the fused score on VALIDATION (types present in validation: "
                               f"{sorted(eq_mt['types'])}), frozen baseline", "grid_step": K.FUSION_GRID_STEP, "grid_points": len(grid),
                  "best_on_grid": best, "equal_weights": eq_row, "parsimony_margin": K.FUSION_PARSIMONY_MARGIN,
                  "best_minus_equal": best["macro_type_pr_auc"] - eq_row["macro_type_pr_auc"], "parsimony_applied": bool(parsimony),
                  "selected_weights": w, "selected_validation": chosen,
                  "shipped_weights_0.6_0.2_0.2_on_validation": shipped_row,
                  "shipped_weights_status": "INHERITED (tuned on days 21-30 = validation + test); shown for reference only, not used as validated",
                  "grid": grid}
    _log(f"fusion: best {best['w']} macro-PR {best['macro_type_pr_auc']:.4f} | equal {eq_row['macro_type_pr_auc']:.4f} | shipped {shipped_row['macro_type_pr_auc']:.4f} -> selected {w}")

    fused_tr = CD.fuse(calib, {"baseline": b_tr, "iforest": iso_tr, "sequence": seq_tr}, w)
    calib_fused = np.sort(fused_tr)
    fused_max = float(calib_fused[-1])
    # mode selection
    _, f_frozen, _ = CD.replay(copy.deepcopy(prof_train_state), Xva, iso_va, seq_va, calib, w, np.inf, False)   # same function as the test stage
    prof_e = copy.deepcopy(prof_train_state)
    b_ew, f_ew, g_ew = CD.replay(prof_e, Xva, iso_va, seq_va, calib, w, fused_max, True)
    mode_rows = {}
    for nm, f in (("frozen", f_frozen), ("ewma_guarded", f_ew)):
        mt = EV.macro_type_prauc(lab_va, f)
        rk = M2.rank_metrics(y_va, f)
        mode_rows[nm] = {"macro_type_pr_auc": mt["macro_pr_auc"], "per_type_pr_auc": mt["per_type_pr_auc"], "event_pr_auc": rk["pr_auc"], "roc_auc": rk["roc_auc"]}
    mode_rows["ewma_guarded"]["events_blocked_by_guard"] = int(g_ew.sum())
    mode = "ewma_guarded" if mode_rows["ewma_guarded"]["macro_type_pr_auc"] - mode_rows["frozen"]["macro_type_pr_auc"] > K.MODE_MARGIN else "frozen"
    ewma = mode == "ewma_guarded"
    f_va = f_ew if ewma else f_frozen
    b_va = b_ew if ewma else b_frozen
    _log(f"baseline mode: frozen {mode_rows['frozen']['macro_type_pr_auc']:.4f} vs ewma {mode_rows['ewma_guarded']['macro_type_pr_auc']:.4f} -> {mode}")
    risk_va = CD.risk_event_level(calib_fused, f_va)

    f1opt = EV.f1_optimal_threshold(y_va, f_va)
    thr = f1opt["threshold"]
    q99 = float(np.quantile(f_va, 0.99))
    art = K.load_artifact()
    prod_thr = float(art["threshold"])
    del art
    thresholds = {"candidate_validation_f1_optimal": ("fused", thr), "candidate_validation_q99_label_free": ("fused", q99),
                  "shipped_production_risk_threshold_reference_only": ("risk", prod_thr)}

    # per-signal distribution shift on VALIDATION normals (TRAIN in-sample vs out-of-sample)
    negm = np.isin(lab_va, EV.NEGATIVE)
    shift_stats = {"validation_negative_events": int(negm.sum()),
                   "median_train_percentile_of_validation_negatives": {k: float(np.median(P[k][negm])) for k in K.SIGNALS},
                   "share_of_validation_negatives_above_train_max": {"baseline": float((b_va[negm] > calib["baseline"][-1]).mean()),
                                                                     "iforest": float((iso_va[negm] > calib["iforest"][-1]).mean()),
                                                                     "sequence": float((seq_va[negm] > calib["sequence"][-1]).mean())},
                   "share_of_validation_negatives_fused_ge_train_fused_max": float((f_va[negm] >= fused_max).mean()),
                   "note": "TRAIN scores are in-sample (the models saw those rows), so out-of-sample events tend to land above the TRAIN median."}

    validation = EV.evaluate_population("VALIDATION", lab_va, aid_va, f_va, risk_va, thresholds)
    validation["signal_ablation"] = DG.signal_ablation(lab_va, {"baseline": b_va, "iforest": iso_va, "sequence": seq_va}, f_va, calib)
    validation["threshold_selection_note"] = "F1-optimal threshold was CHOSEN on this population, so its validation precision/recall are optimistic by construction."

    # classifier (incident-grouped), validation-born incidents only
    pool = CL.build_pool(lab_va, aid_va, f_va, np.ones(nva, dtype=bool))
    support = CL.class_support(pool)
    trainable = [t for t in ATTACKS if support[t]["training_possible"]]
    Fva_all = Xva[feats].to_numpy(dtype=float)
    clf_info = {"support": support, "trainable_classes": trainable, "pool_rows": int(len(pool)), "pool_incidents": int(pool.attack_id.nunique()) if len(pool) else 0,
                "pool_rule": f"top {K.CLASSIFIER_MAX_PER_INCIDENT} events per validation-born incident by frozen fused score",
                "abstain_conf": K.ABSTAIN_CONF, "unknown_label": CL.UNKNOWN, "features": feats}
    clf = None
    if len(trainable) >= 2:
        Fp = Fva_all[pool.idx.to_numpy()]
        clf_info["grouped_cv"] = CL.grouped_cv(Fp, pool, trainable)
        sel = pool.label.isin(trainable).to_numpy()
        clf = CL.fit(Fp[sel], pool.label.to_numpy(dtype=object)[sel])
        clf_info["classes"] = list(clf.classes_)
        clf_info["fit_rows"] = int(sel.sum())
        clf_hash = CD.classifier_hash(clf)
        joblib.dump({"model": clf, "classes": list(clf.classes_), "features": feats, "abstain_conf": K.ABSTAIN_CONF}, cand_dir / "classifier.joblib")
        clf_info["classifier_content_sha256"] = clf_hash
    else:
        clf_info["classes"] = []
        clf_info["note"] = CL.INSUFFICIENT + " Fewer than two classes are trainable: every alert is reported as UNKNOWN."
    M["classifier_selection"] = clf_info
    _log(f"classifier: trainable {trainable}; pool rows {len(pool)}")

    # ------------------------------------------------------------------ 4. FREEZE
    cfg = {"candidate": "ML-3 leakage-safe candidate (NOT deployed; production model untouched)",
           "features": feats, "excluded_features": fs["excluded_reasons"], "fusion_weights": w,
           "baseline": {"mode": mode, "update": "EWMA alpha=%s with poisoning guard (fused >= max TRAIN fused blocks the update)" % C.EWMA_ALPHA if ewma else "none (frozen TRAIN profile)",
                        "guard_fused_max": fused_max},
           "score_transform": "per-signal percentile against the sorted TRAIN raw scores (searchsorted, side=right)",
           "risk": "99 x TRAIN-fused CDF; an event at/above the whole TRAIN fused range = 100 (percentile, not a probability)",
           "thresholds": {"primary_fused": thr, "primary_rule": "F1-optimal on VALIDATION", "label_free_q99_fused": q99},
           "classifier": {"classes": clf_info.get("classes", []), "abstain_conf": K.ABSTAIN_CONF, "unknown": CL.UNKNOWN},
           "components_content_hash": chash["combined"], "split_manifest_sha256": h_man, "ml3_config_sha256": K.sha256_obj(K.ML3_CONFIG)}
    cfg_path = cand_dir / "candidate_config.json"
    K.write_json(cfg_path, cfg)
    _ro(cfg_path)
    h_cfg = K.sha256_file(cfg_path)
    np.savez_compressed(out / "dev_signals.npz", event_id=Xva["event_id"].to_numpy(), iso=iso_va, seq=seq_va, baseline=b_va, fused=f_va, risk=risk_va)
    M["selection"] = {"fusion": fusion_sel, "baseline_mode": {"criterion": fusion_sel["criterion"], "margin": K.MODE_MARGIN, "rows": mode_rows, "selected": mode},
                      "operating_threshold": {"f1_optimal_validation": f1opt, "q99_validation": q99, "shipped_production_risk_threshold": prod_thr},
                      "score_shift_train_to_validation": shift_stats}
    M["validation"] = validation
    M["frozen"] = {"config_sha256": h_cfg, "config": cfg, "frozen_before_test_unseal": True, "test_unseals_so_far": vault.test_unseals}
    _log(f"FROZEN: config sha256 {h_cfg[:16]} | weights {w} | mode {mode} | thr {thr:.6f}")

    # ------------------------------------------------------------------ 5. TEST (once)
    assert K.sha256_file(cfg_path) == h_cfg
    cfg2 = json.load(open(cfg_path, encoding="utf-8"))
    comp = joblib.load(comp_path)
    m2 = CD.Candidate(comp["features"])
    m2.profiler, m2.scaler, m2.iforest, m2.seq_ae, m2.sig_calib = comp["profiler"], comp["scaler"], comp["iforest"], comp["seq_ae"], comp["sig_calib"]
    reload_hash = CD.content_hashes(m2)["combined"]
    assert reload_hash == chash["combined"], "the reloaded candidate artifact differs from the model that was frozen"
    w2 = cfg2["fusion_weights"]
    assert w2 == w and cfg2["features"] == feats
    clf2 = joblib.load(cand_dir / "classifier.joblib")["model"] if clf is not None else None

    t = time.time()
    X_full = build_feature_matrix(p.events, verbose=False)
    pref = {f: bool(np.array_equal(X_full[f].to_numpy()[:n_dev], X_dev[f].to_numpy())) for f in FEATURE_NAMES}
    assert all(pref.values()), "features of dev events changed when TEST events were added: the extractor is not causal"
    _log(f"full features {X_full.shape} ({time.time()-t:.0f}s); dev-prefix identical for all {len(FEATURE_NAMES)} features")
    prev_full = CD.window_index(X_full["entity_id"].to_numpy())
    F32_full = X_full[feats].to_numpy(dtype=np.float32)
    rows_te = np.arange(n_dev, n_all)
    S_te = CD.windows_from(F32_full, prev_full, rows_te)
    assert np.array_equal(CD.windows_from(F32_full, prev_full, np.arange(ntr, n_dev)), S_dev[ntr:]), "validation windows changed"
    pad_te = CD._padded(X_full)[n_dev:]
    M["training"]["window_checks"].update({"test_windows_that_contain_zero_padding": int(pad_te.sum()),
                                           "test_windows": int(len(pad_te)),
                                           "test_windows_that_include_train_or_validation_history": int(((prev_full[n_dev:] >= 0) & (prev_full[n_dev:] < n_dev)).any(axis=1).sum()),
                                           "test_windows_containing_any_event_later_than_the_scored_event": 0})
    iso_te, seq_te = CD.iso_seq(m2, X_full.iloc[n_dev:].reset_index(drop=True), S_te)
    # stream state: TRAIN profile -> validation (saved signals) -> test, one causal pass in the frozen mode
    prof_run = copy.deepcopy(m2.profiler)
    fm = cfg2["baseline"]["guard_fused_max"]
    b_v2, f_v2, _ = CD.replay(prof_run, Xva, iso_va, seq_va, m2.sig_calib, w2, fm, ewma)
    assert np.array_equal(f_v2, f_va), "validation predictions changed between selection and the frozen test-stage run"
    prof_test_start = copy.deepcopy(prof_run)
    b_te, f_te, g_te = CD.replay(prof_run, X_full.iloc[n_dev:].reset_index(drop=True), iso_te, seq_te, m2.sig_calib, w2, fm, ewma)
    risk_te = CD.risk_event_level(calib_fused, f_te)
    _log(f"test stream scored: {len(f_te)} events (validation predictions bit-identical to selection stage)")

    # ---- unseal test labels exactly once
    full_lab = vault.unseal_test("final TEST evaluation of the frozen ML-3 candidate")
    lab_te_all = full_lab["label"].to_numpy(dtype=object)[n_dev:]
    aid_te_all = full_lab["attack_id"].to_numpy(dtype=object)[n_dev:]
    pop = ~p.purged[n_dev:]
    lab_te, aid_te, f_pop, r_pop = lab_te_all[pop], aid_te_all[pop], f_te[pop], risk_te[pop]
    test = EV.evaluate_population("TEST", lab_te, aid_te, f_pop, r_pop, thresholds)
    raw_pop = {"baseline": b_te[pop], "iforest": iso_te[pop], "sequence": seq_te[pop]}
    test["signal_ablation"] = DG.signal_ablation(lab_te, raw_pop, f_pop, calib)
    test["guard_blocked_events"] = int(g_te.sum())
    # classification layer on the population
    Fte = X_full.iloc[n_dev:][feats].to_numpy(dtype=float)[pop]
    if clf2 is not None:
        cl_pred, cl_conf, cl_raw, cl_proba = CL.predict_abstain(clf2, Fte)
    else:
        cl_pred = np.array([CL.UNKNOWN] * len(f_pop), dtype=object)
        cl_conf, cl_raw = np.zeros(len(f_pop)), cl_pred.copy()
    a_primary = f_pop >= thr
    test["classification_layer"] = {
        "on_alerts_at_primary_threshold": CL.layer_on_alerts(cl_pred, cl_conf, lab_te, a_primary, clf_info["classes"]),
        "per_attack_type": {t: {"training_examples": support[t]["training_examples"], "validation_examples": support[t]["validation_examples"],
                                "training_possible": support[t]["training_possible"], "evaluation_statistically_meaningful": support[t]["evaluation_statistically_meaningful"],
                                "test_events": int((lab_te == t).sum()), "test_incidents": int(len(set(aid_te[lab_te == t]) - {""}))} for t in ATTACKS}}
    M["test"] = test
    M["test_unseal"] = {"unseals": vault.test_unseals, "label_vault_log": vault.log}
    K.write_json(out / "metrics_partial_after_test.json", M)
    _log(f"TEST: PR-AUC(fused) {test['ranking_fused']['pr_auc']:.4f}  ROC {test['ranking_fused']['roc_auc']:.4f}  "
         f"F1@thr {test['operating_points']['candidate_validation_f1_optimal']['f1']:.4f}")

    # predictions file (what the reproducibility comparison hashes)
    ev_ids = p.events["event_id"].to_numpy()
    preds = {"val_event_id": ev_ids[ntr:n_dev], "val_baseline": b_va, "val_iforest": iso_va, "val_sequence": seq_va, "val_fused": f_va, "val_risk": risk_va,
             "test_event_id": ev_ids[n_dev:], "test_baseline": b_te, "test_iforest": iso_te, "test_sequence": seq_te, "test_fused": f_te,
             "test_risk": risk_te, "test_in_population": pop, "test_alert_primary": f_te >= thr,
             }
    cl_pred_full = np.array([CL.UNKNOWN] * len(f_te), dtype="U24")
    cl_conf_full = np.zeros(len(f_te))
    if clf2 is not None:
        pr, cf, _, _ = CL.predict_abstain(clf2, X_full.iloc[n_dev:][feats].to_numpy(dtype=float))
        cl_pred_full, cl_conf_full = pr.astype("U24"), cf
    preds["test_class_pred"], preds["test_class_conf"] = cl_pred_full, cl_conf_full
    np.savez_compressed(out / "predictions.npz", **preds)
    M["predictions_sha256"] = arrays_hash(preds)

    # ------------------------------------------------------------------ 6. post-hoc diagnostics (labels of all periods; logged)
    if not skip_diagnostics:
        full = vault.diagnostic("ML-3 shortcut diagnostics on the frozen candidate (post-hoc, never fed back)")
        lab_full = full["label"].to_numpy(dtype=object)
        aid_full = full["attack_id"].to_numpy(dtype=object)
        from eval_ml2 import shortcuts as SC2
        sdf = SC2.shortcut_frame(p)
        te_rows = np.arange(n_dev, n_all)
        va_rows = np.arange(ntr, n_dev)
        seeds = [1, 2]
        t = time.time()
        perm_va = DG.group_permutation(m2, X_full, prev_full, va_rows, lab_full[va_rows], aid_full[va_rows], w2, fm, calib, ewma, prof_train_state, thr, f_va, seeds, keep=None)
        _log(f"permutation (validation) {time.time()-t:.0f}s")
        keep_te = pop
        perm_te = DG.group_permutation(m2, X_full, prev_full, te_rows, lab_full[te_rows], aid_full[te_rows], w2, fm, calib, ewma, prof_test_start, thr, f_te, seeds, keep=keep_te)
        _log(f"permutation (test) {time.time()-t:.0f}s")
        pop_rows = te_rows[pop]
        rules = DG.rules_vs_candidate(sdf, pop_rows, lab_full[pop_rows], aid_full[pop_rows], f_pop, a_primary)
        M["diagnostics"] = {"note": "post-hoc, diagnostic only; test labels read via LabelVault.diagnostic (logged); nothing here changes any frozen choice",
                            "group_permutation_validation": perm_va, "group_permutation_test": perm_te, "one_line_rules_vs_candidate_test": rules,
                            "seeds": seeds}
    M["label_vault_log"] = vault.log

    # ------------------------------------------------------------------ 7. engine check
    if not skip_engine:
        from . import engine_check
        M["engine_check"] = engine_check.run(p, X_full, out, _log)

    # ------------------------------------------------------------------ 8. hashes, environment, artifacts
    after = K.production_hashes()
    K.write_json(out / "hashes_after.json", after)
    M["integrity"] = {"production_files_hashed": len(before), "production_files_changed": sorted(k for k in before if before[k] != after.get(k)),
                      "production_unchanged": before == after, "production_hashes_before": before,
                      "test_labels_unsealed": vault.test_unseals, "features_dev_prefix_identical_when_test_events_added": all(pref.values()),
                      "reloaded_candidate_equals_frozen_content_hash": reload_hash == chash["combined"],
                      "validation_predictions_identical_between_selection_and_frozen_test_run": True}
    art_files = {p_.name: K.sha256_file(p_) for p_ in sorted(cand_dir.glob("*")) if p_.is_file()}
    M["hashes"] = {"dataset": man["ml3"]["dataset_sha256"], "split_manifest": h_man, "assignment": man["ml3"]["assignment_sha256"],
                   "source": source_hashes(), "config": K.sha256_obj(K.ML3_CONFIG), "frozen_config": h_cfg,
                   "candidate_content": chash, "candidate_classifier_content": clf_info.get("classifier_content_sha256"),
                   "candidate_artifact_files": art_files, "ml2_split_manifest": cmp2["ml2_manifest_sha256"],
                   "production_model_pipeline_joblib_sha256": before["models/pipeline.joblib"]}
    M["environment"] = K.env_info()
    M["environment"]["seeds"] = {"model_seed": K.MODEL_SEED, "ml3_seed": K.ML3_SEED, "eval_seed_ml2": K.EVAL_SEED,
                                 "torch_threads": 1, "omp_threads": os.environ["OMP_NUM_THREADS"], "numpy_random": "np.random.default_rng(seed) only"}
    M["meta"].update({"elapsed_seconds": time.time() - t_all, "finished": time.strftime("%Y-%m-%d %H:%M:%S")})
    K.write_json(out / "metrics.json", M)
    try:
        os.remove(out / "metrics_partial_after_test.json")
    except OSError:
        pass
    _log(f"DONE run {run_id} in {time.time()-t_all:.0f}s | production unchanged: {before == after}")
    return M


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--skip-diagnostics", action="store_true")
    ap.add_argument("--skip-engine", action="store_true")
    a = ap.parse_args()
    run(a.run_id, a.skip_diagnostics, a.skip_engine)

"""ML-4 runner.   python -m eval_ml4.run --run-id A [--stages verify,features,fit,dev,sealed,drift,audits] ; python -m eval_ml4.run parity --run-id A

ORDER (label access enforced by the per-dataset Vault, not by convention)
  verify    dataset file hashes vs the canonical manifest (+ optional full regeneration check); onboarding attack-free check on non-sealed data
  features  causal 35-feature matrices for every dataset (production extractor, unchanged)
  fit       global components on the TRAIN datasets' onboarding periods only
  dev       VAL/DEV/legacy datasets: fusion weights, operating points (evaluation-only), FREEZE (config + calibration hashed, read-only)
  sealed    SEALED standard datasets scored with the frozen models; labels unsealed once each; ml4 / ml4_local / ml3 / shipped
  drift     SEALED drift datasets (frozen vs adaptive baselines, per phase, paired with the no-drift control)
  audits    post-hoc: shortcut rules + group permutation, device-spoofing signals, class coverage, near-duplicate incidents
Nothing calibrates probabilities or selects a production threshold; the operating points are evaluation-only.
"""
from __future__ import annotations

import os

for _v in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
    os.environ[_v] = "1"
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

import argparse                                   # noqa: E402
import hashlib                                    # noqa: E402
import json                                       # noqa: E402
import stat                                       # noqa: E402
import sys                                        # noqa: E402
import time                                       # noqa: E402
from concurrent.futures import ProcessPoolExecutor    # noqa: E402
from pathlib import Path                          # noqa: E402

import joblib                                     # noqa: E402
import numpy as np                                # noqa: E402
import pandas as pd                               # noqa: E402

from . import audits as AU                        # noqa: E402
from . import common as K                         # noqa: E402
from . import drift as DR                         # noqa: E402
from . import features4 as F4                     # noqa: E402
from . import xfer as X                           # noqa: E402
from .common import ATTACKS, C                    # noqa: E402
from eval_ml2 import metrics as M2                # noqa: E402
from eval_ml3 import candidate as CD              # noqa: E402
from eval_ml3 import evaluate as EV               # noqa: E402
from .profiles import get_profile                 # noqa: E402


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def arrays_hash(d: dict) -> dict:
    return {k: hashlib.sha256(np.ascontiguousarray(v).tobytes()).hexdigest() for k, v in d.items() if isinstance(v, np.ndarray)}


def source_hashes() -> dict:
    return {f"eval_ml4/{p.name}": K.sha256_file(p) for p in sorted((K.ROOT / "eval_ml4").glob("*.py"))}


# ------------------------------------------------------------------------------------------------------------- workers (module level: picklable)
def _load_model(model_key, out_dir):
    if model_key in ("ml4",):
        return joblib.load(Path(out_dir) / "candidate" / "ml4_global.joblib")
    if model_key == "ml3":
        return X.load_ml3()[0]
    if model_key == "shipped":
        return K.K3.load_artifact()
    raise KeyError(model_key)


def sig_task(args):
    import torch
    torch.set_num_threads(1)
    model_key, did, out_dir, feat_dir = args
    L = F4.Loaded(did, feat_dir)
    m = _load_model(model_key, out_dir)
    return model_key, did, X.signals(model_key, m, L), L.X_eval["event_id"].to_numpy(), L.ts[L.n_onb:].asi8


def sealed_task(args):
    """Signals + frozen and adaptive replays of one (model, dataset) with the FROZEN config. Label-free."""
    import torch
    torch.set_num_threads(1)
    model_key, did, out_dir, feat_dir = args
    out_dir = Path(out_dir)
    cfg4 = json.load(open(out_dir / "candidate" / "frozen_config.json", encoding="utf-8"))
    L = F4.Loaded(did, feat_dir)
    if model_key == "ml4_local":
        m = X.fit_global([did], feat_dir, log=lambda *_: None, tag="local")
        w = cfg4["fusion_weights"]
        calib, fmax = X.calib_fused_for(m, w)
        sig = X.signals("ml4", m, L)
        modes = X.replay_modes("ml4", m, L, sig, w, cfg4["guard_alert_threshold"], calib)
    elif model_key == "ml4":
        m = joblib.load(out_dir / "candidate" / "ml4_global.joblib")
        calib = np.load(out_dir / "candidate" / "frozen_calib_fused.npy")
        sig = X.signals("ml4", m, L)
        modes = X.replay_modes("ml4", m, L, sig, cfg4["fusion_weights"], cfg4["guard_alert_threshold"], calib)
    elif model_key == "ml3":
        m, cfg3 = X.load_ml3()
        sig = X.signals("ml3", m, L)
        modes = X.replay_modes("ml3", m, L, sig, cfg3["fusion_weights"], cfg3["thresholds"]["primary_fused"], np.linspace(0, 1, 1001))
        for v in modes.values():
            v["risk"] = v["fused"] * 100.0            # risk mapping not reproducible for ML-3 (TRAIN fused curve not stored); fused is what is evaluated
    else:
        art = K.K3.load_artifact()
        sig = X.signals("shipped", art, L)
        modes = X.replay_modes("shipped", art, L, sig, None, None, None, thr_shipped=float(art["threshold"]))
    return model_key, did, {"signals": sig, "modes": modes, "event_id": L.X_eval["event_id"].to_numpy(), "ts_ns": L.ts[L.n_onb:].asi8}


def drift_task(args):
    model_key, did, out_dir, feat_dir = args
    out_dir = Path(out_dir)
    cfg = json.load(open(out_dir / "candidate" / "frozen_config.json", encoding="utf-8"))
    cfg["calib_fused"] = np.load(out_dir / "candidate" / "frozen_calib_fused.npy")
    m = joblib.load(out_dir / "candidate" / "ml4_global.joblib")
    return did, DR.score_dataset(did, m, cfg, feat_dir)


def perm_task(args):
    """Group-permutation diagnostic of the frozen ml4 (frozen baseline) on one sealed dataset. Labels are passed in (already unsealed by the parent)."""
    import torch
    torch.set_num_threads(1)
    from eval_ml3 import diagnostics as DG
    did, out_dir, feat_dir, lab, aid, thr, seeds = args
    out_dir = Path(out_dir)
    cfg = json.load(open(out_dir / "candidate" / "frozen_config.json", encoding="utf-8"))
    m = joblib.load(out_dir / "candidate" / "ml4_global.joblib")
    L = F4.Loaded(did, feat_dir)
    prev = CD.window_index(L.X["entity_id"].to_numpy())
    rows = np.arange(L.n_onb, L.n)
    sig = X.signals("ml4", m, L)
    modes = X.replay_modes("ml4", m, L, sig, cfg["fusion_weights"], cfg["fused_max"], np.load(out_dir / "candidate" / "frozen_calib_fused.npy"), modes=("frozen",))
    prof = X.BaselineProfiler().fit(L.X_onb)
    res = DG.group_permutation(m, L.X, prev, rows, lab, aid, cfg["fusion_weights"], cfg["fused_max"], m.sig_calib, False, prof, thr, modes["frozen"]["fused"], seeds)
    return did, res


def parity_task(args):
    from . import parity as PA
    did, variant = args
    return did, variant, PA.run_task(did, variant)


# group-permutation diagnostics are the costliest audit: run on the replica (P0-104), the private-IP stealth profile (P1-202), the public-IP workforce
# profile (P2-302) and the fully unseen burst profile (P4-501)
PERM_IDS = ["P0-104", "P1-202", "P2-302", "P4-501"]


# ------------------------------------------------------------------------------------------------------------- stages
class Ctx:
    def __init__(self, run_id, workers):
        self.run_id, self.workers = run_id, workers
        self.out = K.REPORTS / "ml4_runs" / run_id
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "candidate").mkdir(exist_ok=True)
        self.feat_dir = self.out / "features"
        self.vault = X.Vault()
        self.M: dict = {}
        self.arrays: dict = {}

    def save(self, name, obj):
        K.write_json(self.out / f"{name}.json", obj)

    def checkpoint(self, stage):
        """Persist everything computed so far, so a failure in a later stage can never discard earlier results."""
        K.write_json(self.out / "metrics_partial.json", {**self.M, "_checkpoint_after_stage": stage})
        if self.arrays:
            np.savez_compressed(self.out / "predictions_partial.npz", **{k.replace("/", "__"): v for k, v in self.arrays.items()})
        log(f"checkpoint after stage '{stage}' saved")


def stage_verify(ctx: Ctx, regen: bool):
    man = json.load(open(K.DATA_DIR / "manifest.json", encoding="utf-8"))
    bad = []
    for did, m in man["datasets"].items():
        for f, h in m["file_sha256"].items():
            p = (F4.data_paths(did)["events"].parent / f) if did == K.LEGACY_ID else (K.DATA_DIR / did / f)
            if K.sha256_file(p) != h:
                bad.append(f"{did}/{f}")
    assert not bad, f"dataset files differ from the canonical manifest: {bad}"
    res = {"dataset_set_sha256": man["dataset_set_sha256"], "files_verified": sum(len(m["file_sha256"]) for m in man["datasets"].values()), "regeneration": None}
    if regen:
        from . import build_data as BD
        t = time.time()
        rd = ctx.out / "data_regen"
        metas = BD.build_all(rd, workers=ctx.workers)
        diff = {d: {f: metas[d]["file_sha256"][f] == man["datasets"][d]["file_sha256"][f] for f in metas[d]["file_sha256"]} for d in metas}
        res["regeneration"] = {"datasets": len(metas), "all_files_identical_to_canonical": all(all(v.values()) for v in diff.values()), "seconds": round(time.time() - t, 1),
                               "per_dataset": diff}
        import shutil
        shutil.rmtree(rd, ignore_errors=True)
    # chronology / onboarding checks on non-sealed data (sealed: after unseal)
    res["profile_contrast_label_free_onboarding"] = {d: AU.onboarding_contrast(d) for d in list(K.REGISTRY) + [K.LEGACY_ID]}
    ctx.M["verify"] = res
    log(f"verify: {res['files_verified']} dataset files match the manifest; regeneration identical: {res['regeneration'] and res['regeneration']['all_files_identical_to_canonical']}")


def stage_features(ctx: Ctx, reference_run: str | None = None, recompute=None):
    """Causal feature matrices. Run A computes all 19. A second run may take `reference_run`'s cache for datasets NOT in `recompute` (after verifying their
    array hashes against the reference manifest) and recomputes the `recompute` subset from scratch, hash-comparing them with the reference."""
    import shutil
    mp = ctx.out / "features_manifest.json"
    ids = list(K.REGISTRY) + [K.LEGACY_ID]
    note = "computed by this run"
    if reference_run:
        ref = K.REPORTS / "ml4_runs" / reference_run
        ref_man = json.load(open(ref / "features_manifest.json", encoding="utf-8"))["datasets"]
        recompute = list(recompute or [])
        ctx.feat_dir.mkdir(parents=True, exist_ok=True)
        for d in ids:
            if d not in recompute and not (ctx.feat_dir / f"{d}.npz").exists():
                shutil.copyfile(ref / "features" / f"{d}.npz", ctx.feat_dir / f"{d}.npz")
                z = np.load(ctx.feat_dir / f"{d}.npz")
                assert hashlib.sha256(np.ascontiguousarray(z["X"]).tobytes()).hexdigest() == ref_man[d]["features_sha256"], f"cached features of {d} differ from the reference manifest"
        todo = [d for d in recompute if not (ctx.feat_dir / f"{d}.npz").exists()]
        t = time.time()
        res = F4.compute_all(todo, ctx.feat_dir, workers=ctx.workers, log=log) if todo else {}
        ident = {d: (res[d]["features_sha256"] == ref_man[d]["features_sha256"]) for d in res}
        assert all(ident.values()), f"recomputed feature matrices differ from the reference run: {ident}"
        full = dict(ref_man)
        full.update(res)
        K.write_json(mp, {"datasets": full, "seconds": time.time() - t, "reference_run": reference_run, "recomputed": recompute, "recomputed_identical_to_reference": ident})
        res = full
        note = f"recomputed {recompute} (all hash-identical to run {reference_run}); other datasets read from run {reference_run}'s cache after array-hash verification"
    elif mp.exists() and all((ctx.feat_dir / f"{d}.npz").exists() for d in ids):
        res = json.load(open(mp, encoding="utf-8"))["datasets"]
        log("features: reusing cache written by this run's code")
    else:
        t = time.time()
        res = F4.compute_all(ids, ctx.feat_dir, workers=ctx.workers, log=log)
        K.write_json(mp, {"datasets": res, "seconds": time.time() - t})
    ctx.M["features"] = {d: {"rows": r["rows"], "n_onboarding": r["n_onboarding"], "features_sha256": r["features_sha256"]} for d, r in res.items()}
    ctx.M["features_note"] = note


def stage_fit(ctx: Ctx):
    m = X.fit_global(K.TRAIN_IDS, ctx.feat_dir, log=log)
    path = ctx.out / "candidate" / "ml4_global.joblib"
    joblib.dump(m, path)
    ctx.M["fit"] = {"train_datasets": K.TRAIN_IDS, "fit_info": m.fit_info, "content_hashes": X.content_hashes4(m), "file_sha256": K.sha256_file(path)}
    return m


def _pool(ctx, fn, tasks):
    with ProcessPoolExecutor(max_workers=ctx.workers) as ex:
        return list(ex.map(fn, tasks))


def stage_dev(ctx: Ctx, m4):
    """VAL + DEV + legacy: signals -> fusion selection -> operating points -> FREEZE -> dev evaluation."""
    dev_ids = K.VAL_IDS + K.DEV_IDS + K.TRAIN_IDS        # TRAIN datasets: evaluation period only (their onboarding was used for fitting) = same-profile seen-seed references
    tasks = [(mk, d, str(ctx.out), str(ctx.feat_dir)) for d in dev_ids for mk in ("ml4", "ml3", "shipped")]
    log(f"dev: scoring signals of {len(dev_ids)} datasets x 3 models ({len(tasks)} tasks)")
    S = {}
    for mk, did, sig, eid, ts in _pool(ctx, sig_task, tasks):
        S[(mk, did)] = {"sig": sig, "event_id": eid, "ts_ns": ts}
    labs = {d: ctx.vault.labels(d, "dev") for d in dev_ids}

    def eval_lab(did):
        L = labs[did].loc[S[("ml4", did)]["event_id"]]
        return L["label"].to_numpy(dtype=object), L["attack_id"].to_numpy(dtype=object)

    # ---- fusion selection on VAL (frozen baseline)
    val_items = [(S[("ml4", d)]["sig"], eval_lab(d)[0]) for d in K.VAL_IDS]
    sel = X.select_fusion(val_items, m4)
    w = sel["selected_weights"]
    calib, fmax = X.calib_fused_for(m4, w)
    log(f"dev: fusion best {sel['best_on_grid']['w']} ({sel['best_on_grid']['mean_macro_pr_auc']:.4f}) equal {sel['equal_weights']['mean_macro_pr_auc']:.4f} -> selected {w}")
    # ---- VAL replays in both modes, evaluation-only operating points (pooled over VAL datasets)
    L_val = {d: F4.Loaded(d, ctx.feat_dir) for d in K.VAL_IDS}
    y_val = np.concatenate([EV.is_attack(eval_lab(d)[0]).astype(int) for d in K.VAL_IDS])
    rep_val = {d: X.replay_modes("ml4", m4, L_val[d], S[("ml4", d)]["sig"], w, fmax, calib, modes=("frozen",)) for d in K.VAL_IDS}
    thr = {}
    f_fz = np.concatenate([rep_val[d]["frozen"]["fused"] for d in K.VAL_IDS])
    f1 = EV.f1_optimal_threshold(y_val, f_fz)
    thr["frozen"] = {"f1_optimal": f1["threshold"], "f1_optimal_detail": f1, "q99": float(np.quantile(f_fz, 0.99))}
    # METHODOLOGY CHANGE (made after dev results, before any sealed data was read): the adaptive baseline's poisoning guard is the model's OWN alert
    # threshold (the frozen-mode F1-optimal threshold): an event that would raise an alert must not teach the baseline. The ML-3 guard (event above the
    # whole TRAIN fused range) is far weaker under baseline-heavy weights and is kept only as the explicit 'prodguard' variant of the drift study.
    guard = thr["frozen"]["f1_optimal"]
    for d in K.VAL_IDS:
        rep_val[d].update(X.replay_modes("ml4", m4, L_val[d], S[("ml4", d)]["sig"], w, guard, calib, modes=("adaptive",)))
    f_ad = np.concatenate([rep_val[d]["adaptive"]["fused"] for d in K.VAL_IDS])
    f1a = EV.f1_optimal_threshold(y_val, f_ad)
    thr["adaptive"] = {"f1_optimal": f1a["threshold"], "f1_optimal_detail": f1a, "q99": float(np.quantile(f_ad, 0.99))}
    # ---- FREEZE
    cfg = {"candidate": "ML-4 cross-dataset global components (NOT DEPLOYED; evaluation artifact)", "train_datasets": K.TRAIN_IDS, "val_datasets": K.VAL_IDS,
           "features": m4.features, "fusion_weights": w, "fused_max": fmax, "guard_alert_threshold": guard, "thresholds": thr,
           "thresholds_note": "evaluation-only operating points derived on the VAL datasets; they are NOT production thresholds",
           "content_hashes": ctx.M["fit"]["content_hashes"]["combined"], "ml4_config_sha256": K.sha256_obj(K.ML4_CONFIG)}
    cp = ctx.out / "candidate" / "frozen_config.json"
    np.save(ctx.out / "candidate" / "frozen_calib_fused.npy", calib)
    cfg["calib_fused_sha256"] = K.sha256_file(ctx.out / "candidate" / "frozen_calib_fused.npy")
    if cp.exists():
        os.chmod(cp, stat.S_IWRITE | stat.S_IREAD)
    K.write_json(cp, cfg)
    os.chmod(cp, stat.S_IREAD)
    h_cfg = K.sha256_file(cp)
    log(f"dev: FROZEN config sha256 {h_cfg[:16]} | weights {w} | thresholds frozen {thr['frozen']['f1_optimal']:.5f} adaptive {thr['adaptive']['f1_optimal']:.5f}")
    ctx.M["selection"] = {"fusion": sel, "thresholds": thr, "frozen_config_sha256": h_cfg, "unsealed_datasets_before_freeze": sorted(ctx.vault.unsealed)}
    # ---- dev evaluation (VAL: selection-time; DEV: dev-only diagnostics)
    dev_eval = {}
    m3, cfg3 = X.load_ml3()
    art = K.K3.load_artifact()
    art_thr = float(art["threshold"])
    models = {"ml4": m4, "ml3": m3, "shipped": art}
    for did in dev_ids:
        lab, aid = eval_lab(did)
        incidents = ctx.vault.incidents(did, "dev")
        role = "DEV" if did == K.LEGACY_ID else K.REGISTRY[did][2]
        L = F4.Loaded(did, ctx.feat_dir) if did not in L_val else L_val[did]
        ts_ns = S[("ml4", did)]["ts_ns"]
        dev_eval[did] = {"role": role}
        for mk in ("ml4", "ml3", "shipped"):
            sig = S[(mk, did)]["sig"]
            m = models[mk]
            if mk == "ml4":
                modes = rep_val[did] if did in rep_val else X.replay_modes("ml4", m, L, sig, w, guard, calib)
            elif mk == "ml3":
                modes = X.replay_modes("ml3", m, L, sig, cfg3["fusion_weights"], cfg3["thresholds"]["primary_fused"], np.linspace(0, 1, 1001))
                for v in modes.values():
                    v["risk"] = v["fused"] * 100.0
            else:
                modes = X.replay_modes("shipped", m, L, sig, None, None, None, thr_shipped=art_thr)
            for mode, arr in modes.items():
                th = thr_for(mk, mode, cfg, cfg3, art_thr)
                dev_eval[did][f"{mk}/{mode}"] = X.eval_arrays(did, lab, aid, arr, th, incidents, ts_ns)
                ctx.arrays[f"dev/{mk}/{mode}/{did}"] = arr["fused"]
    ctx.M["dev_evaluation"] = dev_eval
    return cfg


def thr_for(mk, mode, cfg4, cfg3, art_thr):
    if mk in ("ml4", "ml4_local"):
        t = cfg4["thresholds"][mode]
        return {"val_f1_optimal_transferred": ("fused", t["f1_optimal"]), "val_q99_transferred": ("fused", t["q99"])}
    if mk == "ml3":
        return {"ml3_frozen_threshold": ("fused", cfg3["thresholds"]["primary_fused"])}
    return {"shipped_production_threshold": ("risk", art_thr)}


def stage_sealed(ctx: Ctx, m4, cfg):
    """Sealed standard datasets. The frozen config is re-read from disk and its hash verified before any sealed label is opened."""
    cp = ctx.out / "candidate" / "frozen_config.json"
    assert K.sha256_file(cp) == ctx.M["selection"]["frozen_config_sha256"]
    cfg3 = X.load_ml3()[1]
    art_thr = float(K.K3.load_artifact()["threshold"])
    tasks = [(mk, d, str(ctx.out), str(ctx.feat_dir)) for d in K.SEALED_STD_IDS for mk in ("ml4", "ml4_local", "ml3", "shipped")]
    log(f"sealed: scoring {len(tasks)} (model, dataset) tasks with the frozen config")
    R = {}
    for mk, did, r in _pool(ctx, sealed_task, tasks):
        R[(mk, did)] = r
    ctx.sealed_R = R
    sealed_eval = {}
    for did in K.SEALED_STD_IDS:
        ctx.vault.unseal(did, "final evaluation of the frozen models")
        lab_all = ctx.vault.labels(did, "final evaluation")
        incidents = ctx.vault.incidents(did, "final evaluation")
        sealed_eval[did] = {"profile": K.REGISTRY[did][0], "seed": K.REGISTRY[did][1]}
        for mk in ("ml4", "ml4_local", "ml3", "shipped"):
            r = R[(mk, did)]
            L = lab_all.loc[r["event_id"]]
            lab, aid = L["label"].to_numpy(dtype=object), L["attack_id"].to_numpy(dtype=object)
            for mode, arr in r["modes"].items():
                th = thr_for(mk, mode, cfg, cfg3, art_thr)
                sealed_eval[did][f"{mk}/{mode}"] = X.eval_arrays(did, lab, aid, arr, th, incidents, r["ts_ns"])
                ctx.arrays[f"sealed/{mk}/{mode}/{did}"] = arr["fused"]
                if mk == "ml4" and mode == "frozen":
                    from eval_ml3 import diagnostics as DG
                    sg = r["signals"]
                    sealed_eval[did]["ml4/frozen"]["signal_ablation"] = DG.signal_ablation(lab, {"baseline": sg["b_frozen"], "iforest": sg["iso"], "sequence": sg["seq"]}, arr["fused"], m4.sig_calib)
        # integrity: onboarding attack-free (post-hoc, sealed data)
        sealed_eval[did]["onboarding_attack_events"] = int(lab_all[lab_all.index.isin(F4.Loaded(did, ctx.feat_dir).X_onb["event_id"])].label.isin(ATTACKS).sum())
    ctx.M["sealed_evaluation"] = sealed_eval


def stage_drift(ctx: Ctx):
    cp = ctx.out / "candidate" / "frozen_config.json"
    assert K.sha256_file(cp) == ctx.M["selection"]["frozen_config_sha256"]
    cfg = json.load(open(cp, encoding="utf-8"))
    tasks = [("ml4", d, str(ctx.out), str(ctx.feat_dir)) for d in K.SEALED_DRIFT_IDS]
    log(f"drift: scoring {len(tasks)} drift datasets x {len(DR.VARIANTS)} baseline variants")
    A = dict(_pool(ctx, drift_task, tasks))
    res = {}
    for did in K.SEALED_DRIFT_IDS:
        ctx.vault.unseal(did, "controlled drift study")
        lab = ctx.vault.labels(did, "drift study")
        incs = ctx.vault.incidents(did, "drift study")
        res[did] = DR.evaluate(did, A[did], lab, incs, {"frozen": cfg["thresholds"]["frozen"]["f1_optimal"], "adaptive": cfg["thresholds"]["adaptive"]["f1_optimal"]})
        for k, v in A[did].items():
            if k.startswith("fused__"):
                ctx.arrays[f"drift/{did}/{k}"] = v
    ctx.M["drift_evaluation"] = {"datasets": res, "paired_effects_vs_control": DR.paired_effects(res),
                                 "design": {"drift_window_days": [K.DRIFT_START, K.DRIFT_END], "variants": [v[0] for v in DR.VARIANTS],
                                            "note": "thresholds are the evaluation-only VAL-derived operating points of the frozen ml4 model (per mode family)"}}


def _soft(A, key, fn):
    """Run one audit block; an error is recorded in the report instead of discarding the rest of the run."""
    import traceback
    try:
        A[key] = fn()
    except Exception as exc:                                   # noqa: BLE001
        A[key] = {"error": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc()[-1500:]}
        log(f"audits: block '{key}' FAILED: {type(exc).__name__}: {exc}")


def stage_audits(ctx: Ctx, m4, cfg):
    cfg3 = X.load_ml3()[1]
    art_thr = float(K.K3.load_artifact()["threshold"])
    A = {"shortcuts": {}, "device_spoofing": {}, "profile_contrast": {}}
    thr_f = cfg["thresholds"]["frozen"]["f1_optimal"]
    perm_tasks = []
    for did in K.SEALED_STD_IDS:
        try:
            ev = F4.load_events4(did)
            L = F4.Loaded(did, ctx.feat_dir)
            sd = AU.shortcut_frame(ev, L.n_onb).iloc[L.n_onb:].reset_index(drop=True)
            r = ctx.sealed_R[("ml4", did)]
            lab_all = ctx.vault.labels(did, "audit")
            Lb = lab_all.loc[r["event_id"]]
            lab, aid = Lb["label"].to_numpy(dtype=object), Lb["attack_id"].to_numpy(dtype=object)
            fused = r["modes"]["frozen"]["fused"]
            alert = fused >= thr_f
            incs = ctx.vault.incidents(did, "audit")
            A["shortcuts"][did] = AU.shortcut_audit(sd, lab, aid, fused, alert, incs)
            neg = np.isin(lab, ("normal", "benign_drift"))
            A["profile_contrast"][did] = {"normal_public_ip_share": float(sd.public_ip[neg].mean()), "normal_failed_auth_rate": float(sd.failed_auth[neg].mean()),
                                          "normal_foreign_city_generic_share": float(sd.foreign_city_generic[neg].mean()),
                                          "normal_new_ip_for_entity_share": float(sd.new_ip_for_entity[neg].mean()),
                                          "normal_production_sensitive_resource_share": float(sd.sensitive_production_constants[neg].mean()),
                                          "normal_production_privileged_command_share": float(sd.command_production_privileged[neg].mean()),
                                          "profile_sensitive_resources_recognised_by_production_constants": float(np.mean([s_ in C.SENSITIVE for s_ in get_profile(K.REGISTRY[did][0])["sensitive"]]))}
            alerts = {"ml4_frozen": fused >= thr_f, "ml4_adaptive": r["modes"]["adaptive"]["fused"] >= cfg["thresholds"]["adaptive"]["f1_optimal"],
                      "ml3": ctx.sealed_R[("ml3", did)]["modes"]["frozen"]["fused"] >= cfg3["thresholds"]["primary_fused"],
                      "shipped_as_deployed": ctx.sealed_R[("shipped", did)]["modes"]["adaptive"]["risk"] >= art_thr}
            A["device_spoofing"][did] = AU.device_audit(did, ev, L.n_onb, L.X_eval, lab, aid, alerts, incs)
            if did in PERM_IDS:
                perm_tasks.append((did, str(ctx.out), str(ctx.feat_dir), lab, aid, thr_f, [1]))
        except Exception as exc:                                # noqa: BLE001
            A.setdefault("errors", {})[did] = f"{type(exc).__name__}: {exc}"
            log(f"audits: {did} FAILED: {type(exc).__name__}: {exc}")
    log(f"audits: group-permutation diagnostics on {len(perm_tasks)} sealed datasets")
    _soft(A, "group_permutation", lambda: dict(_pool(ctx, perm_task, perm_tasks)))
    man = json.load(open(K.DATA_DIR / "manifest.json", encoding="utf-8"))["datasets"]
    A["class_coverage"] = AU.class_coverage(man)

    def near_dup():
        ref_sig, ref_meta, test_sig, test_meta = {}, {}, {}, {}
        for did in K.TRAIN_IDS + K.VAL_IDS + K.SEALED_STD_IDS:
            L = F4.Loaded(did, ctx.feat_dir)
            lab = ctx.vault.labels(did, "near-duplicate audit")
            aid = lab.loc[L.X["event_id"].to_numpy()]["attack_id"].to_numpy(dtype=object)
            sigs = AU.incident_signatures(L, None, aid, m4.scaler.mean_, m4.scaler.scale_, m4.features)
            incs = {i["attack_id"]: i for i in ctx.vault.incidents(did, "near-duplicate audit")}
            for a_, v in sigs.items():
                if a_ not in incs:                               # benign-drift cases carry an id too but are not attack incidents
                    continue
                key = f"{did}:{a_}"
                meta = {"type": incs[a_]["type"], "profile": K.REGISTRY[did][0]}
                if did in K.SEALED_STD_IDS:
                    test_sig[key], test_meta[key] = v, meta
                else:
                    ref_sig[key], ref_meta[key] = v, meta
        return AU.near_duplicate_audit(test_sig, ref_sig, test_meta, ref_meta)
    _soft(A, "near_duplicates", near_dup)
    A["device_signal_catalogue"] = AU.DEVICE_SIGNAL_CATALOGUE
    ctx.M["audits"] = A


def stage_parity(ctx: Ctx):
    from . import parity as PA
    tasks = [(d, v) for d, vs in PA.DATASETS.items() for v in vs]
    log(f"parity: {len(tasks)} (dataset, variant) tasks")
    res = {}
    for did, variant, r in _pool(ctx, parity_task, tasks):
        res.setdefault(did, {})[variant] = r
        log(f"parity: {did} {variant} done ({r['seconds']}s)")
    rep = {"phase": "ML-4", "purpose": "serving-parity audit: effect of each api.py contract mismatch, NOT compensated", "mismatches": PA.VARIANTS,
           "datasets": {}, "hard_coded_vocabulary_note": "P9 quantified in the cross-profile evaluation (production SENSITIVE/_PRIV constants vs profile vocabularies)"}
    for did, rs in res.items():
        lab = ctx.vault.labels(did, "parity (dev dataset)")
        rep["datasets"][did] = PA.summarise(did, rs, lab, [])
    ctx.M["parity"] = rep
    K.write_json(ctx.out / "parity_report.json", rep)


# ------------------------------------------------------------------------------------------------------------- CLI
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("what", nargs="?", default="main", choices=["main", "parity"])
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--workers", type=int, default=5)
    ap.add_argument("--stages", default="verify,features,fit,dev,sealed,drift,audits")
    ap.add_argument("--regen", action="store_true")
    ap.add_argument("--features-from", default=None, help="reuse this run's feature cache except --features-recompute datasets")
    ap.add_argument("--features-recompute", default="P0-104,P2-302,P4-501,DR-hours,P3-401,orig42")
    a = ap.parse_args()
    ctx = Ctx(a.run_id, a.workers)
    t_all = time.time()
    before = K.production_hashes()
    K.write_json(ctx.out / f"hashes_before_{a.what}.json", before)
    if a.what == "parity":
        stage_parity(ctx)
        after = K.production_hashes()
        K.write_json(ctx.out / "parity_meta.json", {"production_unchanged": before == after, "seconds": time.time() - t_all})
        log(f"parity DONE in {time.time()-t_all:.0f}s | production unchanged: {before == after}")
        return
    stages = a.stages.split(",")
    ctx.M["meta"] = {"run_id": a.run_id, "phase": "ML-4", "config": K.ML4_CONFIG}
    if "verify" in stages:
        stage_verify(ctx, a.regen)
        ctx.checkpoint("verify")
    if "features" in stages:
        stage_features(ctx, a.features_from, a.features_recompute.split(",") if a.features_from else None)
    m4 = cfg = None
    if "fit" in stages:
        m4 = stage_fit(ctx)
        ctx.checkpoint("fit")
    if "dev" in stages:
        cfg = stage_dev(ctx, m4)
        ctx.checkpoint("dev")
    if "sealed" in stages:
        stage_sealed(ctx, m4, cfg)
        ctx.checkpoint("sealed")
    if "drift" in stages:
        stage_drift(ctx)
        ctx.checkpoint("drift")
    if "audits" in stages:
        stage_audits(ctx, m4, cfg)
        ctx.checkpoint("audits")
    after = K.production_hashes()
    K.write_json(ctx.out / "hashes_after_main.json", after)
    ctx.M["integrity"] = {"production_files_hashed": len(before), "production_unchanged": before == after,
                          "production_files_changed": sorted(k for k in before if before[k] != after.get(k)),
                          "sealed_datasets_unsealed": sorted(ctx.vault.unsealed), "vault_log": ctx.vault.log,
                          "frozen_before_any_unseal": ctx.M.get("selection", {}).get("unsealed_datasets_before_freeze") == []}
    env = K.K3.env_info()
    man = json.load(open(K.DATA_DIR / "manifest.json", encoding="utf-8"))["datasets"]
    split_plan = {d: {"role": m["role"], "profile": m["profile"], "seed": m["seed"], "onboarding_end": m.get("onboarding_end", "legacy: first event + 20 days"),
                      "events_sha256": m["file_sha256"]["events.csv"], "labels_sha256": m["file_sha256"]["labels.csv"], "incidents_sha256": m["file_sha256"].get("incidents.json")}
                  for d, m in man.items()}
    metric_sections = {k: K.sha256_obj(ctx.M[k]) for k in ("dev_evaluation", "sealed_evaluation", "drift_evaluation", "audits", "selection") if k in ctx.M}
    ctx.M["hashes"] = {"split": K.sha256_obj(split_plan), "split_plan": split_plan, "metric_sections": metric_sections, "config": K.sha256_obj(K.ML4_CONFIG), "source": source_hashes(), "dataset_set": ctx.M.get("verify", {}).get("dataset_set_sha256"),
                       "frozen_config": ctx.M.get("selection", {}).get("frozen_config_sha256"), "ml4_content": ctx.M.get("fit", {}).get("content_hashes"),
                       "ml4_artifact_file": ctx.M.get("fit", {}).get("file_sha256"), "prediction_arrays": arrays_hash(ctx.arrays),
                       "production_model_sha256": before["models/pipeline.joblib"]}
    ctx.M["environment"] = env
    ctx.M["meta"]["seconds"] = time.time() - t_all
    np.savez_compressed(ctx.out / "predictions.npz", **{k.replace("/", "__"): v for k, v in ctx.arrays.items()})
    ctx.save("metrics", ctx.M)
    log(f"DONE run {a.run_id} in {time.time()-t_all:.0f}s | production unchanged: {before == after}")


if __name__ == "__main__":
    main()

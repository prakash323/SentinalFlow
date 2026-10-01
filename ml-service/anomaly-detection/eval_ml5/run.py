"""ML-5 runner.   python -m eval_ml5.run --run-id E [--workers 3] [--regen]

ORDER (TRAIN -> VALIDATION -> FREEZE -> TEST; label access enforced by Vault5)
  verify     hashes of every input (ML-4 artifact / features / predictions, fresh data, production files); optional regeneration identity check
  tests      the deterministic serving-parity regression suite (eval_ml5/tests)
  serving    whole datasets through each boundary (corrected / production / corrected-without-entityType) -> feature matrices -> parity vs training extraction
  scoring    ML-4 model and shipped model on the served features -> pre-fix vs post-fix metrics (Phase 3); drift datasets (Phase 6)
  tails      onboarding-tail scores of every DEV deployment (out-of-sample, label-free)
  dev        threshold study, onboarding-volume study, calibration study (leave-one-profile-out) on the DEV pool; alpha and calibrator SELECTED; FREEZE (hashed, read-only)
  test       the FRESH datasets: scored with the frozen configuration, labels unsealed exactly once, thresholds and calibration evaluated
No production file, model, threshold or configuration is changed; nothing is deployed.
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
import time                                       # noqa: E402
import unittest                                   # noqa: E402
from concurrent.futures import ProcessPoolExecutor    # noqa: E402
from pathlib import Path                          # noqa: E402

import joblib                                     # noqa: E402
import numpy as np                                # noqa: E402
import pandas as pd                               # noqa: E402

from . import calibration as CA                   # noqa: E402
from . import common as K                         # noqa: E402
from . import parity_lib as PL                    # noqa: E402
from . import serving_eval as SE                  # noqa: E402
from . import thresholds as TH                    # noqa: E402
from .contract import CONTRACT_VERSION, FIELD_POLICY          # noqa: E402
from eval_ml2 import metrics as M2                # noqa: E402
from eval_ml2.common import env_info, load_artifact   # noqa: E402
from eval_ml3 import candidate as CD              # noqa: E402
from eval_ml4 import drift as DR                  # noqa: E402
from eval_ml3 import evaluate as EV               # noqa: E402
from eval_ml4 import features4 as F4              # noqa: E402
from eval_ml4 import run as R4                    # noqa: E402  (tested ML-4 scoring workers, reused unchanged)
from eval_ml4 import xfer as X4                   # noqa: E402
from src.baseline import BaselineProfiler         # noqa: E402

ATT = list(K.ATTACKS)


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def arrays_hash(d: dict) -> dict:
    return {k: hashlib.sha256(np.ascontiguousarray(v).tobytes()).hexdigest() for k, v in d.items() if isinstance(v, np.ndarray)}


def source_hashes() -> dict:
    return {f"eval_ml5/{p.name}": K.sha256_file(p) for p in sorted((K.ROOT / "eval_ml5").glob("*.py"))} | \
           {f"eval_ml5/tests/{p.name}": K.sha256_file(p) for p in sorted((K.ROOT / "eval_ml5" / "tests").glob("*.py"))}


# ------------------------------------------------------------------------------------------------------------- labels
class Vault5:
    """DEV labels (every ML-4 dataset) are readable; a FRESH test dataset's labels and incident registry are unreadable until unseal(), once."""

    def __init__(self):
        self.unsealed: set = set()
        self.log: list = []

    def _paths(self, did):
        return F4.data_paths(did, K.DATA_DIR if did in K.FRESH else K.ML4_DATA_DIR)

    def _check(self, did, purpose):
        if did in K.FRESH and did not in self.unsealed:
            raise PermissionError(f"labels of sealed TEST dataset {did} requested before unseal ({purpose})")

    def labels(self, did, purpose="dev"):
        self._check(did, purpose)
        self.log.append({"access": "labels", "dataset": did, "role": "TEST" if did in K.FRESH else "DEV", "purpose": purpose})
        lab = pd.read_csv(self._paths(did)["labels"])
        lab["attack_id"] = lab["attack_id"].fillna("")
        return lab.set_index("event_id")

    def incidents(self, did, purpose="dev"):
        self._check(did, purpose)
        p = self._paths(did)["incidents"]
        return json.load(open(p, encoding="utf-8")) if p else []

    def unseal(self, did, purpose):
        assert did in K.FRESH and did not in self.unsealed, did
        self.unsealed.add(did)
        self.log.append({"access": "unseal", "dataset": did, "purpose": purpose})


# ------------------------------------------------------------------------------------------------------------- workers
def tail_task(args):
    """Out-of-sample scores of a deployment's onboarding tail: baseline fitted on the onboarding HEAD, ML-4 global components, frozen fusion."""
    import torch
    torch.set_num_threads(1)
    did, feat_dir = args
    m4 = joblib.load(K.ML4_ARTIFACT_DIR / "ml4_global.joblib")
    cfg = json.load(open(K.ML4_ARTIFACT_DIR / "frozen_config.json", encoding="utf-8"))
    L = F4.Loaded(did, feat_dir)
    n_head = int(K.ONBOARD_HEAD_FRACTION * L.n_onb)
    Xh = L.X.iloc[:n_head].reset_index(drop=True)
    Xt = L.X.iloc[n_head:L.n_onb].reset_index(drop=True)
    prof = BaselineProfiler().fit(Xh)
    S = CD.build_sequences_cols(L.X.iloc[:L.n_onb], m4.features)[n_head:]
    iso, seq = CD.iso_seq(m4, Xt, S)
    _, fused, _ = CD.replay(prof, Xt, iso, seq, m4.sig_calib, cfg["fusion_weights"], np.inf, False)
    return did, np.asarray(fused, float)


def tail_task_shipped(args):
    """Same as tail_task for the SHIPPED detector (frozen-baseline fused score of the production pipeline)."""
    import torch
    torch.set_num_threads(1)
    from src.detect import build_sequences
    from src.features import FEATURE_NAMES
    import config as C
    did, feat_dir = args
    det = load_artifact()["detector"]
    L = F4.Loaded(did, feat_dir)
    n_head = int(K.ONBOARD_HEAD_FRACTION * L.n_onb)
    Xh = L.X.iloc[:n_head].reset_index(drop=True)
    Xt = L.X.iloc[n_head:L.n_onb].reset_index(drop=True)
    prof = BaselineProfiler().fit(Xh)
    S = build_sequences(L.X.iloc[:L.n_onb])[n_head:]
    iso = -det.iforest.score_samples(det.scaler.transform(Xt[FEATURE_NAMES].to_numpy(dtype=float)))
    seq, _ = det.seq_ae.score(S)
    b = prof.score_frame(Xt)[0]
    fused = CD.fuse(det.sig_calib, {"baseline": np.asarray(b, float), "iforest": np.asarray(iso, float), "sequence": np.asarray(seq, float)}, C.FUSION_WEIGHTS)
    return did, np.asarray(fused, float)


def serve_task(args):
    return SE.served_features_task(args)


def canon_task(args):
    return SE.canonical_features_task(args)


def _pool(workers, fn, tasks):
    with ProcessPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(fn, tasks))


class Ctx:
    def __init__(self, run_id, workers):
        self.run_id, self.workers = run_id, workers
        self.out = K.REPORTS / "ml5_runs" / run_id
        (self.out / "candidate").mkdir(parents=True, exist_ok=True)
        self.vault = Vault5()
        self.M: dict = {}
        self.arrays: dict = {}
        self.ml4_cfg = json.load(open(K.ML4_ARTIFACT_DIR / "frozen_config.json", encoding="utf-8"))
        self.art_thr = None

    def checkpoint(self, stage):
        K.write_json(self.out / "metrics_partial.json", {**self.M, "_checkpoint_after_stage": stage})
        if self.arrays:
            np.savez_compressed(self.out / "predictions_partial.npz", **{k.replace("/", "__"): v for k, v in self.arrays.items()})
        log(f"checkpoint after stage '{stage}' saved")


# ------------------------------------------------------------------------------------------------------------- stages
def stage_verify(ctx: Ctx, regen: bool):
    out = {}
    man4 = json.load(open(K.ML4_ARTIFACT_DIR / "MANIFEST.json", encoding="utf-8"))
    out["ml4_artifact_files_match_manifest"] = {fn: K.sha256_file(K.ML4_ARTIFACT_DIR / fn) == h for fn, h in man4["files"].items()}
    assert all(out["ml4_artifact_files_match_manifest"].values()), "the ML-4 artifact changed"
    feat_man = json.load(open(K.REPORTS / "ml4_runs" / "A" / "features_manifest.json", encoding="utf-8"))["datasets"]
    need = K.DEV_IDS + K.DRIFT_REEVAL_IDS
    bad = []
    for d in need:
        z = np.load(K.ML4_FEATURE_DIR / f"{d}.npz")
        if hashlib.sha256(np.ascontiguousarray(z["X"]).tobytes()).hexdigest() != feat_man[d]["features_sha256"]:
            bad.append(d)
    assert not bad, f"ML-4 feature caches differ from the ML-4 manifest: {bad}"
    out["ml4_feature_matrices_verified"] = len(need)
    out["ml4_predictions_sha256"] = K.sha256_file(K.K4.REPORTS / "ml4_runs" / "C" / "predictions.npz")
    out["ml4_frozen_config_sha256"] = K.sha256_file(K.ML4_ARTIFACT_DIR / "frozen_config.json")
    fm = json.load(open(K.DATA_DIR / "manifest.json", encoding="utf-8"))
    bad = [d for d, m in fm["datasets"].items() for f, h in m["file_sha256"].items() if K.sha256_file(K.DATA_DIR / d / f) != h]
    assert not bad, f"fresh datasets differ from their manifest: {bad}"
    out["fresh_dataset_set_sha256"] = fm["dataset_set_sha256"]
    if regen:
        from . import build_data as BD
        t = time.time()
        rd = ctx.out / "data_regen"
        metas = BD.build_all(rd, workers=ctx.workers)
        same = all(metas[d]["file_sha256"] == fm["datasets"][d]["file_sha256"] for d in metas)
        import shutil
        shutil.rmtree(rd, ignore_errors=True)
        out["fresh_regeneration_byte_identical"] = same
        out["fresh_regeneration_seconds"] = round(time.time() - t, 1)
    ctx.M["verify"] = out
    log(f"verify: ML-4 inputs intact; fresh regeneration identical: {out.get('fresh_regeneration_byte_identical')}")


def stage_tests(ctx: Ctx):
    from .tests import test_contract_parity as T
    suite = unittest.defaultTestLoader.loadTestsFromModule(T)

    def _flat(s):
        for t in s:
            yield from (_flat(t) if isinstance(t, unittest.TestSuite) else [t])
    names = sorted(t.id().split(".")[-1] for t in _flat(suite))          # collected BEFORE the run (a run empties the suite)
    res = unittest.TextTestRunner(stream=open(os.devnull, "w"), verbosity=0).run(suite)
    ctx.M["parity_unit_tests"] = {"tests_run": res.testsRun, "failures": len(res.failures), "errors": len(res.errors), "skipped": len(res.skipped), "passed": res.wasSuccessful(),
                                  "failure_details": [f"{t.id()}: {m[-300:]}" for t, m in res.failures + res.errors], "test_names": names, "contract_version": CONTRACT_VERSION,
                                  "field_policy": FIELD_POLICY, "tolerance": PL.TOLERANCE}
    assert res.wasSuccessful(), ctx.M["parity_unit_tests"]["failure_details"]
    log(f"tests: {res.testsRun} run, all passed")


def stage_serving(ctx: Ctx):
    served = ctx.out / "served"
    tasks = ([(d, "corrected_full", str(served / "corrected_full")) for d in K.PARITY_REEVAL_IDS + K.FRESH_IDS + K.DRIFT_REEVAL_IDS]
             + [(d, "legacy_live", str(served / "legacy_live")) for d in K.PARITY_REEVAL_IDS + K.DRIFT_REEVAL_IDS]
             + [(d, "corrected_live_no_et", str(served / "corrected_live_no_et")) for d in K.NO_ENTITY_TYPE_IDS])
    log(f"serving: {len(tasks)} dataset passes through the boundaries + {len(K.FRESH_CANONICAL_CHECK_IDS)} canonical passes")
    res = _pool(ctx.workers, serve_task, tasks)
    canon = _pool(ctx.workers, canon_task, [(d, str(ctx.out / "canonical_fresh")) for d in K.FRESH_CANONICAL_CHECK_IDS])
    parity = {"corrected_full": {}, "legacy_live": {}, "corrected_live_no_et": {}}
    for r in res:
        cdir = ctx.out / "canonical_fresh" if r["dataset"] in K.FRESH else K.ML4_FEATURE_DIR
        if r["dataset"] in K.FRESH and r["dataset"] not in K.FRESH_CANONICAL_CHECK_IDS:
            parity[r["path"]][r["dataset"]] = {"dataset": r["dataset"], "rows": r["rows"], "note": "serving path only (canonical extraction compared on the datasets in FRESH_CANONICAL_CHECK_IDS)"}
            continue
        parity[r["path"]][r["dataset"]] = SE.compare_with_canonical(r["dataset"], served / r["path"], cdir)
    ctx.M["serving_parity_at_scale"] = {"tolerance": PL.TOLERANCE, "paths": parity, "feature_hashes": {p: {r["dataset"]: r["features_sha256"] for r in res if r["path"] == p} for p in parity},
                                        "canonical_fresh_hashes": {c["dataset"]: c["features_sha256"] for c in canon}}
    cf = parity["corrected_full"]
    checked = [v for v in cf.values() if "bit_identical_all_rows" in v]
    log(f"serving: corrected path bit-identical on {sum(v['bit_identical_all_rows'] for v in checked)}/{len(checked)} compared datasets")


def _first_op(e):
    ops = e["operating_points"]
    nm = next(iter(ops))
    return nm, ops[nm]


def _metrics_summary(e):
    """Headline numbers of one (dataset, model, mode, path) at its FIRST operating point (ml4: VAL-F1 threshold transferred; shipped: production threshold)."""
    nm, o = _first_op(e)
    per = {t: {"events": v["events"], "incidents": v["incidents"], "incidents_detected": v.get("incidents_detected"), "event_detection_rate": v.get("event_detection_rate"),
               "pr_auc_vs_negatives": v.get("pr_auc_vs_negatives")} for t, v in o["per_attack"].items() if v["events"]}
    return {"pr_auc": e["ranking_fused"]["pr_auc"], "roc_auc": e["ranking_fused"]["roc_auc"], "macro_type_pr_auc": e["macro_type_pr_auc_fused"]["macro_pr_auc"], "threshold_name": nm,
            "threshold": o["threshold_value"], "precision": o["precision"], "recall": o["recall"], "f1": o["f1"], "false_positive_rate": o["false_positive_rate"],
            "alert_rate": o["alert_rate"], "incidents": o["incidents"], "incidents_detected": o["incidents_detected"],
            "incident_recall": o["incidents_detected"] / o["incidents"] if o["incidents"] else None, "per_attack": per}


def _aggregate(rows: list) -> dict:
    """Mean over datasets of each headline metric, and pooled incident recall / per-attack detection."""
    keys = ("pr_auc", "roc_auc", "macro_type_pr_auc", "precision", "recall", "f1", "false_positive_rate", "alert_rate")
    out = {k: float(np.mean([r[k] for r in rows])) for k in keys}
    out["incidents"] = int(sum(r["incidents"] for r in rows))
    out["incidents_detected"] = int(sum(r["incidents_detected"] for r in rows))
    out["pooled_incident_recall"] = out["incidents_detected"] / out["incidents"]
    per = {}
    for t in ATT:
        n = sum(r["per_attack"].get(t, {}).get("incidents", 0) for r in rows)
        d = sum(r["per_attack"].get(t, {}).get("incidents_detected") or 0 for r in rows)
        pa = [r["per_attack"][t]["pr_auc_vs_negatives"] for r in rows if t in r["per_attack"] and r["per_attack"][t].get("pr_auc_vs_negatives") is not None]
        per[t] = {"incidents": int(n), "incidents_detected": int(d), "mean_pr_auc_vs_negatives": float(np.mean(pa)) if pa else None}
    out["per_attack"] = per
    out["datasets"] = len(rows)
    return out


def stage_scoring(ctx: Ctx):
    """Phase 3: ML-4 datasets re-evaluated through the pre-fix (legacy_live) and post-fix (corrected_full) boundaries, plus the platform-as-today path (no entityType)."""
    served = ctx.out / "served"
    ctx.art_thr = float(load_artifact()["threshold"])
    cfg4 = ctx.ml4_cfg
    tasks, tags = [], []
    for d in K.PARITY_REEVAL_IDS:
        for p in ("corrected_full", "legacy_live"):
            for mk in ("ml4", "shipped"):
                tasks.append((mk, d, str(K.ML4_RUN), str(served / p)))
                tags.append(p)
    for d in K.NO_ENTITY_TYPE_IDS:
        tasks.append(("ml4", d, str(K.ML4_RUN), str(served / "corrected_live_no_et")))
        tags.append("corrected_live_no_et")
    log(f"scoring: {len(tasks)} (model, dataset, path) tasks")
    res = _pool(ctx.workers, R4.sealed_task, tasks)
    out = {d: {} for d in K.PARITY_REEVAL_IDS}
    m4metrics = json.load(open(K.K4.REPORTS / "ml4_runs" / "C" / "metrics.json", encoding="utf-8"))["sealed_evaluation"]
    for (mk, did, r), path in zip(res, tags):
        lab_all = ctx.vault.labels(did, "phase-3 re-evaluation (ML-4 dataset, development data in ML-5)")
        incs = ctx.vault.incidents(did, "phase-3 re-evaluation")
        L = lab_all.loc[r["event_id"]]
        lab, aid = L["label"].to_numpy(dtype=object), L["attack_id"].to_numpy(dtype=object)
        mode = "frozen" if mk == "ml4" else "adaptive"          # ml4 frozen = the ML-4 headline; shipped adaptive = the shipped model as deployed
        arr = r["modes"][mode]
        e = X4.eval_arrays(did, lab, aid, arr, R4.thr_for(mk, mode, cfg4, None, ctx.art_thr), incs, r["ts_ns"])
        out[did][f"{mk}/{mode}/{path}"] = _metrics_summary(e)
        ctx.arrays[f"reeval/{mk}/{mode}/{path}/{did}"] = arr["fused"]
    for did in K.PARITY_REEVAL_IDS:
        out[did]["ml4/frozen/canonical_as_reported_in_ML4"] = _metrics_summary(m4metrics[did]["ml4/frozen"])
        out[did]["shipped/adaptive/canonical_as_reported_in_ML4"] = _metrics_summary(m4metrics[did]["shipped/adaptive"])
    variants = sorted({k for v in out.values() for k in v})
    agg = {}
    for v in variants:
        rows = [out[d][v] for d in K.PARITY_REEVAL_IDS if v in out[d]]
        agg[v] = _aggregate(rows)
    # the post-fix boundary must reproduce the ML-4 (canonical) numbers exactly: that is the scoring-level proof of parity
    same = {}
    for mk, mode in (("ml4", "frozen"), ("shipped", "adaptive")):
        same[f"{mk}/{mode}"] = all(out[d][f"{mk}/{mode}/corrected_full"] == out[d][f"{mk}/{mode}/canonical_as_reported_in_ML4"] for d in K.PARITY_REEVAL_IDS)
    ctx.M["phase3_pre_vs_post_fix"] = {"per_dataset": out, "aggregate_over_datasets": agg, "corrected_full_reproduces_ML4_canonical_metrics_exactly": same,
                                       "notes": {"legacy_live": "pre-fix: evaluation events through the production api._canonical_event (onboarding history canonical, as the api warm-up does)",
                                                 "corrected_full": "post-fix: every event through the corrected contract", "corrected_live_no_et": "platform as it is today: corrected contract, no entityType in the payload",
                                                 "canonical_as_reported_in_ML4": "the ML-4 numbers (canonical events, training feature extraction)"}}
    log(f"scoring: phase-3 comparison built; corrected_full reproduces ML-4 exactly: {same}")


def _drift_matched(arrs, labels, aid, incs) -> dict:
    """ML-4 method (eval_ml4.posthoc4.drift_matched) on in-memory arrays: every variant's threshold is set on its own BEFORE-drift negatives for FPR 0.5%, then applied
    to the during / after phases. Removes the threshold-choice confound between the frozen and adaptive modes."""
    ph = DR.phase_of(arrs["day"])
    y = EV.is_attack(labels).astype(int)
    neg = y == 0
    out = {}
    for name, _, _ in DR.VARIANTS:
        f = arrs[f"fused__{name}"]
        thr = float(np.quantile(f[(ph == "before") & neg], 1 - 0.005))
        alert = f >= thr
        row = {"threshold": thr}
        for p_ in DR.PHASES:
            m = ph == p_
            yy = y[m]
            bd = labels[m] == "benign_drift"
            nrm = labels[m] == "normal"
            inc_ids = [i["attack_id"] for i in incs if i.get("period") == p_]
            det = sum(bool(alert[aid == a].any()) for a in inc_ids)
            row[p_] = {"recall": float(alert[m][yy == 1].mean()) if (yy == 1).any() else None, "fpr_normal": float(alert[m][nrm].mean()) if nrm.any() else None,
                       "fpr_benign_drift": float(alert[m][bd].mean()) if bd.any() else None, "incident_recall": (det / len(inc_ids)) if inc_ids else None,
                       "incidents": len(inc_ids), "alert_rate": float(alert[m].mean())}
        out[name] = row
    return out


def stage_drift_reeval(ctx: Ctx):
    """Phase 6 carry-forward: the ML-4 controlled-drift datasets through the pre-fix and post-fix boundaries; frozen vs adaptive baseline variants (ML-4 method)."""
    served = ctx.out / "served"
    cfg4 = ctx.ml4_cfg
    tasks = [("ml4", d, str(K.ML4_RUN), str(served / p)) for p in ("legacy_live", "corrected_full") for d in K.DRIFT_REEVAL_IDS]
    res = _pool(ctx.workers, R4.drift_task, tasks)
    thr = {"frozen": cfg4["thresholds"]["frozen"]["f1_optimal"], "adaptive": cfg4["thresholds"]["adaptive"]["f1_optimal"]}
    per = {"legacy_live": {}, "corrected_full": {}}
    matched = {"legacy_live": {}, "corrected_full": {}}
    for (mk, did, rd, fd), (d2, arrs) in zip(tasks, res):
        path = Path(fd).name
        lab = ctx.vault.labels(did, "phase-6 drift re-evaluation (ML-4 drift dataset, development data in ML-5)")
        incs = ctx.vault.incidents(did, "phase-6")
        per[path][did] = DR.evaluate(did, arrs, lab, incs, thr)
        La = lab.loc[arrs["event_id"]]
        matched[path][did] = _drift_matched(arrs, La["label"].to_numpy(dtype=object), La["attack_id"].to_numpy(dtype=object), incs)
        for k, v in arrs.items():
            if k.startswith("fused__"):
                ctx.arrays[f"drift/{path}/{did}/{k}"] = v
    m4 = json.load(open(K.K4.REPORTS / "ml4_runs" / "C" / "metrics.json", encoding="utf-8"))["drift_evaluation"]["datasets"]
    per["canonical_as_reported_in_ML4"] = {d: m4[d] for d in K.DRIFT_REEVAL_IDS}
    effects = {p: DR.paired_effects(per[p]) for p in per}

    def summ(p):
        """Adaptive (alpha 0.02, alert guard) vs frozen, at each variant's own transferred threshold: what adaptation buys and costs."""
        rows = {}
        for did in K.DRIFT_REEVAL_IDS:
            v = per[p][did]["variants"]
            fz, ad = v["frozen"], v["adaptive_a0.02"]
            rows[did] = {"frozen": {"pr_auc": fz["overall"]["pr_auc"], "recall": fz["overall"]["recall"], "fpr": fz["overall"]["false_positive_rate"],
                                    "benign_drift_fpr": fz["benign_drift_fpr_all_phases"], "recall_after": fz["phases"]["after"]["recall"], "incident_recall_after": fz["phases"]["after"]["incident_recall"]},
                         "adaptive_a0.02": {"pr_auc": ad["overall"]["pr_auc"], "recall": ad["overall"]["recall"], "fpr": ad["overall"]["false_positive_rate"],
                                            "benign_drift_fpr": ad["benign_drift_fpr_all_phases"], "recall_after": ad["phases"]["after"]["recall"],
                                            "incident_recall_after": ad["phases"]["after"]["incident_recall"]}}
        return rows
    from eval_ml4 import posthoc4 as PH
    matched["canonical_as_reported_in_ML4"] = {d: v for d, v in PH.drift_matched(K.ML4_RUN, None).items() if d in K.DRIFT_REEVAL_IDS}
    ctx.M["phase6_matched_operating_point"] = {"design": "each variant's threshold set on its own before-drift negatives for FPR 0.5% (ML-4 method), applied during/after",
                                               "per_dataset": matched}
    ctx.M["phase6_adaptive_vs_frozen"] = {"per_dataset": per, "paired_effects_vs_control": effects, "summary_frozen_vs_adaptive": {p: summ(p) for p in per},
                                          "design": "ML-4 method unchanged (thresholds = ML-4 evaluation operating points of the frozen ml4 model per mode family); legacy_live = pre-fix as served, "
                                                    "corrected_full = post-fix, canonical_as_reported_in_ML4 = the ML-4 numbers"}


def _dev_arrays(ctx, P4):
    """Evaluation-period fused scores of every DEV deployment from ML-4's stored (canonical, frozen-mode) arrays, aligned with their labels."""
    data = {}
    for did in K.DEV_IDS:
        key = f"sealed__ml4__frozen__{did}" if did in K.K4.SEALED_STD_IDS else f"dev__ml4__frozen__{did}"
        Lz = F4.Loaded(did, K.ML4_FEATURE_DIR)
        lab_all = ctx.vault.labels(did, "dev analysis")
        L = lab_all.loc[Lz.X_eval["event_id"].to_numpy()]
        data[did] = {"fused": np.asarray(P4[key], float), "labels": L["label"].to_numpy(dtype=object), "aid": L["attack_id"].to_numpy(dtype=object), "profile": K.DEV_PROFILE[did],
                     "n_onb": Lz.n_onb}
        assert len(data[did]["fused"]) == len(data[did]["labels"])
    return data


def stage_dev(ctx: Ctx):
    P4 = np.load(K.K4.REPORTS / "ml4_runs" / "C" / "predictions.npz")
    data = _dev_arrays(ctx, P4)
    tails = dict(_pool(ctx.workers, tail_task, [(d, str(K.ML4_FEATURE_DIR)) for d in K.DEV_IDS]))
    for d in data:
        data[d]["tail"] = tails[d]
        ctx.arrays[f"dev_tail/{d}"] = tails[d]
    ml4_thr = ctx.ml4_cfg["thresholds"]["frozen"]["f1_optimal"]
    study = TH.study(data, K.ALPHAS, ml4_thr)
    sel = TH.select_alpha(study)
    vol = TH.onboarding_volume_study(data, sel["selected_alpha"])
    vol_ref = TH.onboarding_volume_study(data, K.ALPHA_VOLUME_REFERENCE)
    log(f"dev: alpha selected {sel['selected_alpha']} (mean F1 by alpha {sel['mean_f1_by_alpha']})")
    ctx.M["threshold_study_dev"] = {"study": study, "alpha_selection": sel, "onboarding_volume": vol, "onboarding_volume_reference_alpha": vol_ref,
                                    "alpha_grid_edge_note": "the selected alpha is at an edge of the pre-registered grid" if sel["selected_alpha"] in (min(K.ALPHAS), max(K.ALPHAS)) else None}
    # secondary vehicle: the SHIPPED detector's frozen fused score (production model; its own TRAIN dataset orig42 is excluded because its tail is in-sample)
    ship_ids = [d for d in K.DEV_IDS if d != K.K4.LEGACY_ID]
    ship_tails = dict(_pool(ctx.workers, tail_task_shipped, [(d, str(K.ML4_FEATURE_DIR)) for d in ship_ids]))
    ship = {}
    for d in ship_ids:
        key = f"sealed__shipped__frozen__{d}" if d in K.K4.SEALED_STD_IDS else f"dev__shipped__frozen__{d}"
        ship[d] = {"fused": np.asarray(P4[key], float), "labels": data[d]["labels"], "aid": data[d]["aid"], "profile": data[d]["profile"], "tail": ship_tails[d]}
        ctx.arrays[f"dev_tail_shipped/{d}"] = ship_tails[d]
    ship_study = TH.study(ship, K.ALPHAS, None)
    ship_sel = TH.select_alpha(ship_study)
    ctx.M["threshold_study_dev_shipped"] = {"study": ship_study, "alpha_selection": ship_sel, "onboarding_volume": TH.onboarding_volume_study(ship, ship_sel["selected_alpha"]),
                                            "note": "secondary vehicle: shipped detector, frozen baseline; orig42 excluded (its onboarding trained the shipped model)"}
    log(f"dev: shipped-vehicle alpha selected {ship_sel['selected_alpha']}")
    lop = CA.lopo(data)
    csel = CA.select_method(lop)
    log(f"dev: calibration selected {csel['selected']}")
    ctx.M["calibration_dev"] = {"lopo": lop, "selection": csel, "prevalence_by_dataset": {d: float(EV.is_attack(data[d]["labels"]).mean()) for d in data}}
    # prior-shift stress (leave-one-profile-out predictions re-sampled to other base rates), for identity and every method
    stress = {}
    for m in K.CALIB_METHODS:
        stress[m] = {}
        for d in data:
            tr = [x for x in data if data[x]["profile"] != data[d]["profile"]]
            c = CA.Calibrator(m).fit([data[x]["fused"] for x in tr], [data[x]["tail"] for x in tr], [EV.is_attack(data[x]["labels"]).astype(int) for x in tr])
            stress[m][d] = CA.prior_shift_stress(c.predict(data[d]["fused"], data[d]["tail"]), data[d]["labels"])
        stress[m]["MEAN"] = {pi: {k: float(np.mean([stress[m][d][pi][k] for d in data])) for k in ("mean_predicted", "prevalence", "ece_equal_frequency", "brier", "log_loss")}
                             for pi in next(iter(stress[m].values()))}
    ctx.M["calibration_dev"]["prior_shift_stress_leave_one_profile_out"] = stress
    # ---- FREEZE (everything below is fitted / decided on DEV only)
    chosen = csel["selected"]
    cal = None
    params = None
    if chosen:
        cal = CA.Calibrator(chosen).fit([data[d]["fused"] for d in data], [data[d]["tail"] for d in data], [EV.is_attack(data[d]["labels"]).astype(int) for d in data])
        params = cal.params
    cfg = {"candidate": "ML-5 deployment-threshold rule + score calibrator (NOT DEPLOYED; evaluation artifact)", "ml4_artifact": "models/candidates/ml4/ml4_global.joblib",
           "ml4_frozen_config_sha256": ctx.M["verify"]["ml4_frozen_config_sha256"], "fusion_weights": ctx.ml4_cfg["fusion_weights"], "contract_version": CONTRACT_VERSION,
           "deployment_timezone_convention": K.DEPLOYMENT_TZ,
           "threshold_rule": {"population": f"deployment's own attack-free onboarding tail (last {1 - K.ONBOARD_HEAD_FRACTION:.0%} of onboarding rows, scored with a baseline fitted on the head)",
                              "formula": "t_d = quantile_(1-alpha)(tail fused scores), method='higher'", "alpha_grid": K.ALPHAS, "selected_alpha": sel["selected_alpha"],
                              "alpha_selection": sel["rule"], "onboard_head_fraction": K.ONBOARD_HEAD_FRACTION},
           "shipped_detector_vehicle_threshold_rule": {"selected_alpha": ship_sel["selected_alpha"], "note": "same rule on the shipped detector's frozen fused score (secondary vehicle)"},
           "calibration": {"method": chosen, "fitted_on": list(data), "params_sha256": K.sha256_obj(params) if params else None, "selection": csel["rule"]},
           "ml5_config_sha256": K.sha256_obj(K.ML5_CONFIG), "dev_pool": list(data)}
    cp = ctx.out / "candidate" / "frozen_config5.json"
    if cp.exists():
        os.chmod(cp, stat.S_IWRITE | stat.S_IREAD)
    K.write_json(cp, cfg)
    K.write_json(ctx.out / "candidate" / "calibrator_params.json", {"method": chosen, "params": params})
    os.chmod(cp, stat.S_IREAD)
    ctx.M["freeze"] = {"frozen_config5_sha256": K.sha256_file(cp), "calibrator_params_sha256": K.sha256_file(ctx.out / "candidate" / "calibrator_params.json"), "config": cfg,
                       "test_datasets_unsealed_before_freeze": sorted(ctx.vault.unsealed)}
    log(f"FROZEN: config sha256 {ctx.M['freeze']['frozen_config5_sha256'][:16]} | alpha {sel['selected_alpha']} | calibrator {chosen}")
    return data, cal, cfg


def stage_test(ctx: Ctx, dev_data, cal, cfg, ids=None):
    ids = list(ids or K.FRESH_IDS)
    profile_of = lambda d: K.FRESH[d][0] if d in K.FRESH else K.DEV_PROFILE[d]   # noqa: E731
    cp = ctx.out / "candidate" / "frozen_config5.json"
    assert K.sha256_file(cp) == ctx.M["freeze"]["frozen_config5_sha256"]
    served = ctx.out / "served" / "corrected_full"
    tails = dict(_pool(ctx.workers, tail_task, [(d, str(served)) for d in ids]))
    tasks = [("ml4", d, str(K.ML4_RUN), str(served)) for d in ids]
    res = {d: r for _, d, r in _pool(ctx.workers, R4.sealed_task, tasks)}
    test = {}
    for d in ids:
        if d in K.FRESH:
            ctx.vault.unseal(d, "final evaluation of the frozen ML-5 configuration")
        lab_all = ctx.vault.labels(d, "final evaluation")
        incs = ctx.vault.incidents(d, "final evaluation")
        r = res[d]
        L = lab_all.loc[r["event_id"]]
        test[d] = {"fused": np.asarray(r["modes"]["frozen"]["fused"], float), "labels": L["label"].to_numpy(dtype=object), "aid": L["attack_id"].to_numpy(dtype=object),
                   "profile": profile_of(d), "tail": tails[d], "incidents": incs}
        ctx.arrays[f"test_fused/{d}"] = test[d]["fused"]
        ctx.arrays[f"test_tail/{d}"] = tails[d]
    ml4_thr = ctx.ml4_cfg["thresholds"]["frozen"]["f1_optimal"]
    study = TH.study(test, K.ALPHAS, ml4_thr)
    a_star = cfg["threshold_rule"]["selected_alpha"]
    vol = TH.onboarding_volume_study(test, a_star)
    # universal comparators built from the DEV pool only (nothing from TEST)
    dev_tail = np.concatenate([dev_data[d]["tail"] for d in dev_data])
    uni_dev = {str(a): TH.rule_threshold(dev_tail, a) for a in K.ALPHAS}
    for d in test:
        study["deployments"][d]["universal_pooled_from_DEV_deployments"] = {str(a): TH.evaluate_threshold(test[d]["fused"], test[d]["labels"], test[d]["aid"], uni_dev[str(a)]) for a in K.ALPHAS}
    vol_ref = TH.onboarding_volume_study(test, K.ALPHA_VOLUME_REFERENCE)
    ctx.M["threshold_study_test"] = {"study": study, "onboarding_volume": vol, "onboarding_volume_reference_alpha": vol_ref, "universal_dev_thresholds": uni_dev, "alpha_star": a_star}
    # secondary vehicle: shipped detector (frozen baseline), alpha frozen on DEV
    ship_tails = dict(_pool(ctx.workers, tail_task_shipped, [(d, str(served)) for d in ids]))
    sres = {d: r for _, d, r in _pool(ctx.workers, R4.sealed_task, [("shipped", d, str(K.ML4_RUN), str(served)) for d in ids])}
    ship = {d: {"fused": np.asarray(sres[d]["modes"]["frozen"]["fused"], float), "labels": test[d]["labels"], "aid": test[d]["aid"], "profile": test[d]["profile"], "tail": ship_tails[d]}
            for d in ids}
    for d in ids:
        ctx.arrays[f"test_fused_shipped/{d}"] = ship[d]["fused"]
    ship_study = TH.study(ship, K.ALPHAS, None)
    a_ship = cfg["shipped_detector_vehicle_threshold_rule"]["selected_alpha"]
    ctx.M["threshold_study_test_shipped"] = {"study": ship_study, "alpha_star": a_ship, "onboarding_volume": TH.onboarding_volume_study(ship, a_ship)}
    # ---- calibration on TEST
    cal_test = {"method": cfg["calibration"]["method"], "per_dataset": {}, "all_methods_per_dataset": {}}
    for m in K.CALIB_METHODS:
        c = CA.Calibrator(m)
        if m != "identity":
            c.fit([dev_data[d]["fused"] for d in dev_data], [dev_data[d]["tail"] for d in dev_data], [EV.is_attack(dev_data[d]["labels"]).astype(int) for d in dev_data])
        cal_test["all_methods_per_dataset"][m] = {d: CA.metrics(c.predict(test[d]["fused"], test[d]["tail"]), test[d]["labels"]) for d in test}
        allp = np.concatenate([c.predict(test[d]["fused"], test[d]["tail"]) for d in test])
        alll = np.concatenate([test[d]["labels"] for d in test])
        cal_test["all_methods_per_dataset"][m]["POOLED"] = CA.metrics(allp, alll)
        cal_test.setdefault("prior_shift_stress_pooled_by_method", {})[m] = CA.prior_shift_stress(allp, alll)
        if m == cfg["calibration"]["method"]:
            cal_test["reliability_pooled"] = CA.reliability(allp, EV.is_attack(alll).astype(int))
            for d in test:
                ctx.arrays[f"test_calibrated/{d}"] = c.predict(test[d]["fused"], test[d]["tail"])
    cal_test["per_dataset"] = cal_test["all_methods_per_dataset"].get(cfg["calibration"]["method"] or "identity", {})
    ctx.M["calibration_test"] = cal_test
    ctx.M["test_unseal"] = {"unsealed": sorted(ctx.vault.unsealed), "unseals_per_dataset": 1}
    return test


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--regen", action="store_true")
    ap.add_argument("--dry", action="store_true", help="plumbing rehearsal: the TEST stage runs on two ML-4 sealed (already opened) datasets; no fresh label is read")
    a = ap.parse_args()
    ctx = Ctx(a.run_id, a.workers)
    t_all = time.time()
    before = K.K4.production_hashes()
    K.write_json(ctx.out / "hashes_before.json", before)
    ctx.M["meta"] = {"run_id": a.run_id, "phase": "ML-5", "dry_rehearsal": a.dry, "config": K.ML5_CONFIG}
    stage_verify(ctx, a.regen)
    ctx.checkpoint("verify")
    stage_tests(ctx)
    ctx.checkpoint("tests")
    stage_serving(ctx)
    ctx.checkpoint("serving")
    stage_scoring(ctx)
    ctx.checkpoint("scoring")
    stage_drift_reeval(ctx)
    ctx.checkpoint("drift_reeval")
    dev_data, cal, cfg = stage_dev(ctx)
    ctx.checkpoint("dev")
    test = stage_test(ctx, dev_data, cal, cfg, ids=["P0-104", "P2-302"] if a.dry else None)
    ctx.checkpoint("test")
    from . import artifacts as AR
    ctx.M["candidate_manifest"] = AR.write_candidate_files(ctx.out / "candidate", f"eval_ml5 run {a.run_id}")
    after = K.K4.production_hashes()
    K.write_json(ctx.out / "hashes_after.json", after)
    ctx.M["integrity"] = {"production_files_hashed": len(before), "production_unchanged": before == after, "production_files_changed": sorted(k for k in before if before[k] != after.get(k)),
                          "test_datasets_unsealed": sorted(ctx.vault.unsealed), "frozen_before_any_unseal": ctx.M["freeze"]["test_datasets_unsealed_before_freeze"] == [], "vault_log": ctx.vault.log}
    fm = json.load(open(K.DATA_DIR / "manifest.json", encoding="utf-8"))
    ctx.M["hashes"] = {"config": K.sha256_obj(K.ML5_CONFIG), "source": source_hashes(), "fresh_dataset_set": fm["dataset_set_sha256"], "ml4_predictions": ctx.M["verify"]["ml4_predictions_sha256"],
                       "frozen_config5": ctx.M["freeze"]["frozen_config5_sha256"], "calibrator_params": ctx.M["freeze"]["calibrator_params_sha256"], "prediction_arrays": arrays_hash(ctx.arrays),
                       "metric_sections": {k: K.sha256_obj(ctx.M[k]) for k in ("phase3_pre_vs_post_fix", "phase6_adaptive_vs_frozen", "phase6_matched_operating_point", "threshold_study_dev", "threshold_study_dev_shipped", "threshold_study_test",
                                                                             "threshold_study_test_shipped", "calibration_dev", "calibration_test", "serving_parity_at_scale", "parity_unit_tests")},
                       "candidate_files": ctx.M["candidate_manifest"]["files"], "production_model_sha256": before["models/pipeline.joblib"],
                       "fresh_feature_hashes": ctx.M["serving_parity_at_scale"]["feature_hashes"]}
    ctx.M["environment"] = env_info()
    ctx.M["meta"]["seconds"] = time.time() - t_all
    np.savez_compressed(ctx.out / "predictions.npz", **{k.replace("/", "__"): v for k, v in ctx.arrays.items()})
    K.write_json(ctx.out / "parity_report.json", {"contract_version": CONTRACT_VERSION, "unit_tests": ctx.M["parity_unit_tests"], "serving_parity_at_scale": ctx.M["serving_parity_at_scale"],
                                                  "scoring_level_parity": ctx.M["phase3_pre_vs_post_fix"]["corrected_full_reproduces_ML4_canonical_metrics_exactly"]})
    K.write_json(ctx.out / "metrics.json", ctx.M)
    log(f"DONE run {a.run_id} in {time.time() - t_all:.0f}s | production unchanged: {before == after}")


if __name__ == "__main__":
    main()

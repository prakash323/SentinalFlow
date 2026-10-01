"""Scoring stages for ML-2 (evaluation-only). LABEL-FREE: nothing in this module reads a label.

batch_stage   frozen batch scoring of every event with the shipped artifact (no online updates):
                 shipped semantics   det.fuse() rank-normalises over the scored population + det.to_risk_100(batch)
                                     -> what the README / ML-1 reported. TRANSDUCTIVE (uses the test distribution).
                 frozen train-anchored   per-signal percentile vs the STORED TRAINING distributions
                                     (== Detector.fuse_single, vectorised) + the per-event to_risk_100 mapping
                                     -> uses no test information; differs from streaming only by the online updates.
stream_stage  chronological streaming through the UNMODIFIED production StreamingScorer.process, event by event:
                 warm-up on the TRAIN window only (run_realtime.py's batch-replay semantics), then for every
                 validation+test event: update state -> features -> score -> record -> next.
                 variants: main (as deployed: EWMA baseline updates ON), nodrift (EWMA OFF, diagnostic),
                           heldout (held-out entities: no profile, no warm-up history).
"""
from __future__ import annotations

import time

import numpy as np
import pandas as pd

from . import common as K
from .common import C
from .protocol import Protocol, heldout_entities

FEATURE_NAMES = None


def _fn():
    global FEATURE_NAMES
    if FEATURE_NAMES is None:
        from src.features import FEATURE_NAMES as F
        FEATURE_NAMES = F
    return FEATURE_NAMES


def risk_event_level(det, fused):
    """Vectorised equivalent of calling det.to_risk_100(np.array([f]))[0] one event at a time (streaming semantics):
    a single element above the whole training calibration curve is 'saturated' and returned as exactly 100.0."""
    fused = np.asarray(fused, dtype=float)
    n_cal = max(len(det.calib), 1)
    idx = np.searchsorted(det.calib, fused, side="right")
    risk = 99.0 * idx / n_cal
    risk[idx >= n_cal] = 100.0
    return risk


def fused_train_anchored(det, rawf):
    w = C.FUSION_WEIGHTS
    parts = []
    for k in ("baseline", "iforest", "sequence"):
        arr = det.sig_calib[k]
        parts.append(w[k] * np.searchsorted(arr, np.asarray(rawf[k], dtype=float), side="right") / max(len(arr), 1))
    return np.sum(parts, axis=0) / sum(w.values())


def batch_stage(p: Protocol, out_dir, log=print):
    from src.features import build_feature_matrix
    art = K.load_artifact()
    prof, det = art["profiler"], art["detector"]
    FN = _fn()
    t = time.time()
    X = build_feature_matrix(p.events, verbose=False)                # one causal pass, label-free
    log(f"[batch] features {X.shape} in {time.time()-t:.0f}s")
    b_all, _, lowconf = prof.score_frame(X)                          # FROZEN profile (no update() calls)
    raw = det.raw_scores(X, b_all)
    rawf = {k: raw[k] for k in ("baseline", "iforest", "sequence")}
    log(f"[batch] raw signals scored in {time.time()-t:.0f}s")

    fused_union = det.fuse(rawf)                                     # shipped batch semantics (transductive)
    risk_union = det.to_risk_100(fused_union)
    fused_pct = fused_train_anchored(det, rawf)                      # frozen, train-anchored
    risk_ev = risk_event_level(det, fused_pct)

    # ---- self-checks: my vectorised mappings == the production single-event functions
    rng = np.random.default_rng(K.EVAL_SEED)
    samp = rng.choice(len(X), 1500, replace=False)
    d_f, d_r = 0.0, 0.0
    for i in samp:
        fs = det.fuse_single({k: float(rawf[k][i]) for k in rawf})
        d_f = max(d_f, abs(fs - fused_pct[i]))
        rs = float(det.to_risk_100(np.array([fs]))[0])
        d_r = max(d_r, abs(rs - risk_ev[i]))
    checks = {"vectorised_fuse_vs_fuse_single_max_abs_diff": d_f, "vectorised_risk_vs_to_risk_100_max_abs_diff": d_r}

    # ---- TRAIN integrity: the shipped artifact was fitted on exactly the protocol TRAIN split
    tr = p.m_train
    checks["train_integrity"] = {
        "artifact_profiler_training_events": int(sum(prof.n.values())),
        "protocol_train_events": int(tr.sum()),
        "artifact_calibration_rows": int(len(det.calib)),
        "sig_calib_max_abs_diff_vs_recomputed_train": {
            k: float(np.max(np.abs(np.sort(rawf[k][tr]) - det.sig_calib[k]))) if len(det.sig_calib[k]) == tr.sum() else None
            for k in ("baseline", "iforest", "sequence")},
        "fused_calib_max_abs_diff_vs_recomputed_train": float(np.max(np.abs(np.sort(fused_union[tr]) - det.calib)))
        if len(det.calib) == tr.sum() else None,
        "artifact_threshold": float(art["threshold"]),
        "artifact_entities_profiled": int(len(prof.mu)),
    }
    np.savez_compressed(out_dir / "batch.npz", event_id=p.events["event_id"].to_numpy(),
                        raw_baseline=rawf["baseline"], raw_iforest=rawf["iforest"], raw_sequence=rawf["sequence"],
                        fused_union=fused_union, risk_union=risk_union, fused_pct=fused_pct, risk_event=risk_ev,
                        lowconf=lowconf, features=X[FN].to_numpy(dtype=np.float64))
    K.write_json(out_dir / "batch_checks.json", checks)
    log(f"[batch] done in {time.time()-t:.0f}s | checks: {checks['vectorised_fuse_vs_fuse_single_max_abs_diff']:.2e} / "
        f"{checks['vectorised_risk_vs_to_risk_100_max_abs_diff']:.2e}")


def stream_stage(p: Protocol, variant: str, out_dir, log=print, limit=None):
    import torch
    torch.set_num_threads(1)
    from src.explain import Explainer
    from src.realtime import StreamingScorer

    FN = _fn()
    art = K.load_artifact()
    prof, det, clf = art["profiler"], art["detector"], art["classifier"]
    held: set = set()
    if variant == "nodrift":
        prof.use_drift = False                                        # in-memory copy only
    if variant == "heldout":
        held = set(heldout_entities(p))
        for e in held:                                                # no per-entity profile: peer-prior cold start
            prof.mu.pop(e, None)
            prof.var.pop(e, None)
            prof.n.pop(e, None)

    # exactly api._load_scorer's construction, except the warm-up scope below
    sc = StreamingScorer(prof, det, clf, Explainer(clf), threshold=art["threshold"])
    ev = p.events
    warm_mask = p.m_train & (~ev["entity_id"].isin(held).to_numpy() if held else True)
    t = time.time()
    sc.warmup(ev[warm_mask])                                          # TRAIN window only (leak-free)
    log(f"[stream:{variant}] warm-up on {int(np.sum(warm_mask))} train events in {time.time()-t:.0f}s")

    # ---- instrumentation on THIS process's in-memory copies (production code is not touched)
    cur: dict = {}
    o_score, o_fuse, o_feat = det.score_single, det.fuse_single, sc.extractor.update_and_extract

    def w_score(feat_vec, seq_window, baseline_score):
        out = o_score(feat_vec, seq_window, baseline_score)
        cur["raw"] = out[0]
        return out

    def w_fuse(raw_single):
        f = o_fuse(raw_single)
        cur["fused"] = f
        return f

    def w_feat(event):
        f = o_feat(event)
        cur["feat"] = [f[n] for n in FN]
        return f

    det.score_single, det.fuse_single, sc.extractor.update_and_extract = w_score, w_fuse, w_feat

    stream = ev[~p.m_train.astype(bool)]
    if limit:
        stream = stream.iloc[:limit]
    recs = stream.to_dict("records")
    held_set = held
    n_all = len(recs)
    if variant == "heldout":
        scored_idx = [i for i, e in enumerate(recs) if e["entity_id"] in held_set]
        out_ids = stream["event_id"].to_numpy()[scored_idx]
    else:
        scored_idx = list(range(n_all))
        out_ids = stream["event_id"].to_numpy()
    n = len(scored_idx)
    out = {"event_id": out_ids, "risk": np.zeros(n), "fused": np.zeros(n), "alert": np.zeros(n, bool),
           "conf": np.zeros(n), "raw_baseline": np.zeros(n), "raw_iforest": np.zeros(n), "raw_sequence": np.zeros(n),
           "latency_ms": np.zeros(n), "features": np.zeros((n, len(FN)))}
    pred = [""] * n
    t = time.time()
    j = 0
    for i, e in enumerate(recs):
        if variant == "heldout" and e["entity_id"] not in held_set:
            f = o_feat(e)                                             # shared-state update only (no scoring)
            sc.windows[e["entity_id"]].append(np.array([f[nm] for nm in FN], dtype=float))
            continue
        t1 = time.perf_counter()
        risk, alert = sc.process(e)                                   # production code path, unmodified
        out["latency_ms"][j] = (time.perf_counter() - t1) * 1000.0
        out["risk"][j] = risk
        out["fused"][j] = cur["fused"]
        out["raw_baseline"][j], out["raw_iforest"][j], out["raw_sequence"][j] = (
            cur["raw"]["baseline"], cur["raw"]["iforest"], cur["raw"]["sequence"])
        out["features"][j] = cur["feat"]
        if alert:
            out["alert"][j] = True
            pred[j] = alert["predicted_class"]
            out["conf"][j] = alert["class_confidence"]
        j += 1
        if j and j % 2000 == 0:
            log(f"[stream:{variant}] scored {j}/{n} (stream position {i}/{n_all})  {time.time()-t:.0f}s  alerts {int(out['alert'][:j].sum())}")
    log(f"[stream:{variant}] {n} events in {time.time()-t:.0f}s")
    stats = sc.stats()
    np.savez_compressed(out_dir / f"stream_{variant}.npz", pred=np.array(pred, dtype="U24"), **out)
    K.write_json(out_dir / f"stream_{variant}_stats.json",
                 {"stats": stats, "variant": variant, "heldout_entities": sorted(held),
                  "warm_events": int(np.sum(warm_mask)), "streamed_events": n_all, "scored_events": n,
                  "threshold_used": float(sc.threshold), "drift_notices": sc.drift_notices})

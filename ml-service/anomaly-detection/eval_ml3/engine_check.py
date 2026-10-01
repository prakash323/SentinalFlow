"""Engine check (label-free). ML-3 evaluates the candidate with a fast causal replay (candidate.replay) instead of the ~1 h
per-event StreamingScorer. This check runs the SHIPPED model through the same replay logic (production BaselineProfiler,
Detector.fuse_single, Detector.to_risk_100, profiler.update with the shipped threshold) and compares it, event by event, with
what the UNMODIFIED production StreamingScorer produced in ML-2 (reports/ml2_runs/A/stream_main.npz).
If they agree, the candidate numbers are produced by the same semantics as the ML-2 streaming baseline.
"""
from __future__ import annotations

import numpy as np

from . import common as K
from .common import C


def run(p, X_full, out_dir, log) -> dict:
    from src.detect import build_sequences
    from src.features import FEATURE_NAMES

    ref_path = K.REPORTS / "ml2_runs" / "A" / "stream_main.npz"
    if not ref_path.exists():
        return {"available": False, "reason": "ML-2 streaming reference not found"}
    ref = np.load(ref_path, allow_pickle=True)
    art = K.load_artifact()
    prof, det = art["profiler"], art["detector"]
    thr = float(art["threshold"])
    ntr = int(p.m_train.sum())
    Xs = X_full.iloc[ntr:].reset_index(drop=True)
    assert np.array_equal(Xs["event_id"].to_numpy(), ref["event_id"]), "stream rows differ from the ML-2 streaming reference"
    S = build_sequences(X_full)[ntr:]
    F = det.scaler.transform(Xs[FEATURE_NAMES].to_numpy(dtype=float))
    iso = -det.iforest.score_samples(F)
    seq, _ = det.seq_ae.score(S)
    recs = Xs.to_dict("records")
    n = len(recs)
    b = np.empty(n)
    fu = np.empty(n)
    rk = np.empty(n)
    for i, r in enumerate(recs):
        s = prof.score_row(r, r["entity_id"], r["entity_type"])[0]
        f = det.fuse_single({"baseline": s, "iforest": float(iso[i]), "sequence": float(seq[i])})
        risk = float(det.to_risk_100(np.array([f]))[0])
        prof.update(r, r["entity_id"], risk, thr)
        b[i], fu[i], rk[i] = s, f, risk
    def rel(x, y):
        return float(np.max(np.abs(x - y) / np.maximum(np.abs(y), 1e-12)))

    d = {"raw_baseline": float(np.max(np.abs(b - ref["raw_baseline"]))),
         "raw_iforest": float(np.max(np.abs(iso - ref["raw_iforest"]))),
         "raw_sequence": float(np.max(np.abs(seq - ref["raw_sequence"]))),
         "fused": float(np.max(np.abs(fu - ref["fused"]))),
         "risk": float(np.max(np.abs(rk - ref["risk"]))),
         "features_35": float(np.max(np.abs(Xs[FEATURE_NAMES].to_numpy(dtype=float) - ref["features"])))}
    d_rel = {"raw_baseline": rel(b, ref["raw_baseline"]), "raw_iforest": rel(iso, ref["raw_iforest"]), "raw_sequence": rel(seq, ref["raw_sequence"])}
    alerts = rk >= thr
    n_alert_diff = int((alerts != ref["alert"].astype(bool)).sum())
    cal_step = 99.0 / max(len(det.calib), 1)                       # one step of the training calibration curve on the risk scale
    # The GRU error is computed in float32 and its batch composition differs (one event vs a chunk), so raw_sequence may differ by
    # float32 rounding (~1e-7 relative; e.g. exactly 1 ULP = 0.015625 at the largest error, 139,723). Criterion (written AFTER the first
    # runs A/B printed a 1-ULP difference under an over-strict absolute 1e-5 rule; it checks the replay ENGINE only and touches no candidate output): raw signals equal to 1e-6 relative, fused within
    # 1e-5 absolute, risk within 2 calibration steps (a 1e-6 fused change can cross one training-distribution value), zero alert changes.
    ok = (max(d_rel.values()) < 1e-6 and d["fused"] < 1e-5 and d["risk"] <= 2 * cal_step and n_alert_diff == 0 and d["features_35"] == 0.0)
    res = {"available": True, "events_compared": int(n), "max_abs_diff": d, "max_rel_diff_raw_signals": d_rel, "risk_calibration_step": cal_step,
           "alert_mismatches": n_alert_diff, "alerts_replay": int(alerts.sum()), "alerts_streaming_scorer": int(ref["alert"].astype(bool).sum()),
           "reference": "reports/ml2_runs/A/stream_main.npz (unmodified production StreamingScorer.process, warm-up on TRAIN only)",
           "criterion": "raw signals rel<1e-6; fused abs<1e-5; risk<=2 calibration steps; 0 alert mismatches; features bit-identical",
           "conclusion": "equivalent (float32 rounding only)" if ok else "differs - see max_abs_diff"}
    log(f"engine check: {res['conclusion']} | max abs diff {d}")
    return res

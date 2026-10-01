"""Post-hoc explanation of the frozen candidate's misses (diagnostic only; reads labels AFTER the frozen test evaluation; never
feeds back into any choice). Computed from a run's saved predictions and candidate artifact."""
from __future__ import annotations

import json

import joblib
import numpy as np
import pandas as pd

from . import common as K
from .common import ATTACKS


def first_event_analysis(run_dir) -> dict:
    from pathlib import Path
    run_dir = Path(run_dir)
    P = np.load(run_dir / "predictions.npz", allow_pickle=True)
    comp = joblib.load(run_dir / "candidate" / "components.joblib")
    sc = comp["sig_calib"]
    cfg = json.load(open(run_dir / "candidate" / "candidate_config.json", encoding="utf-8"))
    thr = cfg["thresholds"]["primary_fused"]
    w = cfg["fusion_weights"]
    lab = pd.read_csv(K.DATA / "labels.csv").set_index("event_id").loc[P["test_event_id"]]
    pop = P["test_in_population"].astype(bool)
    pct = {k: np.searchsorted(sc[k], P["test_" + k], side="right") / len(sc[k]) for k in K.SIGNALS}
    out = {"threshold": thr, "weights": w, "note": "post-hoc diagnostic on TEST labels; nothing here changes the frozen candidate"}
    for t in ATTACKS:
        m = (lab.label.to_numpy() == t) & pop
        if not m.any():
            continue
        d = pd.DataFrame({"attack_id": lab.attack_id.to_numpy()[m], "fused": P["test_fused"][m], "baseline_pct": pct["baseline"][m],
                          "iforest_pct": pct["iforest"][m], "sequence_pct": pct["sequence"][m]})
        first = d.groupby("attack_id").first()
        best = d.groupby("attack_id")["fused"].max()
        # what the fused score of the FIRST event would have been with the shipped (inherited, unvalidated) weights - reference only
        sw = K.SHIPPED_FUSION_WEIGHTS
        alt = (sw["baseline"] * first.baseline_pct + sw["iforest"] * first.iforest_pct + sw["sequence"] * first.sequence_pct) / sum(sw.values())
        out[t] = {"incidents": int(len(first)),
                  "first_event": {i: {c: float(first.loc[i, c]) for c in first.columns} for i in first.index},
                  "max_fused_per_incident": {i: float(v) for i, v in best.items()},
                  "incidents_whose_max_fused_reaches_threshold": int((best >= thr).sum()),
                  "first_event_fused_under_inherited_weights_reference_only": {i: float(v) for i, v in alt.items()},
                  "median_signal_percentiles_all_events": {"baseline": float(d.baseline_pct.median()), "iforest": float(d.iforest_pct.median()),
                                                           "sequence": float(d.sequence_pct.median())}}
    # how often the flag that drives the baseline on DS events actually fires (ML-2 streamed features; label-free features, labels post-hoc)
    ref = np.load(K.REPORTS / "ml2_runs" / "A" / "stream_main.npz", allow_pickle=True)
    from src.features import FEATURE_NAMES
    fm = ref["features"][:, FEATURE_NAMES.index("fingerprint_mismatch")]
    l2 = pd.read_csv(K.DATA / "labels.csv").set_index("event_id").loc[ref["event_id"]]
    ds = (l2.label.to_numpy() == "device_spoofing")
    first = ~pd.Series(l2.attack_id.to_numpy()[ds]).duplicated().to_numpy()
    out["device_spoofing_flag_facts"] = {"ds_events_in_stream": int(ds.sum()), "events_with_fingerprint_mismatch_1": int((fm[ds] == 1).sum()),
                                          "first_events_with_mismatch_1": int((fm[ds][first] == 1).sum()), "incidents": int(first.sum()),
                                          "source": "reports/ml2_runs/A/stream_main.npz features (35, causal)"}
    return out

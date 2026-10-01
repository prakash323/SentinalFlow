"""Serving-parity audit (requirement 1). Machine-readable report: reports/ml4_parity_report.json.

Each VARIANT is a transformation of the events exactly as the platform / api.py would present them, applied to the LIVE portion of the stream only
(the api warms the extractor with the sample events in the TRAINING representation, then scores live events). No variant is compensated for.
Effects are measured on the legacy dataset (orig42, the one the shipped model was built on) and the dev-only dataset P0-103 (labels not sealed):
  * features: which of the 35 change, by how much;
  * scores: mean |change|, rank correlation with the canonical run;
  * detection: PR-AUC, and precision / recall / alert rate / per-attack detection at each model's own as-designed threshold.
Models: shipped (models/pipeline.joblib as deployed: EWMA adaptive, production threshold) and the ML-3 candidate (frozen). Nothing here calls /predict.

Contract mismatches audited (read from api.py):
  P1  entity_type forced to 'user'                                 (api._canonical_event)
  P2  sessionDurationMinutes read into the SECONDS field           (api._canonical_event)
  P3  commands: platform separator is a space, extractor splits on '|'
  P4  timestamps converted to UTC (api._to_naive_timestamp) while training/warm-up data are naive local time
  P5  missing optional fields default silently (geo '', fingerprint '', auth_success 1, auth_method 'password')
  P6  unseen entity namespace: platform entity ids are not in the profiler / warm-up
  P7  at-least-once delivery: duplicate events update state twice (the scorer is stateful and not idempotent)
  P8  out-of-order delivery: the extractor assumes strict time order
  (P9 hard-coded vocabularies - SENSITIVE resources, privileged commands - is quantified in the cross-profile evaluation, not here.)
"""
from __future__ import annotations

import copy
import time

import numpy as np
import pandas as pd
from scipy.stats import spearmanr

from . import common as K
from . import features4 as F4
from . import xfer as X
from .common import ATTACKS, C
from eval_ml2 import metrics as M2
from eval_ml3 import evaluate as EV
from src.baseline import BaselineProfiler
from src.features import FEATURE_NAMES, StreamingFeatureExtractor

SHIFT = pd.Timedelta(hours=-5.5)          # IST wall-clock -> UTC

VARIANTS = {
    "V0_canonical": "training representation (control)",
    "V1_entity_type_forced_user": "P1 entity_type := 'user' for every live event",
    "V2_duration_minutes_as_seconds": "P2 session duration delivered in minutes into the seconds field (seconds / 60)",
    "V3_command_space_separated": "P3 command separator '|' -> ' '",
    "V4a_utc_timestamps_live_only": "P4 live timestamps shifted -5.5 h (UTC) while warm-up stays naive local (api behaviour)",
    "V4b_utc_all_consistent": "P4 hour-of-day semantics only: EVERY timestamp shifted -5.5 h (state and live consistent)",
    "V5a_missing_geo": "P5 geo_location empty",
    "V5b_missing_fingerprint": "P5 device_fingerprint empty",
    "V5c_auth_defaults": "P5 auth_success := 1 and auth_method := 'password'",
    "V6_unseen_entity_namespace": "P6 live entity ids not known to profiler / warm-up",
    "V7_duplicate_delivery_2pct": "P7 2% of live events delivered twice (immediately)",
    "V8_out_of_order_5pct": "P8 5% of live events swapped with their successor in delivery order",
    "V9_api_contract_definite": "P1+P2+P3+P4a combined (the mismatches that are certain for every event)",
    "V10_fresh_platform": "V9 + P6 unseen entity namespace (a new platform deployment)",
}
FULL_SET = list(VARIANTS)
KEY_SET = ["V0_canonical", "V1_entity_type_forced_user", "V2_duration_minutes_as_seconds", "V3_command_space_separated", "V4a_utc_timestamps_live_only",
           "V9_api_contract_definite", "V10_fresh_platform"]
DATASETS = {"orig42": FULL_SET, "P0-103": ["V0_canonical", "V1_entity_type_forced_user", "V2_duration_minutes_as_seconds", "V9_api_contract_definite"]}
_SNAP: dict = {}


def transform(ev_live: pd.DataFrame, variant: str, seed: int) -> pd.DataFrame:
    d = ev_live.copy()
    if variant in ("V1_entity_type_forced_user", "V9_api_contract_definite", "V10_fresh_platform"):
        d["entity_type"] = "user"
    if variant in ("V2_duration_minutes_as_seconds", "V9_api_contract_definite", "V10_fresh_platform"):
        d["session_duration"] = d["session_duration"] / 60.0
    if variant in ("V3_command_space_separated", "V9_api_contract_definite", "V10_fresh_platform"):
        d["command_sequence"] = d["command_sequence"].fillna("").str.replace("|", " ", regex=False)
    if variant in ("V4a_utc_timestamps_live_only", "V9_api_contract_definite", "V10_fresh_platform"):
        d["timestamp"] = d["timestamp"] + SHIFT
    if variant == "V5a_missing_geo":
        d["geo_location"] = ""
    if variant == "V5b_missing_fingerprint":
        d["device_fingerprint"] = ""
    if variant == "V5c_auth_defaults":
        d["auth_success"] = 1
        d["auth_method"] = "password"
    if variant in ("V6_unseen_entity_namespace", "V10_fresh_platform"):
        d["entity_id"] = d["entity_id"] + "#live"
    rng = np.random.default_rng([K.ML4_SEED, 9, seed])
    if variant == "V7_duplicate_delivery_2pct":
        dup = np.where(rng.random(len(d)) < 0.02)[0]
        parts, last = [], 0
        for i in dup:
            parts.append(d.iloc[last:i + 1])
            parts.append(d.iloc[i:i + 1])
            last = i + 1
        parts.append(d.iloc[last:])
        d = pd.concat(parts, ignore_index=True)
    if variant == "V8_out_of_order_5pct":
        idx = np.arange(len(d))
        for i in np.where(rng.random(len(d) - 1) < 0.05)[0]:
            idx[i], idx[i + 1] = idx[i + 1], idx[i]
        d = d.iloc[idx].reset_index(drop=True)
    return d


class Mem:
    """Duck-typed stand-in for features4.Loaded built in memory."""

    def __init__(self, X_all: pd.DataFrame, n_onb: int):
        self.X, self.n_onb, self.n = X_all, n_onb, len(X_all)

    @property
    def X_onb(self):
        return self.X.iloc[: self.n_onb].reset_index(drop=True)

    @property
    def X_eval(self):
        return self.X.iloc[self.n_onb:].reset_index(drop=True)


def _rows(ex, recs, ev):
    feats = [ex.update_and_extract(e) for e in recs]
    X = pd.DataFrame(feats, columns=FEATURE_NAMES)
    X.insert(0, "event_id", ev["event_id"].to_numpy())
    X.insert(1, "entity_id", ev["entity_id"].to_numpy())
    X.insert(2, "entity_type", ev["entity_type"].to_numpy())
    X.insert(3, "timestamp", ev["timestamp"].to_numpy())
    return X


def _snapshot(did):
    if did in _SNAP:
        return _SNAP[did]
    ev = F4.load_events4(did)
    n_onb = int((ev["timestamp"] < F4.onboarding_end(did, ev)).sum())
    ex = StreamingFeatureExtractor()
    X_onb = _rows(ex, ev.iloc[:n_onb].to_dict("records"), ev.iloc[:n_onb])
    _SNAP[did] = {"ev": ev, "n_onb": n_onb, "ex": ex, "X_onb": X_onb}
    return _SNAP[did]


def _score_models(did, variant, Xall, n_onb, event_ids_eval, models):
    L = Mem(Xall, n_onb)
    out = {}
    if "shipped" in models:
        art = models["shipped"]
        sig = X.signals("shipped", art, L)
        thr = float(art["threshold"])
        rep = X.replay_modes("shipped", art, L, sig, None, None, None, thr_shipped=thr, modes=("adaptive",))["adaptive"]
        out["shipped"] = {"fused": rep["fused"], "score": rep["risk"], "threshold": thr, "kind": "risk"}
    if "ml3" in models:
        m3, cfg3 = models["ml3"]
        sig = X.signals("ml3", m3, L)
        w = cfg3["fusion_weights"]
        calib = np.linspace(0, 1, 1001)
        rep = X.replay_modes("ml3", m3, L, sig, w, cfg3["baseline"]["guard_fused_max"], calib, modes=("frozen",))["frozen"]
        out["ml3"] = {"fused": rep["fused"], "score": rep["fused"], "threshold": float(cfg3["thresholds"]["primary_fused"]), "kind": "fused"}
    return out


def run_task(did: str, variant: str, seed: int = 1) -> dict:
    """One (dataset, variant): features (whole stream), both models, every metric. Runs inside a worker process."""
    import torch
    torch.set_num_threads(1)
    t = time.time()
    snap = _snapshot(did)
    ev, n_onb = snap["ev"], snap["n_onb"]
    live = transform(ev.iloc[n_onb:].reset_index(drop=True), variant, seed)
    if variant == "V4b_utc_all_consistent":
        ev2 = ev.copy()
        ev2["timestamp"] = ev2["timestamp"] + SHIFT
        ex = StreamingFeatureExtractor()
        X_onb = _rows(ex, ev2.iloc[:n_onb].to_dict("records"), ev2.iloc[:n_onb])
        X_live = _rows(ex, ev2.iloc[n_onb:].to_dict("records"), ev2.iloc[n_onb:])
        live = ev2.iloc[n_onb:].reset_index(drop=True)
    else:
        ex = copy.deepcopy(snap["ex"])
        X_onb = snap["X_onb"]
        X_live = _rows(ex, live.to_dict("records"), live)
    Xall = pd.concat([X_onb, X_live], ignore_index=True)
    from eval_ml3 import candidate as _cd                                     # noqa: F401
    art = K.K3.load_artifact()
    m3, cfg3 = X.load_ml3()
    sc = _score_models(did, variant, Xall, n_onb, live["event_id"].to_numpy(), {"shipped": art, "ml3": (m3, cfg3)})
    first = ~pd.Series(live["event_id"].to_numpy()).duplicated().to_numpy()             # drop duplicate deliveries (keep the original)
    eid = live["event_id"].to_numpy()[first]
    res = {"dataset": did, "variant": variant, "description": VARIANTS[variant], "live_events_delivered": int(len(live)), "live_events_original": int(first.sum()),
           "seconds": round(time.time() - t, 1), "features": Xall.iloc[n_onb:][FEATURE_NAMES].to_numpy()[first], "event_id": eid, "models": {}}
    for k, v in sc.items():
        res["models"][k] = {"fused": v["fused"][first], "score": v["score"][first], "threshold": v["threshold"], "kind": v["kind"]}
    return res


def summarise(did, results: dict, lab: pd.DataFrame, incidents: list) -> dict:
    """results: variant -> run_task output. Compares each variant with V0 on identical events; needs dev labels (legacy / P0-103 are not sealed)."""
    base = results["V0_canonical"]
    order0 = np.argsort(base["event_id"], kind="stable")
    out = {"dataset": did, "variants": {}}
    for v, r in results.items():
        o = np.argsort(r["event_id"], kind="stable")
        ids = r["event_id"][o]
        assert np.array_equal(ids, base["event_id"][order0]), "variant events do not align with the canonical run"
        Fv, F0 = r["features"][o], base["features"][order0]
        dF = np.abs(Fv - F0)
        feat = {n: {"mean_abs_change": float(dF[:, i].mean()), "share_events_changed": float((dF[:, i] > 1e-9).mean())} for i, n in enumerate(FEATURE_NAMES)}
        L = lab.loc[ids]
        labels = L["label"].to_numpy(dtype=object)
        aid = L["attack_id"].to_numpy(dtype=object)
        y = EV.is_attack(labels).astype(int)
        row = {"description": r["description"], "events": int(len(ids)), "delivered": r["live_events_delivered"], "features_changed": sum(1 for n in feat if feat[n]["share_events_changed"] > 0),
               "top_changed_features": [{"feature": n, **feat[n]} for n in sorted(feat, key=lambda n: -feat[n]["share_events_changed"] * (1 + feat[n]["mean_abs_change"]))[:6]],
               "mean_abs_feature_change_all": float(dF.mean()), "models": {}}
        for mk, mv in r["models"].items():
            s = mv["score"][o]
            s0 = base["models"][mk]["score"][order0]
            f = mv["fused"][o]
            thr = mv["threshold"]
            alert = s >= thr
            alert0 = s0 >= thr
            op = M2.operating_point(y, alert)
            op0 = M2.operating_point(y, alert0)
            per = {}
            for t in ATTACKS:
                m = labels == t
                if m.any():
                    ids_t = sorted(set(aid[m]) - {""})
                    per[t] = {"events": int(m.sum()), "event_detection_rate": float(alert[m].mean()), "canonical_event_detection_rate": float(alert0[m].mean()),
                              "incidents": len(ids_t), "incidents_detected": int(sum(alert[aid == i].any() for i in ids_t)),
                              "canonical_incidents_detected": int(sum(alert0[aid == i].any() for i in ids_t))}
            rho = spearmanr(f, base["models"][mk]["fused"][order0]).correlation
            row["models"][mk] = {"score_kind": mv["kind"], "threshold": thr, "mean_abs_score_change": float(np.abs(s - s0).mean()), "max_abs_score_change": float(np.abs(s - s0).max()),
                                 "spearman_vs_canonical": float(rho), "pr_auc": M2.rank_metrics(y, f)["pr_auc"], "roc_auc": M2.rank_metrics(y, f)["roc_auc"],
                                 "canonical_pr_auc": M2.rank_metrics(y, base["models"][mk]["fused"][order0])["pr_auc"],
                                 "alert_rate": op["alert_rate"], "canonical_alert_rate": op0["alert_rate"], "precision": op["precision"], "recall": op["recall"],
                                 "canonical_recall": op0["recall"], "false_positive_rate": op["false_positive_rate"], "canonical_false_positive_rate": op0["false_positive_rate"],
                                 "f1": op["f1"], "incidents_detected": sum(v_["incidents_detected"] for v_ in per.values()),
                                 "canonical_incidents_detected": sum(v_["canonical_incidents_detected"] for v_ in per.values()),
                                 "incidents": sum(v_["incidents"] for v_ in per.values()), "per_attack": per,
                                 "mean_score_on_normal_events": float(s[labels == "normal"].mean()), "canonical_mean_score_on_normal_events": float(s0[labels == "normal"].mean())}
        out["variants"][v] = row
    return out

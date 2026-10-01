"""Cross-dataset training and evaluation.

Models compared on every evaluated dataset (all evaluated the same way: the target dataset's own attack-free onboarding fits ITS per-entity
baseline profiler; the model's GLOBAL components - scaler, Isolation Forest, GRU autoencoder, score distributions - come from elsewhere):
  ml4        global components fitted on the pooled onboarding periods of the TRAIN datasets (P0-101, P0-102, P1-201); fusion weights selected on
             the VAL datasets (P2-301, P3-401, different profiles from TRAIN)
  ml4_local  the same recipe fitted on the dataset's OWN onboarding only (the no-transfer reference; sealed standard datasets only)
  ml3        the ML-3 candidate (fitted on the legacy dataset's days 0-20), frozen config
  shipped    models/pipeline.joblib components (legacy dataset), production weights/threshold
Every model is scored with a frozen baseline and with the adaptive EWMA baseline (production alpha and poisoning guard): the choice is not made
in advance. Nothing here calibrates probabilities or selects a production threshold.
"""
from __future__ import annotations

import copy
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from . import common as K
from . import features4 as F4
from .common import ATTACKS, C
from eval_ml3 import candidate as CD
from eval_ml3 import evaluate as EV
from eval_ml2 import metrics as M2
from src.baseline import BaselineProfiler
from src.detect import SequenceAutoencoder, build_sequences
from src.features import FEATURE_NAMES


# ----------------------------------------------------------------------------------------------------------- label vault (per dataset)
class Vault:
    """Dev labels are readable for TRAIN/VAL/DEV datasets. A SEALED dataset's labels and incident registry are unreadable until unseal(), once."""

    def __init__(self, data_dir=None):
        self.data_dir = data_dir
        self.unsealed: set = set()
        self.log: list = []

    def _role(self, did):
        return "DEV" if did == K.LEGACY_ID else K.REGISTRY[did][2]

    def labels(self, did, purpose="dev") -> pd.DataFrame:
        role = self._role(did)
        if role == "SEALED" and did not in self.unsealed:
            raise PermissionError(f"labels of sealed dataset {did} requested before unseal ({purpose})")
        self.log.append({"access": "labels", "dataset": did, "role": role, "purpose": purpose})
        lab = pd.read_csv(F4.data_paths(did, self.data_dir)["labels"])
        lab["attack_id"] = lab["attack_id"].fillna("")
        return lab.set_index("event_id")

    def incidents(self, did, purpose="dev") -> list:
        role = self._role(did)
        if role == "SEALED" and did not in self.unsealed:
            raise PermissionError(f"incident registry of sealed dataset {did} requested before unseal ({purpose})")
        p = F4.data_paths(did, self.data_dir)["incidents"]
        return json.load(open(p, encoding="utf-8")) if p else []

    def unseal(self, did, purpose):
        if did in self.unsealed:
            raise RuntimeError(f"{did} already unsealed once")
        assert self._role(did) == "SEALED", did
        self.unsealed.add(did)
        self.log.append({"access": "unseal", "dataset": did, "purpose": purpose})


# ----------------------------------------------------------------------------------------------------------- adaptive baseline variants
class AlphaProfiler(BaselineProfiler):
    """BaselineProfiler with a configurable EWMA alpha (identical update rule to production; production reads config.EWMA_ALPHA)."""
    alpha = C.EWMA_ALPHA

    def update(self, feat, eid, risk, threshold):
        from src.baseline import CONTINUOUS
        if not self.use_drift:
            return
        if self.poison_guard and risk >= threshold:
            return
        x = np.array([feat[f] for f in CONTINUOUS], dtype=float)
        a = self.alpha
        if eid not in self.mu:
            self.mu[eid] = x.copy()
            self.var[eid] = np.ones_like(x)
            self.n[eid] = 1
            return
        d = x - self.mu[eid]
        self.mu[eid] = self.mu[eid] + a * d
        self.var[eid] = (1 - a) * (self.var[eid] + a * d * d) + 1e-6
        self.n[eid] = self.n.get(eid, 0) + 1


# ----------------------------------------------------------------------------------------------------------- global fit
def fit_global(ids, feat_dir, log=print, tag="ml4"):
    import torch
    torch.set_num_threads(1)
    t = time.time()
    parts, bs, keeps = [], [], []
    for did in ids:
        L = F4.Loaded(did, feat_dir)
        Xo = L.X_onb
        prof = BaselineProfiler().fit(Xo)
        b = prof.score_frame(Xo)[0]
        parts.append(Xo)
        bs.append(b)
        keeps.append(b <= np.quantile(b, 0.90))            # cleanest 90% by the dataset's own baseline score (as shipped)
    pooled = pd.concat(parts, ignore_index=True)
    b_all, keep = np.concatenate(bs), np.concatenate(keeps)
    fs = CD.select_features(pooled)
    feats = fs["model_features"]
    m = CD.Candidate(feats)
    F = pooled[feats].to_numpy(dtype=float)
    m.scaler = StandardScaler().fit(F)
    m.iforest = IsolationForest(n_estimators=200, contamination=0.02, random_state=C.RANDOM_SEED, n_jobs=1).fit(m.scaler.transform(F))
    S = CD.build_sequences_cols(pooled, feats)            # entity ids are unique per dataset, windows never cross datasets
    m.seq_ae = SequenceAutoencoder(verbose=False).fit(S[keep])
    iso, seq = CD.iso_seq(m, pooled, S)
    m.sig_calib = {"baseline": np.sort(b_all), "iforest": np.sort(iso), "sequence": np.sort(seq)}
    m.train_rows = len(pooled)
    m.fit_info = {"tag": tag, "datasets": list(ids), "rows": int(len(pooled)), "ae_windows_available": int(keep.sum()),
                  "ae_windows_used": int(min(keep.sum(), C.SEQ_FIT_SAMPLE)), "feature_policy": fs, "seconds": round(time.time() - t, 1),
                  "train_windows_padded_share": float(np.mean(CD._padded(pooled)))}
    m._pooled_raw = {"baseline": b_all, "iforest": iso, "sequence": seq}      # in-sample TRAIN raw scores (for the fused calibration curve)
    log(f"[fit:{tag}] {len(ids)} dataset(s), {len(pooled):,} onboarding rows, {len(feats)} features ({m.fit_info['seconds']}s)")
    return m


def content_hashes4(m) -> dict:
    out = {"scaler": CD._h(m.scaler.mean_, m.scaler.scale_)}
    tr = []
    for est in m.iforest.estimators_:
        t = est.tree_
        tr += [t.children_left, t.children_right, t.feature, t.threshold, t.value]
    import numpy as _np
    out["isolation_forest"] = CD._h(*tr, _np.array([m.iforest.offset_]), _np.concatenate([f.astype(_np.int64) for f in m.iforest.estimators_features_]))
    sd = m.seq_ae.model.state_dict()
    out["sequence_ae_weights"] = CD._h(*[sd[k].detach().cpu().numpy() for k in sorted(sd)])
    out["sequence_ae_input_scaler"] = CD._h(m.seq_ae.scaler.mean_, m.seq_ae.scaler.scale_)
    out["train_score_distributions"] = CD._h(*[m.sig_calib[k] for k in K.K3.SIGNALS])
    import hashlib
    out["feature_list"] = hashlib.sha256("|".join(m.features).encode()).hexdigest()
    out["combined"] = hashlib.sha256("|".join(f"{k}={v}" for k, v in sorted(out.items())).encode()).hexdigest()
    return out


def load_ml3():
    """The ML-3 candidate (frozen config). Its TRAIN fused distribution was not stored row-aligned, so only fused scores are evaluated for it."""
    comp = joblib.load(K.CANDIDATE_DIR.parent / "ml3" / "components.joblib")
    cfg = json.load(open(K.CANDIDATE_DIR.parent / "ml3" / "candidate_config.json", encoding="utf-8"))
    m = CD.Candidate(comp["features"])
    m.scaler, m.iforest, m.seq_ae, m.sig_calib = comp["scaler"], comp["iforest"], comp["seq_ae"], comp["sig_calib"]
    return m, cfg


# ----------------------------------------------------------------------------------------------------------- scoring one dataset with one model
def signals(model_key, model, L, extra=None):
    """Label-free raw signals for the evaluation rows of L. Baseline is frozen here; adaptive replays happen in replay_modes()."""
    if model_key == "shipped":
        det = model["detector"]
        S = build_sequences(L.X)[L.n_onb:]
        iso = -det.iforest.score_samples(det.scaler.transform(L.X_eval[FEATURE_NAMES].to_numpy(dtype=float)))
        seq, _ = det.seq_ae.score(S)
    else:
        feats = model.features
        S = CD.build_sequences_cols(L.X, feats)[L.n_onb:]
        iso, seq = CD.iso_seq(model, L.X_eval, S)
    prof = BaselineProfiler().fit(L.X_onb)
    b = prof.score_frame(L.X_eval)[0]
    return {"b_frozen": np.asarray(b, float), "iso": np.asarray(iso, float), "seq": np.asarray(seq, float)}


def replay_modes(model_key, model, L, sig, weights, fused_max, calib_fused, thr_shipped=None, alpha=None, noguard=False, modes=("frozen", "adaptive")):
    """Frozen and adaptive fused/risk arrays for the evaluation rows of L. `fused_max` is the GUARD LEVEL of the adaptive baseline: an event with fused >= level
    never updates the profile (ML-4: the model's own alert threshold; inf = no guard). Production alpha unless `alpha` is given."""
    Xe = L.X_eval
    out = {}
    if model_key == "shipped":
        det = model["detector"]
        raw = {"baseline": sig["b_frozen"], "iforest": sig["iso"], "sequence": sig["seq"]}
        if "frozen" in modes:
            fz = CD.fuse(det.sig_calib, raw, C.FUSION_WEIGHTS)
            out["frozen"] = {"b": sig["b_frozen"], "fused": fz, "risk": CD.risk_event_level(det.calib, fz)}
        if "adaptive" in modes:
            prof = BaselineProfiler().fit(L.X_onb)
            recs = Xe.to_dict("records")
            n = len(recs)
            b, fu, rk = np.empty(n), np.empty(n), np.empty(n)
            for i, r in enumerate(recs):
                s = prof.score_row(r, r["entity_id"], r["entity_type"])[0]
                f = det.fuse_single({"baseline": s, "iforest": float(sig["iso"][i]), "sequence": float(sig["seq"][i])})
                risk = float(det.to_risk_100(np.array([f]))[0])
                prof.update(r, r["entity_id"], risk, thr_shipped)
                b[i], fu[i], rk[i] = s, f, risk
            out["adaptive"] = {"b": b, "fused": fu, "risk": rk}
        return out
    if "frozen" in modes:
        prof = BaselineProfiler().fit(L.X_onb)
        b, fu, _ = CD.replay(prof, Xe, sig["iso"], sig["seq"], model.sig_calib, weights, np.inf, False)
        out["frozen"] = {"b": b, "fused": fu, "risk": CD.risk_event_level(calib_fused, fu)}
    if "adaptive" in modes:
        prof = AlphaProfiler().fit(L.X_onb)
        if alpha is not None:
            prof.alpha = alpha
        b, fu, g = CD.replay(prof, Xe, sig["iso"], sig["seq"], model.sig_calib, weights, np.inf if noguard else fused_max, True)
        out["adaptive"] = {"b": b, "fused": fu, "risk": CD.risk_event_level(calib_fused, fu), "guarded": g}
    return out


def calib_fused_for(model, weights, pooled_raw=None):
    """Sorted TRAIN fused scores under `weights` (the calibration curve for the risk mapping) and their maximum (guard level)."""
    raw = pooled_raw or getattr(model, "_pooled_raw", None)
    f = CD.fuse(model.sig_calib, raw, weights)
    s = np.sort(f)
    return s, float(s[-1])


# ----------------------------------------------------------------------------------------------------------- selection
def select_fusion(val_items, model):
    """val_items: list of (signals, labels). Criterion: mean over VAL datasets of the macro per-attack-type PR-AUC (frozen baseline)."""
    grid = CD.simplex_grid(K.FUSION_GRID_STEP)
    P = []
    for sig, lab in val_items:
        P.append({k: CD.pct(model.sig_calib, k, v) for k, v in (("baseline", sig["b_frozen"]), ("iforest", sig["iso"]), ("sequence", sig["seq"]))})
    rows = []

    def score(w):
        per = []
        for (sig, lab), p in zip(val_items, P):
            f = w[0] * p["baseline"] + w[1] * p["iforest"] + w[2] * p["sequence"]
            per.append(EV.macro_type_prauc(lab, f)["macro_pr_auc"])
        return float(np.mean(per)), per
    for w in grid:
        m, per = score(w)
        rows.append({"w": {"baseline": w[0], "iforest": w[1], "sequence": w[2]}, "mean_macro_pr_auc": m, "per_dataset": per})
    eq_m, eq_per = score((1 / 3, 1 / 3, 1 / 3))
    eq = {"w": {"baseline": 1 / 3, "iforest": 1 / 3, "sequence": 1 / 3}, "mean_macro_pr_auc": eq_m, "per_dataset": eq_per}
    best = max(rows, key=lambda r: r["mean_macro_pr_auc"])
    pars = best["mean_macro_pr_auc"] - eq["mean_macro_pr_auc"] <= K.FUSION_PARSIMONY_MARGIN
    chosen = eq if pars else best
    shipped = next(r for r in rows if all(abs(r["w"][k] - C.FUSION_WEIGHTS[k]) < 1e-9 for k in K.K3.SIGNALS))
    return {"criterion": "mean over VAL datasets of macro per-attack-type PR-AUC of the fused score, frozen baseline", "best_on_grid": best, "equal_weights": eq,
            "shipped_weights_reference": shipped, "parsimony_applied": bool(pars), "selected_weights": chosen["w"], "selected": chosen, "grid": rows}


# ----------------------------------------------------------------------------------------------------------- per-dataset evaluation
def incident_table(incidents, lab, aid, fused, alert, ts_ns) -> list:
    aid = np.asarray(aid, dtype=object)
    neg = np.isin(np.asarray(lab, dtype=object), ("normal", "benign_drift"))
    neg_sorted = np.sort(fused[neg])
    rows = []
    for inc in incidents:
        m = aid == inc["attack_id"]
        if not m.any():
            continue
        idx = np.where(m)[0]
        a = alert[idx]
        first_alert = idx[a][0] if a.any() else None
        row = {k: inc.get(k) for k in ("attack_id", "type", "variant", "src", "src2", "city", "new_ip", "hops", "n_entities", "period", "span_days", "res", "cmd", "foreign", "ip")}
        row.update({"n_events": int(m.sum()), "alerted_events": int(a.sum()), "detected": bool(a.any()), "max_fused": float(fused[idx].max()),
                    "max_fused_percentile_vs_negatives": float(np.searchsorted(neg_sorted, fused[idx].max(), side="right") / max(len(neg_sorted), 1)),
                    "events_before_first_alert": int(np.where(a)[0][0]) if a.any() else None,
                    "minutes_to_first_alert": float((ts_ns[first_alert] - ts_ns[idx[0]]) / 6e10) if first_alert is not None else None})
        rows.append(row)
    return rows


def operating_thresholds(kind_map: dict, fused, own_budget=True) -> dict:
    th = dict(kind_map)
    if own_budget:
        th["own_alert_budget_1pct_label_free"] = ("fused", float(np.quantile(fused, 1 - K.TOPK_FRAC)))
    return th


def eval_arrays(name, lab, aid, arr, thresholds, incidents, ts_ns) -> dict:
    """Metrics of one (dataset, model, mode). `arr` = dict(b, fused, risk)."""
    fused, risk = arr["fused"], arr["risk"]
    th = operating_thresholds(thresholds, fused)
    ev = EV.evaluate_population(name, lab, aid, fused, risk, th)
    first = list(th)[0]
    alert = fused >= th[first][1] if th[first][0] == "fused" else risk >= th[first][1]
    ev["incident_table_at_first_threshold"] = {"threshold_name": first, "rows": incident_table(incidents, lab, aid, fused, alert, ts_ns)}
    ev["signal_ablation_baseline_only_pr_auc"] = M2.rank_metrics(EV.is_attack(lab).astype(int), arr["b"])["pr_auc"]
    return ev

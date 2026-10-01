"""The ML-3 candidate: the SAME components as the shipped model (per-entity baseline profiler, Isolation Forest, GRU sequence
autoencoder, weighted fusion), fitted on TRAIN only, on an explicit feature list, with every choice recorded.

Nothing here modifies src/. Production classes are used as-is (BaselineProfiler, SequenceAutoencoder); the only new code
is (a) an explicit feature list for the IF / AE (the production Detector hard-codes all 35 names), (b) causal replay of the
baseline so it can be evaluated event by event without the 45-60 min per-event StreamingScorer, and (c) hashing.
"""
from __future__ import annotations

import copy
import hashlib
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from . import common as K
from .common import C

from src.baseline import BOOLEAN, CONTINUOUS, BaselineProfiler       # noqa: E402  (production classes, read-only)
from src.detect import SequenceAutoencoder                            # noqa: E402
from src.features import FEATURE_NAMES                                # noqa: E402
from src.utils import psi                                             # noqa: E402


# ----------------------------------------------------------------------------------------------------------- features
def select_features(X_train: pd.DataFrame) -> dict:
    """The candidate feature list for IF / AE / classifier. Determined from TRAIN (label-free) plus the explicit policy."""
    const = [f for f in FEATURE_NAMES if float(np.nanstd(X_train[f].to_numpy(float))) == 0.0]
    policy = list(K.POLICY_EXCLUDED_BY_DEFINITION)
    drop = set(const) | set(policy)
    kept = [f for f in FEATURE_NAMES if f not in drop]
    excluded = [f for f in FEATURE_NAMES if f in drop]
    return {"production_feature_count": len(FEATURE_NAMES), "constant_on_train": const, "policy_excluded": policy,
            "excluded": excluded, "excluded_reasons": {f: ("constant on TRAIN (dead feature)" if f in const else K.POLICY_EXCLUDED_BY_DEFINITION[f])
                                                     for f in excluded},
            "model_features": kept, "model_feature_count": len(kept),
            "baseline_profiler_features": {"continuous": len(CONTINUOUS), "boolean": len(BOOLEAN),
                                           "note": "the production baseline feature lists are unchanged; dead features contribute exactly 0 there"},
            "dead_features_still_inside_baseline_lists": [f for f in const if f in CONTINUOUS or f in BOOLEAN]}


def feature_shift_table(X_train: pd.DataFrame, X_other: pd.DataFrame) -> dict:
    """Per-feature TRAIN vs another dev split: means/stds, share of rows outside the TRAIN [min, max], PSI."""
    out = {}
    for f in FEATURE_NAMES:
        a = X_train[f].to_numpy(float)
        b = X_other[f].to_numpy(float)
        lo, hi = float(np.nanmin(a)), float(np.nanmax(a))
        out[f] = {"train_mean": float(np.nanmean(a)), "train_std": float(np.nanstd(a)), "other_mean": float(np.nanmean(b)),
                  "other_std": float(np.nanstd(b)), "share_outside_train_range": float(np.mean((b < lo) | (b > hi))),
                  "psi": float(psi(a, b)) if np.ptp(a) > 0 else None}
    return out


def build_sequences_cols(X: pd.DataFrame, feats: list[str], seq_len: int = C.SEQ_LEN) -> np.ndarray:
    """Identical logic to src.detect.build_sequences (window = the previous seq_len events of the SAME entity, zero-padded at
    the start of an entity's history, strictly causal), but over an explicit column list."""
    F = X[feats].to_numpy(dtype=np.float32)
    n, d = F.shape
    out = np.zeros((n, seq_len, d), dtype=np.float32)
    idx_by_ent: dict = {}
    for i, eid in enumerate(X["entity_id"].to_numpy()):
        hist = idx_by_ent.setdefault(eid, [])
        hist.append(i)
        w = hist[-seq_len:]
        out[i, seq_len - len(w):, :] = F[w]
    return out


def window_index(ent: np.ndarray, seq_len: int = C.SEQ_LEN) -> np.ndarray:
    """prev[i, j] = row index of the (seq_len-j)-th most recent event of row i's entity, up to and including i; -1 = padding.
    Depends only on the entity sequence, so it lets diagnostics rebuild windows of a modified feature matrix cheaply."""
    n = len(ent)
    prev = np.full((n, seq_len), -1, dtype=np.int64)
    hist: dict = {}
    for i, e in enumerate(ent):
        h = hist.setdefault(e, [])
        h.append(i)
        w = h[-seq_len:]
        prev[i, seq_len - len(w):] = w
    return prev


def windows_from(F32: np.ndarray, prev: np.ndarray, rows) -> np.ndarray:
    P = prev[rows]
    W = F32[np.where(P >= 0, P, 0)]
    W[P < 0] = 0.0
    return W


# ----------------------------------------------------------------------------------------------------------- fitting
class Candidate:
    """Fitted-on-TRAIN components. Fusion weights / threshold are NOT part of the fit (they are selected on VALIDATION and frozen)."""

    def __init__(self, features: list[str]):
        self.features = list(features)
        self.profiler: BaselineProfiler | None = None
        self.scaler: StandardScaler | None = None
        self.iforest: IsolationForest | None = None
        self.seq_ae: SequenceAutoencoder | None = None
        self.sig_calib: dict = {}            # sorted TRAIN raw values per signal (score-transformation distribution)
        self.train_rows = 0
        self.fit_info: dict = {}


def fit(X_train: pd.DataFrame, feats: list[str], log=print) -> Candidate:
    import torch
    torch.set_num_threads(1)
    t = time.time()
    m = Candidate(feats)
    m.train_rows = len(X_train)
    m.profiler = BaselineProfiler().fit(X_train)                              # production class, production defaults
    b_tr = m.profiler.score_frame(X_train)[0]                                 # in-sample, exactly like the shipped fit
    log(f"[fit] baseline profiler on {len(X_train)} TRAIN rows, {len(m.profiler.mu)} entities ({time.time()-t:.0f}s)")

    F = X_train[feats].to_numpy(dtype=float)
    m.scaler = StandardScaler().fit(F)
    m.iforest = IsolationForest(n_estimators=200, contamination=0.02, random_state=C.RANDOM_SEED, n_jobs=1).fit(m.scaler.transform(F))
    log(f"[fit] IsolationForest ({time.time()-t:.0f}s)")

    S = build_sequences_cols(X_train, feats)                                  # TRAIN rows only: no later event can enter a window
    keep = b_tr <= np.quantile(b_tr, 0.90)                                    # cleanest 90% by TRAIN baseline score (as shipped)
    m.seq_ae = SequenceAutoencoder(verbose=True).fit(S[keep])
    log(f"[fit] sequence AE (GRU, backend={m.seq_ae.backend}) fitted on {int(keep.sum())} windows "
        f"(cap {C.SEQ_FIT_SAMPLE}) ({time.time()-t:.0f}s)")

    iso_tr, seq_tr = iso_seq(m, X_train, S)
    m.sig_calib = {"baseline": np.sort(np.asarray(b_tr, float)), "iforest": np.sort(iso_tr), "sequence": np.sort(seq_tr)}
    m.fit_info = {"n_train": len(X_train), "n_ae_windows_available": int(keep.sum()),
                  "n_ae_windows_used": int(min(keep.sum(), C.SEQ_FIT_SAMPLE)), "ae_backend": m.seq_ae.backend,
                  "n_entities_profiled": len(m.profiler.mu), "fit_seconds": time.time() - t,
                  "train_windows_padded_share": float(np.mean(_padded(X_train)))}
    return m, b_tr, iso_tr, seq_tr


def _padded(X: pd.DataFrame, seq_len: int = C.SEQ_LEN) -> np.ndarray:
    """True where the entity has fewer than seq_len events so far (its window contains zero left-padding)."""
    pos = X.groupby("entity_id").cumcount().to_numpy()
    return pos < (seq_len - 1)


def iso_seq(m: Candidate, X: pd.DataFrame, S: np.ndarray | None = None):
    F = m.scaler.transform(X[m.features].to_numpy(dtype=float))
    iso = -m.iforest.score_samples(F)                                         # higher = more anomalous
    if S is None:
        S = build_sequences_cols(X, m.features)
    seq, _ = m.seq_ae.score(S)
    return np.asarray(iso, float), np.asarray(seq, float)


# ----------------------------------------------------------------------------------------------------------- fusion
def pct(m_or_calib, key: str, v) -> np.ndarray:
    arr = m_or_calib[key] if isinstance(m_or_calib, dict) else m_or_calib.sig_calib[key]
    return np.searchsorted(arr, np.asarray(v, dtype=float), side="right") / max(len(arr), 1)


def fuse(sig_calib: dict, raw: dict, w: dict) -> np.ndarray:
    return sum(w[k] * pct(sig_calib, k, raw[k]) for k in K.SIGNALS) / sum(w.values())


def risk_event_level(calib_sorted: np.ndarray, fused) -> np.ndarray:
    """Streaming semantics (one event at a time): 99 x TRAIN-fused CDF; an event above the whole TRAIN range is 'saturated' -> 100."""
    fused = np.asarray(fused, dtype=float)
    n = max(len(calib_sorted), 1)
    idx = np.searchsorted(calib_sorted, fused, side="right")
    r = 99.0 * idx / n
    r[idx >= n] = 100.0
    return r


def simplex_grid(step: float = K.FUSION_GRID_STEP):
    n = int(round(1 / step))
    out = []
    for a in range(n + 1):
        for b in range(n + 1 - a):
            out.append((a / n, b / n, (n - a - b) / n))
    return out


# ----------------------------------------------------------------------------------------------------------- causal replay
def replay(prof: BaselineProfiler, X: pd.DataFrame, iso: np.ndarray, seq: np.ndarray, sig_calib: dict, w: dict,
           fused_train_max: float, ewma: bool):
    """Event-by-event, in time order. For every event: score the baseline from the CURRENT profile, fuse with the (already
    computed, label-free) IF/AE signals, and only AFTER the score is recorded may the event update the profile (EWMA mode,
    poisoning guard: an event above the whole TRAIN fused range never updates). A frozen run never calls update()."""
    recs = X.to_dict("records")
    n = len(recs)
    b = np.empty(n)
    fu = np.empty(n)
    guarded = np.zeros(n, dtype=bool)
    ps = pct(sig_calib, "iforest", iso)
    pq = pct(sig_calib, "sequence", seq)
    barr = sig_calib["baseline"]
    nb = max(len(barr), 1)
    wsum = sum(w.values())
    for i, r in enumerate(recs):
        s = prof.score_row(r, r["entity_id"], r["entity_type"])[0]            # score first ...
        b[i] = s
        f = (w["baseline"] * (np.searchsorted(barr, s, side="right") / nb) + w["iforest"] * ps[i] + w["sequence"] * pq[i]) / wsum
        fu[i] = f
        if ewma:
            sat = f >= fused_train_max
            guarded[i] = sat
            prof.update(r, r["entity_id"], K.GUARD_RISK if sat else 0.0, K.GUARD_RISK)   # ... then (maybe) learn from it
    return b, fu, guarded


# ----------------------------------------------------------------------------------------------------------- hashing
def _h(*arrs) -> str:
    s = hashlib.sha256()
    for a in arrs:
        s.update(np.ascontiguousarray(a).tobytes())
    return s.hexdigest()


def content_hashes(m: Candidate) -> dict:
    """Hashes of the LEARNED CONTENT (not pickle bytes, which may vary): what actually determines the model's outputs."""
    out = {}
    p = m.profiler
    parts = []
    for e in sorted(p.mu):
        parts += [p.mu[e], p.var[e], np.array([p.n[e]], dtype=np.int64)]
    for k in sorted(p.peer_mu):
        parts += [p.peer_mu[k], p.peer_var[k]]
    parts += [p.global_mu, p.global_var]
    out["baseline_profiler"] = _h(*parts)
    out["scaler"] = _h(m.scaler.mean_, m.scaler.scale_)
    tr = []
    for est in m.iforest.estimators_:
        t = est.tree_
        tr += [t.children_left, t.children_right, t.feature, t.threshold, t.value]
    out["isolation_forest"] = _h(*tr, np.array([m.iforest.offset_]), np.concatenate([f.astype(np.int64) for f in m.iforest.estimators_features_]))
    sd = m.seq_ae.model.state_dict()
    out["sequence_ae_weights"] = _h(*[sd[k].detach().cpu().numpy() for k in sorted(sd)])
    out["sequence_ae_input_scaler"] = _h(m.seq_ae.scaler.mean_, m.seq_ae.scaler.scale_)
    out["train_score_distributions"] = _h(*[m.sig_calib[k] for k in K.SIGNALS])
    out["feature_list"] = hashlib.sha256("|".join(m.features).encode()).hexdigest()
    out["combined"] = hashlib.sha256("|".join(f"{k}={v}" for k, v in sorted(out.items())).encode()).hexdigest()
    return out


def classifier_hash(clf) -> str:
    return hashlib.sha256(clf.booster_.model_to_string().encode()).hexdigest()

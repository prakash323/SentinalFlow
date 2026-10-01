"""
Detection layer.

Three unsupervised signals, rank-normalised and fused into one calibrated
0-100 risk score:

  1. baseline z-score        (src/baseline.py)  -- interpretable, per-entity
  2. Isolation Forest        -- global structural outliers
  3. sequence autoencoder    -- reconstruction error over the last SEQ_LEN
                                events of the same entity; this is what catches
                                lateral movement and low-and-slow exfiltration

The autoencoder uses PyTorch (GRU) if torch is installed, and otherwise falls
back to an sklearn MLP autoencoder over flattened windows. Both expose the
same interface, so the pipeline is identical either way.
"""
from __future__ import annotations
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

import config as C
from src.features import FEATURE_NAMES
from src.utils import rank_normalise

try:
    import torch
    import torch.nn as nn
    _HAS_TORCH = True
except Exception:
    _HAS_TORCH = False


# ---------------------------------------------------------------------------
# Sequence construction
# ---------------------------------------------------------------------------
def build_sequences(X: pd.DataFrame, seq_len=C.SEQ_LEN):
    """For each event, the window of the previous `seq_len` events of the SAME
    entity (padded at the start). Strictly causal."""
    F = X[FEATURE_NAMES].to_numpy(dtype=np.float32)
    n, d = F.shape
    out = np.zeros((n, seq_len, d), dtype=np.float32)
    idx_by_ent = {}
    for i, eid in enumerate(X["entity_id"].to_numpy()):
        hist = idx_by_ent.setdefault(eid, [])
        hist.append(i)
        w = hist[-seq_len:]
        out[i, seq_len - len(w):, :] = F[w]
    return out


# ---------------------------------------------------------------------------
# Autoencoders
# ---------------------------------------------------------------------------
class _TorchGRUAE(nn.Module if _HAS_TORCH else object):
    def __init__(self, d, hidden=64, seq_len=C.SEQ_LEN):
        super().__init__()
        self.enc = nn.GRU(d, hidden, batch_first=True)
        self.dec = nn.GRU(hidden, hidden, batch_first=True)
        self.out = nn.Linear(hidden, d)
        self.seq_len = seq_len

    def forward(self, x):
        _, h = self.enc(x)
        rep = h[-1].unsqueeze(1).repeat(1, self.seq_len, 1)
        y, _ = self.dec(rep)
        return self.out(y)


class SequenceAutoencoder:
    """Unified wrapper. `.fit(seqs)` then `.score(seqs)` -> per-event error."""

    def __init__(self, seq_len=C.SEQ_LEN, epochs=12, verbose=True):
        self.seq_len = seq_len
        self.epochs = epochs
        self.verbose = verbose
        self.backend = "torch" if _HAS_TORCH else "sklearn"
        self.model = None
        self.scaler = StandardScaler()
        self.d = None

    def _flat(self, S):
        return S.reshape(len(S), -1)

    def fit(self, S: np.ndarray):
        """Fits on a bounded subsample. The flattened window matrix is
        seq_len x d wide, so materialising all of it in float64 is what kills
        a laptop -- everything here stays float32 and chunked."""
        self.d = S.shape[2]
        rng = np.random.default_rng(C.RANDOM_SEED)
        if len(S) > C.SEQ_FIT_SAMPLE:
            S = S[rng.choice(len(S), C.SEQ_FIT_SAMPLE, replace=False)]
        flat = self.scaler.fit_transform(self._flat(S)).astype(np.float32)
        if self.backend == "torch":
            # Every other model in this pipeline is seeded via
            # C.RANDOM_SEED (IsolationForest, PCA, the classifier, the
            # fit-subsample choice two lines up) -- this one wasn't, so
            # weight init AND the DataLoader's shuffle order were free to
            # vary between two runs of otherwise-identical code. That
            # makes any before/after metric comparison across a code
            # change unreliable, since some of the delta is just noise.
            torch.manual_seed(C.RANDOM_SEED)
            g = torch.Generator().manual_seed(C.RANDOM_SEED)
            Sn = flat.reshape(S.shape).astype(np.float32)
            self.model = _TorchGRUAE(self.d, 64, self.seq_len)
            opt = torch.optim.Adam(self.model.parameters(), lr=1e-3)
            lossf = nn.MSELoss()
            t = torch.tensor(Sn)
            ds = torch.utils.data.TensorDataset(t)
            dl = torch.utils.data.DataLoader(ds, batch_size=256, shuffle=True,
                                             generator=g)
            self.model.train()
            for ep in range(self.epochs):
                tot = 0.0
                for (xb,) in dl:
                    opt.zero_grad()
                    loss = lossf(self.model(xb), xb)
                    loss.backward()
                    opt.step()
                    tot += float(loss) * len(xb)
                if self.verbose:
                    print(f"[seq-ae/torch] epoch {ep+1}/{self.epochs} "
                          f"loss={tot/len(ds):.4f}")
        else:
            # PCA reconstruction autoencoder: a linear bottleneck. Far cheaper
            # than an MLP, gives per-feature reconstruction error for free, and
            # is a defensible fallback when torch is unavailable.
            from sklearn.decomposition import PCA
            k = int(min(24, max(4, flat.shape[1] // 12, )))
            k = min(k, min(flat.shape) - 1)
            if self.verbose:
                print(f"[seq-ae/sklearn] PCA autoencoder, bottleneck={k} "
                      f"(install torch for the GRU version)")
            self.model = PCA(n_components=k, random_state=C.RANDOM_SEED).fit(flat)
        return self

    def score(self, S: np.ndarray):
        """Returns (per_event_error, per_feature_error_matrix). Chunked."""
        n = len(S)
        errs = np.zeros(n, dtype=np.float32)
        pf = np.zeros((n, self.d), dtype=np.float32)
        for i in range(0, n, C.SEQ_CHUNK):
            j = min(i + C.SEQ_CHUNK, n)
            e, p = self._score_chunk(S[i:j])
            errs[i:j] = e
            pf[i:j] = p
        return errs, pf

    def _score_chunk(self, S: np.ndarray):
        flat = self.scaler.transform(self._flat(S)).astype(np.float32)
        if self.backend == "torch":
            Sn = flat.reshape(S.shape).astype(np.float32)
            self.model.eval()
            errs = []
            with torch.no_grad():
                for i in range(0, len(Sn), 1024):
                    xb = torch.tensor(Sn[i:i + 1024])
                    rec = self.model(xb).numpy()
                    errs.append((rec - Sn[i:i + 1024]) ** 2)
            E = np.concatenate(errs, axis=0)          # (n, seq, d)
            per_feature = E[:, -1, :]                 # error on the current event
            return E.mean(axis=(1, 2)), per_feature
        rec = self.model.inverse_transform(self.model.transform(flat))
        E = (rec - flat) ** 2
        per_feature = E.reshape(len(S), self.seq_len, self.d)[:, -1, :]
        return E.mean(axis=1), per_feature


# ---------------------------------------------------------------------------
# Full detector
# ---------------------------------------------------------------------------
class Detector:
    def __init__(self, use_sequence=True, verbose=True):
        self.use_sequence = use_sequence
        self.verbose = verbose
        self.scaler = StandardScaler()
        self.iforest = None
        self.seq_ae = None
        self.calib = None            # sorted training risk scores
        self.sig_calib = None        # per-signal training distributions
        self.threshold_ = None
        self.seq_len_ = C.SEQ_LEN

    def fit(self, X_train: pd.DataFrame, baseline_scores_train: np.ndarray):
        F = self.scaler.fit_transform(X_train[FEATURE_NAMES].to_numpy(dtype=float))
        if self.verbose:
            print("[detect] fitting IsolationForest ...")
        self.iforest = IsolationForest(n_estimators=200, contamination=0.02,
                                       random_state=C.RANDOM_SEED, n_jobs=-1).fit(F)
        if self.use_sequence:
            S = build_sequences(X_train)
            # train only on the cleanest 90% by baseline score -> learns "normal"
            keep = baseline_scores_train <= np.quantile(baseline_scores_train, 0.90)
            self.seq_ae = SequenceAutoencoder(verbose=self.verbose).fit(S[keep])
        return self

    def raw_scores(self, X: pd.DataFrame, baseline_scores: np.ndarray):
        F = self.scaler.transform(X[FEATURE_NAMES].to_numpy(dtype=float))
        iso = -self.iforest.score_samples(F)          # higher = more anomalous
        if self.use_sequence and self.seq_ae is not None:
            S = build_sequences(X)
            seq, seq_pf = self.seq_ae.score(S)
        else:
            seq = np.zeros(len(X))
            seq_pf = np.zeros((len(X), len(FEATURE_NAMES)))
        return {"baseline": baseline_scores, "iforest": iso,
                "sequence": seq, "sequence_per_feature": seq_pf}

    def fuse(self, raw: dict) -> np.ndarray:
        """
        Batch fusion: rank-normalise each signal across the scored set, then
        weight-average. The streaming path (fuse_single) instead percentile-maps
        against the stored training distribution, because a single event has no
        batch to rank within. The two agree closely in ordering but not in
        absolute value -- see limitation 8 in ASSUMPTIONS.md.
        """
        w = C.FUSION_WEIGHTS
        parts = [w[k] * rank_normalise(raw[k])
                 for k in ("baseline", "iforest", "sequence")]
        return np.sum(parts, axis=0) / sum(w.values())

    def calibrate(self, fused_train: np.ndarray):
        self.calib = np.sort(fused_train)
        return self

    # -- single-event path (real-time) -----------------------------------
    def fit_calibrators(self, raw_train: dict):
        """Store the training distribution of each raw signal so a single
        event can be percentile-mapped without seeing the rest of the batch.
        This is what lets batch and streaming produce identical scores."""
        self.sig_calib = {k: np.sort(np.asarray(raw_train[k], dtype=float))
                          for k in ("baseline", "iforest", "sequence")}
        return self

    def _pct(self, key: str, v: float) -> float:
        arr = self.sig_calib[key]
        return float(np.searchsorted(arr, v, side="right") / max(len(arr), 1))

    def fuse_single(self, raw_single: dict) -> float:
        w = C.FUSION_WEIGHTS
        return sum(w[k] * self._pct(k, raw_single[k]) for k in w) / sum(w.values())

    def score_single(self, feat_vec: np.ndarray, seq_window: np.ndarray,
                     baseline_score: float):
        """feat_vec: (d,)  seq_window: (seq_len, d)  -> raw signal dict."""
        F = self.scaler.transform(feat_vec.reshape(1, -1))
        iso = float(-self.iforest.score_samples(F)[0])
        if self.use_sequence and self.seq_ae is not None:
            e, pf = self.seq_ae.score(seq_window.reshape(1, self.seq_len_, -1))
            seq, seq_pf = float(e[0]), pf[0]
        else:
            seq, seq_pf = 0.0, np.zeros(len(FEATURE_NAMES))
        return {"baseline": baseline_score, "iforest": iso, "sequence": seq}, seq_pf

    def to_risk_100(self, fused: np.ndarray) -> np.ndarray:
        """
        Percentile rank against the training distribution -> 0..100.

        SATURATION FIX. A plain percentile map assigns exactly 100.0 to every
        test event that is more anomalous than the entire training set --
        which on the bundled sample was 660 events all tied at the ceiling.
        Ties at the ceiling mean the top of the alert queue was ordered
        ARBITRARILY (by row index), so a saturated brute-force burst could
        outrank a far more anomalous device-spoofing event purely by
        appearing earlier in the file. That silently wrecks precision and
        recall at any alert budget, because the budget slices the top of an
        essentially unordered block.

        So: non-saturated events are mapped onto [0, 99] exactly as before
        (same ordering, same relative spacing), and the saturated block is
        spread over (99, 100] by ranking its members against each other on
        the raw fused score. Monotone overall, every saturated event still
        outranks every non-saturated one, and the ceiling is now ordered by
        actual anomaly magnitude instead of file position.
        """
        if self.calib is None:
            return rank_normalise(fused) * 100
        fused = np.asarray(fused, dtype=float)
        n_cal = max(len(self.calib), 1)
        idx = np.searchsorted(self.calib, fused, side="right")
        risk = 99.0 * idx / n_cal
        sat = idx >= n_cal
        if sat.sum() == 1:
            risk[sat] = 100.0
        elif sat.sum() > 1:
            within = fused[sat].argsort().argsort().astype(float)
            risk[sat] = 99.0 + 1.0 * (within + 1) / sat.sum()
        return risk

    def set_threshold(self, risk: np.ndarray, budget=C.ALERT_BUDGET):
        self.threshold_ = float(np.quantile(risk, 1 - budget))
        return self.threshold_

    def threshold_for_budget(self, budget: float) -> float:
        """
        Retarget the alert threshold (in the same 0-100 risk-score space as
        every alert's `risk_score`) to a NEW budget without retraining or
        rescoring anything, by reusing the training-set calibration curve
        already stored in `self.calib` (sorted training fused scores).

        This is what makes the alert budget a runtime parameter instead of a
        constant baked into the trained artifact: batch (`run_pipeline.py
        --budget`) and real-time (`run_realtime.py --budget`) can both point
        at a wider or narrower queue by reading the same calibration data the
        model was already fit with -- no leakage, since it's the identical
        training-window distribution `calibrate()` used originally, just
        queried at a different percentile and passed back through the same
        `to_risk_100` mapping every other score uses.
        """
        if self.calib is None:
            raise RuntimeError("threshold_for_budget requires calibrate() to "
                                "have been called first")
        fused_at_budget = np.quantile(self.calib, 1 - budget)
        return float(self.to_risk_100(np.array([fused_at_budget]))[0])

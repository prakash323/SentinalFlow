"""
Per-entity behavioural baseline.

This is the interpretable backbone of the system. It answers, for every event:
"how far is this from what THIS entity normally does?" -- as a per-feature
z-score vector, which is what makes the explanations human-readable.

Three problem-statement requirements are solved here:

  COLD START   a new entity inherits its peer-group prior and blends toward its
               own history via Bayesian shrinkage  w = n / (n + k).
  CONCEPT DRIFT profiles update continuously via EWMA rather than being frozen.
  BASELINE POISONING  only events scoring BELOW the alert threshold are allowed
               to update the profile, so an attacker cannot slowly teach the
               system to accept them.
"""
from __future__ import annotations
import numpy as np
import pandas as pd

import config as C
from src.features import FEATURE_NAMES
from src.utils import psi

# Features whose deviation is meaningful as a z-score. Booleans are handled
# separately -- a z-score on a 0/1 flag is not interpretable.
CONTINUOUS = [
    "geo_velocity_kmh", "distance_from_home_km",
    "failed_auth_5min_entity", "failed_auth_5min_ip",
    "distinct_entities_per_ip_1h", "ip_failure_rate_1h",
    "resource_novelty_ratio", "peer_resource_deviation",
    "new_resources_24h", "resource_entropy_24h",
    "hour_zscore", "session_duration_zscore", "interevent_gap_zscore",
    "events_last_1h", "events_last_24h",
    "offhours_count_7d", "sensitive_bytes_proxy_7d", "resource_breadth_7d",
    "cmd_len", "cmd_priv_count", "cmd_bigram_surprise",
    "fingerprint_novelty", "sensitive_offhours_7d", "sensitive_ratio_7d",
]
BOOLEAN = [
    "is_new_resource", "is_new_city", "is_off_hours_for_entity",
    "fingerprint_mismatch", "is_new_ip_for_entity", "auth_method_unusual",
    "is_sensitive_resource",
]
# Boolean flags are hard evidence, not gradual deviation. They are weighted to
# be competitive with continuous z-scores, otherwise a single high-volume attack
# (brute force, whose failure counts explode) monopolises the alert budget and
# the rarer patterns never surface.
BOOL_WEIGHT = {
    "fingerprint_mismatch": 10.0, "is_new_city": 4.0, "is_new_resource": 2.5,
    "is_off_hours_for_entity": 2.5, "is_new_ip_for_entity": 2.0,
    "auth_method_unusual": 3.5, "is_sensitive_resource": 1.5,
}
Z_CLIP = 6.0   # cap continuous deviation so no single feature can dominate


class BaselineProfiler:
    def __init__(self, use_peer_prior=True, use_drift=True,
                 poison_guard=C.POISON_GUARD, k=C.COLD_START_K):
        self.use_peer_prior = use_peer_prior
        self.use_drift = use_drift
        self.poison_guard = poison_guard
        self.k = k
        self.mu = {}          # entity_id -> np.array
        self.var = {}
        self.n = {}
        self.peer_mu = {}     # peer key -> np.array
        self.peer_var = {}
        self.global_mu = None
        self.global_var = None
        self._train_dist = {}  # for PSI drift monitoring

    # ------------------------------------------------------------------
    @staticmethod
    def _peer_key(row) -> str:
        return str(row.get("entity_type", "user"))

    def fit(self, X: pd.DataFrame):
        """Fit on the training window only (days 1..TRAIN_DAYS)."""
        F = X[CONTINUOUS].to_numpy(dtype=float)
        self.global_mu = np.nanmean(F, axis=0)
        self.global_var = np.nanvar(F, axis=0) + 1e-6

        for key, grp in X.groupby("entity_type"):
            G = grp[CONTINUOUS].to_numpy(dtype=float)
            self.peer_mu[key] = np.nanmean(G, axis=0)
            self.peer_var[key] = np.nanvar(G, axis=0) + 1e-6

        for eid, grp in X.groupby("entity_id"):
            G = grp[CONTINUOUS].to_numpy(dtype=float)
            self.mu[eid] = np.nanmean(G, axis=0)
            self.var[eid] = np.nanvar(G, axis=0) + 1e-6
            self.n[eid] = len(G)

        for f in CONTINUOUS:
            self._train_dist[f] = X[f].to_numpy(dtype=float)
        return self

    # ------------------------------------------------------------------
    def _effective_profile(self, eid, etype):
        """Shrinkage blend of own history and peer prior."""
        peer_mu = self.peer_mu.get(etype, self.global_mu)
        peer_var = self.peer_var.get(etype, self.global_var)
        if eid not in self.mu:
            return peer_mu, peer_var, 0
        n = self.n.get(eid, 0)
        if not self.use_peer_prior:
            return self.mu[eid], self.var[eid], n
        w = n / (n + self.k)
        mu = w * self.mu[eid] + (1 - w) * peer_mu
        var = w * self.var[eid] + (1 - w) * peer_var
        return mu, var, n

    def score_row(self, feat: dict, eid: str, etype: str):
        """Returns (score, per_feature_contributions, low_confidence)."""
        mu, var, n = self._effective_profile(eid, etype)
        x = np.array([feat[f] for f in CONTINUOUS], dtype=float)
        z = np.abs(x - mu) / np.sqrt(var + 1e-9)
        z = np.clip(np.nan_to_num(z), 0, Z_CLIP)
        contrib = {f: float(v) for f, v in zip(CONTINUOUS, z)}
        for b in BOOLEAN:
            contrib[b] = float(feat.get(b, 0.0)) * BOOL_WEIGHT.get(b, 1.0)
        vals = np.sort(np.array(list(contrib.values())))
        # Blend of the single strongest signal and the top-3 mean. Pure top-3
        # mean buries attacks whose evidence sits in ONE feature (a spoofed
        # fingerprint, an impossible geo-velocity); pure max is too noisy.
        score = float(0.6 * vals[-1] + 0.4 * vals[-3:].mean())
        return score, contrib, n < C.COLD_START_MIN_EVENTS

    def score_frame(self, X: pd.DataFrame):
        scores, contribs, lowconf = [], [], []
        recs = X.to_dict("records")
        for r in recs:
            s, c, lc = self.score_row(r, r["entity_id"], r["entity_type"])
            scores.append(s)
            contribs.append(c)
            lowconf.append(lc)
        return np.array(scores), contribs, np.array(lowconf)

    # ------------------------------------------------------------------
    def update(self, feat: dict, eid: str, risk: float, threshold: float):
        """EWMA online update, with the poisoning guard."""
        if not self.use_drift:
            return
        if self.poison_guard and risk >= threshold:
            return                                     # suspicious -> do not learn
        x = np.array([feat[f] for f in CONTINUOUS], dtype=float)
        a = C.EWMA_ALPHA
        if eid not in self.mu:
            self.mu[eid] = x.copy()
            self.var[eid] = np.ones_like(x)
            self.n[eid] = 1
            return
        d = x - self.mu[eid]
        self.mu[eid] = self.mu[eid] + a * d
        self.var[eid] = (1 - a) * (self.var[eid] + a * d * d) + 1e-6
        self.n[eid] = self.n.get(eid, 0) + 1

    def drift_report(self, X_recent: pd.DataFrame) -> dict:
        """PSI per feature between the training window and a recent window."""
        out = {}
        for f in CONTINUOUS:
            if f in self._train_dist and f in X_recent:
                out[f] = psi(self._train_dist[f], X_recent[f].to_numpy(dtype=float))
        drifted = {k: v for k, v in out.items() if v > C.DRIFT_PSI_THRESHOLD}
        return {"psi": out, "drifted": drifted,
                "drift_detected": len(drifted) > 0}

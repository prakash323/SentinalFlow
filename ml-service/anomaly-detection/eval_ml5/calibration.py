"""Probability calibration of the anomaly score (Phase 5).

Target: P(event is an attack event | fused score) - an EVENT-level probability under the base rate of the data the calibrator was fitted on. It is NOT the probability
that an alert is a true incident in a new deployment (that depends on the deployment's own prevalence, which is unknown; see prior shift in the report).
Methods (pre-registered, K.CALIB_METHODS): identity (the score read as a probability = the uncalibrated reference), Platt scaling, isotonic regression and
equal-frequency histogram binning on the raw score, and the deployment-normalised variants of Platt / isotonic (the score is first re-centred and re-scaled with the
deployment's own attack-free onboarding tail, label-free). The attack-type classifier is NOT calibrated (insufficient class coverage, ML-4) and no NORMAL class is created.
"""
from __future__ import annotations

import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression

from . import common as K
from eval_ml2 import metrics as M2
from eval_ml3 import evaluate as EV

EPS = 1e-6


def logit(p):
    p = np.clip(np.asarray(p, float), EPS, 1 - EPS)
    return np.log(p / (1 - p))


def normalise(fused, tail) -> np.ndarray:
    """Deployment-normalised score: logit(fused) re-centred and re-scaled by the deployment's benign onboarding tail (median / robust scale). Label-free, rank-preserving."""
    lt = logit(tail)
    med = float(np.median(lt))
    mad = float(np.median(np.abs(lt - med))) * 1.4826
    return (logit(fused) - med) / max(mad, 0.1)


class Calibrator:
    def __init__(self, method: str):
        self.method = method
        self.params: dict = {}

    def _x(self, fused, tail):
        return normalise(fused, tail) if self.method.endswith("deployment_normalised") else logit(fused)

    def fit(self, fused_list, tail_list, y_list):
        if self.method == "identity":
            return self
        x = np.concatenate([self._x(f, t) for f, t in zip(fused_list, tail_list)])
        y = np.concatenate(y_list).astype(int)
        if self.method.startswith("platt"):
            m = LogisticRegression(C=1e6, solver="lbfgs", max_iter=2000).fit(x[:, None], y)
            self.params = {"coef": float(m.coef_[0, 0]), "intercept": float(m.intercept_[0])}
        elif self.method.startswith("isotonic"):
            m = IsotonicRegression(y_min=EPS, y_max=1 - EPS, increasing=True, out_of_bounds="clip").fit(x, y)
            self.params = {"x": m.X_thresholds_.tolist(), "y": m.y_thresholds_.tolist()}
        elif self.method.startswith("histogram"):
            edges = np.unique(np.quantile(x, np.linspace(0, 1, K.CALIB_BINS + 2)[1:-1]))
            b = np.searchsorted(edges, x, side="right")
            k = np.bincount(b, weights=y, minlength=len(edges) + 1)
            n = np.bincount(b, minlength=len(edges) + 1)
            self.params = {"edges": edges.tolist(), "rate": ((k + 1.0) / (n + 2.0)).tolist()}
        else:
            raise ValueError(self.method)
        return self

    def predict(self, fused, tail) -> np.ndarray:
        if self.method == "identity":
            return np.clip(np.asarray(fused, float), EPS, 1 - EPS)
        x = self._x(fused, tail)
        if self.method.startswith("platt"):
            return 1.0 / (1.0 + np.exp(-(self.params["coef"] * x + self.params["intercept"])))
        if self.method.startswith("isotonic"):
            return np.clip(np.interp(x, self.params["x"], self.params["y"]), EPS, 1 - EPS)
        rate = np.array(self.params["rate"])
        return rate[np.searchsorted(np.array(self.params["edges"]), x, side="right")]


def ece(p, y, bins=K.CALIB_BINS, equal_frequency=True) -> float:
    p, y = np.asarray(p, float), np.asarray(y, float)
    edges = np.quantile(p, np.linspace(0, 1, bins + 1)) if equal_frequency else np.linspace(0, 1, bins + 1)
    idx = np.clip(np.searchsorted(edges[1:-1], p, side="right"), 0, bins - 1)
    tot = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            tot += m.mean() * abs(p[m].mean() - y[m].mean())
    return float(tot)


def reliability(p, y, bins=K.CALIB_BINS) -> list:
    p, y = np.asarray(p, float), np.asarray(y, float)
    edges = np.quantile(p, np.linspace(0, 1, bins + 1))
    idx = np.clip(np.searchsorted(edges[1:-1], p, side="right"), 0, bins - 1)
    return [{"bin": b, "events": int((idx == b).sum()), "mean_predicted": float(p[idx == b].mean()), "observed_rate": float(y[idx == b].mean())} for b in range(bins) if (idx == b).any()]


def metrics(p, labels, aid=None) -> dict:
    y = EV.is_attack(labels).astype(int)
    p = np.asarray(p, float)
    pc = np.clip(p, 1e-9, 1 - 1e-9)
    rank = M2.rank_metrics(y, p)
    out = {"events": int(len(y)), "prevalence": float(y.mean()), "mean_predicted": float(p.mean()), "ece_equal_frequency": ece(p, y), "ece_equal_width": ece(p, y, equal_frequency=False),
           "brier": float(np.mean((p - y) ** 2)), "log_loss": float(-np.mean(y * np.log(pc) + (1 - y) * np.log(1 - pc))), "pr_auc": rank["pr_auc"], "roc_auc": rank["roc_auc"],
           "distinct_scores": int(len(np.unique(p)))}
    for thr in (0.5, 0.9):
        op = M2.operating_point(y, p >= thr)
        out[f"at_p>={thr}"] = {"alert_rate": op["alert_rate"], "precision": op["precision"], "recall": op["recall"], "f1": op["f1"],
                              "mean_predicted_among_alerts": float(p[p >= thr].mean()) if (p >= thr).any() else None}
    return out


def lopo(data: dict, methods=K.CALIB_METHODS) -> dict:
    """Leave-one-PROFILE-out on the DEV pool: fit on the datasets of the other profiles, evaluate on the held-out profile's datasets (transfer to an unseen profile).
    Also leave-one-DATASET-out (other seeds of the same profile stay in the training set): calibration on a new seed of a known profile."""
    profiles = sorted({r["profile"] for r in data.values()})
    res = {"by_profile_fold": {}, "by_dataset_fold": {}, "summary": {}}
    for m in methods:
        res["by_profile_fold"][m] = {}
        res["by_dataset_fold"][m] = {}
        for prof in profiles:
            tr = [d for d in data if data[d]["profile"] != prof]
            te = [d for d in data if data[d]["profile"] == prof]
            cal = Calibrator(m).fit([data[d]["fused"] for d in tr], [data[d]["tail"] for d in tr], [EV.is_attack(data[d]["labels"]).astype(int) for d in tr])
            res["by_profile_fold"][m][prof] = {d: metrics(cal.predict(data[d]["fused"], data[d]["tail"]), data[d]["labels"]) for d in te}
        for d in data:
            tr = [x for x in data if x != d]
            cal = Calibrator(m).fit([data[x]["fused"] for x in tr], [data[x]["tail"] for x in tr], [EV.is_attack(data[x]["labels"]).astype(int) for x in tr])
            res["by_dataset_fold"][m][d] = metrics(cal.predict(data[d]["fused"], data[d]["tail"]), data[d]["labels"])
    for m in methods:
        a = [v for fold in res["by_profile_fold"][m].values() for v in fold.values()]
        b = list(res["by_dataset_fold"][m].values())
        res["summary"][m] = {"unseen_profile": {k: float(np.mean([x[k] for x in a])) for k in ("ece_equal_frequency", "brier", "log_loss", "pr_auc", "mean_predicted", "prevalence")},
                             "new_seed_of_known_profile": {k: float(np.mean([x[k] for x in b])) for k in ("ece_equal_frequency", "brier", "log_loss", "pr_auc", "mean_predicted", "prevalence")},
                             "worst_unseen_profile_ece": float(max(x["ece_equal_frequency"] for x in a))}
    return res


def select_method(lopo_res: dict, methods=K.CALIB_METHODS) -> dict:
    """Pre-registered (K.CALIB_SELECTION): lowest mean unseen-profile log-loss and a lower mean ECE than identity; otherwise none."""
    s = lopo_res["summary"]
    cands = [m for m in methods if m != "identity" and s[m]["unseen_profile"]["ece_equal_frequency"] < s["identity"]["unseen_profile"]["ece_equal_frequency"]]
    if not cands:
        return {"rule": K.CALIB_SELECTION, "selected": None, "reason": "no method lowers the unseen-profile ECE below the uncalibrated score"}
    best = min(cands, key=lambda m: s[m]["unseen_profile"]["log_loss"])
    return {"rule": K.CALIB_SELECTION, "selected": best, "unseen_profile_log_loss": {m: s[m]["unseen_profile"]["log_loss"] for m in methods},
            "unseen_profile_ece": {m: s[m]["unseen_profile"]["ece_equal_frequency"] for m in methods}}


def prior_shift_stress(p, labels, prevalences=(0.005, 0.01, 0.035, 0.10), seed=K.ML5_SEED) -> dict:
    """Does a calibrator fitted at one base rate still hold when a deployment's attack prevalence is different? The evaluated events are re-sampled (seeded, the
    over-represented class is sub-sampled) to each target prevalence; scores and labels are untouched. A calibrated-at-3.5% probability is NOT the probability an alert
    is a real incident in a deployment whose base rate differs (prior shift)."""
    p = np.asarray(p, float)
    y = EV.is_attack(labels).astype(int)
    rng = np.random.default_rng(seed)
    pos, neg = np.where(y == 1)[0], np.where(y == 0)[0]
    out = {}
    for pi in prevalences:
        cur = len(pos) / (len(pos) + len(neg))
        if cur > pi:
            keep_pos = rng.choice(pos, size=max(int(round(len(neg) * pi / (1 - pi))), 1), replace=False)
            idx = np.concatenate([keep_pos, neg])
        else:
            keep_neg = rng.choice(neg, size=max(int(round(len(pos) * (1 - pi) / pi)), 1), replace=False)
            idx = np.concatenate([pos, keep_neg])
        m = metrics(p[idx], labels[idx])
        out[str(pi)] = {"events": m["events"], "prevalence": m["prevalence"], "mean_predicted": m["mean_predicted"], "ece_equal_frequency": m["ece_equal_frequency"],
                        "brier": m["brier"], "log_loss": m["log_loss"]}
    return out

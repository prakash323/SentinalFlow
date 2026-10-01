"""ML-3 shortcut-dependence diagnostics for the FROZEN candidate. Diagnostic only: nothing here feeds back into any choice.

(1) Group permutation: shuffle one generator-artifact family of feature columns jointly across the evaluated rows (the rows keep
    their labels and their time order, only that family's values are re-assigned at random), re-score with the frozen
    candidate, and measure the loss. A large loss = the candidate leans on that family. A family that is CORRELATED with
    the label but not USED shows no loss. Features are never removed on correlation alone.
(2) One-line generator rules vs the candidate (the ML-2 rules R1-R3, raw-field only): how many candidate alerts a trivial rule
    also raises, and what the candidate does on the attack events the rule cannot see.
(3) Signal ablation: each raw signal alone vs the fusion.
"""
from __future__ import annotations

import copy

import numpy as np
import pandas as pd

from . import candidate as CD
from . import common as K
from . import evaluate as EV
from .common import ATTACKS
from eval_ml2 import metrics as M2


def _score_rows(m: CD.Candidate, Xp: pd.DataFrame, prev, rows, prof_state, w, guard_max, calib, ewma, extra_cols=None):
    """Score `rows` of the (possibly permuted) matrix Xp with the frozen candidate; returns raw signals and fused."""
    F32 = Xp[m.features].to_numpy(dtype=np.float32)
    S = CD.windows_from(F32, prev, rows)
    seq, _ = m.seq_ae.score(S)
    F = m.scaler.transform(Xp.iloc[rows][m.features].to_numpy(dtype=float))
    iso = -m.iforest.score_samples(F)
    prof = copy.deepcopy(prof_state) if ewma else prof_state
    b, fu, _ = CD.replay(prof, Xp.iloc[rows], np.asarray(iso, float), np.asarray(seq, float), m.sig_calib, w, guard_max, ewma)
    return {"baseline": b, "iforest": np.asarray(iso, float), "sequence": np.asarray(seq, float), "fused": fu}


def group_permutation(m, X, prev, rows, labels_rows, aid_rows, w, guard_max, calib, ewma, prof_state, threshold, base_fused, seeds, keep=None):
    """rows = index positions (into X) of the evaluated population, chronological. labels_rows/aid_rows align with rows."""
    out = {}
    keep = np.ones(len(rows), dtype=bool) if keep is None else np.asarray(keep, dtype=bool)
    labels_rows = np.asarray(labels_rows, dtype=object)[keep]        # metrics are computed on the evaluation population only;
    aid_rows = np.asarray(aid_rows, dtype=object)[keep]              # purged rows are still scored (they are part of the stream)
    base_fused = np.asarray(base_fused, dtype=float)[keep]
    groups = dict(K.SHORTCUT_GROUPS)
    groups["ALL generator-artifact groups together"] = sorted({c for g in K.SHORTCUT_GROUPS.values() for c in g})
    base_macro = EV.macro_type_prauc(labels_rows, base_fused)["macro_pr_auc"]
    y = EV.is_attack(labels_rows).astype(int)
    base_ev = M2.rank_metrics(y, base_fused)
    base_op = EV.operating(labels_rows, aid_rows, base_fused >= threshold)
    out["baseline_unpermuted"] = {"macro_type_pr_auc": base_macro, "event_pr_auc": base_ev["pr_auc"], "roc_auc": base_ev["roc_auc"],
                                  "precision": base_op["precision"], "recall": base_op["recall"], "f1": base_op["f1"],
                                  "incidents_detected": base_op["incidents_detected"], "incidents": base_op["incidents"]}
    out["groups"] = {}
    for gname, cols in groups.items():
        cols = [c for c in cols if c in X.columns]
        res = []
        for s in seeds:
            rng = np.random.default_rng(K.ML3_SEED + s)
            Xp = X.copy()
            perm = rng.permutation(len(rows))
            for c in cols:
                v = Xp[c].to_numpy().copy()
                v[rows] = v[rows][perm]
                Xp[c] = v
            sc = _score_rows(m, Xp, prev, rows, prof_state, w, guard_max, calib, ewma)
            f = sc["fused"][keep]
            mm = EV.macro_type_prauc(labels_rows, f)["macro_pr_auc"]
            rk = M2.rank_metrics(y, f)
            op = EV.operating(labels_rows, aid_rows, f >= threshold)
            res.append({"macro_type_pr_auc": mm, "event_pr_auc": rk["pr_auc"], "roc_auc": rk["roc_auc"], "precision": op["precision"],
                        "recall": op["recall"], "f1": op["f1"], "incidents_detected": op["incidents_detected"]})
        avg = {k: float(np.mean([r[k] for r in res if r[k] is not None])) if any(r[k] is not None for r in res) else None
               for k in res[0]}
        out["groups"][gname] = {"columns": cols, "seeds": len(seeds), "permuted": avg,
                                "delta_macro_type_pr_auc": (avg["macro_type_pr_auc"] - base_macro) if avg["macro_type_pr_auc"] is not None and base_macro is not None else None,
                                "delta_event_pr_auc": (avg["event_pr_auc"] - base_ev["pr_auc"]) if avg["event_pr_auc"] is not None and base_ev["pr_auc"] is not None else None,
                                "delta_recall_at_threshold": (avg["recall"] - base_op["recall"]) if avg["recall"] is not None and base_op["recall"] is not None else None}
    return out


def rules_vs_candidate(shortcut_df: pd.DataFrame, mask_rows, labels_rows, aid_rows, fused, alert) -> dict:
    """`shortcut_df` rows aligned with the FULL event table; `mask_rows` = index positions of the population."""
    sd = shortcut_df.iloc[mask_rows].reset_index(drop=True)
    R1 = ((sd.public_ip > 0) | (sd.failed_auth > 0)).to_numpy()
    R2 = R1 | (sd.foreign_city > 0).to_numpy()
    R3 = R2 | (sd.command_contains_sudo > 0).to_numpy() | (((sd.sensitive_resource > 0) & (sd.off_hours_band_22_to_05 > 0))).to_numpy()
    labels = np.asarray(labels_rows, dtype=object)
    y = EV.is_attack(labels).astype(int)
    out = {"rules": {}, "note": "R1 = public source IP OR failed authentication; R2 = R1 OR foreign city; R3 = R2 OR sudo OR (sensitive resource AND 22-05h)"}
    for nm, r in (("R1", R1), ("R2", R2), ("R3", R3)):
        rr = {"rule_alerts": int(r.sum()), "rule_precision": float(y[r].mean()) if r.any() else None, "rule_recall": float(r[y == 1].mean()),
              "candidate_alerts_also_flagged_by_rule": float(r[alert].mean()) if alert.any() else None,
              "candidate_true_positives_also_flagged_by_rule": float(r[alert & (y == 1)].mean()) if (alert & (y == 1)).any() else None,
              "per_attack": {}}
        for t in ATTACKS:
            mt = labels == t
            if mt.any():
                rr["per_attack"][t] = {"events": int(mt.sum()), "rule_flag_rate": float(r[mt].mean()), "candidate_alert_rate": float(alert[mt].mean()),
                                       "candidate_alert_rate_where_rule_is_blind": float(alert[mt & ~r].mean()) if (mt & ~r).any() else None,
                                       "events_rule_blind": int((mt & ~r).sum())}
        # candidate ranking quality on the events the rule does NOT flag (the shortcut-free sub-population)
        keep = ~r
        yk = y[keep]
        rr["candidate_on_rule_negative_subpopulation"] = {
            "events": int(keep.sum()), "attack_events": int(yk.sum()),
            **({"pr_auc": M2.rank_metrics(yk, fused[keep])["pr_auc"], "roc_auc": M2.rank_metrics(yk, fused[keep])["roc_auc"],
                "recall_at_threshold": float(alert[keep][yk == 1].mean())} if yk.sum() else {})}
        out["rules"][nm] = rr
    fields = ["public_ip", "failed_auth", "foreign_city", "sensitive_resource", "off_hours_band_22_to_05", "hour_of_day", "command_contains_sudo",
              "log_gap_since_prev_event_s"]
    negm = np.isin(labels, ("normal", "benign_drift"))
    from scipy.stats import spearmanr
    out["spearman_fused_vs_field"] = {}
    for f in fields:
        v = sd[f].to_numpy(float)
        rho_all = spearmanr(fused, v).correlation if np.ptp(v) > 0 else None
        rho_neg = spearmanr(fused[negm], v[negm]).correlation if np.ptp(v[negm]) > 0 else None
        out["spearman_fused_vs_field"][f] = {"all_events": None if rho_all is None else float(rho_all),
                                             "negatives_only": None if rho_neg is None else float(rho_neg)}
    return out


def signal_ablation(labels, raw: dict, fused, calib) -> dict:
    """Each raw signal alone (rank of its TRAIN-percentile) vs the fusion, on the same population."""
    labels = np.asarray(labels, dtype=object)
    y = EV.is_attack(labels).astype(int)
    out = {}
    for k in K.SIGNALS:
        s = CD.pct(calib, k, raw[k])
        rk = M2.rank_metrics(y, raw[k])
        out[k] = {"pr_auc": rk["pr_auc"], "roc_auc": rk["roc_auc"], "macro_type_pr_auc": EV.macro_type_prauc(labels, raw[k])["macro_pr_auc"],
                  "per_type_pr_auc": EV.macro_type_prauc(labels, raw[k])["per_type_pr_auc"]}
    rk = M2.rank_metrics(y, fused)
    out["fused"] = {"pr_auc": rk["pr_auc"], "roc_auc": rk["roc_auc"], "macro_type_pr_auc": EV.macro_type_prauc(labels, fused)["macro_pr_auc"],
                    "per_type_pr_auc": EV.macro_type_prauc(labels, fused)["per_type_pr_auc"]}
    return out

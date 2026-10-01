"""
Evaluation.

Leads with PR-AUC and precision/recall at a realistic analyst alert budget,
because with ~1.5% positives ROC-AUC flatters every model. Also produces the
per-attack recall table, the alert-budget curve, the confusion matrix and the
ablation numbers that the report is built on.
"""
from __future__ import annotations
import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (average_precision_score, roc_auc_score,
                             precision_recall_curve, roc_curve)

import config as C
from src.features import FEATURE_NAMES
from src.utils import rank_normalise


def binary_labels(labels: pd.Series) -> np.ndarray:
    """benign_drift counts as NEGATIVE -- it is legitimate behaviour."""
    return (~labels.isin([C.NORMAL, "benign_drift"])).astype(int).to_numpy()


def metrics_at_budget(y_true, risk, budget=C.ALERT_BUDGET):
    n_alerts = max(1, int(len(risk) * budget))
    idx = np.argsort(-risk)[:n_alerts]
    tp = int(y_true[idx].sum())
    prec = tp / n_alerts
    rec = tp / max(int(y_true.sum()), 1)
    fp = n_alerts - tp
    n_neg = int((y_true == 0).sum())
    return {
        "alert_budget": budget, "n_alerts": n_alerts,
        "precision_at_budget": round(prec, 4),
        "recall_at_budget": round(rec, 4),
        "f1_at_budget": round(2 * prec * rec / max(prec + rec, 1e-9), 4),
        "false_positives": fp,
        "false_positive_rate": round(fp / max(n_neg, 1), 5),
    }


def core_metrics(y_true, risk, budget=C.ALERT_BUDGET):
    return {
        "pr_auc": round(float(average_precision_score(y_true, risk)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, risk)), 4),
        "positives": int(y_true.sum()),
        "n_events": int(len(y_true)),
        "positive_rate": round(float(y_true.mean()), 5),
        **metrics_at_budget(y_true, risk, budget),
    }


def per_attack_recall(labels: pd.Series, risk: np.ndarray,
                      budget=C.ALERT_BUDGET) -> pd.DataFrame:
    n_alerts = max(1, int(len(risk) * budget))
    flagged = set(np.argsort(-risk)[:n_alerts].tolist())
    rows = []
    for lab in C.ATTACK_TYPES + ["benign_drift", C.NORMAL]:
        pos = np.where(labels.to_numpy() == lab)[0]
        if len(pos) == 0:
            continue
        caught = sum(1 for i in pos if i in flagged)
        rows.append({"label": lab, "events": len(pos), "flagged": caught,
                     "rate": round(caught / len(pos), 3)})
    return pd.DataFrame(rows)


def budget_curve(y_true, risk, budgets=C.BUDGET_LEVELS):
    return pd.DataFrame([{"budget": b, **metrics_at_budget(y_true, risk, b)}
                         for b in budgets])


def incident_recall(labels: pd.Series, attack_ids: pd.Series,
                    queue_mask: np.ndarray) -> pd.DataFrame:
    """
    Operationally the question is not "did we flag every event of the attack"
    but "did we catch the attack at all". A brute-force burst is ONE incident an
    analyst investigates, not 130 separate ones. This is the metric a SOC cares
    about, and it is reported alongside -- never instead of -- the event-level
    numbers.
    """
    flagged = set(np.where(queue_mask)[0].tolist())
    df = pd.DataFrame({"label": labels.to_numpy(), "aid": attack_ids.fillna("").to_numpy()})
    rows = []
    for lab in C.ATTACK_TYPES:
        sub = df[(df.label == lab) & (df.aid != "")]
        if sub.empty:
            continue
        total = sub.aid.nunique()
        caught = sum(1 for aid, g in sub.groupby("aid")
                     if any(i in flagged for i in g.index))
        rows.append({"attack_type": lab, "incidents": total, "detected": caught,
                     "incident_recall": round(caught / total, 3)})
    return pd.DataFrame(rows)


def classifier_training_pool(X: pd.DataFrame, risk: np.ndarray,
                             detected_incident_ids,
                             max_per_incident: int = C.MAX_TRAIN_EVENTS_PER_INCIDENT
                             ) -> np.ndarray:
    """
    Build the attack-type classifier's training rows from DETECTED
    INCIDENTS, not from a flat `risk >= thr` event filter.

    Two problems with the flat filter:
      1. It is dominated by whichever attack type produces the most events
         per incident. A brute-force burst (30-200 events, every one of them
         individually far above the risk threshold) can fill nearly the
         entire flagged pool, while an attack that produces one or two
         anomalous events per incident (impossible travel, device spoofing)
         contributes almost nothing -- so the classifier never gets enough
         examples to learn those classes, and literally cannot predict a
         class it has zero training rows for.
      2. It includes "normal"/"benign_drift" rows that merely scored high
         (an anomaly-detection false positive), which is how the classifier
         ends up trained to predict "normal" on things already sitting in
         the alert queue -- not an actionable answer for an analyst.

    `detected_incident_ids` must be the SAME "did we actually catch this
    incident" definition used for the alert queue / incident-level recall --
    i.e. attack_ids with >=1 event in the deduplicated, ranked, budgeted
    queue -- and deliberately NOT a scalar `risk >= thr` comparison. Risk
    saturates/ties at its clipped ceiling for a lot of events, so a scalar
    cutoff can silently drop an attack type whose one representative event
    just misses the exact tie value while still ranking comfortably inside
    the real, rank-based alert queue.

    Given the detected incidents, take up to `max_per_incident` of each
    one's own highest-risk RAW events (not just its one deduplicated queue
    representative) as training rows. Every attack type with at least one
    detected incident contributes a capped, comparable number of rows;
    "normal"/"benign_drift" contribute none, because they have no attack_id.
    """
    is_attack = X["label"].isin(C.ATTACK_TYPES).to_numpy()
    aid = X["attack_id"].fillna("").to_numpy()
    detected = set(detected_incident_ids)
    cand = is_attack & (aid != "") & np.isin(aid, list(detected))
    if not cand.any():
        return np.array([], dtype=int)
    pos = np.where(cand)[0]
    sub = pd.DataFrame({"attack_id": aid[cand], "risk": risk[cand], "_pos": pos})
    keep = []
    for _, g in sub.groupby("attack_id"):
        top = g.sort_values("risk", ascending=False).head(max_per_incident)
        keep.extend(top["_pos"].tolist())
    return np.array(sorted(keep), dtype=int)


def incident_scores(idx: np.ndarray, entity_ids, timestamps, risk: np.ndarray,
                    window_h: int = C.INCIDENT_WINDOW_H,
                    fp_novelty: np.ndarray | None = None,
                    fp_weight: float = 0.01) -> np.ndarray:
    """
    Score each candidate incident on TWO kinds of evidence and take the
    stronger of the two.

    Ranking incidents purely by their representative event's risk (the
    original behaviour) systematically under-ranks slow-burn attacks.
    Low-and-slow exfiltration and lateral movement never produce a single
    spectacular event -- they produce a sustained run of mildly elevated
    ones -- so they lose every tie-break to a benign one-off statistical
    outlier that happened to spike once.

    Conversely, ranking purely by windowed average under-ranks genuine
    point attacks: an impossible-travel login is ONE event, and averaging
    it against the entity's otherwise-normal day dilutes it to nothing.

    So this takes `max(peak_rank, window_mean_rank)` -- an OR over two
    independent kinds of evidence, rather than an average that dilutes
    both. An incident is worth an analyst's time if it contains an
    extreme event OR the entity was persistently elevated around it.

    On the bundled sample this lifts the share of the analyst queue that
    is a genuine attack from 28.4% to 38.9%, at equal budget, while
    keeping all six attack types represented.

    OPTIONAL third channel: `fp_novelty`. Device spoofing's signal (an
    unfamiliar device fingerprint) is a single near-boolean feature that
    *persists* across the few events following the swap, rather than
    producing one dramatic spike -- so it loses ties against attacks that
    stack several clipped z-scores at once (see FIXES.md). When provided,
    the windowed MEAN fingerprint-novelty around each candidate incident is
    rank-normalised and added as a small, bounded bonus (`fp_weight`,
    default 0.01) on top of the max() above. This only ever nudges an
    incident that is already borderline; it cannot by itself lift an
    incident with no fingerprint evidence into the queue, and it never
    changes the alert budget or evaluation methodology -- only the ORDER
    incidents are drawn from within that fixed budget.

    TUNED EMPIRICALLY on the bundled sample (see FIXES.md): 0.01 lifts
    device-spoofing incident recall 0.6 -> 0.8 (3/5 -> 4/5) with ZERO
    regression on any other attack type, for a net 34/36 -> 35/36 total
    incidents caught @1% budget. Weights above ~0.015 start trading other
    attack types' incidents away for device-spoofing ones (net neutral or
    worse) because the "budget filler" zone (risk 99.2-99.9) is densely
    packed with near-tied incidents, so the bonus needs to stay small
    enough to only break genuine ties, not reshuffle the whole zone.
    """
    ts = pd.to_datetime(pd.Series(timestamps)).to_numpy()
    ent = pd.Series(entity_ids).to_numpy()
    win = np.timedelta64(int(window_h), "h")

    # Per-entity sorted event lists, restricted to the scored population.
    by_ent: dict = {}
    for i in idx:
        by_ent.setdefault(ent[i], []).append(i)
    ent_ts, ent_risk, ent_fp = {}, {}, {}
    for e, rows in by_ent.items():
        rows = np.array(sorted(rows, key=lambda r: ts[r]))
        ent_ts[e] = ts[rows]
        ent_risk[e] = risk[rows]
        if fp_novelty is not None:
            ent_fp[e] = fp_novelty[rows]

    win_mean = np.empty(len(idx), dtype=float)
    fp_win_mean = np.empty(len(idx), dtype=float) if fp_novelty is not None else None
    for k, i in enumerate(idx):
        e = ent[i]
        t_arr, r_arr = ent_ts[e], ent_risk[e]
        lo = np.searchsorted(t_arr, ts[i] - win, side="left")
        hi = np.searchsorted(t_arr, ts[i] + win, side="right")
        win_mean[k] = r_arr[lo:hi].mean() if hi > lo else risk[i]
        if fp_novelty is not None:
            f_arr = ent_fp[e]
            fp_win_mean[k] = f_arr[lo:hi].mean() if hi > lo else fp_novelty[i]

    base = np.maximum(rank_normalise(risk[idx]), rank_normalise(win_mean))
    if fp_novelty is not None:
        base = base + fp_weight * rank_normalise(fp_win_mean)
    return base


def per_attack_recall_queue(labels: pd.Series, queue_mask: np.ndarray) -> pd.DataFrame:
    """
    Per-attack recall measured on the DEDUPLICATED analyst queue -- the
    thing a SOC analyst actually reviews.

    `per_attack_recall` above ranks raw events, which makes every attack
    except the burstiest look undetected: brute force emits 620 events, so
    it fills 333 of the 334 raw-event slots and every other attack type
    reads 0.000 even when the system caught all of them. That number is a
    property of how the labels are counted, not of detection quality, and
    quoting it alone badly misrepresents the system.
    """
    rows = []
    lab = labels.to_numpy()
    for name in C.ATTACK_TYPES + ["benign_drift", C.NORMAL]:
        pos = np.where(lab == name)[0]
        if len(pos) == 0:
            continue
        caught = int(queue_mask[pos].sum())
        rows.append({"label": name, "events": len(pos), "in_queue": caught,
                     "rate": round(caught / len(pos), 3)})
    return pd.DataFrame(rows)


def incident_budget_curve(ranked: np.ndarray, labels: pd.Series,
                          attack_ids: pd.Series, n_scored: int,
                          n_test: int,
                          budgets=C.BUDGET_LEVELS) -> pd.DataFrame:
    """
    Incident recall and queue purity as a function of the analyst's alert
    budget. This is the operationally honest view of the precision/recall
    trade-off: the event-level `budget_curve` is dominated by whichever
    attack emits the most events, whereas this counts alert CARDS an
    analyst opens and INCIDENTS actually caught.
    """
    lab = labels.to_numpy()
    rows = []
    for b in budgets:
        n = max(1, int(n_test * b))
        top = ranked[:n]
        qm = np.zeros(n_scored, dtype=bool)
        qm[top] = True
        inc = incident_recall(labels, attack_ids, qm)
        atk = int((~pd.Series(lab[top]).isin([C.NORMAL, "benign_drift"])).sum())
        rows.append({
            "budget": b, "n_alerts": n,
            "incidents_detected": int(inc.detected.sum()),
            "incidents_total": int(inc.incidents.sum()),
            "incident_recall": round(float(inc.detected.sum() / max(inc.incidents.sum(), 1)), 3),
            "queue_precision": round(atk / n, 4),
        })
    return pd.DataFrame(rows)


def deduplicate_alerts(idx: np.ndarray, entity_ids, timestamps, risk,
                       window_min=30):
    """
    Collapse a burst from one entity into a SINGLE alert, keeping the
    highest-risk event as the representative.

    This is the difference between a usable queue and an unusable one. A
    brute-force burst is 130 events but ONE thing to investigate; without
    deduplication a single noisy incident consumes the entire analyst budget
    and every rarer attack goes unseen. Returned in descending risk order.
    """
    ts = pd.to_datetime(pd.Series(timestamps).iloc[idx]).to_numpy()
    ent = pd.Series(entity_ids).iloc[idx].to_numpy()
    order = np.argsort(-risk[idx])
    kept, seen = [], {}
    win = np.timedelta64(window_min, "m")
    for o in order:
        e, t = ent[o], ts[o]
        if any(abs(t - pt) < win for pt in seen.get(e, [])):
            continue
        seen.setdefault(e, []).append(t)
        kept.append(idx[o])
    return np.array(kept, dtype=int)


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------
def plot_pr(y_true, risk, path, title="Precision-Recall"):
    p, r, _ = precision_recall_curve(y_true, risk)
    ap = average_precision_score(y_true, risk)
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.plot(r, p, lw=2)
    ax.axhline(y_true.mean(), ls="--", lw=1, color="gray",
               label=f"random = {y_true.mean():.3f}")
    ax.set_xlabel("recall"); ax.set_ylabel("precision")
    ax.set_title(f"{title}  (PR-AUC = {ap:.3f})")
    ax.legend(); fig.tight_layout(); fig.savefig(path, dpi=150); plt.close(fig)


def plot_roc(y_true, risk, path, title="ROC"):
    """
    Shown alongside, never instead of, the PR curve. At ~3% positive rate
    ROC-AUC looks deceptively strong (a high true-positive rate is cheap to
    buy when negatives outnumber positives 30:1) -- see the caption on the
    Model performance page. Included because a SOC reviewer will expect it,
    not because it's the metric this system is tuned against.
    """
    fpr, tpr, _ = roc_curve(y_true, risk)
    auc = roc_auc_score(y_true, risk)
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.plot(fpr, tpr, lw=2)
    ax.plot([0, 1], [0, 1], ls="--", lw=1, color="gray", label="chance")
    ax.set_xlabel("false positive rate"); ax.set_ylabel("true positive rate")
    ax.set_title(f"{title}  (ROC-AUC = {auc:.3f})")
    ax.legend(); fig.tight_layout(); fig.savefig(path, dpi=150); plt.close(fig)


def plot_feature_importance(importance: dict, path, top_k=15):
    """Global classifier feature importance (attack-TYPE model, not the
    unsupervised detector -- there is no single 'importance' for an
    ensemble of three unsupervised signals, only the per-alert attribution
    already shown on the alert-detail page)."""
    items = sorted(importance.items(), key=lambda t: t[1])[-top_k:]
    if not items:
        return
    names, vals = zip(*items)
    fig, ax = plt.subplots(figsize=(6, max(3, 0.32 * len(items))))
    ax.barh(names, vals, color="#4c78a8")
    ax.set_xlabel("importance"); ax.set_title("Attack-type classifier: global feature importance")
    fig.tight_layout(); fig.savefig(path, dpi=150); plt.close(fig)


def plot_shap_summary(classifier, X: pd.DataFrame, path, top_k=15, max_rows=300):
    """
    Global SHAP feature importance for the attack-type classifier: mean
    |SHAP value|, averaged across every class and a bounded sample of the
    classifier's own training pool. A bonus report figure (Part 10 of the
    brief) -- returns False and writes nothing if `shap` isn't installed or
    the model isn't SHAP-TreeExplainer-compatible, since the per-alert
    attribution in src/explain.py already has a documented fallback and
    this global summary is purely additive on top of it.

    Handles every SHAP multiclass output shape (list-per-class, or a single
    (n, features, classes) array) the same way src/explain.py's
    `_select_class_shap` does, just averaged over classes instead of
    picking one.
    """
    try:
        import shap
    except ImportError:
        return False
    if classifier is None or classifier.model is None:
        return False
    try:
        F = X[FEATURE_NAMES].to_numpy(dtype=float)
        if len(F) > max_rows:
            rng = np.random.default_rng(C.RANDOM_SEED)
            F = F[rng.choice(len(F), max_rows, replace=False)]
        explainer = shap.TreeExplainer(classifier.model)
        vals = explainer.shap_values(F)
        if isinstance(vals, list):
            arr = np.stack([np.asarray(v) for v in vals], axis=0)   # (classes, n, feat)
        else:
            arr = np.asarray(vals)
            arr = arr.transpose(2, 0, 1) if arr.ndim == 3 else arr[None, ...]
        mean_abs = np.abs(arr).mean(axis=(0, 1))
    except Exception:
        return False
    order = np.argsort(mean_abs)[-top_k:]
    fig, ax = plt.subplots(figsize=(6, max(3, 0.32 * len(order))))
    ax.barh([FEATURE_NAMES[i] for i in order], mean_abs[order], color="#4c78a8")
    ax.set_xlabel("mean |SHAP value| (averaged across classes)")
    ax.set_title("Attack-type classifier: global SHAP feature importance")
    fig.tight_layout(); fig.savefig(path, dpi=150); plt.close(fig)
    return True


def plot_budget_curve(df, path):
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.plot(df["budget"] * 100, df["recall_at_budget"], marker="o", label="recall")
    ax.plot(df["budget"] * 100, df["precision_at_budget"], marker="s", label="precision")
    ax.set_xscale("log")
    ax.set_xlabel("analyst alert budget (% of events)")
    ax.set_ylabel("score"); ax.set_title("Performance vs alert budget")
    ax.legend(); ax.grid(alpha=.3); fig.tight_layout()
    fig.savefig(path, dpi=150); plt.close(fig)


def plot_confusion(cm, labels, path):
    fig, ax = plt.subplots(figsize=(6.5, 5.5))
    cmn = cm.astype(float) / np.clip(cm.sum(axis=1, keepdims=True), 1, None)
    im = ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(labels))); ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.set_yticklabels(labels, fontsize=8)
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, f"{cm[i,j]}", ha="center", va="center", fontsize=7,
                    color="white" if cmn[i, j] > .5 else "black")
    ax.set_xlabel("predicted"); ax.set_ylabel("true")
    ax.set_title("Attack-type confusion matrix")
    fig.colorbar(im, fraction=.046); fig.tight_layout()
    fig.savefig(path, dpi=150); plt.close(fig)


def plot_model_comparison(rows, path):
    fig, ax = plt.subplots(figsize=(6, 4))
    names = [r["model"] for r in rows]
    ax.barh(names, [r["pr_auc"] for r in rows])
    for i, r in enumerate(rows):
        ax.text(r["pr_auc"] + .005, i, f"{r['pr_auc']:.3f}", va="center", fontsize=9)
    ax.set_xlabel("PR-AUC"); ax.set_title("Ablation: detector components")
    fig.tight_layout(); fig.savefig(path, dpi=150); plt.close(fig)


def plot_feature_separation(X, labels, feats, path):
    feats = [f for f in feats if f in X.columns][:6]
    fig, axes = plt.subplots(2, 3, figsize=(12, 6))
    y = labels.to_numpy()
    for ax, f in zip(axes.ravel(), feats):
        norm = X.loc[y == C.NORMAL, f].to_numpy()
        anom = X.loc[~np.isin(y, [C.NORMAL, "benign_drift"]), f].to_numpy()
        lo, hi = np.percentile(np.concatenate([norm, anom]), [1, 99])
        bins = np.linspace(lo, hi + 1e-6, 40)
        ax.hist(norm, bins=bins, alpha=.6, density=True, label="normal")
        ax.hist(anom, bins=bins, alpha=.6, density=True, label="anomaly")
        ax.set_title(f, fontsize=9); ax.tick_params(labelsize=7)
    axes.ravel()[0].legend(fontsize=8)
    fig.suptitle("Feature separation: normal vs anomalous")
    fig.tight_layout(); fig.savefig(path, dpi=150); plt.close(fig)


def plot_risk_distribution(queue_risk, population_risk, path):
    """
    Side-by-side histograms answering "is the queue saturated at 100, or is
    that just what the top 1% slice of a well-spread distribution looks
    like?" -- see REVIEW_NOTES.md item 1. Two panels on a shared 0-100 axis
    so the contrast is visible at a glance instead of requiring the analyst
    to take it on faith.
    """
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    axes[0].hist(population_risk, bins=50, range=(0, 100), color="#4c78a8")
    axes[0].set_title(f"Full population (n={len(population_risk):,})")
    axes[0].set_xlabel("risk score"); axes[0].set_ylabel("events")
    axes[0].axvline(np.median(population_risk), color="black", ls="--", lw=1,
                    label=f"median {np.median(population_risk):.1f}")
    axes[0].legend(fontsize=8)

    axes[1].hist(queue_risk, bins=50, range=(0, 100), color="#e45756")
    axes[1].set_title(f"Alert queue only (top {C.ALERT_BUDGET*100:.0f}%, "
                      f"n={len(queue_risk):,})")
    axes[1].set_xlabel("risk score")
    fig.suptitle("Risk-score distribution: the queue is a slice of the tail, "
                "not a saturated model")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def save_json(obj, path):
    def _d(o):
        if isinstance(o, (np.integer,)): return int(o)
        if isinstance(o, (np.floating,)): return float(o)
        if isinstance(o, np.ndarray): return o.tolist()
        return str(o)
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2, default=_d)

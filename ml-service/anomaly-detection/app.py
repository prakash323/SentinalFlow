"""
Analyst-facing dashboard.

    streamlit run app.py

ONE dashboard, one entry point, six pages on a sidebar radio (not
`st.tabs()` -- a single widget avoids tab-scoped filters desyncing from
each other, which was the root cause of the "nav bar isn't working"
report):

  Overview           headline KPIs + is the queue saturated or is that
                      just what the top-1% slice of a spread-out
                      distribution looks like (side-by-side histograms)
  Alert queue         ranked by risk, with the reason, the attack-type
                      evidence, and a concrete SOC next step
  Entity view         30-day timeline plus that entity's learned normal
                      behaviour
  Model performance    PR curve, ablations, per-attack and incident recall
  Real-time replay     a bounded run_realtime.py streaming demo, folded into
                      the same app instead of being a second disconnected
                      artifact
  Live Monitor        auto-refreshing view (st.fragment) of a long-running
                      `run_realtime.py --serve` process fed by any of the
                      src/adapters.py input sources

The sidebar's "alert budget" control is a single, shared runtime parameter
(src/detect.py:threshold_for_budget) that drives the Overview KPIs and the
Alert queue page's queue size -- see the comment where it's built, below.

Requires run_pipeline.py to have been run once. `python run_realtime.py`
populates the Real-time replay page; it can also be triggered from inside
that page for a short demo run. `python run_realtime.py --serve` (any
--stream-source) populates the Live Monitor page continuously.
"""
from __future__ import annotations
import json
import subprocess
import sys
import time

import numpy as np
import pandas as pd
import streamlit as st

import config as C
from src.utils import load_events, parse_geo

st.set_page_config(page_title="Behavioural Anomaly Detection",
                   layout="wide", initial_sidebar_state="expanded")

# ---------------------------------------------------------------------------
# Look & feel
# ---------------------------------------------------------------------------
RISK_COLOURS = [(90, "#c0392b"), (75, "#d68910"), (60, "#b7950b"), (0, "#5f6368")]
ACCENT = "#2454a6"

st.markdown("""
<style>
    .block-container {padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1300px;}
    h1, h2, h3, h4 {font-family: -apple-system, "Segoe UI", Roboto, sans-serif;}
    h1 {font-weight: 700; letter-spacing: -0.5px;}
    /*
     * .app-card / stMetric / .alert-header hardcode a LIGHT background.
     * Streamlit's dark theme otherwise supplies light/white text by
     * default, which on a hardcoded light card is invisible text-on-white
     * -- the "overview text isn't visible" report. These cards don't adapt
     * to the theme, so their text colour is pinned dark to match, instead
     * of inherited from an ambient theme it was never designed against.
     */
    div[data-testid="stMetric"] {
        background: #f7f8fa; border: 1px solid #e6e8eb; border-radius: 10px;
        padding: 12px 16px 10px 16px; color: #1a1a1a;
    }
    div[data-testid="stMetric"] label,
    div[data-testid="stMetricValue"],
    div[data-testid="stMetricDelta"] {color: #1a1a1a !important;}
    div[data-testid="stMetricValue"] {font-size: 1.5rem;}
    .app-card {
        border: 1px solid #e6e8eb; border-radius: 10px; padding: 16px 20px;
        background: #ffffff; margin-bottom: 14px; color: #1a1a1a;
    }
    .app-card b {color: #0d1117;}
    .alert-header {
        border-radius: 10px; padding: 14px 20px; margin-bottom: 10px;
        background: #fafafa; color: #1a1a1a;
    }
    .pill {
        display:inline-block; padding:2px 10px; border-radius:999px;
        font-size:0.78rem; font-weight:600; margin-right:6px;
    }
    .pill-conf   {background:#eef3fc; color:#2454a6;}
    .pill-filler {background:#fdf2e3; color:#946200;}
    .pill-cold   {background:#f1eefc; color:#5b3ea6;}
    .section-caption {color:#5f6368; font-size:0.86rem; margin-top:-6px;}
    hr {margin: 0.6rem 0 1.2rem 0;}
</style>
""", unsafe_allow_html=True)


def risk_colour(r):
    for t, c in RISK_COLOURS:
        if r >= t:
            return c
    return "#5f6368"


def risk_badge(r):
    col = risk_colour(r)
    return (f"<span style='background:{col}22;color:{col};padding:3px 12px;"
            f"border-radius:999px;font-weight:700;font-size:1.1rem'>{r:.1f}</span>")


SEVERITY_BANDS = [(90, "Critical"), (75, "High"), (60, "Medium"), (0, "Low")]


def severity_label(r):
    for t, name in SEVERITY_BANDS:
        if r >= t:
            return name
    return "Low"


def severity_pill(r):
    col = risk_colour(r)
    return (f"<span class='pill' style='background:{col}22;color:{col}'>"
            f"{severity_label(r)}</span>")


def budget_row(metrics: dict, key: str, budget: float) -> dict:
    """Exact-match lookup into a precomputed multi-budget table
    (metrics.json's budget_curve / incident_budget_curve, src/evaluate.py).
    Returns {} rather than fabricating a row for a budget that wasn't
    actually swept."""
    for row in metrics.get(key, []):
        if abs(row.get("budget", -1) - budget) < 1e-9:
            return row
    return {}


def available_budgets(metrics: dict, fallback: float) -> list:
    levels = {row["budget"] for row in metrics.get("budget_curve", [])}
    levels |= {row["budget"] for row in metrics.get("incident_budget_curve", [])}
    levels.add(fallback)
    return sorted(levels) or [fallback]


# Attack type -> MITRE ATT&CK technique, shown as extra context on the alert
# detail view. Static mapping (not learned/inferred), so it's exactly as
# reliable as the taxonomy definition itself -- it doesn't degrade the
# honesty of the model's own confidence numbers.
MITRE_MAP = {
    "brute_force": ("T1110", "Brute Force"),
    "credential_stuffing": ("T1110.004", "Credential Stuffing"),
    "impossible_travel": ("T1078", "Valid Accounts (anomalous logon)"),
    "lateral_movement": ("T1021", "Remote Services (lateral movement)"),
    "device_spoofing": ("T1036", "Masquerading (device/asset spoofing)"),
    "low_slow_exfil": ("T1030", "Data Transfer Size Limits (low-and-slow exfil)"),
}


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
@st.cache_data
def load_all():
    alerts = json.loads((C.REPORT / "alerts.json").read_text()) \
        if (C.REPORT / "alerts.json").exists() else []
    metrics = json.loads((C.REPORT / "metrics.json").read_text()) \
        if (C.REPORT / "metrics.json").exists() else {}
    scored = pd.read_csv(C.REPORT / "scored_events.csv") \
        if (C.REPORT / "scored_events.csv").exists() else pd.DataFrame()
    events = load_events(C.SAMPLE_DIR / "events.csv") \
        if (C.SAMPLE_DIR / "events.csv").exists() else pd.DataFrame()
    if len(scored):
        scored["timestamp"] = pd.to_datetime(scored["timestamp"])
    return alerts, metrics, scored, events


@st.cache_data
def load_realtime():
    stats_p = C.REPORT / "realtime_stats.json"
    alerts_p = C.REPORT / "alerts_realtime.jsonl"
    stats = json.loads(stats_p.read_text()) if stats_p.exists() else {}
    rt_alerts = []
    if alerts_p.exists():
        with open(alerts_p) as fh:
            rt_alerts = [json.loads(l) for l in fh if l.strip()]
    return stats, rt_alerts


alerts, metrics, scored, events = load_all()

if not alerts and not metrics:
    st.error("No results found. Run `python run_pipeline.py` first, then "
             "reload this page.")
    st.stop()

o = metrics.get("overall", {})

# ---------------------------------------------------------------------------
# Sidebar: brand + navigation (single widget, page-scoped filters below it)
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown(f"### 🛡️ Behavioural Anomaly Detection")
    st.caption("Analyst console \u2014 Honeywell hackathon submission")
    st.markdown("---")
    page = st.radio("Navigate", [
        "Overview", "Alert queue", "Entity view",
        "Model performance", "Real-time replay", "Live Monitor",
    ], label_visibility="collapsed", key="nav_page")
    st.markdown("---")

    # Alert budget is a runtime parameter, not a constant baked into the
    # report (src/detect.py:threshold_for_budget) -- this control drives the
    # KPI cards on Overview and the queue size on Alert queue, reading the
    # exact precomputed rows from metrics.json's budget_curve /
    # incident_budget_curve (src/evaluate.py). Never a live recompute of
    # dedup/classification -- an honest re-slice / table lookup of what the
    # last `python run_pipeline.py --budget ...` run actually produced.
    st.markdown("#### Alert budget")
    _default_budget = o.get("alert_budget_used", C.ALERT_BUDGET)
    _levels = available_budgets(metrics, _default_budget)
    if "p_budget" not in st.session_state:
        # Fresh session: open on the dashboard's display default
        # (config.DASHBOARD_DEFAULT_BUDGET, 2%) rather than necessarily the
        # pipeline's own calibration budget (1%, kept separate to match the
        # problem statement's stated example and keep every headline number
        # in README.md/FIXES.md reproducible as documented).
        st.session_state.p_budget = (C.DASHBOARD_DEFAULT_BUDGET
                                     if C.DASHBOARD_DEFAULT_BUDGET in _levels
                                     else _default_budget)
    elif st.session_state.p_budget not in _levels:
        # A previously valid selection became stale (e.g. metrics.json was
        # regenerated with a different budget sweep) -- fall back safely.
        st.session_state.p_budget = _default_budget
    budget = st.select_slider(
        "current alert budget", options=_levels,
        value=st.session_state.p_budget,
        format_func=lambda b: f"{b*100:.2g}%", key="w_budget")
    st.session_state.p_budget = budget
    _n_events = o.get("n_events", 0)
    st.caption(
        f"Analyst reviews the top {budget*100:.2g}% of scored events "
        f"(~{int(round(budget * _n_events)):,} of {_n_events:,}). "
        + ("This is the budget the last pipeline run was generated at."
           if abs(budget - _default_budget) < 1e-9 else
           f"Pipeline was generated at {_default_budget*100:.2g}% — "
           f"metrics below re-read the precomputed row for {budget*100:.2g}%; "
           f"the alert queue is a prefix of that run's ranked incidents, not "
           f"a live recompute (see Alert queue page)."))
    st.markdown("---")

st.title("Behavioural anomaly detection \u2014 analyst console")

# ===========================================================================
# PAGE: Overview
# ===========================================================================
if page == "Overview":
    st.caption("System status at a glance. Start here.")

    bcur = budget_row(metrics, "budget_curve", budget)
    icur = budget_row(metrics, "incident_budget_curve", budget)
    # At the budget the pipeline actually ran at, use the exact `overall`
    # figures (bcur/icur are the same numbers via a different table, but
    # `overall` also carries pr_auc/roc_auc which the per-budget tables
    # don't). At any OTHER selected budget, fall back to the swept table --
    # a real precomputed row, never fabricated.
    at_default = abs(budget - o.get("alert_budget_used", C.ALERT_BUDGET)) < 1e-9
    prec = o.get("precision_at_budget") if at_default else bcur.get("precision_at_budget")
    rec = o.get("recall_at_budget") if at_default else bcur.get("recall_at_budget")
    n_alerts_at_budget = icur.get("n_alerts", bcur.get("n_alerts", len(alerts)))

    c = st.columns(6)
    c[0].metric("events scored", f"{o.get('n_events', 0):,}")
    c[1].metric(f"alerts @ {budget*100:.2g}%", f"{n_alerts_at_budget:,}")
    c[2].metric("PR-AUC", o.get("pr_auc", "\u2014"))
    c[3].metric(f"precision @{budget*100:.2g}%", prec if prec is not None else "\u2014")
    c[4].metric(f"recall @{budget*100:.2g}% (events)", rec if rec is not None else "\u2014")
    if icur:
        rate = icur.get("incident_recall")
        c[5].metric(f"incidents caught @{budget*100:.2g}%",
                    f"{icur.get('incidents_detected', 0)}/{icur.get('incidents_total', 0)}",
                    f"{rate:.0%}" if rate is not None else None)
    else:
        c[5].metric("false positive rate", o.get("false_positive_rate", "\u2014"))

    st.markdown(
        "<div class='app-card'>"
        "<b>Read this number as the headline, not event-level recall.</b> "
        f"The alert budget (sidebar) is currently set to the top "
        f"{budget*100:.2g}% of events (a realistic analyst "
        "workload), so event-level recall has an arithmetic ceiling once "
        "one attack produces far more events than the budget has slots "
        "for. <b>Incident recall</b> \u2014 did the analyst queue contain "
        "at least one alert for every attack campaign \u2014 is the "
        "number that reflects operational detection quality."
        "</div>", unsafe_allow_html=True)

    st.markdown("#### Is the queue saturated, or is that just the top slice?")
    st.markdown(
        "<div class='section-caption'>Your alert queue is, by definition, "
        "the riskiest 1% of events \u2014 so it clusters near the top of "
        "the 0\u2013100 scale. That's the review-budget mechanism working "
        "correctly, not the model saturating. The full population "
        "(right) shows a clean, well-spread distribution.</div>",
        unsafe_allow_html=True)
    fig_path = C.FIGURES / "risk_distribution.png"
    if fig_path.exists():
        st.image(str(fig_path), use_container_width=True)
    else:
        st.info("Run `python run_pipeline.py` to generate this figure.")

    st.markdown("#### Problem-statement coverage")
    cov = pd.DataFrame([
        {"requirement": "Sequential data (patterns over time, not single events)",
         "status": "\u2705", "where": "sequence autoencoder over 12-event windows (src/detect.py)"},
        {"requirement": "Extreme class imbalance",
         "status": "\u2705", "where": "unsupervised detection + classifier trained only on flagged events (src/classify.py)"},
        {"requirement": "Concept drift",
         "status": "\u2705", "where": "EWMA baseline updates + PSI drift monitor (src/baseline.py)"},
        {"requirement": "Explainability",
         "status": "\u2705", "where": "per-alert reason, attack-type evidence, next-step action (src/explain.py)"},
        {"requirement": "Cold start",
         "status": "\u2705", "where": "peer-group prior with Bayesian shrinkage (src/baseline.py)"},
        {"requirement": "Real-time + batch, no train/serve skew",
         "status": "\u2705", "where": "shared StreamingFeatureExtractor (src/features.py)"},
        {"requirement": "Baseline poisoning resistance",
         "status": "\u2705", "where": "only sub-threshold events update the profile (src/baseline.py)"},
        {"requirement": "Dynamic, runtime-configurable alert budget",
         "status": "\u2705", "where": "Detector.threshold_for_budget (src/detect.py); sidebar control on this page"},
        {"requirement": "Multiple real-time input modes, one detection pipeline",
         "status": "\u2705", "where": "CSV replay / folder watcher / REST / WebSocket / Kafka & MQTT interfaces (src/adapters.py)"},
        {"requirement": "Live, auto-refreshing analyst view",
         "status": "\u2705", "where": "Live Monitor page (st.fragment) reading report/live_state.json"},
    ])
    st.dataframe(cov, use_container_width=True, hide_index=True)

# ===========================================================================
# PAGE: Alert queue
# ===========================================================================
elif page == "Alert queue":
    if not alerts:
        st.info("No alerts.")
    else:
        # `alerts` is already in queue-priority order (incident_scores rank,
        # src/evaluate.py) from the last pipeline run, at whatever budget it
        # was generated with. A SMALLER selected budget is always an exact
        # prefix of that same ranked list -- a genuine re-slice, not a
        # recompute. A LARGER one can't be conjured from data that was never
        # generated -- say so plainly instead of inventing rows.
        _default_budget = o.get("alert_budget_used", C.ALERT_BUDGET)
        n_slots_at_budget = int(round(budget * o.get("n_events", len(alerts))))
        alerts_at_budget = alerts[: min(n_slots_at_budget, len(alerts))]
        if n_slots_at_budget > len(alerts):
            st.warning(
                f"Budget {budget*100:.2g}% would include ~{n_slots_at_budget:,} "
                f"alerts, but the last pipeline run (at {_default_budget*100:.2g}%) "
                f"only generated {len(alerts):,}. Showing all {len(alerts):,} "
                f"available below. Re-run `python run_pipeline.py --budget "
                f"{budget}` to materialise the full queue at this budget.")
        adf = pd.DataFrame(alerts_at_budget)
        all_kinds = sorted(adf.predicted_class.unique())
        # These filter widgets live inside a page-conditional block, so
        # Streamlit unmounts them whenever the analyst navigates to another
        # page and remounts them on return. Relying on Streamlit's own
        # key<->session_state binding across that unmount/remount is the
        # usual cause of a filter that "sometimes" resets or stops
        # responding -- so instead of trusting it, persistence is handled
        # explicitly here: each filter's real value lives under its own
        # "p_*" slot in session_state, which this code reads and writes
        # itself on every render. The widget's own `key` only has to
        # survive a single page's lifetime, not a round trip through other
        # pages, so it can't desync.
        def _persisted(slot, default):
            if slot not in st.session_state:
                st.session_state[slot] = default
            return st.session_state[slot]

        with st.sidebar:
            st.markdown("#### Filters")
            lo = st.slider("minimum risk", 0, 100,
                           value=_persisted("p_min_risk", 0), step=1,
                           key="w_min_risk")
            st.session_state.p_min_risk = lo
            kinds = st.multiselect(
                "attack type", all_kinds,
                default=_persisted("p_kinds", all_kinds), key="w_kinds")
            st.session_state.p_kinds = kinds
            hide_lc = st.checkbox(
                "hide low-confidence (cold-start) entities",
                value=_persisted("p_hide_lc", False), key="w_hide_lc")
            st.session_state.p_hide_lc = hide_lc
            hide_filler = st.checkbox(
                "show only threshold-clearing incidents (hide budget filler)",
                value=_persisted("p_hide_filler", False), key="w_hide_filler")
            st.session_state.p_hide_filler = hide_filler
            search = st.text_input(
                "search (alert id / entity / IP / resource)",
                value=_persisted("p_search", ""), key="w_search",
                placeholder="e.g. A00012345 or user_0042")
            st.session_state.p_search = search
            st.caption(
                "Cold-start entities are scored against their peer-group prior "
                "and routed separately so they cannot flood the queue. "
                "'Budget filler' alerts filled out the analyst's review budget "
                "from lower-risk incidents once genuine threshold-clearing "
                "incidents ran out \u2014 rarer attack types (device spoofing, "
                "low-and-slow exfil) mostly live in this zone, alongside "
                "some events that are statistically unusual but benign.")

        # Every widget above has an explicit `key`, so its value lives in
        # `st.session_state` under that key and survives reruns triggered by
        # ANY other widget (page nav, entity picker, buttons) instead of only
        # a rerun the widget itself caused -- the usual cause of a Streamlit
        # sidebar filter that "sometimes" seems to stop responding.
        f = adf[(adf.risk_score >= lo) & (adf.predicted_class.isin(kinds))]
        if hide_lc:
            f = f[~f.low_confidence_entity]
        if hide_filler:
            f = f[f.cleared_threshold]
        if search.strip():
            q = search.strip().lower()
            searchable = (f["alert_id"].str.lower() + " " +
                         f["entity_id"].astype(str).str.lower() + " " +
                         f["source_ip"].astype(str).str.lower() + " " +
                         f["resource_accessed"].astype(str).str.lower())
            f = f[searchable.str.contains(q, regex=False)]

        st.subheader(f"{len(f)} alerts")
        left, right = st.columns([1, 1.4], gap="large")

        with left:
            show = f[["alert_id", "risk_score", "entity_id", "predicted_class",
                      "cleared_threshold", "timestamp"]].rename(
                          columns={"cleared_threshold": "confirmed_incident"}
                      ).sort_values("risk_score", ascending=False)
            show["risk_score"] = show["risk_score"].round(1)
            show.insert(2, "severity", show["risk_score"].map(severity_label))
            st.dataframe(show, use_container_width=True, height=560,
                         hide_index=True)
            st.download_button(
                "\u2b07 export filtered queue to CSV",
                data=show.to_csv(index=False).encode("utf-8"),
                file_name="alert_queue_filtered.csv", mime="text/csv",
                use_container_width=True, key="dl_alerts_csv")

        with right:
            if not len(f):
                st.info("No alerts match these filters.")
            else:
                # `options` is derived from the FILTERED set `f`, so it
                # shrinks/changes every time another sidebar widget changes.
                # A selectbox with a static `key` whose remembered value has
                # fallen out of the current options list raises
                # StreamlitAPIException instead of just re-defaulting -- the
                # actual mechanism behind "filters occasionally stop
                # responding". Clamp the stored value BEFORE instantiating
                # the widget so it always has a valid key.
                options = (f.sort_values("risk_score", ascending=False)
                           .alert_id.tolist())
                if st.session_state.get("flt_inspect_pick") not in options:
                    st.session_state.flt_inspect_pick = options[0]
                pick = st.selectbox("Inspect alert", options,
                                    key="flt_inspect_pick")
                a = f[f.alert_id == pick].iloc[0].to_dict()
                col = risk_colour(a["risk_score"])

                pills = ""
                if not a.get("cleared_threshold", True):
                    pills += "<span class='pill pill-filler'>budget filler</span>"
                if a.get("low_confidence_entity"):
                    pills += "<span class='pill pill-cold'>cold-start entity</span>"
                if a.get("low_confidence_classification"):
                    pills += "<span class='pill pill-conf'>low classifier confidence</span>"

                mitre = MITRE_MAP.get(a["predicted_class"])
                mitre_txt = (f"<span style='color:#5f6368;font-size:0.82rem'>"
                            f"MITRE ATT&amp;CK {mitre[0]} — {mitre[1]}</span>"
                            if mitre else "")
                st.markdown(
                    f"<div class='alert-header' style='border-left:6px solid {col};'>"
                    f"<div style='display:flex;align-items:baseline;gap:14px;'>"
                    f"{risk_badge(a['risk_score'])}"
                    f"{severity_pill(a['risk_score'])}"
                    f"<span style='font-size:1.15rem;font-weight:700'>"
                    f"{a['predicted_class'].replace('_',' ').title()}</span>"
                    f"<span style='color:#5f6368'>confidence {a['class_confidence']:.0%}</span>"
                    f"</div><div style='margin-top:8px'>{pills}</div>"
                    f"<div style='margin-top:4px'>{mitre_txt}</div>"
                    f"</div>", unsafe_allow_html=True)

                if not a.get("cleared_threshold", True):
                    st.warning("Budget filler \u2014 this incident's risk score did "
                              "not clear the calibrated alert threshold. Included "
                              "so rarer attack types stay visible within the "
                              "analyst budget, but it is not a confirmed "
                              "high-risk incident the way a threshold-clearing "
                              "alert is.")
                if a.get("low_confidence_entity"):
                    st.warning("Cold-start entity \u2014 limited history, "
                               "scored against its peer-group prior.")
                if a.get("low_confidence_classification"):
                    alt = a.get("runner_up_class")
                    alt_txt = (f" Runner-up guess: **{alt}** "
                              f"({a.get('runner_up_confidence', 0):.0%}).") if alt else ""
                    st.warning(f"Low classifier confidence on the attack-type label "
                              f"({a['class_confidence']:.0%}) \u2014 treat "
                              f"**{a['predicted_class']}** as tentative.{alt_txt}")

                tab_why, tab_type, tab_evidence, tab_action, tab_raw, tab_notes = st.tabs(
                    ["Why flagged", "Why this type", "Feature evidence",
                     "Next step", "Event detail", "Analyst notes"])

                with tab_why:
                    st.markdown("Why this event was flagged as anomalous at all "
                               "(independent of attack type):")
                    st.info(a["reason_text"])

                with tab_type:
                    st.caption("Classifier probability for every known attack "
                              "type. An event already in the queue gets its "
                              "closest-matching attack label, never "
                              "\u201cnormal\u201d \u2014 the tallest bar always "
                              "matches the predicted class above.")
                    cp = a.get("class_probabilities") or {}
                    if cp:
                        cp_s = pd.Series(cp, name="probability") \
                            .sort_values(ascending=False)
                        st.bar_chart(cp_s, height=260)
                    asf = a.get("attack_signal_factors") or []
                    if asf and a["predicted_class"] not in ("normal", "unclassified"):
                        st.markdown(f"**Features that drove the "
                                   f"\u201c{a['predicted_class'].replace('_',' ')}\u201d "
                                   f"call:**")
                        cf = pd.DataFrame(asf)
                        st.bar_chart(cf.set_index("meaning")["contribution"], height=220)

                with tab_evidence:
                    st.caption("Deviation from this entity's own baseline, "
                              "independent of attack type \u2014 answers "
                              "\u201cwhy is this unusual at all\u201d.")
                    tf = pd.DataFrame(a["top_factors"])
                    if len(tf):
                        st.bar_chart(tf.set_index("meaning")["contribution"], height=260)
                    else:
                        st.write("No dominant single feature \u2014 evidence is spread "
                                "thin across the profile.")

                with tab_action:
                    st.caption("Concrete next step for the analyst reviewing "
                              "this alert.")
                    st.success(a.get("recommended_action",
                                     "Review the anomaly evidence manually."))

                with tab_raw:
                    detail = {k: a[k] for k in
                             ["entity_id", "entity_type", "timestamp", "source_ip",
                              "geo_location", "resource_accessed"]}
                    st.table(pd.DataFrame(
                        [{"field": k.replace("_", " "), "value": v}
                         for k, v in detail.items()]).set_index("field"))

                with tab_notes:
                    st.caption("Freeform notes for this alert, appended to "
                              "report/analyst_feedback.jsonl alongside the "
                              "true/false-positive verdict below — the "
                              "same feedback file the report already names "
                              "as the obvious next step for a training loop "
                              "(ASSUMPTIONS.md, known limitations).")
                    note_text = st.text_area(
                        "Add a note", key=f"note_input_{pick}",
                        placeholder="e.g. confirmed with entity owner, "
                                    "travel was pre-approved ...",
                        label_visibility="collapsed")
                    if st.button("Save note", key=f"note_save_{pick}",
                                use_container_width=True):
                        if note_text.strip():
                            p = C.REPORT / "analyst_feedback.jsonl"
                            with open(p, "a") as fh:
                                fh.write(json.dumps({
                                    "alert_id": a["alert_id"],
                                    "note": note_text.strip(),
                                    "saved_at": pd.Timestamp.now().isoformat(),
                                }) + "\n")
                            st.success("Note saved.")
                        else:
                            st.warning("Note is empty — nothing saved.")
                    fb_path = C.REPORT / "analyst_feedback.jsonl"
                    if fb_path.exists():
                        past = [json.loads(l) for l in fb_path.read_text().splitlines()
                               if l.strip()]
                        past_notes = [p for p in past
                                     if p.get("alert_id") == a["alert_id"] and p.get("note")]
                        if past_notes:
                            st.markdown("**Previous notes on this alert:**")
                            for pn in past_notes[-5:]:
                                st.markdown(f"- {pn['note']}  "
                                          f"<span style='color:#5f6368;font-size:0.78rem'>"
                                          f"({pn.get('saved_at', '')[:19]})</span>",
                                          unsafe_allow_html=True)

                fb = st.columns(2)
                if fb[0].button("Mark as false positive", key=f"fp_{pick}",
                               use_container_width=True):
                    p = C.REPORT / "analyst_feedback.jsonl"
                    with open(p, "a") as fh:
                        fh.write(json.dumps({"alert_id": a["alert_id"],
                                             "verdict": "false_positive"}) + "\n")
                    st.success("Recorded \u2014 feeds threshold retuning.")
                if fb[1].button("Confirm true positive", key=f"tp_{pick}",
                               use_container_width=True):
                    p = C.REPORT / "analyst_feedback.jsonl"
                    with open(p, "a") as fh:
                        fh.write(json.dumps({"alert_id": a["alert_id"],
                                             "verdict": "true_positive"}) + "\n")
                    st.success("Recorded \u2014 escalated.")

# ===========================================================================
# PAGE: Entity view
# ===========================================================================
elif page == "Entity view":
    if scored.empty:
        st.info("Run the pipeline to populate entity history.")
    else:
        with st.sidebar:
            st.markdown("#### Entity")
            ent = st.selectbox("Select entity", sorted(scored.entity_id.unique()),
                               key="entity_pick")

        h = scored[scored.entity_id == ent].sort_values("timestamp")
        k = st.columns(4)
        k[0].metric("events", f"{len(h):,}")
        k[1].metric("max risk", f"{h.risk_score.max():.1f}")
        k[2].metric("flagged", int(h.flagged.sum()))
        k[3].metric("cold start", "yes" if h.low_confidence.any() else "no")

        st.markdown("#### Risk over time")
        st.line_chart(h.set_index("timestamp")["risk_score"], height=280)

        if len(events):
            e = events[events.entity_id == ent]
            st.markdown("#### Learned normal behaviour")
            n1, n2 = st.columns(2, gap="large")
            with n1:
                st.write("**Usual active hours**")
                st.bar_chart(pd.to_datetime(e.timestamp).dt.hour
                             .value_counts().sort_index(), height=220)
                st.write("**Known devices**")
                st.dataframe(e.device_fingerprint.value_counts().head(5)
                            .rename("events").reset_index()
                            .rename(columns={"index": "device_fingerprint"}),
                            use_container_width=True, hide_index=True)
            with n2:
                st.write("**Most-used resources**")
                st.bar_chart(e.resource_accessed.value_counts().head(8), height=220)
                st.write("**Locations seen**")
                locs = e.geo_location.map(lambda g: parse_geo(g)[0]).value_counts()
                st.dataframe(locs.rename("events").reset_index()
                            .rename(columns={"index": "city"}),
                            use_container_width=True, hide_index=True)

        st.markdown("#### Flagged events for this entity")
        flagged_h = h[h.flagged][["timestamp", "risk_score", "label"]].copy()
        flagged_h["risk_score"] = flagged_h["risk_score"].round(1)
        if len(flagged_h):
            st.dataframe(flagged_h, use_container_width=True, hide_index=True)
        else:
            st.caption("No flagged events for this entity in the scored window.")

# ===========================================================================
# PAGE: Model performance
# ===========================================================================
elif page == "Model performance":
    # Reactive to the sidebar's alert-budget control, same pattern as
    # Overview: at the budget the pipeline actually ran at, use `overall`
    # (it also carries pr_auc/roc_auc, which are budget-independent ranking
    # metrics and aren't in the per-budget sweep tables); at any OTHER
    # selected budget, fall back to the precomputed budget_curve /
    # incident_budget_curve row. Every number shown is a real precomputed
    # value, never invented for a budget that wasn't actually evaluated.
    bcur_mp = budget_row(metrics, "budget_curve", budget)
    icur_mp = budget_row(metrics, "incident_budget_curve", budget)
    at_default_mp = abs(budget - o.get("alert_budget_used", C.ALERT_BUDGET)) < 1e-9
    prec_mp = o.get("precision_at_budget") if at_default_mp else bcur_mp.get("precision_at_budget")
    rec_mp = o.get("recall_at_budget") if at_default_mp else bcur_mp.get("recall_at_budget")
    fpr_mp = o.get("false_positive_rate") if at_default_mp else bcur_mp.get("false_positive_rate")

    st.markdown("### Headline")
    hc = st.columns(5)
    hc[0].metric("PR-AUC", o.get("pr_auc", "\u2014"))
    hc[1].metric("ROC-AUC", o.get("roc_auc", "\u2014"))
    hc[2].metric(f"precision @{budget*100:.2g}%", prec_mp if prec_mp is not None else "\u2014")
    hc[3].metric(f"recall @{budget*100:.2g}% (events)", rec_mp if rec_mp is not None else "\u2014")
    hc[4].metric("false positive rate", fpr_mp if fpr_mp is not None else "\u2014")
    st.caption(
        "ROC-AUC and PR-AUC are budget-independent ranking-quality metrics "
        "(computed over the whole test window), so they don't change with "
        "the sidebar's alert-budget control \u2014 everything else on this row "
        "does. ROC-AUC is expected to look strong and is less meaningful at "
        "this class imbalance (~3% positive in the test window); PR-AUC and "
        "the budget metrics are what the model is tuned and judged on.")

    if icur_mp:
        st.markdown(f"### Incident-level detection @ {budget*100:.2g}% budget")
        st.caption("Did we catch the attack at all? A brute-force burst is one "
                   "incident to investigate, not 130 separate alerts.")
        ic1, ic2, ic3 = st.columns(3)
        ic1.metric("incidents caught",
                  f"{icur_mp.get('incidents_detected', 0)}/{icur_mp.get('incidents_total', 0)}")
        ic2.metric("incident recall", f"{icur_mp.get('incident_recall', 0):.0%}")
        ic3.metric("queue purity", f"{icur_mp.get('queue_precision', 0):.1%}")

    if metrics.get("incident_recall"):
        st.markdown("### Incident-level detection, per attack type")
        st.caption(
            f"Per-attack-type breakdown is computed at the budget the "
            f"pipeline was actually run at ({o.get('alert_budget_used', C.ALERT_BUDGET)*100:.2g}%) "
            "\u2014 re-run `python run_pipeline.py --budget X` for a per-type "
            "breakdown at a different budget. The aggregate totals above "
            "this table DO update live with the sidebar control.")
        st.dataframe(pd.DataFrame(metrics["incident_recall"]),
                     use_container_width=True, hide_index=True)

    if metrics.get("per_attack_queue"):
        st.markdown("### Attack presence in the deduplicated analyst queue")
        st.caption("What an analyst actually reviews \u2014 raw event-level "
                  "recall alone badly under-represents every attack type "
                  "except the burstiest, since one campaign can emit "
                  "hundreds of individually-flaggable events.")
        st.dataframe(pd.DataFrame(metrics["per_attack_queue"]),
                     use_container_width=True, hide_index=True)

    if metrics.get("ablation_components"):
        st.markdown("### Ablation \u2014 what each component contributes")
        st.dataframe(pd.DataFrame(metrics["ablation_components"]),
                     use_container_width=True, hide_index=True)

    cs = metrics.get("cold_start")
    if cs:
        st.markdown("### Cold start")
        st.write(f"{cs['n_cold_events']:,} events from entities with limited history")
        st.dataframe(pd.DataFrame([
            {"variant": "with peer-group prior",
             "pr_auc": cs["with_peer_prior"]["pr_auc"]},
            {"variant": "without peer-group prior",
             "pr_auc": cs["without_peer_prior"]["pr_auc"]},
        ]), use_container_width=True, hide_index=True)

    d = metrics.get("drift")
    if d:
        st.markdown("### Concept drift")
        dc = st.columns(2)
        dc[0].metric("drift detected", "yes" if d.get("detected") else "no")
        if "benign_drift_false_alarm_rate" in d:
            dc[1].metric("false alarms on legitimate drift",
                        f"{d['benign_drift_false_alarm_rate']:.1%}")
        st.caption("Top drifted features: "
                  + (", ".join(d.get("top_drifted", [])) or "none"))

    st.markdown("### Figures")
    cols = st.columns(2)
    figs = sorted(p for p in C.FIGURES.glob("*.png") if p.stem != "risk_distribution")
    for i, p in enumerate(figs):
        cols[i % 2].image(str(p), caption=p.stem.replace("_", " "),
                          use_container_width=True)

# ===========================================================================
# PAGE: Real-time replay
# ===========================================================================
elif page == "Real-time replay":
    st.caption(
        "This replays `run_realtime.py`'s streaming scorer \u2014 the same "
        "feature and scoring code as the batch pipeline, fed one event at "
        "a time, as a Kafka consumer would see it. There is no separate "
        "web server: the CLI script writes `report/alerts_realtime.jsonl` "
        "and `report/realtime_stats.json`, which this page reads.")

    stats, rt_alerts = load_realtime()

    with st.sidebar:
        st.markdown("#### Run a live demo")
        n_events_total = max(len(events), 1000)
        # Same explicit-persistence pattern as the Alert queue filters --
        # see the comment there for why this page-conditional block can't
        # just trust Streamlit's own key<->session_state binding across a
        # navigate-away-and-back remount.
        if "p_n_limit" not in st.session_state:
            st.session_state.p_n_limit = min(5000, n_events_total)
        n_limit = st.number_input("events to replay", min_value=500,
                                  max_value=n_events_total,
                                  value=min(st.session_state.p_n_limit, n_events_total),
                                  step=500, key="w_n_limit")
        st.session_state.p_n_limit = n_limit
        run_now = st.button("\u25b6 Run replay now", use_container_width=True,
                            key="rt_run_now")
        st.caption("Runs `run_realtime.py` locally with the trained models "
                  "in `models/pipeline.joblib`. Takes a few seconds to a "
                  "couple of minutes depending on the event count.")

    if run_now:
        if not (C.MODELS / "pipeline.joblib").exists():
            st.error("No trained models found. Run `python run_pipeline.py` first.")
        else:
            with st.spinner(f"Replaying {n_limit:,} events ..."):
                result = subprocess.run(
                    [sys.executable, "run_realtime.py", "--limit", str(int(n_limit)),
                     "--budget", str(budget), "--quiet"],
                    cwd=str(C.ROOT), capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=600)
            if result.returncode == 0:
                st.success("Replay complete.")
                load_realtime.clear()
                stats, rt_alerts = load_realtime()
            else:
                st.error("Replay failed \u2014 see details below.")
                st.code(result.stderr[-3000:] or result.stdout[-3000:])

    if not stats:
        st.info("No real-time run recorded yet. Run "
               "`python run_realtime.py` from the project root, or use "
               "**Run replay now** in the sidebar.")
    else:
        c = st.columns(5)
        c[0].metric("events processed", f"{stats.get('events_processed', 0):,}")
        c[1].metric("alerts raised", f"{stats.get('alerts_raised', 0):,}",
                    f"{stats.get('alert_rate_pct', 0)}%")
        c[2].metric("median latency", f"{stats.get('latency_ms_median', 0)} ms")
        c[3].metric("p99 latency", f"{stats.get('latency_ms_p99', 0)} ms")
        c[4].metric("throughput", f"{stats.get('throughput_events_per_sec', 0):,}/s")

        thr = stats.get("alert_threshold")
        if stats.get("calibrated_from_stream"):
            st.caption(f"Alert threshold (risk ≥ {thr}) was re-calibrated from "
                      "this stream's own risk-score distribution "
                      "(`--calib-events`), not just inherited from the batch "
                      "run — see ASSUMPTIONS.md \"Dynamic alert budget\".")
        else:
            st.caption(f"Alert threshold (risk ≥ {thr}) is the batch-calibrated "
                      "one, inherited as-is. Batch and streaming score "
                      "distributions are not numerically identical "
                      "(ASSUMPTIONS.md) — pass `--calib-events N` to "
                      "`run_realtime.py` to calibrate it against this "
                      "stream's own scores instead.")

        notices = stats.get("drift_notices") or []
        if notices:
            st.warning(f"{len(notices)} concept-drift notice(s) raised during "
                      "the replay (system-level, not per-event alerts).")
            st.dataframe(pd.DataFrame([
                {"at_event": d["at_event"],
                 "drifted_features": ", ".join(d["drifted_features"])}
                for d in notices]), use_container_width=True, hide_index=True)
        else:
            st.caption("No concept drift detected during this replay window.")

        if rt_alerts:
            st.markdown(f"### {len(rt_alerts)} alerts raised during replay")
            rdf = pd.DataFrame(rt_alerts)
            rdf["timestamp"] = pd.to_datetime(rdf["timestamp"])
            st.line_chart(rdf.set_index("timestamp")["risk_score"]
                         .rename("risk score at alert time"), height=260)

            show = rdf[["alert_id", "risk_score", "entity_id",
                       "predicted_class", "timestamp"]] \
                .sort_values("timestamp", ascending=False)
            show["risk_score"] = show["risk_score"].round(1)
            st.dataframe(show, use_container_width=True, height=360, hide_index=True)

            rt_options = rdf.alert_id.tolist()
            if st.session_state.get("rt_inspect_pick") not in rt_options:
                st.session_state.rt_inspect_pick = rt_options[0]
            pick = st.selectbox("Inspect a streamed alert", rt_options,
                                key="rt_inspect_pick")
            row = rdf[rdf.alert_id == pick].iloc[0].to_dict()
            st.markdown(
                f"<div class='alert-header' style='border-left:6px solid "
                f"{risk_colour(row['risk_score'])};'>"
                f"{risk_badge(row['risk_score'])} &nbsp;"
                f"<b>{row['predicted_class'].replace('_',' ').title()}</b>"
                f"</div>", unsafe_allow_html=True)
            st.info(row.get("reason_text", ""))
            if row.get("recommended_action"):
                st.success(row["recommended_action"])
        else:
            st.caption("No alerts were raised in this replay window.")

# ===========================================================================
# PAGE: Live Monitor
# ===========================================================================
elif page == "Live Monitor":
    st.caption(
        "Auto-refreshing view of a long-running `python run_realtime.py "
        "--serve` process (any --stream-source: csv loop / folder watcher / "
        "REST / Kafka / MQTT -- see README.md). This page only reads "
        "report/live_state.json; it does not run any detection itself, so "
        "it stays responsive regardless of stream volume.")

    live_path = C.REPORT / "live_state.json"
    if not live_path.exists():
        st.info(
            "No live run detected yet. Start one in another terminal, e.g.\n\n"
            "```\npython run_realtime.py --stream-source rest --serve\n```\n"
            "then POST events:\n\n"
            "```\ncurl -X POST http://127.0.0.1:8765/events "
            "-d '{\"entity_id\": \"U0001\", \"timestamp\": \"2026-07-01T09:00:00\", "
            "\"resource_accessed\": \"/repo/api\"}'\n```\n\n"
            "or watch a folder instead:\n\n"
            "```\npython run_realtime.py --stream-source folder "
            "--watch-dir data/live_drop --serve\n```\n"
            "then drop a `.json` file with the same shape into that folder.")
        st.stop()

    # A `st.fragment` re-runs only this block on its own timer, not the
    # whole page -- the rest of the dashboard (sidebar, other widgets)
    # doesn't flicker or lose state every couple of seconds because of it.
    @st.fragment(run_every=2)
    def _live_monitor():
        try:
            state = json.loads(live_path.read_text())
        except (json.JSONDecodeError, OSError):
            st.warning("live_state.json is being written right now -- "
                      "refreshing shortly.")
            return

        age_s = time.time() - state.get("updated_at", 0)
        if age_s > 15:
            st.error(f"● stale -- {age_s:.0f}s since the last update from "
                     "the streaming process (is it still running?)")
        else:
            st.success(f"● live -- updated {age_s:.1f}s ago "
                      f"(uptime {state.get('uptime_s', 0):,.0f}s)")

        c = st.columns(6)
        c[0].metric("events processed", f"{state.get('events_processed', 0):,}")
        c[1].metric("alerts raised", f"{state.get('alerts_raised', 0):,}")
        c[2].metric("active entities",
                    f"{state.get('active_entities', 0)}/{state.get('known_entities', 0)}")
        c[3].metric("throughput", f"{state.get('throughput_events_per_sec', 0):,}/s")
        b = state.get("alert_budget")
        c[4].metric("current alert budget",
                    f"{b*100:.2g}%" if b is not None else "fixed threshold",
                    f"risk ≥ {state.get('alert_threshold', '—')}")
        cpu, mem = state.get("cpu_percent"), state.get("memory_mb")
        c[5].metric("CPU / memory",
                    f"{cpu:.0f}% / {mem:,.0f} MB" if cpu is not None and mem is not None
                    else "install psutil")
        if state.get("calibrated_from_stream"):
            st.caption("Threshold re-calibrated from this stream's own risk "
                      "scores (`run_realtime.py --calib-events`), not just "
                      "inherited from the batch run.")

        c2 = st.columns(3)
        c2[0].metric("p50 latency", f"{state.get('latency_ms_p50', 0)} ms")
        c2[1].metric("p95 latency", f"{state.get('latency_ms_p95', 0)} ms")
        c2[2].metric("p99 latency", f"{state.get('latency_ms_p99', 0)} ms")

        left, right = st.columns(2, gap="large")
        with left:
            st.markdown("##### Live risk-score distribution")
            risks = state.get("recent_risk_scores") or []
            if risks:
                counts, edges = np.histogram(risks, bins=20, range=(0, 100))
                hist = pd.Series(counts, index=[f"{int(e)}" for e in edges[:-1]],
                                 name="events")
                st.bar_chart(hist, height=220)
                st.caption(f"last {len(risks)} scored events")
            else:
                st.caption("No events processed yet.")

            st.markdown("##### Live attack-type distribution")
            atc = state.get("attack_type_counts") or {}
            if atc:
                st.bar_chart(pd.Series(atc).sort_values(ascending=False)
                            .rename("alerts"), height=220)
            else:
                st.caption("No alerts raised yet.")

        with right:
            st.markdown("##### Alert trend / attack timeline")
            ra = state.get("recent_alerts") or []
            if ra:
                radf = pd.DataFrame(ra)
                radf["timestamp"] = pd.to_datetime(radf["timestamp"])
                st.line_chart(radf.set_index("timestamp")["risk_score"]
                             .rename("risk at alert time"), height=220)
            else:
                st.caption("No alerts raised yet.")

            st.markdown("##### Incident statistics")
            if atc:
                st.dataframe(pd.DataFrame(
                    [{"attack_type": k, "alerts": v} for k, v in
                     sorted(atc.items(), key=lambda t: -t[1])]),
                    use_container_width=True, hide_index=True, height=190)
            else:
                st.caption("No alerts raised yet.")

        st.markdown("##### Recent alerts")
        if ra:
            show = pd.DataFrame(ra)[["alert_id", "risk_score", "entity_id",
                                     "predicted_class", "timestamp"]] \
                .sort_values("timestamp", ascending=False)
            show["risk_score"] = show["risk_score"].round(1)
            st.dataframe(show, use_container_width=True, height=280, hide_index=True)
        else:
            st.caption("No alerts raised yet.")

        notices = state.get("drift_notices") or []
        if notices:
            st.warning(f"{len(notices)} concept-drift notice(s) raised during "
                      "this run (system-level, not per-event alerts).")

    _live_monitor()

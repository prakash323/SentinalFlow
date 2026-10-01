"""ML-4 audits: generator shortcuts, device-spoofing signals, attack-class coverage, near-duplicate incidents.

Everything here that reads labels of SEALED datasets is called only after the vault has unsealed them (post-freeze diagnostics; nothing feeds back).
"""
from __future__ import annotations

from collections import defaultdict, deque

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from . import common as K
from .common import ATTACKS, C
from eval_ml2 import metrics as M2
from eval_ml2.shortcuts import _best_stump
from eval_ml3 import evaluate as EV

PROD_PRIV = {"sudo", "exec", "delete", "download"}


def _is_private(ip: str) -> bool:
    """RFC1918 (10/8, 172.16/12, 192.168/16). NOTE: ML-2/ML-3's rule treated only 10.* and 192.168.* as private; this is the correct definition."""
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except ValueError:
            return False
    return False


def shortcut_frame(ev: pd.DataFrame, n_onb: int) -> pd.DataFrame:
    """Raw-field shortcuts per event (no model, no label). `ev` = the dataset's events in chronological order."""
    ip = ev["source_ip"].fillna("")
    ts = pd.to_datetime(ev["timestamp"])
    city = ev["geo_location"].fillna("").str.split("|").str[0]
    df = pd.DataFrame(index=ev.index)
    df["public_ip"] = (~ip.map(_is_private)).astype(float)
    df["failed_auth"] = (ev["auth_success"] == 0).astype(float)
    # generic foreign-city: differs from the entity's MODAL city during its own onboarding (label-free, dataset-agnostic)
    modal = city.iloc[:n_onb].groupby(ev["entity_id"].iloc[:n_onb]).agg(lambda s: s.mode().iloc[0])
    df["foreign_city_generic"] = (city != ev["entity_id"].map(modal)).astype(float)
    df["foreign_city_production_constants"] = (~city.isin(C.HOME_CITIES)).astype(float)
    cmd = ev["command_sequence"].fillna("")
    df["command_production_privileged"] = cmd.map(lambda s: float(any(t in PROD_PRIV for t in s.split("|") if t)))
    df["command_contains_sudo"] = cmd.str.contains("sudo").astype(float)
    df["sensitive_production_constants"] = ev["resource_accessed"].isin(C.SENSITIVE).astype(float)
    hour = ts.dt.hour + ts.dt.minute / 60.0
    df["hour_of_day"] = hour
    df["off_hours_band_22_to_05"] = ((hour >= 22) | (hour < 5)).astype(float)
    df["session_duration_s"] = ev["session_duration"].astype(float)
    gap = ts.groupby(ev["entity_id"]).diff().dt.total_seconds()
    df["log_gap_since_prev_event_s"] = np.log1p(gap.fillna(gap.median()).clip(lower=0))
    df["new_ip_for_entity"] = (~ev["source_ip"].duplicated().astype(bool)).astype(float)   # placeholder replaced below
    seen = defaultdict(set)
    v = np.zeros(len(ev))
    for i, (e, x) in enumerate(zip(ev["entity_id"].to_numpy(), ip.to_numpy())):
        v[i] = float(x not in seen[e])
        seen[e].add(x)
    df["new_ip_for_entity"] = v
    return df


def rule_masks(sd: pd.DataFrame) -> dict:
    r1 = (sd.public_ip > 0) | (sd.failed_auth > 0)
    r2 = r1 | (sd.foreign_city_generic > 0)
    r3 = r2 | (sd.command_production_privileged > 0) | ((sd.sensitive_production_constants > 0) & (sd.off_hours_band_22_to_05 > 0))
    r4 = r1 | (sd.new_ip_for_entity > 0)
    return {"R1: public IP OR failed auth": r1.to_numpy(), "R2: R1 OR city != entity's modal onboarding city": r2.to_numpy(),
            "R3: R2 OR production-privileged command OR (production-sensitive resource AND 22-05h)": r3.to_numpy(), "R4: R1 OR first-seen IP for entity": r4.to_numpy()}


def shortcut_audit(sd_eval: pd.DataFrame, labels, aid, fused, alert, incidents) -> dict:
    """Rules vs the model on one dataset's evaluation rows. `sd_eval`/labels/aid/fused/alert are aligned."""
    labels = np.asarray(labels, dtype=object)
    aid = np.asarray(aid, dtype=object)
    y = EV.is_attack(labels).astype(int)
    out = {"rules": {}, "single_field": {}}
    for nm, r in rule_masks(sd_eval).items():
        tp, fp = int((r & (y == 1)).sum()), int((r & (y == 0)).sum())
        row = {"alerts": int(r.sum()), "precision": tp / max(tp + fp, 1), "recall": tp / max(int(y.sum()), 1),
               "false_positive_rate": fp / max(int((y == 0).sum()), 1), "per_attack": {}}
        for t in ATTACKS:
            m = labels == t
            if m.any():
                ids = sorted(set(aid[m]) - {""})
                row["per_attack"][t] = {"events": int(m.sum()), "rule_flag_rate": float(r[m].mean()), "model_alert_rate": float(alert[m].mean()),
                                        "model_alert_rate_where_rule_silent": float(alert[m & ~r].mean()) if (m & ~r).any() else None,
                                        "events_rule_silent": int((m & ~r).sum()), "incidents": len(ids),
                                        "incidents_rule_flags_any": int(sum(r[aid == i].any() for i in ids)),
                                        "incidents_model_detects": int(sum(alert[aid == i].any() for i in ids)),
                                        "incidents_model_detects_where_rule_never_fires": int(sum(alert[aid == i].any() for i in ids if not r[aid == i].any())),
                                        "incidents_rule_never_fires": int(sum(not r[aid == i].any() for i in ids))}
        sil = ~r
        ys = y[sil]
        row["model_on_rule_silent_events"] = {"events": int(sil.sum()), "attack_events": int(ys.sum()),
                                              **({"pr_auc": M2.rank_metrics(ys, fused[sil])["pr_auc"], "roc_auc": M2.rank_metrics(ys, fused[sil])["roc_auc"],
                                                  "recall_at_threshold": float(alert[sil][ys == 1].mean())} if ys.sum() and (ys == 0).sum() else {})}
        out["rules"][nm] = row
    # best single raw field (AUC attack vs rest) - what a trivially simple detector reaches
    for col in sd_eval.columns:
        x = sd_eval[col].to_numpy(float)
        if np.ptp(x) == 0 or y.sum() == 0:
            continue
        auc = roc_auc_score(y, x)
        out["single_field"][col] = {"auc_strength": float(max(auc, 1 - auc)), "best_stump": _best_stump(y, x)}
    best = sorted(out["single_field"].items(), key=lambda kv: -kv[1]["auc_strength"])[:3]
    out["top3_single_fields"] = [{"field": k, "auc_strength": v["auc_strength"]} for k, v in best]
    return out


# ----------------------------------------------------------------------------------------------------------- device spoofing
DEVICE_SIGNAL_CATALOGUE = [
    {"signal": "device_fingerprint string (OS|MAC|protocol)", "in_current_schema": True, "observable_in_real_telemetry": "yes (NAC/DHCP/EDR/agent inventory), partly spoofable",
     "generator_specific": "the value semantics are: exactly one stable string per entity, changed only by attacks and by explicit refresh events", "verdict": "available; kept as-is"},
    {"signal": "fingerprint concurrency (same fingerprint seen from >=2 source IPs within minutes)", "in_current_schema": True,
     "observable_in_real_telemetry": "yes - derivable from (fingerprint, source_ip, timestamp) already in every event", "generator_specific": "no, but dynamic-IP / VPN users create benign concurrency",
     "verdict": "candidate (needs a benign-concurrency measurement; see coverage below)"},
    {"signal": "TLS client fingerprint (JA3/JA4)", "in_current_schema": False, "observable_in_real_telemetry": "yes (Zeek/IDS/proxy), stable per client stack, spoofable by mimicry",
     "generator_specific": "no", "verdict": "candidate (requires a collector field)"},
    {"signal": "client certificate serial / thumbprint / issuer (mTLS, 802.1X)", "in_current_schema": False, "observable_in_real_telemetry": "yes for managed edge devices and service accounts",
     "generator_specific": "no", "verdict": "candidate (strong for edge/service, absent for password users)"},
    {"signal": "MAC OUI vs claimed OS/vendor", "in_current_schema": "partly (MAC inside the fingerprint string)", "observable_in_real_telemetry": "yes at layer-2 (DHCP/NAC); modern clients randomise MAC",
     "generator_specific": "yes in this data (MACs are random, OUIs carry no vendor information)", "verdict": "unsuitable on this data; conditional in reality (fixed IoT only)"},
    {"signal": "TCP/IP stack fingerprint (TTL, window, options) vs claimed OS", "in_current_schema": False, "observable_in_real_telemetry": "yes at a network sensor; unreliable behind proxies/NAT",
     "generator_specific": "no", "verdict": "candidate (noisy)"},
    {"signal": "switch port / VLAN / AP / network segment", "in_current_schema": False, "observable_in_real_telemetry": "yes for wired/Wi-Fi via NAC; not for VPN/remote",
     "generator_specific": "no", "verdict": "candidate for on-premise edge/OT"},
    {"signal": "hardware attestation / TPM measured boot / secure element", "in_current_schema": False, "observable_in_real_telemetry": "yes where deployed (managed fleets, modern IoT)",
     "generator_specific": "no", "verdict": "candidate (strongest, deployment-dependent)"},
    {"signal": "firmware / build version reported by heartbeat", "in_current_schema": False, "observable_in_real_telemetry": "yes for edge devices; changes legitimately on updates",
     "generator_specific": "no", "verdict": "candidate (needs update-event awareness)"},
    {"signal": "traffic cadence / inter-arrival regularity of periodic devices", "in_current_schema": "partly (timestamps -> interevent_gap_zscore)", "observable_in_real_telemetry": "yes",
     "generator_specific": "yes: only the OT profile has periodic devices", "verdict": "candidate for periodic devices only"},
    {"signal": "clock skew estimate", "in_current_schema": False, "observable_in_real_telemetry": "research-grade, needs high-resolution timestamps", "generator_specific": "n/a",
     "verdict": "unsuitable for production"},
    {"signal": "any generator ground truth (entity_profiles.json expected fingerprint, an 'is_spoofed' flag)", "in_current_schema": False, "observable_in_real_telemetry": "NO - an oracle",
     "generator_specific": "yes", "verdict": "UNSUITABLE (would leak the label; never used)"},
]


def fingerprint_concurrency(ev: pd.DataFrame, window_s: float = 600.0) -> np.ndarray:
    """1.0 where the event's (entity, fingerprint) was already used from a DIFFERENT source IP within `window_s` seconds. Raw fields only."""
    ts = pd.to_datetime(ev["timestamp"]).to_numpy().astype("datetime64[ns]").astype(np.int64) / 1e9
    ent, fp, ip = ev["entity_id"].to_numpy(), ev["device_fingerprint"].fillna("").to_numpy(), ev["source_ip"].fillna("").to_numpy()
    hist = defaultdict(deque)
    out = np.zeros(len(ev))
    for i in range(len(ev)):
        k = (ent[i], fp[i])
        q = hist[k]
        while q and ts[i] - q[0][0] > window_s:
            q.popleft()
        out[i] = float(any(p != ip[i] for _, p in q))
        q.append((ts[i], ip[i]))
    return out


def device_audit(did, ev, n_onb, X_eval, labels, aid, alert_by_model: dict, incidents) -> dict:
    """Signals for device spoofing on one dataset's evaluation rows. alert_by_model: name -> boolean alert array (evaluation rows)."""
    labels = np.asarray(labels, dtype=object)
    aid = np.asarray(aid, dtype=object)
    ev_eval = ev.iloc[n_onb:].reset_index(drop=True)
    fm = X_eval["fingerprint_mismatch"].to_numpy()
    fn = X_eval["fingerprint_novelty"].to_numpy()
    conc = fingerprint_concurrency(ev.reset_index(drop=True))[n_onb:]
    ds = labels == "device_spoofing"
    benign = np.isin(labels, ("normal", "benign_drift"))
    out = {"dataset": did, "device_spoofing_events": int(ds.sum()),
           "fingerprint_field_coverage": float((ev_eval["device_fingerprint"].fillna("") != "").mean()),
           "fingerprint_mismatch_fires_on_events": {"device_spoofing": int(fm[ds].sum()), "benign": int(fm[benign].sum()),
                                                    "precision_as_a_detector": float(ds[fm == 1].mean()) if (fm == 1).any() else None},
           "concurrency_signal": {"fires_on_device_spoofing_events": int(conc[ds].sum()), "fires_on_benign_events": int(conc[benign].sum()),
                                  "benign_fire_rate": float(conc[benign].mean()), "precision_as_a_detector": float(ds[conc == 1].mean()) if (conc == 1).any() else None},
           "per_variant": {}}
    for i in incidents:
        if i["type"] != "device_spoofing":
            continue
        m = aid == i["attack_id"]
        if not m.any():
            continue
        v = out["per_variant"].setdefault(i.get("variant", "unknown"), {"incidents": 0, "events": 0, "first_event_mismatch_fires": 0, "any_mismatch_fires": 0,
                                                                        "concurrency_fires_any": 0, "new_ip_incidents": 0, "detected": {k: 0 for k in alert_by_model}})
        v["incidents"] += 1
        v["events"] += int(m.sum())
        idx = np.where(m)[0]
        v["first_event_mismatch_fires"] += int(fm[idx[0]] == 1)
        v["any_mismatch_fires"] += int((fm[idx] == 1).any())
        v["concurrency_fires_any"] += int((conc[idx] == 1).any())
        v["new_ip_incidents"] += int(bool(i.get("new_ip")))
        for k, a in alert_by_model.items():
            v["detected"][k] += int(a[idx].any())
    out["variants_summary"] = {k: {**v, "first_event_mismatch_share": v["first_event_mismatch_fires"] / v["incidents"],
                                   "concurrency_share": v["concurrency_fires_any"] / v["incidents"]} for k, v in out["per_variant"].items()}
    return out


# ----------------------------------------------------------------------------------------------------------- class coverage / near duplicates
def class_coverage(metas: dict, incidents_by_ds: dict | None = None) -> dict:
    """Independent incidents per class per role/profile, from dataset metadata. Rule (pre-registered): a class is LEARNABLE if TRAIN datasets hold
    >= CLASS_LEARNABLE_MIN_INCIDENTS incidents drawn from >= CLASS_LEARNABLE_MIN_PROFILES profiles AND VAL datasets (a different profile) hold
    >= CLASS_EVALUABLE_MIN_VAL_INCIDENTS incidents. Nothing is fabricated, resampled or trained here."""
    rows = {}
    for t in ATTACKS:
        per_role = {}
        profiles_train, profiles_val = set(), set()
        for did, m in metas.items():
            n = m["incidents_by_type"].get(t, 0)
            role = m["role"]
            per_role.setdefault(role, {"incidents": 0, "events": 0, "datasets": {}})
            per_role[role]["incidents"] += n
            per_role[role]["events"] += m["attack_events_by_type"].get(t, 0)
            per_role[role]["datasets"][did] = n
            if n and role == "TRAIN":
                profiles_train.add(m["profile"])
            if n and role == "VAL":
                profiles_val.add(m["profile"])
        tr, va = per_role.get("TRAIN", {"incidents": 0})["incidents"], per_role.get("VAL", {"incidents": 0})["incidents"]
        learnable = tr >= K.CLASS_LEARNABLE_MIN_INCIDENTS and len(profiles_train) >= K.CLASS_LEARNABLE_MIN_PROFILES
        evaluable = va >= K.CLASS_EVALUABLE_MIN_VAL_INCIDENTS and bool(profiles_val - profiles_train)
        rows[t] = {"train_incidents": tr, "train_profiles": sorted(profiles_train), "val_incidents": va, "val_profiles": sorted(profiles_val),
                   "sealed_test_incidents": per_role.get("SEALED", {"incidents": 0})["incidents"], "dev_incidents": per_role.get("DEV", {"incidents": 0})["incidents"],
                   "per_role": per_role, "enough_independent_incidents_for_learning": bool(learnable),
                   "enough_for_reliable_evaluation_on_a_different_profile": bool(evaluable),
                   "statement": ("Enough independent incidents across profiles to attempt learning (not done in ML-4)." if learnable and evaluable else
                                 "Insufficient data for reliable classifier training/evaluation.")}
    return rows


def incident_signatures(L, labels, aid, scaler_mean, scaler_scale, feats, max_events=30) -> dict:
    """Mean standardised model-feature vector per incident (first `max_events` events). L = Loaded dataset; labels/aid aligned with ALL rows."""
    X = L.X[feats].to_numpy(float)
    Z = (X - scaler_mean) / scaler_scale
    aid = np.asarray(aid, dtype=object)
    out = {}
    for a in sorted(set(aid) - {""}):
        idx = np.where(aid == a)[0][:max_events]
        out[a] = Z[idx].mean(axis=0)
    return out


def near_duplicate_audit(test_sigs: dict, ref_sigs: dict, test_meta: dict, ref_meta: dict) -> dict:
    """For every sealed-test incident: distance to its nearest TRAIN/VAL incident of the same type, and whether that neighbour has the same profile.
    Threshold for 'near-duplicate' = the NEAR_DUP_QUANTILE quantile of pair distances among incidents of the same type INSIDE the reference set."""
    out = {"per_type": {}, "note": "signature = mean standardised feature vector over the incident's first 30 events"}
    for t in ATTACKS:
        ref = [(k, v) for k, v in ref_sigs.items() if ref_meta[k]["type"] == t]
        tst = [(k, v) for k, v in test_sigs.items() if test_meta[k]["type"] == t]
        if len(ref) < 2 or not tst:
            out["per_type"][t] = {"reference_incidents": len(ref), "test_incidents": len(tst), "note": "too few to audit"}
            continue
        R = np.array([v for _, v in ref])
        d_in = np.linalg.norm(R[:, None] - R[None], axis=-1)[np.triu_indices(len(ref), 1)]
        thr = float(np.quantile(d_in, K.NEAR_DUP_QUANTILE))
        rows = []
        for k, v in tst:
            d = np.linalg.norm(R - v, axis=1)
            j = int(d.argmin())
            rows.append({"test_incident": k, "test_profile": test_meta[k]["profile"], "nearest_reference": ref[j][0], "nearest_profile": ref_meta[ref[j][0]]["profile"],
                         "distance": float(d[j]), "near_duplicate": bool(d[j] <= thr), "same_profile_neighbour": test_meta[k]["profile"] == ref_meta[ref[j][0]]["profile"]})
        out["per_type"][t] = {"reference_incidents": len(ref), "test_incidents": len(tst), "near_duplicate_threshold": thr,
                              "median_within_reference_distance": float(np.median(d_in)), "median_test_to_nearest_distance": float(np.median([r["distance"] for r in rows])),
                              "near_duplicates": int(sum(r["near_duplicate"] for r in rows)), "same_profile_neighbours": int(sum(r["same_profile_neighbour"] for r in rows)),
                              "rows": rows}
    return out


def onboarding_contrast(did: str, data_dir=None) -> dict:
    """LABEL-FREE profile fingerprint from the attack-free onboarding period only (safe for sealed datasets): how different the profiles really are."""
    from . import features4 as F4
    ev = F4.load_events4(did, data_dir)
    n_onb = int((ev["timestamp"] < F4.onboarding_end(did, ev, data_dir)).sum())
    o = ev.iloc[:n_onb]
    ip = o["source_ip"].fillna("")
    city = o["geo_location"].str.split("|").str[0]
    ts = pd.to_datetime(o["timestamp"])
    hour = ts.dt.hour + ts.dt.minute / 60.0
    per_ent = o.groupby("entity_id").size()
    days = max((ts.max() - ts.min()).total_seconds() / 86400.0, 1.0)
    cmd = o["command_sequence"].fillna("")
    return {"dataset": did, "onboarding_events": int(n_onb), "entities": int(o.entity_id.nunique()),
            "entity_mix": {k: int(v) for k, v in o.groupby("entity_type").entity_id.nunique().items()},
            "events_per_entity_day_median": float(per_ent.median() / days),
            "public_ip_share": float((~ip.map(_is_private)).mean()), "distinct_ips_per_entity_median": float(o.groupby("entity_id").source_ip.nunique().median()),
            "share_ips_used_by_multiple_entities": float((o.groupby("source_ip").entity_id.nunique() > 1).mean()),
            "failed_auth_rate": float((o["auth_success"] == 0).mean()),
            "city_outside_production_home_cities": float((~city.isin(C.HOME_CITIES)).mean()), "distinct_cities": int(city.nunique()),
            "hour_of_day_mean": float(hour.mean()), "hour_of_day_sd": float(hour.std()), "share_events_22_to_05": float(((hour >= 22) | (hour < 5)).mean()),
            "weekend_share": float((ts.dt.weekday >= 5).mean()),
            "resources_matching_production_SENSITIVE": float(o["resource_accessed"].isin(C.SENSITIVE).mean()), "distinct_resources": int(o["resource_accessed"].nunique()),
            "resources_in_production_vocabulary": float(o["resource_accessed"].isin({r for v in C.RESOURCES.values() for r in v}).mean()),
            "commands_with_production_privileged_tokens": float(cmd.map(lambda s: any(t in PROD_PRIV for t in s.split("|") if t)).mean()),
            "share_events_with_command": float((cmd != "").mean()), "auth_methods": {k: round(float(v), 3) for k, v in o["auth_method"].value_counts(normalize=True).items()},
            "distinct_fingerprints_per_entity_max": int(o.groupby("entity_id").device_fingerprint.nunique().max())}

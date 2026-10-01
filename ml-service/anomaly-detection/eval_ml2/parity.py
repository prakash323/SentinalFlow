"""Feature / API parity checks (evaluation-only, DIAGNOSTIC: uses labels only to choose representative events).

For representative events, the same underlying event is presented in several representations, each processed from an
identical private copy of the causal state (extractor + windows) as of just before that event:

  V0  training / streaming representation   canonical CSV row (what the model was trained on and what the streaming
                                            evaluation feeds)                                  <- reference
  V1  entity_type forced to 'user'          api._canonical_event hard-codes entity_type="user"
  V2  minutes read as seconds               the platform sends sessionDurationMinutes; api.py stores it in
                                            session_duration (SECONDS in the training data)
  V3  command separator                     the platform sends "sudo exec download"; features.py splits on "|"
  V4  full API path                         real api._canonical_event(EventRequest(...)) on a platform-style payload

The profiler is frozen for this check (use_drift=False on an in-memory copy), so differences are purely representational.

Warm-up scope: api.py replays ALL 30 days (including the attack incidents) before serving, run_realtime.py's replay path
uses the training window only. For the first event of every attack incident we present it as a NEW event arriving on the
day after each state's last event (same clock time), under (a) the TRAIN-only state (run_realtime replay path) and (b) the
all-30-days state (api.py), and also report the causal as-of state the streaming evaluation actually had. Presenting the
event after the state's end avoids replaying an event into a state that already lies in its future.
"""
from __future__ import annotations

import copy
import time
from collections import defaultdict, deque

import numpy as np
import pandas as pd

from . import common as K
from .common import ATTACKS, C
from .protocol import Protocol

THR_NOTE = "alert = risk >= shipped ML threshold"


def _platform_payload(e: dict) -> dict:
    cmd = e.get("command_sequence") or ""
    return {"ip": e["source_ip"], "location": e["geo_location"], "resource": e["resource_accessed"],
            "authMethod": e["auth_method"], "loginSuccess": bool(int(e["auth_success"])),
            "sessionDurationMinutes": float(e["session_duration"]) / 60.0,
            "commandSequence": cmd.replace("|", " "), "deviceFingerprint": e["device_fingerprint"]}


def _api_event(api, e: dict) -> dict:
    ts = pd.Timestamp(e["timestamp"])
    req = api.EventRequest(eventId=f"ml2-{e['event_id']}", entityId=e["entity_id"], eventType="FILE_ACCESS",
                           occurredAt=ts.isoformat() + "Z", payload=_platform_payload(e))
    return api._canonical_event(req)


def _score(ex, windows, prof, det, event, FN, thr):
    """Process one event on PRIVATE copies and return features + score pieces (same order of operations as
    StreamingScorer.process, minus explanation/classification/profile update)."""
    eid = event["entity_id"]
    feat = ex.update_and_extract(event)
    vec = np.array([feat[f] for f in FN], dtype=float)
    w = windows[eid]
    w.append(vec)
    win = np.zeros((C.SEQ_LEN, len(FN)), dtype=np.float32)
    arr = np.array(w, dtype=np.float32)
    win[C.SEQ_LEN - len(arr):] = arr
    b, _, low = prof.score_row(feat, eid, event.get("entity_type", "user"))
    raw, _ = det.score_single(vec, win, b)
    fused = det.fuse_single(raw)
    risk = float(det.to_risk_100(np.array([fused]))[0])
    return {"vec": vec, "raw": raw, "fused": float(fused), "risk": risk, "alert": bool(risk >= thr), "low_conf": bool(low)}


def _diff(a: dict, b: dict, FN) -> dict:
    d = np.abs(a["vec"] - b["vec"])
    changed = [FN[i] for i in np.where(d > 1e-9)[0]]
    return {"features_changed": changed, "n_features_changed": len(changed),
            "linf": float(d.max()),
            "changed_detail": {FN[i]: [float(a["vec"][i]), float(b["vec"][i])] for i in np.where(d > 1e-9)[0]},
            "risk_ref": a["risk"], "risk_other": b["risk"], "risk_delta": b["risk"] - a["risk"],
            "fused_delta": b["fused"] - a["fused"],
            "raw_delta": {k: float(b["raw"][k] - a["raw"][k]) for k in a["raw"]},
            "alert_ref": a["alert"], "alert_other": b["alert"], "alert_flip": a["alert"] != b["alert"]}


def parity_stage(p: Protocol, out_dir, log=print):
    import torch
    torch.set_num_threads(1)
    import api                                            # production module, imported read-only (no server started)
    from src.features import FEATURE_NAMES as FN, StreamingFeatureExtractor

    art = K.load_artifact()
    prof, det = art["profiler"], art["detector"]
    prof.use_drift = False                                # frozen profile for the representation check
    thr = float(art["threshold"])

    ev = p.events
    lab = p.labels["label"].to_numpy()
    aid = p.labels["attack_id"].to_numpy()
    etype = ev["entity_type"].to_numpy()

    # ---- deterministic representative sample (labels used ONLY to pick examples)
    rng = np.random.default_rng(K.EVAL_SEED)
    first_idx = {a: int(np.where(aid == a)[0].min()) for a in sorted(p.incident_home)}     # first event of each incident
    inc_type = {a: lab[i] for a, i in first_idx.items()}
    rep_attack = {}
    for t in ATTACKS:                                                                       # first incident of each type
        ids = sorted([a for a in first_idx if inc_type[a] == t], key=lambda a: first_idx[a])
        if ids:
            rep_attack[t] = first_idx[ids[0]]
    cmd_idx = [int(i) for i in np.where((ev["command_sequence"].fillna("") != "").to_numpy() & (lab == "normal") & p.m_test)[0]]
    normals = []
    for et, n in (("user", 4), ("service_account", 3), ("edge_device", 3)):
        pool = np.where((etype == et) & (lab == "normal") & p.m_test)[0]
        normals += [int(i) for i in rng.choice(pool, n, replace=False)]
    normals += [int(i) for i in rng.choice(cmd_idx, 3, replace=False)]                     # normal events WITH commands
    variant_samples = {("attack:" + t): i for t, i in rep_attack.items()}
    variant_samples.update({f"normal:{etype[i]}:{k}": i for k, i in enumerate(normals)})
    need_variants = set(variant_samples.values())
    need_first = set(first_idx.values())

    # ---- one causal pass: state after each event; deep-copy the state just before the sampled events
    ex = StreamingFeatureExtractor()
    windows = defaultdict(lambda: deque(maxlen=C.SEQ_LEN))
    recs = ev.to_dict("records")
    variant_out, asof, sizes_train_end = {}, {}, None
    train_state, t_train_last = None, None
    t0 = time.time()
    tr_end_idx = int(p.m_train.sum())
    for i, e in enumerate(recs):
        if i == tr_end_idx:                                                                 # state at end of TRAIN
            sizes_train_end = {eid: (len(s.fingerprints), len(s.ips), len(s.resources), s.n) for eid, s in ex.ent.items()}
            train_state = (copy.deepcopy(ex), copy.deepcopy(windows))                       # == run_realtime.py replay warm-up
            t_train_last = recs[i - 1]["timestamp"]
        if i in need_variants or i in need_first:
            base = (copy.deepcopy(ex), copy.deepcopy(windows))
            v0 = _score(base[0], base[1], prof, det, e, FN, thr)
            if i in need_first:
                asof[i] = v0
            if i in need_variants:
                res = {"V0": v0}
                variants = {
                    "V1_entity_type_user": {**e, "entity_type": "user"},
                    "V2_minutes_as_seconds": {**e, "session_duration": float(e["session_duration"]) / 60.0},
                    "V3_space_separated_commands": {**e, "command_sequence": (e.get("command_sequence") or "").replace("|", " ")},
                    "V4_full_api_path": _api_event(api, e),
                }
                for name, ve in variants.items():
                    cp = (copy.deepcopy(ex), copy.deepcopy(windows))
                    res[name] = _score(cp[0], cp[1], prof, det, ve, FN, thr)
                variant_out[i] = res
        f = ex.update_and_extract(e)
        windows[e["entity_id"]].append(np.array([f[n] for n in FN], dtype=float))
        if i and i % 20000 == 0:
            log(f"[parity] pass {i}/{len(recs)} {time.time()-t0:.0f}s")
    final_ex, final_windows = ex, windows
    log(f"[parity] causal pass done in {time.time()-t0:.0f}s; scoring warm-scope copies")

    # ---- representation results
    rep_rows = []
    per_variant = defaultdict(lambda: {"features_changed": defaultdict(int), "linf": [], "risk_delta": [], "flips": 0, "n": 0})
    for name, i in sorted(variant_samples.items(), key=lambda t: t[1]):
        res = variant_out[i]
        row = {"sample": name, "event_id": int(ev["event_id"].iloc[i]), "entity_id": recs[i]["entity_id"],
               "true_entity_type": etype[i], "label": lab[i], "V0_risk": res["V0"]["risk"]}
        for v in ("V1_entity_type_user", "V2_minutes_as_seconds", "V3_space_separated_commands", "V4_full_api_path"):
            d = _diff(res["V0"], res[v], FN)
            row[v] = d
            pv = per_variant[v]
            pv["n"] += 1
            pv["linf"].append(d["linf"])
            pv["risk_delta"].append(d["risk_delta"])
            pv["flips"] += int(d["alert_flip"])
            for f in d["features_changed"]:
                pv["features_changed"][f] += 1
        rep_rows.append(row)
    variant_summary = {v: {"samples": s["n"], "features_changed_counts": dict(s["features_changed"]),
                           "max_linf": float(max(s["linf"])) if s["linf"] else 0.0,
                           "mean_abs_risk_delta": float(np.mean(np.abs(s["risk_delta"]))) if s["risk_delta"] else 0.0,
                           "max_abs_risk_delta": float(np.max(np.abs(s["risk_delta"]))) if s["risk_delta"] else 0.0,
                           "alert_flips_at_production_threshold": int(s["flips"])} for v, s in per_variant.items()}

    # ---- warm-up scope. Each incident's FIRST event is presented as a NEW event arriving shortly after the end of each
    # warm-up state (same clock time of day, next day), so no state ever sees an event from its own future/past:
    #   train-only state = run_realtime.py replay path (TRAIN window replayed)
    #   all-days state   = api.py (all 30 days, including every attack incident, replayed)
    # plus the causal as-of state (the state the streaming evaluation actually had at the event's own time).
    def _shift_after(e, end_ts):
        ts = pd.Timestamp(e["timestamp"])
        new_ts = end_ts.normalize() + pd.Timedelta(days=1) + (ts - ts.normalize())
        return {**e, "timestamp": new_ts}

    novelty = ("fingerprint_mismatch", "fingerprint_novelty", "is_new_ip_for_entity", "is_new_resource", "is_off_hours_for_entity")
    scope_rows = []
    for a, i in sorted(first_idx.items(), key=lambda t: t[1]):
        e = recs[i]
        causal = asof[i]
        s_tr = _score(copy.deepcopy(train_state[0]), copy.deepcopy(train_state[1]), prof, det, _shift_after(e, t_train_last), FN, thr)
        s_all = _score(copy.deepcopy(final_ex), copy.deepcopy(final_windows), prof, det, _shift_after(e, recs[-1]["timestamp"]), FN, thr)
        d = _diff(s_tr, s_all, FN)
        row = {"incident": a, "type": inc_type[a], "event_id": int(ev["event_id"].iloc[i]),
               "risk_causal_state": causal["risk"], "risk_train_only_state": s_tr["risk"], "risk_all_days_state": s_all["risk"],
               "alert_causal": causal["alert"], "alert_train_only": s_tr["alert"], "alert_all_days": s_all["alert"],
               "n_features_changed_train_vs_all_days": d["n_features_changed"], "features_changed_train_vs_all_days": d["features_changed"]}
        for nm, st in (("causal", causal), ("train_only", s_tr), ("all_days", s_all)):
            row[f"novelty_features_{nm}"] = {f: float(st["vec"][FN.index(f)]) for f in novelty}
        scope_rows.append(row)

    def _fires(r, nm):
        return any(v > 0.5 for k, v in r[f"novelty_features_{nm}"].items() if k != "fingerprint_novelty")
    by_type = {}
    for t in ATTACKS:
        rr = [r for r in scope_rows if r["type"] == t]
        if rr:
            by_type[t] = {"incidents": len(rr)}
            for nm in ("causal", "train_only", "all_days"):
                key = {"causal": "causal", "train_only": "train_only", "all_days": "all_days"}[nm]
                risk_k = {"causal": "risk_causal_state", "train_only": "risk_train_only_state", "all_days": "risk_all_days_state"}[nm]
                alert_k = {"causal": "alert_causal", "train_only": "alert_train_only", "all_days": "alert_all_days"}[nm]
                by_type[t][f"mean_risk_{key}"] = float(np.mean([r[risk_k] for r in rr]))
                by_type[t][f"alerts_{key}"] = int(sum(r[alert_k] for r in rr))
                by_type[t][f"novelty_fires_{key}"] = int(sum(_fires(r, nm) for r in rr))

    # ---- state-content difference: what does an all-days warm-up know that a train-window warm-up does not?
    fin = {eid: (len(s.fingerprints), len(s.ips), len(s.resources), s.n) for eid, s in final_ex.ent.items()}
    extra = {"entities_with_more_known_fingerprints": 0, "entities_with_more_known_ips": 0, "entities_with_more_known_resources": 0,
             "extra_fingerprints": 0, "extra_ips": 0, "extra_resources": 0, "extra_events_in_entity_counters": 0}
    for eid, (fp, ips, rs, n) in fin.items():
        a = sizes_train_end.get(eid, (0, 0, 0, 0))
        extra["entities_with_more_known_fingerprints"] += int(fp > a[0])
        extra["entities_with_more_known_ips"] += int(ips > a[1])
        extra["entities_with_more_known_resources"] += int(rs > a[2])
        extra["extra_fingerprints"] += fp - a[0]
        extra["extra_ips"] += ips - a[1]
        extra["extra_resources"] += rs - a[2]
        extra["extra_events_in_entity_counters"] += n - a[3]
    atk = np.isin(lab, ATTACKS)
    tr = p.m_train
    def _vals(col):
        return ev[col].fillna("").to_numpy()
    origin = {}
    for name, col in (("fingerprints", "device_fingerprint"), ("ips", "source_ip"), ("resources", "resource_accessed")):
        v = _vals(col)
        e_ids = ev["entity_id"].to_numpy()
        train_set = set(zip(e_ids[tr], v[tr]))
        atk_set = set(zip(e_ids[atk], v[atk]))
        origin[name] = int(len(atk_set - train_set))
    extra["entries_that_exist_only_because_of_attack_events"] = origin
    extra["timespans"] = {"train_only_state_events": int(tr.sum()), "api_state_events": int(len(ev))}

    K.write_json(out_dir / "parity.json", {
        "note": "Diagnostic. Profiler frozen (no EWMA updates) so differences are purely representational. " + THR_NOTE,
        "threshold": thr, "sample_size": len(rep_rows), "representative_events": rep_rows,
        "variant_summary": variant_summary, "warmup_scope": {"by_type": by_type, "incidents": scope_rows, "state_content_difference": extra},
        "code_facts": {
            "api.py_entity_type": "hard-coded 'user' in _canonical_event",
            "api.py_session_duration": "reads sessionDurationMinutes into session_duration (training data is in seconds)",
            "api.py_commands": "reads commandSequence verbatim; features.py splits on '|'",
            "api.py_warmup": "StreamingScorer.warmup(load_events(events.csv)) = ALL events (all 30 days incl. attacks)",
            "run_realtime.py_warmup_replay_path": "warm = events[ts < cut] (TRAIN window only)",
            "run_realtime.py_warmup_live_source_path": "scorer.warmup(events) = ALL events",
            "platform_simulator_payload": "sessionDurationMinutes / space-separated commandSequence (frontend/src/pages/Simulator.tsx)",
        }})
    log("[parity] done")

"""
Feature engineering.

CRITICAL DESIGN CHOICE: features are produced by a single forward pass over
time-sorted events, holding per-entity state. Every feature for an event at
time t uses ONLY information available before t. This means:

  * no target leakage, so offline metrics are trustworthy;
  * the exact same code runs in batch and in the real-time scorer, so there is
    no train/serve skew.

`StreamingFeatureExtractor.update_and_extract(event)` is the single entry point.
"""
from __future__ import annotations
from collections import defaultdict, deque
import numpy as np
import pandas as pd

import config as C
from src.utils import haversine_km, parse_geo

FEATURE_NAMES = [
    "hour_sin", "hour_cos", "is_weekend",
    "geo_velocity_kmh", "distance_from_home_km", "is_new_city",
    "failed_auth_5min_entity", "failed_auth_5min_ip",
    "distinct_entities_per_ip_1h", "ip_failure_rate_1h",
    "is_new_resource", "resource_novelty_ratio", "new_resources_24h",
    "resource_entropy_24h", "is_sensitive_resource", "peer_resource_deviation",
    "hour_zscore", "is_off_hours_for_entity",
    "session_duration_zscore", "interevent_gap_zscore",
    "fingerprint_mismatch", "fingerprint_novelty",
    "is_new_ip_for_entity", "auth_method_unusual",
    "events_last_1h", "events_last_24h",
    "offhours_count_7d", "sensitive_bytes_proxy_7d", "resource_breadth_7d",
    "sensitive_offhours_7d", "sensitive_ratio_7d",
    "cmd_len", "cmd_priv_count", "cmd_bigram_surprise",
    "entity_event_count",
]

_PRIV = {"sudo", "exec", "delete", "download"}


class _EntityState:
    __slots__ = ("n", "hours", "resources", "res_counts", "fingerprints", "fp_counts", "ips",
                 "auth_methods", "dur_sum", "dur_sq", "gap_sum", "gap_sq", "gap_n",
                 "last_ts", "last_latlon", "home_latlon", "recent", "day_events",
                 "offhours_7d", "sens_proxy_7d", "sens_off_7d", "cmd_bigrams", "cmd_total")

    def __init__(self):
        self.n = 0
        self.hours = np.zeros(24)
        self.resources = set()
        self.res_counts = defaultdict(int)
        self.fingerprints = set()
        self.fp_counts = defaultdict(int)
        self.ips = set()
        self.auth_methods = defaultdict(int)
        self.dur_sum = 0.0
        self.dur_sq = 0.0
        self.gap_sum = 0.0
        self.gap_sq = 0.0
        self.gap_n = 0
        self.last_ts = None
        self.last_latlon = None
        self.home_latlon = None
        self.recent = deque()          # (ts, resource) within 24h
        self.day_events = deque()      # ts within 7d
        self.offhours_7d = deque()
        self.sens_proxy_7d = deque()   # (ts, duration*sensitive)
        self.sens_off_7d = deque()     # off-hours AND sensitive
        self.cmd_bigrams = defaultdict(int)
        self.cmd_total = 0


class StreamingFeatureExtractor:
    """Stateful, online, leak-free. Feed events in strict time order."""

    def __init__(self):
        self.ent = defaultdict(_EntityState)
        self.ip_events = defaultdict(deque)      # ip -> (ts, entity, success)
        self.global_res_counts = defaultdict(int)
        self.global_total = 0
        # Peer-group (entity_type) resource histograms -- for
        # peer_resource_deviation, see update_and_extract. Separate from
        # global_res_counts (all entities pooled) and from the entity's own
        # BaselineProfiler z-scores (this entity vs ITS OWN history): this is
        # "how rare is this resource within entities of the SAME type", which
        # catches an entity drifting into a peer's territory (lateral
        # movement) even when the resource itself is common org-wide.
        self.peer_res_counts = defaultdict(lambda: defaultdict(int))
        self.peer_total = defaultdict(int)

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _z(x, mean, var, n):
        if n < 5 or var <= 1e-9:
            return 0.0
        return float(np.clip((x - mean) / np.sqrt(var), -10, 10))

    @staticmethod
    def _prune(dq, ts, seconds, idx=0):
        cutoff = ts - pd.Timedelta(seconds=seconds)
        while dq and (dq[0][idx] if isinstance(dq[0], tuple) else dq[0]) < cutoff:
            dq.popleft()

    # -- main -------------------------------------------------------------
    def update_and_extract(self, ev: dict) -> dict:
        eid = ev["entity_id"]
        st = self.ent[eid]
        ts = ev["timestamp"]
        city, lat, lon = parse_geo(ev.get("geo_location", ""))
        res = ev.get("resource_accessed", "") or ""
        ip = ev.get("source_ip", "") or ""
        fp = ev.get("device_fingerprint", "") or ""
        etype = ev.get("entity_type", "") or "user"
        auth = ev.get("auth_method", "") or ""
        success = int(ev.get("auth_success", 1))
        dur = float(ev.get("session_duration", 0) or 0)
        cmd = (ev.get("command_sequence", "") or "")

        f = {}
        hour = ts.hour + ts.minute / 60.0
        f["hour_sin"] = np.sin(2 * np.pi * hour / 24)
        f["hour_cos"] = np.cos(2 * np.pi * hour / 24)
        f["is_weekend"] = float(ts.weekday() >= 5)

        # --- travel ---
        if st.last_latlon is not None and st.last_ts is not None:
            km = haversine_km(st.last_latlon[0], st.last_latlon[1], lat, lon)
            hrs = max((ts - st.last_ts).total_seconds() / 3600.0, 1e-3)
            f["geo_velocity_kmh"] = float(min(km / hrs, 50000))
        else:
            f["geo_velocity_kmh"] = 0.0
        if st.home_latlon is None:
            st.home_latlon = (lat, lon)
        f["distance_from_home_km"] = haversine_km(
            st.home_latlon[0], st.home_latlon[1], lat, lon)
        f["is_new_city"] = float(st.n > 0 and city not in
                                 {c for c, _, _ in [(city, 0, 0)]} and
                                 (lat, lon) != st.home_latlon and st.n > 10)

        # --- auth failures (entity and IP side) ---
        ipq = self.ip_events[ip]
        self._prune(ipq, ts, 3600)
        f["failed_auth_5min_ip"] = float(sum(
            1 for t, _, s in ipq if s == 0 and (ts - t).total_seconds() <= 300))
        f["failed_auth_5min_entity"] = float(sum(
            1 for t, e, s in ipq if s == 0 and e == eid and (ts - t).total_seconds() <= 300))
        f["distinct_entities_per_ip_1h"] = float(len({e for _, e, _ in ipq}))
        f["ip_failure_rate_1h"] = float(
            sum(1 for _, _, s in ipq if s == 0) / max(len(ipq), 1))

        # --- resource novelty ---
        f["is_new_resource"] = float(st.n > 0 and res not in st.resources)
        f["resource_novelty_ratio"] = float(
            1.0 - self.global_res_counts[res] / max(self.global_total, 1))
        self._prune(st.recent, ts, 86400)
        recent_res = [r for _, r in st.recent]
        f["new_resources_24h"] = float(len(set(recent_res) - st.resources))
        if recent_res:
            _, cnt = np.unique(recent_res, return_counts=True)
            p = cnt / cnt.sum()
            f["resource_entropy_24h"] = float(-(p * np.log(p + 1e-12)).sum())
        else:
            f["resource_entropy_24h"] = 0.0
        f["is_sensitive_resource"] = float(res in C.SENSITIVE)
        # How rare this resource is WITHIN this entity's own peer group
        # (same entity_type), as opposed to resource_novelty_ratio's global
        # population. An admin touching an ops-only resource is common
        # globally (ops entities do it constantly) but rare for the admin
        # peer group specifically -- the signal lateral movement/insider
        # drift actually needs.
        peer_hist = self.peer_res_counts[etype]
        f["peer_resource_deviation"] = float(
            1.0 - peer_hist.get(res, 0) / max(self.peer_total[etype], 1))

        # --- temporal deviation ---
        if st.n >= 10:
            p = st.hours / st.hours.sum()
            f["hour_zscore"] = float(np.clip(
                (p.mean() - p[int(hour) % 24]) / (p.std() + 1e-9), -10, 10))
            f["is_off_hours_for_entity"] = float(p[int(hour) % 24] < 0.01)
        else:
            f["hour_zscore"] = 0.0
            f["is_off_hours_for_entity"] = 0.0
        mean_d = st.dur_sum / max(st.n, 1)
        var_d = st.dur_sq / max(st.n, 1) - mean_d ** 2
        f["session_duration_zscore"] = self._z(dur, mean_d, var_d, st.n)
        if st.last_ts is not None:
            gap = (ts - st.last_ts).total_seconds()
            mg = st.gap_sum / max(st.gap_n, 1)
            vg = st.gap_sq / max(st.gap_n, 1) - mg ** 2
            f["interevent_gap_zscore"] = self._z(gap, mg, vg, st.gap_n)
        else:
            f["interevent_gap_zscore"] = 0.0

        # --- device / identity ---
        f["fingerprint_mismatch"] = float(st.n > 0 and fp not in st.fingerprints)
        # Decaying novelty: a spoofed fingerprint stays suspicious for several
        # events, not just the first one. A hard boolean fires once and then the
        # attacker is silently accepted -- which is exactly the failure mode.
        f["fingerprint_novelty"] = float(1.0 / (1.0 + st.fp_counts.get(fp, 0))) \
            if st.n > 0 else 0.0
        f["is_new_ip_for_entity"] = float(st.n > 0 and ip not in st.ips)
        tot_auth = sum(st.auth_methods.values())
        f["auth_method_unusual"] = float(
            st.auth_methods.get(auth, 0) / max(tot_auth, 1) < 0.05 and tot_auth > 20)

        # --- volume ---
        self._prune(st.day_events, ts, 7 * 86400)
        f["events_last_1h"] = float(sum(
            1 for t in st.day_events if (ts - t).total_seconds() <= 3600))
        f["events_last_24h"] = float(sum(
            1 for t in st.day_events if (ts - t).total_seconds() <= 86400))

        # --- slow-burn aggregates (catch low-and-slow exfiltration) ---
        self._prune(st.offhours_7d, ts, 7 * 86400)
        self._prune(st.sens_proxy_7d, ts, 7 * 86400)
        f["offhours_count_7d"] = float(len(st.offhours_7d))
        f["sensitive_bytes_proxy_7d"] = float(sum(v for _, v in st.sens_proxy_7d))
        f["resource_breadth_7d"] = float(len({r for _, r in st.recent}))
        # The conjunction is the actual signature of slow exfiltration: sensitive
        # resources touched OUTSIDE this entity's normal hours, accumulating over
        # days. Either signal alone is common; together they are very rare.
        self._prune(st.sens_off_7d, ts, 7 * 86400)
        f["sensitive_offhours_7d"] = float(len(st.sens_off_7d))
        f["sensitive_ratio_7d"] = float(
            sum(1 for _, r in st.recent if r in C.SENSITIVE) / max(len(st.recent), 1))

        # --- command sequence ---
        toks = [t for t in cmd.split("|") if t]
        f["cmd_len"] = float(len(toks))
        f["cmd_priv_count"] = float(sum(1 for t in toks if t in _PRIV))
        if len(toks) >= 2 and st.cmd_total > 20:
            probs = []
            for a, b in zip(toks, toks[1:]):
                probs.append(st.cmd_bigrams.get((a, b), 0) / max(st.cmd_total, 1))
            f["cmd_bigram_surprise"] = float(-np.log(np.mean(probs) + 1e-6))
        else:
            f["cmd_bigram_surprise"] = 0.0

        f["entity_event_count"] = float(st.n)

        # ------------------------------------------------------------------
        # STATE UPDATE happens AFTER feature extraction. Order matters.
        # ------------------------------------------------------------------
        st.n += 1
        st.hours[int(hour) % 24] += 1
        st.resources.add(res)
        st.res_counts[res] += 1
        st.fingerprints.add(fp)
        st.fp_counts[fp] += 1
        st.ips.add(ip)
        st.auth_methods[auth] += 1
        st.dur_sum += dur
        st.dur_sq += dur * dur
        if st.last_ts is not None:
            g = (ts - st.last_ts).total_seconds()
            st.gap_sum += g
            st.gap_sq += g * g
            st.gap_n += 1
        st.last_ts = ts
        st.last_latlon = (lat, lon)
        st.recent.append((ts, res))
        st.day_events.append(ts)
        if f["is_off_hours_for_entity"]:
            st.offhours_7d.append(ts)
        if res in C.SENSITIVE:
            st.sens_proxy_7d.append((ts, dur))
            if f["is_off_hours_for_entity"] or not (7 <= ts.hour <= 21):
                st.sens_off_7d.append(ts)
        for a, b in zip(toks, toks[1:]):
            st.cmd_bigrams[(a, b)] += 1
            st.cmd_total += 1
        ipq.append((ts, eid, success))
        self.global_res_counts[res] += 1
        self.global_total += 1
        self.peer_res_counts[etype][res] += 1
        self.peer_total[etype] += 1
        return f


def build_feature_matrix(events: pd.DataFrame, verbose=True) -> pd.DataFrame:
    """Batch wrapper. Uses the identical streaming code path."""
    ex = StreamingFeatureExtractor()
    rows = []
    recs = events.to_dict("records")
    for i, ev in enumerate(recs):
        rows.append(ex.update_and_extract(ev))
        if verbose and i and i % 50000 == 0:
            print(f"[feat] {i:,}/{len(recs):,}")
    X = pd.DataFrame(rows, columns=FEATURE_NAMES)
    X.insert(0, "event_id", events["event_id"].values)
    X.insert(1, "entity_id", events["entity_id"].values)
    X.insert(2, "entity_type", events["entity_type"].values)
    X.insert(3, "timestamp", events["timestamp"].values)
    return X

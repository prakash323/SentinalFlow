"""Profile-parameterised synthetic access-log generator for ML-4 (independent of src/generate.py, which is not modified).

Determinism: every random decision uses a named stream derived from (seed, purpose, indices) with numpy SeedSequence, so
  * the same (profile, seed) always yields byte-identical files;
  * a drift dataset and its no-drift control share identical entities, benign events and attacks (drift modifies benign events only).
Chronology: events are sorted by timestamp and timestamps are made strictly increasing (1 microsecond steps on ties); event_id = position.
Labels/incident ground truth are written to SEPARATE files (events.csv never contains them).
"""
from __future__ import annotations

import json
import math

import numpy as np
import pandas as pd

import config as C
from src.utils import haversine_km

from . import common as K
from .profiles import CITY, get_profile

BASE = pd.Timestamp("2026-06-01")
DAY_NS = 86400 * 10 ** 9
SCHEMA_COLS = [c for c in C.SCHEMA if c != "event_id"]
ATTACK_INDEX = {t: i for i, t in enumerate(C.ATTACK_TYPES)}


def _geo(city: str) -> str:
    lat, lon = CITY[city]
    return f"{city}|{lat}|{lon}"


class Gen:
    def __init__(self, P: dict, seed: int, days: int, onboarding: int, target_events: int, drift_kind: str | None = None, drift_study: bool = False):
        self.P, self.seed, self.days, self.onb = P, seed, days, onboarding
        self.target, self.drift_kind, self.drift_study = target_events, drift_kind, drift_study
        self.pool_all_res = sorted({r for v in P["resources"].values() for r in v})
        self.sens = set(P["sensitive"])
        self.rows: list = []                                  # attack rows: (ts_ns, entity_idx, ip, city, res, auth, success, dur, cmd, fp, label, aid)
        self.incidents: list = []
        self._pname_seed = sum(ord(c) * (i + 1) for i, c in enumerate(P["name"]))

    # ------------------------------------------------------------------ RNG streams
    def rng(self, *key):
        return np.random.default_rng([self.seed, *key])

    # ------------------------------------------------------------------ entities
    def build_entities(self):
        P, rng = self.P, self.rng(1)
        ipc = P["ip"]
        shared = None
        if ipc["nat_share"] > 0:
            shared = [f"{self._pref(rng, ipc['private_bases'])}.{rng.integers(0, 255)}.{rng.integers(1, 254)}" for _ in range(ipc["n_shared"])]

        ents = []
        counts = [("user", "user", P["n_users"], "U"), ("service", "service_account", P["n_service"], "S"), ("edge", "edge_device", P["n_devices"], "D")]
        for tkey, etype, n, pre in counts:
            for i in range(n):
                role = P["roles"][i % len(P["roles"])] if tkey == "user" else etype
                home = str(rng.choice(P["home_cities"]))
                lo, hi = P["events_per_day"][tkey]
                wlo, whi = P["weekend"][tkey]
                if tkey == "user":
                    m0, s0 = P["hours"]["user_mean"]
                    local = rng.normal(m0, s0)
                    sh = P["hours"]["shifts"]
                    mean = float(rng.choice(sh)) if sh else float((local - float(rng.choice(P["hours"]["tz_offsets"]))) % 24)
                    sd = float(rng.uniform(*P["hours"]["user_sd"]))
                    dur_mu, dur_sd = float(rng.uniform(5.2, 6.4)), float(rng.uniform(0.5, 1.0))
                    methods = P["auth"]["user_methods"]
                    zipf = float(rng.uniform(1.6, 2.4))
                elif tkey == "service":
                    mean, sd = 12.0, 6.9
                    dur_mu, dur_sd = float(rng.uniform(2.0, 3.5)), float(rng.uniform(0.2, 0.5))
                    methods = P["auth"]["service_methods"]
                    zipf = float(rng.uniform(2.4, 3.2))
                else:
                    mean, sd = 12.0, 6.9
                    dur_mu, dur_sd = float(rng.uniform(0.5, 1.5)), 0.3
                    methods = P["auth"]["edge_methods"]
                    zipf = 3.0
                k = ipc["pool_size"][tkey]
                if ipc["mode"] == "private_pool":
                    if shared and rng.random() < ipc["nat_share"]:
                        pool = [str(x) for x in rng.choice(shared, size=min(k, len(shared)), replace=False)]
                    else:
                        base = f"{self._pref(rng, ipc['private_bases'])}.{rng.integers(0, 255)}"
                        pool = [f"{base}.{rng.integers(1, 254)}" for _ in range(k)]
                elif ipc["mode"] == "public_dynamic":
                    pref = str(rng.choice(ipc["public_isp"]))
                    pool = [f"{pref}.{rng.integers(0, 255)}.{rng.integers(1, 254)}" for _ in range(k)]
                else:  # mixed: half private pools, half static public
                    if rng.random() < 0.5:
                        base = f"{self._pref(rng, ipc['private_bases'])}.{rng.integers(0, 255)}"
                        pool = [f"{base}.{rng.integers(1, 254)}" for _ in range(k)]
                    else:
                        pref = str(rng.choice(ipc["public_isp"]))
                        pool = [f"{pref}.{rng.integers(0, 255)}.{rng.integers(1, 254)}" for _ in range(max(1, k - 1))]
                dev = P["device"]
                osl = dev[f"{tkey}_os"]
                protol = dev[f"{tkey}_proto"]
                res = P["resources"][role]
                w = 1.0 / (np.arange(1, len(res) + 1) ** zipf)
                ents.append({
                    "idx": len(ents), "entity_id": f"{pre}{i:04d}", "entity_type": etype, "tkey": tkey, "role": role, "home_city": home,
                    "hour_mean": mean, "hour_sd": sd, "epd": float(rng.uniform(lo, hi)), "dur_mu": dur_mu, "dur_sigma": dur_sd,
                    "auth": str(rng.choice(methods)), "weekend": float(rng.uniform(wlo, whi)), "ip_pool": pool,
                    "os": str(rng.choice(osl)), "mac": ":".join(f"{rng.integers(0, 255):02x}" for _ in range(6)), "protocol": str(rng.choice(protol)),
                    "resources": list(res), "res_w": (w / w.sum()), "priv": role in P["priv_roles"],
                    "isp": pool[0].rsplit(".", 2)[0] if ipc["mode"] != "private_pool" else None})
        self.ents = ents
        self.by_type = {t: [e for e in ents if e["tkey"] == t] for t in ("user", "service", "edge")}
        exp = 0.0
        for e in ents:
            for d in range(self.days):
                exp += e["epd"] * (e["weekend"] if (P["start_offset_days"] + d) % 7 >= 5 else 1.0)
        self.scale = self.target / max(exp, 1.0)
        self._build_command_pools()

    @staticmethod
    def _pref(rng, bases):
        """Two-octet private prefix: '10' -> '10.<a>', '172.16' / '192.168' are already two octets."""
        b = str(rng.choice(bases))
        return b if b.count(".") == 1 else f"{b}.{rng.integers(0, 255)}"

    def _fp(self, e, mac=None, os_=None, proto=None):
        return f"{os_ or e['os']}|{mac or e['mac']}|{proto or e['protocol']}"

    # ------------------------------------------------------------------ commands
    def _build_command_pools(self):
        cm = self.P["commands"]
        rng = np.random.default_rng([self._pname_seed, 7])
        vocab = cm["vocab"]
        if cm["original_chains"]:
            trans = {"list": ["read", "read", "list", "write"], "read": ["read", "list", "write", "download"], "write": ["read", "list", "exec"],
                     "exec": ["read", "list"], "sudo": ["read", "write", "exec", "list"], "download": ["read", "list"], "delete": ["list"]}
        else:
            trans = {t: [str(x) for x in rng.choice(vocab, size=4)] for t in vocab}
        self.cmd_pool = {}
        for role in sorted({e["role"] for e in self.ents if e["priv"]}):      # sorted: set order depends on PYTHONHASHSEED
            pool = []
            for _ in range(80):
                cur = cm["start"].get(role, cm["default_start"])
                seq = [cur]
                for _ in range(int(rng.integers(1, 6))):
                    cur = str(rng.choice(trans.get(cur, vocab)))
                    seq.append(cur)
                pool.append("|".join(seq))
            self.cmd_pool[role] = pool
        self.mal_cmd = "|".join(cm["malicious"])

    def _normal_cmd(self, e, rng):
        pool = self.cmd_pool.get(e["role"]) or next(iter(self.cmd_pool.values()))
        return pool[int(rng.integers(len(pool)))]

    # ------------------------------------------------------------------ IPs / cities
    def _pub(self, rng):
        return f"{rng.integers(11, 220)}.{rng.integers(0, 255)}.{rng.integers(0, 255)}.{rng.integers(1, 254)}"

    def _ip(self, kind, e, rng):
        if kind == "own":
            return str(rng.choice(e["ip_pool"]))
        if kind == "public":
            return self._pub(rng)
        if kind == "private_internal":
            return f"10.{rng.integers(0, 255)}.{rng.integers(0, 255)}.{rng.integers(1, 254)}"
        if kind == "residential":
            return f"{rng.choice(self.P['ip']['public_isp'])}.{rng.integers(0, 255)}.{rng.integers(1, 254)}"
        return self._pub(rng)

    def _city(self, mode, e, rng):
        if mode == "home":
            return e["home_city"]
        if mode == "near":
            return str(rng.choice([c for c in self.P["home_cities"] if c != e["home_city"]] or self.P["home_cities"]))
        return str(rng.choice(self.P["foreign_cities"]))

    # ------------------------------------------------------------------ normal traffic
    def _day_events(self, e, day, rng, n_override=None, extra=False):
        P = self.P
        d = P["start_offset_days"] + day
        f = e["weekend"] if d % 7 >= 5 else 1.0
        n = int(rng.poisson(e["epd"] * f * self.scale)) if n_override is None else n_override
        if n <= 0:
            return None
        if P["periodic_devices"] and e["tkey"] == "edge":
            interval = 86400.0 / n
            secs = (np.arange(n) + rng.uniform(0, 1)) * interval + rng.normal(0, interval * 0.08, n)
            secs = np.clip(secs, 0, 86399.0)
        else:
            secs = (rng.normal(e["hour_mean"], e["hour_sd"], n) % 24) * 3600.0
        ts = (BASE.value + (d) * DAY_NS + (secs * 1e9)).astype(np.int64)
        cf = P["confounder"]
        conf = rng.random(n) < cf["rate"]
        trav = conf & (rng.random(n) < cf["travel_p"])
        city = np.full(n, e["home_city"], dtype=object)
        if trav.any():
            city[trav] = rng.choice(P["home_cities"], size=int(trav.sum()))
        pool = e["ip_pool"]
        if P["ip"]["rotate_daily"]:
            base_ip = pool[(day + e["idx"]) % len(pool)]
            ip = np.where(rng.random(n) < 0.85, base_ip, rng.choice(pool, size=n)).astype(object)
        else:
            ip = rng.choice(pool, size=n).astype(object)
        if trav.any():
            nt = int(trav.sum())
            if P["ip"]["travel_ip"] == "public":
                ip[trav] = [f"{rng.choice(P['ip']['public_isp'])}.{rng.integers(0, 255)}.{rng.integers(1, 254)}" for _ in range(nt)]
            else:
                ip[trav] = [f"192.168.{rng.integers(0, 255)}.{rng.integers(1, 254)}" for _ in range(nt)]
        res = rng.choice(e["resources"], size=n, p=e["res_w"]).astype(object)
        atyp = conf & (rng.random(n) < cf["atypical_res_p"])
        if atyp.any():
            res[atyp] = rng.choice(e["resources"], size=int(atyp.sum()))
        dur = np.round(np.exp(rng.normal(e["dur_mu"], e["dur_sigma"], n)), 1)
        success = (rng.random(n) > P["auth"]["fail_rate"][e["tkey"]]).astype(np.int8)
        auth = np.full(n, e["auth"], dtype=object)
        if P["auth"]["alt_method_p"] > 0:
            alt = rng.random(n) < P["auth"]["alt_method_p"]
            if alt.any():
                auth[alt] = rng.choice(P["auth"]["user_methods"] + ["token"], size=int(alt.sum()))
        cmd = np.full(n, "", dtype=object)
        if e["priv"]:
            pl = self.cmd_pool[e["role"]]
            cmd = np.array([pl[i] for i in rng.integers(len(pl), size=n)], dtype=object)
        fp = np.full(n, self._fp(e), dtype=object)
        return pd.DataFrame({"ts_ns": ts, "ei": e["idx"], "ip": ip, "city": city, "res": res, "auth": auth, "success": success, "dur": dur, "cmd": cmd,
                             "fp": fp, "label": "normal", "aid": "", "day": day + secs / 86400.0})

    def generate_normal(self):
        parts = []
        for e in self.ents:
            for day in range(self.days):
                df = self._day_events(e, day, self.rng(2, e["idx"], day))
                if df is not None:
                    parts.append(df)
        return pd.concat(parts, ignore_index=True)

    # ------------------------------------------------------------------ attack helpers
    def _emit(self, e, ts_ns, ip, city, res, auth, success, dur, cmd, fp, label, aid):
        self.rows.append((int(ts_ns), e["idx"], ip, city, res, auth, int(success), round(float(dur), 1), cmd, fp, label, aid))

    def _t0(self, cls, i, rng, hour_range=None, fixed_hour=None):
        p = self.P["attacks"][cls]
        periods = self.P.get("attack_periods")
        if periods:
            lo, hi = periods[i % len(periods)]
        else:
            lo, hi = p["window"][0] * self.days, p["window"][1] * self.days
        lo = max(lo, self.onb + 0.5)
        hi = min(max(hi, lo + 0.5), self.days - 1.0)
        day = int(np.floor(rng.uniform(lo, hi)))
        if fixed_hour is not None:
            hour = fixed_hour
        elif hour_range:
            hour = rng.uniform(*hour_range)
        else:
            hour = rng.uniform(0, 24)
        d = self.P["start_offset_days"] + day
        return int(BASE.value + d * DAY_NS + hour * 3600 * 1e9), day

    def _victims(self, vt, rng, k=1):
        pools = {"any": self.ents, "user": self.by_type["user"], "service": self.by_type["service"],
                 "edge_service": self.by_type["edge"] + self.by_type["service"], "user_service": self.by_type["user"] + self.by_type["service"]}
        pool = pools.get(vt) or self.ents
        idx = rng.choice(len(pool), size=min(k, len(pool)), replace=False)
        return [pool[int(i)] for i in idx]

    def _register(self, aid, typ, ents, **params):
        self.incidents.append({"attack_id": aid, "type": typ, "entities": [e["entity_id"] for e in ents][:12], "n_entities": len(ents), **params})

    # ------------------------------------------------------------------ injectors
    def inject_brute_force(self):
        p, rng = self.P["attacks"]["brute_force"], self.rng(3, 0)
        vt = p.get("victims") if isinstance(p.get("victims"), str) else "any"
        for a in range(p["n"]):
            e = self._victims(vt, rng)[0]
            t, day = self._t0("brute_force", a, rng, p.get("hour_range"))
            src = self._ip(p["src"], e, rng)
            n = int(rng.integers(*p["events"]))
            fs = rng.uniform(*p["fail_share"])
            aid = f"BF{a:03d}"
            cm = self._city(p["city"], e, rng) if p["city"] != "foreign" else None
            for k in range(n):
                t += int(rng.uniform(*p["gap_s"]) * 1e9)
                fail = rng.random() < fs
                self._emit(e, t, src, cm or self._city("foreign", e, rng), str(rng.choice(e["resources"])), e["auth"], 0 if fail else 1,
                           rng.uniform(0.1, 1.5) if fail else rng.uniform(5, 60), "", self._fp(e), "brute_force", aid)
            if rng.random() < p["success_end_p"]:
                self._emit(e, t + int(3e9), src, cm or self._city("foreign", e, rng), str(rng.choice(e["resources"])), e["auth"], 1, 300, "", self._fp(e), "brute_force", aid)
            self._register(aid, "brute_force", [e], src=p["src"], city=p["city"], fail_share=round(float(fs), 3), day=day, victim_type=e["tkey"])

    def inject_credential_stuffing(self):
        p, rng = self.P["attacks"]["credential_stuffing"], self.rng(3, 1)
        for a in range(p["n"]):
            k = int(rng.integers(*p["victims"]))
            vs = self._victims(p.get("victim_types", "any"), rng, k)
            ips = [self._ip(p["src"], vs[0], rng) for _ in range(int(rng.integers(p["n_ips"][0], p["n_ips"][1] + 1)))]
            t0, day = self._t0("credential_stuffing", a, rng, p.get("hour_range"))
            aid = f"CS{a:03d}"
            lo, hi = p["spread_s"]
            for j, e in enumerate(vs):
                for _ in range(int(rng.integers(*p["tries"]))):
                    ts = t0 + int((j * hi + rng.uniform(lo, max(hi, lo + 1))) * 1e9)
                    self._emit(e, ts, str(rng.choice(ips)), self._city(p["city"], e, rng), str(rng.choice(e["resources"])), "password",
                               1 if rng.random() < p["success_p"] else 0, rng.uniform(0.1, 2.0), "", self._fp(e), "credential_stuffing", aid)
            self._register(aid, "credential_stuffing", vs, src=p["src"], n_ips=len(ips), city=p["city"], day=day)

    def inject_impossible_travel(self):
        p, rng = self.P["attacks"]["impossible_travel"], self.rng(3, 2)
        fc = self.P["foreign_cities"]

        def far(e, min_km, max_km=None):
            lat, lon = CITY[e["home_city"]]
            c = [x for x in fc if haversine_km(lat, lon, *CITY[x]) >= min_km and (max_km is None or haversine_km(lat, lon, *CITY[x]) <= max_km)]
            return str(rng.choice(c or fc))
        for a in range(p["n"]):
            e = self._victims(p.get("victim_types", "any"), rng)[0]
            t0, day = self._t0("impossible_travel", a, rng, p.get("hour_range") or (8, 20))
            aid = f"IT{a:03d}"
            self._emit(e, t0, str(rng.choice(e["ip_pool"])), e["home_city"], str(rng.choice(e["resources"])), e["auth"], 1, rng.uniform(200, 900), "", self._fp(e), "normal", "")
            t = t0
            hops = p["hops"] if p["hops"] == 1 else int(rng.integers(2, p["hops"] + 1))
            for h in range(hops):
                t += int(rng.uniform(*p["gap_h"]) * 3600 * 1e9)
                self._emit(e, t, self._ip(p["src2"], e, rng), far(e, p["min_km"], p.get("max_km")), str(rng.choice(e["resources"])), e["auth"], 1,
                           rng.uniform(200, 900), "", self._fp(e), "impossible_travel", aid)
            self._register(aid, "impossible_travel", [e], src2=p["src2"], hops=hops, day=day)
        for _ in range(max(2, int(p["n"] * p["near_miss"]))):     # plausible long flights: labelled normal (near-misses)
            e = self._victims(p.get("victim_types", "any"), rng)[0]
            t0, _ = self._t0("impossible_travel", 0, rng, None)
            self._emit(e, t0, str(rng.choice(e["ip_pool"])), e["home_city"], str(rng.choice(e["resources"])), e["auth"], 1, 400, "", self._fp(e), "normal", "")
            self._emit(e, t0 + int(rng.uniform(9, 14) * 3600 * 1e9), self._ip("residential" if p["src2"] == "residential" else "public", e, rng),
                       str(rng.choice(fc)), str(rng.choice(e["resources"])), e["auth"], 1, 400, "", self._fp(e), "normal", "")

    def inject_lateral_movement(self):
        p, rng = self.P["attacks"]["lateral_movement"], self.rng(3, 3)
        for a in range(p["n"]):
            e = self._victims(p.get("victim_types", "any"), rng)[0]
            own = set(e["resources"])
            if p["foreign"] == "peer":
                foreign = sorted({r for role, rs in self.P["resources"].items() if role not in ("service_account", "edge_device") and role != e["role"] for r in rs} - own)
            else:
                foreign = [r for r in self.pool_all_res if r not in own]
            foreign = foreign or self.pool_all_res
            hrs = p["hours"]
            fixed = float(rng.uniform(hrs[0], hrs[1])) if len(hrs) == 2 else float(rng.choice(hrs)) + rng.uniform(0, 0.9)
            t0, day = self._t0("lateral_movement", a, rng, None, fixed_hour=fixed)
            aid = f"LM{a:03d}"
            n = int(rng.integers(*p["events"]))
            t = t0
            ipk = p["ip"]
            src = self._ip(ipk, e, rng) if ipk != "own" else None
            for k in range(n):
                t += int(rng.uniform(*p["gap_min"]) * 60 * 1e9)
                res = str(rng.choice(foreign[: max(3, int(len(foreign) * (k + 1) / n))]))
                if p["cmd"] == "malicious" or (p["cmd"] == "mixed" and rng.random() < 0.5):
                    cmd = self.mal_cmd
                else:
                    cmd = self._normal_cmd(e, rng) if e["priv"] else self.mal_cmd.split("|")[0]
                self._emit(e, t, src or str(rng.choice(e["ip_pool"])), e["home_city"], res, e["auth"], 1, rng.uniform(5, 90), cmd, self._fp(e), "lateral_movement", aid)
            self._register(aid, "lateral_movement", [e], foreign=p["foreign"], cmd=p["cmd"], ip=ipk, day=day)

    def _spoof_fp(self, e, variant, rng):
        dev = self.P["device"]
        new_os = str(rng.choice([o for o in dev["os_pool_all"] if o != e["os"]]))
        new_mac = ":".join(f"{rng.integers(0, 255):02x}" for _ in range(6))
        new_pr = str(rng.choice([x for x in dev["proto_pool_all"] if x != e["protocol"]]))
        return {"full_swap": self._fp(e, new_mac, new_os, str(rng.choice(dev["proto_pool_all"]))), "partial_mac": self._fp(e, mac=new_mac),
                "partial_os": self._fp(e, os_=new_os), "protocol_only": self._fp(e, proto=new_pr), "clone": self._fp(e)}[variant]

    def inject_device_spoofing(self):
        p, rng = self.P["attacks"]["device_spoofing"], self.rng(3, 4)
        names = list(p["variants"])
        probs = np.array([p["variants"][k] for k in names], dtype=float)
        probs /= probs.sum()
        for a in range(p["n"]):
            e = self._victims(p.get("victim_types", "any"), rng)[0]
            variant = str(rng.choice(names, p=probs))
            fp = self._spoof_fp(e, variant, rng)
            new_ip = (variant == "clone" and rng.random() < p["clone_ip_new_p"]) or (variant != "clone" and p["ip"] == "new")
            src = self._ip("public" if new_ip else "own", e, rng)
            t0, day = self._t0("device_spoofing", a, rng, p.get("hour_range"))
            aid = f"DS{a:03d}"
            t = t0
            for k in range(int(rng.integers(*p["events"]))):
                t += int(rng.uniform(*p["gap_min"]) * 60 * 1e9)
                self._emit(e, t, src if new_ip else str(rng.choice(e["ip_pool"])), e["home_city"], str(rng.choice(e["resources"])), e["auth"], 1,
                           rng.uniform(1, 30), "", fp, "device_spoofing", aid)
            self._register(aid, "device_spoofing", [e], variant=variant, new_ip=bool(new_ip), day=day)

    def inject_low_slow_exfil(self):
        p, rng = self.P["attacks"]["low_slow_exfil"], self.rng(3, 5)
        for a in range(p["n"]):
            e = self._victims(p.get("victim_types", "user"), rng)[0]
            sens = [r for r in e["resources"] if r in self.sens] or list(e["resources"])[:2]
            aid = f"LS{a:03d}"
            periods = self.P.get("attack_periods")
            lo_f, hi_f = (periods[a % len(periods)] if periods else (p["window"][0] * self.days, p["window"][1] * self.days))
            span = int(rng.integers(*p["span_days"]))
            lo = max(int(lo_f), self.onb + 1)
            hi = min(int(hi_f), self.days - 1)
            start = int(rng.integers(lo, max(lo + 1, hi - span if hi - span > lo else lo + 1)))
            span = max(3, min(span, self.days - start - 1))
            for d in range(span):
                dd = self.P["start_offset_days"] + start + d
                for _ in range(int(rng.integers(*p["per_day"]))):
                    hour = float(rng.choice(p["hours"])) + rng.uniform(0, 0.98)
                    res = str(rng.choice(sens)) if p["res"] == "sensitive" or (p["res"] == "mixed" and rng.random() < 0.5) else str(rng.choice(e["resources"]))
                    self._emit(e, BASE.value + dd * DAY_NS + int(hour * 3600 * 1e9), str(rng.choice(e["ip_pool"])), e["home_city"], res, e["auth"], 1,
                               rng.uniform(20, 180), self._normal_cmd(e, rng) if e["priv"] else "", self._fp(e), "low_slow_exfil", aid)
            self._register(aid, "low_slow_exfil", [e], span_days=span, start_day=start, res=p["res"])

    # ------------------------------------------------------------------ benign drift (transformations of benign events)
    def apply_drift(self, normal: pd.DataFrame, kind: str, affected: list, d_start: float, d_end: float, rng, tag_start: int = 0):
        P = self.P
        dr = P.get("drift") or {}
        ramp_days = max(d_end - d_start, 1e-6)
        aidx = {e["idx"]: n for n, e in enumerate(affected)}
        ei = normal["ei"].to_numpy()
        day = normal["day"].to_numpy()
        for n, e in enumerate(affected):
            m = (ei == e["idx"]) & (day >= d_start)
            if not m.any():
                continue
            idx = np.where(m)[0]
            ramp = np.clip((day[idx] - d_start) / ramp_days, 0.0, 1.0)
            aid = f"BD{tag_start + n:03d}"
            if kind == "hours":
                shift = dr.get("hours_delta", 3.5) * ramp
                normal.loc[idx, "ts_ns"] = normal.loc[idx, "ts_ns"].to_numpy() + (shift * 3600 * 1e9).astype(np.int64)
                sel = idx[ramp > 0.05]
            elif kind == "resources":
                others = [r for r in self.pool_all_res if r not in set(e["resources"]) and r not in self.sens]
                new = list(rng.choice(others, size=min(dr.get("n_new_resources", 4), len(others)), replace=False)) if others else []
                take = rng.random(len(idx)) < dr.get("resource_prob", 0.35) * ramp
                sel = idx[take] if new else idx[:0]
                if len(sel):
                    normal.loc[sel, "res"] = rng.choice(new, size=len(sel))
            elif kind == "location":
                s = rng.uniform(d_start, d_end)
                sel = idx[day[idx] >= s]
                newc = str(rng.choice([c for c in P["home_cities"] if c != e["home_city"]]))
                if P["ip"]["mode"] == "private_pool":
                    npool = [f"10.{rng.integers(0, 255)}.{rng.integers(0, 255)}.{rng.integers(1, 254)}" for _ in range(3)]
                else:
                    pref = str(rng.choice(P["ip"]["public_isp"]))
                    npool = [f"{pref}.{rng.integers(0, 255)}.{rng.integers(1, 254)}" for _ in range(3)]
                if len(sel):
                    normal.loc[sel, "city"] = newc
                    normal.loc[sel, "ip"] = rng.choice(npool, size=len(sel))
            elif kind == "device":
                s = rng.uniform(d_start, d_end)
                sel = idx[day[idx] >= s]
                dev = P["device"]
                nos = str(rng.choice([o for o in dev[f"{e['tkey']}_os"] + dev["os_pool_all"] if o != e["os"]]))
                nmac = e["mac"] if rng.random() < 0.5 else ":".join(f"{rng.integers(0, 255):02x}" for _ in range(6))
                if len(sel):
                    normal.loc[sel, "fp"] = self._fp(e, nmac, nos)
            else:
                raise ValueError(kind)
            if len(sel):
                normal.loc[sel, "label"] = "benign_drift"
                normal.loc[sel, "aid"] = aid
        return normal

    def volume_drift(self, normal: pd.DataFrame, affected: list, d_start: float, d_end: float, rng_key: int) -> pd.DataFrame:
        dr = self.P.get("drift") or {}
        extra = []
        for n, e in enumerate(affected):
            for day in range(int(math.floor(d_start)), self.days):
                ramp = float(np.clip((day + 0.5 - d_start) / max(d_end - d_start, 1e-6), 0, 1))
                rng = self.rng(4, rng_key, e["idx"], day)
                dd = self.P["start_offset_days"] + day
                f = e["weekend"] if dd % 7 >= 5 else 1.0
                k = int(rng.poisson(e["epd"] * f * self.scale * dr.get("volume_factor", 0.9) * ramp))
                df = self._day_events(e, day, rng, n_override=k, extra=True)
                if df is not None:
                    df["label"] = "benign_drift"
                    df["aid"] = f"BD{n:03d}"
                    extra.append(df)
        return pd.concat([normal] + extra, ignore_index=True) if extra else normal

    # ------------------------------------------------------------------ orchestration
    def run(self):
        self.build_entities()
        normal = self.generate_normal()
        for fn in (self.inject_brute_force, self.inject_credential_stuffing, self.inject_impossible_travel, self.inject_lateral_movement,
                   self.inject_device_spoofing, self.inject_low_slow_exfil):
            fn()
        bd = self.P["benign_drift"]
        drift_meta = []
        if self.drift_study and self.drift_kind:
            drng = self.rng(4, 0)
            pool = self.by_type["user"] if self.drift_kind in ("hours", "resources", "location") else self.ents
            k = int(round(self.P["drift"]["affected_fraction"] * len(pool)))
            aff = [pool[int(i)] for i in drng.choice(len(pool), size=k, replace=False)]
            rng = self.rng(4, 1)
            if self.drift_kind == "volume":
                normal = self.volume_drift(normal, aff, K.DRIFT_START, K.DRIFT_END, 1)
            else:
                normal = self.apply_drift(normal, self.drift_kind, aff, K.DRIFT_START, K.DRIFT_END, rng)
            drift_meta.append({"kind": self.drift_kind, "affected_entities": len(aff), "start_day": K.DRIFT_START, "end_day": K.DRIFT_END,
                               "parameters": self.P["drift"]})
        elif bd["n"] > 0:
            rng = self.rng(5, 0)
            pool = self.by_type["user"] if bd.get("pool", "user") == "user" else self.by_type["edge"]
            aff = [pool[int(i)] for i in rng.choice(len(pool), size=min(bd["n"], len(pool)), replace=False)]
            s = bd["start_frac"] * self.days
            normal = self.apply_drift(normal, bd["kind"], aff, s, s + bd["days"], rng)
            drift_meta.append({"kind": bd["kind"], "affected_entities": len(aff), "start_day": s, "end_day": s + bd["days"]})
        cols = ["ts_ns", "ei", "ip", "city", "res", "auth", "success", "dur", "cmd", "fp", "label", "aid"]
        atk = pd.DataFrame(self.rows, columns=cols)
        allr = pd.concat([normal[cols], atk], ignore_index=True)
        order = np.argsort(allr["ts_ns"].to_numpy(), kind="stable")
        allr = allr.iloc[order].reset_index(drop=True)
        ts = (allr["ts_ns"].to_numpy() // 1000) * 1000
        for i in range(1, len(ts)):
            if ts[i] <= ts[i - 1]:
                ts[i] = ts[i - 1] + 1000
        ents = pd.DataFrame(self.ents)
        e = ents.set_index("idx").loc[allr["ei"].to_numpy()]
        events = pd.DataFrame({
            "event_id": np.arange(len(allr)), "entity_id": e["entity_id"].to_numpy(), "entity_type": e["entity_type"].to_numpy(),
            "timestamp": pd.to_datetime(ts), "source_ip": allr["ip"].to_numpy(),
            "geo_location": [_geo(c) for c in allr["city"].to_numpy()], "resource_accessed": allr["res"].to_numpy(),
            "auth_method": allr["auth"].to_numpy(), "auth_success": allr["success"].to_numpy(), "session_duration": allr["dur"].to_numpy(),
            "command_sequence": allr["cmd"].to_numpy(), "device_fingerprint": allr["fp"].to_numpy()})[C.SCHEMA]
        labels = pd.DataFrame({"event_id": np.arange(len(allr)), "label": allr["label"].to_numpy(), "attack_id": allr["aid"].to_numpy()})
        return events, labels, ents, drift_meta


def dataset_spec(dataset_id: str) -> dict:
    prof, seed, role, kind = K.REGISTRY[dataset_id]
    drift = kind == "drift"
    P = get_profile(prof, drift_study=drift)
    return {"dataset_id": dataset_id, "profile": prof, "seed": seed, "role": role, "kind": kind, "params": P,
            "drift_kind": K.DRIFT_KIND.get(dataset_id), "target_events": K.DRIFT_TARGET_EVENTS if drift else K.TARGET_EVENTS}


def generate_dataset(dataset_id: str, out_dir) -> dict:
    """Generate, write events.csv / labels.csv / incidents.json / entities.json / meta.json, return the meta (with file hashes)."""
    from pathlib import Path
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    spec = dataset_spec(dataset_id)
    g = Gen(spec["params"], spec["seed"], K.DAYS, K.ONBOARDING_DAYS, spec["target_events"], spec["drift_kind"], spec["kind"] == "drift")
    events, labels, ents, drift_meta = g.run()
    # unique entity ids per dataset (so pooled sequence windows / profilers can never mix datasets)
    tag = dataset_id.replace("-", "").lower()
    events["entity_id"] = tag + "-" + events["entity_id"]
    events.to_csv(out_dir / "events.csv", index=False)
    labels.to_csv(out_dir / "labels.csv", index=False)
    # incident ground truth (post-hoc completion from labels)
    lab = labels.merge(events[["event_id", "timestamp"]], on="event_id")
    inc = []
    for i in g.incidents:
        sub = lab[lab.attack_id == i["attack_id"]]
        t0, t1 = sub.timestamp.min(), sub.timestamp.max()
        i = dict(i)
        i.update({"n_events": int(len(sub)), "t_start": str(t0), "t_end": str(t1), "first_day": float((t0 - BASE).total_seconds() / 86400.0),
                  "duration_h": float((t1 - t0).total_seconds() / 3600.0), "entities": [f"{tag}-{x}" for x in i["entities"]]})
        if spec["kind"] == "drift":
            fd = i["first_day"]
            i["period"] = "before" if fd < K.DRIFT_START else ("during" if fd < K.DRIFT_END else "after")
        inc.append(i)
    json.dump(inc, open(out_dir / "incidents.json", "w"), indent=1, default=str)
    ents_out = ents.drop(columns=["res_w"]).copy()
    ents_out["entity_id"] = tag + "-" + ents_out["entity_id"]
    ents_out.to_json(out_dir / "entities.json", orient="records", indent=1)
    vc = labels.label.value_counts().to_dict()
    inc_by = pd.Series([i["type"] for i in inc]).value_counts().to_dict()
    ev_by = {t: int(vc.get(t, 0)) for t in C.ATTACK_TYPES}
    ts = events["timestamp"]
    meta = {"dataset_id": dataset_id, "role": spec["role"], "kind": spec["kind"], "profile": spec["profile"], "profile_description": spec["params"]["description"],
            "seed": spec["seed"], "generator_version": K.GEN_VERSION, "profile_version": spec["params"]["version"], "drift_kind": spec["drift_kind"],
            "days": K.DAYS, "onboarding_days": K.ONBOARDING_DAYS, "events": int(len(events)), "entities": int(events.entity_id.nunique()),
            "entities_by_type": events.groupby("entity_type").entity_id.nunique().to_dict(),
            "attack_events": int(sum(ev_by.values())), "incidents": int(len(inc)), "attack_types": [t for t in C.ATTACK_TYPES if ev_by[t] > 0],
            "attack_events_by_type": ev_by, "incidents_by_type": {t: int(inc_by.get(t, 0)) for t in C.ATTACK_TYPES},
            "benign_drift_events": int(vc.get("benign_drift", 0)), "label_counts": {k: int(v) for k, v in vc.items()},
            "time_span": {"start": str(ts.min()), "end": str(ts.max()), "days": float((ts.max() - ts.min()).total_seconds() / 86400.0)},
            "onboarding_end": str(BASE + pd.Timedelta(days=K.ONBOARDING_DAYS + spec["params"]["start_offset_days"])),
            "chronological": bool(ts.is_monotonic_increasing), "strictly_increasing": bool((ts.diff().dropna() > pd.Timedelta(0)).all()),
            "drift": drift_meta, "generator_parameters": spec["params"]}
    t_on = pd.Timestamp(meta["onboarding_end"])
    meta["integrity"] = {"attack_events_in_onboarding": int(((lab.timestamp < t_on) & lab.label.isin(C.ATTACK_TYPES)).sum()),
                         "benign_drift_events_in_onboarding": int(((lab.timestamp < t_on) & (lab.label == "benign_drift")).sum()),
                         "incident_ids_unique": bool(len({i["attack_id"] for i in inc}) == len(inc)),
                         "events_before_onboarding_end": int((events.timestamp < t_on).sum())}
    for f in ("events.csv", "labels.csv", "incidents.json", "entities.json"):
        meta.setdefault("file_sha256", {})[f] = K.sha256_file(out_dir / f)
    K.write_json(out_dir / "meta.json", meta)
    return meta

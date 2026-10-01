"""
Synthetic access-log generator.

Design principle: build NORMAL behaviour first and make it genuinely habitual
but noisy, then inject attacks on top. Ground-truth labels are written to a
SEPARATE file and are never present in the event stream the model consumes.

Run:  python -m src.generate --days 30 --out data/sample
"""
from __future__ import annotations
import argparse
import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

import config as C
from src.utils import haversine_km, set_seed

try:                      # optional -- only used for prettier IDs
    from faker import Faker
    _FAKE = Faker()
    Faker.seed(C.RANDOM_SEED)
except Exception:
    _FAKE = None


# ---------------------------------------------------------------------------
# 1. Entity profiles
# ---------------------------------------------------------------------------
def build_entities(rng: np.random.Generator) -> pd.DataFrame:
    """One row per entity, holding its behavioural profile parameters."""
    rows = []

    def _ip_pool(k):
        base = f"10.{rng.integers(0,255)}.{rng.integers(0,255)}"
        return [f"{base}.{rng.integers(1,254)}" for _ in range(k)]

    for i in range(C.N_USERS):
        role = C.ROLES[i % len(C.ROLES)]
        city = C.HOME_CITIES[rng.integers(len(C.HOME_CITIES))]
        rows.append(dict(
            entity_id=f"U{i:04d}", entity_type="user", role=role,
            home_city=city,
            login_hour_mean=float(rng.normal(10.0, 1.6)),
            login_hour_sd=float(rng.uniform(1.2, 2.6)),
            events_per_day=float(rng.uniform(18, 55)),
            dur_mu=float(rng.uniform(5.2, 6.4)),      # lognormal mu (seconds)
            dur_sigma=float(rng.uniform(0.5, 1.0)),
            auth_method=str(rng.choice(["password", "password", "biometric"])),
            weekend_factor=float(rng.uniform(0.02, 0.25)),
            ip_pool=_ip_pool(3),
            os=str(rng.choice(C.OS_POOL[:6])),
            mac=":".join(f"{rng.integers(0,255):02x}" for _ in range(6)),
            protocol="TLS1.3",
            zipf_a=float(rng.uniform(1.6, 2.4)),
        ))

    for i in range(C.N_SERVICE):
        city = C.HOME_CITIES[rng.integers(len(C.HOME_CITIES))]
        rows.append(dict(
            entity_id=f"S{i:04d}", entity_type="service_account", role="service_account",
            home_city=city,
            login_hour_mean=12.0, login_hour_sd=6.9,   # near-uniform across the day
            events_per_day=float(rng.uniform(120, 400)),
            dur_mu=float(rng.uniform(2.0, 3.5)), dur_sigma=float(rng.uniform(0.2, 0.5)),
            auth_method=str(rng.choice(["token", "certificate"])),
            weekend_factor=float(rng.uniform(0.85, 1.0)),  # no weekends off
            ip_pool=_ip_pool(2),
            os=str(rng.choice(["Ubuntu 22.04", "RHEL 9.3"])),
            mac=":".join(f"{rng.integers(0,255):02x}" for _ in range(6)),
            protocol="TLS1.2", zipf_a=float(rng.uniform(2.4, 3.2)),
        ))

    for i in range(C.N_DEVICES):
        city = C.HOME_CITIES[rng.integers(len(C.HOME_CITIES))]
        rows.append(dict(
            entity_id=f"D{i:04d}", entity_type="edge_device", role="edge_device",
            home_city=city,
            login_hour_mean=12.0, login_hour_sd=6.9,
            events_per_day=float(rng.uniform(200, 500)),
            dur_mu=float(rng.uniform(0.5, 1.5)), dur_sigma=0.3,
            auth_method="certificate",
            weekend_factor=1.0,
            ip_pool=_ip_pool(1),
            os=str(rng.choice(["Yocto 4.0", "FreeRTOS 10.5"])),
            mac=":".join(f"{rng.integers(0,255):02x}" for _ in range(6)),
            protocol=str(rng.choice(["MQTT3.1.1", "OPC-UA"])),
            zipf_a=3.0,
        ))

    df = pd.DataFrame(rows)
    # Habitual resource set: a Zipf-weighted subset of the role's resource pool.
    res_sets, res_w = [], []
    for _, r in df.iterrows():
        pool = C.RESOURCES[r["role"]]
        w = 1.0 / (np.arange(1, len(pool) + 1) ** r["zipf_a"])
        w = w / w.sum()
        res_sets.append(pool)
        res_w.append(w.tolist())
    df["resources"] = res_sets
    df["resource_w"] = res_w
    return df


def _fingerprint(row) -> str:
    return f"{row['os']}|{row['mac']}|{row['protocol']}"


def _geo(city: str) -> str:
    lat, lon = C.CITIES[city]
    return f"{city}|{lat}|{lon}"


def _command_sequence(role: str, rng, length=None, malicious=False) -> str:
    """Role-conditioned Markov chain over actions."""
    if length is None:
        length = int(rng.integers(2, 7))
    if malicious:
        seq = ["list", "sudo", "read", "read", "download"][:max(3, length)]
        return "|".join(seq)
    start = {"admin": "sudo", "ops": "read", "engineer": "list"}.get(role, "read")
    trans = {
        "list": ["read", "read", "list", "write"],
        "read": ["read", "list", "write", "download"],
        "write": ["read", "list", "exec"],
        "exec": ["read", "list"],
        "sudo": ["read", "write", "exec", "list"],
        "download": ["read", "list"],
        "delete": ["list"],
    }
    seq, cur = [start], start
    for _ in range(length - 1):
        cur = str(rng.choice(trans[cur]))
        seq.append(cur)
    return "|".join(seq)


# ---------------------------------------------------------------------------
# 2. Normal traffic
# ---------------------------------------------------------------------------
def generate_normal(ents: pd.DataFrame, days: int, rng) -> pd.DataFrame:
    start = datetime(2026, 6, 1)
    recs = []
    for _, e in ents.iterrows():
        pool, w = e["resources"], np.array(e["resource_w"])
        for d in range(days):
            day = start + timedelta(days=d)
            factor = e["weekend_factor"] if day.weekday() >= 5 else 1.0
            n = max(0, int(rng.poisson(e["events_per_day"] * factor)))
            if n == 0:
                continue
            hours = rng.normal(e["login_hour_mean"], e["login_hour_sd"], n) % 24
            for h in hours:
                ts = day + timedelta(hours=float(h))
                city = e["home_city"]
                ip = str(rng.choice(e["ip_pool"]))
                # 6% confounders: legitimate but unusual behaviour
                conf = rng.random() < C.CONFOUNDER_RATE
                if conf and rng.random() < 0.35:
                    city = str(rng.choice(C.HOME_CITIES))       # domestic travel
                    ip = f"192.168.{rng.integers(0,255)}.{rng.integers(1,254)}"
                res = str(rng.choice(pool, p=w))
                if conf and rng.random() < 0.3:
                    res = str(rng.choice(pool))                 # atypical resource
                dur = float(np.exp(rng.normal(e["dur_mu"], e["dur_sigma"])))
                success = 1 if rng.random() > 0.02 else 0       # 2% honest typos
                priv = e["role"] in ("admin", "ops", "engineer")
                recs.append((
                    e["entity_id"], e["entity_type"], ts, ip, _geo(city), res,
                    e["auth_method"], success, round(dur, 1),
                    _command_sequence(e["role"], rng) if priv else "",
                    _fingerprint(e),
                ))
    df = pd.DataFrame(recs, columns=[c for c in C.SCHEMA if c != "event_id"])
    return df


# ---------------------------------------------------------------------------
# 3. Attack injectors -- one function each, independently toggleable
# ---------------------------------------------------------------------------
def _blank(e, ts, ip, city, res, auth, success, dur, cmd, fp):
    return (e["entity_id"], e["entity_type"], ts, ip, _geo(city), res,
            auth, success, round(float(dur), 1), cmd, fp)


def inject_brute_force(ents, rng, n_attacks, days=C.N_DAYS):
    out, meta = [], []
    for a in range(n_attacks):
        e = ents.sample(1, random_state=int(rng.integers(1e6))).iloc[0]
        t0 = datetime(2026, 6, 1) + timedelta(days=float(rng.uniform(days * 0.70, days)))
        src = f"{rng.integers(11,220)}.{rng.integers(0,255)}.{rng.integers(0,255)}.{rng.integers(1,254)}"
        n = int(rng.integers(30, 200))
        aid = f"BF{a:03d}"
        for k in range(n):
            ts = t0 + timedelta(seconds=float(k * rng.uniform(1, 12)))
            out.append(_blank(e, ts, src, str(rng.choice(C.FOREIGN_CITIES)),
                              str(rng.choice(e["resources"])), e["auth_method"],
                              0, rng.uniform(0.1, 1.5), "", _fingerprint(e)))
            meta.append(("brute_force", aid))
        if rng.random() < 0.4:                       # 40% eventually succeed
            out.append(_blank(e, t0 + timedelta(seconds=float(n * 6 + 3)), src,
                              str(rng.choice(C.FOREIGN_CITIES)),
                              str(rng.choice(e["resources"])), e["auth_method"],
                              1, 300, "", _fingerprint(e)))
            meta.append(("brute_force", aid))
    return out, meta


def inject_credential_stuffing(ents, rng, n_attacks, days=C.N_DAYS):
    out, meta = [], []
    for a in range(n_attacks):
        victims = ents.sample(int(rng.integers(25, 70)),
                              random_state=int(rng.integers(1e6)))
        ips = [f"{rng.integers(11,220)}.{rng.integers(0,255)}.{rng.integers(0,255)}.{rng.integers(1,254)}"
               for _ in range(int(rng.integers(2, 4)))]
        t0 = datetime(2026, 6, 1) + timedelta(days=float(rng.uniform(days * 0.70, days)))
        aid = f"CS{a:03d}"
        for j, (_, e) in enumerate(victims.iterrows()):
            for _ in range(int(rng.integers(1, 4))):
                ts = t0 + timedelta(seconds=float(j * 40 + rng.uniform(0, 40)))
                out.append(_blank(e, ts, str(rng.choice(ips)),
                                  str(rng.choice(C.FOREIGN_CITIES)),
                                  str(rng.choice(e["resources"])), "password",
                                  1 if rng.random() < 0.03 else 0,
                                  rng.uniform(0.1, 2.0), "", _fingerprint(e)))
                meta.append(("credential_stuffing", aid))
    return out, meta


def inject_impossible_travel(ents, rng, n_attacks, days=C.N_DAYS):
    """Includes deliberate NEAR-MISSES labelled normal: a plausible long flight."""
    out, meta = [], []
    for a in range(n_attacks):
        e = ents.sample(1, random_state=int(rng.integers(1e6))).iloc[0]
        t0 = datetime(2026, 6, 1) + timedelta(days=float(rng.uniform(days * 0.70, days)),
                                              hours=float(rng.uniform(8, 20)))
        home = e["home_city"]
        far = str(rng.choice([c for c in C.FOREIGN_CITIES
                              if haversine_km(*C.CITIES[home], *C.CITIES[c]) > 6000]))
        aid = f"IT{a:03d}"
        out.append(_blank(e, t0, str(rng.choice(e["ip_pool"])), home,
                          str(rng.choice(e["resources"])), e["auth_method"], 1,
                          rng.uniform(200, 900), "", _fingerprint(e)))
        meta.append(("normal", ""))                              # the home login
        gap = float(rng.uniform(0.4, 1.6))                       # 24-96 minutes
        out.append(_blank(e, t0 + timedelta(hours=gap),
                          f"{rng.integers(11,220)}.{rng.integers(0,255)}.{rng.integers(0,255)}.{rng.integers(1,254)}",
                          far, str(rng.choice(e["resources"])), e["auth_method"], 1,
                          rng.uniform(200, 900), "", _fingerprint(e)))
        meta.append(("impossible_travel", aid))
    # Near-misses: same distance, but a physically possible 9-14 hour gap.
    for _ in range(max(2, n_attacks // 2)):
        e = ents.sample(1, random_state=int(rng.integers(1e6))).iloc[0]
        t0 = datetime(2026, 6, 1) + timedelta(days=float(rng.uniform(days * 0.70, days)))
        far = str(rng.choice(C.FOREIGN_CITIES))
        out.append(_blank(e, t0, str(rng.choice(e["ip_pool"])), e["home_city"],
                          str(rng.choice(e["resources"])), e["auth_method"], 1, 400, "",
                          _fingerprint(e)))
        meta.append(("normal", ""))
        out.append(_blank(e, t0 + timedelta(hours=float(rng.uniform(9, 14))),
                          f"{rng.integers(11,220)}.{rng.integers(0,255)}.0.5", far,
                          str(rng.choice(e["resources"])), e["auth_method"], 1, 400, "",
                          _fingerprint(e)))
        meta.append(("normal", ""))
    return out, meta


def inject_lateral_movement(ents, rng, n_attacks, days=C.N_DAYS):
    out, meta = [], []
    all_res = sorted({r for v in C.RESOURCES.values() for r in v})
    for a in range(n_attacks):
        e = ents.sample(1, random_state=int(rng.integers(1e6))).iloc[0]
        own = set(e["resources"])
        foreign = [r for r in all_res if r not in own]
        t0 = datetime(2026, 6, 1) + timedelta(days=float(rng.uniform(days * 0.70, days)),
                                              hours=float(rng.uniform(1, 5)))
        aid = f"LM{a:03d}"
        n = int(rng.integers(15, 45))
        for k in range(n):
            ts = t0 + timedelta(minutes=float(k * rng.uniform(1.5, 6)))
            # breadth expands over time -- the signature of lateral movement
            res = str(rng.choice(foreign[: max(3, int(len(foreign) * (k + 1) / n))]))
            out.append(_blank(e, ts, str(rng.choice(e["ip_pool"])), e["home_city"],
                              res, e["auth_method"], 1, rng.uniform(5, 90),
                              _command_sequence(e["role"], rng, malicious=True),
                              _fingerprint(e)))
            meta.append(("lateral_movement", aid))
    return out, meta


def inject_device_spoofing(ents, rng, n_attacks, days=C.N_DAYS):
    out, meta = [], []
    pool = ents[ents.entity_type.isin(["edge_device", "service_account"])]
    if pool.empty:
        pool = ents
    for a in range(n_attacks):
        e = pool.sample(1, random_state=int(rng.integers(1e6))).iloc[0]
        t0 = datetime(2026, 6, 1) + timedelta(days=float(rng.uniform(days * 0.70, days)))
        bad_fp = "{}|{}|{}".format(
            str(rng.choice([o for o in C.OS_POOL if o != e["os"]])),
            ":".join(f"{rng.integers(0,255):02x}" for _ in range(6)),
            str(rng.choice(C.PROTOCOLS)))
        aid = f"DS{a:03d}"
        for k in range(int(rng.integers(6, 25))):
            ts = t0 + timedelta(minutes=float(k * rng.uniform(2, 15)))
            out.append(_blank(e, ts, str(rng.choice(e["ip_pool"])), e["home_city"],
                              str(rng.choice(e["resources"])), e["auth_method"], 1,
                              rng.uniform(1, 30), "", bad_fp))
            meta.append(("device_spoofing", aid))
    return out, meta


def inject_low_slow_exfil(ents, rng, n_attacks, days=C.N_DAYS):
    """Each event looks near-normal. The signal exists only in the aggregate."""
    out, meta = [], []
    for a in range(n_attacks):
        e = ents[ents.entity_type == "user"].sample(
            1, random_state=int(rng.integers(1e6))).iloc[0]
        sens = [r for r in e["resources"] if r in C.SENSITIVE] or list(e["resources"])[:2]
        aid = f"LS{a:03d}"
        # Anchored to the TEST window. Starting it inside the training window
        # would let the campaign poison its own baseline, which both hides the
        # attack and misrepresents how the system performs in deployment.
        start = int(days * 0.68)
        span = max(4, min(int(rng.integers(6, 14)), days - start - 1))
        for d in range(span):
            day = datetime(2026, 6, 1) + timedelta(days=float(start + d))
            for _ in range(int(rng.integers(1, 4))):
                hour = float(rng.choice([1, 2, 3, 22, 23]))     # off-hours, but plausible
                ts = day + timedelta(hours=hour, minutes=float(rng.uniform(0, 59)))
                out.append(_blank(e, ts, str(rng.choice(e["ip_pool"])), e["home_city"],
                                  str(rng.choice(sens)), e["auth_method"], 1,
                                  rng.uniform(20, 180),
                                  _command_sequence(e["role"], rng), _fingerprint(e)))
                meta.append(("low_slow_exfil", aid))
    return out, meta


def inject_benign_drift(ents, rng, n_cases, days=C.N_DAYS):
    """Legitimate expansion of footprint. Labelled benign_drift -- FP tuning."""
    out, meta = [], []
    all_res = sorted({r for v in C.RESOURCES.values() for r in v})
    for a in range(n_cases):
        e = ents[ents.entity_type == "user"].sample(
            1, random_state=int(rng.integers(1e6))).iloc[0]
        new = [r for r in all_res if r not in set(e["resources"])][:4]
        aid = f"BD{a:03d}"
        start = int(days * 0.45)
        for d in range(min(14, days - start - 1)):
            day = datetime(2026, 6, 1) + timedelta(days=float(start + d))
            n = int(1 + d * 0.6)                     # ramps up, then stays
            for _ in range(n):
                ts = day + timedelta(hours=float(rng.normal(e["login_hour_mean"], 1.5) % 24))
                out.append(_blank(e, ts, str(rng.choice(e["ip_pool"])), e["home_city"],
                                  str(rng.choice(new)), e["auth_method"], 1,
                                  float(np.exp(rng.normal(e["dur_mu"], e["dur_sigma"]))),
                                  _command_sequence(e["role"], rng), _fingerprint(e)))
                meta.append(("benign_drift", aid))
    return out, meta


# ---------------------------------------------------------------------------
# 4. Orchestration
# ---------------------------------------------------------------------------
def generate(days=C.N_DAYS, seed=C.RANDOM_SEED, out_dir=C.SAMPLE_DIR, scale=1.0):
    rng = set_seed(seed)
    ents = build_entities(rng)
    if scale != 1.0:
        ents["events_per_day"] = ents["events_per_day"] * scale

    print(f"[gen] {len(ents)} entities, {days} days ...")
    normal = generate_normal(ents, days, rng)
    normal_labels = pd.DataFrame({"label": [C.NORMAL] * len(normal),
                                  "attack_id": [""] * len(normal)})

    # Sized so that TOTAL anomalous EVENTS land near INJECTION_RATE of the
    # corpus -- attacks differ hugely in events-per-incident, so counting
    # incidents rather than events would give a wildly wrong positive rate.
    n_base = max(2, int(len(normal) * C.INJECTION_RATE / 250))
    injectors = [
        (inject_brute_force,         max(2, n_base)),
        (inject_credential_stuffing, max(1, n_base // 3)),
        (inject_impossible_travel,   max(6, n_base * 3)),
        (inject_lateral_movement,    max(3, n_base)),
        (inject_device_spoofing,     max(3, n_base)),
        (inject_low_slow_exfil,      max(3, n_base)),
        (inject_benign_drift,        max(2, n_base // 2)),
    ]
    atk_rows, atk_meta = [], []
    for fn, n in injectors:
        # Every injector now takes `days` and places its attack window as a
        # FRACTION of the timeline (not a hardcoded absolute day range), so
        # --days values other than the default 30 place attacks inside the
        # actual generated date range instead of past the end of it.
        r, m = fn(ents, rng, n, days)
        atk_rows += r
        atk_meta += m
        print(f"[gen]   {fn.__name__:28s} -> {len(r):6d} events")

    atk = pd.DataFrame(atk_rows, columns=[c for c in C.SCHEMA if c != "event_id"])
    atk_labels = pd.DataFrame(atk_meta, columns=["label", "attack_id"])

    events = pd.concat([normal, atk], ignore_index=True)
    labels = pd.concat([normal_labels, atk_labels], ignore_index=True)
    events["_lab"] = labels["label"].values
    events["_aid"] = labels["attack_id"].values

    events = events.sort_values("timestamp").reset_index(drop=True)
    events.insert(0, "event_id", np.arange(len(events)))

    labels_out = events[["event_id", "_lab", "_aid"]].rename(
        columns={"_lab": "label", "_aid": "attack_id"})
    events_out = events[C.SCHEMA]

    out_dir.mkdir(parents=True, exist_ok=True)
    events_out.to_csv(out_dir / "events.csv", index=False)
    labels_out.to_csv(out_dir / "labels.csv", index=False)
    ents.drop(columns=["resource_w"]).to_json(out_dir / "entity_profiles.json",
                                              orient="records", indent=1)

    vc = labels_out.label.value_counts()
    anom = len(labels_out) - vc.get(C.NORMAL, 0)
    print(f"[gen] {len(events_out):,} events | anomalous+edge: {anom:,} "
          f"({100*anom/len(events_out):.2f}%)")
    print(vc.to_string())
    print(f"[gen] written to {out_dir}")
    return events_out, labels_out


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--days", type=int, default=C.N_DAYS)
    p.add_argument("--seed", type=int, default=C.RANDOM_SEED)
    p.add_argument("--scale", type=float, default=1.0,
                   help="scale events-per-day (use 0.3 for a fast smoke test)")
    p.add_argument("--out", type=str, default=str(C.SAMPLE_DIR))
    a = p.parse_args()
    from pathlib import Path
    generate(days=a.days, seed=a.seed, out_dir=Path(a.out), scale=a.scale)

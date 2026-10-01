"""
Real-dataset adapters.

Everything downstream consumes the canonical schema in config.SCHEMA. Each
adapter's only job is to map a public dataset INTO that schema, so the same
feature pipeline, detector, classifier and dashboard work unchanged on
synthetic and real data. That portability is itself a talking point: the
problem statement stresses the task is domain-agnostic.

Datasets are NOT bundled (they are 1-12 GB and licence-restricted). Download
them yourself -- see REFERENCES.md -- and drop them in data/raw/.

Usage:
    python -m src.datasets --source lanl  --path data/raw/lanl --out data/lanl
    python -m src.datasets --source cert  --path data/raw/r4.2 --out data/cert
    python -m src.datasets --list
"""
from __future__ import annotations
import argparse
from pathlib import Path
import numpy as np
import pandas as pd

import config as C

CATALOGUE = {
    "lanl": {
        "name": "LANL Comprehensive, Multi-Source Cyber-Security Events",
        "url": "https://csr.lanl.gov/data/cyber1/",
        "files": "auth.txt.gz (~70GB uncompressed), redteam.txt.gz (4.8K)",
        "labels": "redteam.txt gives ground-truth compromise events",
        "why": "real enterprise auth logs with red-team labels; ideal for "
               "lateral movement and credential misuse",
        "cite": "A. D. Kent, Comprehensive Multi-Source Cyber-Security Events, "
                "Los Alamos National Laboratory, 2015. doi:10.17021/1179829",
    },
    "cert": {
        "name": "CMU CERT Insider Threat Test Dataset (r4.2 recommended)",
        "url": "https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247",
        "files": "logon.csv, device.csv, file.csv, http.csv, email.csv, answers/",
        "labels": "answers/ directory contains the malicious-scenario key",
        "why": "per-user behavioural logs over 17 months with insider scenarios; "
               "closest public analogue to this problem statement",
        "cite": "Glasser & Lindauer, Bridging the Gap: A Pragmatic Approach to "
                "Generating Insider Threat Data, IEEE S&P Workshops, 2013",
    },
    "generic": {
        "name": "Any CSV already in (or close to) the canonical schema",
        "url": "-",
        "files": "your own export",
        "labels": "optional labels.csv with event_id,label",
        "why": "escape hatch for a SIEM export or another public set",
        "cite": "-",
    },
}


def _mk(df: pd.DataFrame) -> pd.DataFrame:
    for col in C.SCHEMA:
        if col not in df.columns:
            df[col] = "" if col not in ("auth_success", "session_duration",
                                        "event_id") else 0
    return df[C.SCHEMA]


# ---------------------------------------------------------------------------
def load_lanl(path: Path, max_rows: int = 3_000_000, day_range=(6, 12)):
    """
    LANL auth.txt columns:
      time, src_user@domain, dst_user@domain, src_computer, dst_computer,
      auth_type, logon_type, auth_orientation, success/failure
    Time is seconds since epoch-of-capture. Days 6-12 contain most red-team
    activity, so we default to that slice to keep it laptop-sized.
    """
    path = Path(path)
    auth = path / "auth.txt" if (path / "auth.txt").exists() else path / "auth.txt.gz"
    red = path / "redteam.txt" if (path / "redteam.txt").exists() else path / "redteam.txt.gz"
    if not auth.exists():
        raise FileNotFoundError(f"expected {auth}. See REFERENCES.md for the download link.")

    cols = ["time", "src_user", "dst_user", "src_comp", "dst_comp",
            "auth_type", "logon_type", "auth_orient", "outcome"]
    lo, hi = day_range[0] * 86400, day_range[1] * 86400
    chunks = []
    total = 0
    for ch in pd.read_csv(auth, names=cols, header=None, chunksize=500_000):
        ch = ch[(ch.time >= lo) & (ch.time < hi)]
        if len(ch):
            chunks.append(ch)
            total += len(ch)
        if ch.time.max() if len(ch) else 0 > hi or total > max_rows:
            break
    df = pd.concat(chunks, ignore_index=True) if chunks else pd.DataFrame(columns=cols)
    print(f"[lanl] {len(df):,} auth events in day window {day_range}")

    base = pd.Timestamp("2026-06-01")
    out = pd.DataFrame({
        "entity_id": df.src_user.astype(str),
        "entity_type": np.where(df.src_user.astype(str).str.contains("C"),
                                "service_account", "user"),
        "timestamp": base + pd.to_timedelta(df.time, unit="s"),
        "source_ip": df.src_comp.astype(str),
        "geo_location": "Datacenter|0.0|0.0",     # LANL has no geo; feature degrades to 0
        "resource_accessed": df.dst_comp.astype(str),
        "auth_method": df.auth_type.astype(str),
        "auth_success": (df.outcome.astype(str) == "Success").astype(int),
        "session_duration": 0.0,
        "command_sequence": df.auth_orient.astype(str),
        "device_fingerprint": df.src_comp.astype(str) + "|" + df.logon_type.astype(str),
    })
    out = out.sort_values("timestamp").reset_index(drop=True)
    out.insert(0, "event_id", np.arange(len(out)))

    labels = pd.DataFrame({"event_id": out.event_id, "label": C.NORMAL, "attack_id": ""})
    if red.exists():
        rt = pd.read_csv(red, names=["time", "user", "src_comp", "dst_comp"], header=None)
        key = set(zip(rt.user.astype(str), rt.src_comp.astype(str), rt.dst_comp.astype(str)))
        mask = [ (u, s, d) in key for u, s, d in
                 zip(out.entity_id, out.source_ip, out.resource_accessed) ]
        labels.loc[mask, "label"] = "lateral_movement"
        labels.loc[mask, "attack_id"] = "REDTEAM"
        print(f"[lanl] {int(np.sum(mask)):,} red-team events matched")
    return out, labels


# ---------------------------------------------------------------------------
def load_cert(path: Path, users: int = 200):
    """
    CERT r4.2: logon.csv / device.csv / file.csv / http.csv, each with
    id,date,user,pc,activity(+url/filename). Answers dir holds ground truth.
    """
    path = Path(path)
    frames = []

    def _read(name, act_col="activity", extra=None):
        f = path / name
        if not f.exists():
            print(f"[cert] skipping missing {name}")
            return None
        d = pd.read_csv(f)
        d.columns = [c.lower() for c in d.columns]
        return d

    logon = _read("logon.csv")
    if logon is None:
        raise FileNotFoundError(f"expected {path/'logon.csv'}. See REFERENCES.md.")
    keep = logon.user.drop_duplicates().head(users)
    logon = logon[logon.user.isin(keep)]

    def _emit(d, kind, res_col=None):
        if d is None or len(d) == 0:
            return
        d = d[d.user.isin(keep)]
        frames.append(pd.DataFrame({
            "entity_id": d.user.astype(str),
            "entity_type": "user",
            "timestamp": pd.to_datetime(d.date),
            "source_ip": d.pc.astype(str),
            "geo_location": "Office|0.0|0.0",
            "resource_accessed": (d[res_col].astype(str) if res_col and res_col in d
                                  else kind + "/" + d.get("activity", kind).astype(str)),
            "auth_method": "password",
            "auth_success": 1,
            "session_duration": 0.0,
            "command_sequence": d.get("activity", pd.Series([""] * len(d))).astype(str),
            "device_fingerprint": d.pc.astype(str),
        }))

    _emit(logon, "logon")
    _emit(_read("device.csv"), "device")
    _emit(_read("file.csv"), "file", res_col="filename")
    _emit(_read("http.csv"), "http", res_col="url")

    out = pd.concat(frames, ignore_index=True).sort_values("timestamp")
    out = out.reset_index(drop=True)
    out.insert(0, "event_id", np.arange(len(out)))
    print(f"[cert] {len(out):,} events for {out.entity_id.nunique()} users")

    labels = pd.DataFrame({"event_id": out.event_id, "label": C.NORMAL, "attack_id": ""})
    ans = path / "answers"
    if ans.exists():
        mal_users = set()
        for f in ans.rglob("*.csv"):
            try:
                a = pd.read_csv(f, header=None)
                mal_users |= set(a.iloc[:, 3].astype(str)) if a.shape[1] > 3 else set()
            except Exception:
                continue
        mask = out.entity_id.isin(mal_users)
        labels.loc[mask, "label"] = "low_slow_exfil"
        labels.loc[mask, "attack_id"] = "CERT"
        print(f"[cert] {int(mask.sum()):,} events from {len(mal_users)} flagged insiders")
    else:
        print("[cert] no answers/ dir found -- running unlabelled")
    return out, labels


# ---------------------------------------------------------------------------
def load_generic(path: Path):
    path = Path(path)
    ev = pd.read_csv(path if path.is_file() else path / "events.csv")
    ev["timestamp"] = pd.to_datetime(ev["timestamp"])
    ev = _mk(ev)
    lp = (path.parent if path.is_file() else path) / "labels.csv"
    labels = pd.read_csv(lp) if lp.exists() else pd.DataFrame(
        {"event_id": ev.event_id, "label": C.NORMAL, "attack_id": ""})
    return ev, labels


LOADERS = {"lanl": load_lanl, "cert": load_cert, "generic": load_generic}


def load(source: str, path):
    if source == "synthetic":
        from src.utils import load_events
        p = Path(path)
        return load_events(p / "events.csv"), pd.read_csv(p / "labels.csv")
    return LOADERS[source](Path(path))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=list(LOADERS), default="lanl")
    ap.add_argument("--path", type=str, default="data/raw")
    ap.add_argument("--out", type=str, default="data/real")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        for k, v in CATALOGUE.items():
            print(f"\n=== {k} ===")
            for kk, vv in v.items():
                print(f"  {kk:8s}: {vv}")
        raise SystemExit
    ev, lb = LOADERS[a.source](Path(a.path))
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    ev.to_csv(out / "events.csv", index=False)
    lb.to_csv(out / "labels.csv", index=False)
    print(f"[{a.source}] wrote {len(ev):,} events -> {out}")

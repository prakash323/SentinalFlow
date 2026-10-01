"""Small shared helpers."""
from __future__ import annotations
import math
import numpy as np
import pandas as pd


def set_seed(seed: int) -> np.random.Generator:
    np.random.seed(seed)
    return np.random.default_rng(seed)


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    """Great-circle distance in km. Used for geo-velocity."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def parse_geo(g: str):
    """'City|lat|lon' -> (city, lat, lon)"""
    if not isinstance(g, str) or "|" not in g:
        return ("unknown", 0.0, 0.0)
    parts = g.split("|")
    try:
        return (parts[0], float(parts[1]), float(parts[2]))
    except Exception:
        return (parts[0], 0.0, 0.0)


def psi(expected: np.ndarray, actual: np.ndarray, bins: int = 10) -> float:
    """Population Stability Index. >0.25 conventionally means major shift."""
    expected = np.asarray(expected, dtype=float)
    actual = np.asarray(actual, dtype=float)
    expected = expected[np.isfinite(expected)]
    actual = actual[np.isfinite(actual)]
    if len(expected) < 20 or len(actual) < 20:
        return 0.0
    qs = np.unique(np.quantile(expected, np.linspace(0, 1, bins + 1)))
    if len(qs) < 3:
        return 0.0
    e, _ = np.histogram(expected, bins=qs)
    a, _ = np.histogram(actual, bins=qs)
    e = np.clip(e / max(e.sum(), 1), 1e-6, None)
    a = np.clip(a / max(a.sum(), 1), 1e-6, None)
    return float(np.sum((a - e) * np.log(a / e)))


def rank_normalise(x: np.ndarray) -> np.ndarray:
    """Map any score to [0,1] by rank. Makes heterogeneous scores fusable."""
    x = np.asarray(x, dtype=float)
    x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)
    order = x.argsort().argsort()
    return order / max(len(x) - 1, 1)


def load_events(path):
    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    if "command_sequence" in df:
        df["command_sequence"] = df["command_sequence"].fillna("")
    return df.sort_values("timestamp").reset_index(drop=True)

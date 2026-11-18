"""Result events, in the spec's event schema, appended as JSON lines.

One file per test per UTC day: <results_dir>/<YYYY-MM-DD>/<test>.jsonl. Files are
world-readable so a future collector, or anyone on the box, can read them
without root.
"""
from __future__ import annotations

import datetime
import fcntl
import json
import math
import os
import statistics
import time

from . import config as C


def utc_iso(ts: float | None = None) -> str:
    dt = datetime.datetime.fromtimestamp(time.time() if ts is None else ts, datetime.timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def make(cfg: dict, client: dict | None, test: str, target=None, resolver=None, ts=None) -> dict:
    return {
        "ts": utc_iso(ts),
        "probe_id": cfg["probe_id"],
        "client_id": client["id"] if client else None,
        "iface": client["iface"] if client else None,
        "vlan": client.get("vlan", "") if client else "",
        "zone": client.get("zone", "") if client else "",
        "test": test,
        "target": target,
        "resolver": resolver,
        "outcome": None,
        "phase_ms": {},
        "value": {},
        "error": None,
        "agent_ver": C.AGENT_VER,
        "config_ver": cfg["_ver"],
        "hw_class": cfg.get("hw_class"),
    }


def emit(cfg: dict, ev: dict, summary: str | None = None) -> str:
    """Append one event and print a one-line summary for the scheduler's log."""
    if ev.get("outcome") is None:
        ev["outcome"] = C.HARNESS
        ev["error"] = ev.get("error") or "test finished without an outcome"
    day_dir = os.path.join(cfg["results_dir"], ev["ts"][:10])
    os.makedirs(day_dir, mode=0o755, exist_ok=True)
    path = os.path.join(day_dir, f"{ev['test']}.jsonl")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        # Stamped under the lock, so each file is in "emitted" order: the collector resumes from it.
        ev["emitted"] = utc_iso()       # when the result was written; ts is when the test started
        os.write(fd, (json.dumps(ev, separators=(",", ":"), default=str) + "\n").encode())
    finally:
        os.close(fd)
    if summary is None:
        bits = [ev["test"], ev["client_id"] or "-", ev["target"] or "-", f"outcome={ev['outcome']}"]
        if ev.get("error"):
            bits.append(f"error={ev['error']}")
        summary = " ".join(str(b) for b in bits)
    print(summary, flush=True)
    return path


def pct(values, p: float):
    """Percentile by linear interpolation; None for an empty list."""
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    if len(vals) == 1:
        return round(vals[0], 2)
    k = (len(vals) - 1) * p / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    return round(vals[lo] + (vals[hi] - vals[lo]) * (k - lo), 2)


def median(values):
    vals = [v for v in values if v is not None]
    return round(statistics.median(vals), 2) if vals else None


def ms(seconds) -> float | None:
    return None if seconds is None else round(seconds * 1000.0, 2)

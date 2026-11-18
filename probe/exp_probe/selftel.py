"""Self telemetry: `probe_self` every 60 s (02-probe.md 5.12) and the status file health reads.

* `Stats` -- sliding-window counters (measurements/min per test, fail/error per min, skipped/hour).
* `build_probe_self` -- the `probe_self` measurement (spool depth/bytes, push lag, clock offset,
  CPU, RSS, dropped, skipped).
* `StatusWriter` -- writes ``/run/exp/probe/status.json`` atomically; `exp-probe health` (a separate
  process) combines it with live namespace counters and the spool file.
"""
from __future__ import annotations

import collections
import logging
import os
import re
import threading
import time
from collections.abc import Callable
from typing import Any

from exp_common.atomic import atomic_write_json
from exp_common.schema import Measurement, measure

from . import __version__
from .config import Paths, ProbeConfig

log = logging.getLogger(__name__)

STATUS_SCHEMA = "exp.probe.status/1"
STATUS_MAX_AGE_S = 30.0
# measurement test -> health line key used in ports[].last
LINE_OF_TEST = {"gateway": "network", "dhcp_hb": "dhcp", "dhcp": "dhcp", "dns_hb": "dns", "dns": "dns",
                "ping": "internet", "trace": "internet"}
OUTCOME_WORD = {"ok": "ok", "degraded": "warn", "fail": "fail", "error": "unknown"}


def build_measurement(cfg: ProbeConfig, test: str, outcome: str, **kw: Any) -> Measurement:
    """Every probe measurement is created here so identity fields are always right."""
    return measure(cfg.probe_id, test, outcome, site=cfg.site, agent_ver=__version__, **kw)


class Stats:
    """Thread-safe sliding-window counters."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self.clock = clock
        self._lock = threading.Lock()
        self._recent: collections.deque[tuple[float, str, str]] = collections.deque()
        self._skips: collections.deque[tuple[float, str]] = collections.deque()
        self.skipped_total: collections.Counter[str] = collections.Counter()
        self.ports: dict[str, dict[str, Any]] = {}
        self.unavailable: set[str] = set()
        self.clock_offset_ms: float | None = None

    def record(self, m: Measurement) -> None:
        now = self.clock()
        with self._lock:
            self._recent.append((now, m.test, m.outcome))
            self._trim(now)
            if m.test == "probe_self":
                self.clock_offset_ms = m.metrics.get("clock_offset_ms")
            port = m.labels.get("port")
            if port:
                st = self.ports.setdefault(port, {"last": {}, "last_error_ts": None})
                line = LINE_OF_TEST.get(m.test)
                if line:
                    st["last"][line] = OUTCOME_WORD.get(m.outcome, "unknown")
                if m.outcome in ("error", "fail"):
                    st["last_error_ts"] = now
                    st["last_error"] = (m.error or "")[:200]

    def skipped(self, test: str) -> None:
        now = self.clock()
        with self._lock:
            self._skips.append((now, test))
            self.skipped_total[test] += 1
            self._trim(now)

    def _trim(self, now: float) -> None:
        while self._recent and now - self._recent[0][0] > 60:
            self._recent.popleft()
        while self._skips and now - self._skips[0][0] > 3600:
            self._skips.popleft()

    def snapshot(self) -> dict[str, Any]:
        now = self.clock()
        with self._lock:
            self._trim(now)
            by_test = collections.Counter(t for _, t, _ in self._recent)
            return {
                "measurements_per_min": len(self._recent),
                "by_test_per_min": dict(by_test),
                "fail_per_min": sum(1 for _, _, o in self._recent if o == "fail"),
                "error_per_min": sum(1 for _, _, o in self._recent if o == "error"),
                "skipped_per_hour": len(self._skips),
                "clock_offset_ms": self.clock_offset_ms,
                "skipped": dict(self.skipped_total),
                "ports": {k: {"last": dict(v["last"]), "last_error_ts": v.get("last_error_ts"),
                              "last_error": v.get("last_error", "")} for k, v in self.ports.items()},
            }


# ------------------------------------------------------------------------------- process stats

class ProcSampler:
    """CPU% of this process between samples, RSS from /proc."""

    def __init__(self, proc: str | os.PathLike[str] = "/proc", clock: Callable[[], float] = time.monotonic) -> None:
        self.proc = str(proc)
        self.clock = clock
        self._last: tuple[float, float] | None = None
        self.ticks = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100

    def _cpu_seconds(self) -> float | None:
        try:
            with open(f"{self.proc}/self/stat", encoding="utf-8") as fh:
                data = fh.read()
            fields = data[data.rindex(")") + 2:].split()
            return (int(fields[11]) + int(fields[12])) / self.ticks      # utime + stime
        except (OSError, ValueError, IndexError):
            return None

    def cpu_pct(self) -> float | None:
        cpu, now = self._cpu_seconds(), self.clock()
        if cpu is None:
            return None
        prev, self._last = self._last, (cpu, now)
        if prev is None or now <= prev[1]:
            return None
        return round(max(0.0, (cpu - prev[0]) / (now - prev[1]) * 100.0), 2)

    def rss_mb(self) -> float | None:
        try:
            with open(f"{self.proc}/self/status", encoding="utf-8") as fh:
                for ln in fh:
                    if ln.startswith("VmRSS:"):
                        return round(int(ln.split()[1]) / 1024.0, 2)
        except (OSError, ValueError, IndexError):
            return None
        return None


_UNIT_MS = {"us": 0.001, "µs": 0.001, "ms": 1.0, "s": 1000.0}
_OFFSET_RE = re.compile(r"Offset:\s*([+-]?[0-9.]+)\s*(us|µs|ms|s)\b")


def clock_offset(runner: Any) -> tuple[float | None, bool | None]:
    """(offset in ms or None, ntp_synced or None). Tries chrony, then systemd-timesyncd; every tool
    may be absent -- that yields (None, None), never an error."""
    synced: bool | None = None
    r = runner.run(["timedatectl", "show", "--property=NTPSynchronized", "--value"], 3)
    if r.ok and r.stdout.strip() in ("yes", "no"):
        synced = r.stdout.strip() == "yes"
    r = runner.run(["chronyc", "-c", "tracking"], 3)
    if r.ok:
        parts = r.stdout.strip().split(",")
        try:
            return abs(float(parts[4])) * 1000.0, True if synced is None else synced   # system time, seconds
        except (IndexError, ValueError):
            pass
    r = runner.run(["timedatectl", "timesync-status"], 3)
    if r.ok:
        m = _OFFSET_RE.search(r.stdout)
        if m:
            return abs(float(m.group(1))) * _UNIT_MS[m.group(2)], True if synced is None else synced
    r = runner.run(["timedatectl", "show-timesync"], 3)    # presence + server name only; no offset
    if r.ok and synced is None:
        synced = "ServerName=" in r.stdout
    return None, synced


def build_probe_self(cfg: ProbeConfig, spool: Any, stats: Stats, shipper_status: dict[str, Any],
                     sampler: ProcSampler, runner: Any, now: float | None = None) -> Measurement:
    st = spool.stat()
    metrics: dict[str, float] = {
        "spool_depth": float(st["depth"]), "spool_bytes": float(st["bytes"]),
        "push_lag_s": round(spool.push_lag_s(now), 3), "dropped_total": float(st["dropped_total"]),
    }
    off, synced = clock_offset(runner)
    if off is not None:
        metrics["clock_offset_ms"] = round(off, 3)
    cpu, rss = sampler.cpu_pct(), sampler.rss_mb()
    if cpu is not None:
        metrics["cpu_pct"] = cpu
    if rss is not None:
        metrics["rss_mb"] = rss
    snap = stats.snapshot()
    detail: dict[str, Any] = {"skipped": snap["skipped"], "skipped_total": sum(snap["skipped"].values()),
                              "shipper_state": shipper_status.get("state", "")}
    if synced is not None:
        detail["ntp_synced"] = synced
    return build_measurement(cfg, "probe_self", "ok", metrics=metrics, detail=detail)


class StatusWriter:
    """Writes status.json (atomic, 0644) at most every `min_interval` seconds."""

    def __init__(self, paths: Paths, cfg: ProbeConfig, stats: Stats, spool: Any,
                 shipper_status: Callable[[], dict[str, Any]], clock: Callable[[], float] = time.time,
                 min_interval: float = 4.0, counters: Callable[[], dict[str, Any]] | None = None) -> None:
        self.paths, self.cfg, self.stats, self.spool = paths, cfg, stats, spool
        self.shipper_status, self.clock, self.min_interval = shipper_status, clock, min_interval
        self.counters = counters
        self.started = clock()
        self._last = 0.0

    def write(self, force: bool = False) -> None:
        now = self.clock()
        if not force and now - self._last < self.min_interval:
            return
        self._last = now
        doc = {"schema": STATUS_SCHEMA, "pid": os.getpid(), "started": self.started, "ts": now,
               "version": __version__, "probe_id": self.cfg.probe_id, "mode": self.cfg.mode,
               "stats": self.stats.snapshot(), "shipper": self.shipper_status(),
               "spool": self.spool.stat(), "counters": self.counters() if self.counters else {}}
        try:
            atomic_write_json(self.paths.status_file, doc, mode=0o644, indent=None)
        except OSError as exc:
            log.warning("cannot write %s: %s", self.paths.status_file, exc)

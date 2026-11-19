"""Health: live metrics, the snapshot the daemon writes for ``exp-collector health``, and the
``exp.health/1`` document (01-contracts.md section 8.1).

The daemon's ``Monitor`` thread computes every collector metric key every few seconds and writes
them atomically to ``<run>/health.json`` (no secrets). ``exp-collector health --json`` (a separate
process, as the agent runs it) reads that snapshot, adds the TLS fingerprint and listen address,
and derives ``status``. Missing/stale snapshot = the daemon is not running = ``fail``.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import shutil
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from exp_common import atomic, tlspin

from . import __version__

if TYPE_CHECKING:  # pragma: no cover
    from .app import CollectorApp
    from .config import CollectorConfig, Paths

log = logging.getLogger(__name__)

SNAPSHOT_SCHEMA = "exp.collector.snapshot/1"
SNAPSHOT_INTERVAL_S = 5.0
SNAPSHOT_STALE_S = 20.0
SNAPSHOT_MAX_BYTES = 64 * 1024
SAMPLE_EVERY_S = 600.0
SAMPLE_KEEP_S = 25 * 3600
MIN_GROWTH_WINDOW_S = 600.0
GB = 1024.0 ** 3
FREE_FAIL_GB = 0.5
FREE_WARN_GB = 2.0
DAYS_TO_FULL_WARN = 3.0

METRIC_KEYS = (
    "ingest_records_per_s", "ingest_rejected_per_min", "ingest_duplicates_per_min", "ingest_bytes_per_s",
    "probes_total", "probes_reporting", "vm_up", "vm_backlog_points", "vm_series", "vm_storage_gb",
    "records_db_gb", "storage_free_gb", "days_to_full", "sse_clients", "open_incidents",
    "webhook_failures_1h", "rules_eval_ms_p95", "probes",
)


def empty_metrics() -> dict[str, Any]:
    m: dict[str, Any] = dict.fromkeys(METRIC_KEYS, 0)
    m["days_to_full"] = None
    m["probes"] = []
    return m


def days_to_full(free_bytes: float, samples: list[tuple[float, float]], now: float) -> float | None:
    """Free storage divided by the 24-h average growth of collector storage. `samples` are
    (epoch_s, used_bytes). None when growth is <= 0 or there is too little history."""
    recent = [(t, b) for t, b in samples if now - t <= 24 * 3600]
    if len(recent) < 2:
        return None
    recent.sort()
    (t0, b0), (t1, b1) = recent[0], recent[-1]
    span = t1 - t0
    if span < MIN_GROWTH_WINDOW_S:
        return None
    growth_per_day = (b1 - b0) / span * 86400.0
    if growth_per_day <= 0:
        return None
    return round(free_bytes / growth_per_day, 2)


_VM_SIZE = re.compile(r"^vm_data_size_bytes\{[^}]*\}\s+([0-9.eE+-]+)\s*$", re.MULTILINE)


class Monitor:
    """Collects metrics and writes the health snapshot."""

    def __init__(self, app: CollectorApp, interval_s: float = SNAPSHOT_INTERVAL_S,
                 clock: Callable[[], float] = time.time) -> None:
        self.app = app
        self.interval_s = interval_s
        self._clock = clock
        self.started_at = clock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._samples: list[tuple[float, float]] = []
        self._last_sample = 0.0
        self.vm_series = 0
        self.vm_storage_bytes = 0.0
        self._last_vm_poll = 0.0
        self.metrics: dict[str, Any] = empty_metrics()
        self.extra_sources: list[Callable[[], dict[str, Any]]] = []   # later steps: rules/SSE/incidents

    # --- sampling -----------------------------------------------------------------------------
    def load_samples(self) -> None:
        try:
            raw = self.app.store.get_meta("storage_samples")
            if raw:
                self._samples = [(float(t), float(b)) for t, b in json.loads(raw)][-400:]
        except (ValueError, TypeError, OSError):
            log.warning("storage samples unreadable; starting fresh")

    def _sample_storage(self, now: float, used: float) -> None:
        if now - self._last_sample < SAMPLE_EVERY_S and self._samples:
            return
        self._last_sample = now
        self._samples = [(t, b) for t, b in self._samples if now - t <= SAMPLE_KEEP_S] + [(now, used)]
        with contextlib.suppress(Exception):
            self.app.store.set_meta("storage_samples", json.dumps(self._samples))

    def _poll_vm(self, now: float) -> None:
        if now - self._last_vm_poll < 30.0:
            return
        self._last_vm_poll = now
        vm = self.app.vm
        try:
            data = vm.get_json("/api/v1/series/count")
            self.vm_series = int(data["data"][0])
        except (OSError, ValueError, KeyError, IndexError, TypeError):
            pass
        try:
            text = vm.get_text("/metrics")
            self.vm_storage_bytes = sum(float(x) for x in _VM_SIZE.findall(text))
        except (OSError, ValueError):
            pass

    # --- the metric set -----------------------------------------------------------------------
    def collect(self) -> dict[str, Any]:
        app = self.app
        now = self._clock()
        st = app.ingestor.stats
        w = st.window(60)
        win = 60.0
        m = empty_metrics()
        m["ingest_records_per_s"] = round(w["accepted"] / win, 3)
        m["ingest_rejected_per_min"] = int(w["rejected"])
        m["ingest_duplicates_per_min"] = int(w["duplicates"])
        m["ingest_bytes_per_s"] = round(w["bytes"] / win, 1)
        m["probes_total"] = len(app.config.probes)
        m["probes_reporting"] = app.ingestor.reporting_probes()
        m["probes"] = app.ingestor.probe_rows()
        m["vm_up"] = 1 if app.vm.up else 0
        m["vm_backlog_points"] = app.vm.backlog_points
        self._poll_vm(now)
        m["vm_series"] = self.vm_series
        m["vm_storage_gb"] = round(self.vm_storage_bytes / GB, 4)
        db_bytes = app.store.db_bytes()
        m["records_db_gb"] = round(db_bytes / GB, 4)
        try:
            free = shutil.disk_usage(app.paths.state_dir).free
        except OSError:
            free = 0
        m["storage_free_gb"] = round(free / GB, 3)
        self._sample_storage(now, db_bytes + self.vm_storage_bytes)
        m["days_to_full"] = days_to_full(free, self._samples, now)
        for src in self.extra_sources:
            try:
                m.update(src())
            except Exception:  # noqa: BLE001
                log.exception("health source failed")
        self.metrics = m
        return m

    def problems(self, m: dict[str, Any]) -> list[str]:
        out: list[str] = []
        app = self.app
        if not app.store.alive:
            out.append("record store writer is not running")
        if app.creds.last_error:
            out.append("credential reload failing; previous credentials in use")
        if not m["vm_up"]:
            out.append(f"VictoriaMetrics unreachable ({m['vm_backlog_points']} points buffered)")
        elif m["vm_backlog_points"] > 0:
            out.append(f"{m['vm_backlog_points']} points waiting in the VM backlog")
        return out

    def snapshot(self) -> dict[str, Any]:
        m = self.collect()
        return {"schema": SNAPSHOT_SCHEMA, "pid": os.getpid(), "started_at": self.started_at,
                "written_at": self._clock(), "version": __version__, "metrics": m,
                "problems": self.problems(m)}

    def write_snapshot(self) -> None:
        snap = self.snapshot()
        atomic.atomic_write(self.app.paths.health_snapshot,
                            json.dumps(snap, separators=(",", ":")).encode("utf-8"), 0o644)

    def start(self) -> None:
        self.load_samples()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        with contextlib.suppress(OSError):
            os.unlink(self.app.paths.health_snapshot)

    def _run(self) -> None:
        while True:
            try:
                self.write_snapshot()
            except Exception:  # noqa: BLE001
                log.exception("health snapshot failed")
            if self._stop.wait(self.interval_s):
                return


# --------------------------------------------------------------------------- CLI side (own process)

def read_snapshot(path: Path) -> dict[str, Any] | None:
    """Read and sanity-check the daemon's snapshot; None if absent/unreadable/invalid."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        data = os.read(fd, SNAPSHOT_MAX_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(data) > SNAPSHOT_MAX_BYTES:
        return None
    try:
        doc = json.loads(data.decode("utf-8"))
    except ValueError:
        return None
    if (not isinstance(doc, dict) or doc.get("schema") != SNAPSHOT_SCHEMA
            or not isinstance(doc.get("metrics"), dict) or not isinstance(doc.get("written_at"), (int, float))):
        return None
    return doc


def evaluate(metrics: dict[str, Any], problems: list[str]) -> tuple[str, str]:
    """(status, detail) from metrics + the daemon's own problem list."""
    free = metrics.get("storage_free_gb")
    if isinstance(free, (int, float)) and free < FREE_FAIL_GB:
        return "fail", f"only {free:.2f} GB free for collector storage"
    notes = list(problems)
    if isinstance(free, (int, float)) and free < FREE_WARN_GB:
        notes.append(f"low disk space ({free:.2f} GB free)")
    d = metrics.get("days_to_full")
    if isinstance(d, (int, float)) and d < DAYS_TO_FULL_WARN:
        notes.append(f"storage full in about {d:.1f} days")
    if notes:
        return "degraded", "; ".join(notes)[:1000]
    return "ok", ""


def build_health(config: CollectorConfig, paths: Paths, now: float | None = None) -> dict[str, Any]:
    """The ``exp.health/1`` document for ``exp-collector health --json``."""
    t = time.time() if now is None else now
    snap = read_snapshot(paths.health_snapshot)
    facts: dict[str, Any] = {"listen": config.listen}
    try:
        facts["tls_fingerprint_sha256"] = tlspin.fingerprint_of_pem_file(paths.tls_cert)
        tls_ok = True
    except (OSError, ValueError, tlspin.TlsPinError):
        tls_ok = False
    metrics = empty_metrics()
    uptime = 0.0
    if snap is None or t - float(snap["written_at"]) > SNAPSHOT_STALE_S:
        status, detail = "fail", "collector daemon is not running (no fresh status snapshot)"
    else:
        for k in METRIC_KEYS:
            if k in snap["metrics"]:
                metrics[k] = snap["metrics"][k]
        if not isinstance(metrics.get("probes"), list):
            metrics["probes"] = []
        extra = {k: v for k, v in snap["metrics"].items() if k not in metrics and isinstance(v, (int, float))}
        metrics.update(extra)
        uptime = max(0.0, t - float(snap.get("started_at", t)))
        probs = [str(p)[:200] for p in snap.get("problems", []) if isinstance(p, str)][:10]
        status, detail = evaluate(metrics, probs)
    if not tls_ok:
        status = "fail"
        detail = (detail + "; " if detail else "") + "TLS certificate is missing or unreadable"
    return {"schema": "exp.health/1", "status": status, "detail": detail[:1024], "version": __version__,
            "uptime_s": round(uptime, 1), "metrics": metrics, "facts": facts}

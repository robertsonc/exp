"""Health (``exp.health/1``, 01 section 8.1): the daemon writes ``<run>/health.json`` every few seconds; ``exp-runner health``
(a separate process, as the agent runs it) reads it. A missing or stale snapshot means the daemon is not running = ``fail``."""
from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from exp_common import atomic

from . import __version__

log = logging.getLogger(__name__)

SNAPSHOT_SCHEMA = "exp.runner.snapshot/1"
SNAPSHOT_INTERVAL_S = 5.0
SNAPSHOT_STALE_S = 20.0
SNAPSHOT_MAX_BYTES = 64 * 1024

METRIC_KEYS = ("drills_active", "pullers", "correlations_per_hour", "evidence_lag_s_p95", "syslog_lines_per_s", "syslog_dropped_per_min")


def empty_metrics() -> dict[str, Any]:
    m: dict[str, Any] = dict.fromkeys(METRIC_KEYS, 0)
    m["pullers"] = []
    m["evidence_lag_s_p95"] = 0.0
    return m


def health_doc(status: str, detail: str, uptime_s: float, metrics: dict[str, Any] | None = None,
               facts: dict[str, Any] | None = None) -> dict[str, Any]:
    m = empty_metrics()
    m.update(metrics or {})
    return {"schema": "exp.health/1", "status": status, "detail": detail[:1000], "version": __version__,
            "uptime_s": int(uptime_s), "metrics": m, "facts": facts or {"inventory": []}}


def write_snapshot(path: Path, doc: dict[str, Any]) -> None:
    atomic.atomic_write_json(path, doc, mode=0o644, indent=None)


def read_health(path: Path, now: float | None = None) -> dict[str, Any]:
    """The ``exp.health/1`` document for the daemon behind snapshot `path`."""
    now = time.time() if now is None else now
    try:
        with path.open("rb") as fh:
            raw = fh.read(SNAPSHOT_MAX_BYTES + 1)
        if len(raw) > SNAPSHOT_MAX_BYTES:
            raise ValueError("snapshot too large")
        snap = json.loads(raw.decode("utf-8"))
        if not isinstance(snap, dict) or snap.get("schema") != SNAPSHOT_SCHEMA:
            raise ValueError("not a runner snapshot")
        at = float(snap["at"])
    except (OSError, ValueError, KeyError, TypeError):
        return health_doc("fail", "exp-runner is not running (no health snapshot)", 0)
    if now - at > SNAPSHOT_STALE_S:
        return health_doc("fail", f"health snapshot is {int(now - at)}s old: exp-runner is not running", 0)
    doc = health_doc(str(snap.get("status", "fail")), str(snap.get("detail", "")), now - float(snap.get("started", now)),
                     snap.get("metrics") if isinstance(snap.get("metrics"), dict) else None,
                     snap.get("facts") if isinstance(snap.get("facts"), dict) else None)
    if doc["status"] not in ("ok", "degraded", "fail"):
        doc["status"] = "fail"
    return doc


class Monitor:
    """Computes the snapshot every ``SNAPSHOT_INTERVAL_S`` and writes it."""

    def __init__(self, path: Path, collect: Callable[[], dict[str, Any]], started: float,
                 now_fn: Callable[[], float] = time.time) -> None:
        self.path, self.collect, self.started, self.now = path, collect, started, now_fn
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def write_once(self) -> None:
        try:
            snap = self.collect()
        except Exception as exc:  # noqa: BLE001
            log.exception("health collection failed")
            snap = {"status": "degraded", "detail": f"health collection failed: {type(exc).__name__}", "metrics": {}, "facts": {}}
        snap.update({"schema": SNAPSHOT_SCHEMA, "at": self.now(), "started": self.started})
        try:
            write_snapshot(self.path, snap)
        except OSError as exc:
            log.warning("cannot write the health snapshot %s: %s", self.path, exc)

    def start(self) -> Monitor:
        self.write_once()
        self._thread = threading.Thread(target=self._loop, name="health", daemon=True)
        self._thread.start()
        return self

    def _loop(self) -> None:
        while not self._stop.wait(SNAPSHOT_INTERVAL_S):
            self.write_once()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

"""Pruning (03-collector.md section 4): hourly, records older than ``retention.records_days`` in
batches of 10,000 (never one long transaction); incidents are kept 90 days (closed ones only).
VictoriaMetrics retention is VM's own."""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

from .store import INCIDENT_KEEP_DAYS, PRUNE_BATCH, Store

log = logging.getLogger(__name__)

INTERVAL_S = 3600.0


def prune_once(store: Store, records_days: int, now: float | None = None,
               batch: int = PRUNE_BATCH) -> dict[str, int]:
    """One pruning pass. Returns {"records": n, "incidents": m} rows deleted."""
    t = time.time() if now is None else now
    rec = store.prune_records(int((t - records_days * 86400) * 1000), batch)
    inc = store.prune_incidents(int((t - INCIDENT_KEEP_DAYS * 86400) * 1000), batch)
    if rec or inc:
        log.info("pruned %d records and %d incidents", rec, inc)
    return {"records": rec, "incidents": inc}


class Pruner:
    def __init__(self, store: Store, records_days: int, interval_s: float = INTERVAL_S,
                 now: Callable[[], float] = time.time) -> None:
        self.store, self.records_days, self.interval_s, self._now = store, records_days, interval_s, now
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_result: dict[str, int] = {}
        self.last_run: float | None = None

    def run_once(self) -> dict[str, int]:
        self.last_result = prune_once(self.store, self.records_days, self._now())
        self.last_run = self._now()
        return self.last_result

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="pruner", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self) -> None:
        # first pass shortly after start, then hourly
        wait = 30.0
        while not self._stop.wait(wait):
            try:
                self.run_once()
            except Exception:  # noqa: BLE001
                log.exception("prune failed")
            wait = self.interval_s

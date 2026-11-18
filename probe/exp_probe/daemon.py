"""`exp-probe run`: scheduler + test workers + spool + shipper + probe_self (02-probe.md section 1)."""
from __future__ import annotations

import logging
import os
import signal
import threading
import time
from typing import Any

from exp_common import creds as exp_creds
from exp_common.schema import Measurement

from . import __version__
from . import health as health_mod
from .config import Paths, ProbeConfig
from .scheduler import Rotation, Scheduler, WorkerPool
from .selftel import ProcSampler, Stats, StatusWriter, build_probe_self
from .shipper import Shipper
from .spool import Spool

log = logging.getLogger(__name__)

COUNTERS_EVERY_S = 15.0


class Emitter:
    """Every measurement is written to the spool BEFORE anything is sent (02 section 6)."""

    def __init__(self, spool: Spool, stats: Stats, shipper: Shipper) -> None:
        self.spool, self.stats, self.shipper = spool, stats, shipper
        self.invalid = 0

    def __call__(self, ms: list[Measurement]) -> None:
        stored = False
        for m in ms:
            try:
                m.validate(require_id=True)
            except ValueError as exc:
                self.invalid += 1
                log.error("dropping invalid %s measurement: %s", m.test, exc)
                continue
            if self.spool.add(m.to_dict()):
                self.stats.record(m)
                stored = True
        if stored:
            self.shipper.notify()


class Daemon:
    def __init__(self, cfg: ProbeConfig, runner: Any, paths: Paths, *, creds_dir: str | None = None,
                 workers: int = 8, clock=time.time) -> None:
        self.cfg, self.runner, self.paths, self.clock = cfg, runner, paths, clock
        for d in (paths.state_dir, paths.run_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.stats = Stats(clock)
        self.spool = Spool(paths.spool_db, cfg.spool_max_mb, cfg.spool_max_days, clock)
        self.shipper = Shipper(cfg.collector, self.spool,
                               lambda: exp_creds.read_credential("ingest_token", creds_dir), clock=clock)
        self.emitter = Emitter(self.spool, self.stats, self.shipper)
        self.sampler = ProcSampler(paths.proc)
        self.pool = WorkerPool(workers)
        self.scheduler = Scheduler(cfg, paths, runner, self.emitter, self.pool, clock=clock, stats=self.stats,
                                   rotation=Rotation(paths.rotation_file), selftel=self._probe_self)
        self._counters: dict[str, Any] = {}
        self._counters_at = 0.0
        self.writer = StatusWriter(paths, cfg, self.stats, self.spool, self.shipper.status, clock,
                                   counters=self._counters_cached)
        self.stop = threading.Event()

    def _probe_self(self) -> Measurement:
        return build_probe_self(self.cfg, self.spool, self.stats, self.shipper.status(), self.sampler,
                                self.runner, self.clock())

    def _counters_cached(self) -> dict[str, Any]:
        now = self.clock()
        if now - self._counters_at >= COUNTERS_EVERY_S:
            self._counters_at = now
            self._counters = health_mod.counters_snapshot(self.runner, self.cfg, now)
        return self._counters

    def _status_loop(self) -> None:
        while not self.stop.wait(1.0):
            self.writer.write()

    def install_signals(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: self.stop.set())

    def run(self) -> int:
        log.info("exp-probe %s starting: probe=%s site=%s mode=%s ports=%s collector=%s", __version__,
                 self.cfg.probe_id, self.cfg.site, self.cfg.mode, ",".join(p.id for p in self.cfg.ports),
                 self.cfg.collector.url if self.cfg.collector else "none")
        threads = [threading.Thread(target=self.shipper.run, args=(self.stop,), name="exp-shipper", daemon=True),
                   threading.Thread(target=self._status_loop, name="exp-status", daemon=True)]
        self.writer.write(force=True)
        for t in threads:
            t.start()
        try:
            self.scheduler.run(self.stop)
        finally:
            self.stop.set()
            self.pool.shutdown(wait=True, timeout=10.0)
            for t in threads:
                t.join(timeout=3.0)
            self.writer.write(force=True)
            self.spool.close()
            try:
                os.unlink(self.paths.status_file)      # a stopped daemon must not look alive
            except OSError:
                pass
        log.info("exp-probe stopped")
        return 0

"""Scheduler (02-probe.md section 4). Deterministic: the clock, RNG seed and worker pool are injected.

* Heartbeat cycle every ``heartbeat.interval_s`` aligned to the wall clock (``t % interval == 0``):
  ``gateway`` (all ports), ``dhcp_hb``, ``dns_hb`` and ``ping`` run in parallel; **traces run one
  after another** (test-port trace, then the control path from the management interface).
* ``dhcp_hb`` / ``dns_hb`` / ``ping`` / ``trace`` each use ONE client port per cycle, rotating through
  the ports with a persisted rotation index (load stays constant as ports grow).
* Scheduled tests (dhcp, dns, app, throughput, path, wifi_join) run every ``interval_s`` per port,
  staggered evenly (``slot = interval / ports``) with +-10% of a slot of deterministic jitter.
* No overlap: a test still running when its next slot arrives is skipped and counted
  (``probe_self.detail.skipped``). ``throughput`` is globally serialized per probe and never runs at
  the same time as a trace (a trace that comes due during a throughput run is skipped and counted).
* A bounded priority worker pool caps concurrency; heartbeat work has priority over scheduled work.

Tests register with `register_test`; step 2 of WP-1 provides the measurement modules
(``exp_probe/checks/*``). A configured test that is not registered is logged once and skipped.
Scheduler concepts ported from reference/exm/lib/exm/heartbeat.py (`run`, rotation, sequential traces).
"""
from __future__ import annotations

import heapq
import itertools
import json
import logging
import math
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from exp_common.atomic import atomic_write_json
from exp_common.schema import Measurement

from .config import Paths, Port, ProbeConfig
from .runner import ns_exec_argv
from .selftel import Stats, build_measurement

log = logging.getLogger(__name__)

PRIO_BEAT, PRIO_SCHEDULED = 0, 1
JITTER_FRACTION = 0.10
SELFTEL_INTERVAL_S = 60
BEAT_PARALLEL = ("gateway", "dhcp_hb", "dns_hb", "ping")
SCHEDULED = ("dhcp", "dns", "app", "throughput", "path", "wifi_join")
DEFAULT_ROLES: dict[str, tuple[str, ...]] = {
    "gateway": ("client", "wifi"), "dhcp_hb": ("client",), "dns_hb": ("client", "wifi"),
    "ping": ("client", "wifi"), "trace": ("client", "wifi"),
    "dhcp": ("client",), "dns": ("client", "wifi"), "app": ("client", "wifi"),
    "throughput": ("client", "wifi"), "path": ("client", "wifi"), "wifi_join": ("wifi",),
}
TestFn = Callable[["TestContext"], "list[Measurement] | Measurement | None"]


# ------------------------------------------------------------------------------------ registry

@dataclass
class TestSpec:
    __test__ = False        # not a pytest class
    name: str
    fn: TestFn
    roles: tuple[str, ...]


REGISTRY: dict[str, TestSpec] = {}


def register_test(name: str, fn: TestFn | None = None, *, roles: tuple[str, ...] | None = None,
                  registry: dict[str, TestSpec] | None = None) -> Any:
    """Register a test function (usable as a decorator). `roles` overrides the default eligibility."""
    reg = REGISTRY if registry is None else registry

    def deco(f: TestFn) -> TestFn:
        reg[name] = TestSpec(name, f, roles or DEFAULT_ROLES.get(name, ("client",)))
        return f
    return deco(fn) if fn is not None else deco


@dataclass
class TestContext:
    """What a test function receives."""
    __test__ = False
    cfg: ProbeConfig
    paths: Paths
    runner: Any
    clock: Callable[[], float]
    port: Port | None = None
    path: str = ""                 # "test" | "control" for trace
    beat_ts: float = 0.0
    explicit: bool = False         # `exp-probe test`: run on exactly this port, no fallback to another
    net: Callable[..., Any] | None = None    # (cfg, port, control) -> NetEnv; tests inject fakes

    def measure(self, test: str, outcome: str, **kw: Any) -> Measurement:
        labels = dict(kw.pop("labels", None) or {})
        if self.port is not None:
            labels.setdefault("port", self.port.id)
        return build_measurement(self.cfg, test, outcome, labels=labels, **kw)

    def netenv(self, port: Port | None = None, control: bool = False) -> Any:
        """Where this test's sockets live: the port's namespace (host mode: pinned host namespace),
        or with control=True the host namespace on the management interface."""
        from .netio import env_for
        return (self.net or env_for)(self.cfg, port if port is not None else self.port, control)

    def ns_argv(self, argv: list[str]) -> list[str]:
        """Wrap argv for the port's namespace (host mode: unchanged)."""
        if self.port is None or self.cfg.mode == "host":
            return list(argv)
        return ns_exec_argv(self.port.id, argv)


# ---------------------------------------------------------------------------------------- pools

class WorkerPool:
    """Bounded thread pool whose queue is ordered by (priority, submission order)."""

    def __init__(self, workers: int = 8) -> None:
        self._q: list[tuple[int, int, Callable[[], None]]] = []
        self._cv = threading.Condition()
        self._seq = itertools.count()
        self._stop = False
        self._active = 0
        self._threads = [threading.Thread(target=self._loop, name=f"exp-worker-{i}", daemon=True)
                         for i in range(max(1, workers))]
        for t in self._threads:
            t.start()

    def submit(self, prio: int, fn: Callable[[], None]) -> None:
        with self._cv:
            heapq.heappush(self._q, (prio, next(self._seq), fn))
            self._cv.notify()

    def _loop(self) -> None:
        while True:
            with self._cv:
                while not self._q and not self._stop:
                    self._cv.wait()
                if self._stop and not self._q:
                    return
                _, _, fn = heapq.heappop(self._q)
                self._active += 1
            try:
                fn()
            except Exception:
                log.exception("worker task crashed")
            finally:
                with self._cv:
                    self._active -= 1
                    self._cv.notify_all()

    def wait_idle(self, timeout: float = 30.0) -> bool:
        end = time.monotonic() + timeout
        with self._cv:
            while self._q or self._active:
                left = end - time.monotonic()
                if left <= 0:
                    return False
                self._cv.wait(left)
        return True

    def shutdown(self, wait: bool = True, timeout: float = 10.0) -> None:
        if wait:
            self.wait_idle(timeout)
        with self._cv:
            self._stop = True
            self._cv.notify_all()


class ManualPool:
    """Deterministic pool for tests: tasks are queued and `drain()` runs them in priority order on the
    calling thread (or immediately, with ``autorun=True``)."""

    def __init__(self, autorun: bool = False) -> None:
        self.autorun = autorun
        self._q: list[tuple[int, int, Callable[[], None]]] = []
        self._seq = itertools.count()
        self.ran: list[Callable[[], None]] = []

    def submit(self, prio: int, fn: Callable[[], None]) -> None:
        if self.autorun:
            fn()
            return
        heapq.heappush(self._q, (prio, next(self._seq), fn))

    def drain(self) -> int:
        n = 0
        while self._q:
            _, _, fn = heapq.heappop(self._q)
            fn()
            n += 1
        return n

    def wait_idle(self, timeout: float = 0.0) -> bool:
        self.drain()
        return True

    def shutdown(self, wait: bool = True, timeout: float = 0.0) -> None:
        if wait:
            self.drain()


# ------------------------------------------------------------------------------------ rotation

class Rotation:
    """Persisted rotation index per test (exm heartbeat.rotation.json)."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.idx: dict[str, int] = {}
        if path is not None:
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
                self.idx = {k: int(v) for k, v in doc.items() if isinstance(v, int) and not isinstance(v, bool)}
            except (OSError, ValueError, AttributeError):
                self.idx = {}

    def pick(self, name: str, n: int) -> int:
        """Next index in [0, n) for `name`; persisted."""
        if n <= 0:
            raise ValueError("nothing to rotate over")
        nxt = (self.idx.get(name, -1) + 1) % n
        self.idx[name] = nxt
        if self.path is not None:
            try:
                atomic_write_json(self.path, self.idx, mode=0o644, indent=None)
            except OSError as exc:
                log.warning("cannot persist rotation index: %s", exc)
        return nxt


# ------------------------------------------------------------------------------------ scheduler

@dataclass
class Job:
    key: tuple[str, str]
    prio: int
    run: Callable[[], list[Measurement]]
    port: str = ""
    test: str = ""
    on_done: list[Callable[[], None]] = field(default_factory=list)


class Scheduler:
    def __init__(self, cfg: ProbeConfig, paths: Paths, runner: Any, emit: Callable[[list[Measurement]], None],
                 pool: Any, *, clock: Callable[[], float] = time.time, stats: Stats | None = None,
                 registry: dict[str, TestSpec] | None = None, rotation: Rotation | None = None,
                 selftel: Callable[[], Measurement | None] | None = None,
                 jitter: float = JITTER_FRACTION, net: Callable[..., Any] | None = None) -> None:
        self.cfg, self.paths, self.runner, self.emit, self.pool = cfg, paths, runner, emit, pool
        self.net = net                      # (cfg, port, control) -> NetEnv; tests inject fakes
        self.clock = clock
        self.stats = stats or Stats(clock)
        self.registry = REGISTRY if registry is None else registry
        self.rotation = rotation or Rotation(None)
        self.selftel = selftel
        self.jitter = jitter
        self.interval = int(cfg.heartbeat["interval_s"])
        self._lock = threading.RLock()
        self._running: set[tuple[str, str]] = set()
        self._trace_active = False
        self._throughput_active = False
        self._next_due: dict[tuple[str, str], float] = {}
        self._deferred_since: dict[tuple[str, str], float] = {}
        t0 = clock()
        self._last_beat = math.floor(t0 / self.interval) * self.interval
        self._last_selftel = math.floor(t0 / SELFTEL_INTERVAL_S) * SELFTEL_INTERVAL_S
        self._warned: set[str] = set()
        self.cycles = 0

    # ------------------------------------------------------------------------------- helpers
    def _eligible(self, test: str) -> list[Port]:
        spec = self.registry.get(test)
        roles = spec.roles if spec else DEFAULT_ROLES.get(test, ("client",))
        return self.cfg.ports_with_role(*roles)

    def _spec(self, test: str) -> TestSpec | None:
        spec = self.registry.get(test)
        if spec is None:
            self.stats.unavailable.add(test)
            if test not in self._warned:
                self._warned.add(test)
                log.warning("test %r is configured but not available in this build; skipping", test)
        return spec

    def _ctx(self, port: Port | None, path: str = "", beat_ts: float = 0.0) -> TestContext:
        return TestContext(self.cfg, self.paths, self.runner, self.clock, port, path, beat_ts, net=self.net)

    def _error_measurement(self, test: str, port: Port | None, exc: BaseException) -> Measurement:
        labels = {"port": port.id} if port else {}
        if test == "gateway" and port:
            labels["iface"] = port.iface
        reason = f"{type(exc).__name__}: {exc}"[:500]
        return build_measurement(self.cfg, test, "error", labels=labels, error=reason)

    def _call(self, test: str, spec: TestSpec, port: Port | None, path: str, beat_ts: float) -> list[Measurement]:
        try:
            out = spec.fn(self._ctx(port, path, beat_ts))
        except Exception as exc:    # a test bug or tool crash is `error`, never `fail` (02 section 5)
            log.warning("test %s on %s crashed: %s", test, port.id if port else "-", exc)
            return [self._error_measurement(test, port, exc)]
        if out is None:
            return []
        return [out] if isinstance(out, Measurement) else list(out)

    def _submit(self, job: Job) -> bool:
        """Queue `job` unless the same key is still running (then skip and count)."""
        with self._lock:
            if job.key in self._running:
                self.stats.skipped(job.test or job.key[0])
                log.warning("skipping %s on %s: previous run still in progress", job.key[0], job.key[1] or "-")
                for cb in job.on_done:
                    cb()
                return False
            self._running.add(job.key)

        def task() -> None:
            try:
                ms = job.run()
                if ms:
                    self.emit(ms)
            finally:
                with self._lock:
                    self._running.discard(job.key)
                for cb in job.on_done:
                    cb()
        self.pool.submit(job.prio, task)
        return True

    # ---------------------------------------------------------------------------------- beats
    def _beat_tests_enabled(self) -> dict[str, bool]:
        hb = self.cfg.heartbeat
        return {"gateway": hb["gateway"], "dhcp_hb": hb["dhcp"], "dns_hb": hb["dns"],
                "ping": bool(hb["ping"]), "trace": True}

    def run_beat(self, beat_ts: float) -> None:
        enabled = self._beat_tests_enabled()
        self.cycles += 1
        for test in BEAT_PARALLEL:
            if not enabled[test]:
                continue
            ports = self._eligible(test)
            if not ports or (spec := self._spec(test)) is None:
                continue
            chosen = ports if test == "gateway" else [ports[self.rotation.pick(test, len(ports))]]
            for port in chosen:
                self._submit(Job((test, port.id), PRIO_BEAT, self._runner_for(test, spec, port, "", beat_ts),
                                 port.id, test))
        if enabled["trace"]:
            self._run_trace_chain(beat_ts)

    def _runner_for(self, test: str, spec: TestSpec, port: Port | None, path: str,
                    beat_ts: float) -> Callable[[], list[Measurement]]:
        return lambda: self._call(test, spec, port, path, beat_ts)

    def _run_trace_chain(self, beat_ts: float) -> None:
        ports = self._eligible("trace")
        if not ports or (spec := self._spec("trace")) is None:
            return
        port = ports[self.rotation.pick("trace", len(ports))]
        with self._lock:
            if self._throughput_active:
                self.stats.skipped("trace")
                log.info("trace skipped for this cycle: a throughput test is running")
                return
            self._trace_active = True
        control = self.cfg.control_path

        def chain() -> list[Measurement]:
            out = self._call("trace", spec, port, "test", beat_ts)       # test port first ...
            if control:                                                  # ... then the control path
                out += self._call("trace", spec, port, "control", beat_ts)
            return out

        def done() -> None:
            with self._lock:
                self._trace_active = False
        job = Job(("trace", port.id), PRIO_BEAT, chain, port.id, "trace", [done])
        self._submit(job)

    # ------------------------------------------------------------------------------ scheduled
    def _slots(self, test: str) -> list[tuple[str, Port, int, int, int]]:
        conf = self.cfg.tests.get("wifi" if test == "wifi_join" else test)
        if not conf:
            return []
        ports = self._eligible(test)
        interval = int(conf.get("interval_s", 300))
        return [(test, p, i, len(ports), interval) for i, p in enumerate(ports)]

    def due_after(self, test: str, port_id: str, idx: int, n: int, interval: int, t: float) -> float:
        """Smallest slot time > t for this (test, port): k*interval + idx*slot + jitter(k)."""
        slot = interval / n
        k0 = math.floor(t / interval)
        for k in range(k0 - 1, k0 + 3):
            rnd = random.Random(f"{self.cfg.probe_id}|{test}|{port_id}|{k}")  # noqa: S311 - jitter only
            d = k * interval + idx * slot + rnd.uniform(-self.jitter, self.jitter) * slot
            if d > t:
                return d
        raise RuntimeError("no slot found")  # pragma: no cover

    def _scheduled_due(self, now: float) -> None:
        for test in SCHEDULED:
            for _, port, idx, n, interval in self._slots(test):
                key = (test, port.id)
                due = self._next_due.get(key)
                if due is None:
                    self._next_due[key] = self.due_after(test, port.id, idx, n, interval, now)
                    continue
                if now < due:
                    continue
                if now - due > interval:           # we were stalled for more than a whole interval
                    self._next_due[key] = self.due_after(test, port.id, idx, n, interval, now)
                    continue
                if self._fire_scheduled(test, port, key, now, interval):
                    self._next_due[key] = self.due_after(test, port.id, idx, n, interval, now)

    def _fire_scheduled(self, test: str, port: Port, key: tuple[str, str], now: float, interval: int) -> bool:
        """Start a scheduled test. Returns False when it is deferred (the slot stays due)."""
        spec = self._spec(test)
        if spec is None:
            return True
        done: list[Callable[[], None]] = []
        with self._lock:
            if key in self._running:
                self.stats.skipped(test)
                log.warning("skipping %s on %s: previous run still in progress", test, port.id)
                return True
            if test == "throughput":
                if self._throughput_active or self._trace_active:
                    first = self._deferred_since.setdefault(key, now)
                    if now - first > interval:               # could never start within its own interval
                        self.stats.skipped(test)
                        self._deferred_since.pop(key, None)
                        return True
                    return False
                self._deferred_since.pop(key, None)
                self._throughput_active = True

                def release() -> None:
                    with self._lock:
                        self._throughput_active = False
                done.append(release)
        self._submit(Job(key, PRIO_SCHEDULED, self._runner_for(test, spec, port, "", now), port.id, test, done))
        return True

    # ------------------------------------------------------------------------------------ tick
    def tick(self, now: float | None = None) -> None:
        """Do everything that is due at `now`."""
        now = self.clock() if now is None else now
        bt = math.floor(now / self.interval) * self.interval
        if bt > self._last_beat:
            self._last_beat = bt
            self.run_beat(bt)
        st = math.floor(now / SELFTEL_INTERVAL_S) * SELFTEL_INTERVAL_S
        if st > self._last_selftel:
            self._last_selftel = st
            self._run_selftel()
        self._scheduled_due(now)

    def _run_selftel(self) -> None:
        if self.selftel is None:
            return
        fn = self.selftel
        self._submit(Job(("probe_self", ""), PRIO_BEAT, lambda: [m] if (m := fn()) else [], "", "probe_self"))

    def next_wakeup(self, now: float | None = None) -> float:
        now = self.clock() if now is None else now
        cands = [self._last_beat + self.interval, self._last_selftel + SELFTEL_INTERVAL_S]
        cands += [d for k, d in self._next_due.items() if k not in self._deferred_since]
        # a deferred throughput is retried every second
        if self._deferred_since:
            cands.append(now + 1.0)
        return min(cands)

    def run(self, stop: threading.Event, on_tick: Callable[[], None] | None = None) -> None:
        while not stop.is_set():
            self.tick()
            if on_tick:
                on_tick()
            wait = self.next_wakeup() - self.clock()
            stop.wait(min(max(wait, 0.001), 1.0))      # capped so wall-clock steps are noticed

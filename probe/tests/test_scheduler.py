"""Scheduler (02-probe.md section 4): alignment, rotation, sequential traces, stagger, no overlap,
throughput serialization -- all deterministic (fake clock, manual pool, local registry)."""
from __future__ import annotations

import threading
import time

from conftest import make_config
from fakes import FakeClock

from exp_probe.scheduler import ManualPool, Rotation, Scheduler, TestSpec, WorkerPool, register_test
from exp_probe.selftel import Stats, build_measurement

PORTS3 = [{"id": f"c0{i}", "iface": f"t{i}", "role": "client"} for i in (1, 2, 3)]


class Rig:
    def __init__(self, tmp_path, ports=PORTS3, t0=1_000_000.3, tests=None, pool=None, rotation=None, selftel=None,
                 behaviours=None):
        self.cfg = make_config(ports=ports, tests=tests or {}, heartbeat={"interval_s": 10, "ping": ["1.1.1.1"]})
        self.clock = FakeClock(t0)
        self.pool = pool or ManualPool()
        self.calls: list[tuple] = []
        self.emitted: list = []
        self.stats = Stats(self.clock)
        self.registry: dict[str, TestSpec] = {}
        behaviours = behaviours or {}
        for name in ("gateway", "dhcp_hb", "dns_hb", "ping", "trace", "dhcp", "dns", "app", "throughput", "path"):
            def fn(ctx, _n=name):
                self.calls.append((_n, ctx.port.id if ctx.port else None, ctx.path, ctx.beat_ts))
                if _n in behaviours:
                    behaviours[_n](ctx)
                return [ctx.measure(_n, "ok", labels={"path": ctx.path} if ctx.path else {})]
            register_test(name, fn, registry=self.registry)
        self.rotation = rotation or Rotation(tmp_path / "rotation.json")
        self.sched = Scheduler(self.cfg, None, None, self.emitted.extend, self.pool, clock=self.clock,
                               stats=self.stats, registry=self.registry, rotation=self.rotation, selftel=selftel)

    def at(self, t: float):
        self.clock.t = t
        self.sched.tick(t)
        self.pool.drain()

    def tests(self, name=None):
        return [c for c in self.calls if name is None or c[0] == name]


def test_beat_is_aligned_to_the_wall_clock(tmp_path):
    r = Rig(tmp_path)
    r.at(1_000_005.0)
    assert r.calls == []                                        # not a boundary yet
    r.at(1_000_010.0)                                           # t % 10 == 0
    assert {c[3] for c in r.calls} == {1_000_010}
    n = len(r.calls)
    r.at(1_000_010.7)
    assert len(r.calls) == n                                    # once per boundary
    r.at(1_000_055.0)                                           # a stall does not trigger catch-up cycles
    assert {c[3] for c in r.calls} - {1_000_010} == {1_000_050}
    assert all(c[3] % 10 == 0 for c in r.calls)
    assert r.sched.next_wakeup(1_000_055.0) == 1_000_060


def test_beat_composition_and_one_port_per_cycle_for_rotating_tests(tmp_path):
    r = Rig(tmp_path)
    r.at(1_000_010.0)
    assert sorted(p for t, p, *_ in r.calls if t == "gateway") == ["c01", "c02", "c03"]    # every port
    for t in ("dhcp_hb", "dns_hb", "ping", "trace"):
        assert len({p for tt, p, *_ in r.calls if tt == t}) == 1, t                         # one port each
    assert len(r.tests("trace")) == 2                                                         # test path + control path


def test_rotation_visits_every_port_and_persists(tmp_path):
    r = Rig(tmp_path)
    seen = []
    for k in range(1, 7):
        r.at(1_000_000.0 + 10 * k)
        seen.append([p for t, p, *_ in r.calls if t == "dhcp_hb"][-1])
    assert seen == ["c01", "c02", "c03", "c01", "c02", "c03"]
    # a restart continues the rotation instead of starting over (persisted index)
    r2 = Rig(tmp_path, rotation=Rotation(tmp_path / "rotation.json"))
    r2.at(1_000_010.0)
    assert [p for t, p, *_ in r2.calls if t == "dhcp_hb"] == ["c01"]            # last saved idx was 2 -> next is 0
    assert Rotation(tmp_path / "rotation.json").idx["dhcp_hb"] == 0
    # indices of different tests are independent and robust to a changed port count
    rot = Rotation(tmp_path / "x.json")
    assert [rot.pick("a", 2), rot.pick("a", 2), rot.pick("b", 5), rot.pick("a", 1)] == [0, 1, 0, 0]


def test_traces_run_one_after_another_never_together(tmp_path):
    inflight, peak, order = [0], [0], []
    lock = threading.Lock()

    def slow_trace(ctx):
        with lock:
            inflight[0] += 1
            peak[0] = max(peak[0], inflight[0])
        time.sleep(0.05)
        order.append(ctx.path)
        with lock:
            inflight[0] -= 1
    pool = WorkerPool(8)
    r = Rig(tmp_path, pool=pool, behaviours={"trace": slow_trace})
    r.clock.t = 1_000_010.0
    r.sched.tick(1_000_010.0)
    assert pool.wait_idle(5)
    assert peak[0] == 1 and order == ["test", "control"]       # test-port trace first, then the control path
    pool.shutdown()


def test_control_path_can_be_disabled(tmp_path):
    r = Rig(tmp_path)
    r.cfg.heartbeat["trace"]["control_path"] = False
    r.at(1_000_010.0)
    assert [c[2] for c in r.tests("trace")] == ["test"]


def test_gateway_runs_in_parallel_with_the_other_beat_tests(tmp_path):
    barrier = threading.Barrier(3, timeout=3)                 # gateway x3 must be in flight together

    def wait(ctx):
        barrier.wait()
    pool = WorkerPool(8)
    r = Rig(tmp_path, pool=pool, behaviours={"gateway": wait})
    r.sched.tick(1_000_010.0)
    assert pool.wait_idle(5) and barrier.n_waiting == 0 and len(r.tests("gateway")) == 3
    pool.shutdown()


def test_overlap_is_skipped_and_counted(tmp_path):
    r = Rig(tmp_path)                                          # ManualPool: nothing runs until drained
    r.sched.tick(1_000_010.0)                                   # cycle 1 queued (still "running")
    r.sched.tick(1_000_020.0)                                   # cycle 2: same keys still running
    snap = r.stats.snapshot()
    assert snap["skipped"]["gateway"] == 3 and snap["skipped_per_hour"] >= 3
    r.pool.drain()
    assert len(r.tests("gateway")) == 3                         # only the first cycle's jobs ran
    r.at(1_000_030.0)
    assert len(r.tests("gateway")) == 6                         # and the next cycle is free again


def test_test_exception_is_an_error_measurement_not_fail(tmp_path):
    def boom(ctx):
        raise RuntimeError("tool crashed")
    r = Rig(tmp_path, behaviours={"gateway": boom})
    r.at(1_000_010.0)
    errs = [m for m in r.emitted if m.test == "gateway"]
    assert len(errs) == 3 and all(m.outcome == "error" and "tool crashed" in m.error for m in errs)
    assert all(m.labels["port"] in ("c01", "c02", "c03") and m.labels["iface"] for m in errs)
    assert not [m for m in r.emitted if m.outcome == "fail"]


def test_unregistered_test_is_skipped_without_crashing(tmp_path):
    r = Rig(tmp_path)
    del r.registry["dns_hb"]
    r.at(1_000_010.0)
    assert r.tests("dns_hb") == [] and "dns_hb" in r.stats.unavailable
    assert r.tests("gateway")


def test_heartbeat_work_has_priority_over_scheduled_work(tmp_path):
    r = Rig(tmp_path, tests={"dns": {"interval_s": 30}})
    r.sched.tick(1_000_000.3)
    due = min(r.sched._next_due.values())
    r.clock.t = 1_000_060.0
    r.sched.tick(1_000_060.0)                                   # beat boundary AND scheduled dns due in the same tick
    assert due < 1_000_060
    r.pool.drain()
    kinds = [c[0] for c in r.calls]
    assert kinds.index("dns") > max(i for i, k in enumerate(kinds) if k in ("gateway", "trace", "dhcp_hb", "ping"))


def test_worker_pool_caps_concurrency_and_orders_by_priority():
    live, peak = [0], [0]
    lock = threading.Lock()

    def job():
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        time.sleep(0.02)
        with lock:
            live[0] -= 1
    pool = WorkerPool(3)
    for _ in range(12):
        pool.submit(1, job)
    assert pool.wait_idle(5) and peak[0] <= 3
    gate, order = threading.Event(), []
    one = WorkerPool(1)
    one.submit(0, gate.wait)                                     # occupy the only worker
    one.submit(1, lambda: order.append("scheduled"))
    one.submit(0, lambda: order.append("beat"))
    gate.set()
    assert one.wait_idle(5) and order == ["beat", "scheduled"]
    pool.shutdown()
    one.shutdown()


# ---------------------------------------------------------------------------------- scheduled tests

def test_scheduled_tests_are_staggered_across_the_interval(tmp_path):
    r = Rig(tmp_path, tests={"dns": {"interval_s": 300}})
    s = r.sched
    t = 2_000_000.0
    firsts = []
    for i, p in enumerate(("c01", "c02", "c03")):
        d = s.due_after("dns", p, i, 3, 300, t)
        firsts.append(d)
        assert d > t
    # slot = 100 s; each port sits at idx*100 +- 10 within the interval grid
    for i, p in enumerate(("c01", "c02", "c03")):
        for k in range(5):
            d = s.due_after("dns", p, i, 3, 300, 2_000_000.0 + 300 * k)
            off = (d - 300 * (d // 300)) - i * 100
            off = (off + 150) % 300 - 150
            assert -10.0 <= off <= 10.0, (p, k, off)
    # deterministic, and jitter differs between ports/cycles
    assert s.due_after("dns", "c01", 0, 3, 300, t) == s.due_after("dns", "c01", 0, 3, 300, t)
    assert len({round(s.due_after("dns", "c01", 0, 3, 300, t + 300 * k) % 300, 3) for k in range(6)}) > 1


def test_scheduled_test_runs_once_per_interval_per_port(tmp_path):
    r = Rig(tmp_path, tests={"dns": {"interval_s": 60}}, pool=ManualPool(autorun=True))
    r.sched.jitter = 0.0
    for sec in range(0, 3601):
        r.clock.t = 1_000_000.3 + sec
        r.sched.tick(r.clock.t)
    runs = {p: sorted(c[3] for c in r.tests("dns") if c[1] == p) for p in ("c01", "c02", "c03")}
    for p, ts in runs.items():
        assert 58 <= len(ts) <= 60, (p, len(ts))
        gaps = {round(b - a) for a, b in zip(ts, ts[1:], strict=False)}
        assert gaps <= {59, 60, 61}, gaps
    starts = sorted(min(ts) for ts in runs.values())
    assert 15 <= starts[1] - starts[0] <= 25 and 15 <= starts[2] - starts[1] <= 25      # 60 s / 3 ports


def test_slow_scheduled_test_is_skipped_not_stacked(tmp_path):
    r = Rig(tmp_path, tests={"dns": {"interval_s": 30}})        # manual pool: the first run never finishes
    r.sched.jitter = 0.0
    for sec in range(0, 200):
        r.clock.t = 1_000_000.3 + sec
        r.sched.tick(r.clock.t)
    assert r.stats.snapshot()["skipped"].get("dns", 0) >= 3 * 4        # 3 ports, several missed slots each
    r.pool.drain()
    assert len(r.tests("dns")) == 3                                      # one run per port at a time, never stacked


def test_throughput_is_globally_serialized(tmp_path):
    r = Rig(tmp_path, tests={"throughput": {"interval_s": 60, "providers": ["cloudflare"]}})
    r.sched.jitter = 0.0
    r.sched.tick(1_000_000.3)
    # both ports' slots arrive while the first is still running (manual pool: running until drained)
    started = []
    for sec in range(0, 61):
        r.clock.t = 1_000_000.3 + sec
        r.sched.tick(r.clock.t)
        started.append(len(r.sched._running & {("throughput", p) for p in ("c01", "c02", "c03")}))
    assert max(started) == 1                                     # never two at once, even if all are due
    assert r.sched._deferred_since                               # the others are waiting, not dropped


def test_throughput_and_trace_exclude_each_other(tmp_path):
    r = Rig(tmp_path, tests={"throughput": {"interval_s": 600}})
    r.sched.tick(1_000_000.3)                                    # initialise the slot table
    for k in list(r.sched._next_due):
        r.sched._next_due[k] = 1e12                              # park every slot ...
    r.sched._next_due[("throughput", "c01")] = 1_000_001.0       # ... except one throughput slot
    r.sched.tick(1_000_002.0)                                    # it starts (queued in the manual pool)
    assert r.sched._throughput_active and not r.sched._trace_active
    r.sched.tick(1_000_010.0)                                    # the next beat: its trace is skipped and counted
    assert r.stats.snapshot()["skipped"].get("trace", 0) == 1
    r.pool.drain()
    assert r.tests("trace") == [] and r.tests("gateway")         # other beat tests are unaffected
    assert not r.sched._throughput_active                        # released when the throughput test finished
    r.sched.tick(1_000_020.0)                                    # trace chain queued, not finished
    assert r.sched._trace_active
    r.sched._next_due[("throughput", "c01")] = 1_000_020.5
    r.sched.tick(1_000_021.0)                                    # a throughput slot arrives meanwhile: deferred
    assert not r.sched._throughput_active and ("throughput", "c01") in r.sched._deferred_since
    assert len(r.tests("throughput")) == 1                       # only the first run so far
    r.pool.drain()                                               # trace done
    r.sched.tick(1_000_022.0)                                    # retried on the next tick
    r.pool.drain()
    assert len(r.tests("throughput")) == 2 and not r.sched._deferred_since


def test_probe_self_runs_every_60s(tmp_path):
    n = []

    def selftel():
        n.append(1)
        return build_measurement(make_config(), "probe_self", "ok", metrics={"spool_depth": 0.0})
    r = Rig(tmp_path, selftel=selftel, t0=1_000_000.3)
    for sec in range(0, 190):
        r.at(1_000_000.3 + sec)
    assert len(n) == 3 and [m.test for m in r.emitted].count("probe_self") == 3

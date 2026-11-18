"""probe_self (02-probe.md 5.12) and the sliding-window stats behind health."""
from __future__ import annotations

from conftest import make_config
from exp_common.schema import Measurement
from fakes import FakeClock

from exp_probe.runner import CmdResult
from exp_probe.selftel import ProcSampler, Stats, build_measurement, build_probe_self, clock_offset
from exp_probe.spool import Spool


class Scripted:
    def __init__(self, table):
        self.table = table
        self.calls = []

    def run(self, argv, timeout=10, **kw):
        self.calls.append(list(argv))
        r = self.table.get(tuple(argv))
        return r if r else CmdResult(tuple(argv), 127, "", "not found")


def cr(out, rc=0):
    return CmdResult((), rc, out, "")


def test_stats_windows():
    clock = FakeClock(1000.0)
    st = Stats(clock)
    cfg = make_config()
    for outcome in ("ok", "ok", "fail", "error"):
        st.record(build_measurement(cfg, "gateway", outcome, labels={"port": "c01"}))
    st.record(build_measurement(cfg, "dns_hb", "ok", labels={"port": "c01"}))
    st.skipped("app")
    snap = st.snapshot()
    assert snap["measurements_per_min"] == 5 and snap["by_test_per_min"] == {"gateway": 4, "dns_hb": 1}
    assert snap["fail_per_min"] == 1 and snap["error_per_min"] == 1 and snap["skipped_per_hour"] == 1
    assert snap["ports"]["c01"]["last"] == {"network": "unknown", "dns": "ok"}
    clock.advance(61)
    assert st.snapshot()["measurements_per_min"] == 0 and st.snapshot()["skipped_per_hour"] == 1
    clock.advance(3600)
    snap = st.snapshot()
    assert snap["skipped_per_hour"] == 0 and snap["skipped"] == {"app": 1}       # cumulative counts survive


def test_clock_offset_from_chrony_and_timesyncd():
    chrony = Scripted({("timedatectl", "show", "--property=NTPSynchronized", "--value"): cr("yes\n"),
                       ("chronyc", "-c", "tracking"): cr("A9FEA97B,169.254.169.123,3,1.0,-0.000250,0.0,0.0\n")})
    off, synced = clock_offset(chrony)
    assert round(off, 3) == 0.25 and synced is True
    td = Scripted({("timedatectl", "timesync-status"): cr("       Server: x\n       Offset: -1.5ms\n    Delay: 2ms\n"),
                   ("timedatectl", "show", "--property=NTPSynchronized", "--value"): cr("no\n")})
    off, synced = clock_offset(td)
    assert off == 1.5 and synced is False
    assert clock_offset(Scripted({})) == (None, None)                           # no tools at all: unknown, no crash


def test_proc_sampler(tmp_path):
    (tmp_path / "self").mkdir()
    (tmp_path / "self" / "status").write_text("Name:\tpython\nVmRSS:\t   20480 kB\n")
    state = {"ticks": 1000}

    def write_stat():
        (tmp_path / "self" / "stat").write_text(
            f"1 (py thon) S 0 0 0 0 0 0 0 0 0 0 {state['ticks']} 100 0 0 0 0 1 0 0 0")
    write_stat()
    t = [0.0]
    sp = ProcSampler(tmp_path, clock=lambda: t[0])
    sp.ticks = 100
    assert sp.rss_mb() == 20.0 and sp.cpu_pct() is None                           # first sample has no delta
    state["ticks"] = 1050                                                          # +0.5 s of CPU in 2 s
    write_stat()
    t[0] = 2.0
    assert sp.cpu_pct() == 25.0
    assert ProcSampler(tmp_path / "nowhere").rss_mb() is None


def test_probe_self_measurement(tmp_path):
    cfg = make_config(probe_id="probe-a1")
    clock = FakeClock(1_795_000_000.0)
    sp = Spool(tmp_path / "s.db", clock=clock)
    sp.add(build_measurement(cfg, "gateway", "ok", labels={"port": "c01"}, ts="2026-11-18T02:00:00.000Z").to_dict())
    st = Stats(clock)
    st.skipped("throughput")
    m = build_probe_self(cfg, sp, st, {"state": "unreachable"}, ProcSampler(tmp_path), Scripted({}), clock())
    Measurement.from_dict(m.to_dict(), require_id=True)                            # ingest-valid
    assert m.test == "probe_self" and m.outcome == "ok" and m.labels == {}
    assert m.metrics["spool_depth"] == 1 and m.metrics["spool_bytes"] > 0 and m.metrics["dropped_total"] == 0
    assert m.metrics["push_lag_s"] > 0 and "clock_offset_ms" not in m.metrics       # unknown -> omitted, not faked
    assert m.detail["skipped"] == {"throughput": 1} and m.detail["skipped_total"] == 1
    assert m.detail["shipper_state"] == "unreachable" and m.probe == "probe-a1" and m.site == "hall-b"

"""M1 measurement tests wired into the scheduler (beat set vs scheduled set) and the CLI."""
from __future__ import annotations

import json
import time

import pytest
from conftest import make_config
from dnsstub import DnsStub
from fakes import FakeClock
from measure_support import BOUND, PORTS2
from netfakes import FakeEnv, FakeIcmp, FakePacketIO, ScriptRunner, link_rules, path_responder, validate_measurements

from exp_probe import cli, scheduler
from exp_probe.config import Paths
from exp_probe.lease import write_lease
from exp_probe.scheduler import BEAT_PARALLEL, REGISTRY, SCHEDULED, ManualPool, Rotation, Scheduler
from exp_probe.tests import dns as dns_mod
from exp_probe.tests import register_all

S1 = {"ip": "10.1.0.2", "offer_delay": 0.01, "ack_delay": 0.02, "yiaddr": "10.1.0.31"}
M1 = {"gateway", "dhcp_hb", "dhcp", "dns_hb", "dns", "trace", "ping", "app"}


def test_all_m1_tests_are_registered_with_the_right_roles():
    register_all()
    assert M1 <= set(REGISTRY)
    assert REGISTRY["dhcp_hb"].roles == ("client",) and REGISTRY["dhcp"].roles == ("client",)
    for name in ("gateway", "dns_hb", "dns", "trace", "ping", "app"):
        assert set(REGISTRY[name].roles) == {"client", "wifi"}


def test_beat_set_and_scheduled_set_cover_exactly_the_m1_tests():
    register_all()
    beat = set(BEAT_PARALLEL) | {"trace"}
    assert beat == {"gateway", "dhcp_hb", "dns_hb", "ping", "trace"}
    assert {"dhcp", "dns", "app"} <= set(SCHEDULED) and not (beat & set(SCHEDULED))
    assert (beat | {"dhcp", "dns", "app"}) <= set(REGISTRY)


def rig(tmp_path, monkeypatch, ports=3, tests=None):
    ports_cfg = [{"id": f"c0{i}", "iface": f"t{i}", "role": "client"} for i in range(1, ports + 1)]
    cfg = make_config(ports=ports_cfg, tests=tests or {},
                      heartbeat={"interval_s": 10, "ping": ["1.1.1.1"], "alternate_resolver": "127.0.0.2",
                                 "dns_names": ["a.example"], "trace": {"target": "8.8.8.8", "pace_ms": 1, "max_hops": 8,
                                                                       "timeout_s": 0.3, "control_path": True}})
    paths = Paths(state_dir=tmp_path / "s", run_dir=tmp_path / "r", etc_netns=tmp_path / "e", sys_class_net=tmp_path / "n",
                  proc=tmp_path / "p")
    paths.state_dir.mkdir()
    paths.run_dir.mkdir()
    runner = ScriptRunner()
    for p in cfg.ports:
        write_lease(paths, p, {**BOUND, "dns": ["127.0.0.1"]})
        link_rules(runner, p.iface)
    stub = DnsStub("normal", "127.0.0.1")
    alt = DnsStub("normal", "127.0.0.2", stub.port)
    monkeypatch.setattr(dns_mod, "DNS_PORT", stub.port)
    env = FakeEnv(icmp=lambda: FakeIcmp(path_responder(["10.1.0.2"], "8.8.8.8")), packet_io=FakePacketIO([S1]))
    # every probe of a given kind answers: gateway/ping/resolver pings are plain echoes to the target address
    from netfakes import echo_reply

    def responder(dst, ident, seq, ttl, t):
        if ttl is not None:
            return path_responder(["10.1.0.2"], "8.8.8.8")(dst, ident, seq, ttl, t)
        return [(0.002, echo_reply(ident, seq, dst), dst)]
    env = FakeEnv(icmp=lambda: FakeIcmp(responder), packet_io=FakePacketIO([S1]))
    ctl = FakeEnv(icmp=lambda: FakeIcmp(responder), ns=None)
    emitted: list = []
    clock = FakeClock(1_000_000.0)
    sched = Scheduler(cfg, paths, runner, emitted.extend, ManualPool(), clock=clock, registry=REGISTRY,
                      rotation=Rotation(None), net=lambda c, p, control=False: ctl if control else env)
    return sched, emitted, clock, [stub, alt]


def test_three_ports_produce_schema_valid_heartbeats_every_cycle(tmp_path, monkeypatch):
    register_all()
    sched, emitted, clock, stubs = rig(tmp_path, monkeypatch)
    try:
        per_cycle = []
        for i in range(1, 4):
            before = len(emitted)
            t0 = time.monotonic()
            sched.tick(1_000_000.0 + 10 * i)
            sched.pool.drain()
            per_cycle.append((time.monotonic() - t0, emitted[before:]))
        for dur, batch in per_cycle:
            validate_measurements(batch)
            tests = [m.test for m in batch]
            assert tests.count("gateway") == 3                                    # every port, every beat
            assert {"dhcp_hb", "dns_hb", "ping"} <= set(tests)
            assert [m.labels["path"] for m in batch if m.test == "trace"] == ["test", "control"]
            assert {m.outcome for m in batch} <= {"ok"}, [(m.test, m.outcome, m.error) for m in batch if m.outcome != "ok"]
            assert dur < 7.0
        # rotation: dhcp_hb / dns_hb / ping / trace walk through all three ports over three cycles
        for test in ("dhcp_hb", "dns_hb", "ping"):
            ports = [next(m.labels["port"] for m in batch if m.test == test) for _, batch in per_cycle]
            assert sorted(ports) == ["c01", "c02", "c03"], (test, ports)
        trace_ports = [next(m.labels["port"] for m in b if m.test == "trace") for _, b in per_cycle]
        assert sorted(trace_ports) == ["c01", "c02", "c03"]
    finally:
        for s in stubs:
            s.close()


def test_scheduled_tests_run_staggered_per_port_and_validate(tmp_path, monkeypatch):
    register_all()
    sched, emitted, clock, stubs = rig(tmp_path, monkeypatch, ports=2, tests={
        "dhcp": {"interval_s": 60, "offer_collect_s": 0.5}, "dns": {"interval_s": 60, "names": ["x.example"]}})
    try:
        for step in range(0, 150):
            clock.t = 1_000_000.0 + step
            sched.tick(clock.t)
            sched.pool.drain()
        sched_tests = [m for m in emitted if m.test in ("dhcp", "dns")]
        validate_measurements(sched_tests)
        seen = {(m.test, m.labels["port"]) for m in sched_tests}
        assert seen == {("dhcp", "c01"), ("dhcp", "c02"), ("dns", "c01"), ("dns", "c02")}
    finally:
        for s in stubs:
            s.close()


def test_a_crashing_test_becomes_an_error_record_not_a_fail(tmp_path, monkeypatch):
    register_all()
    sched, emitted, _, stubs = rig(tmp_path, monkeypatch)
    try:
        orig = REGISTRY["gateway"]
        monkeypatch.setitem(REGISTRY, "gateway", scheduler.TestSpec("gateway", lambda ctx: 1 / 0, orig.roles))
        sched.tick(1_000_010.0)
        sched.pool.drain()
        gws = [m for m in emitted if m.test == "gateway"]
        assert len(gws) == 3 and {m.outcome for m in gws} == {"error"} and "ZeroDivisionError" in gws[0].error
    finally:
        for s in stubs:
            s.close()


# -------------------------------------------------------------------------------------------- CLI

@pytest.fixture
def cfgfile(tmp_path):
    cfg = make_config(heartbeat={"ping": ["1.1.1.1"]}, tests={"app": {"targets": [{"app": "g", "url": "https://www.google.com/"}]}})
    f = tmp_path / "config.json"
    f.write_text(json.dumps(cfg.raw))
    return f


def args(cfgfile, tmp_path):
    return ["--config", str(cfgfile), "--state-dir", str(tmp_path / "state"), "--run-dir", str(tmp_path / "run")]


@pytest.mark.parametrize("test", sorted(M1))
def test_cli_test_runs_every_m1_test_and_prints_valid_records_without_spooling(test, cfgfile, tmp_path, capsys):
    rc = cli.main(["test", test, "--port", "c01", "--once", *args(cfgfile, tmp_path)], runner=ScriptRunner())
    assert rc == 0
    out = [json.loads(ln) for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert out and {d["test"] for d in out} == {test}
    from exp_common.config import iter_errors
    for d in out:
        assert not iter_errors(d, "measurement")
        assert d["outcome"] == "error" and d["error"]                 # no namespace / lease here: error, never fail
    assert not (tmp_path / "state" / "spool.db").exists()


def test_cli_trace_paths(cfgfile, tmp_path, capsys):
    cli.main(["test", "trace", "--port", "c01", "--path", "both", *args(cfgfile, tmp_path)], runner=ScriptRunner())
    paths = [json.loads(ln)["labels"]["path"] for ln in capsys.readouterr().out.splitlines()]
    assert paths == ["test", "control"]
    cli.main(["test", "trace", "--port", "c01", "--path", "control", *args(cfgfile, tmp_path)], runner=ScriptRunner())
    assert [json.loads(ln)["labels"]["path"] for ln in capsys.readouterr().out.splitlines()] == ["control"]


def test_cli_trace_control_refused_when_disabled(tmp_path, capsys):
    cfg = make_config(heartbeat={"trace": {"control_path": False}})
    f = tmp_path / "c.json"
    f.write_text(json.dumps(cfg.raw))
    assert cli.main(["test", "trace", "--port", "c01", "--path", "control", *args(f, tmp_path)], runner=ScriptRunner()) == 2
    assert "control path is disabled" in capsys.readouterr().err


def test_cli_rejects_a_role_the_test_does_not_run_on(tmp_path, capsys):
    cfg = make_config(ports=[*PORTS2, {"id": "w01", "iface": "wl0", "role": "wifi"}])
    f = tmp_path / "c.json"
    f.write_text(json.dumps(cfg.raw))
    assert cli.main(["test", "dhcp_hb", "--port", "w01", *args(f, tmp_path)], runner=ScriptRunner()) == 2
    assert "does not run on a wifi port" in capsys.readouterr().err

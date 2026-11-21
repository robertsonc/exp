"""The path timer (SR-22): only the configured hops and the requesting client are ever probed; idle vs loaded samples; ICMP."""
from __future__ import annotations

import socket
import struct
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from stbox import FakeClock, FakePinger

from exp_speedtest import path as pathmod
from exp_speedtest.path import (
    IcmpPinger,
    PathTimer,
    TargetNotAllowed,
    build_echo,
    checksum,
    default_gateway,
    parse_extended_error,
)


def timer(**kw) -> tuple[PathTimer, FakePinger, FakeClock, dict]:
    p, clock, state = FakePinger(), FakeClock(), {"loaded": False}
    t = PathTimer(gateway=kw.get("gateway", "10.0.0.1"), edge=kw.get("edge", "10.0.0.2"), edge1=kw.get("edge1", "203.0.113.1"), pinger=p,
                  loaded=lambda: state["loaded"], clock=clock, default_gw=kw.get("default_gw", lambda: "10.9.9.9"))
    return t, p, clock, state


def test_only_configured_hops_and_session_clients_may_be_probed():
    t, p, _, _ = timer()
    assert t.allowed_targets() == {"10.0.0.1", "10.0.0.2", "203.0.113.1"}
    for bad in ("8.8.8.8", "1.1.1.1", "10.0.0.3", "127.0.0.1", "10.0.0.1 ", "10.0.0.1;id", ""):
        with pytest.raises(TargetNotAllowed):
            t.ping_target(bad)
    assert p.pinged == [], "a refused target is never sent anything"
    t.watch_device("st_a", "10.60.1.7")
    assert t.ping_target("10.60.1.7") == 0.5 and p.pinged == ["10.60.1.7"]
    t.forget_device("st_a")
    with pytest.raises(TargetNotAllowed):
        t.ping_target("10.60.1.7")


def test_sample_cycle_only_touches_allowed_addresses_and_one_client_per_session():
    t, p, _, _ = timer()
    t.watch_device("st_a", "10.60.1.7")
    for _ in range(20):
        t.sample_once()
    assert set(p.pinged) == {"10.0.0.1", "10.0.0.2", "203.0.113.1", "10.60.1.7"}
    assert p.pinged.count("10.60.1.7") <= pathmod.MAX_DEVICE_SAMPLES, "bounded per session (no ping flood at a phone)"
    assert t.device_icmp_ms("st_a") == 0.5


def test_idle_and_loaded_samples_are_kept_apart():
    t, p, clock, state = timer()
    p.rtt = 1.0
    for _ in range(4):
        t.sample_once()
        clock.advance(5)
    state["loaded"] = True
    p.rtt = 9.0
    since = clock()
    for _ in range(3):
        t.sample_once()
        clock.advance(1)
    snap = t.snapshot("st_a", since=since)
    assert snap["gateway_ms"] == {"idle": 1.0, "loaded": 9.0, "samples": 7}
    assert t.snapshot("st_a", since=clock() + 100)["gateway_ms"]["loaded"] is None, "only loaded samples of this session's window"
    p.rtt = None                                                        # timeouts are not samples
    t.sample_once()
    assert t.snapshot(None)["gateway_ms"]["samples"] == 7


def test_unconfigured_hops_report_nothing_and_windows_expire():
    t, p, clock, _ = timer(edge=None, edge1=None)
    t.sample_once()
    snap = t.snapshot(None)
    assert snap["edge_ms"] == {"idle": None, "loaded": None, "samples": 0} and snap["edge1_addr"] is None
    assert set(p.pinged) == {"10.0.0.1"}
    clock.advance(301)
    assert t.snapshot(None)["gateway_ms"]["idle"] is None


def test_gateway_auto_follows_the_default_route():
    gw = ["10.9.9.9"]
    t, p, clock, _ = timer(gateway="auto", default_gw=lambda: gw[0])
    t.sample_once()
    assert "10.9.9.9" in p.pinged
    gw[0] = "10.8.8.8"
    clock.advance(61)
    t.sample_once()
    assert "10.8.8.8" in p.pinged


def test_edge1_auto_is_the_hop_after_the_edge():
    class Tracer(FakePinger):
        hops = {1: "10.0.0.1", 2: "10.0.0.2", 3: "203.0.113.1"}

        def trace_hop(self, target, ttl, timeout=1.5):
            self.pinged.append(f"trace:{target}:{ttl}")
            return self.hops.get(ttl), False
    p, clock = Tracer(), FakeClock()
    t = PathTimer(gateway="10.0.0.1", edge="10.0.0.2", edge1="auto", pinger=p, clock=clock)
    t.sample_once()
    snap = t.snapshot(None)
    assert snap["edge1_addr"] == "203.0.113.1"
    traces = [x for x in p.pinged if x.startswith("trace:")]
    assert set(x.split(":")[1] for x in traces) == {"1.1.1.1"} and max(int(x.split(":")[2]) for x in traces) == 3, "never past edge+1"
    assert "203.0.113.1" in p.pinged


def test_edge1_auto_unresolved_when_the_edge_never_answers_and_retries_later():
    class Silent(FakePinger):
        def trace_hop(self, target, ttl, timeout=1.5):
            return None, False
    t = PathTimer(gateway=None, edge="10.0.0.2", edge1="auto", pinger=Silent(), clock=FakeClock())
    t.sample_once()
    assert t.snapshot(None)["edge1_addr"] is None


def test_icmp_helpers():
    pkt = build_echo(7, 9, b"hello")
    assert pkt[0] == 8 and checksum(pkt) == 0
    assert checksum(b"\x00") >= 0
    # sock_extended_err(errno=EHOSTUNREACH, origin=ICMP(2), type=11, code=0, pad, info, data) + sockaddr_in(10.1.2.3)
    blob = struct.pack("=IBBBBII", 113, 2, 11, 0, 0, 0, 0) + struct.pack("=HH", socket.AF_INET, 0) + socket.inet_aton("10.1.2.3") + b"\0" * 8
    assert parse_extended_error(blob) == (2, 11, 0, "10.1.2.3")
    assert parse_extended_error(blob[:16])[3] is None
    with pytest.raises(ValueError):
        parse_extended_error(b"short")


def test_default_gateway_parser(tmp_path: Path):
    f = tmp_path / "route"
    f.write_text("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
                 "eth1\t00000000\t0100000A\t0003\t0\t0\t200\t00000000\t0\t0\t0\n"
                 "eth0\t00000000\t0200000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
                 "eth0\t0000FEA9\t00000000\t0001\t0\t0\t1000\t0000FFFF\t0\t0\t0\n")
    assert default_gateway(str(f)) == "10.0.0.2", "lowest metric wins"
    assert default_gateway(str(tmp_path / "missing")) is None
    f.write_text("garbage\nmore garbage\n")
    assert default_gateway(str(f)) is None


def test_ping_binary_fallback_uses_argv_and_parses(monkeypatch):
    calls = []

    def fake_run(argv, **kw):
        calls.append((argv, kw))
        return SimpleNamespace(stdout="64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.734 ms\n", returncode=0)
    monkeypatch.setattr(pathmod.subprocess, "run", fake_run)
    monkeypatch.setattr(pathmod.shutil, "which", lambda n: "/bin/ping")
    pinger = IcmpPinger(backend="ping")
    assert pinger.ping("10.0.0.1") == 0.734
    argv, kw = calls[0]
    assert argv[0] == "/bin/ping" and argv[-1] == "10.0.0.1" and isinstance(argv, list) and "shell" not in kw
    with pytest.raises(ValueError):                                     # not an IPv4 literal: refused before any subprocess
        pinger.ping("10.0.0.1; rm -rf /")
    with pytest.raises(ValueError):
        pinger.ping("$(id)")
    assert len(calls) == 1
    monkeypatch.setattr(pathmod.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("ping", 1)))
    assert pinger.ping("10.0.0.1") is None


def test_ping_binary_trace_parsing(monkeypatch):
    monkeypatch.setattr(pathmod.shutil, "which", lambda n: "/bin/ping")
    out = {"v": SimpleNamespace(stdout="From 10.0.0.2 icmp_seq=1 Time to live exceeded\n", returncode=1)}
    monkeypatch.setattr(pathmod.subprocess, "run", lambda *a, **k: out["v"])
    pinger = IcmpPinger(backend="ping")
    assert pinger.trace_hop("1.1.1.1", 2) == ("10.0.0.2", False)
    out["v"] = SimpleNamespace(stdout="64 bytes from 1.1.1.1: time=3 ms\n", returncode=0)
    assert pinger.trace_hop("1.1.1.1", 9) == ("1.1.1.1", True)
    out["v"] = SimpleNamespace(stdout="", returncode=1)
    assert pinger.trace_hop("1.1.1.1", 1) == (None, False)


def test_no_backend_means_no_rtts_not_an_error():
    pinger = IcmpPinger(backend="none")
    assert pinger.ping("127.0.0.1") is None and pinger.trace_hop("1.1.1.1", 1) == (None, False)


@pytest.fixture()
def real_pinger() -> IcmpPinger:
    p = IcmpPinger()
    if p.backend != "dgram":
        pytest.skip("unprivileged ICMP sockets are not permitted here (net.ipv4.ping_group_range)")
    return p


def test_real_unprivileged_icmp_to_loopback(real_pinger: IcmpPinger):
    rtt = real_pinger.ping("127.0.0.1")
    assert rtt is not None and 0 < rtt < 100
    assert real_pinger.ping("127.0.0.1", timeout=1.0) is not None


def test_real_ttl_limited_probe_reaches_loopback(real_pinger: IcmpPinger):
    hop, reached = real_pinger.trace_hop("127.0.0.1", 1)
    assert reached is True and hop == "127.0.0.1"

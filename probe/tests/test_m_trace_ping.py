"""`trace` (paced, sequential, control path) and `ping`."""
from __future__ import annotations

import json

import pytest
from dnsstub import DnsStub
from measure_support import BOUND, make_ctx
from netfakes import (
    FakeEnv,
    FakeIcmp,
    ScriptRunner,
    answer_all,
    echo_reply,
    path_responder,
    recorded,
    silent,
    validate_measurements,
)

from exp_probe.scheduler import ManualPool, Scheduler, TestSpec, register_test
from exp_probe.tests import dns as dns_mod
from exp_probe.tests import ping as ping_mod
from exp_probe.tests import trace as trace_mod

T = "8.8.8.8"
GOOD_PATH = ["10.1.0.2", "10.1.0.1", None]


def tctx(tmp_path, responder, control=None, **kw):
    ep = FakeIcmp(responder)
    cep = FakeIcmp(control) if control else None
    ctx = make_ctx(tmp_path, env=FakeEnv(icmp=ep), control=FakeEnv(icmp=cep, ns=None) if cep else None, **kw)
    return ctx, ep, cep


# --------------------------------------------------------------------------------------------- trace

def test_trace_ok_has_exactly_the_catalog_shape(tmp_path):
    ctx, ep, _ = tctx(tmp_path, path_responder(GOOD_PATH, T, rtts=[0.0004, 0.0009, 0.0, 0.0113]))
    (m,) = trace_mod.trace(ctx)
    validate_measurements([m])
    assert m.test == "trace" and m.outcome == "ok" and m.labels == {"port": "c01", "path": "test"}
    assert set(m.metrics) == {"reached", "hops", "last_ttl", "rtt_ms"}
    assert m.metrics["reached"] == 1 and m.metrics["hops"] == 4 and m.metrics["last_ttl"] == 4 and m.metrics["rtt_ms"] == 11.3
    assert m.detail["hops"] == [[1, "10.1.0.2", 0.4], [2, "10.1.0.1", 0.9], [3, None, None], [4, T, 11.3]]
    assert m.detail["last_ip"] == T and m.detail["target"] == T and ep.closed


def test_trace_uses_the_configured_pace_hops_and_timeout(tmp_path):
    ctx, ep, _ = tctx(tmp_path, silent, heartbeat={"trace": {"target": T, "pace_ms": 50, "max_hops": 5, "timeout_s": 0.5}})
    (m,) = trace_mod.trace(ctx)
    times = [s[0] for s in ep.sent]
    assert len(times) == 5 and all(abs((b - a) - 0.05) < 1e-9 for a, b in zip(times, times[1:], strict=False))
    assert m.outcome == "fail" and m.metrics["hops"] == 0 and m.error == f"no reply from {T}; no hop answered"


def test_trace_egress_cut_names_the_last_hop_and_control_path_still_reaches(tmp_path):
    cut = path_responder(["10.1.0.2", "10.1.0.1"], T, rtts=[0.0003, 0.0007], reach=False)
    ok = path_responder(["192.168.9.1", "100.64.0.1"], T, rtts=[0.001, 0.004, 0.014])
    ctx, _, _ = tctx(tmp_path, cut, control=ok)
    (m,) = trace_mod.trace(ctx)
    validate_measurements([m])
    assert m.outcome == "fail" and m.metrics["reached"] == 0 and m.metrics["last_ttl"] == 2 and "rtt_ms" not in m.metrics
    assert m.detail["last_ip"] == "10.1.0.1" and m.error == f"no reply from {T}; path stops after 10.1.0.1 (hop 2)"
    ctx.path = "control"
    (c,) = trace_mod.trace(ctx)
    validate_measurements([c])
    assert c.outcome == "ok" and c.labels == {"port": "c01", "path": "control"} and c.metrics["reached"] == 1


def test_trace_slow_destination_is_degraded(tmp_path):
    ctx, _, _ = tctx(tmp_path, path_responder(["10.1.0.2"], T, rtts=[0.001, 0.260]))
    (m,) = trace_mod.trace(ctx)
    assert m.outcome == "degraded" and m.metrics["rtt_ms"] == 260.0
    ctx, _, _ = tctx(tmp_path, path_responder(["10.1.0.2"], T, rtts=[0.001, 0.260]), tests={"trace": {"thresholds": {"rtt_ms": 400}}})
    assert trace_mod.trace(ctx)[0].outcome == "ok"


def test_trace_with_no_lease_anywhere_says_no_client_could_run_it(tmp_path):
    ctx, ep, _ = tctx(tmp_path, answer_all(), leased=())
    (m,) = trace_mod.trace(ctx)
    validate_measurements([m])
    assert m.outcome == "error" and m.error == "no client could run it: c01 has no lease; c02 has no lease"
    assert "null" not in m.error.lower() and m.labels == {"port": "c01", "path": "test"} and ep.sent == []


def test_trace_falls_back_to_a_port_with_a_lease_but_explicit_does_not(tmp_path):
    ctx, _, _ = tctx(tmp_path, path_responder([], T), leased=("c02",))
    (m,) = trace_mod.trace(ctx)
    assert m.outcome == "ok" and m.labels["port"] == "c02"
    ctx, ep, _ = tctx(tmp_path, path_responder([], T), leased=("c02",), explicit=True)
    (m,) = trace_mod.trace(ctx)
    assert m.outcome == "error" and m.error == "no lease: c01 has no lease" and ep.sent == []


def test_control_path_needs_no_lease_and_runs_in_the_host_environment(tmp_path):
    ctx, ep, cep = tctx(tmp_path, silent, control=path_responder([], T), leased=(), path="control")
    (m,) = trace_mod.trace(ctx)
    assert m.outcome == "ok" and m.labels["path"] == "control" and ep.sent == [] and cep.sent


def test_trace_missing_namespace_and_no_raw_socket_are_errors(tmp_path):
    ctx = make_ctx(tmp_path, env=FakeEnv(exists=False))
    assert "is missing" in trace_mod.trace(ctx)[0].error
    ctx = make_ctx(tmp_path, env=FakeEnv(icmp=None))
    (m,) = trace_mod.trace(ctx)
    assert m.outcome == "error" and "ICMP socket unavailable" in m.error


def test_trace_detail_is_bounded_and_valid_at_the_maximum_sweep(tmp_path):
    ctx, _, _ = tctx(tmp_path, path_responder([f"10.{i}.0.1" for i in range(1, 70)], T),
                     heartbeat={"trace": {"target": T, "pace_ms": 1, "max_hops": 64, "timeout_s": 0.2}})
    (m,) = trace_mod.trace(ctx)
    validate_measurements([m])
    assert len(m.detail["hops"]) == 64 and len(json.dumps(m.detail)) < 8 * 1024


def test_trace_target_hostname_is_resolved_with_the_ports_resolvers(tmp_path, monkeypatch):
    stub = DnsStub("normal", "127.0.0.1")
    monkeypatch.setattr(dns_mod, "DNS_PORT", stub.port)
    try:
        ctx, ep, _ = tctx(tmp_path, answer_all(), lease_doc={**BOUND, "dns": ["127.0.0.1"]},
                          heartbeat={"trace": {"target": "svc.example", "pace_ms": 5, "max_hops": 5, "timeout_s": 0.3}})
        (m,) = trace_mod.trace(ctx)
        assert m.outcome == "ok" and ep.sent[0][1] in ("192.0.2.10", "192.0.2.11") and m.detail["target"] == "svc.example"
        ctx, _, _ = tctx(tmp_path, silent, lease_doc={**BOUND, "dns": []},
                         heartbeat={"trace": {"target": "svc.example", "pace_ms": 5, "max_hops": 5, "timeout_s": 0.3}})
        (m,) = trace_mod.trace(ctx)
        assert m.outcome == "error" and "cannot resolve" in m.error
    finally:
        stub.close()


def test_scheduler_runs_the_test_sweep_then_the_control_sweep_never_together(tmp_path):
    log: list[str] = []

    class Logged(FakeIcmp):
        def __init__(self, tag, responder):
            super().__init__(responder)
            self.tag = tag
            log.append(f"open:{tag}")

        def close(self):
            log.append(f"close:{tag_of(self)}")
            super().close()

    def tag_of(ep):
        return ep.tag

    env = FakeEnv(icmp=lambda: Logged("test", path_responder([], T)))
    ctl = FakeEnv(icmp=lambda: Logged("control", path_responder([], T)), ns=None)
    ctx = make_ctx(tmp_path, env=env, control=ctl)
    reg: dict[str, TestSpec] = {}
    register_test("trace", trace_mod.trace, roles=("client", "wifi"), registry=reg)
    emitted: list = []
    sched = Scheduler(ctx.cfg, ctx.paths, ctx.runner, emitted.extend, ManualPool(), clock=ctx.clock, registry=reg,
                      net=ctx.net)
    sched.cfg.heartbeat["trace"]["pace_ms"] = 1
    sched.run_beat(1_000_010.0)
    sched.pool.drain()
    assert log == ["open:test", "close:test", "open:control", "close:control"]
    assert [m.labels["path"] for m in emitted] == ["test", "control"]
    validate_measurements(emitted)


# ---------------------------------------------------------------------------------------------- ping

def pctx(tmp_path, responder, **kw):
    ep = FakeIcmp(responder)
    kw.setdefault("heartbeat", {"ping": ["1.1.1.1", "8.8.8.8"]})
    return make_ctx(tmp_path, env=FakeEnv(icmp=ep), **kw), ep


def test_ping_one_record_per_target_with_catalog_shape(tmp_path):
    ctx, ep = pctx(tmp_path, answer_all(0.0102))
    ms = ping_mod.ping(ctx)
    validate_measurements(ms)
    assert [m.target for m in ms] == ["1.1.1.1", "8.8.8.8"] and {m.outcome for m in ms} == {"ok"}
    for m in ms:
        assert m.test == "ping" and m.labels == {"port": "c01"} and set(m.metrics) == {"rtt_ms", "loss_pct"}
        assert m.metrics == {"rtt_ms": 10.2, "loss_pct": 0}
    assert ep.closed and {s[1] for s in ep.sent} == {"1.1.1.1", "8.8.8.8"}


def test_ping_loss_and_total_loss(tmp_path):
    def resp(dst, ident, seq, ttl, t):
        if dst == "8.8.8.8":
            return []
        return [] if seq == 1 else [(0.09, echo_reply(ident, seq, dst), dst)]
    ms = {m.target: m for m in ping_mod.ping(pctx(tmp_path, resp)[0])}
    validate_measurements(list(ms.values()))
    assert ms["1.1.1.1"].outcome == "degraded" and ms["1.1.1.1"].metrics["loss_pct"] == 25.0
    assert ms["8.8.8.8"].outcome == "fail" and ms["8.8.8.8"].error == "100% loss" and ms["8.8.8.8"].metrics == {"loss_pct": 100}


def test_ping_slow_is_degraded(tmp_path):
    (m, _) = ping_mod.ping(pctx(tmp_path, answer_all(0.4))[0])
    assert m.outcome == "degraded" and "mean rtt" in m.error


def test_ping_no_lease_is_an_error_with_the_reason(tmp_path):
    (m,) = ping_mod.ping(pctx(tmp_path, answer_all(), leased=())[0])
    validate_measurements([m])
    assert m.outcome == "error" and m.error.startswith("no client could run it:") and m.target == "1.1.1.1"


def test_ping_without_targets_emits_nothing(tmp_path):
    assert ping_mod.ping(make_ctx(tmp_path, env=FakeEnv(icmp=FakeIcmp(answer_all())))) == []


def test_ping_falls_back_to_the_ping_binary_without_a_raw_socket(tmp_path):
    r = ScriptRunner()
    r.on("ping", out=recorded("ping_ok.txt"))
    ctx = make_ctx(tmp_path, runner=r, env=FakeEnv(icmp=None), heartbeat={"ping": ["1.1.1.1"]})
    (m,) = ping_mod.ping(ctx)
    validate_measurements([m])
    assert m.outcome == "ok" and m.metrics == {"rtt_ms": 0.03, "loss_pct": 0}
    assert r.calls[0][:4] == ["ip", "netns", "exec", "exp-c01"] and "ping" in r.calls[0] and "1.1.1.1" == r.calls[0][-1]
    r2 = ScriptRunner()
    r2.on("ping", out=recorded("ping_loss.txt"), rc=1)
    (m,) = ping_mod.ping(make_ctx(tmp_path, runner=r2, env=FakeEnv(icmp=None), heartbeat={"ping": ["1.1.1.1"]}))
    assert m.outcome == "fail" and m.metrics == {"loss_pct": 100}


def test_ping_with_neither_raw_socket_nor_binary_is_error(tmp_path):
    (m,) = ping_mod.ping(make_ctx(tmp_path, runner=ScriptRunner(), env=FakeEnv(icmp=None), heartbeat={"ping": ["1.1.1.1"]}))
    validate_measurements([m])
    assert m.outcome == "error" and "ICMP socket unavailable" in m.error


def test_ping_unresolvable_hostname_is_a_fail_of_that_target(tmp_path):
    ctx, ep = pctx(tmp_path, answer_all(), heartbeat={"ping": ["1.1.1.1", "nope.example"]}, lease_doc={**BOUND, "dns": []})
    ms = {m.target: m for m in ping_mod.ping(ctx)}
    assert ms["1.1.1.1"].outcome == "ok" and ms["nope.example"].outcome == "fail" and "cannot resolve" in ms["nope.example"].error


@pytest.mark.parametrize("fn", [ping_mod.ping, trace_mod.trace])
def test_unusable_state_never_says_from_null(tmp_path, fn):
    (m,) = fn(make_ctx(tmp_path, leased=(), env=FakeEnv(icmp=FakeIcmp(silent)), heartbeat={"ping": ["1.1.1.1"]}))
    assert "null" not in (m.error or "").lower() and "none" not in (m.error or "").lower().split(":")[0]

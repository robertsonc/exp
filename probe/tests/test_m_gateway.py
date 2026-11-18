"""`gateway`: one record per port with exactly the catalog labels/metrics (01-contracts.md 3)."""
from __future__ import annotations

from measure_support import make_ctx
from netfakes import FakeEnv, FakeIcmp, ScriptRunner, answer_all, echo_reply, link_rules, silent, validate_measurements

from exp_probe.checks.gateway import classify, gateway


def run(tmp_path, responder, **kw):
    ep = FakeIcmp(responder)
    ctx = make_ctx(tmp_path, env=FakeEnv(icmp=ep), **kw)
    return gateway(ctx), ep


def test_ok_record_has_exactly_the_catalog_shape(tmp_path):
    (m,), ep = run(tmp_path, answer_all(0.0006))
    validate_measurements([m])
    assert m.test == "gateway" and m.outcome == "ok"
    assert m.labels == {"port": "c01", "iface": "t0"}
    assert set(m.metrics) == {"link_up", "rtt_ms", "loss_pct", "carrier_changes"}
    assert m.metrics["link_up"] == 1 and m.metrics["loss_pct"] == 0 and m.metrics["carrier_changes"] == 2
    assert m.metrics["rtt_ms"] == 0.6 and m.duration_ms == 0.6
    assert m.detail == {"gateway_ip": "10.1.0.1", "gateway_mac": "00:00:5e:00:01:65", "neighbor_state": "REACHABLE"}
    assert {s[1] for s in ep.sent} == {"10.1.0.1"} and ep.closed


def test_partial_loss_is_degraded(tmp_path):
    n = {"i": 0}

    def resp(dst, ident, seq, ttl, t):
        n["i"] += 1
        return [] if n["i"] == 3 else [(0.002, echo_reply(ident, seq, dst), dst)]
    (m,), _ = run(tmp_path, resp)
    validate_measurements([m])
    assert m.outcome == "degraded" and m.metrics["loss_pct"] == 25.0 and not m.error


def test_no_reply_is_fail_and_names_the_ip(tmp_path):
    (m,), _ = run(tmp_path, silent)
    validate_measurements([m])
    assert m.outcome == "fail" and m.error == "no reply from 10.1.0.1"
    assert m.metrics["loss_pct"] == 100 and m.metrics["link_up"] == 1 and "rtt_ms" not in m.metrics
    assert m.detail["gateway_ip"] == "10.1.0.1"


def test_classification_boundaries():
    assert [classify(x) for x in (0, 0.1, 25, 49.9, 50, 75, 100)] == \
        ["ok", "degraded", "degraded", "degraded", "fail", "fail", "fail"]


def test_link_down_is_a_network_failure_not_an_error(tmp_path):
    r = ScriptRunner()
    link_rules(r, "t0", up=False, changes=5)
    ep = FakeIcmp(answer_all())
    (m,) = gateway(make_ctx(tmp_path, runner=r, env=FakeEnv(icmp=ep)))
    validate_measurements([m])
    assert m.outcome == "fail" and m.metrics == {"link_up": 0, "carrier_changes": 5} and "no link" in m.error
    assert ep.sent == []                                         # nothing is sent into a dead link


def test_no_lease_is_error_not_fail(tmp_path):
    (m,), ep = run(tmp_path, answer_all(), leased=())
    validate_measurements([m])
    assert m.outcome == "error" and "no gateway" in m.error and ep.sent == []


def test_missing_namespace_is_error(tmp_path):
    (m,) = gateway(make_ctx(tmp_path, env=FakeEnv(icmp=FakeIcmp(answer_all()), exists=False)))
    validate_measurements([m])
    assert m.outcome == "error" and m.error == "namespace for port c01 is missing"
    assert m.labels == {"port": "c01", "iface": "t0"}


def test_no_raw_socket_is_error(tmp_path):
    (m,) = gateway(make_ctx(tmp_path, env=FakeEnv(icmp=None)))
    assert m.outcome == "error" and "ICMP socket unavailable" in m.error


def test_unreadable_link_state_is_error(tmp_path):
    (m,) = gateway(make_ctx(tmp_path, runner=ScriptRunner(), env=FakeEnv(icmp=FakeIcmp(answer_all()))))
    assert m.outcome == "error" and "cannot read link state" in m.error


def test_carrier_changes_unknown_is_just_omitted(tmp_path):
    r = ScriptRunner()
    link_rules(r, "t0", changes=None)
    (m,) = gateway(make_ctx(tmp_path, runner=r, env=FakeEnv(icmp=FakeIcmp(answer_all()))))
    assert m.outcome == "ok" and "carrier_changes" not in m.metrics

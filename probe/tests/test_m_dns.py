"""`dns_hb` and `dns` against in-process DNS stubs (UDP on loopback), negative controls included."""
from __future__ import annotations

import pytest
from dnsstub import DnsStub
from measure_support import BOUND, make_ctx
from netfakes import FakeEnv, FakeIcmp, answer_all, silent, validate_measurements

from exp_probe.tests import dns as D

ALT_HB = {"interval_s": 10, "alternate_resolver": "127.0.0.2", "dns_names": ["a.example", "b.example", "c.example"]}


@pytest.fixture
def stubs(monkeypatch):
    made: list[DnsStub] = []

    def make(mode_dhcp="normal", mode_alt="normal", **kw):
        main = DnsStub(mode_dhcp, "127.0.0.1", **kw)
        alt = DnsStub(mode_alt, "127.0.0.2", main.port)
        made.extend([main, alt])
        monkeypatch.setattr(D, "DNS_PORT", main.port)
        return main, alt
    monkeypatch.setattr(D, "DNS_TIMEOUT_S", 0.4)
    yield make
    for s in made:
        s.close()


def ctx_for(tmp_path, icmp=None, **kw):
    kw.setdefault("lease_doc", {**BOUND, "dns": ["127.0.0.1"]})
    kw.setdefault("heartbeat", ALT_HB)
    return make_ctx(tmp_path, env=FakeEnv(icmp=icmp if icmp is not None else FakeIcmp(answer_all(0.003))), **kw)


def by_kind(ms):
    return {m.labels["resolver_kind"]: m for m in ms}


# ------------------------------------------------------------------------------------------- dns_hb

def test_hb_one_record_per_resolver_with_exact_catalog_shape(tmp_path, stubs):
    main, alt = stubs()
    ms = D.dns_hb(ctx_for(tmp_path, beat_ts=1_000_010.0))
    validate_measurements(ms)
    assert len(ms) == 2 and {m.test for m in ms} == {"dns_hb"}
    d, a = by_kind(ms)["dhcp"], by_kind(ms)["alternate"]
    assert d.labels == {"port": "c01", "resolver": "127.0.0.1", "resolver_kind": "dhcp"}
    assert a.labels == {"port": "c01", "resolver": "127.0.0.2", "resolver_kind": "alternate"}
    assert set(d.metrics) == {"rtt_ms", "rcode", "answers", "ping_rtt_ms"} == set(a.metrics)
    assert d.outcome == a.outcome == "ok" and d.metrics["rcode"] == 0 and d.metrics["answers"] == 2
    assert d.metrics["ping_rtt_ms"] == 3.0 and d.duration_ms == d.metrics["rtt_ms"]
    assert d.detail["name"] == a.detail["name"]
    assert "nxdomain_canary" not in d.detail and a.detail["nxdomain_canary"]["intercepted"] is False
    assert d.detail["name"] in main.queries and not any(q.endswith(".invalid") for q in main.queries)


def test_hb_rotates_the_name_with_the_beat(tmp_path, stubs):
    stubs()
    names = [by_kind(D.dns_hb(ctx_for(tmp_path, beat_ts=1_000_000.0 + 10 * i)))["dhcp"].detail["name"] for i in range(4)]
    assert names[0] != names[1] != names[2] and names[0] == names[3]


def test_hb_blocking_dns_fails_with_a_timeout_but_ping_still_answers(tmp_path, stubs):
    stubs("drop", "normal")
    ms = D.dns_hb(ctx_for(tmp_path))
    validate_measurements(ms)
    d = by_kind(ms)["dhcp"]
    assert d.outcome == "fail" and d.error == "no answer from 127.0.0.1 within 0.4 s"
    assert "rtt_ms" not in d.metrics and d.metrics["ping_rtt_ms"] == 3.0       # reachable, just not answering DNS
    assert by_kind(ms)["alternate"].outcome == "ok"                            # the alternate tells "edge" from "resolver"


def test_hb_dead_resolver_without_icmp_reply_has_no_ping_metric(tmp_path, stubs):
    stubs("drop", "normal")
    d = by_kind(D.dns_hb(ctx_for(tmp_path, icmp=FakeIcmp(silent))))["dhcp"]
    assert d.outcome == "fail" and d.metrics == {}


@pytest.mark.parametrize("mode,fragment", [("servfail", "rcode SERVFAIL"), ("empty", "no records for")])
def test_hb_bad_answers_are_fail(tmp_path, stubs, mode, fragment):
    stubs(mode, "normal")
    d = by_kind(D.dns_hb(ctx_for(tmp_path)))["dhcp"]
    validate_measurements([d])
    assert d.outcome == "fail" and fragment in d.error
    if mode == "servfail":
        assert d.metrics["rcode"] == 2 and d.metrics["rtt_ms"] > 0


def test_hb_slow_answer_is_degraded(tmp_path, stubs):
    stubs("normal", "normal", delay=0.1)
    d = by_kind(D.dns_hb(ctx_for(tmp_path, tests={"dns": {"thresholds": {"rtt_ms": 50}}})))["dhcp"]
    assert d.outcome == "degraded" and d.metrics["rtt_ms"] >= 100


def test_hb_truncated_response_still_counts(tmp_path, stubs):
    stubs("truncated", "normal")
    d = by_kind(D.dns_hb(ctx_for(tmp_path)))["dhcp"]
    assert d.outcome == "ok" and d.metrics["answers"] == 2


def test_hb_interception_negative_control_nxdomain_hijack_is_degraded(tmp_path, stubs):
    stubs("normal", "hijack")                                  # the "alternate" answers a name that cannot exist
    a = by_kind(D.dns_hb(ctx_for(tmp_path)))["alternate"]
    validate_measurements([a])
    assert a.outcome == "degraded" and a.detail["nxdomain_canary"] == {"rcode": 0, "answers": 2, "intercepted": True}
    assert "interception" in a.error


def test_hb_honest_resolver_is_not_flagged(tmp_path, stubs):
    stubs()
    a = by_kind(D.dns_hb(ctx_for(tmp_path)))["alternate"]
    assert a.outcome == "ok" and a.detail["nxdomain_canary"]["rcode"] == 3


def test_hb_no_lease_is_error_with_reason(tmp_path, stubs):
    stubs()
    (m,) = D.dns_hb(ctx_for(tmp_path, leased=(), explicit=True))
    validate_measurements([m])
    assert m.outcome == "error" and m.error == "port c01 has no lease (no resolver known)"
    (m,) = D.dns_hb(ctx_for(tmp_path, leased=()))
    assert m.error.startswith("no client could run it:") and "null" not in m.error


def test_hb_falls_back_to_a_port_with_a_lease(tmp_path, stubs):
    stubs()
    ms = D.dns_hb(ctx_for(tmp_path, leased=("c02",)))
    assert {m.labels["port"] for m in ms} == {"c02"} and {m.outcome for m in ms} == {"ok"}


def test_hb_hostname_alternate_is_a_config_error_record_not_a_system_resolver_lookup(tmp_path, stubs):
    stubs()
    ms = D.dns_hb(ctx_for(tmp_path, heartbeat={**ALT_HB, "alternate_resolver": "dns.example.net"}))
    validate_measurements(ms)
    assert {m.outcome for m in ms} == {"ok", "error"}
    assert any("must be an IPv4 address" in m.error for m in ms if m.outcome == "error")


def test_hb_lease_without_dns_option_is_error(tmp_path, stubs):
    stubs()
    ms = D.dns_hb(ctx_for(tmp_path, lease_doc={**BOUND, "dns": []}, heartbeat={"interval_s": 10}))
    assert [m.outcome for m in ms] == ["error"] and "no resolver" in ms[0].error


def test_hb_alternate_equal_to_dhcp_resolver_is_asked_once(tmp_path, stubs):
    stubs()
    ms = D.dns_hb(ctx_for(tmp_path, heartbeat={**ALT_HB, "alternate_resolver": "127.0.0.1"}))
    assert [m.labels["resolver_kind"] for m in ms] == ["dhcp"]


def test_hb_missing_namespace_is_error(tmp_path, stubs):
    stubs()
    ctx = ctx_for(tmp_path)
    ctx.net = lambda cfg, port, control=False: FakeEnv(exists=False)
    (m,) = D.dns_hb(ctx)
    assert m.outcome == "error" and "is missing" in m.error


# --------------------------------------------------------------------------------------------- dns

def test_dns_one_record_per_resolver_and_name(tmp_path, stubs):
    main, _ = stubs()
    ms = D.dns_test(ctx_for(tmp_path, tests={"dns": {"interval_s": 300, "names": ["www.google.com", "teams.microsoft.com"]}}))
    validate_measurements(ms)
    assert len(ms) == 4 and {m.test for m in ms} == {"dns"}
    m = next(x for x in ms if x.target == "www.google.com" and x.labels["resolver"] == "127.0.0.1")
    assert m.labels == {"port": "c01", "resolver": "127.0.0.1"} and set(m.metrics) == {"rtt_ms", "rcode", "answers"}
    assert m.detail["name"] == "www.google.com" and sorted(m.detail["answers"]) == ["192.0.2.10", "192.0.2.11"] and m.outcome == "ok"
    assert m.detail["nxdomain_canary"]["intercepted"] is False


def test_dns_falls_back_to_the_heartbeat_names(tmp_path, stubs):
    stubs()
    ms = D.dns_test(ctx_for(tmp_path, tests={"dns": {"interval_s": 300}}))
    assert {m.target for m in ms} == set(ALT_HB["dns_names"])


def test_dns_blocked_resolver_fails_with_counts_and_two_attempts(tmp_path, stubs):
    main, _ = stubs("drop", "normal")
    ms = D.dns_test(ctx_for(tmp_path, tests={"dns": {"interval_s": 300, "names": ["x.example"]}}))
    validate_measurements(ms)
    d = next(m for m in ms if m.labels["resolver"] == "127.0.0.1")
    assert d.outcome == "fail" and d.error == "no answers (2 timeouts, 0 errors)" and d.metrics == {"answers": 0}
    assert main.queries.count("x.example") == 2                                # 2 attempts
    assert next(m for m in ms if m.labels["resolver"] == "127.0.0.2").outcome == "ok"


def test_dns_interception_negative_control(tmp_path, stubs):
    stubs("hijack", "normal")
    ms = D.dns_test(ctx_for(tmp_path, tests={"dns": {"interval_s": 300, "names": ["x.example"]}}))
    d = next(m for m in ms if m.labels["resolver"] == "127.0.0.1")
    assert d.outcome == "degraded" and d.detail["nxdomain_canary"]["intercepted"] is True
    assert next(m for m in ms if m.labels["resolver"] == "127.0.0.2").detail["nxdomain_canary"]["intercepted"] is False


def test_dns_no_lease_is_error(tmp_path, stubs):
    stubs()
    (m,) = D.dns_test(ctx_for(tmp_path, leased=()))
    assert m.outcome == "error" and "no lease" in m.error


def test_query_a_rejects_a_bad_name_without_touching_the_network(tmp_path, stubs):
    main, _ = stubs()
    r = D.query_a(FakeEnv(), "127.0.0.1", "a" * 70 + ".example")
    assert r.error and not r.responded and main.queries == []


def test_send_errors_are_a_fail_with_the_reason_not_a_crash(tmp_path, stubs):
    import socket as _s
    stubs()

    class BadSock(_s.socket):
        def sendto(self, *a, **k):
            raise OSError(22, "Invalid argument")            # what a blackhole route does

    class Blackholed(FakeEnv):
        def socket(self, family, type_, proto=0):
            return BadSock(family, type_, proto)
    r = D.query_a(Blackholed(), "127.0.0.1", "x.example")
    assert not r.responded and not r.timed_out and r.error == "cannot query 127.0.0.1: Invalid argument"
    out, err = D.assess(r, 250)
    assert out == "fail" and err == r.error


def test_cannot_open_a_socket_is_reported(tmp_path, stubs):
    class NoSock(FakeEnv):
        def socket(self, family, type_, proto=0):
            raise OSError(19, "No such device")
    r = D.query_a(NoSock(), "127.0.0.1", "x.example")
    assert r.error == "cannot open a socket: No such device"

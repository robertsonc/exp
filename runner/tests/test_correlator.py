"""The correlation loop against the c1 fake collector."""
from __future__ import annotations

import json
import time

import fake_ca
import fake_st_collector as fst
import pytest
from exp_common import tlspin
from rthelpers import PIN, make_cfg, runner_token, secret, st_result

from exp_runner import evidence as ev
from exp_runner.collector_client import AuthError, CollectorClient, CollectorError
from exp_runner.connectors import Connector, EvidenceResult, SyslogConnector
from exp_runner.correlator import READY_GRACE_S, Correlator, StateStore
from exp_runner.identity import IdentityResolver
from exp_runner.ring import Ring
from exp_runner.syslog_parse import parse_line

NOW = time.time()


class Env:
    def __init__(self, tmp_path, cfg=None, connectors=None, now_fn=time.time, token=None, **fake_kw):
        self.tmp = tmp_path
        self.toks = fst.default_tokens()
        self.fake = fst.start(tokens=self.toks, **fake_kw)
        self.cfg = cfg or make_cfg()
        self.ring = Ring(tmp_path / "syslog.db").open()
        self.state = StateStore(tmp_path / "runner.db").open()
        self.connectors = connectors if connectors is not None else [SyslogConnector(self.cfg)]
        self.now = now_fn
        self.token = token or runner_token(self.toks)
        self.posted: list[tuple[str, str]] = []
        self.corr = self.build()

    def client(self, **kw):
        c = CollectorClient(f"http://127.0.0.1:{self.fake.port}", None, self.token, sleep=lambda _s: None, **kw)
        orig = c.post_evidence

        def counting(tid, doc):
            self.posted.append((tid, doc["kind"]))
            return orig(tid, doc)
        c.post_evidence = counting
        return c

    def build(self, connectors=None, **kw):
        res = IdentityResolver(self.cfg, self.ring, secret())
        return Correlator(self.cfg, self.client(**kw), self.ring, res, connectors if connectors is not None else self.connectors,
                          self.state, now_fn=self.now, workers=2)

    def add_test(self, n=1, **kw):
        doc = st_result(n, **kw)
        t, _ = self.fake.app.store(doc, "spd-core", doc["site"])
        return doc["id"], t

    def close(self):
        self.corr.close()
        self.fake.stop()
        self.ring.close()
        self.state.close()


@pytest.fixture()
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.close()


def lines(env, ip="10.60.14.77", n=3, at=None):
    at = at or time.time() - 880
    for i in range(n):
        p = parse_line(f"action=deny src={ip} dst=10.0.0.10 dport=22 proto=tcp rule=guest-deny from_zone=Guest to_zone=Mgmt", at + i)
        env.ring.insert_many([(p, "10.0.0.9", at + i)])
    p = parse_line(f"DHCPACK on {ip} to f0:18:98:aa:bb:01 (alices-iphone) via eth1", at - 30)
    env.ring.insert_many([(p, "10.0.0.1", at - 30)])


def test_new_test_gets_every_kind_exactly_once_then_completes(env):
    lines(env)
    tid, t = env.add_test()
    assert env.corr.tick() == 1
    assert sorted(k for _, k in env.posted) == sorted(ev.KINDS) and len({k for _, k in env.posted}) == 8
    assert t.state == "final" and t.complete_status == "partial"            # identity via DHCP is partial
    by = t.evidence
    assert by["identity"]["data"]["resolved_by"] == "dhcp" and by["identity"]["data"]["mac"] == "f0:18:98:aa:bb:01"
    assert by["identity"]["data"]["device_key"] and by["identity"]["data"]["zone"] == "hallb-row12"
    sec = by["security"]
    assert sec["status"] == "ok" and sec["data"]["events"][0]["count"] == 3 and sec["data"]["counts"]["deny"] == 3
    assert sec["data"]["events"][0]["zone_from"] == "Guest"
    for k in ("wifi", "wired", "flows", "wan", "baseline", "dns"):
        assert by[k]["status"] == "unavailable" and by[k]["data"] == {}
    assert t.diagnosis["stage"] == "final"
    assert env.corr.metrics()["correlations_per_hour"] == 1
    assert env.ring.count_kept() >= 1                                       # the lines cited by the evidence were attached


def test_a_second_tick_does_not_repost(env):
    env.add_test()
    env.corr.tick()
    n = len(env.posted)
    env.corr.tick()
    assert len(env.posted) == n == 8


def test_restart_idempotency_completed_tests_are_never_touched(tmp_path):
    e = Env(tmp_path)
    try:
        tid, t = e.add_test()
        e.corr.tick()
        assert len(e.posted) == 8
        e.corr.close()
        # a fresh runner process: new client, new correlator, same state db
        e.posted.clear()
        e.corr = e.build()
        e.corr.tick()
        assert e.posted == []
        # even if the collector still listed the test as pending (final flag lost), the local done table stops the re-post
        t.state = "submitted"
        e.corr.tick()
        assert e.posted == []
    finally:
        e.close()


def test_crash_between_evidence_and_complete_replaces_not_duplicates(tmp_path):
    e = Env(tmp_path)
    try:
        tid, t = e.add_test()
        c1 = e.corr
        c1.client.complete = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("killed"))
        c1.tick()
        assert t.state != "final" and len(e.posted) == 8
        assert not e.state.is_done(tid)
        c1.close()
        e.posted.clear()
        e.corr = e.build()                                   # restart
        e.corr.tick()
        assert t.state == "final" and len(t.evidence) == 8   # replaced per kind, never 16
        assert len(e.posted) == 8
    finally:
        e.close()


def test_unresolved_test_still_runs_connectors_and_yields_baseline(tmp_path):
    class Baseline(Connector):
        name, kinds = "baseline", ("baseline",)

        def collect(self, ctx):
            return [EvidenceResult("baseline", "exp", "ok", {"probe": "probe-a", "site": "hall-b", "distance": "same_site",
                                                              "at": ev._fmt(ctx.test.ended), "severity": "ok", "lines": []})]

    cfg = make_cfg()
    e = Env(tmp_path, cfg=cfg, connectors=[SyslogConnector(cfg), Baseline()])
    try:
        tid, t = e.add_test(ip="10.0.0.2")                      # a translated address: identity fails closed
        e.corr.tick()
        ident = t.evidence["identity"]["data"]
        assert ident["nat_suspected"] and ident["nat_reason"] == "translated_address" and ident["zone"] == "unresolved"
        assert "mac" not in ident
        assert t.evidence["baseline"]["status"] == "ok" and t.state == "final"
    finally:
        e.close()


def test_window_must_close_before_correlation(tmp_path):
    clock = [time.time()]
    e = Env(tmp_path, now_fn=lambda: clock[0])
    try:
        doc = st_result(1, now=clock[0], age_s=30)               # ended 10 s ago; window runs to ended + 120 s
        e.fake.app.store(doc, "spd-core", "hall-b")
        assert e.corr.tick() == 0 and e.posted == []
        clock[0] += 120 + READY_GRACE_S + 15
        assert e.corr.tick() == 1 and len(e.posted) == 8
    finally:
        e.close()


def test_collector_5xx_is_retried_with_backoff_then_succeeds(tmp_path):
    clock = [time.time()]
    e = Env(tmp_path, now_fn=lambda: clock[0])
    try:
        e.corr.close()
        e.corr = e.build(retries=0)
        e.add_test()
        e.corr.poll_once()
        e.fake.app.set_force(503, count=1)
        assert e.corr.process_ready() == 1 and not e.state.is_done(next(iter(e.fake.app.tests)))
        assert e.corr.process_ready() == 0                        # backing off
        clock[0] += 6
        assert e.corr.process_ready() == 1
        assert next(iter(e.fake.app.tests.values())).state == "final"
    finally:
        e.close()


def test_client_retries_idempotent_calls_and_honours_retry_after(tmp_path):
    sleeps: list[float] = []
    e = Env(tmp_path)
    try:
        e.fake.app.set_force(503, count=2, retry_after=3)
        c = CollectorClient(f"http://127.0.0.1:{e.fake.port}", None, e.token, retries=3, sleep=sleeps.append)
        items, _ = c.feed()
        assert items == [] and len(sleeps) == 2 and all(s >= 3 for s in sleeps)
        e.fake.app.set_force(503, count=10)
        c2 = CollectorClient(f"http://127.0.0.1:{e.fake.port}", None, e.token, retries=1, sleep=lambda _s: None)
        with pytest.raises(CollectorError) as ei:
            c2.feed()
        assert ei.value.retryable and ei.value.status == 503
    finally:
        e.close()


def test_wrong_or_foreign_token_is_an_auth_error_and_never_crashes_the_loop(tmp_path):
    e = Env(tmp_path, token=fst.fc.fixture_token("expr", "somebody-else"))
    try:
        e.add_test()
        assert e.corr.tick() == 0
        assert e.corr.auth_failed and e.posted == []
        with pytest.raises(AuthError):
            e.corr.client.feed()
        # a speedtest (exps_) token is unknown on the runner routes
        e.token = e.toks["speedtest"]["spd-core"]["token"]
        c = e.client()
        with pytest.raises(AuthError):
            c.feed()
    finally:
        e.close()


def test_connector_failure_and_timeout_mark_error_explicitly(tmp_path):
    class Boom(Connector):
        name, kinds = "mist", ("wifi", "wired")

        def collect(self, ctx):
            raise RuntimeError("mist down token=expr_secretsecretsecret")

    class Slow(Connector):
        name, kinds, timeout_s = "ec", ("flows", "wan"), 0.3

        def collect(self, ctx):
            time.sleep(2.0)
            return []

    cfg = make_cfg()
    e = Env(tmp_path, cfg=cfg, connectors=[SyslogConnector(cfg), Boom(), Slow()])
    try:
        tid, t = e.add_test()
        t0 = time.monotonic()
        e.corr.tick()
        assert time.monotonic() - t0 < 1.8
        for k in ("wifi", "wired", "flows", "wan"):
            assert t.evidence[k]["status"] == "error" and t.evidence[k]["data"] == {}
        assert t.evidence["security"]["status"] == "ok" and t.state == "final" and t.complete_status == "partial"
        pu = {p["source"]: p for p in e.corr.pullers()}
        assert pu["mist"]["errors_1h"] == 1 and pu["ec"]["errors_1h"] == 1 and pu["syslog"]["last_ok"] and pu["syslog"]["errors_1h"] == 0
    finally:
        e.close()


def test_schema_invalid_connector_output_becomes_an_error_placeholder(tmp_path):
    class Bad(Connector):
        name, kinds = "mist", ("wifi",)

        def collect(self, ctx):
            return [EvidenceResult("wifi", "mist", "ok", {"client": {"mac": "NOT-A-MAC", "guest_name": "Alice"}})]

    cfg = make_cfg()
    e = Env(tmp_path, cfg=cfg, connectors=[SyslogConnector(cfg), Bad()])
    try:
        tid, t = e.add_test()
        e.corr.tick()
        assert t.evidence["wifi"]["status"] == "error" and t.evidence["wifi"]["data"] == {}
        assert "Alice" not in json.dumps(t.evidence)
    finally:
        e.close()


def test_evidence_is_bounded_to_the_per_test_budget(tmp_path):
    flows = [{"application": f"app{i}", "ip1": "10.60.14.77", "ip2": "52.1.1.1", "bytes_total": 10 ** 6, "protocol": "tcp"} for i in range(50)]

    class Big(Connector):
        name, kinds = "ec", ("flows", "wan", "dns")

        def collect(self, ctx):
            wan = {"appliances": [{"ne_pk": "1.NE", "alarms": [{"sequence_id": i, "severity": "minor", "type": "t", "alarm_name": "x" * 120,
                                                                "description": "d" * 4000, "time_occurred_ms": 1, "service_affect": False,
                                                                "closed": False} for i in range(50)]}]}
            dns = {"queries": [{"ts": ev._fmt(ctx.test.ended), "qname": "q" * 250, "client_ip": ctx.test.client_ip} for _ in range(200)],
                   "failures": 0, "slow": 0}
            return [EvidenceResult("flows", "ec", "ok", {"flows": flows}), EvidenceResult("wan", "ec", "ok", wan), EvidenceResult("dns", "ec", "ok", dns)]

    cfg = make_cfg()
    e = Env(tmp_path, cfg=cfg, connectors=[Big()])
    try:
        tid, t = e.add_test()
        e.corr.tick()
        assert t.state == "final"
        assert sum(t.sizes.values()) <= ev.MAX_TOTAL_BYTES
    finally:
        e.close()


def test_fit_total_shrinks_largest_first_and_marks_partial():
    w = {"from": ev._fmt(NOW - 300), "to": ev._fmt(NOW)}
    big = ev.envelope("st_01M7R3X9G0RBGD0H1DC76AJK35", "dns", "syslog", "ok",
                      {"queries": [{"ts": ev._fmt(NOW), "qname": "q" * 250, "client_ip": "10.0.0.1"} for _ in range(200)], "failures": 0, "slow": 0},
                      w, NOW)
    small = ev.envelope("st_01M7R3X9G0RBGD0H1DC76AJK35", "baseline", "exp", "unavailable", {}, w, NOW)
    out = ev.fit_total([big, small], 20_000)
    assert sum(ev.size(d) for d in out) <= 20_000 and out[0]["status"] == "partial" and out[1] == small
    assert not ev.validation_errors(out[0])


def test_scrub_after_diagnosis_drops_the_clients_ring_rows(tmp_path):
    cfg = make_cfg(privacy={"scrub_after_diagnosis": True})
    e = Env(tmp_path, cfg=cfg)
    try:
        lines(e)
        lines(e, ip="10.60.14.99")
        e.add_test()
        e.corr.tick()
        assert e.ring.query("10.60.14.77", 0, time.time() + 10) == []
        assert e.ring.query("10.60.14.99", 0, time.time() + 10) != []
    finally:
        e.close()


def test_without_scrub_the_ring_rows_stay(env):
    lines(env)
    env.add_test()
    env.corr.tick()
    assert env.ring.query("10.60.14.77", 0, time.time() + 10)


def test_only_this_runners_site_is_fed(tmp_path):
    e = Env(tmp_path)
    try:
        doc = st_result(1, site="hall-c", server="spd-core")
        e.fake.app.store(doc, "spd-core", "hall-c")
        assert e.corr.tick() == 0
    finally:
        e.close()


def test_health_metrics_lag_and_per_hour(tmp_path):
    e = Env(tmp_path)
    try:
        for i in range(3):
            e.add_test(i + 1)
        e.corr.tick()
        m = e.corr.metrics()
        assert m["correlations_per_hour"] == 3 and 800 < m["evidence_lag_s_p95"] < 1000
        assert e.corr.feed_ok is not None and e.corr.feed_error is None
    finally:
        e.close()


def test_malformed_feed_items_are_skipped(tmp_path):
    e = Env(tmp_path)
    try:
        e.corr.client.feed = lambda **kw: ([{"id": "st_x", "client_ip": "not-an-ip", "started": "2026-01-01T00:00:00Z",
                                             "ended": "2026-01-01T00:00:10Z"}, {"id": "st_y"}], None)
        assert e.corr.poll_once() == 0
    finally:
        e.close()


def test_https_pinned_collector(tmp_path):
    ca, leaf = fake_ca.make_server_tls(tmp_path / "pki")
    fake = fst.start(tls=(leaf.cert_chain, leaf.key))
    try:
        pin = tlspin.fingerprint_of_pem_file(leaf.cert_chain)
        c = CollectorClient(f"https://127.0.0.1:{fake.port}", pin, fst.default_tokens()["runner"]["runner-core"]["token"])
        assert c.feed() == ([], None)
        bad = CollectorClient(f"https://127.0.0.1:{fake.port}", PIN, fst.default_tokens()["runner"]["runner-core"]["token"], retries=0)
        with pytest.raises(CollectorError):
            bad.feed()
    finally:
        fake.stop()


def test_client_refuses_non_loopback_http_and_unpinned_https():
    with pytest.raises(ValueError):
        CollectorClient("http://10.1.2.3:8443", None, "x")
    with pytest.raises(ValueError):
        CollectorClient("https://10.1.2.3:8443", None, "x")
    with pytest.raises(ValueError):
        CollectorClient("ftp://localhost", PIN, "x")

"""query_range: only exp_* metrics, query <= 2 KiB, range <= 30 d, step >= 10 s, <= 500 series, VM down -> 503."""
from __future__ import annotations

import json
import urllib.parse

import pytest
from colhelpers import check_openapi, https

from exp_collector import queryguard

ACCEPT = [
    "exp_gateway_rtt_ms",
    'exp_gateway_rtt_ms{probe="probe-a1",port=~"c0.*"}',
    'avg_over_time(exp_ping_rtt_ms{outcome="ok"}[5m])',
    'sum by (probe) (rate(exp_collector_ingest_records_total[1m]))',
    'sum(exp_ping_rtt_ms) by (probe, site)',
    'histogram_quantile(0.95, sum(rate(exp_app_total_ms_bucket[5m])) by (le))',
    'exp_a / on(probe) group_left(site) exp_b',
    'exp_a > bool 3',
    'exp_a or exp_b',
    'exp_a offset 5m',
    '{__name__="exp_ping_rtt_ms", probe="probe-a1"}',
    'label_replace(exp_a, "dst", "$1", "src", "(.*)")',
    'max_over_time(exp_a[1h:1m])',
    'exp_a * 1000 + 5',
    'quantile_over_time(0.9, exp_a[10m])',
    'exp_a and exp_b unless exp_c',
]
REFUSE = [
    ("up", "only exp_"),
    ('{__name__=~".*"}', "only exp_"),
    ('{__name__!="exp_a"}', "only exp_"),
    ('{__name__="up"}', "only exp_"),
    ('{__name__="exp_a" or job="x"}', "selector"),
    ('{job="x"}', "selector"),
    ('{probe="a"}', "selector"),
    ("process_cpu_seconds_total", "only exp_"),
    ("sum(up)", "only exp_"),
    ("exp_a or up", "only exp_"),
    ('exp_a or {job="x"}', "selector"),
    ("up == 1", "only exp_"),
    ('exp_a{__name__="up"}', "only exp_"),
    ('exp_a{__name__=~"up|exp_a"}', "only exp_"),
    ("WITH (x = up) x", "WITH"),
    ("with (x = up) x", "WITH"),
    ("exp_a # up", "comment"),
    ("sum(and)", "unexpected"),
    ("or", "unexpected"),
    ("by", "unexpected"),
    ("offset", "unexpected"),
    ("expー_a", "ASCII"),
    ("exp_a\\x20b", "character"),
    ("", "empty"),
    ("   ", "empty"),
    ('exp_a{', "unterminated"),
    ('"exp_a"', "only exp_"),                        # a bare string is no metric; harmless but refused? see below
    ("{'exp_a'}", "matcher"),
    ("exp_a[5m] ", "ok-placeholder"),
]
# a bare string literal and a range selector without a function are valid queries that read only exp_*; the
# guard need not refuse them. Keep the table honest: drop the two entries above that are not refusals.
REFUSE = [r for r in REFUSE if r[1] not in ("ok-placeholder",) and r[0] != '"exp_a"']


@pytest.mark.parametrize("q", ACCEPT)
def test_guard_accepts_exp_queries(q):
    queryguard.check_query(q)


@pytest.mark.parametrize(("q", "why"), REFUSE)
def test_guard_refuses_everything_else(q, why):
    with pytest.raises(queryguard.QueryRefused) as e:
        queryguard.check_query(q)
    assert str(e.value)                       # always a reason a human can read


def test_guard_refuses_oversize_and_control_characters():
    with pytest.raises(queryguard.QueryRefused):
        queryguard.check_query("exp_a" + " " * 3000)
    with pytest.raises(queryguard.QueryRefused):
        queryguard.check_query("exp_a\x00")
    with pytest.raises(queryguard.QueryRefused):
        queryguard.check_query("exp_a + (" * 5)


def dash(env):
    return {"Authorization": f"Bearer {env.dash_token}"}


def qr(port, env, query="exp_ping_rtt_ms", start="2026-11-18T10:00:00Z", end="2026-11-18T11:00:00Z", step="30s", **kw):
    q = {"query": query, "start": start, "end": end, "step": step}
    q.update(kw)
    return https(port, "GET", "/api/v1/query_range?" + urllib.parse.urlencode(q), headers=dash(env))


def err_code(r):
    assert r.status in (400, 422, 503), (r.status, r.body[:200])
    doc = r.json()
    check_openapi("collector", "/query_range", "get", r.status, doc)
    return doc["error"]["code"]


def test_valid_query_is_proxied_to_vm_and_matches_openapi(env, vm, port):
    vm.query_body = json.dumps({"status": "success", "data": {"resultType": "matrix", "result": [
        {"metric": {"__name__": "exp_ping_rtt_ms", "probe": "probe-a1"}, "values": [[1763460000, "12.5"]]}]}}).encode()
    r = qr(port, env)
    assert r.status == 200
    doc = r.json()
    check_openapi("collector", "/query_range", "get", 200, doc)
    assert doc["data"]["result"][0]["metric"]["probe"] == "probe-a1"
    sent = urllib.parse.parse_qs(urllib.parse.urlsplit(vm.queries[-1]).query)
    assert sent["query"] == ["exp_ping_rtt_ms"] and sent["step"] == ["30s"]
    assert sent["start"] == ["1794996000.000"] and sent["end"] == ["1794999600.000"]
    assert sent["timeout"] == ["10s"]


def test_step_forms_and_epoch_times_are_accepted(env, vm, port):
    assert qr(port, env, step="1m").status == 200
    assert qr(port, env, step="10").status == 200
    assert qr(port, env, start="1763460000", end="1763463600", step="1h").status == 200


@pytest.mark.parametrize("query", ["up", '{__name__=~".*"}', "sum(up)", "{job=\"x\"}", "exp_a or up"])
def test_non_exp_metrics_are_refused_and_never_reach_vm(env, vm, port, query):
    n = len(vm.queries)
    r = qr(port, env, query=query)
    assert r.status == 400 and err_code(r) == "invalid_query"
    assert len(vm.queries) == n


def test_oversize_query_is_refused(env, vm, port):
    r = qr(port, env, query="exp_a" + " " * 2100)
    assert r.status == 400 and err_code(r) == "invalid_query"
    r = qr(port, env, query="exp_ping_rtt_ms{probe=\"" + "a" * 2048 + "\"}")
    assert r.status == 400 and err_code(r) == "invalid_query"
    assert not vm.queries


def test_range_over_30_days_is_refused(env, vm, port):
    r = qr(port, env, start="2026-10-01T00:00:00Z", end="2026-11-18T00:00:00Z", step="1h")
    assert r.status == 400 and err_code(r) == "range_too_large"
    r = qr(port, env, start="2026-10-19T00:00:00Z", end="2026-11-18T00:00:00Z", step="1h")      # exactly 30 d
    assert r.status == 200
    r = qr(port, env, start="2026-10-18T23:59:59Z", end="2026-11-18T00:00:00Z", step="1h")
    assert r.status == 400 and err_code(r) == "range_too_large"
    assert len(vm.queries) == 1


@pytest.mark.parametrize("step", ["1s", "9s", "0", "0s", "9"])
def test_step_under_10_seconds_is_refused(env, vm, port, step):
    r = qr(port, env, step=step)
    assert r.status == 400 and err_code(r) == "step_too_small"
    assert not vm.queries


def test_too_many_points_per_series_is_refused(env, vm, port):
    r = qr(port, env, start="2026-11-01T00:00:00Z", end="2026-11-18T00:00:00Z", step="10s")
    assert r.status == 400 and err_code(r) == "step_too_small"


@pytest.mark.parametrize("params", [
    {"step": "fast"}, {"step": "-5s"}, {"start": "yesterday"}, {"end": "2026-11-18 11:00:00"},
    {"start": "2026-11-18T11:00:00Z", "end": "2026-11-18T10:00:00Z"}, {"query": ""}])
def test_malformed_parameters_are_400(env, vm, port, params):
    r = qr(port, env, **params)
    assert r.status == 400 and err_code(r) in ("invalid_request", "invalid_query")


def test_missing_parameters_are_400(env, port):
    for q in ("", "query=exp_a", "query=exp_a&start=1763460000&end=1763463600"):
        r = https(port, "GET", "/api/v1/query_range?" + q, headers=dash(env))
        assert r.status == 400 and err_code(r) == "invalid_request"


def test_more_than_500_series_is_refused_422(env, vm, port):
    series = [{"metric": {"__name__": "exp_a", "i": str(i)}, "values": [[1, "1"]]} for i in range(501)]
    vm.query_body = json.dumps({"status": "success", "data": {"resultType": "matrix", "result": series}}).encode()
    r = qr(port, env)
    assert r.status == 422 and err_code(r) == "too_many_series"
    vm.query_body = json.dumps({"status": "success", "data": {"resultType": "matrix", "result": series[:500]}}).encode()
    assert qr(port, env).status == 200


def test_vm_own_series_limit_is_mapped_to_422(env, vm, port):
    vm.query_status = 422
    vm.query_body = b'{"status":"error","error":"cannot select more than -search.maxSeries=500 series"}'
    r = qr(port, env)
    assert r.status == 422 and err_code(r) == "too_many_series"


def test_vm_rejecting_the_query_is_invalid_query(env, vm, port):
    vm.query_status = 400
    vm.query_body = b'{"status":"error","error":"parse error"}'
    r = qr(port, env)
    assert r.status == 400 and err_code(r) == "invalid_query"
    assert "parse error" not in r.body.decode()                    # VM's text is not echoed


def test_vm_down_is_503_with_retry_after_and_ingest_is_unaffected(env, vm, app, port):
    vm.stop()
    r = qr(port, env)
    assert r.status == 503 and err_code(r) == "vm_unavailable" and r.h("retry-after")
    from colhelpers import ingest, rec
    assert ingest(port, env.ingest_token, [rec()]).json()["accepted"] == 1


def test_vm_garbage_answer_is_503(env, vm, port):
    vm.query_body = b"<html>not json</html>"
    r = qr(port, env)
    assert r.status == 503 and err_code(r) == "vm_unavailable"


def test_query_range_needs_a_dashboard_token(env, port):
    r = https(port, "GET", "/api/v1/query_range?query=exp_a&start=1763460000&end=1763463600&step=30s")
    assert r.status == 401
    r = https(port, "GET", "/api/v1/query_range?query=exp_a&start=1763460000&end=1763463600&step=30s",
              headers={"Authorization": f"Bearer {env.ingest_token}"})
    assert r.status == 401

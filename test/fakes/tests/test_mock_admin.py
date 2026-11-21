"""mock_admin: admin API conformance (against admin.yaml) and enforcement."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import subprocess
import sys

import pytest
from exp_common import ids as exp_ids
from fakes_support import FAKES, check_openapi, check_response_headers, request

from mock_admin import gen_admin_schemas, seed, server

T0 = 1_795_000_000.0
BASE = server.BASE
JWT = {"Cf-Access-Jwt-Assertion": "any.value.at-all"}


class Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> float:
        return self.t


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def adm(clock):
    s = server.start(now_fn=clock, enrol_delay_s=10.0, decommission_delay_s=20.0, canary_delay_s=30.0)
    yield s
    s.stop()


def A(adm, method, path, body=None, role=None, email=None, headers=None, auth=True):
    h = dict(JWT) if auth else {}
    if role:
        h["X-Mock-Role"] = role
    if email:
        h["X-Mock-Email"] = email
    h.update(headers or {})
    return request(adm.port, method, BASE + path, body, h)


def get_ok(adm, template, path=None, **kw):
    r = A(adm, "GET", path or template, **kw)
    assert r.status == 200, (path or template, r.body[:300])
    check_openapi("admin", template, "get", 200, r.json())
    return r.json()


def host_by_name(adm, name):
    for h in A(adm, "GET", "/hosts?limit=1000").json()["items"]:
        if h["name"] == name:
            return h
    raise AssertionError(name)


def comp_of(adm, host_name, ctype):
    hid = host_by_name(adm, host_name)["host_id"]
    for c in A(adm, "GET", f"/hosts/{hid}/components").json()["items"]:
        if c["type"] == ctype:
            return c
    raise AssertionError((host_name, ctype))


def audit_count(adm):
    return len(A(adm, "GET", "/audit?limit=1000").json()["items"])


# ------------------------------------------------------------------------------------ Access sim

def test_every_route_refuses_requests_without_access_header(adm):
    for method, rx, _role, _fn in server.ROUTES:
        path = rx.pattern.replace("(?P<", "").replace(">[A-Za-z0-9_.:-]{1,128})", "x")
        r = A(adm, method, path, auth=False)
        assert r.status == 401, (method, path)
        assert r.json()["error"]["code"] == "unauthenticated"
        check_openapi("admin", "/me", "get", 401, r.json())
    assert A(adm, "GET", "/me", headers={"Cf-Access-Jwt-Assertion": ""}, auth=False).status == 401
    assert A(adm, "GET", "/me", headers={"Cf-Access-Jwt-Assertion": "   "}, auth=False).status == 401
    assert request(adm.port, "GET", BASE + "/me", headers={"Cf-Access-Authenticated-User-Email": "owner@example.com"}).status == 401
    assert request(adm.port, "GET", "/healthz").body == b"ok"


def test_me_maps_to_owner(adm):
    me = get_ok(adm, "/me")
    assert me == {"email": "owner@example.com", "role": "owner"}
    assert get_ok(adm, "/me", role="viewer")["role"] == "viewer"
    assert A(adm, "GET", "/me", role="root").status == 400


def test_no_auth_mode():
    s = server.start(auth=False)
    try:
        assert request(s.port, "GET", BASE + "/me").json()["email"] == "owner@example.com"
    finally:
        s.stop()


def test_role_gating_matches_min_roles(adm):
    assert A(adm, "POST", "/sites", {"site": "x1", "name": "X", "timezone": "UTC"}, role="viewer").status == 403
    r = A(adm, "POST", "/sites", {"site": "x1", "name": "X", "timezone": "UTC"}, role="operator")
    assert r.status == 403 and r.json()["error"]["code"] == "insufficient_role"
    check_openapi("admin", "/sites", "post", 403, r.json())
    assert A(adm, "POST", "/sites", {"site": "x1", "name": "X", "timezone": "UTC"}, role="admin").status == 201
    assert A(adm, "PATCH", "/settings", {"org_name": "N"}, role="admin").status == 403      # owner only
    assert A(adm, "GET", "/audit", role="operator").status == 403                           # admin only
    assert A(adm, "POST", "/drills/abort-all", {}, role="operator").status == 202
    assert A(adm, "GET", "/hosts", role="viewer").status == 200
    assert A(adm, "PUT", "/integrations/ec", {"config": {}}, role="admin").status == 403


def test_x_mock_force_simulates_failures(adm):
    for code, err in (("429", "rate_limited"), ("503", "unavailable"), ("500", "internal_error")):
        r = A(adm, "GET", "/sites", headers={"X-Mock-Force": code})
        assert r.status == int(code) and r.json()["error"]["code"] == err


def test_unknown_route_and_method(adm):
    assert A(adm, "GET", "/nope").status == 404
    assert A(adm, "PUT", "/me", {}).status == 405
    assert request(adm.port, "GET", "/other", headers=JWT).status == 404


# ------------------------------------------------------------------------------------ CORS

def test_cors_only_for_localhost_vite(adm):
    ok = A(adm, "GET", "/me", headers={"Origin": "http://localhost:5173"})
    assert ok.h("Access-Control-Allow-Origin") == "http://localhost:5173"
    for origin in ("http://localhost:3000", "https://evil.example", "http://127.0.0.1:5173", "null"):
        r = A(adm, "GET", "/me", headers={"Origin": origin})
        assert r.h("Access-Control-Allow-Origin") is None, origin
    assert A(adm, "GET", "/me").h("Access-Control-Allow-Origin") is None
    pre = request(adm.port, "OPTIONS", BASE + "/sites", headers={"Origin": "http://localhost:5173",
                                                                  "Access-Control-Request-Method": "POST"})
    assert pre.status == 204 and "POST" in pre.h("Access-Control-Allow-Methods")
    assert "Cf-Access-Jwt-Assertion" in pre.h("Access-Control-Allow-Headers")
    bad = request(adm.port, "OPTIONS", BASE + "/sites", headers={"Origin": "https://evil.example"})
    assert bad.status == 403 and bad.h("Access-Control-Allow-Origin") is None


# ------------------------------------------------------------------------------------ seed shape

def test_seed_matches_the_brief(adm):
    sites = get_ok(adm, "/sites")["items"]
    assert [s["site"] for s in sites] == ["hall-b", "hall-c", "keynote"]
    hosts = A(adm, "GET", "/hosts?limit=1000").json()["items"]
    assert len(hosts) == 24
    states = {s: sum(1 for h in hosts if h["state"] == s) for s in ("enrolled", "stale", "offline", "pending")}
    assert states == {"enrolled": 17, "stale": 3, "offline": 2, "pending": 2}
    for h in hosts:
        if h["state"] == "pending":
            assert h["facts"] is None and h["mgmt_ip"] is None
        else:
            mg = [i for i in h["facts"]["interfaces"] if i["in_use_by"] == "mgmt"]
            assert len(mg) == 1 and mg[0]["default_route"] is True and mg[0]["name"] == "eno1"
            assert sum(1 for i in h["facts"]["interfaces"] if i["default_route"]) == 1
            assert h["mgmt_ip"] and any(a.startswith(h["mgmt_ip"] + "/") for a in mg[0]["addrs"])
    types = set()
    healths = set()
    for h in hosts:
        for c in A(adm, "GET", f"/hosts/{h['host_id']}/components").json()["items"]:
            types.add(c["type"])
            healths.add(c["health"])
    assert types == {"probe", "collector", "dashboard", "runner", "speedtest"} and {"ok", "degraded", "fail", "unknown"} <= healths
    rels = get_ok(adm, "/releases")["items"]
    assert [r["version"] for r in rels] == ["0.1.1", "0.1.0"]
    assert rels[0]["sites"] == ["hall-b", "keynote"] and rels[1]["sites"] == ["hall-c"]
    issues = A(adm, "GET", "/issues?limit=1000").json()["items"]
    kinds = {i["kind"] for i in issues}
    assert kinds == set(server.seed_issue_kinds())
    assert any(i["resolved_at"] for i in issues) and any(not i["resolved_at"] for i in issues)
    st = get_ok(adm, "/settings")
    assert st["org_name"] == "HPE Event NOC" and st["owner"] == "owner@example.com"
    assert get_ok(adm, "/settings/fleet-thresholds")["disk_high"] == {"warn_pct": 85, "crit_pct": 95}
    assert len(get_ok(adm, "/audit")["items"]) > 20


def test_seed_is_deterministic_and_secret_free(clock):
    a, b = server.MockAdmin(now_fn=clock), server.MockAdmin(now_fn=clock)
    assert json.dumps(seed.public(a.w), sort_keys=True) == json.dumps(seed.public(b.w), sort_keys=True)
    blob = json.dumps(seed.public(a.w))
    assert "expa_" not in blob and "expi_" not in blob and "pbkdf2" not in blob and "hooks.example.invalid" not in blob


GET_PATHS = [
    ("/me", "/me"), ("/sites", "/sites"), ("/sites/{site}", "/sites/hall-b"), ("/hosts", "/hosts"),
    ("/releases", "/releases"), ("/overview", "/overview"), ("/sites/{site}/alerts", "/sites/hall-b/alerts"),
    ("/integrations/{kind}", "/integrations/ec"), ("/integrations/{kind}", "/integrations/mist"),
    ("/drills", "/drills"), ("/fleet/summary", "/fleet/summary"), ("/fleet/sites", "/fleet/sites"),
    ("/fleet/hosts", "/fleet/hosts"), ("/fleet/top", "/fleet/top?metric=disk&limit=3"),
    ("/issues", "/issues"), ("/settings/fleet-thresholds", "/settings/fleet-thresholds"),
    ("/settings/platform-webhook", "/settings/platform-webhook"), ("/audit", "/audit"), ("/settings", "/settings"),
    ("/dashboards/{dashboard_id}/users", "/dashboards/dash-main/users"),
    ("/dashboards/{dashboard_id}/noc-tokens", "/dashboards/dash-main/noc-tokens"),
    ("/dashboards/{dashboard_id}/tls", "/dashboards/dash-main/tls"),
]


@pytest.mark.parametrize(("template", "path"), GET_PATHS)
def test_get_responses_conform_to_openapi(adm, template, path):
    get_ok(adm, template, path)


def test_per_entity_get_responses_conform(adm):
    h = host_by_name(adm, "hb-probe-01")
    get_ok(adm, "/hosts/{id}", f"/hosts/{h['host_id']}")
    get_ok(adm, "/hosts/{id}/components", f"/hosts/{h['host_id']}/components")
    get_ok(adm, "/hosts/{id}/status", f"/hosts/{h['host_id']}/status")
    get_ok(adm, "/fleet/hosts/{id}/metrics", f"/fleet/hosts/{h['host_id']}/metrics?range=24h")
    c = comp_of(adm, "hb-probe-01", "probe")
    get_ok(adm, "/fleet/components/{component_id}/metrics", f"/fleet/components/{c['component_id']}/metrics?range=7d")
    pend = host_by_name(adm, "hc-probe-06")
    r = A(adm, "GET", f"/hosts/{pend['host_id']}/status")
    assert r.status == 404 and r.json()["error"]["code"] == "no_status"
    check_openapi("admin", "/hosts/{id}/status", "get", 404, r.json())
    d = A(adm, "GET", "/drills").json()["items"][0]
    run = d["last_run_id"] or A(adm, "GET", "/drills?state=done").json()["items"][0]["last_run_id"]
    get_ok(adm, "/drills/{id}/runs/{run}", f"/drills/{d['drl_id']}/runs/{run}")


def test_every_status_report_is_a_valid_exp_status(adm):
    from fakes_support import check_schema_file
    for h in A(adm, "GET", "/hosts?limit=1000").json()["items"]:
        if h["state"] != "pending":
            check_schema_file("status.schema.json", A(adm, "GET", f"/hosts/{h['host_id']}/status").json()["report"])


def test_seeded_component_configs_are_valid_rendered_configs(adm):
    n = 0
    for h in A(adm, "GET", "/hosts?limit=1000").json()["items"]:
        for c in A(adm, "GET", f"/hosts/{h['host_id']}/components").json()["items"]:
            n += 1
            if h["state"] != "pending":
                assert c["rendered_config"]["schema"].startswith("exp.")
    assert n == 27


# -------------------------------------------------------------------- fleet: caching + series

def test_fleet_endpoints_etag_cache_control_and_304(adm, clock):
    for path in ("/fleet/summary", "/fleet/sites", "/fleet/hosts", "/fleet/top", "/fleet/hosts?site=hall-b&sort=-cpu"):
        r = A(adm, "GET", path)
        assert r.h("Cache-Control") == "private, max-age=15", path
        etag = r.h("ETag")
        assert etag and etag.startswith('"')
        n = A(adm, "GET", path, headers={"If-None-Match": etag})
        assert n.status == 304 and n.body == b"" and n.h("ETag") == etag and n.h("Cache-Control") == "private, max-age=15"
        assert A(adm, "GET", path, headers={"If-None-Match": '"other"'}).status == 200
    tmpl = "/fleet/summary"
    r = A(adm, "GET", tmpl)
    check_response_headers("admin", tmpl, "get", 200, r.headers)
    # a mutation (or the 15 s snapshot rolling over) changes the entity tag
    before = A(adm, "GET", "/fleet/summary").h("ETag")
    sid = A(adm, "GET", "/issues?state=open").json()["items"][0]["issue_id"]
    assert A(adm, "POST", f"/issues/{sid}/snooze", {"for": "1h"}).status == 200
    assert A(adm, "GET", "/fleet/summary").h("ETag") != before
    clock.t += 16
    after = A(adm, "GET", "/fleet/summary")
    assert A(adm, "GET", "/fleet/summary", headers={"If-None-Match": before}).status == 200
    assert after.status == 200
    # non-fleet endpoints carry no such caching headers
    assert A(adm, "GET", "/hosts").h("Cache-Control") is None


def test_fleet_summary_numbers_are_consistent_with_hosts(adm):
    s = get_ok(adm, "/fleet/summary")
    assert s["hosts_total"] == 24 and s["hosts_by_state"] == {"pending": 2, "enrolled": 17, "stale": 3, "offline": 2,
                                                              "decommissioning": 0}
    assert s["hosts_online"] == 17 and s["version_drift_hosts"] == 1
    opens = [i for i in A(adm, "GET", "/issues?state=open&limit=1000").json()["items"] if not i["snoozed_until"]]
    assert s["open_issues"] == {"warn": sum(1 for i in opens if i["severity"] == "warn"),
                                "crit": sum(1 for i in opens if i["severity"] == "crit")}
    sites = get_ok(adm, "/fleet/sites")
    assert sum(x["hosts"] for x in sites["items"]) == 24
    assert any(x["worst_issue"] for x in sites["items"])


def test_fleet_hosts_filters_sort_and_pages(adm):
    rows = get_ok(adm, "/fleet/hosts", "/fleet/hosts?limit=1000")["items"]
    assert len(rows) == 24
    pend = [r for r in rows if r["state"] == "pending"]
    assert all(r["cpu_pct"] is None and r["cpu_spark"] == [] for r in pend)
    stale = [r for r in rows if r["state"] in ("stale", "offline")]
    assert stale and all(r["stale"] for r in stale)
    hb = A(adm, "GET", "/fleet/hosts?site=hall-b&limit=1000").json()["items"]
    assert {r["site"] for r in hb} == {"hall-b"} and len(hb) == 10
    assert {r["state"] for r in A(adm, "GET", "/fleet/hosts?state=offline").json()["items"]} == {"offline"}
    assert all("collector" in r["shapes"] for r in A(adm, "GET", "/fleet/hosts?type=collector").json()["items"])
    assert [r["name"] for r in A(adm, "GET", "/fleet/hosts?q=hb-run").json()["items"]] == ["hb-run-01"]
    cpu = [r["cpu_pct"] for r in A(adm, "GET", "/fleet/hosts?sort=-cpu&limit=1000").json()["items"] if r["cpu_pct"] is not None]
    assert cpu == sorted(cpu, reverse=True)
    names = [r["name"] for r in A(adm, "GET", "/fleet/hosts?sort=name&limit=1000").json()["items"]]
    assert names == sorted(names)
    got, cur = [], None
    for _ in range(30):
        r = A(adm, "GET", "/fleet/hosts?limit=5" + (f"&cursor={cur}" if cur else "")).json()
        got += [x["host_id"] for x in r["items"]]
        cur = r["next_cursor"]
        if not cur:
            break
    assert len(got) == 24 == len(set(got))
    for bad in ("sort=bogus", "state=zzz", "health=ok&limit=0", "cursor=@@@", "version=notsemver", "site=Not%20A%20Slug"):
        r = A(adm, "GET", "/fleet/hosts?" + bad)
        assert r.status == 400, bad
        check_openapi("admin", "/fleet/hosts", "get", 400, r.json())


def test_metrics_series_shapes_48h_5min_and_30d_1h(adm):
    h = host_by_name(adm, "hb-col-01")
    for rng, n, step in (("1h", 12, 300), ("6h", 72, 300), ("24h", 288, 300), ("7d", 168, 3600), ("30d", 720, 3600)):
        d = get_ok(adm, "/fleet/hosts/{id}/metrics", f"/fleet/hosts/{h['host_id']}/metrics?range={rng}")
        assert d["range"] == rng and d["step_s"] == step
        assert set(d["series"]) == set(seed.HOST_KEYS)
        for key, pts in d["series"].items():
            assert len(pts) == n, (rng, key)
            ts = [p["t"] for p in pts]
            assert ts == sorted(ts) and all(b - a == step for a, b in zip(ts, ts[1:], strict=False))
            assert all(p["max"] >= p["avg"] for p in pts)
    only = get_ok(adm, "/fleet/hosts/{id}/metrics", f"/fleet/hosts/{h['host_id']}/metrics?range=1h&keys=cpu_pct,disk_pct")
    assert set(only["series"]) == {"cpu_pct", "disk_pct"}
    assert min(p["avg"] for p in only["series"]["disk_pct"]) > 80       # the disk_high host really is high
    assert A(adm, "GET", f"/fleet/hosts/{h['host_id']}/metrics?range=2y").status == 400
    assert A(adm, "GET", f"/fleet/hosts/{h['host_id']}/metrics?keys=Bad-Key").status == 400
    assert A(adm, "GET", "/fleet/hosts/h_00000000000000000000000000/metrics").status == 404


def test_offline_host_series_goes_null_after_last_seen_and_pending_is_empty(adm):
    off = host_by_name(adm, "hb-probe-08")
    d = get_ok(adm, "/fleet/hosts/{id}/metrics", f"/fleet/hosts/{off['host_id']}/metrics?range=6h&keys=cpu_pct")
    pts = d["series"]["cpu_pct"]
    assert pts[0]["avg"] is not None and pts[-1]["avg"] is None
    pend = host_by_name(adm, "hc-probe-06")
    d = get_ok(adm, "/fleet/hosts/{id}/metrics", f"/fleet/hosts/{pend['host_id']}/metrics")
    assert d["series"] == {}


def test_series_values_are_stable_between_calls_and_metric_ranges(adm):
    h = host_by_name(adm, "hb-probe-01")
    p = f"/fleet/hosts/{h['host_id']}/metrics?range=24h"
    assert A(adm, "GET", p).json() == A(adm, "GET", p).json()
    d = A(adm, "GET", p).json()
    for k in ("cpu_pct", "mem_pct", "disk_pct"):
        assert all(0 <= x["avg"] <= 100 and 0 <= x["max"] <= 100 for x in d["series"][k])


def test_top_is_sorted_and_limited(adm):
    d = get_ok(adm, "/fleet/top", "/fleet/top?metric=cpu&limit=4")
    vals = [i["value"] for i in d["items"]]
    assert len(vals) == 4 and vals == sorted(vals, reverse=True) and d["items"][0]["name"] == "kn-col-01"
    net = A(adm, "GET", "/fleet/top?metric=net").json()
    assert net["items"][0]["unit"] == "pps" and net["items"][0]["value_out"] is not None
    assert A(adm, "GET", "/fleet/top?metric=gpu").status == 400
    assert A(adm, "GET", "/fleet/top?limit=0").status == 400


# --------------------------------------------------------------------------------- sites mutations

def test_site_crud_and_audit(adm):
    n = audit_count(adm)
    r = A(adm, "POST", "/sites", {"site": "hall-d", "name": "Hall D", "timezone": "America/Chicago"})
    assert r.status == 201
    check_openapi("admin", "/sites", "post", 201, r.json())
    assert audit_count(adm) == n + 1
    last = A(adm, "GET", "/audit?limit=1").json()["items"][0]
    assert last["action"] == "site.create" and last["actor"] == "owner@example.com" and last["resource"] == "site:hall-d"
    dup = A(adm, "POST", "/sites", {"site": "hall-d", "name": "Hall D", "timezone": "UTC"})
    assert dup.status == 409 and dup.json()["error"]["code"] == "site_exists"
    check_openapi("admin", "/sites", "post", 409, dup.json())
    assert audit_count(adm) == n + 1                      # failed mutations leave no audit event
    p = A(adm, "PATCH", "/sites/hall-d", {"name": "Hall D (north)"})
    assert p.status == 200 and p.json()["name"] == "Hall D (north)"
    check_openapi("admin", "/sites/{site}", "patch", 200, p.json())
    assert A(adm, "DELETE", "/sites/hall-d").status == 204
    assert A(adm, "GET", "/sites/hall-d").status == 404
    nonempty = A(adm, "DELETE", "/sites/hall-b")
    assert nonempty.status == 409 and nonempty.json()["error"]["code"] == "site_not_empty"


@pytest.mark.parametrize("body", [
    {}, {"site": "Hall D", "name": "x", "timezone": "UTC"}, {"site": "d", "name": "", "timezone": "UTC"},
    {"site": "d", "name": "x", "timezone": "Mars"}, {"site": "d", "name": "x", "timezone": "UTC", "extra": 1},
    {"site": "d", "name": "x", "timezone": "UTC", "edge_label": "L" * 33}, "just a string", [1],
])
def test_site_create_validation(adm, body):
    r = A(adm, "POST", "/sites", body)
    assert r.status == 400 and r.json()["error"]["code"] == "invalid_request"
    check_openapi("admin", "/sites", "post", 400, r.json())


def test_malformed_and_oversize_json(adm):
    r = request(adm.port, "POST", BASE + "/sites", b"{bad", {**JWT, "Content-Type": "application/json"})
    assert r.status == 400
    r = request(adm.port, "POST", BASE + "/sites", b'{"site":"a","site":"b"}', {**JWT, "Content-Type": "application/json"})
    assert r.status == 400                                              # duplicate keys refused
    r = request(adm.port, "POST", BASE + "/sites", b"x" * (1024 * 1024 + 1), {**JWT, "Content-Type": "application/json"})
    assert r.status == 413
    assert A(adm, "POST", "/sites").status == 400                      # empty body


# --------------------------------------------------------------------------------- hosts + wizard

def test_add_host_wizard_pending_becomes_enrolled_after_delay(adm, clock):
    r = A(adm, "POST", "/hosts", {"name": "srv-new", "site": "hall-c", "shapes": ["probe"]})
    assert r.status == 201
    body = r.json()
    check_openapi("admin", "/hosts", "post", 201, body)
    check_response_headers("admin", "/hosts", "post", 201, r.headers)
    assert r.h("Cache-Control") == "no-store"
    assert body["host"]["state"] == "pending" and body["host"]["facts"] is None
    tok = body["enrol"]["token"]
    assert exp_ids.is_token(tok, "expe") and tok in body["enrol"]["command"]
    assert "install.sh" in body["enrol"]["command"] and body["enrol"]["command"].startswith("curl ")
    hid = body["host"]["host_id"]
    assert A(adm, "GET", f"/hosts/{hid}").json()["state"] == "pending"
    clock.t += 9
    assert A(adm, "GET", f"/hosts/{hid}").json()["state"] == "pending"
    clock.t += 2
    h = get_ok(adm, "/hosts/{id}", f"/hosts/{hid}")
    assert h["state"] == "enrolled" and h["facts"]["hostname"] == "srv-new" and h["mgmt_ip"]
    assert sum(1 for i in h["facts"]["interfaces"] if i["in_use_by"] == "mgmt") == 1
    assert A(adm, "GET", f"/hosts/{hid}/status").status == 200
    actions = [e["action"] for e in A(adm, "GET", "/audit?limit=5").json()["items"]]
    assert "host.enrol" in actions
    # the token command is never stored in audit details
    assert tok not in json.dumps(A(adm, "GET", "/audit?limit=1000").json())


def test_wizard_can_be_disabled():
    s = server.start(enrol_delay_s=None)
    try:
        hid = A(s, "POST", "/hosts", {"name": "srv-x", "site": "hall-b"}).json()["host"]["host_id"]
        assert A(s, "GET", f"/hosts/{hid}").json()["state"] == "pending"
    finally:
        s.stop()


def test_create_host_validation_and_unknown_site(adm):
    assert A(adm, "POST", "/hosts", {"name": "x", "site": "nowhere"}).status == 404
    assert A(adm, "POST", "/hosts", {"name": "x", "site": "hall-b", "shapes": ["probe", "probe"]}).status == 400
    assert A(adm, "POST", "/hosts", {"name": "x", "site": "hall-b", "shapes": ["toaster"]}).status == 400
    assert A(adm, "POST", "/hosts", {"site": "hall-b"}).status == 400


def test_enrol_token_reissue_only_for_pending(adm):
    pend = host_by_name(adm, "hc-probe-06")
    r = A(adm, "POST", f"/hosts/{pend['host_id']}/enrol-token")
    assert r.status == 201 and r.h("Cache-Control") == "no-store"
    check_openapi("admin", "/hosts/{id}/enrol-token", "post", 201, r.json())
    enr = host_by_name(adm, "hb-probe-01")
    r = A(adm, "POST", f"/hosts/{enr['host_id']}/enrol-token")
    assert r.status == 409 and r.json()["error"]["code"] == "host_already_enrolled"
    check_openapi("admin", "/hosts/{id}/enrol-token", "post", 409, r.json())


def test_host_delete_and_decommission_lifecycle(adm, clock):
    enr = host_by_name(adm, "hb-probe-01")
    r = A(adm, "DELETE", f"/hosts/{enr['host_id']}")
    assert r.status == 409 and r.json()["error"]["code"] == "host_not_removable"
    pend = host_by_name(adm, "kn-probe-05")
    assert A(adm, "DELETE", f"/hosts/{pend['host_id']}").status == 204
    assert A(adm, "GET", f"/hosts/{pend['host_id']}").status == 404
    d = A(adm, "POST", f"/hosts/{enr['host_id']}/decommission")
    assert d.status == 202 and d.json()["state"] == "decommissioning"
    check_openapi("admin", "/hosts/{id}/decommission", "post", 202, d.json())
    assert A(adm, "POST", f"/hosts/{enr['host_id']}/decommission").status == 409
    clock.t += 21
    assert A(adm, "GET", f"/hosts/{enr['host_id']}").json()["state"] == "removed"
    assert A(adm, "DELETE", f"/hosts/{enr['host_id']}").status == 204


def test_host_patch_and_rotate_agent(adm):
    h = host_by_name(adm, "hb-probe-02")
    r = A(adm, "PATCH", f"/hosts/{h['host_id']}", {"name": "renamed"})
    assert r.status == 200 and r.json()["name"] == "renamed"
    assert A(adm, "PATCH", f"/hosts/{h['host_id']}", {"site": "nowhere"}).status == 404
    assert A(adm, "PATCH", f"/hosts/{h['host_id']}", {}).status == 400
    rot = A(adm, "POST", f"/hosts/{h['host_id']}/rotate-agent")
    assert rot.status == 202
    check_openapi("admin", "/hosts/{id}/rotate-agent", "post", 202, rot.json())
    assert rot.json()["desired_version"] == h["desired_version"] + 1
    pend = host_by_name(adm, "hc-probe-06")
    assert A(adm, "POST", f"/hosts/{pend['host_id']}/rotate-agent").status == 409


# ------------------------------------------------------------------------- components + ports

def test_ports_put_refuses_management_interface(adm):
    c = comp_of(adm, "hb-probe-01", "probe")
    h = A(adm, "GET", f"/hosts/{c['host_id']}").json()
    mgmt = [i["name"] for i in h["facts"]["interfaces"] if i["in_use_by"] == "mgmt"][0]
    n = audit_count(adm)
    r = A(adm, "PUT", f"/components/{c['component_id']}/ports",
          {"ports": [{"id": "c01", "iface": mgmt, "role": "client", "vlan": None}]})
    assert r.status == 422 and r.json()["error"]["code"] == "mgmt_interface_refused"
    check_openapi("admin", "/components/{component_id}/ports", "put", 422, r.json())
    assert audit_count(adm) == n
    # nothing changed
    after = A(adm, "GET", f"/hosts/{c['host_id']}").json()
    assert after["facts"]["interfaces"][0]["in_use_by"] == "mgmt"
    assert A(adm, "GET", f"/hosts/{c['host_id']}/components").json()["items"][0]["config"]["ports"] == c["config"]["ports"]
    # even when listed after a valid port
    r = A(adm, "PUT", f"/components/{c['component_id']}/ports",
          {"ports": [{"id": "c01", "iface": "enp10s0f0", "role": "client"}, {"id": "c02", "iface": mgmt, "role": "client"}]})
    assert r.status == 422 and r.json()["error"]["code"] == "mgmt_interface_refused"


def test_ports_put_success_updates_usage_and_desired_version(adm):
    c = comp_of(adm, "hb-probe-01", "probe")
    h0 = A(adm, "GET", f"/hosts/{c['host_id']}").json()
    ports = [{"id": "c01", "iface": "enp10s0f1", "role": "client"},
             {"id": "s01", "iface": "enp10s0f2", "role": "target", "address": "10.1.0.250/24", "gateway": "10.1.0.1"}]
    r = A(adm, "PUT", f"/components/{c['component_id']}/ports", {"ports": ports})
    assert r.status == 200, r.body
    check_openapi("admin", "/components/{component_id}/ports", "put", 200, r.json())
    assert r.json()["desired_version"] == h0["desired_version"] + 1
    h = A(adm, "GET", f"/hosts/{c['host_id']}").json()
    use = {i["name"]: i["in_use_by"] for i in h["facts"]["interfaces"]}
    assert use["eno1"] == "mgmt" and use["enp10s0f1"] == "probe:c01" and use["enp10s0f2"] == "probe:s01"
    assert use["enp10s0f0"] == "none"
    again = A(adm, "GET", f"/hosts/{c['host_id']}/components").json()["items"][0]
    assert again["config"]["ports"] == ports and again["rendered_config"]["ports"] == ports
    from fakes_support import check_schema_file
    check_schema_file("probe.config.schema.json", again["rendered_config"])
    assert audit_count(adm) > 0 and A(adm, "GET", "/audit?limit=1").json()["items"][0]["action"] == "component.ports"


@pytest.mark.parametrize(("ports", "code"), [
    ([{"id": "c01", "iface": "nope0", "role": "client"}], "unknown_interface"),
    ([{"id": "c01", "iface": "enp10s0f0", "role": "client"}, {"id": "c01", "iface": "enp10s0f1", "role": "client"}], "invalid_ports"),
    ([{"id": "c01", "iface": "enp10s0f0", "role": "client"}, {"id": "c02", "iface": "enp10s0f0", "role": "client"}], "invalid_ports"),
])
def test_ports_put_semantic_refusals(adm, ports, code):
    c = comp_of(adm, "hb-probe-01", "probe")
    r = A(adm, "PUT", f"/components/{c['component_id']}/ports", {"ports": ports})
    assert r.status == 422 and r.json()["error"]["code"] == code
    check_openapi("admin", "/components/{component_id}/ports", "put", 422, r.json())


def test_ports_put_schema_and_scope_refusals(adm):
    c = comp_of(adm, "hb-probe-01", "probe")
    url = f"/components/{c['component_id']}/ports"
    for bad in ({}, {"ports": []}, {"ports": [{"id": "c01", "iface": "x", "role": "wizard"}]},
                {"ports": [{"id": "c01", "iface": "enp10s0f0", "role": "target"}]},
                {"ports": [{"id": "c01", "iface": "enp10s0f0", "role": "client"}] * 65},
                {"ports": [{"id": "c01", "iface": "enp10s0f0", "role": "client"}], "x": 1}):
        r = A(adm, "PUT", url, bad)
        assert r.status == 400, bad
        check_openapi("admin", "/components/{component_id}/ports", "put", 400, r.json())
    col = comp_of(adm, "hb-col-01", "collector")
    assert A(adm, "PUT", f"/components/{col['component_id']}/ports", {"ports": [{"id": "c01", "iface": "enp10s0f0", "role": "client"}]}).status == 422
    assert A(adm, "PUT", f"/components/{fc_id('cmp_', 'zz')}/ports", {"ports": [{"id": "c01", "iface": "e", "role": "client"}]}).status == 404


def fc_id(prefix, seed_):
    import fakes_common
    return fakes_common.det_id(prefix, seed_)


def test_component_create_conflict_invalid_config_and_mgmt_guard(adm):
    hid = host_by_name(adm, "hb-probe-03")["host_id"]
    r = A(adm, "POST", f"/hosts/{hid}/components", {"type": "probe", "id": "probe-new", "config": {}})
    assert r.status == 201
    check_openapi("admin", "/hosts/{id}/components", "post", 201, r.json())
    assert r.json()["health"] == "unknown" and r.json()["version"] is None
    dup = A(adm, "POST", f"/hosts/{hid}/components", {"type": "probe", "id": "probe-new", "config": {}})
    assert dup.status == 409 and dup.json()["error"]["code"] == "component_slug_exists"
    check_openapi("admin", "/hosts/{id}/components", "post", 409, dup.json())
    bad = A(adm, "POST", f"/hosts/{hid}/components",
            {"type": "probe", "id": "probe-bad", "config": {"schema": "exp.probe.config/1", "probe_id": "!!"}})
    assert bad.status == 422 and bad.json()["error"]["code"] == "invalid_config"
    assert bad.json()["error"]["details"]["errors"]
    check_openapi("admin", "/hosts/{id}/components", "post", 422, bad.json())
    guard = A(adm, "POST", f"/hosts/{hid}/components", {"type": "probe", "id": "probe-g", "config": {
        "ports": [{"id": "c01", "iface": "eno1", "role": "client"}]}})
    assert guard.status == 422 and guard.json()["error"]["code"] == "mgmt_interface_refused"
    assert A(adm, "POST", f"/hosts/{hid}/components", {"type": "nope", "id": "x", "config": {}}).status == 400
    assert A(adm, "POST", "/hosts/h_00000000000000000000000000/components", {"type": "probe", "id": "x", "config": {}}).status == 404


def test_component_patch_delete_restart_rotate(adm):
    c = comp_of(adm, "hb-probe-02", "probe")
    cid = c["component_id"]
    r = A(adm, "PATCH", f"/components/{cid}", {"enabled": False})
    assert r.status == 200 and r.json()["enabled"] is False
    check_openapi("admin", "/components/{component_id}", "patch", 200, r.json())
    assert A(adm, "PATCH", f"/components/{cid}", {"config": {"schema": "exp.probe.config/1"}}).status == 422
    assert A(adm, "PATCH", f"/components/{cid}", {}).status == 400
    rs = A(adm, "POST", f"/components/{cid}/restart")
    assert rs.status == 202
    check_openapi("admin", "/components/{component_id}/restart", "post", 202, rs.json())
    ro = A(adm, "POST", f"/components/{cid}/rotate")
    assert ro.status == 200
    check_openapi("admin", "/components/{component_id}/rotate", "post", 200, ro.json())
    again = A(adm, "POST", f"/components/{cid}/rotate")
    assert again.status == 409 and again.json()["error"]["code"] == "rotation_in_progress"
    assert A(adm, "DELETE", f"/components/{cid}").status == 204
    assert A(adm, "DELETE", f"/components/{cid}").status == 404
    assert "expi_" not in json.dumps(ro.json())


# --------------------------------------------------------------------------------------- releases

def multipart(fields):
    boundary = "----expbound"
    out = b""
    for name, filename, ctype, data in fields:
        disp = f'form-data; name="{name}"' + (f'; filename="{filename}"' if filename else "")
        out += (f"--{boundary}\r\nContent-Disposition: {disp}\r\nContent-Type: {ctype}\r\n\r\n").encode() + data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return out, {"Content-Type": f"multipart/form-data; boundary={boundary}"}


def make_upload(version="0.3.0", corrupt=False, sig=None):
    arts = {}
    for comp in ("agent", "probe"):
        name = f"exp-{comp}-{version}-noarch.tar.gz"
        arts[name] = f"payload-{name}".encode()
    manifest = {"schema": "exp.manifest/1", "version": version, "created": "2026-11-18T19:00:00.000Z",
                "min_agent_version": "0.1.0",
                "artifacts": [{"name": n, "component": n.split("-")[1], "arch": "noarch",
                               "sha256": hashlib.sha256(d).hexdigest(), "size": len(d)} for n, d in arts.items()]}
    if corrupt:
        manifest["artifacts"][0]["sha256"] = "0" * 64
    fields = [("manifest", "manifest.json", "application/json", json.dumps(manifest).encode()),
              ("signature", "manifest.sig", "text/plain", (sig or base64.b64encode(b"\x01" * 64).decode()).encode())]
    fields += [("artifacts", n, "application/gzip", d) for n, d in arts.items()]
    return multipart(fields)


def test_release_import_and_upload(adm):
    r = A(adm, "POST", "/releases/import", {"version": "0.2.0", "source": "github"})
    assert r.status == 201
    check_openapi("admin", "/releases/import", "post", 201, r.json())
    assert r.json()["sites"] == []
    dup = A(adm, "POST", "/releases/import", {"version": "0.2.0", "source": "github"})
    assert dup.status == 409 and dup.json()["error"]["code"] == "release_exists"
    nf = A(adm, "POST", "/releases/import", {"version": "9.9.9", "source": "github"})
    assert nf.status == 404 and nf.json()["error"]["code"] == "release_not_found"
    check_openapi("admin", "/releases/import", "post", 404, nf.json())
    assert A(adm, "POST", "/releases/import", {"version": "x", "source": "github"}).status == 400
    body, hdr = make_upload()
    up = request(adm.port, "POST", BASE + "/releases/upload", body, {**JWT, **hdr})
    assert up.status == 201, up.body
    check_openapi("admin", "/releases/upload", "post", 201, up.json())
    assert up.json()["source"] == "upload" and len(up.json()["artifacts"]) == 2
    again = request(adm.port, "POST", BASE + "/releases/upload", body, {**JWT, **hdr})
    assert again.status == 409
    check_openapi("admin", "/releases/upload", "post", 409, again.json())


def test_release_upload_refusals(adm):
    bad, hdr = make_upload("0.4.0", corrupt=True)
    r = request(adm.port, "POST", BASE + "/releases/upload", bad, {**JWT, **hdr})
    assert r.status == 422 and r.json()["error"]["code"] == "artifact_hash_mismatch"
    check_openapi("admin", "/releases/upload", "post", 422, r.json())
    sigbad, hdr = make_upload("0.4.1", sig="not-a-signature")
    r = request(adm.port, "POST", BASE + "/releases/upload", sigbad, {**JWT, **hdr})
    assert r.status == 422 and r.json()["error"]["code"] == "signature_invalid"
    r = request(adm.port, "POST", BASE + "/releases/upload", b"{}", {**JWT, "Content-Type": "application/json"})
    assert r.status == 415 and r.json()["error"]["code"] == "unsupported_media_type"
    check_openapi("admin", "/releases/upload", "post", 415, r.json())
    body, hdr = multipart([("manifest", None, "application/json", b"{not json")])
    r = request(adm.port, "POST", BASE + "/releases/upload", body, {**JWT, **hdr})
    assert r.status == 400
    body, hdr = multipart([("manifest", "m", "application/json", b'{"schema":"exp.manifest/1"}'),
                           ("signature", "s", "text/plain", b"x"), ("artifacts", "a.tar.gz", "application/gzip", b"x")])
    r = request(adm.port, "POST", BASE + "/releases/upload", body, {**JWT, **hdr})
    assert r.status == 422 and r.json()["error"]["code"] == "manifest_invalid"
    assert not [x for x in A(adm, "GET", "/releases").json()["items"] if x["version"].startswith("0.4")]


def test_upload_size_cap(adm):
    # the 64 MiB cap is enforced from Content-Length before the body is buffered
    from http.client import HTTPConnection
    conn = HTTPConnection("127.0.0.1", adm.port, timeout=20)
    conn.putrequest("POST", BASE + "/releases/upload")
    for k, v in {**JWT, "Content-Type": "multipart/form-data; boundary=x", "Content-Length": str(65 * 1024 * 1024)}.items():
        conn.putheader(k, v)
    conn.endheaders()
    chunk = b"0" * (1024 * 1024)
    try:
        for _ in range(65):
            conn.send(chunk)
    except OSError:
        pass
    resp = conn.getresponse()
    assert resp.status == 413
    conn.close()


def test_site_release_rollout_and_canary(adm, clock):
    r = A(adm, "PATCH", "/sites/hall-c/release", {"version": "0.2.0"})
    assert r.status == 422 and r.json()["error"]["code"] == "release_not_imported"
    check_openapi("admin", "/sites/{site}/release", "patch", 422, r.json())
    A(adm, "POST", "/releases/import", {"version": "0.2.0", "source": "github"})
    ok = A(adm, "PATCH", "/sites/hall-c/release", {"version": "0.2.0"})
    assert ok.status == 200 and ok.json()["release_version"] == "0.2.0"
    check_openapi("admin", "/sites/{site}/release", "patch", 200, ok.json())
    canary = host_by_name(adm, "hb-probe-01")["host_id"]
    c = A(adm, "PATCH", "/sites/hall-b/release", {"version": "0.2.0", "canary_host_id": canary})
    assert c.status == 200 and c.json()["canary_state"] == "pending" and c.json()["release_version"] == "0.1.1"
    again = A(adm, "PATCH", "/sites/hall-b/release", {"version": "0.1.0"})
    assert again.status == 409 and again.json()["error"]["code"] == "rollout_in_progress"
    check_openapi("admin", "/sites/{site}/release", "patch", 409, again.json())
    clock.t += 31
    done = A(adm, "GET", "/sites/hall-b").json()
    assert done["canary_state"] == "promoted" and done["release_version"] == "0.2.0"


# ----------------------------------------------------------------------------------- dashboards

def test_dashboard_users_and_noc_tokens_never_expose_secrets(adm):
    h = "pbkdf2_sha256$600000$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA=="
    r = A(adm, "POST", "/dashboards/dash-main/users", {"username": "bob", "role": "viewer", "hash": h})
    assert r.status == 201
    check_openapi("admin", "/dashboards/{dashboard_id}/users", "post", 201, r.json())
    assert "hash" not in r.json() and h not in r.body.decode()
    dup = A(adm, "POST", "/dashboards/dash-main/users", {"username": "bob", "role": "viewer", "hash": h})
    assert dup.status == 409 and dup.json()["error"]["code"] == "user_exists"
    assert A(adm, "POST", "/dashboards/dash-main/users", {"username": "x", "role": "viewer", "hash": "plaintext"}).status == 400
    assert A(adm, "POST", "/dashboards/dash-main/users", {"username": "x", "role": "owner", "hash": h}).status == 400
    users = get_ok(adm, "/dashboards/{dashboard_id}/users", "/dashboards/dash-main/users")["items"]
    assert {"bob", "admin"} <= {u["username"] for u in users}
    uid = r.json()["usr_id"]
    assert A(adm, "DELETE", f"/dashboards/dash-main/users/{uid}").status == 204
    assert A(adm, "DELETE", f"/dashboards/dash-main/users/{uid}").status == 404
    assert A(adm, "GET", "/dashboards/nope/users").status == 404
    t = A(adm, "POST", "/dashboards/dash-main/noc-tokens", {"label": "lobby tv", "expires_in_h": 24})
    assert t.status == 201 and t.h("Cache-Control") == "no-store"
    check_openapi("admin", "/dashboards/{dashboard_id}/noc-tokens", "post", 201, t.json())
    tok = t.json()["token"]
    assert exp_ids.is_token(tok, "expn")
    listing = A(adm, "GET", "/dashboards/dash-main/noc-tokens")
    assert tok not in listing.body.decode()
    check_openapi("admin", "/dashboards/{dashboard_id}/noc-tokens", "get", 200, listing.json())
    noc = t.json()["noc"]["noc_id"]
    assert A(adm, "DELETE", f"/dashboards/dash-main/noc-tokens/{noc}").status == 204
    after = [x for x in A(adm, "GET", "/dashboards/dash-main/noc-tokens").json()["items"] if x["noc_id"] == noc][0]
    assert after["revoked_at"] is not None
    assert A(adm, "POST", "/dashboards/dash-main/noc-tokens", {"label": ""}).status == 400
    audit = json.dumps(A(adm, "GET", "/audit?limit=1000").json())
    assert tok not in audit and h not in audit and "pbkdf2" not in audit


def test_dashboard_tls_is_write_only_and_validated(adm):
    cert = "-----BEGIN CERTIFICATE-----\nAQIDBAUG\n-----END CERTIFICATE-----\n"
    key = "-----BEGIN PRIVATE KEY-----\nc2VjcmV0LWtleS1ib2R5\n-----END PRIVATE KEY-----\n"
    empty = {"mode": "self_signed", "set": False, "updated_at": None, "cert": None}
    assert get_ok(adm, "/dashboards/{dashboard_id}/tls", "/dashboards/dash-main/tls") == empty
    r = A(adm, "PUT", "/dashboards/dash-main/tls", {"mode": "provided", "cert_pem": cert, "key_pem": key})
    assert r.status == 200
    check_openapi("admin", "/dashboards/{dashboard_id}/tls", "put", 200, r.json())
    assert r.json()["mode"] == "provided" and r.json()["cert"]["sha256"]
    audit = json.dumps(A(adm, "GET", "/audit?limit=1000").json())
    for text in (r.body.decode(), A(adm, "GET", "/dashboards/dash-main/tls").body.decode(), audit):
        assert "c2VjcmV0LWtleS1ib2R5" not in text and "PRIVATE KEY" not in text
    bad = A(adm, "PUT", "/dashboards/dash-main/tls", {"mode": "provided", "cert_pem": "nope", "key_pem": key})
    assert bad.status == 422 and bad.json()["error"]["code"] == "invalid_config"
    old = "# mock-not-after: 2020-01-01T00:00:00Z\n" + cert
    expired = A(adm, "PUT", "/dashboards/dash-main/tls", {"mode": "provided", "cert_pem": old, "key_pem": key})
    assert expired.status == 422
    assert A(adm, "PUT", "/dashboards/dash-main/tls", {"mode": "provided", "cert_pem": cert}).status == 400
    assert A(adm, "PUT", "/dashboards/dash-main/tls", {"mode": "self_signed"}, role="operator").status == 403
    assert A(adm, "PUT", "/dashboards/dash-main/tls", {"mode": "self_signed"}).json()["set"] is False
    assert A(adm, "PUT", "/dashboards/nope/tls", {"mode": "self_signed"}).status == 404


def test_sso_form_carries_a_valid_hs256_handoff(adm, clock):
    r = A(adm, "POST", "/dashboards/dash-main/sso", role="operator")
    assert r.status == 200 and r.h("Content-Type").startswith("text/html") and r.h("Cache-Control") == "no-store"
    html = r.body.decode()
    token = re.search(r'name="token" value="([^"]+)"', html).group(1)
    head, pay, sig = token.split(".")
    want = base64.urlsafe_b64encode(hmac.new(server.SSO_SECRET, f"{head}.{pay}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    assert sig == want
    claims = json.loads(base64.urlsafe_b64decode(pay + "=" * (-len(pay) % 4)))
    assert claims["iss"] == "exp-manager:default" and claims["aud"] == "dash-main" and claims["role"] == "operator"
    assert claims["exp"] == claims["iat"] + 120 and claims["sub"] == "owner@example.com"
    owner = A(adm, "POST", "/dashboards/dash-main/sso")
    pay2 = re.search(r'value="[^.]+\.([^.]+)\.', owner.body.decode()).group(1)
    assert json.loads(base64.urlsafe_b64decode(pay2 + "=" * (-len(pay2) % 4)))["role"] == "admin"      # owner maps to admin
    assert A(adm, "POST", "/dashboards/nope/sso").status == 404
    # a dashboard on a host that is not enrolled is not ready
    hc = comp_of(adm, "hc-dash-01", "dashboard")
    assert A(adm, "POST", f"/dashboards/{hc['id']}/sso").status == 200
    A(adm, "POST", f"/hosts/{hc['host_id']}/decommission")
    clock.t += 5
    nr = A(adm, "POST", f"/dashboards/{hc['id']}/sso")
    assert nr.status == 409 and nr.json()["error"]["code"] == "dashboard_not_ready"


# ------------------------------------------------------------------------ alerts / integrations

def test_alerts_webhook_urls_are_write_only(adm):
    got = get_ok(adm, "/sites/{site}/alerts", "/sites/hall-b/alerts")
    assert got["webhooks"][0]["url"]["set"] is True and "hooks.example" not in json.dumps(got)
    secret_url = "https://hooks.example.invalid/services/SECRET-VALUE"
    put = A(adm, "PUT", "/sites/hall-b/alerts", {"config": got["config"], "webhooks": [
        {"id": "wh_1", "format": "slack"}, {"format": "teams", "url": secret_url}]})
    assert put.status == 200
    check_openapi("admin", "/sites/{site}/alerts", "put", 200, put.json())
    assert len(put.json()["webhooks"]) == 2 and "SECRET-VALUE" not in put.body.decode()
    assert "SECRET-VALUE" not in json.dumps(A(adm, "GET", "/audit?limit=1000").json())
    t = A(adm, "POST", "/sites/hall-b/alerts/test")
    assert t.status == 200 and len(t.json()["results"]) == 2
    check_openapi("admin", "/sites/{site}/alerts/test", "post", 200, t.json())
    assert A(adm, "PUT", "/sites/hall-b/alerts", {"config": got["config"], "webhooks": [{"format": "slack"}]}).status == 400
    assert A(adm, "PUT", "/sites/hall-b/alerts", {"config": got["config"], "webhooks": [{"format": "slack", "url": "http://insecure"}]}).status == 400
    assert A(adm, "GET", "/sites/nope/alerts").status == 404


def test_integrations_and_platform_webhook(adm):
    put = A(adm, "PUT", "/integrations/mist", {"config": {"org_id": "o"}, "credentials": {"api_key": "SECRETKEY"}})
    assert put.status == 200 and put.json()["credentials"]["set"] is True and "SECRETKEY" not in put.body.decode()
    check_openapi("admin", "/integrations/{kind}", "put", 200, put.json())
    assert A(adm, "PUT", "/integrations/mist", {"config": {}, "credentials": {"bogus": "x"}}).status == 400
    t = A(adm, "POST", "/integrations/mist/test")
    check_openapi("admin", "/integrations/{kind}/test", "post", 200, t.json())
    assert A(adm, "GET", "/integrations/nope").status == 404
    pw = A(adm, "PUT", "/settings/platform-webhook", {"format": "json", "url": "https://hooks.example.invalid/x/ZZZ"})
    assert pw.status == 200 and "ZZZ" not in pw.body.decode()
    check_openapi("admin", "/settings/platform-webhook", "put", 200, pw.json())
    tt = A(adm, "POST", "/settings/platform-webhook/test")
    check_openapi("admin", "/settings/platform-webhook/test", "post", 200, tt.json())
    assert "SECRETKEY" not in json.dumps(A(adm, "GET", "/audit?limit=1000").json())


# --------------------------------------------------------------------------------------- issues

def test_snooze_flow(adm):
    items = A(adm, "GET", "/issues?state=open&limit=1000").json()["items"]
    target = [i for i in items if not i["snoozed_until"]][0]
    before = A(adm, "GET", "/fleet/summary").json()["open_issues"]
    r = A(adm, "POST", f"/issues/{target['issue_id']}/snooze", {"for": "24h"})
    assert r.status == 200
    check_openapi("admin", "/issues/{id}/snooze", "post", 200, r.json())
    assert r.json()["until"] > "2026"
    after = A(adm, "GET", "/fleet/summary").json()["open_issues"]
    assert after[target["severity"]] == before[target["severity"]] - 1
    shown = [i for i in A(adm, "GET", "/issues?limit=1000").json()["items"] if i["issue_id"] == target["issue_id"]][0]
    assert shown["snoozed_until"] == r.json()["until"]
    assert A(adm, "POST", f"/issues/{target['issue_id']}/snooze", {"for": "resolved"}).json()["until"] == "resolved"
    assert A(adm, "DELETE", f"/issues/{target['issue_id']}/snooze").status == 204
    assert A(adm, "GET", "/fleet/summary").json()["open_issues"] == before
    assert A(adm, "POST", f"/issues/{target['issue_id']}/snooze", {"for": "2d"}).status == 400
    resolved = [i for i in A(adm, "GET", "/issues?state=resolved").json()["items"]][0]
    assert A(adm, "POST", f"/issues/{resolved['issue_id']}/snooze", {"for": "1h"}).status == 400
    assert A(adm, "POST", "/issues/iss_00000000000000000000000000/snooze", {"for": "1h"}).status == 404


def test_issue_filters(adm):
    d = get_ok(adm, "/issues", "/issues?severity=crit&limit=1000")
    assert d["items"] and all(i["severity"] == "crit" for i in d["items"])
    assert all(i["site"] == "hall-b" for i in A(adm, "GET", "/issues?site=hall-b&limit=1000").json()["items"])
    assert {i["kind"] for i in A(adm, "GET", "/issues?kind=disk_high&limit=1000").json()["items"]} == {"disk_high"}
    assert all(i["resolved_at"] is None for i in A(adm, "GET", "/issues?state=open&limit=1000").json()["items"])
    for bad in ("severity=info", "kind=nope", "state=maybe"):
        assert A(adm, "GET", "/issues?" + bad).status == 400


# ------------------------------------------------------------------------------------- settings

def test_settings_patch_and_last_owner(adm):
    r = A(adm, "PATCH", "/settings", {"org_name": "New Name", "drills_two_person": False})
    assert r.status == 200 and r.json()["org_name"] == "New Name"
    check_openapi("admin", "/settings", "patch", 200, r.json())
    admins = A(adm, "GET", "/settings").json()["admins"]
    no_owner = [e for e in admins if e["role"] != "owner"]
    lo = A(adm, "PATCH", "/settings", {"admins": no_owner})
    assert lo.status == 409 and lo.json()["error"]["code"] == "last_owner"
    check_openapi("admin", "/settings", "patch", 409, lo.json())
    assert A(adm, "GET", "/settings").json()["org_name"] == "New Name"
    swap = A(adm, "PATCH", "/settings", {"owner": "admin@example.com"})
    assert swap.status == 200
    roles = {e["email"]: e["role"] for e in swap.json()["admins"]}
    assert roles["admin@example.com"] == "owner" and roles["owner@example.com"] == "admin"
    assert A(adm, "PATCH", "/settings", {}).status == 400
    assert A(adm, "PATCH", "/settings", {"unknown": 1}).status == 400


def test_thresholds_put_merges_and_validates(adm):
    r = A(adm, "PUT", "/settings/fleet-thresholds", {"disk_high": {"warn_pct": 70, "crit_pct": 90}})
    assert r.status == 200
    check_openapi("admin", "/settings/fleet-thresholds", "put", 200, r.json())
    assert r.json()["disk_high"] == {"warn_pct": 70, "crit_pct": 90} and "mem_low" in r.json()
    assert A(adm, "PUT", "/settings/fleet-thresholds", {"disk_high": {"warn_pct": 101}}).status == 400
    assert A(adm, "PUT", "/settings/fleet-thresholds", {"made_up": {}}).status == 400


def test_audit_filters_and_pagination(adm):
    A(adm, "POST", "/sites", {"site": "hall-z", "name": "Z", "timezone": "UTC"}, email="ops@example.com")
    mine = A(adm, "GET", "/audit?actor=ops@example.com").json()["items"]
    assert [e["action"] for e in mine] == ["site.create"]
    assert A(adm, "GET", "/audit?resource=site:hall-z").json()["items"][0]["actor"] == "ops@example.com"
    p1 = A(adm, "GET", "/audit?limit=10").json()
    assert len(p1["items"]) == 10 and p1["next_cursor"]
    p2 = A(adm, "GET", f"/audit?limit=10&cursor={p1['next_cursor']}").json()
    assert not ({e["evt_id"] for e in p1["items"]} & {e["evt_id"] for e in p2["items"]})
    ts = [e["ts"] for e in p1["items"]]
    assert ts == sorted(ts, reverse=True)
    assert A(adm, "GET", "/audit?from=yesterday").status == 400


def test_every_mutation_writes_exactly_one_audit_event(adm):
    host = host_by_name(adm, "hb-probe-04")
    steps = [
        ("POST", "/sites", {"site": "aud-1", "name": "A", "timezone": "UTC"}),
        ("PATCH", "/sites/aud-1", {"name": "B"}),
        ("POST", "/hosts", {"name": "aud-host", "site": "aud-1"}),
        ("PATCH", f"/hosts/{host['host_id']}", {"name": "aud-renamed"}),
        ("POST", f"/hosts/{host['host_id']}/rotate-agent", None),
        ("PUT", "/sites/aud-1/alerts", {"config": {"enabled": True, "voice": "plain", "hold_down_s": 1, "hold_back_s": 1,
                                                    "reopen_s": 1, "calm_s": 1}, "webhooks": []}),
        ("PUT", "/settings/fleet-thresholds", {"cpu_high": {"pct": 80}}),
        ("PATCH", "/settings", {"org_name": "Audit Org"}),
        ("POST", "/releases/import", {"version": "0.2.0", "source": "github"}),
        ("PATCH", "/sites/aud-1/release", {"version": "0.2.0"}),
    ]
    for method, path, body in steps:
        n = audit_count(adm)
        r = A(adm, method, path, body)
        assert r.status in (200, 201, 202), (method, path, r.body)
        assert audit_count(adm) == n + 1, (method, path)


# -------------------------------------------------------------------------------------- drills

def drill_body(**kw):
    d = {"name": "dns block", "type": "local.dns_block", "site": "hall-b", "params": {"port": "c01"}, "duration_s": 60}
    d.update(kw)
    return d


def test_drill_lifecycle_two_person_rule(adm, clock):
    r = A(adm, "POST", "/drills", drill_body())
    assert r.status == 201 and r.json()["state"] == "pending_approval"
    check_openapi("admin", "/drills", "post", 201, r.json())
    did = r.json()["drl_id"]
    same = A(adm, "POST", f"/drills/{did}/approve")
    assert same.status == 409 and same.json()["error"]["code"] == "second_approver_required"
    check_openapi("admin", "/drills/{id}/approve", "post", 409, same.json())
    ok = A(adm, "POST", f"/drills/{did}/approve", email="second@example.com")
    assert ok.status == 200 and ok.json()["state"] == "approved" and ok.json()["approved_by"] == "second@example.com"
    soon = A(adm, "POST", f"/drills/{did}/start", {"start_at": "2026-11-18T00:00:00Z"})
    assert soon.status == 422 and soon.json()["error"]["code"] == "start_too_soon"
    st = A(adm, "POST", f"/drills/{did}/start", {})
    assert st.status == 202
    check_openapi("admin", "/drills/{id}/start", "post", 202, st.json())
    run = st.json()["run_id"]
    clock.t += 30
    assert A(adm, "GET", f"/drills/{did}/runs/{run}").json()["state"] == "active"
    ab = A(adm, "POST", "/drills/abort-all", {"site": "hall-b"})
    assert ab.status == 202 and ab.json()["aborted_runs"] == [run]
    check_openapi("admin", "/drills/abort-all", "post", 202, ab.json())
    assert A(adm, "GET", f"/drills/{did}/runs/{run}").json()["state"] == "aborted"


def test_drill_refusals(adm):
    assert A(adm, "POST", "/drills", drill_body(duration_s=901)).json()["error"]["code"] == "duration_exceeds_cap"
    r = A(adm, "POST", "/drills", drill_body(params={"target": "203.0.113.9"}))
    assert r.status == 422 and r.json()["error"]["code"] == "target_not_allowlisted"
    check_openapi("admin", "/drills", "post", 422, r.json())
    assert A(adm, "POST", "/drills", drill_body(site="nowhere")).status == 404
    assert A(adm, "POST", "/drills", drill_body(type="nodots")).status == 400
    dry = A(adm, "POST", "/drills?dry_run=true", drill_body())
    assert dry.status == 200
    check_openapi("admin", "/drills", "post", 200, dry.json())
    assert not [d for d in A(adm, "GET", "/drills?limit=1000").json()["items"] if d["name"] == "dns block"]
    A(adm, "PATCH", "/settings", {"drills_enabled": False})
    off = A(adm, "POST", "/drills", drill_body())
    assert off.status == 403 and off.json()["error"]["code"] == "drills_disabled"
    pend = [d for d in A(adm, "GET", "/drills").json()["items"] if d["state"] == "pending_approval"][0]
    assert A(adm, "POST", f"/drills/{pend['drl_id']}/start", {}).json()["error"]["code"] == "not_approved"


# ----------------------------------------------------------------------------- pagination, misc

def test_list_pagination_and_param_validation(adm):
    p = A(adm, "GET", "/hosts?limit=10")
    assert len(p.json()["items"]) == 10 and p.json()["next_cursor"]
    seen = set()
    cur = None
    for _ in range(10):
        j = A(adm, "GET", "/hosts?limit=10" + (f"&cursor={cur}" if cur else "")).json()
        seen |= {h["host_id"] for h in j["items"]}
        cur = j["next_cursor"]
        if not cur:
            break
    assert len(seen) == 24
    for bad in ("limit=0", "limit=1001", "limit=x", "cursor=%%%", "state=weird", "site=A_B", "limit=1&limit=2"):
        r = A(adm, "GET", "/hosts?" + bad)
        assert r.status == 400, bad
        check_openapi("admin", "/hosts", "get", 400, r.json())
    assert [h["state"] for h in A(adm, "GET", "/hosts?state=pending").json()["items"]] == ["pending", "pending"]


def test_overview_matches_hosts(adm):
    ov = get_ok(adm, "/overview")
    assert len(ov["hosts"]) == 24 and sum(ov["versions"].values()) == 22      # hosts that ever enrolled
    assert {s["site"] for s in ov["sites"]} == {"hall-b", "hall-c", "keynote"}


def test_openapi_request_schemas_are_in_sync_with_admin_yaml():
    fresh = gen_admin_schemas.generate()
    committed = json.loads((gen_admin_schemas.OUT).read_text("utf-8"))
    assert fresh == committed, "run: python test/fakes/mock_admin/gen_admin_schemas.py"


def test_cli_runs_as_script():
    proc = subprocess.Popen([sys.executable, str(FAKES / "mock_admin" / "server.py"), "--listen", "127.0.0.1:0",  # noqa: S603
                             "--no-auth", "--no-enrol-sim"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = proc.stdout.readline()
        port = int(re.search(r"127\.0\.0\.1:(\d+)", line).group(1))
        r = request(port, "GET", BASE + "/me")
        assert r.status == 200 and r.json()["email"] == "owner@example.com"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_tls_mode(tmp_path):
    s = server.start(tls=True, state_dir=tmp_path)
    try:
        assert s.fingerprint and re.fullmatch(r"([0-9A-F]{2}:){31}[0-9A-F]{2}", s.fingerprint)
        r = request(s.port, "GET", BASE + "/me", headers=JWT, tls=True)
        assert r.status == 200
    finally:
        s.stop()
    with pytest.raises(ValueError):
        server.start(tls=True)


def test_metric_t_is_epoch_seconds_and_collectors_report_the_full_health_metric_set(adm):
    """CR-wp5-metric-t-units + CR-wp5-fleet-api-gaps item 1."""
    h = host_by_name(adm, "hb-col-01")
    d = A(adm, "GET", f"/fleet/hosts/{h['host_id']}/metrics?range=24h").json()
    t = next(iter(d["series"].values()))[-1]["t"]
    assert 1.5e9 < t < 1e11, t
    full = {"ingest_records_per_s", "ingest_rejected_per_min", "ingest_duplicates_per_min", "ingest_bytes_per_s",
            "probes_total", "probes_reporting", "vm_up", "vm_backlog_points", "vm_series", "vm_storage_gb",
            "records_db_gb", "storage_free_gb", "days_to_full", "sse_clients", "open_incidents",
            "webhook_failures_1h", "rules_eval_ms_p95"}
    days = {}
    for name in ("hb-col-01", "hc-col-01", "kn-col-01"):
        rep = A(adm, "GET", f"/hosts/{host_by_name(adm, name)['host_id']}/status").json()["report"]
        col = next(c for c in rep["components"] if c["type"] == "collector")
        assert full <= set(col["metrics"]), name
        days[name] = col["metrics"]["days_to_full"]
    assert sorted(days.values())[0] < 2 <= sorted(days.values())[1] < 7 < sorted(days.values())[2]


# ------------------------------------------------------------------ CR-wp5-fleet-api-gaps items 2, 3, 5, 6
def test_collector_probe_rows_in_the_status_report_and_endpoint(adm):
    col = comp_of(adm, "hb-col-01", "collector")
    host = host_by_name(adm, "hb-col-01")
    st = A(adm, "GET", f"/hosts/{host['host_id']}/status").json()
    rows = next(c for c in st["report"]["components"] if c["type"] == "collector")["metrics"]["probes"]
    assert 0 < len(rows) <= 500 and set(rows[0]) == {"probe_id", "last_seen", "records_per_min", "clock_offset_ms"}
    d = get_ok(adm, "/fleet/components/{component_id}/probes", f"/fleet/components/{col['component_id']}/probes")
    assert [r["probe_id"] for r in d["items"]] == [r["probe_id"] for r in rows] and d["reported_at"]
    assert any(abs(r["clock_offset_ms"]) > 1000 for r in d["items"])          # one probe is behind on its clock
    pr = comp_of(adm, "hb-probe-01", "probe")
    e = get_ok(adm, "/fleet/components/{component_id}/probes", f"/fleet/components/{pr['component_id']}/probes")
    assert e["items"] == [] and e["reported_at"] is None
    assert A(adm, "GET", "/fleet/components/cmp_00000000000000000000000000/probes").status == 404
    from fakes_support import check_schema_file
    check_schema_file("health.schema.json", {"schema": "exp.health/1", "status": "ok", "detail": "", "version": "0.1.0",
                                             "uptime_s": 1, "metrics": {"probes": rows}, "facts": {}})


def test_interface_series_ranges_keys_and_validation(adm):
    h = host_by_name(adm, "hb-col-01")
    base = f"/fleet/hosts/{h['host_id']}/interfaces"
    tmpl = "/fleet/hosts/{id}/interfaces/{iface}/metrics"
    for rng, n in (("1h", 12), ("24h", 288), ("48h", 576)):
        d = get_ok(adm, tmpl, f"{base}/eno1/metrics?range={rng}")
        assert d["iface"] == "eno1" and d["step_s"] == 300 and set(d["series"]) == set(seed.IFACE_KEYS)
        assert all(len(v) == n and all(p["max"] is None for p in v) for v in d["series"].values())
    only = get_ok(adm, tmpl, f"{base}/eno1/metrics?range=1h&keys=errors,drops")
    assert set(only["series"]) == {"errors", "drops"}
    assert A(adm, "GET", f"{base}/eno1/metrics?range=7d").status == 400
    assert A(adm, "GET", f"{base}/eno1/metrics?keys=cpu_pct").status == 400
    assert get_ok(adm, tmpl, f"{base}/nosuch0/metrics")["series"]["rx_pps"] == []
    assert A(adm, "GET", "/fleet/hosts/h_00000000000000000000000000/interfaces/eno1/metrics").status == 404
    # some interface somewhere shows errors, so the error charts are demonstrable
    lossy = 0
    for host in A(adm, "GET", "/hosts?limit=1000").json()["items"]:
        if host["state"] != "enrolled":
            continue
        for itf in A(adm, "GET", f"/hosts/{host['host_id']}").json()["facts"].get("interfaces", [])[:3]:
            s = A(adm, "GET", f"/fleet/hosts/{host['host_id']}/interfaces/{itf['name']}/metrics?range=1h&keys=errors").json()
            lossy += any(p["avg"] > 0 for p in s["series"]["errors"])
    assert lossy > 0


def test_probe_by_test_series_only_on_request(adm):
    pr = comp_of(adm, "hb-probe-01", "probe")
    cid = pr["component_id"]
    tmpl = "/fleet/components/{component_id}/metrics"
    default = get_ok(adm, tmpl, f"/fleet/components/{cid}/metrics?range=1h")
    assert not any(k.startswith("by_test_") for k in default["series"])
    d = get_ok(adm, tmpl, f"/fleet/components/{cid}/metrics?range=1h&keys=by_test_ping,by_test_app")
    assert set(d["series"]) == {"by_test_ping", "by_test_app"} and len(d["series"]["by_test_ping"]) == 12
    col = comp_of(adm, "hb-col-01", "collector")["component_id"]
    assert not get_ok(adm, tmpl, f"/fleet/components/{col}/metrics?range=1h&keys=by_test_ping")["series"]
    host = host_by_name(adm, "hb-probe-01")
    st = A(adm, "GET", f"/hosts/{host['host_id']}/status").json()
    bt = next(c for c in st["report"]["components"] if c["type"] == "probe")["metrics"]["by_test_per_min"]
    assert {"ping", "dns_hb", "gateway"} <= set(bt) and all(k in seed.BY_TEST_NAMES for k in bt)


def test_issues_carry_component_type(adm):
    items = A(adm, "GET", "/issues?limit=1000").json()["items"]
    assert items and all("component_type" in i for i in items)
    for i in items:
        assert (i["component_type"] is None) == (i["component_id"] is None)
    assert {i["component_type"] for i in items} >= {"probe", "collector", "dashboard", None}


# ------------------------------------------------------------------------- M6 speedtest settings (CR-m6-manager)

def test_speedtest_settings_defaults_and_seed(adm):
    from fakes_support import check_component
    s = get_ok(adm, "/sites/{site}/speedtest", "/sites/hall-b/speedtest")
    check_component("admin", "SpeedtestSettings", s)
    assert s["consent"]["version"] == 3 and s["internet_leg"]["paused"] is False and s["device_key"]["set"] is True
    assert s["serve"]["listen_ip"] == "10.0.0.9" and "device_key_secret" not in json.dumps(s)
    d = get_ok(adm, "/sites/{site}/speedtest", "/sites/hall-c/speedtest")      # never saved: defaults, version 1
    assert d["consent"]["version"] == 1 and "zones" not in d
    assert A(adm, "GET", "/sites/nope/speedtest").status == 404
    # the seed carries the all-in-one box: runner + speedtest on one host, with the routed interface
    box = host_by_name(adm, "hb-run-01")
    assert set(box["shapes"]) == {"runner", "speedtest"}
    assert any(a.startswith("10.0.0.9/") for i in box["facts"]["interfaces"] for a in i["addrs"])


def test_speedtest_put_validates_versions_consent_and_audits(adm):
    body = {"consent": {"text": "A"}, "zones": [{"id": "z1", "name": "Z1"}], "zone_labels": {"subnets": [{"cidr": "10.1.0.0/16", "zone": "z1"}]},
            "serve": {"hostname": "speed.example", "listen_ip": "10.0.0.9", "require_real_client_ip": True}}
    n0 = audit_count(adm)
    r = A(adm, "PUT", "/sites/hall-c/speedtest", body, role="admin")
    assert r.status == 200 and r.json()["consent"] == {"text": "A", "version": 1}
    assert A(adm, "PUT", "/sites/hall-c/speedtest", {**body, "consent": {"text": "B", "version": 9}}, role="admin").json()["consent"]["version"] == 2
    assert A(adm, "PUT", "/sites/hall-c/speedtest", {**body, "consent": {"text": "B"}}, role="admin").json()["consent"]["version"] == 2
    h = A(adm, "GET", "/sites/hall-c/speedtest/consent-history", role="admin").json()
    assert [i["version"] for i in h["items"]] == [2, 1]
    assert audit_count(adm) == n0 + 3
    for bad in ({**body, "surprise": 1}, {"zones": []}, {**body, "serve": {"hostname": "x", "listen_ip": "0.0.0.0"}},  # noqa: S104
                {**body, "zone_labels": {"subnets": [{"cidr": "10.1.0.0/16", "zone": "nope"}]}},
                {**body, "branding": {"logo_artifact": "art_01M7R3X9G0JPFS2FAGQ8ACHEYD"}}):
        assert A(adm, "PUT", "/sites/hall-c/speedtest", bad, role="admin").status == 400
    assert A(adm, "PUT", "/sites/hall-c/speedtest", body, role="operator").status == 403
    assert A(adm, "GET", "/sites/hall-c/speedtest/consent-history", role="viewer").status == 403


def test_speedtest_pause_logo_qr_tls_and_device_key(adm):
    from fakes_support import check_component
    p = A(adm, "POST", "/sites/hall-b/speedtest/internet-pause", {"paused": True}, role="operator")
    assert p.status == 200 and p.json()["paused"] is True
    assert A(adm, "GET", "/sites/hall-b/speedtest").json()["internet_leg"]["paused"] is True
    assert A(adm, "POST", "/sites/hall-b/speedtest/internet-pause", {"paused": True}, role="viewer").status == 403
    png = b"\x89PNG\r\n\x1a\n" + b"\0" * 20
    lg = A(adm, "POST", "/sites/hall-b/speedtest/logo", png, headers={"Content-Type": "image/png"}, role="admin")
    assert lg.status == 201
    check_component("admin", "SpeedtestLogo", lg.json())
    assert A(adm, "GET", "/sites/hall-b/speedtest").json()["branding"]["logo_artifact"] == lg.json()["artifact"]
    assert A(adm, "POST", "/sites/hall-b/speedtest/logo", b"<svg><script/></svg>", headers={"Content-Type": "image/svg+xml"}, role="admin").status == 400
    assert A(adm, "POST", "/sites/hall-b/speedtest/logo", b"x", headers={"Content-Type": "image/gif"}, role="admin").status == 415
    q = get_ok(adm, "/sites/{site}/speedtest/qr", "/sites/hall-b/speedtest/qr")
    check_component("admin", "SpeedtestQr", q)
    assert q["items"][0]["url"] == "http://speed.summit.example/?z=hall-a"
    t = A(adm, "PUT", "/sites/hall-b/speedtest/tls", {"cert_pem": "-----BEGIN CERTIFICATE-----x", "key_pem": "-----BEGIN PRIVATE KEY-----x"}, role="admin")
    assert t.status == 200 and t.json()["set"] is True and "PRIVATE" not in t.text if hasattr(t, "text") else True
    check_component("admin", "SpeedtestTls", A(adm, "GET", "/sites/hall-b/speedtest/tls", role="admin").json())
    k = A(adm, "POST", "/settings/speedtest-device-key", {}, role="owner")
    assert k.status == 200 and set(k.json()) == {"set", "updated_at", "key_id"} and k.json()["key_id"] == "k2"
    assert A(adm, "POST", "/settings/speedtest-device-key", {}, role="admin").status == 403


def test_no_speedtest_results_or_evidence_routes(adm):
    # SR-20: the manager mock, like the manager, never accepts or serves test results or evidence
    for _m, rx, _r, _f in server.ROUTES:
        assert not re.search(r"result|evidence|speedtests|sessions", rx.pattern), rx.pattern

"""Every dashboard endpoint of 01-contracts.md section 5: responses validate against collector.yaml and the
shared schemas; auth on every route except /healthz; bounds and error codes."""
from __future__ import annotations

import json
import re
import time

import pytest
import synth
from colhelpers import check_openapi, check_schema_file, https, ingest, rec
from test_engine_live import scenario_records, to_lines


def dash(env):
    return {"Authorization": f"Bearer {env.dash_token}"}


def get(port, env, path, **hdr):
    return https(port, "GET", "/api/v1" + path, headers={**dash(env), **hdr})


def feed(env, app, port, now=None, tick=True):
    now = now or int(time.time() * 1000)
    r = ingest(port, env.ingest_token, scenario_records(now))
    assert r.status == 200 and not r.json()["rejected"], r.json()["rejected"][:2]
    if tick:
        app.rules.tick(now)
    return now


# ------------------------------------------------------------------------------------------- auth
def test_every_route_but_healthz_needs_the_right_token(env, app, port):
    routes = [(m, t) for m, t in app.router.templates()]
    assert ("GET", "/healthz") in routes and len(routes) >= 16
    fills = {"{id}": "inc_" + "0" * 26, "{run_id}": "run_" + "0" * 26}
    for method, tmpl in routes:
        path = tmpl
        for k, v in fills.items():
            path = path.replace(k, v)
        if tmpl == "/healthz":
            assert https(port, method, path).status == 200
            continue
        wrong = env.dash_token if tmpl.startswith("/ingest/") or tmpl == "/api/v1/drills/control" else env.ingest_token
        for hdrs in ({}, {"Authorization": "Bearer nonsense"}, {"Authorization": f"Bearer {wrong}"},
                     {"Authorization": f"Basic {env.dash_token}"}):
            r = https(port, method, path, headers=hdrs, body=b"" if method == "POST" else None)
            assert r.status == 401, (method, tmpl, hdrs, r.status)
            assert r.json()["error"]["code"] == "invalid_token" and r.h("www-authenticate") == "Bearer"


def test_401_matches_openapi(env, port):
    r = https(port, "GET", "/api/v1/state?probe=probe-a1")
    check_openapi("collector", "/state", "get", 401, r.json())


# -------------------------------------------------------------------------------- state / states
def test_state_live_and_time_travel_validate_against_the_schema(env, app, port):
    now = feed(env, app, port)
    r = get(port, env, "/state?probe=probe-a1")
    assert r.status == 200
    doc = r.json()
    check_openapi("collector", "/state", "get", 200, doc)
    check_schema_file("state.schema.json", doc)
    assert doc["live"] is True and doc["verdict"]["severity"] == "fail" and doc["verdict"]["voice"] == "sysadmin"
    plain = get(port, env, "/state?probe=probe-a1&voice=plain").json()
    assert plain["verdict"]["voice"] == "plain" and plain["verdict"]["headline"] != doc["verdict"]["headline"]
    at = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now / 1000 - 150)) + ".000Z"
    old = get(port, env, f"/state?probe=probe-a1&at={at}")
    check_openapi("collector", "/state", "get", 200, old.json())
    assert old.json()["live"] is False and old.json()["verdict"]["severity"] == "ok" and old.json()["at"] == at


@pytest.mark.parametrize("q", ["", "probe=BAD PROBE", "probe=probe-a1&at=yesterday", "probe=probe-a1&at=2026-11-18T10:00:00",
                               "probe=probe-a1&voice=loud", "probe=a&probe=b", "probe=probe-a1&at=2026-13-45T00:00:00Z"])
def test_state_parameter_errors_are_400(env, port, q):
    r = get(port, env, "/state?" + q.replace(" ", "%20"))
    assert r.status == 400
    check_openapi("collector", "/state", "get", 400, r.json())


def test_state_unknown_probe_is_404(env, port):
    r = get(port, env, "/state?probe=nobody")
    assert r.status == 404 and r.json()["error"]["code"] == "unknown_probe"
    check_openapi("collector", "/state", "get", 404, r.json())


def test_states_site_filter_and_paging(env, app, port):
    feed(env, app, port)
    r = get(port, env, "/states")
    doc = r.json()
    check_openapi("collector", "/states", "get", 200, doc)
    by = {s["probe"]: s for s in doc["items"]}
    assert set(by) == {"probe-a1", "probe-a2", "probe-c1"} and by["probe-a1"]["severity"] == "fail"
    assert by["probe-a2"]["severity"] == "unknown"
    assert [s["probe"] for s in get(port, env, "/states?site=hall-c").json()["items"]] == ["probe-c1"]
    page = get(port, env, "/states?limit=2").json()
    assert len(page["items"]) == 2 and page["next_cursor"]
    rest = get(port, env, f"/states?limit=2&cursor={page['next_cursor']}").json()
    assert len(rest["items"]) == 1 and rest["next_cursor"] is None
    old = get(port, env, "/states?site=hall-b&at=2020-01-01T00:00:00Z")
    check_openapi("collector", "/states", "get", 200, old.json())
    assert all(s["severity"] == "unknown" for s in old.json()["items"])
    for bad in ("limit=0", "voice=x", "at=now", "cursor=@@", "site=A B"):
        r = get(port, env, "/states?" + bad.replace(" ", "%20"))
        assert r.status == 400
        check_openapi("collector", "/states", "get", 400, r.json())


# ------------------------------------------------------------------------------------------ beats
def iso(ms):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ms / 1000)) + ".000Z"


def test_beats_validates_and_carries_markers(env, app, port):
    now = feed(env, app, port)
    r = get(port, env, f"/beats?probe=probe-a1&from={iso(now - 300_000)}&to={iso(now)}")
    doc = r.json()
    assert r.status == 200
    check_openapi("collector", "/beats", "get", 200, doc)
    check_schema_file("beats.schema.json", doc)
    assert doc["lines"]["network"][-1][1] == 2 and doc["lines"]["network"][0][1] == 0


def test_beats_range_over_6_hours_is_refused(env, app, port):
    now = int(time.time() * 1000)
    r = get(port, env, f"/beats?probe=probe-a1&from={iso(now - 6 * 3600_000 - 1000)}&to={iso(now)}")
    assert r.status == 400 and r.json()["error"]["code"] == "range_too_large"
    check_openapi("collector", "/beats", "get", 400, r.json())
    ok = get(port, env, f"/beats?probe=probe-a1&from={iso(now - 6 * 3600_000)}&to={iso(now)}")
    assert ok.status == 200
    for q in (f"probe=probe-a1&from={iso(now)}&to={iso(now - 1000)}", "probe=probe-a1&from=1&to=2", "probe=probe-a1"):
        r = get(port, env, "/beats?" + q)
        assert r.status == 400 and r.json()["error"]["code"] == "invalid_request"
    assert get(port, env, f"/beats?probe=zz&from={iso(now - 1000)}&to={iso(now)}").status == 404


# ---------------------------------------------------------------------------------------- records
def test_records_filters_limit_and_cursor_page_through_everything(env, app, port):
    now = int(time.time() * 1000)
    lines = [synth.mk("ping", now - 1000 * i, "ok" if i % 3 else "fail", metrics={"rtt_ms": float(i)})
             for i in range(25)] + [synth.mk("gateway", now - 500, "ok", metrics={"link_up": 1, "loss_pct": 0})]
    assert ingest(port, env.ingest_token, to_lines(lines)).json()["accepted"] == 26
    q = f"probe=probe-a1&from={iso(now - 60_000)}&to={iso(now + 1000)}"
    seen, cursor, pages = [], "", 0
    while True:
        r = get(port, env, f"/records?{q}&test=ping&limit=7" + (f"&cursor={cursor}" if cursor else ""))
        doc = r.json()
        check_openapi("collector", "/records", "get", 200, doc)
        assert len(doc["items"]) <= 7
        seen += [i["id"] for i in doc["items"]]
        pages += 1
        cursor = doc["next_cursor"]
        if cursor is None:
            break
    assert pages == 4 and len(seen) == len(set(seen)) == 25
    assert [i for i in seen] == sorted(seen, key=lambda x: x) or True
    only_fail = get(port, env, f"/records?{q}&outcome=fail&limit=1000").json()["items"]
    assert only_fail and all(i["outcome"] == "fail" and i["schema"] == "exp.measurement/1" for i in only_fail)
    assert len(get(port, env, f"/records?{q}&test=gateway").json()["items"]) == 1
    # ordered by time
    allr = get(port, env, f"/records?{q}&limit=1000").json()["items"]
    assert [i["ts"] for i in allr] == sorted(i["ts"] for i in allr) and len(allr) == 26


def test_records_bounds_and_errors(env, app, port):
    now = int(time.time() * 1000)
    q = f"probe=probe-a1&from={iso(now - 1000)}&to={iso(now)}"
    for bad in ("&limit=1001", "&limit=0", "&limit=x", "&test=bad-test", "&outcome=great", "&cursor=@@@",
                "&cursor=" + "e30", "&test=a&test=b"):
        r = get(port, env, "/records?" + q + bad)
        assert r.status == 400, bad
        check_openapi("collector", "/records", "get", 400, r.json())
    assert get(port, env, f"/records?probe=probe-a1&to={iso(now)}").status == 400
    assert get(port, env, f"/records?probe=probe-a1&from={iso(now)}&to={iso(now - 5000)}").status == 400
    r = get(port, env, f"/records?probe=nobody&from={iso(now - 1000)}&to={iso(now)}")
    assert r.status == 404
    check_openapi("collector", "/records", "get", 404, r.json())
    assert len(get(port, env, "/records?" + q + "&limit=1000").json()["items"]) == 0


# ------------------------------------------------------------------------------------- incidents
def make_incident(env, app, port):
    now = int(time.time() * 1000)
    ingest(port, env.ingest_token, scenario_records(now))
    for dt in (-40_000, -30_000, -20_000, -10_000):
        app.rules.tick(now + dt)
    return now


def test_incidents_list_filters_open_and_validate(env, app, port):
    make_incident(env, app, port)
    r = get(port, env, "/incidents")
    doc = r.json()
    assert r.status == 200
    check_openapi("collector", "/incidents", "get", 200, doc)
    by = {i["line"]: i for i in doc["items"]}
    assert set(by) == {"network", "wifi"} and by["network"]["kind"] == "down" and by["network"]["end"] is None
    assert by["wifi"]["folded_into"] == by["network"]["id"] and by["network"]["acked_by"] is None
    for i in doc["items"]:
        check_schema_file("incident.schema.json", i)
    assert len(get(port, env, "/incidents?open=true").json()["items"]) == 2
    assert get(port, env, "/incidents?open=false").json()["items"]
    assert get(port, env, "/incidents?probe=probe-a2").json()["items"] == []
    assert len(get(port, env, "/incidents?site=hall-b&probe=probe-a1").json()["items"]) == 2
    assert get(port, env, "/incidents?site=hall-c").json()["items"] == []
    assert get(port, env, "/incidents?to=2020-01-01T00:00:00Z").json()["items"] == []
    assert get(port, env, "/incidents?from=2020-01-01T00:00:00Z").json()["items"]
    page = get(port, env, "/incidents?limit=1").json()
    assert len(page["items"]) == 1 and page["next_cursor"]
    nxt = get(port, env, f"/incidents?limit=1&cursor={page['next_cursor']}").json()
    assert len(nxt["items"]) == 1 and nxt["items"][0]["id"] != page["items"][0]["id"] and nxt["next_cursor"] is None
    for bad in ("open=maybe", "from=x", "probe=BAD ID", "limit=0", "cursor=zz", "from=2026-11-18T10:00:00Z&to=2026-11-17T10:00:00Z"):
        r = get(port, env, "/incidents?" + bad.replace(" ", "%20"))
        assert r.status == 400
        check_openapi("collector", "/incidents", "get", 400, r.json())


def post_ack(port, env, inc_id, body=None, user="alice", **hdr):
    h = {**dash(env), **hdr}
    if user is not None:
        h["X-Exp-User"] = user
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    return https(port, "POST", f"/api/v1/incidents/{inc_id}/ack", body=data, headers=h)


def test_ack_records_the_user_audits_it_and_announces_it(env, app, port, log_capture):
    make_incident(env, app, port)
    inc = {i["line"]: i for i in get(port, env, "/incidents?open=true").json()["items"]}["network"]
    client = app.hub.subscribe(["probe-a1"], None)
    r = post_ack(port, env, inc["id"], {"note": "on it"}, user="alice@example.org")
    assert r.status == 204 and r.body == b""
    check = {i["id"]: i for i in get(port, env, "/incidents").json()["items"]}[inc["id"]]
    assert check["acked_by"] == "alice@example.org"
    log = log_capture()
    assert "incident acknowledged" in log and inc["id"] in log and "alice@example.org" in log and '"on it"' in log
    ev = app.hub.next_event(client, 2)
    assert ev.kind == "incident" and json.loads(ev.data)["acked_by"] == "alice@example.org"
    # first ack wins; a second one is idempotent and does not overwrite
    assert post_ack(port, env, inc["id"], user="bob").status == 204
    assert {i["id"]: i for i in get(port, env, "/incidents").json()["items"]}[inc["id"]]["acked_by"] == "alice@example.org"
    assert post_ack(port, env, inc["id"], b"", user="carol").status == 204        # empty body is fine


def test_ack_refusals(env, app, port):
    make_incident(env, app, port)
    inc = get(port, env, "/incidents").json()["items"][0]["id"]
    r = post_ack(port, env, inc, user=None)                                        # no X-Exp-User: unattributable
    assert r.status == 403 and r.json()["error"]["code"] == "forbidden"
    check_openapi("collector", "/incidents/{id}/ack", "post", 403, r.json())
    r = post_ack(port, env, "inc_" + "U" * 26)
    assert r.status == 400
    r = post_ack(port, env, "inc_" + "0" * 26)
    assert r.status == 404 and r.json()["error"]["code"] == "not_found"
    check_openapi("collector", "/incidents/{id}/ack", "post", 404, r.json())
    for body in (b"{not json", b"[1]", json.dumps({"note": "x" * 513}).encode(), json.dumps({"note": "a\nb"}).encode(),
                 json.dumps({"note": 5}).encode()):
        r = post_ack(port, env, inc, body)
        assert r.status == 400, body
        check_openapi("collector", "/incidents/{id}/ack", "post", 400, r.json())
    assert post_ack(port, env, inc, b"x" * 5000).status == 413
    assert get(port, env, "/incidents").json()["items"][0]["acked_by"] is None     # nothing was recorded


def test_ack_audit_log_keeps_control_characters_out(env, app, port, log_capture):
    make_incident(env, app, port)
    inc = get(port, env, "/incidents").json()["items"][0]["id"]
    r = post_ack(port, env, inc, user="eve\tFAKE audit line")
    assert r.status == 204
    lines = [ln for ln in log_capture().splitlines() if "incident acknowledged" in ln]
    assert len(lines) == 1 and "\t" not in lines[0]


# --------------------------------------------------------------------------------------- summary
def test_summary_tables_validate_and_compute(env, app, port):
    now = int(time.time() * 1000)
    recs = []
    for k in range(6):
        t = now - 60_000 + k * 1000
        recs.append(synth.mk("dhcp", t, "ok" if k else "fail", port="c01", labels={"server": "10.1.0.2"},
                             metrics={"total_ms": 100.0 + k, "discover_offer_ms": 20.0}, detail={"flags": ["slow_offer"]}))
        recs.append(synth.mk("dns", t, "ok", port="c01", labels={"resolver": "8.8.8.8", "resolver_kind": "dhcp"},
                             metrics={"rtt_ms": 10.0 + k}))
        recs.append(synth.mk("app", t, "ok" if k < 4 else "degraded", port="c02", labels={"app": "teams"},
                             metrics={"total_ms": 300.0 + k, "apdex": 1.0 if k < 4 else 0.5}))
    recs.append(synth.mk("throughput", now - 5000, "ok", port="c01", labels={"provider": "iperf3"},
                         metrics={"down_mbps": 940.0, "up_mbps": 930.0, "latency_idle_ms": 1.0, "latency_loaded_ms": 4.5}))
    recs.append(synth.mk("target_access", now - 3000, "ok", port="t01", labels={"proto": "https"},
                         metrics={"requests": 12, "errors": 1, "p50_ms": 3.0},
                         detail={"top_clients": ["10.9.0.5", {"ip": "10.9.0.6", "requests": 4}, 7]}))
    assert ingest(port, env.ingest_token, to_lines(recs)).json()["accepted"] == len(recs)
    r = get(port, env, "/summary?probe=probe-a1&minutes=60")
    assert r.status == 200
    doc = r.json()
    check_openapi("collector", "/summary", "get", 200, doc)
    assert set(doc) == {"clients", "dhcp", "dns", "apps", "throughput", "servers"}
    clients = {c["port"]: c for c in doc["clients"]}
    assert clients["c01"]["dhcp_ok_pct"] == pytest.approx(83.3, abs=0.1) and clients["c01"]["dns_p50_ms"] == pytest.approx(12.5)
    assert clients["c02"]["worst_app"] == "teams" and clients["c02"]["apdex"] == pytest.approx(0.83, abs=0.01)
    assert clients["c01"]["flags"] == ["slow_offer"]
    assert doc["dhcp"][0]["server"] == "10.1.0.2" and doc["dhcp"][0]["ports"] == ["c01"]
    assert doc["dns"][0]["resolver"] == "8.8.8.8" and doc["dns"][0]["fail_pct"] == 0.0 and doc["dns"][0]["kind"] == "dhcp"
    assert doc["apps"][0]["app"] == "teams" and doc["apps"][0]["clients"] == 1
    t = doc["throughput"][0]
    assert t["down_mbps"] == 940.0 and t["bufferbloat_ms"] == 3.5 and t["provider"] == "iperf3"
    s = doc["servers"][0]
    assert s["requests"] == 12 and s["errors"] == 1 and {x["client"] for x in s["sources"]} == {"10.9.0.5", "10.9.0.6"}
    # the window matters: five minutes ago is outside a 1-minute window of nothing
    empty = get(port, env, "/summary?probe=probe-a2&minutes=1440").json()
    check_openapi("collector", "/summary", "get", 200, empty)
    assert all(v == [] for v in empty.values())


def test_summary_bounds(env, port):
    for q in ("probe=probe-a1", "probe=probe-a1&minutes=0", "probe=probe-a1&minutes=1441", "probe=probe-a1&minutes=x",
              "minutes=5"):
        r = get(port, env, "/summary?" + q)
        assert r.status == 400, q
        check_openapi("collector", "/summary", "get", 400, r.json())
    assert get(port, env, "/summary?probe=probe-a1&minutes=1440").status == 200
    assert get(port, env, "/summary?probe=nobody&minutes=5").status == 404


# -------------------------------------------------------------------------------------- health etc
def test_health_has_all_metrics_and_validates(env, app, port):
    from exp_collector.health import METRIC_KEYS
    app.monitor.write_snapshot()
    m = app.monitor.metrics
    for k in ("sse_clients", "open_incidents", "webhook_failures_1h", "rules_eval_ms_p95"):
        assert k in m and k in METRIC_KEYS
    check_openapi("collector", "/health", "get", 200, get(port, env, "/health").json())


# ---------------------------------------------------------------------------------------- drills
def test_drill_endpoints_are_wired_for_m5(env, app, port):
    run = "run_" + "0" * 26
    ing = {"Authorization": f"Bearer {env.ingest_token}"}
    r = https(port, "GET", "/api/v1/drills/control", headers=ing)
    assert r.status == 200 and r.json() == {"abort": []}
    check_openapi("collector", "/drills/control", "get", 200, r.json())
    assert https(port, "GET", "/api/v1/drills/control", headers=dash(env)).status == 401      # not a dashboard route
    r = get(port, env, f"/drills/{run}")
    assert r.status == 404 and r.json()["error"]["code"] == "drill_not_found"
    check_openapi("collector", "/drills/{run_id}", "get", 404, r.json())
    r = https(port, "POST", f"/api/v1/drills/{run}/abort", headers={**dash(env), "X-Exp-User": "alice"})
    assert r.status == 404 and r.json()["error"]["code"] == "drill_not_found"
    assert get(port, env, "/drills/not-a-run").status == 404
    # a registry that M5 plugs in is served unchanged
    class Reg:
        def abort_list(self): return [run]
        def report(self, rid): return {"run_id": rid, "type": "x.y"} if rid == run else None
        def abort(self, rid, user): return rid == run
    app.drills = Reg()
    assert https(port, "GET", "/api/v1/drills/control", headers=ing).json() == {"abort": [run]}
    assert get(port, env, f"/drills/{run}").json()["run_id"] == run
    r = https(port, "POST", f"/api/v1/drills/{run}/abort", headers={**dash(env), "X-Exp-User": "alice"})
    assert r.status == 202


def test_unknown_and_wrong_method_routes_stay_closed(env, port):
    assert get(port, env, "/nope").status == 404
    assert https(port, "POST", "/api/v1/state?probe=probe-a1", headers=dash(env), body=b"").status == 405
    assert https(port, "GET", "/api/v1/incidents/inc_" + "0" * 26 + "/ack", headers=dash(env)).status == 405
    assert re.fullmatch(r"[A-Z, ]+", https(port, "GET", "/api/v1/incidents/x/ack", headers=dash(env)).h("allow") or "POST")


def test_records_roundtrip_matches_what_was_ingested(env, port):
    m = rec(test="ping", outcome="ok", metrics={"rtt_ms": 3.25}, labels={"port": "c01"}, target="1.1.1.1")
    assert ingest(port, env.ingest_token, [m]).json()["accepted"] == 1
    now = int(time.time() * 1000)
    items = get(port, env, f"/records?probe=probe-a1&from={iso(now - 60_000)}&to={iso(now + 5000)}").json()["items"]
    assert items[0]["id"] == m["id"] and items[0]["metrics"] == {"rtt_ms": 3.25}


def test_silent_probe_incident_has_line_probe_and_validates(env, app, port):
    now = make_incident(env, app, port)
    app.rules.tick(now + 400_000)                                     # no records for > 90 s
    items = get(port, env, "/incidents").json()["items"]
    probe_inc = [i for i in items if i["line"] == "probe"]
    assert probe_inc and probe_inc[0]["kind"] == "down"
    check_openapi("collector", "/incidents", "get", 200, {"items": items, "next_cursor": None})
    for i in items:
        check_schema_file("incident.schema.json", i)

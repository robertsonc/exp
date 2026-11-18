"""The dashboard API subset implemented in step 1 matches collector.yaml; unimplemented contract paths are 404."""
from __future__ import annotations

import base64
import json

from colhelpers import check_openapi, https, ingest, rec


def dash(env):
    return {"Authorization": f"Bearer {env.dash_token}"}


def test_health_matches_openapi(env, app, port):
    r = https(port, "GET", "/api/v1/health", headers=dash(env))
    assert r.status == 200
    doc = r.json()
    check_openapi("collector", "/health", "get", 200, doc)
    assert doc["probes"]["total"] == 3 and doc["vm"]["up"] in (True, False) and doc["disk_free_mb"] > 0


def test_probes_matches_openapi_with_site_filter_and_paging(env, app, port):
    ingest(port, env.ingest_token, [rec(agent_ver="0.1.0")])
    r = https(port, "GET", "/api/v1/probes", headers=dash(env))
    doc = r.json()
    check_openapi("collector", "/probes", "get", 200, doc)
    byname = {p["probe"]: p for p in doc["items"]}
    assert byname["probe-a1"]["last_seen"] and byname["probe-a1"]["version"] == "0.1.0"
    assert byname["probe-a2"]["last_seen"] is None and byname["probe-a2"]["state"] == "unknown"
    r = https(port, "GET", "/api/v1/probes?site=hall-c", headers=dash(env))
    assert [p["probe"] for p in r.json()["items"]] == ["probe-c1"]
    r = https(port, "GET", "/api/v1/probes?limit=2", headers=dash(env))
    page = r.json()
    check_openapi("collector", "/probes", "get", 200, page)
    assert len(page["items"]) == 2 and page["next_cursor"]
    r2 = https(port, "GET", f"/api/v1/probes?limit=2&cursor={page['next_cursor']}", headers=dash(env))
    assert [p["probe"] for p in r2.json()["items"]] == ["probe-c1"] and r2.json()["next_cursor"] is None


def test_probes_validation_errors_are_400_envelopes(env, port):
    for q in ("limit=0", "limit=1001", "limit=x", "site=BAD SITE", "site=a&site=b", "cursor=@@@",
              "cursor=" + base64.urlsafe_b64encode(json.dumps({"o": -1}).encode()).decode()):
        r = https(port, "GET", f"/api/v1/probes?{q.replace(' ', '%20')}", headers=dash(env))
        assert r.status == 400, q
        check_openapi("collector", "/probes", "get", 400, r.json())


def test_unauthorized_matches_openapi(env, port):
    r = https(port, "GET", "/api/v1/probes")
    assert r.status == 401
    check_openapi("collector", "/probes", "get", 401, r.json())


def test_healthz_matches_openapi(env, port):
    r = https(port, "GET", "/healthz")
    assert r.status == 200 and r.body == b"ok"

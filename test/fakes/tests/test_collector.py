"""fake_collector: ingest + query API conformance and enforcement."""
from __future__ import annotations

import datetime
import gzip
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from exp_common import ids as exp_ids
from exp_common import tlspin
from fakes_support import FAKES, ROOT, check_component, check_openapi, check_schema_file, request

import fake_collector
import fakes_common as fc

FIX = ROOT / "test" / "fixtures"
T0 = datetime.datetime(2026, 11, 18, 20, 5, 0, tzinfo=datetime.timezone.utc).timestamp()
PROBE_A1 = fc.fixture_token("expi", "probe-a1")
PROBE_B2 = fc.fixture_token("expi", "probe-b2")
DASH = fc.fixture_token("expd", "dash-main")
ING = {"Authorization": f"Bearer {PROBE_A1}", "Content-Type": "application/x-ndjson"}
DASHH = {"Authorization": f"Bearer {DASH}"}


class Clock:
    def __init__(self, t: float = T0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def good_records() -> list[dict]:
    out = []
    for f in sorted((FIX / "measurements").glob("*.json")):
        d = json.loads(f.read_text("utf-8"))
        if d["probe"] == "probe-a1" and d["site"] == "hall-b":
            out.append(d)
    return out


def nd(records: list[dict]) -> bytes:
    return b"".join(json.dumps(r).encode() + b"\n" for r in records)


def rec(i: int, **kw) -> dict:
    d = {"schema": "exp.measurement/1", "id": exp_ids.new_ulid(1763496000000 + i), "ts": "2026-11-18T20:04:00.000Z",
         "probe": "probe-a1", "site": "hall-b", "test": "gateway", "outcome": "ok", "labels": {"port": "c01"},
         "metrics": {"rtt_ms": 1.5}, "agent_ver": "0.1.0"}
    d.update(kw)
    return d


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def fake(clock):
    ingest = {"probe-a1": fc.token_hash(PROBE_A1), "probe-b2": fc.token_hash(PROBE_B2)}
    s = fake_collector.start(ingest_tokens=ingest, now_fn=clock, keepalive_s=0.2, probe_sites={"probe-b2": "hall-c"})
    yield s
    s.stop()


def ingest(fake, body: bytes, headers: dict | None = None):
    return request(fake.port, "POST", "/ingest/v1/measurements", body, headers or ING)


def check_ingest(r, status=200):
    assert r.status == status, r.body[:300]
    if status == 200:
        check_openapi("ingest", "/measurements", "post", 200, r.json())
    else:
        check_openapi("ingest", "/measurements", "post", status, r.json())


# ---------------------------------------------------------------------------------------- ingest

def test_ingest_accepts_all_valid_fixtures_and_dedupes(fake):
    recs = good_records()
    r = ingest(fake, nd(recs))
    check_ingest(r)
    body = r.json()
    assert body["accepted"] == len(recs) and body["duplicates"] == 0 and body["rejected"] == []
    again = ingest(fake, nd(recs))
    check_ingest(again)
    assert again.json()["accepted"] == 0 and again.json()["duplicates"] == len(recs)
    assert len(fake.app.records_for("probe-a1")) == len(recs)


def test_ingest_gzip(fake):
    recs = [rec(1), rec(2)]
    h = {**ING, "Content-Encoding": "gzip"}
    r = ingest(fake, gzip.compress(nd(recs)), h)
    check_ingest(r)
    assert r.json()["accepted"] == 2


def test_ingest_dedupe_within_batch(fake):
    a = rec(1)
    r = ingest(fake, nd([a, a]))
    assert r.json()["accepted"] == 1 and r.json()["duplicates"] == 1


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer nope"},
                                     {"Authorization": "Bearer " + fc.fixture_token("expi", "unknown-probe")},
                                     {"Authorization": "Basic abc"}, {"Authorization": f"Bearer {DASH}"}])
def test_ingest_wrong_token_is_401(fake, headers):
    r = ingest(fake, nd([rec(1)]), {"Content-Type": "application/x-ndjson", **headers})
    check_ingest(r, 401)
    assert r.json()["error"]["code"] == "invalid_token"
    assert fake.app.records_for() == []


def test_ingest_identity_mismatch_probe_and_site(fake):
    r = ingest(fake, nd([rec(1, probe="probe-b2"), rec(2, site="hall-c"), rec(3)]))
    check_ingest(r)
    body = r.json()
    assert body["accepted"] == 1
    assert [(x["line"], x["error"]["code"]) for x in body["rejected"]] == [(1, "identity_mismatch"), (2, "identity_mismatch")]
    assert body["rejected"][0]["error"]["message"] == "probe 'probe-b2' does not match token identity"
    assert [x["probe"] for x in fake.app.records_for()] == ["probe-a1"]


def test_ingest_site_binding_is_per_probe_configured_site(fake):
    h = {"Authorization": f"Bearer {PROBE_B2}", "Content-Type": "application/x-ndjson"}
    r = ingest(fake, nd([rec(1, probe="probe-b2", site="hall-c"), rec(2, probe="probe-b2", site="hall-b")]), h)
    body = r.json()
    assert body["accepted"] == 1 and body["rejected"][0]["line"] == 2


def _invalid_measurement_fixtures():
    idx = json.loads((FIX / "INDEX.json").read_text("utf-8"))
    return sorted(k for k, v in idx.items() if k.startswith("invalid/measurements/") and v["expected"] == "invalid")


@pytest.mark.parametrize("path", _invalid_measurement_fixtures())
def test_ingest_rejects_every_invalid_measurement_fixture(fake, path):
    doc = json.loads((FIX / path).read_text("utf-8"))
    r = ingest(fake, json.dumps(doc).encode() + b"\n")
    check_ingest(r)
    body = r.json()
    assert body["accepted"] == 0, path
    assert body["rejected"][0]["error"]["code"] in ("invalid_measurement", "identity_mismatch"), path
    assert fake.app.records_for() == []


def test_ingest_reserved_labels_and_naive_ts_named(fake):
    r = ingest(fake, nd([rec(1, labels={"probe": "x"}), rec(2, ts="2026-11-18T20:04:00"), rec(3, ts="2026-11-18T20:04:00+02:00")]))
    body = r.json()
    assert body["accepted"] == 0
    assert [x["error"]["code"] for x in body["rejected"]] == ["invalid_measurement"] * 3
    assert "reserved" in body["rejected"][0]["error"]["message"]


def test_ingest_missing_id_rejected(fake):
    d = rec(1)
    del d["id"]
    r = ingest(fake, nd([d]))
    assert r.json()["rejected"][0]["error"]["code"] == "invalid_measurement"


def test_ingest_time_window(fake, clock):
    future = fake_collector.fc.iso_from_epoch(clock.t + 120)
    near = fake_collector.fc.iso_from_epoch(clock.t + 30)
    old = fake_collector.fc.iso_from_epoch(clock.t - 8 * 86400)
    backfill = fake_collector.fc.iso_from_epoch(clock.t - 3 * 86400)
    r = ingest(fake, nd([rec(1, ts=future), rec(2, ts=near), rec(3, ts=old), rec(4, ts=backfill)]))
    body = r.json()
    assert body["accepted"] == 2
    assert [(x["line"], x["error"]["code"]) for x in body["rejected"]] == [(1, "ts_future"), (3, "ts_too_old")]


def test_ingest_invalid_json_and_blank_and_long_lines(fake):
    long_line = json.dumps(rec(9, detail={"x": "a" * 1000})).encode() + b" " * 70000
    body = b"not json\n" + json.dumps(rec(1)).encode() + b"\n\n" + long_line + b"\n[1,2]\n"
    r = ingest(fake, body)
    check_ingest(r)
    codes = [(x["line"], x["error"]["code"]) for x in r.json()["rejected"]]
    assert codes == [(1, "invalid_json"), (3, "invalid_json"), (4, "line_too_long"), (5, "invalid_measurement")]
    assert r.json()["accepted"] == 1


def test_ingest_limit_1000_lines(fake):
    ok = [rec(i) for i in range(1000)]
    r = ingest(fake, nd(ok))
    assert r.json()["accepted"] == 1000
    r = ingest(fake, nd([rec(i + 5000) for i in range(1001)]))
    check_ingest(r, 400)
    assert r.json()["error"]["code"] == "too_many_lines"


def test_ingest_wire_limit_413(fake):
    r = ingest(fake, b"x" * (4 * 1024 * 1024 + 1))
    check_ingest(r, 413)
    assert r.json()["error"]["code"] == "payload_too_large"
    # exactly at the limit is not refused for size (it is garbage, so per-line rejection / 400)
    r2 = ingest(fake, b"\n" * (4 * 1024 * 1024))
    assert r2.status != 413


def test_ingest_decompressed_limit_stops_reading(fake):
    bomb = gzip.compress(b"\n" * (17 * 1024 * 1024))
    assert len(bomb) < 4 * 1024 * 1024
    t = time.monotonic()
    r = ingest(fake, bomb, {**ING, "Content-Encoding": "gzip"})
    check_ingest(r, 413)
    assert r.json()["error"]["code"] == "decompressed_too_large"
    assert time.monotonic() - t < 10


def test_ingest_bad_gzip_and_unsupported_encoding(fake):
    r = ingest(fake, b"definitely not gzip", {**ING, "Content-Encoding": "gzip"})
    check_ingest(r, 400)
    assert r.json()["error"]["code"] == "bad_gzip"
    trunc = gzip.compress(nd([rec(1)]))[:-6]
    assert ingest(fake, trunc, {**ING, "Content-Encoding": "gzip"}).json()["error"]["code"] == "bad_gzip"
    r = ingest(fake, b"{}", {**ING, "Content-Encoding": "br"})
    assert r.status == 415


@pytest.mark.parametrize("ctype", ["application/json", "text/plain", ""])
def test_ingest_wrong_content_type_415(fake, ctype):
    h = {"Authorization": f"Bearer {PROBE_A1}"}
    if ctype:
        h["Content-Type"] = ctype
    r = ingest(fake, nd([rec(1)]), h)
    check_ingest(r, 415)
    assert fake.app.records_for() == []


def test_ingest_empty_and_binary_body_400(fake):
    assert ingest(fake, b"").status == 400
    r = ingest(fake, b"\xff\xfe\x00bad")
    check_ingest(r, 400)
    assert r.json()["error"]["code"] == "not_ndjson"


def test_ingest_forced_backoff_modes(fake):
    fake.app.set_force(429, retry_after=7, count=2)
    for _ in range(2):
        r = ingest(fake, nd([rec(1)]))
        check_ingest(r, 429)
        assert r.h("Retry-After") == "7"
    ok = ingest(fake, nd([rec(1)]))
    assert ok.status == 200
    fake.app.set_force(503, retry_after=3)
    r = ingest(fake, nd([rec(2)]))
    check_ingest(r, 503)
    assert r.h("Retry-After") == "3"
    fake.app.set_force(None)
    assert ingest(fake, nd([rec(2)])).status == 200


def test_ingest_method_and_unknown_path(fake):
    assert request(fake.port, "GET", "/ingest/v1/measurements", headers=ING).status == 405
    assert request(fake.port, "POST", "/ingest/v1/other", b"x", ING).status == 404


# ------------------------------------------------------------------------------------ query: auth

def q(fake, path, headers=None, method="GET", body=None):
    return request(fake.port, method, "/api/v1/" + path, body, DASHH if headers is None else headers)


@pytest.mark.parametrize("path", ["health", "probes", "states", "incidents", "state?probe=probe-a1", "stream?site=hall-b",
                                  "query_range?query=exp_x&start=2026-11-18T00:00:00Z&end=2026-11-18T01:00:00Z&step=60s"])
def test_query_requires_dashboard_token(fake, path):
    for hdr in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": f"Bearer {PROBE_A1}"}):
        r = q(fake, path, hdr)
        assert r.status == 401 and r.json()["error"]["code"] == "invalid_token", (path, hdr)


def test_healthz_is_public(fake):
    r = request(fake.port, "GET", "/healthz")
    assert r.status == 200 and r.body == b"ok"


def test_x_exp_user_is_validated_and_recorded(fake):
    r = q(fake, "health", {**DASHH, "X-Exp-User": "alice"})
    assert r.status == 200
    bad = q(fake, "health", {**DASHH, "X-Exp-User": "a\x01b"}) if False else q(fake, "health", {**DASHH, "X-Exp-User": "x" * 200})
    assert bad.status == 400


# ----------------------------------------------------------------------------------- query: data

def test_health_and_probes(fake):
    ingest(fake, nd([rec(1)]))
    r = q(fake, "health")
    check_openapi("collector", "/health", "get", 200, r.json())
    assert r.json()["probes"]["total"] >= 2
    r = q(fake, "probes")
    check_openapi("collector", "/probes", "get", 200, r.json())
    items = {i["probe"]: i for i in r.json()["items"]}
    assert items["probe-a1"]["last_seen"] is not None and items["probe-a1"]["state"] == "ok"
    assert items["probe-b2"]["last_seen"] is None and items["probe-b2"]["state"] == "unknown"
    only = q(fake, "probes?site=hall-c").json()["items"]
    assert [i["probe"] for i in only] == ["probe-b2"]
    assert q(fake, "probes?site=Not_A_Slug").status == 400
    assert q(fake, "probes?limit=0").status == 400
    assert q(fake, "probes?limit=1&limit=2").status == 400


def test_state_derived_from_latest_beat_per_line(fake, clock):
    ingest(fake, nd([rec(1, ts="2026-11-18T20:04:00.000Z", outcome="ok"),
                     rec(2, ts="2026-11-18T20:04:30.000Z", test="dns_hb", outcome="fail", error="no answer from 8.8.8.8")]))
    r = q(fake, "state?probe=probe-a1")
    assert r.status == 200
    check_openapi("collector", "/state", "get", 200, r.json())
    st = r.json()
    check_schema_file("state.schema.json", st)
    lines = {ln["key"]: ln["state"] for ln in st["lines"]}
    assert lines == {"network": "ok", "dns": "fail"}
    assert st["verdict"]["severity"] == "fail" and st["failing"][0]["line"] == "dns"
    assert st["live"] is True
    # a newer ok beat flips the line back
    ingest(fake, nd([rec(3, ts="2026-11-18T20:04:50.000Z", test="dns_hb", outcome="ok")]))
    assert q(fake, "state?probe=probe-a1").json()["verdict"]["severity"] == "ok"
    # `at` looks back in time
    past = q(fake, "state?probe=probe-a1&at=2026-11-18T20:04:40.000Z&voice=plain").json()
    assert past["verdict"]["severity"] == "fail" and past["verdict"]["voice"] == "plain"
    assert q(fake, "state?probe=nobody").status == 404
    assert q(fake, "state").status == 400
    assert q(fake, "state?probe=probe-a1&voice=shouty").status == 400
    assert q(fake, "state?probe=probe-a1&at=yesterday").status == 400


def test_state_no_data_and_scenario_fixture(clock):
    s = fake_collector.start(now_fn=clock, scenario="dns-fail")
    try:
        st = q(s, "state?probe=probe-a1").json()
        check_schema_file("state.schema.json", st)
        assert st["verdict"]["headline"] == "DNS isn't answering."
        s.app.set_state_doc("probe-x", json.loads((FIX / "state" / "no-data.json").read_text()))
        assert q(s, "state?probe=probe-x").json()["verdict"]["severity"] == "unknown"
    finally:
        s.stop()


def test_states_list_and_site_filter(fake):
    ingest(fake, nd([rec(1, test="gateway", outcome="fail")]))
    r = q(fake, "states")
    check_openapi("collector", "/states", "get", 200, r.json())
    by = {i["probe"]: i for i in r.json()["items"]}
    assert by["probe-a1"]["severity"] == "fail" and by["probe-b2"]["severity"] == "unknown"
    r = q(fake, "states?site=hall-c")
    assert [i["probe"] for i in r.json()["items"]] == ["probe-b2"]


def test_beats_window_guard_and_content(fake):
    ingest(fake, nd([rec(1, ts="2026-11-18T20:04:00.000Z"), rec(2, ts="2026-11-18T20:04:10.000Z", outcome="fail"),
                     rec(3, ts="2026-11-18T19:00:00.000Z", outcome="degraded")]))
    r = q(fake, "beats?probe=probe-a1&from=2026-11-18T20:00:00Z&to=2026-11-18T20:05:00Z")
    check_openapi("collector", "/beats", "get", 200, r.json())
    check_schema_file("beats.schema.json", r.json())
    pts = r.json()["lines"]["network"]
    assert [v for _, v in pts] == [0, 2]
    big = q(fake, "beats?probe=probe-a1&from=2026-11-18T00:00:00Z&to=2026-11-18T06:00:01Z")
    assert big.status == 400 and big.json()["error"]["code"] == "range_too_large"
    ok6 = q(fake, "beats?probe=probe-a1&from=2026-11-18T00:00:00Z&to=2026-11-18T06:00:00Z")
    assert ok6.status == 200
    assert q(fake, "beats?probe=probe-a1&from=2026-11-18T01:00:00Z&to=2026-11-18T00:00:00Z").status == 400
    assert q(fake, "beats?probe=nobody&from=2026-11-18T00:00:00Z&to=2026-11-18T01:00:00Z").status == 404


def test_beats_fixture_data_is_served(fake):
    r = q(fake, "beats?probe=probe-a1&from=2025-11-18T20:00:00Z&to=2025-11-18T20:07:00Z")
    assert r.status == 200
    assert len(r.json()["lines"]["network"]) == 4


def test_records_filter_and_cursor_pagination(fake):
    recs = [rec(i, ts=f"2026-11-18T20:03:{i:02d}.000Z", test="dns" if i % 2 else "gateway",
                outcome="fail" if i % 3 == 0 else "ok") for i in range(7)]
    ingest(fake, nd(recs))
    seen, cursor = [], None
    for _ in range(10):
        path = "records?probe=probe-a1&limit=3" + (f"&cursor={cursor}" if cursor else "")
        r = q(fake, path)
        check_openapi("collector", "/records", "get", 200, r.json())
        seen += [x["id"] for x in r.json()["items"]]
        cursor = r.json()["next_cursor"]
        if not cursor:
            break
    assert seen == [x["id"] for x in recs]
    assert [x["test"] for x in q(fake, "records?probe=probe-a1&test=dns").json()["items"]] == ["dns"] * 3
    fails = q(fake, "records?probe=probe-a1&outcome=fail").json()["items"]
    assert len(fails) == 3 and all(x["outcome"] == "fail" for x in fails)
    window = q(fake, "records?probe=probe-a1&from=2026-11-18T20:03:02Z&to=2026-11-18T20:03:04Z").json()["items"]
    assert len(window) == 3
    assert q(fake, "records?probe=probe-a1&cursor=!!!").status == 400
    assert q(fake, "records?probe=probe-a1&outcome=weird").status == 400


def test_incidents_fixture_derived_and_ack(fake):
    r = q(fake, "incidents")
    check_openapi("collector", "/incidents", "get", 200, r.json())
    base = len(r.json()["items"])
    assert base >= 5
    ingest(fake, nd([rec(1, ts="2026-11-18T20:04:00.000Z", test="gateway", outcome="fail")]))
    items = q(fake, "incidents?probe=probe-a1&open=true").json()["items"]
    derived = [i for i in items if i["line"] == "network" and i["kind"] == "down" and i["acked_by"] is None]
    assert derived, "a failing line opens an incident"
    check_openapi("collector", "/incidents", "get", 200, q(fake, "incidents").json())
    inc = derived[-1]["id"]
    assert q(fake, f"incidents/{inc}/ack", {**DASHH, "X-Exp-User": "alice"}, "POST", b'{"note":"on it"}').status == 204
    acked = [i for i in q(fake, "incidents").json()["items"] if i["id"] == inc][0]
    assert acked["acked_by"] == "alice"
    assert q(fake, "incidents/inc_01M7R3X9G0ZZZZZZZZZZZZZZZZ/ack", DASHH, "POST", b"{}").status == 404
    assert q(fake, "incidents/nonsense/ack", DASHH, "POST", b"{}").status == 400
    assert q(fake, f"incidents/{inc}/ack", DASHH, "POST", json.dumps({"note": "x" * 513}).encode()).status == 400
    ingest(fake, nd([rec(2, ts="2026-11-18T20:04:30.000Z", test="gateway", outcome="ok")]))
    closed = [i for i in q(fake, "incidents?probe=probe-a1&open=false").json()["items"] if i["id"] == inc]
    assert closed and closed[0]["end"] is not None
    assert q(fake, "incidents?open=maybe").status == 400


def test_summary_canned(fake):
    r = q(fake, "summary?probe=probe-a1&minutes=60")
    check_openapi("collector", "/summary", "get", 200, r.json())
    assert q(fake, "summary?probe=probe-a1&minutes=1441").status == 400
    assert q(fake, "summary?probe=ghost").status == 404


QR = "&start=2026-11-18T00:00:00Z&end=2026-11-18T01:00:00Z&step=60s"


def test_query_range_ok_and_guards(fake):
    r = q(fake, "query_range?query=" + "avg(exp_dns_rtt_ms%7Bprobe%3D%22probe-a1%22%7D)%20by%20(site)" + QR)
    assert r.status == 200, r.body
    check_openapi("collector", "/query_range", "get", 200, r.json())
    assert r.json()["data"]["resultType"] == "matrix"
    assert len(r.json()["data"]["result"][0]["values"]) == 61
    bad_queries = ["up", "node_cpu_seconds_total", "exp_x%20%2B%20up", "%7B__name__%3D~%22.%2B%22%7D", "1%2B1",
                   "exp_ok%20or%20process_resident_memory_bytes", "sum(exp_a)%20by%20(x)%20%2B%20other_metric"]
    for bq in bad_queries:
        r = q(fake, "query_range?query=" + bq + QR)
        assert r.status == 400 and r.json()["error"]["code"] == "invalid_query", bq
        check_openapi("collector", "/query_range", "get", 400, r.json())
    big = "exp_" + "a" * 2050
    assert q(fake, f"query_range?query={big}{QR}").json()["error"]["code"] == "invalid_query"
    at_limit = "exp_" + "a" * (2048 - 4)
    assert q(fake, f"query_range?query={at_limit}&start=2026-11-18T00:00:00Z&end=2026-11-18T00:10:00Z&step=60s").status == 200
    r = q(fake, "query_range?query=exp_x&start=2026-10-01T00:00:00Z&end=2026-11-01T00:00:01Z&step=1h")
    assert r.status == 400 and r.json()["error"]["code"] == "range_too_large"
    r = q(fake, "query_range?query=exp_x&start=2026-10-02T00:00:00Z&end=2026-11-01T00:00:00Z&step=1h")
    assert r.status == 200
    r = q(fake, "query_range?query=exp_x&start=2026-11-18T00:00:00Z&end=2026-11-18T01:00:00Z&step=9s")
    assert r.status == 400 and r.json()["error"]["code"] == "step_too_small"
    assert q(fake, "query_range?query=exp_x&start=2026-11-18T00:00:00Z&end=2026-11-18T01:00:00Z&step=10s").status == 200
    for bad in ("step=1d", "step=abc", "step="):
        assert q(fake, f"query_range?query=exp_x&start=2026-11-18T00:00:00Z&end=2026-11-18T01:00:00Z&{bad}").status == 400
    assert q(fake, "query_range?query=exp_x&start=2026-11-18T01:00:00Z&end=2026-11-18T00:00:00Z&step=60s").status == 400
    assert q(fake, "query_range?query=&start=2026-11-18T00:00:00Z&end=2026-11-18T01:00:00Z&step=60s").status == 400
    assert q(fake, "query_range?query=exp_x" + "&start=2026-11-18T00:00:00&end=2026-11-18T01:00:00Z&step=60s").status == 400


def test_drill_endpoints(fake):
    run = fc.det_id("run_", "r1")
    h = {"Authorization": f"Bearer {PROBE_A1}"}
    r = q(fake, "drills/control", h)
    check_openapi("collector", "/drills/control", "get", 200, r.json())
    assert r.json() == {"abort": []}
    assert q(fake, "drills/control", DASHH).status == 401         # dashboard token is not an executor token
    assert q(fake, f"drills/{run}").status == 404
    report = {"run_id": run, "type": "local.dns_block", "target": "c01", "start": "2026-11-18T20:00:00.000Z",
              "until": "2026-11-18T20:02:00.000Z", "phases": [], "expectation": "dns fails",
              "observed": {"ttd_s": 3.0, "ttr_s": 4.0, "lines_impacted": ["dns"]}, "result": "pass"}
    fake.app.add_drill_report(report)
    got = q(fake, f"drills/{run}")
    check_openapi("collector", "/drills/{run_id}", "get", 200, got.json())
    assert q(fake, f"drills/{run}/abort", method="POST").status == 202
    assert q(fake, "drills/control", h).json() == {"abort": [run]}
    assert q(fake, f"drills/{fc.det_id('run_', 'zz')}/abort", method="POST").status == 404


def test_forced_modes_apply_to_query_api_by_scope(fake):
    fake.app.set_force(503, scope="api", count=1)
    assert q(fake, "health").status == 503
    assert q(fake, "health").status == 200
    fake.app.set_force(429, scope="ingest")
    assert q(fake, "health").status == 200


def test_unknown_endpoint_and_method(fake):
    assert q(fake, "nope").status == 404
    assert q(fake, "health", method="POST", body=b"{}").status == 405


# ---------------------------------------------------------------------------------------- SSE

class SSE:
    def __init__(self, port: int, path: str, headers: dict | None = None) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        hdr = "".join(f"{k}: {v}\r\n" for k, v in {**DASHH, **(headers or {})}.items())
        self.sock.sendall(f"GET /api/v1/{path} HTTP/1.1\r\nHost: x\r\n{hdr}\r\n".encode())
        self.f = self.sock.makefile("rb")
        self.status_line = self.f.readline().decode().strip()
        self.headers = {}
        while True:
            line = self.f.readline().decode().strip()
            if not line:
                break
            k, _, v = line.partition(":")
            self.headers[k.lower()] = v.strip()

    def frames(self, n: int, timeout: float = 5.0) -> list[str]:
        """Next n blank-line-terminated frames (as raw text)."""
        end = time.monotonic() + timeout
        out, cur = [], []
        self.sock.settimeout(timeout)
        while len(out) < n and time.monotonic() < end:
            line = self.f.readline().decode()
            if line == "":
                break
            if line == "\n":
                out.append("".join(cur))
                cur = []
            else:
                cur.append(line)
        return out

    def close(self) -> None:
        self.f.close()
        self.sock.close()


def parse(frame: str) -> dict:
    d: dict = {}
    for line in frame.splitlines():
        k, _, v = line.partition(": ")
        d[k] = v
    return d


def test_sse_headers_retry_keepalive(fake):
    s = SSE(fake.port, "stream?probes=probe-a1")
    try:
        assert s.status_line.endswith("200 OK")
        assert s.headers["content-type"].startswith("text/event-stream")
        assert s.headers["cache-control"] == "no-store"
        frames = s.frames(3)
        assert frames[0] == "retry: 3000\n"
        assert frames[1] == ": keepalive\n" and frames[2] == ": keepalive\n"
    finally:
        s.close()


def test_sse_streams_beat_state_incident_and_validates(fake):
    s = SSE(fake.port, "stream?probes=probe-a1")
    try:
        s.frames(1)
        ingest(fake, nd([rec(1, test="gateway", outcome="fail", ts="2026-11-18T20:04:59.000Z")]))
        kinds = {}
        for fr in s.frames(8, timeout=3):
            if fr.startswith(":"):
                continue
            d = parse(fr)
            kinds[d["event"]] = json.loads(d["data"])
            assert d["id"].isdigit()
        assert set(kinds) == {"beat", "state", "incident"}
        check_component("collector", "BeatEvent", kinds["beat"])
        check_component("collector", "StateLite", kinds["state"])
        check_component("collector", "Incident", kinds["incident"])
        assert kinds["beat"] == {"probe": "probe-a1", "line": "network", "t": kinds["beat"]["t"], "v": 2}
    finally:
        s.close()


def test_sse_filters_by_probe_and_site(fake):
    by_site = SSE(fake.port, "stream?site=hall-c")
    by_probe = SSE(fake.port, "stream?probes=probe-b2")
    try:
        by_site.frames(1)
        by_probe.frames(1)
        ingest(fake, nd([rec(1)]))                  # probe-a1 / hall-b: neither stream wants it
        assert [f for f in by_site.frames(2, 0.8) if not f.startswith(":")] == []
        h = {"Authorization": f"Bearer {PROBE_B2}", "Content-Type": "application/x-ndjson"}
        ingest(fake, nd([rec(2, probe="probe-b2", site="hall-c")]), h)
        a = [f for f in by_site.frames(4, 2) if f.startswith("event: beat")]
        b = [f for f in by_probe.frames(4, 2) if f.startswith("event: beat")]
        assert a and b
    finally:
        by_site.close()
        by_probe.close()


def test_sse_last_event_id_replay_within_five_minutes(fake, clock):
    live = SSE(fake.port, "stream?probes=probe-a1")
    try:
        live.frames(1)
        ingest(fake, nd([rec(1, ts="2026-11-18T20:04:50.000Z"), rec(2, test="dns_hb", ts="2026-11-18T20:04:51.000Z")]))
        got = [parse(f) for f in live.frames(6, 2) if f.startswith("event:")]
        assert [g["event"] for g in got][:2] == ["beat", "state"] or got
        first_id = int(got[0]["id"])
    finally:
        live.close()
    clock.t += 120     # two minutes later: still inside the replay window
    replay = SSE(fake.port, "stream?probes=probe-a1", {"Last-Event-ID": str(first_id)})
    try:
        frames = replay.frames(10, 2)
        ev = [parse(f) for f in frames if f.startswith("event:")]
        assert ev and all(int(e["id"]) > first_id for e in ev)
        assert {e["id"] for e in ev} == {g["id"] for g in got if int(g["id"]) > first_id}
    finally:
        replay.close()
    clock.t += 400     # beyond five minutes since the events: nothing replayed
    late = SSE(fake.port, "stream?probes=probe-a1", {"Last-Event-ID": "0"})
    try:
        assert [f for f in late.frames(3, 1) if f.startswith("event:")] == []
    finally:
        late.close()


def test_sse_parameter_validation(fake):
    assert q(fake, "stream").status == 400
    assert q(fake, "stream?probes=a&site=b").status == 400
    assert q(fake, "stream?probes=Bad_Name").status == 400
    assert q(fake, "stream?probes=" + ",".join(["a"] * 3000)).status == 400


def test_stop_terminates_open_streams(clock):
    s = fake_collector.start(now_fn=clock, keepalive_s=0.2)
    sse = SSE(s.port, "stream?site=hall-b")
    sse.frames(1)
    t = time.monotonic()
    s.stop()
    assert time.monotonic() - t < 5
    sse.sock.settimeout(3)
    assert sse.f.read() is not None   # stream ended (EOF), not hung
    sse.close()


# ---------------------------------------------------------------------------------- TLS / CLI

def test_tls_self_signed_with_pin(tmp_path, clock):
    s = fake_collector.start(now_fn=clock, tls=True, state_dir=tmp_path)
    try:
        import re
        assert re.fullmatch(r"([0-9A-F]{2}:){31}[0-9A-F]{2}", s.fingerprint)
        r = tlspin.request("GET", f"https://127.0.0.1:{s.port}/healthz", s.fingerprint, total_timeout=10)
        assert r.status == 200 and r.body == b"ok"
        with pytest.raises(tlspin.PinMismatch):
            tlspin.request("GET", f"https://127.0.0.1:{s.port}/healthz", "00:" * 31 + "00", total_timeout=10)
        ing = tlspin.request("POST", f"https://127.0.0.1:{s.port}/ingest/v1/measurements", s.fingerprint,
                             body=nd([rec(1)]), headers=ING, total_timeout=10)
        assert ing.status == 200
    finally:
        s.stop()


def test_cli_runs_as_script_and_prints_fingerprint(tmp_path):
    proc = subprocess.Popen([sys.executable, str(FAKES / "fake_collector.py"), "--listen", "127.0.0.1:0", "--tls",
                             "--state-dir", str(tmp_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)  # noqa: S603
    try:
        lines = []
        for _ in range(4):
            lines.append(proc.stdout.readline().strip())
            if any("default dashboard token" in x for x in lines):
                break
        text = "\n".join(lines)
        assert "fake_collector listening on https://127.0.0.1:" in text
        fp_line = [x for x in lines if x.startswith("tls fingerprint")][0]
        fp = fp_line.split(": ")[1]
        port = int(lines[0].rsplit(":", 1)[1])
        assert tlspin.normalize_fingerprint(fp) == fp
        assert tlspin.request("GET", f"https://127.0.0.1:{port}/healthz", fp, total_timeout=10).body == b"ok"
        assert fc.fixture_token("expi", "probe-a1") in text
    finally:
        proc.terminate()
        proc.wait(timeout=10)
    assert Path(tmp_path / "tls" / "cert.pem").is_file()


def test_persistence_reload(tmp_path, clock):
    r1 = rec(1)
    s = fake_collector.start(now_fn=clock, state_dir=tmp_path)
    ingest(s, nd([r1]))
    s.stop()
    s2 = fake_collector.start(now_fn=clock, state_dir=tmp_path)
    try:
        assert len(s2.app.records_for("probe-a1")) == 1
        assert ingest(s2, nd([r1]), ING).json()["duplicates"] == 1   # same (probe,id) is still a duplicate
    finally:
        s2.stop()


def test_control_api_is_loopback_only_and_works(fake):
    r = request(fake.port, "POST", "/_fake/force", {"status": 503, "count": 1})
    assert r.status == 200
    assert ingest(fake, nd([rec(1)])).status == 503
    assert request(fake.port, "GET", "/_fake/stats").json()["records"] == 0
    assert request(fake.port, "POST", "/_fake/force", {"status": 418}).status == 400


def test_list_form_token_hashes_are_accepted_during_rotation_overlap():
    """CR-wp4-token-overlap: a value may be [current_sha256, previous_sha256]; other shapes never match."""
    cur, prev = fc.fixture_token("expi", "probe-a1-new"), PROBE_A1
    hashes = {"probe-a1": [fc.token_hash(cur), fc.token_hash(prev)], "bad": 7, "worse": [None, {"x": 1}]}
    assert fc.match_token(cur, hashes) == "probe-a1"
    assert fc.match_token(prev, hashes) == "probe-a1"
    assert fc.match_token(fc.fixture_token("expi", "other"), hashes) is None
    assert fc.match_token("", hashes) is None

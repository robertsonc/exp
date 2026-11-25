"""Federation over three fake collectors (spec section 7 items 5 and 6)."""
from __future__ import annotations

import json
import socket
import threading
import time

from exp_common import tlspin

from conftest import DASH_TOKEN


def direct(world, cid: str, path: str):
    f = world.fakes[cid]
    r = tlspin.request("GET", f"{f.base_url}/api/v1/{path}", f.fingerprint,
                       headers={"Authorization": f"Bearer {DASH_TOKEN}"}, connect_timeout=3,
                       read_timeout=5, total_timeout=5)
    return r.status, r.body


def incident(iid: str, probe: str, site: str, start: str) -> dict:
    return {"id": iid, "probe": probe, "site": site, "line": "dns", "kind": "down", "start": start,
            "end": None, "where": {"seg": "edge", "ip": "10.1.0.2"}, "facts": ["x"], "folded_into": None,
            "acked_by": None, "link": f"https://10.0.0.1/probe/{probe}"}


def by_id(doc) -> dict:
    return {c["collector_id"]: c for c in doc["collectors"]}


def test_probes_merged_across_three_collectors(world):
    c = world.as_user("vera")
    r = c.get("/api/v1/probes")
    assert r.status == 200
    doc = r.json()
    assert {i["probe"] for i in doc["items"]} == {"probe-a1", "probe-b1", "probe-c1"}
    assert {(i["probe"], i["collector_id"], i["site"]) for i in doc["items"]} == {
        ("probe-a1", "col-a", "hall-a"), ("probe-b1", "col-b", "hall-b"), ("probe-c1", "col-c", "hall-c")}
    assert [x["ok"] for x in doc["collectors"]] == [True, True, True]
    assert all("error" not in x for x in doc["collectors"])
    assert doc["next_cursor"] is None
    assert [i["site"] for i in doc["items"]] == sorted(i["site"] for i in doc["items"])


def test_site_filter_is_forwarded(world):
    c = world.as_user("vera")
    items = c.get("/api/v1/probes?site=hall-b").json()["items"]
    assert [i["probe"] for i in items] == ["probe-b1"]


def test_one_collector_down_gives_partial_results_flagged(world):
    c = world.as_user("vera")
    world.fakes["col-b"].stop()
    r = c.get("/api/v1/probes")
    assert r.status == 200
    doc = r.json()
    assert {i["probe"] for i in doc["items"]} == {"probe-a1", "probe-c1"}
    st = by_id(doc)
    assert st["col-b"]["ok"] is False and st["col-b"]["error"] in ("unreachable", "timeout")
    assert st["col-a"]["ok"] and st["col-c"]["ok"] and "error" not in st["col-a"]
    for ep in ("states", "incidents", "health"):
        d = c.get(f"/api/v1/{ep}").json()
        assert by_id(d)["col-b"]["ok"] is False and by_id(d)["col-a"]["ok"] is True
    # the board for the healthy collectors still works; the down one reports which collector failed
    assert c.get("/api/v1/state?probe=probe-a1").status == 200
    down = c.get("/api/v1/state?probe=probe-b1")
    assert down.status == 502
    err = down.json()["error"]
    assert err["code"] == "collector_unreachable" and err["details"]["collector_id"] == "col-b"
    # collectors endpoint + health reflect it
    assert not [x for x in c.get("/api/v1/collectors").json()["collectors"] if x["collector_id"] == "col-b"][0]["ok"]
    h = world.app.health()
    assert h["status"] == "degraded" and h["metrics"]["collectors_reachable"] == 2
    assert "col-b" in h["detail"]


def test_down_collector_comes_back(world):
    c = world.as_user("vera")
    f = world.fakes["col-b"]
    port = f.port
    f.stop()
    assert not by_id(c.get("/api/v1/probes").json())["col-b"]["ok"]
    f.httpd = None
    f._want_port = port
    f.start()
    assert world.wait_for(lambda: by_id(c.get("/api/v1/probes").json())["col-b"]["ok"], timeout=10)


def test_hung_collector_times_out_in_parallel(make_world):
    w = make_world(start=False)
    hang = socket.socket()
    hang.bind(("127.0.0.1", 0))
    hang.listen(8)
    conns = []
    t = threading.Thread(target=lambda: [conns.append(hang.accept()[0]) for _ in range(20)], daemon=True)
    t.start()
    cols = json.loads(w.config_path.read_text())["collectors"]
    cols[2]["url"] = f"https://127.0.0.1:{hang.getsockname()[1]}"
    w.write_config(collectors=cols)
    w.start()
    try:
        c = w.as_user("vera")
        t0 = time.monotonic()
        r = c.get("/api/v1/probes")
        took = time.monotonic() - t0
        assert r.status == 200 and took < 6.0, took
        st = by_id(r.json())
        assert st["col-c"]["ok"] is False and st["col-c"]["error"] == "timeout"
        assert st["col-a"]["ok"] and st["col-b"]["ok"]
        assert {i["probe"] for i in r.json()["items"]} == {"probe-a1", "probe-b1"}
    finally:
        hang.close()
        for s in conns:
            s.close()


def test_probe_scoped_calls_route_to_owner_and_pass_through_exactly(world):
    c = world.as_user("vera")
    at = "2026-11-18T20:06:00.000Z"
    for probe, cid in (("probe-a1", "col-a"), ("probe-b1", "col-b"), ("probe-c1", "col-c")):
        for q in (f"state?probe={probe}", f"state?probe={probe}&at={at}&voice=plain",
                  f"beats?probe={probe}&from=2026-11-18T20:00:00Z&to=2026-11-18T21:00:00Z",
                  f"summary?probe={probe}&minutes=15", f"records?probe={probe}&from=2026-11-18T20:00:00Z"
                  "&to=2026-11-18T21:00:00Z"):
            r = c.get("/api/v1/" + q)
            st, body = direct(world, cid, q)
            assert r.status == st == 200, q
            if q.startswith("state?probe=" + probe + "&at"):
                assert json.loads(r.body) == json.loads(body)        # rewind: exactly the collector's state?at=
            assert r.headers["x-exp-collector"] == cid
        assert c.get(f"/api/v1/state?probe={probe}").json()["probe"] == probe


def test_rewind_state_at_is_the_collectors_state_at(world):
    f = world.fakes["col-b"]
    # ingest nothing: the state at two different instants must still be byte-identical to the collector's
    c = world.as_user("vera")
    for at in ("2026-11-18T19:00:00.000Z", "2026-11-18T20:06:00.000Z"):
        r = c.get(f"/api/v1/state?probe=probe-b1&at={at}")
        _, body = direct(world, "col-b", f"state?probe=probe-b1&at={at}")
        assert r.body == body
    assert f.app.requests > 0


def test_unknown_probe_and_bad_parameters(world):
    c = world.as_user("vera")
    assert c.get("/api/v1/state?probe=nope-9").status == 404
    assert c.get("/api/v1/state").status == 400
    for bad in ("../x", "UP", "a%20b", "a" * 80, "p;rm"):
        assert c.get(f"/api/v1/state?probe={bad}").status == 400, bad
    assert c.get("/api/v1/state?probe=probe-a1&voice=loud").status == 400
    assert c.get("/api/v1/state?probe=probe-a1&at=yesterday").status == 400
    assert c.get("/api/v1/beats?probe=probe-a1").status == 400
    assert c.get("/api/v1/summary?probe=probe-a1&minutes=999999").status == 400
    assert c.get("/api/v1/records?probe=probe-a1&from=2026-11-18T00:00:00Z&to=2026-11-18T01:00:00Z"
                 "&limit=5000").status == 400
    # unknown query parameters are dropped, not forwarded
    assert c.get("/api/v1/probes?evil=1&site=hall-a").json()["items"][0]["probe"] == "probe-a1"


def test_states_and_incidents_merge_and_sort(world):
    ids_ = {"col-a": "inc_01M7R3X9G0NTM2HDJYD21Y49WA", "col-b": "inc_01M7R3X9G0NTM2HDJYD21Y49WB",
            "col-c": "inc_01M7R3X9G0NTM2HDJYD21Y49WC"}
    starts = {"col-a": "2026-11-18T10:00:00.000Z", "col-b": "2026-11-18T12:00:00.000Z",
              "col-c": "2026-11-18T11:00:00.000Z"}
    for cid, f in world.fakes.items():
        ch = cid[-1]
        f.app.inject_incident(incident(ids_[cid], f"probe-{ch}1", f"hall-{ch}", starts[cid]))
    c = world.as_user("vera")
    inc = c.get("/api/v1/incidents").json()
    assert [i["collector_id"] for i in inc["items"]] == ["col-b", "col-c", "col-a"]     # newest first
    assert [i["id"] for i in c.get("/api/v1/incidents?probe=probe-c1").json()["items"]] == [ids_["col-c"]]
    assert [i["id"] for i in c.get("/api/v1/incidents?site=hall-a").json()["items"]] == [ids_["col-a"]]
    assert c.get("/api/v1/incidents?open=true").json()["items"].__len__() == 3
    states = c.get("/api/v1/states").json()
    assert {s["probe"]: s["collector_id"] for s in states["items"]} == {
        "probe-a1": "col-a", "probe-b1": "col-b", "probe-c1": "col-c"}


def test_health_endpoint_lists_every_collector(world):
    d = world.as_user("vera").get("/api/v1/health").json()
    assert sorted(i["collector_id"] for i in d["items"]) == ["col-a", "col-b", "col-c"]
    assert all(i["health"]["status"] == "ok" for i in d["items"])


def test_tls_pin_mismatch_refuses_without_sending(make_world):
    w = make_world(start=False)
    cols = json.loads(w.config_path.read_text())["collectors"]
    cols[1]["tls_fingerprint_sha256"] = ":".join(["AA"] * 32)
    w.write_config(collectors=cols)
    w.start()
    before = w.fakes["col-b"].app.requests
    c = w.as_user("vera")
    d = c.get("/api/v1/probes").json()
    assert by_id(d)["col-b"] == {"collector_id": "col-b", "site": "hall-b", "ok": False,
                                 "error": "tls_pin_mismatch"}
    assert w.fakes["col-b"].app.requests == before            # not a single HTTP request went out
    assert c.get("/api/v1/state?probe=probe-a1").status == 200


def test_wrong_collector_token_is_reported_unauthorized(make_world):
    w = make_world(start=False)
    from exp_common import ids
    w.write_creds(collector_tokens={"col-a": DASH_TOKEN, "col-b": ids.new_token("expd"), "col-c": DASH_TOKEN})
    w.start()
    d = w.as_user("vera").get("/api/v1/probes").json()
    assert by_id(d)["col-b"]["error"] == "unauthorized" and by_id(d)["col-a"]["ok"]


def test_missing_collector_credential_and_live_rotation(world):
    c = world.as_user("vera")
    world.write_creds(collector_tokens={"col-a": DASH_TOKEN, "col-c": DASH_TOKEN})
    assert world.wait_for(lambda: by_id(c.get("/api/v1/probes").json())["col-b"].get("error") == "no_credential",
                          timeout=10)
    world.write_creds()
    assert world.wait_for(lambda: by_id(c.get("/api/v1/probes").json())["col-b"]["ok"], timeout=10)


def test_malformed_collector_token_entries_are_ignored(world):
    world.write_creds(collector_tokens={"col-a": "not-a-token", "col-b": DASH_TOKEN, "col-c": DASH_TOKEN})
    world.app.creds.reload(force=True)
    d = world.as_user("vera").get("/api/v1/probes").json()
    assert by_id(d)["col-a"]["error"] == "no_credential"


def test_query_range_needs_collector_when_federated(world):
    c = world.as_user("vera")
    q = "query_range?query=exp_up&start=2026-11-18T20:00:00Z&end=2026-11-18T21:00:00Z&step=60s"
    assert c.get("/api/v1/" + q).status == 400
    r = c.get("/api/v1/" + q + "&collector=col-b")
    assert r.status == 200 and r.headers["x-exp-collector"] == "col-b"
    assert c.get("/api/v1/query_range?query=up&start=2026-11-18T20:00:00Z&end=2026-11-18T21:00:00Z"
                 "&step=60s&collector=col-b").status == 400        # collector's own guard (only exp_* metrics)


def test_probe_map_refresh_picks_up_new_probe(world):
    c = world.as_user("vera")
    f = world.fakes["col-c"]
    f.app.probe_sites["probe-new"] = "hall-c"
    f.app.ingest_tokens["probe-new"] = "x"
    world.app.fed.refresh_map()
    assert world.app.fed.probe_map["probe-new"] == ("col-c", "hall-c")
    assert c.get("/api/v1/state?probe=probe-new").status == 200


def test_drill_report_lookup_fans_out(world):
    run = "run_01M7R3X9G0NTM2HDJYD21Y49WH"
    f = world.fakes["col-c"]
    f.app.add_drill_report({"run_id": run, "type": "dns", "target": "x", "start": "2026-11-18T20:00:00.000Z",
                            "until": "2026-11-18T20:10:00.000Z", "phases": [], "expectation": {},
                            "observed": {"ttd_s": 1, "ttr_s": 2, "lines_impacted": []}, "result": "pass"})
    c = world.as_user("vera")
    r = c.get(f"/api/v1/drills/{run}")
    assert r.status == 200 and r.json()["run_id"] == run and r.headers["x-exp-collector"] == "col-c"
    assert c.get("/api/v1/drills/run_01M7R3X9G0NTM2HDJYD21Y49ZZ").status == 404


def test_upstream_requests_carry_user_for_audit(world):
    world.fakes["col-a"].app.inject_incident(
        incident("inc_01M7R3X9G0NTM2HDJYD21Y49WA", "probe-a1", "hall-a", "2026-11-18T10:00:00.000Z"))
    c = world.as_user("alice")
    assert c.post("/api/v1/incidents/inc_01M7R3X9G0NTM2HDJYD21Y49WA/ack", json_body={"note": "seen"}).status == 204
    last = world.fakes["col-a"].app.audit[-1]
    assert last["user"] == "alice" and last["note"] == "seen"
    inc = world.fakes["col-a"].app.incidents[-1]
    assert inc["acked_by"] == "alice"


def test_site_lines_board_goes_to_the_collector_that_serves_the_site(world):
    """CR-site-lines-board: /sites/{site}/lines[/timeline] is relayed to the collector of that site; a site no
    collector serves is 404; the site and the query are validated before anything leaves the dashboard."""
    doc = {"schema": "exp.lines/1", "site": "hall-b", "networks": [], "findings": []}
    with world.fakes["col-b"].app.lock:
        world.fakes["col-b"].app.board_docs["hall-b"] = doc
        world.fakes["col-b"].app.board_timelines["hall-b"] = {"schema": "exp.lines-timeline/1", "networks": []}
    c = world.as_user("vera")
    r = c.get("/api/v1/sites/hall-b/lines")
    assert r.status == 200 and r.json() == doc and r.headers.get("x-exp-collector") == "col-b"
    assert c.get("/api/v1/sites/hall-b/lines/timeline?step_s=10").json()["schema"] == "exp.lines-timeline/1"
    assert c.get("/api/v1/sites/nowhere/lines").status == 404
    assert c.get("/api/v1/sites/Bad_Site/lines").status == 400
    assert c.get("/api/v1/sites/hall-b/lines?at=not-a-time").status == 400
    assert c.get("/api/v1/sites/hall-b/lines/other").status == 404

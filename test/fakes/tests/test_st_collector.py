"""fake_st_collector: result ingest + status + comment, the runner feed (poll, long-poll, SSE), evidence + token checks, baseline, scrub."""
from __future__ import annotations

import copy
import json
import threading
import time

import pytest
from fakes_support import ROOT, check_openapi, request

import fake_st_collector as fst
import fakes_common as fc

FIX = ROOT / "test" / "fixtures"
T0 = 1_795_000_000.0


def load(rel):
    return json.loads((FIX / rel).read_text())


class Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> float:
        return self.t


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def toks():
    t = fst.default_tokens()
    t["speedtest"]["spd-two"] = {"token": fc.fixture_token("exps", "spd-two"), "sha256": fc.token_hash(fc.fixture_token("exps", "spd-two")), "site": "hall-c"}
    t["runner"]["runner-c"] = {"token": fc.fixture_token("expr", "runner-c"), "sha256": fc.token_hash(fc.fixture_token("expr", "runner-c")), "site": "hall-c"}
    return t


@pytest.fixture()
def fake(clock, toks):
    f = fst.start(now_fn=clock, tokens=toks)
    yield f
    f.stop()


def tok(toks, family, ident=None):
    ident = ident or next(iter(toks[family]))
    return toks[family][ident]["token"]


def auth(t):
    return {"Authorization": f"Bearer {t}"}


def result(n: int = 1, *, server="spd-core", site="hall-b", ip="10.60.14.77", zone_source=None):
    doc = copy.deepcopy(load("speedtest/result.ok.json"))
    doc["id"] = fc.det_id("st_", f"test-{n}")
    doc["observed"]["server_id"], doc["site"], doc["client"]["ip"] = server, site, ip
    if zone_source:
        doc["zone_source"] = zone_source
    return doc


def ev(kind_file, test_id, mutate=None):
    d = copy.deepcopy(load(f"evidence/{kind_file}.json"))
    d["test_id"] = test_id
    if mutate:
        mutate(d)
    return d


def ingest(fake, toks, doc, ident="spd-core"):
    return request(fake.port, "POST", "/api/v1/speedtests", doc, auth(tok(toks, "speedtest", ident)))


def post_ev(fake, toks, tid, doc, ident="runner-core"):
    return request(fake.port, "POST", f"/api/v1/speedtests/{tid}/evidence", doc, auth(tok(toks, "runner", ident)))


def complete(fake, toks, tid, kinds=("identity",), status="ok", ident="runner-core"):
    return request(fake.port, "POST", f"/api/v1/speedtests/{tid}/evidence/complete", {"kinds": list(kinds), "status": status},
                   auth(tok(toks, "runner", ident)))


def feed(fake, toks, ident="runner-core", **q):
    qs = "&".join(f"{k}={v}" for k, v in q.items())
    return request(fake.port, "GET", "/api/v1/speedtests/feed" + ("?" + qs if qs else ""), headers=auth(tok(toks, "runner", ident)))


# ------------------------------------------------------------------------------------------------- ingest
def test_ingest_created_then_duplicate(fake, toks):
    doc = result()
    r = ingest(fake, toks, doc)
    assert r.status == 201 and r.json()["status"] == "stored" and r.json()["diagnosis"]["stage"] == "quick"
    check_openapi("collector", "/speedtests", "post", 201, r.json())
    r2 = ingest(fake, toks, doc)
    assert r2.status == 200 and r2.json()["status"] == "duplicate"
    check_openapi("collector", "/speedtests", "post", 200, r2.json())
    assert len(fake.app.tests) == 1


def test_ingest_token_checks(fake, toks):
    doc = result()
    p = "/api/v1/speedtests"
    assert request(fake.port, "POST", p, doc).status == 401
    for family, ident in (("runner", "runner-core"), ("dashboard", "dash-main")):          # right shape, wrong family
        assert request(fake.port, "POST", p, doc, auth(tok(toks, family, ident))).status == 401
    assert request(fake.port, "POST", p, doc, auth(fc.fixture_token("exps", "nobody"))).status == 401
    assert request(fake.port, "POST", p, doc, {"Authorization": f"Basic {tok(toks, 'speedtest')}"}).status == 401
    assert len(fake.app.tests) == 0


def test_ingest_identity_binding(fake, toks):
    assert ingest(fake, toks, result(server="spd-other")).status == 403
    assert ingest(fake, toks, result(site="hall-c")).status == 403
    r = ingest(fake, toks, result(server="spd-two", site="hall-b"), ident="spd-two")      # token of spd-two (hall-c) claiming hall-b
    assert r.status == 403 and r.json()["error"]["code"] == "identity_mismatch"
    assert ingest(fake, toks, result(5, server="spd-two", site="hall-c"), ident="spd-two").status == 201


def test_ingest_validation(fake, toks):
    bad = result()
    bad["score"]["total"] = 500
    assert ingest(fake, toks, bad).status == 400
    noip = result()
    del noip["client"]["ip"]
    assert ingest(fake, toks, noip).status == 400
    named = result()
    named["client"]["name"] = "Alice"                      # structural anonymity: no name field exists
    assert ingest(fake, toks, named).status == 400
    r = request(fake.port, "POST", "/api/v1/speedtests", b"{nope", auth(tok(toks, "speedtest")))
    assert r.status == 400
    big = result()
    big["comment"] = "x" * (fst.MAX_RESULT_BYTES + 10)
    assert ingest(fake, toks, big).status == 413


# -------------------------------------------------------------------------------------------- status + comment
def test_status_visible_only_to_owner_and_valid(fake, toks):
    doc = result()
    ingest(fake, toks, doc)
    p = f"/api/v1/speedtests/{doc['id']}/status"
    r = request(fake.port, "GET", p, headers=auth(tok(toks, "speedtest")))
    assert r.status == 200
    j = r.json()
    check_openapi("collector", "/speedtests/{id}/status", "get", 200, j)
    assert j["state"] == "submitted" and j["diagnosis"]["stage"] == "quick" and len(j["checks"]) == 8 and all(c["state"] == "checking" for c in j["checks"])
    assert request(fake.port, "GET", p, headers=auth(tok(toks, "speedtest", "spd-two"))).status == 404        # not this speedtest's test
    assert request(fake.port, "GET", p, headers=auth(tok(toks, "runner"))).status == 401
    assert request(fake.port, "GET", p).status == 401
    assert request(fake.port, "GET", "/api/v1/speedtests/st_BADBADBADBADBADBADBADBADBA/status", headers=auth(tok(toks, "speedtest"))).status == 404
    # user-safe: no raw identifiers anywhere in the status document
    text = json.dumps(j)
    assert "10.60.14.77" not in text and "f0:18" not in text


def test_comment(fake, toks):
    doc = result()
    ingest(fake, toks, doc)
    p = f"/api/v1/speedtests/{doc['id']}/comment"
    h = auth(tok(toks, "speedtest"))
    assert request(fake.port, "POST", p, {"comment": "wifi drops\nin hall B"}, h).status == 204
    assert request(fake.port, "GET", f"/api/v1/speedtests/{doc['id']}/status", headers=h).json()["comment"] == "wifi drops\nin hall B"
    for bad in ({"comment": ""}, {"comment": "x" * 501}, {"comment": "a\x07b"}, {"comment": 5}, {"comment": "ok", "extra": 1}, {}):
        assert request(fake.port, "POST", p, bad, h).status == 400, bad
    assert request(fake.port, "POST", p, {"comment": "x"}, auth(tok(toks, "speedtest", "spd-two"))).status == 404
    assert request(fake.port, "POST", p, {"comment": "x"}, auth(tok(toks, "runner"))).status == 401


# ------------------------------------------------------------------------------------------------------ feed
def test_feed_runner_view_and_cursor(fake, toks):
    a, b = result(1), result(2)
    ingest(fake, toks, a)
    ingest(fake, toks, b)
    ingest(fake, toks, result(3, server="spd-two", site="hall-c"), ident="spd-two")
    r = feed(fake, toks)
    assert r.status == 200
    j = r.json()
    check_openapi("collector", "/speedtests/feed", "get", 200, j)
    assert [i["id"] for i in j["items"]] == [a["id"], b["id"]]                     # oldest first, own site only
    it = j["items"][0]
    assert it["client_ip"] == "10.60.14.77" and it["site"] == "hall-b" and it["observed_server"] == "spd-core"
    assert it["window"] == {"from": fc.iso_from_epoch(fst.iso_to_ms(a["started"]) / 1000 - 300), "to": fc.iso_from_epoch(fst.iso_to_ms(a["ended"]) / 1000 + 120)}
    assert it["zone_hint"] is None
    again = feed(fake, toks, after=j["next_cursor"]).json()
    assert again["items"] == []
    one = feed(fake, toks, limit=1).json()
    assert len(one["items"]) == 1
    assert [i["id"] for i in feed(fake, toks, after=one["next_cursor"]).json()["items"]] == [b["id"]]
    assert [i["id"] for i in feed(fake, toks, ident="runner-c").json()["items"]] == [fc.det_id("st_", "test-3")]
    for q in ("limit=0", "limit=101", "wait_s=26", "after=abc"):
        assert feed(fake, toks, **dict([q.split("=")])).status == 400, q


def test_feed_qr_zone_hint_and_zone_window_config(fake, toks):
    ingest(fake, toks, result(1, zone_source="qr"))
    assert feed(fake, toks).json()["items"][0]["zone_hint"] == "hallb-row12"
    request(fake.port, "POST", "/_fake/window", {"before_s": 60, "after_s": 30})
    w = feed(fake, toks).json()["items"][0]
    assert fst.iso_to_ms(w["window"]["to"]) - fst.iso_to_ms(w["window"]["from"]) == (fst.iso_to_ms(w["ended"]) - fst.iso_to_ms(w["started"])) + 90_000


def test_feed_token_family_and_long_poll(fake, toks):
    assert request(fake.port, "GET", "/api/v1/speedtests/feed", headers=auth(tok(toks, "speedtest"))).status == 401
    assert request(fake.port, "GET", "/api/v1/speedtests/feed").status == 401
    doc = result()
    threading.Timer(0.3, lambda: ingest(fake, toks, doc)).start()
    t = time.monotonic()
    j = feed(fake, toks, wait_s=5).json()
    assert [i["id"] for i in j["items"]] == [doc["id"]] and 0.2 < time.monotonic() - t < 4
    t = time.monotonic()
    assert feed(fake, toks, after=j["next_cursor"], wait_s=1).json()["items"] == []
    assert time.monotonic() - t >= 0.9


def test_feed_drops_finished_tests(fake, toks):
    doc = result()
    ingest(fake, toks, doc)
    assert post_ev(fake, toks, doc["id"], ev("identity.mist", doc["id"])).status == 200
    assert len(feed(fake, toks).json()["items"]) == 1               # evidence started but not final: still pending
    complete(fake, toks, doc["id"])
    assert feed(fake, toks).json()["items"] == []


# --------------------------------------------------------------------------------------------------- evidence
def test_evidence_accept_replace_and_state(fake, toks):
    doc = result()
    ingest(fake, toks, doc)
    tid = doc["id"]
    r = post_ev(fake, toks, tid, ev("wifi.ok", tid))
    assert r.status == 200
    check_openapi("collector", "/speedtests/{id}/evidence", "post", 200, r.json())
    assert r.json()["kind"] == "wifi" and r.json()["stored_bytes"] == r.json()["total_bytes"] > 100
    r2 = post_ev(fake, toks, tid, ev("wifi.ok", tid, lambda d: d["data"]["client"].update(rssi=-80)))        # replaces
    assert r2.status == 200 and r2.json()["total_bytes"] == r2.json()["stored_bytes"]
    post_ev(fake, toks, tid, ev("identity.mist", tid))
    st = request(fake.port, "GET", f"/api/v1/speedtests/{tid}/status", headers=auth(tok(toks, "speedtest"))).json()
    check_openapi("collector", "/speedtests/{id}/status", "get", 200, st)
    assert st["state"] == "correlating" and st["evidence"]["kinds_done"] == ["wifi", "identity"] and st["zone"] == "hallb-row12" and st["zone_source"] == "mist"
    by = {c["kind"]: c["state"] for c in st["checks"]}
    assert by["wifi"] == "ok" and by["identity"] == "ok" and by["wan"] == "checking"
    assert st["network_details"] == {"ap_name": "hallb-ap-12", "band": "5", "channel": 44}


def test_evidence_rejections(fake, toks):
    doc = result()
    ingest(fake, toks, doc)
    tid = doc["id"]
    good = ev("wifi.ok", tid)
    p = f"/api/v1/speedtests/{tid}/evidence"
    assert request(fake.port, "POST", p, good).status == 401
    assert request(fake.port, "POST", p, good, auth(tok(toks, "speedtest"))).status == 401           # exps_ cannot post evidence
    assert request(fake.port, "POST", p, good, auth(tok(toks, "dashboard", "dash-main"))).status == 401
    mism = post_ev(fake, toks, tid, ev("wifi.ok", fc.det_id("st_", "other")))
    assert mism.status == 400 and mism.json()["error"]["code"] == "id_mismatch"
    assert post_ev(fake, toks, tid, ev("wifi.ok", tid, lambda d: d.update(kind="wired"))).status == 400       # kind/data mismatch
    assert post_ev(fake, toks, tid, ev("wifi.ok", tid, lambda d: d["data"]["client"].update(name="Alice"))).status == 400
    assert post_ev(fake, toks, tid, {"schema": "exp.evidence/1"}).status == 400
    ghost = fc.det_id("st_", "ghost")
    assert post_ev(fake, toks, ghost, ev("wifi.ok", ghost)).status == 404
    assert post_ev(fake, toks, tid, good, ident="runner-c").status == 403                             # runner of another site
    assert request(fake.port, "POST", p, b"x" * (fst.MAX_EVIDENCE_BODY + 5), auth(tok(toks, "runner"))).status == 413


def test_evidence_total_size_limit(fake, toks, monkeypatch):
    doc = result()
    ingest(fake, toks, doc)
    tid = doc["id"]
    wifi = ev("wifi.ok", tid)
    size = len(json.dumps(wifi, separators=(",", ":")))
    monkeypatch.setattr(fst, "MAX_EVIDENCE_TOTAL", size + 50)
    assert post_ev(fake, toks, tid, wifi).status == 200
    assert post_ev(fake, toks, tid, wifi).status == 200                      # replacing the same kind does not double count
    r = post_ev(fake, toks, tid, ev("identity.mist", tid))
    assert r.status == 413 and r.json()["error"]["code"] == "evidence_too_large"
    check_openapi("collector", "/speedtests/{id}/evidence", "post", 413, r.json())


def test_complete_marks_final_and_blocks_more_evidence(fake, toks):
    doc = result()
    ingest(fake, toks, doc)
    tid = doc["id"]
    post_ev(fake, toks, tid, ev("wifi.ok", tid, lambda d: d["data"]["client"].update(rssi=-82) or d["data"]["ap"]["radio"].update(util_all=20)))
    post_ev(fake, toks, tid, ev("identity.mist", tid))
    r = complete(fake, toks, tid, ("wifi", "identity"))
    assert r.status == 200
    j = r.json()
    check_openapi("collector", "/speedtests/{id}/evidence/complete", "post", 200, j)
    assert j["diagnosis"]["stage"] == "final" and j["diagnosis"]["cause"][0]["id"] == "wifi_signal"
    assert post_ev(fake, toks, tid, ev("dns.ok", tid)).status == 409
    assert post_ev(fake, toks, tid, ev("dns.ok", tid)).json()["error"]["code"] == "evidence_final"
    r2 = complete(fake, toks, tid)
    assert r2.status == 409 and r2.json()["error"]["code"] == "already_final"
    st = request(fake.port, "GET", f"/api/v1/speedtests/{tid}/status", headers=auth(tok(toks, "speedtest"))).json()
    assert st["state"] == "final" and st["evidence"]["state"] == "final" and st["evidence"]["final_at"] and st["diagnosis"]["stage"] == "final"
    assert {c["kind"]: c["state"] for c in st["checks"]}["wan"] == "unavailable"          # no evidence of that kind arrived
    assert "noc_text" not in st["diagnosis"]                                                # user-safe view only
    for bad in ({}, {"kinds": ["wifi", "wifi"], "status": "ok"}, {"kinds": ["x"], "status": "ok"}, {"kinds": [], "status": "weird"}):
        assert request(fake.port, "POST", f"/api/v1/speedtests/{tid}/evidence/complete", bad, auth(tok(toks, "runner"))).status in (400, 409)
    assert complete(fake, toks, tid, ident="runner-c").status in (403, 409)


@pytest.mark.parametrize("name,files,mut,expect", [
    ("wifi_congestion", [("wifi.ok", None)], None, "wifi_congestion"),
    ("policy_block", [("security.policy-block", None)], None, "policy_block"),
    ("wan_saturation", [("wan.ok", None)], lambda d: d["data"].update(wan_util_pct=92.5), "wan_saturation"),
    ("wired_port", [("wired.ok", None)], lambda d: d["data"]["port"].update(rx_errors=50000, full_duplex=False), "wired_port"),
    ("healthy", [("identity.mist", None)], None, "none"),
])
def test_stand_in_final_diagnosis(fake, toks, name, files, mut, expect):
    doc = result()
    ingest(fake, toks, doc)
    for f, _ in files:
        assert post_ev(fake, toks, doc["id"], ev(f, doc["id"], mut)).status == 200
    assert complete(fake, toks, doc["id"], ("wifi",)).json()["diagnosis"]["cause"][0]["id"] == expect


def test_nat_suspected_never_blames_the_user_device(fake, toks):
    doc = result(zone_source="subnet")
    ingest(fake, toks, doc)
    post_ev(fake, toks, doc["id"], ev("identity.nat-suspected", doc["id"]))
    post_ev(fake, toks, doc["id"], ev("wifi.ok", doc["id"], lambda d: d["data"]["client"].update(rssi=-90)))
    top = complete(fake, toks, doc["id"]).json()["diagnosis"]["cause"][0]["id"]
    assert top == "none"
    st = request(fake.port, "GET", f"/api/v1/speedtests/{doc['id']}/status", headers=auth(tok(toks, "speedtest"))).json()
    assert st["zone"] == "unresolved"


# ------------------------------------------------------------------------------------------------ scrub + detail
def test_scrub_after_diagnosis_drops_raw_identifiers_keeps_device_key(clock, toks):
    f = fst.start(now_fn=clock, tokens=toks, scrub_after_diagnosis=True)
    try:
        doc = result()
        ingest(f, toks, doc)
        post_ev(f, toks, doc["id"], ev("identity.mist", doc["id"]))
        post_ev(f, toks, doc["id"], ev("wifi.ok", doc["id"]))
        complete(f, toks, doc["id"], ("wifi", "identity"))
        d = request(f.port, "GET", f"/api/v1/speedtests/{doc['id']}?identifiers=true", headers=auth(tok(toks, "dashboard", "dash-main"))).json()
        check_openapi("collector", "/speedtests/{id}", "get", 200, d)
        text = json.dumps(d)
        for raw in ("10.60.14.77", "f0:18:98:aa:bb:01", "alices-iphone", "guest-portal-7731"):
            assert raw not in text, raw
        identity = [e for e in d["evidence"] if e["kind"] == "identity"][0]["data"]
        assert identity["scrubbed"] is True and identity["device_key"] == d["device_key"] and identity["zone"] == "hallb-row12"
        assert "ip" not in d["test"]["client"]
        # the quoted "no name/email field anywhere" assertion: asserted always
        assert not any(k in ("name", "email", "phone") for e in d["evidence"] for k in e["data"].get("client", {}))
    finally:
        f.stop()


def test_without_scrub_raw_identifiers_only_on_request(fake, toks):
    doc = result()
    ingest(fake, toks, doc)
    post_ev(fake, toks, doc["id"], ev("identity.mist", doc["id"]))
    complete(fake, toks, doc["id"], ("identity",))
    h = auth(tok(toks, "dashboard", "dash-main"))
    plain = request(fake.port, "GET", f"/api/v1/speedtests/{doc['id']}", headers=h).json()
    assert "10.60.14.77" not in json.dumps(plain) and "f0:18:98:aa:bb:01" not in json.dumps(plain)
    full = request(fake.port, "GET", f"/api/v1/speedtests/{doc['id']}?identifiers=true", headers=h).json()
    assert "10.60.14.77" in json.dumps(full) and "f0:18:98:aa:bb:01" in json.dumps(full)
    assert request(fake.port, "GET", f"/api/v1/speedtests/{doc['id']}", headers=auth(tok(toks, "runner"))).status == 401


def test_list_and_row_shape(fake, toks):
    for i in (1, 2, 3):
        ingest(fake, toks, result(i))
    h = auth(tok(toks, "dashboard", "dash-main"))
    r = request(fake.port, "GET", "/api/v1/speedtests?limit=2&site=hall-b", headers=h)
    check_openapi("collector", "/speedtests", "get", 200, r.json())
    assert len(r.json()["items"]) == 2 and r.json()["next_cursor"]
    assert "ip" not in json.dumps(r.json()) and "client" not in r.json()["items"][0]
    r2 = request(fake.port, "GET", f"/api/v1/speedtests?limit=2&cursor={r.json()['next_cursor']}", headers=h)
    assert len(r2.json()["items"]) == 1 and r2.json()["next_cursor"] is None


def test_purge_by_ip_test_mac_and_audit(clock, toks):
    f = fst.start(now_fn=clock, tokens=toks, device_key_secret=fc.fixture_token("expk", "org"))
    try:
        h = {**auth(tok(toks, "dashboard", "dash-main")), "X-Exp-User": "admin@example.com"}
        docs = [result(i) for i in (1, 2)]
        for d in docs:
            ingest(f, toks, d)
        assert request(f.port, "POST", "/api/v1/speedtests/purge", {"by": "ip", "value": "10.60.14.77"}, auth(tok(toks, "dashboard", "dash-main"))).status == 403
        dry = request(f.port, "POST", "/api/v1/speedtests/purge", {"by": "ip", "value": "10.60.14.77", "dry_run": True}, h)
        check_openapi("collector", "/speedtests/purge", "post", 200, dry.json())
        assert dry.json()["matched_tests"] == 2 and dry.json()["deleted"]["tests"] == 0 and len(f.app.tests) == 2
        r = request(f.port, "POST", "/api/v1/speedtests/purge", {"by": "test", "value": docs[0]["id"]}, h)
        assert r.json()["deleted"]["tests"] == 1 and r.json()["audited_by"] == "admin@example.com" and len(f.app.tests) == 1
        assert request(f.port, "POST", "/api/v1/speedtests/purge", {"by": "ip", "value": "10.60.14.77"}, h).json()["deleted"]["tests"] == 1
        assert request(f.port, "POST", "/api/v1/speedtests/purge", {"by": "bogus", "value": "x"}, h).status == 400
        assert [a["action"] for a in f.app.audit].count("purge") == 3
    finally:
        f.stop()


# --------------------------------------------------------------------------------------------------- baseline
def test_baseline(fake, toks):
    h = auth(tok(toks, "runner"))
    r = request(fake.port, "GET", "/api/v1/speedtests/baseline?site=hall-b&zone=hallb-row12&at=2026-11-18T14:02:11.120Z", headers=h)
    assert r.status == 200
    check_openapi("collector", "/speedtests/baseline", "get", 200, r.json())
    assert r.json()["site"] == "hall-b" and r.json()["at"] == "2026-11-18T14:02:11.120Z" and r.json()["probe"]
    assert request(fake.port, "GET", "/api/v1/speedtests/baseline?site=hall-b", headers=h).status == 400         # at required
    assert request(fake.port, "GET", "/api/v1/speedtests/baseline?site=hall-b&at=yesterday", headers=h).status == 400
    assert request(fake.port, "GET", "/api/v1/speedtests/baseline?site=hall-c&at=2026-11-18T14:02:11.120Z", headers=h).status == 404
    assert request(fake.port, "GET", "/api/v1/speedtests/baseline?site=hall-b&at=2026-11-18T14:02:11.120Z", headers=auth(tok(toks, "speedtest"))).status == 401
    fake.app.set_baseline(None)
    assert request(fake.port, "GET", "/api/v1/speedtests/baseline?site=hall-b&at=2026-11-18T14:02:11.120Z", headers=h).status == 404


# ------------------------------------------------------------------------------------------------- faults + SSE
def test_forced_failures_with_retry_after(fake, toks):
    fake.app.set_force(503, count=1, retry_after=7)
    r = ingest(fake, toks, result())
    assert r.status == 503 and r.h("Retry-After") == "7"
    assert ingest(fake, toks, result()).status == 201
    request(fake.port, "POST", "/_fake/force", {"status": 429, "count": 1})
    assert feed(fake, toks).status == 429


def read_sse(port, token, path="/api/v1/speedtests/stream", headers=None, seconds=1.5, until=None):
    """Raw-socket SSE reader: returns the response body text collected for up to `seconds`."""
    import socket
    hdrs = {**auth(token), **(headers or {})}
    req = f"GET {path} HTTP/1.1\r\nHost: x\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(0.3)
    s.sendall(req.encode())
    buf, end = b"", time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            chunk = s.recv(4096)
        except TimeoutError:
            continue
        if not chunk:
            break
        buf += chunk
        if until and until(buf.partition(b"\r\n\r\n")[2]):
            break
    s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200") and b"text/event-stream" in head and b"no-store" in head, head
    return body.decode()


def test_sse_stream_events(fake, toks):
    dash = tok(toks, "dashboard", "dash-main")
    out: dict = {}
    t = threading.Thread(target=lambda: out.update(text=read_sse(fake.port, dash, until=lambda b: b.count(b"event: ") >= 4)))
    t.start()
    time.sleep(0.3)
    doc = result()
    ingest(fake, toks, doc)
    post_ev(fake, toks, doc["id"], ev("wifi.ok", doc["id"]))
    complete(fake, toks, doc["id"], ("wifi",))
    t.join(timeout=8)
    text = out["text"]
    assert text.startswith("retry: 3000\n\n")
    kinds = [line.split(": ", 1)[1] for line in text.splitlines() if line.startswith("event: ")]
    assert kinds == ["speedtest", "diagnosis", "evidence", "diagnosis"][: len(kinds)] and len(kinds) >= 4
    assert f'"id":"{doc["id"]}"' in text and '"kind":"wifi"' in text and '"stage":"final"' in text
    assert "10.60.14.77" not in text                         # stream rows never carry raw identifiers


def test_sse_replay_window_and_keepalive(fake, toks, clock):
    fake.app.keepalive_s = 0.2
    doc = result()
    ingest(fake, toks, doc)                                  # events 1, 2 at T0
    dash = tok(toks, "dashboard", "dash-main")
    clock.t = T0 + 100
    got = read_sse(fake.port, dash, headers={"Last-Event-ID": "0"}, seconds=1.0)
    assert "event: speedtest" in got and ": keepalive" in got and "id: 1" in got
    clock.t = T0 + 1000                                      # older than the 300 s replay window
    got2 = read_sse(fake.port, dash, headers={"Last-Event-ID": "0"}, seconds=0.8)
    assert "event: speedtest" not in got2
    assert request(fake.port, "GET", "/api/v1/speedtests/stream", headers=auth(tok(toks, "runner"))).status == 401


def test_runtime_derived_tokens_not_literal():
    t = fst.default_tokens()
    src = open(fst.__file__).read()
    for fam in t.values():
        for v in fam.values():
            assert v["token"] not in src

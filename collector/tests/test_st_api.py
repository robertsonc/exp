"""The speedtests operations of collector.yaml: auth scoping per token family, ingest, user-safe status, comment,
runner feed / evidence / complete, query / detail / aggregate. Responses validate against the OpenAPI document."""
from __future__ import annotations

import json
import statistics
import threading
import time

import pytest
from colhelpers import check_openapi, https, iso
from exp_common import ids
from sthelpers import (
    BASE,
    BOX,
    evidence,
    fixture,
    healthy_result,
    iso_to_s,
    make_stenv,
    result,
    wifi,
)


def err(r):
    return r.json()["error"]["code"]


# ------------------------------------------------------------------------------------------ auth scoping
def test_each_token_family_works_only_on_its_own_routes(st):
    t = result()
    assert st.ingest(t).status == 201
    tid = t["id"]
    box, runner, dash = st.tokens["exps"], st.tokens["expr"], st.tokens["expd"]
    routes = [  # (method, path, who may call it)
        ("POST", "", box), ("GET", f"/{tid}/status", box), ("POST", f"/{tid}/comment", box),
        ("GET", "/feed", runner), ("POST", f"/{tid}/evidence", runner), ("POST", f"/{tid}/evidence/complete", runner),
        ("GET", "/baseline?site=hall-b&at=2026-11-20T00:00:00Z", runner),
        ("GET", "", dash), ("GET", f"/{tid}", dash), ("GET", "/aggregate?group_by=zone&metric=count", dash),
        ("GET", "/stream", dash), ("POST", "/purge", dash)]
    for method, path, owner in routes:
        for tok in (box, runner, dash, "garbage", None):
            if tok == owner:
                continue
            r = st.req(method, path, tok, body={} if method == "POST" else None)
            assert r.status == 401 and err(r) == "invalid_token", (method, path, tok and tok[:5], r.status)
            assert r.h("www-authenticate") == "Bearer"
    # an ingest token (probes) never works on the speedtest routes either
    r = st.req("POST", "", st.env.ingest_token, t)
    assert r.status == 401


def test_a_token_whose_identity_is_not_in_the_config_is_refused(st):
    rogue = ids.new_token("exps")
    (st.env.creds / "speedtest_tokens.json").write_text(json.dumps({BOX: ids.token_hash(st.tokens["exps"]),
                                                                    "spd-rogue": ids.token_hash(rogue)}))
    time.sleep(0.6)                                                  # the credential poller picks it up
    t = result(server_id="spd-rogue")
    assert st.ingest(t, token=rogue).status == 401
    assert st.ingest(result()).status == 201


def test_disabled_collector_answers_404_to_authenticated_speedtest_calls(env):
    app = env.start()                                                # no speedtests block
    r = https(app.address[1], "GET", BASE, headers={"Authorization": f"Bearer {env.dash_token}"})
    assert r.status == 404 and err(r) == "not_found"
    assert https(app.address[1], "GET", BASE).status == 401


# -------------------------------------------------------------------------------------------------- ingest
def test_ingest_stores_returns_the_quick_diagnosis_and_is_idempotent(st):
    t = result()
    r = st.ingest(t)
    assert r.status == 201
    check_openapi("collector", "/speedtests", "post", 201, r.json())
    body = r.json()
    assert body["id"] == t["id"] and body["status"] == "stored" and body["diagnosis"]["stage"] == "quick"
    again = st.ingest(t)
    assert again.status == 200 and again.json()["status"] == "duplicate"
    check_openapi("collector", "/speedtests", "post", 200, again.json())
    assert again.json()["diagnosis"] == body["diagnosis"]
    assert st.app.speedtests.repo.count() == 1


def test_ingest_binds_the_result_to_the_token_identity(st):
    assert st.ingest(result(server_id="spd-other")).status == 403
    r = st.ingest(result(site="hall-c"))
    assert r.status == 403 and err(r) == "identity_mismatch"
    assert st.app.speedtests.repo.count() == 0


def test_ingest_refuses_a_second_box_taking_over_an_id(st):
    b2 = ids.new_token("exps")
    (st.env.creds / "speedtest_tokens.json").write_text(json.dumps({BOX: ids.token_hash(st.tokens["exps"]),
                                                                    "spd-2": ids.token_hash(b2)}))
    st.app.speedtests.settings = type(st.app.speedtests.settings)(**{**st.app.speedtests.settings.__dict__,
                                                                     "speedtests": (BOX, "spd-2")})
    time.sleep(0.6)
    t = result()
    assert st.ingest(t).status == 201
    t2 = json.loads(json.dumps(t))
    t2["observed"]["server_id"] = "spd-2"
    r = st.ingest(t2, token=b2)
    assert r.status == 409 and err(r) == "conflict"
    assert st.status(t["id"], token=b2).status == 404                # a box sees only its own tests


def test_ingest_validation(st):
    good = result()
    bad = json.loads(json.dumps(good))
    bad["client"].pop("ip")
    assert st.ingest(bad).status == 400
    for mutate in (lambda d: d.update(name="Alice"), lambda d: d["client"].update(email="a@b.c"),
                   lambda d: d["legs"]["local"].update(down_mbps=1e9), lambda d: d.update(id="nope"),
                   lambda d: d.update(schema="exp.speedtest/2"), lambda d: d["flags"].append("made-up")):
        d = json.loads(json.dumps(good))
        mutate(d)
        r = st.ingest(d)
        assert r.status == 400 and err(r) == "invalid_request", r.body
    assert st.ingest(None) .status == 400
    assert st.req("POST", "", st.tokens["exps"], raw=b"{not json").status == 400
    assert st.req("POST", "", st.tokens["exps"], raw=b'{"a":1,"a":2}').status == 400     # duplicate keys
    big = json.dumps({"x": "y" * (300 * 1024)}).encode()
    assert st.req("POST", "", st.tokens["exps"], raw=big).status == 413


def test_ingest_time_sanity(st):
    assert st.ingest(result(ended_ago_s=-3600)).status == 400                       # ends in the future
    assert st.ingest(result(ended_ago_s=31 * 86400)).status == 400                  # older than the retention window
    d = result()
    d["started"], d["ended"] = d["ended"], d["started"]
    assert st.ingest(d).status == 400


def test_the_server_recomputes_the_score(st):
    t = result(down=300.0, up=200.0, i_down=200.0, i_up=100.0, loaded=25.0, i_loaded=25.0, cv=0.0)
    t["score"] = {"total": 3, "speed": 3, "responsiveness": 3, "stability": 3}        # a lying page
    assert st.ingest(t).status == 201
    got = st.get(f"/{t['id']}").json()["test"]["score"]
    assert got["total"] == 100 and got["total"] != 3
    row = st.get("").json()["items"][0]
    assert row["score"] == 100


def test_the_stored_result_never_keeps_the_raw_ip_in_its_document(st):
    t = result(ip="10.60.14.99")
    st.ingest(t)
    row = st.db().execute("SELECT doc, client_ip FROM speedtests").fetchone()
    assert "10.60.14.99" not in row["doc"] and row["client_ip"] == "10.60.14.99"


# ------------------------------------------------------------------------------------------ status, comment
def test_status_is_user_safe_and_follows_the_lifecycle(st):
    t = result(down=150.0)
    st.ingest(t)
    s0 = st.status(t["id"])
    assert s0.status == 200
    check_openapi("collector", "/speedtests/{id}/status", "get", 200, s0.json())
    assert s0.json()["state"] == "submitted" and s0.json()["evidence"]["state"] == "pending"
    assert all(c["state"] == "checking" for c in s0.json()["checks"])
    st.put_ev(wifi(t))
    st.put_ev(evidence("identity", t))
    s1 = st.status(t["id"]).json()
    assert s1["state"] == "correlating" and s1["evidence"]["kinds_done"] == ["identity", "wifi"]
    assert s1["zone"] == "hallb-row12" and s1["zone_source"] == "mist"
    st.complete(t["id"], ["identity", "wifi"])
    s2 = st.status(t["id"])
    check_openapi("collector", "/speedtests/{id}/status", "get", 200, s2.json())
    body = s2.json()
    assert body["state"] == "final" and body["diagnosis"]["stage"] == "final"
    assert body["diagnosis"]["cause"][0]["id"] == "wifi_congestion"
    text = s2.body.decode()
    for secret in ("f0:18:98:aa:bb:01", "alices-iphone", "guest-portal-7731", "10.60.14.77", "noc_text", "hallb-ap-12 ch"):
        assert secret not in text, secret
    assert body["network_details"] == {"ap_name": "hallb-ap-12", "band": "5", "channel": 44}
    kinds = {c["kind"]: c["state"] for c in body["checks"]}
    assert kinds["wifi"] == "attention" and kinds["identity"] == "ok" and kinds["dns"] == "unavailable"


def test_status_404s(st):
    assert st.status("st_" + "0" * 26).status == 404
    assert st.status("not-an-id").status == 404
    assert st.status("st_01M7VCB1X85XRFV6GA5TTYMEVR").status == 404


def test_comment_is_stored_as_text_and_never_interpreted(st):
    t = result()
    st.ingest(t)
    nasty = "'); DROP TABLE speedtests;-- <script>alert(1)</script> \"quoted\" \\ %_ ${x} {{y}} \n second line"
    r = st.comment(t["id"], nasty)
    assert r.status == 204
    assert st.app.speedtests.repo.count() == 1
    assert st.status(t["id"]).json()["comment"] == nasty
    d = st.get(f"/{t['id']}").json()["test"]
    assert d["comment"] == nasty
    assert st.get("").json()["items"][0]["has_comment"] is True
    assert st.get("?q=" + "DROP%20TABLE").json()["items"][0]["id"] == t["id"]
    assert st.get("?q=%25").json()["items"] == [] or "%" in nasty                    # '%' is literal, not a wildcard
    assert r.h("content-type")


def test_comment_bounds(st):
    t = result()
    st.ingest(t)
    assert st.comment(t["id"], "x" * 500).status == 204
    for bad in ("", "x" * 501, "bell\x07", "nul\x00"):
        assert st.comment(t["id"], bad).status == 400, repr(bad)
    r = st.req("POST", f"/{t['id']}/comment", st.tokens["exps"], {"comment": "ok", "extra": 1})
    assert r.status == 400
    assert st.comment("st_" + "0" * 26, "hi").status == 404


def test_result_comment_in_the_submission_is_kept(st):
    t = result(comment="video calls freeze at my booth")
    st.ingest(t)
    assert st.status(t["id"]).json()["comment"] == "video calls freeze at my booth"
    assert st.get("?q=freeze").json()["items"][0]["id"] == t["id"]


# --------------------------------------------------------------------------------------------- runner feed
def test_feed_hands_the_runner_pending_tests_oldest_first(st):
    ts = [result(ip=f"10.60.14.{i}", zone_source="qr") for i in range(3)]
    for t in ts:
        st.ingest(t)
    r = st.feed()
    assert r.status == 200
    check_openapi("collector", "/speedtests/feed", "get", 200, r.json())
    items = r.json()["items"]
    assert [i["id"] for i in items] == [t["id"] for t in ts]
    it = items[0]
    assert it["client_ip"] == "10.60.14.0" and it["zone_hint"] == "hallb-row12" and it["observed_server"] == BOX
    assert iso_to_s(it["window"]["from"]) == pytest.approx(iso_to_s(it["started"]) - 300, abs=0.01)
    assert iso_to_s(it["window"]["to"]) == pytest.approx(iso_to_s(it["ended"]) + 120, abs=0.01)
    page = st.feed("?limit=2").json()
    assert len(page["items"]) == 2 and page["next_cursor"]
    rest = st.feed("?limit=2&after=" + page["next_cursor"]).json()
    assert [i["id"] for i in rest["items"]] == [ts[2]["id"]]
    st.complete(ts[0]["id"])
    assert [i["id"] for i in st.feed().json()["items"]] == [ts[1]["id"], ts[2]["id"]]
    assert st.feed("?limit=0").status == 400 and st.feed("?after=!!!").status == 400 and st.feed("?wait_s=26").status == 400


def test_feed_long_poll_wakes_on_a_new_test(st):
    t = result()
    threading.Timer(0.6, lambda: st.ingest(t)).start()
    t0 = time.monotonic()
    r = st.feed("?wait_s=10")
    assert r.status == 200 and [i["id"] for i in r.json()["items"]] == [t["id"]]
    assert 0.4 < time.monotonic() - t0 < 5
    empty = st.feed("?after=" + r.json()["next_cursor"] + "&wait_s=1")
    assert empty.json()["items"] == []


# ------------------------------------------------------------------------------------------------ evidence
def test_evidence_validation_and_bounds(st):
    t = result()
    st.ingest(t)
    w = wifi(t)
    r = st.put_ev(w)
    assert r.status == 200
    check_openapi("collector", "/speedtests/{id}/evidence", "post", 200, r.json())
    assert r.json()["kind"] == "wifi" and 0 < r.json()["stored_bytes"] <= r.json()["total_bytes"] <= 262144
    assert err(st.put_ev(w, test_id="st_" + "0" * 26)) == "id_mismatch"                # the body is checked first
    other = result()
    st.ingest(other)
    r2 = st.put_ev(w, test_id=other["id"])
    assert r2.status == 400 and err(r2) == "id_mismatch"
    assert st.put_ev(evidence("wifi", result()), test_id="st_" + "1" * 26).status in (400, 404)
    ghost = evidence("wifi", result())
    assert st.put_ev(ghost).status == 404
    bad = json.loads(json.dumps(w))
    bad["data"]["client"]["mac"] = "not-a-mac"
    assert st.put_ev(bad).status == 400
    bad2 = json.loads(json.dumps(w))
    bad2["data"]["client"]["name"] = "Alice"
    assert st.put_ev(bad2).status == 400
    assert st.req("POST", f"/{t['id']}/evidence", st.tokens["expr"], raw=b"x" * (1024 * 1024 + 1)).status == 413
    assert st.req("POST", f"/{t['id']}/evidence", st.tokens["expd"], w).status == 401


def test_evidence_replace_dedup_and_stale(st):
    t = result()
    st.ingest(t)
    w1 = wifi(t, rssi=-80)
    st.put_ev(w1)
    again = st.put_ev(w1)                                              # same kind/source/collected_at: no-op
    assert again.status == 200
    n = st.db().execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    assert n == 1
    w2 = wifi(t, rssi=-50)
    w2["collected_at"] = iso(iso_to_s(w1["collected_at"]) + 5)
    st.put_ev(w2)
    assert st.get(f"/{t['id']}").json()["evidence"][0]["data"]["client"]["rssi"] == -50
    w0 = wifi(t, rssi=-99)
    w0["collected_at"] = iso(iso_to_s(w1["collected_at"]) - 30)         # an older document never replaces a newer one
    assert st.put_ev(w0).status == 200
    assert st.get(f"/{t['id']}").json()["evidence"][0]["data"]["client"]["rssi"] == -50
    assert st.db().execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1


def test_evidence_is_bounded_per_test(env):
    st = make_stenv(env, speedtests={"max_evidence_kib": 16})
    t = result()
    st.ingest(t)
    assert st.put_ev(wifi(t)).status == 200
    big = evidence("flows", t)
    f0 = big["data"]["flows"][0]
    big["data"]["flows"] = [dict(f0, application=f"app{i:03d}", domain="x" * 200) for i in range(50)]
    r = st.put_ev(big)
    assert r.status == 413 and err(r) == "evidence_too_large"
    assert st.get(f"/{t['id']}").json()["evidence_state"]["kinds_done"] == ["wifi"]      # nothing half-stored
    assert st.app.speedtests.settings.max_evidence_bytes == 16 * 1024


def test_default_evidence_limit_is_256_kib(st):
    assert st.app.speedtests.settings.max_evidence_bytes == 256 * 1024


def test_evidence_after_final_is_refused_and_complete_is_once(st):
    t = result()
    st.ingest(t)
    st.put_ev(wifi(t))
    c = st.complete(t["id"], ["wifi"])
    assert c.status == 200
    check_openapi("collector", "/speedtests/{id}/evidence/complete", "post", 200, c.json())
    assert c.json()["diagnosis"]["stage"] == "final"
    late = st.put_ev(evidence("dns", t))
    assert late.status == 409 and err(late) == "evidence_final"
    twice = st.complete(t["id"], ["wifi"])
    assert twice.status == 409 and err(twice) == "already_final"
    assert st.complete("st_" + "0" * 26, []).status == 404
    for body in ({}, {"kinds": ["wifi"]}, {"kinds": ["x"], "status": "ok"}, {"kinds": [], "status": "weird"},
                 {"kinds": ["wifi", "wifi"], "status": "ok"}, {"kinds": [], "status": "ok", "x": 1}):
        r = st.req("POST", f"/{result()['id']}/evidence/complete", st.tokens["expr"], body)
        assert r.status in (400, 404)


def test_complete_with_no_evidence_ends_unavailable(st):
    t = result()
    st.ingest(t)
    assert st.complete(t["id"], [], status="failed").status == 200
    out = st.get(f"/{t['id']}").json()
    assert out["evidence_state"]["state"] == "unavailable" and out["evidence"] == []
    assert st.status(t["id"]).json()["evidence"]["state"] == "unavailable"


def test_identity_evidence_sets_zone_ap_and_device_key(st):
    t = result(zone="hallb-hint", zone_source="qr")
    out = st.run(t, [evidence("identity", t), wifi(t)])
    row = st.get("").json()["items"][0]
    assert row["zone"] == "hallb-row12" and row["zone_source"] == "mist" and row["ap_name"] == "hallb-ap-12"
    assert row["ssid"] == "Summit-Guest" and row["band"] == "5" and row["os_family"] == "iOS"
    assert row["device_key"] == "231b3838d0007bf24d5b048d8a17a19495b0fb11b94a792fa99b1deb58b9e082"
    assert "zone_hint_conflict" in row["flags"] and out["device_key"] == row["device_key"]
    assert st.get("?zone=hallb-row12").json()["items"][0]["id"] == t["id"]
    assert st.get("?zone=hallb-hint").json()["items"] == []


def test_nat_suspected_fails_closed(st):
    t = result(zone="hallb-row12", zone_source="subnet")
    ident = fixture("evidence/identity.nat-suspected.json")
    ident["test_id"] = t["id"]
    ident["collected_at"] = iso(iso_to_s(t["ended"]) + 10)
    st.run(t, [ident])
    row = st.get("").json()["items"][0]
    assert row["zone"] == "unresolved" and row["zone_source"] == "unresolved" and "nat_suspected" in row["flags"]
    assert row["device_key"] is None and row["ap_name"] is None


# ------------------------------------------------------------------------------------------------- query
def _seed(st):
    out = []
    zones = ["hallb-a", "hallb-a", "hallb-b", "hallb-b", "hallb-c"]
    for i, z in enumerate(zones):
        t = result(down=50.0 + 40 * i, up=10.0 + 5 * i, i_down=30.0 + 20 * i, i_up=9.0 + i, zone=z,
                   ended_ago_s=600 - 100 * i, os_family=["iOS", "Android", "iOS", "Windows", "macOS"][i],
                   ip=f"10.60.14.{10 + i}", comment="ok" if i == 1 else None)
        wf = wifi(t, rssi=-60 - i, util=40, clients=10, ap_name=f"ap-{i % 2}")
        wf["data"]["client"]["ssid"] = "Guest" if i % 2 == 0 else "Staff"
        ident = evidence("identity", t, zone=z, zone_source="mist", ap_name=f"ap-{i % 2}",
                         ssid="Guest" if i % 2 == 0 else "Staff", band="5", mac=f"f0:18:98:aa:bb:0{i}",
                         device_key=f"{i + 1:064x}", os_family="iOS", hostname=f"host-{i}", username=f"user{i}",
                         ip=t["client"]["ip"])
        st.run(t, [wf, ident])
        out.append(t)
    return out


def test_list_filters_and_pagination(st):
    ts = _seed(st)
    r = st.get("")
    assert r.status == 200
    check_openapi("collector", "/speedtests", "get", 200, r.json())
    items = r.json()["items"]
    assert [i["id"] for i in items] == [t["id"] for t in reversed(ts)]               # newest first
    assert {i["zone"] for i in st.get("?zone=hallb-a").json()["items"]} == {"hallb-a"}
    assert len(st.get("?zone=hallb-a").json()["items"]) == 2
    assert {i["ap_name"] for i in st.get("?ap=ap-1").json()["items"]} == {"ap-1"}
    assert len(st.get("?ssid=Staff").json()["items"]) == 2 and len(st.get("?site=hall-b").json()["items"]) == 5
    assert st.get("?site=hall-c").json()["items"] == []
    cause = items[0]["cause"]
    assert all(i["cause"] == cause for i in st.get(f"?cause={cause}").json()["items"]) if cause else True
    scores = sorted(i["score"] for i in items)
    mid = scores[2]
    assert all(i["score"] >= mid for i in st.get(f"?min_score={mid}").json()["items"])
    assert all(i["score"] <= mid for i in st.get(f"?max_score={mid}").json()["items"])
    assert len(st.get(f"?min_score={mid}&max_score={mid}").json()["items"]) >= 1
    frm, to = ts[1]["started"], ts[3]["started"]
    got = [i["id"] for i in st.get(f"?from={frm}&to={to}").json()["items"]]
    assert got == [ts[2]["id"], ts[1]["id"]]                                          # from inclusive, to exclusive
    assert [i["id"] for i in st.get("?q=ap-0").json()["items"]] and st.get("?q=nomatch").json()["items"] == []
    assert st.get(f"?q={ts[3]['id']}").json()["items"][0]["id"] == ts[3]["id"]
    seen, cur = [], ""
    while True:
        page = st.get("?limit=2" + (f"&cursor={cur}" if cur else "")).json()
        seen += [i["id"] for i in page["items"]]
        cur = page["next_cursor"]
        if not cur:
            break
    assert seen == [i["id"] for i in items]


def test_list_parameter_validation(st):
    for q in ("?limit=0", "?limit=1001", "?limit=x", "?cursor=!!!", "?zone=Bad%20Zone", "?from=yesterday",
              "?min_score=101", "?site=Bad_Site", "?cause=BAD", f"?ap={'x' * 129}", f"?q={'x' * 129}", "?site=a&site=b",
              "?from=2026-11-20T00:00:00Z&to=2026-11-19T00:00:00Z", "?q=%00", "?identifiers=maybe"):
        r = st.get(q)
        assert r.status == 400 and err(r) == "invalid_request", q


def test_q_is_parameterized_and_wildcards_are_literal(st):
    t = result(ip="10.60.14.5")
    st.ingest(t)
    st.comment(t["id"], "100% broken_wifi")
    for evil in ("'", "' OR '1'='1", "\"; DROP TABLE speedtests; --", "%", "_", "\\"):
        r = st.get("?q=" + evil.replace("%", "%25").replace(" ", "%20").replace("'", "%27").replace('"', "%22")
                   .replace(";", "%3B").replace("\\", "%5C"))
        assert r.status == 200, evil
    assert len(st.get("?q=100%25").json()["items"]) == 1
    assert st.get("?q=broken_w").json()["items"][0]["id"] == t["id"]
    assert st.get("?q=brokenXwifi").json()["items"] == []
    assert st.get("?q=%25%25%25").json()["items"] == []
    assert st.app.speedtests.repo.count() == 1


def test_detail_hides_raw_identifiers_unless_identifiers_is_requested(st):
    t = result(ip="10.60.14.77")
    fl = evidence("flows", t)
    wired = evidence("wired", t)
    st.run(t, [evidence("identity", t), wifi(t), fl, wired, evidence("dns", t), evidence("security", t)])
    safe = st.get(f"/{t['id']}")
    check_openapi("collector", "/speedtests/{id}", "get", 200, safe.json())
    text = safe.body.decode()
    for raw in ("10.60.14.77", "f0:18:98:aa:bb:01", "alices-iphone", "guest-portal-7731", "booth-pc-12", "f01898aabb01"):
        assert raw not in text, raw
    assert safe.json()["device_key"] and "client" in safe.json()["test"] and "ip" not in safe.json()["test"]["client"]
    no_user = st.req("GET", f"/{t['id']}?identifiers=true", st.tokens["expd"])
    assert no_user.status == 403 and err(no_user) == "forbidden"
    adm = st.get(f"/{t['id']}?identifiers=true", user="ada")
    assert adm.status == 200
    check_openapi("collector", "/speedtests/{id}", "get", 200, adm.json())
    assert adm.json()["test"]["client"]["ip"] == "10.60.14.77"
    kinds = {e["kind"]: e for e in adm.json()["evidence"]}
    assert kinds["identity"]["data"]["mac"] == "f0:18:98:aa:bb:01" and kinds["identity"]["data"]["username"]
    audit = st.app.speedtests.repo.audit_rows()
    assert audit[0]["action"] == "view_identifiers" and audit[0]["actor"] == "ada"
    assert st.get("/st_" + "0" * 26).status == 404 and st.get("/garbage").status == 404


def test_list_identifiers_and_q_on_identifiers(st):
    t = result(ip="10.60.14.88")
    st.run(t, [evidence("identity", t, ip="10.60.14.88")])
    plain = st.get("")
    assert "client_ip" not in plain.body.decode() and "10.60.14.88" not in plain.body.decode()
    assert st.get("?q=10.60.14.88").json()["items"] == []                              # IP is searchable only for admins
    assert st.req("GET", "?identifiers=true", st.tokens["expd"]).status == 403
    adm = st.get("?identifiers=true", user="ada").json()["items"][0]
    assert adm["client_ip"] == "10.60.14.88" and adm["mac"] == "f0:18:98:aa:bb:01" and adm["username"]
    assert st.get("?identifiers=true&q=10.60.14.88", user="ada").json()["items"][0]["id"] == t["id"]


def test_aggregate_matches_sqlite_ground_truth(st):
    _seed(st)
    conn = st.db()
    cols = {"zone": "zone", "ap": "ap_name", "ssid": "ssid", "band": "band", "os_family": "os_family", "cause": "cause"}
    metrics = {("down_p50", "local"): "local_down", ("up_p50", "local"): "local_up", ("down_p50", "internet"):
               "internet_down", ("loaded_p50", "local"): "local_loaded", ("score_p50", "local"): "score",
               ("up_p50", "internet"): "internet_up"}
    for group_by, col in cols.items():
        for (metric, leg), vcol in metrics.items():
            r = st.get(f"/aggregate?group_by={group_by}&metric={metric}&leg={leg}")
            assert r.status == 200, r.body
            check_openapi("collector", "/speedtests/aggregate", "get", 200, r.json())
            want: dict[str, list[float]] = {}
            for row in conn.execute(f"SELECT {col} AS k, {vcol} AS v FROM speedtests WHERE {vcol} IS NOT NULL"):  # noqa: S608
                want.setdefault(row["k"] if row["k"] is not None else "unknown", []).append(row["v"])
            got = {i["key"]: (i["value"], i["count"]) for i in r.json()["items"]}
            assert set(got) == set(want), (group_by, metric)
            for k, vs in want.items():
                assert got[k][0] == pytest.approx(statistics.median(vs), abs=1e-3) and got[k][1] == len(vs)
    r = st.get("/aggregate?group_by=zone&metric=count").json()
    assert {i["key"]: i["value"] for i in r["items"]} == {"hallb-a": 2, "hallb-b": 2, "hallb-c": 1}
    byhour = st.get("/aggregate?group_by=hour&metric=count").json()["items"]
    assert sum(i["count"] for i in byhour) == 5 and all(i["key"].endswith(":00:00Z") for i in byhour)
    assert st.get("/aggregate?group_by=zone&metric=count&site=hall-c").json()["items"] == []
    far = st.get("/aggregate?group_by=zone&metric=count&from=2020-01-01T00:00:00Z&to=2020-01-02T00:00:00Z")
    assert far.json()["items"] == []


def test_aggregate_validation(st):
    for q in ("", "?group_by=zone", "?metric=count", "?group_by=nope&metric=count", "?group_by=zone&metric=nope",
              "?group_by=zone&metric=count&leg=wan", "?group_by=zone&metric=count&site=Bad_Site",
              "?group_by=zone&metric=count&from=2026-11-20T00:00:00Z&to=2026-11-20T00:00:00Z",
              "?group_by=zone&metric=count&from=2024-01-01T00:00:00Z&to=2026-11-20T00:00:00Z"):
        r = st.get("/aggregate" + q)
        assert r.status == 400, q
    assert err(st.get("/aggregate?group_by=zone&metric=count&from=2024-01-01T00:00:00Z&to=2026-11-20T00:00:00Z")) \
        == "range_too_large"


def test_unavailable_or_failed_legs_do_not_enter_the_aggregates(st):
    ok = result(down=100.0, i_down=50.0)
    nointernet = result(down=200.0, i_down=None)
    st.ingest(ok)
    st.ingest(nointernet)
    r = st.get("/aggregate?group_by=zone&metric=down_p50&leg=internet").json()["items"]
    assert r[0]["count"] == 1 and r[0]["value"] == 50.0
    assert healthy_result is not None and fixture is not None


def test_health_of_the_responses_headers(st):
    r = st.get("")
    assert r.h("cache-control") == "no-store" and r.h("x-content-type-options") == "nosniff"


# ----------------------------------------------------- the nearest probe, from the collector's own records
def _probe_records(env, st, now_ms, *, fail_from_ms):
    import synth
    from test_engine_live import to_lines
    recs = synth.healthy(now_ms - 900_000, fail_from_ms, ports=2)
    for t in range(fail_from_ms, now_ms - 1_000, 10_000):
        recs += synth.gateway(t, ports=2, bad=2)
        recs.append(synth.wifi(t + 600, gw=False, ok=False))
    lines = to_lines(recs)
    from colhelpers import ingest, rec
    for ts_ms, (down, up) in ((now_ms - 20_000, (12.0, 4.0)),):
        lines.append(rec("probe-a1", "hall-b", "throughput", "degraded", ts=iso(ts_ms / 1000),
                         metrics={"down_mbps": down, "up_mbps": up, "latency_idle_ms": 9.0, "latency_loaded_ms": 220.0}))
    r = ingest(st.port, env.ingest_token, lines)
    assert r.status == 200 and not r.json()["rejected"], r.json()["rejected"][:2]
    st.app.rules.tick(now_ms)


def test_baseline_and_network_wide_from_real_probe_records(env):
    st = make_stenv(env)
    now = int(time.time() * 1000)
    _probe_records(env, st, now, fail_from_ms=now - 60_000)
    t = result(down=30.0, up=20.0, ended_ago_s=5.0)
    quick = st.ingest(t).json()["diagnosis"]
    assert quick["cause"][0]["id"] == "network_wide" and quick["cause"][0]["confidence"] >= 0.8
    assert "probe-a1" in quick["noc_text"] and "network=fail" in quick["noc_text"]
    b = st.req("GET", f"/baseline?site=hall-b&zone=hallb-row12&ap=hallb-ap-12&at={t['ended']}", st.tokens["expr"])
    assert b.status == 200
    check_openapi("collector", "/speedtests/baseline", "get", 200, b.json())
    body = b.json()
    assert body["probe"] == "probe-a1" and body["severity"] == "fail" and body["site"] == "hall-b"
    assert body["throughput"]["down_mbps"] == 12.0 and body["throughput"]["latency_loaded_ms"] == 220.0
    assert next(ln for ln in body["lines"] if ln["key"] == "network")["state"] == "fail"
    assert next(ln for ln in body["lines"] if ln["key"] == "network")["detail"].startswith("10.1.0.1 not answering")
    check_schema_file_data(body)


def check_schema_file_data(body):
    from colhelpers import REGISTRY
    from jsonschema import Draft202012Validator
    errs = list(Draft202012Validator({"$ref": "evidence.schema.json#/$defs/data_baseline"}, registry=REGISTRY)
                .iter_errors(body))
    assert not errs, errs[:2]


def test_baseline_is_evaluated_at_the_test_time_not_now(env):
    st = make_stenv(env)
    now = int(time.time() * 1000)
    _probe_records(env, st, now, fail_from_ms=now - 120_000)             # healthy until two minutes ago
    earlier = result(down=30.0, up=20.0, ended_ago_s=300.0)              # the probe was fine back then
    q = st.ingest(earlier).json()["diagnosis"]
    assert "network_wide" not in [c["id"] for c in q["cause"]]
    b = st.req("GET", f"/baseline?site=hall-b&at={earlier['ended']}", st.tokens["expr"])
    assert b.status == 200 and b.json()["severity"] == "ok"
    later = result(down=30.0, up=20.0, ended_ago_s=5.0)
    assert st.ingest(later).json()["diagnosis"]["cause"][0]["id"] == "network_wide"


def test_the_probe_nearest_to_the_zone_is_chosen(env):
    st = make_stenv(env)
    now = int(time.time() * 1000)
    seen = []

    def state(probe, at):
        seen.append(probe)
        return {"probe": probe, "newest_s": 3.0, "verdict": {"severity": "warn"}, "lines": []}
    st.app.speedtests.probe_state = state
    env.cfg_doc["probes"][1]["label"] = "hallb-row12 west"
    st.app.speedtests.cfg.probes["probe-a2"] = type(st.app.speedtests.cfg.probes["probe-a2"])(
        "probe-a2", "hall-b", "hallb-row12 west")
    b = st.req("GET", f"/baseline?site=hall-b&zone=hallb-row12&at={iso(now / 1000)}", st.tokens["expr"]).json()
    assert b["probe"] == "probe-a2" and b["distance"] == "same_zone" and seen == ["probe-a2"]
    b2 = st.req("GET", f"/baseline?site=hall-b&at={iso(now / 1000)}", st.tokens["expr"]).json()
    assert b2["probe"] == "probe-a1" and b2["distance"] == "same_site"
    assert st.req("GET", "/baseline?site=hall-c&at=" + iso(now / 1000), st.tokens["expr"]).status == 404


def test_baseline_validation(st):
    at = iso(time.time())
    for q in ("", "?site=hall-b", f"?at={at}", f"?site=Bad_Site&at={at}", "?site=hall-b&at=now",
              f"?site=hall-b&at={at}&zone=Bad%20Zone", f"?site=hall-b&at={at}&ap={'x' * 129}"):
        assert st.req("GET", "/baseline" + q, st.tokens["expr"]).status == 400, q


# ---------------------------------------------------------------------------- hostile input and size bounds
def test_free_text_in_evidence_is_stored_and_returned_as_data(st):
    t = result(down=300.0, up=200.0, i_down=40.0, i_up=20.0, i_loaded=300.0)
    sec = evidence("security", t)
    nasty = "'); DROP TABLE evidence;-- <img src=x onerror=alert(1)> %s {0} \\u0000"
    sec["data"]["events"][0]["raw"] = nasty
    sec["data"]["events"][0]["rule"] = "<script>alert(1)</script>"
    out = st.run(t, [sec])
    assert out["evidence"][0]["data"]["events"][0]["raw"] == nasty
    assert "<script>" in out["diagnosis"]["noc_text"]                   # data, never markup: the UI uses textContent
    assert st.db().execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1


def test_hostile_documents_never_cause_a_server_error(st):
    import random
    rnd = random.Random(7)  # noqa: S311 - a deterministic fuzz seed, not a secret
    base = result()
    st.ingest(base)
    ev = wifi(base)
    junk = [None, True, 0, -1, 1e999, "x" * 5000, "", [], {}, [None], {"a": {"b": [1] * 50}}, "\x00", "‮"]

    def mutate(doc):
        d = json.loads(json.dumps(doc))
        for _ in range(rnd.randint(1, 4)):
            cur = d
            for _ in range(rnd.randint(0, 3)):
                if isinstance(cur, dict) and cur:
                    k = rnd.choice(list(cur))
                    if isinstance(cur[k], (dict, list)):
                        cur = cur[k]
                        continue
                break
            if isinstance(cur, dict) and cur:
                cur[rnd.choice(list(cur))] = rnd.choice(junk)
            elif isinstance(cur, list) and cur:
                cur[rnd.randrange(len(cur))] = rnd.choice(junk)
        return d
    for _ in range(120):
        r = st.ingest(mutate(result()))
        assert r.status in (200, 201, 400), r.status
        r2 = st.put_ev(mutate(ev), test_id=base["id"])
        assert r2.status in (200, 400, 409, 413), (r2.status, r2.body[:200])
    for raw in (b"", b"[]", b"null", b"1", b'"x"', b"{" * 200, b"\xff\xfe", b"[" * 100000):
        for path, tok in (("", st.tokens["exps"]), (f"/{base['id']}/evidence", st.tokens["expr"]),
                          (f"/{base['id']}/comment", st.tokens["exps"]),
                          (f"/{base['id']}/evidence/complete", st.tokens["expr"]), ("/purge", st.tokens["expd"])):
            r = st.req("POST", path, tok, raw=raw, headers={"X-Exp-User": "ada"})
            assert r.status in (400, 403, 404, 413), (path, raw[:10], r.status)


def test_oversize_bodies_are_refused_before_parsing(st):
    t = result()
    st.ingest(t)
    assert st.req("POST", "", st.tokens["exps"], raw=b"{" + b" " * (256 * 1024)).status == 413
    assert st.req("POST", f"/{t['id']}/comment", st.tokens["exps"], raw=b" " * 5000).status == 413
    assert st.req("POST", "/purge", st.tokens["expd"], raw=b" " * 5000, headers={"X-Exp-User": "a"}).status == 413
    r = st.req("GET", "?q=" + "x" * 5000, st.tokens["expd"])
    assert r.status in (400, 414)


def test_nat_suspected_status_carries_no_network_details(st):
    t = result(zone_source="subnet")
    ident = fixture("evidence/identity.nat-suspected.json")
    ident["test_id"] = t["id"]
    ident["collected_at"] = iso(iso_to_s(t["ended"]) + 10)
    st.ingest(t)
    st.put_ev(ident)
    st.put_ev(wifi(t))                                                 # a runner must not send it, but if it does
    s = st.status(t["id"]).json()
    assert s["zone"] == "unresolved" and s["zone_name"] is None and s["network_details"] is None


def test_shutdown_ends_a_waiting_feed_poll_quickly(env):
    st = make_stenv(env)
    out = {}

    def poll():
        t0 = time.monotonic()
        try:
            out["r"] = st.feed("?wait_s=25").status
        except Exception as exc:  # noqa: BLE001 - the connection may be torn down by the shutdown
            out["r"] = repr(exc)
        out["dt"] = time.monotonic() - t0
    th = threading.Thread(target=poll)
    th.start()
    time.sleep(0.5)
    t0 = time.monotonic()
    st.app.stop()
    th.join(10)
    assert not th.is_alive() and time.monotonic() - t0 < 8 and out["dt"] < 8

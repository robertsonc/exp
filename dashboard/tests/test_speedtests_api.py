"""Speedtest analytics routes (12 section 8): federation, partial results, role gating (SR-25), purge, CSRF."""
from __future__ import annotations

import json

import pytest
from exp_dashboard import speedtests as stmod

import st_fake

RAW = (st_fake.RAW_IP, st_fake.RAW_MAC, st_fake.RAW_HOST, st_fake.RAW_USER)
BASE = "/api/v1/speedtests"


@pytest.fixture()
def sw(make_world, monkeypatch):
    st_fake.install(monkeypatch)
    w = make_world()
    w.st = st_fake.attach(w)
    return w


def admin(w):
    c = w.client()
    r = c.post("/auth/sso", json_body={"token": w.sso_token(role="admin")})
    assert r.status == 200 and r.json()["role"] == "admin"
    c.csrf = r.json()["csrf"]
    return c


def calls(w, cid="col-a"):
    return w.st[cid].calls


def test_requires_a_session(sw):
    c = sw.client()
    assert c.get(BASE).status == 401
    assert c.get(BASE + "/aggregate?group_by=zone&metric=count").status == 401
    assert c.get(BASE + "/" + st_fake.st_id(1001)).status == 401
    assert c.post(BASE + "/purge", json_body={"by": "test", "value": st_fake.st_id(1001)}).status == 401


def test_list_federates_three_collectors_newest_first(sw):
    c = sw.as_user("vera")
    r = c.get(BASE + "?limit=1000")
    assert r.status == 200
    doc = r.json()
    assert {x["collector_id"] for x in doc["collectors"]} == {"col-a", "col-b", "col-c"}
    assert all(x["ok"] for x in doc["collectors"])
    assert len(doc["items"]) == 3 * 37 and doc["next_cursor"] is None
    ended = [i["ended"] for i in doc["items"]]
    assert ended == sorted(ended, reverse=True)
    assert {i["collector_id"] for i in doc["items"]} == {"col-a", "col-b", "col-c"}
    assert doc["identifiers"] is False


def test_viewer_and_operator_never_receive_raw_identifiers(sw):
    for who in ("vera", "alice"):
        c = sw.as_user(who)
        for path in (BASE + "?limit=1000&identifiers=1", BASE + "?identifiers=true", BASE + "?q=" + st_fake.RAW_IP):
            r = c.get(path)
            assert r.status == 200
            assert not any(x in r.body.decode() for x in RAW), (who, path)
            assert r.json()["identifiers"] is False
        tid = st_fake.st_id(1001)
        for suffix in ("", "?identifiers=1", "?identifiers=true"):
            d = c.get(f"{BASE}/{tid}{suffix}")
            assert d.status == 200 and not any(x in d.body.decode() for x in RAW), (who, suffix)
    # the flag never reached a collector, and no user text search matched a raw value
    for cid in sw.st:
        assert all("identifiers" not in x["query"] for x in calls(sw, cid))


def test_noc_session_is_a_viewer(sw):
    c = sw.client()
    assert c.noc(sw.noc_token).status == 200
    r = c.get(BASE + f"/{st_fake.st_id(1001)}?identifiers=1")
    assert r.status == 200 and not any(x in r.body.decode() for x in RAW)
    assert c.post(BASE + "/purge", json_body={"by": "test", "value": st_fake.st_id(1001), "confirm": True}).status == 403


def test_admin_gets_identifiers_only_when_asked_and_it_is_audited_by_user(sw):
    c = admin(sw)
    plain = c.get(BASE + "?limit=5")
    assert plain.status == 200 and not any(x in plain.body.decode() for x in RAW)
    asked = c.get(BASE + "?limit=5&identifiers=1")
    doc = asked.json()
    assert doc["identifiers"] is True and doc["items"][0]["client_ip"] == st_fake.RAW_IP
    sent = [x for x in calls(sw) if x["query"].get("identifiers") == "true"]
    assert sent and all(x["user"] == "admin@example.com" for x in sent)
    d = c.get(f"{BASE}/{st_fake.st_id(1001)}?identifiers=1").json()
    assert d["identifiers"] is True and d["test"]["client"]["ip"] == st_fake.RAW_IP
    ident = next(e for e in d["evidence"] if e["kind"] == "identity")["data"]
    assert ident["mac"] == st_fake.RAW_MAC and ident["username"] == st_fake.RAW_USER
    # without asking, the admin sees the redacted view too
    d2 = c.get(f"{BASE}/{st_fake.st_id(1001)}")
    assert not any(x in d2.body.decode() for x in RAW)


def test_a_leaky_collector_still_does_not_reach_a_viewer(sw):
    for s in sw.st.values():
        s.leaky = True
    c = sw.as_user("vera")
    r = c.get(BASE + "?limit=1000")
    assert r.status == 200 and not any(x in r.body.decode() for x in RAW)
    d = c.get(f"{BASE}/{st_fake.st_id(1001)}")
    body = d.body.decode()
    assert d.status == 200 and not any(x in body for x in RAW)
    doc = d.json()
    assert "ip" not in doc["test"]["client"]
    assert next(e for e in doc["evidence"] if e["kind"] == "identity")["data"]["scrubbed"] is True
    assert doc["device_key"] == st_fake.DEVICE_KEY            # the pseudonymous join key stays


def test_one_collector_down_gives_flagged_partial_results(sw):
    sw.fakes["col-b"].stop()
    c = sw.as_user("vera")
    r = c.get(BASE + "?limit=1000")
    assert r.status == 200
    doc = r.json()
    by = {x["collector_id"]: x for x in doc["collectors"]}
    assert by["col-b"]["ok"] is False and by["col-b"]["error"] and by["col-a"]["ok"] and by["col-c"]["ok"]
    assert len(doc["items"]) == 2 * 37
    a = c.get(BASE + "/aggregate?group_by=zone&metric=count").json()
    assert {x["collector_id"]: x["ok"] for x in a["collectors"]}["col-b"] is False
    # a test that lives only on the dead collector: a clear 502, not a misleading 404
    r = c.get(f"{BASE}/{st_fake.st_id(2001)}")
    assert r.status == 502 and r.json()["error"]["code"] == "collector_unreachable"
    # a test on a live one still opens
    assert c.get(f"{BASE}/{st_fake.st_id(1001)}").status == 200


def test_collector_without_analytics_is_flagged_not_an_error(sw):
    sw.st["col-c"].enabled = False
    doc = sw.as_user("vera").get(BASE + "?limit=1000").json()
    by = {x["collector_id"]: x for x in doc["collectors"]}
    assert by["col-c"]["ok"] is False and by["col-c"]["error"] == "speedtests_disabled"
    assert len(doc["items"]) == 2 * 37
    assert sw.as_user("vera").get(f"{BASE}/{st_fake.st_id(1001)}").status == 200
    assert sw.as_user("vera").get(f"{BASE}/{st_fake.st_id(3001)}").status == 404


def test_filters_are_validated_forwarded_and_unknown_params_dropped(sw):
    c = sw.as_user("vera")
    r = c.get(BASE + "?site=hall-a&zone=lobby&min_score=50&max_score=90&cause=dns&evil=1&limit=1000")
    assert r.status == 200
    sent = calls(sw, "col-a")[-1]["query"]
    assert sent["site"] == "hall-a" and sent["min_score"] == "50" and "evil" not in sent
    assert all(i["zone"] == "lobby" and 50 <= i["score"] <= 90 for i in r.json()["items"])
    for bad in ("min_score=101", "limit=0", "limit=1001", "site=Bad_Site", "from=yesterday", "cursor=%24%24",
                "q=" + "x" * 129, "zone=a%00b"):
        r = c.get(BASE + "?" + bad)
        assert r.status == 400, bad
    assert c.get(BASE + "/aggregate?group_by=nope&metric=count").status == 400
    assert c.get(BASE + "/aggregate?group_by=zone").status == 400


def test_paging_walks_every_test_exactly_once_across_collectors(sw):
    c = sw.as_user("vera")
    seen: list[str] = []
    cursor = None
    for _ in range(20):
        r = c.get(BASE + "?limit=10" + (f"&cursor={cursor}" if cursor else ""))
        assert r.status == 200
        doc = r.json()
        seen += [i["id"] for i in doc["items"]]
        cursor = doc["next_cursor"]
        if not cursor:
            break
    assert len(seen) == len(set(seen)) == 3 * 37
    assert c.get(BASE + "?cursor=AAAA").status == 400            # a cursor that is not ours


def test_aggregate_merges_counts_and_flags_approximate_medians(sw):
    c = sw.as_user("vera")
    r = c.get(BASE + "/aggregate?group_by=zone&metric=count")
    assert r.status == 200
    doc = r.json()
    total = sum(i["count"] for i in doc["items"])
    assert total == 3 * 37 and sum(i["value"] for i in doc["items"]) == total
    assert doc["items"] == sorted(doc["items"], key=lambda i: (-i["count"], i["key"]))
    med = c.get(BASE + "/aggregate?group_by=zone&metric=score_p50&leg=internet").json()
    assert all(0 <= i["value"] <= 100 for i in med["items"]) and any(i.get("approximate") for i in med["items"])
    hours = c.get(BASE + "/aggregate?group_by=hour&metric=count").json()["items"]
    assert [h["key"] for h in hours] == sorted(h["key"] for h in hours)


def test_detail_shape_and_not_found(sw):
    c = sw.as_user("vera")
    d = c.get(f"{BASE}/{st_fake.st_id(2002)}")
    assert d.status == 200 and d.headers["x-exp-collector"] == "col-b"
    doc = d.json()
    assert {e["kind"] for e in doc["evidence"]} == {"wifi", "wired", "flows", "wan", "security", "baseline", "dns",
                                                    "identity"}
    assert doc["diagnosis"]["stage"] == "final" and doc["collector_id"] == "col-b"
    assert c.get(f"{BASE}/{st_fake.st_id(999999)}").status == 404
    assert c.get(BASE + "/st_bad").status == 404
    assert c.get(BASE + "/purge").status == 404 and c.get(BASE + "/stream").status == 404


def test_purge_is_admin_only_csrf_protected_confirmed_and_audited(sw):
    tid = st_fake.st_id(1002)
    body = {"by": "test", "value": tid, "confirm": True}
    for who in ("vera", "alice"):
        c = sw.as_user(who)
        r = c.post(BASE + "/purge", json_body=body)
        assert r.status == 403 and r.json()["error"]["code"] == "insufficient_role"
    assert all(x["path"] != "speedtests/purge" for cid in sw.st for x in calls(sw, cid))
    c = admin(sw)
    assert c.post(BASE + "/purge", json_body=body, csrf=False).status == 403
    assert c.post(BASE + "/purge", json_body=body, origin="https://evil.example").status == 403
    assert c.post(BASE + "/purge", json_body={"by": "test", "value": tid}).status == 400      # not confirmed
    assert any(r["id"] == tid for r in sw.st["col-a"].rows)
    dry = c.post(BASE + "/purge", json_body={"by": "test", "value": tid, "dry_run": True})
    assert dry.status == 200 and dry.json()["dry_run"] is True and dry.json()["matched_tests"] == 1
    assert any(r["id"] == tid for r in sw.st["col-a"].rows)
    done = c.post(BASE + "/purge", json_body=body)
    assert done.status == 200
    doc = done.json()
    assert doc["matched_tests"] == 1 and doc["deleted"]["tests"] == 1 and doc["partial"] is False
    assert not any(r["id"] == tid for r in sw.st["col-a"].rows)                           # end state: gone
    assert sw.as_user("vera").get(f"{BASE}/{tid}").status == 404
    assert [a["actor"] for a in sw.st["col-a"].audit] == ["admin@example.com", "admin@example.com"]


def test_purge_by_device_key_hits_every_collector_and_reports_partial(sw):
    c = admin(sw)
    sw.fakes["col-c"].stop()
    r = c.post(BASE + "/purge", json_body={"by": "device_key", "value": st_fake.DEVICE_KEY.upper(),
                                           "confirm": True})
    doc = r.json()
    assert r.status == 200 and doc["partial"] is True and doc["matched_tests"] == 2 * 37
    assert {p["collector_id"] for p in doc["per_collector"]} == {"col-a", "col-b"}
    assert sw.st["col-a"].rows == [] and sw.st["col-b"].rows == []


@pytest.mark.parametrize("by,value", [("device_key", "abc"), ("mac", "not-a-mac"), ("ip", "x y"), ("test", "st_1"),
                                      ("name", "alice"), ("mac", ""), ("ip", 5)])
def test_purge_rejects_bad_subjects(sw, by, value):
    r = admin(sw).post(BASE + "/purge", json_body={"by": by, "value": value, "confirm": True})
    assert r.status == 400


def test_purge_audit_log_never_contains_the_identifier(sw, caplog):
    caplog.set_level("INFO", logger="exp_dashboard.speedtests")
    admin(sw).post(BASE + "/purge", json_body={"by": "mac", "value": st_fake.RAW_MAC, "confirm": True})
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "speedtest purge by=mac" in text and st_fake.RAW_MAC not in text and "admin@example.com" in text


def test_spa_routes_serve_the_shell(sw):
    c = sw.as_user("vera")
    tid = st_fake.st_id(1001)
    for p in ("/speedtests", "/speedtests/breakdowns", "/speedtests/support", f"/speedtests/test/{tid}"):
        r = c.get(p)
        assert r.status == 200 and b"<main id=\"app\"" in r.body, p
    for p in ("/speedtests/test/st_x", "/speedtests/other", "/speedtests/test"):
        assert c.get(p).status == 404, p


def test_sanitize_detail_is_idempotent_and_keeps_device_key():
    d = st_fake.StData("hall-a", "probe-a1", count=1).docs[st_fake.st_id(1)]
    s1 = stmod.sanitize_detail(d)
    assert not any(x in json.dumps(s1) for x in RAW)
    assert stmod.sanitize_detail(s1) == s1 and s1["device_key"] == st_fake.DEVICE_KEY
    # AP and switch MACs (infrastructure) are kept
    wifi = next(e for e in s1["evidence"] if e["kind"] == "wifi")["data"]
    assert wifi["ap"]["mac"] == "5c:5b:35:00:01:a0"

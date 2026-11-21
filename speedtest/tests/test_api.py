"""Integration tests: every public route against the real daemon + the fake collector (validation errors, limits, tokens)."""
from __future__ import annotations

import base64
import json
import socket
import struct
import time

import oas
import pytest
from exp_common import ids
from exp_common import speedtest as st
from stbox import SENTINEL_ID, Box, FakeClock, submission, wait_for

from exp_speedtest.core import Core

XSS = "<script>alert(1)</script>\"'><img src=x onerror=alert(2)> ${7*7} {{7*7}} ' OR 1=1 --"


def err_code(r) -> str:
    return r.json()["error"]["code"]


# --------------------------------------------------------------------------------------------- page + config
def test_page_and_headers(box: Box):
    for path in ("/", f"/st/r/{st.new_speedtest_id()}"):
        r = box.get(path)
        assert r.status == 200 and r.h("content-type") == "text/html; charset=utf-8"
        csp = r.h("content-security-policy")
        assert "script-src 'sha256-" in csp and "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp
        assert r.h("x-content-type-options") == "nosniff" and r.h("referrer-policy") == "no-referrer"
        assert r.h("cache-control") == "no-cache" and b"<title>" in r.body
    assert box.get("/st/r/not-an-id").status == 404
    h = box.request("HEAD", "/")
    assert h.status == 200 and h.body == b"" and int(h.h("content-length")) > 100


def test_config_matches_openapi_and_leaks_nothing_internal(box: Box):
    r = box.get("/st/api/v1/config")
    assert r.status == 200
    oas.check("/st/api/v1/config", "get", 200, r.json())
    body = r.body.decode()
    for secret in ("127.0.0.1", "collector", "listen_ip", "client_subnets", "translated", "fingerprint", "token"):
        assert secret not in body, secret
    doc = r.json()
    assert doc["consent"]["version"] == 3 and doc["dns_zone"] == "t.speed.test.example" and doc["tls_mode"] == "none"
    assert doc["internet_leg"] == {"enabled": True, "paused": False, "provider": "cloudflare"}


def test_unknown_route_and_wrong_method(box: Box):
    r = box.get("/nope")
    assert r.status == 404 and err_code(r) == "not_found"
    r = box.post("/st/api/v1/config", {})
    assert r.status == 405 and r.h("allow") == "GET"
    assert box.get("/st/api/v1/sessions").status == 405
    assert box.get("/st/assets/nope.png").status == 404


def test_error_responses_carry_security_headers_and_no_store(box: Box):
    r = box.get("/nope")
    assert r.h("x-content-type-options") == "nosniff" and r.h("cache-control") == "no-store"
    assert "frame-ancestors 'none'" in r.h("content-security-policy")


def test_px_dns_leg_target(box: Box):
    r = box.get("/st/px", headers={"Host": f"0123456789abcdef.{box.config().dns_zone}"})
    assert r.status == 204 and r.h("timing-allow-origin") == "*" and r.h("access-control-allow-origin") == "*"
    assert r.h("cache-control") == "no-store"
    o = box.request("OPTIONS", "/st/px", headers={"Origin": "http://x", "Access-Control-Request-Method": "GET"})
    assert o.status == 204 and "GET" in o.h("access-control-allow-methods")


def test_assets_logo_served_with_locked_down_headers(box: Box):
    (box.paths.assets_dir / "logo").write_bytes(b"\x89PNG\r\n\x1a\n" + b"1" * 50)
    r = box.get("/st/assets/logo")
    assert r.status == 200 and r.h("content-type") == "image/png" and r.h("x-content-type-options") == "nosniff"
    assert "sandbox" in r.h("content-security-policy")
    assert box.get("/st/api/v1/config").json()["logo"] == "/st/assets/logo"


# ---------------------------------------------------------------------------------------------------- where
def test_where_sources(box: Box):
    r = box.get("/st/api/v1/where")
    assert r.status == 200 and r.json() == {"zone": "hall-a", "zone_name": "Hall A", "source": "subnet", "nat_suspected": False}
    oas.check("/st/api/v1/where", "get", 200, r.json())
    # hint only (an address outside the subnet table but inside client_subnets)
    r = box.get("/st/api/v1/where?z=hall-b", src="127.0.5.5")
    assert r.json()["source"] == "qr" and r.json()["zone"] == "hall-b"
    assert box.get("/st/api/v1/where?z=zzz-unknown", src="127.0.5.5").json()["source"] == "unresolved"
    assert box.get("/st/api/v1/where?z=BAD%20ZONE").status == 400
    # translated address -> fails closed even with a hint
    r = box.get("/st/api/v1/where?z=hall-a", src="127.0.9.9")
    assert r.json() == {"zone": "unresolved", "zone_name": None, "source": "unresolved", "nat_suspected": True}


def test_where_uses_the_runners_mist_cache_and_asks_for_unknown_ips(box: Box):
    assert box.get("/st/api/v1/where", src="127.0.0.7").json()["source"] == "subnet"
    wanted = box.channel("GET", "/local/v1/where/wanted").json()
    assert "127.0.0.7" in [i["ip"] for i in wanted["items"]]
    oas.check("/local/v1/where/wanted", "get", 200, wanted)
    put = {"items": [{"ip": "127.0.0.7", "zone": "hall-b", "zone_source": "mist", "ap_name": "ap-12", "ssid": "guest",
                      "band": "5", "nat_suspected": False, "ttl_s": 60}]}
    r = box.channel("PUT", "/local/v1/where", put)
    assert r.status == 200 and r.json() == {"ok": True}
    assert box.get("/st/api/v1/where", src="127.0.0.7").json() == {"zone": "hall-b", "zone_name": "Hall B", "source": "mist",
                                                                    "nat_suspected": False}
    assert "127.0.0.7" not in [i["ip"] for i in box.channel("GET", "/local/v1/where/wanted").json()["items"]]
    r = box.get("/st/api/v1/where", src="127.0.0.7")
    assert "ap" not in r.body.decode() and "guest" not in r.body.decode(), "no device detail reaches an anonymous caller"


def test_where_is_fast(box: Box):
    t0 = time.monotonic()
    for _ in range(20):
        box.get("/st/api/v1/where")
    assert (time.monotonic() - t0) / 20 < 0.3


# ------------------------------------------------------------------------------------------------- sessions
def test_create_session_matches_openapi(box: Box):
    s = box.new_session()
    oas.check("/st/api/v1/sessions", "post", 201, s.doc)
    assert ids.is_token(s.leg_token, "expt") and st.is_speedtest_session_id(s.sid)
    assert s.doc["internet_leg"] == "ok" and len(s.doc["dns_nonces"]) == 3 and s.doc["dns_zone"] == "t.speed.test.example"
    assert s.doc["limits"]["bytes_local"] == 50_000_000 and s.doc["leg_token_expires_in_s"] == 60


@pytest.mark.parametrize("body,code", [
    ({}, "invalid_request"),
    ({"consent": {"text_version": 3}}, "invalid_request"),
    ({"consent": {"text_version": 3}, "view_verifier": "short"}, "invalid_request"),
    ({"consent": {"text_version": "3"}, "view_verifier": "a" * 64}, "invalid_request"),
    ({"consent": {"text_version": True}, "view_verifier": "a" * 64}, "invalid_request"),
    ({"consent": {"text_version": 3, "extra": 1}, "view_verifier": "a" * 64}, "invalid_request"),
    ({"consent": {"text_version": 3}, "view_verifier": "a" * 64, "name": "Ada"}, "invalid_request"),
    ({"consent": {"text_version": 3}, "view_verifier": "a" * 64, "email": "a@b.c"}, "invalid_request"),
    ({"consent": {"text_version": 3}, "view_verifier": "a" * 64, "zone_hint": "no-such-zone"}, "invalid_request"),
    ({"consent": {"text_version": 3}, "view_verifier": "a" * 64, "zone_hint": 5}, "invalid_request"),
    ({"consent": {"text_version": 2}, "view_verifier": "a" * 64}, "consent_version_stale"),
    ([], "invalid_request"),
])
def test_create_session_validation(box: Box, body, code):
    r = box.post("/st/api/v1/sessions", body)
    assert r.status == 400 and err_code(r) == code, r.body
    oas.check("/st/api/v1/sessions", "post", 400, r.json())


def test_create_session_rejects_bad_json_and_oversize(box: Box):
    assert box.post("/st/api/v1/sessions", raw_body=b"{nope").status == 400
    assert box.post("/st/api/v1/sessions", raw_body=b'{"a":1,"a":2}').status == 400, "duplicate keys refused"
    assert box.post("/st/api/v1/sessions", raw_body=b'{"x":NaN}').status == 400
    r = box.post("/st/api/v1/sessions", raw_body=b" " * 5000)
    assert r.status == 413
    r = box.request("POST", "/st/api/v1/sessions", headers={"Transfer-Encoding": "chunked"}, raw_body=b"0\r\n\r\n")
    assert r.status == 501


def test_zone_hint_accepted_and_stored_as_qr_source(box: Box):
    s = box.new_session(src="127.0.5.5", zone_hint="hallb-row12")
    assert box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view, src="127.0.5.5").status == 202
    stored = box.fake.app.tests[s.sid].doc
    assert stored["zone"] == "hallb-row12" and stored["zone_source"] == "qr"


def test_rate_limit_per_ip_tests_per_10_minutes(tmp_path):
    clock = FakeClock()
    b = Box(tmp_path, clock=clock, cfg_over={"limits": {"tests_per_10min_per_ip": 3, "max_concurrent_per_ip": 5,
                                                          "max_concurrent_tests": 50}})
    b.start()
    try:
        for _ in range(3):
            assert b.new_session().sid
        r = b.post("/st/api/v1/sessions", {"consent": {"text_version": 3}, "view_verifier": "a" * 64})
        assert r.status == 429 and err_code(r) == "rate_limited" and r.json()["error"]["details"]["limit"] == "tests_per_10min_per_ip"
        assert int(r.h("retry-after")) >= 1
        oas.check("/st/api/v1/sessions", "post", 429, r.json())
        assert b.new_session(src="127.0.0.2").sid, "another address is unaffected"
        clock.advance(601)
        assert b.new_session().sid, "the window moved on"
    finally:
        b.stop()


def test_one_concurrent_test_per_ip_until_result_or_token_expiry(tmp_path):
    clock = FakeClock()
    b = Box(tmp_path, clock=clock)
    b.start()
    try:
        s = b.new_session()
        r = b.post("/st/api/v1/sessions", {"consent": {"text_version": 3}, "view_verifier": "a" * 64})
        assert r.status == 429 and r.json()["error"]["details"]["limit"] == "max_concurrent_per_ip"
        assert b.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view).status == 202
        assert b.new_session().sid, "a finished test frees the address"
        clock.advance(66)                                             # token TTL + grace: the second one is no longer active
        assert b.new_session().sid
    finally:
        b.stop()


def test_box_wide_concurrency_cap(tmp_path):
    b = Box(tmp_path, cfg_over={"limits": {"max_concurrent_tests": 2, "max_concurrent_per_ip": 9, "tests_per_10min_per_ip": 99}})
    b.start()
    try:
        b.new_session(src="127.0.0.2")
        b.new_session(src="127.0.0.3")
        r = b.post("/st/api/v1/sessions", {"consent": {"text_version": 3}, "view_verifier": "a" * 64}, src="127.0.0.4")
        assert r.status == 429 and r.json()["error"]["details"]["limit"] == "max_concurrent_tests" and r.h("retry-after")
        assert b.core.metrics()["active_tests"] == 2
    finally:
        b.stop()


def test_general_per_address_request_budget(box: Box):
    codes = [box.get("/st/api/v1/config", src="127.0.0.20").status for _ in range(90)]
    assert 429 in codes and codes[0] == 200
    r = box.get("/st/api/v1/config", src="127.0.0.20")
    assert r.status == 429 and r.h("retry-after")
    assert box.get("/st/api/v1/config", src="127.0.0.21").status == 200


# ----------------------------------------------------------------------------------------------- local leg
def test_ping_requires_a_valid_token(box: Box):
    s = box.new_session()
    r = box.get("/st/ping?n=7", headers=s.leg)
    assert r.status == 204 and r.h("x-exp-seq") == "7" and r.h("cache-control") == "no-store"
    oas.check("/st/ping", "get", 204, None)
    for hdrs in ({}, {"X-Exp-Leg-Token": "garbage"}, {"X-Exp-Leg-Token": "expt_" + "A" * 43},
                 {"X-Exp-Leg-Token": s.leg_token[:-1] + ("A" if s.leg_token[-1] != "A" else "B")}):
        r = box.get("/st/ping", headers=hdrs)
        assert r.status == 401 and err_code(r) == "invalid_token", hdrs
        oas.check("/st/ping", "get", 401, r.json())
    assert box.get("/st/ping?n=abc", headers=s.leg).status == 400
    assert box.get("/st/ping?n=99999999", headers=s.leg).status == 400


def test_token_of_another_session_or_foreign_address_is_refused(box: Box):
    a = box.new_session(src="127.0.0.2")
    b = box.new_session(src="127.0.0.3")
    r = box.get("/st/ping", headers=a.leg, src="127.0.0.3")
    assert r.status == 403 and err_code(r) == "ip_mismatch"
    assert box.get("/st/ping", headers=a.leg, src="127.0.0.2").status == 204
    assert box.get("/st/ping", headers=b.leg, src="127.0.0.3").status == 204


def test_expired_token_is_refused(tmp_path):
    clock = FakeClock()
    b = Box(tmp_path, clock=clock)
    b.start()
    try:
        s = b.new_session()
        assert b.get("/st/ping", headers=s.leg).status == 204
        clock.advance(61)
        r = b.get("/st/ping", headers=s.leg)
        assert r.status == 401 and err_code(r) == "token_expired"
        assert b.get("/st/down?bytes=1000", headers=s.leg).status == 401
        assert b.post("/st/up", raw_body=b"x", headers=s.leg).status == 401
    finally:
        b.stop()


def test_down_returns_exact_bytes_and_counts_them(box: Box):
    s = box.new_session()
    r = box.get("/st/down?bytes=2500000", headers=s.leg)
    assert r.status == 200 and len(r.body) == 2_500_000 and r.h("cache-control") == "no-store"
    assert r.h("content-type") == "application/octet-stream" and int(r.h("content-length")) == 2_500_000
    assert len(set(r.body[i:i + 4096] for i in range(0, 200000, 4096))) > 40, "the payload is not trivially repetitive"
    assert box.core._sessions[s.sid].bytes_down == 2_500_000


def test_aborted_download_still_books_the_bytes_it_sent(box: Box):
    """Every on-network direction ends by aborting the requests still in flight. socket.sendfile raises when the client goes
    away mid-segment (SEG_BYTES = 8 MiB) and its own count is lost with the exception; the bytes it had already sent must still
    be booked (CR-m6-speedtest-server item 28). Before, the whole unfinished segment vanished from the session counter (and the
    byte budget), so the box counted LESS than the client provably received and the counters cross-check flagged good runs."""
    s = box.new_session()
    total = 0
    # five aborts: each request starts at a random payload offset, so a short first segment can end before the abort and hide
    # the loss once; five in a row cannot (the old code booked only the completed segments)
    for _ in range(5):
        sock = socket.create_connection(("127.0.0.1", box.http_port), timeout=10)
        try:
            sock.sendall(f"GET /st/down?bytes=20000000 HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Exp-Leg-Token: {s.leg_token}\r\n\r\n"
                         .encode())
            got = 0
            while got < 3_000_000:
                chunk = sock.recv(65536)
                assert chunk, f"connection closed after {got} bytes"
                got += len(chunk)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))   # abrupt close (RST): an aborted fetch
        finally:
            sock.close()
        total += got
        assert wait_for(lambda: box.core.transfers_active == 0, 10), "the aborted transfer did not end"
    booked = box.core._sessions[s.sid].bytes_down
    # the box put at least what the client read (minus the ~200-byte headers) on the connections, and at most a segment more each
    assert total - 5 * 4096 <= booked <= total + 5 * 8 * 1024 * 1024, (total, booked)


def test_down_payload_is_incompressible(box: Box):
    import zlib
    s = box.new_session()
    body = box.get("/st/down?bytes=1000000", headers=s.leg).body
    assert len(zlib.compress(body, 6)) > 0.95 * len(body)


@pytest.mark.parametrize("q", ["", "?bytes=0", "?bytes=-5", "?bytes=abc", "?bytes=1e6", "?bytes=100000001", "?bytes=%20", "?bytes=99999999999999"])
def test_down_validation(box: Box, q):
    s = box.new_session()
    r = box.get("/st/down" + q, headers=s.leg)
    assert r.status == 400 and err_code(r) == "invalid_request", (q, r.status)
    oas.check("/st/down", "get", 400, r.json())


def test_down_over_budget_is_413_with_remaining(box: Box):
    s = box.new_session()                                              # budget 50 MB
    assert box.get("/st/down?bytes=30000000", headers=s.leg).status == 200
    r = box.get("/st/down?bytes=30000000", headers=s.leg)
    assert r.status == 413 and err_code(r) == "budget_exceeded" and r.json()["error"]["details"]["remaining"] == 20_000_000
    oas.check("/st/down", "get", 413, r.json())
    assert box.get("/st/down?bytes=20000000", headers=s.leg).status == 200, "exactly the remainder is fine"
    assert box.get("/st/down?bytes=1", headers=s.leg).status == 413
    assert box.core._sessions[s.sid].capped


def test_up_counts_discards_and_enforces_the_budget(box: Box):
    s = box.new_session()
    r = box.post("/st/up", raw_body=b"z" * 3_000_000, headers=s.leg)
    assert r.status == 204 and r.h("x-exp-received") == "3000000"
    oas.check("/st/up", "post", 204, None)
    assert box.core._sessions[s.sid].bytes_up == 3_000_000
    # over budget: refused from the declared Content-Length alone, before a single body byte is read
    raw = box.raw(f"POST /st/up HTTP/1.1\r\nHost: x\r\nX-Exp-Leg-Token: {s.leg_token}\r\nContent-Length: 60000000\r\n\r\n".encode())
    assert raw.startswith(b"HTTP/1.1 413") and b"budget_exceeded" in raw and b"Connection: close" in raw
    oas.check("/st/up", "post", 413, json.loads(raw.split(b"\r\n\r\n", 1)[1]))
    r = box.request("POST", "/st/up", headers=s.leg)
    assert r.status in (204, 411) and (r.status == 411 or r.h("x-exp-received") == "0")


def test_up_without_a_token_does_not_read_the_body(box: Box):
    r = box.post("/st/up", raw_body=b"z" * 200_000, headers={})
    assert r.status == 401


def test_up_and_down_share_one_budget_and_counters(box: Box):
    s = box.new_session()
    box.get("/st/down?bytes=20000000", headers=s.leg)
    box.post("/st/up", raw_body=b"1" * 20_000_000, headers=s.leg)
    sess = box.core._sessions[s.sid]
    assert (sess.bytes_down, sess.bytes_up) == (20_000_000, 20_000_000)
    assert box.get("/st/down?bytes=11000000", headers=s.leg).status == 413


def test_core_guard_shrinks_the_remaining_budget_mid_test(box: Box):
    box.core.guard.cap_bytes = 50_000_000
    box.core.guard.min_bytes = 1_000_000
    box.core.guard.util_pct = 70
    s = box.new_session()
    assert box.get("/st/down?bytes=10000000", headers=s.leg).status == 200
    box.core.guard.set_utilization(100)                                # the core link saturates during the test
    r = box.get("/st/down?bytes=10000000", headers=s.leg)
    assert r.status == 413 and r.json()["error"]["details"]["remaining"] == 0
    assert box.new_session(src="127.0.0.9").doc["limits"]["bytes_local"] == 1_000_000, "new sessions start with the shrunk cap"


def test_bad_token_attempts_are_rate_limited(box: Box):
    codes = [box.get("/st/ping", headers={"X-Exp-Leg-Token": "x"}, src="127.0.0.30").status for _ in range(75)]
    assert codes[0] == 401 and 429 in codes
    s = box.new_session(src="127.0.0.31")
    assert box.get("/st/ping", headers=s.leg, src="127.0.0.31").status == 204, "other addresses are unaffected"


def test_keepalive_connection_serves_many_requests(box: Box):
    import http.client
    s = box.new_session()
    c = http.client.HTTPConnection("127.0.0.1", box.http_port, timeout=5)
    for i in range(30):
        c.request("GET", f"/st/ping?n={i}", headers=s.leg)
        r = c.getresponse()
        r.read()
        assert r.status == 204 and r.getheader("Connection") == "keep-alive"
    c.request("GET", "/st/down?bytes=100000", headers=s.leg)
    r = c.getresponse()
    assert len(r.read()) == 100000
    c.request("GET", "/st/ping", headers=s.leg)
    assert c.getresponse().status == 204
    c.close()


# ----------------------------------------------------------------------------------------------- view proof
def test_session_routes_require_the_view_proof_and_hide_existence(box: Box):
    s = box.new_session()
    other = box.new_session(src="127.0.0.2")
    for method, suffix, body in (("GET", "", None), ("GET", "/path", None), ("POST", "/internet-slot", {"action": "acquire"}),
                                 ("POST", "/result", submission()), ("POST", "/comment", {"comment": "x"})):
        base = f"/st/api/v1/sessions/{s.sid}{suffix}"
        for hdrs in ({}, {"X-Exp-View-Proof": "bad"}, other.view, {"X-Exp-View-Proof": st.view_proof(st.new_view_key(), SENTINEL_ID)}):
            r = box.request(method, base, body, headers=hdrs)
            assert r.status == 404 and err_code(r) == "not_found", (method, suffix, hdrs)
            oas.check(f"/st/api/v1/sessions/{{id}}{suffix}", method, 404, r.json())
        unknown = box.request(method, f"/st/api/v1/sessions/{st.new_speedtest_id()}{suffix}", body, headers=s.view)
        assert unknown.status == 404 and unknown.json() == r.json(), "an unknown id looks the same as a wrong proof"
    assert box.get(f"/st/api/v1/sessions/{s.leg_token}").status == 404


# ----------------------------------------------------------------------------------------------- internet slots
def test_internet_slot_http_flow_queue_pause_and_release(box: Box):
    sessions = [box.new_session(src=f"127.0.0.{i}") for i in range(2, 6)]
    slot = lambda s, a: box.post(f"/st/api/v1/sessions/{s.sid}/internet-slot", {"action": a}, headers=s.view, src=s.src)  # noqa: E731
    r0, r1, r2, r3 = (slot(s, "acquire") for s in sessions)           # max_concurrent_internet = 2
    assert [r.json()["state"] for r in (r0, r1, r2, r3)] == ["granted", "granted", "queued", "queued"]
    assert (r2.json()["queue_position"], r3.json()["queue_position"]) == (1, 2)
    for r in (r0, r2):
        oas.check("/st/api/v1/sessions/{id}/internet-slot", "post", 200, r.json())
    assert box.get("/st/api/v1/config").json()["internet_leg"]["paused"] is False
    assert box.new_session(src="127.0.0.7").doc["internet_leg"] == "queued"
    assert slot(sessions[0], "release").json()["state"] == "released"
    assert slot(sessions[2], "acquire").json()["state"] == "granted"
    # runner auto-pause
    r = box.channel("PUT", "/local/v1/pause", {"wan_util_pct": 93.5, "source": "ec", "measured_at": _now_iso()})
    assert r.status == 200
    p = slot(sessions[3], "acquire").json()
    assert p["state"] == "paused" and p["reason"] == "wan_utilization"
    assert box.get("/st/api/v1/config").json()["internet_leg"]["paused"] is True
    assert box.new_session(src="127.0.0.8").doc["internet_leg"] == "paused"
    box.channel("PUT", "/local/v1/pause", {"wan_util_pct": 12.0, "source": "ec", "measured_at": _now_iso()})
    assert slot(sessions[3], "acquire").json()["state"] in ("granted", "queued")


def _now_iso() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@pytest.mark.parametrize("body", [{}, {"action": "grab"}, {"action": "acquire", "x": 1}, [], {"action": 1}])
def test_internet_slot_validation(box: Box, body):
    s = box.new_session()
    r = box.post(f"/st/api/v1/sessions/{s.sid}/internet-slot", body, headers=s.view)
    assert r.status == 400 and err_code(r) == "invalid_request"


def test_internet_leg_disabled_in_config(tmp_path):
    b = Box(tmp_path, cfg_over={"internet_leg": {"enabled": False}})
    b.start()
    try:
        s = b.new_session()
        assert s.doc["internet_leg"] == "unavailable"
        r = b.post(f"/st/api/v1/sessions/{s.sid}/internet-slot", {"action": "acquire"}, headers=s.view)
        assert r.json()["state"] == "unavailable" and r.json()["reason"] == "disabled"
        # a modified client submitting internet numbers anyway does not get them stored
        r = b.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
        assert r.status == 202, r.body
        oas.check("/st/api/v1/sessions/{id}/result", "post", 202, r.json())
        assert "internet_off" in r.json()["flags"]
        doc = b.fake.app.tests[s.sid].doc
        oas.check_schema("speedtest.schema.json", doc)
        assert doc["legs"]["internet"] == {"status": "unavailable"} and "internet_off" in doc["flags"]
        assert "internet_unavailable" not in doc["flags"], "switched off by the operator is not an outage"
    finally:
        b.stop()


def test_admin_pause_via_config_and_runtime_switch(tmp_path):
    b = Box(tmp_path)
    b.start()
    try:
        assert b.new_session().doc["internet_leg"] == "ok"
        from exp_speedtest.slots import RuntimeState
        RuntimeState.write(b.paths.runtime_json, True)
        b.clock.advance(2)
        s = b.new_session(src="127.0.0.2")
        assert s.doc["internet_leg"] == "paused"
        assert b.core.metrics()["internet_leg_paused"] == 1
    finally:
        b.stop()


# ------------------------------------------------------------------------------------------------- result
def test_result_flow_overwrites_server_fields_and_recomputes_the_score(box: Box):
    s = box.new_session(ua="Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Version/18.1 Mobile/15E148 Safari/604.1")
    box.get("/st/down?bytes=4000000", headers=s.leg)
    box.post("/st/up", raw_body=b"q" * 1_000_000, headers=s.leg)
    sub = submission()
    sub["legs"]["local"]["bytes"] = 5_000_000
    r = box.post(f"/st/api/v1/sessions/{s.sid}/result", sub, headers=s.view)
    assert r.status == 202, r.body
    oas.check("/st/api/v1/sessions/{id}/result", "post", 202, r.json())
    acc = r.json()
    stored = box.fake.app.tests[s.sid].doc
    oas.check_schema("speedtest.schema.json", stored)
    assert stored["client"]["ip"] == "127.0.0.1" and stored["site"] == "hall-b" and stored["observed"]["server_id"] == "spd-core"
    assert stored["client"]["ua"] == {"os_family": "iOS", "os_version": "18.1", "browser": "Safari", "device_class": "phone"}
    assert stored["observed"]["local_bytes_down"] == 4_000_000 and stored["observed"]["local_bytes_up"] == 1_000_000
    assert stored["legs"]["local"]["server"] == "spd-core" and stored["legs"]["internet"]["server"] == "cloudflare:FRA"
    assert "colo" not in stored["legs"]["internet"] and stored["consent"] == {"text_version": 3}
    assert stored["score"] == st.compute_score(stored["legs"], {"down_mbps": 25, "up_mbps": 10}) == acc["score"]
    assert "counters_disagree" not in stored["flags"]
    assert stored["ended"] >= stored["started"] and stored["zone"] == "hall-a" and stored["zone_source"] == "subnet"
    assert acc["diagnosis"]["stage"] == "quick" and acc["diagnosis"]["noc_text"] == "" and acc["diagnosis"]["cause"][0]["cites"] == []
    assert "Mozilla" not in json.dumps(stored)
    assert stored["legs"]["path"]["gateway_ms"]["samples"] >= 0 and "device_icmp_ms" in stored["legs"]["path"]


def test_result_ignores_client_claims_it_may_not_make(box: Box):
    s = box.new_session()
    for forged in ({"client": {"ip": "1.2.3.4"}}, {"site": "evil"}, {"score": {"total": 100}}, {"flags": []},
                   {"observed": {"server_id": "x"}}, {"id": "st_01M7R3X9G0QWCYM3A3S1DE8MT4"}, {"name": "Ada"}, {"email": "a@b.c"}):
        r = box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(**forged), headers=s.view)
        assert r.status == 400 and err_code(r) == "invalid_result", forged
        oas.check("/st/api/v1/sessions/{id}/result", "post", 400, r.json())
    assert box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view).status == 202


@pytest.mark.parametrize("mutate", [
    lambda d: d["legs"]["local"].update(down_mbps=100001),
    lambda d: d["legs"]["local"].update(down_mbps=-1),
    lambda d: d["legs"]["local"].update(idle_ms=60001),
    lambda d: d["legs"]["local"].update(down_mbps="fast"),
    lambda d: d["legs"]["local"].update(rpm=1.5),
    lambda d: d["legs"]["local"].update(unknown=1),
    lambda d: d["legs"].pop("local"),
    lambda d: d.update(schema="exp.speedtest/1"),
    lambda d: d.update(comment="x" * 501),
    lambda d: d.update(comment="bell\x07"),
    lambda d: d.update(duration_ms=60001),
    lambda d: d["legs"]["internet"].update(colo="TOOLONGCOLO"),
])
def test_result_bounds_every_number_and_field(box: Box, mutate):
    s = box.new_session()
    sub = submission()
    mutate(sub)
    r = box.post(f"/st/api/v1/sessions/{s.sid}/result", sub, headers=s.view)
    assert r.status == 400 and err_code(r) == "invalid_result"
    assert s.sid not in box.fake.app.tests


def test_result_is_accepted_once_and_only_from_the_session_address(box: Box):
    s = box.new_session(src="127.0.0.2")
    r = box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view, src="127.0.0.3")
    assert r.status == 403 and err_code(r) == "ip_mismatch"
    oas.check("/st/api/v1/sessions/{id}/result", "post", 403, r.json())
    assert box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view, src="127.0.0.2").status == 202
    r = box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view, src="127.0.0.2")
    assert r.status == 409 and err_code(r) == "already_submitted"
    oas.check("/st/api/v1/sessions/{id}/result", "post", 409, r.json())


def test_result_deadline(tmp_path):
    clock = FakeClock()
    b = Box(tmp_path, clock=clock)
    b.start()
    try:
        s = b.new_session()
        clock.advance(181)
        r = b.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
        assert r.status == 409 and err_code(r) == "result_deadline_passed"
    finally:
        b.stop()


def test_result_body_limit(box: Box):
    s = box.new_session()
    r = box.post(f"/st/api/v1/sessions/{s.sid}/result", raw_body=b"{" + b" " * 70_000 + b"}", headers=s.view)
    assert r.status == 413
    oas.check("/st/api/v1/sessions/{id}/result", "post", 413, r.json())


def test_counters_disagree_flag_when_browser_and_box_differ(box: Box):
    s = box.new_session()
    box.get("/st/down?bytes=1000000", headers=s.leg)
    sub = submission()
    sub["legs"]["local"]["bytes"] = 4_000_000                          # the browser claims 4x what the box served
    r = box.post(f"/st/api/v1/sessions/{s.sid}/result", sub, headers=s.view)
    assert "counters_disagree" in r.json()["flags"]
    s2 = box.new_session(src="127.0.0.2")
    box.get("/st/down?bytes=1000000", headers=s2.leg, src="127.0.0.2")
    sub2 = submission()
    sub2["legs"]["local"]["bytes"] = 1_050_000                         # within 20 %
    assert "counters_disagree" not in box.post(f"/st/api/v1/sessions/{s2.sid}/result", sub2, headers=s2.view, src="127.0.0.2").json()["flags"]
    s3 = box.new_session(src="127.0.0.3")
    sub3 = submission()
    sub3["legs"]["local"]["bytes"] = 123_456                           # claims traffic the box never saw
    assert "counters_disagree" in box.post(f"/st/api/v1/sessions/{s3.sid}/result", sub3, headers=s3.view, src="127.0.0.3").json()["flags"]


def test_non_ok_internet_leg_is_normalised_and_flagged(box: Box):
    for status, flag in (("paused", "internet_paused"), ("unavailable", "internet_unavailable"), ("queued", "internet_queued")):
        s = box.new_session(src="127.0.0.2")
        sub = submission()
        sub["legs"]["internet"] = {"status": status, "down_mbps": 999.0}   # numbers on a non-ok leg are dropped
        r = box.post(f"/st/api/v1/sessions/{s.sid}/result", sub, headers=s.view, src="127.0.0.2")
        assert flag in r.json()["flags"], status
        assert box.fake.app.tests[s.sid].doc["legs"]["internet"] == {"status": status}
        s2 = box.new_session(src="127.0.0.2")                          # (the first test is finished, so this is allowed)
        box.post(f"/st/api/v1/sessions/{s2.sid}/result", submission(), headers=s2.view, src="127.0.0.2")
        box.core.create_limiter._d.clear()
    s = box.new_session(src="127.0.0.9")
    sub = submission()
    sub["legs"].pop("internet")
    box.post(f"/st/api/v1/sessions/{s.sid}/result", sub, headers=s.view, src="127.0.0.9")
    assert "internet" not in box.fake.app.tests[s.sid].doc["legs"], "no internet leg and nothing paused: nothing invented"


def test_nat_suspected_result_is_unresolved_and_flagged(box: Box):
    s = box.new_session(src="127.0.9.9", zone_hint=None)
    r = box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view, src="127.0.9.9")
    assert r.status == 202 and "nat_suspected" in r.json()["flags"]
    stored = box.fake.app.tests[s.sid].doc
    assert stored["zone"] == "unresolved" and stored["zone_source"] == "unresolved"


def test_zone_hint_conflict_flag(box: Box):
    s = box.new_session(src="127.0.1.5", zone_hint="hall-a")           # the subnet table says hall-b
    r = box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view, src="127.0.1.5")
    assert "zone_hint_conflict" in r.json()["flags"]
    stored = box.fake.app.tests[s.sid].doc
    assert stored["zone"] == "hall-b" and stored["zone_source"] == "subnet"


def test_dns_fallback_without_delegation_and_browser_source_with_it(box: Box):
    import dns.message
    import dns.query
    s = box.new_session(src="127.0.0.2")
    r = box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view, src="127.0.0.2")
    assert "dns_fallback" in r.json()["flags"]
    assert box.fake.app.tests[s.sid].doc["legs"]["dns"] == {"cold_ms": None, "warm_ms": None, "resolver_ip": None, "source": "probe"}
    s2 = box.new_session(src="127.0.0.3")
    q = dns.message.make_query(f"{s2.doc['dns_nonces'][0]}.t.speed.test.example", "A")
    dns.query.udp(q, "127.0.0.1", port=box.dns_port, timeout=2, source="127.0.0.44")      # a resolver recursing to the box
    p = box.get(f"/st/api/v1/sessions/{s2.sid}/path", headers=s2.view, src="127.0.0.3").json()
    assert p["resolver_seen"] == "127.0.0.44"
    oas.check("/st/api/v1/sessions/{id}/path", "get", 200, p)
    r = box.post(f"/st/api/v1/sessions/{s2.sid}/result", submission(), headers=s2.view, src="127.0.0.3")
    assert "dns_fallback" not in r.json()["flags"]
    dnsleg = box.fake.app.tests[s2.sid].doc["legs"]["dns"]
    assert dnsleg == {"cold_ms": 38.0, "warm_ms": 2.1, "resolver_ip": "127.0.0.44", "source": "browser"}, "the box overrides the resolver"
    p = box.get(f"/st/api/v1/sessions/{s2.sid}/path", headers=s2.view, src="127.0.0.3").json()
    assert p["dns_cold_split"] == {"device_to_resolver_ms": 2.1, "resolver_to_authority_ms": 35.9}


def test_dns_leg_server_not_running_degrades_gracefully(tmp_path):
    b = Box(tmp_path, cfg_over={"dns_leg": {"enabled": False, "zone": "t.speed.test.example"}})
    b.start()
    try:
        s = b.new_session()
        assert s.doc["dns_nonces"] == [] and s.doc["dns_zone"] is None
        assert b.get("/st/api/v1/config").json()["dns_zone"] is None
        r = b.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
        assert "dns_fallback" in r.json()["flags"]
    finally:
        b.stop()


def test_path_route_reports_box_timed_legs_and_device_icmp(box: Box):
    s = box.new_session()
    assert wait_for(lambda: box.core.path.device_icmp_ms(s.sid) is not None, 5)
    p = box.get(f"/st/api/v1/sessions/{s.sid}/path", headers=s.view).json()
    oas.check("/st/api/v1/sessions/{id}/path", "get", 200, p)
    assert p["path"]["device_icmp_ms"] == 0.5 and p["path"]["edge1_addr"] == "127.0.0.3"
    assert p["path"]["gateway_ms"]["idle"] == 0.5


def test_path_sse_stream(box: Box):
    import socket
    s = box.new_session()
    c = socket.create_connection(("127.0.0.1", box.http_port), timeout=3)
    c.sendall(f"GET /st/api/v1/sessions/{s.sid}/path HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n"
              f"X-Exp-View-Proof: {s.proof}\r\n\r\n".encode())
    buf = b""
    while buf.count(b"event: path") < 2:
        buf += c.recv(4096)
    c.close()
    assert b"text/event-stream" in buf and b"retry: 2000" in buf
    data = [json.loads(line[6:]) for line in buf.decode().split("\n") if line.startswith("data: ")]
    oas.check("/st/api/v1/sessions/{id}/path", "get", 200, data[0])


def test_path_never_probes_a_client_chosen_target(box: Box):
    s = box.new_session()
    box.pinger.pinged.clear()
    for q in ("?target=8.8.8.8", "?host=1.1.1.1", "?ip=9.9.9.9&addr=9.9.9.9"):
        r = box.get(f"/st/api/v1/sessions/{s.sid}/path{q}", headers={**s.view, "X-Forwarded-For": "8.8.8.8", "Host": "8.8.8.8"})
        assert r.status == 200
    box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(client={"connection_hint": "wifi"}), headers=s.view)
    time.sleep(1.3)
    allowed = {"127.0.0.1", "127.0.0.2", "127.0.0.3"}
    assert set(box.pinger.pinged) <= allowed, set(box.pinger.pinged) - allowed


# ------------------------------------------------------------------------------------------------- view + comment
def test_session_view_is_user_safe_and_matches_openapi(box: Box):
    s = box.new_session()
    v = box.get(f"/st/api/v1/sessions/{s.sid}", headers=s.view)
    assert v.status == 200 and v.json()["state"] == "created" and v.json()["result"] is None
    oas.check("/st/api/v1/sessions/{id}", "get", 200, v.json())
    box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
    v = box.get(f"/st/api/v1/sessions/{s.sid}", headers=s.view)
    doc = v.json()
    oas.check("/st/api/v1/sessions/{id}", "get", 200, doc)
    assert doc["state"] in ("submitted", "correlating") and doc["diagnosis"]["stage"] == "quick"
    assert "noc_text" not in v.body.decode() and "cites" not in v.body.decode()
    assert "client" not in doc["result"] or "ip" not in doc["result"]["client"], "the client IP is not reflected back"
    assert "127.0.0.1" not in v.body.decode().replace('"resolver_ip"', "")
    assert doc["zone_name"] == "Hall A" and doc["network_details"] is None


def test_view_follows_the_collectors_final_diagnosis_and_hides_network_details(box: Box):
    s = box.new_session()
    box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
    app = box.fake.app
    t = app.tests[s.sid]
    ev = {"schema": "exp.evidence/1", "test_id": s.sid, "kind": "wifi", "source": "mist", "status": "ok",
          "collected_at": "2026-11-20T00:00:00.000Z", "window": {"from": "2026-11-20T00:00:00.000Z", "to": "2026-11-20T00:05:00.000Z"},
          "data": {"client": {"rssi": -80, "band": "5", "channel": 44}, "ap": {"name": "ap-secret-12"}}, "raw_refs": []}
    t.evidence["wifi"] = ev
    box.clock.advance(2)                                              # past the 1 s status cache
    doc = box.get(f"/st/api/v1/sessions/{s.sid}", headers=s.view).json()
    assert doc["state"] == "correlating" and "wifi" in doc["evidence"]["kinds_done"]
    assert doc["network_details"] is None and "ap-secret-12" not in json.dumps(doc), "hidden unless display.show_network_details"
    oas.check("/st/api/v1/sessions/{id}", "get", 200, doc)


def test_network_details_shown_when_the_event_enables_them(tmp_path):
    b = Box(tmp_path, cfg_over={"display": {"show_network_details": True}})
    b.start()
    try:
        s = b.new_session()
        b.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
        t = b.fake.app.tests[s.sid]
        t.evidence["wifi"] = {"schema": "exp.evidence/1", "test_id": s.sid, "kind": "wifi", "source": "mist", "status": "ok",
                              "collected_at": "2026-11-20T00:00:00.000Z", "window": {"from": "2026-11-20T00:00:00.000Z",
                                                                                     "to": "2026-11-20T00:05:00.000Z"},
                              "data": {"client": {"band": "5", "channel": 44}, "ap": {"name": "ap-12"}}, "raw_refs": []}
        b.clock.advance(2)
        d = b.get(f"/st/api/v1/sessions/{s.sid}", headers=s.view).json()
        assert d["network_details"] == {"ap_name": "ap-12", "band": "5", "channel": 44}
    finally:
        b.stop()


def test_comment_xss_payload_is_stored_verbatim_as_text_and_served_as_json(box: Box):
    s = box.new_session()
    box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
    r = box.post(f"/st/api/v1/sessions/{s.sid}/comment", {"comment": XSS}, headers=s.view)
    assert r.status == 204
    oas.check("/st/api/v1/sessions/{id}/comment", "post", 204, None)
    assert box.fake.app.tests[s.sid].comment == XSS, "the collector received the exact text"
    box.clock.advance(2)
    v = box.get(f"/st/api/v1/sessions/{s.sid}", headers=s.view)
    assert v.json()["comment"] == XSS and v.h("content-type") == "application/json" and v.h("x-content-type-options") == "nosniff"
    assert "default-src 'none'" in v.h("content-security-policy")
    assert box.core.store.get_session(s.sid)["comment"] == XSS


def test_comment_before_the_result_travels_with_it(box: Box):
    s = box.new_session()
    assert box.post(f"/st/api/v1/sessions/{s.sid}/comment", {"comment": "video calls freeze at my booth"}, headers=s.view).status == 204
    box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(comment=None), headers=s.view)
    assert box.fake.app.tests[s.sid].doc["comment"] == "video calls freeze at my booth"


@pytest.mark.parametrize("body", [{}, {"comment": ""}, {"comment": "x" * 501}, {"comment": "bell\x07"}, {"comment": 5}, {"comment": "x", "name": "Ada"}, []])
def test_comment_validation(box: Box, body):
    s = box.new_session()
    r = box.post(f"/st/api/v1/sessions/{s.sid}/comment", body, headers=s.view)
    assert r.status == 400 and err_code(r) == "invalid_request"
    oas.check("/st/api/v1/sessions/{id}/comment", "post", 400, r.json())


def test_comment_allows_newlines_and_500_chars_and_limits_replacements(box: Box):
    s = box.new_session()
    assert box.post(f"/st/api/v1/sessions/{s.sid}/comment", {"comment": "a\nb\tc" + "é" * 495}, headers=s.view).status == 204
    for i in range(3):
        assert box.post(f"/st/api/v1/sessions/{s.sid}/comment", {"comment": f"v{i}"}, headers=s.view).status == 204
    r = box.post(f"/st/api/v1/sessions/{s.sid}/comment", {"comment": "one too many"}, headers=s.view)
    assert r.status == 409 and err_code(r) == "conflict"
    oas.check("/st/api/v1/sessions/{id}/comment", "post", 409, r.json())


def test_comment_text_is_never_logged(box: Box, caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    s = box.new_session()
    box.post(f"/st/api/v1/sessions/{s.sid}/comment", {"comment": "SECRET-COMMENT-MARKER-123"}, headers=s.view)
    box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
    assert "SECRET-COMMENT-MARKER-123" not in caplog.text
    assert s.proof not in caplog.text and s.leg_token not in caplog.text and s.key not in caplog.text


def test_share_link_view_works_from_another_address_and_after_memory_is_gone(box: Box):
    s = box.new_session()
    box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
    box.core._sessions.clear()                                         # as after a restart: only SQLite remembers
    box.core._by_nonce.clear()
    v = box.get(f"/st/api/v1/sessions/{s.sid}", headers=s.view, src="127.0.0.77")
    assert v.status == 200 and v.json()["result"]["id"] == s.sid and v.json()["state"] in ("submitted", "correlating", "final")
    r = box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
    assert r.status == 409 and err_code(r) == "already_submitted"
    assert box.get(f"/st/api/v1/sessions/{s.sid}", headers={"X-Exp-View-Proof": st.view_proof(st.new_view_key(), SENTINEL_ID)}).status == 404


def test_result_after_the_box_forgot_the_session_is_a_conflict(box: Box):
    s = box.new_session()
    box.core._sessions.clear()
    r = box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
    assert r.status == 409 and err_code(r) == "result_deadline_passed"


# --------------------------------------------------------------------------------------------- runner channel
def test_channel_refuses_non_loopback_peers_before_looking_at_the_token(box: Box):
    r = box.channel("GET", "/local/v1/where/wanted", src="127.0.0.2")
    assert r.status == 403 and err_code(r) == "forbidden"
    oas.check("/local/v1/where/wanted", "get", 403, r.json())
    r = box.channel("GET", "/local/v1/where/wanted", token="wrong", src="127.0.0.2")
    assert r.status == 403, "the address check precedes the token check"


def test_channel_token_checks(box: Box):
    for tok in ("expl_" + "A" * 43, "garbage", ids.new_token("expl"), ids.new_token("exps")):
        r = box.channel("GET", "/local/v1/where/wanted", token=tok)
        assert r.status == 401 and err_code(r) == "invalid_token"
    r = box.request("GET", "/local/v1/where/wanted", port=box.chan_port)
    assert r.status == 401
    oas.check("/local/v1/where/wanted", "get", 401, r.json())
    assert box.channel("GET", "/local/v1/where/wanted").status == 200
    assert box.channel("POST", "/local/v1/where").status == 405
    assert box.channel("GET", "/local/v1/nothing").status == 404


def test_channel_is_not_reachable_on_the_public_port(box: Box):
    r = box.request("GET", "/local/v1/where/wanted", headers={"Authorization": f"Bearer {box.channel_token}"})
    assert r.status == 404


@pytest.mark.parametrize("body", [
    {}, {"items": "x"}, {"items": [{}]}, {"items": [{"ip": "nope", "zone": "a", "zone_source": "mist", "nat_suspected": False}]},
    {"items": [{"ip": "10.0.0.1", "zone": "BAD", "zone_source": "mist", "nat_suspected": False}]},
    {"items": [{"ip": "10.0.0.1", "zone": "a", "zone_source": "other", "nat_suspected": False}]},
    {"items": [{"ip": "10.0.0.1", "zone": "a", "zone_source": "mist", "nat_suspected": "no"}]},
    {"items": [{"ip": "10.0.0.1", "zone": "a", "zone_source": "mist", "nat_suspected": False, "mac": "aa:bb:cc:dd:ee:ff"}]},
    {"items": [{"ip": "10.0.0.1", "zone": "a", "zone_source": "mist", "nat_suspected": False, "ttl_s": 0}]},
    {"items": [{"ip": "10.0.0.1", "zone": "a", "zone_source": "mist", "nat_suspected": False, "ap_name": "x" * 129}]},
    {"items": [{"ip": "10.0.0.1", "zone": "a", "zone_source": "mist", "nat_suspected": False}] * 101},
])
def test_channel_put_where_validation_and_no_mac_accepted(box: Box, body):
    r = box.channel("PUT", "/local/v1/where", body)
    assert r.status == 400 and err_code(r) == "invalid_request"
    oas.check("/local/v1/where", "put", 400, r.json())


@pytest.mark.parametrize("body", [
    {}, {"wan_util_pct": 5, "source": "ec"}, {"wan_util_pct": "x", "source": "ec", "measured_at": "2026-11-20T00:00:00Z"},
    {"wan_util_pct": 5, "source": "other", "measured_at": "2026-11-20T00:00:00Z"},
    {"wan_util_pct": 5, "source": "ec", "measured_at": "yesterday"},
    {"wan_util_pct": 5000, "source": "ec", "measured_at": "2026-11-20T00:00:00Z"},
    {"wan_util_pct": 5, "source": "ec", "measured_at": "2026-11-20T00:00:00Z", "pause": "yes"},
])
def test_channel_put_pause_validation(box: Box, body):
    r = box.channel("PUT", "/local/v1/pause", body)
    assert r.status == 400 and err_code(r) == "invalid_request"


def test_auto_pause_ignores_stale_runner_values_and_reopens(tmp_path):
    clock = FakeClock()
    b = Box(tmp_path, clock=clock)
    b.start()
    try:
        r = b.channel("PUT", "/local/v1/pause", {"wan_util_pct": 99, "source": "ec", "measured_at": _now_iso()})
        assert r.status == 200 and b.core.internet.state() == ("paused", "wan_utilization")
        clock.advance(91)
        assert b.core.internet.state() == ("ok", None), "a silent runner must never keep the leg paused"
    finally:
        b.stop()


def test_where_cache_is_bounded(box: Box):
    items = [{"ip": f"10.1.{i // 250}.{i % 250 + 1}", "zone": "hall-a", "zone_source": "mist", "nat_suspected": False} for i in range(100)]
    for _ in range(50):
        assert box.channel("PUT", "/local/v1/where", {"items": items}).status == 200
    assert len(box.core.resolver._cache) <= 4096


def test_metrics_counts(box: Box):
    s = box.new_session()
    box.get("/st/ping", headers={"X-Exp-Leg-Token": "x"})
    box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
    m = box.core.metrics()
    assert m["tests_per_hour"] == 1 and m["rejected_per_hour"] >= 1 and m["queue_depth"] == 0
    assert set(m) == {"tests_per_hour", "active_tests", "queue_depth", "internet_leg_paused", "local_leg_gbps_p95", "rejected_per_hour"}


def test_core_type_exposed():
    assert Core.__name__ == "Core" and base64.urlsafe_b64encode(b"x")

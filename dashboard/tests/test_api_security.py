"""API authz, CSRF, security headers, static files, request limits (spec section 7 items 3, 4; section 5)."""
from __future__ import annotations

import http.client
import re
import socket
import ssl
import warnings
from pathlib import Path

import exp_dashboard.server as server
import pytest

from conftest import Client

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
INC = "inc_01M7R3X9G0NTM2HDJYD21Y49WH"
API_GETS = ["probes", "states", "incidents", "health", "collectors", "state?probe=probe-a1",
            "beats?probe=probe-a1&from=2026-11-18T00:00:00Z&to=2026-11-18T01:00:00Z",
            "summary?probe=probe-a1&minutes=5", "stream?site=hall-a", "drills/run_01M7R3X9G0NTM2HDJYD21Y49WH"]


def raw(port: int, data: bytes, tls: bool = True, timeout: float = 10) -> bytes:
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s)
    s.sendall(data)
    out = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
    except (TimeoutError, ssl.SSLError, ConnectionError):
        pass
    finally:
        s.close()
    return out


# ------------------------------------------------------------------------------------ authn/authz

@pytest.mark.parametrize("path", API_GETS)
def test_unauthenticated_api_is_401(world, path):
    r = world.client().get("/api/v1/" + path)
    assert r.status == 401 and r.json()["error"]["code"] == "unauthorized"


def test_unauthenticated_mutations_are_401_not_403(world):
    c = world.client()
    assert c.post(f"/api/v1/incidents/{INC}/ack", csrf=False).status == 401
    assert c.post("/api/v1/drills/run_01M7R3X9G0NTM2HDJYD21Y49WH/abort").status == 401


def test_garbage_and_forged_cookies_are_401(world):
    c = world.client()
    for val in ("x", "A" * 43, "A" * 500, "../../etc", ""):
        c.cookie = val
        assert c.get("/api/v1/probes").status == 401


def test_viewer_cannot_ack_or_abort(world):
    c = world.as_user("vera")
    r = c.post(f"/api/v1/incidents/{INC}/ack", json_body={"note": "x"})
    assert r.status == 403 and r.json()["error"]["code"] == "insufficient_role"
    assert c.post("/api/v1/drills/run_01M7R3X9G0NTM2HDJYD21Y49WH/abort").status == 403
    for f in world.fakes.values():
        assert f.app.audit == []                       # nothing reached any collector


def test_operator_ack_reaches_owning_collector_with_user(world):
    world.fakes["col-b"].app.inject_incident({
        "id": INC, "probe": "probe-b1", "site": "hall-b", "line": "dns", "kind": "down",
        "start": "2026-11-18T15:13:42.000Z", "end": None, "where": {"seg": "edge", "ip": "10.1.0.2"},
        "facts": ["x"], "folded_into": None, "acked_by": None, "link": "https://10.0.0.1/probe/probe-b1"})
    c = world.as_user("alice")
    r = c.post(f"/api/v1/incidents/{INC}/ack", json_body={"note": "on it"})
    assert r.status == 204 and r.body == b""
    audit = world.fakes["col-b"].app.audit
    assert audit and audit[-1]["action"] == "incident.ack" and audit[-1]["user"] == "alice"
    assert world.fakes["col-a"].app.audit == [] and world.fakes["col-c"].app.audit == []


def test_ack_unknown_incident_404_and_bad_note_400(world):
    c = world.as_user("alice")
    assert c.post(f"/api/v1/incidents/{INC}/ack").status == 404
    assert c.post(f"/api/v1/incidents/{INC}/ack", json_body={"note": "x" * 2000}).status == 400
    assert c.post(f"/api/v1/incidents/{INC}/ack", json_body={"note": 5}).status == 400
    assert c.post(f"/api/v1/incidents/{INC}/ack", body=b"{bad", headers={"Content-Type": "application/json"}
                  ).status == 400


def test_operator_can_abort_drill_passthrough(world):
    run = "run_01M7R3X9G0NTM2HDJYD21Y49WH"
    world.fakes["col-c"].app.add_drill_report({"run_id": run, "type": "x", "target": "y"})
    c = world.as_user("alice")
    r = c.post(f"/api/v1/drills/{run}/abort")
    assert r.status == 202
    assert run in world.fakes["col-c"].app.drill_aborts
    assert world.fakes["col-c"].app.audit[-1]["user"] == "alice"


def test_drills_control_is_not_exposed(world):
    c = world.as_user("alice")
    assert c.get("/api/v1/drills/control").status == 404
    assert c.post("/api/v1/drills/control/abort").status == 404


# ----------------------------------------------------------------------------------------- CSRF

def test_csrf_missing_token_is_403(world):
    c = world.as_user("alice")
    r = c.post(f"/api/v1/incidents/{INC}/ack", csrf=False)
    assert r.status == 403 and r.json()["error"]["code"] == "csrf_token"


def test_csrf_wrong_token_is_403(world):
    c = world.as_user("alice")
    assert c.post(f"/api/v1/incidents/{INC}/ack", csrf="A" * 43).status == 403
    assert c.post(f"/api/v1/incidents/{INC}/ack", csrf="").status == 403


def test_csrf_token_of_another_session_is_403(world):
    a, v = world.as_user("alice"), world.as_user("vera")
    assert a.post(f"/api/v1/incidents/{INC}/ack", csrf=v.csrf).status == 403


def test_csrf_wrong_or_missing_origin_is_403(world):
    c = world.as_user("alice")
    for origin in ("https://evil.example", "http://127.0.0.1", "null", f"https://127.0.0.1:{world.port}.evil.example",
                   "https://127.0.0.1:1"):
        r = c.post(f"/api/v1/incidents/{INC}/ack", origin=origin)
        assert r.status == 403 and r.json()["error"]["code"] == "csrf_origin", origin
    assert c.post(f"/api/v1/incidents/{INC}/ack", origin=False).status == 403
    for f in world.fakes.values():
        assert f.app.audit == []


def test_csrf_correct_origin_and_token_passes_gate(world):
    c = world.as_user("alice")
    assert c.post(f"/api/v1/incidents/{INC}/ack").status == 404          # passed the gate, no such incident


def test_configured_origin_is_also_accepted(world):
    c = world.as_user("alice")
    assert c.post(f"/api/v1/incidents/{INC}/ack", origin="https://10.32.98.30").status == 404


def test_csrf_gate_applies_to_logout_and_unknown_mutations(world):
    c = world.as_user("alice")
    assert c.post("/api/v1/probes", csrf=False).status == 403
    assert c.request("DELETE", "/api/v1/probes", csrf=False).status == 403
    assert c.post("/auth/logout", csrf=False).status == 403


def test_cross_origin_login_post_refused(world):
    c = world.client()
    r = c.post("/auth/login", json_body={"username": "vera", "password": "vera-pass-1"},
               origin="https://evil.example")
    assert r.status == 403 and c.cookie is None


def test_get_requests_need_no_csrf_token(world):
    c = world.as_user("vera")
    assert c.get("/api/v1/probes", headers={"Origin": "https://evil.example"}).status == 200


# --------------------------------------------------------------------------------------- headers

def _check_headers(r, api: bool = False, hsts: bool = False):
    h = r.headers
    assert h["content-security-policy"] == CSP
    assert "unsafe-inline" not in h["content-security-policy"] and "unsafe-eval" not in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff"
    assert h["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert "camera=()" in h["permissions-policy"]
    assert ("strict-transport-security" in h) is hsts
    if api:
        assert h["cache-control"] == "no-store"


def test_security_headers_on_every_kind_of_response(world):
    c = world.as_user("vera")
    anon = world.client()
    for resp, api in [(c.get("/api/v1/probes"), True), (anon.get("/api/v1/probes"), True),
                      (c.get("/api/v1/nope"), True), (c.get("/auth/session"), True),
                      (anon.get("/auth/login"), False), (anon.get("/"), False), (anon.get("/app.js"), False),
                      (anon.get("/no-such-file.js"), False), (anon.get("/healthz"), False),
                      (anon.post("/auth/login", json_body={}), True), (c.get("/probe/probe-a1"), False),
                      (anon.request("PUT", "/api/v1/probes"), True)]:
        _check_headers(resp, api)


def test_error_responses_use_envelope_without_internals(world):
    c = world.as_user("vera")
    for r in (c.get("/api/v1/nope"), c.get("/api/v1/state"), c.request("PUT", "/api/v1/probes"),
              world.client().get("/api/v1/probes")):
        err = r.json()["error"]
        assert set(err) == {"code", "message", "details"}
        assert "Traceback" not in r.body.decode() and "File \"" not in r.body.decode()
    assert c.get("/healthz").headers["server"] == "exp-dashboard"


def test_hsts_only_when_tls_provided(make_world):
    w = make_world(tls_mode="provided")
    anon = w.client()
    r = anon.get("/")
    _check_headers(r, hsts=True)
    assert "max-age=" in r.headers["strict-transport-security"]


def test_no_inline_script_or_style_in_shipped_pages():
    static = Path(server.STATIC_DIR)
    assert (static / "index.html").is_file()
    for p in static.rglob("*.html"):
        text = p.read_text(encoding="utf-8")
        assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", text, re.I), p
        assert not re.search(r"<style", text, re.I), p
        assert not re.search(r"\sstyle\s*=", text, re.I), p
        assert not re.search(r"\son[a-z]+\s*=", text, re.I), p
        assert not re.search(r"(?:src|href)=[\"']https?://", text, re.I), p


# ------------------------------------------------------------------------------------- static

@pytest.mark.parametrize("target", [
    "/../../../../etc/passwd", "/..%2f..%2f..%2fetc/passwd", "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/%252e%252e/%252e%252e/etc/passwd", "/.%2e/.%2e/etc/passwd", "//etc/passwd", "/..\\..\\etc\\passwd",
    "/%5c..%5c..%5cetc%5cpasswd", "/app.js%00.png", "/%00", "/./../../etc/passwd", "/static/../../etc/passwd",
    "/.git/config", "/.hidden", "/css/", "/../exp_dashboard/server.py", "/../__init__.py",
    "/%2e%2e%2fserver.py", "/....//....//etc/passwd",
])
def test_static_path_traversal_refused(world, target):
    r = raw(world.port, f"GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
    status = int(r.split(b" ", 2)[1])
    body = r.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in r else b""
    assert status in (400, 404), (target, r[:200])
    assert b"root:" not in body and b"def " not in body and b"import " not in body


def test_static_symlink_escape_refused(world, tmp_path, monkeypatch):
    root = tmp_path / "static-root"
    root.mkdir()
    (root / "index.html").write_text("<!doctype html><title>x</title>")
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET")
    (root / "leak.txt").symlink_to(secret)
    (root / "dirlink").symlink_to(tmp_path)
    monkeypatch.setattr(server, "STATIC_DIR", root)
    c = world.client()
    assert c.get("/index.html").status == 200
    assert c.get("/leak.txt").status == 404
    assert c.get("/dirlink/secret.txt").status == 404


def test_static_content_types_and_no_listing(world):
    c = world.client()
    for path, ctype in [("/", "text/html"), ("/index.html", "text/html"), ("/app.js", "text/javascript"),
                        ("/login.css", "text/css"), ("/auth/login", "text/html")]:
        r = c.get(path)
        assert r.status == 200 and r.headers["content-type"].startswith(ctype), path
        assert r.headers["x-content-type-options"] == "nosniff"
    assert c.get("/probe/probe-a1").headers["content-type"].startswith("text/html")   # SPA fallback
    for path in ("/css", "/css/", "/nothing", "/probe/", "/probe/UPPER", "/index.html/", "/a/b/c.js"):
        assert c.get(path).status == 404
    # static is read-only and HEAD works
    assert c.request("POST", "/app.js", body=b"x", headers={"Content-Type": "text/plain"}).status == 405
    h = c.request("HEAD", "/app.js")
    assert h.status == 200 and h.body == b""


def test_static_serves_only_known_types(world, tmp_path, monkeypatch):
    root = tmp_path / "sr"
    root.mkdir()
    (root / "index.html").write_text("x")
    (root / "tool.exe").write_bytes(b"MZ")
    (root / "notes").write_text("x")
    monkeypatch.setattr(server, "STATIC_DIR", root)
    c = world.client()
    assert c.get("/tool.exe").status == 404 and c.get("/notes").status == 404


# ------------------------------------------------------------------------------------ transport

def test_http_listener_only_redirects(world):
    port = world.app.http_port
    for method, status in (("GET", 301), ("HEAD", 301), ("POST", 308), ("PUT", 308)):
        r = raw(port, f"{method} /probe/p1?x=1 HTTP/1.1\r\nHost: evil.example\r\nContent-Length: 0\r\n"
                      "Connection: close\r\n\r\n".encode(), tls=False)
        head = r.decode("latin-1")
        assert head.startswith(f"HTTP/1.1 {status} "), head[:80]
        assert "Location: https://10.32.98.30/probe/p1?x=1" in head       # configured origin, never Host
        assert "evil.example" not in head
    # the redirector serves nothing, not even health or API paths
    r = raw(port, b"GET /api/v1/probes HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", tls=False)
    assert b" 301 " in r.split(b"\r\n")[0] and b"{" not in r
    # header injection attempts do not split the response
    r = raw(port, b"GET /x\rSet-Cookie:a=b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", tls=False)
    assert b"Set-Cookie" not in r


def test_tls_minimum_version_is_1_2(world):
    assert world.app.ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection(("127.0.0.1", world.port), timeout=5) as s, ctx.wrap_socket(s) as t:
        assert t.version() == "TLSv1.2"
    old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    old.check_hostname = False
    old.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)    # deliberately offering legacy TLS
            old.minimum_version = ssl.TLSVersion.TLSv1
            old.maximum_version = ssl.TLSVersion.TLSv1_1
        old.set_ciphers("ALL:@SECLEVEL=0")
    except (ssl.SSLError, ValueError):
        return                                   # this OpenSSL cannot even offer TLS 1.1: nothing to test
    with pytest.raises(ssl.SSLError), socket.create_connection(("127.0.0.1", world.port), timeout=5) as s:
        old.wrap_socket(s)


def test_plain_http_to_https_port_gets_nothing_useful(world):
    r = raw(world.port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", tls=False, timeout=3)
    assert b"<html" not in r.lower() and b"index" not in r.lower()


def test_request_size_limits(world):
    c = world.client()
    big = b"x" * (server.MAX_BODY + 1)
    # the server refuses on Content-Length without reading the body, so the client's send may hit
    # a closed pipe; the refusal is what is asserted, so read the status from a raw exchange.
    r = raw(world.port, b"POST /auth/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                        b"Content-Length: " + str(len(big)).encode() + b"\r\n\r\n" + big[:1024])
    assert r.split(b" ", 2)[1] == b"413"
    r = raw(world.port, b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-Big: " + b"a" * 20000 + b"\r\n\r\n")
    assert r.split(b" ", 2)[1] in (b"431", b"400")
    r = raw(world.port, b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\nHost: x\r\n\r\n")
    assert r.split(b" ", 2)[1] in (b"400", b"414", b"431")
    r = raw(world.port, b"POST /auth/login HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
                        b"Content-Type: application/json\r\n\r\n0\r\n\r\n")
    assert r.split(b" ", 2)[1] == b"501"
    r = raw(world.port, b"POST /auth/login HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n"
                        b"Content-Type: application/json\r\n\r\n")
    assert r.split(b" ", 2)[1] == b"400"
    r = c.post("/auth/login", body=b"{}", headers={"Content-Type": "text/plain"})
    assert r.status == 415
    r = c.post("/auth/login", body=b"[1,2]", headers={"Content-Type": "application/json"})
    assert r.status == 400
    assert world.client().get("/healthz").status == 200            # server still fine


def test_slow_unfinished_request_does_not_block_other_clients(world):
    s = socket.create_connection(("127.0.0.1", world.port), timeout=5)
    s.sendall(b"")                                                   # connected, never speaks
    try:
        assert world.client().get("/healthz").status == 200
    finally:
        s.close()


def test_connection_keepalive_reuses_socket(world):
    conn = http.client.HTTPSConnection("127.0.0.1", world.port, context=Client(0).ctx, timeout=5)
    try:
        for _ in range(3):
            conn.request("GET", "/healthz")
            r = conn.getresponse()
            assert r.status == 200 and r.read() == b"ok"
    finally:
        conn.close()


def test_unread_body_on_refused_request_does_not_desync(world):
    # a 401 on a POST with a body must close the connection rather than parse the body as a request
    body = b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n"
    req = (b"POST /api/v1/incidents/" + INC.encode() + b"/ack HTTP/1.1\r\nHost: x\r\nContent-Length: "
           + str(len(body)).encode() + b"\r\nContent-Type: application/json\r\n\r\n" + body)
    r = raw(world.port, req)
    assert r.count(b"HTTP/1.1 ") == 1 and b"401" in r.split(b"\r\n")[0]

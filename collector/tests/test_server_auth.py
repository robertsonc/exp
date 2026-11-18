"""Server hardening and authentication: scoping, fixed routes, limits, slowloris, connection cap, TLS,
credential rotation without restart. Every control is proven by attempting the forbidden thing."""
from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
import time

import pytest
from colhelpers import check_openapi, client_ctx, https, ingest, raw_tls, rec, wait_for
from exp_common import ids

from exp_collector.app import CollectorApp
from exp_collector.config import CollectorConfigError


def auth(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


# ----------------------------------------------------------------------------------- /healthz
def test_healthz_is_unauthenticated_and_says_only_ok(app, port):
    r = https(port, "GET", "/healthz")
    assert r.status == 200 and r.body == b"ok"
    assert https(port, "HEAD", "/healthz").status == 200
    assert r.h("Server") == "exp-collector"            # no Python/version banner


def test_healthz_reports_fail_when_the_store_is_dead(env):
    app = env.start()
    app.store.close()
    r = https(app.address[1], "GET", "/healthz")
    assert r.status == 503 and r.body == b"fail"


# ------------------------------------------------------------------------------- route table
@pytest.mark.parametrize("path", ["/", "/nope", "/api/v2/health", "/api/v1/", "/ingest/v1/other", "/metrics",
                                  "/healthz/", "/ingest/v1/measurements/", "/../etc/passwd", "/api/v1/health/x",
                                  "//healthz", "/%2e%2e/healthz"])
def test_anything_else_is_404(env, app, port, path):
    for headers in ({}, auth(env.dash_token), auth(env.ingest_token)):
        r = https(port, "GET", path, headers=headers)
        assert r.status == 404, (path, r.status)
        assert r.json()["error"]["code"] == "not_found"
        assert "Traceback" not in r.body.decode()


def test_wrong_method_is_405(env, port):
    assert https(port, "POST", "/healthz", body=b"").status == 405
    r = https(port, "GET", "/ingest/v1/measurements", headers=auth(env.ingest_token))
    assert r.status == 405 and "POST" in r.h("Allow")
    assert https(port, "DELETE", "/api/v1/health", headers=auth(env.dash_token)).status == 405


def test_router_refuses_misscoped_registration(app):
    from exp_collector.server import AUTH_DASHBOARD, AUTH_INGEST
    with pytest.raises(ValueError):
        app.router.add("GET", "/api/v1/x", lambda r: None, auth=AUTH_INGEST)
    with pytest.raises(ValueError):
        app.router.add("POST", "/ingest/v1/x", lambda r: None, auth=AUTH_DASHBOARD)
    with pytest.raises(ValueError):
        app.router.add("GET", "/api/v1/y", lambda r: None, auth="none")


# ------------------------------------------------------------------------------ auth scoping
def test_ingest_token_is_rejected_on_api(env, port):
    r = https(port, "GET", "/api/v1/health", headers=auth(env.ingest_token))
    assert r.status == 401 and r.json()["error"]["code"] == "invalid_token"
    assert r.h("WWW-Authenticate") == "Bearer"
    check_openapi("collector", "/health", "get", 401, r.json())
    assert https(port, "GET", "/api/v1/probes", headers=auth(env.ingest_token)).status == 401


def test_dashboard_token_is_rejected_on_ingest(env, app, port):
    r = ingest(port, env.dash_token, [rec()])
    assert r.status == 401
    check_openapi("ingest", "/measurements", "post", 401, r.json())
    assert app.store.count_records() == 0


def test_valid_tokens_work_on_their_own_surface(env, port):
    assert https(port, "GET", "/api/v1/health", headers=auth(env.dash_token)).status == 200
    assert ingest(port, env.ingest_token, [rec()]).status == 200


def test_token_hash_in_the_wrong_table_still_401(env, port):
    """Even if a dashboard token's hash were placed in ingest_tokens.json (or vice versa), the
    prefix check keeps token kinds apart."""
    env.write_creds({"probe-a1": ids.token_hash(env.dash_token)}, {"dash-main": ids.token_hash(env.ingest_token)}, [])
    app = env.start()
    p = app.address[1]
    assert ingest(p, env.dash_token, [rec()]).status == 401
    assert https(p, "GET", "/api/v1/health", headers=auth(env.ingest_token)).status == 401


@pytest.mark.parametrize("header", [None, "", "Bearer", "Bearer ", "bearer x", "Basic abc", "Bearer a b",
                                    "Bearer expi_" + "A" * 43 + "x", "Bearer expi_short", "Token expi_" + "A" * 43,
                                    "Bearer " + "x" * 5000])
def test_malformed_or_unknown_credentials_401(env, port, header):
    hdr = {} if header is None else {"Authorization": header}
    for method, path in (("POST", "/ingest/v1/measurements"), ("GET", "/api/v1/health")):
        r = https(port, method, path, headers={**hdr, "Content-Type": "application/x-ndjson"},
                  body=b"{}\n" if method == "POST" else None)
        assert r.status in (401, 431), (header, method, r.status)


def test_unknown_but_well_formed_token_401(env, port):
    assert ingest(port, ids.new_token("expi"), [rec()]).status == 401
    assert https(port, "GET", "/api/v1/health", headers=auth(ids.new_token("expd"))).status == 401


def test_token_identity_binds_the_probe(env, app, port):
    """probe-a2's token cannot store records claiming probe-a1."""
    r = ingest(port, env.ingest_token2, [rec(probe="probe-a1")])
    assert r.json()["accepted"] == 0 and r.json()["rejected"][0]["error"]["code"] == "identity_mismatch"
    assert app.store.count_records() == 0
    assert ingest(port, env.ingest_token2, [rec(probe="probe-a2")]).json()["accepted"] == 1


# --------------------------------------------------------------------------- credential reload
def test_rotation_takes_effect_without_restart(env, app, port):
    new_tok = ids.new_token("expi")
    assert ingest(port, new_tok, [rec()]).status == 401
    env.write_creds({"probe-a1": ids.token_hash(new_tok)}, {"dash-main": ids.token_hash(env.dash_token)}, [])
    assert wait_for(lambda: ingest(port, new_tok, [rec()]).status == 200, 10)
    assert ingest(port, env.ingest_token, [rec()]).status == 401         # old token revoked
    assert https(port, "GET", "/api/v1/health", headers=auth(env.dash_token)).status == 200


def test_bad_credential_reload_keeps_previous_set(env, app, port, log_capture):
    (env.creds / "ingest_tokens.json").write_text("{this is not json")
    assert wait_for(lambda: app.creds.last_error != "", 10)
    assert ingest(port, env.ingest_token, [rec()]).status == 200         # previous good set still active
    assert "not valid JSON" in log_capture()
    (env.creds / "ingest_tokens.json").write_text(json.dumps({"probe-a1": "zz"}))   # not a sha256
    assert wait_for(lambda: "sha256" in app.creds.last_error or app.creds.reload_errors >= 2, 10)
    assert ingest(port, env.ingest_token, [rec()]).status == 200
    env.write_creds({"probe-a1": ids.token_hash(env.ingest_token)}, {}, [])   # a good file clears the error
    assert wait_for(lambda: app.creds.last_error == "", 10)
    assert https(port, "GET", "/api/v1/health", headers=auth(env.dash_token)).status == 401   # dash table emptied


def test_startup_refuses_invalid_credentials(env):
    (env.creds / "ingest_tokens.json").write_text("[1,2")
    from exp_common.creds import CredentialError
    with pytest.raises(CredentialError):
        env.start()


def test_poll_interval_must_allow_10s_rotation(env):
    from exp_collector.config import CredStore
    with pytest.raises(ValueError):
        CredStore(env.creds, poll_s=30)


# ------------------------------------------------------------------------------------ limits
def _read_status(s: ssl.SSLSocket) -> bytes:
    s.settimeout(10)
    try:
        return s.recv(65536)
    except (OSError, ssl.SSLError):
        return b""


def test_request_line_over_8k_is_414(env, port):
    s = raw_tls(port)
    s.sendall(b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\nHost: x\r\n\r\n")
    assert _read_status(s).startswith(b"HTTP/1.1 414")
    s.close()
    ok = raw_tls(port)                                   # at the limit it is a normal 404, not 414
    ok.sendall(b"GET /" + b"a" * 8000 + b" HTTP/1.1\r\nHost: x\r\n\r\n")
    assert _read_status(ok).startswith(b"HTTP/1.1 404")
    ok.close()


def test_oversized_headers_431(env, port):
    s = raw_tls(port)
    s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n" + b"".join(b"X-%d: y\r\n" % i for i in range(100)) + b"\r\n")
    assert _read_status(s).startswith(b"HTTP/1.1 431")
    s.close()
    s = raw_tls(port)
    s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-Big: " + b"y" * 9000 + b"\r\n\r\n")
    assert _read_status(s).startswith(b"HTTP/1.1 431")
    s.close()


def test_malformed_requests_are_400_not_crashes(env, port):
    for bad in (b"GARBAGE\r\n\r\n", b"GET / HTTP/9.9\r\n\r\n", b"GET http://evil/ HTTP/1.1\r\nHost: x\r\n\r\n",
                b"GET /healthz HTTP/1.1\r\nContent-Length: abc\r\n\r\n"):
        s = raw_tls(port)
        s.sendall(bad)
        assert _read_status(s)[:12] in (b"HTTP/1.1 400", b"HTTP/1.1 404"), bad
        s.close()
    assert https(port, "GET", "/healthz").status == 200


def test_slowloris_headers_are_cut_off_at_the_header_timeout(env):
    app = env.start(header_timeout=1.0)
    port = app.address[1]
    s = raw_tls(port)
    s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")       # never finishes the header block
    t0 = time.monotonic()
    s.settimeout(8)
    try:
        data = s.recv(100)
    except (OSError, ssl.SSLError):
        data = b""
    elapsed = time.monotonic() - t0
    assert data == b"" and elapsed < 4, (data, elapsed)       # closed by the server, not by our timeout
    # a drip-feed (one byte every 0.4 s) cannot keep the header window open either
    s2 = raw_tls(port)
    t0 = time.monotonic()
    closed = False
    try:
        for ch in b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-A: b\r\n":
            s2.sendall(bytes([ch]))
            time.sleep(0.15)
            if time.monotonic() - t0 > 6:
                break
    except (OSError, ssl.SSLError):
        closed = True
    assert closed or time.monotonic() - t0 < 6.5
    assert time.monotonic() - t0 < 6.5
    assert https(port, "GET", "/healthz").status == 200


def test_idle_tls_handshake_does_not_block_other_clients(env):
    app = env.start(header_timeout=2.0)
    port = app.address[1]
    stalled = [socket.create_connection(("127.0.0.1", port)) for _ in range(5)]   # TCP only, no ClientHello
    t0 = time.monotonic()
    assert https(port, "GET", "/healthz").status == 200
    assert time.monotonic() - t0 < 1.5
    for s in stalled:
        s.close()


def test_connection_cap_returns_503_then_recovers(env):
    app = env.start(max_connections=4, header_timeout=30.0)
    port = app.address[1]
    held = [raw_tls(port) for _ in range(4)]
    assert wait_for(lambda: app.server.active_connections == 4, 5)
    s = raw_tls(port)
    s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
    data = _read_status(s)
    assert data.startswith(b"HTTP/1.1 503") and b"Retry-After: 1" in data, data
    s.close()
    assert app.server.rejected_connections >= 1
    for h in held:
        h.close()
    assert wait_for(lambda: app.server.active_connections == 0, 5)
    assert https(port, "GET", "/healthz").status == 200


def test_default_cap_is_512():
    from exp_collector.server import HEADER_TIMEOUT_S, MAX_CONNECTIONS, MAX_REQUEST_LINE
    assert (MAX_CONNECTIONS, HEADER_TIMEOUT_S, MAX_REQUEST_LINE) == (512, 10.0, 8192)


def test_keepalive_serves_several_requests_on_one_connection(env, port):
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=10, context=client_ctx())
    for _ in range(3):
        conn.request("GET", "/api/v1/health", headers=auth(env.dash_token))
        r = conn.getresponse()
        assert r.status == 200
        r.read()
    conn.close()


def test_error_does_not_poison_keepalive_connection(env, port):
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=10, context=client_ctx())
    conn.request("POST", "/ingest/v1/measurements", body=b"x" * 1000, headers={"Content-Type": "application/x-ndjson"})
    r = conn.getresponse()
    assert r.status == 401
    r.read()
    conn.request("GET", "/healthz")                       # small body was drained, connection reusable
    assert conn.getresponse().status == 200
    conn.close()


# ------------------------------------------------------------------------------------- TLS
def test_tls_minimum_is_1_2(env, app, port):
    assert app.server.ssl_context.minimum_version == ssl.TLSVersion.TLSv1_2
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, ctx.wrap_socket(raw) as s:
        assert s.version() == "TLSv1.2"
    old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    old.check_hostname = False
    old.verify_mode = ssl.CERT_NONE
    try:
        old.minimum_version = ssl.TLSVersion.TLSv1
        old.maximum_version = ssl.TLSVersion.TLSv1_1
    except (ValueError, ssl.SSLError):
        pytest.skip("local OpenSSL cannot even offer TLS 1.1")
    with pytest.raises((ssl.SSLError, OSError)), socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        old.wrap_socket(raw)


def test_plain_http_to_the_tls_port_is_not_served(env, port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
    s.settimeout(5)
    try:
        data = s.recv(1000)
    except OSError:
        data = b""
    assert b"ok" not in data and not data.startswith(b"HTTP/1.1 200")
    s.close()


def test_world_readable_tls_key_is_refused(env):
    os.chmod(env.key, 0o644)
    with pytest.raises(ssl.SSLError):
        env.start()


def test_wildcard_listen_is_refused(env):
    for host in ("0.0.0.0", "::", ""):
        with pytest.raises(CollectorConfigError):
            CollectorApp(env.config(), env.paths(), listen=(host, 8443))
    env.cfg_doc["listen"] = "0.0.0.0:8443"
    with pytest.raises(CollectorConfigError):
        CollectorApp(env.config(), env.paths())


def test_binds_only_the_configured_address(env, app):
    assert app.address[0] == "127.0.0.1"

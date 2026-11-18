"""`app`: curl -w '%{json}' parsing on recorded outputs, and the real curl against a local HTTP server
(captive portal and failure negative controls)."""
from __future__ import annotations

import json
import shutil
import tempfile

import pytest
from httpstub import HttpStub
from measure_support import make_ctx
from netfakes import ScriptRunner, recorded, validate_measurements

from exp_probe.checks import app as A
from exp_probe.runner import CommandRunner

HAVE_CURL = shutil.which("curl") is not None
needs_curl = pytest.mark.skipif(not HAVE_CURL, reason="needs curl >= 7.81")


# ---------------------------------------------------------------------------- recorded curl output

def test_parse_recorded_https_success():
    r = A.parse_curl(recorded("curl_https_ok.stdout.json"), recorded("curl_https_ok.stderr.txt"), 0)
    assert r.ok and r.status == 200 and r.bytes == 5100 and r.scheme == "https" and r.remote_ip == "127.0.0.1"
    assert r.tls_version == "TLSv1.3" and r.total_ms == 4.0 and r.num_redirects == 0
    assert r.dns_ms == 0.02 and r.connect_ms == 0.12 and r.tls_ms == 3.47     # connect-dns, appconnect-connect
    assert r.ttfb_ms == 0.33                                                 # starttransfer - appconnect (EXM phase math)
    assert r.error is None


def test_parse_recorded_connect_failure():
    r = A.parse_curl(recorded("curl_refused.stdout.json"), recorded("curl_refused.stderr.txt"), 7)
    assert not r.ok and r.status == 0 and r.exitcode == 7 and "Couldn't connect" in r.error and r.tls_version is None


def test_parse_garbage_never_raises():
    for out, rc in (("", 0), ("not json", 0), ("{", 7), ("[]", 0), ('{"exitcode": "x"}', 0), ("\x00\xff", 28)):
        r = A.parse_curl(out, "curl: (28) Operation timed out", rc)
        assert not r.ok and r.error


def test_apdex_bands():
    assert [A.apdex(x, 100) for x in (10, 100, 101, 400, 401, None)] == [1.0, 1.0, 0.5, 0.5, 0.0, 0.0]


def test_captive_detection_rules():
    base = dict(ok=True, exitcode=0, status=200, bytes=40)
    r200 = A.CurlResult(**base)
    assert "expected HTTP 204" in A.detect_captive("http://x.example/generate_204", r200, "", {})
    assert A.detect_captive("http://x.example/generate_204", A.CurlResult(ok=True, exitcode=0, status=204), "", {}) is None
    assert "expected HTTP 204, got 200 (redirected to http://portal.venue.net/login)" in A.detect_captive(
        "http://x.example/gen_204", A.CurlResult(**base, num_redirects=1, url_effective="http://portal.venue.net/login"), "", {})
    assert "did not contain" in A.detect_captive("http://captive.apple.com/hotspot-detect.html", r200, "portal", {})
    assert A.detect_captive("http://captive.apple.com/hotspot-detect.html", r200, "<HTML>Success</HTML>", {}) is None
    moved = A.CurlResult(**base, num_redirects=1, url_effective="http://portal.venue.net/x")
    assert "another site" in A.detect_captive("http://example.com/", moved, "", {})
    same = A.CurlResult(**base, num_redirects=1, url_effective="http://www.example.com/")
    assert A.detect_captive("http://example.com/", same, "", {}) is None                  # same registrable domain
    assert A.detect_captive("https://example.com/", moved, "", {}) is None                # only plain-http targets
    assert A.detect_captive("http://x.example/generate_204", A.CurlResult(ok=True, exitcode=0, status=503), "", {}) is None
    assert A.detect_captive("http://x.example/p", r200, "", {"expect_status": 200}) is None


def test_command_is_an_argv_list_without_a_shell(tmp_path):
    r = ScriptRunner()
    r.on("curl", out=recorded("curl_https_ok.stdout.json"), err=recorded("curl_https_ok.stderr.txt"))
    ctx = make_ctx(tmp_path, runner=r, tests={"app": {"targets": [{"app": "g", "url": "https://www.google.com/"}]}})
    (m,) = A.app(ctx)
    validate_measurements([m])
    argv = r.calls[0]
    assert argv[:4] == ["ip", "netns", "exec", "exp-c01"] and argv[4] == "curl" and isinstance(argv, list)
    assert "%{json}" in argv and argv[argv.index("-w") + 1] == "%{json}" and "-L" in argv
    assert argv[argv.index("--max-redirs") + 1] == "5" and argv[argv.index("--max-time") + 1] == "15"
    assert argv[argv.index("-o") + 1] == "/dev/null" and argv[-2:] == ["--url", "https://www.google.com/"]
    assert m.detail["tls_version"] == "TLSv1.3" and m.detail["url"] == "https://www.google.com/"
    assert m.outcome == "ok" and m.metrics["apdex"] == 1.0 and m.detail["apdex_t_ms"] == 500


def test_curl_missing_or_hung_and_bad_inputs(tmp_path):
    tgt = {"app": "g", "url": "https://www.google.com/"}
    (m,) = A.app(make_ctx(tmp_path, runner=ScriptRunner(), tests={"app": {"targets": [tgt]}}))
    assert m.outcome == "error" and m.error == "curl is not installed"
    r = ScriptRunner()
    from exp_probe.runner import CmdResult
    r.on("curl", fn=lambda a: CmdResult(tuple(a), 124, "", "", True))
    (m,) = A.app(make_ctx(tmp_path, runner=r, tests={"app": {"targets": [tgt]}}))
    assert m.outcome == "fail" and "did not finish" in m.error and m.metrics["apdex"] == 0
    ctx = make_ctx(tmp_path, runner=r)
    m = A.run_target(ctx, ctx.port, {"app": "x", "url": "http://a b/"}, None)       # config validation stops this earlier
    validate_measurements([m])
    assert m.outcome == "error" and "invalid url" in m.error
    fresh = tmp_path / "nolease"
    fresh.mkdir()
    (m,) = A.app(make_ctx(fresh, runner=r, leased=(), tests={"app": {"targets": [tgt]}}))
    assert m.outcome == "error" and "no lease" in m.error and m.labels == {"port": "c01", "app": "g"}
    (m,) = A.app(make_ctx(fresh, runner=r))
    assert m.outcome == "error" and "no app targets" in m.error


# ------------------------------------------------------------------------------- real curl, local server

@pytest.fixture
def web():
    s = HttpStub()
    yield s
    s.close()


def real(tmp_path, web, targets):
    """host mode on loopback: real curl through the real command runner, pinned with --interface lo."""
    ctx = make_ctx(tmp_path, mode="host", ports=[{"id": "c01", "iface": "lo", "role": "client"}],
                   tests={"app": {"interval_s": 300, "targets": [{**t, "url": web.url(t["url"])} for t in targets]}})
    ctx.runner = CommandRunner()
    ms = A.app(ctx)
    validate_measurements(ms)
    return ms


@needs_curl
def test_real_ok_has_the_catalog_metrics(tmp_path, web):
    (m,) = real(tmp_path, web, [{"app": "local", "url": "/ok", "apdex_t_ms": 1000}])
    assert m.outcome == "ok" and m.labels == {"port": "c01", "app": "local"}
    assert m.metrics["status_code"] == 200 and m.metrics["bytes"] == 11 and m.metrics["apdex"] == 1.0
    assert {"dns_ms", "connect_ms", "ttfb_ms", "total_ms"} <= set(m.metrics) and m.duration_ms == m.metrics["total_ms"]
    assert m.detail["url"].endswith("/ok") and m.detail["ip"] == "127.0.0.1" and m.detail["apdex_t_ms"] == 1000


@needs_curl
def test_real_204_connectivity_check_is_ok(tmp_path, web):
    (m,) = real(tmp_path, web, [{"app": "cc", "url": "/cp-ok/generate_204"}])
    assert m.outcome == "ok" and m.metrics["status_code"] == 204 and m.metrics["bytes"] == 0 and "captive_portal" not in m.detail


@needs_curl
@pytest.mark.parametrize("path", ["/cp-200/generate_204", "/cp-302/generate_204"])
def test_real_captive_portal_negative_control(tmp_path, web, path):
    (m,) = real(tmp_path, web, [{"app": "cc", "url": path}])
    assert m.outcome == "fail" and m.detail["captive_portal"] is True and "captive portal suspected" in m.error
    assert "expected HTTP 204, got 200" in m.detail["captive_reason"]
    if "302" in path:
        assert "redirected to" in m.detail["captive_reason"] and m.detail["num_redirects"] == 1


@needs_curl
def test_real_body_expectation_detects_portal_content_on_a_200(tmp_path, web):
    ok, portal = real(tmp_path, web, [{"app": "a", "url": "/hotspot-ok", "expect_body": "Success"},
                                      {"app": "b", "url": "/hotspot-portal", "expect_body": "Success"}])
    assert ok.outcome == "ok" and portal.outcome == "fail" and portal.detail["captive_portal"] is True
    assert not [p for p in __import__("pathlib").Path(tempfile.gettempdir()).glob("exp-probe-body-*")]   # temp body removed


@needs_curl
def test_real_slow_endpoint_is_degraded_by_the_4x_rule_and_by_apdex(tmp_path, web):
    far, mid, fine = real(tmp_path, web, [{"app": "far", "url": "/slow/0.2", "apdex_t_ms": 20},
                                          {"app": "mid", "url": "/slow/0.2", "apdex_t_ms": 100},
                                          {"app": "fine", "url": "/slow/0.2", "apdex_t_ms": 1000}])
    assert far.outcome == "degraded" and far.metrics["apdex"] == 0.0 and "exceeds 4x" in far.error      # total > 4T
    assert mid.outcome == "degraded" and mid.metrics["apdex"] == 0.5 and "apdex 0.5" in mid.error       # tolerating
    assert fine.outcome == "ok" and fine.metrics["apdex"] == 1.0


@needs_curl
def test_real_http_errors_and_connection_failures(tmp_path, web):
    e500, e404, loop, down = real(tmp_path, web, [{"app": "a", "url": "/err500"}, {"app": "b", "url": "/err404"},
                                                  {"app": "c", "url": "/loop"}, {"app": "d", "url": "/ok"}])
    assert e500.outcome == "fail" and e500.error == "HTTP 500"
    assert e404.outcome == "degraded" and e404.error == "HTTP 404"
    assert loop.outcome == "fail" and "redirect" in e500.error + loop.error.lower()
    web.close()
    (m,) = real(tmp_path, web, [{"app": "gone", "url": "/ok"}])
    assert m.outcome == "fail" and m.metrics["status_code"] == 0 and m.metrics["apdex"] == 0.0
    assert "connect" in m.error.lower() and m.outcome != "error"                 # a network verdict, not a probe error


@needs_curl
def test_real_untrusted_tls_is_a_fail_not_an_error(tmp_path):
    import subprocess
    d = tmp_path / "tls"
    d.mkdir()
    if not shutil.which("openssl"):
        pytest.skip("needs openssl")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", str(d / "k.pem"), "-out", str(d / "c.pem"), "-subj", "/CN=localhost", "-days", "1"],
                   check=True, capture_output=True)
    import socket
    import ssl
    import threading
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(d / "c.pem", d / "k.pem")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        try:
            c, _ = srv.accept()
            try:
                sctx.wrap_socket(c, server_side=True).close()
            except (ssl.SSLError, OSError):
                pass
        except OSError:
            pass
    threading.Thread(target=serve, daemon=True).start()
    ctx = make_ctx(tmp_path, mode="host", ports=[{"id": "c01", "iface": "lo", "role": "client"}],
                   tests={"app": {"targets": [{"app": "tls", "url": f"https://127.0.0.1:{port}/"}]}})
    ctx.runner = CommandRunner()
    (m,) = A.app(ctx)
    srv.close()
    validate_measurements([m])
    assert m.outcome == "fail" and ("certificate" in m.error.lower() or "ssl" in m.error.lower())


@needs_curl
def test_real_run_json_roundtrips_through_the_schema(tmp_path, web):
    (m,) = real(tmp_path, web, [{"app": "local", "url": "/ok"}])
    from exp_common.schema import Measurement
    Measurement.from_dict(json.loads(json.dumps(m.to_dict())), require_id=True)


def test_hostile_curl_error_text_is_clipped_and_clean():
    evil = json.dumps({"exitcode": 35, "errormsg": "boom\x00\x1b[31m\n" + "Z" * 5000, "response_code": 0})
    r = A.parse_curl(evil, "", 35)
    assert not r.ok and len(r.error) <= 300 and all(ch.isprintable() for ch in r.error)
    from exp_common.schema import Measurement
    Measurement(probe="p", test="app", outcome="fail", error=r.error).validate()

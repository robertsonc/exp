"""cloudflare_speed fake: headers equal the live recording's, behaviour knobs, HTTPS with a throwaway CA."""
from __future__ import annotations

import http.client
import json
import re
import ssl
import time

import pytest
from fakes_support import request

import fake_ca
from cloudflare_speed import server as cf

REC = cf.load_recording()
DYNAMIC = {"date", "content-length", "cf-ray", "cf-meta-request-time", "cf-meta-upload-bytes", "server-timing", "cf-meta-ip",
           "colo", "cf-meta-colo", "report-to", "asn", "city", "country", "latitude", "longitude", "postalcode", "timezone"}
GEO_LOW = {"asn", "city", "country", "latitude", "longitude", "postalcode", "timezone"}


@pytest.fixture()
def fake():
    f = cf.start()
    yield f
    f.stop()


def raw(port: int, method: str, path: str, body: bytes | None = None, tls_ctx: ssl.SSLContext | None = None,
        headers: dict[str, str] | None = None, host: str = "127.0.0.1") -> tuple[int, list[tuple[str, str]], bytes]:
    conn = (http.client.HTTPSConnection(host, port, timeout=10, context=tls_ctx) if tls_ctx
            else http.client.HTTPConnection(host, port, timeout=10))
    try:
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        data = r.read()
        return r.status, r.getheaders(), data
    finally:
        conn.close()


def exchange(label_part: str, method: str, url_part: str) -> dict:
    for ex in REC["exchanges"]:
        if ex["request"]["method"] == method and url_part in ex["request"]["url"] and label_part in ex["label"]:
            return ex["response"]
    raise AssertionError(label_part)


def assert_same_headers(got: list[tuple[str, str]], recorded: list[list[str]], what: str) -> None:
    """Same names in the same order and case; static values identical; generated values only checked for shape."""
    assert [n for n, _ in got] == [n for n, _ in recorded], f"{what}: header names/order differ"
    for (n, v), (_, rv) in zip(got, recorded, strict=True):
        low = n.lower()
        if low not in DYNAMIC:
            assert v == rv, f"{what}: static header {n!r} differs: {v!r} != {rv!r}"
        elif low == "report-to":
            norm = lambda s: re.sub(r"\?s=[^\"]+", "?s=X", s)  # noqa: E731
            assert norm(v) == norm(rv)
        elif low == "date":
            assert re.fullmatch(r"[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT", v)
        elif low == "cf-ray":
            assert re.fullmatch(r"[0-9a-f]{16}-[A-Z]{3}", v)
        elif low == "server-timing":
            assert re.fullmatch(r"cfSpeedEdge;dur=\d+, cfSpeedWorker;dur=\d+|cfL4;desc=\"\?proto=TCP&rtt=\d+.*\"", v)
        elif low in ("cf-meta-request-time", "cf-meta-upload-bytes", "content-length"):
            assert v.isdigit()


def test_down_headers_equal_recording(fake):
    st, hdrs, body = raw(fake.port, "GET", "/__down?bytes=0", headers={"Origin": "http://speed.summit.example"})
    assert st == 200 and body == b""
    assert_same_headers(hdrs, exchange("latency probe (idle)", "GET", "__down?bytes=0")["headers"], "down bytes=0")
    st, hdrs, body = raw(fake.port, "GET", "/__down?bytes=100000")
    assert st == 200 and body == b"0" * 100000
    assert dict((k.lower(), v) for k, v in hdrs)["content-length"] == "100000"
    assert_same_headers(hdrs, exchange("download 100 kB", "GET", "__down?bytes=100000")["headers"], "down 100k")


def test_down_during_load_headers(fake):
    st, hdrs, _ = raw(fake.port, "GET", "/__down?bytes=0&during=downloadload")
    assert st == 200
    assert_same_headers(hdrs, exchange("during download load", "GET", "during=downloadload")["headers"], "during")


def test_up_headers_equal_recording_and_counts_bytes(fake):
    st, hdrs, body = raw(fake.port, "POST", "/__up?bytes=1000", body=b"0" * 1000,
                         headers={"Content-Type": "text/plain;charset=UTF-8"})
    assert st == 200 and body == b""
    assert_same_headers(hdrs, exchange("upload 1 kB", "POST", "__up")["headers"], "up")
    assert dict((k.lower(), v) for k, v in hdrs)["cf-meta-upload-bytes"] == "1000"
    assert fake.app.snapshot()["stats"]["bytes_up"] == 1000


def test_trace_headers_and_body(fake):
    st, hdrs, body = raw(fake.port, "GET", "/cdn-cgi/trace")
    assert st == 200
    assert_same_headers(hdrs, exchange("colo / loc", "GET", "cdn-cgi/trace")["headers"], "trace")
    text = body.decode()
    kv = dict(line.split("=", 1) for line in text.splitlines())
    assert kv["colo"] == "FRA" and kv["loc"] == "DE" and kv["h"] == "speed.cloudflare.com"
    # the recording's first 32 bytes are "fl=...\nh=speed.cloudflare.co": same key order
    assert bytes.fromhex(REC["exchanges"][4]["response"]["body"]["head_hex"]).decode().split("\n")[1].startswith("h=speed")
    assert text.splitlines()[0].startswith("fl=") and text.splitlines()[1] == "h=speed.cloudflare.com"
    assert int(dict((k.lower(), v) for k, v in hdrs)["content-length"]) == len(body)
    # no Timing-Allow-Origin on the trace (the recording has none)
    assert "timing-allow-origin" not in [k.lower() for k, _ in hdrs]


@pytest.mark.parametrize("path,label", [("/__up?bytes=1000", "no custom headers"), ("/__down?bytes=0", "preflight for __down")])
def test_preflight_equals_recording(fake, path, label):
    st, hdrs, body = raw(fake.port, "OPTIONS", path, headers={"Origin": "http://x.example", "Access-Control-Request-Method": "POST"})
    assert st == 204 and body == b""
    assert_same_headers(hdrs, exchange(label, "OPTIONS", path.split("?")[0])["headers"], "preflight")
    d = {k.lower(): v for k, v in hdrs}
    assert d["access-control-allow-origin"] == "*" and d["timing-allow-origin"] == "*"
    assert "content-length" not in d


def test_recorded_geo_ip_values_are_never_replayed(fake):
    _, hdrs, _ = raw(fake.port, "GET", "/__down?bytes=0")
    rec_vals = {v for ex in REC["exchanges"] for n, v in ex["response"]["headers"] if n.lower() in GEO_LOW | {"cf-meta-ip"}}
    got = {v for n, v in hdrs if n.lower() in GEO_LOW | {"cf-meta-ip"}}
    assert got and not (got & rec_vals)
    assert dict((k.lower(), v) for k, v in hdrs)["cf-meta-ip"].startswith("203.0.113.")


def test_colo_is_configurable_and_readable_only_where_recorded(fake):
    fake.app.set(colo="AMS", loc="NL")
    _, hdrs, body = raw(fake.port, "GET", "/cdn-cgi/trace")
    assert b"colo=AMS" in body
    _, hdrs, _ = raw(fake.port, "GET", "/__down?bytes=0")
    d = {k.lower(): v for k, v in hdrs}
    assert d["colo"] == "AMS" and "cf-meta-colo" not in d      # recording: __down has no cf-meta-colo ...
    assert "colo" not in [x.strip() for x in d["access-control-expose-headers"].split(",")]  # ... and does not expose `colo`
    _, hdrs, _ = raw(fake.port, "POST", "/__up?bytes=1", body=b"0", headers={"Content-Type": "text/plain"})
    assert {k.lower(): v for k, v in hdrs}["cf-meta-colo"] == "AMS"
    with pytest.raises(ValueError):
        fake.app.set(colo="x")
    with pytest.raises(KeyError):
        fake.app.set(nope=1)


def test_bad_inputs(fake):
    assert raw(fake.port, "GET", "/__down?bytes=abc")[0] == 400
    assert raw(fake.port, "GET", "/__down?bytes=99999999999")[0] == 400
    assert raw(fake.port, "GET", "/nope")[0] == 404
    assert raw(fake.port, "GET", "/__up?bytes=1")[0] == 405


def test_rate_limit_slows_download(fake):
    fake.app.set(down_bps=8_000_000)     # 1 MB/s
    t = time.monotonic()
    st, _, body = raw(fake.port, "GET", "/__down?bytes=300000")
    assert st == 200 and len(body) == 300000
    assert time.monotonic() - t >= 0.25


def test_rate_limit_slows_upload(fake):
    fake.app.set(up_bps=4_000_000)       # 0.5 MB/s
    t = time.monotonic()
    st, hdrs, _ = raw(fake.port, "POST", "/__up?bytes=150000", body=b"0" * 150000)
    assert st == 200 and time.monotonic() - t >= 0.25


def test_latency_idle_vs_loaded(fake):
    fake.app.set(latency_ms=30, loaded_latency_ms=250)
    t = time.monotonic()
    raw(fake.port, "GET", "/__down?bytes=0")
    idle = time.monotonic() - t
    t = time.monotonic()
    raw(fake.port, "GET", "/__down?bytes=0&during=downloadload")
    loaded = time.monotonic() - t
    assert idle >= 0.025 and loaded >= 0.24 and loaded > idle


def test_kill_resets_connections_and_heal_restores(fake):
    fake.app.kill()
    with pytest.raises((ConnectionError, http.client.HTTPException, OSError)):
        raw(fake.port, "GET", "/__down?bytes=0")
    fake.app.heal()
    assert raw(fake.port, "GET", "/__down?bytes=0")[0] == 200
    assert fake.app.snapshot()["stats"]["failed"] >= 1


def test_http500_mode(fake):
    fake.app.set(fail="http500")
    assert raw(fake.port, "GET", "/__down?bytes=10")[0] == 500


def test_fail_after_bytes_cuts_mid_body(fake):
    fake.app.set(fail_after_bytes=20000)
    with pytest.raises((http.client.IncompleteRead, ConnectionError, http.client.HTTPException, OSError)):
        raw(fake.port, "GET", "/__down?bytes=100000")


def test_stall_mode_times_out(fake):
    fake.app.set(fail="stall")
    conn = http.client.HTTPConnection("127.0.0.1", fake.port, timeout=0.5)
    with pytest.raises((TimeoutError, OSError)):
        conn.request("GET", "/__down?bytes=0")
        conn.getresponse()
    conn.close()


def test_control_api_loopback(fake):
    r = request(fake.port, "POST", "/_fake/set", {"latency_ms": 5})
    assert r.status == 200 and r.json()["cfg"]["latency_ms"] == 5
    assert request(fake.port, "POST", "/_fake/set", {"bogus": 1}).status == 400
    assert request(fake.port, "POST", "/_fake/kill").json()["cfg"]["fail"] == "reset"
    assert request(fake.port, "POST", "/_fake/heal").json()["cfg"]["fail"] == "none"
    assert request(fake.port, "GET", "/_fake/stats").json()["stats"]["requests"] >= 0


def test_https_with_runtime_throwaway_ca(tmp_path):
    ca, leaf = fake_ca.make_server_tls(tmp_path)
    f = cf.start(tls=(leaf.cert_chain, leaf.key))
    try:
        ctx = fake_ca.client_context(ca)
        st, hdrs, body = raw(f.port, "GET", "/cdn-cgi/trace", tls_ctx=ctx, host="localhost")
        assert st == 200 and b"colo=FRA" in body
        assert f.scheme == "https"
        # a client that does not trust the throwaway CA must refuse it
        with pytest.raises(ssl.SSLError):
            raw(f.port, "GET", "/cdn-cgi/trace", tls_ctx=ssl.create_default_context(), host="localhost")
    finally:
        f.stop()


def test_recording_is_json_and_fake_never_contains_recorded_egress_ip():
    ip = [v for n, v in REC["exchanges"][0]["response"]["headers"] if n == "cf-meta-ip"][0]
    src = (cf.HERE / "server.py").read_text()
    assert ip not in src
    assert json.dumps(cf.GEO).find("Council") < 0


def test_fake_ca_rejects_bad_inputs(tmp_path):
    with pytest.raises(ValueError):
        fake_ca.make_ca(tmp_path, cn="bad/cn")
    ca = fake_ca.make_ca(tmp_path / "ca")
    with pytest.raises(ValueError):
        fake_ca.issue(ca, tmp_path / "x", sans=("DNS:ok", "bogus"))
    assert oct(ca.key.stat().st_mode & 0o777) == "0o600"

"""The shared bounded HTTP client: retries only idempotent reads, never past the budget, 429 pauses, size and timeout caps."""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from exp_runner import upstream as up
from exp_runner.connectors import CallBudget
from exp_runner.upstream import UpstreamClient, UpstreamError


class Srv(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), H)
        self.script: list[tuple[int, bytes, dict]] = []
        self.hits: list[tuple[str, str]] = []
        threading.Thread(target=self.serve_forever, daemon=True).start()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _do(self):
        self.server.hits.append((self.command, self.path))
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        code, body, hdr = self.server.script.pop(0) if self.server.script else (200, b"{}", {})
        self.send_response(code)
        for k, v in hdr.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _do


@pytest.fixture()
def srv():
    s = Srv()
    yield s
    s.shutdown()


def client(srv, **kw):
    kw.setdefault("sleep", lambda _s: None)
    return UpstreamClient("t", f"http://127.0.0.1:{srv.server_address[1]}/api", {"X-Key": "k"}, **kw)


def test_get_returns_json_and_prefixes_the_path(srv):
    srv.script = [(200, b'{"a": 1}', {})]
    assert client(srv).get("/x", {"q": "1 2", "skip": None}) == {"a": 1}
    assert srv.hits == [("GET", "/api/x?q=1+2")]


def test_retries_5xx_on_idempotent_calls_with_backoff_and_counts_each_attempt(srv):
    srv.script = [(503, b"", {}), (503, b"", {}), (200, b"[]", {})]
    sleeps = []
    c = client(srv, retries=2, sleep=sleeps.append, backoff_s=0.5)
    b = CallBudget(10)
    assert c.get("/x", budget=b) == [] and b.used == 3 and sleeps == [0.5, 1.0]


def test_non_idempotent_calls_do_not_retry(srv):
    srv.script = [(503, b"", {}), (200, b"{}", {})]
    with pytest.raises(UpstreamError) as ei:
        client(srv).request("POST", "/x", body={"a": 1}, idempotent=False)
    assert ei.value.kind == "http" and len(srv.hits) == 1


def test_budget_caps_attempts_including_retries(srv):
    srv.script = [(503, b"", {})] * 5
    c = client(srv, retries=4)
    with pytest.raises(UpstreamError) as ei:
        c.get("/x", budget=CallBudget(2))
    assert ei.value.kind == "budget" and len(srv.hits) == 2


def test_429_is_not_retried_and_pauses_the_client_using_retry_after(srv):
    srv.script = [(429, b"{}", {"Retry-After": "7"})]
    c = client(srv, retries=3)
    with pytest.raises(UpstreamError) as ei:
        c.get("/x")
    assert ei.value.kind == "rate_limited" and len(srv.hits) == 1 and 5 < c.blocked_for() <= 7
    with pytest.raises(UpstreamError):
        c.get("/y")
    assert len(srv.hits) == 1                                                   # fails fast: no request while paused


def test_429_without_retry_after_uses_the_default_pause(srv):
    srv.script = [(429, b"{}", {})]
    c = client(srv)
    with pytest.raises(UpstreamError):
        c.get("/x")
    assert up.RATE_LIMIT_PAUSE_S - 2 < c.blocked_for() <= up.RATE_LIMIT_PAUSE_S


def test_auth_and_404_are_distinct_and_never_retried(srv):
    srv.script = [(401, b"{}", {}), (404, b"{}", {})]
    c = client(srv, retries=3)
    with pytest.raises(UpstreamError) as e1:
        c.get("/x")
    with pytest.raises(UpstreamError) as e2:
        c.get("/y")
    assert (e1.value.kind, e2.value.kind) == ("auth", "not_found") and len(srv.hits) == 2


def test_oversized_and_non_json_responses_are_bad_responses(srv):
    srv.script = [(200, b"x" * 5000, {}), (200, b"not json", {})]
    c = client(srv, max_bytes=1000)
    with pytest.raises(UpstreamError) as e1:
        c.get("/x")
    with pytest.raises(UpstreamError) as e2:
        c.get("/y")
    assert e1.value.kind == "bad_response" and e2.value.kind == "bad_response"


def test_deadline_stops_the_chain(srv):
    c = client(srv)
    with pytest.raises(UpstreamError) as ei:
        c.get("/x", deadline=time.monotonic() - 1)
    assert ei.value.kind == "deadline" and not srv.hits


def test_connection_refused_is_a_transport_error_after_bounded_retries():
    c = UpstreamClient("t", "http://127.0.0.1:9/api", {}, timeout_s=0.3, retries=2, sleep=lambda _s: None)
    with pytest.raises(UpstreamError) as ei:
        c.get("/x")
    assert ei.value.kind in ("transport", "timeout") and c.calls == 3


def test_base_url_rules():
    for bad in ("ftp://x/", "http://example.com/api", "https://u:p@example.com/", "https:///x"):
        with pytest.raises(ValueError):
            UpstreamClient("t", bad, {})
    UpstreamClient("t", "https://api.mist.example/api/v1", {})
    UpstreamClient("t", "http://localhost:1/api", {})


def test_sanitizers():
    assert up.s("a\x00b\x1f c" + "x" * 100, 8) == "ab cxxxx" and up.s({"a": 1}) is None and up.s(True) is None and up.s("   ") is None
    assert up.i("12") == 12 and up.i(True) is None and up.i(1.9) == 1 and up.i("x") is None and up.i(float("nan")) is None
    assert up.f("1.5") == 1.5 and up.f(float("inf")) is None and up.f(None) is None and up.b(1) is None and up.b(True) is True
    d = {}
    up.put(d, "a", None)
    up.put(d, "b", 0)
    assert d == {"b": 0}
    assert json.dumps(d)

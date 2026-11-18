"""SSE multiplexing: one upstream per collector, filtered browser streams, reconnect, resume."""
from __future__ import annotations

import json
import socket
import ssl
import time

import exp_dashboard.server as server

from test_federation import incident

INC_A = "inc_01M7R3X9G0NTM2HDJYD21Y49WA"


class Sse:
    """Raw TLS SSE reader."""

    def __init__(self, world, path: str, client, last_event_id: str | None = None) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.sock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", world.port), timeout=10))
        self.sock.settimeout(0.3)
        hdr = f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n"
        if client.cookie:
            hdr += f"Cookie: __Host-exp_session={client.cookie}\r\n"
        if last_event_id:
            hdr += f"Last-Event-ID: {last_event_id}\r\n"
        self.sock.sendall((hdr + "\r\n").encode())
        self.buf = b""
        self.events: list[dict] = []
        self.closed = False
        self.status = 0
        self.headers = ""

    def pump(self, seconds: float = 0.5) -> None:
        end = time.time() + seconds
        while time.time() < end and not self.closed:
            try:
                chunk = self.sock.recv(65536)
            except TimeoutError:
                continue
            except (ssl.SSLError, OSError):
                self.closed = True
                break
            if not chunk:
                self.closed = True
                break
            self.buf += chunk
        self._parse()

    def _parse(self) -> None:
        if not self.status and b"\r\n\r\n" in self.buf:
            head, _, self.buf = self.buf.partition(b"\r\n\r\n")
            self.headers = head.decode()
            self.status = int(self.headers.split(" ", 2)[1])
        if not self.status:
            return
        while b"\n\n" in self.buf:
            block, _, self.buf = self.buf.partition(b"\n\n")
            ev: dict = {}
            for line in block.decode().split("\n"):
                if line.startswith(":"):
                    ev.setdefault("comment", line)
                    continue
                k, _, v = line.partition(": ")
                if k == "data":
                    ev["data"] = json.loads(v)
                else:
                    ev[k] = v
            self.events.append(ev)

    def wait(self, pred, timeout: float = 10.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.pump(0.2)
            if pred():
                return True
            if self.closed:
                break
        return pred()

    def kinds(self, kind: str) -> list[dict]:
        return [e for e in self.events if e.get("event") == kind]

    def close(self) -> None:
        self.sock.close()


def beat(world, cid: str, probe: str, line: str = "dns", v: int = 0, site: str | None = None) -> None:
    f = world.fakes[cid]
    with f.app.cond:
        f.app._emit("beat", probe, site or f"hall-{cid[-1]}", {"probe": probe, "line": line, "t": int(time.time() * 1000), "v": v})
        f.app.cond.notify_all()


def wait_upstream(world, timeout=10):
    assert world.wait_for(lambda: all(world.app.hub.upstream_up.values()), timeout=timeout)


def test_stream_requires_auth_and_valid_filter(world):
    c = world.client()
    assert c.get("/api/v1/stream?site=hall-a").status == 401
    v = world.as_user("vera")
    for q in ("", "?probes=a&site=b", "?probes=BAD!", "?site=UP", "?probes=" + ",".join(["a"] * 300)):
        assert v.get("/api/v1/stream" + q).status == 400, q


def test_one_upstream_per_collector_multiplexed_to_all_clients(world):
    wait_upstream(world)
    v = world.as_user("vera")
    streams = [Sse(world, "/api/v1/stream?site=hall-a", v) for _ in range(5)]
    try:
        for s in streams:
            assert s.wait(lambda s=s: s.status == 200)
            assert "text/event-stream" in s.headers and "no-store" in s.headers
            assert "Content-Security-Policy" in s.headers
        assert len(world.app.hub._threads) == 3                     # one upstream thread per collector
        beat(world, "col-a", "probe-a1", v=2)
        for s in streams:
            assert s.wait(lambda s=s: len(s.kinds("beat")) >= 1)
            e = s.kinds("beat")[0]
            assert e["data"]["probe"] == "probe-a1" and e["data"]["v"] == 2 and e["data"]["collector_id"] == "col-a"
            assert e["id"].count(".") == 1
        assert world.app.hub.client_count == 5
        # exactly one upstream connection per collector: the collector sees one stream request each
        assert world.fakes["col-a"].app.requests < 40
    finally:
        for s in streams:
            s.close()
    assert world.wait_for(lambda: world.app.hub.client_count == 0, timeout=10)


def test_browser_clients_are_filtered_by_probe_and_site(world):
    wait_upstream(world)
    v = world.as_user("vera")
    only_a = Sse(world, "/api/v1/stream?probes=probe-a1", v)
    only_b = Sse(world, "/api/v1/stream?probes=probe-b1,probe-c1", v)
    site_c = Sse(world, "/api/v1/stream?site=hall-c", v)
    try:
        for s in (only_a, only_b, site_c):
            assert s.wait(lambda s=s: s.status == 200)
        beat(world, "col-a", "probe-a1")
        beat(world, "col-b", "probe-b1")
        beat(world, "col-c", "probe-c1")
        world.fakes["col-c"].app.inject_incident(incident(INC_A, "probe-c1", "hall-c", "2026-11-18T10:00:00.000Z"))
        assert only_b.wait(lambda: len(only_b.kinds("beat")) >= 2)
        assert site_c.wait(lambda: len(site_c.kinds("incident")) >= 1)
        only_a.pump(1.0)
        only_b.pump(0.5)
        site_c.pump(0.5)
        assert {e["data"]["probe"] for e in only_a.kinds("beat")} == {"probe-a1"}
        assert {e["data"]["probe"] for e in only_b.kinds("beat")} == {"probe-b1", "probe-c1"}
        assert {e["data"]["probe"] for e in site_c.kinds("beat")} == {"probe-c1"}
        assert [e["data"]["id"] for e in site_c.kinds("incident")] == [INC_A]
        assert only_a.kinds("incident") == []
    finally:
        for s in (only_a, only_b, site_c):
            s.close()


def test_keepalive_and_retry_are_sent(world, monkeypatch):
    wait_upstream(world)
    s = Sse(world, "/api/v1/stream?probes=probe-a1", world.as_user("vera"))
    try:
        assert s.wait(lambda: s.status == 200)
        assert "retry: 3000" in (s.buf.decode() + "") or s.events[0].get("retry") == "3000"
        monkeypatch.setattr(server, "SSE_KEEPALIVE_S", 0.5)
        assert s.wait(lambda: any(e.get("comment") == ": keepalive" for e in s.events), timeout=20)
    finally:
        s.close()


def test_resume_with_last_event_id_replays_missed_events(world):
    wait_upstream(world)
    v = world.as_user("vera")
    s1 = Sse(world, "/api/v1/stream?probes=probe-a1", v)
    assert s1.wait(lambda: s1.status == 200)
    beat(world, "col-a", "probe-a1", v=0)
    assert s1.wait(lambda: len(s1.kinds("beat")) == 1)
    last = s1.kinds("beat")[-1]["id"]
    s1.close()
    beat(world, "col-a", "probe-a1", v=1)
    beat(world, "col-a", "probe-a1", v=2)
    beat(world, "col-b", "probe-b1", v=2)                     # not subscribed: never replayed
    assert world.wait_for(lambda: len(world.app.hub._ring) >= 4, timeout=10)
    s2 = Sse(world, "/api/v1/stream?probes=probe-a1", v, last_event_id=last)
    try:
        assert s2.wait(lambda: len(s2.kinds("beat")) >= 2)
        s2.pump(0.5)
        assert [e["data"]["v"] for e in s2.kinds("beat")] == [1, 2]
        # a stale id from another boot is ignored (no replay, no error)
        s3 = Sse(world, "/api/v1/stream?probes=probe-a1", v, last_event_id="zzzz.1")
        s3.pump(1.0)
        assert s3.status == 200 and s3.kinds("beat") == []
        s3.close()
    finally:
        s2.close()


def test_replay_window_is_five_minutes(world):
    wait_upstream(world)
    hub = world.app.hub
    hub.publish("beat", "col-a", {"probe": "probe-a1", "line": "dns", "t": 1, "v": 0}, "probe-a1", "hall-a")
    first = hub._ring[-1].hub_id
    hub.publish("beat", "col-a", {"probe": "probe-a1", "line": "dns", "t": 2, "v": 1}, "probe-a1", "hall-a")
    old = hub._ring[-1]
    hub._ring[-1] = type(old)(old.seq, old.ts - 301, old.kind, old.probe, old.site, old.collector_id,
                              old.data, old.hub_id)
    s = Sse(world, "/api/v1/stream?probes=probe-a1", world.as_user("vera"), last_event_id=first)
    try:
        s.pump(1.0)
        assert s.status == 200 and s.kinds("beat") == []
    finally:
        s.close()


def test_upstream_reconnects_with_backoff_and_reports_collector_state(world):
    wait_upstream(world)
    v = world.as_user("vera")
    s = Sse(world, "/api/v1/stream?probes=probe-b1", v)
    assert s.wait(lambda: s.status == 200)
    f = world.fakes["col-b"]
    port = f.port
    f.stop()
    assert s.wait(lambda: any(e["data"] == {"collector_id": "col-b", "site": "hall-b", "ok": False}
                              for e in s.kinds("collector")), timeout=15)
    assert world.app.hub.upstream_up["col-b"] is False
    f.httpd = None
    f._want_port = port
    f.start()
    assert world.wait_for(lambda: world.app.hub.upstream_up["col-b"], timeout=20)       # reconnected
    assert s.wait(lambda: any(e["data"].get("ok") is True and e["data"]["collector_id"] == "col-b"
                              for e in s.kinds("collector")), timeout=10)
    beat(world, "col-b", "probe-b1", v=2)
    assert s.wait(lambda: len(s.kinds("beat")) >= 1, timeout=10)
    s.close()


def test_upstream_sends_last_event_id_on_reconnect(world, monkeypatch):
    wait_upstream(world)
    hub = world.app.hub
    beat(world, "col-b", "probe-b1")
    assert world.wait_for(lambda: hub._last_id.get("col-b") is not None, timeout=10)
    seen = []
    f = world.fakes["col-b"]
    from fake_collector import Handler
    real = Handler._h_stream

    def spy(self, q):
        seen.append(self.header("Last-Event-ID"))
        return real(self, q)
    monkeypatch.setattr(Handler, "_h_stream", spy)
    expected = hub._last_id["col-b"]
    port = f.port
    f.stop()
    # let the hub notice the drop before the fake restarts: restarting clears the fake's stop flag, and
    # an old stream handler that has not yet noticed it would otherwise stay connected (a test race)
    assert world.wait_for(lambda: hub.upstream_up["col-b"] is False, timeout=30)
    f.httpd = None
    f._want_port = port
    f.start()
    assert world.wait_for(lambda: seen and hub.upstream_up["col-b"], timeout=30)
    assert seen[0] == expected


def test_sse_closes_when_session_is_invalidated(world, monkeypatch):
    wait_upstream(world)
    monkeypatch.setattr(server, "SESSION_RECHECK_S", 0.5)
    alice = world.as_user("alice")
    s = Sse(world, "/api/v1/stream?probes=probe-a1", alice)
    assert s.wait(lambda: s.status == 200)
    t0 = time.time()
    world.write_creds(users=["vera"])
    assert s.wait(lambda: s.closed, timeout=30)
    assert time.time() - t0 < 30
    s.close()


def test_logout_closes_stream(world):
    wait_upstream(world)
    c = world.as_user("vera")
    s = Sse(world, "/api/v1/stream?probes=probe-a1", c)
    assert s.wait(lambda: s.status == 200)
    assert c.post("/auth/logout").status == 204
    assert s.wait(lambda: s.closed, timeout=15)
    s.close()


def test_slow_client_is_dropped_not_buffered_forever(world):
    wait_upstream(world)
    hub = world.app.hub
    from exp_dashboard.sse import CLIENT_QUEUE_MAX, Subscription
    sub = Subscription({"probe-a1"}, None, "h")
    hub.subscribe(sub, None)
    for i in range(CLIENT_QUEUE_MAX + 5):
        hub.publish("beat", "col-a", {"probe": "probe-a1", "line": "dns", "t": i, "v": 0}, "probe-a1", "hall-a")
    assert sub.dropped is True
    hub.unsubscribe(sub)


def test_invalid_upstream_events_are_ignored(world):
    wait_upstream(world)
    hub = world.app.hub
    c = world.app.settings.collectors[0]
    before = len(hub._ring)
    hub._on_upstream_event(c, "beat", "{not json", "1")
    hub._on_upstream_event(c, "beat", "[1,2]", "2")
    hub._on_upstream_event(c, "weird-kind", "{}", "3")
    assert len(hub._ring) == before


def test_dashboard_restart_mid_sse_browser_reconnects(world):
    """A unit restart (credential rotation) drops open streams; the session survives and a reconnect works."""
    wait_upstream(world)
    v = world.as_user("vera")
    s1 = Sse(world, "/api/v1/stream?probes=probe-a1", v)
    assert s1.wait(lambda: s1.status == 200)
    world.restart()
    s1.pump(1.0)
    assert s1.closed                                   # the server went away; EventSource would retry
    s1.close()
    wait_upstream(world)
    v.port = world.port
    assert v.whoami().status == 200                    # sessions live in the state dir, not in memory
    s2 = Sse(world, "/api/v1/stream?probes=probe-a1", v, last_event_id="stale.1")
    try:
        assert s2.wait(lambda: s2.status == 200)
        beat(world, "col-a", "probe-a1", v=7)
        assert s2.wait(lambda: len(s2.kinds("beat")) == 1)
    finally:
        s2.close()

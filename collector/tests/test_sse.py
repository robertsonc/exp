"""SSE hub (03-collector.md section 7): filters, event ids, 5-minute replay, keepalive, bounded queues,
slow clients disconnected, clients counted in health."""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest
from colhelpers import check_openapi, client_ctx, https, wait_for

from exp_collector import sse


# ---------------------------------------------------------------------------------- a tiny SSE client
class Sse:
    def __init__(self, port, token, query="probes=probe-a1", last_id=None, timeout=5.0):
        raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.s = client_ctx().wrap_socket(raw, server_hostname="localhost")
        self.s.settimeout(timeout)
        hdr = f"GET /api/v1/stream?{query} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\nAccept: text/event-stream\r\n"
        if last_id:
            hdr += f"Last-Event-ID: {last_id}\r\n"
        self.s.sendall((hdr + "\r\n").encode())
        self.buf = b""
        head = self._until(b"\r\n\r\n")
        self.status = int(head.split(b" ", 2)[1])
        self.head = head.decode("latin-1")

    def _until(self, marker: bytes) -> bytes:
        while marker not in self.buf:
            chunk = self.s.recv(65536)
            if not chunk:
                raise EOFError("closed")
            self.buf += chunk
        out, _, self.buf = self.buf.partition(marker)
        return out

    def block(self) -> str:
        """The next blank-line-terminated block (an event, a comment or the retry line)."""
        return self._until(b"\n\n").decode()

    def event(self, skip_comments=True):
        while True:
            b = self.block()
            if skip_comments and (b.startswith(":") or b.startswith("retry:")):
                continue
            ev = {}
            for line in b.split("\n"):
                k, _, v = line.partition(": ")
                ev[k] = v
            if "data" in ev:
                ev["json"] = json.loads(ev["data"])
            return ev

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------------------- hub (unit)
def beat(probe, t, line="network", v=0):
    return {"probe": probe, "line": line, "t": t, "v": v}


def test_hub_filters_by_probe_and_by_site():
    sites = {"p1": "s1", "p2": "s1", "p3": "s2"}
    hub = sse.Hub(site_of=sites.get)
    a, b, c = hub.subscribe(["p1"], None), hub.subscribe(None, "s1"), hub.subscribe(["p3", "p2"], None)
    for p in ("p1", "p2", "p3"):
        hub.publish("beat", beat(p, 1))
    hub.publish("state", {"probe": "p3", "site": "s2", "severity": "ok", "headline": "h", "lines": []})
    got = lambda cl: [(e.kind, e.probe) for e in iter(lambda: hub.next_event(cl, 0.01), None) if e != "closed"]  # noqa: E731
    assert got(a) == [("beat", "p1")]
    assert got(b) == [("beat", "p1"), ("beat", "p2")]
    assert got(c) == [("beat", "p2"), ("beat", "p3"), ("state", "p3")]
    assert hub.client_count() == 3


def test_hub_ignores_unknown_kinds_and_payloads_without_a_probe():
    hub = sse.Hub()
    c = hub.subscribe(["p1"], None)
    hub.publish("nope", {"probe": "p1"})
    hub.publish("beat", {"line": "x"})
    hub.publish("beat", {"probe": 5})
    assert hub.next_event(c, 0.01) is None and hub.ring_len() == 0


def test_event_ids_increase_and_wire_format():
    hub = sse.Hub()
    c = hub.subscribe(["p1"], None)
    hub.publish("beat", beat("p1", 5, v=2))
    hub.publish("beat", beat("p1", 6))
    e1, e2 = hub.next_event(c, 1), hub.next_event(c, 1)
    assert e1.seq + 1 == e2.seq and e1.id != e2.id and e1.id.startswith(hub.boot + ".")
    assert e1.wire() == f'id: {e1.id}\nevent: beat\ndata: {{"probe":"p1","line":"network","t":5,"v":2}}\n\n'.encode()


def test_replay_returns_only_newer_events_for_the_clients_filter():
    hub = sse.Hub(site_of={"p1": "s", "p2": "s"}.get)
    c0 = hub.subscribe(None, "s")
    for i in range(6):
        hub.publish("beat", beat("p1" if i % 2 else "p2", i))
    evs = [hub.next_event(c0, 0.1) for _ in range(6)]
    resumed = hub.subscribe(["p1"], None, evs[2].id)
    replay = [hub.next_event(resumed, 0.01) for _ in range(2)]
    assert [json.loads(e.data)["t"] for e in replay] == [3, 5]
    assert hub.next_event(resumed, 0.01) is None
    hub.publish("beat", beat("p1", 99))                      # live events follow the replay without a gap
    assert json.loads(hub.next_event(resumed, 1).data)["t"] == 99


def test_replay_is_limited_to_five_minutes_and_foreign_ids_replay_nothing():
    now = [1_000_000.0]
    hub = sse.Hub(clock=lambda: now[0])
    c0 = hub.subscribe(["p1"], None)
    hub.publish("beat", beat("p1", 1))
    first = hub.next_event(c0, 0.1)
    now[0] += 200
    hub.publish("beat", beat("p1", 2))
    now[0] += 150                                            # the first is now 350 s old, the second 150 s
    hub.publish("beat", beat("p1", 3))
    r = hub.subscribe(["p1"], None, f"{hub.boot}.0")
    assert [json.loads(e.data)["t"] for e in r.backlog] == [2, 3]            # t=1 fell out of the 5-minute window
    assert hub.subscribe(["p1"], None, "deadbeef.1").backlog == []           # an id from before a restart
    assert hub.subscribe(["p1"], None, "garbage").backlog == []
    assert hub.subscribe(["p1"], None, first.id).backlog[0].seq == first.seq + 1
    assert hub.ring_len() == 2


def test_a_client_that_falls_behind_is_disconnected_and_the_producer_never_blocks():
    hub = sse.Hub(queue_max=5)
    slow, fast = hub.subscribe(["p1"], None), hub.subscribe(["p1"], None)
    t0 = time.monotonic()
    for i in range(8):
        hub.publish("beat", beat("p1", i))
        if i < 5:
            hub.next_event(fast, 0.01)                       # the fast client keeps up
    while hub.next_event(fast, 0.01) not in (None, "closed"):
        pass
    for i in range(8, 20):
        hub.publish("beat", beat("p1", i))
        hub.next_event(fast, 0.01)
    assert time.monotonic() - t0 < 1.0
    assert slow.closed and "too slow" in slow.reason and hub.dropped_clients == 1
    assert hub.next_event(slow, 0.5) == "closed"
    assert not fast.closed and hub.client_count() == 1


def test_default_queue_bound_is_1000_and_max_clients_enforced():
    assert sse.QUEUE_MAX == 1000 and sse.KEEPALIVE_S == 15 and sse.RETRY_MS == 3000 and sse.RING_SECONDS == 300
    hub = sse.Hub(max_clients=2)
    hub.subscribe(["p"], None), hub.subscribe(["p"], None)
    with pytest.raises(sse.TooManyClients):
        hub.subscribe(["p"], None)
    c = sse.Hub().subscribe(["p"], None)
    assert c.q.maxsize == 1000


def test_close_wakes_every_client():
    hub = sse.Hub()
    cs = [hub.subscribe(["p"], None) for _ in range(3)]
    threading.Timer(0.1, hub.close).start()
    assert [hub.next_event(c, 3) for c in cs] == ["closed"] * 3
    with pytest.raises(sse.TooManyClients):
        hub.subscribe(["p"], None)


# ------------------------------------------------------------------------------------ over HTTPS
def pub(app, probe="probe-a1", t=1, v=0):
    app.hub.publish("beat", beat(probe, t, v=v))


def test_stream_headers_retry_and_events(env, app, port):
    c = Sse(port, env.dash_token)
    assert c.status == 200
    low = c.head.lower()
    assert "content-type: text/event-stream" in low and "cache-control: no-store" in low
    assert c.block() == "retry: 3000"
    assert wait_for(lambda: app.hub.client_count() == 1)
    pub(app, t=11, v=2)
    pub(app, "probe-a2", t=12)                               # not subscribed: never delivered
    pub(app, t=13)
    e = c.event()
    assert e["event"] == "beat" and e["json"] == {"probe": "probe-a1", "line": "network", "t": 11, "v": 2}
    check_openapi_event(e["json"], "BeatEvent")
    assert e["id"].startswith(app.hub.boot + ".")
    assert c.event()["json"]["t"] == 13
    c.close()


def check_openapi_event(doc, name):
    from colhelpers import REGISTRY
    from jsonschema import Draft202012Validator
    v = Draft202012Validator({"$ref": f"collector.yaml#/components/schemas/{name}"}, registry=REGISTRY)
    assert not list(v.iter_errors(doc))


def test_stream_keepalive_comment(env, app, port):
    app.hub.keepalive_s = 0.4
    c = Sse(port, env.dash_token)
    assert c.block() == "retry: 3000"
    t0 = time.monotonic()
    assert c.block() == ": keepalive"
    assert time.monotonic() - t0 < 3
    assert c.block() == ": keepalive"
    c.close()


def test_default_keepalive_interval_is_15_seconds(app):
    assert app.hub.keepalive_s == 15


def test_stream_resumes_with_last_event_id_and_only_what_was_missed(env, app, port):
    c = Sse(port, env.dash_token)
    c.block()
    assert wait_for(lambda: app.hub.client_count() == 1)
    for t in (1, 2, 3):
        pub(app, t=t)
    seen = [c.event() for _ in range(3)]
    c.close()
    assert wait_for(lambda: app.hub.client_count() == 0)       # disconnects are noticed and counted out
    for t in (4, 5):
        pub(app, t=t)                                          # missed while away
    r = Sse(port, env.dash_token, last_id=seen[1]["id"])       # the last it processed was t=2
    assert r.block() == "retry: 3000"
    assert [r.event()["json"]["t"] for _ in range(3)] == [3, 4, 5]
    pub(app, t=6)
    assert r.event()["json"]["t"] == 6
    r.close()


def test_stream_filter_by_site_and_validation(env, app, port):
    c = Sse(port, env.dash_token, query="site=hall-b")
    c.block()
    assert wait_for(lambda: app.hub.client_count() == 1)
    pub(app, "probe-c1", t=1)
    pub(app, "probe-a2", t=2)
    assert c.event()["json"]["probe"] == "probe-a2"
    c.close()
    auth = {"Authorization": f"Bearer {env.dash_token}"}
    for q in ("", "probes=probe-a1&site=hall-b", "probes=nobody", "probes=BAD", "site=nowhere", "site=A B".replace(" ", "%20"),
              "probes=" + ",".join(["probe-a1"] * 65)):
        r = https(port, "GET", "/api/v1/stream?" + q, headers=auth)
        assert r.status == 400, q
        check_openapi("collector", "/stream", "get", 400, r.json())
    assert https(port, "GET", "/api/v1/stream?probes=probe-a1", headers={"Last-Event-ID": "x"}).status == 401
    assert https(port, "GET", "/api/v1/stream?probes=probe-a1",
                 headers={**auth, "Last-Event-ID": "x" * 200}).status == 400


def test_stream_needs_a_dashboard_token(env, port):
    r = https(port, "GET", "/api/v1/stream?probes=probe-a1", headers={"Authorization": f"Bearer {env.ingest_token}"})
    assert r.status == 401
    check_openapi("collector", "/stream", "get", 401, r.json())


def test_sse_clients_are_counted_in_health_and_telemetry(env, app, port, vm):
    cs = [Sse(port, env.dash_token) for _ in range(3)]
    for c in cs:
        c.block()
    assert wait_for(lambda: app.hub.client_count() == 3)
    assert app.monitor.collect()["sse_clients"] == 3
    app.telemetry.emit_once()
    app.vm.flush_now()
    assert wait_for(lambda: any(ln["metric"]["__name__"] == "exp_collector_sse_clients" and ln["values"] == [3.0]
                                for ln in list(vm.lines)))
    cs[0].close()
    cs[1].close()
    assert wait_for(lambda: app.hub.client_count() == 1)
    assert app.monitor.collect()["sse_clients"] == 1
    cs[2].close()


def test_slow_client_over_the_wire_is_disconnected(env, app, port):
    """A client that never reads: the kernel buffers fill, the handler stalls, the bounded queue overflows and
    the hub drops the client -- while a healthy client on the same stream is unaffected."""
    app.hub.queue_max = 5
    app.hub.max_clients = 10
    slow = Sse(port, env.dash_token)
    good = Sse(port, env.dash_token)
    slow.block()
    good.block()
    assert wait_for(lambda: app.hub.client_count() == 2)
    pad = "x" * 60_000
    got = []
    for i in range(400):
        app.hub.publish("beat", {"probe": "probe-a1", "line": "network", "t": i, "v": 0, "pad": pad})
        got.append(good.event()["json"]["t"])                  # the good client keeps reading
        if app.hub.dropped_clients:
            break
    assert app.hub.dropped_clients == 1 and got == list(range(len(got)))
    assert wait_for(lambda: app.hub.client_count() == 1)
    slow.close()
    good.close()


def test_open_streams_are_released_on_shutdown(env, app, port):
    c = Sse(port, env.dash_token)
    c.block()
    assert wait_for(lambda: app.hub.client_count() == 1)
    t0 = time.monotonic()
    env.stop_all()
    assert time.monotonic() - t0 < 10
    c.s.settimeout(5)
    with pytest.raises((EOFError, OSError)):
        while True:
            c.block()

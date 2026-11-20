"""GET speedtests/stream: new tests, evidence and diagnosis updates over SSE (12 section 7.4)."""
from __future__ import annotations

import socket
import time

from colhelpers import client_ctx, wait_for
from sthelpers import evidence, result, wifi


class Stream:
    def __init__(self, port, token, query="", last_id=None, timeout=6.0):
        raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.s = client_ctx().wrap_socket(raw, server_hostname="localhost")
        self.s.settimeout(timeout)
        hdr = (f"GET /api/v1/speedtests/stream{query} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n"
               "Accept: text/event-stream\r\n")
        if last_id:
            hdr += f"Last-Event-ID: {last_id}\r\n"
        self.s.sendall((hdr + "\r\n").encode())
        self.buf = b""
        head = self._until(b"\r\n\r\n")
        self.status = int(head.split(b" ", 2)[1])
        self.head = head.decode("latin-1")

    def _until(self, marker):
        while marker not in self.buf:
            chunk = self.s.recv(65536)
            if not chunk:
                raise EOFError("closed")
            self.buf += chunk
        out, _, self.buf = self.buf.partition(marker)
        return out

    def block(self):
        return self._until(b"\n\n").decode()

    def event(self):
        import json
        while True:
            b = self.block()
            if b.startswith(":") or b.startswith("retry:"):
                continue
            ev = {}
            for line in b.split("\n"):
                k, _, v = line.partition(": ")
                ev[k] = v
            ev["json"] = json.loads(ev["data"])
            return ev

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def test_stream_carries_tests_evidence_and_diagnoses(st):
    s = Stream(st.port, st.tokens["expd"])
    try:
        assert s.status == 200 and "text/event-stream" in s.head and "no-store" in s.head
        assert s.block() == "retry: 3000"
        assert wait_for(lambda: st.app.speedtests.hub.client_count() == 1)
        t = result(down=150.0)
        st.ingest(t)
        e1, e2 = s.event(), s.event()
        assert e1["event"] == "speedtest" and e1["json"]["id"] == t["id"] and e1["json"]["site"] == "hall-b"
        assert e2["event"] == "diagnosis" and e2["json"] == {"id": t["id"], "stage": "quick", "cause": "unknown"}
        st.put_ev(wifi(t))
        e3 = s.event()
        assert e3["event"] == "evidence" and e3["json"] == {"id": t["id"], "kind": "wifi"}
        st.complete(t["id"], ["wifi"])
        e4 = s.event()
        assert e4["event"] == "diagnosis" and e4["json"]["stage"] == "final" and e4["json"]["cause"] == "wifi_congestion"
        assert e1["id"] != e4["id"] and "." in e1["id"]
        raw = "".join(str(e) for e in (e1, e2, e3, e4))
        for secret in ("10.60.14.77", "f0:18:98", "alices"):
            assert secret not in raw
    finally:
        s.close()


def test_stream_replays_from_last_event_id_within_the_window(st):
    t1 = result()
    st.ingest(t1)
    s = Stream(st.port, st.tokens["expd"])
    try:
        s.block()
        t2 = result()
        st.ingest(t2)
        first = s.event()
        assert first["json"]["id"] == t2["id"]
        s.event()                                                       # t2's quick diagnosis
        last_id = first["id"]
    finally:
        s.close()
    r = Stream(st.port, st.tokens["expd"], last_id=last_id)
    try:
        r.block()
        ev = r.event()
        assert ev["event"] == "diagnosis" and ev["json"]["id"] == t2["id"]   # everything after the given id, no more
    finally:
        r.close()
    foreign = Stream(st.port, st.tokens["expd"], last_id="deadbeef.1")       # an id from another boot: no replay
    try:
        foreign.block()
        foreign.s.settimeout(0.5)
        try:
            foreign.block()
            raise AssertionError("nothing should be replayed")
        except TimeoutError:
            pass
    finally:
        foreign.close()


def test_stream_site_filter_and_keepalive(st):
    st.app.speedtests.hub.keepalive_s = 0.3
    s = Stream(st.port, st.tokens["expd"], query="?site=hall-c")
    try:
        s.block()
        st.ingest(result())                                              # hall-b: filtered out
        assert s.block() == ": keepalive"
    finally:
        s.close()
    s2 = Stream(st.port, st.tokens["expd"], query="?site=hall-b")
    try:
        s2.block()
        t = result()
        st.ingest(t)
        assert s2.event()["json"]["id"] == t["id"]
    finally:
        s2.close()


def test_stream_validation_and_cleanup(st):
    for q in ("?site=Bad_Site", "?site=a&site=b"):
        s = Stream(st.port, st.tokens["expd"], query=q)
        assert s.status == 400
        s.close()
    s = Stream(st.port, st.tokens["expd"], last_id="x" * 200)
    assert s.status == 400
    s.close()
    ok = Stream(st.port, st.tokens["expd"])
    assert wait_for(lambda: st.app.speedtests.hub.client_count() == 1)
    ok.close()
    assert wait_for(lambda: st.app.speedtests.hub.client_count() == 0, timeout=8)
    assert time.time() > 0 and evidence is not None


def test_slow_client_is_dropped_and_the_producer_never_blocks():
    from exp_collector.speedtest.stream import StHub
    hub = StHub(queue_max=3)
    c = hub.subscribe(None, None)
    other = hub.subscribe(None, None)
    t0 = time.monotonic()
    for i in range(10):
        hub.publish("speedtest", "hall-b", {"id": f"st_{i}"})
        while other.q.qsize():                                          # a healthy client keeps up
            hub.next_event(other, 0.01)
    assert time.monotonic() - t0 < 1.0 and hub.dropped_clients == 1 and c.closed and not other.closed
    assert hub.next_event(c, 0.1) == "closed"
    hub.close()
    assert hub.next_event(other, 0.1) == "closed"
    hub.publish("speedtest", "hall-b", {"id": "after-close"})            # publishing after close is a no-op


def test_unknown_event_kinds_are_ignored():
    from exp_collector.speedtest.stream import StHub
    hub = StHub()
    c = hub.subscribe(None, None)
    hub.publish("beat", "hall-b", {"x": 1})
    assert hub.next_event(c, 0.05) is None

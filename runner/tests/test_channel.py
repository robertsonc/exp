"""The localhost channel to the speedtest: where-cache answers and the auto-pause publisher."""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from exp_common import ids as exp_ids
from rthelpers import make_cfg, secret

from exp_runner.channel import ChannelError, PausePublisher, SpeedtestChannel, WhereLoop
from exp_runner.connectors import ClientCandidate, ClientLookup, IdentityProvider
from exp_runner.identity import IdentityResolver
from exp_runner.ring import Ring

TOKEN = exp_ids.new_token("expl")


class StubSpeedtest(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), H)
        self.wanted = []
        self.where = []
        self.pause = []
        self.status = 200
        threading.Thread(target=self.serve_forever, daemon=True).start()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _reply(self, code, doc):
        b = json.dumps(doc).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _auth(self):
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self._reply(401, {"error": {"code": "unauthorized", "message": "x"}})
            return False
        if self.server.status != 200:
            self._reply(self.server.status, {})
            return False
        return True

    def do_GET(self):
        if self._auth() and self.path == "/local/v1/where/wanted":
            self._reply(200, {"items": [{"ip": i, "since": "2026-11-18T14:00:00.000Z"} for i in self.server.wanted]})

    def do_PUT(self):
        if not self._auth():
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        (self.server.where if self.path == "/local/v1/where" else self.server.pause).append(body)
        self._reply(200, {"ok": True})


@pytest.fixture()
def stub():
    s = StubSpeedtest()
    yield s
    s.shutdown()
    s.server_close()


def chan(stub, token=TOKEN):
    return SpeedtestChannel(f"http://127.0.0.1:{stub.server_address[1]}/local/v1", token)


class Prov(IdentityProvider):
    def lookup_client(self, ip, window, budget):
        return ClientLookup("ok", [ClientCandidate(mac="f0:18:98:aa:bb:01", username="alice", ap_name="hallb-ap-3", ssid="Summit", band="5")])


def test_channel_must_be_loopback_http():
    for bad in ("http://10.0.0.5:8480/local/v1", "https://127.0.0.1:8480/local/v1", "http://localhost:8480/local/v1", "http://127.0.0.1/local/v1"):
        with pytest.raises(ValueError):
            SpeedtestChannel(bad, TOKEN)


def test_where_loop_answers_wanted_ips_without_leaking_identity(stub, tmp_path):
    ring = Ring(tmp_path / "s.db").open()
    try:
        res = IdentityResolver(make_cfg(mist=True), ring, secret(), Prov())
        loop = WhereLoop(chan(stub), lambda ip, now: res.resolve(*_ref(ip, now)), time.time)
        stub.wanted = ["10.60.14.77", "10.0.0.2", "192.168.9.9"]
        assert loop.poll_once() == 3
        items = {i["ip"]: i for i in stub.where[0]["items"]}
        ok, nat, outside = items["10.60.14.77"], items["10.0.0.2"], items["192.168.9.9"]
        assert (ok["zone_source"], ok["ap_name"], ok["ssid"], ok["nat_suspected"]) == ("mist", "hallb-ap-3", "Summit", False)
        assert ok["zone"] == "hall-b"
        assert nat["nat_suspected"] and nat["zone"] == "unresolved" and nat["zone_source"] == "unresolved"
        assert outside["nat_suspected"] and outside["zone"] == "unresolved"
        blob = json.dumps(stub.where)
        assert "f0:18:98" not in blob and "alice" not in blob and "mac" not in blob and "username" not in blob
    finally:
        ring.close()


def _ref(ip, now):
    from exp_runner import evidence as ev
    from exp_runner.connectors import SpeedtestRef, Window
    w = Window(now - 300, now, ev._fmt(now - 300), ev._fmt(now))
    return SpeedtestRef("", "hall-b", now, now, ip, w), w


def test_where_loop_survives_channel_failures(stub, caplog):
    c = chan(stub)
    stub.status = 500
    loop = WhereLoop(c, lambda ip, now: (_ for _ in ()).throw(AssertionError("not reached")), time.time)
    assert loop.poll_once() == 0 and c.errors >= 1
    stub.status = 200
    stub.wanted = []
    assert loop.poll_once() == 0


def test_wrong_channel_token_is_an_error(stub):
    with pytest.raises(ChannelError):
        chan(stub, exp_ids.new_token("expl")).wanted()


def test_unreachable_speedtest_is_contained():
    c = SpeedtestChannel("http://127.0.0.1:1/local/v1", TOKEN, timeout=0.5)
    with pytest.raises(ChannelError):
        c.wanted()
    loop = WhereLoop(c, lambda ip, now: None, time.time)
    assert loop.poll_once() == 0


def test_pause_publisher_publishes_ec_utilization_and_stays_quiet_without_a_value(stub):
    p = PausePublisher(chan(stub), now_fn=lambda: 1_795_000_000.0)
    assert p.publish_once() is False and stub.pause == []                 # no source registered (r2 wires EC)
    p.set_source(lambda: None)
    assert p.publish_once() is False and stub.pause == []                 # nothing to say: the speedtest fails open
    p.set_source(lambda: 91.5)
    assert p.publish_once() is True
    assert stub.pause[0]["wan_util_pct"] == 91.5 and stub.pause[0]["measured_at"] == "2026-11-18T11:06:40.000Z"
    assert stub.pause[0]["source"] == "ec" and stub.pause[0]["measured_at"].endswith("Z")
    p.set_source(lambda: 5000.0)
    p.publish_once()
    assert stub.pause[-1]["wan_util_pct"] == 1000.0                       # clamped to the contract range
    p.set_source(lambda: (_ for _ in ()).throw(RuntimeError("ec down")))
    assert p.publish_once() is False


"""Shipper against test/fakes/fake_collector.py over real pinned TLS, plus transport-level stubs for the
status table of 01-contracts.md section 4."""
from __future__ import annotations

import gzip
import json
import logging
import os
import shutil

import fake_collector
import fakes_common
import pytest
from conftest import make_config
from exp_common import tlspin
from exp_common.ids import new_ulid
from exp_common.schema import utcnow

from exp_probe import shipper as sh
from exp_probe.config import Collector
from exp_probe.selftel import build_measurement
from exp_probe.shipper import Shipper
from exp_probe.spool import Spool

TOKEN = fakes_common.fixture_token("expi", "probe-a1")
CFG = make_config(probe_id="probe-a1", site="hall-b")


def add(spool: Spool, n: int, probe_cfg=CFG) -> list[str]:
    ids = []
    for _ in range(n):
        m = build_measurement(probe_cfg, "gateway", "ok", metrics={"rtt_ms": 1.5}, labels={"port": "c01", "iface": "t0"})
        spool.add(m.to_dict())
        ids.append(m.id)
    return ids


@pytest.fixture
def spool(tmp_path):
    s = Spool(tmp_path / "spool.db")
    yield s
    s.close()


@pytest.fixture
def server(tmp_path):
    srv = fake_collector.start(tls=True, state_dir=tmp_path / "col")
    yield srv
    srv.stop()


def mk(server_, spool_, clock, token=TOKEN, fingerprint=None, fallback=(), **kw):
    col = Collector(f"https://127.0.0.1:{server_.port}", fingerprint or server_.fingerprint, tuple(fallback))
    return Shipper(col, spool_, lambda: token, clock=clock, rng=kw.pop("rng", lambda: 1.0), **kw)


def drain(shipper, spool_, clock, limit=200):
    for _ in range(limit):
        if spool_.stat()["depth"] == 0:
            return
        d = shipper.step()
        clock.advance(max(d, 0.0))
    raise AssertionError("spool did not drain")


def stored_ids(server_):
    return [r["id"] for r in server_.app.records if r.get("test") == "gateway"]


def test_accepted_lines_are_deleted_oldest_first(server, spool, clock):
    ids = add(spool, 1200)
    s = mk(server, spool, clock)
    assert s.step() == 0.0                                      # more to send: go again immediately
    assert spool.stat()["depth"] == 700                        # first batch was the 500 OLDEST
    drain(s, spool, clock)
    assert stored_ids(server) == ids                           # every record once, in order
    assert s.state in (sh.S_OK, sh.S_IDLE) and s.collector_reachable and s.shipped_total == 1200
    assert s.step() <= sh.IDLE_POLL_S                          # nothing left: idle poll


def test_request_shape(server, spool, clock):
    add(spool, 3)
    seen = {}

    def spy(method, url, pins, **kw):
        seen.update(method=method, url=url, pins=pins, **kw)
        return tlspin.request(method, url, pins, **kw)
    s = mk(server, spool, clock, request=spy)
    s.step()
    h = seen["headers"]
    assert seen["method"] == "POST" and seen["url"].endswith("/ingest/v1/measurements")
    assert h["Authorization"] == f"Bearer {TOKEN}" and h["Content-Type"] == "application/x-ndjson"
    assert h["Content-Encoding"] == "gzip" and h["User-Agent"].startswith("exp-probe/")
    assert seen["pins"] == server.fingerprint and seen["connect_timeout"] > 0 and seen["total_timeout"] > 0
    assert len(gzip.decompress(seen["body"]).splitlines()) == 3


def test_duplicates_and_rejected_lines_are_deleted_too(server, spool, clock):
    ids = add(spool, 4)
    s = mk(server, spool, clock)
    s.step()
    assert spool.stat()["depth"] == 0
    for i in ids[:2]:                                           # same ids again -> duplicates
        spool.add({**json.loads(_body_of(server, i)), "id": i})
    other = make_config(probe_id="probe-zz")                      # identity mismatch -> rejected per line
    bad = add(spool, 1, other)
    s.step()
    assert spool.stat()["depth"] == 0                          # accepted + duplicate + rejected all removed
    assert s.rejected_total == 1 and bad[0] not in stored_ids(server)
    assert len(stored_ids(server)) == 4


def _body_of(server_, rid):
    return json.dumps(next(r for r in server_.app.records if r["id"] == rid))


def test_401_stops_pushing_and_retries_every_60s(server, spool, clock):
    add(spool, 3)
    wrong = fakes_common.fixture_token("expi", "someone-else")
    s = mk(server, spool, clock, token=wrong)
    wait = s.step()
    assert s.state == sh.S_AUTH and wait == sh.AUTH_RETRY_S and s.collector_reachable is True
    assert spool.stat()["depth"] == 3                          # nothing deleted
    n = server.app.requests
    clock.advance(30)
    assert 29 < s.step() <= 30 and server.app.requests == n    # not pushing during the 60 s hold
    clock.advance(31)
    s.step()
    assert server.app.requests == n + 1 and s.state == sh.S_AUTH
    s.token_provider = lambda: TOKEN                            # operator rotated the credential
    clock.advance(61)
    s.step()
    assert s.state in (sh.S_OK, sh.S_IDLE) and spool.stat()["depth"] == 0


@pytest.mark.parametrize("token", ["", "garbage", "expa_" + "A" * 43])
def test_bad_token_never_leaves_the_probe(server, spool, clock, token):
    add(spool, 2)
    s = mk(server, spool, clock, token=token)
    s.step()
    assert s.state == sh.S_AUTH and server.app.requests == 0


def test_429_waits_retry_after(server, spool, clock):
    add(spool, 5)
    server.app.set_force(429, retry_after=7, count=1)
    s = mk(server, spool, clock)
    assert s.step() == 7 and s.state == sh.S_THROTTLED and spool.stat()["depth"] == 5
    clock.advance(3)
    assert s.step() == 4                                         # still waiting, no request
    clock.advance(4)
    s.step()
    assert spool.stat()["depth"] == 0


@pytest.mark.parametrize("raw,expected", [("7", 7.0), ("0", 1.0), ("-3", 5.0), ("x", 5.0), ("99999", 300.0), (None, 5.0)])
def test_retry_after_parsing(raw, expected):
    assert sh.parse_retry_after(raw) == expected


def test_503_backoff_doubles_with_full_jitter_and_resets(server, spool, clock):
    add(spool, 3)
    server.app.set_force(503, retry_after=1, count=8)
    s = mk(server, spool, clock, rng=lambda: 1.0)                 # rng=1.0 -> the cap itself
    delays = []
    for _ in range(7):
        delays.append(s.step())
        clock.advance(delays[-1])
    assert delays == [1, 2, 4, 8, 16, 32, 60]
    assert s.state == sh.S_ERROR and spool.stat()["depth"] == 3
    server.app.set_force(None)
    s.step()
    assert spool.stat()["depth"] == 0 and s.fail_count == 0
    # full jitter: the wait is uniform in [0, cap]
    add(spool, 1)
    server.app.set_force(503, count=1)
    s2 = mk(server, spool, clock, rng=lambda: 0.25)
    assert s2.step() == 0.25


def test_network_failure_backs_off_and_marks_unreachable(spool, clock, tmp_path):
    add(spool, 2)
    srv = fake_collector.start(tls=True, state_dir=tmp_path / "c")
    s = mk(srv, spool, clock)
    srv.stop()
    d = s.step()
    assert s.state == sh.S_DOWN and s.collector_reachable is False and 0 < d <= 1 and spool.stat()["depth"] == 2


def test_pin_mismatch_sends_nothing(server, spool, clock):
    add(spool, 3)
    wrong = "AA:" * 31 + "AA"
    s = mk(server, spool, clock, fingerprint=wrong)
    d = s.step()
    assert s.state == sh.S_PIN and "does not match the pin" in s.detail and s.collector_reachable is False
    assert server.app.requests == 0                            # the server saw NO request at all
    assert spool.stat()["depth"] == 3 and d > 0
    for _ in range(5):                                          # and it never falls back to unpinned
        clock.advance(61)
        s.step()
    assert server.app.requests == 0


def test_no_collector_configured_keeps_spooling(spool, clock):
    add(spool, 2)
    s = Shipper(None, spool, lambda: TOKEN, clock=clock)
    assert s.step() > 0 and s.state == sh.S_NO_COLLECTOR and spool.stat()["depth"] == 2


# ----------------------------------------------------------- transport stubs for split/limits

class Stub:
    def __init__(self, handler):
        self.handler = handler
        self.calls: list[list[str]] = []
        self.delivered: list[str] = []

    def __call__(self, method, url, pins, *, body=None, headers=None, **kw):
        lines = gzip.decompress(body).decode().splitlines()
        self.calls.append(lines)
        status, extra = self.handler(lines)
        if status == 200:
            self.delivered += [json.loads(x)["id"] for x in lines]
            doc = {"accepted": len(lines), "duplicates": 0, "rejected": [], "server_time": utcnow()}
            return tlspin.Response(200, "OK", {}, json.dumps(extra or doc).encode())
        return tlspin.Response(status, "x", {}, json.dumps({"error": {"code": "too_big", "message": "m"}}).encode())


def stub_shipper(spool, clock, handler):
    st = Stub(handler)
    col = Collector("https://127.0.0.1:9", "AA:" * 31 + "AA")
    return Shipper(col, spool, lambda: TOKEN, clock=clock, request=st), st


@pytest.mark.parametrize("status", [413, 400])
def test_oversized_batch_is_split_until_it_fits(spool, clock, status):
    ids = add(spool, 500)
    s, st = stub_shipper(spool, clock, lambda lines: (status, None) if len(lines) > 100 else (200, None))
    s.step()
    assert spool.stat()["depth"] == 0
    assert st.delivered == ids                                  # still oldest-first and complete
    assert max(len(c) for c in st.calls if len(c) <= 100) <= 100 and len(st.calls[0]) == 500


def test_single_poison_line_is_dropped_after_split(spool, clock):
    ids = add(spool, 8)
    poison = ids[3]
    s, st = stub_shipper(spool, clock, lambda lines: (400, None) if any(poison in x for x in lines) else (200, None))
    s.step()
    assert spool.stat()["depth"] == 0 and s.poison_total == 1
    assert st.delivered == [i for i in ids if i != poison]


def test_200_with_inconsistent_counts_keeps_the_batch(spool, clock):
    add(spool, 4)
    s, st = stub_shipper(spool, clock, lambda lines: (200, {"accepted": 1, "duplicates": 0, "rejected": [],
                                                              "server_time": utcnow()}))
    s.step()
    assert spool.stat()["depth"] == 4 and s.state == sh.S_ERROR


def test_batch_limits_500_records_and_1mib_gzip():
    recs = [(new_ulid(), os.urandom(4000).hex().encode()) for _ in range(700)]
    batch, body = sh.build_batch(recs)
    assert len(batch) <= 500 and len(body) <= sh.MAX_GZIP_BYTES and batch == recs[:len(batch)]
    assert len(batch) < 500                                     # 500 x 8 KB of hex does not fit 1 MiB gzipped
    assert len(gzip.decompress(body).splitlines()) == len(batch)


# --------------------------------------------------------------------------- outage and fallback

def test_collector_killed_five_minutes_every_record_arrives_once_in_order(spool, clock, tmp_path):
    sd = tmp_path / "col"
    srv = fake_collector.start(tls=True, state_dir=sd)
    port, fp = srv.port, srv.fingerprint
    s = mk(srv, spool, clock)
    sent = add(spool, 300)
    drain(s, spool, clock)
    assert stored_ids(srv) == sent
    srv.stop()                                                  # the collector is killed ...
    for _ in range(30):                                         # ... for 5 minutes of 10-s beats
        sent += add(spool, 5)
        s.step()
        clock.advance(10)
    assert spool.stat()["depth"] == 150 and s.state == sh.S_DOWN
    srv2 = fake_collector.start(tls=True, state_dir=sd, port=port)
    try:
        assert srv2.fingerprint == fp                           # same certificate, so the pin still holds
        sent += add(spool, 5)
        for _ in range(100):
            if spool.stat()["depth"] == 0:
                break
            clock.advance(max(s.step(), 0.0))
        assert spool.stat()["depth"] == 0
        got = stored_ids(srv2)
        assert got == sent and len(set(got)) == len(got) == 455    # exactly once, in order
    finally:
        srv2.stop()


def test_fallback_after_60s_unreachable_then_back_to_primary(spool, clock, tmp_path):
    a_dir, b_dir = tmp_path / "a", tmp_path / "b"
    a = fake_collector.start(tls=True, state_dir=a_dir)
    (b_dir).mkdir()
    shutil.copytree(a_dir / "tls", b_dir / "tls")               # same pin on the fallback
    b = fake_collector.start(tls=True, state_dir=b_dir)
    port_a = a.port
    s = mk(a, spool, clock, fallback=[f"https://127.0.0.1:{b.port}"])
    a.stop()
    try:
        ids = add(spool, 3)
        for _ in range(3):                                      # < 60 s: still only the primary is tried
            s.step()
            clock.advance(10)
        assert b.app.requests == 0 and spool.stat()["depth"] == 3
        clock.advance(60)
        s.step()                                                # primary failed again -> now the fallback
        clock.advance(61)
        for _ in range(5):
            s.step()
            clock.advance(5)
        assert stored_ids(b) == ids and spool.stat()["depth"] == 0
        a2 = fake_collector.start(tls=True, state_dir=a_dir, port=port_a)
        try:
            more = add(spool, 2)
            clock.advance(61)                                   # on the fallback for > 60 s: retry the primary
            for _ in range(5):
                s.step()
                clock.advance(2)
            assert stored_ids(a2)[-2:] == more and s.active_url.endswith(str(port_a))
        finally:
            a2.stop()
    finally:
        b.stop()


def test_token_is_never_logged(server, spool, clock, caplog):
    caplog.set_level(logging.DEBUG)
    add(spool, 2)
    server.app.set_force(503, count=1)
    s = mk(server, spool, clock, token=TOKEN)
    s.step()
    clock.advance(5)
    s.step()
    bad = mk(server, spool, clock, token=fakes_common.fixture_token("expi", "nobody"))
    add(spool, 1)
    bad.step()
    assert TOKEN not in caplog.text and "expi_" not in caplog.text

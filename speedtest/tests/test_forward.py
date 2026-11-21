"""speedtest -> collector delivery: durable spool, backoff, replay after outage/restart, idempotency, auth/pin problems."""
from __future__ import annotations

import json
import time

import fake_st_collector as fstc
import pytest
from stbox import Box, FakeClock, submission, wait_for

from exp_speedtest.daemon import Daemon
from exp_speedtest.forward import CollectorClient, Forwarder, Outcome
from exp_speedtest.store import Store


def spool_depth(b: Box) -> int:
    return b.core.store.spool_stat(time.time())["depth"]


def restart_fake(b: Box) -> None:
    """A new fake collector on the SAME port (same deterministic tokens), as after a collector restart."""
    b.fake = fstc.start(tls=b.cert_key, port=b.collector_port, **b.fake_args)


def test_collector_outage_spools_then_replays_without_loss(box: Box):
    port = box.collector_port
    box.fake.stop()                                                    # the collector goes away
    sessions = [box.new_session(src=f"127.0.0.{i}") for i in range(2, 6)]
    for s in sessions:
        r = box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view, src=s.src)
        assert r.status == 202 and r.json()["diagnosis"] is None, "accepted and spooled; no quick diagnosis yet"
    assert spool_depth(box) == 4
    assert box.daemon.forwarder.state == "unreachable"
    v = box.get(f"/st/api/v1/sessions/{sessions[0].sid}", headers=sessions[0].view, src="127.0.0.2")
    assert v.status == 200 and v.json()["state"] == "submitted" and v.json()["evidence"] == {"state": "pending", "kinds_done": []}, \
        "the user-safe view degrades instead of failing"
    box.collector_port = port
    restart_fake(box)
    for row in box.core.store.spool_due(time.time() + 3600):          # do not wait for the backoff clock
        box.core.store.spool_retry(row["seq"], row["attempts"], 0)
    box.daemon.forwarder.wake.set()
    assert wait_for(lambda: len(box.fake.app.tests) == 4, 10), len(box.fake.app.tests)
    assert wait_for(lambda: spool_depth(box) == 0, 5)
    assert {s.sid for s in sessions} == set(box.fake.app.tests)
    assert box.daemon.forwarder.state == "ok"


def test_restart_of_the_box_loses_nothing(tmp_path):
    b = Box(tmp_path)
    b.start()
    s = b.new_session()
    b.fake.stop()
    assert b.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view).status == 202
    assert spool_depth(b) == 1
    b.daemon.stop()                                                    # the box restarts while the collector is still away
    restart_fake(b)
    d2 = Daemon(b.config(), b.paths, pinger=b.pinger, clock=b.clock)
    b.daemon = d2
    d2.start()
    try:
        for row in d2.store.spool_due(time.time() + 3600):
            d2.store.spool_retry(row["seq"], row["attempts"], 0)
        d2.forwarder.wake.set()
        assert wait_for(lambda: s.sid in b.fake.app.tests, 10)
        assert wait_for(lambda: d2.store.spool_stat(time.time())["depth"] == 0, 5)
        # the share link of the pre-restart test still works (SQLite remembers the verifier and the result)
        v = b.get(f"/st/api/v1/sessions/{s.sid}", headers=s.view)
        assert v.status == 200 and v.json()["result"]["id"] == s.sid
    finally:
        b.stop()


def test_spooled_result_is_idempotent_and_duplicates_are_harmless(box: Box):
    s = box.new_session()
    box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
    doc = box.fake.app.tests[s.sid].doc
    seq = box.daemon.forwarder.enqueue_result(doc)                    # a replay of an already-delivered result
    out = box.daemon.forwarder.attempt(seq)
    assert out.kind == "ok" and out.body["status"] == "duplicate"
    assert spool_depth(box) == 0 and len(box.fake.app.tests) == 1


def test_a_result_the_collector_will_never_accept_is_dropped_not_retried_forever(box: Box):
    bad = {"schema": "exp.speedtest/1", "id": "st_01M7R3X9G0QWCYM3A3S1DE8MT4"}      # fails the collector's schema -> 400
    seq = box.daemon.forwarder.enqueue_result(bad)
    out = box.daemon.forwarder.attempt(seq)
    assert out.kind == "drop" and spool_depth(box) == 0 and box.daemon.forwarder.dropped_total == 1


def test_collector_throttling_is_honoured(box: Box):
    box.fake.app.set_force(429, count=1, retry_after=7)
    s = box.new_session()
    r = box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
    assert r.status == 202 and r.json()["diagnosis"] is None
    row = box.core.store.spool_due(time.time() + 3600)[0]
    assert row["attempts"] == 1
    due_in = box.core.store._db.execute("SELECT next_try FROM spool").fetchone()[0] - time.time()
    assert 5 <= due_in <= 8, due_in
    box.core.store.spool_retry(row["seq"], 1, 0)
    box.daemon.forwarder.wake.set()
    assert wait_for(lambda: s.sid in box.fake.app.tests, 8)


def test_collector_503_backs_off_exponentially_with_jitter():
    class Fake:
        def __init__(self) -> None:
            self.n = 0

        def __call__(self, *a, **k):
            self.n += 1
            from exp_common import tlspin
            return tlspin.Response(503, "x", {}, b"")
    store = Store(None)
    clock = FakeClock()
    from exp_speedtest.config import CollectorRef
    fw = Forwarder(CollectorClient(CollectorRef("https://127.0.0.1:1", "AA:" * 31 + "AA"), lambda: "exps_" + "A" * 43, Fake()), store, clock,
                   rng=lambda: 1.0)
    seq = store.spool_add("result", "st_01M7R3X9G0QWCYM3A3S1DE8MT4", json.dumps({"id": "st_01M7R3X9G0QWCYM3A3S1DE8MT4"}), clock())
    waits = []
    for _ in range(5):
        fw.attempt(seq)
        waits.append(round(store._db.execute("SELECT next_try FROM spool").fetchone()[0] - clock()))
    assert waits == [2, 4, 8, 16, 32], waits                          # 1 s * 2**attempts, capped at 60 s
    assert fw.state == "unreachable" and fw.collector_reachable is False


def test_bad_collector_token_is_an_auth_failure_visible_in_health(tmp_path):
    b = Box(tmp_path)
    b.fake_args = {}
    b.start_fake()
    b.write_creds(collector_token="exps_" + "B" * 43)                  # not the collector's token for this speedtest
    b.paths.assets_dir.mkdir(parents=True, exist_ok=True)
    b._seed_payload()
    b.daemon = Daemon(b.config(), b.paths, pinger=b.pinger, clock=b.clock)
    b.daemon.start()
    try:
        s = b.new_session()
        r = b.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
        assert r.status == 202, "the page is never blocked by a collector problem"
        assert b.daemon.forwarder.state == "auth_failed"
        from exp_speedtest import health
        b.daemon.write_status()
        doc = health.collect(b.config(), None, b.paths)
        assert doc["status"] == "fail" and "auth_failed" in doc["detail"] and health.exit_code(doc) == 1
        assert spool_depth(b) == 1
    finally:
        b.stop()


def test_pin_mismatch_sends_nothing(tmp_path):
    b = Box(tmp_path)
    b.start_fake()
    b.fp = "AB:" * 31 + "AB"                                           # the wrong pin
    b.write_creds()
    b._seed_payload()
    b.daemon = Daemon(b.config(), b.paths, pinger=b.pinger, clock=b.clock)
    b.daemon.start()
    try:
        s = b.new_session()
        b.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
        assert b.daemon.forwarder.state == "tls_pin_mismatch"
        assert len(b.fake.app.tests) == 0
    finally:
        b.stop()


def test_missing_collector_token_credential_is_an_auth_state_not_a_crash(tmp_path):
    b = Box(tmp_path)
    b.start_fake()
    b.write_creds()
    (b.paths.creds_dir / "collector_token").unlink()
    b._seed_payload()
    b.daemon = Daemon(b.config(), b.paths, pinger=b.pinger, clock=b.clock)
    b.daemon.start()
    try:
        s = b.new_session()
        assert b.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view).status == 202
        assert b.daemon.forwarder.state == "auth_failed" and "collector token unavailable" in b.daemon.forwarder.detail
    finally:
        b.stop()


def test_spool_full_refuses_new_results_and_lets_the_page_retry(tmp_path):
    b = Box(tmp_path)
    b.start()
    try:
        b.core.store.max_rows = 1
        b.fake.stop()
        s1, s2 = b.new_session(src="127.0.0.2"), b.new_session(src="127.0.0.3")
        assert b.post(f"/st/api/v1/sessions/{s1.sid}/result", submission(), headers=s1.view, src="127.0.0.2").status == 202
        r = b.post(f"/st/api/v1/sessions/{s2.sid}/result", submission(), headers=s2.view, src="127.0.0.3")
        assert r.status == 503 and r.json()["error"]["code"] == "spool_full" and r.h("retry-after") == "30"
        assert spool_depth(b) == 1, "old rows are never dropped to make room"
        b.core.store.max_rows = 100                                    # an operator frees space / the collector returns
        assert b.post(f"/st/api/v1/sessions/{s2.sid}/result", submission(), headers=s2.view, src="127.0.0.3").status == 202
    finally:
        b.stop()


def test_comment_after_result_with_collector_down_is_spooled_and_delivered_later(box: Box):
    s = box.new_session()
    box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
    box.fake.stop()
    assert box.post(f"/st/api/v1/sessions/{s.sid}/comment", {"comment": "still broken"}, headers=s.view).status == 204
    assert spool_depth(box) == 1
    restart_fake(box)
    box.fake.app.tests[s.sid] = fstc.Test(1, {"id": s.sid, "zone": "hall-a", "zone_source": "subnet", "schema": "exp.speedtest/1"},
                                           "spd-core", "hall-b", time.time()) if s.sid not in box.fake.app.tests else None
    for row in box.core.store.spool_due(time.time() + 3600):
        box.core.store.spool_retry(row["seq"], row["attempts"], 0)
    box.daemon.forwarder.wake.set()
    assert wait_for(lambda: box.fake.app.tests[s.sid].comment == "still broken", 8)


def test_outcome_classification_of_collector_statuses():
    from exp_common import tlspin
    cases = {200: "ok", 201: "ok", 204: "ok", 400: "drop", 403: "drop", 413: "drop", 401: "auth", 404: "notfound", 429: "throttle",
             500: "down", 502: "down", 503: "down"}
    for status, kind in cases.items():
        assert CollectorClient._classify(tlspin.Response(status, "x", {"retry-after": "3"}, b"{}")).kind == kind, status
    assert CollectorClient._classify(tlspin.Response(429, "x", {"retry-after": "9999"}, b"")).retry_after == 300
    assert CollectorClient._classify(tlspin.Response(429, "x", {"retry-after": "nan"}, b"")).retry_after == 5
    assert isinstance(Outcome("ok"), Outcome)


@pytest.mark.parametrize("garbage", [b"not json", b"[1,2]", b"", b'{"diagnosis": "x"}'])
def test_garbage_from_the_collector_never_breaks_the_result_route(box: Box, garbage):
    from exp_common import tlspin
    box.daemon.client.request = lambda *a, **k: tlspin.Response(201, "x", {}, garbage)
    s = box.new_session()
    r = box.post(f"/st/api/v1/sessions/{s.sid}/result", submission(), headers=s.view)
    assert r.status == 202 and r.json()["diagnosis"] is None

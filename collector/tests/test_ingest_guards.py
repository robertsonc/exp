"""Acceptance 1: every ingest guard rejects with the right code, valid lines in the same batch are
still accepted, and the END STATE (SQLite, VM queue) matches."""
from __future__ import annotations

import gzip
import json
import time
import zlib

from colhelpers import check_openapi, ingest, iso, new_id, rec, wait_for

from exp_collector.app import CollectorApp


def codes(resp) -> dict[int, str]:
    return {r["line"]: r["error"]["code"] for r in resp.json()["rejected"]}


def stored(app: CollectorApp, probe: str = "probe-a1") -> list[str]:
    return [i for _, i, _ in app.store.read_records(probe, 0, 2**62)]


def test_valid_batch_is_stored_and_series_reach_vm(env, app, port, vm):
    batch = [rec(test="gateway", metrics={"link_up": 1, "rtt_ms": 0.4}), rec(test="dns", metrics={"rtt_ms": 20})]
    r = ingest(port, env.ingest_token, batch)
    assert r.status == 200
    body = r.json()
    assert (body["accepted"], body["duplicates"], body["rejected"]) == (2, 0, [])
    assert sorted(stored(app)) == sorted(b["id"] for b in batch)
    assert wait_for(lambda: vm.count() == 3, 6), vm.names()
    assert set(vm.names()) == {"exp_gateway_link_up", "exp_gateway_rtt_ms", "exp_dns_rtt_ms"}
    sample = vm.lines[0]
    assert sample["metric"]["probe"] == "probe-a1" and sample["metric"]["site"] == "hall-b"
    check_openapi("ingest", "/measurements", "post", 200, body)


def test_each_guard_rejects_with_its_code_and_valid_lines_still_land(env, app, port):
    now = time.time()
    good1, good2 = rec(), rec(test="dns")
    reserved = rec()
    reserved["labels"] = {"probe": "evil"}
    naive = rec()
    naive["ts"] = "2026-11-18T20:00:00.123"
    future = rec(ts=iso(now + 3600))
    too_old = rec(ts=iso(now - 30 * 86400))
    other_probe = rec(probe="probe-a2")
    wrong_site = rec(site="hall-z")
    no_id = rec()
    del no_id["id"]
    bad_id = rec()
    bad_id["id"] = "not-a-ulid"
    nan_metric = b'{"schema":"exp.measurement/1","id":"%s","ts":"%s","probe":"probe-a1","site":"hall-b","test":"x","outcome":"ok","metrics":{"a":NaN}}' % (
        new_id().encode(), iso(now).encode())
    oversize = b'{"pad":"' + b"x" * 70_000 + b'"}'
    lines = [good1, b"{not json", reserved, naive, future, too_old, other_probe, wrong_site, no_id, bad_id,
             nan_metric, oversize, b"", good2]
    r = ingest(port, env.ingest_token, lines)
    assert r.status == 200, r.body
    body = r.json()
    assert body["accepted"] == 2 and body["duplicates"] == 0
    assert codes(r) == {2: "invalid_json", 3: "invalid_measurement", 4: "invalid_measurement", 5: "ts_future",
                        6: "ts_too_old", 7: "identity_mismatch", 8: "identity_mismatch", 9: "invalid_measurement",
                        10: "invalid_measurement", 11: "invalid_json", 12: "line_too_long", 13: "invalid_json"}
    # END STATE: only the two valid records exist, and nothing from the rejected probe/site lines
    assert sorted(stored(app)) == sorted([good1["id"], good2["id"]])
    assert stored(app, "probe-a2") == []
    assert stored(app, "evil") == []
    ids_in_rejects = {x["id"] for x in body["rejected"] if x["id"]}
    assert other_probe["id"] in ids_in_rejects and good1["id"] not in ids_in_rejects
    for x in body["rejected"]:
        assert len(x["error"]["message"]) <= 512
    check_openapi("ingest", "/measurements", "post", 200, body)


def test_future_boundary_60s(env, app, port):
    ok = rec(ts=iso(time.time() + 40))
    bad = rec(ts=iso(time.time() + 90))
    r = ingest(port, env.ingest_token, [ok, bad])
    assert r.json()["accepted"] == 1 and codes(r) == {2: "ts_future"}


def test_unconfigured_probe_token_cannot_store(env, port):
    """A token whose identity has no configured site stores nothing (identity_mismatch)."""
    from exp_common import ids
    tok = ids.new_token("expi")
    env.write_creds({"probe-zz": ids.token_hash(tok)}, {}, [])
    app2 = env.start()
    r = ingest(app2.address[1], tok, [rec(probe="probe-zz")])
    assert r.status == 200 and r.json()["accepted"] == 0 and codes(r) == {1: "identity_mismatch"}
    assert app2.store.count_records() == 0


def test_more_than_1000_lines_is_400_and_nothing_stored(env, app, port):
    batch = [rec() for _ in range(1001)]
    r = ingest(port, env.ingest_token, batch)
    assert r.status == 400 and r.json()["error"]["code"] == "too_many_lines"
    check_openapi("ingest", "/measurements", "post", 400, r.json())
    assert app.store.count_records() == 0
    # exactly 1000 is fine
    r = ingest(port, env.ingest_token, [rec() for _ in range(1000)], gz=True)
    assert r.status == 200 and r.json()["accepted"] == 1000
    assert app.store.count_records() == 1000


def test_many_blank_lines_cannot_be_used_to_blow_up(env, app, port):
    r = ingest(port, env.ingest_token, b"\n" * 5000 + b"{}")
    assert r.status == 400 and r.json()["error"]["code"] == "too_many_lines"


def test_zip_bomb_is_413_without_inflating(env, app, port):
    # 200 MiB of zeros compresses to ~200 KiB: well under the 4 MiB wire limit
    comp = zlib.compressobj(wbits=31)
    bomb = comp.compress(b"\x00" * (200 * 1024 * 1024)) + comp.flush()
    assert len(bomb) < 1024 * 1024
    t0 = time.monotonic()
    from colhelpers import https
    r = https(port, "POST", "/ingest/v1/measurements", body=bomb, headers={
        "Authorization": f"Bearer {env.ingest_token}", "Content-Type": "application/x-ndjson",
        "Content-Encoding": "gzip"})
    assert r.status == 413 and r.json()["error"]["code"] == "decompressed_too_large"
    assert time.monotonic() - t0 < 10
    check_openapi("ingest", "/measurements", "post", 413, r.json())
    assert app.store.count_records() == 0


def test_gzip_just_over_cap_413_and_exactly_valid_gzip_ok(env, app, port):
    import pytest

    from exp_collector.ingest import IngestError, gunzip_bounded
    data = gzip.compress(b"a" * 1000)
    assert gunzip_bounded(data, 1000) == b"a" * 1000
    with pytest.raises(IngestError) as e:
        gunzip_bounded(data, 999)
    assert e.value.status == 413
    # concatenated members are honoured and capped as one stream
    two = gzip.compress(b"x" * 600) + gzip.compress(b"y" * 600)
    assert len(gunzip_bounded(two, 2000)) == 1200
    with pytest.raises(IngestError):
        gunzip_bounded(two, 1100)


def test_corrupt_and_truncated_gzip_is_400(env, port):
    from colhelpers import https
    hdr = {"Authorization": f"Bearer {env.ingest_token}", "Content-Type": "application/x-ndjson",
           "Content-Encoding": "gzip"}
    assert https(port, "POST", "/ingest/v1/measurements", body=b"definitely not gzip", headers=hdr).status == 400
    good = gzip.compress(json.dumps(rec()).encode() + b"\n")
    r = https(port, "POST", "/ingest/v1/measurements", body=good[:-6], headers=hdr)
    assert r.status == 400 and r.json()["error"]["code"] == "bad_gzip"
    r = https(port, "POST", "/ingest/v1/measurements", body=good + b"trailing garbage", headers=hdr)
    assert r.status == 400


def test_wire_limit_413(env, app, port):
    r = ingest(port, env.ingest_token, b"x" * (4 * 1024 * 1024 + 1))
    assert r.status == 413 and r.json()["error"]["code"] == "payload_too_large"
    check_openapi("ingest", "/measurements", "post", 413, r.json())


def test_content_type_and_encoding_415(env, port):
    r = ingest(port, env.ingest_token, [rec()], ctype="application/json")
    assert r.status == 415 and r.json()["error"]["code"] == "unsupported_media_type"
    check_openapi("ingest", "/measurements", "post", 415, r.json())
    r = ingest(port, env.ingest_token, [rec()], extra={"Content-Encoding": "br"})
    assert r.status == 415


def test_empty_and_nul_bodies_400(env, port):
    for body in (b"", b"   \n", b'{"a":1}\n\x00\n'):
        r = ingest(port, env.ingest_token, body)
        assert r.status == 400 and r.json()["error"]["code"] == "not_ndjson", body
        check_openapi("ingest", "/measurements", "post", 400, r.json())


def test_error_envelope_has_no_stack_trace(env, port):
    r = ingest(port, env.ingest_token, b"")
    assert set(r.json()["error"]) == {"code", "message", "details"}
    assert "Traceback" not in r.body.decode()


def test_missing_content_length_is_refused(env, port):
    from colhelpers import raw_tls
    s = raw_tls(port)
    s.sendall(f"POST /ingest/v1/measurements HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {env.ingest_token}\r\n"
              "Content-Type: application/x-ndjson\r\n\r\n".encode())
    assert s.recv(65536).startswith(b"HTTP/1.1 400")
    s.close()
    s = raw_tls(port)
    s.sendall(f"POST /ingest/v1/measurements HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {env.ingest_token}\r\n"
              "Content-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".encode())
    assert s.recv(65536).startswith(b"HTTP/1.1 400")
    s.close()

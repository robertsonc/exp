"""The SQLite ring: indexing, expiry vs attached retention, purge, DHCP lookups, bounds."""
from __future__ import annotations

import os
import stat

import pytest

from exp_runner.ring import Ring, RingError
from exp_runner.syslog_parse import parse_line

NOW = 1_795_000_000.0


@pytest.fixture()
def ring(tmp_path):
    r = Ring(tmp_path / "state" / "syslog.db", 60).open()
    yield r
    r.close()


def put(ring, line, recv=NOW, src="10.9.9.9"):
    p = parse_line(line, recv)
    ring.insert_many([(p, src, recv)])
    return p


def test_indexed_by_ip_and_time(ring):
    put(ring, "action=deny src=10.1.1.1 dst=10.2.2.2 dport=22", NOW)
    put(ring, "action=deny src=10.1.1.1 dst=10.2.2.2 dport=23", NOW + 100)
    put(ring, "action=deny src=10.3.3.3 dst=10.1.1.1", NOW + 50)
    rows = ring.query("10.1.1.1", NOW - 1, NOW + 200)
    assert [r["fields"].get("dst_port") for r in rows if r["fields"].get("src_ip") == "10.1.1.1"] == [22, 23]
    assert len(rows) == 3                                   # the destination side is indexed too
    assert len(ring.query("10.1.1.1", NOW + 60, NOW + 200)) == 1
    assert ring.query("10.1.1.1", NOW - 1, NOW + 200, kinds=("dns",)) == []
    assert ring.query("10.200.200.200", 0, NOW * 2) == []
    plan = ring._conn().execute("EXPLAIN QUERY PLAN SELECT line_id FROM ips WHERE ip=? AND ts>=? AND ts<=?", ("1", 0, 1)).fetchall()
    assert any("ips_ip_ts" in str(r) for r in plan)


def test_file_mode_is_private(tmp_path):
    r = Ring(tmp_path / "d" / "s.db").open()
    try:
        assert stat.S_IMODE(os.stat(tmp_path / "d" / "s.db").st_mode) == 0o600
    finally:
        r.close()


def test_ring_expiry_versus_attached_retention(ring):
    old = NOW - 3 * 3600
    put(ring, "action=deny src=10.1.1.1 dst=10.2.2.2 dport=1", old, )
    keep = put(ring, "action=deny src=10.1.1.1 dst=10.2.2.2 dport=2", old)
    fresh = put(ring, "action=deny src=10.1.1.1 dst=10.2.2.2 dport=3", NOW - 60)
    assert ring.count() == 3
    # attach only the second line to a test's evidence
    ids = {r["fields"]["dst_port"]: r["id"] for r in ring.query("10.1.1.1", 0, NOW * 2)}
    ring.attach([ids[2]], NOW)
    assert ring.prune(NOW) == 1                           # port-1 line (expired, not attached) is gone
    left = {r["fields"]["dst_port"] for r in ring.query("10.1.1.1", 0, NOW * 2)}
    assert left == {2, 3} and ring.count_kept() == 1
    # past the ring window but inside the attached retention: the attached line survives, the fresh one expires
    ring.prune(NOW + 2 * 3600)
    left = {r["fields"]["dst_port"] for r in ring.query("10.1.1.1", 0, NOW * 2)}
    assert left == {2}
    # past the attached retention: gone
    ring.prune(NOW + 31 * 86400)
    assert ring.count() == 0
    assert keep.ips and fresh.ips


def test_ring_minutes_is_capped_at_60(tmp_path):
    r = Ring(tmp_path / "a.db", ring_minutes=600)
    assert r.ring_s == 3600


def test_delete_ip_removes_ring_and_attached_rows(ring):
    put(ring, "action=deny src=10.1.1.1 dst=10.2.2.2", NOW)
    put(ring, "DHCPACK on 10.1.1.1 to f0:18:98:aa:bb:01 (alice) via eth0", NOW)
    put(ring, "action=deny src=10.5.5.5 dst=10.2.2.2", NOW)
    ring.attach([r["id"] for r in ring.query("10.1.1.1", 0, NOW * 2)], NOW)
    assert ring.delete_ip("10.1.1.1") == 2
    assert ring.query("10.1.1.1", 0, NOW * 2) == [] and ring.count() == 1


def test_delete_mentions_removes_lines_without_an_ip(ring):
    """Regression (A6.6): a DHCPDISCOVER names the device by MAC and hostname but carries no lease IP, so delete_ip never reached it."""
    put(ring, "DHCPDISCOVER from f0:18:98:aa:bb:01 (alice-laptop) via eth0", NOW)
    put(ring, "DHCPDISCOVER from F0-18-98-AA-BB-01 via eth0", NOW)
    put(ring, "something else about ALICE-LAPTOP happened", NOW)
    put(ring, "DHCPDISCOVER from f0:18:98:cc:dd:02 (bob) via eth0", NOW)
    assert ring.delete_mentions(["f0:18:98:aa:bb:01", "f0-18-98-aa-bb-01", "alice-laptop", "ab", "%"]) == 3
    assert ring.count() == 1 and ring.delete_mentions([]) == 0 and ring.delete_mentions(["x'; DROP TABLE lines; --"]) == 0


def test_dhcp_queries(ring):
    put(ring, "DHCPACK on 10.1.1.1 to f0:18:98:aa:bb:01 (alice) via eth0", NOW)
    put(ring, "DHCPRELEASE of 10.1.1.1 from f0:18:98:aa:bb:01 via eth0 (found)", NOW + 10)
    ev = ring.dhcp_events("10.1.1.1", NOW - 1, NOW + 20)
    assert [e["event"] for e in ev] == ["ack", "release"] and ev[0]["mac"] == "f0:18:98:aa:bb:01"
    assert ring.last_dhcp_before("10.1.1.1", NOW + 5)["event"] == "ack"
    assert ring.last_dhcp_before("10.1.1.1", NOW) is None


def test_max_rows_drops_oldest_unattached(tmp_path):
    r = Ring(tmp_path / "m.db", max_rows=5).open()
    try:
        for i in range(10):
            put(r, f"action=deny src=10.1.1.1 dst=10.2.2.2 dport={i}", NOW + i)
        r.attach([r.query("10.1.1.1", 0, NOW * 2)[0]["id"]], NOW)
        r.prune(NOW + 20)
        assert r.count() == 5
        assert r.count_kept() == 1
    finally:
        r.close()


def test_sql_is_parameterized(ring):
    evil = "10.1.1.1' OR '1'='1"
    put(ring, "action=deny src=10.1.1.1 dst=10.2.2.2", NOW)
    assert ring.query(evil, 0, NOW * 2) == []
    assert ring.delete_ip("x'; DROP TABLE lines; --") == 0
    assert ring.count() == 1


def test_use_before_open_raises(tmp_path):
    with pytest.raises(RingError):
        Ring(tmp_path / "z.db").count()

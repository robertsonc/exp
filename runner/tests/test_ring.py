"""The SQLite ring: indexing, expiry vs attached retention, purge, DHCP lookups, bounds."""
from __future__ import annotations

import os
import stat

import pytest

from exp_runner.correlator import device_tokens
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
    assert len(ring.query("10.1.1.1", NOW - 1, NOW + 200, kinds=("security", "dns"))) == 3   # the kinds filter is one bound JSON array
    assert len(ring.query("10.1.1.1", NOW - 1, NOW + 200, kinds="security")) == 3              # a bare string is one kind, not letters
    assert ring.query("10.1.1.1", NOW - 1, NOW + 200, kinds=("security') OR ('1'='1",)) == []
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


def _left(ring):
    return sorted(r[0] for r in ring._conn().execute("SELECT raw FROM lines"))


def test_scrub_hostname_precision_keeps_other_devices(ring):
    """Regression (A6.6/A6.5): a generic hostname must not delete other devices' DHCP lines."""
    a, b = "f0:18:98:aa:bb:01", "f0:18:98:cc:dd:02"
    put(ring, f"DHCPACK on 10.1.2.4 to {b} (iPhone)", NOW)
    put(ring, "DHCPACK on 10.1.2.5 to aa:bb:cc:00:00:09 (Johns-iPhone)", NOW)
    put(ring, "johns-iphone.local announced", NOW)
    put(ring, "hostname iPhone renewed", NOW)
    for mac in (a, a.replace(":", "-"), "f018.98aa.bb01", a.replace(":", "").upper()):
        put(ring, f"DHCPDISCOVER from {mac} (iPhone)", NOW)
    toks = [a, a.replace(":", "-"), a.replace(":", ""), "f018.98aa.bb01", "iPhone"]
    assert ring.delete_mentions(toks, ip="10.1.2.3") == 5
    assert _left(ring) == sorted([f"DHCPACK on 10.1.2.4 to {b} (iPhone)", "DHCPACK on 10.1.2.5 to aa:bb:cc:00:00:09 (Johns-iPhone)",
                                  "johns-iphone.local announced"])


def test_hostname_boundaries_and_ip_guard(ring):
    put(ring, "johns-iphone.local seen", NOW)
    put(ring, "lease 10.1.2.9 (iphone) acked", NOW)         # names another indexed IP: kept
    put(ring, "lease 10.1.2.3 (iphone) acked", NOW)         # this device's IP: deleted
    assert ring.delete_mentions(["johns-iphone"], ip="10.1.2.3") == 1
    assert ring.delete_mentions(["iphone"], ip="10.1.2.3") == 1
    assert _left(ring) == ["lease 10.1.2.9 (iphone) acked"]


def test_bare_mac_is_a_plain_substring(ring):
    """The bare 12-hex spelling matches anywhere (bare DUIDs / client-ids glue it to other hex); a split spelling is not the MAC."""
    put(ring, "session f018 98aabb01 ok", NOW)
    put(ring, "session id deadf01898aabb01beef", NOW)
    put(ring, "mac F01898AABB01 here", NOW)
    assert ring.delete_mentions(["f01898aabb01"]) == 2
    assert _left(ring) == ["session f018 98aabb01 ok"]


def test_mac_inside_a_longer_octet_run_is_deleted(ring):
    """Owner's privacy rule (A6.6): this device's 6-octet MAC embedded in a longer octet run (DUID, client-id, MAC= header) is this
    device's identifier; a separator spelling is only refused when glued to another hex DIGIT (then it is not this MAC)."""
    mac = "f0:18:98:aa:bb:01"
    for text in ("client addr:f0:18:98:aa:bb:01 assoc", "id 11:f0:18:98:aa:bb:01:22 x", "duid F0-18-98-AA-BB-01-00-01 x",
                 "id 0001.f018.98aa.bb01 x"):
        put(ring, text, NOW)
    put(ring, "id 1f0:18:98:aa:bb:01 x", NOW)        # glued to a hex digit: a different (non-MAC) token
    put(ring, "id f0:18:98:aa:bb:01a x", NOW)
    assert ring.delete_mentions([mac, "f0-18-98-aa-bb-01", "f018.98aa.bb01"]) == 4
    assert _left(ring) == ["id 1f0:18:98:aa:bb:01 x", "id f0:18:98:aa:bb:01a x"]


def test_mac_prefix_ending_in_hex_letters_is_still_the_devices_own_line(ring):
    """Regression (p3 validator): "mac:" ends in the hex pair "ac"; it must not hide the MAC. Since the A6.6 follow-up a MAC inside a
    longer octet run ("id 11:<MAC>:22") is deleted too (it was kept by the former "longer MAC = another device" rule)."""
    mac = "f0:18:98:aa:bb:01"
    for pre in ("mac:", "mac=", "dev-", "addr:", "bssid ", "ab:"):
        put(ring, f"{pre}{mac} assoc", NOW)
    put(ring, f"id 11:{mac}:22 x", NOW)
    assert ring.delete_mentions([mac]) == 7
    assert _left(ring) == []


MAC, HOST, IP = "f0:18:98:aa:bb:01", "Johns-iPhone", "10.1.2.3"
_SCRUB_CASES = [
    # (id, this device's hostname, line, deleted?)
    ("a-duid-llt", HOST, "dnsmasq-dhcp[412]: 1823719283 DHCPSOLICIT(br0) 00:01:00:01:2c:3d:4e:5f:f0:18:98:aa:bb:01", True),
    ("b-duid-ll", HOST, "dnsmasq-dhcp[412]: 1823719283 DHCPREQUEST(br0) 00:03:00:01:f0:18:98:aa:bb:01", True),
    ("c-option61", HOST, "dnsmasq-dhcp[412]: 1823719283 sent size:  7 option: 61 client-id  01:f0:18:98:aa:bb:01", True),
    ("d-netfilter-mac", HOST, "kernel: [UFW BLOCK] IN=br0 OUT=eth0 MAC=dc:a6:32:01:02:03:f0:18:98:aa:bb:01:86:dd SRC=fd00::1234 "
                              "DST=2001:db8::1 PROTO=TCP", True),
    ("e-bare-duid", HOST, "dnsmasq-dhcp[412]: 1823719283 client-id 000100012c3d4e5ff01898aabb01", True),
    ("f-mac-colon-word", HOST, "hostapd: wlan0: STA f0:18:98:aa:bb:01:deauth", True),
    ("g-header-host-ip", HOST, "<30>Nov 20 10:00:00 10.1.0.1 dnsmasq-dhcp[412]: 1823719283 client provides name: Johns-iPhone", True),
    ("h-in-addr-arpa", HOST, "<30>Nov 20 10:00:00 dhcp-core dhcpd[1]: Added reverse map from 3.2.1.10.in-addr.arpa. to "
                             "Johns-iPhone.example.com", True),
    ("header-host-ip-5424", HOST, "<30>1 2026-11-20T10:00:00Z 10.1.0.1 dnsmasq-dhcp 412 - - client provides name: Johns-iPhone", True),
    ("ip6-arpa", HOST, "<30>Nov 20 10:00:00 dhcp-core dhcpd[1]: Added reverse map from 4.3.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0."
                       "0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa. to Johns-iPhone.example.com", True),
    ("fqdn", HOST, "<30>Nov 20 10:00:00 dhcp-core named[9]: client update for Johns-iPhone.example.com denied", True),
    ("double-quoted", HOST, 'dnsmasq-dhcp[412]: client provides name "Johns-iPhone"', True),
    ("single-quoted", HOST, "wpa: hostname='JOHNS-IPHONE' seen", True),
    ("parenthesised", HOST, "DHCPDISCOVER via eth0 (johns-iphone)", True),
    ("generic-name-header-only", "iPhone", "<30>Nov 20 10:00:00 10.1.0.1 dnsmasq-dhcp[412]: client provides name: iPhone", True),
    # kept: lines about OTHER devices
    ("other-client-ip-and-mac", "iPhone", "DHCPACK(br0) 10.1.2.9 aa:bb:cc:dd:ee:ff iPhone", False),
    ("other-client-ip-and-mac-3164", "iPhone", "<30>Nov 20 10:00:00 10.1.0.1 dnsmasq-dhcp[412]: 1823719283 DHCPACK(br0) 10.1.2.9 "
                                               "aa:bb:cc:dd:ee:ff iPhone", False),
    ("other-client-ip-beside-header", "iPhone", "<30>Nov 20 10:00:00 10.1.0.1 dnsmasq-dhcp[412]: DHCPACK(br0) 10.1.2.9 iPhone", False),
    ("other-client-reverse-ip-not-arpa", "iPhone", "lease 9.2.1.10 (iphone) acked", False),
    ("token-inside-longer-name", "iPhone", "<30>Nov 20 10:00:00 10.1.0.1 dnsmasq-dhcp[412]: client provides name: Johns-iPhone", False),
    ("longer-name", HOST, "dnsmasq-dhcp[412]: client provides name: Johns-iPhone2", False),
    ("other-duid", HOST, "dnsmasq-dhcp[412]: DHCPSOLICIT(br0) 00:01:00:01:2c:3d:4e:5f:aa:bb:cc:dd:ee:ff", False),
    ("other-reverse-map", HOST, "<30>Nov 20 10:00:00 dhcp-core dhcpd[1]: Added reverse map from 9.2.1.10.in-addr.arpa. to "
                                "Bobs-iPhone.example.com", False),
]


@pytest.mark.parametrize(("host", "line", "deleted"), [c[1:] for c in _SCRUB_CASES], ids=[c[0] for c in _SCRUB_CASES])
def test_scrub_removes_every_identifier_of_this_device_only(ring, host, line, deleted):
    """Regression (A6.6 / SR-25 review): after the final diagnosis no raw identifier of THIS device (IP, MAC in any spelling, also
    embedded in a DUID / client-id / MAC= header, hostname) stays in the ring; lines about other devices survive. Lines go through the
    receiver's path (parse_line + insert_many) and the scrub is the correlator's (delete_ip, then delete_mentions(device_tokens))."""
    put(ring, line, NOW)
    put(ring, "DHCPACK on 10.1.2.4 to f0:18:98:cc:dd:02 (bobs-laptop) via eth0", NOW)   # a bystander, always kept
    ring.delete_ip(IP)
    ring.delete_mentions(device_tokens(MAC, host), ip=IP)
    left = _left(ring)
    assert (line not in left) is deleted, left
    assert "DHCPACK on 10.1.2.4 to f0:18:98:cc:dd:02 (bobs-laptop) via eth0" in left


def test_scrub_unicode_hostname_is_case_folded(ring):
    """Regression: SQLite lower() folds ASCII only, so the LIKE prefilter never matched 'BÜRO-PC' for the token 'büro-pc'."""
    for text in ("dnsmasq-dhcp[412]: client provides name: BÜRO-PC", "dnsmasq-dhcp[412]: client provides name: büro-pc",
                 "dnsmasq-dhcp[412]: client provides name: GROSSBÜRO-PC", "dnsmasq-dhcp[412]: client provides name: Großbüro-pc"):
        put(ring, text, NOW)
    assert ring.delete_mentions(["BÜRO-PC"], ip=IP) == 2
    assert _left(ring) == ["dnsmasq-dhcp[412]: client provides name: GROSSBÜRO-PC", "dnsmasq-dhcp[412]: client provides name: Großbüro-pc"]


def test_ring_sql_has_no_interpolated_execute():
    """Every statement the ring executes is a string literal (or a name only ever bound to one): values and lists are bound
    parameters (lists as one JSON array to json_each(?)), never spliced or joined into the SQL text."""
    import ast
    import pathlib
    import re as _re
    src = (pathlib.Path(__file__).parents[1] / "exp_runner" / "ring.py").read_text()
    assert not _re.search(r"execute\(\s*(f[\"']|[\"'][^\"']*[\"']\s*[%+])", src)
    tree = ast.parse(src)
    bound: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    bound.setdefault(t.id, []).append(node.value)
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)) and isinstance(node.target, ast.Name):
            bound.setdefault(node.target.id, []).append(node)          # a += / annotated build-up is never a literal

    def literal(n: ast.AST) -> bool:
        if isinstance(n, ast.Constant):
            return isinstance(n.value, str)
        if isinstance(n, ast.IfExp):
            return literal(n.body) and literal(n.orelse)
        if isinstance(n, ast.Name):
            return bool(bound.get(n.id)) and all(literal(v) for v in bound[n.id])
        return False

    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr in ("execute", "executemany", "executescript")]
    assert len(calls) >= 15
    bad = [ast.get_source_segment(src, c) for c in calls if not (c.args and literal(c.args[0]))]
    assert bad == []

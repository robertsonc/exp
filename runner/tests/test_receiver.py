"""Syslog receiver: allowlist, rate limits, framings, oversize lines, TLS (SR-24)."""
from __future__ import annotations

import ipaddress
import socket
import time

import fake_ca
import pytest
import syslog_sender as ss

from exp_runner.config import SyslogCfg
from exp_runner.receiver import FrameReader, FramingError, SyslogReceiver
from exp_runner.ring import Ring

NOW = 1_795_000_000.0


def cfg(listen=(("udp", 0), ("tcp", 0)), allow=("127.0.0.0/8",), rate=1000, max_line=1024):
    return SyslogCfg(listen=tuple(listen), bind="127.0.0.1", allow=tuple(ipaddress.ip_network(a) for a in allow),
                     rate_limit_lines_per_s=rate, max_line_bytes=max_line, ring_minutes=60, tls_mode="provided")


@pytest.fixture()
def make(tmp_path):
    made = []

    def _make(c=None, **kw):
        ring = Ring(tmp_path / f"r{len(made)}.db").open()
        rcv = SyslogReceiver(c or cfg(), ring, **kw).start()
        made.append((rcv, ring))
        return rcv, ring
    yield _make
    for rcv, ring in made:
        rcv.stop()
        ring.close()


def line(i=1, src="10.60.14.77"):
    return f"action=deny src={src} dst=10.0.0.10 dport={i} proto=tcp"


def stored(ring, ip="10.60.14.77"):
    return ring.query(ip, 0, time.time() + 3600)


def test_udp_lines_land_in_the_ring(make):
    rcv, ring = make()
    ss.send_udp("127.0.0.1", rcv.ports["udp"], [line(1), line(2)])
    time.sleep(0.2)
    assert rcv.flush()
    assert [r["fields"]["dst_port"] for r in stored(ring)] == [1, 2]
    st = rcv.stats()
    assert st["received"] == 2 and st["stored"] == 2 and st["refused"] == 0


def test_allowlist_refuses_udp_and_tcp_sources(make):
    rcv, ring = make(cfg(allow=("10.0.0.0/8",)))
    ss.send_udp("127.0.0.1", rcv.ports["udp"], [line()])
    try:
        ss.send_tcp("127.0.0.1", rcv.ports["tcp"], [line()])
    except OSError:
        pass
    time.sleep(0.3)
    rcv.flush()
    assert stored(ring) == [] and ring.count() == 0
    assert rcv.stats()["refused"] >= 2


def test_empty_allowlist_receives_nothing(make):
    rcv, ring = make(cfg(allow=()))
    ss.send_udp("127.0.0.1", rcv.ports["udp"], [line()])
    time.sleep(0.2)
    assert ring.count() == 0 and rcv.stats()["refused"] == 1


def test_per_source_rate_limit_counts_drops(make):
    rcv, ring = make(cfg(rate=5), now_fn=lambda: 1000.0)      # frozen clock: the bucket never refills
    for i in range(20):
        rcv.handle("10.9.9.9", line(i).encode())
    rcv.flush()
    st = rcv.stats()
    assert ring.count() == 5 and st["dropped_rate"] == 15 and st["dropped_per_min"] == 15
    rcv.handle("10.9.9.8", line(99).encode())               # a different source has its own bucket
    rcv.flush()
    assert ring.count() == 6


def test_global_rate_limit(make):
    rcv, ring = make(cfg(rate=1000), now_fn=lambda: 1000.0, global_rate_lines_per_s=4)
    for i in range(12):
        rcv.handle(f"10.9.9.{i}", line(i).encode())
    rcv.flush()
    assert ring.count() == 4 and rcv.stats()["dropped_rate"] == 8


def test_rate_refills_over_time(make):
    t = [1000.0]
    rcv, ring = make(cfg(rate=2), now_fn=lambda: t[0])
    for i in range(4):
        rcv.handle("10.9.9.9", line(i).encode())
    t[0] += 1.0
    for i in range(4):
        rcv.handle("10.9.9.9", line(10 + i).encode())
    rcv.flush()
    assert ring.count() == 4 and rcv.stats()["dropped_rate"] == 4


def tcp_send(port, payload: bytes, shutdown=True):
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        s.sendall(payload)
        if shutdown:
            s.shutdown(socket.SHUT_WR)
        time.sleep(0.1)
    finally:
        s.close()


def test_tcp_octet_counting_and_lf_framing_in_one_stream(make):
    rcv, ring = make()
    oc = ss.frame([line(1), line(2)], "octet")
    lf = ss.frame([line(3), line(4)], "newline")
    tcp_send(rcv.ports["tcp"], oc + lf + b"\r\n" + (line(5) + "\r\n").encode())
    time.sleep(0.2)
    assert rcv.flush()
    assert [r["fields"]["dst_port"] for r in stored(ring)] == [1, 2, 3, 4, 5]


def test_tcp_split_across_many_small_writes(make):
    rcv, ring = make()
    data = ss.frame([line(1), line(2)], "octet") + ss.frame([line(3)], "newline")
    s = socket.create_connection(("127.0.0.1", rcv.ports["tcp"]), timeout=3)
    try:
        for i in range(0, len(data), 3):
            s.sendall(data[i:i + 3])
            time.sleep(0.002)
    finally:
        s.close()
    time.sleep(0.2)
    rcv.flush()
    assert [r["fields"]["dst_port"] for r in stored(ring)] == [1, 2, 3]


def test_oversize_lines_are_dropped_and_counted_without_breaking_the_stream(make):
    rcv, ring = make(cfg(max_line=300))
    big = "action=deny src=10.60.14.77 dst=10.0.0.1 " + "x" * 400
    ss.send_udp("127.0.0.1", rcv.ports["udp"], [big, line(1)])
    time.sleep(0.2)
    rcv.flush()
    assert [r["fields"]["dst_port"] for r in stored(ring)] == [1] and rcv.stats()["dropped_oversize"] == 1
    # TCP: oversize LF line, oversize octet-counted frame, and valid lines around them
    payload = (line(10) + "\n").encode() + (big + "\n").encode() + f"{len(big)} {big}".encode() + (line(11) + "\n").encode()
    tcp_send(rcv.ports["tcp"], payload)
    time.sleep(0.2)
    rcv.flush()
    ports = [r["fields"]["dst_port"] for r in stored(ring)]
    assert ports == [1, 10, 11]
    assert rcv.stats()["dropped_oversize"] == 3


def test_endless_line_without_newline_does_not_grow_memory(make):
    rcv, ring = make(cfg(max_line=300))
    tcp_send(rcv.ports["tcp"], b"A" * 200_000 + b"\n" + (line(7) + "\n").encode())
    time.sleep(0.3)
    rcv.flush()
    assert [r["fields"]["dst_port"] for r in stored(ring)] == [7]
    assert rcv.stats()["dropped_oversize"] >= 1


def test_absurd_octet_count_closes_the_connection(make):
    rcv, ring = make()
    s = socket.create_connection(("127.0.0.1", rcv.ports["tcp"]), timeout=3)
    s.sendall(b"99999999 hello")
    s.settimeout(2)
    assert s.recv(10) == b""                                # the receiver hung up
    s.close()
    assert ring.count() == 0


def test_frame_reader_edge_cases():
    out, big = [], []
    fr = FrameReader(50, out.append, lambda: big.append(1))
    fr.feed(b"5 hello")
    fr.feed(b"7 world!!")
    fr.feed(b"2026-11-18 not octet counting\n")           # digits not followed by a space
    fr.feed(b"10.60.14.77 ip-first line\n")
    assert out == [b"hello", b"world!!", b"2026-11-18 not octet counting", b"10.60.14.77 ip-first line"]
    with pytest.raises(FramingError):
        fr.feed(b"0 x")
    assert big == []


def test_tls_listener_receives_and_rejects_plaintext(make, tmp_path):
    ca, leaf = fake_ca.make_server_tls(tmp_path / "pki")
    rcv, ring = make(cfg(listen=(("tls", 0),)), tls_files=(leaf.cert_chain, leaf.key))
    ss.send_tls("127.0.0.1", rcv.ports["tls"], [line(1), line(2)], ca=ca.cert, server_hostname="localhost")
    time.sleep(0.3)
    rcv.flush()
    assert [r["fields"]["dst_port"] for r in stored(ring)] == [1, 2]
    # a plaintext client on the TLS port is a counted handshake failure, never data
    tcp_send(rcv.ports["tls"], (line(3) + "\n").encode())
    time.sleep(0.3)
    rcv.flush()
    assert len(stored(ring)) == 2 and rcv.stats()["tls_failures"] >= 1


def test_tls_listener_without_certificate_is_not_started(make):
    rcv, _ = make(cfg(listen=(("tls", 0), ("udp", 0))), tls_files=None)
    assert "tls" not in rcv.ports and "udp" in rcv.ports


def test_non_utf8_and_control_bytes_are_stored_safely(make):
    rcv, ring = make()
    ss_bytes = b"action=deny src=10.60.14.77 dst=10.0.0.1 reason=\xff\xfe\x00\x1b[2J bad"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(ss_bytes, ("127.0.0.1", rcv.ports["udp"]))
    s.close()
    time.sleep(0.2)
    rcv.flush()
    rows = stored(ring)
    assert len(rows) == 1 and "\x00" not in rows[0]["raw"] and "\x1b" not in rows[0]["raw"]


def test_ports_below_1024_are_not_what_the_defaults_use():
    from exp_runner.config import DEFAULT_LISTEN, parse_listen
    assert all(p >= 1024 for _, p in parse_listen(list(DEFAULT_LISTEN)))

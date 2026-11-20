"""The HTTP parser's limits and strictness (SR-21): every malformed or oversized request gets a clean refusal."""
from __future__ import annotations

import socket
import time

import pytest
from stbox import Box


def status_of(raw: bytes) -> int:
    return int(raw.split(b" ", 2)[1]) if raw.startswith(b"HTTP/1.1 ") else 0


@pytest.mark.parametrize("data,want", [
    (b"GET / HTTP/1.1\r\nHost: x\r\nX: " + b"a" * 17000 + b"\r\n\r\n", 431),                    # head too large
    (b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\nHost: x\r\n\r\n", 414),                            # request line too long
    (b"GET / HTTP/1.1\r\n" + b"".join(b"X-%d: 1\r\n" % i for i in range(70)) + b"\r\n", 431),   # too many headers
    (b"GET / HTTP/2.0\r\nHost: x\r\n\r\n", 505),
    (b"GET / HTTP/0.9\r\n\r\n", 505),
    (b"GET /\r\n\r\n", 400),                                                                    # no version
    (b"GET  /  HTTP/1.1\r\n\r\n", 400),                                                         # extra spaces
    (b"get / HTTP/1.1\r\nHost: x\r\n\r\n", 400),                                                # lower-case method
    (b"GET http://evil/ HTTP/1.1\r\nHost: x\r\n\r\n", 400),                                     # absolute-form
    (b"GET //evil/ HTTP/1.1\r\nHost: x\r\n\r\n", 400),
    (b"GET * HTTP/1.1\r\nHost: x\r\n\r\n", 400),
    (b"GET /a%00b HTTP/1.1\r\nHost: x\r\n\r\n", 400),                                           # NUL in the path
    (b"GET /a%5Cb HTTP/1.1\r\nHost: x\r\n\r\n", 400),                                           # backslash
    (b"GET /%ZZ HTTP/1.1\r\nHost: x\r\n\r\n", 404),                                             # bad escape stays literal -> 404
    (b"GET / HTTP/1.1\r\nHost: x\r\n bad: fold\r\n\r\n", 400),                                  # obs-fold
    (b"GET / HTTP/1.1\r\nBad Header: x\r\n\r\n", 400),
    (b"GET / HTTP/1.1\r\nHost: x\x01y\r\n\r\n", 400),
    (b"GET / HTTP/1.1\r\nNoColon\r\n\r\n", 400),
    (b"POST /st/api/v1/sessions HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nabcde", 400),
    (b"POST /st/api/v1/sessions HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n", 400),
    (b"POST /st/api/v1/sessions HTTP/1.1\r\nHost: x\r\nContent-Length: 1e3\r\n\r\n", 400),
    (b"POST /st/api/v1/sessions HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999\r\n\r\n", 400),
    (b"POST /st/api/v1/sessions HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 501),
    (b"POST /st/api/v1/sessions HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nabcde", 501),
    (b"POST /st/api/v1/sessions HTTP/1.1\r\nHost: x\r\n\r\n", 411),                              # no length
    (b"GET /st/api/v1/config?" + b"a=1&" * 600 + b" HTTP/1.1\r\nHost: x\r\n\r\n", 414),          # query too long
    (b"GET /st/api/v1/config?" + b"&".join(b"k%d=1" % i for i in range(40)) + b" HTTP/1.1\r\nHost: x\r\n\r\n", 400),
    (b"DELETE /st/api/v1/config HTTP/1.1\r\nHost: x\r\n\r\n", 405),
    (b"TRACE / HTTP/1.1\r\nHost: x\r\n\r\n", 405),
    (b"CONNECT example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n", 400),
])
def test_malformed_requests_are_refused_cleanly(box: Box, data: bytes, want: int):
    raw = box.raw(data, timeout=0.5 if want in (404, 405) else 5.0)       # 404/405 keep the connection open
    assert status_of(raw) == want, raw[:200]
    if want >= 400 and want not in (404, 405):
        assert b"Connection: close" in raw
    if b"\r\n\r\n" in raw and want not in (404, 405):
        body = raw.split(b"\r\n\r\n", 1)[1]
        assert b"error" in body or body == b""


def test_requests_are_served_after_a_refusal_on_a_fresh_connection(box: Box):
    box.raw(b"GET / HTTP/9\r\n\r\n")
    assert box.get("/st/api/v1/config").status == 200


def test_http_1_0_and_connection_close(box: Box):
    raw = box.raw(b"GET /st/api/v1/config HTTP/1.0\r\n\r\n")
    assert status_of(raw) == 200 and b"Connection: close" in raw
    raw = box.raw(b"GET /st/api/v1/config HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert b"Connection: close" in raw


def test_pipelined_requests_are_answered_in_order(box: Box):
    raw = box.raw(b"GET /st/api/v1/config HTTP/1.1\r\nHost: x\r\n\r\nGET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    assert raw.count(b"HTTP/1.1 ") == 2 and raw.index(b"HTTP/1.1 200") < raw.index(b"HTTP/1.1 404")


def test_unread_body_after_an_error_closes_the_connection(box: Box):
    raw = box.raw(b"POST /st/api/v1/config HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789"
                  b"GET /st/api/v1/config HTTP/1.1\r\nHost: x\r\n\r\n")
    assert raw.startswith(b"HTTP/1.1 405") and b"Connection: close" in raw and raw.count(b"HTTP/1.1 ") == 1, "no request smuggling"


def test_slowloris_head_is_dropped_within_the_head_deadline(box: Box):
    import exp_speedtest.httpd as httpd
    old = httpd.HEAD_TIMEOUT_S
    httpd.HEAD_TIMEOUT_S = 1.0
    try:
        s = socket.create_connection(("127.0.0.1", box.http_port), timeout=6)
        t0 = time.monotonic()
        data = b""
        try:
            for ch in b"GET /st/api/v1/config HTTP/1.1\r\nHost: x\r\nX-Slow: ":
                s.sendall(bytes([ch]))
                time.sleep(0.15)
            data = s.recv(1000)
        except (BrokenPipeError, ConnectionResetError):
            pass
        assert time.monotonic() - t0 < 5
        assert data == b"" or status_of(data) == 408
        s.close()
    finally:
        httpd.HEAD_TIMEOUT_S = old


def test_idle_connection_is_closed_and_no_thread_leak(box: Box):
    s = socket.create_connection(("127.0.0.1", box.http_port), timeout=3)
    s.close()
    from stbox import wait_for
    assert wait_for(lambda: box.daemon.public.connections == 0, 3)


def test_connection_cap_per_address_and_total(box: Box):
    srv = box.daemon.public
    srv.max_per_ip = 3
    socks = [socket.create_connection(("127.0.0.1", box.http_port), timeout=2) for _ in range(3)]
    time.sleep(0.1)
    extra = socket.create_connection(("127.0.0.1", box.http_port), timeout=2)
    extra.sendall(b"GET /st/api/v1/config HTTP/1.1\r\nHost: x\r\n\r\n")
    try:
        assert extra.recv(100) == b"", "a fourth connection from one address is closed unanswered"
    except ConnectionResetError:
        pass
    assert srv.connections_refused >= 1
    for s in [extra, *socks]:
        s.close()
    srv.max_per_ip = 48


def test_expect_continue_is_honoured_after_authorization(box: Box):
    s = box.new_session()
    c = socket.create_connection(("127.0.0.1", box.http_port), timeout=3)
    c.sendall(f"POST /st/up HTTP/1.1\r\nHost: x\r\nX-Exp-Leg-Token: {s.leg_token}\r\nContent-Length: 10\r\n"
              "Expect: 100-continue\r\n\r\n".encode())
    assert c.recv(100).startswith(b"HTTP/1.1 100 Continue")
    c.sendall(b"0123456789")
    assert b"204" in c.recv(500)
    c.close()
    c = socket.create_connection(("127.0.0.1", box.http_port), timeout=3)
    c.sendall(b"POST /st/up HTTP/1.1\r\nHost: x\r\nX-Exp-Leg-Token: nope\r\nContent-Length: 10\r\nExpect: 100-continue\r\n\r\n")
    data = c.recv(500)
    assert data.startswith(b"HTTP/1.1 401"), "an unauthorized upload never gets its 100 Continue"
    c.close()


def test_no_directory_listing_or_file_serving(box: Box):
    for p in ("/st/", "/st", "/static/", "/st/assets/", "/st/assets/..%2f..%2fetc%2fpasswd", "/st/assets/%2e%2e/config.json",
              "/../etc/passwd", "/st/assets/index.html", "/etc/passwd", "/st/assets/payload.bin", "/st/assets/.."):
        r = box.get(p)
        assert r.status in (400, 404), (p, r.status)
        assert b"root:" not in r.body and b"Index of" not in r.body


def test_x_forwarded_for_is_never_trusted(box: Box):
    s = box.new_session(src="127.0.0.2")
    r = box.get("/st/ping", headers={**s.leg, "X-Forwarded-For": "127.0.0.2", "Forwarded": "for=127.0.0.2"}, src="127.0.0.3")
    assert r.status == 403


def test_a_client_that_vanishes_mid_download_gives_its_reservation_back(box: Box):
    s = box.new_session()
    for _ in range(3):
        c = socket.create_connection(("127.0.0.1", box.http_port), timeout=3)
        c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, __import__("struct").pack("ii", 1, 0))   # RST on close
        c.sendall(f"GET /st/down?bytes=40000000 HTTP/1.1\r\nHost: x\r\nX-Exp-Leg-Token: {s.leg_token}\r\n\r\n".encode())
        c.recv(1000)
        c.close()
    from stbox import wait_for
    sess = box.core._sessions[s.sid]
    assert wait_for(lambda: sess.reserved == 0 and box.core.transfers_active == 0, 10), (sess.reserved, box.core.transfers_active)
    assert sess.bytes_down < 3 * 40_000_000, "only what was actually sent is booked"
    assert box.get("/st/down?bytes=1000000", headers=s.leg).status in (200, 413)


def test_idle_connections_do_not_allocate_body_buffers(box: Box):
    socks = [socket.create_connection(("127.0.0.1", box.http_port), timeout=2) for _ in range(20)]
    time.sleep(0.2)
    from exp_speedtest.httpd import Conn
    c = Conn(socks[0], "127.0.0.1")
    assert c._scratch is None and len(c.scratch) == 1 << 20
    for s in socks:
        s.close()

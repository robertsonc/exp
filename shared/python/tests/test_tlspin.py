import socket
import ssl
import threading
import time

import pytest
from exp_common import tlspin
from exp_common.tlspin import PinFormatError, PinMismatch, PinnedTimeout


class TlsServer:
    """Minimal one-shot-per-connection TLS server recording every byte the client sends."""

    def __init__(self, cert, key, reply=b"hello", hang=False):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(key))
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.ctx, self.reply, self.hang = ctx, reply, hang
        self.received: list[bytes] = []
        self.handshakes = 0
        self._stop = False
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                raw, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, raw):
        try:
            raw.settimeout(3)
            tls = self.ctx.wrap_socket(raw, server_side=True)
            self.handshakes += 1
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                buf += chunk
                self.received.append(chunk)
            if self.hang:
                time.sleep(3)
            elif buf:
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(self.reply)
                            + self.reply)
            tls.close()
        except (OSError, ssl.SSLError):
            pass

    def close(self):
        self._stop = True
        self.sock.close()


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    return tlspin.generate_self_signed_cert(tmp_path_factory.mktemp("cert"))


@pytest.fixture()
def server(cert):
    s = TlsServer(*cert)
    yield s
    s.close()


def fp(cert):
    return tlspin.fingerprint_of_pem_file(cert[0])


def test_fingerprint_helpers_agree(cert):
    pem = cert[0].read_bytes()
    der = ssl.PEM_cert_to_DER_cert(pem.decode())
    f = tlspin.fingerprint_of_pem(pem)
    assert f == tlspin.fingerprint_of_der(der) == tlspin.fingerprint_of_pem(pem.decode())
    assert len(f) == 95 and f == f.upper() and f.count(":") == 31
    import subprocess
    out = subprocess.run(["openssl", "x509", "-in", str(cert[0]), "-noout", "-fingerprint", "-sha256"],
                         capture_output=True, text=True, check=True).stdout
    assert out.strip().split("=", 1)[1] == f
    with pytest.raises(ValueError):
        tlspin.fingerprint_of_pem("not a cert")


def test_normalize_fingerprint_accepts_variants_and_refuses_garbage(cert):
    f = fp(cert)
    assert tlspin.normalize_fingerprint(f.lower()) == f
    assert tlspin.normalize_fingerprint(f.replace(":", "")) == f
    assert tlspin.normalize_fingerprint("  " + f + "\n") == f
    for badv in ("", "AB:CD", f + "00", "zz" * 32, None, 5, f[:-1]):
        with pytest.raises(PinFormatError):
            tlspin.normalize_fingerprint(badv)


def test_right_pin_succeeds(server, cert):
    r = tlspin.request("GET", f"https://127.0.0.1:{server.port}/x?y=1", fp(cert), headers={"X-T": "1"})
    assert r.status == 200 and r.body == b"hello"
    assert b"GET /x?y=1 HTTP/1.1" in b"".join(server.received)


def test_lowercase_nocolon_pin_accepted(server, cert):
    pin = fp(cert).replace(":", "").lower()
    assert tlspin.request("GET", f"https://127.0.0.1:{server.port}/", pin).status == 200


def test_wrong_pin_refused_and_server_sees_no_request_bytes(server, cert):
    wrong = tlspin.fingerprint_of_der(b"some other cert")
    with pytest.raises(PinMismatch) as ei:
        tlspin.request("POST", f"https://127.0.0.1:{server.port}/ingest", wrong, body=b"SECRET-PAYLOAD",
                       headers={"Authorization": "Bearer expi_x"})
    assert ei.value.actual == fp(cert)
    time.sleep(0.3)
    assert server.handshakes == 1            # handshake happened (needed to read the cert)...
    assert server.received == []             # ...but not one request byte was sent


def test_fallback_pins_for_rotation(server, cert):
    wrong = tlspin.fingerprint_of_der(b"old")
    assert tlspin.request("GET", f"https://127.0.0.1:{server.port}/", [wrong, fp(cert)]).status == 200
    with pytest.raises(PinMismatch):
        tlspin.request("GET", f"https://127.0.0.1:{server.port}/", [wrong, tlspin.fingerprint_of_der(b"x")])


def test_no_pins_is_refused_never_unpinned(server):
    with pytest.raises(PinFormatError):
        tlspin.request("GET", f"https://127.0.0.1:{server.port}/", [])
    assert server.handshakes == 0


def test_only_https_urls(server, cert):
    for url in (f"http://127.0.0.1:{server.port}/", "ftp://x/", "https:///x", "/relative"):
        with pytest.raises(ValueError):
            tlspin.request("GET", url, fp(cert))


def test_expired_certificate_still_works_when_pinned(tmp_path):
    cert, key = tlspin.generate_self_signed_cert(tmp_path, not_before="20200101000000Z",
                                                 not_after="20200102000000Z")
    s = TlsServer(cert, key)
    try:
        r = tlspin.request("GET", f"https://127.0.0.1:{s.port}/", tlspin.fingerprint_of_pem_file(cert))
        assert r.status == 200      # the pin, not the validity period, is the trust anchor
    finally:
        s.close()


def test_different_cert_same_host_refused(server, cert, tmp_path):
    other = tlspin.generate_self_signed_cert(tmp_path)
    with pytest.raises(PinMismatch):
        tlspin.request("GET", f"https://127.0.0.1:{server.port}/", tlspin.fingerprint_of_pem_file(other[0]))


def test_probe_fingerprint_sends_nothing(server, cert):
    assert tlspin.probe_fingerprint("127.0.0.1", server.port) == fp(cert)
    time.sleep(0.2)
    assert server.received == []


def test_read_timeout_enforced(cert):
    s = TlsServer(*cert, hang=True)
    try:
        t0 = time.monotonic()
        with pytest.raises(PinnedTimeout):
            tlspin.request("GET", f"https://127.0.0.1:{s.port}/", fp(cert), read_timeout=0.4)
        assert time.monotonic() - t0 < 2.5
    finally:
        s.close()


def test_connect_timeout_enforced_on_silent_listener():
    # a listener that accepts TCP but never speaks TLS: handshake must time out, not hang
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    try:
        t0 = time.monotonic()
        with pytest.raises(PinnedTimeout):
            tlspin.request("GET", f"https://127.0.0.1:{ls.getsockname()[1]}/", tlspin.fingerprint_of_der(b"x"),
                           connect_timeout=0.4)
        assert time.monotonic() - t0 < 2.5
    finally:
        ls.close()


def test_connection_refused_is_an_error_not_a_hang():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(OSError):
        tlspin.request("GET", f"https://127.0.0.1:{port}/", tlspin.fingerprint_of_der(b"x"), connect_timeout=1)


@pytest.mark.parametrize("kw", [{"connect_timeout": 0}, {"read_timeout": -1}, {"total_timeout": 0},
                                {"connect_timeout": None}, {"read_timeout": float("inf")},
                                {"connect_timeout": float("nan")}, {"read_timeout": True}])
def test_timeouts_are_mandatory_and_validated(kw, cert):
    with pytest.raises(ValueError):
        tlspin.request("GET", "https://127.0.0.1:1/", fp(cert), **kw)


def test_response_size_bounded(cert):
    s = TlsServer(*cert, reply=b"x" * 5000)
    try:
        with pytest.raises(tlspin.TlsPinError, match="exceeds"):
            tlspin.request("GET", f"https://127.0.0.1:{s.port}/", fp(cert), max_response_bytes=1000)
    finally:
        s.close()


def test_tls_minimum_version_is_1_2():
    assert tlspin._context().minimum_version >= ssl.TLSVersion.TLSv1_2


def test_generate_cert_rejects_injection_and_sets_key_mode(tmp_path):
    with pytest.raises(ValueError):
        tlspin.generate_self_signed_cert(tmp_path, cn="a/CN=b")
    with pytest.raises(ValueError):
        tlspin.generate_self_signed_cert(tmp_path, san=["DNS:x,IP:1.1.1.1;rm"])
    with pytest.raises(ValueError):
        tlspin.generate_self_signed_cert(tmp_path, not_before="20200101000000Z")
    _, key = tlspin.generate_self_signed_cert(tmp_path)
    assert key.stat().st_mode & 0o777 == 0o600

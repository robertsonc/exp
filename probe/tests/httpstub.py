"""A local HTTP server for the app tests: connectivity-check endpoints, a captive portal, slow and
failing endpoints, redirects. Loopback only."""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a) -> None:            # silence
        pass

    def _send(self, code: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if code != 204:
            self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if code != 204:
            self.wfile.write(body)

    def do_GET(self) -> None:                      # noqa: N802
        p = self.path.split("?")[0]
        if p == "/ok":
            self._send(200, b"hello world")
        elif p == "/cp-ok/generate_204":
            self._send(204)
        elif p == "/cp-200/generate_204":          # a portal answering 200 + its login page for everything
            self._send(200, b"<html><body>Please log in to the guest network</body></html>")
        elif p == "/cp-302/generate_204":          # a portal redirecting to its login page
            self._send(302, b"", {"Location": "/login"})
        elif p == "/login":
            self._send(200, b"<html>portal login</html>")
        elif p == "/hotspot-ok":
            self._send(200, b"<HTML><BODY>Success</BODY></HTML>")
        elif p == "/hotspot-portal":
            self._send(200, b"<html>Welcome to the venue wifi, accept the terms</html>")
        elif p.startswith("/slow"):
            time.sleep(float(p.split("/")[2]) if p.count("/") > 1 else 0.3)
            self._send(200, b"slow")
        elif p == "/err500":
            self._send(500, b"boom")
        elif p == "/err404":
            self._send(404, b"nope")
        elif p == "/loop":
            self._send(302, b"", {"Location": "/loop"})
        elif p == "/big":
            self._send(200, b"x" * 200_000)
        else:
            self._send(404, b"?")


class HttpStub:
    def __init__(self, host: str = "127.0.0.1") -> None:
        self.host = host
        self.srv = ThreadingHTTPServer((host, 0), Handler)
        self.port = self.srv.server_address[1]
        self._t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self._t.start()

    def url(self, path: str) -> str:
        return f"http://{self.host}:{self.port}{path}"

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()

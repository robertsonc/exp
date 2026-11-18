#!/usr/bin/python3
"""Local HTTP(S) stand-ins for the internet apps (runs in the `isp` namespace and listens on every address
there: 142.250.80.46 "google", ...). 200 on any path; /generate_204 -> 204 (captive-portal detectors);
/bytes/<n> -> n bytes. Stdlib only."""
from __future__ import annotations

import argparse
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "exp-harness-target"
    protocol_version = "HTTP/1.1"

    def _send(self, code: int, body: bytes = b"", ctype: str = "text/plain") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path.endswith("/generate_204") or path.endswith("/gen_204"):
            self._send(204)
            return
        if path.startswith("/bytes/"):
            try:
                n = max(0, min(int(path[7:]), 10_000_000))
            except ValueError:
                n = 0
            self._send(200, b"x" * n, "application/octet-stream")
            return
        host = (self.headers.get("Host") or "").split(":")[0]
        self._send(200, f"exp harness target for {host}\n".encode())

    do_HEAD = do_GET  # noqa: N815

    def log_message(self, fmt: str, *args: object) -> None:
        pass


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    a = ap.parse_args()
    http = ThreadingHTTPServer(("0.0.0.0", 80), Handler)
    https = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(a.cert, a.key)
    https.socket = ctx.wrap_socket(https.socket, server_side=True)
    for s in (http, https):
        s.daemon_threads = True
    threading.Thread(target=http.serve_forever, daemon=True).start()
    print("targets listening on :80 and :443", flush=True)
    https.serve_forever()


if __name__ == "__main__":
    main()

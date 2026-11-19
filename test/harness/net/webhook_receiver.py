#!/usr/bin/python3
"""Webhook receiver for the multisite harness: a stdlib HTTPS server (certificate from the harness CA) that records
EVERY POST it gets as one JSON line, so a test can assert on exactly what a collector sent (headers, raw body).

  POST /hook/<format>/<secret>   recorded; answers with the status in --mode-file (default 200)
  GET  /_health                  200 (readiness only, never recorded)

Record: {"seq", "ts" (epoch s), "hook" (path segment 2), "path", "client", "headers", "body" (text), "status"}.
The mode file holds a bare HTTP status code (e.g. 503) to simulate a failing chat service; delete it or write 200
to restore. Runs inside the net container (see lan-up.sh); the tests read the log with `docker exec ... cat`.
"""
from __future__ import annotations

import argparse
import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOCK = threading.Lock()
SEQ = [0]
MAX_BODY = 1 << 20


class Handler(BaseHTTPRequestHandler):
    server_version = "exp-hooks/1"
    log_path = Path("/var/lib/lan/webhooks.jsonl")
    mode_file = Path("/run/lan/hooks.mode")

    def log_message(self, fmt: str, *args: object) -> None:      # the path carries a secret: no access log
        return

    def _status(self) -> int:
        try:
            code = int(self.mode_file.read_text().strip())
            return code if 100 <= code <= 599 else 200
        except (OSError, ValueError):
            return 200

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200 if self.path == "/_health" else 404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = -1
        if not 0 <= n <= MAX_BODY:
            self.send_response(413)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = self.rfile.read(n).decode("utf-8", "replace")
        parts = self.path.split("?")[0].split("/")
        status = self._status()
        with LOCK:
            SEQ[0] += 1
            rec = {"seq": SEQ[0], "ts": time.time(), "hook": parts[2] if len(parts) > 2 else "", "path": self.path,
                   "client": self.client_address[0], "headers": {k.lower(): v for k, v in self.headers.items()},
                   "body": body, "status": status}
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
        self.send_response(status)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9443)
    ap.add_argument("--log", default="/var/lib/lan/webhooks.jsonl")
    ap.add_argument("--mode-file", default="/run/lan/hooks.mode")
    a = ap.parse_args()
    Handler.log_path, Handler.mode_file = Path(a.log), Path(a.mode_file)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(a.cert, a.key)
    srv = ThreadingHTTPServer((a.bind, a.port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()

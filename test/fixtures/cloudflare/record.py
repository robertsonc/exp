#!/usr/bin/env python3
"""Re-record Cloudflare's public speed-test endpoints exactly as the exp speedtest page uses them.

Dev tool, never product code. The ONLY place in the repo that talks to the public internet on purpose
(the M6 contracts step ran it once, 2026-11-20). Usage:

    python3 record.py [--out recording-YYYY-MM-DD.json] [--origin http://speed.summit.example]

Honours HTTPS_PROXY / SSL_CERT_FILE (or /root/.ccr/ca-bundle.crt when present). Every response header is kept
as received, in order; only cookie headers are dropped. Bodies are not stored (length, sha256 and the first
32 bytes only).
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import ssl
import sys
import time
import urllib.parse
from typing import Any

HOST = "speed.cloudflare.com"
DROP = {"set-cookie", "cookie", "set-cookie2"}


def _conn() -> http.client.HTTPSConnection:
    cafile = os.environ.get("SSL_CERT_FILE") or ("/root/.ccr/ca-bundle.crt" if os.path.exists("/root/.ccr/ca-bundle.crt") else None)
    ctx = ssl.create_default_context(cafile=cafile)
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if proxy:
        p = urllib.parse.urlsplit(proxy)
        c = http.client.HTTPSConnection(p.hostname, p.port, timeout=30, context=ctx)
        hdrs = {}
        if p.username:
            import base64
            tok = base64.b64encode(("%s:%s" % (urllib.parse.unquote(p.username), urllib.parse.unquote(p.password or ""))).encode()).decode()
            hdrs["Proxy-Authorization"] = "Basic " + tok
        c.set_tunnel(HOST, 443, headers=hdrs)
        return c
    return http.client.HTTPSConnection(HOST, 443, timeout=30, context=ctx)


def once(method: str, path: str, headers: dict[str, str], body: bytes | None = None, label: str = "") -> dict[str, Any]:
    c = _conn()
    t0 = time.perf_counter()
    c.connect()
    t_conn = time.perf_counter()
    h = {"Host": HOST, "Accept": "*/*", "User-Agent": "exp-recorder/1", **headers}
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    t_first = time.perf_counter()
    data = r.read()
    t_end = time.perf_counter()
    rh = [[k, v] for k, v in r.getheaders() if k.lower() not in DROP]
    c.close()
    return {
        "label": label, "request": {"method": method, "url": "https://%s%s" % (HOST, path),
                                    "headers": [[k, v] for k, v in h.items()], "body_bytes": len(body or b"")},
        "response": {"status": r.status, "reason": r.reason, "headers": rh,
                     "body": {"length": len(data), "sha256": hashlib.sha256(data).hexdigest(), "head_hex": data[:32].hex()}},
        "timing_ms": {"connect_incl_tunnel_tls": round((t_conn - t0) * 1000, 1), "ttfb_after_send": round((t_first - t_conn) * 1000, 1),
                      "total_after_connect": round((t_end - t_conn) * 1000, 1)},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="recording-%s.json" % time.strftime("%Y-%m-%d", time.gmtime()))
    ap.add_argument("--origin", default="http://speed.summit.example")
    a = ap.parse_args()
    o = {"Origin": a.origin}
    ce = {"Content-Type": "text/plain;charset=UTF-8"}  # what fetch() sends for a string body
    rec = [
        once("GET", "/__down?bytes=0", o, label="latency probe (idle): library GET __down?bytes=0"),
        once("GET", "/__down?bytes=0&during=downloadload", o, label="latency probe during download load (library adds during=)"),
        once("GET", "/__down?bytes=100000", o, label="download 100 kB"),
        once("POST", "/__up?bytes=1000", {**o, **ce}, b"0" * 1000, label="upload 1 kB (body is a string of '0', no custom headers)"),
        once("GET", "/cdn-cgi/trace", o, label="colo / loc from the trace endpoint"),
        once("OPTIONS", "/__up?bytes=1000", {**o, "Access-Control-Request-Method": "POST"}, label="CORS preflight for __up, no custom headers (what the library sends when authorization is off)"),
        once("OPTIONS", "/__up?bytes=1000", {**o, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type"}, label="CORS preflight for __up with custom headers (only if the library's authorization option were enabled; exp does not enable it)"),
        once("OPTIONS", "/__down?bytes=0", {**o, "Access-Control-Request-Method": "GET"}, label="CORS preflight for __down (not normally sent: simple GET)"),
    ]
    idle = [once("GET", "/__down?bytes=0", o, label="idle latency sample %d" % i)["timing_ms"]["ttfb_after_send"] for i in range(8)]
    doc = {"recorded_at": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()), "origin_header": a.origin, "host": HOST,
           "via_proxy": bool(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")),
           "note": "Only cookie headers are stripped. Timing includes the agent proxy hop when via_proxy is true.",
           "exchanges": rec, "idle_latency_ttfb_ms_samples": idle}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print("wrote", a.out, "(%d exchanges)" % len(rec))
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Test server ports: hard-coded endpoints for Marvis Minis and the EXM clients.

A port with role = "server" gets a fixed address instead of DHCP and serves:
  ICMP echo and traceroute    answered by the kernel (Minis "Network" targets)
  HTTP  (default port 80)     200 on every path (Minis "Application" targets need 200)
  HTTPS (default port 443)    the same, self-signed certificate for the port's IP
  /bytes/N                    N bytes, for throughput checks (capped at 100 MB)
  /health                     a small JSON document
Every request is logged to results/<day>/server_access.jsonl with its source
address and user agent, so Minis checks are visible as they arrive.

Faults can be injected per server with `exm server set`: an HTTP delay, a forced
status code, or netem impairment (delay, loss) on the port itself.
"""
from __future__ import annotations

import fcntl
import http.server
import ipaddress
import json
import os
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse

from . import config as C
from . import events
from . import netns

TLS_DIR = "/etc/exm/tls"
MAX_BYTES = 100_000_000


def ip_of(c: dict) -> str:
    return c["address"].split("/")[0]


def fault_path(cfg: dict, cid: str) -> str:
    return C.state_path(cfg, f"{cid}.server.json")


def read_fault(cfg: dict, cid: str) -> dict:
    try:
        with open(fault_path(cfg, cid)) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def write_fault(cfg: dict, cid: str, fault: dict) -> None:
    tmp = fault_path(cfg, cid) + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(fault, fh)
    os.chmod(tmp, 0o644)
    os.replace(tmp, fault_path(cfg, cid))


def _carrier(ns: str, iface: str) -> bool:
    r = netns.sh(["ip", "netns", "exec", ns, "cat", f"/sys/class/net/{iface}/carrier"], check=False)
    return r.returncode == 0 and r.stdout.strip() == "1"


def _global_v4(ns: str, iface: str) -> list[str]:
    out = []
    for entry in netns.ip_json(["-4", "addr", "show", "dev", iface], ns):
        for a in entry.get("addr_info", []):
            if a.get("scope") == "global":
                out.append(f"{a['local']}/{a['prefixlen']}")
    return out


def claim_address(cfg: dict, c: dict, carrier_wait_s: int = 30) -> int:
    """Give a server port its fixed address. 0 on success; non-zero leaves it unclaimed."""
    ns, iface, addr, ip = C.ns_name(c["id"]), c["iface"], c["address"], ip_of(c)
    if not (netns.netns_exists(ns) and netns.iface_present(iface, ns)):
        print(f"server {c['id']}: {iface} is not in {ns}; start exm-netns.service first", flush=True)
        return 3
    for _ in range(carrier_wait_s):
        if _carrier(ns, iface):
            break
        time.sleep(1)
    else:
        print(f"server {c['id']}: no carrier on {iface} after {carrier_wait_s}s; {ip} not claimed", flush=True)
        return 4

    current = _global_v4(ns, iface)
    canonical = str(ipaddress.IPv4Interface(addr))
    if canonical not in current:
        # RFC 5227 probe: any reply means another host already uses this address.
        # Fail closed: never take an address someone else is using.
        r = netns.sh(["ip", "netns", "exec", ns, "busybox", "arping", "-D", "-c", "3", "-w", "4",
                      "-I", iface, ip], check=False)
        if r.returncode != 0:
            print(f"server {c['id']}: REFUSED to claim {ip}: another host answered for it on {iface} "
                  f"({(r.stdout + r.stderr).strip().splitlines()[-1:]}). Pick a free address.", flush=True)
            return 2
        for old in current:
            netns.sh(["ip", "-n", ns, "addr", "del", old, "dev", iface], check=False)
        netns.sh(["ip", "-n", ns, "addr", "add", canonical, "dev", iface])
        # Gratuitous ARP so the gateway and switches learn the new owner at once.
        netns.sh(["ip", "netns", "exec", ns, "busybox", "arping", "-U", "-c", "2", "-I", iface, ip], check=False)
    if c.get("gateway"):
        netns.sh(["ip", "-n", ns, "route", "replace", "default", "via", c["gateway"], "dev", iface])
    lines = [f"# exm: static server port {c['id']} ({canonical})"] + [f"nameserver {d}" for d in c.get("dns", [])]
    netns.write_inplace(netns.resolv_path(c["id"]), "\n".join(lines) + "\n")
    with open(C.state_path(cfg, f"{c['id']}.lease.json") + ".tmp", "w") as fh:
        json.dump({"state": "static", "ts": events.utc_iso(), "ip": ip,
                   "prefix": ipaddress.IPv4Interface(addr).network.prefixlen,
                   "router": [c["gateway"]] if c.get("gateway") else [], "dns": c.get("dns", [])}, fh)
    os.replace(C.state_path(cfg, f"{c['id']}.lease.json") + ".tmp", C.state_path(cfg, f"{c['id']}.lease.json"))
    print(f"server {c['id']}: {canonical} on {iface}, gateway {c.get('gateway') or '-'}", flush=True)
    return 0


def ensure_cert(c: dict) -> tuple[str, str]:
    """Self-signed certificate whose SAN is the port's address; regenerated if the address changes."""
    os.makedirs(TLS_DIR, mode=0o755, exist_ok=True)
    base = os.path.join(TLS_DIR, f"{c['id']}-{ip_of(c)}")
    crt, key = base + ".crt", base + ".key"
    if not (os.path.exists(crt) and os.path.exists(key)):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                        "-subj", f"/CN=exm-{c['id']}", "-addext", f"subjectAltName=IP:{ip_of(c)}",
                        "-keyout", key, "-out", crt], check=True, capture_output=True)
        os.chmod(key, 0o600)
    return crt, key


class _Faults:
    """Fault settings, re-read whenever the state file changes."""

    def __init__(self, cfg, cid):
        self.path, self.mtime, self.data = fault_path(cfg, cid), None, {}

    def get(self) -> dict:
        try:
            m = os.stat(self.path).st_mtime
        except FileNotFoundError:
            return {}
        if m != self.mtime:
            try:
                with open(self.path) as fh:
                    self.data = json.load(fh)
                self.mtime = m
            except (OSError, json.JSONDecodeError):
                pass
        return self.data


def _log_access(cfg, c, rec: dict) -> None:
    ev = events.make(cfg, c, "server_access", target=rec["path"])
    ev["outcome"] = C.OK if rec["status"] < 400 else C.DEGRADED
    ev["phase_ms"] = {"handler": rec["ms"]}
    ev["value"] = rec
    day_dir = os.path.join(cfg["results_dir"], ev["ts"][:10])
    os.makedirs(day_dir, mode=0o755, exist_ok=True)
    fd = os.open(os.path.join(day_dir, "server_access.jsonl"), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        ev["emitted"] = events.utc_iso()          # under the lock, like events.emit: the collector resumes by it
        os.write(fd, (json.dumps(ev, separators=(",", ":")) + "\n").encode())
    finally:
        os.close(fd)


def _handler(cfg, c, scheme, faults):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = f"exm-test-server/{C.AGENT_VER}"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _serve(self, head_only):
            t0 = time.perf_counter()
            fault = faults.get()
            if fault.get("http_delay_ms"):
                time.sleep(int(fault["http_delay_ms"]) / 1000.0)
            status = int(fault.get("http_status") or 200)
            path = urllib.parse.urlsplit(self.path).path
            ctype, body, length = "text/plain; charset=utf-8", None, 0
            if path.startswith("/bytes/") and path[7:].isdigit():
                length = min(int(path[7:]), MAX_BYTES)
                ctype = "application/octet-stream"
            elif path == "/health":
                body = json.dumps({"server": c["id"], "address": c["address"], "ts": events.utc_iso(),
                                   "fault": fault}).encode()
                ctype = "application/json"
            else:
                body = f"EXM test server {c['id']} ({ip_of(c)}) {scheme} ok\n".encode()
            if body is not None:
                length = len(body)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            sent = 0
            if not head_only:
                try:
                    if body is not None:
                        self.wfile.write(body)
                        sent = length
                    else:
                        chunk = b"\0" * 65536
                        while sent < length:
                            n = min(len(chunk), length - sent)
                            self.wfile.write(chunk[:n])
                            sent += n
                except (BrokenPipeError, ConnectionResetError):
                    pass
            _log_access(cfg, c, {"scheme": scheme, "method": self.command, "path": path,
                                 "status": status, "src_ip": self.client_address[0],
                                 "src_port": self.client_address[1],
                                 "user_agent": self.headers.get("User-Agent", ""),
                                 "bytes": sent, "ms": events.ms(time.perf_counter() - t0),
                                 "fault": fault or None})

        def do_GET(self):
            self._serve(False)

        def do_HEAD(self):
            self._serve(True)

    return Handler


class _HTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(cfg: dict, c: dict) -> int:
    """Run HTTP and HTTPS inside the server port's namespace until killed."""
    faults = _Faults(cfg, c["id"])
    http_port, https_port = int(c.get("http_port", 80)), int(c.get("https_port", 443))
    crt = os.path.join(TLS_DIR, f"{c['id']}-{ip_of(c)}.crt")
    key = os.path.join(TLS_DIR, f"{c['id']}-{ip_of(c)}.key")
    plain = _HTTPServer(("0.0.0.0", http_port), _handler(cfg, c, "http", faults))
    tls = _HTTPServer(("0.0.0.0", https_port), _handler(cfg, c, "https", faults))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
    os.makedirs(C.RUN_DIR, exist_ok=True)
    with open(os.path.join(C.RUN_DIR, f"server-{c['id']}.pid"), "w") as fh:
        fh.write(str(os.getpid()))
    print(f"server {c['id']}: serving http://{ip_of(c)}:{http_port}/ and https://{ip_of(c)}:{https_port}/",
          flush=True)
    t = threading.Thread(target=tls.serve_forever, daemon=True)
    t.start()
    try:
        plain.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def set_netem(c: dict, spec: str | None) -> str:
    """Apply (or clear, with spec None) netem impairment on the server's port."""
    ns, iface = C.ns_name(c["id"]), c["iface"]
    if not spec:
        netns.sh(["ip", "netns", "exec", ns, "tc", "qdisc", "del", "dev", iface, "root"], check=False)
        return "cleared"
    r = netns.sh(["ip", "netns", "exec", ns, "tc", "qdisc", "replace", "dev", iface, "root", "netem"]
                 + spec.split(), check=False)
    if r.returncode != 0:
        sys.exit(f"exm: tc rejected netem '{spec}': {r.stderr.strip()}")
    return spec

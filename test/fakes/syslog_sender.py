# ruff: noqa: E501  (protocol tables in the module docstring)
"""Syslog test traffic for the M6 runner's syslog listener (dev/test tooling; stdlib only).

Line generators (message bodies and syslog envelopes) plus senders for UDP, TCP and TLS, and a ``Receiver`` that captures
what was sent (so the framing logic is itself tested). Sources of every format, stated honestly:

* **RFC 5424** (``rfc5424_message``): RFC 5424 section 6 (HEADER ``<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID``, then
  STRUCTURED-DATA ``[SD-ID name="value" ...]`` or ``-``, then MSG); SD-PARAM values escape ``"``, ``\\`` and ``]``. RFC 3164
  (``rfc3164_message``) is the BSD envelope ``<PRI>Mmm dd hh:mm:ss HOST TAG: MSG``. Public RFCs, from knowledge; not a local file.
* **Framing**: UDP = one message per datagram (RFC 5426); TCP and TLS use octet counting ``LEN SP MSG`` (RFC 6587 section 3.4.1,
  RFC 5425 for TLS) or newline-delimited non-transparent framing (RFC 6587 section 3.4.2).
* **CEF** (``cef``): ArcSight "Common Event Format" implementation standard: ``CEF:Version|Device Vendor|Device Product|Device
  Version|Signature ID|Name|Severity|Extension``; header escapes ``\\`` and ``|``; extension is ``key=value`` pairs separated by
  spaces with ``\\``, ``=`` and newlines escaped in values. Public spec, from knowledge.
* **LEEF** (``leef``): IBM QRadar LEEF 1.0 / 2.0: ``LEEF:2.0|Vendor|Product|Version|EventID|<delimiter>|key=value<delim>...``
  (1.0 has no delimiter field and uses tab). Public IBM spec, from knowledge.
* **EdgeConnect firewall / zone-policy lines** (``ec_firewall``): **no local vendor documentation exists** (pyedgeconnect
  documents only the syslog *configuration* calls in ``orch/_logging.py``, not the log text; HPE Aruba SSE has no local docs
  either). These lines are *representative* ``key=value`` text shaped by the flow-row vocabulary pyedgeconnect does document
  (zones, drop reason, ZBF); they are fixtures for parser robustness, not vendor ground truth. A runner must parse by key name
  and ignore unknown keys.
* **DHCP**: ISC dhcpd (``dhcpd[pid]: DHCPACK on <ip> to <mac> (<hostname>) via <if>``, the documented dhcpd log messages),
  Kea (``DHCP4_LEASE_ALLOC [hwtype=1 <mac>], cid=[..], tid=0x..: lease <ip> has been allocated for <n> seconds``, Kea 2.x
  message id) and Windows DHCP Server (the CSV audit log ``ID,Date,Time,Description,IP Address,Host Name,MAC Address,...`` with
  event ids 10 new lease / 11 renew / 12 release; MAC without separators; forwarded over syslog by an agent). All from public
  documentation as known; none is a local reference.
* **key=value** (``kv``): the common ``k=v k2="v 2"`` shape (iptables / Fortinet / generic firewalls).

CLI: ``python test/fakes/syslog_sender.py --to udp://127.0.0.1:5514 --format cef --src 10.60.14.77 [--count 3]``.
"""
from __future__ import annotations

import argparse
import datetime
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

FACILITY_LOCAL0 = 16
SEV = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warning": 4, "notice": 5, "info": 6, "debug": 7}
MAX_MSG = 8192
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _dt(ts: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)


def pri(facility: int = FACILITY_LOCAL0, severity: str | int = "info") -> int:
    if isinstance(severity, str) and severity not in SEV:
        raise ValueError(f"unknown severity {severity!r}")
    s = SEV[severity] if isinstance(severity, str) else int(severity)
    if not (0 <= facility <= 23 and 0 <= s <= 7):
        raise ValueError("facility 0-23 and severity 0-7")
    return facility * 8 + s


# ------------------------------------------------------------------------------------------------- envelopes
def rfc3164_message(msg: str, *, ts: float, host: str = "ec-core", tag: str = "exp-fake", pid: int | None = None,
                    facility: int = FACILITY_LOCAL0, severity: str | int = "info") -> str:
    d = _dt(ts)
    head = f"<{pri(facility, severity)}>{MONTHS[d.month - 1]} {d.day:2d} {d:%H:%M:%S} {host} {tag}"
    if pid is not None:
        head += f"[{pid}]"
    return f"{head}: {msg}"


def sd_escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def rfc5424_message(msg: str, *, ts: float, host: str = "ec-core", app: str = "exp-fake", procid: str = "-", msgid: str = "-",
                    sd: dict[str, dict[str, str]] | None = None, facility: int = FACILITY_LOCAL0, severity: str | int = "info") -> str:
    """``sd`` maps SD-ID -> {param: value}; ``{}``/None renders the NILVALUE ``-``."""
    for name, val in (("host", host), ("app", app), ("procid", procid), ("msgid", msgid)):
        if not val or " " in val:
            raise ValueError(f"{name} must be a non-empty token without spaces")
    sd_text = "".join("[" + sid + "".join(f' {k}="{sd_escape(v)}"' for k, v in params.items()) + "]" for sid, params in (sd or {}).items()) or "-"
    return f"<{pri(facility, severity)}>1 {_dt(ts).isoformat(timespec='milliseconds').replace('+00:00', 'Z')} {host} {app} {procid} {msgid} {sd_text} {msg}"


# ----------------------------------------------------------------------------------------------- bodies
def _cef_header(v: str) -> str:
    return v.replace("\\", "\\\\").replace("|", "\\|")


def _cef_ext(v: str) -> str:
    return v.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r")


def cef(*, vendor: str = "ExpFake", product: str = "EdgeConnect", version: str = "9.3", sig_id: str = "FW-DENY", name: str = "Firewall deny",
        severity: int = 5, ext: dict[str, Any] | None = None) -> str:
    if not 0 <= severity <= 10:
        raise ValueError("CEF severity 0-10")
    head = "|".join(_cef_header(x) for x in (vendor, product, version, sig_id, name)) + f"|{severity}|"
    return "CEF:0|" + head + " ".join(f"{k}={_cef_ext(str(v))}" for k, v in (ext or {}).items())


def leef(*, vendor: str = "ExpFake", product: str = "EdgeConnect", version: str = "9.3", event_id: str = "FW-DENY", attrs: dict[str, Any] | None = None,
         version_major: int = 2, delimiter: str = "\t") -> str:
    if version_major not in (1, 2):
        raise ValueError("LEEF version 1 or 2")
    for v in (vendor, product, version, event_id):
        if "|" in v:
            raise ValueError("'|' is not allowed in LEEF header fields")
    if len(delimiter) != 1:
        raise ValueError("delimiter is a single character")
    for k, v in (attrs or {}).items():
        if delimiter in str(v) or delimiter in k:
            raise ValueError("delimiter occurs inside an attribute")
    head = f"LEEF:{version_major}.0|{vendor}|{product}|{version}|{event_id}|"
    if version_major == 2:
        head += ("x09" if delimiter == "\t" else delimiter) + "|"
    return head + delimiter.join(f"{k}={v}" for k, v in (attrs or {}).items())


def kv(fields: dict[str, Any]) -> str:
    def q(v: Any) -> str:
        s = str(v)
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"' if (" " in s or "=" in s or '"' in s or not s) else s
    return " ".join(f"{k}={q(v)}" for k, v in fields.items())


def ec_firewall(*, src: str = "10.60.14.77", dst: str = "10.0.0.10", sport: int = 51234, dport: int = 22, proto: str = "tcp", action: str = "DROP",
                from_zone: str = "Guest", to_zone: str = "Mgmt", rule: str = "deny-guest-to-mgmt", reason: str = "zone-policy", style: str = "kv") -> str:
    """Representative EdgeConnect zone-policy / firewall line (NO vendor doc: see the module docstring)."""
    if style == "kv":
        return kv({"event": "firewall", "action": action, "rule": rule, "from_zone": from_zone, "to_zone": to_zone, "src": src, "sport": sport,
                   "dst": dst, "dport": dport, "proto": proto, "reason": reason})
    if style == "flow":
        return (f"ZBF {action} {proto} {src}:{sport} -> {dst}:{dport} zones {from_zone}->{to_zone} policy={rule}")
    raise ValueError("style kv or flow")


def dhcp_isc(event: str, ip: str, mac: str, hostname: str | None = None, via: str = "eth1", server: str | None = "10.0.0.1") -> str:
    host = f" ({hostname})" if hostname else ""
    ev = event.upper()
    if ev == "DHCPDISCOVER":
        return f"DHCPDISCOVER from {mac}{host} via {via}"
    if ev == "DHCPOFFER":
        return f"DHCPOFFER on {ip} to {mac}{host} via {via}"
    if ev == "DHCPREQUEST":
        return f"DHCPREQUEST for {ip} ({server}) from {mac}{host} via {via}" if server else f"DHCPREQUEST for {ip} from {mac}{host} via {via}"
    if ev == "DHCPACK":
        return f"DHCPACK on {ip} to {mac}{host} via {via}"
    if ev == "DHCPRELEASE":
        return f"DHCPRELEASE of {ip} from {mac}{host} via {via} (found)"
    raise ValueError(f"unknown dhcpd event {event!r}")


def dhcp_kea(ip: str, mac: str, *, ts: float, lease_s: int = 3600, tid: int = 0x1A2B3C4D, pid: int = 1234) -> str:
    d = _dt(ts)
    cid = "01:" + mac
    return (f"{d:%Y-%m-%d %H:%M:%S}.{d.microsecond // 1000:03d} INFO  [kea-dhcp4.leases/{pid}.140123456789] DHCP4_LEASE_ALLOC "
            f"[hwtype=1 {mac}], cid=[{cid}], tid=0x{tid:x}: lease {ip} has been allocated for {lease_s} seconds")


WINDOWS_DHCP_EVENTS = {10: "Assign", 11: "Renew", 12: "Release"}
WINDOWS_DHCP_HEADER = ("ID,Date,Time,Description,IP Address,Host Name,MAC Address,User Name,TransactionID,QResult,Probationtime,CorrelationID,"
                       "Dhcid,VendorClass(Hex),VendorClass(ASCII),UserClass(Hex),UserClass(ASCII),RelayAgentInformation,DnsRegError")


def dhcp_windows(event_id: int, ip: str, mac: str, hostname: str, *, ts: float, tid: int = 305419896) -> str:
    if event_id not in WINDOWS_DHCP_EVENTS:
        raise ValueError("event id 10, 11 or 12")
    d = _dt(ts)
    mac12 = mac.replace(":", "").upper()
    return (f"{event_id},{d:%m/%d/%y},{d:%H:%M:%S},{WINDOWS_DHCP_EVENTS[event_id]},{ip},{hostname},{mac12},,{tid},0,,,,,,,,0,0")


# -------------------------------------------------------------------------------------------------- senders
def _check(msgs: Sequence[str]) -> list[bytes]:
    out = []
    for m in msgs:
        b = m.encode("utf-8")
        if len(b) > MAX_MSG:
            raise ValueError("message over 8 KiB")
        out.append(b)
    return out


def frame(msgs: Sequence[str], framing: str) -> bytes:
    if framing == "octet":
        return b"".join(str(len(b)).encode() + b" " + b for b in _check(msgs))
    if framing == "newline":
        for m in msgs:
            if "\n" in m:
                raise ValueError("newline framing cannot carry a newline inside a message")
        return b"".join(b + b"\n" for b in _check(msgs))
    raise ValueError("framing octet or newline")


def send_udp(host: str, port: int, msgs: Iterable[str], timeout: float = 5.0) -> int:
    n = 0
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        for b in _check(list(msgs)):
            s.sendto(b, (host, port))
            n += 1
    return n


def send_tcp(host: str, port: int, msgs: Sequence[str], *, framing: str = "octet", timeout: float = 5.0) -> int:
    data = frame(msgs, framing)
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(data)
    return len(msgs)


def send_tls(host: str, port: int, msgs: Sequence[str], *, ca: str | Path | None = None, framing: str = "octet", server_hostname: str | None = None,
             verify: bool = True, timeout: float = 5.0) -> int:
    ctx = ssl.create_default_context(cafile=str(ca) if ca else None)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    data = frame(msgs, framing)
    with socket.create_connection((host, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=server_hostname or host) as s:
        s.settimeout(timeout)
        s.sendall(data)
    return len(msgs)


def send(url: str, msgs: Sequence[str], *, ca: str | Path | None = None, framing: str = "octet", verify: bool = True) -> int:
    """``udp://h:p``, ``tcp://h:p`` or ``tls://h:p``."""
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("udp", "tcp", "tls") or not u.hostname or not u.port:
        raise ValueError("url must be udp://host:port, tcp://host:port or tls://host:port")
    if u.scheme == "udp":
        return send_udp(u.hostname, u.port, msgs)
    if u.scheme == "tcp":
        return send_tcp(u.hostname, u.port, msgs, framing=framing)
    return send_tls(u.hostname, u.port, msgs, ca=ca, framing=framing, verify=verify)


# ------------------------------------------------------------------------------------------------- receiver
def parse_stream(buf: bytes) -> tuple[list[str], bytes]:
    """Split a TCP/TLS byte stream into messages (octet counting if it starts with a digit, else LF); returns (messages, rest)."""
    out: list[str] = []
    while buf:
        if buf[:1].isdigit():
            sp = buf.find(b" ")
            if sp < 0 or sp > 6 or not buf[:sp].isdigit():
                break
            n = int(buf[:sp])
            if n > MAX_MSG:
                raise ValueError("octet count over 8 KiB")
            if len(buf) < sp + 1 + n:
                break
            out.append(buf[sp + 1: sp + 1 + n].decode("utf-8", "replace"))
            buf = buf[sp + 1 + n:]
        else:
            nl = buf.find(b"\n")
            if nl < 0:
                if len(buf) > MAX_MSG:
                    raise ValueError("line over 8 KiB")
                break
            out.append(buf[:nl].decode("utf-8", "replace"))
            buf = buf[nl + 1:]
    return out, buf


class Receiver:
    """Loopback UDP + TCP (+ TLS) syslog listener that records messages as ``(transport, text)``."""

    def __init__(self, host: str = "127.0.0.1", *, tls: tuple[Path, Path] | None = None) -> None:
        self.host = host
        self.messages: list[tuple[str, str]] = []
        self.lock = threading.Lock()
        self.stop_ev = threading.Event()
        self._socks: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self.udp_port = self._bind(socket.SOCK_DGRAM)
        self.tcp_port = self._bind(socket.SOCK_STREAM)
        self.tls_port = 0
        self._ctx: ssl.SSLContext | None = None
        if tls is not None:
            self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._ctx.load_cert_chain(str(tls[0]), str(tls[1]))
            self.tls_port = self._bind(socket.SOCK_STREAM, tls=True)

    def _bind(self, kind: int, tls: bool = False) -> int:
        s = socket.socket(socket.AF_INET, kind)
        s.bind((self.host, 0))
        s.settimeout(0.2)
        if kind == socket.SOCK_STREAM:
            s.listen(16)
        self._socks.append(s)
        target = self._udp_loop if kind == socket.SOCK_DGRAM else (lambda sock=s: self._tcp_loop(sock, tls))
        t = threading.Thread(target=target, args=(s,) if kind == socket.SOCK_DGRAM else (), daemon=True)
        t.start()
        self._threads.append(t)
        return s.getsockname()[1]

    def _add(self, transport: str, text: str) -> None:
        with self.lock:
            self.messages.append((transport, text))

    def _udp_loop(self, s: socket.socket) -> None:
        while not self.stop_ev.is_set():
            try:
                data, _ = s.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                return
            self._add("udp", data.decode("utf-8", "replace").rstrip("\n"))

    def _tcp_loop(self, s: socket.socket, tls: bool) -> None:
        while not self.stop_ev.is_set():
            try:
                conn, _ = s.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn, tls), daemon=True).start()

    def _serve(self, conn: socket.socket, tls: bool) -> None:
        name = "tls" if tls else "tcp"
        try:
            conn.settimeout(5)
            if tls and self._ctx is not None:
                conn = self._ctx.wrap_socket(conn, server_side=True)
            buf = b""
            while not self.stop_ev.is_set():
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                msgs, buf = parse_stream(buf)
                for m in msgs:
                    self._add(name, m)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def wait_for(self, n: int, timeout: float = 5.0) -> list[tuple[str, str]]:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            with self.lock:
                if len(self.messages) >= n:
                    break
            time.sleep(0.02)
        with self.lock:
            return list(self.messages)

    def stop(self) -> None:
        self.stop_ev.set()
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=2)

    def __enter__(self) -> Receiver:
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


# ----------------------------------------------------------------------------------------------------- CLI
def build(fmt: str, *, src: str, dst: str, mac: str, hostname: str, ts: float, envelope: str = "5424") -> str:
    if fmt == "cef":
        body = cef(ext={"src": src, "dst": dst, "spt": 51234, "dpt": 22, "proto": "TCP", "act": "deny", "cs1Label": "zone", "cs1": "Guest->Mgmt"})
    elif fmt == "leef":
        body = leef(attrs={"src": src, "dst": dst, "srcPort": 51234, "dstPort": 22, "proto": "TCP", "action": "deny"})
    elif fmt == "kv":
        body = kv({"action": "deny", "src": src, "dst": dst, "dport": 22, "proto": "tcp"})
    elif fmt == "ec":
        body = ec_firewall(src=src, dst=dst)
    elif fmt == "isc":
        return rfc3164_message(dhcp_isc("DHCPACK", src, mac, hostname), ts=ts, host="dhcp1", tag="dhcpd", pid=1234)
    elif fmt == "kea":
        return rfc3164_message(dhcp_kea(src, mac, ts=ts), ts=ts, host="kea1", tag="kea-dhcp4", pid=1234)
    elif fmt == "windows":
        return rfc3164_message(dhcp_windows(10, src, mac, hostname, ts=ts), ts=ts, host="dc1", tag="DhcpSrvLog")
    elif fmt == "rfc5424":
        return rfc5424_message(kv({"action": "deny", "src": src, "dst": dst}), ts=ts, msgid="FW", sd={"exp@32473": {"zone": "Guest", "rule": "deny"}})
    else:
        raise ValueError(f"unknown format {fmt!r}")
    if envelope == "5424":
        return rfc5424_message(body, ts=ts, msgid="FW")
    if envelope == "3164":
        return rfc3164_message(body, ts=ts)
    return body


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--to", required=True, help="udp://host:port | tcp://host:port | tls://host:port")
    ap.add_argument("--format", default="cef", choices=("cef", "leef", "kv", "ec", "rfc5424", "isc", "kea", "windows"))
    ap.add_argument("--envelope", default="5424", choices=("5424", "3164", "none"))
    ap.add_argument("--framing", default="octet", choices=("octet", "newline"))
    ap.add_argument("--src", default="10.60.14.77")
    ap.add_argument("--dst", default="10.0.0.10")
    ap.add_argument("--mac", default="f0:18:98:aa:bb:01")
    ap.add_argument("--hostname", default="alices-iphone")
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--ca")
    args = ap.parse_args(argv)
    msgs = [build(args.format, src=args.src, dst=args.dst, mac=args.mac, hostname=args.hostname, ts=time.time(), envelope=args.envelope)
            for _ in range(args.count)]
    n = send(args.to, msgs, ca=args.ca, framing=args.framing)
    print(f"sent {n} message(s) to {args.to}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

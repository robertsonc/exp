"""The box-side path timer (12 section 4.2, SR-22): ICMP round trips from the core box to the configured gateway, the
edge (EdgeConnect LAN side), the hop one past the edge, and -- per test -- to the requesting client ONLY.

The ONLY targets that can ever be probed are ``allowed_targets()``: the configured/auto-discovered path hops plus the
observed address of a live session. ``PathTimer.ping_target`` refuses everything else with ``TargetNotAllowed``; no
route, header or body field names a target. gateway/edge/edge+1 are shared venue-infrastructure context; the figures are
idle samples on a schedule plus *loaded* samples taken while a test is moving bytes.

Mechanism (no ``CAP_NET_RAW``): an unprivileged ICMP datagram socket (``SOCK_DGRAM``/``IPPROTO_ICMP``), which needs
``net.ipv4.ping_group_range`` to include the service group. Fallback when the kernel refuses: the system ``ping``
binary run with an argv list (iputils ``ping`` carries its own capability) -- ``requirements.apt`` lists iputils-ping.
With neither, the path legs are simply empty and the box reports ``degraded`` in health.

``edge1: auto`` is found with a TTL-limited probe toward a fixed well-known address (never client-chosen): the first hop
whose time-exceeded reply comes from ``edge`` is hop N, the sender of hop N+1's reply is edge+1.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import select
import shutil
import socket
import statistics
import struct
import subprocess  # noqa: S404 - argv-only fallback to the system ping
import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Any

log = logging.getLogger(__name__)

TRACE_TARGET = "1.1.1.1"          # TTL-limited trace destination for edge1: fixed, packets never get past edge+1
TRACE_MAX_TTL = 12
WINDOW_S = 300.0
IDLE_INTERVAL_S = 5.0
LOADED_INTERVAL_S = 1.0
PING_TIMEOUT_S = 1.0
MAX_DEVICE_SAMPLES = 12
RING = 600
ICMP_ECHO, ICMP_ECHO_REPLY = 8, 0
IP_RECVERR = getattr(socket, "IP_RECVERR", 11)
MSG_ERRQUEUE = getattr(socket, "MSG_ERRQUEUE", 0x2000)
SO_EE_ORIGIN_ICMP = 2
ICMP_TIME_EXCEEDED = 11


class TargetNotAllowed(Exception):
    """A probe target outside the configured hops and the session clients (SR-22)."""


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_echo(ident: int, seq: int, payload: bytes = b"exp-speedtest") -> bytes:
    hdr = struct.pack("!BBHHH", ICMP_ECHO, 0, 0, ident & 0xFFFF, seq & 0xFFFF)
    csum = checksum(hdr + payload)
    return struct.pack("!BBHHH", ICMP_ECHO, 0, csum, ident & 0xFFFF, seq & 0xFFFF) + payload


def parse_extended_error(cmsg_data: bytes) -> tuple[int, int, int, str | None]:
    """``(origin, icmp_type, icmp_code, offender_ip)`` of a ``struct sock_extended_err`` (16 bytes) followed by the
    offender ``sockaddr_in``. Raises ValueError on a short buffer."""
    if len(cmsg_data) < 16:
        raise ValueError("short sock_extended_err")
    _errno, origin, typ, code, _pad, _info, _data = struct.unpack("=IBBBBII", cmsg_data[:16])
    off = None
    if len(cmsg_data) >= 16 + 8:
        fam = struct.unpack("=H", cmsg_data[16:18])[0]
        if fam == socket.AF_INET:
            off = socket.inet_ntoa(cmsg_data[20:24])
    return origin, typ, code, off


def default_gateway(path: str = "/proc/net/route") -> str | None:
    """The default route's gateway (lowest metric among 0.0.0.0/0 gateway routes), or None."""
    best: tuple[int, str] | None = None
    try:
        with open(path, encoding="ascii", errors="replace") as fh:
            next(fh, None)
            for line in fh:
                f = line.split()
                if len(f) < 8 or f[1] != "00000000" or f[7] != "00000000" or not int(f[3], 16) & 2:
                    continue
                gw = socket.inet_ntoa(struct.pack("<I", int(f[2], 16)))
                metric = int(f[6])
                if gw != "0.0.0.0" and (best is None or metric < best[0]):  # noqa: S104 - comparing, not binding
                    best = (metric, gw)
    except (OSError, ValueError, StopIteration):
        return None
    return best[1] if best else None


class IcmpPinger:
    """``ping(addr) -> rtt_ms | None`` and ``trace_hop(target, ttl) -> (hop_addr | None, reached)``."""

    def __init__(self, backend: str | None = None) -> None:
        self._seq = 0
        self._lock = threading.Lock()
        self.backend = backend or self._detect()

    @staticmethod
    def _detect() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
            s.close()
            return "dgram"
        except OSError:
            pass
        if shutil.which("ping"):
            return "ping"
        return "none"

    def _next_seq(self) -> int:
        with self._lock:
            self._seq = (self._seq + 1) & 0xFFFF
            return self._seq

    def ping(self, addr: str, timeout: float = PING_TIMEOUT_S) -> float | None:
        ipaddress.IPv4Address(addr)                               # literal IPv4 only (argv safety)
        if self.backend == "dgram":
            return self._ping_dgram(addr, timeout)
        if self.backend == "ping":
            return self._ping_binary(addr, timeout)
        return None

    def _ping_dgram(self, addr: str, timeout: float) -> float | None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        except OSError:
            return None
        try:
            seq = self._next_seq()
            pkt = build_echo(0, seq)
            t0 = time.monotonic()
            s.sendto(pkt, (addr, 0))
            while True:
                left = timeout - (time.monotonic() - t0)
                if left <= 0:
                    return None
                r, _, _ = select.select([s], [], [], left)
                if not r:
                    return None
                data, src = s.recvfrom(1024)
                rtt = (time.monotonic() - t0) * 1000.0
                if src[0] == addr and len(data) >= 8 and data[0] == ICMP_ECHO_REPLY and struct.unpack("!H", data[6:8])[0] == seq:
                    return round(rtt, 3)
        except OSError:
            return None
        finally:
            s.close()

    _TIME_RE = re.compile(r"time[=<]([0-9.]+) ?ms")

    def _ping_binary(self, addr: str, timeout: float) -> float | None:
        exe = shutil.which("ping")
        if exe is None:
            return None
        try:
            out = subprocess.run([exe, "-n", "-c", "1", "-W", str(max(1, int(timeout + 0.5))), addr],  # noqa: S603
                                 capture_output=True, text=True, timeout=timeout + 2, check=False).stdout
        except (OSError, subprocess.SubprocessError):
            return None
        m = self._TIME_RE.search(out)
        return round(float(m.group(1)), 3) if m else None

    def trace_hop(self, target: str, ttl: int, timeout: float = 1.5) -> tuple[str | None, bool]:
        """Send one echo to ``target`` with the given TTL; return ``(responder, reached_target)``."""
        ipaddress.IPv4Address(target)
        if self.backend == "dgram":
            return self._trace_dgram(target, ttl, timeout)
        if self.backend == "ping":
            return self._trace_binary(target, ttl, timeout)
        return None, False

    def _trace_dgram(self, target: str, ttl: int, timeout: float) -> tuple[str | None, bool]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        except OSError:
            return None, False
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            s.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
            seq = self._next_seq()
            s.sendto(build_echo(0, seq), (target, 0))
            poll = select.poll()
            poll.register(s, select.POLLIN | select.POLLERR)
            deadline = time.monotonic() + timeout
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    return None, False
                events = poll.poll(left * 1000)
                if not events:
                    return None, False
                if events[0][1] & select.POLLERR:
                    try:
                        _d, anc, _f, _a = s.recvmsg(256, 512, MSG_ERRQUEUE)
                    except OSError:
                        return None, False
                    for level, typ, data in anc:
                        if level == socket.SOL_IP and typ == IP_RECVERR:
                            origin, icmp_type, _code, off = parse_extended_error(data)
                            if origin == SO_EE_ORIGIN_ICMP and icmp_type == ICMP_TIME_EXCEEDED:
                                return off, False
                    continue
                data, src = s.recvfrom(1024)
                if len(data) >= 8 and data[0] == ICMP_ECHO_REPLY:
                    return src[0], True
        except OSError:
            return None, False
        finally:
            s.close()

    _FROM_RE = re.compile(r"[Ff]rom (\d{1,3}(?:\.\d{1,3}){3})")

    def _trace_binary(self, target: str, ttl: int, timeout: float) -> tuple[str | None, bool]:
        exe = shutil.which("ping")
        if exe is None:
            return None, False
        try:
            r = subprocess.run([exe, "-n", "-c", "1", "-t", str(int(ttl)), "-W", str(max(1, int(timeout + 0.5))), target],  # noqa: S603
                               capture_output=True, text=True, timeout=timeout + 2, check=False)
        except (OSError, subprocess.SubprocessError):
            return None, False
        m = self._FROM_RE.search(r.stdout)
        if r.returncode == 0:
            return target, True
        return (m.group(1), False) if m else (None, False)


class PathTimer:
    """Samples the hops and watched session clients; answers ``snapshot``."""

    def __init__(self, *, gateway: str | None, edge: str | None, edge1: str | None, pinger: Any,
                 loaded: Callable[[], bool] = lambda: False, clock: Callable[[], float] = time.time,
                 default_gw: Callable[[], str | None] = default_gateway, trace_target: str = TRACE_TARGET) -> None:
        self._gateway_cfg, self._edge, self._edge1_cfg = gateway, edge, edge1
        self.pinger, self.loaded, self.clock = pinger, loaded, clock
        self._default_gw = default_gw
        self.trace_target = trace_target
        self._gw: str | None = None if gateway == "auto" else gateway
        self._gw_checked = 0.0
        self._edge1: str | None = None if edge1 in (None, "auto") else edge1
        self._edge1_checked = 0.0
        self._samples: dict[str, deque[tuple[float, float | None, bool]]] = {
            k: deque(maxlen=RING) for k in ("gateway", "edge", "edge1")}
        self._devices: dict[str, dict[str, Any]] = {}          # session id -> {ip, rtts, watching}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.probes_sent = 0

    # ------------------------------------------------------------------------------------ allowlist (SR-22)
    def hop_addresses(self) -> dict[str, str | None]:
        return {"gateway": self._gw, "edge": self._edge, "edge1": self._edge1}

    def allowed_targets(self) -> set[str]:
        with self._lock:
            devs = {d["ip"] for d in self._devices.values()}
        return {a for a in self.hop_addresses().values() if a} | devs

    def ping_target(self, addr: str) -> float | None:
        """The only way to send a probe. Refuses any address that is not a configured hop or a live session's client."""
        if addr not in self.allowed_targets():
            raise TargetNotAllowed(addr)
        self.probes_sent += 1
        return self.pinger.ping(addr)

    # ------------------------------------------------------------------------------------------ sessions
    def watch_device(self, session_id: str, ip: str) -> None:
        with self._lock:
            self._devices[session_id] = {"ip": ip, "rtts": [], "tries": 0}
            if len(self._devices) > 256:
                self._devices.pop(next(iter(self._devices)))

    def unwatch_device(self, session_id: str) -> None:
        with self._lock:
            d = self._devices.get(session_id)
            if d is not None:
                d["done"] = True

    def forget_device(self, session_id: str) -> None:
        with self._lock:
            self._devices.pop(session_id, None)

    def device_icmp_ms(self, session_id: str) -> float | None:
        with self._lock:
            d = self._devices.get(session_id)
            rtts = list(d["rtts"]) if d else []
        return round(statistics.median(rtts), 3) if rtts else None

    # --------------------------------------------------------------------------------------------- cycle
    def _discover(self) -> None:
        now = self.clock()
        if self._gateway_cfg == "auto" and (self._gw is None or now - self._gw_checked > 60):
            self._gw, self._gw_checked = self._default_gw(), now
        if self._edge1_cfg == "auto" and self._edge1 is None and self._edge and now - self._edge1_checked > 300:
            self._edge1_checked = now
            self._edge1 = self._trace_edge1()

    def _trace_edge1(self) -> str | None:
        edge_ttl = None
        for ttl in range(1, TRACE_MAX_TTL):
            hop, reached = self.pinger.trace_hop(self.trace_target, ttl)
            if reached:
                return None
            if hop == self._edge:
                edge_ttl = ttl
                break
        if edge_ttl is None:
            return None
        hop, reached = self.pinger.trace_hop(self.trace_target, edge_ttl + 1)
        return hop if hop and hop != self._edge and not reached else None

    def sample_once(self) -> None:
        """One cycle: refresh hop addresses, ping each hop once, ping each watched client once."""
        self._discover()
        loaded = bool(self.loaded())
        now = self.clock()
        for name, addr in self.hop_addresses().items():
            if not addr:
                continue
            try:
                rtt = self.ping_target(addr)
            except TargetNotAllowed:                    # cannot happen for a hop; kept as the invariant
                continue
            with self._lock:
                self._samples[name].append((now, rtt, loaded))
        with self._lock:
            todo = [(sid, d["ip"]) for sid, d in self._devices.items()
                    if not d.get("done") and d["tries"] < MAX_DEVICE_SAMPLES * 2 and len(d["rtts"]) < MAX_DEVICE_SAMPLES]
        for sid, ip in todo:
            try:
                rtt = self.ping_target(ip)
            except TargetNotAllowed:
                continue
            with self._lock:
                d = self._devices.get(sid)
                if d is not None:
                    d["tries"] += 1
                    if rtt is not None:
                        d["rtts"].append(rtt)

    def _hop_summary(self, name: str, since: float | None) -> dict[str, Any]:
        cutoff = self.clock() - WINDOW_S
        with self._lock:
            rows = [(t, r, ld) for t, r, ld in self._samples[name] if t >= cutoff and r is not None]
        idle = [r for _t, r, ld in rows if not ld]
        loaded = [r for t, r, ld in rows if ld and (since is None or t >= since)]
        return {"idle": round(statistics.median(idle), 3) if idle else None,
                "loaded": round(statistics.median(loaded), 3) if loaded else None,
                "samples": len(idle) + len(loaded)}

    def snapshot(self, session_id: str | None = None, since: float | None = None) -> dict[str, Any]:
        """A speedtest.schema.json ``path_leg`` document."""
        return {"gateway_ms": self._hop_summary("gateway", since), "edge_ms": self._hop_summary("edge", since),
                "edge1_ms": self._hop_summary("edge1", since), "edge1_addr": self._edge1,
                "device_icmp_ms": self.device_icmp_ms(session_id) if session_id else None}

    # -------------------------------------------------------------------------------------------- thread
    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="path-timer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self) -> None:
        while not self._stop.is_set():
            t0 = time.monotonic()
            try:
                self.sample_once()
            except Exception:
                log.exception("path timer cycle failed")
            interval = LOADED_INTERVAL_S if self.loaded() or self._devices_pending() else IDLE_INTERVAL_S
            self._stop.wait(max(0.1, interval - (time.monotonic() - t0)))

    def _devices_pending(self) -> bool:
        with self._lock:
            return any(not d.get("done") and len(d["rtts"]) < MAX_DEVICE_SAMPLES and d["tries"] < MAX_DEVICE_SAMPLES * 2
                       for d in self._devices.values())


def backend_ok(pinger: IcmpPinger) -> bool:
    return pinger.backend != "none" and (pinger.backend != "dgram" or os.path.exists("/proc/sys/net/ipv4/ping_group_range"))

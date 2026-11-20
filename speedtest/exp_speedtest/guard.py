"""Core-bandwidth guard and throughput meter (12 section 4.4).

With one box at the core every on-network download crosses the access and core links, so the per-test byte cap shrinks
while the core-facing interface is busy: at or below ``util_pct`` the full ``bytes_local`` applies; above it the cap
falls linearly to ``min_bytes`` at 100 % utilization. Utilization = max(rx, tx) rate of ``core_guard.iface`` (from
``/proc/self/net/dev`` (the same table as ``/proc/net/dev``, but visible under ``ProcSubset=pid``) over the link
speed (``/sys/class/net/<iface>/speed``; an unknown speed assumes 1 Gb/s, the conservative choice for a core link).
The guard is advisory input to byte budgeting, never a gate on the page itself.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Callable

log = logging.getLogger(__name__)

ASSUMED_LINK_MBPS = 1000.0
EWMA = 0.5


def read_proc_net_dev(iface: str, path: str = "/proc/self/net/dev") -> tuple[int, int] | None:
    """``(rx_bytes, tx_bytes)`` of ``iface``, or None when it is absent / unreadable."""
    try:
        with open(path, encoding="ascii", errors="replace") as fh:
            for line in fh:
                name, sep, rest = line.partition(":")
                if sep and name.strip() == iface:
                    f = rest.split()
                    return int(f[0]), int(f[8])
    except (OSError, ValueError, IndexError):
        return None
    return None


def read_link_mbps(iface: str, base: str = "/sys/class/net") -> float:
    try:
        with open(f"{base}/{iface}/speed", encoding="ascii") as fh:
            v = float(fh.read().strip())
        if v > 0:
            return v
    except (OSError, ValueError):
        pass
    return ASSUMED_LINK_MBPS


class CoreGuard:
    def __init__(self, iface: str | None, util_pct: float, cap_bytes: int, min_bytes: int, *,
                 read_counters: Callable[[str], tuple[int, int] | None] = read_proc_net_dev,
                 link_mbps: Callable[[str], float] = read_link_mbps,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.iface, self.util_pct, self.cap_bytes, self.min_bytes = iface, float(util_pct), cap_bytes, min(min_bytes, cap_bytes)
        self._read, self._speed, self.clock = read_counters, link_mbps, clock
        self._last: tuple[float, int, int] | None = None
        self.utilization_pct: float | None = None
        self.available = iface is not None
        self._lock = threading.Lock()

    def sample(self) -> None:
        """Take one counter sample (called about once a second by the housekeeper)."""
        if not self.iface:
            return
        cur = self._read(self.iface)
        now = self.clock()
        with self._lock:
            if cur is None:
                self.available = False
                self.utilization_pct = None
                self._last = None
                return
            self.available = True
            if self._last is not None and now > self._last[0]:
                dt = now - self._last[0]
                rate_mbps = max(0, cur[0] - self._last[1], cur[1] - self._last[2]) * 8 / dt / 1e6
                util = min(100.0, 100.0 * rate_mbps / max(1.0, self._speed(self.iface)))
                self.utilization_pct = util if self.utilization_pct is None else EWMA * util + (1 - EWMA) * self.utilization_pct
            self._last = (now, cur[0], cur[1])

    def set_utilization(self, pct: float | None) -> None:
        """Test hook / external source."""
        with self._lock:
            self.utilization_pct = pct

    def effective_cap(self) -> int:
        """The per-test on-network byte cap right now."""
        with self._lock:
            u = self.utilization_pct
        if u is None or u <= self.util_pct or self.util_pct >= 100:
            return self.cap_bytes
        frac = max(0.0, 1.0 - (u - self.util_pct) / (100.0 - self.util_pct))
        return max(self.min_bytes, int(self.min_bytes + (self.cap_bytes - self.min_bytes) * frac))


class ThroughputMeter:
    """Aggregate box throughput: a monotonically increasing byte counter sampled once a second into a ring of Gb/s
    values (only seconds with traffic), for the ``local_leg_gbps_p95`` health metric."""

    def __init__(self, clock: Callable[[], float] = time.time, keep_s: int = 3600) -> None:
        self.clock = clock
        self.keep_s = keep_s
        self._bytes = 0
        self._last_bytes = 0
        self._last_t: float | None = None
        self._samples: deque[tuple[float, float]] = deque(maxlen=keep_s)
        self._lock = threading.Lock()

    def add(self, n: int) -> None:
        with self._lock:
            self._bytes += n

    def total(self) -> int:
        return self._bytes

    def sample(self) -> None:
        now = self.clock()
        with self._lock:
            if self._last_t is not None and now > self._last_t:
                delta = self._bytes - self._last_bytes
                if delta > 0:
                    self._samples.append((now, delta * 8 / (now - self._last_t) / 1e9))
            self._last_t, self._last_bytes = now, self._bytes

    def p95_gbps(self) -> float:
        with self._lock:
            cutoff = self.clock() - self.keep_s
            vals = sorted(v for t, v in self._samples if t >= cutoff)
        if not vals:
            return 0.0
        return round(vals[min(len(vals) - 1, int(0.95 * len(vals)))], 4)

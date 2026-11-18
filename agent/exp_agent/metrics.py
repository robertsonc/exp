"""Host and process metrics (01-contracts.md section 8, 06-agent.md section 3.1).

Read from /proc and /sys (cheap, no subprocess except `systemctl show`). Rates are deltas between two
reports: the first report after a start has `null` rates, and a counter that went DOWN (reboot, link or
unit reset) yields `null` for that interval -- never a negative number.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from .context import Context
from .facts import read_text

log = logging.getLogger(__name__)

_DISK_RE = re.compile(r"(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+)\Z")
_U64_MAX = 2**64 - 1
_IFACE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,15}\Z")


def _delta(cur: float | int | None, prev: float | int | None) -> float | None:
    """cur - prev, or None when either is missing or the counter went backwards."""
    if cur is None or prev is None or cur < prev:
        return None
    return cur - prev


def _rate(d: float | None, dt: float, scale: float = 1.0) -> float | None:
    return None if d is None or dt <= 0 else round(d * scale / dt, 3)


def _int(d: float | None) -> int | None:
    return None if d is None else int(d)


class HostMetrics:
    """Stateful collector: keep one instance for the life of the agent process."""

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self._prev: dict[str, Any] = {}
        self._prev_t: float | None = None
        self._unit_prev: dict[str, tuple[int, float]] = {}

    # ---------------------------------------------------------------- readers
    def _cpu(self) -> dict[str, int] | None:
        text = read_text(self.ctx.paths.proc / "stat")
        if not text:
            return None
        for line in text.splitlines():
            if line.startswith("cpu "):
                f = [int(x) for x in line.split()[1:] if x.isdigit()]
                if len(f) < 4:
                    return None
                f += [0] * (10 - len(f))
                user, nice, system, idle, iowait, irq, softirq, steal = f[:8]
                return {
                    "total": user + nice + system + idle + iowait + irq + softirq + steal,
                    "idle": idle,
                    "iowait": iowait,
                    "steal": steal,
                }
        return None

    def _mem(self) -> dict[str, Any]:
        kv: dict[str, int] = {}
        for line in (read_text(self.ctx.paths.proc / "meminfo") or "").splitlines():
            k, _, rest = line.partition(":")
            parts = rest.split()
            if parts and parts[0].isdigit():
                kv[k] = int(parts[0])
        total = kv.get("MemTotal", 0)
        avail = kv.get("MemAvailable", kv.get("MemFree", 0))
        used = max(0, total - avail)
        mb = 1024.0
        return {
            "total_mb": round(total / mb, 1),
            "used_mb": round(used / mb, 1),
            "available_mb": round(avail / mb, 1),
            "pct": round(100.0 * used / total, 1) if total else 0.0,
            "swap_used_mb": round(max(0, kv.get("SwapTotal", 0) - kv.get("SwapFree", 0)) / mb, 1),
        }

    def _loadavg(self) -> tuple[float | None, float | None, float | None]:
        parts = (read_text(self.ctx.paths.proc / "loadavg") or "").split()
        try:
            return float(parts[0]), float(parts[1]), float(parts[2])
        except (IndexError, ValueError):
            return None, None, None

    def _uptime(self) -> float | None:
        parts = (read_text(self.ctx.paths.proc / "uptime") or "").split()
        try:
            return float(parts[0])
        except (IndexError, ValueError):
            return None

    def _mounts(self) -> list[str]:
        """ "/" plus the mount holding /var/lib/exp (longest prefix in mountinfo), deduplicated."""
        best = "/"
        for line in (read_text(self.ctx.paths.proc / "self" / "mountinfo", 1 << 20) or "").splitlines():
            f = line.split()
            if len(f) > 4:
                mp = f[4].replace("\\040", " ")
                if ("/var/lib/exp" == mp or "/var/lib/exp".startswith(mp.rstrip("/") + "/")) and len(
                    mp
                ) > len(best):
                    best = mp
        return ["/"] if best == "/" else ["/", best]

    def _disks(self) -> list[dict[str, Any]]:
        out = []
        for mount in self._mounts():
            p = self.ctx.paths.host(mount)
            try:
                st = os.statvfs(p)
            except OSError:
                continue
            total = st.f_blocks * st.f_frsize
            used = (st.f_blocks - st.f_bfree) * st.f_frsize
            gb = 1024.0**3
            out.append(
                {
                    "mount": mount,
                    "total_gb": round(total / gb, 2),
                    "used_gb": round(used / gb, 2),
                    "pct": round(100.0 * used / total, 1) if total else 0.0,
                }
            )
        return out

    def _diskstats(self) -> tuple[int, int] | None:
        text = read_text(self.ctx.paths.proc / "diskstats", 1 << 20)
        if text is None:
            return None
        rd = wr = 0
        for line in text.splitlines():
            f = line.split()
            if len(f) >= 10 and _DISK_RE.match(f[2]) and f[5].isdigit() and f[9].isdigit():
                rd += int(f[5])
                wr += int(f[9])
        return rd * 512, wr * 512

    def _net_counters(self) -> dict[str, dict[str, int]]:
        base = self.ctx.paths.sys / "class" / "net"
        out: dict[str, dict[str, int]] = {}
        try:
            names = sorted(os.listdir(base))
        except OSError:
            return out
        for name in names:
            if name == "lo" or not _IFACE_RE.match(name):
                continue
            c: dict[str, int] = {}
            for key in (
                "rx_packets",
                "tx_packets",
                "rx_bytes",
                "tx_bytes",
                "rx_errors",
                "tx_errors",
                "rx_dropped",
                "tx_dropped",
            ):
                v = (read_text(base / name / "statistics" / key, 32) or "").strip()
                if v.isdigit():
                    c[key] = int(v)
            out[name] = c
        return out

    def _temp(self) -> float | None:
        base = self.ctx.paths.sys / "class" / "thermal"
        best: float | None = None
        try:
            zones = sorted(d for d in os.listdir(base) if d.startswith("thermal_zone"))
        except OSError:
            return None
        for z in zones:
            v = (read_text(base / z / "temp", 32) or "").strip().lstrip("-")
            if v.isdigit():
                t = int(v) / 1000.0
                best = t if best is None else max(best, t)
        return None if best is None else round(best, 1)

    # ---------------------------------------------------------------- collect
    def collect(self, interval_s: int, roles: dict[str, str] | None = None) -> dict[str, Any]:
        now = self.ctx.monotonic()
        dt = (now - self._prev_t) if self._prev_t is not None else 0.0
        first = self._prev_t is None or dt <= 0
        roles = roles or {}

        cpu = self._cpu()
        pcpu = self._prev.get("cpu")
        cpu_out: dict[str, Any] = {"pct": None, "iowait_pct": None, "steal_pct": None}
        if cpu and pcpu and not first:
            dtot = _delta(cpu["total"], pcpu["total"])
            if dtot and dtot > 0:
                didle, diow, dst = (
                    _delta(cpu["idle"], pcpu["idle"]),
                    _delta(cpu["iowait"], pcpu["iowait"]),
                    _delta(cpu["steal"], pcpu["steal"]),
                )
                if didle is not None and diow is not None:
                    cpu_out["pct"] = round(max(0.0, 100.0 * (dtot - didle - diow) / dtot), 1)
                    cpu_out["iowait_pct"] = round(100.0 * diow / dtot, 1)
                if dst is not None:
                    cpu_out["steal_pct"] = round(100.0 * dst / dtot, 1)
        l1, l5, l15 = self._loadavg()
        cpu_out.update({"load1": l1, "load5": l5, "load15": l15})

        io = self._diskstats()
        pio = self._prev.get("io")
        io_out: dict[str, Any] = {"read_kbps": None, "write_kbps": None}
        if io and pio and not first:
            io_out["read_kbps"] = _rate(_delta(io[0], pio[0]), dt, 1 / 1024)
            io_out["write_kbps"] = _rate(_delta(io[1], pio[1]), dt, 1 / 1024)

        net_now = self._net_counters()
        net_prev = self._prev.get("net", {})
        net_out: list[dict[str, Any]] = []
        for name, c in net_now.items():
            p = net_prev.get(name, {}) if not first else {}
            oper = (read_text(self.ctx.paths.sys / "class" / "net" / name / "operstate", 16) or "").strip()
            sp = (
                (read_text(self.ctx.paths.sys / "class" / "net" / name / "speed", 16) or "")
                .strip()
                .lstrip("-")
            )
            speed: int | None = int(sp) if sp.isdigit() and int(sp) > 0 else None
            d = {k: _delta(c.get(k), p.get(k)) for k in c}
            net_out.append(
                {
                    "iface": name,
                    "role": roles.get(name, "none")[:32],
                    "link": {"up": "up", "down": "down"}.get(oper, "unknown"),
                    "speed_mbps": speed,
                    "rx_pps": _rate(d.get("rx_packets"), dt),
                    "tx_pps": _rate(d.get("tx_packets"), dt),
                    "rx_bps": _rate(d.get("rx_bytes"), dt, 8.0),
                    "tx_bps": _rate(d.get("tx_bytes"), dt, 8.0),
                    "rx_errors": _int(d.get("rx_errors")),
                    "tx_errors": _int(d.get("tx_errors")),
                    "rx_drops": _int(d.get("rx_dropped")),
                    "tx_drops": _int(d.get("tx_dropped")),
                }
            )

        self._prev = {"cpu": cpu, "io": io, "net": net_now}
        self._prev_t = now
        return {
            "interval_s": int(interval_s),
            "uptime_s": self._uptime(),
            "cpu": cpu_out,
            "mem": self._mem(),
            "disk": self._disks(),
            "disk_io": io_out,
            "net": net_out[:256],
            "temp_c_max": self._temp(),
        }

    # ---------------------------------------------------------------- per component process metrics
    def process(self, units: list[str]) -> dict[str, Any]:
        """Summed over the component's units via `systemctl show`. cpu_pct is null on the first look at
        a unit and after a counter reset (CPUUsageNSec going down)."""
        ctx = self.ctx
        now = ctx.monotonic()
        cpu_pct: float | None = 0.0
        rss = 0
        have_rss = False
        restarts = 0
        have_restarts = False
        uptimes: list[float] = []
        mono = self._uptime()
        for u in units:
            kv = ctx.sysctl.show(
                u,
                [
                    "CPUUsageNSec",
                    "MemoryCurrent",
                    "NRestarts",
                    "ActiveEnterTimestampMonotonic",
                    "ActiveState",
                ],
            )
            ns = _num(kv.get("CPUUsageNSec"))
            prev = self._unit_prev.get(u)
            if ns is None:
                cpu_pct = None
            else:
                self._unit_prev[u] = (ns, now)
                if prev is None or ns < prev[0] or now - prev[1] <= 0 or cpu_pct is None:
                    cpu_pct = None
                else:
                    cpu_pct += 100.0 * (ns - prev[0]) / 1e9 / (now - prev[1])
            mem = _num(kv.get("MemoryCurrent"))
            if mem is not None:
                rss += mem
                have_rss = True
            nr = _num(kv.get("NRestarts"))
            if nr is not None:
                restarts += nr
                have_restarts = True
            am = _num(kv.get("ActiveEnterTimestampMonotonic"))
            if am and mono is not None and kv.get("ActiveState") == "active":
                uptimes.append(max(0.0, mono - am / 1e6))
        return {
            "cpu_pct": round(cpu_pct, 1) if cpu_pct is not None and units else None,
            "rss_mb": round(rss / 1048576, 1) if have_rss else None,
            "restarts": restarts if have_restarts else None,
            "uptime_s": round(min(uptimes), 1) if uptimes else None,
        }


def _num(v: str | None) -> int | None:
    if v is None or not v.isdigit():
        return None
    n = int(v)
    return None if n >= _U64_MAX else n

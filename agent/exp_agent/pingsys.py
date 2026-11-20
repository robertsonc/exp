"""Unprivileged ICMP for the speedtest box (M6): an agent-managed, SCOPED sysctl drop-in.

`exp-speedtest` times the venue path (gateway / edge / edge+1) with ICMP echo over unprivileged datagram
ICMP sockets instead of holding CAP_NET_RAW (its unit grants CAP_NET_BIND_SERVICE only). Those sockets
work only for groups inside `net.ipv4.ping_group_range`. Most distributions already cover every group (`0
2147483647`); then the agent changes nothing. Otherwise it writes ONE drop-in, `/etc/sysctl.d/60-exp-
speedtest-ping.conf`, that widens the range by the minimum needed to include the `exp-speedtest` group
(an empty range becomes exactly that group), applies it with `sysctl -w`, and remembers the ORIGINAL
range in the file's own header so decommission (and removing the speedtest component) can delete the file
and put the original value back. Nothing else in /etc/sysctl.d is ever touched (the path guard allows
exactly this one file)."""

from __future__ import annotations

import logging
import os
import re

from .context import Context
from .errors import AgentError

log = logging.getLogger(__name__)

KEY = "net.ipv4.ping_group_range"
SERVICE_USER = "exp-speedtest"
_RANGE_RE = re.compile(r"\s*([0-9]{1,10})\s+([0-9]{1,10})\s*\Z")
_ORIG_RE = re.compile(r"^# exp-original: ([0-9]{1,10}) ([0-9]{1,10})$", re.M)
MAX_BYTES = 4096


def _live_path(ctx: Context):
    return ctx.paths.proc / "sys" / "net" / "ipv4" / "ping_group_range"


def read_live(ctx: Context) -> tuple[int, int] | None:
    try:
        with open(_live_path(ctx), "rb") as fh:
            raw = fh.read(256).decode("ascii", "replace")
    except OSError:
        return None
    m = _RANGE_RE.match(raw)
    return (int(m.group(1)), int(m.group(2))) if m else None


def _recorded_original(ctx: Context) -> tuple[int, int] | None:
    raw = ctx.fs.read_bytes(ctx.paths.sysctl_dropin, MAX_BYTES)
    if raw is None:
        return None
    m = _ORIG_RE.search(raw.decode("utf-8", "replace"))
    return (int(m.group(1)), int(m.group(2))) if m else None


def covers(rng: tuple[int, int], gid: int) -> bool:
    return rng[0] <= gid <= rng[1]


def wanted_range(orig: tuple[int, int], gid: int) -> tuple[int, int]:
    """Smallest widening of `orig` that contains `gid` (an empty range, lo > hi, becomes exactly gid)."""
    if orig[0] > orig[1]:
        return gid, gid
    return min(orig[0], gid), max(orig[1], gid)


def render(orig: tuple[int, int], want: tuple[int, int]) -> str:
    return (
        "# Managed by exp-agent for exp-speedtest (unprivileged ICMP sockets for the path timer).\n"
        "# Removed again when the speedtest component or the agent is decommissioned.\n"
        f"# exp-original: {orig[0]} {orig[1]}\n"
        f"{KEY} = {want[0]} {want[1]}\n"
    )


def _apply(ctx: Context, rng: tuple[int, int]) -> None:
    res = ctx.runner.run(["sysctl", "-w", f"{KEY}={rng[0]} {rng[1]}"], timeout=20)
    if res.rc != 0:
        raise AgentError(f"sysctl {KEY} failed: {(res.stderr or res.stdout).strip()[-160:]}")


def ensure(ctx: Context, gid: int) -> bool:
    """Make `gid` a member of ping_group_range, scoped and reversible. True if anything changed.
    Failures are logged and reported as an agent event, never fatal: the speedtest falls back to `ping`."""
    fs = ctx.fs
    try:
        live = read_live(ctx)
        orig = _recorded_original(ctx) or live
        if orig is None:
            log.warning("cannot read %s; leaving it alone (the speedtest falls back to ping)", KEY)
            return False
        if covers(orig, gid):
            return revert(ctx) if fs.exists(ctx.paths.sysctl_dropin) else False
        want = wanted_range(orig, gid)
        text = render(orig, want)
        changed = False
        if fs.read_bytes(ctx.paths.sysctl_dropin, MAX_BYTES) != text.encode("utf-8"):
            os.makedirs(
                ctx.paths.sysctl_dropin.parent, mode=0o755, exist_ok=True
            )  # fixed path; exists on real hosts
            fs.write(ctx.paths.sysctl_dropin, text, 0o644)
            changed = True
        if live != want:
            _apply(ctx, want)
            changed = True
        return changed
    except (AgentError, OSError) as exc:
        log.warning("ping_group_range setup failed: %s", exc)
        ctx.state.event("warn", f"unprivileged ICMP setup for the speedtest failed: {exc}")
        return False


def revert(ctx: Context) -> bool:
    """Delete the drop-in and restore the recorded original range. True if a drop-in was removed."""
    fs = ctx.fs
    try:
        if not fs.exists(ctx.paths.sysctl_dropin):
            return False
        orig = _recorded_original(ctx)
        fs.remove(ctx.paths.sysctl_dropin)
        live = read_live(ctx)
        if orig is not None and live is not None and live != orig:
            _apply(ctx, orig)
        return True
    except (AgentError, OSError) as exc:
        log.warning("reverting ping_group_range failed: %s", exc)
        return True

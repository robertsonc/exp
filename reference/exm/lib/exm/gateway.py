"""Network heartbeat: link and one gateway ping on every port, every few seconds.

The slower tests (DHCP, DNS, apps) each come round every few minutes per port.
This one is cheap enough to run every 10 s, so "is the network stable?" has a
real heartbeat: one event per run covering every port, client and server alike.

Per port it reads the carrier state and the kernel's carrier_changes counter
(so a link that dropped and came back between runs is still caught), then sends
a single ping to the port's gateway. The event is ok when every port passed,
degraded when some failed, and fail when half or more failed.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import re

from . import config as C
from . import events
from . import netns

RTT = re.compile(r"time=([\d.]+) ms")


def _gateway_of(cfg: dict, c: dict) -> str | None:
    if c.get("role") == "server":
        return c.get("gateway") or None
    try:
        with open(C.state_path(cfg, f"{c['id']}.lease.json")) as fh:
            lease = json.load(fh)
        if lease.get("state") == "bound" and lease.get("router"):
            return lease["router"][0]
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    for r in netns.ip_json(["route", "show", "default"], C.ns_name(c["id"])):
        if r.get("gateway"):
            return r["gateway"]
    return None


def _check(cfg: dict, c: dict, timeout_s: float) -> dict:
    ns, iface = C.ns_name(c["id"]), c["iface"]
    if not netns.netns_exists(ns):
        return {"ok": False, "error": "no namespace"}
    gw = _gateway_of(cfg, c)
    script = (f"cat /sys/class/net/{iface}/carrier /sys/class/net/{iface}/carrier_changes 2>/dev/null; "
              + (f"ping -n -c 1 -W {max(1, int(round(timeout_s)))} -I {iface} {gw}" if gw else "true"))
    r = netns.sh(["ip", "netns", "exec", ns, "sh", "-c", script], check=False)
    lines = r.stdout.splitlines()
    carrier = bool(lines) and lines[0].strip() == "1"
    changes = int(lines[1]) if len(lines) > 1 and lines[1].strip().isdigit() else None
    res = {"carrier": carrier, "carrier_changes": changes, "gateway": gw, "rtt_ms": None, "ok": False}
    if not carrier:
        res["error"] = "no link"
        return res
    if not gw:
        res["error"] = "no gateway (no lease)"
        return res
    m = RTT.search(r.stdout)
    if m:
        res["rtt_ms"] = float(m.group(1))
        res["ok"] = True
    else:
        res["error"] = f"no reply from {gw}"
    return res


def run(cfg: dict) -> dict:
    g = cfg.get("gateway", {})
    timeout_s = float(g.get("timeout_s", 1))
    slow_ms = float(g.get("degraded_ms", 20))
    ports = list(cfg["client"])
    prev_path = C.state_path(cfg, "gateway.prev.json")
    try:
        with open(prev_path) as fh:
            prev = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        prev = {}
    ev = events.make(cfg, None, "gateway", target="all ports")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(ports))) as pool:
        results = dict(zip((c["id"] for c in ports), pool.map(lambda c: _check(cfg, c, timeout_s), ports)))
    flapped, slow = [], []
    for cid, res in results.items():
        before, now = prev.get(cid), res.get("carrier_changes")
        if res["carrier"] and before is not None and now is not None and now > before:
            res["flaps"] = (now - before + 1) // 2         # each drop-and-recover is two transitions
            flapped.append(cid)
        if res.get("rtt_ms") is not None and res["rtt_ms"] > slow_ms:
            slow.append(cid)
    with open(prev_path + ".tmp", "w") as fh:
        json.dump({cid: r.get("carrier_changes") for cid, r in results.items()}, fh)
    os.replace(prev_path + ".tmp", prev_path)

    down = [cid for cid, r in results.items() if not r["ok"]]
    total = len(results)
    ev["value"] = {"ports": results, "up": total - len(down), "total": total, "down": down,
                   "flapped": flapped, "slow": slow}
    rtts = [r["rtt_ms"] for r in results.values() if r.get("rtt_ms") is not None]
    ev["phase_ms"] = {"rtt_p50": events.median(rtts), "rtt_max": max(rtts) if rtts else None}
    if total == 0:
        ev["outcome"], ev["error"] = C.HARNESS, "no ports configured"
    elif len(down) * 2 >= total:
        ev["outcome"] = C.FAIL
    elif down or flapped or slow:
        ev["outcome"] = C.DEGRADED
    else:
        ev["outcome"] = C.OK
    problems = [f"{cid} {results[cid].get('error')}" for cid in down] + [f"{cid} link dropped and recovered" for cid in flapped if cid not in down]
    if problems:
        ev["error"] = "; ".join(problems)[:300]
    events.emit(cfg, ev, f"gateway {total - len(down)}/{total} ports up, rtt p50 {ev['phase_ms']['rtt_p50']}ms "
                         f"outcome={ev['outcome']}" + (f" problems={ev['error']}" if problems else ""))
    return ev

"""DHCP lease holder: the busybox udhcpc command line and its event hook.

udhcpc runs inside the client namespace and calls this hook with an event name
and the lease in environment variables. The hook configures only the client's
own namespace: address, default route, MTU and the namespace's resolv.conf.
It never touches the host's resolver.
"""
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys

from . import config as C
from . import events
from . import netns

HOOK = os.path.join(C.EXM_HOME, "hooks", "udhcpc-hook")


def udhcpc_argv(cfg: dict, client: dict) -> list[str]:
    d = cfg["dhcp"]
    hostname = f"{d.get('hostname_prefix', 'exm')}-{client['id']}"
    return [
        "ip", "netns", "exec", C.ns_name(client["id"]),
        "busybox", "udhcpc",
        "-f",                                  # foreground, supervised by systemd
        "-i", client["iface"],
        "-s", HOOK,
        "-p", os.path.join(C.RUN_DIR, f"udhcpc-{client['id']}.pid"),
        "-R",                                  # DHCPRELEASE on exit: lease hygiene
        "-t", "4", "-T", "4", "-A", "15",      # 4 discovers 4 s apart, then retry after 15 s
        "-x", f"hostname:{hostname}",
        "-V", d.get("vendor_class", "exm-probe"),
        "-O", "mtu", "-O", "114",              # interface MTU and captive-portal URI
    ]


def _run(args):
    return subprocess.run(args, capture_output=True, text=True)


def _global_v4(iface):
    out = []
    for entry in netns.ip_json(["-4", "addr", "show", "dev", iface]):
        for a in entry.get("addr_info", []):
            if a.get("scope") == "global":
                out.append(f"{a['local']}/{a['prefixlen']}")
    return out


def _hexopt_text(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return bytes.fromhex(value).decode("utf-8", "replace")
    except ValueError:
        return value


def hook(cfg: dict, event: str) -> int:
    env = os.environ
    iface = env.get("interface", "")
    try:
        client = C.client_by_iface(cfg, iface)
    except C.ConfigError as exc:
        print(f"udhcpc-hook: {exc}", file=sys.stderr)
        return 0
    cid = client["id"]
    lease_file = C.state_path(cfg, f"{cid}.lease.json")
    resolv = netns.resolv_path(cid)

    ip = env.get("ip")
    prefix = env.get("mask")
    if ip and not (prefix and prefix.isdigit()) and env.get("subnet"):
        prefix = str(ipaddress.IPv4Network(f"0.0.0.0/{env['subnet']}").prefixlen)
    routers = env.get("router", "").split()
    dns = env.get("dns", "").split()
    lease_s = env.get("lease")
    mtu = env.get("mtu")
    captive = _hexopt_text(env.get("opt114"))

    if event == "deconfig":
        _run(["ip", "-4", "addr", "flush", "dev", iface, "scope", "global"])
        _run(["ip", "link", "set", "dev", iface, "up"])
        netns.write_inplace(resolv, netns.PLACEHOLDER_RESOLV)
        _write_json(lease_file, {"state": "none", "ts": events.utc_iso()})
        print(f"dhcp_lease {cid} deconfig", flush=True)
        return 0

    if event in ("bound", "renew") and ip and prefix:
        for old in _global_v4(iface):
            if old.split("/")[0] != ip:
                _run(["ip", "addr", "del", old, "dev", iface])
        cmd = ["ip", "addr", "replace", f"{ip}/{prefix}", "dev", iface]
        if env.get("broadcast"):
            cmd += ["broadcast", env["broadcast"]]
        if lease_s and lease_s.isdigit():
            cmd += ["valid_lft", lease_s, "preferred_lft", lease_s]
        _run(cmd)
        if routers:
            _run(["ip", "route", "replace", "default", "via", routers[0], "dev", iface])
        else:
            _run(["ip", "route", "del", "default"])
        if mtu and mtu.isdigit() and 576 <= int(mtu) <= 9216:
            _run(["ip", "link", "set", "dev", iface, "mtu", mtu])

        lines = [f"# exm: from DHCP lease on {iface}, server {env.get('serverid', '?')}, {event} {events.utc_iso()}"]
        lines += [f"nameserver {d}" for d in dns]
        search = env.get("search") or env.get("domain")
        if search:
            lines.append(f"search {search}")
        netns.write_inplace(resolv, "\n".join(lines) + "\n")

        lease = {"state": "bound", "event": event, "ts": events.utc_iso(), "ip": ip,
                 "prefix": int(prefix), "router": routers, "dns": dns,
                 "domain": env.get("domain"), "search": env.get("search"),
                 "serverid": env.get("serverid"),
                 "lease_s": int(lease_s) if lease_s and lease_s.isdigit() else None,
                 "mtu": int(mtu) if mtu and mtu.isdigit() else None,
                 "captive_portal_uri": captive, "hostname_sent": f"{cfg['dhcp'].get('hostname_prefix', 'exm')}-{cid}"}
        _write_json(lease_file, lease)
        ev = events.make(cfg, client, "dhcp_lease", target=env.get("serverid"))
        ev["outcome"] = C.OK
        ev["value"] = {"event": event, **{k: v for k, v in lease.items() if k not in ("state", "event", "ts")}}
        events.emit(cfg, ev, f"dhcp_lease {cid} {event} ip={ip}/{prefix} gw={routers[:1]} dns={dns} lease={lease_s}s")
        return 0

    if event in ("leasefail", "nak"):
        if event == "leasefail":
            # An unplugged port fails every ~31 s; record the transition, not every retry.
            try:
                with open(lease_file) as fh:
                    prev = json.load(fh)
            except (FileNotFoundError, json.JSONDecodeError):
                prev = {}
            if prev.get("state") == "leasefail":
                prev["retries_since"] = prev.get("retries_since", 0) + 1
                _write_json(lease_file, prev)
                print(f"dhcp_lease {cid} leasefail (still failing since {prev.get('ts')}, "
                      f"retry {prev['retries_since']})", flush=True)
                return 0
            _write_json(lease_file, {"state": "leasefail", "ts": events.utc_iso(), "retries_since": 0})
        ev = events.make(cfg, client, "dhcp_lease", target=env.get("serverid"))
        ev["outcome"] = C.FAIL if event == "leasefail" else C.DEGRADED
        ev["value"] = {"event": event, "message": env.get("message")}
        ev["error"] = "no lease obtained" if event == "leasefail" else "DHCPNAK received"
        events.emit(cfg, ev)
    return 0


def _write_json(path: str, obj: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(obj, fh, indent=1)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)

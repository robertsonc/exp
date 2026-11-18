"""Client network namespaces: one physical port per namespace (access mode).

`up` moves each configured port into its own namespace "exm-<id>". Deleting a
namespace returns a physical port to the host automatically, so `down` is a
clean undo. A port is never moved if it carries an address, is enslaved to a
bond or bridge, or holds the default route: the guard refuses and leaves it
alone rather than risk the management path.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import time

from . import config as C

PLACEHOLDER_RESOLV = "# exm: no DHCP lease yet; resolvers appear here when one is bound\n"


def sh(args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True)


def ip_json(args, ns=None):
    cmd = ["ip", "-j"] + (["-n", ns] if ns else []) + list(args)
    out = sh(cmd, check=False).stdout.strip()
    try:
        return json.loads(out) if out else []
    except json.JSONDecodeError:
        return []


def netns_exists(ns: str) -> bool:
    return os.path.exists(f"/run/netns/{ns}")


def iface_present(iface: str, ns: str | None = None) -> bool:
    cmd = ["ip"] + (["-n", ns] if ns else []) + ["link", "show", "dev", iface]
    return sh(cmd, check=False).returncode == 0


def guard(iface: str) -> str | None:
    """Reason this host interface must not be moved, or None if it is safe."""
    link = ip_json(["-d", "link", "show", "dev", iface])
    if link and link[0].get("master"):
        return f"enslaved to {link[0]['master']}"
    if link and link[0].get("linkinfo", {}).get("info_kind") in ("bond", "bridge", "vlan", "macvlan"):
        return f"is a {link[0]['linkinfo']['info_kind']} device"
    for entry in ip_json(["addr", "show", "dev", iface]):
        for a in entry.get("addr_info", []):
            if a.get("scope") == "global":
                return f"carries address {a.get('local')}/{a.get('prefixlen')}"
    for r in ip_json(["route", "show", "default"]):
        if r.get("dev") == iface:
            return "holds the host's default route"
    return None


def resolv_path(client_id: str) -> str:
    return os.path.join(C.ETC_NETNS, C.ns_name(client_id), "resolv.conf")


def write_inplace(path: str, text: str) -> None:
    """Rewrite a file keeping its inode.

    `ip netns exec` bind-mounts /etc/netns/<ns>/resolv.conf over /etc/resolv.conf;
    replacing the file by rename would leave running processes on the old inode.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.write(fd, text.encode())
    finally:
        os.close(fd)


def up(cfg: dict, only: list[str] | None = None) -> bool:
    all_ok = True
    for c in cfg["client"]:
        if only and c["id"] not in only:
            continue
        ns, iface = C.ns_name(c["id"]), c["iface"]
        if not netns_exists(ns):
            sh(["ip", "netns", "add", ns])
        os.makedirs(os.path.dirname(resolv_path(c["id"])), exist_ok=True)
        if not os.path.exists(resolv_path(c["id"])):
            write_inplace(resolv_path(c["id"]), PLACEHOLDER_RESOLV)

        if not iface_present(iface, ns):
            # At boot the port may still be getting its udev name.
            for _ in range(30):
                if iface_present(iface):
                    break
                time.sleep(1)
            else:
                print(f"{c['id']}: {iface} not found on the host or in {ns}; skipped", flush=True)
                all_ok = False
                continue
            reason = guard(iface)
            if reason:
                print(f"{c['id']}: REFUSED to move {iface}: it {reason}. Left untouched.", flush=True)
                all_ok = False
                continue
            sh(["ip", "link", "set", "dev", iface, "netns", ns])

        sh(["ip", "-n", ns, "link", "set", "lo", "up"])
        if not c.get("ipv6"):
            r = sh(["ip", "netns", "exec", ns, "sysctl", "-qw",
                    f"net.ipv6.conf.{iface}.disable_ipv6=1"], check=False)
            if r.returncode != 0:
                print(f"{c['id']}: could not disable IPv6 on {iface}: {r.stderr.strip()}", flush=True)
        sh(["ip", "-n", ns, "link", "set", "dev", iface, "up"])
        print(f"{c['id']}: {iface} up in {ns}", flush=True)
    return all_ok


def _kill_ns_pids(ns: str) -> None:
    pids = [int(p) for p in sh(["ip", "netns", "pids", ns], check=False).stdout.split() if p.isdigit()]
    for sig in (signal.SIGTERM, signal.SIGKILL):
        alive = []
        for pid in pids:
            try:
                os.kill(pid, sig)
                alive.append(pid)
            except ProcessLookupError:
                pass
        if not alive:
            return
        time.sleep(2)
        pids = alive


def down(cfg: dict, only: list[str] | None = None) -> None:
    for c in cfg["client"]:
        if only and c["id"] not in only:
            continue
        ns, iface = C.ns_name(c["id"]), c["iface"]
        if netns_exists(ns):
            _kill_ns_pids(ns)
            sh(["ip", "-n", ns, "link", "set", "dev", iface, "down"], check=False)
            # Hand the port back explicitly: a physical NIC would return when the namespace goes,
            # but a virtual one (veth, some hypervisor NICs) would be destroyed with it.
            sh(["ip", "-n", ns, "link", "set", "dev", iface, "netns", "1"], check=False)
            sh(["ip", "netns", "del", ns], check=False)
            for _ in range(20):
                if iface_present(iface):
                    break
                time.sleep(0.25)
        if iface_present(iface):
            sh(["ip", "link", "set", "dev", iface, "down"], check=False)
            print(f"{c['id']}: {iface} returned to the host, admin down", flush=True)
        else:
            print(f"{c['id']}: {iface} not visible on the host after teardown", flush=True)
        d = os.path.dirname(resolv_path(c["id"]))
        if os.path.isdir(d):
            for f in os.listdir(d):
                os.unlink(os.path.join(d, f))
            os.rmdir(d)


def remove_stale(cfg: dict) -> list[str]:
    """Delete exm namespaces whose port is no longer in the config (renamed or removed).

    Run after their units are stopped. A physical port goes back to the host when
    its namespace is deleted, so `up` can then move it into its new namespace.
    """
    configured = {C.ns_name(c["id"]) for c in cfg["client"]}
    gone = []
    names = os.listdir("/run/netns") if os.path.isdir("/run/netns") else []
    for ns in sorted(n for n in names if n.startswith(C.NS_PREFIX) and n not in configured):
        _kill_ns_pids(ns)
        for link in json.loads(sh(["ip", "-n", ns, "-j", "link", "show"], check=False).stdout or "[]"):
            if link.get("ifname") != "lo":
                sh(["ip", "-n", ns, "link", "set", "dev", link["ifname"], "netns", "1"], check=False)
        sh(["ip", "netns", "del", ns], check=False)
        d = os.path.join(C.ETC_NETNS, ns)
        if os.path.isdir(d):
            for f in os.listdir(d):
                os.unlink(os.path.join(d, f))
            os.rmdir(d)
        print(f"{ns}: removed (no longer in the config); its port returns to the host", flush=True)
        gone.append(ns)
    return gone


def read_resolvers(path: str) -> list[str]:
    try:
        with open(path) as fh:
            return [ln.split()[1] for ln in fh if ln.startswith("nameserver") and len(ln.split()) > 1]
    except FileNotFoundError:
        return []


def udhcpc_pid(client_id: str) -> int | None:
    try:
        with open(os.path.join(C.RUN_DIR, f"udhcpc-{client_id}.pid")) as fh:
            pid = int(fh.read().strip())
        os.kill(pid, 0)
        return pid
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
        return None


def server_pid(client_id: str) -> int | None:
    try:
        with open(os.path.join(C.RUN_DIR, f"server-{client_id}.pid")) as fh:
            pid = int(fh.read().strip())
        os.kill(pid, 0)
        return pid
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
        return None


def status(cfg: dict) -> list[dict]:
    rows = []
    for c in cfg["client"]:
        ns, iface = C.ns_name(c["id"]), c["iface"]
        row = {"client": c["id"], "iface": iface, "netns": ns, "vlan": c.get("vlan", ""),
               "zone": c.get("zone", ""), "ns_exists": netns_exists(ns), "in_ns": False,
               "operstate": None, "carrier": None, "speed_mbps": None, "mac": None,
               "ip": None, "prefix": None, "gateway": None, "dns": [], "lease": None,
               "udhcpc_pid": udhcpc_pid(c["id"]), "role": c.get("role", "client"), "daemon": None}
        if row["role"] == "server":
            pid = server_pid(c["id"])
            row["daemon"] = f"server {'running' if pid else 'stopped'}"
        if row["ns_exists"] and iface_present(iface, ns):
            row["in_ns"] = True
            link = ip_json(["link", "show", "dev", iface], ns)
            if link:
                row["operstate"] = link[0].get("operstate")
                row["carrier"] = "LOWER_UP" in link[0].get("flags", [])
                row["mac"] = link[0].get("address")
            spd = sh(["ip", "netns", "exec", ns, "cat", f"/sys/class/net/{iface}/speed"], check=False)
            if spd.returncode == 0 and spd.stdout.strip().lstrip("-").isdigit():
                v = int(spd.stdout.strip())
                row["speed_mbps"] = v if v > 0 else None
            for entry in ip_json(["-4", "addr", "show", "dev", iface], ns):
                for a in entry.get("addr_info", []):
                    if a.get("scope") == "global":
                        row["ip"], row["prefix"] = a.get("local"), a.get("prefixlen")
            for r in ip_json(["route", "show", "default"], ns):
                row["gateway"] = r.get("gateway")
        row["dns"] = read_resolvers(resolv_path(c["id"]))
        try:
            with open(C.state_path(cfg, f"{c['id']}.lease.json")) as fh:
                row["lease"] = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        rows.append(row)
    return rows

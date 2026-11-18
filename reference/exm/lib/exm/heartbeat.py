"""Heartbeats: network, DHCP and DNS checks every 10 s, so the live view is live.

The full tests (dhcp, dns, apps) come round every few minutes per client and a
failed DORA takes 28 s of retries to report. These checks are small enough to
run every 10 s from the scheduler, all at once:

  gateway   every port: link, link drops since the last run, one gateway ping (gateway.py)
  dhcp_hb   one client per run, in rotation: a DHCPDISCOVER with the client's own
            MAC and client-id, waiting up to 3 s for an OFFER. It never sends a
            REQUEST, so no lease is taken or changed and no pool address is used up.
  dns_hb    one client per run, in rotation: one A query to the resolver DHCP gave
            that client, 2 s timeout.
  trace     one client per run, in rotation: a traceroute to trace_target, one ICMP
            echo per TTL, all sent at once and collected within 2 s. It finds the last
            hop that answers when the internet is unreachable. Diagnostic only: it
            never colours a line, since some paths drop ICMP while the web works.
  trace_ctl the same traceroute from this host's own management path, which reaches
            the internet without the WAN edge the test ports use. If it gets out and
            the ports' trace doesn't, the fault is the edge, not the ISP.
  dns_hb also asks an alternate resolver, so a dead resolver is told apart from a
            dead path, and pings both, so a server that is unreachable is told apart
            from one that is reachable but not answering DNS. Only the DNS answer of
            the resolver DHCP gives clients decides the outcome.

DHCP, DNS and trace run in their own thread, moved into the client's namespace with
setns(2), and use plain sockets: no scapy and no child process per check.
"""
from __future__ import annotations

import concurrent.futures
import fcntl
import json
import os
import random
import select
import socket
import struct
import threading
import time

from . import config as C
from . import events
from . import gateway
from . import netns

SIOCGIFFLAGS, SIOCGIFHWADDR, IFF_RUNNING = 0x8913, 0x8927, 0x40
ETH_P_IP = 0x0800
PRL = [1, 3, 6, 15, 28, 51, 54]
NAMES = ["google.com", "apple.com", "microsoft.com", "cloudflare.com", "amazon.com", "wikipedia.org"]


def _in_netns(ns: str, fn, *args):
    """Run fn in a fresh thread whose network namespace is ns; return its result or raise its error."""
    box = {}

    def target():
        try:
            fd = os.open(f"/run/netns/{ns}", os.O_RDONLY)
            try:
                os.setns(fd, os.CLONE_NEWNET)
            finally:
                os.close(fd)
            box["result"] = fn(*args)
        except BaseException as exc:            # handed back to the caller
            box["error"] = exc

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join()
    if "error" in box:
        raise box["error"]
    return box["result"]


def _link(iface: str) -> tuple[bool, bytes]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        flags = struct.unpack("16sH", fcntl.ioctl(s, SIOCGIFFLAGS, struct.pack("16sH", iface.encode(), 0)))[1]
        hw = fcntl.ioctl(s, SIOCGIFHWADDR, struct.pack("256s", iface.encode()))[18:24]
    finally:
        s.close()
    return bool(flags & IFF_RUNNING), hw


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _discover_frame(mac: bytes, xid: int, hostname: str, vendor: str) -> bytes:
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0, 0x8000,
                        bytes(4), bytes(4), bytes(4), bytes(4), mac + bytes(10), bytes(64), bytes(128))
    h, v = hostname.encode()[:63], vendor.encode()[:63]
    opts = (b"\x63\x82\x53\x63" + bytes([53, 1, 1]) + bytes([61, 7, 1]) + mac + bytes([12, len(h)]) + h
            + bytes([60, len(v)]) + v + bytes([55, len(PRL)]) + bytes(PRL) + b"\xff")
    payload = bootp + opts
    payload += bytes(max(0, 300 - len(payload)))            # BOOTP minimum size
    udp = struct.pack("!HHHH", 68, 67, 8 + len(payload), 0) + payload
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), random.getrandbits(16), 0, 64, 17, 0,
                      bytes(4), b"\xff\xff\xff\xff")
    iph = iph[:10] + struct.pack("!H", _checksum(iph)) + iph[12:]
    return b"\xff" * 6 + mac + b"\x08\x00" + iph + udp


def _parse_offer(frame: bytes, xid: int):
    """(offered ip, server id) when frame is a DHCPOFFER for xid, else None.

    Anyone on the LAN can send to port 68, so a short or malformed frame is
    ignored, never raised: one bad packet must not turn a DHCP result into a
    probe error.
    """
    try:
        if len(frame) < 14 + 20 or frame[12:14] != b"\x08\x00" or frame[14] >> 4 != 4:
            return None
        ihl = (frame[14] & 0x0F) * 4
        if ihl < 20 or frame[14 + 9] != 17:
            return None
        udp = frame[14 + ihl:]
        if len(udp) < 8 + 240 or struct.unpack("!H", udp[2:4])[0] != 68:
            return None
        b = udp[8:]
        if b[0] != 2 or struct.unpack("!I", b[4:8])[0] != xid or b[236:240] != b"\x63\x82\x53\x63":
            return None
        yiaddr = socket.inet_ntoa(b[16:20])
        opts, i, mtype, server = b[240:], 0, None, None
        while i < len(opts) and opts[i] != 255:
            if opts[i] == 0:
                i += 1
                continue
            if i + 1 >= len(opts):
                return None
            code, ln = opts[i], opts[i + 1]
            if i + 2 + ln > len(opts):
                return None
            val = opts[i + 2:i + 2 + ln]
            if code == 53 and ln:
                mtype = val[0]
            elif code == 54 and ln == 4:
                server = socket.inet_ntoa(val)
            i += 2 + ln
        return (yiaddr, server) if mtype == 2 else None
    except (IndexError, struct.error, ValueError, OSError):
        return None


def _dhcp_probe(iface: str, hostname: str, vendor: str, timeout_s: float) -> dict:
    up, mac = _link(iface)
    if not up:
        return {"skip": "no link"}
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    try:
        s.bind((iface, ETH_P_IP))
        xid = random.getrandbits(32)
        frame = _discover_frame(mac, xid, hostname, vendor)
        t0 = time.perf_counter()
        s.send(frame)
        resent, offers = False, []
        while True:
            left = timeout_s - (time.perf_counter() - t0)
            if offers or left <= 0:
                break
            if not resent and time.perf_counter() - t0 > timeout_s / 2:
                s.send(frame)                       # one retransmit covers a single lost packet
                resent = True
            r, _, _ = select.select([s], [], [], min(left, 0.1))
            if r:
                got = _parse_offer(s.recv(4096), xid)
                if got:
                    offers.append((time.perf_counter() - t0, got))
        if not offers:
            return {"ok": False, "mac": mac.hex(":"), "resent": resent}
        dt, (ip, server) = offers[0]
        return {"ok": True, "ms": round(dt * 1000, 2), "offered_ip": ip, "server_id": server, "mac": mac.hex(":"),
                "resent": resent}
    finally:
        s.close()


def _dns_query(name: str) -> tuple[bytes, int]:
    qid = random.getrandbits(16)
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
    return q, qid


def _dns_probe(iface: str, server: str, name: str, timeout_s: float) -> dict:
    up, _ = _link(iface)
    if not up:
        return {"skip": "no link"}
    q, qid = _dns_query(name)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout_s)
        t0 = time.perf_counter()
        s.sendto(q, (server, 53))
        while True:
            try:
                data, _ = s.recvfrom(4096)
            except socket.timeout:
                return {"ok": False, "error": f"no answer from {server} within {timeout_s:g} s"}
            if len(data) >= 12 and struct.unpack("!H", data[:2])[0] == qid:
                break
        dt = time.perf_counter() - t0
        flags, _, ancount = struct.unpack("!HHH", data[2:8])
        rcode = flags & 0x0F
        res = {"ms": round(dt * 1000, 2), "rcode": rcode, "answers": ancount}
        if rcode != 0:
            res.update(ok=False, error=f"rcode {rcode} from {server}")
        elif ancount == 0:
            res.update(ok=False, error=f"no records for {name} from {server}")
        else:
            res["ok"] = True
        return res
    finally:
        s.close()


def _trace_probe(iface: str | None, target: str, max_hops: int, timeout_s: float, gap_s: float = 0.02) -> dict:
    """[(ttl, ip or None, rtt ms or None)] up to the destination or the last hop that answered.
    iface None: this host's own routing (the management path), no link check."""
    if iface:
        up, _ = _link(iface)
        if not up:
            return {"skip": "no link"}
    ident = random.getrandbits(16)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try:
        sent = {}
        for ttl in range(1, max_hops + 1):
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            hdr = struct.pack("!BBHHH", 8, 0, 0, ident, ttl) + b"exm-trace"
            pkt = hdr[:2] + struct.pack("!H", _checksum(hdr)) + hdr[4:]
            if ttl > 1:
                time.sleep(gap_s)               # paced: Google's edge and others drop a simultaneous burst
            sent[ttl] = time.perf_counter()
            try:
                s.sendto(pkt, (target, 0))
            except OSError as exc:              # no route: nothing left the box
                return {"skip": str(exc)} if ttl == 1 else {"error": str(exc)}
        hops, dest_ttl, unreach = {}, None, None
        deadline = sent[1] + timeout_s
        while time.perf_counter() < deadline:
            if dest_ttl and all(t in hops for t in range(1, dest_ttl + 1)):
                break
            r, _, _ = select.select([s], [], [], max(0.0, deadline - time.perf_counter()))
            if not r:
                break
            data, (src, _) = s.recvfrom(2048)
            got = time.perf_counter()
            try:
                ihl = (data[0] & 0x0F) * 4
                itype = data[ihl]
                if itype == 0:                                       # echo reply: the destination
                    rid, seq = struct.unpack("!HH", data[ihl + 4:ihl + 8])
                    if rid != ident or seq not in sent:
                        continue
                    dest_ttl = seq if dest_ttl is None else min(dest_ttl, seq)
                elif itype in (3, 11):                               # unreachable / time exceeded
                    inner = data[ihl + 8:]
                    iihl = (inner[0] & 0x0F) * 4
                    if inner[9] != 1:
                        continue
                    if struct.unpack("!BBHHH", inner[iihl:iihl + 8])[0] != 8:
                        continue
                    rid, seq = struct.unpack("!HH", inner[iihl + 4:iihl + 8])
                    if rid != ident or seq not in sent:
                        continue
                    if itype == 3:
                        unreach = {"ip": src, "code": data[ihl + 1], "ttl": seq}
                else:
                    continue
            except (IndexError, struct.error):                       # a malformed packet is someone else's
                continue
            if seq not in hops:
                hops[seq] = (src, round((got - sent[seq]) * 1000, 2))
        last = dest_ttl or (max(hops) if hops else 0)
        path = [[t] + list(hops.get(t, (None, None))) for t in range(1, last + 1)]
        mids = [t for t in hops if dest_ttl is None or t < dest_ttl]
        res = {"hops": path, "reached": dest_ttl is not None, "dest_ttl": dest_ttl, "unreachable": unreach}
        if mids:
            res["last_ttl"] = max(mids)
            res["last_ip"] = hops[res["last_ttl"]][0]
        if dest_ttl:
            res["ms"] = hops[dest_ttl][1]
        return res
    finally:
        s.close()


def _ping(target: str, timeout_s: float = 1.0, tries: int = 2) -> float | None:
    """ICMP echo, up to `tries` times 0.5 s apart (public resolvers rate-limit ICMP, and the traceroute
    may be hitting the same address that second): round trip in ms, or None. A raw socket: root."""
    for i in range(tries):
        if i:
            time.sleep(0.5)
        ms = _echo(target, timeout_s)
        if ms is not None:
            return ms
    return None


def _echo(target: str, timeout_s: float) -> float | None:
    ident, seq = random.getrandbits(16), random.getrandbits(15)
    hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + b"exm-ping"
    pkt = hdr[:2] + struct.pack("!H", _checksum(hdr)) + hdr[4:]
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try:
        t0 = time.perf_counter()
        try:
            s.sendto(pkt, (target, 0))
        except OSError:
            return None
        while True:
            left = timeout_s - (time.perf_counter() - t0)
            if left <= 0:
                return None
            r, _, _ = select.select([s], [], [], left)
            if not r:
                return None
            data, (src, _) = s.recvfrom(2048)
            try:
                ihl = (data[0] & 0x0F) * 4
                if src == target and data[ihl] == 0 and struct.unpack("!HH", data[ihl + 4:ihl + 8]) == (ident, seq):
                    return round((time.perf_counter() - t0) * 1000, 2)
            except (IndexError, struct.error):
                continue
    finally:
        s.close()


def _rotation(cfg: dict) -> dict:
    try:
        with open(C.state_path(cfg, "heartbeat.rotation.json")) as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"dhcp": -1, "dns": -1, "name": -1}


def _save_rotation(cfg: dict, rot: dict) -> None:
    path = C.state_path(cfg, "heartbeat.rotation.json")
    with open(path + ".tmp", "w") as fh:
        json.dump(rot, fh)
    os.replace(path + ".tmp", path)


def dhcp_hb(cfg: dict, rot: dict) -> dict:
    h = cfg.get("heartbeat", {})
    d = cfg["dhcp"]
    timeout_s = float(h.get("dhcp_timeout_s", 3))
    slow_ms = float(h.get("dhcp_degraded_ms", d.get("degraded_ms", 1500)))
    clients = C.clients(cfg)
    skipped = []
    for step in range(1, len(clients) + 1):
        c = clients[(rot["dhcp"] + step) % len(clients)]
        ns = C.ns_name(c["id"])
        if not netns.netns_exists(ns):
            skipped.append(f"{c['id']} no namespace")
            continue
        try:
            res = _in_netns(ns, _dhcp_probe, c["iface"], f"{d.get('hostname_prefix', 'exm')}-{c['id']}",
                            d.get("vendor_class", "exm-probe"), timeout_s)
        except OSError as exc:
            skipped.append(f"{c['id']} {exc}")
            continue
        if res.get("skip"):
            skipped.append(f"{c['id']} {res['skip']}")
            continue
        rot["dhcp"] = clients.index(c)
        ev = events.make(cfg, c, "dhcp_hb", target="broadcast")
        ev["value"] = {k: v for k, v in res.items() if k != "ms"}
        if res["ok"]:
            ev["phase_ms"] = {"offer": res["ms"]}
            ev["outcome"] = C.DEGRADED if res["ms"] > slow_ms else C.OK
        else:
            ev["outcome"], ev["error"] = C.FAIL, f"no DHCPOFFER within {timeout_s:g} s"
        events.emit(cfg, ev, f"dhcp_hb {c['id']} outcome={ev['outcome']} offer={res.get('ms', '-')}ms "
                             f"ip={res.get('offered_ip', '-')} server={res.get('server_id', '-')}")
        return ev
    # No port could send: that is unknown, not a DHCP failure.
    ev = events.make(cfg, None, "dhcp_hb", target="broadcast")
    ev["outcome"], ev["error"] = C.HARNESS, "no client port to test from: " + "; ".join(skipped)[:200]
    events.emit(cfg, ev)
    return ev


def dns_hb(cfg: dict, rot: dict) -> dict:
    h = cfg.get("heartbeat", {})
    timeout_s = float(h.get("dns_timeout_s", 2))
    slow_ms = float(h.get("dns_degraded_ms", cfg["dns"].get("degraded_p95_ms", 250)))
    clients = C.clients(cfg)
    rot["name"] = (rot.get("name", -1) + 1) % len(NAMES)
    name = NAMES[rot["name"]]
    skipped = []
    for step in range(1, len(clients) + 1):
        c = clients[(rot["dns"] + step) % len(clients)]
        ns = C.ns_name(c["id"])
        servers = netns.read_resolvers(netns.resolv_path(c["id"]))
        if not netns.netns_exists(ns) or not servers:
            skipped.append(f"{c['id']} no resolver (no lease)")
            continue
        alt = h.get("dns_alt", "1.1.1.1")
        if alt == servers[0]:
            alt = h.get("dns_alt2", "8.8.8.8")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                main_f = pool.submit(_in_netns, ns, _dns_probe, c["iface"], servers[0], name, timeout_s)
                alt_f = pool.submit(_in_netns, ns, _dns_probe, c["iface"], alt, name, timeout_s) if alt else None
                ping_f = pool.submit(_in_netns, ns, _ping, servers[0]) if h.get("dns_ping", True) else None
                aping_f = pool.submit(_in_netns, ns, _ping, alt) if alt and h.get("dns_ping", True) else None
                res = main_f.result()
                alt_res = alt_f.result() if alt_f else None
                ping_ms = ping_f.result() if ping_f else None
                alt_ping_ms = aping_f.result() if aping_f else None
        except OSError as exc:
            skipped.append(f"{c['id']} {exc}")
            continue
        if res.get("skip"):
            skipped.append(f"{c['id']} {res['skip']}")
            continue
        rot["dns"] = clients.index(c)
        ev = events.make(cfg, c, "dns_hb", target=name, resolver="dhcp")
        ev["value"] = dict({k: v for k, v in res.items() if k not in ("ms", "error")}, server=servers[0])
        if ping_f:
            ev["value"]["ping_ms"] = ping_ms                # None: no ICMP reply within 1 s
        if alt_res and not alt_res.get("skip"):
            ev["value"]["alt"] = {"server": alt, "ok": bool(alt_res.get("ok")), "ms": alt_res.get("ms"),
                                  "error": alt_res.get("error"), "ping_ms": alt_ping_ms}
        if res.get("ms") is not None:
            ev["phase_ms"] = {"rtt": res["ms"]}
        if res["ok"]:
            ev["outcome"] = C.DEGRADED if res["ms"] > slow_ms else C.OK
        else:
            ev["outcome"], ev["error"] = C.FAIL, res.get("error")
        events.emit(cfg, ev, f"dns_hb {c['id']} {name} @{servers[0]} outcome={ev['outcome']} rtt={res.get('ms', '-')}ms"
                             + (f" error={ev['error']}" if ev.get("error") else ""))
        return ev
    ev = events.make(cfg, None, "dns_hb", target=name, resolver="dhcp")
    ev["outcome"], ev["error"] = C.HARNESS, "no client port to test from: " + "; ".join(skipped)[:200]
    events.emit(cfg, ev)
    return ev


def trace(cfg: dict, rot: dict) -> dict:
    h = cfg.get("heartbeat", {})
    target = h.get("trace_target", "8.8.8.8")
    max_hops = max(2, min(30, int(h.get("trace_max_hops", 16))))
    timeout_s = float(h.get("trace_timeout_s", 2))
    clients = C.clients(cfg)
    skipped = []
    for step in range(1, len(clients) + 1):
        c = clients[(rot.get("trace", -1) + step) % len(clients)]
        ns = C.ns_name(c["id"])
        if not netns.netns_exists(ns):
            skipped.append(f"{c['id']} no namespace")
            continue
        try:
            res = _in_netns(ns, _trace_probe, c["iface"], target, max_hops, timeout_s)
        except OSError as exc:
            skipped.append(f"{c['id']} {exc}")
            continue
        if res.get("skip"):
            skipped.append(f"{c['id']} {res['skip']}")
            continue
        rot["trace"] = clients.index(c)
        ev = events.make(cfg, c, "trace", target=target)
        ev["value"] = {k: v for k, v in res.items() if k not in ("ms", "error")}
        if res.get("ms") is not None:
            ev["phase_ms"] = {"rtt": res["ms"]}
        if res.get("reached"):
            ev["outcome"] = C.OK
        else:
            ev["outcome"] = C.FAIL
            where = (f"path stops after {res['last_ip']} (hop {res['last_ttl']})" if res.get("last_ip")
                     else "no hop answered")
            if res.get("unreachable"):
                u = res["unreachable"]
                where += f"; {u['ip']} says unreachable (code {u['code']})"
            ev["error"] = res.get("error") or f"no reply from {target}; {where}"
        events.emit(cfg, ev, f"trace {c['id']} {target} reached={res.get('reached')} "
                             f"last={res.get('last_ip', '-')}@{res.get('last_ttl', '-')} hops={len(res.get('hops', []))}")
        return ev
    ev = events.make(cfg, None, "trace", target=target)
    ev["outcome"], ev["error"] = C.HARNESS, "no client port to trace from: " + "; ".join(skipped)[:200]
    events.emit(cfg, ev)
    return ev


def trace_ctl(cfg: dict) -> dict:
    """The control path: this host's own route to the same target, around the WAN edge."""
    h = cfg.get("heartbeat", {})
    target = h.get("trace_target", "8.8.8.8")
    max_hops = max(2, min(30, int(h.get("trace_max_hops", 16))))
    res = _trace_probe(None, target, max_hops, float(h.get("trace_timeout_s", 2)))
    ev = events.make(cfg, None, "trace_ctl", target=target)
    if res.get("skip"):
        ev["outcome"], ev["error"] = C.HARNESS, f"control path: {res['skip']}"
        events.emit(cfg, ev)
        return ev
    ev["value"] = {k: v for k, v in res.items() if k not in ("ms", "error")}
    if res.get("ms") is not None:
        ev["phase_ms"] = {"rtt": res["ms"]}
    if res.get("reached"):
        ev["outcome"] = C.OK
    else:
        ev["outcome"] = C.FAIL
        where = f"stops after {res['last_ip']} (hop {res['last_ttl']})" if res.get("last_ip") else "no hop answered"
        ev["error"] = res.get("error") or f"control path: no reply from {target}; {where}"
    events.emit(cfg, ev, f"trace_ctl {target} reached={res.get('reached')} last={res.get('last_ip', '-')}@{res.get('last_ttl', '-')}")
    return ev


def run(cfg: dict) -> int:
    """One heartbeat: the checks in parallel. Returns non-zero only if the probe itself failed."""
    h = cfg.get("heartbeat", {})
    rot = _rotation(cfg)
    results, jobs = {}, []

    def job(name, fn, *args):
        try:
            results[name] = fn(*args)
        except Exception as exc:
            ev = events.make(cfg, None, {"gateway": "gateway", "dhcp": "dhcp_hb", "dns": "dns_hb", "trace": "trace",
                                         "trace_ctl": "trace_ctl"}[name])
            ev["outcome"], ev["error"] = C.HARNESS, f"{type(exc).__name__}: {exc}"
            events.emit(cfg, ev)
            results[name] = ev

    jobs.append(threading.Thread(target=job, args=("gateway", gateway.run, cfg)))
    if C.clients(cfg) and h.get("dhcp", True):
        jobs.append(threading.Thread(target=job, args=("dhcp", dhcp_hb, cfg, rot)))
    if C.clients(cfg) and h.get("dns", True):
        jobs.append(threading.Thread(target=job, args=("dns", dns_hb, cfg, rot)))
    # The two traceroutes run one after the other, never together: from behind one public address,
    # two sweeps at once toward the same target get rate-limited, and a lost one would blame the edge.
    def traces():
        if C.clients(cfg):
            job("trace", trace, cfg, rot)
        if h.get("control_trace", True):
            job("trace_ctl", trace_ctl, cfg)
    if h.get("trace", True):
        jobs.append(threading.Thread(target=traces))
    for t in jobs:
        t.start()
    for t in jobs:
        t.join()
    _save_rotation(cfg, rot)
    return 1 if any(r.get("outcome") == C.HARNESS for r in results.values()) else 0

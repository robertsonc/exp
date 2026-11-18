"""DHCP timing test: a raw-socket client that stamps every phase.

Runs inside the client namespace with the client's own MAC and client-id, so a
DORA re-confirms the binding udhcpc already holds rather than taking a second
lease (stable MAC, no churn, as the spec requires). Timings come from kernel
packet timestamps on both the sent and received frames.

Modes:
  dora         Discover, Offer, Request, Ack: a client joining the network.
  init-reboot  Request for the held address with no server id: a phone rejoining.
"""
from __future__ import annotations

import ipaddress
import os
import random
import signal
import threading
import time

from . import config as C
from . import events
from . import netns

PRL = [1, 3, 6, 12, 15, 26, 28, 42, 51, 54, 58, 59, 114, 119, 121]
MTYPE = {1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform"}
# Flags recorded on a DHCP event that say nothing about DHCP itself, so they never lower its outcome.
INFO_FLAGS = {"first_dns_failed"}


def _plain(v):
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return v.hex()
    return v


def _opts(pkt) -> dict:
    from scapy.all import DHCP
    out = {}
    for o in pkt[DHCP].options:
        if isinstance(o, tuple) and len(o) >= 2:
            vals = [_plain(v) for v in o[1:]]
            out[str(o[0])] = vals[0] if len(vals) == 1 else vals
    return out


def _mtype(pkt):
    v = _opts(pkt).get("message-type")
    return v if isinstance(v, int) else None


def _held(iface):
    for entry in netns.ip_json(["-4", "addr", "show", "dev", iface]):
        for a in entry.get("addr_info", []):
            if a.get("scope") == "global":
                return a["local"], a["prefixlen"]
    return None, None


def _first(v):
    return v[0] if isinstance(v, list) else v


def run(cfg: dict, client: dict, mode: str = "dora") -> dict:
    from scapy.all import ARP, BOOTP, DHCP, IP, UDP, AsyncSniffer, Ether, conf, srp
    conf.verb = 0

    d = cfg["dhcp"]
    iface, cid = client["iface"], client["id"]
    ev = events.make(cfg, client, "dhcp")
    ev["value"]["mode"] = mode
    try:
        with open(f"/sys/class/net/{iface}/address") as fh:
            mac = fh.read().strip().lower()
    except OSError as exc:
        ev["outcome"], ev["error"] = C.HARNESS, f"cannot read MAC of {iface}: {exc}"
        events.emit(cfg, ev)
        return ev

    held_ip, held_prefix = _held(iface)
    ev["value"]["held_ip"] = held_ip
    if mode == "init-reboot" and not held_ip:
        ev["outcome"] = C.HARNESS
        ev["error"] = "no held lease: INIT-REBOOT needs a previous address (see dhcp_lease events)"
        events.emit(cfg, ev)
        return ev

    macb = bytes.fromhex(mac.replace(":", ""))
    xid = random.getrandbits(32)
    hostname = f"{d.get('hostname_prefix', 'exm')}-{cid}"
    common = [("client_id", b"\x01" + macb), ("hostname", hostname.encode()),
              ("vendor_class_id", d.get("vendor_class", "exm-probe").encode()),
              ("param_req_list", PRL)]
    flags = 0x8000 if d.get("broadcast_flag", True) else 0
    backoff = [float(x) for x in d.get("retry_backoff_s", [4, 8, 16])]

    def frame():
        return (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(op=1, chaddr=macb, xid=xid, flags=flags))

    captured, cv = [], threading.Condition()

    def on_pkt(p):
        with cv:
            captured.append(p)
            cv.notify_all()

    def ours(p):
        return p.haslayer(BOOTP) and p.haslayer(DHCP) and p[BOOTP].xid == xid

    def mine(p):
        return p[Ether].src.lower() == mac

    def wait_for(pred, timeout):
        deadline = time.monotonic() + timeout
        with cv:
            while True:
                for p in captured:
                    if pred(p):
                        return p
                rem = deadline - time.monotonic()
                if rem <= 0:
                    return None
                cv.wait(rem)

    sniffer = None
    for bpf in ("udp and (port 67 or port 68)", None):
        started = threading.Event()
        kw = {"filter": bpf} if bpf else {}
        sniffer = AsyncSniffer(iface=iface, lfilter=ours, prn=on_pkt, store=False,
                               started_callback=started.set, **kw)
        sniffer.start()
        if started.wait(3):
            break
        try:
            sniffer.stop()
        except Exception:
            pass
        sniffer = None
    if sniffer is None:
        ev["outcome"], ev["error"] = C.HARNESS, f"could not open a capture on {iface}"
        events.emit(cfg, ev)
        return ev

    # One send socket for the whole exchange: sendp() opens a fresh socket per
    # call (tens of ms), which would be counted as network time.
    l2 = conf.L2socket(iface=iface)

    def send(pkt):
        l2.send(pkt)

    retries, sent = 0, {}
    reply = offer = None
    try:
        if mode == "dora":
            disc_opts = [("message-type", "discover")]
            if held_ip:
                disc_opts.append(("requested_addr", held_ip))   # as a client with a previous lease does
            discover = frame() / DHCP(options=disc_opts + common + ["end"])
            for wait in backoff:
                sent.setdefault("discover_first", time.time())
                sent["discover_last"] = time.time()
                send(discover)
                offer = wait_for(lambda p: _mtype(p) == 2 and not mine(p), wait)
                if offer:
                    break
                retries += 1
            if not offer:
                ev["outcome"] = C.FAIL
                ev["error"] = f"no DHCPOFFER after {len(backoff)} discovers"
            else:
                o = _opts(offer)
                server_id = o.get("server_id") or offer[IP].src
                req = frame() / DHCP(options=[("message-type", "request"), ("server_id", server_id),
                                              ("requested_addr", offer[BOOTP].yiaddr)] + common + ["end"])
                for wait in backoff:
                    sent["request_last"] = time.time()
                    send(req)
                    reply = wait_for(lambda p: _mtype(p) in (5, 6) and not mine(p), wait)
                    if reply:
                        break
                    retries += 1
        else:
            req = frame() / DHCP(options=[("message-type", "request"), ("requested_addr", held_ip)] + common + ["end"])
            for wait in backoff:
                sent.setdefault("request_first", time.time())
                sent["request_last"] = time.time()
                send(req)
                reply = wait_for(lambda p: _mtype(p) in (5, 6) and not mine(p), wait)
                if reply:
                    break
                retries += 1

        if offer is not None or mode != "dora":
            if reply is None and ev["outcome"] is None:
                ev["outcome"] = C.FAIL
                ev["error"] = f"no DHCPACK/NAK after {len(backoff)} requests"
        # Keep listening briefly: a second server's offer is how a rogue shows itself.
        time.sleep(float(d.get("offer_collect_s", 3.0)))
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass
        l2.close()

    # Kernel timestamps of our own frames, falling back to wall clock at send.
    own = {}
    for p in captured:
        if mine(p):
            own.setdefault(MTYPE.get(_mtype(p)), []).append(float(p.time))
    ph = ev["phase_ms"]
    if offer is not None:
        disc_before = [t for t in own.get("discover", []) if t <= float(offer.time)]
        t_disc = max(disc_before) if disc_before else sent.get("discover_last")
        ph["discover_offer"] = events.ms(float(offer.time) - t_disc)
    if reply is not None:
        req_before = [t for t in own.get("request", []) if t <= float(reply.time)]
        t_req = max(req_before) if req_before else sent.get("request_last")
        ph["request_reply"] = events.ms(float(reply.time) - t_req)
        first = min(own.get("discover" if mode == "dora" else "request", []) or
                    [sent.get("discover_first") or sent.get("request_first")])
        ph["total"] = events.ms(float(reply.time) - first)

    offers = []
    for p in captured:
        if _mtype(p) == 2 and not mine(p):
            po = _opts(p)
            offers.append({"server_id": po.get("server_id"), "src_ip": p[IP].src,
                           "src_mac": p[Ether].src, "yiaddr": p[BOOTP].yiaddr})
    servers = sorted({o["server_id"] or o["src_ip"] for o in offers})
    v = ev["value"]
    v.update({"xid": f"{xid:08x}", "retries": retries, "offers": offers, "servers": servers})
    flag_list = []
    if retries:
        flag_list.append("retries")
    if len(servers) > 1:
        flag_list.append("multiple_dhcp_servers")

    if reply is not None and _mtype(reply) == 6:
        ev["outcome"] = C.FAIL
        ev["error"] = "DHCPNAK: " + str(_opts(reply).get("error_message", "")).strip()
        v["nak_from"] = _opts(reply).get("server_id") or reply[IP].src

    if reply is not None and _mtype(reply) == 5:
        a = _opts(reply)
        ack_ip = reply[BOOTP].yiaddr
        router = _first(a.get("router"))
        dns_list = a.get("name_server")
        dns_list = dns_list if isinstance(dns_list, list) else ([dns_list] if dns_list else [])
        ev["target"] = a.get("server_id") or reply[IP].src
        v.update({"ack_ip": ack_ip, "server_id": a.get("server_id"), "router": router,
                  "dns": dns_list, "domain": a.get("domain"), "subnet_mask": a.get("subnet_mask"),
                  "lease_s": a.get("lease_time"), "renew_s": a.get("renewal_time"),
                  "rebind_s": a.get("rebinding_time"), "mtu": a.get("interface-mtu"),
                  "captive_portal_uri": a.get("captive-portal") or a.get("114"),
                  "options": a})

        if router:
            ans, _ = srp(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                         ARP(op=1, hwsrc=mac, psrc=ack_ip, pdst=router),
                         iface=iface, timeout=2, verbose=False)
            if ans:
                s, r = ans[0]
                ph["gateway_arp"] = events.ms(float(r.time) - float(s.sent_time))
                v["gateway_mac"] = r[ARP].hwsrc
            else:
                v["gateway_mac"] = None
                flag_list.append("gateway_no_arp_reply")

        if d.get("arp_conflict_probe", True):
            ans, _ = srp(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                         ARP(op=1, hwsrc=mac, psrc="0.0.0.0", hwdst="00:00:00:00:00:00", pdst=ack_ip),
                         iface=iface, timeout=1, multi=True, verbose=False)
            conflicts = sorted({r[ARP].hwsrc for _, r in ans if r[ARP].hwsrc.lower() != mac})
            v["arp_conflicts"] = conflicts
            if conflicts:
                flag_list.append("arp_conflict")

        if dns_list:
            try:
                import dns.message
                import dns.query
                q = dns.message.make_query("google.com", "A")
                t0 = time.perf_counter()
                dns.query.udp(q, dns_list[0], timeout=2.0)
                ph["first_dns"] = events.ms(time.perf_counter() - t0)
            except Exception as exc:
                v["first_dns_error"] = f"{type(exc).__name__}: {exc}"
                flag_list.append("first_dns_failed")

        wrong_subnet = False
        if client.get("expect_subnet"):
            try:
                wrong_subnet = ipaddress.IPv4Address(ack_ip) not in ipaddress.IPv4Network(client["expect_subnet"], strict=False)
            except ValueError:
                pass
            if wrong_subnet:
                flag_list.append("wrong_subnet")

        if held_ip and ack_ip != held_ip:
            flag_list.append("ack_ip_differs_from_held_lease")
            pid = netns.udhcpc_pid(cid)
            if pid:
                os.kill(pid, signal.SIGUSR1)     # ask the lease holder to renew and converge
                v["renew_signalled"] = True

        total = ph.get("total") or 0
        if total > float(d.get("degraded_ms", 1500)):
            flag_list.append("slow")
        # A DNS outage is DNS's result, not DHCP's: report the flag but keep it out of the score.
        scored = [f for f in flag_list if f not in INFO_FLAGS]
        ev["outcome"] = C.FAIL if wrong_subnet else (C.DEGRADED if scored else C.OK)

    v["flags"] = flag_list
    if ev["outcome"] is None:
        ev["outcome"] = C.HARNESS
        ev["error"] = "exchange ended without a classifiable reply"
    def f(k):
        return f"{ph[k]}ms" if ph.get(k) is not None else "-"
    summary = (f"dhcp {cid} {mode} outcome={ev['outcome']} total={f('total')} "
               f"disc>offer={f('discover_offer')} req>reply={f('request_reply')} gw_arp={f('gateway_arp')} "
               f"first_dns={f('first_dns')} servers={len(servers) if mode == 'dora' else '-'} retries={retries} "
               f"ip={v.get('ack_ip')} flags={','.join(flag_list) or '-'}")
    if ev.get("error"):
        summary += f" error={ev['error']}"
    events.emit(cfg, ev, summary)
    return ev

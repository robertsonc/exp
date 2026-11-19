#!/usr/bin/python3
"""pktwatch: record every IP address a host puts on the wire or receives (AF_PACKET, stdlib only; there is no tcpdump
in the harness image). Runs inside a harness host: `pktwatch.py OUT.json SUBNET [SUBNET...]` captures until SIGTERM, then
writes {"packets": N, "outside": [{"src","dst","proto","t"}...]}: every IPv4 packet with an endpoint outside SUBNET(s)
(multicast/broadcast/loopback excepted) and every IPv6 packet with a global (2000::/3) endpoint. Used by the A3.4 test
to prove that nothing from the dashboard host heads for a public address while the internet is away."""
from __future__ import annotations

import ipaddress
import json
import signal
import socket
import sys
import time

ETH_P_ALL = 3
stop = False


def _term(_s: int, _f: object) -> None:
    global stop
    stop = True


def main(argv: list[str]) -> int:
    out, nets = argv[1], [ipaddress.ip_network(n) for n in argv[2:]]
    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    cap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    cap.settimeout(0.5)
    total, outside = 0, []
    print("ready", flush=True)
    while not stop:
        try:
            pkt = cap.recv(65535)
        except TimeoutError:
            continue
        total += 1
        et = pkt[12:14]
        if et == b"\x08\x00" and len(pkt) >= 34:
            a, b = ipaddress.ip_address(pkt[26:30]), ipaddress.ip_address(pkt[30:34])
            for ip in (a, b):
                if ip.is_multicast or ip.is_loopback or ip == ipaddress.ip_address("255.255.255.255") or ip.is_unspecified:
                    continue
                if not any(ip in n for n in nets):
                    outside.append({"src": str(a), "dst": str(b), "proto": pkt[23], "t": time.time()})
                    break
        elif et == b"\x86\xdd" and len(pkt) >= 54:
            a, b = ipaddress.ip_address(pkt[22:38]), ipaddress.ip_address(pkt[38:54])
            if any(ip.packed[0] & 0xE0 == 0x20 for ip in (a, b)):
                outside.append({"src": str(a), "dst": str(b), "proto": pkt[20], "t": time.time()})
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"packets": total, "outside": outside[:200]}, f)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

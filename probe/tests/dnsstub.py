"""An in-process DNS server on loopback (UDP) for the DNS tests: responses are crafted with dnspython,
no dnslib. Modes: normal | hijack | drop | servfail | empty | truncated | slow."""
from __future__ import annotations

import socket
import threading
import time

import dns.flags
import dns.message
import dns.rcode
import dns.rrset


class DnsStub:
    def __init__(self, mode: str = "normal", host: str = "127.0.0.1", port: int = 0, delay: float = 0.0,
                 answer: str = "192.0.2.10") -> None:
        self.mode, self.delay, self.answer = mode, delay, answer
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(0.1)
        self.host, self.port = self.sock.getsockname()
        self.queries: list[str] = []
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                q = dns.message.from_wire(data)
            except Exception:                      # noqa: BLE001, S112 - a stub: ignore junk
                continue
            name = q.question[0].name.to_text().rstrip(".")
            self.queries.append(name)
            if self.mode == "drop":
                continue
            if self.delay:
                time.sleep(self.delay)
            r = dns.message.make_response(q)
            invalid = name.endswith(".invalid")
            if self.mode == "servfail":
                r.set_rcode(dns.rcode.SERVFAIL)
            elif self.mode == "empty":
                pass
            elif invalid and self.mode != "hijack":
                r.set_rcode(dns.rcode.NXDOMAIN)
            else:
                r.answer.append(dns.rrset.from_text(q.question[0].name, 60, "IN", "A", self.answer, "192.0.2.11"))
                if self.mode == "truncated":
                    r.flags |= dns.flags.TC
            self.sock.sendto(r.to_wire(), addr)

    def close(self) -> None:
        self._stop.set()
        self._t.join(2)
        self.sock.close()

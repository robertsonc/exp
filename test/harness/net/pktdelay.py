#!/usr/bin/python3
"""pktdelay: hold every packet a netfilter NFQUEUE hands over for a constant time, then accept it (a constant one-way delay
on ONE egress, the job `tc netem delay` does where the kernel has sch_netem; kernels without it, such as many cloud/firecracker
images, still have nfnetlink_queue, so the harness never depends on netem).

Runs INSIDE the network namespace whose packets it delays (the netlink socket belongs to the namespace):
    ip netns exec NS pktdelay.py --queue N --delay-ms D
and prints `ready` on stdout once the queue is bound. SIGTERM/SIGINT accept everything still held, then exit. Only the packet
metadata is copied to user space (COPY_META: id, no payload), FIFO order is kept (constant delay), the queue is long.
Stdlib only: a minimal nfnetlink_queue client (see linux/netfilter/nfnetlink_queue.h)."""
from __future__ import annotations

import argparse
import collections
import signal
import socket
import struct
import sys
import threading
import time

NETLINK_NETFILTER, SOL_NETLINK, NETLINK_NO_ENOBUFS = 12, 270, 5
NFNL_SUBSYS_QUEUE = 3
MSG_PACKET, MSG_VERDICT, MSG_CONFIG = 0, 1, 2
CFG_CMD_BIND = 1
A_PACKET_HDR, A_VERDICT_HDR = 1, 2
A_CFG_CMD, A_CFG_PARAMS, A_CFG_MAXLEN = 1, 2, 3
NLM_F_REQUEST, NLM_F_ACK = 1, 4
NF_ACCEPT = 1
COPY_META = 1


def attr(kind: int, payload: bytes) -> bytes:
    n = 4 + len(payload)
    return struct.pack("=HH", n, kind) + payload + b"\0" * ((4 - n % 4) % 4)


def message(msg: int, queue: int, attrs: bytes, flags: int = NLM_F_REQUEST) -> bytes:
    body = struct.pack("=BBH", 0, 0, socket.htons(queue)) + attrs      # nfgenmsg: AF_UNSPEC, version 0, res_id = queue
    return struct.pack("=IHHII", 16 + len(body), (NFNL_SUBSYS_QUEUE << 8) | msg, flags, 0, 0) + body


def packet_ids(data: bytes):
    """Yield the packet id of every NFQNL_MSG_PACKET in one netlink datagram."""
    off = 0
    while off + 16 <= len(data):
        ln, typ = struct.unpack_from("=IH", data, off)
        if ln < 16 or off + ln > len(data):
            break
        if typ == (NFNL_SUBSYS_QUEUE << 8) | MSG_PACKET:
            a = off + 20                                        # nlmsghdr (16) + nfgenmsg (4)
            while a + 4 <= off + ln:
                alen, atype = struct.unpack_from("=HH", data, a)
                if alen < 4:
                    break
                if atype & 0x3FFF == A_PACKET_HDR:
                    yield struct.unpack_from("!I", data, a + 4)[0]
                a += (alen + 3) & ~3
        off += (ln + 3) & ~3


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--queue", type=int, required=True)
    ap.add_argument("--delay-ms", type=float, required=True)
    a = ap.parse_args()
    delay = a.delay_ms / 1000.0
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
    s.bind((0, 0))
    s.setsockopt(SOL_NETLINK, NETLINK_NO_ENOBUFS, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, 33, 8 << 20)            # SO_RCVBUFFORCE
    except OSError:
        pass
    s.send(message(MSG_CONFIG, a.queue, attr(A_CFG_CMD, struct.pack("=BBH", CFG_CMD_BIND, 0, 0))))
    s.send(message(MSG_CONFIG, a.queue, attr(A_CFG_PARAMS, struct.pack("!IB", 0, COPY_META))))
    s.send(message(MSG_CONFIG, a.queue, attr(A_CFG_MAXLEN, struct.pack("!I", 65535))))
    held: collections.deque[tuple[float, int]] = collections.deque()
    cv = threading.Condition()
    stop = threading.Event()
    lock = threading.Lock()

    def verdict(pid: int) -> None:
        with lock:
            s.send(message(MSG_VERDICT, a.queue, attr(A_VERDICT_HDR, struct.pack("!II", NF_ACCEPT, pid))))

    def releaser() -> None:
        while True:
            with cv:
                while not held and not stop.is_set():
                    cv.wait(0.5)
                if not held:
                    return
                due, pid = held[0]
                wait = due - time.monotonic()
                if wait > 0 and not stop.is_set():
                    cv.wait(min(wait, 0.5))
                    continue
                held.popleft()
            try:
                verdict(pid)
            except OSError:
                return

    t = threading.Thread(target=releaser, daemon=True)
    t.start()

    def on_term(_sig, _frm) -> None:
        stop.set()
        with cv:
            cv.notify_all()
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    print("ready", flush=True)
    s.settimeout(0.3)
    while not stop.is_set():
        try:
            data = s.recv(1 << 20)
        except TimeoutError:
            continue
        except OSError:
            break
        now = time.monotonic()
        with cv:
            for pid in packet_ids(data):
                held.append((now + delay, pid))
            cv.notify()
    # accept whatever is still held, then leave (closing the socket unbinds the queue)
    with cv:
        pending = [p for _d, p in held]
        held.clear()
    for pid in pending:
        try:
            verdict(pid)
        except OSError:
            break
    t.join(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())

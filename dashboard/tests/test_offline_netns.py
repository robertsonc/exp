"""04-dashboard.md 7.7: offline operation in a network namespace with no default route.

The outer test re-executes this file inside `unshare -n` (only a loopback interface, no default
route). The inner test brings lo up, runs the dashboard against fake collectors on loopback,
logs in with a local user and a NOC token, receives a live SSE event, and asserts by packet
capture (AF_PACKET) that no packet left loopback and that a connection to a public address fails.
"""
from __future__ import annotations

import errno
import fcntl
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from test_federation import incident
from test_sse import Sse, wait_upstream

INNER = "EXP_OFFLINE_INNER"
HERE = Path(__file__).resolve()


def _lo_up() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifr = struct.pack("16sH14x", b"lo", 0)
        flags = struct.unpack("16sH14x", fcntl.ioctl(s, 0x8913, ifr))[1]          # SIOCGIFFLAGS
        fcntl.ioctl(s, 0x8914, struct.pack("16sH14x", b"lo", flags | 0x1))         # SIOCSIFFLAGS, IFF_UP
    finally:
        s.close()


if os.environ.get(INNER):
    _lo_up()          # a fresh namespace has lo down; bring it up before any fixture binds


def _route_table() -> list[str]:
    return Path("/proc/net/route").read_text().splitlines()[1:]


def test_outer_runs_inside_netns() -> None:
    if os.environ.get(INNER):
        pytest.skip("inner run")
    unshare = shutil.which("unshare")
    if not unshare:
        pytest.skip("unshare not available")
    probe = subprocess.run([unshare, "-n", "true"], capture_output=True, timeout=20)
    if probe.returncode != 0:
        pytest.skip("cannot create a network namespace here")
    env = dict(os.environ, **{INNER: "1"})
    r = subprocess.run(
        [unshare, "-n", sys.executable, "-m", "pytest", f"{HERE}::test_inner_offline", "-q",
         "-p", "no:cacheprovider", "--rootdir", str(HERE.parent)],
        capture_output=True, text=True, timeout=240, env=env)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-2000:]
    assert "1 passed" in r.stdout


def test_inner_offline(world) -> None:
    if not os.environ.get(INNER):
        pytest.skip("runs only inside the namespace")
    # no default route, no non-loopback interface
    assert [ln for ln in _route_table() if ln.split()[1] == "00000000"] == []
    ifaces = {ln.split(":")[0].strip() for ln in Path("/proc/net/dev").read_text().splitlines()[2:]}
    assert ifaces <= {"lo"}
    with pytest.raises(OSError) as ei:
        socket.create_connection(("192.0.2.1", 443), timeout=3)
    assert ei.value.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH)

    seen: set[str] = set()
    stop = threading.Event()
    cap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    cap.settimeout(0.2)

    def sniff() -> None:
        while not stop.is_set():
            try:
                pkt = cap.recv(65535)
            except TimeoutError:
                continue
            if len(pkt) >= 34 and pkt[12:14] == b"\x08\x00":
                seen.add(socket.inet_ntoa(pkt[26:30]))
                seen.add(socket.inet_ntoa(pkt[30:34]))

    t = threading.Thread(target=sniff, daemon=True)
    t.start()
    try:
        c = world.as_user("alice")                                   # local login
        assert c.whoami().status == 200
        n = world.client()
        assert n.noc(world.noc_token).status == 200                  # NOC token
        assert n.get("/api/v1/probes").status == 200
        wait_upstream(world)
        s = Sse(world, "/api/v1/stream?probes=probe-c1", n)          # live updates
        try:
            assert s.wait(lambda: s.status == 200)
            world.fakes["col-c"].app.inject_incident(
                incident("inc_01M7R3X9G0NTM2HDJYD21Y49WA", "probe-c1", "hall-c", "2026-11-18T10:00:00.000Z"))
            assert s.wait(lambda: len(s.kinds("incident")) >= 1)
        finally:
            s.close()
    finally:
        stop.set()
        t.join(5)
        cap.close()
    assert seen, "capture saw no traffic at all (capture not working)"
    assert all(ip.startswith("127.") for ip in seen), seen

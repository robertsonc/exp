"""Network access inside a port's namespace (the seam every measurement test talks through).

The probe daemon runs in the host namespace. A test that needs sockets "inside" a port's namespace
runs its socket code in a short-lived thread that switched to that namespace with setns(2) -- plain
sockets, no child process per check (ported from reference/exm/lib/exm/heartbeat.py:_in_netns).
Only the calling thread moves; the daemon's other threads stay where they are.

* `NetEnv.call(fn, ...)`  run `fn` in the namespace (host mode / control path: in place).
* `NetEnv.socket(...)`    create a socket; in host mode it is pinned to the test interface with
                          SO_BINDTODEVICE (a host-namespace probe must never leak onto mgmt).
* `NetEnv.icmp()`         the raw ICMP endpoint (`exp_probe.icmp.RawIcmp`).
* `NetEnv.packet_io(i)`   an AF_PACKET endpoint for the raw DHCP client.

Unit tests substitute `LocalEnv`-style subclasses (see probe/tests/netfakes.py) so that nothing here
needs root or a real namespace. Python 3.10 has no os.setns (3.12+), so ctypes/libc is the fallback.
"""
from __future__ import annotations

import ctypes
import fcntl
import logging
import os
import select
import socket
import struct
import threading
import time
from collections.abc import Callable
from typing import Any, TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")
CLONE_NEWNET = 0x40000000
SIOCGIFFLAGS, IFF_RUNNING = 0x8913, 0x40
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
ETH_P_IP = 0x0800
NETNS_DIR = "/run/netns"


class NetnsMissing(OSError):
    """The port's namespace does not exist (netns service not up, or the port was never set up)."""


def _setns(fd: int) -> None:
    if hasattr(os, "setns"):
        os.setns(fd, CLONE_NEWNET)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.setns(fd, CLONE_NEWNET) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


class NetEnv:
    """A network context: a named namespace (or the host's own) plus an optional device pin."""

    def __init__(self, ns: str | None = None, bind_iface: str | None = None, label: str = "",
                 netns_dir: str = NETNS_DIR) -> None:
        self.ns = ns
        self.bind_iface = bind_iface
        self.label = label or (ns or "host")
        self.netns_dir = netns_dir

    # ---- existence
    def exists(self) -> bool:
        return self.ns is None or os.path.exists(os.path.join(self.netns_dir, self.ns))

    # ---- running code in the namespace
    def call(self, fn: Callable[..., T], *args: Any, **kw: Any) -> T:
        if self.ns is None:
            return fn(*args, **kw)
        path = os.path.join(self.netns_dir, self.ns)
        box: dict[str, Any] = {}

        def target() -> None:
            try:
                try:
                    fd = os.open(path, os.O_RDONLY)
                except FileNotFoundError as exc:
                    raise NetnsMissing(f"namespace {self.ns} is missing") from exc
                try:
                    _setns(fd)
                finally:
                    os.close(fd)
                box["result"] = fn(*args, **kw)
            except BaseException as exc:             # noqa: BLE001 - handed back to the caller verbatim
                box["error"] = exc

        t = threading.Thread(target=target, name=f"exp-ns-{self.ns}", daemon=True)
        t.start()
        t.join()
        if "error" in box:
            raise box["error"]
        return box["result"]

    # ---- sockets (MUST be created inside `call` when ns is set)
    def socket(self, family: int, type_: int, proto: int = 0) -> socket.socket:
        s = socket.socket(family, type_, proto)
        if self.bind_iface:
            try:
                s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, self.bind_iface.encode() + b"\0")
            except OSError:
                s.close()
                raise
        return s

    def icmp(self) -> Any:
        from .icmp import RawIcmp
        return RawIcmp(self.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP))

    def packet_io(self, iface: str) -> Any:
        from .dhcpwire import PacketIO
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        try:
            s.bind((iface, ETH_P_IP))
        except OSError:
            s.close()
            raise
        return PacketIO(s)

    def link_running(self, iface: str) -> bool:
        """IFF_RUNNING (carrier) of `iface` as seen from this namespace (call inside `call`)."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            flags = struct.unpack("16sH", fcntl.ioctl(s, SIOCGIFFLAGS, struct.pack("16sH", iface.encode(), 0)))[1]
        finally:
            s.close()
        return bool(flags & IFF_RUNNING)


def env_for(cfg: Any, port: Any, control: bool = False) -> NetEnv:
    """The environment a test of `port` runs in (control=True: the host namespace, pinned to mgmt)."""
    from .runner import ns_name
    if control:
        return NetEnv(None, cfg.mgmt_iface, label="control")
    if cfg.mode == "host":
        return NetEnv(None, port.lease_iface, label=f"host:{port.id}")
    return NetEnv(ns_name(port.id), None, label=port.id)


def wait_readable(sock: socket.socket, timeout: float) -> bool:
    if timeout <= 0:
        timeout = 0.0
    r, _, _ = select.select([sock], [], [], timeout)
    return bool(r)


def monotonic() -> float:
    return time.perf_counter()

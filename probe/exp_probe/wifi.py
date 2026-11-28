"""Wi-Fi ports (02-probe.md 5.11): the radio in its own namespace, ``wpa_supplicant`` joining ONE SSID.

* **Namespace.** A Wi-Fi interface cannot be moved with ``ip link set ... netns`` (cfg80211 marks it
  netns-local); its whole radio (phy) moves with ``iw phy <phy> set netns name <ns>`` and back with
  ``iw phy <phy> set netns 1``. A radio that carries any other interface is refused by preflight (moving
  the phy would take that interface with it).
* **Supervisor.** ``exp-probe wifi <port>`` (unit ``exp-probe-wifi@<port>``) writes
  ``/run/exp/probe/<port>/wpa_supplicant.conf`` (root 0600) and execs ``wpa_supplicant`` inside the
  namespace. The config lists only the target SSID, so the supplicant cannot wander to another network;
  the heartbeat still checks (``on_target``). The SSID is written hex-encoded (no quoting / injection).
* **Security.** Open and OWE (Enhanced Open) networks only -- an event's public Wi-Fi has no credential.
  ``security: auto`` (default) offers OWE first and plain open second, so an OWE or OWE-transition SSID
  is joined encrypted and a plain open one still works. PSK / 802.1X are not in this build.
* **MAC.** The radio's permanent MAC is used for scans and association (``mac_addr=0``): a venue NOC can
  allowlist it past a captive portal, and the address does not change between joins.
* **Control.** The daemon talks to the supplicant's control socket directly (a datagram UNIX socket under
  /run, reachable from the host namespace; ``wpa_cli`` would bind its reply socket in a private /tmp the
  supplicant cannot see). `Ctrl` is the seam unit tests replace.
"""
from __future__ import annotations

import logging
import os
import socket
import sys
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .config import Paths, Port, ProbeConfig
from .runner import ns_exec_argv

log = logging.getLogger(__name__)

SECURITY = ("auto", "open", "owe")
BANDS = ("2.4", "5", "6", "any")
CTRL_TIMEOUT_S = 2.0
# Primary 20 MHz channels per band (IEEE 802.11 channel -> MHz); 5 GHz U-NII-1..4 without the
# rarely-used 68-96 block, 6 GHz PSC and non-PSC channels 1..233.
_CH_24 = [*range(1, 14)]
_CH_5 = [*range(36, 65, 4), *range(100, 145, 4), *range(149, 178, 4)]
_CH_6 = [*range(1, 234, 4)]


def chan_to_freq(band: str, ch: int) -> int:
    if band == "2.4":
        return 2484 if ch == 14 else 2407 + 5 * ch
    if band == "5":
        return 5000 + 5 * ch
    return 5950 + 5 * ch


def freq_to_channel(freq: int | None) -> tuple[int | None, str | None]:
    """(channel, band) of a centre frequency in MHz; (None, None) when unknown."""
    if not isinstance(freq, int) or isinstance(freq, bool):
        return None, None
    if freq == 2484:
        return 14, "2.4"
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5, "2.4"
    if 5150 <= freq <= 5925:
        return (freq - 5000) // 5, "5"
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5, "6"
    return None, None


def freq_list(band: str | None) -> list[int]:
    if band == "2.4":
        return [chan_to_freq("2.4", c) for c in _CH_24]
    if band == "5":
        return [chan_to_freq("5", c) for c in _CH_5]
    if band == "6":
        return [chan_to_freq("6", c) for c in _CH_6]
    return []


# ------------------------------------------------------------------------------------ port options

def ssid_of(port: Port) -> str:
    return str(port.raw.get("ssid") or "")


def security_of(port: Port) -> str:
    v = port.raw.get("security") or "auto"
    return v if v in SECURITY else "auto"


def band_of(port: Port) -> str:
    v = port.raw.get("band") or "any"
    return v if v in BANDS else "any"


def ctrl_dir(paths: Paths, port_id: str) -> Path:
    return paths.port_run_dir(port_id) / "wpa"


def conf_path(paths: Paths, port_id: str) -> Path:
    return paths.port_run_dir(port_id) / "wpa_supplicant.conf"


def wpa_conf(cfg: ProbeConfig, port: Port, paths: Paths) -> str:
    """wpa_supplicant.conf for an open / OWE network. Never contains a credential."""
    ssid = ssid_of(port)
    if not ssid:
        raise ValueError(f"port {port.id}: role wifi needs an ssid")
    hexssid = ssid.encode("utf-8").hex()
    lines = [
        f"# exp-probe: generated for port {port.id}; rewritten on every start, do not edit",
        f"ctrl_interface=DIR={ctrl_dir(paths, port.id)} GROUP=root",
        "update_config=0",
        "ap_scan=1",
        "mac_addr=0",            # the radio's permanent MAC: stable, allowlistable
        "preassoc_mac_addr=0",
        "gas_rand_mac_addr=0",
        "p2p_disabled=1",
        "pmf=1",
    ]
    country = port.raw.get("country")
    if isinstance(country, str) and len(country) == 2 and country.isalpha() and country.isascii():
        lines.append(f"country={country.upper()}")
    freqs = freq_list(band_of(port))
    common = [f"\tssid={hexssid}", "\tscan_ssid=1",
              '\tbgscan="simple:30:-70:3600"']      # look for a better AP while connected (venue roaming)
    if freqs:
        common.append("\tfreq_list=" + " ".join(str(f) for f in freqs))
    sec = security_of(port)
    blocks: list[list[str]] = []
    if sec in ("auto", "owe"):
        blocks.append(["network={", *common, "\tkey_mgmt=OWE", "\tieee80211w=2", "\tpriority=2", "}"])
    if sec in ("auto", "open"):
        blocks.append(["network={", *common, "\tkey_mgmt=NONE", "\tpriority=1", "}"])
    for b in blocks:
        lines += b
    return "\n".join(lines) + "\n"


def supplicant_argv(port: Port, paths: Paths) -> list[str]:
    return ns_exec_argv(port.id, ["wpa_supplicant", "-i", port.iface, "-D", "nl80211",
                                  "-c", str(conf_path(paths, port.id))])


def run_wifi(cfg: ProbeConfig, port_id: str, runner: Any, paths: Paths,
             exec_fn: Callable[[str, list[str], Mapping[str, str]], Any] = os.execvpe) -> int:
    """`exp-probe wifi <port>`: write the config and exec wpa_supplicant in the port's namespace."""
    from .netns import netns_names
    port = cfg.port(port_id)
    if port.role != "wifi":
        print(f"exp-probe: port {port_id} has role {port.role}; only wifi ports run wpa_supplicant", file=sys.stderr)
        return 2
    if port.ns not in netns_names(runner):
        print(f"exp-probe: namespace {port.ns} does not exist (is exp-probe-netns.service up?)", file=sys.stderr)
        return 3
    rd = paths.port_run_dir(port.id)
    rd.mkdir(parents=True, exist_ok=True)
    cd = ctrl_dir(paths, port.id)
    if cd.is_symlink():
        print(f"exp-probe: {cd} is a symlink; refusing", file=sys.stderr)
        return 4
    cd.mkdir(mode=0o700, exist_ok=True)
    for stale in cd.iterdir():          # a socket left by a crashed supplicant blocks its restart
        if stale.is_socket():
            stale.unlink()
    p = conf_path(paths, port.id)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, wpa_conf(cfg, port, paths).encode())
    finally:
        os.close(fd)
    argv = supplicant_argv(port, paths)
    log.info("exec %s", " ".join(argv))
    exec_fn(argv[0], argv, dict(os.environ))
    return 0          # only reached by a test double


# ------------------------------------------------------------------------- join in progress
# A wifi_join cycles the association on purpose; while it runs, the other heartbeats leave that port alone
# (their failures would be the test's own doing, not an outage).
_JOINING: set[str] = set()
_JOINING_LOCK = threading.Lock()


def begin_join(port_id: str) -> bool:
    with _JOINING_LOCK:
        if port_id in _JOINING:
            return False
        _JOINING.add(port_id)
        return True


def end_join(port_id: str) -> None:
    with _JOINING_LOCK:
        _JOINING.discard(port_id)


def joining(port_id: str) -> bool:
    with _JOINING_LOCK:
        return port_id in _JOINING


# ------------------------------------------------------------------------------- control socket

class CtrlUnavailable(OSError):
    """The supplicant's control socket is missing or did not answer."""


class Ctrl:
    """Request/response on wpa_supplicant's control socket (``ctrl_dir/<iface>``)."""

    _seq = 0
    _lock = threading.Lock()

    def __init__(self, paths: Paths, port: Port, timeout: float = CTRL_TIMEOUT_S) -> None:
        self.server = ctrl_dir(paths, port.id) / port.iface
        self.client_dir = paths.port_run_dir(port.id)
        self.timeout = timeout

    def request(self, cmd: str) -> str:
        if not self.server.exists():
            raise CtrlUnavailable(f"wpa_supplicant control socket {self.server} is missing")
        with Ctrl._lock:
            Ctrl._seq += 1
            local = self.client_dir / f".ctrl-{os.getpid()}-{Ctrl._seq}"
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            s.settimeout(self.timeout)
            s.bind(str(local))
            s.connect(str(self.server))
            s.send(cmd.encode())
            while True:
                data = s.recv(8192).decode("utf-8", "replace")
                if not data.startswith("<"):       # skip unsolicited event messages ("<3>CTRL-EVENT-...")
                    return data
        except (TimeoutError, OSError) as exc:
            raise CtrlUnavailable(f"wpa_supplicant did not answer {cmd.split()[0]}: {exc}") from exc
        finally:
            s.close()
            try:
                local.unlink()
            except OSError:
                pass


def parse_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for ln in text.splitlines():
        k, sep, v = ln.partition("=")
        if sep and k and k.isidentifier():
            out[k] = v
    return out


def decode_ssid(s: str) -> str:
    """Undo wpa_supplicant's printf_encode (\\\\, \\", \\e, \\n, \\r, \\t, \\xNN)."""
    out = bytearray()
    i = 0
    raw = s.encode("utf-8", "surrogateescape")
    simple = {ord("\\"): 0x5C, ord('"'): 0x22, ord("e"): 0x1B, ord("n"): 0x0A, ord("r"): 0x0D, ord("t"): 0x09}
    while i < len(raw):
        c = raw[i]
        if c == 0x5C and i + 1 < len(raw):
            n = raw[i + 1]
            if n in simple:
                out.append(simple[n])
                i += 2
                continue
            if n == ord("x") and i + 3 < len(raw):
                try:
                    out.append(int(raw[i + 2:i + 4].decode(), 16))
                    i += 4
                    continue
                except ValueError:
                    pass
        out.append(c)
        i += 1
    return out.decode("utf-8", "replace")


def int_or_none(v: str | None, lo: int = -10_000, hi: int = 1_000_000) -> int | None:
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        return None
    return n if lo <= n <= hi else None

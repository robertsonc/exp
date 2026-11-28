"""`wifi_hb` (every beat) and `wifi_join` (scheduled, `tests.wifi`) -- 02-probe.md 5.11.

The port's own ``wpa_supplicant`` (`exp_probe.wifi`) holds the association; these tests read it over its
control socket and never change the configuration.

``wifi_hb`` -- one record per Wi-Fi port per beat. Labels: ``port``, ``ssid`` (the SSID actually joined,
``none`` when not associated) and ``band`` (configured). Metrics: ``link_up``, ``rssi_dbm``, ``noise_dbm``,
``snr_db``, ``tx_rate_mbps``, ``channel``, ``gw_rtt_ms``. Detail: ``bssid``, ``freq_mhz``, ``band_seen``,
``security`` (``open`` | ``owe``), ``on_target``, ``target_ssid``, ``portal`` (true / false / null when
not known), ``portal_reason``, ``dhcp_captive_portal_uri``, ``rejoin`` (a rejoin was requested this beat).
Outcome:

* not associated, associated to another SSID, no DHCP lease, or no reply from the gateway -> ``fail``;
  while not on target a rejoin (``REASSOCIATE``) is requested at most every REJOIN_EVERY_S;
* a captive portal intercepting the connectivity check, RSSI below ``thresholds.rssi_dbm`` (-75), SNR
  below ``thresholds.snr_db`` (15), gateway RTT above ``thresholds.gw_rtt_ms`` (150) or some loss to the
  gateway -> ``degraded``;
* the supplicant not running / its control socket silent -> ``error`` (the probe could not measure).

Captive portal check: ``curl`` inside the namespace to ``tests.wifi.portal_url`` (default
http://connectivitycheck.gstatic.com/generate_204, which always answers an empty 204) on the first beat
after a (re)association or a lease change and then every PORTAL_EVERY_S; the result is cached in between.
A portal is reported, never clicked through: ask the venue to allowlist the probe's MAC.

``wifi_join`` -- an active join measurement: DISCONNECT, RECONNECT, then the times to association
(``assoc_ms``), to a completed join (``auth_ms``: OWE key exchange; ~0 on an open network), and to a
renewed DHCP lease (``dhcp_ms``; udhcpc SIGUSR1), plus ``total_ms``. The Wi-Fi port is offline for
that time (typically 1-3 s), so it runs only when `tests.wifi` is configured (``interval_s``). States are
sampled every POLL_S, so the phase times are +-POLL_S. Outcome: no join within JOIN_TIMEOUT_S, another
SSID, or no lease -> ``fail``; total above ``thresholds.join_ms`` (5000) -> ``degraded``.
"""
from __future__ import annotations

import logging
import os
import signal
import threading
import time
from dataclasses import dataclass
from typing import Any

from exp_common.schema import Measurement

from .. import wifi as wf
from ..icmp import IcmpUnavailable
from ..lease import read_lease
from ..netio import NetnsMissing
from ..scheduler import TestContext, register_test
from .app import detect_captive, parse_curl
from .common import clip, error_record, num, port_info, test_option, thresholds
from .gateway import _echo

log = logging.getLogger(__name__)

REJOIN_EVERY_S = 60.0
PORTAL_EVERY_S = 60.0
PORTAL_MAX_TIME_S = 5
DEFAULT_PORTAL_URL = "http://connectivitycheck.gstatic.com/generate_204"
POLL_S = 0.05
JOIN_TIMEOUT_S = 20.0
DHCP_TIMEOUT_S = 15.0
NOISE_UNKNOWN = 9999
ASSOCIATED = ("ASSOCIATED", "4WAY_HANDSHAKE", "GROUP_HANDSHAKE", "COMPLETED")

# The seam unit tests replace: (paths, port) -> object with .request(cmd) -> str
CTRL_FACTORY: Any = wf.Ctrl
SLEEP: Any = time.sleep
MONO: Any = time.monotonic
KILL: Any = os.kill


@dataclass
class _PortState:
    bssid: str | None = None
    lease_ts: str | None = None
    last_rejoin: float = -1e18
    portal_at: float = -1e18
    portal: bool | None = None
    portal_reason: str | None = None


_STATE: dict[str, _PortState] = {}
_STATE_LOCK = threading.Lock()


def _state(port_id: str) -> _PortState:
    with _STATE_LOCK:
        return _STATE.setdefault(port_id, _PortState())


def reset_state() -> None:
    with _STATE_LOCK:
        _STATE.clear()


def _security(key_mgmt: str | None) -> str | None:
    if not key_mgmt:
        return None
    k = key_mgmt.upper()
    if k == "NONE":
        return "open"
    if k == "OWE":
        return "owe"
    return clip(key_mgmt.lower(), 32)


def _noise_from_survey(ctx: TestContext, iface: str) -> int | None:
    """Noise floor of the in-use channel from ``iw dev <if> survey dump`` (when SIGNAL_POLL has none)."""
    r = ctx.runner.run(ctx.ns_argv(["iw", "dev", iface, "survey", "dump"]), 5)
    if not r.ok:
        return None
    in_use = False
    for ln in r.stdout.splitlines():
        s = ln.strip()
        if s.startswith("frequency:"):
            in_use = "[in use]" in s
        elif in_use and s.startswith("noise:"):
            return wf.int_or_none(s.split()[1], -130, 0)
    return None


def _portal(ctx: TestContext, port: Any) -> tuple[bool | None, str | None]:
    url = str(test_option(ctx, "wifi", "portal_url", DEFAULT_PORTAL_URL))
    argv = ["curl", "-sS", "-L", "--max-redirs", "3", "--max-time", str(PORTAL_MAX_TIME_S), "--noproxy", "*",
            "-A", "exp-probe", "-o", os.devnull, "-w", "%{json}", "--url", url]
    r = ctx.runner.run(ctx.ns_argv(argv), PORTAL_MAX_TIME_S + 3)
    if r.rc == 127:
        return None, "curl is not installed"
    res = parse_curl(r.stdout, r.stderr, r.rc)
    if not res.ok:
        return None, clip(f"connectivity check failed: {res.error or 'no result'}", 200)
    why = detect_captive(url, res, "", {})
    return (True, clip(why, 200)) if why else (False, None)


def _gateway(ctx: TestContext, port: Any, gw: str) -> tuple[float | None, float | None, str | None]:
    """(rtt_ms, loss_pct, error) of the gateway echo inside the namespace."""
    env = ctx.netenv(port)
    try:
        res = env.call(_echo, env, gw)
    except NetnsMissing:
        return None, None, f"namespace for port {port.id} is missing"
    except IcmpUnavailable as exc:
        return None, None, str(exc)
    except OSError as exc:
        return None, None, f"ICMP failed: {exc.strerror or exc}"
    if res.error and not res.received:
        return None, None, f"cannot send to {gw}: {res.error}"
    return res.rtt_ms, res.loss_pct, None


def _rejoin(ctrl: Any, st: _PortState) -> bool:
    now = MONO()
    if now - st.last_rejoin < REJOIN_EVERY_S:
        return False
    st.last_rejoin = now
    try:
        ctrl.request("REASSOCIATE")
    except wf.CtrlUnavailable as exc:
        log.warning("rejoin request failed: %s", exc)
    return True


@register_test("wifi_hb", roles=("wifi",))
def wifi_hb(ctx: TestContext) -> list[Measurement]:
    port = ctx.port
    assert port is not None
    target = wf.ssid_of(port)
    labels = {"port": port.id, "ssid": "none", "band": wf.band_of(port)}
    if not ctx.netenv(port).exists():
        return [error_record(ctx, "wifi_hb", f"namespace for port {port.id} is missing", labels=labels)]
    ctrl = CTRL_FACTORY(ctx.paths, port)
    try:
        status = wf.parse_kv(ctrl.request("STATUS"))
    except wf.CtrlUnavailable as exc:
        return [error_record(ctx, "wifi_hb", f"wpa_supplicant not running for {port.id} "
                             f"(exp-probe-wifi@{port.id}): {exc}", labels=labels)]
    st = _state(port.id)
    if wf.joining(port.id):
        return []                   # wifi_join has the radio offline on purpose; not an outage
    state = status.get("wpa_state", "UNKNOWN")
    detail: dict[str, Any] = {"target_ssid": target, "on_target": False, "wpa_state": clip(state, 32)}
    metrics: dict[str, float] = {"link_up": 0.0}
    if state != "COMPLETED":
        st.bssid = None
        detail["rejoin"] = _rejoin(ctrl, st)
        return [ctx.measure("wifi_hb", "fail", labels=labels, metrics=metrics, detail=detail,
                            error=f"not associated to {clip(target, 32)!r} (wpa_state {clip(state, 32)})")]
    ssid = clip(wf.decode_ssid(status.get("ssid", "")), 32) or "none"
    labels["ssid"] = ssid
    bssid = clip(status.get("bssid", ""), 17).lower() or None
    freq = wf.int_or_none(status.get("freq"), 2000, 8000)
    ch, band_seen = wf.freq_to_channel(freq)
    detail.update({"bssid": bssid, "freq_mhz": freq, "band_seen": band_seen,
                   "security": _security(status.get("key_mgmt"))})
    metrics["link_up"] = 1.0
    if ch is not None:
        metrics["channel"] = float(ch)
    try:
        sig = wf.parse_kv(ctrl.request("SIGNAL_POLL"))
    except wf.CtrlUnavailable:
        sig = {}
    rssi = wf.int_or_none(sig.get("RSSI"), -130, 0)
    noise = wf.int_or_none(sig.get("NOISE"), -130, 0)
    if noise is None:
        noise = _noise_from_survey(ctx, port.iface)
    rate = wf.int_or_none(sig.get("LINKSPEED"), 0, 100_000)
    if rssi is not None:
        metrics["rssi_dbm"] = float(rssi)
    if noise is not None:
        metrics["noise_dbm"] = float(noise)
        if rssi is not None:
            metrics["snr_db"] = float(rssi - noise)
    if rate is not None:
        metrics["tx_rate_mbps"] = float(rate)
    on_target = ssid == target
    detail["on_target"] = on_target
    roamed = bssid != st.bssid
    st.bssid = bssid
    if not on_target:
        detail["rejoin"] = _rejoin(ctrl, st)
        return [ctx.measure("wifi_hb", "fail", labels=labels, metrics=metrics, detail=detail,
                            error=f"joined {ssid!r}, not the target {clip(target, 32)!r}")]
    lease = read_lease(ctx.paths, port.id) or {}
    info = port_info(ctx, port)
    if info.captive_portal_uri:
        detail["dhcp_captive_portal_uri"] = clip(info.captive_portal_uri, 500)
    if not info.bound or not info.gateway:
        return [ctx.measure("wifi_hb", "fail", labels=labels, metrics=metrics, detail=detail,
                            error=f"associated to {ssid!r} but no DHCP lease")]
    detail["gateway_ip"] = info.gateway
    rtt, loss, gerr = _gateway(ctx, port, info.gateway)
    if gerr:
        return [error_record(ctx, "wifi_hb", gerr, labels=labels, detail=detail)]
    kw: dict[str, Any] = {}
    if rtt is not None:
        metrics["gw_rtt_ms"] = num(rtt)  # type: ignore[assignment]
        kw["duration_ms"] = num(rtt)
    if loss:
        metrics["gw_loss_pct"] = float(loss)
    if loss is not None and loss >= 100:
        return [ctx.measure("wifi_hb", "fail", labels=labels, metrics=metrics, detail=detail,
                            error=f"no reply from gateway {info.gateway} over Wi-Fi", **kw)]
    now = MONO()
    lease_ts = str(lease.get("ts") or "")
    if lease_ts != st.lease_ts or now - st.portal_at >= PORTAL_EVERY_S or (roamed and st.portal is None):
        st.portal, st.portal_reason = _portal(ctx, port)
        st.portal_at, st.lease_ts = now, lease_ts
    detail["portal"] = st.portal
    if st.portal_reason:
        detail["portal_reason"] = st.portal_reason
    problems: list[str] = []
    if st.portal:
        problems.append(f"captive portal: {st.portal_reason}")
    rssi_min = -abs(thresholds(ctx, "wifi", "rssi_dbm", 75.0))
    if rssi is not None and rssi < rssi_min:
        problems.append(f"weak signal {rssi} dBm (below {rssi_min:g})")
    snr = metrics.get("snr_db")
    snr_min = thresholds(ctx, "wifi", "snr_db", 15.0)
    if snr is not None and snr < snr_min:
        problems.append(f"SNR {snr:g} dB (below {snr_min:g})")
    rtt_max = thresholds(ctx, "wifi", "gw_rtt_ms", 150.0)
    if rtt is not None and rtt > rtt_max:
        problems.append(f"gateway RTT {rtt:g} ms (above {rtt_max:g})")
    if loss:
        problems.append(f"{loss:g}% loss to the gateway")
    if problems:
        return [ctx.measure("wifi_hb", "degraded", labels=labels, metrics=metrics, detail=detail,
                            error=clip("; ".join(problems), 500), **kw)]
    return [ctx.measure("wifi_hb", "ok", labels=labels, metrics=metrics, detail=detail, **kw)]


def _wait_state(ctrl: Any, want: tuple[str, ...], deadline: float) -> tuple[str | None, dict[str, str]]:
    last: dict[str, str] = {}
    while MONO() < deadline:
        try:
            last = wf.parse_kv(ctrl.request("STATUS"))
        except wf.CtrlUnavailable:
            last = {}
        if last.get("wpa_state") in want:
            return last["wpa_state"], last
        SLEEP(POLL_S)
    return None, last


def _renew(ctx: TestContext, port: Any, deadline: float) -> tuple[bool, str | None]:
    """SIGUSR1 to the port's udhcpc (renew now) and wait for a fresh bound lease."""
    before = (read_lease(ctx.paths, port.id) or {}).get("ts")
    try:
        pid = int(ctx.paths.pid_file(port.id).read_text(encoding="utf-8").strip())
        KILL(pid, signal.SIGUSR1)
    except (OSError, ValueError) as exc:
        return False, f"cannot ask the DHCP client to renew: {exc}"
    while MONO() < deadline:
        doc = read_lease(ctx.paths, port.id) or {}
        if doc.get("state") == "bound" and doc.get("ts") != before:
            return True, None
        SLEEP(POLL_S)
    return False, f"no DHCP lease within {DHCP_TIMEOUT_S:g} s of joining"


@register_test("wifi_join", roles=("wifi",))
def wifi_join(ctx: TestContext) -> list[Measurement]:
    port = ctx.port
    assert port is not None
    target = wf.ssid_of(port)
    labels = {"port": port.id, "ssid": clip(target, 32) or "none"}
    if not ctx.netenv(port).exists():
        return [error_record(ctx, "wifi_join", f"namespace for port {port.id} is missing", labels=labels)]
    st = _state(port.id)
    if not wf.begin_join(port.id):
        return []
    try:
        return _join(ctx, port, target, labels)
    finally:
        wf.end_join(port.id)
        st.bssid = None             # the next heartbeat re-checks the portal on the fresh association


def _join(ctx: TestContext, port: Any, target: str, labels: dict[str, str]) -> list[Measurement]:
    ctrl = CTRL_FACTORY(ctx.paths, port)
    try:
        ctrl.request("DISCONNECT")
    except wf.CtrlUnavailable as exc:
        return [error_record(ctx, "wifi_join", f"wpa_supplicant not running for {port.id}: {exc}", labels=labels)]
    _wait_state(ctrl, ("DISCONNECTED", "INACTIVE"), MONO() + 2.0)
    t0 = MONO()
    try:
        ctrl.request("RECONNECT")
    except wf.CtrlUnavailable as exc:
        return [error_record(ctx, "wifi_join", f"wpa_supplicant stopped answering: {exc}", labels=labels)]
    detail: dict[str, Any] = {"reason": "scheduled", "target_ssid": target}
    deadline = t0 + JOIN_TIMEOUT_S
    seen, _ = _wait_state(ctrl, ASSOCIATED, deadline)
    t_assoc = MONO()
    if seen is None:
        return [ctx.measure("wifi_join", "fail", labels=labels, detail=detail,
                            error=f"no association to {clip(target, 32)!r} within {JOIN_TIMEOUT_S:g} s")]
    done, status = (seen, None) if seen == "COMPLETED" else _wait_state(ctrl, ("COMPLETED",), deadline)
    t_auth = MONO()
    if done is None:
        return [ctx.measure("wifi_join", "fail", labels=labels, detail=detail,
                            metrics={"assoc_ms": round((t_assoc - t0) * 1000, 1)},
                            error="associated but the join did not complete (key exchange)")]
    if status is None:
        try:
            status = wf.parse_kv(ctrl.request("STATUS"))
        except wf.CtrlUnavailable:
            status = {}
    ssid = clip(wf.decode_ssid(status.get("ssid", "")), 32) or "none"
    detail.update({"bssid": clip(status.get("bssid", ""), 17).lower() or None,
                   "security": _security(status.get("key_mgmt"))})
    metrics: dict[str, float] = {"assoc_ms": round((t_assoc - t0) * 1000, 1),
                                 "auth_ms": round((t_auth - t_assoc) * 1000, 1)}
    if ssid != target:
        labels["ssid"] = ssid
        return [ctx.measure("wifi_join", "fail", labels=labels, metrics=metrics, detail=detail,
                            error=f"joined {ssid!r}, not the target {clip(target, 32)!r}")]
    ok, why = _renew(ctx, port, t_auth + DHCP_TIMEOUT_S)
    t_dhcp = MONO()
    if not ok:
        return [ctx.measure("wifi_join", "fail", labels=labels, metrics=metrics, detail=detail,
                            error=why or "no DHCP lease")]
    metrics["dhcp_ms"] = round((t_dhcp - t_auth) * 1000, 1)
    total = round((t_dhcp - t0) * 1000, 1)
    metrics["total_ms"] = total
    limit = thresholds(ctx, "wifi", "join_ms", 5000.0)
    if total > limit:
        return [ctx.measure("wifi_join", "degraded", labels=labels, metrics=metrics, detail=detail,
                            duration_ms=total, error=f"join took {total:g} ms (above {limit:g})")]
    return [ctx.measure("wifi_join", "ok", labels=labels, metrics=metrics, detail=detail, duration_ms=total)]

"""Diagnosis rules (12 section 5.3), server-side (D3).

``diagnose(test, evidence, baseline, targets, th, stage, now_iso)`` is pure and deterministic: the same inputs
give the same ordered causes. It runs on the quick result (legs only, plus the collector's own probe baseline) and
again when the evidence is final.

Output is the ``exp.speedtest/1`` ``diagnosis`` object: ``cause[]`` ordered by confidence (ties by the order of the
section 5.3 table), each with the evidence it cites; ``user_text`` is one plain, blame-free sentence;
``noc_text`` names the evidence ("hallb-ap-12 ch 44/80 MHz, util 81 %, 74 clients; RSSI -61 dBm").

* ``none`` only when the score is at or above ``none_score`` (default 80); then it is the only cause. If the internet
  leg was not measured (status other than ok) every rule runs first; ``none`` (0.6, status-specific text) only if
  none fires.
* A degraded test where no rule fires gets an empty cause list ("could not pinpoint"); ``cause`` is never invented.
* Evidence with status ``unavailable`` / ``error`` is ignored. Evidence texts (AP names, SSIDs) are untrusted:
  control characters are removed and every text is clipped before it enters ``noc_text``.
"""
from __future__ import annotations

import dataclasses
import math
import re
from collections.abc import Callable, Mapping
from typing import Any

from .settings import Thresholds

CAUSES = ("wifi_signal", "wifi_congestion", "wifi_roaming", "wired_port", "device_limit", "wan_saturation",
          "internet_path", "policy_block", "qos_shaping", "dns", "network_wide", "none")
_PRIORITY = {c: i for i, c in enumerate(CAUSES)}
USER_MAX, NOC_MAX = 280, 600
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_BAD_AUTH = re.compile(r"auth.*(fail|den|reject|timeout)|(fail|den|reject|timeout).*auth", re.IGNORECASE)
_HIGH_HEALTH = ("major", "critical")
_OLD_PROTO = ("a", "b", "g", "n")

USER_TEXT = {
    "none": "Your connection looks healthy.",
    "wifi_signal": "Your Wi-Fi signal is weak where you are. Moving closer to an access point may help.",
    "wifi_congestion": "The Wi-Fi in this area is very busy right now. It should improve as demand drops.",
    "wifi_roaming": "Your device switched between Wi-Fi access points during the test, which interrupts the speed.",
    "wired_port": "The wired network port you are using is reporting problems. The network team can check it.",
    "device_limit": "Your device's own Wi-Fi hardware or settings are limiting the speed. The network looks fine.",
    "wan_saturation": "The venue's internet link is very busy right now. Speeds should recover when demand drops.",
    "internet_path": "The venue network is working, but the route to the internet is slow right now.",
    "policy_block": "Some of your traffic is being blocked by network policy. The network team can look into it.",
    "qos_shaping": "Some of your traffic is rate-limited by network policy to keep things fair for everyone.",
    "dns": "Name lookups are slow or failing, which makes pages feel slow.",
    "network_wide": "It is not just you: nearby network checks show the same slowdown right now.",
}
USER_INTERNET_DOWN = "The venue network is working, but the internet could not be reached right now."
USER_INTERNET_UNMEASURED = {
    "paused": "The venue network is working well. The internet check was paused because the event's internet link "
              "is busy; try again in a few minutes.",
    "queued": "The internet check was still waiting for its turn, so this result covers the venue network only.",
    "skipped": "The internet check was stopped before it finished, so this result covers the venue network only.",
    "unavailable": USER_INTERNET_DOWN,
}
USER_UNKNOWN = "Your speed is below target. We could not pinpoint a cause on the network."
USER_PENDING_UNKNOWN = "Your speed is below target. We are checking the network to find out why."


def clean(v: Any, n: int = 64) -> str:
    return _CTRL.sub("", str(v))[:n]


def _num(v: Any) -> float | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        return None
    return float(v)


def _fmt(v: float | None, unit: str = "", nd: int = 0) -> str:
    return "?" if v is None else (f"{v:.{nd}f}".rstrip("0").rstrip(".") if nd else f"{v:.0f}") + unit


def _band_key(band: Any) -> str | None:
    s = str(band or "")
    if s.startswith("24"):
        return "24"
    if s.startswith("5"):
        return "5"
    if s.startswith("6"):
        return "6"
    return None


def _cite(kind: str, ref: str | None = None) -> dict[str, str]:
    return {"kind": kind, **({"ref": ref} if ref else {})}


@dataclasses.dataclass
class Hit:
    cause: str
    conf: float
    noc: str
    cites: list[dict[str, str]]


@dataclasses.dataclass
class Ctx:
    test: Mapping[str, Any]
    ev: dict[str, dict[str, Any]]            # kind -> evidence data (usable evidence only)
    baseline: Mapping[str, Any] | None
    targets: Mapping[str, float]
    th: Thresholds
    stage: str

    # ---- legs ---------------------------------------------------------------------------------------------------
    @property
    def legs(self) -> Mapping[str, Any]:
        return self.test.get("legs") or {}

    @property
    def local(self) -> Mapping[str, Any]:
        return self.legs.get("local") or {}

    @property
    def internet(self) -> Mapping[str, Any]:
        return self.legs.get("internet") or {}

    @property
    def score(self) -> int | None:
        s = self.test.get("score")
        return int(s["total"]) if isinstance(s, Mapping) and _num(s.get("total")) is not None else None

    # ---- evidence helpers -----------------------------------------------------------------------------------------
    @property
    def wifi_client(self) -> Mapping[str, Any]:
        return (self.ev.get("wifi") or {}).get("client") or {}

    @property
    def wifi_ap(self) -> Mapping[str, Any]:
        return (self.ev.get("wifi") or {}).get("ap") or {}

    @property
    def radio(self) -> Mapping[str, Any]:
        return self.wifi_ap.get("radio") or {}

    @property
    def rssi(self) -> float | None:
        return _num(self.wifi_client.get("rssi"))

    @property
    def snr(self) -> float | None:
        return _num(self.wifi_client.get("snr"))

    @property
    def wired_port(self) -> Mapping[str, Any]:
        return (self.ev.get("wired") or {}).get("port") or {}

    @property
    def is_wired(self) -> bool:
        ident = self.ev.get("identity") or {}
        if ident.get("wired") is True:
            return True
        if ident.get("wired") is False:
            return False
        return bool(self.wired_port) and not self.wifi_client

    def window_ok(self, ts: Any) -> bool:
        """An event epoch-seconds timestamp 'during the test' (the test's [started, ended] +- slack)."""
        t = _num(ts)
        if t is None:
            return True
        s, e = self.test.get("_started_s"), self.test.get("_ended_s")
        if s is None or e is None:
            return True
        return s - self.th.roam_slack_s <= t <= e + self.th.roam_slack_s

    # ---- expectations ---------------------------------------------------------------------------------------------
    def wifi_expectation(self) -> float | None:
        band = _band_key(self.wifi_client.get("band") or self.radio.get("band"))
        if band is None:
            return None
        width = self.radio.get("bandwidth_mhz")
        w = int(width) if _num(width) is not None else (20 if band == "24" else 80)
        table = self.th.wifi_expect_mbps
        for key in (f"{band}/{w}", f"{band}/{20 if band == '24' else 80}"):
            if key in table:
                return float(table[key])
        return None

    def expectation(self) -> float | None:
        if self.wifi_client:
            return self.wifi_expectation()
        sp = _num(self.wired_port.get("speed_mbps"))
        if sp:
            return 0.8 * sp
        return None

    def local_known(self) -> bool:
        return _num(self.local.get("down_mbps")) is not None or _num(self.local.get("up_mbps")) is not None

    def local_slow(self) -> bool:
        down, up = _num(self.local.get("down_mbps")), _num(self.local.get("up_mbps"))
        exp = self.expectation()
        frac = self.th.local_slow_pct / 100.0
        if exp is not None:
            if down is not None:
                return down < frac * exp
            return up is not None and up < frac * exp / 2
        return ((down is not None and down < self.targets["down_mbps"])
                or (up is not None and up < self.targets["up_mbps"]))

    def internet_ok(self) -> bool:
        return bool(self.internet) and self.internet.get("status", "ok") == "ok" and (
            _num(self.internet.get("down_mbps")) is not None or _num(self.internet.get("up_mbps")) is not None)

    def internet_slow(self) -> bool:
        if not self.internet_ok():
            return False
        down, up = _num(self.internet.get("down_mbps")), _num(self.internet.get("up_mbps"))
        loaded = [x for x in (_num(self.internet.get("loaded_down_ms")), _num(self.internet.get("loaded_up_ms")))
                  if x is not None]
        return ((down is not None and down < self.targets["down_mbps"])
                or (up is not None and up < self.targets["up_mbps"])
                or (bool(loaded) and max(loaded) > self.th.internet_loaded_ms))

    def signal_bad(self) -> bool:
        return ((self.rssi is not None and self.rssi < self.th.wifi_rssi_dbm)
                or (self.snr is not None and self.snr < self.th.wifi_snr_db))

    def signal_known(self) -> bool:
        return self.rssi is not None or self.snr is not None

    def ap_util(self) -> float | None:
        return _num(self.radio.get("util_all"))

    def ap_clients(self) -> int | None:
        n = _num(self.wifi_ap.get("num_clients"))
        if n is None:
            n = _num(self.radio.get("num_clients"))
        return None if n is None else int(n)

    def ap_busy(self) -> bool:
        u, c = self.ap_util(), self.ap_clients()
        return (u is not None and u > self.th.wifi_util_pct) or (c is not None and c > self.th.wifi_clients)

    def wan_util(self) -> float | None:
        wan = self.ev.get("wan") or {}
        v = _num(wan.get("wan_util_pct"))
        if v is not None:
            return v
        best: float | None = None
        for a in wan.get("appliances") or []:
            for i in (a.get("interfaces") or []):
                if i.get("wan_if"):
                    u = _num(i.get("util_pct"))
                    if u is not None and (best is None or u > best):
                        best = u
        return best

    def wan_health_bad(self) -> list[str]:
        out: list[str] = []
        for a in (self.ev.get("wan") or {}).get("appliances") or []:
            h = a.get("health") or {}
            for metric in ("loss", "latency", "jitter"):
                for t in h.get(metric) or []:
                    if str(t.get("health_status", "")).lower() in _HIGH_HEALTH:
                        out.append(metric)
        return sorted(set(out))


# ------------------------------------------------------------------------------------------------------- rules
def _clamp(x: float, lo: float = 0.0, hi: float = 0.95) -> float:
    return round(max(lo, min(hi, x)), 2)


def _ap_text(c: Ctx) -> str:
    ap = c.wifi_ap
    name = clean(ap.get("ap_name") or c.wifi_client.get("ap_id") or "AP", 64)
    r = c.radio
    ch = c.wifi_client.get("channel") or r.get("channel")
    bw = r.get("bandwidth_mhz")
    parts = [name]
    if ch is not None:
        parts.append(f"ch {ch}/{bw} MHz" if bw else f"ch {ch}")
    return " ".join(parts)


def _rssi_text(c: Ctx) -> str:
    bits = []
    if c.rssi is not None:
        bits.append(f"RSSI {_fmt(c.rssi, ' dBm')}")
    if c.snr is not None:
        bits.append(f"SNR {_fmt(c.snr, ' dB')}")
    return ", ".join(bits)


def rule_wifi_signal(c: Ctx) -> Hit | None:
    if not c.wifi_client or not c.signal_bad() or not c.local_slow():
        return None
    th = c.th
    both = (c.rssi is not None and c.rssi < th.wifi_rssi_dbm) and (c.snr is not None and c.snr < th.wifi_snr_db)
    deficit = max(th.wifi_rssi_dbm - c.rssi, 0.0) if c.rssi is not None else 0.0
    conf = _clamp(0.7 + (0.1 if both else 0.0) + min(0.15, deficit / 40.0 * 0.15))
    down = _num(c.local.get("down_mbps"))
    exp = c.expectation()
    noc = f"{_ap_text(c)}; {_rssi_text(c)}; local {_fmt(down, ' Mb/s')}"
    if exp:
        noc += f" vs ~{_fmt(exp, ' Mb/s')} expected"
    return Hit("wifi_signal", conf, noc, [_cite("wifi", "data.client.rssi"), _cite("wifi", "data.client.snr"),
                                          _cite("legs", "local.down_mbps")])


def rule_wifi_congestion(c: Ctx) -> Hit | None:
    if not c.wifi_client or not c.ap_busy() or not c.local_slow() or c.signal_bad():
        return None
    u, n = c.ap_util(), c.ap_clients()
    th = c.th
    conf = 0.65 + (min(0.2, ((u or 0) - th.wifi_util_pct) / 30.0 * 0.2) if u is not None and u > th.wifi_util_pct
                   else 0.0)
    if u is not None and u > th.wifi_util_pct and n is not None and n > th.wifi_clients:
        conf += 0.05
    bits = [_ap_text(c)]
    if u is not None:
        bits.append(f"util {_fmt(u, ' %')}")
    if n is not None:
        bits.append(f"{n} clients")
    noc = ", ".join(bits)
    r = _rssi_text(c)
    if r:
        noc += f"; {r}"
    return Hit("wifi_congestion", _clamp(conf), noc,
               [_cite("wifi", "data.ap.radio.util_all"), _cite("wifi", "data.ap.num_clients"),
                _cite("legs", "local.down_mbps")])


def rule_wifi_roaming(c: Ctx) -> Hit | None:
    wifi = c.ev.get("wifi")
    if not wifi:
        return None
    th = c.th
    roams = [r for r in (wifi.get("roams") or []) if isinstance(r, Mapping)
             and str(r.get("type", "")) != "none" and c.window_ok(r.get("timestamp"))]
    n_roams = len(roams)
    if not wifi.get("roams") and isinstance(wifi.get("roam_count"), int):
        n_roams = int(wifi["roam_count"])
    events = [e for e in (wifi.get("events") or []) if isinstance(e, Mapping) and c.window_ok(e.get("timestamp"))]
    auth_events = [e for e in events if _BAD_AUTH.search(str(e.get("type", "")) + " " + str(e.get("text", "")))]
    auth_fail = len(auth_events) if wifi.get("events") else int(wifi.get("auth_failures") or 0)
    if n_roams < th.roams and auth_fail < 1:
        return None
    conf = 0.6 + min(0.2, 0.05 * max(0, n_roams - th.roams)) + (0.1 if auth_fail else 0.0)
    bad = [r for r in roams if r.get("type") in ("fail", "pingpong", "poor", "slow")]
    if bad:
        conf += 0.05
    bits = []
    if n_roams:
        bits.append(f"{n_roams} roams in the test window")
    if auth_fail:
        bits.append(f"{auth_fail} auth failure{'s' if auth_fail != 1 else ''}")
    ap = clean(c.wifi_ap.get("ap_name") or "", 64)
    noc = (f"{ap}: " if ap else "") + ", ".join(bits)
    return Hit("wifi_roaming", _clamp(conf), noc, [_cite("wifi", "data.roams"), _cite("wifi", "data.auth_failures")])


def rule_wired_port(c: Ctx) -> Hit | None:
    port = c.wired_port
    if not port or not c.is_wired:
        return None
    th = c.th
    errs = (int(_num(port.get("rx_errors")) or 0)) + (int(_num(port.get("tx_errors")) or 0))
    half = port.get("full_duplex") is False
    speed = _num(port.get("speed_mbps"))
    slow_link = speed is not None and speed <= th.wired_speed_mbps
    many = errs >= th.wired_errors
    if not (half or slow_link or many):
        return None
    n = int(half) + int(slow_link) + int(many)
    conf = _clamp(0.75 + 0.05 * n + (0.05 if c.local_slow() else 0.0))
    bits = []
    pid = clean(port.get("port_id") or "", 32)
    if pid:
        bits.append(f"port {pid}")
    if slow_link:
        bits.append(f"{_fmt(speed, ' Mb/s')} link")
    if half:
        bits.append("half duplex")
    if many:
        bits.append(f"{errs} errors")
    return Hit("wired_port", conf, ", ".join(bits),
               [_cite("wired", "data.port.speed_mbps"), _cite("wired", "data.port.full_duplex"),
                _cite("wired", "data.port.rx_errors")])


def rule_device_limit(c: Ctx) -> Hit | None:
    if not c.local_slow():
        return None
    if c.wifi_client:
        if not c.signal_known() or c.signal_bad() or c.ap_busy():
            return None
        cl = c.wifi_client
        proto = str(cl.get("proto") or "")
        conf = 0.55 + (0.1 if cl.get("power_saving") is True else 0.0) + (0.1 if proto in _OLD_PROTO else 0.0)
        tx = _num(cl.get("tx_rate_mbps"))
        if tx is not None and tx < 150:
            conf += 0.05
        bits = [_rssi_text(c)]
        if proto:
            bits.append(f"proto {clean(proto, 8)}")
        if cl.get("power_saving") is True:
            bits.append("power save on")
        if tx is not None:
            bits.append(f"tx {_fmt(tx, ' Mb/s')}")
        return Hit("device_limit", _clamp(conf, hi=0.85), f"{_ap_text(c)}; local slow with good signal: "
                   + ", ".join(b for b in bits if b),
                   [_cite("wifi", "data.client.rssi"), _cite("wifi", "data.client.proto"),
                    _cite("legs", "local.down_mbps")])
    if c.is_wired and c.wired_port and not rule_wired_port(c):
        return Hit("device_limit", 0.5, "wired port healthy, local leg slow", [_cite("wired", "data.port"),
                                                                                 _cite("legs", "local.down_mbps")])
    return None


def rule_wan_saturation(c: Ctx) -> Hit | None:
    if not c.local_known() or c.local_slow():
        return None
    th = c.th
    util = c.wan_util()
    hot = util is not None and util > th.wan_util_pct
    health = c.wan_health_bad()
    if not hot and not health:
        return None
    conf = 0.6
    if hot:
        conf = 0.75 + min(0.15, ((util or 0) - th.wan_util_pct) / 15.0 * 0.15)
    if hot and health:
        conf += 0.05
    if c.internet_slow():
        conf += 0.05
    bits = []
    if util is not None:
        bits.append(f"WAN util {_fmt(util, ' %', 1)}")
    if health:
        bits.append("tunnel " + "/".join(health) + " health major or critical")
    alarms = [a for a in ((c.ev.get("wan") or {}).get("appliances") or [{}])[0:1] for a in (a.get("alarms") or [])
              if not a.get("closed")]
    if alarms:
        bits.append("alarm: " + clean(alarms[0].get("alarm_name") or alarms[0].get("type") or "", 48))
    return Hit("wan_saturation", _clamp(conf), ", ".join(bits),
               [_cite("wan", "data.wan_util_pct"), _cite("wan", "data.appliances.health")])


def rule_internet_path(c: Ctx, wan_hit: Hit | None) -> Hit | None:
    if not c.local_known() or c.local_slow() or wan_hit is not None:
        return None
    if c.internet_slow():
        conf = 0.45
        if "wan" in c.ev:
            conf += 0.2
        if c.baseline and c.baseline.get("severity") == "ok":
            conf += 0.1
        dn = _num(c.internet.get("down_mbps"))
        ld = max([x for x in (_num(c.internet.get("loaded_down_ms")), _num(c.internet.get("loaded_up_ms")))
                  if x is not None] or [0.0])
        srv = clean(c.internet.get("server") or "", 32)
        noc = (f"internet leg {_fmt(dn, ' Mb/s')} down, loaded {_fmt(ld, ' ms')} ({srv}) while the on-network leg "
               f"is fine; WAN not saturated")
        return Hit("internet_path", _clamp(conf, hi=0.85), noc,
                   [_cite("legs", "internet.down_mbps"), _cite("legs", "local.down_mbps")])
    if c.internet and c.internet.get("status") == "unavailable":
        return Hit("internet_path", 0.55, "internet leg could not run (unavailable) while the on-network leg is fine",
                   [_cite("legs", "internet.status")])
    return None


def _policy_counts(sec: Mapping[str, Any]) -> tuple[int, int, int, int]:
    """(deny+block+reset, drop, session_limit, flow_drops) from counts and/or the events."""
    counts = sec.get("counts") or {}
    deny, drop, lim = int(counts.get("deny") or 0) + int(counts.get("block") or 0), int(counts.get("drop") or 0), \
        int(counts.get("session_limit") or 0)
    if not counts:
        for e in sec.get("events") or []:
            n = int(e.get("count") or 1)
            a = e.get("action")
            if e.get("category") == "session_limit" or a == "limit":
                lim += n
            elif a in ("deny", "block", "reset"):
                deny += n
            elif a == "drop":
                drop += n
    return deny, drop, lim, int(sec.get("ec_dropped_flows") or 0)


def rule_policy_block(c: Ctx) -> Hit | None:
    sec = c.ev.get("security") or {}
    deny, drop, lim, ecd = _policy_counts(sec)
    fl = c.ev.get("flows") or {}
    fdrop = int((fl.get("counts") or {}).get("flows_firewall_dropped") or 0) or sum(
        1 for f in fl.get("flows") or [] if f.get("firewall_dropped"))
    total = deny + drop + lim + max(ecd, fdrop)
    if total < c.th.policy_min_events:
        return None
    conf = 0.7 + (0.1 if lim else 0.0) + (0.1 if deny else 0.0) + (0.05 if (ecd or fdrop) else 0.0)
    bits = []
    if deny:
        bits.append(f"{deny} deny/block")
    if drop:
        bits.append(f"{drop} drops")
    if lim:
        bits.append(f"{lim} session-limit hits")
    if ecd or fdrop:
        bits.append(f"{max(ecd, fdrop)} flows dropped by the EC firewall")
    ev0 = next((e for e in sec.get("events") or [] if e.get("action") in ("deny", "drop", "block", "reset", "limit")),
               None)
    if ev0 and ev0.get("rule"):
        bits.append("rule " + clean(ev0["rule"], 48))
    return Hit("policy_block", _clamp(conf), ", ".join(bits),
               [_cite("security", "data.counts"), _cite("security", "data.events"), _cite("flows", "data.counts")])


def rule_qos_shaping(c: Ctx) -> Hit | None:
    fl = c.ev.get("flows") or {}
    limited = set(c.th.qos_limited_classes)
    hits = [f for f in fl.get("flows") or [] if f.get("traffic_class") in limited
            and int(f.get("slow_duration") or 0) > 0]
    if not hits:
        return None
    f0 = max(hits, key=lambda f: int(f.get("bytes_total") or 0))
    conf = 0.7
    alarms = [a for ap in (c.ev.get("wan") or {}).get("appliances") or [] for a in ap.get("alarms") or []
              if "shap" in (str(a.get("alarm_name", "")) + str(a.get("type", ""))).lower()]
    if alarms:
        conf += 0.1
    bits = [f"{len(hits)} flow{'s' if len(hits) != 1 else ''} in traffic class {f0.get('traffic_class')}",
            f"slow {int(f0.get('slow_duration') or 0)} s"]
    if f0.get("application"):
        bits.insert(1, clean(f0["application"], 32))
    if alarms:
        bits.append("shaper alarm")
    return Hit("qos_shaping", _clamp(conf), ", ".join(bits),
               [_cite("flows", "data.flows"), _cite("wan", "data.appliances.alarms")])


def rule_dns(c: Ctx) -> Hit | None:
    th = c.th
    dns = c.ev.get("dns") or {}
    bits: list[str] = []
    conf = 0.0
    cites: list[dict[str, str]] = []
    failures, slow = int(dns.get("failures") or 0), int(dns.get("slow") or 0)
    slowest = _num(dns.get("slowest_ms"))
    if failures + slow >= th.dns_slow_count or (slowest is not None and slowest > th.dns_slow_ms and failures + slow):
        conf = 0.55 + min(0.25, 0.03 * (failures + slow))
        extra = f", slowest {_fmt(slowest, ' ms')}" if slowest else ""
        bits.append(f"{failures} failed and {slow} slow lookups{extra}")
        cites.append(_cite("dns", "data.failures"))
    probe_dns = dns.get("probe_dns") or {}
    leg = c.legs.get("dns") or {}
    base_dns = next((ln for ln in (c.baseline or {}).get("lines") or [] if ln.get("key") == "dns"), None)
    if leg.get("source") == "probe" or probe_dns:
        state = probe_dns.get("state") or (base_dns or {}).get("state")
        if state == "fail":
            conf = max(conf, 0.7)
            bits.append("probe DNS line failing")
            cites.append(_cite("dns", "data.probe_dns.state") if probe_dns else _cite("baseline", "data.lines.dns"))
    cold = _num(leg.get("cold_ms"))
    if leg.get("source") == "browser" and cold is not None and cold > th.dns_cold_ms:
        conf = max(conf, 0.55)
        bits.append(f"cold lookup {_fmt(cold, ' ms')} from the page")
        cites.append(_cite("legs", "dns.cold_ms"))
    if not bits:
        return None
    return Hit("dns", _clamp(conf), ", ".join(bits), cites)


def rule_network_wide(c: Ctx) -> Hit | None:
    b = c.baseline
    if not b:
        return None
    sev = b.get("severity")
    bad_lines = [ln for ln in b.get("lines") or [] if ln.get("state") in ("warn", "fail")
                 and ln.get("key") != "wifi"]
    tp = b.get("throughput") or {}
    tp_down = _num(tp.get("down_mbps"))
    tp_low = tp_down is not None and tp_down < c.targets["down_mbps"]
    if sev not in ("warn", "fail") and not tp_low:
        return None
    if sev not in ("warn", "fail") and not bad_lines:
        conf = 0.55
    else:
        conf = 0.8 if sev == "fail" else 0.6
    if tp_low:
        conf += 0.1
    if b.get("distance") == "same_ap":
        conf += 0.05
    bits = [f"probe {clean(b.get('probe') or '', 32)} ({clean(b.get('distance') or '', 16)}) {sev}"]
    if bad_lines:
        bits.append("lines " + ", ".join(clean(ln.get("key"), 12) + "=" + clean(ln.get("state"), 8)
                                         for ln in bad_lines[:4]))
    if tp_low:
        bits.append(f"probe throughput {_fmt(tp_down, ' Mb/s')}")
    return Hit("network_wide", _clamp(conf), ", ".join(bits), [_cite("baseline", "data.severity"),
                                                               _cite("baseline", "data.lines")])


RULES: tuple[Callable[[Ctx], Hit | None], ...] = (
    rule_wifi_signal, rule_wifi_congestion, rule_wifi_roaming, rule_wired_port, rule_device_limit,
    rule_wan_saturation, rule_policy_block, rule_qos_shaping, rule_dns, rule_network_wide)


def usable_evidence(evidence: Mapping[str, Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """kind -> data for the documents whose status is ok or partial and whose data is not empty."""
    out: dict[str, dict[str, Any]] = {}
    for kind, doc in evidence.items():
        if doc.get("status") in ("ok", "partial") and isinstance(doc.get("data"), dict) and doc["data"]:
            out[kind] = doc["data"]
    return out


def diagnose(test: Mapping[str, Any], evidence: Mapping[str, Mapping[str, Any]], baseline: Mapping[str, Any] | None,
             targets: Mapping[str, float], th: Thresholds, stage: str, now_iso: str,
             started_s: float | None = None, ended_s: float | None = None) -> dict[str, Any]:
    """The ``diagnosis`` object for a test (see the module docstring)."""
    tview = dict(test)
    tview["_started_s"], tview["_ended_s"] = started_s, ended_s
    ctx = Ctx(tview, usable_evidence(evidence), baseline, targets, th, stage)
    if baseline is None and "baseline" in ctx.ev:
        ctx.baseline = ctx.ev["baseline"]
    score = ctx.score
    # internet_measured is False iff the internet leg exists and its status is not "ok" (unavailable / paused /
    # queued / skipped): the score then rests on the on-network leg alone and must not short-circuit to "healthy"
    # (regressions: test_internet_down_is_not_healthy, test_unmeasured_internet_*)
    istatus = str(ctx.internet.get("status", "ok")) if ctx.internet else "ok"
    internet_measured = not (ctx.internet and istatus != "ok")
    internet_down = bool(ctx.internet) and istatus == "unavailable"
    if score is not None and score >= th.none_score and internet_measured:
        conf = 0.9 if score >= 90 else 0.8
        return {"stage": stage, "updated": now_iso,
                "cause": [{"id": "none", "confidence": conf, "cites": [_cite("legs", "score.total")]}],
                "user_text": USER_TEXT["none"][:USER_MAX],
                "noc_text": f"score {score}: no fault indicated"[:NOC_MAX]}
    hits: list[Hit] = []
    for rule in RULES:
        h = rule(ctx)
        if h is not None:
            hits.append(h)
    wan = next((h for h in hits if h.cause == "wan_saturation"), None)
    ip = rule_internet_path(ctx, wan)
    if ip is not None:
        hits.append(ip)
    hits.sort(key=lambda h: (-h.conf, _PRIORITY[h.cause]))
    hits = hits[:8]
    cause = [{"id": h.cause, "confidence": h.conf, "cites": h.cites[:16]} for h in hits]
    if not hits and not internet_measured and score is not None and score >= th.none_score \
            and ctx.local_known() and not ctx.local_slow():
        user = USER_INTERNET_UNMEASURED.get(istatus, USER_INTERNET_UNMEASURED["skipped"])
        return {"stage": stage, "updated": now_iso,
                "cause": [{"id": "none", "confidence": 0.6,
                           "cites": [_cite("legs", "score.total"), _cite("legs", "internet.status")]}],
                "user_text": user[:USER_MAX],
                "noc_text": (f"internet leg {istatus}: local-only score {score}; on-network leg fine, "
                             f"no rule fired on the {'legs' if stage == 'quick' else 'evidence'}")[:NOC_MAX]}
    if not hits:
        user = USER_PENDING_UNKNOWN if stage == "quick" else USER_UNKNOWN
        sc = "no score" if score is None else f"score {score}"
        return {"stage": stage, "updated": now_iso, "cause": [], "user_text": user,
                "noc_text": f"{sc}: no rule fired on the {'legs' if stage == 'quick' else 'evidence'}"[:NOC_MAX]}
    user = USER_INTERNET_DOWN if (hits[0].cause == "internet_path" and internet_down) else USER_TEXT[hits[0].cause]
    if len(hits) > 1 and hits[1].conf >= 0.6 and len(user) + 1 + len(USER_TEXT[hits[1].cause]) <= USER_MAX:
        user += " " + USER_TEXT[hits[1].cause]
    noc = " | ".join(f"{h.cause} ({h.conf:.2f}): {h.noc}" for h in hits[:3])
    return {"stage": stage, "updated": now_iso, "cause": cause, "user_text": clean(user, USER_MAX),
            "noc_text": clean(noc, NOC_MAX)}

"""Fake Juniper Mist API server for the M6 runner (HTTP, or HTTPS with a runtime throwaway CA).

Implements ONLY what the runner needs, with request and response shapes taken from the Mist OpenAPI 3.1 document bundled
in the official ``mistapi`` 0.64.1 SDK (MIT; ``mist_openapi/mist.openapi.json``; a dev-time reference, never imported):

=========================================================  ===============================================================
route                                                      OAS operationId (response schema)
=========================================================  ===============================================================
GET /api/v1/sites/{site_id}/clients/search                 searchSiteWirelessClients (response_client_search / client_wireless)
GET /api/v1/orgs/{org_id}/clients/search                   searchOrgWirelessClients (same; extra ``site_id`` filter)
GET /api/v1/sites/{site_id}/stats/clients                  listSiteWirelessClientsStats (stats_client_any_of)
GET /api/v1/sites/{site_id}/stats/clients/{client_mac}     getSiteWirelessClientStats (stats_wireless_client)
GET /api/v1/sites/{site_id}/stats/devices/{device_id}      getSiteDeviceStats (stats_ap: ``radio_stat.band_*`` util/channel/num_clients)
GET /api/v1/sites/{site_id}/stats/devices                  listSiteDevicesStats (array of stats_ap)
GET /api/v1/sites/{site_id}/wired_clients/search           searchSiteWiredClients (search_wired_client / wired_client_response)
GET /api/v1/orgs/{org_id}/wired_clients/search             searchOrgWiredClients (same)
GET /api/v1/sites/{site_id}/stats/ports/search             searchSiteSwOrGwPorts (response_switch_port_search / stats_switch_port)
GET /api/v1/sites/{site_id}/clients/events/search          searchSiteWirelessClientEvents (response_events_search / events_client)
GET /api/v1/sites/{site_id}/clients/{client_mac}/events    getSiteEventsForClient (response_client_events_search / events_client)
GET /api/v1/const/client_events                            listClientEventsDefinitions (const_events: ``key`` / ``display``)
=========================================================  ===============================================================

What the OAS documents and this fake follows (and where it is silent):

* **Auth**: ``Authorization: Token <apitoken>`` (securityScheme ``apiToken``). Missing, malformed (e.g. ``Bearer``) or wrong
  -> 401 ``{"detail": "Authentication credentials were not provided."}`` (the OAS example of response_http401).
* **Rate limit**: response_http429's documented example is "Too Many Request. The API Token used for the request reached the
  5000 API Calls per hour threshold". The fake counts calls per token over a rolling hour of its clock; over the limit
  (default 5000, ``set_rate_limit``) -> 429 with that ``detail``. The OAS documents no ``Retry-After``; none is sent.
* **Time window**: ``start`` / ``end`` (epoch seconds, or relative ``-1d`` / ``-2h`` / ``now``) and ``duration`` (``10m``, ``7d``,
  ``2w``; default ``1d``). ``start``+``end`` win; otherwise ``end`` defaults to now and ``start`` = ``end`` - ``duration``.
* **Pagination**: ``limit`` (default 100, minimum 0) and ``search_after``; the response carries ``start``, ``end``, ``limit``,
  ``total`` and ``results`` plus ``next`` (a request path + query with ``search_after``) while more pages exist. The cursor is
  opaque. The OAS states no maximum limit; the fake clamps at 1000.
* **Filters** (``ip``, ``mac``, ``hostname``, ``username`` ...): exact, ``prefix*`` or ``*substring*`` (suffix-only wildcards
  are rejected with 400, as the OAS says). MACs are 12 lower-case hex digits without separators in every response (the OAS
  examples); colon forms are accepted in filters and the ``client_mac`` path parameter.
* **404** for an unknown site / device / client (response_http404 has only an ``id`` property).

Client events: ``events_client`` has **no client-MAC property** and ``searchSiteWirelessClientEvents`` no MAC filter (AP, SSID,
band, type and time only: AP-level, every client's events mixed). The per-client route is ``getSiteEventsForClient``: ``client_mac``
is a PATH parameter (12 lower-case hex digits; colon forms accepted), query ``type``, ``proto``, ``band``, ``channel``, ``wlan_id``,
``ssid``, ``start``, ``end``, ``duration``, ``limit`` (default 100) and ``page`` (1-based; the OAS parameter ``page``); the response is
``response_client_events_search`` (``start``, ``end``, ``limit``, ``total``, ``results`` of ``events_client``, ``next``). The fake keeps
the owning MAC in an internal ``client_mac`` key that is never serialised. Event type keys are discovered via
``GET /api/v1/const/client_events``; only
``CLIENT_AUTH_ASSOCIATION_11R`` (the OAS example of ``const_events``) and ``MARVIS_EVENT_CLIENT_FBT_FAILURE`` (the OAS example of
``events_client.type``) are OAS-documented; ``FAKE_CLIENT_AUTH_FAILURE`` is a fake-chosen key so a runner cannot hard-code it.

Scenarios (``MistState.load_scenario`` / ``POST /_fake/scenario``): ``healthy``, ``weak_rssi``, ``congested_ap``, ``roaming``,
``wired_port_errors``, ``nat_ambiguity`` (two MACs on one IP in the window), ``no_client``. Control API under ``/_fake/`` (loopback
only): ``POST scenario|reset|force|rate_limit|clients|events``, ``GET log``.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import logging
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import fakes_common as fc  # noqa: E402

log = logging.getLogger("exp.fakes.mist")

ORG_ID = "00000000-0000-0000-0000-0000000000a0"
SITE_ID = "00000000-0000-0000-0000-00000000aa01"
AP1 = {"id": "00000000-0000-0000-1000-5c5b350001a0", "mac": "5c5b350001a0", "name": "hallb-ap-12"}
AP2 = {"id": "00000000-0000-0000-1000-5c5b350001b0", "mac": "5c5b350001b0", "name": "hallb-ap-13"}
SWITCH = {"id": "00000000-0000-0000-1000-020000aabb01", "mac": "020000aabb01", "name": "hallb-sw-1"}
WLAN_ID = "00000000-0000-0000-0000-00000000bb01"
RATE_LIMIT_DETAIL = "Too Many Request. The API Token used for the request reached the 5000 API Calls per hour threshold"
DEFAULT_RATE_LIMIT = 5000
MAX_LIMIT = 1000
SCENARIOS = ("healthy", "weak_rssi", "congested_ap", "roaming", "roaming_other_client", "wired_port_errors", "nat_ambiguity",
             "no_client")
EVT_ROAM = "CLIENT_AUTH_ASSOCIATION_11R"            # OAS example of const_events
EVT_FBT_FAIL = "MARVIS_EVENT_CLIENT_FBT_FAILURE"    # OAS example of events_client.type
EVT_AUTH_FAIL = "FAKE_CLIENT_AUTH_FAILURE"          # fake-chosen
EVENT_DEFS = [
    {"key": EVT_ROAM, "display": "11r Association"},
    {"key": EVT_FBT_FAIL, "display": "Client Fast BSS Transition Failure"},
    {"key": EVT_AUTH_FAIL, "display": "Client Authentication Failure (fake)"},
]
_MAC12 = re.compile(r"[0-9a-f]{12}\Z")
_DUR = re.compile(r"([0-9]+)([smhdw])\Z")
_REL = re.compile(r"-([0-9]+)([smhdw])\Z")
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class MistError(Exception):
    def __init__(self, status: int, body: dict[str, Any]) -> None:
        super().__init__(f"{status} {body}")
        self.status = status
        self.body = body


def bad(detail: str) -> MistError:
    return MistError(400, {"detail": detail})


def norm_mac(mac: str) -> str:
    m = mac.strip().lower().replace(":", "").replace("-", "")
    if not _MAC12.match(m):
        raise ValueError(f"bad MAC {mac!r}")
    return m


def pattern_match(pattern: str, value: str | None) -> bool:
    """Mist wildcard filter: exact, ``prefix*`` or ``*substring*`` (a leading-only ``*`` is rejected by the caller)."""
    if value is None:
        return False
    if pattern.startswith("*") and pattern.endswith("*") and len(pattern) > 2:
        return pattern[1:-1].lower() in value.lower()
    if pattern.endswith("*"):
        return value.lower().startswith(pattern[:-1].lower())
    return value.lower() == pattern.lower()


def _check_patterns(csv: str) -> list[str]:
    pats = [p for p in csv.split(",") if p]
    for p in pats:
        if p.startswith("*") and not p.endswith("*"):
            raise bad("suffix-only wildcards are not supported")
    return pats


def any_match(csv: str, values: list[str | None]) -> bool:
    return any(pattern_match(p, v) for p in _check_patterns(csv) for v in values)


class MistState:
    """In-memory org: sites, APs, switches, client sessions, events. Times are epoch seconds."""

    def __init__(self, *, now_fn: Any = time.time) -> None:
        self.now = now_fn
        self.lock = threading.RLock()
        self.sites: dict[str, str] = {SITE_ID: "hall-b"}
        self.aps: dict[str, dict[str, Any]] = {}
        self.switches: dict[str, dict[str, Any]] = {}
        self.ports: list[dict[str, Any]] = []
        self.sessions: list[dict[str, Any]] = []       # wireless client sessions
        self.wired: list[dict[str, Any]] = []          # wired client observations
        self.events: list[dict[str, Any]] = []
        self.reset()

    # ---- topology -------------------------------------------------------------------------------------------
    def reset(self) -> None:
        with self.lock:
            self.aps = {a["id"]: self._ap(a, 20) for a in (AP1, AP2)}
            self.switches = {SWITCH["id"]: {**SWITCH, "site_id": SITE_ID, "org_id": ORG_ID}}
            self.ports = []
            self.sessions = []
            self.wired = []
            self.events = []

    def _ap(self, ap: dict[str, str], util: int, clients: int = 12, noise: int = -95, channel: int = 36) -> dict[str, Any]:
        t = self.now()
        radio = {"bandwidth": 80, "channel": channel, "dynamic_chaining_enabled": False, "mac": ap["mac"], "noise_floor": noise,
                 "num_clients": clients, "num_wlans": 1, "power": 15, "usage": "5", "util_all": util, "util_non_wifi": 2,
                 "util_rx_in_bss": 3, "util_rx_other_bss": max(0, util // 4), "util_tx": max(0, util // 3),
                 "util_undecodable_wifi": 1, "util_unknown_wifi": 1}
        return {
            "id": ap["id"], "mac": ap["mac"], "name": ap["name"], "type": "ap", "site_id": SITE_ID, "org_id": ORG_ID,
            "model": "AP45", "ip": "10.60.0." + str(10 + len(self.aps)), "status": "connected", "num_clients": clients,
            "uptime": 864000, "last_seen": t, "version": "0.14.29313", "serial": "A" + ap["mac"][-6:].upper(),
            "radio_stat": {"band_5": radio, "band_24": {**radio, "channel": 6, "usage": "24", "util_all": max(5, util // 2),
                                                        "num_clients": max(0, clients // 3), "bandwidth": 20, "mac": ap["mac"][:-1] + "0"}},
        }

    def set_ap_radio(self, ap: dict[str, str], *, util_all: int | None = None, num_clients: int | None = None,
                     noise_floor: int | None = None, channel: int | None = None, band: str = "band_5") -> None:
        with self.lock:
            st = self.aps[ap["id"]]
            r = st["radio_stat"][band]
            if util_all is not None:
                r["util_all"] = util_all
                r["util_tx"] = util_all // 3
                r["util_rx_other_bss"] = util_all // 3
            if num_clients is not None:
                r["num_clients"] = num_clients
                st["num_clients"] = num_clients
            if noise_floor is not None:
                r["noise_floor"] = noise_floor
            if channel is not None:
                r["channel"] = channel

    # ---- raw adds -------------------------------------------------------------------------------------------
    def add_wireless_session(self, *, mac: str, ip: str, t_from: float, t_to: float | None = None, ap: dict[str, str] = AP1,
                             site_id: str = SITE_ID, ssid: str = "Summit-Guest", band: str = "5", channel: int = 36,
                             proto: str = "ax", rssi: float = -58, snr: float = 38, tx_rate: float = 866.7, rx_rate: float = 780.0,
                             tx_retries: int = 120, rx_retries: int = 90, hostname: str | None = "client-host",
                             os_name: str | None = "iOS 18", manufacture: str | None = "Apple", username: str | None = None,
                             vlan: int = 160, key_mgmt: str = "WPA2-PSK/CCMP") -> dict[str, Any]:
        s = {"mac": norm_mac(mac), "ip": ip, "t_from": t_from, "t_to": t_to, "ap_mac": ap["mac"], "ap_id": ap["id"], "site_id": site_id,
             "ssid": ssid, "band": band, "channel": channel, "proto": proto, "rssi": rssi, "snr": snr, "tx_rate": tx_rate,
             "rx_rate": rx_rate, "tx_retries": tx_retries, "rx_retries": rx_retries, "hostname": hostname, "os": os_name,
             "manufacture": manufacture, "username": username, "vlan": vlan, "key_mgmt": key_mgmt}
        with self.lock:
            self.sessions.append(s)
        return s

    def add_wired(self, *, mac: str, ip: str, t_from: float, t_to: float | None = None, device_mac: str = SWITCH["mac"],
                  port_id: str = "ge-0/0/12", vlan: int = 160, auth_method: str = "mab", auth_state: str = "authenticated",
                  dhcp_hostname: str | None = "wired-host", site_id: str = SITE_ID) -> dict[str, Any]:
        w = {"mac": norm_mac(mac), "ip": ip, "t_from": t_from, "t_to": t_to, "device_mac": device_mac, "port_id": port_id, "vlan": vlan,
             "auth_method": auth_method, "auth_state": auth_state, "dhcp_hostname": dhcp_hostname, "site_id": site_id}
        with self.lock:
            self.wired.append(w)
        return w

    def add_port(self, **kw: Any) -> dict[str, Any]:
        p: dict[str, Any] = {"mac": SWITCH["mac"], "org_id": ORG_ID, "site_id": SITE_ID, "port_id": "ge-0/0/12", "up": True,
                             "active": True, "disabled": False, "speed": 1000, "full_duplex": True, "rx_errors": 0, "tx_errors": 0,
                             "rx_bps": 4_000_000, "tx_bps": 1_000_000, "rx_pkts": 500000, "tx_pkts": 400000, "rx_bytes": 700000000,
                             "tx_bytes": 300000000, "last_flapped": 0, "mac_count": 1, "stp_state": "forwarding", "stp_role": "designated",
                             "poe_on": False, "port_usage": "default", "uplink": False, "auth_state": "authenticated",
                             "neighbor_system_name": "", "port_mac": SWITCH["mac"][:-2] + "0c", "type": "ap", "for_site": True}
        p.update(kw)
        with self.lock:
            self.ports.append(p)
        return p

    def add_event(self, *, ts: float, type_: str, ap: dict[str, str] = AP1, site_id: str = SITE_ID, ssid: str = "Summit-Guest",
                  band: str = "5", channel: int = 36, proto: str = "ax", text: str = "", type_code: int | None = None,
                  mac: str | None = None) -> dict[str, Any]:
        # ``client_mac`` is internal (events_client has no MAC property): it only routes getSiteEventsForClient; None = unattributed
        e = {"site_id": site_id, "client_mac": norm_mac(mac) if mac else None, "ap": ap["mac"], "band": band,
             "bssid": ap["mac"][:-1] + "1", "channel": channel, "proto": proto,
             "ssid": ssid, "text": text or type_, "timestamp": ts, "type": type_, "wlan_id": WLAN_ID, "key_mgmt": "WPA2-PSK/CCMP"}
        if type_code is not None:
            e["type_code"] = type_code
        with self.lock:
            self.events.append(e)
        return e

    # ---- scenarios ------------------------------------------------------------------------------------------
    def load_scenario(self, name: str, *, at: float, ip: str = "10.60.14.77", mac: str = "f0:18:98:aa:bb:01",
                      other_mac: str = "f0:18:98:cc:dd:02", window_s: float = 600.0) -> dict[str, Any]:
        """Set the world for a test running at `at` (epoch s) from `ip`. Returns what was created (for assertions)."""
        if name not in SCENARIOS:
            raise ValueError(f"unknown scenario {name!r}; one of {SCENARIOS}")
        self.reset()
        t0 = at - window_s
        out: dict[str, Any] = {"scenario": name, "ip": ip, "mac": norm_mac(mac), "ap": AP1["mac"]}
        if name == "healthy":
            self.add_wireless_session(mac=mac, ip=ip, t_from=t0)
        elif name == "weak_rssi":
            self.add_wireless_session(mac=mac, ip=ip, t_from=t0, rssi=-83, snr=9, tx_rate=26.0, rx_rate=19.5, tx_retries=48000,
                                      rx_retries=30000, proto="n")
        elif name == "congested_ap":
            self.add_wireless_session(mac=mac, ip=ip, t_from=t0, rssi=-54, snr=41)
            self.set_ap_radio(AP1, util_all=93, num_clients=64, noise_floor=-86)
        elif name == "roaming":
            self.add_wireless_session(mac=mac, ip=ip, t_from=t0, t_to=at - 150, ap=AP1, rssi=-71)
            self.add_wireless_session(mac=mac, ip=ip, t_from=at - 150, ap=AP2, rssi=-66)
            for i, d in enumerate((400, 300, 200, 150)):
                self.add_event(ts=at - d, type_=EVT_ROAM, ap=AP2 if i == 3 else AP1, text="11r association", mac=mac)
            self.add_event(ts=at - 250, type_=EVT_FBT_FAIL, ap=AP1, text="FBT failure", mac=mac)
            self.add_event(ts=at - 180, type_=EVT_AUTH_FAIL, ap=AP2, text="auth failure", type_code=15, mac=mac)
        elif name == "roaming_other_client":
            # the attendee is steady on AP1; ANOTHER client on the same AP roams and fails auth (must never reach the attendee)
            self.add_wireless_session(mac=mac, ip=ip, t_from=t0)
            self.add_wireless_session(mac=other_mac, ip="10.60.14.99", t_from=t0, ap=AP1, rssi=-75)
            for d in (400, 300, 200):
                self.add_event(ts=at - d, type_=EVT_ROAM, ap=AP1, text="11r association", mac=other_mac)
            self.add_event(ts=at - 250, type_=EVT_FBT_FAIL, ap=AP1, text="FBT failure", mac=other_mac)
            self.add_event(ts=at - 180, type_=EVT_AUTH_FAIL, ap=AP1, text="auth failure", type_code=15, mac=other_mac)
            out["other_mac"] = norm_mac(other_mac)
        elif name == "wired_port_errors":
            self.add_wired(mac=mac, ip=ip, t_from=t0)
            self.add_port(port_id="ge-0/0/12", speed=100, full_duplex=False, rx_errors=41822, tx_errors=900, last_flapped=at - 90,
                          stp_state="forwarding", port_usage="default", type="nac")
            self.add_port(port_id="ge-0/0/13")
            out["port"] = "ge-0/0/12"
        elif name == "nat_ambiguity":
            self.add_wireless_session(mac=mac, ip=ip, t_from=t0)
            self.add_wireless_session(mac=other_mac, ip=ip, t_from=t0 + 60, ap=AP2, rssi=-61)
            out["other_mac"] = norm_mac(other_mac)
        # no_client: nothing
        return out

    # ---- queries --------------------------------------------------------------------------------------------
    def window(self, q: dict[str, str]) -> tuple[float, float]:
        now = self.now()

        def parse(v: str, name: str) -> float:
            if v == "now":
                return now
            if re.fullmatch(r"[0-9]+(\.[0-9]+)?", v):
                return float(v)
            m = _REL.match(v)
            if m:
                return now - int(m.group(1)) * _UNIT[m.group(2)]
            raise bad(f"invalid {name}")

        end = parse(q["end"], "end") if q.get("end") else now
        if q.get("start"):
            start = parse(q["start"], "start")
        else:
            dur = q.get("duration") or "1d"
            m = _DUR.match(dur)
            if not m:
                raise bad("invalid duration")
            start = end - int(m.group(1)) * _UNIT[m.group(2)]
        if start > end:
            raise bad("start is after end")
        return start, end

    @staticmethod
    def _overlap(rec: dict[str, Any], start: float, end: float) -> bool:
        return rec["t_from"] <= end and (rec["t_to"] is None or rec["t_to"] >= start)

    def wireless_search(self, q: dict[str, str], site_id: str | None) -> list[dict[str, Any]]:
        start, end = self.window(q)
        by_mac: dict[str, list[dict[str, Any]]] = {}
        with self.lock:
            for s in self.sessions:
                if site_id and s["site_id"] != site_id:
                    continue
                if q.get("site_id") and s["site_id"] != q["site_id"]:
                    continue
                if not self._overlap(s, start, end):
                    continue
                if q.get("ip") and not any_match(q["ip"], [s["ip"]]):
                    continue
                if q.get("mac") and not any_match(",".join(p.replace(":", "") for p in q["mac"].split(",")), [s["mac"]]):
                    continue
                if q.get("hostname") and not any_match(q["hostname"], [s["hostname"]]):
                    continue
                if q.get("username") and not any_match(q["username"], [s["username"]]):
                    continue
                if q.get("text") and not any_match(q["text"], [s["mac"], s["hostname"], s["username"], s["ip"]]):
                    continue
                if q.get("ssid") and s["ssid"] != q["ssid"]:
                    continue
                if q.get("ap") and s["ap_mac"] != q["ap"].replace(":", "").lower():
                    continue
                if q.get("band") and s["band"] not in q["band"].split(","):
                    continue
                if q.get("vlan") and str(s["vlan"]) != q["vlan"]:
                    continue
                by_mac.setdefault(s["mac"], []).append(s)
        results = []
        for mac, ss in by_mac.items():
            ss.sort(key=lambda x: x["t_from"])
            last = ss[-1]

            def uniq(key: str, ss: list[dict[str, Any]] = ss) -> list[Any]:
                return list(dict.fromkeys(x[key] for x in ss if x[key] is not None))
            rec: dict[str, Any] = {
                "mac": mac, "ap": uniq("ap_mac"), "ip": uniq("ip"), "ssid": uniq("ssid"), "vlan": uniq("vlan"),
                "band": last["band"], "protocol": last["proto"], "last_ap": last["ap_mac"], "last_ip": last["ip"],
                "last_ssid": last["ssid"], "last_vlan": last["vlan"], "last_wlan_id": WLAN_ID, "wlan_id": [WLAN_ID],
                "site_id": last["site_id"], "site_ids": uniq("site_id"), "org_id": ORG_ID, "random_mac": False,
                "timestamp": last["t_from"], "ftc": False,
            }
            if last["hostname"]:
                rec["hostname"] = uniq("hostname")
                rec["last_hostname"] = last["hostname"]
            if last["os"]:
                rec["os"] = uniq("os")
                rec["last_os"] = last["os"]
            if last["manufacture"]:
                rec["mfg"] = last["manufacture"]
            if last["username"]:
                rec["username"] = uniq("username")
                rec["last_username"] = last["username"]
            results.append(rec)
        results.sort(key=lambda r: -r["timestamp"])
        return results

    def wireless_stats(self, site_id: str, mac: str | None = None) -> list[dict[str, Any]]:
        now = self.now()
        out = []
        with self.lock:
            for s in self.sessions:
                if s["site_id"] != site_id or s["t_from"] > now or (s["t_to"] is not None and s["t_to"] < now):
                    continue
                if mac and s["mac"] != mac:
                    continue
                rec = {
                    "ap_id": s["ap_id"], "ap_mac": s["ap_mac"], "band": s["band"], "channel": s["channel"], "is_guest": False,
                    "key_mgmt": s["key_mgmt"], "mac": s["mac"], "proto": s["proto"], "rssi": s["rssi"], "snr": s["snr"],
                    "ssid": s["ssid"], "wlan_id": WLAN_ID, "bssid": s["ap_mac"][:-1] + "1", "ip": s["ip"], "site_id": s["site_id"],
                    "tx_rate": s["tx_rate"], "rx_rate": s["rx_rate"], "tx_retries": s["tx_retries"], "rx_retries": s["rx_retries"],
                    "last_seen": now, "uptime": max(0.0, now - s["t_from"]), "assoc_time": int(s["t_from"]), "vlan_id": str(s["vlan"]),
                    "idle_time": 1.0, "rx_bps": 2_000_000, "tx_bps": 9_000_000, "rx_bytes": 90_000_000, "tx_bytes": 400_000_000,
                    "rx_pkts": 80000, "tx_pkts": 300000, "power_saving": False, "dual_band": True, "type": "regular",
                }
                for k_out, k_in in (("hostname", "hostname"), ("os", "os"), ("manufacture", "manufacture"), ("username", "username")):
                    if s[k_in]:
                        rec[k_out] = s[k_in]
                out.append(rec)
        return out

    def wired_search(self, q: dict[str, str], site_id: str | None) -> list[dict[str, Any]]:
        start, end = self.window(q)
        results = []
        with self.lock:
            for w in self.wired:
                if site_id and w["site_id"] != site_id:
                    continue
                if not self._overlap(w, start, end):
                    continue
                if q.get("ip") and q["ip"] != w["ip"]:
                    continue
                if q.get("mac") and q["mac"].replace(":", "").lower() != w["mac"]:
                    continue
                if q.get("device_mac") and q["device_mac"].replace(":", "").lower() != w["device_mac"]:
                    continue
                if q.get("port_id") and q["port_id"] != w["port_id"]:
                    continue
                if q.get("vlan") and q["vlan"] != str(w["vlan"]):
                    continue
                if q.get("dhcp_hostname") and q["dhcp_hostname"] != w["dhcp_hostname"]:
                    continue
                rec = {"mac": w["mac"], "ip": [w["ip"]], "vlan": [w["vlan"]], "port_id": [w["port_id"]], "device_mac": [w["device_mac"]],
                       "device_mac_port": [{"device_mac": w["device_mac"], "ip": w["ip"], "port_id": w["port_id"], "vlan": w["vlan"]}],
                       "auth_method": w["auth_method"], "auth_state": w["auth_state"], "site_id": w["site_id"], "org_id": ORG_ID,
                       "timestamp": w["t_from"]}
                if w["dhcp_hostname"]:
                    rec["dhcp_hostname"] = w["dhcp_hostname"]
                results.append(rec)
        results.sort(key=lambda r: -r["timestamp"])
        return results

    def port_search(self, q: dict[str, str], site_id: str) -> list[dict[str, Any]]:
        out = []
        with self.lock:
            for p in self.ports:
                if p["site_id"] != site_id:
                    continue
                if q.get("mac") and q["mac"].replace(":", "").lower() != p["mac"]:
                    continue
                if q.get("port_id") and q["port_id"] != p["port_id"]:
                    continue
                if q.get("up") and p["up"] != (q["up"] == "true"):
                    continue
                if q.get("full_duplex") and p["full_duplex"] != (q["full_duplex"] == "true"):
                    continue
                if q.get("speed") and str(p["speed"]) != q["speed"]:
                    continue
                out.append(dict(p))
        return out

    def event_search(self, q: dict[str, str], site_id: str) -> list[dict[str, Any]]:
        start, end = self.window(q)
        out = []
        with self.lock:
            for e in self.events:
                if e["site_id"] != site_id or not (start <= e["timestamp"] <= end):
                    continue
                if q.get("type") and e["type"] not in q["type"].split(","):
                    continue
                if q.get("ap") and e["ap"] != q["ap"].replace(":", "").lower():
                    continue
                if q.get("ssid") and e["ssid"] != q["ssid"]:
                    continue
                if q.get("band") and e["band"] != q["band"]:
                    continue
                if q.get("proto") and e["proto"] != q["proto"]:
                    continue
                if q.get("wlan_id") and e["wlan_id"] != q["wlan_id"]:
                    continue
                if q.get("reason_code") and str(e.get("type_code")) != q["reason_code"]:
                    continue
                out.append({k: v for k, v in e.items() if k not in ("site_id", "client_mac")})
        out.sort(key=lambda r: -r["timestamp"])
        return out

    def client_events(self, q: dict[str, str], site_id: str, mac: str) -> list[dict[str, Any]]:
        """getSiteEventsForClient: this client's events only (OAS query: type, proto, band, channel, wlan_id, ssid, start, end, duration)."""
        start, end = self.window(q)
        with self.lock:
            known = any(s["mac"] == mac and s["site_id"] == site_id for s in self.sessions) or \
                any(e["client_mac"] == mac and e["site_id"] == site_id for e in self.events)
            if not known:
                raise MistError(404, {"id": mac})
            out = []
            for e in self.events:
                if e["site_id"] != site_id or e["client_mac"] != mac or not (start <= e["timestamp"] <= end):
                    continue
                if q.get("type") and e["type"] not in q["type"].split(","):
                    continue
                if any(q.get(k) and str(e[k]) != q[k] for k in ("ssid", "band", "proto", "wlan_id", "channel")):
                    continue
                out.append({k: v for k, v in e.items() if k not in ("site_id", "client_mac")})
        out.sort(key=lambda r: -r["timestamp"])
        return out


class MistApp:
    def __init__(self, token: str, *, now_fn: Any = time.time) -> None:
        self.token = token
        self.now = now_fn
        self.state = MistState(now_fn=now_fn)
        self.lock = threading.Lock()
        self.calls: dict[str, list[float]] = {}
        self.rate_limit = DEFAULT_RATE_LIMIT
        self.force: dict[str, Any] | None = None
        self.log: list[dict[str, Any]] = []

    def set_rate_limit(self, per_hour: int) -> None:
        with self.lock:
            self.rate_limit = int(per_hour)
            self.calls.clear()

    def set_force(self, status: int | None, count: int | None = None) -> None:
        with self.lock:
            self.force = None if status is None else {"status": int(status), "left": count}

    def take_force(self) -> int | None:
        with self.lock:
            f = self.force
            if not f:
                return None
            if f["left"] is not None:
                f["left"] -= 1
                if f["left"] <= 0:
                    self.force = None
            return f["status"]

    def charge(self, token: str) -> bool:
        """Count one call for `token` in the rolling hour; False when over the limit."""
        t = self.now()
        with self.lock:
            q = [x for x in self.calls.get(token, []) if x > t - 3600]
            q.append(t)
            self.calls[token] = q
            return len(q) <= self.rate_limit

    def record(self, method: str, path: str, query: dict[str, str], status: int) -> None:
        with self.lock:
            self.log.append({"method": method, "path": path, "query": dict(query), "status": status})
            del self.log[:-5000]

    def calls_to(self, fragment: str) -> int:
        with self.lock:
            return sum(1 for r in self.log if fragment in r["path"])


def _cursor_enc(off: int) -> str:
    return base64.urlsafe_b64encode(f"o:{off}".encode()).decode().rstrip("=")


def _cursor_dec(c: str | None) -> int:
    if not c:
        return 0
    try:
        raw = base64.urlsafe_b64decode(c + "=" * (-len(c) % 4)).decode()
        if not raw.startswith("o:"):
            raise ValueError
        off = int(raw[2:])
    except (ValueError, UnicodeDecodeError) as exc:
        raise bad("invalid search_after") from exc
    if off < 0:
        raise bad("invalid search_after")
    return off


_SITE_RE = re.compile(r"/api/v1/sites/([0-9a-f-]{36})/(.+)\Z")
_ORG_RE = re.compile(r"/api/v1/orgs/([0-9a-f-]{36})/(.+)\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


class Handler(fc.BaseHandler):
    def dispatch(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        app: MistApp = self.app
        q = {k: v[-1] for k, v in query.items()}
        if path.startswith("/_fake/"):
            return self._control(method, path, q)
        status = 200
        try:
            status, body = self._api(app, method, path, q)
        except MistError as exc:
            status, body = exc.status, exc.body
        app.record(method, path, q, status)
        self.send_json(status, body)

    def _api(self, app: MistApp, method: str, path: str, q: dict[str, str]) -> tuple[int, Any]:
        # auth first: Authorization: Token <apitoken>   (OAS securityScheme apiToken)
        auth = self.header("Authorization") or ""
        scheme, _, tok = auth.partition(" ")
        if scheme != "Token" or not tok.strip() or not fc.exp_ids.tokens_equal(hashlib.sha256(tok.strip().encode()).hexdigest(),
                                                                                hashlib.sha256(app.token.encode()).hexdigest()):
            raise MistError(401, {"detail": "Authentication credentials were not provided."})
        forced = app.take_force()
        if forced is not None:
            raise MistError(forced, {"detail": "forced by test"})
        if not app.charge(tok.strip()):
            raise MistError(429, {"detail": RATE_LIMIT_DETAIL})
        if method != "GET":
            raise MistError(405, {"detail": "Method not allowed."})
        if path == "/api/v1/const/client_events":
            return 200, list(EVENT_DEFS)
        st = app.state
        m = _SITE_RE.match(path)
        if m:
            site_id, rest = m.groups()
            if site_id not in st.sites:
                raise MistError(404, {"id": site_id})
            return self._site(app, st, site_id, rest, path, q)
        m = _ORG_RE.match(path)
        if m:
            org_id, rest = m.groups()
            if org_id != ORG_ID:
                raise MistError(404, {"id": org_id})
            if rest == "clients/search":
                return 200, self._page(path, q, st.wireless_search(q, None), q)
            if rest == "wired_clients/search":
                return 200, self._page(path, q, st.wired_search(q, None), q)
        raise MistError(404, {"id": path})

    def _site(self, app: MistApp, st: MistState, site_id: str, rest: str, path: str, q: dict[str, str]) -> tuple[int, Any]:
        if rest == "clients/search":
            return 200, self._page(path, q, st.wireless_search(q, site_id), q)
        if rest == "wired_clients/search":
            return 200, self._page(path, q, st.wired_search(q, site_id), q)
        if rest == "stats/ports/search":
            return 200, self._page(path, q, st.port_search(q, site_id), q, window=False)
        if rest == "clients/events/search":
            return 200, self._page(path, q, st.event_search(q, site_id), q)
        m = re.fullmatch(r"clients/([0-9a-fA-F:-]{12,17})/events", rest)       # getSiteEventsForClient
        if m:
            try:
                mac = norm_mac(m.group(1))
            except ValueError as exc:
                raise bad("invalid client_mac") from exc
            return 200, self._page_n(path, q, st.client_events(q, site_id, mac))
        if rest == "stats/clients":
            if q.get("wired") == "true":
                return 200, []
            return 200, st.wireless_stats(site_id)[: self._limit(q)]
        m = re.fullmatch(r"stats/clients/([0-9a-fA-F:-]{12,17})", rest)
        if m:
            try:
                mac = norm_mac(m.group(1))
            except ValueError as exc:
                raise bad("invalid client_mac") from exc
            found = [] if q.get("wired") == "true" else st.wireless_stats(site_id, mac)
            if not found:
                raise MistError(404, {"id": mac})
            return 200, found[0]
        if rest == "stats/devices":
            with st.lock:
                return 200, [dict(a) for a in st.aps.values() if a["site_id"] == site_id]
        m = re.fullmatch(r"stats/devices/([0-9a-f-]{36})", rest)
        if m:
            with st.lock:
                ap = st.aps.get(m.group(1))
                if ap is None or ap["site_id"] != site_id:
                    raise MistError(404, {"id": m.group(1)})
                ap = dict(ap)
                ap["last_seen"] = app.now()
                return 200, ap
        raise MistError(404, {"id": rest})

    @staticmethod
    def _limit(q: dict[str, str]) -> int:
        raw = q.get("limit", "100")
        if not re.fullmatch(r"[0-9]{1,6}", raw):
            raise bad("invalid limit")
        return min(int(raw), MAX_LIMIT)

    def _page(self, path: str, q: dict[str, str], items: list[dict[str, Any]], raw_q: dict[str, str], window: bool = True) -> dict[str, Any]:
        limit = self._limit(q)
        off = _cursor_dec(q.get("search_after"))
        page = items[off: off + limit]
        out: dict[str, Any] = {"limit": limit, "total": len(items), "results": page}
        if window:
            start, end = self.app.state.window(q)
            out["start"], out["end"] = int(start), int(end)
        if off + limit < len(items) and limit > 0:
            nq = {k: v for k, v in raw_q.items() if k != "search_after"}
            nq["search_after"] = _cursor_enc(off + limit)
            out["next"] = path + "?" + "&".join(f"{k}={v}" for k, v in nq.items())
        return out

    def _page_n(self, path: str, q: dict[str, str], items: list[dict[str, Any]]) -> dict[str, Any]:
        """Page-based pagination of getSiteEventsForClient (``limit`` default 100, ``page`` >= 1); ``next`` while more pages exist."""
        limit = self._limit(q)
        raw = q.get("page", "1")
        if not re.fullmatch(r"[0-9]{1,6}", raw) or int(raw) < 1:
            raise bad("invalid page")
        page = int(raw)
        off = (page - 1) * limit
        start, end = self.app.state.window(q)
        out: dict[str, Any] = {"start": int(start), "end": int(end), "limit": limit, "total": len(items), "results": items[off: off + limit]}
        if limit > 0 and off + limit < len(items):
            nq = {k: v for k, v in q.items() if k != "page"}
            nq["page"] = str(page + 1)
            out["next"] = path + "?" + "&".join(f"{k}={v}" for k, v in nq.items())
        return out

    # ---- test-only control -----------------------------------------------------------------------------------
    def _control(self, method: str, path: str, q: dict[str, str]) -> None:
        if not self.client_is_loopback():
            self.send_err(403, "forbidden", "loopback only")
            return
        app: MistApp = self.app
        sub = path[len("/_fake/"):]
        try:
            if method == "GET" and sub == "log":
                with app.lock:
                    self.send_json(200, {"calls": list(app.log), "per_token": {k[:4]: len(v) for k, v in app.calls.items()}})
                return
            doc, ok = self.read_json(64 * 1024) if method == "POST" and self.content_length() else ({}, True)
            if not ok:
                return
            if method != "POST":
                self.send_err(404, "not_found", "no such control")
                return
            if sub == "scenario":
                info = app.state.load_scenario(str(doc["name"]), at=float(doc.get("at", app.now())), ip=doc.get("ip", "10.60.14.77"),
                                               mac=doc.get("mac", "f0:18:98:aa:bb:01"))
                self.send_json(200, info)
            elif sub == "reset":
                app.state.reset()
                with app.lock:
                    app.log.clear()
                    app.calls.clear()
                self.send_json(200, {"ok": True})
            elif sub == "force":
                app.set_force(doc.get("status"), doc.get("count"))
                self.send_json(200, {"ok": True})
            elif sub == "rate_limit":
                app.set_rate_limit(int(doc["per_hour"]))
                self.send_json(200, {"ok": True})
            elif sub == "clients":
                self.send_json(200, app.state.add_wireless_session(**doc))
            elif sub == "events":
                self.send_json(200, app.state.add_event(**doc))
            else:
                self.send_err(404, "not_found", "no such control")
        except (KeyError, TypeError, ValueError) as exc:
            self.send_err(400, "invalid_request", str(exc)[:200])


class FakeMist(fc.FakeServer):
    @property
    def token(self) -> str:
        return self.app.token

    @property
    def state(self) -> MistState:
        return self.app.state


def default_token() -> str:
    """Deterministic fake API token (derived at runtime, 40 hex chars; never a real Mist token)."""
    return hashlib.sha256(b"fixture:mist-api-token").hexdigest()[:40]


def start(*, host: str = "127.0.0.1", port: int = 0, tls: tuple[Path, Path] | None = None, token: str | None = None,
          now_fn: Any = time.time, rate_limit: int = DEFAULT_RATE_LIMIT) -> FakeMist:
    app = MistApp(token or default_token(), now_fn=now_fn)
    app.rate_limit = rate_limit
    srv = FakeMist(Handler, app, host=host, port=port, tls=tls, name="fake-mist")
    srv.start()
    return srv


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--listen", default="127.0.0.1:8485")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--scenario", choices=SCENARIOS)
    ap.add_argument("--ip", default="10.60.14.77")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, stream=sys.stderr)
    host, _, port = args.listen.rpartition(":")
    tls = (Path(args.cert), Path(args.key)) if args.cert and args.key else None
    app = MistApp(default_token())
    if args.scenario:
        app.state.load_scenario(args.scenario, at=time.time(), ip=args.ip)
    srv = FakeMist(Handler, app, host=host or "127.0.0.1", port=int(port), tls=tls, name="fake-mist")
    fc.run_forever(srv, lambda: f"fake-mist on {srv.base_url} org={ORG_ID} site={SITE_ID} token={app.token} scenario={args.scenario}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# ruff: noqa: E501  (protocol tables in the module docstring)
"""Fake HPE EdgeConnect Orchestrator for the M6 runner (HTTP, or HTTPS with a runtime throwaway CA).

Request and response shapes come from HPE's official SDK **pyedgeconnect 0.16.0a1** (MIT; ``pyedgeconnect/orch/*.py``;
a dev-time reference, never imported). The REST root is ``/gms/rest`` (``Orchestrator.url_prefix`` in ``__init__.py``).

**Auth** (``pyedgeconnect/__init__.py`` ``Orchestrator.__init__`` and ``orch/_login.py``):

* API key: header ``X-Auth-Token: <key>`` (``self.headers = {"X-Auth-Token": api_key}``);
* login session: ``POST /authentication/login`` with ``{"user", "password", "token", "loginType"}`` (loginType 0 local, 1 RADIUS,
  2 TACACS+). On 200 the response sets a cookie named ``orchCsrfToken``; the client then sends its value in ``X-XSRF-TOKEN`` on
  every request, plus the session cookie that ``requests.Session`` carries. pyedgeconnect does not name the session cookie; the
  fake uses ``fake_orch_session``. Without a valid key, or a session cookie **and** a matching ``X-XSRF-TOKEN``: 401. Sessions expire
  after ``session_ttl_s`` of the fake clock (a runner must log in again). ``GET /authentication/logout`` ends the session.
  MFA (``/authentication/loginToken``) is not simulated.

**Endpoints** (pyedgeconnect function -> path; both the >= 9.3 query form and the older ``/{neId}`` path form are served):

=============================================  ==========================================================================
``get_orchestrator_server_brief``              ``GET /gmsserver/briefInfo`` (``uptime``, ``release``, ``time``, ``timeZone``, ``inContainerMode``)
``get_appliances``                             ``GET /appliance`` and ``?nePk=`` (``_appliance.py`` fields: ``id``, ``nePk``, ``hostName``, ``IP``, ``state`` 0-5 ...)
``get_appliance_flows``                        ``GET /flow?nePk=..&ip1=..`` (and ``/flow/{neId}/q?..``): flow rows are the 63-element positional lists of the docstring
``get_appliance_interface_state``              ``GET /interfaceState?nePk=..&cached=..`` (and ``/interfaceState/{neId}``): ``sysConfig``, ``scalars.maxWanBandwidth``, ``ifInfo[]``
``get_timeseries_stats_interface_single_appliance``  ``GET /stats/timeseries/interface?nePk=..&startTime=..&endTime=..&granularity=..&trafficType=..&interfaceName=..``
``get_timeseries_stats_traffic_class_single_appliance``  ``GET /stats/timeseries/trafficClass?nePk=..&trafficType=..&trafficClass=..``
``get_health_latency / _loss / _jitter / _mos``  ``GET /health/{latency,loss,jitter,mos}PeriodSummary?applianceId=..&time=..&overlayId=..``
``get_alarms_from_appliances``                 ``POST /alarm/appliance?view=..&severity=..&maxAlarms=..&from=..&to=..`` body ``{"nePks": [..]}`` (``{"ids": [..]}`` before 9.3)
=============================================  ==========================================================================

What pyedgeconnect does **not** document, and how the fake handles it (stated plainly, never presented as vendor fact):

* **Time-series column names.** The docstrings say only "COLUMN_DEF ... and DATA". The fake answers
  ``{"COLUMN_DEF": [...], "DATA": {"<nePk>": [[...], ...]}}`` (envelope shape chosen from the docstring prose; the
  ``get_..._interface_...`` docstring types it ``list``, so a client must tolerate both) with **fake-chosen** column names
  (interface: ``time, interface, rx_bytes, tx_bytes``; traffic class: ``time, tx_bytes, rx_bytes, drop_pkts``) that tests can
  rename (``fake.app.interface_columns``) to prove a parser reads COLUMN_DEF at runtime. Bytes are per granularity bucket (minute).
* **Health summary shape.** The docstrings type the four health calls ``dict`` yet describe per-tunnel fields. Default
  (``health_shape="dict"``) returns the worst tunnel; ``"list"`` returns one object per tunnel.
* **``ipEitherFlag``.** The docstring says True "will treat ip1 as source ip and ip2 as destination ip" although the parameter
  name suggests "either". The fake follows the docstring (True = directional, False = either direction); a client passing the
  client IP as ``ip1`` of a client-originated flow gets the same flows under both readings.
* The EC firewall / zone-policy **syslog** line text: no local vendor doc; see ``syslog_sender.py``.

Scenarios (``OrchState.load_scenario`` / ``POST /_fake/scenario``): ``healthy``, ``saturated_wan`` (WAN at 92.5 % of
``maxWanBandwidth``, latency health major), ``qos_shaped`` (client flows in traffic class 7 with shaper drops), ``loss``
(tunnel loss critical + alarm), ``firewall_drop`` (client flows dropped by the zone firewall, ``drop_reason`` 1). Control API
under ``/_fake/`` (loopback only): ``POST scenario|reset|force|wan_load|login_fail``, ``GET log``.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import sys
import threading
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import fakes_common as fc  # noqa: E402

log = logging.getLogger("exp.fakes.orchestrator")

PREFIX = "/gms/rest"
SESSION_COOKIE = "fake_orch_session"
CSRF_COOKIE = "orchCsrfToken"
RELEASE = "9.3.4"
NE_CORE = {"id": "1.NE", "hostName": "ec-core", "IP": "10.0.0.2", "serial": "FAKE-CORE-0001", "model": "EC-L"}
NE_EDGE = {"id": "2.NE", "hostName": "ec-edge", "IP": "10.0.0.3", "serial": "FAKE-EDGE-0002", "model": "EC-M"}
DEFAULT_MAX_WAN_KBPS = 200_000
SCENARIOS = ("healthy", "saturated_wan", "qos_shaped", "loss", "firewall_drop")
INTERFACE_COLUMNS = ["time", "interface", "rx_bytes", "tx_bytes"]
TRAFFIC_CLASS_COLUMNS = ["time", "tx_bytes", "rx_bytes", "drop_pkts"]
MAX_ROWS = 10_000
FLOW_ROW_LEN = 63


def ip_to_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip)) if ":" not in ip else 0


def flow_row(f: dict[str, Any]) -> list[Any]:
    """The 63-element positional flow row of ``get_appliance_flows`` (indices as documented in its docstring)."""
    r: list[Any] = [0] * FLOW_ROW_LEN
    ver1 = 6 if ":" in f["src_ip"] else 4
    ver2 = 6 if ":" in f["dst_ip"] else 4
    r[0], r[1], r[2] = f.get("flow_id", 1), 1, f.get("flow_id", 1)       # [0] flow id, [1] sequence id, [2] SilverPeak flow id
    r[3] = f["application"]                                               # [3] Application Name
    r[4], r[8], r[9], r[10] = ip_to_int(f["src_ip"]), ver1, f["src_ip"], f["src_port"]       # [4] IP1_1, [8] version, [9] IP1 string, [10] Port1
    r[11], r[15], r[16], r[17] = ip_to_int(f["dst_ip"]), ver2, f["dst_ip"], f["dst_port"]    # [11] IP2_1, [15] version, [16] IP2 string, [17] Port2
    r[18] = f.get("optimization", 0)                                      # [18] Flow Optimization Status
    r[20], r[21], r[22], r[23] = f.get("bytes_in_tx", 0), f.get("bytes_in_rx", 0), f.get("bytes_out_rx", 0), f.get("bytes_out_tx", 0)
    r[25] = f.get("uptime_ms", 0)                                         # [25] Uptime in ms
    r[26] = f.get("protocol", "tcp")                                      # [26] Protocol
    r[27], r[28], r[29] = f.get("out_tunnel", "to_dc"), f.get("in_tunnel", "to_dc"), f.get("out_tunnel", "to_dc")
    r[30] = f.get("vlan", 160)                                            # [30] LAN side VLAN
    r[31] = f.get("traffic_class", 3)                                     # [31] QoS Traffic Class (1-10)
    r[32], r[33] = f.get("lan_dscp", "trust-lan"), f.get("wan_dscp", "trust-lan")
    r[38] = f["start_s"]                                                  # [38] Flow Start Time, unix epoch seconds
    r[39] = f.get("end_s", 0)                                             # [39] Flow End Time (0 = still active)
    r[43] = f.get("slow_duration", 0)                                     # [43] TCP Slow Duration
    r[46], r[47] = f.get("from_zone", 1), f.get("to_zone", 2)             # [46] From Zone, [47] To Zone
    r[48] = 1 if f.get("drop_reason", 0) == 1 else 0                      # [48] dropped by security policy (ZBF)
    r[49] = "false"                                                       # [49] EdgeHA
    r[58] = f.get("app_type", "Interactive")                              # [58] Application Type
    r[59] = f.get("drop_reason", 0)                                       # [59] Drop reason: 0 none, 1 ZBF, 2 routing
    r[60] = f.get("overlay", "DefaultOverlay")                            # [60] Business Intent Overlay
    r[61], r[62] = 0, 0                                                   # [61] source VRF, [62] destination VRF
    return r


class OrchState:
    def __init__(self, *, now_fn: Any = time.time) -> None:
        self.now = now_fn
        self.lock = threading.RLock()
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.appliances: dict[str, dict[str, Any]] = {a["id"]: dict(a, state=1) for a in (NE_CORE, NE_EDGE)}
            self.flows: dict[str, list[dict[str, Any]]] = {k: [] for k in self.appliances}
            self.wan_load: dict[tuple[str, str], list[tuple[float, int, int]]] = {}    # (nePk, ifname) -> [(from, rx_bps, tx_bps)]
            self.max_wan_kbps = {k: DEFAULT_MAX_WAN_KBPS for k in self.appliances}
            self.tunnels: dict[str, list[dict[str, Any]]] = {k: [self._tunnel("to_dc")] for k in self.appliances}
            self.alarms: dict[str, list[dict[str, Any]]] = {k: [] for k in self.appliances}
            self.class_drops: dict[tuple[str, int], int] = {}
            self.seq = 500
            for ne in self.appliances:
                self.wan_load[(ne, "wan0")] = [(0.0, 12_000_000, 4_000_000)]

    @staticmethod
    def _tunnel(tid: str, lat: float = 12, loss: float = 0.0, jitter: float = 1.5, mos: float = 4.3, status: str = "HEALTHY",
                crit: int = 0, major: int = 0) -> dict[str, Any]:
        return {"tunnelId": tid, "healthStatus": status, "criticalMins": crit, "majorMins": major, "normalMins": 60 - crit - major,
                "latency": lat, "loss": loss, "jitter": jitter, "mos": mos}

    # ---- mutation -----------------------------------------------------------------------------------------
    def set_wan_load(self, ne_pk: str, ifname: str, rx_bps: int, tx_bps: int, t_from: float | None = None) -> None:
        """From `t_from` (default: now) the interface carries rx/tx bps. Segments are kept sorted by start."""
        with self.lock:
            segs = self.wan_load.setdefault((ne_pk, ifname), [])
            segs.append((self.now() if t_from is None else t_from, int(rx_bps), int(tx_bps)))
            segs.sort()

    def wan_util_pct(self, ne_pk: str, ifname: str = "wan0") -> float:
        rx, tx = self.load_at(ne_pk, ifname, self.now())
        return max(rx, tx) / (self.max_wan_kbps[ne_pk] * 1000) * 100

    def load_at(self, ne_pk: str, ifname: str, t: float) -> tuple[int, int]:
        with self.lock:
            cur = (0, 0)
            for frm, rx, tx in self.wan_load.get((ne_pk, ifname), []):
                if frm <= t:
                    cur = (rx, tx)
            return cur

    def add_flow(self, ne_pk: str, **kw: Any) -> dict[str, Any]:
        with self.lock:
            f = {"flow_id": len(self.flows[ne_pk]) + 1, "application": "https", "src_port": 51000, "dst_port": 443, "dst_ip": "203.0.113.50",
                 "protocol": "tcp", "traffic_class": 3, "overlay": "DefaultOverlay", **kw}
            self.flows[ne_pk].append(f)
            return f

    def add_alarm(self, ne_pk: str, *, severity: str, name: str, description: str, type_: str, t: float, closed: bool = False,
                  service_affect: bool = True, count: int = 1) -> dict[str, Any]:
        with self.lock:
            self.seq += 1
            a = {"applianceId": ne_pk, "severity": severity, "sequenceId": self.seq, "source": "system", "acknowledged": False,
                 "clearable": True, "timeOccurredInMills": int(t * 1000), "description": description, "type": type_,
                 "recommendedAction": "", "serviceAffect": service_affect, "typeId": 40000 + self.seq, "name": name,
                 "occurrenceCount": count, "hostName": self.appliances[ne_pk]["hostName"], "closed": closed}
            if closed:
                a["clearedTimeInMills"] = int(t * 1000) + 60_000
            self.alarms[ne_pk].append(a)
            return a

    def load_scenario(self, name: str, *, at: float, client_ip: str = "10.60.14.77", ne_pk: str = "1.NE") -> dict[str, Any]:
        if name not in SCENARIOS:
            raise ValueError(f"unknown scenario {name!r}; one of {SCENARIOS}")
        self.reset()
        out: dict[str, Any] = {"scenario": name, "ne_pk": ne_pk, "client_ip": client_ip}
        base = {"src_ip": client_ip, "start_s": int(at - 120), "uptime_ms": 120_000}
        with self.lock:
            self.add_flow(ne_pk, **base, application="speedtest_http", bytes_out_tx=60_000_000, bytes_in_rx=190_000_000, bytes_in_tx=1_000)
            self.add_flow(ne_pk, **base, application="dns", protocol="udp", dst_port=53, src_port=40001, bytes_out_tx=900, bytes_in_rx=2_400,
                          dst_ip="10.0.0.53", app_type="Interactive")
            self.add_flow(ne_pk, **{**base, "src_ip": "10.60.15.9"}, application="https", bytes_out_tx=1_000, bytes_in_rx=2_000)   # another client
        if name == "healthy":
            pass
        elif name == "saturated_wan":
            self.set_wan_load(ne_pk, "wan0", 185_000_000, 60_000_000, t_from=at - 600)       # 92.5 % of 200 Mbps
            self.tunnels[ne_pk] = [self._tunnel("to_dc", lat=38, major=14, crit=6, status="CRITICAL")]
            self.add_alarm(ne_pk, severity="major", name="Tunnel state", description="WAN link wan0 utilisation above 90%", type_="tunnel", t=at - 300)
            out["util_pct"] = 92.5
        elif name == "qos_shaped":
            for f in self.flows[ne_pk]:
                if f["src_ip"] == client_ip and f["application"] == "speedtest_http":
                    f.update(traffic_class=7, app_type="Bulk_Data_transfer", slow_duration=40, lan_dscp="be", wan_dscp="be")
            self.class_drops[(ne_pk, 7)] = 4_200
            self.add_alarm(ne_pk, severity="warning", name="Shaper drops", description="Traffic class 7 exceeding its shaper rate", type_="shaper",
                           t=at - 200, service_affect=False)
            out["traffic_class"] = 7
        elif name == "loss":
            self.tunnels[ne_pk] = [self._tunnel("to_dc", lat=22, loss=3.5, jitter=9, mos=3.2, status="CRITICAL", crit=11)]
            self.add_alarm(ne_pk, severity="critical", name="Tunnel loss", description="Tunnel to_dc packet loss above threshold", type_="tunnel",
                           t=at - 240)
            out["loss_pct"] = 3.5
        elif name == "firewall_drop":
            self.add_flow(ne_pk, **base, application="ssh", src_port=51234, dst_port=22, drop_reason=1, bytes_out_tx=0, bytes_in_rx=0,
                          from_zone=1, to_zone=3)
            out["dropped"] = True
        return out

    # ---- queries ------------------------------------------------------------------------------------------
    def appliance_json(self, a: dict[str, Any]) -> dict[str, Any]:
        return {"id": a["id"], "nePk": a["id"], "uuid": hashlib.sha256(a["id"].encode()).hexdigest()[:32], "networkRole": "0", "site": "hall-b",
                "sitePriority": 0, "userName": "admin", "groupId": "0.Network", "IP": a["IP"], "ip": a["IP"], "webProtocolType": 2,
                "serial": a["serial"], "hasUnsavedChanges": False, "rebootRequired": False, "model": a["model"], "hardwareRevision": "200",
                "hostName": a["hostName"], "applianceId": 1, "mode": "router", "bypass": False, "softwareVersion": "9.3.2.0_12345",
                "startupTime": int(self.now() - 86400), "webProtocol": "BOTH", "systemBandwidth": self.max_wan_kbps[a["id"]],
                "state": a["state"], "dynamicUuid": "", "portalObjectId": "", "discoveredFrom": 3, "reachabilityChannel": 2,
                "zoneList": {"zones": ["0", "1", "2"]}, "interfaceList": {"interfaceLabels": ["1", "2"]}, "tagsList": []}

    def interface_state(self, ne_pk: str) -> dict[str, Any]:
        a = self.appliances[ne_pk]
        return {
            "sysConfig": {"mode": "router", "submode": "inline", "bonding": False},
            "scalars": {"maxWanBandwidth": self.max_wan_kbps[ne_pk], "maxTunnels": 1000, "maxRouteMapEntries": 1000, "processorCount": 4},
            "ifInfo": [
                {"ifname": "wan0", "admin": True, "oper": True, "ipv4": "198.51.100.2", "ipv4mask": "255.255.255.252", "ipv4dhcp": False,
                 "ifSpeed": "1000", "ifDuplex": "auto", "duplex": "full (auto)", "mtu": 1500, "mac": "02:00:00:00:00:01", "wan-if": True,
                 "lan-if": False, "harden": False, "label": "2", "publicIp": "203.0.113.2",
                 "supported": "10/full,100/full,1000/full,auto/auto", "vrf": 0},
                {"ifname": "lan0", "admin": True, "oper": True, "ipv4": a["IP"], "ipv4mask": "255.255.255.0", "ipv4dhcp": False,
                 "ifSpeed": "1000", "ifDuplex": "auto", "duplex": "full (auto)", "mtu": 1500, "mac": "02:00:00:00:00:02", "wan-if": False,
                 "lan-if": True, "harden": False, "label": "1", "publicIp": "", "supported": "10/full,100/full,1000/full,auto/auto", "vrf": 0},
            ],
            "macIfs": ["wan0", "lan0"], "availMACs": [],
        }

    def health(self, ne_pk: str, kind: str, shape: str) -> Any:
        rows = []
        for t in self.tunnels[ne_pk]:
            r = {"tunnelId": t["tunnelId"], "healthStatus": t["healthStatus"], "criticalMins": t["criticalMins"], "majorMins": t["majorMins"],
                 "normalMins": t["normalMins"]}
            if kind == "loss":
                r["maxLossPercentage"] = t["loss"]
            else:
                r["max"] = {"latency": t["latency"], "jitter": t["jitter"], "mos": t["mos"]}[kind]
            rows.append(r)
        if shape == "list":
            return rows
        order = {"CRITICAL": 0, "MAJOR": 1, "HEALTHY": 2}
        rows.sort(key=lambda r: order.get(r["healthStatus"], 3))
        return rows[0] if rows else {}


class OrchApp:
    def __init__(self, *, api_keys: set[str], users: dict[str, str], now_fn: Any = time.time, release: str = RELEASE) -> None:
        self.now = now_fn
        self.state = OrchState(now_fn=now_fn)
        self.api_keys = api_keys
        self.users = users
        self.release = release
        self.sessions: dict[str, dict[str, Any]] = {}
        self.session_ttl_s = 1800.0
        self.interface_columns = list(INTERFACE_COLUMNS)
        self.health_shape = "dict"
        self.force: dict[str, Any] | None = None
        self.lock = threading.Lock()
        self.log: list[dict[str, Any]] = []
        self.login_fail = False

    def record(self, method: str, path: str, query: dict[str, str], status: int, auth: str) -> None:
        with self.lock:
            self.log.append({"method": method, "path": path, "query": dict(query), "status": status, "auth": auth})
            del self.log[:-5000]

    def calls_to(self, fragment: str) -> int:
        with self.lock:
            return sum(1 for r in self.log if fragment in r["path"])

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

    def new_session(self) -> tuple[str, str]:
        sid, csrf = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        with self.lock:
            self.sessions[sid] = {"csrf": csrf, "expires": self.now() + self.session_ttl_s}
        return sid, csrf

    def check_session(self, sid: str | None, xsrf: str | None) -> bool:
        if not sid or not xsrf:
            return False
        with self.lock:
            s = self.sessions.get(sid)
            if s is None or s["expires"] < self.now():
                self.sessions.pop(sid, None)
                return False
            return hmac.compare_digest(s["csrf"].encode(), xsrf.encode())

    def expire_sessions(self) -> None:
        with self.lock:
            self.sessions.clear()


def _cookies(header: str | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (header or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            out[k] = v
    return out


def _bool(v: str | None, default: bool = False) -> bool:
    return default if v is None else v.lower() == "true"


class ApiError(Exception):
    def __init__(self, status: int, body: Any = None) -> None:
        super().__init__(status)
        self.status = status
        self.body = body


class Handler(fc.BaseHandler):
    def dispatch(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        app: OrchApp = self.app
        q = {k: v[-1] for k, v in query.items()}
        if path.startswith("/_fake/"):
            return self._control(method, path)
        if not path.startswith(PREFIX + "/"):
            self.send_err(404, "not_found", "not under /gms/rest")
            return
        rest = path[len(PREFIX):]
        auth_kind = "none"
        extra: list[tuple[str, str]] = []
        try:
            if rest == "/authentication/login" and method == "POST":
                status, body, extra = self._login(app)
            else:
                auth_kind = self._auth(app)
                forced = app.take_force()
                if forced is not None:
                    raise ApiError(forced, {"error": "forced by test"})
                status, body, extra = self._api(app, method, rest, q)
        except ApiError as exc:
            status, body = exc.status, exc.body if exc.body is not None else {"error": "error"}
        app.record(method, rest, q, status, auth_kind)
        data = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if data and method != "HEAD":
            self.wfile.write(data)

    # ---- auth ----------------------------------------------------------------------------------------------
    def _auth(self, app: OrchApp) -> str:
        key = self.header("X-Auth-Token")
        if key is not None:
            if any(fc.exp_ids.tokens_equal(hashlib.sha256(key.encode()).hexdigest(), hashlib.sha256(k.encode()).hexdigest()) for k in app.api_keys):
                return "api_key"
            raise ApiError(401, {"error": "invalid API key"})
        cookies = _cookies(self.header("Cookie"))
        if app.check_session(cookies.get(SESSION_COOKIE), self.header("X-XSRF-TOKEN")):
            return "session"
        raise ApiError(401, {"error": "unauthorized"})

    def _login(self, app: OrchApp) -> tuple[int, Any, list[tuple[str, str]]]:
        doc, ok = self.read_json(4096)
        if not ok:
            raise ApiError(400, {"error": "bad login body"})
        if app.login_fail or not isinstance(doc, dict) or not (isinstance(doc.get("user"), str) and isinstance(doc.get("password"), str)) \
                or doc.get("loginType") not in (0, 1, 2) or "token" not in doc:
            raise ApiError(401, {"error": "login failed"})
        pw = app.users.get(doc["user"])
        if pw is None or not hmac.compare_digest(pw.encode(), doc["password"].encode()):
            raise ApiError(401, {"error": "login failed"})
        sid, csrf = app.new_session()
        return 200, {}, [("Set-Cookie", f"{CSRF_COOKIE}={csrf}; Path=/"), ("Set-Cookie", f"{SESSION_COOKIE}={sid}; Path=/; HttpOnly")]

    # ---- routes --------------------------------------------------------------------------------------------
    def _api(self, app: OrchApp, method: str, rest: str, q: dict[str, str]) -> tuple[int, Any, list[tuple[str, str]]]:
        st = app.state
        if rest == "/authentication/logout" and method == "GET":
            sid = _cookies(self.header("Cookie")).get(SESSION_COOKIE)
            with app.lock:
                app.sessions.pop(sid or "", None)
            return 200, {}, []
        if rest == "/gmsserver/briefInfo" and method == "GET":
            return 200, {"uptime": "3 days, 2 hours", "release": app.release, "time": "Fri Nov 20 01:23:28 2026", "timeZone": "UTC",
                         "inContainerMode": False}, []
        if rest == "/appliance" and method == "GET":
            if q.get("nePk"):
                ne = self._ne(st, q["nePk"])
                return 200, st.appliance_json(st.appliances[ne]), []
            return 200, [st.appliance_json(a) for a in st.appliances.values()], []
        if rest == "/flow" and method == "GET":
            return 200, self._flows(st, self._ne(st, q.get("nePk")), q), []
        if rest.startswith("/flow/") and rest.endswith("/q") and method == "GET":
            return 200, self._flows(st, self._ne(st, rest[len("/flow/"):-2]), q), []
        if rest == "/interfaceState" and method == "GET":
            return 200, st.interface_state(self._ne(st, q.get("nePk"))), []
        if rest.startswith("/interfaceState/") and method == "GET":
            return 200, st.interface_state(self._ne(st, rest[len("/interfaceState/"):])), []
        if rest == "/stats/timeseries/interface" and method == "GET":
            return 200, self._ts_interface(app, self._ne(st, q.get("nePk")), q), []
        if rest.startswith("/stats/timeseries/interface/") and method == "GET":
            return 200, self._ts_interface(app, self._ne(st, rest.rsplit("/", 1)[1]), q), []
        if rest == "/stats/timeseries/trafficClass" and method == "GET":
            return 200, self._ts_class(app, self._ne(st, q.get("nePk")), q), []
        for kind in ("latency", "loss", "jitter", "mos"):
            if rest == f"/health/{kind}PeriodSummary" and method == "GET":
                ne = self._ne(st, q.get("applianceId"))
                if not (q.get("time") or "").lstrip("-").isdigit():
                    raise ApiError(400, {"error": "time must be epoch seconds"})
                return 200, st.health(ne, kind, app.health_shape), []
        if rest == "/alarm/appliance" and method == "POST":
            return 200, self._alarms(app, q), []
        raise ApiError(404, {"error": "unknown route " + rest})

    @staticmethod
    def _ne(st: OrchState, ne: str | None) -> str:
        if not ne or ne not in st.appliances:
            raise ApiError(404, {"error": f"unknown appliance {ne}"})
        return ne

    def _flows(self, st: OrchState, ne: str, q: dict[str, str]) -> dict[str, Any]:
        def net(ip: str | None, mask: str | None) -> Any:
            if not ip:
                return None
            try:
                a = ipaddress.ip_address(ip)
                return ipaddress.ip_network(f"{ip}/{mask}", strict=False) if mask else a
            except ValueError as exc:
                raise ApiError(400, {"error": "bad ip/mask"}) from exc

        n1, n2 = net(q.get("ip1"), q.get("mask1")), net(q.get("ip2"), q.get("mask2"))

        def in_net(n: Any, ip: str) -> bool:
            a = ipaddress.ip_address(ip)
            return a in n if isinstance(n, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else a == n

        directional = _bool(q.get("ipEitherFlag"), True)
        now = st.now()

        def int_param(name: str) -> int | None:
            v = q.get(name)
            if v is None or v == "None":
                return None
            if not v.lstrip("-").isdigit():
                raise ApiError(400, {"error": f"bad {name}"})
            return int(v)

        any_s, any_e = int_param("anyStartTime"), int_param("anyEndTime")
        term_s, term_e = int_param("termStartTime"), int_param("termEndTime")
        cat = q.get("filter", "all")
        with st.lock:
            allf = list(st.flows[ne])
        matched = []
        for f in allf:
            if n1 is not None and n2 is not None:
                ok = (in_net(n1, f["src_ip"]) and in_net(n2, f["dst_ip"])) or (not directional and in_net(n1, f["dst_ip"]) and in_net(n2, f["src_ip"]))
            elif n1 is not None:
                ok = in_net(n1, f["src_ip"]) or (not directional and in_net(n1, f["dst_ip"]))
            elif n2 is not None:
                ok = in_net(n2, f["dst_ip"]) or (not directional and in_net(n2, f["src_ip"]))
            else:
                ok = True
            if not ok:
                continue
            if q.get("port1") not in (None, "None") and int(q["port1"]) != f["src_port"]:
                continue
            if q.get("port2") not in (None, "None") and int(q["port2"]) != f["dst_port"]:
                continue
            if q.get("application") and q["application"] != f["application"]:
                continue
            if q.get("protocol") and q["protocol"] != f["protocol"]:
                continue
            if q.get("vlan") and q["vlan"] != str(f.get("vlan", 160)):
                continue
            if q.get("overlays") and q["overlays"].split("|") and f.get("overlay") and not any(o in ("1", f["overlay"]) for o in q["overlays"].split("|")):
                continue
            if cat == "firewallDropped" and f.get("drop_reason") != 1:
                continue
            if cat == "routeDropped" and f.get("drop_reason") != 2:
                continue
            start, end = f["start_s"], f.get("end_s", 0)
            if any_s is not None and any_e is not None and not (start <= any_e / 1000 and (end == 0 or end >= any_s / 1000)):
                continue
            if term_s is not None and term_e is not None and not (end != 0 and term_s / 1000 <= end <= term_e / 1000):
                continue
            matched.append(f)

        def bucket(fs: list[dict[str, Any]]) -> dict[str, int]:
            return {"total_flows": len(fs), "stale_flows": 0, "inconsistent_flows": 0, "flows_with_issues": sum(1 for f in fs if f.get("drop_reason")),
                    "flows_optimized": sum(1 for f in fs if f.get("optimization")), "flows_with_ignores": 0, "flows_passthrough": 0,
                    "flows_management": 0, "flows_asymmetric": 0, "flows_route_dropped": sum(1 for f in fs if f.get("drop_reason") == 2),
                    "flows_firewall_dropped": sum(1 for f in fs if f.get("drop_reason") == 1)}
        active = bucket([f for f in allf if f.get("end_s", 0) == 0])
        inactive = bucket([f for f in allf if f.get("end_s", 0) != 0])
        rows = [flow_row(f) for f in matched[:MAX_ROWS]]
        return {"total_flows": len(allf), "matched_flows": len(matched), "now": int(now), "returned_flows": len(rows), "stale_flows": 0,
                "inconsistent_flows": 0, "flows_with_issues": sum(1 for f in allf if f.get("drop_reason")), "flows_optimized": 0,
                "flows_with_ignores": 0, "flows_passthrough": 0, "flows_management": 0, "active": active, "inactive": inactive,
                "ret_code": 0, "err_msg": "", "flows": rows}

    @staticmethod
    def _window(q: dict[str, str]) -> tuple[int, int, int]:
        for k in ("startTime", "endTime"):
            if not (q.get(k) or "").isdigit():
                raise ApiError(400, {"error": f"{k} must be epoch seconds"})
        if q.get("granularity") not in ("minute", "hour", "day"):
            raise ApiError(400, {"error": "granularity must be minute, hour or day"})
        step = {"minute": 60, "hour": 3600, "day": 86400}[q["granularity"]]
        s, e = int(q["startTime"]), int(q["endTime"])
        if e < s:
            raise ApiError(400, {"error": "endTime before startTime"})
        return s, e, step

    def _ts_interface(self, app: OrchApp, ne: str, q: dict[str, str]) -> dict[str, Any]:
        s, e, step = self._window(q)
        limit = min(int(q["limit"]), MAX_ROWS) if (q.get("limit") or "").isdigit() else MAX_ROWS
        rows = []
        names = [n for n in ("wan0", "lan0") if not q.get("interfaceName") or q["interfaceName"] == n]
        t = s - s % step
        while t <= e and len(rows) < limit:
            for n in names:
                rx, tx = app.state.load_at(ne, n, t + step / 2) if n == "wan0" else (3_000_000, 1_000_000)
                vals = {"time": t, "interface": n, "rx_bytes": rx * step // 8, "tx_bytes": tx * step // 8}
                rows.append([vals.get(c) for c in app.interface_columns])
            t += step
        return {"COLUMN_DEF": list(app.interface_columns), "DATA": {ne: rows}}

    def _ts_class(self, app: OrchApp, ne: str, q: dict[str, str]) -> dict[str, Any]:
        s, e, step = self._window(q)
        if not (q.get("trafficClass") or "").isdigit() or not 1 <= int(q["trafficClass"]) <= 10:
            raise ApiError(400, {"error": "trafficClass must be 1-10"})
        klass = int(q["trafficClass"])
        drops = app.state.class_drops.get((ne, klass), 0)
        rows = []
        t = s - s % step
        while t <= e and len(rows) < MAX_ROWS:
            rows.append([t, 5_000_000 * step // 8 if drops else 1_000_000 * step // 8, 800_000, drops if drops else 0])
            t += step
        return {"COLUMN_DEF": list(TRAFFIC_CLASS_COLUMNS), "DATA": {ne: rows}}

    def _alarms(self, app: OrchApp, q: dict[str, str]) -> list[dict[str, Any]]:
        doc, ok = self.read_json(64 * 1024)
        if not ok:
            raise ApiError(400, {"error": "bad body"})
        ids = doc.get("nePks") if isinstance(doc, dict) else None
        ids = ids if ids is not None else (doc.get("ids") if isinstance(doc, dict) else None)
        if not isinstance(ids, list):
            raise ApiError(400, {"error": "nePks required"})
        view = q.get("view", "all")
        if view not in ("active", "closed", "all"):
            raise ApiError(400, {"error": "view must be active, closed or all"})
        out = []
        for ne in ids:
            self._ne(app.state, ne)
            for a in app.state.alarms[ne]:
                if view == "active" and a["closed"] or view == "closed" and not a["closed"]:
                    continue
                if q.get("severity") and a["severity"] != q["severity"]:
                    continue
                if q.get("from") and a["timeOccurredInMills"] < int(q["from"]):
                    continue
                if q.get("to") and a["timeOccurredInMills"] > int(q["to"]):
                    continue
                out.append(dict(a))
        rank = {"critical": 0, "major": 1, "minor": 2, "warning": 3}
        if _bool(q.get("orderBySeverity")):
            out.sort(key=lambda a: rank.get(a["severity"], 9))
        if (q.get("maxAlarms") or "").isdigit():
            out = out[: int(q["maxAlarms"])]
        return out

    # ---- test-only control -----------------------------------------------------------------------------------
    def _control(self, method: str, path: str) -> None:
        if not self.client_is_loopback():
            self.send_err(403, "forbidden", "loopback only")
            return
        app: OrchApp = self.app
        sub = path[len("/_fake/"):]
        if method == "GET" and sub == "log":
            with app.lock:
                self.send_json(200, {"calls": list(app.log)})
            return
        if method != "POST":
            self.send_err(404, "not_found", "no such control")
            return
        doc, ok = self.read_json(64 * 1024) if self.content_length() else ({}, True)
        if not ok:
            return
        try:
            if sub == "scenario":
                self.send_json(200, app.state.load_scenario(str(doc["name"]), at=float(doc.get("at", app.now())),
                                                            client_ip=doc.get("client_ip", "10.60.14.77"), ne_pk=doc.get("ne_pk", "1.NE")))
            elif sub == "reset":
                app.state.reset()
                with app.lock:
                    app.log.clear()
                self.send_json(200, {"ok": True})
            elif sub == "force":
                app.set_force(doc.get("status"), doc.get("count"))
                self.send_json(200, {"ok": True})
            elif sub == "wan_load":
                app.state.set_wan_load(doc.get("ne_pk", "1.NE"), doc.get("ifname", "wan0"), int(doc["rx_bps"]), int(doc["tx_bps"]), doc.get("t_from"))
                self.send_json(200, {"util_pct": app.state.wan_util_pct(doc.get("ne_pk", "1.NE"), doc.get("ifname", "wan0"))})
            elif sub == "login_fail":
                app.login_fail = bool(doc.get("on", True))
                self.send_json(200, {"ok": True})
            else:
                self.send_err(404, "not_found", "no such control")
        except (KeyError, TypeError, ValueError) as exc:
            self.send_err(400, "invalid_request", str(exc)[:200])


class FakeOrchestrator(fc.FakeServer):
    @property
    def state(self) -> OrchState:
        return self.app.state

    @property
    def api_key(self) -> str:
        return sorted(self.app.api_keys)[0]

    @property
    def user(self) -> tuple[str, str]:
        u = sorted(self.app.users)[0]
        return u, self.app.users[u]


def default_credentials() -> tuple[str, str, str]:
    """(api_key, user, password): deterministic, derived at runtime (never literal secrets in the repo)."""
    d = hashlib.sha256(b"fixture:orchestrator").hexdigest()
    return d[:32], "exp-fake-user", d[32:56]


def start(*, host: str = "127.0.0.1", port: int = 0, tls: tuple[Path, Path] | None = None, now_fn: Any = time.time,
          release: str = RELEASE, api_keys: set[str] | None = None, users: dict[str, str] | None = None) -> FakeOrchestrator:
    key, user, pw = default_credentials()
    app = OrchApp(api_keys=api_keys if api_keys is not None else {key}, users=users if users is not None else {user: pw}, now_fn=now_fn,
                  release=release)
    srv = FakeOrchestrator(Handler, app, host=host, port=port, tls=tls, name="fake-orchestrator")
    srv.start()
    return srv


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--listen", default="127.0.0.1:8486")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--scenario", choices=SCENARIOS)
    ap.add_argument("--release", default=RELEASE)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, stream=sys.stderr)
    host, _, port = args.listen.rpartition(":")
    tls = (Path(args.cert), Path(args.key)) if args.cert and args.key else None
    key, user, pw = default_credentials()
    app = OrchApp(api_keys={key}, users={user: pw}, release=args.release)
    if args.scenario:
        app.state.load_scenario(args.scenario, at=time.time())
    srv = FakeOrchestrator(Handler, app, host=host or "127.0.0.1", port=int(port), tls=tls, name="fake-orchestrator")
    fc.run_forever(srv, lambda: f"fake-orchestrator on {srv.base_url}{PREFIX} api_key={key} user={user} password={pw} scenario={args.scenario}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

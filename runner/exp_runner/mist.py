"""Juniper Mist connector: identity by client IP (wireless + wired) and the ``wifi`` / ``wired`` evidence (12 sections 5.1 and 5.2).

**Vendor field names come only from the Mist OpenAPI 3.1 document bundled in the official ``mistapi`` 0.64.1 SDK (MIT, a dev-time
reference, never imported)**; every field used below names its OAS schema:

=========================================================  =====================================================================
call                                                       OAS operationId / schema
=========================================================  =====================================================================
GET /sites/{site_id}/clients/search?ip&start&end           searchSiteWirelessClients / client_wireless (``ap``, ``last_ap``,
                                                           ``last_ssid``, ``band``, ``mfg``, ``last_hostname``, ``last_os``,
                                                           ``last_username``, ``last_vlan``, ``site_id``, ``mac``)
GET /sites/{site_id}/wired_clients/search?ip&start&end     searchSiteWiredClients / wired_client_response (``device_mac``,
                                                           ``port_id``, ``vlan``, ``auth_*``, ``dhcp_*``, ``mac``)
GET /sites/{site_id}/stats/clients/{client_mac}            getSiteWirelessClientStats / stats_wireless_client
GET /sites/{site_id}/stats/devices/{device_id}             getSiteDeviceStats / stats_ap (+ ap_radio_stat in ``radio_stat``)
GET /sites/{site_id}/clients/{client_mac}/events?start&end getSiteEventsForClient / response_client_events_search
                                                           (``results``: events_client; ``client_mac`` = 12 lower-case hex, as
                                                           mistapi's clients.py puts it in the path unchanged)
GET /const/client_events                                   listClientEventsDefinitions (``key`` / ``display``)
GET /sites/{site_id}/stats/ports/search?mac&port_id        searchSiteSwOrGwPorts / stats_switch_port
GET /sites/{site_id}/devices/events/search?mac&start&end   searchSiteDeviceEvents / device_event (best effort)
=========================================================  =====================================================================

Honest limits (never presented as vendor fact):

* ``events_client`` has no client-MAC property and the AP-level ``searchSiteWirelessClientEvents`` has no MAC filter, so that
  endpoint is **never used**: any client's roam or auth failure on the same AP would be attributed to this test. The client's own
  events come from ``getSiteEventsForClient`` (MAC in the path) in the test window: ``roams`` / ``roam_count`` / ``auth_failures`` /
  ``events`` are derived from that single call only. Event type keys are *discovered* from ``GET /const/client_events`` at runtime
  (never hard-coded) and classified by their key / display text. One page (``limit`` 100) is read, never followed.
* ``stats_wireless_client`` is the client's *current* state (the runner reads it after the correlation window closed); when the
  client is gone (404) the ``wifi`` evidence falls back to the search record and is ``partial``.
* Mist zones (``stats_wireless_client.zones``) are map zones, not exp zones: the exp zone comes from ``sources.mist.zone_map``
  (``identity.map_zone``), then the subnet fallback.

Budget (12 5.2): at most ``max_calls_per_test`` (default 6) calls per test, retries included; AP and port documents are cached
``cache_ttl_s`` (30 s) so neighbouring tests share them; the event-type constants are reference data refreshed hourly outside the
per-test budget. ``429`` pauses the whole connector (``upstream``). The token is only ever sent as ``Authorization: Token <apitoken>``
(OAS securityScheme ``apiToken``) and is never logged.
"""
from __future__ import annotations

import dataclasses
import logging
import re
import threading
import time
from collections.abc import Callable
from typing import Any

from . import upstream as up
from .config import RunnerConfig
from .connectors import CallBudget, ClientCandidate, ClientLookup, Connector, Context, EvidenceResult, IdentityProvider, Window
from .upstream import Scope, Ttl, UpstreamClient, UpstreamError

log = logging.getLogger(__name__)

LOOKUP_DEADLINE_S = 30.0
CONNECTOR_TIMEOUT_S = 60.0
COLLECT_DEADLINE_S = 50.0
SEARCH_LIMIT = 5
EVENTS_LIMIT = 100
MAX_EVENTS = 100
MAX_ROAMS = 50
FOUND_KEEP = 256
FOUND_TTL_S = 180.0
CONST_TTL_S = 3600.0
BANDS = frozenset({"24", "5", "5-dedicated", "5-selectable", "6", "6-dedicated", "6-selectable"})
PROTOS = frozenset({"a", "ac", "ax", "b", "be", "g", "n"})
_ID = re.compile(r"[0-9A-Za-z_\-]{1,64}\Z")
_MAC12 = re.compile(r"[0-9a-f]{12}\Z")
_AUTH_FAIL = re.compile(r"auth.*(fail|den|reject|timeout)|(fail|den|reject|timeout).*auth", re.I)
_ROAM = re.compile(r"roam|11r|\bfbt\b|_fbt_|fast.?bss|fast.?transition|handoff|reassoc", re.I)
_FAILWORD = re.compile(r"fail|den(y|ied)|reject|timeout|error", re.I)


def _mac12(v: Any) -> str | None:
    if not isinstance(v, str):
        return None
    h = re.sub(r"[:.\-]", "", v.strip().lower())
    return h if _MAC12.match(h) else None


def _colon(v: Any) -> str | None:
    h = _mac12(v)
    return None if h is None else ":".join(h[k:k + 2] for k in range(0, 12, 2))


def _first(v: Any) -> Any:
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return list(v) if isinstance(v, list) else [v]


def classify_event(key: str, display: str, text: str) -> str | None:
    """``auth_fail`` | ``roam`` | ``roam_fail`` | None, from Mist's runtime event constants (key + display) and the event text."""
    blob = f"{key} {display} {text}"
    if _AUTH_FAIL.search(blob):
        return "auth_fail"
    if _ROAM.search(f"{key} {display}"):
        return "roam_fail" if _FAILWORD.search(f"{key} {display}") else "roam"
    return None


@dataclasses.dataclass
class Found:
    kind: str                           # wireless | wired
    site_id: str
    mac12: str
    rec: dict[str, Any]
    at: float
    stats: dict[str, Any] | None = None
    ap: dict[str, Any] | None = None
    errors: list[str] = dataclasses.field(default_factory=list)
    enriched: bool = False


class MistService(IdentityProvider):
    """Shared by the identity step (``lookup_client``) and the connector (``MistConnector``)."""

    def __init__(self, cfg: dict[str, Any], creds: dict[str, str], *, clock: Callable[[], float] = time.time,
                 client: UpstreamClient | None = None, ca_file: str | None = None) -> None:
        self.cfg = cfg
        self.clock = clock
        self.sites = [str(s["site_id"]) for s in (cfg.get("sites") or []) if isinstance(s, dict) and _ID.match(str(s.get("site_id", "")))]
        self.max_calls = int(cfg.get("max_calls_per_test", 6))
        ttl = float(cfg.get("cache_ttl_s", 30))
        base = creds["api_base"].rstrip("/")
        if not base.endswith("/api/v1"):
            base += "/api/v1"
        self.client = client or UpstreamClient("mist", base, {"Authorization": f"Token {creds['token']}"}, ca_file=ca_file)
        self._lookups = Ttl(ttl, clock)
        self._aps = Ttl(ttl, clock)
        self._ports = Ttl(ttl, clock)
        self._found = Ttl(FOUND_TTL_S, clock, FOUND_KEEP)
        self._ttl = max(1.0, ttl)
        self._const: dict[str, str] | None = None
        self._const_at = 0.0
        self._const_lock = threading.Lock()

    def scope(self, budget: CallBudget, seconds: float) -> Scope:
        return Scope(budget, self.client._clock() + seconds)

    # ------------------------------------------------------------------------------------------ primitive reads
    def _results(self, path: str, params: dict[str, Any], sc: Scope) -> list[dict[str, Any]]:
        doc = self.client.get(path, params, budget=sc.budget, deadline=sc.deadline)
        res = doc.get("results") if isinstance(doc, dict) else doc
        if not isinstance(res, list):
            raise UpstreamError("bad_response", "mist: unexpected search response")
        return [r for r in res if isinstance(r, dict)]

    @staticmethod
    def _win(window: Window) -> dict[str, int]:
        return {"start": int(window.from_ts), "end": int(window.to_ts) + 1}

    def search(self, kind: str, site: str, ip: str, window: Window, sc: Scope) -> list[dict[str, Any]]:
        leaf = "clients/search" if kind == "wireless" else "wired_clients/search"
        return self._results(f"/sites/{site}/{leaf}", {"ip": ip, **self._win(window), "limit": SEARCH_LIMIT}, sc)

    def client_stats(self, site: str, mac12: str, sc: Scope) -> dict[str, Any] | None:
        try:
            doc = self.client.get(f"/sites/{site}/stats/clients/{mac12}", budget=sc.budget, deadline=sc.deadline)
        except UpstreamError as exc:
            if exc.kind == "not_found":
                return None
            raise
        return doc if isinstance(doc, dict) else None

    def ap_stats(self, site: str, ap_id: str, sc: Scope) -> dict[str, Any] | None:
        if not _ID.match(ap_id):
            return None
        key = (site, ap_id)
        hit = self._aps.get(key)
        if hit is not None:
            return hit
        try:
            doc = self.client.get(f"/sites/{site}/stats/devices/{ap_id}", budget=sc.budget, deadline=sc.deadline)
        except UpstreamError as exc:
            if exc.kind == "not_found":
                return None
            raise
        if isinstance(doc, dict):
            self._aps.put(key, doc)
            return doc
        return None

    def port_stats(self, site: str, switch12: str, port_id: str, sc: Scope) -> dict[str, Any] | None:
        key = (site, switch12, port_id)
        hit = self._ports.get(key)
        if hit is not None:
            return hit
        rows = self._results(f"/sites/{site}/stats/ports/search", {"mac": switch12, "port_id": port_id, "limit": 10}, sc)
        for r in rows:
            if str(r.get("port_id")) == port_id and _mac12(r.get("mac")) in (switch12, None):
                self._ports.put(key, r)
                return r
        return None

    def event_types(self) -> dict[str, str]:
        """``{key: display}`` discovered from the constants (cached; refreshed hourly; its own tiny budget, not the per-test one)."""
        with self._const_lock:
            if self._const is not None and self.clock() - self._const_at < CONST_TTL_S:
                return self._const
        try:
            doc = self.client.get("/const/client_events", budget=CallBudget(1), deadline=self.client._clock() + 10)
        except UpstreamError as exc:
            log.warning("mist: event constants unavailable (%s)", exc.kind)
            return self._const or {}
        out: dict[str, str] = {}
        for it in doc if isinstance(doc, list) else []:
            if isinstance(it, dict) and isinstance(it.get("key"), str):
                out[it["key"][:128]] = str(it.get("display") or "")[:128]
        with self._const_lock:
            self._const, self._const_at = out, self.clock()
        return out

    # -------------------------------------------------------------------------------------------- identity step
    def lookup_client(self, ip: str, window: Window, budget: CallBudget) -> ClientLookup:
        if not self.sites:
            return ClientLookup("unavailable")
        key = (ip, int(window.from_ts // self._ttl), int(window.to_ts // self._ttl))
        hit = self._lookups.get(key)
        if hit is not None:
            return hit
        sc = self.scope(budget, LOOKUP_DEADLINE_S)
        hits: dict[str, tuple[str, str, dict[str, Any]]] = {}
        try:
            for site in self.sites:
                for kind in ("wireless", "wired"):
                    for rec in self.search(kind, site, ip, window, sc):
                        mac = _mac12(rec.get("mac"))
                        if mac:
                            hits.setdefault(mac, (kind, site, rec))
                if hits:
                    break
        except UpstreamError as exc:
            log.warning("mist identity lookup failed (%s)", exc.kind)
            return ClientLookup("error")
        cands = []
        for mac, (kind, site, rec) in hits.items():
            cands.append(self._candidate(kind, site, mac, rec))
        if len(cands) == 1:
            kind, site, rec = next(iter(hits.values()))
            found = Found(kind, site, next(iter(hits)), rec, self.clock())
            if kind == "wireless":
                self.enrich(found, sc, cands[0])
            self._found.put((ip, found.mac12), found)
        out = ClientLookup("ok", cands)
        self._lookups.put(key, out)
        return out

    def _candidate(self, kind: str, site: str, mac12: str, rec: dict[str, Any]) -> ClientCandidate:
        mac = _colon(mac12) or mac12
        if kind == "wired":
            sw = _colon(_first(rec.get("device_mac")))
            vlan = up.i(_first(rec.get("vlan")))
            return ClientCandidate(mac=mac, hostname=up.s(rec.get("dhcp_hostname")), wired=True, site_id=up.s(site), switch_mac=sw,
                                   switch_port=up.s(_first(rec.get("port_id"))), vlan=vlan, ref=f"mist:wired:{mac12}")
        band = up.s(rec.get("band"), 16)
        aps = tuple(m for m in (_colon(a) for a in _as_list(rec.get("ap"))) if m)[:8]
        last_ap = _colon(rec.get("last_ap")) or (aps[-1] if aps else None)
        return ClientCandidate(
            mac=mac, hostname=up.s(rec.get("last_hostname") or _first(rec.get("hostname"))),
            username=up.s(rec.get("last_username") or _first(rec.get("username"))), manufacture=up.s(rec.get("mfg")),
            os_family=up.s(rec.get("last_os") or _first(rec.get("os"))), wired=False, site_id=up.s(site), ap_mac=last_ap,
            ssid=up.s(rec.get("last_ssid") or _first(rec.get("ssid"))), band=band if band in BANDS else None,
            vlan=up.i(rec.get("last_vlan") if rec.get("last_vlan") is not None else _first(rec.get("vlan"))),
            ref=f"mist:client:{mac12}", ap_macs=aps)

    def enrich(self, found: Found, sc: Scope, cand: ClientCandidate | None = None) -> None:
        """Client stats + the AP document (the AP name feeds the zone map; the evidence step reuses both). Idempotent."""
        if not found.enriched:
            found.enriched = True
            try:
                found.stats = self.client_stats(found.site_id, found.mac12, sc)
                ap_id = up.s((found.stats or {}).get("ap_id"))
                if ap_id:
                    found.ap = self.ap_stats(found.site_id, ap_id, sc)
            except UpstreamError as exc:
                found.errors.append(exc.kind)
                log.debug("mist enrich: %s", exc.kind)
        if cand is not None and found.ap:
            cand.ap_name = up.s(found.ap.get("name"))

    def recall(self, ip: str, mac: str | None) -> Found | None:
        m = _mac12(mac)
        return self._found.get((ip, m)) if m else None


# ------------------------------------------------------------------------------------------------ connector
class MistConnector(Connector):
    name = "mist"
    kinds = ("wifi", "wired")
    timeout_s = CONNECTOR_TIMEOUT_S

    def __init__(self, svc: MistService, cfg: RunnerConfig | None = None) -> None:
        self.svc = svc

    def collect(self, ctx: Context) -> list[EvidenceResult]:
        ident = ctx.identity
        if ident.resolved_by != "mist" or not ident.mac:
            st = "error" if ident.mist_status == "error" else "unavailable"
            return [EvidenceResult("wifi", "mist", st), EvidenceResult("wired", "mist", st)]
        budget = ctx.budget("mist", self.svc.max_calls)
        sc = self.svc.scope(budget, COLLECT_DEADLINE_S)
        found = self.svc.recall(ident.ip, ident.mac)
        if found is None:      # the memo expired between the identity step and now: look again (counts against the budget)
            look = self.svc.lookup_client(ident.ip, ctx.window, budget)
            found = self.svc.recall(ident.ip, ident.mac) if look.status == "ok" and len(look.candidates) == 1 else None
        if found is None:
            return [EvidenceResult("wifi", "mist", "error"), EvidenceResult("wired", "mist", "error")]
        if found.kind == "wired":
            return [EvidenceResult("wifi", "mist", "unavailable"), self._wired(found, ctx, sc)]
        return [self._wifi(found, ctx, sc), EvidenceResult("wired", "mist", "unavailable")]

    # ------------------------------------------------------------------------------------------------- wifi
    def _wifi(self, found: Found, ctx: Context, sc: Scope) -> EvidenceResult:
        svc = self.svc
        svc.enrich(found, sc)
        errors = list(found.errors)
        refs = [f"mist:client:{found.mac12}"]
        stats = found.stats
        client = self._wifi_client(found)
        ap = self._wifi_ap(found.ap, client.get("band")) if found.ap else {}
        data: dict[str, Any] = {"client": client}
        if ap:
            data["ap"] = ap
            refs.append(f"mist:ap:{ap.get('mac', '')}")
        roams: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []
        ev_ok = True
        try:
            roams, events = self._events(found, ctx, sc)
        except UpstreamError as exc:
            ev_ok = False
            errors.append(exc.kind)
        data["roams"] = roams[:MAX_ROAMS]
        data["events"] = events[:MAX_EVENTS]
        data["roam_count"] = sum(1 for r in roams if r.get("type") != "none")
        data["auth_failures"] = sum(1 for e in events if e.get("_cls") == "auth_fail")
        for e in data["events"]:
            e.pop("_cls", None)
        complete = stats is not None and found.ap is not None and ev_ok and not errors
        if not client and not ap:
            return EvidenceResult("wifi", "mist", "error" if errors else "unavailable")
        return EvidenceResult("wifi", "mist", "ok" if complete else "partial", data, refs[:20])

    @staticmethod
    def _wifi_client(found: Found) -> dict[str, Any]:
        rec, st = found.rec, found.stats or {}
        c: dict[str, Any] = {}
        up.put(c, "mac", _colon(found.mac12))
        # stats_wireless_client.* (current state); fall back to client_wireless.* (search record) where the stats are missing
        ap_mac = _colon(st.get("ap_mac")) or _colon(rec.get("last_ap"))
        up.put(c, "ap_mac", ap_mac)
        up.put(c, "ap_id", up.s(st.get("ap_id")))
        up.put(c, "bssid", up.s(st.get("bssid"), 17))
        up.put(c, "ssid", up.s(st.get("ssid") or rec.get("last_ssid")))
        band = up.s(st.get("band") or rec.get("band"), 16)
        if band in BANDS:
            c["band"] = band
        up.put(c, "channel", up.i(st.get("channel")))
        proto = up.s(st.get("proto") or rec.get("protocol"), 8)
        if proto in PROTOS:
            c["proto"] = proto
        for out, key, conv in (("rssi", "rssi", up.f), ("snr", "snr", up.f), ("tx_rate_mbps", "tx_rate", up.f), ("rx_rate_mbps", "rx_rate", up.f),
                               ("tx_retries", "tx_retries", up.i), ("rx_retries", "rx_retries", up.i), ("tx_pkts", "tx_pkts", up.i),
                               ("rx_pkts", "rx_pkts", up.i), ("tx_bps", "tx_bps", up.i), ("rx_bps", "rx_bps", up.i),
                               ("idle_time_s", "idle_time", up.f), ("uptime_s", "uptime", up.f), ("last_seen", "last_seen", up.f)):
            up.put(c, out, conv(st.get(key)))
        for out, key in (("power_saving", "power_saving"), ("dual_band", "dual_band")):
            up.put(c, out, up.b(st.get(key)))
        for out, key, n in (("key_mgmt", "key_mgmt", 64), ("vlan_id", "vlan_id", 16), ("wlan_id", "wlan_id", 64),
                            ("manufacture", "manufacture", 64), ("family", "family", 64), ("os", "os", 64), ("model", "model", 64)):
            up.put(c, out, up.s(st.get(key), n))
        if "manufacture" not in c:
            up.put(c, "manufacture", up.s(rec.get("mfg")))
        tx, pk = c.get("tx_retries"), c.get("tx_pkts")
        if isinstance(tx, int) and isinstance(pk, int) and pk > 0:
            c["retry_pct"] = round(min(100.0, tx / pk * 100.0), 2)
        return c

    @staticmethod
    def _wifi_ap(doc: dict[str, Any], band: Any) -> dict[str, Any]:
        a: dict[str, Any] = {}
        up.put(a, "mac", _colon(doc.get("mac")))
        up.put(a, "ap_name", up.s(doc.get("name")))
        for out, key in (("model", "model"), ("version", "version"), ("status", "status")):
            up.put(a, out, up.s(doc.get(key)))
        up.put(a, "num_clients", up.i(doc.get("num_clients")))
        up.put(a, "uptime_s", up.f(doc.get("uptime")))
        up.put(a, "cpu_util", up.i(doc.get("cpu_util")))
        up.put(a, "power_constrained", up.b(doc.get("power_constrained")))
        key = {"2": "band_24", "5": "band_5", "6": "band_6"}.get(str(band)[:1]) if band else None
        radios = doc.get("radio_stat") if isinstance(doc.get("radio_stat"), dict) else {}
        r = radios.get(key) if key else None
        if isinstance(r, dict):
            radio: dict[str, Any] = {"band": key[5:]}
            for out, k in (("channel", "channel"), ("bandwidth_mhz", "bandwidth"), ("power_dbm", "power"), ("noise_floor_dbm", "noise_floor"),
                           ("num_clients", "num_clients"), ("util_all", "util_all"), ("util_tx", "util_tx"), ("util_rx_in_bss", "util_rx_in_bss"),
                           ("util_rx_other_bss", "util_rx_other_bss"), ("util_non_wifi", "util_non_wifi"),
                           ("util_unknown_wifi", "util_unknown_wifi"), ("util_undecodable_wifi", "util_undecodable_wifi")):
                up.put(radio, out, up.i(r.get(k)))
            a["radio"] = radio
        return a

    def _events(self, found: Found, ctx: Context, sc: Scope) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """This client's roam / auth-failure events: getSiteEventsForClient (``client_mac`` path parameter; response_client_events_search)."""
        svc = self.svc
        ssid = up.s((found.stats or {}).get("ssid") or found.rec.get("last_ssid"))
        roams: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        rows = svc._results(f"/sites/{found.site_id}/clients/{found.mac12}/events", {**svc._win(ctx.window), "limit": EVENTS_LIMIT}, sc)
        types = svc.event_types() if rows else {}
        for r in rows:
            ts = up.f(r.get("timestamp"))
            typ = up.s(r.get("type"), 128)
            if ts is None or typ is None:
                continue
            if ssid and up.s(r.get("ssid")) not in (None, ssid):
                continue
            cls = classify_event(typ, types.get(typ, ""), str(r.get("text") or ""))
            if cls is None:
                continue
            sig = (ts, typ, r.get("ap"), r.get("bssid"))
            if sig in seen:
                continue
            seen.add(sig)
            e: dict[str, Any] = {"timestamp": ts, "type": typ, "_cls": cls}
            up.put(e, "type_code", up.i(r.get("type_code")))
            up.put(e, "text", up.s(r.get("text"), 256))
            up.put(e, "ssid", up.s(r.get("ssid")))
            up.put(e, "bssid", up.s(r.get("bssid"), 17))
            up.put(e, "ap_mac", _colon(r.get("ap")))
            up.put(e, "band", up.s(r.get("band"), 16))
            up.put(e, "channel", up.i(r.get("channel")))
            up.put(e, "proto", up.s(r.get("proto"), 16))
            up.put(e, "wlan_id", up.s(r.get("wlan_id"), 64))
            events.append(e)
            if cls in ("roam", "roam_fail"):
                ro: dict[str, Any] = {"timestamp": ts, "type": "fail" if cls == "roam_fail" else "success"}
                up.put(ro, "ap_mac", _colon(r.get("ap")))
                up.put(ro, "ssid", up.s(r.get("ssid")))
                roams.append(ro)
        events.sort(key=lambda x: x["timestamp"])
        roams.sort(key=lambda x: x["timestamp"])
        return roams, events

    # ------------------------------------------------------------------------------------------------- wired
    def _wired(self, found: Found, ctx: Context, sc: Scope) -> EvidenceResult:
        svc = self.svc
        rec = found.rec
        client: dict[str, Any] = {}
        up.put(client, "mac", _colon(found.mac12))
        conv = {"ip": lambda v: up.s(v, 45), "vlan": up.i, "port_id": up.s, "device_mac": _colon}
        for key, fn in conv.items():
            vals = [x for x in (fn(v) for v in _as_list(rec.get(key))[:8]) if x is not None]
            if vals:
                client[key] = vals
        for out, key in (("auth_method", "auth_method"), ("auth_state", "auth_state"), ("dhcp_hostname", "dhcp_hostname"),
                         ("dhcp_fqdn", "dhcp_fqdn"), ("dhcp_vendor_class_identifier", "dhcp_vendor_class_identifier")):
            up.put(client, out, up.s(rec.get(key)))
        up.put(client, "timestamp", up.f(rec.get("timestamp")))
        data: dict[str, Any] = {"client": client}
        refs = [f"mist:wired:{found.mac12}"]
        errors: list[str] = []
        sw12 = _mac12(_first(rec.get("device_mac")))
        port_id = up.s(_first(rec.get("port_id")))
        port: dict[str, Any] | None = None
        if sw12 and port_id:
            try:
                port = svc.port_stats(found.site_id, sw12, port_id, sc)
            except UpstreamError as exc:
                errors.append(exc.kind)
        if port:
            data["port"] = self._port(port, sw12 or "")
            refs.append(f"mist:port:{sw12}:{port_id}")
            try:
                events = self._port_events(found.site_id, sw12 or "", port_id, ctx, sc)
            except UpstreamError as exc:
                if exc.kind not in ("not_found", "budget", "deadline"):
                    errors.append(exc.kind)
                events = []
            if events:
                data["events"] = events
        elif sw12 and port_id and not errors:
            errors.append("port_not_found")
        status = "ok" if "port" in data and not errors else "partial"
        return EvidenceResult("wired", "mist", status, data, refs[:20])

    @staticmethod
    def _port(p: dict[str, Any], switch12: str) -> dict[str, Any]:
        o: dict[str, Any] = {}
        up.put(o, "switch_mac", _colon(p.get("mac")) or _colon(switch12))
        up.put(o, "port_id", up.s(p.get("port_id")))
        for out, key in (("up", "up"), ("disabled", "disabled"), ("full_duplex", "full_duplex"), ("poe_on", "poe_on"), ("uplink", "uplink")):
            up.put(o, out, up.b(p.get(key)))
        for out, key in (("speed_mbps", "speed"), ("rx_errors", "rx_errors"), ("tx_errors", "tx_errors"), ("rx_bps", "rx_bps"),
                         ("tx_bps", "tx_bps"), ("rx_pkts", "rx_pkts"), ("tx_pkts", "tx_pkts"), ("mac_count", "mac_count")):
            up.put(o, out, up.i(p.get(key)))
        up.put(o, "last_flapped", up.f(p.get("last_flapped")))
        up.put(o, "power_draw_w", up.f(p.get("power_draw")))
        for out, key in (("stp_state", "stp_state"), ("stp_role", "stp_role"), ("poe_mode", "poe_mode"), ("auth_state", "auth_state"),
                         ("port_usage", "port_usage"), ("neighbor_system_name", "neighbor_system_name")):
            up.put(o, out, up.s(p.get(key)))
        return o

    def _port_events(self, site: str, switch12: str, port_id: str, ctx: Context, sc: Scope) -> list[dict[str, Any]]:
        svc = self.svc
        rows = svc._results(f"/sites/{site}/devices/events/search", {"mac": switch12, **svc._win(ctx.window), "limit": 50}, sc)
        out = []
        for r in rows:
            if up.s(r.get("port_id")) != port_id:
                continue
            ts, typ = up.f(r.get("timestamp")), up.s(r.get("type"), 128)
            if ts is None or typ is None:
                continue
            e: dict[str, Any] = {"timestamp": ts, "type": typ}
            for k, n in (("text", 256), ("port_id", 64), ("device_name", 64), ("reason", 128)):
                up.put(e, k, up.s(r.get(k), n))
            out.append(e)
        out.sort(key=lambda x: x["timestamp"])
        return out[:50]


def make_mist(cfg: RunnerConfig, creds: dict[str, str] | None, **kw: Any) -> tuple[MistConnector, MistService] | None:
    """The Mist connector pair, or None when Mist is not configured / has no credentials."""
    if cfg.mist is None or not creds:
        return None
    try:
        svc = MistService(cfg.mist, creds, **kw)
    except ValueError as exc:
        log.error("mist connector disabled: %s", exc)
        return None
    return MistConnector(svc, cfg), svc


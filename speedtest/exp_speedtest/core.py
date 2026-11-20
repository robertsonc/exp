"""The speedtest brain: sessions, limits, byte budgets, results, the user-safe view. No sockets here: the HTTP layers
(``routes``, ``channel``) translate requests into calls on :class:`Core`, which makes every rule testable with an injected
clock and fakes.

Contracts: shared/openapi/speedtest.yaml, 01-contracts.md sections 14.2-14.4, CR-m6-spec-resolutions.
"""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Any

from exp_common import config as exp_config
from exp_common import speedtest as st
from exp_common.schema import iso_to_ms

from .config import Paths, SpeedtestConfig
from .dnsleg import NonceBook
from .errors import ApiError, bad_request, not_found, too_many
from .forward import CollectorClient, Forwarder
from .guard import CoreGuard, ThroughputMeter
from .limits import SlidingWindow, TokenBucket
from .path import PathTimer
from .slots import InternetLeg
from .store import SpoolFull, Store
from .tokens import LegTokens
from .ua import parse_ua
from .whereis import Where, ZoneResolver

log = logging.getLogger(__name__)

MAX_PER_REQUEST = 100_000_000          # openapi: bytes <= 100 MB per request
MAX_PINGS_PER_SESSION = 5000
MAX_SESSIONS_IN_MEMORY = 20_000
VIEW_CACHE_S = 1.0
COMMENT_REPLACEMENTS = 3
TOKEN_GRACE_S = 5.0
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_ZONE = re.compile(r"(unresolved|[a-z0-9][a-z0-9-]{0,63})\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_COMMENT_BAD = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_LEG_KEYS = ("down_mbps", "up_mbps", "idle_ms", "jitter_ms", "loaded_down_ms", "loaded_up_ms", "rpm", "cv", "failures", "bytes")
_INET_FLAGS = {"unavailable": "internet_unavailable", "paused": "internet_paused", "queued": "internet_queued"}
_KINDS = frozenset({"wifi", "wired", "flows", "wan", "security", "baseline", "dns", "identity"})
USER_CAUSES = frozenset({"wifi_signal", "wifi_congestion", "wifi_roaming", "wired_port", "device_limit", "wan_saturation",
                         "internet_path", "policy_block", "qos_shaping", "dns", "network_wide", "none"})


def iso(ts: float) -> str:
    import datetime
    return (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"))


@dataclasses.dataclass
class Session:
    id: str
    created: float
    client_ip: str
    verifier: str
    nonce: bytes
    token_expires_at: int
    cap: int
    ua: dict[str, str]
    zone_hint: str | None
    where: Where
    dns_nonces: list[str]
    consent_version: int
    bytes_down: int = 0
    bytes_up: int = 0
    reserved: int = 0
    requests: int = 0
    pings: int = 0
    capped: bool = False
    first_use: float | None = None
    submitted: bool = False
    dns_submitted: dict[str, Any] | None = None

    @property
    def used(self) -> int:
        return self.bytes_down + self.bytes_up


class Core:
    def __init__(self, cfg: SpeedtestConfig, paths: Paths, store: Store, *, forwarder: Forwarder | None = None,
                 client: CollectorClient | None = None, internet: InternetLeg | None = None,
                 guard: CoreGuard | None = None, resolver: ZoneResolver | None = None, path: PathTimer | None = None,
                 nonces: NonceBook | None = None, clock: Callable[[], float] = time.time) -> None:
        self.cfg, self.paths, self.store, self.clock = cfg, paths, store, clock
        self.forwarder, self.client = forwarder, client
        self.tokens = LegTokens()
        lim = cfg.limits
        self.internet = internet or InternetLeg(enabled=cfg.internet_enabled, config_paused=cfg.internet_paused,
                                                max_concurrent=lim.max_concurrent_internet,
                                                auto_pause_pct=cfg.auto_pause_wan_util_pct, clock=clock)
        self.guard = guard or CoreGuard(cfg.core_guard.iface, cfg.core_guard.util_pct, lim.bytes_local,
                                        cfg.core_guard.min_bytes)
        self.resolver = resolver or ZoneResolver(cfg, clock)
        self.nonces = nonces or NonceBook(clock)
        self.path = path
        self.meter = ThroughputMeter(clock)
        self.dns_active = cfg.dns_enabled
        self.channel_sha256: str | None = None
        self.api_limiter = TokenBucket(rate=20.0, burst=60.0)            # general per-IP request budget (page + API)
        self.auth_fail_limiter = SlidingWindow(60, 60.0)                  # bad leg tokens per IP per minute
        self.create_limiter = SlidingWindow(lim.tests_per_10min_per_ip, 600.0)
        self._sessions: dict[str, Session] = {}
        self._by_nonce: dict[bytes, Session] = {}
        self._lock = threading.RLock()
        self._transfers = 0
        self._submit_times: deque[float] = deque(maxlen=20000)
        self._reject_times: deque[float] = deque(maxlen=20000)
        self._view_cache: dict[str, tuple[float, dict[str, Any] | None]] = {}
        self.started = clock()
        self._last_prune = 0.0

    # ============================================================================================ helpers
    def note_rejected(self) -> None:
        self._reject_times.append(self.clock())

    def is_active(self, s: Session, now: float | None = None) -> bool:
        now = self.clock() if now is None else now
        return not s.submitted and now < s.token_expires_at + TOKEN_GRACE_S

    def active_sessions(self, now: float | None = None) -> list[Session]:
        now = self.clock() if now is None else now
        with self._lock:
            return [s for s in self._sessions.values() if self.is_active(s, now)]

    @property
    def transfers_active(self) -> int:
        return self._transfers

    def _limits_doc(self, cap: int) -> dict[str, int]:
        lim = self.cfg.limits
        return {"bytes_local": cap, "bytes_internet": lim.bytes_internet, "streams_start": lim.streams_start,
                "streams_max": lim.streams_max, "ramp_min_bytes": min(lim.ramp_min_bytes, cap),
                "ramp_max_bytes": min(lim.ramp_max_bytes, cap), "ping_count": lim.ping_count,
                "leg_token_ttl_s": lim.leg_token_ttl_s, "result_deadline_s": lim.result_deadline_s}

    # ============================================================================================= config
    def public_config(self) -> dict[str, Any]:
        cfg = self.cfg
        digest = hashlib.sha256(json.dumps(cfg.raw, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:12]
        state, _reason = self.internet.state()
        logo = "/st/assets/logo" if (self.paths.assets_dir / "logo").is_file() else None
        return {"title": cfg.title, "logo": logo, "colors": dict(cfg.colors), "languages": list(cfg.languages),
                "copy": dict(cfg.copy), "consent": {"text": cfg.consent_text, "version": cfg.consent_version},
                "targets": {"down_mbps": cfg.target_down_mbps, "up_mbps": cfg.target_up_mbps},
                "dns_zone": cfg.dns_zone if self.dns_active else None,
                "internet_leg": {"enabled": cfg.internet_enabled, "paused": state == "paused", "provider": "cloudflare"},
                "show_network_details": cfg.show_network_details, "tls_mode": cfg.tls_mode, "version": f"{digest}"}

    # ============================================================================================== where
    def where(self, peer: str, hint: str | None) -> dict[str, Any]:
        return self.resolver.resolve(peer, hint).public()

    # ========================================================================================== sessions
    def create_session(self, peer: str, body: Any, user_agent: str | None) -> dict[str, Any]:
        cfg, lim = self.cfg, self.cfg.limits
        if not isinstance(body, dict) or not set(body) <= {"consent", "zone_hint", "view_verifier"}:
            raise bad_request("unknown or missing fields")
        consent = body.get("consent")
        if not isinstance(consent, dict) or set(consent) != {"text_version"} or isinstance(consent["text_version"], bool) \
                or not isinstance(consent["text_version"], int):
            raise bad_request("consent.text_version is required")
        verifier = body.get("view_verifier")
        if not isinstance(verifier, str) or not _HEX64.match(verifier):
            raise bad_request("view_verifier must be a sha256 hex string")
        hint = body.get("zone_hint")
        if hint is not None and (not isinstance(hint, str) or not _SLUG.match(hint) or hint not in cfg.zones):
            raise bad_request("unknown zone_hint", field="zone_hint")
        if consent["text_version"] != cfg.consent_version:
            raise bad_request("the consent text has changed; reload the page", code="consent_version_stale",
                              current_version=cfg.consent_version)
        now = self.clock()
        with self._lock:
            if len(self._sessions) >= MAX_SESSIONS_IN_MEMORY:
                raise ApiError(503, "busy", "too many sessions", headers={"Retry-After": "30"})
            ra = self.create_limiter.retry_after(peer, now)
            if ra > 0:
                raise too_many("tests_per_10min_per_ip", ra, "too many tests from this address")
            active = [s for s in self._sessions.values() if self.is_active(s, now)]
            mine = [s for s in active if s.client_ip == peer]
            if len(mine) >= lim.max_concurrent_per_ip:
                wait = min(s.token_expires_at + TOKEN_GRACE_S for s in mine) - now
                raise too_many("max_concurrent_per_ip", wait, "a test from this address is still running")
            if len(active) >= lim.max_concurrent_tests:
                raise too_many("max_concurrent_tests", 5.0, "the speedtest box is busy")
            sid = st.new_speedtest_id()
            expires = int(now) + lim.leg_token_ttl_s
            token, nonce = self.tokens.mint(sid, peer, expires)
            cap = self.guard.effective_cap()
            where = self.resolver.resolve(peer, hint)
            nonces = [secrets.token_hex(8) for _ in range(3)] if self.dns_active else []
            sess = Session(sid, now, peer, verifier, nonce, expires, cap, parse_ua(user_agent), hint, where, nonces,
                           cfg.consent_version)
            self.store.add_session(sid, now, verifier, hint)
            self._sessions[sid] = sess
            self._by_nonce[nonce] = sess
            self.create_limiter.record(peer, now)
        for n in nonces:
            self.nonces.register(n, sid)
        if self.path is not None:
            self.path.watch_device(sid, peer)
        leg_state, _ = self.internet.state()
        return {"session_id": sid, "leg_token": token, "leg_token_expires_in_s": lim.leg_token_ttl_s,
                "limits": self._limits_doc(cap), "dns_nonces": nonces, "dns_zone": cfg.dns_zone if self.dns_active else None,
                "internet_leg": leg_state, "queue_position": self.internet.queue_estimate() if leg_state == "queued" else None,
                "server_time": iso(now)}

    # ==================================================================================== leg endpoints
    def authorize_leg(self, token: str | None, peer: str) -> Session:
        """Validate ``X-Exp-Leg-Token`` for a local-leg request: format, live session, MAC (session + address binding),
        expiry, the observed address. 401 invalid_token / token_expired, 403 ip_mismatch."""
        now = self.clock()
        ra = self.auth_fail_limiter.retry_after(peer, now)
        if ra > 0:
            raise too_many("bad_tokens", ra, "too many refused requests")
        parsed = LegTokens.parse(token)
        s = self._by_nonce.get(parsed[1]) if parsed else None
        if parsed is None or s is None or token is None or not self.tokens.verify(token, s.id, s.client_ip):
            self.auth_fail_limiter.record(peer, now)
            raise ApiError(401, "invalid_token", "invalid token")
        if now >= parsed[0] or now >= s.token_expires_at:
            raise ApiError(401, "token_expired", "token expired")
        if peer != s.client_ip:
            self.auth_fail_limiter.record(peer, now)
            raise ApiError(403, "ip_mismatch", "ip mismatch")
        if s.first_use is None:
            s.first_use = now
        s.requests += 1
        return s

    def ping(self, s: Session) -> None:
        with self._lock:
            s.pings += 1
            if s.pings > MAX_PINGS_PER_SESSION:
                raise too_many("pings_per_session", 5.0, "too many pings for this session")

    def reserve(self, s: Session, n: int) -> None:
        """Reserve ``n`` on-network bytes of the session's budget (413 with the remaining budget when it does not fit)."""
        with self._lock:
            allowed = min(s.cap, self.guard.effective_cap())
            used = s.used + s.reserved
            if n > allowed - used:
                s.capped = True
                raise ApiError(413, "budget_exceeded", "on-network byte budget exceeded",
                               {"remaining": max(0, allowed - used)}, close=False)
            s.reserved += n
            self._transfers += 1

    def settle(self, s: Session, reserved: int, moved: int, down: bool) -> None:
        """Return the reservation and book what actually moved (the server-side counters the result cross-checks)."""
        with self._lock:
            s.reserved = max(0, s.reserved - reserved)
            self._transfers = max(0, self._transfers - 1)
            if down:
                s.bytes_down += moved
            else:
                s.bytes_up += moved
            if s.used >= min(s.cap, self.guard.effective_cap()):
                s.capped = True

    # ======================================================================================= view-proof
    def _auth_view(self, sid: str, proof: str | None) -> tuple[Session | None, dict[str, Any]]:
        """Resolve a session route: wrong id, missing/malformed/wrong proof are all the same 404 (no enumeration)."""
        if not st.is_speedtest_session_id(sid):
            raise not_found()
        s = self._sessions.get(sid)
        verifier = s.verifier if s else None
        row = None
        if verifier is None:
            row = self.store.get_session(sid)
            verifier = row["verifier"] if row else None
        if verifier is None or proof is None or not st.verify_view_proof(verifier, proof):
            raise not_found()
        if row is None:
            row = self.store.get_session(sid)
            if row is None:
                raise not_found()
        return s, row

    # ================================================================================= internet-slot
    def internet_slot(self, sid: str, proof: str | None, body: Any) -> dict[str, Any]:
        s, _row = self._auth_view(sid, proof)
        if not isinstance(body, dict) or set(body) != {"action"} or body["action"] not in ("acquire", "release"):
            raise bad_request("action must be acquire or release")
        if s is None:
            raise not_found()
        return self.internet.acquire(sid) if body["action"] == "acquire" else self.internet.release(sid)

    # ========================================================================================== path
    def session_path(self, sid: str, proof: str | None) -> dict[str, Any]:
        s, row = self._auth_view(sid, proof)
        now = self.clock()
        base = self.path.snapshot(sid, since=s.created if s else None) if self.path is not None else {
            "gateway_ms": {"idle": None, "loaded": None, "samples": 0}, "edge_ms": {"idle": None, "loaded": None, "samples": 0},
            "edge1_ms": {"idle": None, "loaded": None, "samples": 0}, "edge1_addr": None, "device_icmp_ms": None}
        resolver_ip = None
        split = {"device_to_resolver_ms": None, "resolver_to_authority_ms": None}
        if s is not None and s.dns_nonces:
            arrivals = self.nonces.for_session(s.dns_nonces)
            resolver_ip = arrivals[0][1].resolver_ip if arrivals else None
            d = s.dns_submitted or {}
            cold, warm = d.get("cold_ms"), d.get("warm_ms")
            if resolver_ip and isinstance(cold, (int, float)) and isinstance(warm, (int, float)):
                # a cached (warm) answer costs device<->resolver; the cold extra is resolver<->authority (an estimate)
                split = {"device_to_resolver_ms": round(float(warm), 3),
                         "resolver_to_authority_ms": round(max(0.0, cold - warm), 3)}
        elif s is None and row.get("result"):
            res_dns = (row["result"].get("legs") or {}).get("dns") or {}
            resolver_ip = res_dns.get("resolver_ip")
        return {"session_id": sid, "updated": iso(now), "path": base, "resolver_seen": resolver_ip, "dns_cold_split": split}

    # ======================================================================================== result
    def _clean_leg(self, leg: dict[str, Any], server: str | None) -> dict[str, Any]:
        status = leg.get("status")
        if status is None:
            status = "ok" if any(k in leg for k in ("down_mbps", "up_mbps")) else "skipped"
        out: dict[str, Any] = {"status": status}
        if status == "ok":
            for k in _LEG_KEYS:
                if k in leg:
                    out[k] = leg[k]
        if server:
            out["server"] = server
        return out

    def submit_result(self, sid: str, proof: str | None, peer: str, submission: Any) -> dict[str, Any]:
        s, row = self._auth_view(sid, proof)
        if row["state"] == "submitted" or (s is not None and s.submitted):
            raise ApiError(409, "already_submitted", "a result was already submitted for this session")
        if s is None:
            raise ApiError(409, "result_deadline_passed", "the session has ended")
        if peer != s.client_ip:
            raise ApiError(403, "ip_mismatch", "ip mismatch")
        now = self.clock()
        if now > s.created + self.cfg.limits.result_deadline_s:
            raise ApiError(409, "result_deadline_passed", "the result deadline has passed")
        errs = exp_config.iter_errors(submission, "exp.speedtest.submission/1")
        if errs:
            raise bad_request("invalid result", code="invalid_result", issues=[str(e)[:200] for e in errs[:5]])
        hint = submission.get("zone_hint")
        if hint is not None and hint not in self.cfg.zones:
            raise bad_request("unknown zone_hint", code="invalid_result", field="zone_hint")
        doc = self._build_result(s, submission, now)
        bad = exp_config.iter_errors(doc, "exp.speedtest/1")
        if bad:                                                   # our own output failing the contract is a bug
            log.error("built an invalid result for %s: %s", sid, "; ".join(str(e) for e in bad[:3]))
            raise ApiError(500, "internal_error", "internal error")
        no_ip = copy.deepcopy(doc)
        no_ip["client"].pop("ip", None)
        if not self.store.mark_submitted(sid, no_ip):
            raise ApiError(409, "already_submitted", "a result was already submitted for this session")
        diagnosis = None
        if self.forwarder is not None:
            try:
                seq = self.forwarder.enqueue_result(doc)
            except SpoolFull:
                self.store.unmark_submitted(sid)
                raise ApiError(503, "spool_full", "results cannot be accepted right now", headers={"Retry-After": "30"}) from None
            out = self.forwarder.attempt(seq, sync=True)
            if out is not None and out.kind == "ok" and out.body:
                diagnosis = self._user_diagnosis(out.body.get("diagnosis"), full=True)
            self.forwarder.wake.set()
        with self._lock:
            s.submitted = True
            s.dns_submitted = (submission.get("legs") or {}).get("dns")
        self.internet.forget(sid)
        if self.path is not None:
            self.path.unwatch_device(sid)
        self._submit_times.append(now)
        return {"id": sid, "flags": doc["flags"], "score": doc["score"], "diagnosis": diagnosis}

    def _build_result(self, s: Session, sub: dict[str, Any], now: float) -> dict[str, Any]:
        cfg = self.cfg
        flags: set[str] = set()
        legs_in = sub["legs"]
        local = self._clean_leg(legs_in["local"], cfg.speedtest_id)
        legs: dict[str, Any] = {"local": local}

        # ---- internet leg: what the page measured, with the box's own knowledge applied
        inet_in = legs_in.get("internet")
        leg_state, reason = self.internet.state()
        if not cfg.internet_enabled:
            legs["internet"] = {"status": "unavailable"}
        elif inet_in is not None:
            colo = (inet_in.get("colo") or "").upper()
            legs["internet"] = self._clean_leg(inet_in, f"cloudflare:{colo}" if colo else None)
        elif leg_state == "paused":
            legs["internet"] = {"status": "paused"}
        elif leg_state == "queued":
            legs["internet"] = {"status": "queued"}
        inet = legs.get("internet")
        if inet is not None:
            flag = _INET_FLAGS.get(inet["status"])
            if flag:
                flags.add(flag)
            if inet["status"] == "skipped":
                flags.add("partial")
        if local["status"] != "ok":
            flags.add("partial")

        # ---- DNS leg: the box's view of the nonces decides whether the browser figure is a real cold lookup
        arrivals = self.nonces.for_session(s.dns_nonces) if self.dns_active else []
        d_in = legs_in.get("dns") or {}
        if arrivals:
            legs["dns"] = {"cold_ms": d_in.get("cold_ms"), "warm_ms": d_in.get("warm_ms"),
                           "resolver_ip": arrivals[0][1].resolver_ip, "source": "browser"}
        else:
            legs["dns"] = {"cold_ms": None, "warm_ms": None, "resolver_ip": None, "source": "probe"}
            flags.add("dns_fallback")

        # ---- path (shared infrastructure context + this client only)
        if self.path is not None:
            legs["path"] = self.path.snapshot(s.id, since=s.created)

        # ---- counters cross-check (local leg only)
        server_bytes = s.used
        client_bytes = local.get("bytes")
        if local["status"] == "ok" and client_bytes is not None and st.counters_disagree(client_bytes, server_bytes):
            flags.add("counters_disagree")
        if s.capped:
            flags.add("bytes_capped")

        # ---- zone: correlation-friendly stamp; the runner later refines it (fail-closed NAT guard)
        where = self.resolver.resolve(s.client_ip, s.zone_hint or sub.get("zone_hint"), ask=False)
        if where.nat_suspected:
            flags.add("nat_suspected")
        if where.zone_hint_conflict:
            flags.add("zone_hint_conflict")

        basis = st.score_basis(legs)
        failures = int(basis[1].get("failures", 0)) if basis else 0
        score = st.compute_score(legs, {"down_mbps": cfg.target_down_mbps, "up_mbps": cfg.target_up_mbps}, failures)

        started = s.first_use if s.first_use is not None else s.created
        client: dict[str, Any] = {"ip": s.client_ip}
        if s.ua:
            client["ua"] = s.ua
        hint_conn = (sub.get("client") or {}).get("connection_hint")
        if hint_conn:
            client["connection_hint"] = hint_conn
        doc: dict[str, Any] = {
            "schema": "exp.speedtest/1", "id": s.id, "site": cfg.site, "zone": where.zone, "zone_source": where.source,
            "started": iso(min(started, now)), "ended": iso(now), "client": client,
            "consent": {"text_version": s.consent_version}, "legs": legs, "score": score,
            "flags": sorted(flags),
            "observed": {"received_at": iso(now), "server_id": cfg.speedtest_id, "local_bytes_down": s.bytes_down,
                         "local_bytes_up": s.bytes_up, "session_ms": round(min(60000.0, max(0.0, (now - s.created) * 1000)), 1)}}
        comment = sub.get("comment")
        if comment is None:
            comment = (self.store.get_session(s.id) or {}).get("comment")
        if comment:
            doc["comment"] = comment
        return doc

    @staticmethod
    def _user_diagnosis(d: Any, full: bool = False) -> dict[str, Any] | None:
        """The user-safe projection of a collector diagnosis: stage, ordered cause ids with confidence, plain text. NOC
        text and evidence citations are never exposed (SR-21)."""
        if not isinstance(d, dict) or d.get("stage") not in ("quick", "final") or not isinstance(d.get("cause"), list):
            return None
        causes = []
        for c in d["cause"][:8]:
            if isinstance(c, dict) and isinstance(c.get("id"), str) and isinstance(c.get("confidence"), (int, float)) \
                    and not isinstance(c["confidence"], bool):
                causes.append({"id": c["id"][:64], "confidence": max(0.0, min(1.0, float(c["confidence"])))})
        text = d.get("user_text") if isinstance(d.get("user_text"), str) else ""
        updated = d.get("updated") if isinstance(d.get("updated"), str) else iso(time.time())
        out: dict[str, Any] = {"stage": d["stage"], "updated": updated, "cause": causes,
                               "user_text": _CTRL.sub(" ", text)[:280]}
        if full:   # the ResultAccepted schema reuses the full diagnosis def: required keys present, content withheld
            out["cause"] = [{**c, "cites": []} for c in causes]
            out["noc_text"] = ""
        return out

    # ========================================================================================== view
    def get_view(self, sid: str, proof: str | None) -> dict[str, Any]:
        s, row = self._auth_view(sid, proof)
        result = row["result"]
        submitted = row["state"] == "submitted"
        remote = self._collector_status(sid) if submitted else None
        state = "created"
        if submitted:
            state = remote["state"] if remote and remote.get("state") in ("correlating", "final") else "submitted"
        elif s is not None and s.first_use is not None:
            state = "running"
        zone, zname, zsrc = "unresolved", None, "unresolved"
        if remote and remote.get("zone"):
            zone, zname, zsrc = remote["zone"], remote.get("zone_name"), remote.get("zone_source", "unresolved")
        elif result:
            zone, zsrc = result.get("zone", "unresolved"), result.get("zone_source", "unresolved")
            zname = self.resolver.zone_name(zone)
        elif s is not None:
            zone, zname, zsrc = s.where.zone, s.where.zone_name, s.where.source
        evidence = (remote or {}).get("evidence") or {"state": "pending", "kinds_done": []}
        details = (remote or {}).get("network_details") if self.cfg.show_network_details else None
        return {"id": sid, "state": state, "zone": zone, "zone_name": zname, "zone_source": zsrc, "result": result,
                "diagnosis": self._user_diagnosis((remote or {}).get("diagnosis")),
                "evidence": evidence, "checks": (remote or {}).get("checks") or [],
                "network_details": details, "comment": row["comment"]}

    def _collector_status(self, sid: str) -> dict[str, Any] | None:
        now = self.clock()
        hit = self._view_cache.get(sid)
        if hit and now - hit[0] < VIEW_CACHE_S:
            return hit[1]
        doc = None
        if self.client is not None:
            out = self.client.get_status(sid)
            if out.kind == "ok" and out.body:
                doc = self._sanitize_status(out.body)
        if len(self._view_cache) > 2000:
            self._view_cache.clear()
        self._view_cache[sid] = (now, doc)
        return doc

    @staticmethod
    def _sanitize_status(b: dict[str, Any]) -> dict[str, Any]:
        """Whitelist and bound the collector's status document: it is relayed to the page."""
        out: dict[str, Any] = {}
        if b.get("state") in ("submitted", "correlating", "final"):
            out["state"] = b["state"]
        if isinstance(b.get("zone"), str) and _ZONE.match(b["zone"]):
            out["zone"] = b["zone"]
            out["zone_name"] = b["zone_name"][:64] if isinstance(b.get("zone_name"), str) else None
        if b.get("zone_source") in ("qr", "subnet", "mist", "dhcp", "unresolved"):
            out["zone_source"] = b["zone_source"]
        out["diagnosis"] = b.get("diagnosis")
        ev = b.get("evidence")
        if isinstance(ev, dict) and ev.get("state") in ("pending", "correlating", "final", "unavailable"):
            kinds = [k for k in (ev.get("kinds_done") or []) if k in _KINDS]
            out["evidence"] = {"state": ev["state"], "kinds_done": sorted(set(kinds))[:8]}
        checks = []
        for c in (b.get("checks") or [])[:8]:
            if isinstance(c, dict) and c.get("kind") in _KINDS \
                    and c.get("state") in ("checking", "ok", "attention", "unavailable"):
                item: dict[str, Any] = {"kind": c["kind"], "state": c["state"]}
                if isinstance(c.get("text"), str):
                    item["text"] = _CTRL.sub(" ", c["text"])[:160]
                checks.append(item)
        out["checks"] = checks
        nd = b.get("network_details")
        if isinstance(nd, dict):
            d: dict[str, Any] = {}
            if isinstance(nd.get("ap_name"), str):
                d["ap_name"] = _CTRL.sub(" ", nd["ap_name"])[:128]
            if isinstance(nd.get("band"), str):
                d["band"] = _CTRL.sub(" ", nd["band"])[:16]
            if isinstance(nd.get("channel"), int) and not isinstance(nd["channel"], bool) and 0 <= nd["channel"] <= 400:
                d["channel"] = nd["channel"]
            out["network_details"] = d
        return out

    # ======================================================================================== comment
    def post_comment(self, sid: str, proof: str | None, body: Any) -> None:
        _s, row = self._auth_view(sid, proof)
        if not isinstance(body, dict) or set(body) != {"comment"}:
            raise bad_request("comment is required")
        c = body["comment"]
        if not isinstance(c, str) or not 1 <= len(c) <= st.MAX_COMMENT_CHARS or _COMMENT_BAD.search(c):
            raise bad_request("comment must be 1-500 characters without control characters")
        if row["comment_n"] >= COMMENT_REPLACEMENTS + 1:
            raise ApiError(409, "conflict", "too many comment replacements")
        self.store.set_comment(sid, c)                             # verbatim text; never logged
        if row["state"] == "submitted" and self.forwarder is not None:
            try:
                seq = self.forwarder.enqueue_comment(sid, c)
            except SpoolFull:
                raise ApiError(503, "spool_full", "comments cannot be accepted right now",
                               headers={"Retry-After": "30"}) from None
            self.forwarder.attempt(seq, sync=True)
            self.forwarder.wake.set()

    # ========================================================================================= channel
    def channel_where_wanted(self) -> dict[str, Any]:
        return {"items": [{"ip": ip, "since": iso(t)} for ip, t in self.resolver.wanted()]}

    def channel_put_where(self, body: Any) -> None:
        import ipaddress
        if not isinstance(body, dict) or set(body) != {"items"} or not isinstance(body["items"], list) \
                or len(body["items"]) > 100:
            raise bad_request("items required (at most 100)")
        clean: list[dict[str, Any]] = []
        for it in body["items"]:
            if not isinstance(it, dict) or not {"ip", "zone", "zone_source", "nat_suspected"} <= set(it) \
                    or not set(it) <= {"ip", "zone", "zone_source", "ap_name", "ssid", "band", "nat_suspected", "ttl_s"}:
                raise bad_request("invalid item")
            try:
                ip = str(ipaddress.ip_address(it["ip"]))
            except ValueError:
                raise bad_request("invalid ip") from None
            if not isinstance(it["zone"], str) or not _ZONE.match(it["zone"]) \
                    or it["zone_source"] not in ("mist", "dhcp", "subnet", "unresolved") \
                    or not isinstance(it["nat_suspected"], bool):
                raise bad_request("invalid item")
            ttl = it.get("ttl_s")
            if ttl is not None and (isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= 3600):
                raise bad_request("invalid ttl_s")
            item = {"ip": ip, "zone": it["zone"], "zone_source": it["zone_source"],
                    "nat_suspected": it["nat_suspected"], "ttl_s": ttl}
            for key, mx in (("ap_name", 128), ("ssid", 64), ("band", 16)):
                v = it.get(key)
                if v is not None and (not isinstance(v, str) or len(v) > mx or _CTRL.search(v)):
                    raise bad_request(f"invalid {key}")
                item[key] = v
            clean.append(item)
        self.resolver.put(clean)

    def channel_put_pause(self, body: Any) -> None:
        if not isinstance(body, dict) or not {"wan_util_pct", "source", "measured_at"} <= set(body) \
                or not set(body) <= {"wan_util_pct", "source", "measured_at", "pause"} or body["source"] != "ec":
            raise bad_request("invalid pause document")
        util = body["wan_util_pct"]
        if util is not None and (isinstance(util, bool) or not isinstance(util, (int, float)) or not 0 <= util <= 1000):
            raise bad_request("invalid wan_util_pct")
        pause = body.get("pause")
        if pause is not None and not isinstance(pause, bool):
            raise bad_request("invalid pause")
        try:
            at = iso_to_ms(body["measured_at"]) / 1000.0
        except ValueError:
            raise bad_request("invalid measured_at") from None
        self.internet.put_wan(None if util is None else float(util), at, pause)

    # ======================================================================================== metrics
    def metrics(self) -> dict[str, Any]:
        now = self.clock()
        hour = now - 3600
        return {"tests_per_hour": sum(1 for t in self._submit_times if t >= hour),
                "active_tests": len(self.active_sessions(now)), "queue_depth": self.internet.queue_depth,
                "internet_leg_paused": 1 if self.internet.paused else 0,
                "local_leg_gbps_p95": self.meter.p95_gbps(),
                "rejected_per_hour": sum(1 for t in self._reject_times if t >= hour)}

    # ==================================================================================== housekeeping
    def housekeeping(self) -> None:
        now = self.clock()
        with self._lock:
            horizon = max(self.cfg.limits.result_deadline_s, self.cfg.limits.leg_token_ttl_s) + 60
            for sid in [k for k, s in self._sessions.items() if now > s.created + horizon]:
                s = self._sessions.pop(sid)
                self._by_nonce.pop(s.nonce, None)
                self.internet.forget(sid)
                if self.path is not None:
                    self.path.forget_device(sid)
        self.internet.housekeeping()
        self.create_limiter.prune(now)
        self.auth_fail_limiter.prune(now)
        self.api_limiter.prune(now)
        self.nonces.prune()
        cutoff = now - 3600
        while self._submit_times and self._submit_times[0] < cutoff:
            self._submit_times.popleft()
        while self._reject_times and self._reject_times[0] < cutoff:
            self._reject_times.popleft()
        if now - self._last_prune >= 600:
            self._last_prune = now
            self.store.prune_sessions(now - self.cfg.retention_days * 86400)


def payload_ready(path: os.PathLike[str] | str) -> bool:
    try:
        return os.path.getsize(path) > 0
    except OSError:
        return False

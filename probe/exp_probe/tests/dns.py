"""`dns_hb` (beat, rotating port) and `dns` (scheduled) -- 02-probe.md 5.4.

Each resolver the port's DHCP lease gave (``resolver_kind=dhcp``) and the configured
`heartbeat.alternate_resolver` (``alternate``) is asked an A query, inside the port's namespace, with
dnspython (2 s timeout), and ICMP-pinged (``ping_rtt_ms``, 2 tries 0.5 s apart: public resolvers
rate-limit ICMP). The alternate resolver is how the rules engine tells "the DHCP resolver is down"
from "DNS traffic dies at the edge"; the ping tells "unreachable" from "reachable but not answering".

Interception: a name under ``.invalid`` can never exist (RFC 6761). A resolver (or an on-path box
redirecting port 53) that answers it with NOERROR + records is rewriting NXDOMAIN, recorded as
``detail.nxdomain_canary.intercepted`` and the outcome becomes ``degraded`` (never a resolver failure).
The canary runs against the alternate resolver on every beat and against every resolver in `dns`.

`dns` asks every configured name (`tests.dns.names`, default `heartbeat.dns_names`) at every resolver,
one record per (resolver, name), two attempts per query.

Ported from reference/exm/lib/exm/heartbeat.py (`_dns_probe`, `dns_hb`) and dnstest.py (`_query`).
"""
from __future__ import annotations

import logging
import secrets
import socket
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
from exp_common.schema import Measurement

from ..icmp import IcmpUnavailable, open_icmp, ping_many
from ..netio import NetnsMissing
from ..scheduler import TestContext, register_test
from .common import clip, error_record, is_ipv4, num, pick_port, port_info, thresholds

log = logging.getLogger(__name__)

DNS_PORT = 53                     # tests point this at a local stub (the product never changes it)
DNS_TIMEOUT_S = 2.0
PING_TRIES, PING_GAP_S, PING_TIMEOUT_S = 2, 0.5, 1.0
DEFAULT_SLOW_MS = 250.0
MAX_WORKERS = 8
MAX_DETAIL_ANSWERS = 8
MAX_DETAIL_NAMES = 16


@dataclass
class QueryResult:
    resolver: str
    name: str
    rcode: int | None = None
    rtt_ms: float | None = None
    an_count: int = 0
    answers: list[str] = field(default_factory=list)
    timed_out: bool = False
    error: str | None = None

    @property
    def responded(self) -> bool:
        return self.rcode is not None


def _answer_texts(resp: Any) -> list[str]:
    out: list[str] = []
    for rrset in resp.answer:
        for rd in rrset:
            out.append(clip(rd.to_text(), 255))
            if len(out) >= MAX_DETAIL_ANSWERS:
                return out
    return out


def query_a(env: Any, resolver: str, name: str, timeout: float = DNS_TIMEOUT_S, attempts: int = 1) -> QueryResult:
    """One A query (up to `attempts` on timeout) from inside `env`. Never raises on network trouble."""
    res = QueryResult(resolver, name)
    try:
        q = dns.message.make_query(name, "A")
    except (dns.exception.DNSException, ValueError) as exc:
        res.error = f"bad name {clip(name, 80)!r}: {exc}"
        return res
    for _ in range(max(1, attempts)):
        res.timed_out, res.error = False, None
        try:
            sock = env.call(_make_sock, env)
        except OSError as exc:
            res.error = f"cannot open a socket: {exc.strerror or exc}"
            return res
        t0 = time.perf_counter()
        try:
            resp = dns.query.udp(q, resolver, timeout=timeout, port=DNS_PORT, sock=sock, ignore_unexpected=True)
        except dns.exception.Timeout:
            res.timed_out = True
            continue
        except dns.message.Truncated as exc:                 # TC=1: the header and rcode are still the answer
            resp = exc.message() if callable(getattr(exc, "message", None)) else None
            if resp is None:
                res.error = "truncated response"
                return res
        except OSError as exc:                                # no route, EINVAL from a blackhole, ...
            res.error = f"cannot query {resolver}: {exc.strerror or exc}"[:200]
            return res
        except (dns.exception.DNSException, ValueError) as exc:
            res.error = f"{type(exc).__name__}: {exc}"[:200]
            return res
        finally:
            sock.close()
        res.rtt_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        res.rcode = int(resp.rcode())
        res.an_count = sum(len(r) for r in resp.answer)
        res.answers = _answer_texts(resp)
        return res
    return res


def _make_sock(env: Any) -> socket.socket:
    s = env.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    return s


def canary_check(env: Any, resolver: str, timeout: float = DNS_TIMEOUT_S) -> dict[str, Any]:
    name = f"exp-{secrets.token_hex(4)}.invalid"
    r = query_a(env, resolver, name, timeout)
    if not r.responded:
        return {"error": "no answer" if r.timed_out else clip(r.error or "no answer", 120), "intercepted": False}
    return {"rcode": r.rcode, "answers": r.an_count, "intercepted": r.rcode == 0 and r.an_count > 0}


def assess(res: QueryResult, slow_ms: float, timeout: float | None = None) -> tuple[str, str | None]:
    """(outcome, error) of one resolver answer."""
    if not res.responded:
        if res.timed_out:
            return "fail", f"no answer from {res.resolver} within {DNS_TIMEOUT_S if timeout is None else timeout:g} s"
        return "fail", clip(res.error or f"no answer from {res.resolver}", 200)
    if res.rcode != 0:
        return "fail", f"rcode {dns.rcode.to_text(res.rcode)} from {res.resolver}"
    if res.an_count == 0:
        return "fail", f"no records for {res.name} from {res.resolver}"
    if res.rtt_ms is not None and res.rtt_ms > slow_ms:
        return "degraded", f"answer took {res.rtt_ms:g} ms"
    return "ok", None


def _ping_resolvers(env: Any, ips: list[str]) -> dict[str, float | None]:
    try:
        ep = open_icmp(env)
    except (IcmpUnavailable, OSError) as exc:
        log.debug("resolver ping unavailable: %s", exc)
        return {ip: None for ip in ips}
    try:
        res = ping_many(ep, ips, PING_TRIES, PING_GAP_S, PING_TIMEOUT_S, stop_on_reply=True)
    finally:
        ep.close()
    return {ip: res[ip].rtts[0] if res[ip].rtts else None for ip in ips}


def resolvers_of(ctx: TestContext, dhcp_dns: list[str]) -> tuple[list[tuple[str, str]], list[str]]:
    """[(ip, kind)], plus problems with the configuration."""
    out = [(ip, "dhcp") for ip in dhcp_dns]
    problems: list[str] = []
    alt = ctx.cfg.heartbeat.get("alternate_resolver")
    if alt:
        if not is_ipv4(alt):
            problems.append(f"alternate_resolver {clip(alt, 60)!r} must be an IPv4 address")
        elif alt not in dhcp_dns:
            out.append((alt, "alternate"))
    return out, problems


def _map(fns: list[Callable[[], Any]]) -> list[Any]:
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, max(1, len(fns)))) as pool:
        futs = [pool.submit(f) for f in fns]
        return [f.result() for f in futs]


def _wrap(fn: Callable[..., Any], *a: Any) -> Callable[[], Any]:
    def run() -> Any:
        try:
            return fn(*a)
        except NetnsMissing as exc:
            return exc
        except OSError as exc:
            return exc
    return run


# ----------------------------------------------------------------------------------------- dns_hb

@register_test("dns_hb", roles=("client", "wifi"))
def dns_hb(ctx: TestContext) -> list[Measurement]:
    assert ctx.port is not None
    names = ctx.cfg.heartbeat["dns_names"]
    interval = max(1, int(ctx.cfg.heartbeat["interval_s"]))
    name = names[int(ctx.beat_ts // interval) % len(names)] if names else "google.com"
    slow_ms = thresholds(ctx, "dns", "rtt_ms", DEFAULT_SLOW_MS)
    port, info, why = pick_port(ctx)
    if port is None or info is None:
        if ctx.explicit:
            return [error_record(ctx, "dns_hb", f"port {ctx.port.id} has no lease (no resolver known)",
                                 labels={"resolver": "none", "resolver_kind": "dhcp"})]
        return [error_record(ctx, "dns_hb", "no client could run it: " + "; ".join(why),
                             labels={"resolver": "none", "resolver_kind": "dhcp"})]
    resolvers, problems = resolvers_of(ctx, info.dns)
    out: list[Measurement] = [error_record(ctx, "dns_hb", p, port=port, labels={"resolver": "none",
                              "resolver_kind": "alternate"}) for p in problems]
    if not resolvers:
        out.append(error_record(ctx, "dns_hb", f"port {port.id} has no resolver (the lease carried no DNS option)",
                                port=port, labels={"resolver": "none", "resolver_kind": "dhcp"}))
        return out
    env = ctx.netenv(port)
    if not env.exists():
        return [error_record(ctx, "dns_hb", f"namespace for port {port.id} is missing", port=port,
                             labels={"resolver": "none", "resolver_kind": "dhcp"})]
    jobs: list[Callable[[], Any]] = [_wrap(query_a, env, ip, name, DNS_TIMEOUT_S) for ip, _ in resolvers]
    canary_idx = {ip: i for i, (ip, k) in enumerate(resolvers) if k == "alternate"}
    jobs += [_wrap(canary_check, env, ip, DNS_TIMEOUT_S) for ip in canary_idx]
    jobs.append(_wrap(env.call, _ping_resolvers, env, [ip for ip, _ in resolvers]))
    done = _map(jobs)
    qres, canaries, pings = done[:len(resolvers)], done[len(resolvers):-1], done[-1]
    canary_of = dict(zip(canary_idx, canaries, strict=True))
    for (ip, kind), r in zip(resolvers, qres, strict=True):
        labels = {"resolver": ip, "resolver_kind": kind}
        if isinstance(r, OSError):
            out.append(error_record(ctx, "dns_hb", f"DNS query failed: {r.strerror or r}", port=port, labels=labels))
            continue
        outcome, err = assess(r, slow_ms)
        detail: dict[str, Any] = {"name": name}
        can = canary_of.get(ip)
        if isinstance(can, dict):
            detail["nxdomain_canary"] = can
            if can.get("intercepted") and outcome == "ok":
                outcome, err = "degraded", f"DNS interception suspected: {ip} answered an NXDOMAIN canary"
        metrics: dict[str, float] = {}
        if r.responded:
            metrics.update(rtt_ms=num(r.rtt_ms), rcode=float(r.rcode), answers=float(r.an_count))  # type: ignore[arg-type]
        ping = pings.get(ip) if isinstance(pings, dict) else None
        if ping is not None:
            metrics["ping_rtt_ms"] = num(ping)  # type: ignore[assignment]
        kw: dict[str, Any] = {"error": err} if err else {}
        if r.responded:
            kw["duration_ms"] = num(r.rtt_ms)
        out.append(ctx.measure("dns_hb", outcome, labels={"port": port.id, **labels}, metrics=metrics,
                               detail=detail, **kw))
    return out


# ------------------------------------------------------------------------------------------- dns

@register_test("dns", roles=("client", "wifi"))
def dns_test(ctx: TestContext) -> list[Measurement]:
    port = ctx.port
    assert port is not None
    conf = ctx.cfg.tests.get("dns") or {}
    names = list(conf.get("names") or ctx.cfg.heartbeat["dns_names"])[:MAX_DETAIL_NAMES * 4]
    slow_ms = thresholds(ctx, "dns", "rtt_ms", DEFAULT_SLOW_MS)
    info = port_info(ctx, port)
    if not info.bound:
        return [error_record(ctx, "dns", f"port {port.id} has no lease (no resolver known)", labels={"resolver": "none"})]
    resolvers, problems = resolvers_of(ctx, info.dns)
    out = [error_record(ctx, "dns", p, labels={"resolver": "none"}) for p in problems]
    if not resolvers or not names:
        out.append(error_record(ctx, "dns", f"port {port.id} has no resolver or no names to ask",
                                labels={"resolver": "none"}))
        return out
    env = ctx.netenv(port)
    if not env.exists():
        return [error_record(ctx, "dns", f"namespace for port {port.id} is missing", labels={"resolver": "none"})]
    jobs = [_wrap(query_a, env, ip, n, DNS_TIMEOUT_S, 2) for ip, _ in resolvers for n in names]
    jobs += [_wrap(canary_check, env, ip, DNS_TIMEOUT_S) for ip, _ in resolvers]
    done = _map(jobs)
    qres, cans = done[:len(resolvers) * len(names)], done[len(resolvers) * len(names):]
    canary_of = {ip: c for (ip, _), c in zip(resolvers, cans, strict=True)}
    k = 0
    for ip, _kind in resolvers:
        for n in names:
            r = qres[k]
            k += 1
            labels = {"port": port.id, "resolver": ip}
            if isinstance(r, OSError):
                out.append(error_record(ctx, "dns", f"DNS query failed: {r.strerror or r}", labels=labels, target=n))
                continue
            outcome, err = assess(r, slow_ms)
            detail: dict[str, Any] = {"name": n, "answers": r.answers}
            can = canary_of.get(ip)
            if isinstance(can, dict):
                detail["nxdomain_canary"] = can
                if can.get("intercepted") and outcome == "ok":
                    outcome, err = "degraded", f"DNS interception suspected: {ip} answered an NXDOMAIN canary"
            metrics: dict[str, float] = {"answers": float(r.an_count)}
            if r.responded:
                metrics.update(rtt_ms=num(r.rtt_ms), rcode=float(r.rcode))  # type: ignore[arg-type]
            if outcome == "fail" and not r.responded:
                err = f"no answers ({2 if r.timed_out else 0} timeouts, {0 if r.timed_out else 1} errors)"
            kw: dict[str, Any] = {"error": err} if err else {}
            if r.responded:
                kw["duration_ms"] = num(r.rtt_ms)
            out.append(ctx.measure("dns", outcome, labels=labels, target=n, metrics=metrics, detail=detail, **kw))
    return out

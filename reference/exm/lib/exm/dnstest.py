"""DNS test: the DHCP-learned resolvers against the public ones.

Per run, a random sample of the domain list is asked for A, AAAA and HTTPS
(type 65, which iOS asks on every lookup) at every resolver. One event per
resolver carries the latency percentiles, rcode counts and per-query detail.
Two more checks run against the public resolvers: interception (is port 53
being redirected to someone else's resolver?) and DNS over TLS reachability.
"""
from __future__ import annotations

import random
import time

from . import config as C
from . import events
from . import netns

# Each public resolver answers a "who are you" question only when you really
# reached it. A redirected port 53 answers differently, or not at all. Checked
# against live answers on 2026-10-23:
#   google      o-o.myaddr.l.google.com TXT -> the Google resolver's egress IP, which
#               must fall in the ranges Google publishes at locations.publicdns.goog
#   cloudflare  whoami.cloudflare CH TXT    -> your public IP, only Cloudflare answers it
#   quad9       id.server CH TXT            -> "res<n>.<pop>", e.g. res710.qmci2
#   opendns     debug.opendns.com TXT       -> "server r2004.dfw", only OpenDNS answers it
# Limit: an interceptor that forwards to the very resolver it impersonates is
# indistinguishable from that resolver by this method.
WHOAMI = {
    "google": ("o-o.myaddr.l.google.com", "TXT", "IN"),
    "cloudflare": ("whoami.cloudflare", "TXT", "CH"),
    "quad9": ("id.server", "TXT", "CH"),
    "opendns": ("debug.opendns.com", "TXT", "IN"),
}
GOOGLE_RANGES_TTL_S = 86400


def _google_ranges(cfg, fallback_server):
    """Google Public DNS egress ranges, cached for a day. One TXT record, too big for UDP."""
    import ipaddress
    import json
    import os
    import dns.message
    import dns.query
    cache = C.state_path(cfg, "google-dns-ranges.json")
    try:
        with open(cache) as fh:
            data = json.load(fh)
        if time.time() - data["fetched"] < GOOGLE_RANGES_TTL_S:
            return [ipaddress.ip_network(n) for n in data["nets"]]
    except (FileNotFoundError, KeyError, ValueError):
        pass
    for server in ("8.8.8.8", fallback_server):
        if not server:
            continue
        try:
            r = dns.query.tcp(dns.message.make_query("locations.publicdns.goog", "TXT"), server, timeout=5)
            tokens = " ".join(b"".join(rd.strings).decode() for rr in r.answer for rd in rr).split()
            nets = [str(ipaddress.ip_network(t)) for t in tokens if "/" in t]
            if nets:
                tmp = cache + ".tmp"
                with open(tmp, "w") as fh:
                    json.dump({"fetched": time.time(), "nets": nets}, fh)
                os.replace(tmp, cache)
                return [ipaddress.ip_network(n) for n in nets]
        except Exception:
            continue
    return None


def _genuine(cfg, name, rcode, texts, fallback_server):
    """True if the answer could only come from the named resolver, False if not, None if undecidable."""
    import ipaddress
    import re
    if rcode != "NOERROR" or not texts:
        return False
    if name == "google":
        nets = _google_ranges(cfg, fallback_server)
        if nets is None:
            return None
        for t in texts:
            try:
                ip = ipaddress.ip_address(t.strip())
            except ValueError:
                continue
            return any(ip in n for n in nets if n.version == ip.version)
        return False
    if name == "cloudflare":
        return any(re.fullmatch(r"[0-9a-fA-F:.]+", t.strip()) for t in texts)
    if name == "quad9":
        return any(re.match(r"res\d+\.", t.strip()) for t in texts)
    if name == "opendns":
        return any(t.startswith("server ") for t in texts)
    return None


def _query(server, name, rdtype, timeout, rdclass="IN"):
    import dns.exception
    import dns.flags
    import dns.message
    import dns.query
    import dns.rcode
    q = dns.message.make_query(name, rdtype, rdclass)
    q.flags |= dns.flags.AD
    row = {"name": name, "type": rdtype, "rcode": None, "rtt_ms": None, "an": 0, "ttl": None, "ad": False, "err": None}
    t0 = time.perf_counter()
    try:
        r = dns.query.udp(q, server, timeout=timeout, ignore_unexpected=True)
        if r.flags & dns.flags.TC:
            r = dns.query.tcp(q, server, timeout=timeout)
            row["tcp_fallback"] = True
        row["rtt_ms"] = events.ms(time.perf_counter() - t0)
        row["rcode"] = dns.rcode.to_text(r.rcode())
        row["an"] = sum(len(rr) for rr in r.answer)
        ttls = [rr.ttl for rr in r.answer]
        row["ttl"] = min(ttls) if ttls else None
        row["ad"] = bool(r.flags & dns.flags.AD)
        row["_answer"] = r.answer
    except dns.exception.Timeout:
        row["err"] = "timeout"
    except Exception as exc:
        row["err"] = f"{type(exc).__name__}: {exc}"
    return row


def _resolver_event(cfg, client, label, server, domains, types, timeout):
    ev = events.make(cfg, client, "dns", target=server, resolver=label)
    rows = []
    for name in domains:
        for t in types:
            r = _query(server, name, t, timeout)
            r.pop("_answer", None)
            rows.append(r)
    answered = [r for r in rows if r["rcode"] is not None]
    rtts = [r["rtt_ms"] for r in answered]
    rcodes = {}
    for r in answered:
        rcodes[r["rcode"]] = rcodes.get(r["rcode"], 0) + 1
    timeouts = sum(1 for r in rows if r["err"] == "timeout")
    errors = sum(1 for r in rows if r["err"] and r["err"] != "timeout")
    ev["phase_ms"] = {"p50": events.pct(rtts, 50), "p95": events.pct(rtts, 95), "max": max(rtts) if rtts else None}
    per_type = {}
    for t in types:
        tr = [r["rtt_ms"] for r in answered if r["type"] == t]
        per_type[t] = {"n": len(tr), "p50": events.pct(tr, 50)}
    ev["value"] = {"queries": len(rows), "answered": len(answered), "timeouts": timeouts,
                   "errors": errors, "rcodes": rcodes,
                   "ad_set": sum(1 for r in answered if r["ad"]), "per_type": per_type,
                   "detail": [[r["name"], r["type"], r["rcode"] or r["err"], r["rtt_ms"], r["an"], r["ttl"]] for r in rows]}
    servfail = rcodes.get("SERVFAIL", 0)
    p95 = ev["phase_ms"]["p95"]
    if not answered:
        ev["outcome"], ev["error"] = C.FAIL, f"no answers ({timeouts} timeouts, {errors} errors)"
    elif timeouts or servfail or errors or (p95 is not None and p95 > float(cfg["dns"].get("degraded_p95_ms", 250))):
        ev["outcome"] = C.DEGRADED
    else:
        ev["outcome"] = C.OK
    summary = (f"dns {client['id']} {label}@{server} outcome={ev['outcome']} p50={ev['phase_ms']['p50']}ms "
               f"p95={p95}ms answered={len(answered)}/{len(rows)} timeouts={timeouts} servfail={servfail}")
    events.emit(cfg, ev, summary)


def _interception(cfg, client, name, server, timeout, fallback_server):
    q = WHOAMI.get(name)
    if not q:
        return
    qname, qtype, qclass = q
    ev = events.make(cfg, client, "dns_intercept", target=server, resolver=name)
    r = _query(server, qname, qtype, timeout, rdclass=qclass)
    texts = []
    for rrset in r.pop("_answer", None) or []:
        for rd in rrset:
            texts.append(b"".join(rd.strings).decode("utf-8", "replace") if hasattr(rd, "strings") else rd.to_text())
    ev["phase_ms"] = {"rtt": r["rtt_ms"]}
    ev["value"] = {"question": f"{qname} {qclass} {qtype}", "rcode": r["rcode"] or r["err"], "answers": texts}
    if r["rcode"] is None:
        ev["outcome"], ev["error"] = C.FAIL, f"no reply: {r['err']}"
        ev["value"]["intercepted"] = None
    else:
        genuine = _genuine(cfg, name, r["rcode"], texts, fallback_server)
        ev["value"]["intercepted"] = None if genuine is None else (not genuine)
        # The spec: flag interception, never count it as a resolver failure.
        ev["outcome"] = C.DEGRADED if genuine is False else C.OK
        if genuine is None:
            ev["value"]["note"] = "could not decide (reference data unavailable)"
    events.emit(cfg, ev, f"dns_intercept {client['id']} {name}@{server} outcome={ev['outcome']} "
                         f"intercepted={ev['value'].get('intercepted')} answers={texts[:2]}")


def _dot(cfg, client, name, server, sni, timeout):
    import dns.message
    import dns.query
    import dns.rcode
    ev = events.make(cfg, client, "dns_dot", target=f"{server}:853", resolver=name)
    t0 = time.perf_counter()
    try:
        r = dns.query.tls(dns.message.make_query("google.com", "A"), server, timeout=timeout + 2,
                          server_hostname=sni)
        ev["phase_ms"] = {"total": events.ms(time.perf_counter() - t0)}
        ev["value"] = {"sni": sni, "rcode": dns.rcode.to_text(r.rcode())}
        ev["outcome"] = C.OK
    except Exception as exc:
        ev["phase_ms"] = {"total": events.ms(time.perf_counter() - t0)}
        ev["value"] = {"sni": sni}
        ev["outcome"], ev["error"] = C.FAIL, f"{type(exc).__name__}: {exc}"
    events.emit(cfg, ev, f"dns_dot {client['id']} {name}@{server} outcome={ev['outcome']} "
                         f"total={ev['phase_ms'].get('total')}ms" + (f" error={ev['error']}" if ev["error"] else ""))


def run(cfg: dict, client: dict) -> None:
    d = cfg["dns"]
    timeout = float(d.get("timeout_s", 2.0))
    types = list(d.get("record_types", ["A", "AAAA", "HTTPS"]))
    domains_all = list(d.get("domains", {}).get("list", [])) or ["google.com"]
    domains = random.sample(domains_all, min(int(d.get("domains_per_run", 8)), len(domains_all)))
    public = dict(d.get("public_resolvers", {}))

    # Inside the client namespace /etc/resolv.conf is that namespace's own file,
    # written from its DHCP lease.
    dhcp_resolvers = netns.read_resolvers("/etc/resolv.conf")
    if not dhcp_resolvers:
        ev = events.make(cfg, client, "dns", resolver="dhcp")
        ev["outcome"], ev["error"] = C.FAIL, "no DHCP-learned resolver (no lease, or the lease carried no DNS option)"
        events.emit(cfg, ev)
    for i, server in enumerate(dhcp_resolvers):
        _resolver_event(cfg, client, f"dhcp{i + 1}" if len(dhcp_resolvers) > 1 else "dhcp", server, domains, types, timeout)
    for name, server in public.items():
        _resolver_event(cfg, client, name, server, domains, types, timeout)
    if d.get("interception_check", True):
        for name, server in public.items():
            _interception(cfg, client, name, server, timeout, dhcp_resolvers[0] if dhcp_resolvers else None)
    if d.get("dot_check", True):
        for name, sni in dict(d.get("dot_names", {})).items():
            if name in public:
                _dot(cfg, client, name, public[name], sni, timeout)

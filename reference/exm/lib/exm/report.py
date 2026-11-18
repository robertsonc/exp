"""Read the JSON-lines results back: a terminal summary while there is no collector."""
from __future__ import annotations

import datetime
import glob
import os

from . import config as C
from . import events
from . import tail


def load(cfg: dict, minutes: int, tests=None) -> list[dict]:
    now = datetime.datetime.now(datetime.timezone.utc)
    since = now - datetime.timedelta(minutes=minutes)
    days = {since.date().isoformat(), now.date().isoformat()}
    out = []
    for day in sorted(days):
        for path in glob.glob(os.path.join(cfg["results_dir"], day, "*.jsonl")):
            test = os.path.basename(path)[:-6]
            if tests and test not in tests:
                continue
            out.extend(tail.lines_since(path, since))
    return sorted(out, key=lambda e: e["ts"])


def summarize(cfg: dict, minutes: int) -> dict:
    evs = load(cfg, minutes)
    by_client = {c["id"]: {"dhcp": [], "dns": {}, "apps": {}, "speed": {}, "intercept": {}, "dot": {}, "lease": None,
                      "unreachable": 0}
                 for c in C.clients(cfg)}
    for e in evs:
        c = by_client.get(e.get("client_id"))
        if c is None:
            continue
        t = e["test"]
        if t == "dhcp":
            c["dhcp"].append(e)
        elif t == "dns":
            if e.get("resolver"):                     # "no link" failures carry no resolver
                c["dns"].setdefault(e["resolver"], []).append(e)
            else:
                c["unreachable"] += 1
        elif t == "app":
            if e.get("target"):
                c["apps"].setdefault(e["target"], []).append(e)
            else:
                c["unreachable"] += 1
        elif t == "speedtest" and e.get("outcome") != "harness_error":
            c["speed"][e.get("target") or "unknown"] = e
        elif t == "dns_intercept" and e.get("resolver"):
            c["intercept"][e["resolver"]] = e
        elif t == "dns_dot" and e.get("resolver"):
            c["dot"][e["resolver"]] = e
        elif t == "dhcp_lease":
            c["lease"] = e
    result = {}
    for cid, c in by_client.items():
        dh = c["dhcp"]
        dns = {}
        for res, es in c["dns"].items():
            rtts = [row[3] for e in es for row in e["value"].get("detail", []) if isinstance(row[3], (int, float))]
            q = sum(e["value"].get("queries", 0) for e in es)
            to = sum(e["value"].get("timeouts", 0) for e in es)
            dns[res] = {"p50": events.pct(rtts, 50), "p95": events.pct(rtts, 95),
                        "timeout_pct": round(100 * to / q, 1) if q else None, "runs": len(es)}
        apps = {}
        for app, es in c["apps"].items():
            sat = sum(1 for e in es if e["value"].get("apdex_class") == "satisfied")
            tol = sum(1 for e in es if e["value"].get("apdex_class") == "tolerating")
            apps[app] = {"apdex": round((sat + tol / 2) / len(es), 2), "n": len(es),
                         "portal": sum(1 for e in es if e["outcome"] == "portal")}
        result[cid] = {
            # A lease that came back slow or with a warning still counts as served; only fail and harness_error do not.
            "dhcp": {"runs": len(dh), "ok_pct": round(100 * sum(1 for e in dh if e["outcome"] in (C.OK, C.DEGRADED)) / len(dh), 1) if dh else None,
                     "total_p50": events.pct([e["phase_ms"].get("total") for e in dh], 50),
                     "total_p95": events.pct([e["phase_ms"].get("total") for e in dh], 95),
                     "flags": sorted({f for e in dh for f in e["value"].get("flags", [])})},
            "dns": dns, "apps": apps,
            "speed": {p: {"down": e["value"].get("down_mbps"), "up": e["value"].get("up_mbps"),
                          "idle": e["phase_ms"].get("idle_rtt"), "bloat": e["value"].get("bufferbloat_ms"),
                          "outcome": e["outcome"], "ts": e["ts"]} for p, e in c["speed"].items()},
            "intercepted": sorted(r for r, e in c["intercept"].items() if e["value"].get("intercepted")),
            "dot_fail": sorted(r for r, e in c["dot"].items() if e["outcome"] != "ok"),
            "no_link_runs": c["unreachable"] + sum(1 for e in dh if "carrier down" in (e.get("error") or "")),
        }
    return result


def servers_seen(cfg: dict, minutes: int) -> dict:
    """Who is testing each server port: requests, sources and user agents."""
    out = {}
    for e in load(cfg, minutes, tests={"server_access"}):
        v = e["value"]
        r = out.setdefault(e["client_id"], {"requests": 0, "statuses": {}, "sources": {}, "agents": {}})
        r["requests"] += 1
        r["statuses"][str(v.get("status"))] = r["statuses"].get(str(v.get("status")), 0) + 1
        r["sources"][v.get("src_ip")] = r["sources"].get(v.get("src_ip"), 0) + 1
        ua = (v.get("user_agent") or "-")[:60]
        r["agents"][ua] = r["agents"].get(ua, 0) + 1
    return out


def dashboard_summary(cfg: dict, minutes: int = 60) -> dict:
    """What the dashboard's details tables show for this probe: per client, per resolver, per app, per server port.

    Computed on the probe (it knows its ports) and published every minute as a "summary" result, which
    the collector streams like any other; Wi-Fi is added on the collector from the laptops attached there."""
    from . import events
    s = summarize(cfg, minutes)
    pooled, apps = {}, {}
    for r in s.values():
        for res, v in r["dns"].items():
            pooled.setdefault(res, []).append(v)
        for app, v in r["apps"].items():
            apps.setdefault(app, []).append(v["apdex"])
    resolvers = {res: {"p50": events.median([v["p50"] for v in vs]), "p95": events.median([v["p95"] for v in vs]),
                       "timeout_pct": events.median([v["timeout_pct"] for v in vs])} for res, vs in pooled.items()}
    servers = servers_seen(cfg, minutes)
    return {
        "generated": events.utc_iso(), "minutes": minutes, "probe": cfg["probe_id"],
        "probe_info": {"version": C.AGENT_VER, "config_ver": cfg.get("_ver"), "hw_class": cfg.get("hw_class"),
                       "clients": len(C.clients(cfg)), "servers": len(C.servers(cfg))},
        "clients": s, "resolvers": resolvers,
        "apps": {a: {"apdex": round(sum(v) / len(v), 2), "clients": len(v)} for a, v in apps.items()},
        "servers": {c["id"]: dict(servers.get(c["id"], {}), address=c["address"]) for c in C.servers(cfg)},
    }


def emit_summary(cfg: dict, minutes: int = 60) -> dict:
    """Write the dashboard summary as a result line (test "summary"), for the collector."""
    from . import events
    ev = events.make(cfg, None, "summary", target="dashboard")
    ev["value"] = dashboard_summary(cfg, minutes)
    ev["outcome"] = C.OK
    events.emit(cfg, ev)
    return ev


def render(cfg: dict, minutes: int) -> str:
    s = summarize(cfg, minutes)
    lines = [f"EXM summary, last {minutes} min, probe {cfg['probe_id']}", ""]
    lines.append(f"{'client':7} {'dhcp ok%':>8} {'dora p50':>9} {'dora p95':>9}  {'dns(dhcp) p50/p95':>18}  {'worst app (apdex)':28} flags")
    for cid, r in s.items():
        d = r["dhcp"]
        dd = r["dns"].get("dhcp") or r["dns"].get("dhcp1") or {}
        worst = min(r["apps"].items(), key=lambda kv: kv[1]["apdex"], default=None)
        worst_s = f"{worst[0]} ({worst[1]['apdex']})" if worst else "-"
        flags = list(d["flags"]) + [f"intercepted:{x}" for x in r["intercepted"]] + [f"dot-fail:{x}" for x in r["dot_fail"]]
        if r["no_link_runs"]:
            flags.append(f"no-link-runs:{r['no_link_runs']}")
        dns_s = f"{dd.get('p50')}/{dd.get('p95')}" if dd else "-"
        lines.append(f"{cid:7} {str(d['ok_pct']):>8} {str(d['total_p50']):>9} {str(d['total_p95']):>9}  {dns_s:>18}  {worst_s:28} {','.join(flags) or '-'}")
    lines += ["", "DNS p50/p95 ms by resolver (all clients pooled):"]
    pooled = {}
    for r in s.values():
        for res, v in r["dns"].items():
            pooled.setdefault(res, []).append(v)
    for res, vs in sorted(pooled.items()):
        p50 = events.median([v["p50"] for v in vs])
        p95 = events.median([v["p95"] for v in vs])
        to = events.median([v["timeout_pct"] for v in vs])
        lines.append(f"  {res:12} p50 {p50}  p95 {p95}  timeouts {to}%")
    lines += ["", "Apdex by app (all clients pooled):"]
    apps = {}
    for r in s.values():
        for app, v in r["apps"].items():
            apps.setdefault(app, []).append(v["apdex"])
    for app, vs in sorted(apps.items()):
        lines.append(f"  {app:22} {round(sum(vs) / len(vs), 2)}  ({len(vs)} clients)")
    srv = servers_seen(cfg, minutes)
    if C.servers(cfg):
        lines += ["", "Server ports (requests received, e.g. Marvis Minis checks):"]
        for c in C.servers(cfg):
            r = srv.get(c["id"])
            if not r:
                lines.append(f"  {c['id']:6} {c['address']:18} no requests in window")
                continue
            top_src = sorted(r["sources"].items(), key=lambda kv: -kv[1])[:5]
            top_ua = sorted(r["agents"].items(), key=lambda kv: -kv[1])[:3]
            lines.append(f"  {c['id']:6} {c['address']:18} {r['requests']} requests  status {r['statuses']}")
            lines.append(f"         sources {', '.join(f'{ip} x{n}' for ip, n in top_src)}")
            lines.append(f"         agents  {', '.join(f'{ua} x{n}' for ua, n in top_ua)}")
    lines += ["", "Latest speed tests:"]
    for cid, r in s.items():
        for p, v in r["speed"].items():
            lines.append(f"  {cid} {str(p):10} down {v['down']} Mbps  up {v['up']} Mbps  idle {v['idle']} ms  "
                         f"bloat {v['bloat']} ms  {v['outcome']}  {v['ts']}")
    return "\n".join(lines)

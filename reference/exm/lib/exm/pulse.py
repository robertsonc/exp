"""The Pulse board's rules in Python, for the alerter (alert.py).

A line-for-line port of static/pulse-core.js; test/parity.sh runs both on the
same real results and fails on any difference. Events are web.compact() dicts.
Times are epoch milliseconds, as in the page.
"""
from __future__ import annotations

import datetime

LANES = ["Network", "DHCP", "DNS", "Internet", "Wi-Fi"]
CADENCE = [10000, 10000, 10000, 40000, 10000]
STATE_WINDOW = [30000, 30000, 30000, 120000, 30000]
RECENT = 60000
TRACE_HOLD = 30000


def ms(iso: str) -> int:
    return int(datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000)


def cls(o):
    return "ok" if o == "ok" else "slow" if o == "degraded" else "fail" if o in ("fail", "portal") else None


def find_last(a, f):
    for x in reversed(a):
        if f(x):
            return x
    return None


def beats(pool: list, lane: int) -> list:
    evs = [e for e in pool if e.get("l") == lane]
    if lane != 3:
        return [{"t": ms(e["w"]), "o": cls(e.get("o")), "items": [e]} for e in evs if cls(e.get("o"))]
    out, open_ = [], {}
    for e in evs:
        t = ms(e["w"])
        if e.get("k") == "speedtest":
            out.append({"t": t, "items": [e]})
            continue
        g = open_.get(e.get("c"))
        if g and t - g["t"] < 30000:
            g["items"].append(e)
            g["t"] = t
        else:
            ng = {"t": t, "items": [e]}
            open_[e.get("c")] = ng
            out.append(ng)
    for g in out:
        k = [x for x in (cls(e.get("o")) for e in g["items"]) if x]
        f = k.count("fail")
        g["o"] = None if not k else ("fail" if f * 2 >= len(k) else "slow" if (f or "slow" in k) else "ok")
    return sorted((b for b in out if b["o"]), key=lambda b: b["t"])


def state_of(bs: list, lane: int, t: int) -> dict:
    r = [b for b in bs if b["t"] <= t and t - b["t"] <= STATE_WINDOW[lane]]
    if not r:
        return {"s": "unk", "n": 0, "f": 0, "d": 0}
    f = sum(b["o"] == "fail" for b in r)
    d = sum(b["o"] == "slow" for b in r)
    s = "ok"
    if f * 2 >= len(r):
        s = "fail"
    elif f or (d if lane < 3 else d * 3 >= len(r)):
        s = "warn"
    return {"s": s, "n": len(r), "f": f, "d": d}


def since_of(bs: list, fails_only: bool) -> dict:
    ok_run, earliest, found = 0, None, False
    for b in reversed(bs):
        bad = b["o"] == "fail" if fails_only else b["o"] != "ok"
        if not bad:
            ok_run += 1
            if ok_run >= 3:
                found = True
                break
        else:
            ok_run, earliest = 0, b["t"]
    return {"t": earliest, "open": earliest is not None and not found}


def series(bs: list, lane: int, start: int, t: int) -> list:
    return [{"t": b["t"], "s": state_of(bs, lane, b["t"])["s"]} for b in bs if start <= b["t"] <= t]


def last_outage(bs: list, lane: int, t: int, within: int):
    ser = series(bs, lane, t - within, t)
    if not ser or ser[-1]["s"] == "fail":
        return None
    k = max((i for i, x in enumerate(ser) if x["s"] == "fail"), default=-1)
    if k < 0:
        return None
    s = since_of([b for b in bs if b["t"] <= ser[k]["t"]], True)
    return {"start": s["t"], "end": ser[k + 1]["t"], "open": s["open"]}


def flaps(bs: list, lane: int, t: int, span: int) -> int:
    ser = series(bs, lane, t - span, t)
    return sum(1 for i in range(1, len(ser)) if ser[i]["s"] == "fail" and ser[i - 1]["s"] != "fail")


def where_of(V: list, t: int, st: list):
    def bad(i):
        return st[i]["s"] in ("fail", "warn")

    if not any(bad(i) for i in range(5)):
        return None

    def recent(k):
        return find_last(V, lambda e: e.get("k") == k and t - ms(e["w"]) <= RECENT)

    g, d, w = recent("gateway"), recent("dns_hb"), recent("wifi_hb")

    def path(k):                  # a lost trace (rate limiting) doesn't outweigh one that got through recently
        last = recent(k)
        if not last or last.get("rc"):
            return last
        ok = find_last(V, lambda e: e.get("k") == k and e.get("rc") and t - ms(e["w"]) <= TRACE_HOLD)
        return dict(last, rc=True, dt=ok.get("dt")) if ok else last

    tr, tc = path("trace"), path("trace_ctl")
    raw_tr = recent("trace")              # both resolvers silent corroborate a failed traceroute
    if raw_tr and not raw_tr.get("rc") and d and d.get("o") == "fail" and d.get("ao") is False:
        tr = raw_tr
    dh = find_last(V, lambda e: e.get("k") == "dhcp_hb" and e.get("sv"))
    w_on = bool(w and (not w.get("tg") or w.get("sd") == w.get("tg")) and w.get("sd"))
    net_fail = st[0]["s"] == "fail"
    if bad(0) and g:
        nl, ug = g.get("nl") or [], g.get("ug") or []
        if nl and len(nl) * 2 >= (g.get("n") or 1):
            return {"seg": "link", "ports": nl, "n": g.get("n")}
        if ug:
            ip = ug[0][0]
            if w_on and w.get("gk"):
                return {"seg": "switch", "ip": ip}
            if w_on and not w.get("gk"):
                return {"seg": "gateway", "ip": ip}
            return {"seg": "lan", "ip": ip}
        if nl:
            return {"seg": "link", "ports": nl, "n": g.get("n")}
    if (bad(2) or bad(3)) and not net_fail:
        if tr and not tr.get("rc"):
            if tc and tc.get("rc"):
                return {"seg": "edge", "lh": tr.get("lh"), "lt": tr.get("lt"), "target": tr.get("g")}
            if tc and not tc.get("rc"):
                return {"seg": "isp", "lh": tr.get("lh"), "lt": tr.get("lt"), "clh": tc.get("lh"), "target": tr.get("g")}
            return {"seg": "wan", "lh": tr.get("lh"), "lt": tr.get("lt"), "target": tr.get("g")}
        if bad(2) and d and d.get("o") == "fail":
            if d.get("ao"):
                return {"seg": "resolver", "sx": d.get("sx"), "ax": d.get("ax")}
            if tr and tr.get("rc"):
                return {"seg": "dns_path", "sx": d.get("sx"), "ax": d.get("ax")}
        if bad(3) and not bad(2) and tr and tr.get("rc"):
            return {"seg": "apps", "target": tr.get("g")}
    if bad(1) and not net_fail:
        return {"seg": "dhcp", "sv": dh.get("sv") if dh else None}
    if bad(4) and w and not any(bad(i) for i in range(4)):
        if not w_on:
            return {"seg": "ssid", "tg": w.get("tg"), "sd": w.get("sd")}
        if not w.get("gk"):
            return {"seg": "wifi"}
    return None


def states(pool: list, t: int) -> tuple[list, list]:
    """Beats and line states at t for all five lines."""
    bsets = [[b for b in beats(pool, i) if b["t"] <= t] for i in range(5)]
    return bsets, [state_of(bs, i, t) for i, bs in enumerate(bsets)]

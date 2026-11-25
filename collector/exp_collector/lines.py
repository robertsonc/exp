"""The site lines board (CR-site-lines-board): one line per network, one station per check, one train per probe port.

Pure: ``site_lines(evaluations, ports, at)`` turns the rules engine's per-probe Evaluations (live or time travel)
into the ``exp.lines/1`` document. Same evaluations in, same board out; the dashboard only renders it (decision D3).

Per port, every station is judged by the rules engine on that port's own records at the port's own cadence
(CR-heartbeat-cadence), then mapped onto the board's words:

* ``stopped``     the station's state is ``fail``;
* ``confirming``  ``warn`` (some checks failed or were slow inside the window);
* ``hollow``      ``ok``, but the newest check failed (one miss parks a hollow marker and changes nothing else);
* ``verifying``   ``ok`` again, within VERIFY_MS (at least 12 beats) of the end of an outage;
* ``untestable``  a station after the port's first stopped station (it cannot be tested, it did not fail);
* ``na``          Wi-Fi on a wired port; ``unknown`` no result in the window.

Findings group ports by pattern (the prototype's ring / multi / arc / spoke) per station; the out-of-band reference
network is reported beside production, never counted as "everyone". The headline is the first finding's, in words.
Untrusted input: names are slugs from the collector config; record free text never reaches this module's output.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .config import BoardPort
from .rules import (
    BEAT_FAIL,
    FAIL,
    LINE_SPECS,
    STREAMS,
    WARN,
    BeatStore,
    Evaluation,
    cadence_ms,
    evaluate,
    series,
    window_for,
)

SCHEMA = "exp.lines/1"
STATIONS: tuple[str, ...] = ("wifi", "dhcp", "network", "dns", "internet", "apps")
LABEL = {"wifi": "Wi-Fi", "dhcp": "DHCP", "network": "Network", "dns": "DNS", "internet": "Internet", "apps": "Apps"}
NOUN = {
    "wifi": "Wi-Fi",
    "dhcp": "DHCP",
    "network": "the gateway",
    "dns": "DNS",
    "internet": "the internet",
    "apps": "the web by name",
}
ERR = {
    "wifi": "no association",
    "dhcp": "no DHCP lease",
    "network": "gateway not answering",
    "dns": "DNS failing",
    "internet": "no internet path",
    "apps": "HTTPS by name failing",
}
# What each station needs to be testable. The internet line is measured by IP (ping, traceroute), so it does not need
# DNS: with DNS stopped it is still measured, and that is the evidence that tells a resolver fault from a dead path.
DEPENDS: dict[str, tuple[str, ...]] = {"wifi": (), "dhcp": ("wifi",), "network": ("dhcp",), "dns": ("network",),
                                       "internet": ("network",), "apps": ("dns", "internet")}
BAD = ("stopped", "confirming", "verifying")
RANK = {"stopped": 3, "confirming": 2, "verifying": 1}
VERIFY_MS = 120_000  # the prototype's 12 clean checks at 10 s; never shorter than 12 beats of the real cadence
STALE_MIN_MS = 30_000  # spec 04 section 4; a port is silent after 3 missed beats, never sooner than this
RING_SHARE = 0.8


# ------------------------------------------------------------------------------------------------ per port
def port_store(store: BeatStore, port: str, at: int) -> BeatStore:
    """The records of one port (labels.port), at or before `at`, as their own BeatStore."""
    out = BeatStore()
    for name in STREAMS:
        for g in store.groups(name):
            if g.t0 > at:
                break
            for r in g.recs:
                if r.ts <= at and r.port == port:
                    out.add(r)
    return out


def _station(le: Any, at: int, cadence: int | None) -> dict[str, Any]:
    if le is None or le.state == "unknown" or not le.n:
        return {"state": "unknown"}
    if le.state == FAIL:
        return {"state": "stopped", "since": le.since}
    if le.state == WARN:
        return {"state": "confirming", "since": le.since}
    hi = len(le.ts)
    while hi and le.ts[hi - 1] > at:
        hi -= 1
    if hi and le.beats[hi - 1].v == BEAT_FAIL:
        return {"state": "hollow"}
    lo = le.last_outage
    hold = max(VERIFY_MS, 12 * (cadence or 0))
    if lo is not None and not lo.open and at - lo.end <= hold:
        return {"state": "verifying", "since": lo.end, "clean_ms": at - lo.end, "hold_ms": hold}
    return {"state": "ok"}


@dataclass
class PortView:
    probe: str
    port: BoardPort
    silent: bool
    newest: int | None
    cadence: int | None
    st: dict[str, dict[str, Any]]

    @property
    def wired(self) -> bool:
        return self.port.media == "wired"

    def state(self, key: str) -> str:
        return str(self.st[key]["state"])

    def doc(self, at: int) -> dict[str, Any]:
        return {
            "probe": self.probe,
            "port": self.port.id,
            "media": self.port.media,
            "silent": self.silent,
            "newest_s": None if self.newest is None else round(max(0, at - self.newest) / 1000, 1),
            "cadence_s": None if self.cadence is None else round(self.cadence / 1000, 1),
            "stations": {k: {kk: vv for kk, vv in v.items() if vv is not None} for k, v in self.st.items()},
        }


def view_port(ev: Evaluation, bp: BoardPort, at: int) -> PortView:
    ps = port_store(ev.store, bp.id, at)
    keys = [k for k in STATIONS if not (k == "wifi" and bp.media == "wired")]
    pe = evaluate(ps, at, probe=ev.probe, site=ev.site, lines=keys)
    cad = pe.cadence_ms
    newest = ps.newest_ts(at)
    stale = max(STALE_MIN_MS, 3 * (cad or 10_000))
    silent = newest is None or at - newest > stale
    st: dict[str, dict[str, Any]] = {}
    for k in STATIONS:                                  # STATIONS is in dependency order
        if k == "wifi" and bp.media == "wired":
            st[k] = {"state": "na"}
        elif silent:
            st[k] = {"state": "unknown"}
        elif any(st[d]["state"] in ("stopped", "untestable") for d in DEPENDS[k]):
            st[k] = {"state": "untestable"}
        else:
            st[k] = _station(pe.lines.get(k), at, cad)
    return PortView(ev.probe, bp, silent, newest, cad, st)


# ------------------------------------------------------------------------------------------------ findings
def _worst(states: Iterable[str]) -> str:
    best, r = "ok", 0
    for s in states:
        if RANK.get(s, 0) > r:
            best, r = s, RANK[s]
    return best


def _phase(ports: Sequence[PortView], key: str) -> str:
    sts = [p.state(key) for p in ports]
    if sum(s == "verifying" for s in sts) * 2 > len(sts):
        return "verifying"
    if "stopped" in sts:
        return "down"
    if "confirming" in sts:
        return "failing"
    return "verifying"


def _usable(p: PortView, key: str) -> bool:
    return not p.silent and p.state(key) not in ("na", "untestable", "unknown")


def _evidence(key: str, ports: Sequence[PortView]) -> dict[str, Any] | None:
    """By-IP reachability beside a by-name failure (DNS, apps): tells names from a dead path."""
    if key not in ("dns", "apps"):
        return None
    t = [p for p in ports if not p.silent and p.state("internet") not in ("unknown", "untestable", "na")]
    if not t:
        return None
    ok = sum(p.state("internet") in ("ok", "hollow") for p in t)
    kind = "names" if ok >= 0.8 * len(t) else "path" if ok <= 0.2 * len(t) else "mixed"
    return {"by_ip_ok": ok, "n": len(t), "kind": kind}


def _since(ports: Sequence[PortView], key: str) -> int | None:
    s = [p.st[key].get("since") for p in ports]
    s2 = [x for x in s if isinstance(x, int)]
    return min(s2) if s2 else None


def findings(views: Sequence[PortView]) -> list[dict[str, Any]]:
    prod_nets = sorted({v.port.network for v in views if not v.port.reference})
    out: list[dict[str, Any]] = []
    for key in STATIONS:
        test = [v for v in views if not v.port.reference and _usable(v, key)]
        bad = [v for v in test if v.state(key) in BAD]
        ref_t = [v for v in views if v.port.reference and _usable(v, key)]
        ref_b = [v for v in ref_t if v.state(key) in BAD]
        ref = "unknown" if not ref_t else "bad" if len(ref_b) == len(ref_t) else "mixed" if ref_b else "ok"
        hit = sorted({v.port.network for v in bad})
        groups: list[dict[str, Any]] = []
        if bad and len(bad) >= RING_SHARE * len(test) and len(hit) >= min(3, len(prod_nets)):
            groups.append(
                {"scope": "ring", "networks": hit, "media": None, "ports": bad, "total": len(test), "ref": ref}
            )
        else:
            for net in hit:
                groups += _arcs(
                    key,
                    [v for v in test if v.port.network == net],
                    [v for v in bad if v.port.network == net],
                    [v for v in views if v.port.network == net and not v.silent],
                )
        if ref_b and not (groups and groups[0]["scope"] == "ring" and ref == "bad"):
            for g in _arcs(key, ref_t, ref_b, [v for v in views if v.port.reference and not v.silent]):
                g["reference"] = True
                groups.append(g)
        # the same pattern on several networks (same station, same medium) is one finding, not several
        arcs = [g for g in groups if g["scope"] == "arc" and not g.get("reference")]
        by_media: dict[str | None, list[dict[str, Any]]] = {}
        for g in arcs:
            by_media.setdefault(g["media"], []).append(g)
        for media, parts in by_media.items():
            if len(parts) > 1:
                groups = [g for g in groups if g not in parts]
                groups.append(
                    {
                        "scope": "multi",
                        "networks": [n for g in parts for n in g["networks"]],
                        "media": media,
                        "ports": [p for g in parts for p in g["ports"]],
                        "total": sum(g["total"] for g in parts),
                        "onset_spread_s": _spread(key, parts),
                    }
                )
        for g in groups:
            g["station"] = key
            g["phase"] = _phase(g["ports"], key)
            g["since"] = _since(g["ports"], key)
            g["evidence"] = _evidence(key, g["ports"])
        out += [g for g in groups if not (g["scope"] == "spoke" and g["phase"] == "failing")]
    rank = {"ring": 0, "multi": 1, "arc": 2, "spoke": 3}
    out.sort(
        key=lambda g: (
            g["phase"] == "verifying",
            bool(g.get("reference")),
            rank[g["scope"]],
            STATIONS.index(g["station"]),
        )
    )
    return out


def _arcs(key: str, st: list[PortView], sb: list[PortView], live: list[PortView]) -> list[dict[str, Any]]:
    net = sb[0].port.network
    wired = [v for v in st if v.wired]
    wless = [v for v in st if not v.wired]
    has_wired = any(v.wired for v in live)

    def only(m: list[PortView]) -> bool:
        return len(m) >= 2 and len(sb) == len(m) and all(v in sb for v in m)

    full = len(sb) == len(st) and len(st) >= 2
    media = (
        ("wireless" if key == "wifi" and has_wired else None)
        if full
        else "wireless"
        if only(wless) and has_wired
        else "wired"
        if only(wired) and wless
        else None
    )
    if full or media:
        total = len(wless) if media == "wireless" else len(wired) if media == "wired" else len(st)
        return [{"scope": "arc", "networks": [net], "media": media, "ports": sb, "total": total}]
    return [{"scope": "spoke", "networks": [net], "media": None, "ports": [v], "total": len(st)} for v in sb]


def _spread(key: str, parts: Sequence[Mapping[str, Any]]) -> int:
    on = [_since(g["ports"], key) for g in parts]
    t = [x for x in on if x is not None]
    return round((max(t) - min(t)) / 1000) if len(t) > 1 else 0


# ------------------------------------------------------------------------------------------------ words
def _list(a: Sequence[str]) -> str:
    a = list(a)
    return "" if not a else a[0] if len(a) == 1 else ", ".join(a[:-1]) + " and " + a[-1]


def _name(net: str) -> str:
    return net.replace("-", " ").title()


WHY = {
    "wifi": "{s} WLAN: the SSID or its APs.",
    "dhcp": "{s} addressing: the scope, the relay or the DHCP server for that VLAN.",
    "network": "{s} first hop: the gateway, SVI or trunk.",
    "dns": "{s} resolver path.",
    "internet": "{s} internet policy or edge path: NAT, firewall rule or steering.",
    "apps": "{s} web path: web policy, TLS inspection or a proxy.",
}
SHARED = {
    "wifi": "a controller, an AP group or the RADIUS path",
    "dhcp": "a DHCP server, a scope set or a relay",
    "network": "a distribution hop or gateway pair",
    "dns": "a resolver, or the path to it",
    "internet": "an internet policy, a firewall context or an uplink",
    "apps": "a web policy or a proxy",
}


def headline(fs: Sequence[Mapping[str, Any]], views: Sequence[PortView], at: int) -> dict[str, str]:
    silent = [v for v in views if v.silent]
    live = [v for v in views if not v.silent]
    if not fs:
        if not views:
            return {
                "phase": "ok",
                "chip": "OBSERVED",
                "h": "No probe port is on the board yet.",
                "sub": "Give probe ports a network on their component page to put them on the board.",
                "why": "",
            }
        if silent:
            names = _list([f"{v.probe}:{v.port.id}" for v in silent[:4]]) + (" and others" if len(silent) > 4 else "")
            return {
                "phase": "ok",
                "chip": "OBSERVED",
                "h": "One port went quiet." if len(silent) == 1 else f"{len(silent)} ports went quiet.",
                "sub": f"{names} stopped reporting. The other {len(live)} agree on every line.",
                "why": "A gap in what we can see, not a fault anyone can feel.",
            }
        return {
            "phase": "ok",
            "chip": "OBSERVED",
            "h": "All good. Nobody push a change.",
            "sub": f"All {len(views)} ports agree on every line.",
            "why": "No unresolved condition.",
        }
    f = fs[0]
    k = f["station"]
    who = (
        "Everyone"
        if f["scope"] == "ring"
        else _list([_name(n) for n in f["networks"]])
        if f["scope"] in ("multi", "arc")
        else f"{f['ports'][0].probe}:{f['ports'][0].port.id}"
    )
    media = f" {f['media']}" if f.get("media") and k != "wifi" else ""
    behind = [
        LABEL[s] for s in STATIONS[STATIONS.index(k) + 1 :] if any(p.state(s) == "untestable" for p in f["ports"])
    ]
    shadow = (
        f" {_list(behind)} behind it {'are' if len(behind) > 1 else 'is'} untestable, not failed." if behind else ""
    )
    n, total = len(f["ports"]), f["total"]
    ev = f.get("evidence")
    if f["phase"] == "verifying":
        subject = LABEL[k] if f["scope"] == "ring" else who
        h = f"{subject} {'are' if f['scope'] == 'multi' else 'is'} back. Waiting for it to hold."
        sub = f"{n} of {total} affected ports pass {LABEL[k]} again."
        why = "Holding before calling it: a relapse now reopens the same finding."
        return {"phase": "verifying", "chip": "VERIFYING", "h": h, "sub": sub, "why": why}
    if f["scope"] == "ring":
        ref = f.get("ref")
        if ref == "bad":
            h = (
                "The internet is down. For once it isn't us."
                if k == "internet"
                else f"{LABEL[k]} is down everywhere, the reference too."
            )
            why = ("Outside both paths: the destinations themselves, or something upstream of production and the "
                   "reference alike.")
        else:
            h = "No internet. Just us and the LAN." if k == "internet" else f"{LABEL[k]} is down for everyone."
            why = (
                "Ours: the production edge or its uplink; the reference reaches the same destinations on its own path."
                if ref == "ok"
                else "Upstream of every network. Without a reference path, our edge cannot be told from the outside."
            )
        sub = (
            f"{n} of {total} production ports fail {LABEL[k]}, on every network. "
            + (
                "The reference passes on its own path."
                if ref == "ok"
                else "The reference fails too."
                if ref == "bad"
                else "No reference is reporting."
            )
            + shadow
        )
    elif f["scope"] == "multi":
        h = f"{who} lost {NOUN[k]}. Same failure, {len(f['networks'])} networks."
        spread = f.get("onset_spread_s", 0)
        sub = (
            f"{n} of {total}{media} ports on {who} fail {LABEL[k]}. "
            + ("Started together." if spread <= 2 else f"Started {spread} s apart.")
            + shadow
        )
        why = f"Look at what {who} share: {SHARED[k]}. Seen together, not proven."
    elif f["scope"] == "arc" and f.get("reference"):
        h = f"The reference lost {NOUN[k]}. Production is fine."
        sub = f"{n} of {total} reference ports fail {LABEL[k]}. No attendee is on that path.{shadow}"
        why = "Until the reference returns, an upstream fault cannot be told from an outside one."
    elif f["scope"] == "arc":
        h = f"{who}{media} lost {NOUN[k]}." + (" Everyone else is fine." if len(fs) == 1 else "")
        sub = f"{n} of {total}{media} {who} ports fail {LABEL[k]}.{shadow}"
        why = WHY[k].format(s=who)
    else:
        p = f["ports"][0]
        h = "One port is having a bad day."
        sub = f"{who} fails {LABEL[k]} ({ERR[k]}); its {total - 1} {_name(p.port.network)} neighbours pass.{shadow}"
        why = (
            "Local to that port: the switch port, the cable or the probe itself."
            if p.wired
            else "Local to that port: RF where it sits, or the probe itself."
        )
    if ev and k == "dns":
        why = (
            f"By IP {ev['by_ip_ok']} of {ev['n']} still reach the internet, so the path is fine: it is the resolver."
            if ev["kind"] == "names"
            else "They cannot get out by IP either: the path is down and DNS is a casualty."
            if ev["kind"] == "path"
            else why
        )
    elif ev and k == "apps":
        why = (
            f"By IP {ev['by_ip_ok']} of {ev['n']} still get out; HTTPS by name does not: web policy, TLS "
            "inspection or a proxy."
            if ev["kind"] == "names"
            else why
        )
    if len(fs) > 1:
        why += (
            " Also open: "
            + _list(
                [
                    f"{_list([_name(n) for n in x['networks']]) or 'everyone'} at {LABEL[x['station']]}"
                    for x in fs[1:3]
                ]
            )
            + "."
        )
    return {
        "phase": "failing" if f["phase"] == "failing" else "down",
        "chip": "INVESTIGATING",
        "h": h,
        "sub": sub,
        "why": why,
    }


# ------------------------------------------------------------------------------------------------ the document
def _finding_doc(f: Mapping[str, Any], at: int) -> dict[str, Any]:
    return {
        "scope": f["scope"],
        "station": f["station"],
        "networks": list(f["networks"]),
        "media": f.get("media"),
        "reference": bool(f.get("reference")),
        "phase": f["phase"],
        "ports": [
            {"probe": p.probe, "port": p.port.id, "network": p.port.network, "state": p.state(f["station"])}
            for p in f["ports"]
        ],
        "affected": len(f["ports"]),
        "total": f["total"],
        "since_s": None if f.get("since") is None else round(max(0, at - f["since"]) / 1000),
        "evidence": f.get("evidence"),
        "onset_spread_s": f.get("onset_spread_s"),
    }


def site_lines(
    evaluations: Mapping[str, Evaluation],
    ports: Mapping[str, Sequence[BoardPort]],
    site: str,
    at: int,
    *,
    live: bool = False,
) -> dict[str, Any]:
    """exp.lines/1 for one site. `evaluations`: probe -> Evaluation at `at`; `ports`: probe -> its board ports."""
    views: list[PortView] = []
    for probe in sorted(ports):
        ev = evaluations.get(probe)
        if ev is None:
            continue
        views += [view_port(ev, bp, at) for bp in ports[probe]]
    fs = findings(views)
    nets: dict[str, list[PortView]] = {}
    for v in views:
        nets.setdefault(v.port.network, []).append(v)
    net_docs = []
    for net in sorted(nets, key=lambda n: (any(v.port.reference for v in nets[n]), n)):
        vs = nets[net]
        live_vs = [v for v in vs if not v.silent]
        stations = {}
        closed_at = None
        for k in STATIONS:
            cs = [v for v in live_vs if v.state(k) != "na"]
            bad = [v for v in cs if v.state(k) in BAD]
            unt = [v for v in cs if v.state(k) == "untestable"]
            agg = (
                _worst(v.state(k) for v in bad)
                if bad
                else "untestable"
                if cs and len(unt) == len(cs)
                else "ok"
                if cs
                else "na"
            )
            stations[k] = {"state": agg, "affected": len(bad), "of": len(cs)}
        for i, k in enumerate(STATIONS):
            rest = [v.state(x) for x in STATIONS[i:] for v in live_vs if v.state(x) != "na"]
            if rest and all(s in ("stopped", "untestable") for s in rest):
                closed_at = k
                break
        through = sum(all(v.state(k) in ("ok", "hollow", "na") for k in STATIONS) for v in live_vs)
        net_docs.append(
            {
                "id": net,
                "name": _name(net),
                "reference": any(v.port.reference for v in vs),
                "through": through,
                "ports_total": len(vs),
                "silent": len(vs) - len(live_vs),
                "closed_at": closed_at,
                "stations": stations,
                "ports": [v.doc(at) for v in vs],
            }
        )
    coverage = [
        f"{d['name']} has no port reporting" for d in net_docs if d["ports_total"] and d["silent"] == d["ports_total"]
    ]
    cads = [v.cadence for v in views if v.cadence]
    return {
        "schema": SCHEMA,
        "site": site,
        "at": _iso(at),
        "live": live,
        "stations": [{"key": k, "label": LABEL[k]} for k in STATIONS],
        "cadence_s": None if not cads else round(min(cads) / 1000, 1),
        "headline": headline(fs, views, at),
        "networks": net_docs,
        "findings": [_finding_doc(f, at) for f in fs],
        "coverage": coverage,
    }


# ------------------------------------------------------------------------------------------------ timeline
def timeline(
    evaluations: Mapping[str, Evaluation],
    ports: Mapping[str, Sequence[BoardPort]],
    start: int,
    end: int,
    step_ms: int = 10_000,
) -> dict[str, Any]:
    """Per network and step: the worst station state of its ports and the share of ports not passing (the ribbon)."""
    steps = max(1, min(2160, (end - start) // step_ms + 1))
    per_net: dict[str, list[list[str]]] = {}
    for probe in sorted(ports):
        ev = evaluations.get(probe)
        if ev is None:
            continue
        for bp in ports[probe]:
            ps = port_store(ev.store, bp.id, end)
            marks = ["ok"] * steps
            seen = [False] * steps
            for k in STATIONS:
                if k == "wifi" and bp.media == "wired":
                    continue
                bs, ts = ps.line(k)
                if not bs:
                    continue
                cad = cadence_ms(ts, end)
                ser = (
                    series(bs, k, start, end, ts)
                    if window_for(k, cad) == LINE_SPECS[k].window_ms
                    else _series_w(bs, ts, k, start, end, window_for(k, cad))
                )
                j = 0
                cur = None
                for i in range(steps):
                    t = start + i * step_ms
                    while j < len(ser) and ser[j][0] <= t:
                        cur = ser[j][1]
                        j += 1
                    if cur is None:
                        continue
                    seen[i] = True
                    mark = "stopped" if cur == FAIL else "confirming" if cur == WARN else "ok"
                    if RANK.get(mark, 0) > RANK.get(marks[i], 0):
                        marks[i] = mark
            per_net.setdefault(bp.network, []).append(
                [m if s else "unknown" for m, s in zip(marks, seen, strict=True)]
            )
    out = []
    for net in sorted(per_net):
        rows = per_net[net]
        pts = []
        for i in range(steps):
            col = [r[i] for r in rows]
            known = [c for c in col if c != "unknown"]
            bad = [c for c in known if c in BAD]
            pts.append(
                {
                    "t": _iso(start + i * step_ms),
                    "state": _worst(bad) if bad else "ok" if known else "unknown",
                    "share": round(len(bad) / len(known), 3) if known else 0.0,
                    "known": len(known),
                }
            )
        out.append({"network": net, "points": pts})
    return {
        "schema": "exp.lines-timeline/1",
        "from": _iso(start),
        "to": _iso(end),
        "step_s": step_ms // 1000,
        "networks": out,
    }


def _series_w(bs: Any, ts: Any, k: str, start: int, end: int, window: int) -> list[tuple[int, str]]:
    from .rules import _series

    return [(bt, s) for _, bt, s in _series(bs, ts, k, start, end, window)]


def _iso(ms: int) -> str:
    import datetime

    return (
        datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )

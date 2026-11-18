"""Verdict text: headline + sub in the `plain` and `sysadmin` voices, and the "where" sentence
(03-collector.md section 5; ported from reference/exm/lib/exm/static/pulse.html verdictText / LINES /
whereText and reference/exm/lib/exm/alert.py HEAD / BACK / QUIP_* / WHERE).

The rules (rules.py) decide what is true; this module decides how it is said. Same facts in both voices:
`plain` is the factual line, `sysadmin` adds the board's dry humour (a quip chosen deterministically
from when the incident started, so it does not change every second).

EXM bugs fixed here instead of ported:
  * doubled punctuation ("ACME_CORP..", "1 a.m..") -- every sentence goes through ``tidy`` and every
    interpolated value through ``clean`` (trailing punctuation stripped, runs collapsed);
  * a traceroute "from null" -- when no client could run it, the text says so;
  * "No error text in the last 60 seconds" next to a line that lists errors -- never emitted: a line with
    no error text states how many checks failed instead;
  * overview and board disagreeing -- one implementation, so impossible.

Everything probe-supplied is untrusted: ``clean`` removes control characters, collapses whitespace and
bounds the length. Escaping for chat markup is done where the text is posted (alerts.py).
"""
from __future__ import annotations

import datetime
import re
import zoneinfo
from collections.abc import Mapping, Sequence
from typing import Any

from .rules import LABELS, LINE_SPECS, Evaluation, norm_error

STALE_MS = 90_000          # no records for this long: nothing on the screen is current
VOICES = ("plain", "sysadmin")

_PUNCT = ".!?,;:"
_PUNCT_RUN = re.compile(r"([.!?,;:])(?:\s*[.!?,;:])+")
_SPACE_BEFORE = re.compile(r"\s+([.!?,;:])")
_WS = re.compile(r"\s+")
_PLACEHOLDER = re.compile(r"\{(\w+)\}")


class Raw(str):
    """A value this module built itself (not probe text): inserted as is."""

    __slots__ = ()


# ------------------------------------------------------------------------------------------ text tools
def clean(v: object, limit: int = 80) -> str:
    """Make one probe-supplied value safe to put inside a sentence: printable characters only, one-space
    separation, no punctuation runs, no trailing sentence punctuation, bounded length."""
    if v is None:
        return ""
    s = "".join(ch if ch.isprintable() else " " for ch in str(v))
    s = _PUNCT_RUN.sub(r"\1", _WS.sub(" ", s).strip())
    if len(s) > limit:
        s = s[: limit - 1].rstrip() + "…"
    return s.strip(_PUNCT + " ")


def tidy(s: str) -> str:
    """Whitespace and punctuation hygiene of a finished text: one space between words, none before
    punctuation, and never two punctuation marks in a row ("..", "?.", ",.")."""
    s = _WS.sub(" ", s).strip()
    s = _SPACE_BEFORE.sub(r"\1", s)
    return _PUNCT_RUN.sub(r"\1", s)


def fin(s: str) -> str:
    """One sentence with exactly one terminal mark ('' stays '')."""
    s = tidy(s)
    if not s:
        return ""
    return s if s[-1] in ".!?" else s + "."


def cap(s: str) -> str:
    return s[:1].upper() + s[1:]


def join_words(a: Sequence[str]) -> str:
    return "".join(a) if len(a) < 2 else ", ".join(a[:-1]) + " and " + a[-1]


def few(a: Sequence[str]) -> str:
    return ", ".join(a[:3]) + f" +{len(a) - 3}" if len(a) > 4 else ", ".join(a)


def clip(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def text(*parts: str) -> str:
    """Join sentences (each one already ends in its own mark or is empty) and tidy the result."""
    return tidy(" ".join(p for p in parts if p))


def dur(ms: float) -> str:
    """Duration in words (# ported from pulse.html dur): seconds below 90 s, minutes below 90 min."""
    s = max(0, round(ms / 1000))
    if s < 90:
        return f"{s} seconds"
    m = round(s / 60)
    if m < 90:
        return f"{m} minutes"
    h, r = divmod(m, 60)
    return f"{h} hour{'s' if h != 1 else ''}" + (f" {r} minutes" if r else "")


def _zone(tz: str) -> datetime.tzinfo:
    try:
        return zoneinfo.ZoneInfo(tz)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError, OSError):
        return datetime.timezone.utc


def local_time(ms: int, tz: str) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(ms / 1000, _zone(tz))


def hms(ms: int, tz: str) -> str:
    return local_time(ms, tz).strftime("%H:%M:%S")


def hhmm(ms: int, tz: str) -> str:
    return local_time(ms, tz).strftime("%H:%M")


def hour_text(ms: int, tz: str) -> str:
    h = local_time(ms, tz).hour
    return "midnight" if h == 0 else "noon" if h == 12 else f"{h % 12} {'a.m.' if h < 12 else 'p.m.'}"


def fnv(s: str) -> int:
    """FNV-1a over UTF-16 code units: the EXM board's hash, so quips are picked the same way."""
    h = 2166136261
    data = s.encode("utf-16-le")
    for i in range(0, len(data), 2):
        h ^= data[i] | (data[i + 1] << 8)
        h = (h * 16777619) & 0xFFFFFFFF
    return h


def one(pool: Sequence[str], seed: object) -> str:
    return pool[fnv(str(seed)) % len(pool)]


def fill(template: str, f: Mapping[str, object], defaults: Mapping[str, str] | None = None) -> str:
    """{name} substitution. Values are cleaned unless they are ``Raw``; a missing/empty value uses its
    default (or nothing)."""
    d = defaults or {}

    def sub(m: re.Match[str]) -> str:
        v = f.get(m.group(1))
        if isinstance(v, Raw):
            return str(v)
        c = clean(v) if v is not None else ""
        return c or d.get(m.group(1), "")

    return tidy(_PLACEHOLDER.sub(sub, template))


_DEFAULTS = {"ip": "the gateway", "ports": "some ports", "edge": "edge", "lh": "the first hop", "lt": "unknown",
             "target": "the target", "sx": "the resolver", "ax": "the alternate", "tg": "its network",
             "sd": "another network"}


# ------------------------------------------------------------------------------------------ tables
# The board's lines (# ported from reference/exm/lib/exm/static/pulse.html LINES). Same facts as the plain
# headline; the sysadmin voice picks one of these (seeded by when the problem began).
LINES: dict[str, Any] = {
    "netGw": {
        "fresh": ["The gateway has left the building.", "Nobody can reach the gateway.",
                  "The gateway has stopped taking calls.", "The gateway is not answering. Rude."],
        "long": ["The gateway is still gone.", "Still no gateway. It isn't coming back on its own.",
                 "The gateway has been gone a while. Somebody go and look."],
        "epic": ["The gateway has been gone over an hour. This is a site visit now.",
                 "Still no gateway. At this point, bring a ladder."],
    },
    "netLink": {
        "fresh": ["Somebody unplugged something.", "No link. That's a cable, not a config.", "The ports went dark.",
                  "Link down. Put the cable back."],
        "long": ["Still no link. Cables don't heal.", "The ports are still dark. The cable is still out."],
    },
    "netOther": {"fresh": ["The network is falling over.", "The network is coming apart."],
                 "long": ["The network is still falling over."]},
    "dhcpDns": {
        "fresh": ["DHCP and DNS are both down. Bold.", "No addresses, no names. Impressive.",
                  "DHCP and DNS went down together. Cute."],
        "long": ["DHCP and DNS are still down. Someone's having a night.",
                 "Still no DHCP and no DNS. The users have noticed."],
    },
    "dhcp": {
        "fresh": ["DHCP has stopped handing out addresses.", "DHCP is out of office.",
                  "No offers. DHCP has gone quiet.", "DHCP has closed the doors."],
        "long": ["DHCP is still not answering. New arrivals are queueing at 169.254.",
                 "Still no DHCP. Nobody new gets on."],
    },
    "internet": {
        "fresh": ["The internet is down. No, really.", "We're an intranet now.",
                  "The internet has left the building.", "No internet. Just us and the LAN."],
        "long": ["Still no internet. Have you tried turning it off and on again?",
                 "The internet is still down. Morale is holding. Barely.",
                 "Still offline. The cat videos will have to wait."],
        "epic": ["The internet has been down over an hour. This is a story now.",
                 "Still no internet. Somebody start the incident report."],
    },
    "dns": {
        "fresh": ["It was DNS.", "It's always DNS.", "It's not DNS. There's no way it's DNS. It was DNS.",
                  "DNS. Of course."],
        "long": ["Still DNS. It's always DNS.", "DNS is still down. Nobody is surprised."],
    },
    "dnsNight": ["It's {hour}. Of course it's DNS.", "DNS, at {hour}. Naturally."],
    "wifiOff": {
        "fresh": ["The laptop wandered off to {sd}.", "The test laptop has eloped with {sd}.",
                  "The laptop is on {sd}. It was told not to."],
        "long": ["The laptop is still on {sd}. It isn't coming back by itself.",
                 "Still on {sd}. The AP must still be down."],
    },
    "wifiGone": {"fresh": ["The laptop can't find {tg}.", "{tg} has vanished.", "No {tg} in the air."],
                 "long": ["{tg} is still missing."]},
    "wifiDown": {"fresh": ["Wi-Fi has left the chat.", "The Wi-Fi is down. The laptop is sulking."],
                 "long": ["Wi-Fi is still down."]},
    "pathFail": {"fresh": ["The path to the collector is falling over.", "The path test has given up."],
                 "long": ["The path is still falling over."]},
    "netWarn": ["The network is flaky.", "The network is having a wobble.", "Something keeps unplugging itself."],
    "dhcpWarn": ["DHCP is having a moment.", "DHCP is dropping the odd offer.", "DHCP is mostly awake."],
    "dnsWarn": ["DNS is dropping queries. Of course it is.", "DNS is mostly working. Mostly.",
                "DNS is a bit flaky. Nobody is shocked."],
    "appsFail": ["Some apps are broken. Not ours, presumably.", "A few apps are down. Not my circus.",
                 "Some apps are failing. The internet itself is fine-ish."],
    "appsSlow": ["The internet is crawling.", "Everything is slow. Someone's streaming in 4K.",
                 "The internet is wading through treacle."],
    "netSlow": ["The internet is wobbling.", "The internet is having a moment."],
    "wifiWarn": ["Wi-Fi is limping.", "Wi-Fi is fine-ish.", "Wi-Fi is having an off day."],
    "pathWarn": ["The path is a bit rough.", "The path to the collector is having an off day."],
    "flap": ["{lane} can't make up its mind.", "{lane} keeps falling over and getting back up.",
             "{lane} is flapping. Pick a state, any state."],
    "recovered": ["Back after {dur} down. Zero apologies.", "And we're back. Nobody touch anything.",
                  "Restored after {dur}. Someone owes someone a beer.", "It's back. Act like it never happened.",
                  "Back up after {dur}. Write it down before you forget."],
    "allGood": ["All good. Don't touch anything.", "Nothing is on fire.", "All quiet. Suspiciously quiet.",
                "Uptime is holding. Hands off the config.", "Green across the board. Enjoy it while it lasts.",
                "All good. Nobody push a change.", "Working as designed. For once.", "No news is good news.",
                "All systems nominal. Touch wood."],
    "allGoodNight": ["All quiet. Go get some sleep.", "All good. Even the network's asleep.",
                     "Nothing is broken. Go to bed."],
    "allGoodFriday": ["It's Friday. Don't you dare push that change.", "All good. Read-only Friday is working.",
                      "Green on a Friday. Leave it that way."],
    "laptopAway": ["Wired is fine. The laptop went to lunch.", "Wired is fine. The Wi-Fi laptop has wandered off."],
    "silent": {"fresh": ["Silence for {dur}.", "The probe has gone quiet. Check its pulse."],
               "long": ["Still nothing from the probe. That's not a good sign.",
                        "The probe has been quiet for {dur}. Go and look."]},
    "waiting": ["Waiting on results.", "Results are on their way. Probably."],
}

# "Where" sentences. P: plain / alert wording (# ported from alert.py WHERE and pulse.html whereText);
# X: the sysadmin voice. Placeholders are filled with cleaned values.
WHERE_P: dict[str, str] = {
    "link": "Where: {ports}: no link. A cable or the switch.",
    "ports": "Where: {ports}: no link. A cable or the port.",
    "switch": "Where: the wired side. Wi-Fi reaches {ip}, the ports don't: the switch, its uplink or the VLAN.",
    "gateway": "Where: the gateway or the link to it. Neither wired nor Wi-Fi reach {ip}.",
    "lan": "Where: between the ports and {ip}: the switch or the gateway's LAN side.",
    "edge": "Where: the {edge}. The path stops after {lh} (hop {lt}); the management path reaches {target} around it.",
    "isp": "Where: upstream of the {edge}. The management path can't reach {target} either.",
    "wan": "Where: past the gateway. The path to {target} stops after {lh} (hop {lt}).",
    "resolver": "Where: the resolver. {sx} isn't answering, {ax} is.",
    "dns_path": "Where: DNS on the way out. The path is up, but neither {sx} nor {ax} answers.",
    "dns": "Where: DNS. {sx} isn't answering and nothing else says why.",
    "apps": "Where: the apps or their CDNs. The path and DNS are fine.",
    "dhcp": "Where: the DHCP server{sv}. The gateway answers, offers don't come.",
    "ssid": "Where: the AP or SSID. The laptop can't get on {tg}{sdpart}.",
    "wifi": "Where: the Wi-Fi side: the AP, its uplink or the WLAN. Wired reaches the gateway.",
    "path": "Where: the path test. Loss, delay or jitter on the way to the collector.",
}
WHERE_X: dict[str, str] = {
    "link": "That's a cable. No link on {ports}.",
    "ports": "No link on {ports}. A cable, most likely.",
    "switch": "Wi-Fi gets to {ip}, the wires don't. Look at the switch.",
    "gateway": "Nobody gets to {ip}, wired or wireless. It's the gateway or the cable to it.",
    "lan": "Somewhere between the ports and {ip}. Start with the switch.",
    "edge": "It's the {edge}. The ISP answers around it; our traffic dies after {lh}.",
    "isp": "It's upstream. Even the management path can't get out. Call the ISP and enjoy the hold music.",
    "wan": "Past the gateway: traffic dies after {lh} (hop {lt}).",
    "resolver": "{sx} is ghosting us; {ax} answers fine. Hand out a different resolver.",
    "dns_path": "Something is eating DNS on the way out. The path is up; {sx} and {ax} are both silent.",
    "dns": "DNS is silent and nothing else explains it. Start with {sx}.",
    "apps": "The pipe is fine and DNS is fine. The apps are someone else's problem.",
    "dhcp": "The gateway answers; the DHCP server{sv} doesn't.",
    "ssid": "The laptop can't get on {tg}{sdpart}. Check the AP.",
    "wifi": "Wired reaches the gateway, Wi-Fi doesn't. It's the AP or its uplink.",
    "path": "The path to the collector is rough: loss, delay or jitter. Look between here and there.",
}
SEG_LABEL = {"link": "Link", "ports": "Ports", "switch": "Switch", "gateway": "Gateway", "lan": "LAN", "edge": "Edge",
             "isp": "ISP", "wan": "WAN", "resolver": "Resolver", "dns_path": "DNS path", "dns": "DNS",
             "apps": "Apps", "dhcp": "DHCP server", "ssid": "SSID", "wifi": "Wi-Fi", "path": "Path"}

# The path a client's traffic takes and how each hop looks for a segment verdict (# ported from
# pulse-core.js CHIPS). o ok, f the break, s one of these, u past the break (can't tell).
CHAIN_SEGS = ("ports", "switch", "gateway", "edge", "isp", "dns", "apps")
_CHIPS = {"link": "fuuuuuu", "ports": "fuuuuuu", "switch": "ofouuuu", "gateway": "oofuuuu", "lan": "ossuuuu",
          "edge": "ooofouu", "isp": "oooufuu", "wan": "ooossuu", "resolver": "ooooofu", "dns_path": "ooooofu",
          "dns": "ooooofu", "apps": "oooooof"}
_CHIP_STATE = {"o": "ok", "f": "fail", "s": "warn", "u": "unknown"}


def where_fields(w: Mapping[str, Any], edge_label: str) -> dict[str, object]:
    ports = w.get("ports") or []
    return {"edge": edge_label, "ip": w.get("ip"), "ports": few([str(p) for p in ports]) if ports else "",
            "lh": w.get("lh"), "lt": w.get("lt"), "target": w.get("target"), "sx": w.get("sx"), "ax": w.get("ax"),
            "tg": w.get("tg"), "sd": w.get("sd"),
            "sv": Raw(f" ({clean(w['sv'])})") if w.get("sv") else Raw(""),
            "sdpart": Raw(f" (it is on {clean(w['sd'])})") if w.get("sd") else Raw("")}


def where_text(w: Mapping[str, Any] | None, voice: str = "plain", edge_label: str = "EC") -> str:
    """One sentence saying where the fault is ('' when there is none)."""
    if not w:
        return ""
    table = WHERE_P if voice == "plain" else WHERE_X
    f = where_fields(w, edge_label)
    if w.get("seg") in ("gateway", "switch", "lan") and not w.get("ip"):
        f["ip"] = "the gateway"
    return fill(table.get(str(w.get("seg")), ""), f, _DEFAULTS)


def where_alert_text(w: Mapping[str, Any] | None, edge_label: str = "EC") -> str:
    """The 'Where: ...' line of an alert (always the factual wording, as EXM's alerts)."""
    return where_text(w, "plain", edge_label)


def _ipv4(v: object) -> str | None:
    from .rules import _ip
    return _ip(v)


def where_doc(w: Mapping[str, Any] | None, voice: str, edge_label: str = "EC") -> dict[str, Any] | None:
    """The `verdict.where` object of exp.state/1: {seg, label, ip, explain, chain}."""
    if not w:
        return None
    seg = str(w["seg"])
    ip = _ipv4(w.get("ip") or w.get("lh") or w.get("sx") or w.get("sv"))
    explain = where_text(w, voice, edge_label)
    if voice == "plain":
        explain = cap(explain[len("Where: "):] if explain.startswith("Where: ") else explain)
    chips = _CHIPS.get(seg)
    chain = [{"seg": name, "state": _CHIP_STATE[c]} for name, c in zip(CHAIN_SEGS, chips, strict=True)] if chips else []
    label = clean(edge_label, 16) or "Edge" if seg == "edge" else SEG_LABEL.get(seg, seg)
    return {"seg": seg, "label": label[:64], "ip": ip, "explain": explain[:512], "chain": chain}


def where_summary(w: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """The small `where` of an Incident: {seg, ip}."""
    if not w:
        return None
    return {"seg": str(w["seg"]), "ip": _ipv4(w.get("ip") or w.get("lh") or w.get("sx") or w.get("sv"))}


# ------------------------------------------------------------------------------------------- facts text
def gateway_facts(ev: Evaluation) -> list[str]:
    g = ev.facts.gateway
    out: list[str] = []
    if g:
        out += [f"{ip} not answering ({bad} of {n} ports)" for ip, bad, n in g["ug"]]
        if g["nl"]:
            out.append(f"no link: {few([clean(p, 16) for p in g['nl']])}")
    return out


def trace_fact(t: Mapping[str, Any] | None, ev: Evaluation | None = None) -> str:
    if not t:
        if ev is not None and ev.facts.trace_unrunnable:
            return "No client could run the traceroute"
        return ""
    tg = clean(t.get("g")) or "the target"
    if t["rc"]:
        return f"{tg} reachable in {int(t['dt'])} hops" if t.get("dt") else f"{tg} reachable"
    if t.get("lh"):
        return f"traceroute to {tg} stops after {t['lh']} (hop {t['lt'] if t.get('lt') is not None else 'unknown'})"
    return f"traceroute to {tg}: no hop answers"


def _last_error(ev: Evaluation, key: str, *, within: int | None = None) -> str | None:
    """Newest error text of a non-ok record of the line within the window (prefers heartbeats)."""
    span = within if within is not None else max(LINE_SPECS[key].window_ms, 60_000)
    best: tuple[int, int, str] | None = None
    for s in LINE_SPECS[key].streams:
        for g in reversed(ev.store.groups(s)):
            if g.t > ev.at:
                continue
            if ev.at - g.t > span:
                break
            for r in g.recs:
                if r.error and r.outcome != "ok" and r.ts <= ev.at:
                    cand = (int(r.test.endswith("_hb")), r.ts, r.error)
                    if best is None or cand[:2] > best[:2]:
                        best = cand
    return norm_error(best[2]) if best else None


def what_of(ev: Evaluation, key: str) -> str | None:
    """What is failing on a line, in one clause (alerts and the State detail)."""
    le = ev.lines[key]
    if key == "network" and ev.facts.gateway:
        parts = [f"gateway {ip} not answering on {bad} of {n} ports" for ip, bad, n in ev.facts.gateway["ug"]]
        if ev.facts.gateway["nl"]:
            parts.append(f"no link on {', '.join(clean(p, 16) for p in ev.facts.gateway['nl'])}")
        if parts:
            return "; ".join(parts)
    e = _last_error(ev, key, within=60_000)
    if e:
        return clip(re.sub(r"\s+", " ", e), 200).rstrip(". ")
    if le.n:
        return f"{le.f} of {le.n} checks failed in the last {LINE_SPECS[key].window_ms // 1000} s"
    return None


def line_detail(ev: Evaluation, key: str) -> str:
    """The `detail` of a State line: why it is not ok (# ported from pulse.html whyOf)."""
    le = ev.lines[key]
    if le.state not in ("fail", "warn"):
        return ""
    if key == "network":
        f = gateway_facts(ev)
        if f:
            return " · ".join(f)
    if key == "internet":
        t = trace_fact(ev.facts.raw_trace, ev)
        if t:
            return t
    e = _last_error(ev, key)
    return clip(clean(e, 200), 80) if e else ""


# --------------------------------------------------------------------------------------------- verdict
def _items(ev: Evaluation, key: str) -> tuple[int, int, int]:
    """(records, failed records, slow records) in the line's window: counts results, not beats."""
    n = f = d = 0
    for s in LINE_SPECS[key].streams:
        for g in reversed(ev.store.groups(s)):
            if g.t > ev.at:
                continue
            if ev.at - g.t > LINE_SPECS[key].window_ms:
                break
            for r in g.recs:
                if r.ts <= ev.at and r.outcome != "error":
                    n += 1
                    f += r.outcome == "fail"
                    d += r.outcome == "degraded"
    return n, f, d


_WINDOW_TEXT = {"network": "30 seconds", "dhcp": "30 seconds", "dns": "30 seconds", "internet": "2 minutes",
                "apps": "2 minutes", "wifi": "30 seconds", "path": "3 minutes"}
_FINE_NAMES = {"network": "our network", "dhcp": "DHCP", "dns": "DNS", "internet": "the internet", "apps": "apps",
               "wifi": "Wi-Fi", "path": "the path test"}


class _V:
    """A verdict being built (EXM's v object)."""

    def __init__(self, h: str, sub: str, sev: str, *, kind: str | None = None, line: str | None = None,
                 src: str | None = None, seed: object = None, f: Mapping[str, object] | None = None,
                 stale: bool = False) -> None:
        self.h, self.sub, self.sev, self.kind, self.line, self.src = h, sub, sev, kind, line, src
        self.seed, self.f, self.stale = seed, dict(f or {}), stale


def verdict(states: Evaluation, where: Mapping[str, Any] | None, voice: str = "sysadmin", tz: str = "UTC",
            edge_label: str = "EC") -> dict[str, Any]:
    """verdict(states, where, voice, tz) -> {severity, headline, sub, voice, where}.

    `states` is the Evaluation of the probe at the moment shown; `where` its where_of() result (passed
    separately so callers can show a verdict for a hypothetical segment)."""
    if voice not in VOICES:
        voice = "sysadmin"
    ev, plain, t = states, voice == "plain", states.at
    v = _compose(ev, plain, tz)
    since: int | None = None
    sub = v.sub
    if v.src is not None:
        le = ev.lines.get(v.src)
        since = le.since if le else None
        if since is not None and le is not None:
            when = ("before " + hhmm(since, tz)) if le.since_open else hms(since, tz)
            sub = sub.replace("{since}", when)
        else:
            sub = sub.replace(" since {since}", "").replace("Since {since}. ", "").replace("{since}", "").strip()
    kind = v.kind
    if v.line is not None and v.sev in ("fail", "warn"):          # flapping is its own story
        n = ev.lines[v.line].flaps if v.line in ev.lines else 0
        if n >= 3:
            kind = "flap"
            sub = text(fin(f"It has failed {n} times in the last 10 minutes"), sub)
    headline = v.h
    if not plain and kind:
        f: dict[str, object] = {"since": since, "lane": LABELS.get(v.line or "", ""), "hour": Raw(hour_text(t, tz))}
        f.update(v.f)
        headline = _line(kind, v.seed if v.seed is not None else (since or ""), t, f) or v.h
    headline = fin(headline)
    sub = tidy(sub)
    return {"severity": v.sev, "headline": headline[:256], "sub": sub[:512], "voice": voice,
            "where": where_doc(where, voice, edge_label) if v.sev in ("fail", "warn") and not v.stale else None}


def _tier(d: float) -> str:
    return "epic" if d >= 3_600_000 else "long" if d >= 600_000 else "fresh"


def _line(kind: str, seed: object, t: int, f: Mapping[str, object]) -> str | None:
    p = LINES.get(kind)
    if p is None:
        return None
    if isinstance(p, list):
        pool = p
    else:
        since = f.get("since")
        pool = p.get(_tier(t - since if isinstance(since, int) else 0)) or p.get("long") or p["fresh"]
    return fill(one(pool, f"{kind}:{seed}"), f, _DEFAULTS)


def _fine(ev: Evaluation, *skip: str) -> str:
    ok = [_FINE_NAMES[k] for k, le in ev.lines.items() if le.state == "ok" and k not in skip]
    return fin(cap(join_words(ok)) + (" are fine" if len(ok) > 1 else " is fine")) if ok else ""


def _ratio(ev: Evaluation, key: str, what: str) -> str:
    le = ev.lines[key]
    return fin(f"{le.f} of {le.n} {what} failed in the last {_WINDOW_TEXT[key]}" if le.f
               else f"{le.d} of {le.n} {what} were slow in the last {_WINDOW_TEXT[key]}")


def _compose(ev: Evaluation, plain: bool, tz: str) -> _V:
    """The verdict text (# ported from pulse.html verdictText), exp lines instead of EXM lanes."""
    t = ev.at
    sn = (lambda a, b: a) if plain else (lambda a, b: b)         # pick(plain, snark)
    S = {k: le.state for k, le in ev.lines.items()}
    newest = ev.newest
    if newest is None:
        return _V(sn("No results yet.", "Nothing yet."),
                  text("Waiting for the first test to finish.", sn("", "It gets there.")), "unknown")
    if t - newest > STALE_MS:
        d = dur(t - newest)
        return _V(f"No data for {d}.", text(fin(f"The probe stopped reporting at {hms(newest, tz)}"),
                                           "Nothing on this screen is current.",
                                           sn("", "Dead or sulking; either way, go and look.")),
                  "unknown", kind="silent", seed=newest, f={"since": newest, "dur": Raw(d)}, stale=True)
    night = local_time(t, tz).hour < 6
    w = ev.facts.wifi
    g = ev.facts.gateway
    tr = ev.facts.raw_trace
    net, dh, dn = S.get("network"), S.get("dhcp"), S.get("dns")
    inet, apps, wf, path = S.get("internet"), S.get("apps"), S.get("wifi"), S.get("path")
    fine = lambda *skip: _fine(ev, *skip)  # noqa: E731

    if net == "fail":
        ug = (g or {}).get("ug") or []
        nl = (g or {}).get("nl") or []
        facts = [f"Gateway {ip} isn't answering on {bad} of {n} ports" for ip, bad, n in ug]
        if nl:
            total = g["n"] if g else len(nl)
            facts.append(f"{len(nl)} of {total} ports have no link ({few([clean(p, 16) for p in nl])})")
        what = "; ".join(facts) if facts else "Ports keep losing link or the gateway"
        return _V("The network is unstable.", fin(f"{what} since {{since}}"), "fail",
                  kind="netGw" if ug else "netLink" if nl else "netOther", line="network", src="network")
    if dh == "fail" and dn == "fail":
        return _V("DHCP and DNS are failing.",
                  text("Since {since}.", sn("", "New devices get no address and the rest can't look anything up."),
                       fine("dhcp", "dns")), "fail", kind="dhcpDns", line="dhcp", src="dhcp")
    if dh == "fail":
        return _V("DHCP is failing.", text("No offers since {since}.",
                                           sn("", "New arrivals get 169.254 and a bad attitude."), fine("dhcp")),
                  "fail", kind="dhcp", line="dhcp", src="dhcp")
    web_down = inet == "fail" or (apps == "fail" and not (tr and tr["rc"]))
    if web_down:
        path_txt = ""
        if tr:
            tgt = clean(tr.get("g")) or "the target"
            reach = sn(f"{tgt} is reachable, so suspect DNS or the apps.", f"{tgt} answers fine, so it isn't the pipe.")
            path_txt = reach if tr["rc"] else fin(cap(trace_fact(tr, ev)))
        elif ev.facts.trace_unrunnable:
            path_txt = fin(trace_fact(None, ev))
        return _V("The internet is down.",
                  text("Since {since}.", path_txt,
                       sn("DNS isn't answering either.", "DNS is down too, before you ask.") if dn == "fail" else "",
                       fine("dns", "internet", "apps")),
                  "fail", kind="internet", line="internet" if inet == "fail" else "apps",
                  src="internet" if inet == "fail" else "apps")
    if apps == "fail":
        tgt = clean(tr.get("g")) if tr else ""
        return _V("Apps are failing.",
                  text("Since {since}.", sn(f"{tgt} is reachable, so suspect DNS or the apps." if tgt else "",
                                           f"{tgt} answers fine, so it isn't the pipe." if tgt else ""), fine("apps")),
                  "fail", kind="appsFail", line="apps", src="apps")
    if dn == "fail":
        sx = (ev.facts.dns or {}).get("sx")
        who = f" from {sx}" if sx else ""
        return _V("DNS is failing.",
                  text(fin(f"No answers{who} since {{since}}"), sn("", "It's always DNS."), fine("dns")),
                  "fail", kind="dnsNight" if night else "dns", line="dns", src="dns")
    if wf == "fail":
        off = bool(w and not w["on"])
        f = {"sd": (w or {}).get("sd"), "tg": (w or {}).get("tg")}
        kind = ("wifiOff" if f["sd"] else "wifiGone") if off else "wifiDown"
        lead = ""
        if off and not plain and f["tg"]:
            lead = fin(f"It's supposed to be on {clean(f['tg'])}")
        elif w and w.get("err"):
            lead = fin(cap(clean(w["err"], 160)))
        return _V("Wi-Fi is down.", text(lead, "Since {since}.", fine("wifi")), "fail", kind=kind, line="wifi",
                  src="wifi", f=f)
    if path == "fail":
        e = _last_error(ev, "path")
        return _V("The path test is failing.",
                  text("Since {since}.", fin(cap(clean(e, 160))) if e else "", fine("path")), "fail",
                  kind="pathFail", line="path", src="path")
    if net == "warn":
        bad: set[str] = set()
        for grp in ev.store.groups("gateway"):
            if grp.t <= t and t - grp.t <= LINE_SPECS["network"].window_ms:
                bad.update(r.port for r in grp.recs if r.outcome == "fail" or r.metrics.get("link_up") == 0)
        ports = sorted(p for p in bad if p)
        names = join_words([clean(p, 16) for p in ports])
        who = names + (" are" if len(ports) > 1 else " is") if ports else "Some ports are"
        return _V("The network is shaky.", text(fin(f"{who} dropping link or missing the gateway"),
                                                sn("", "Cable, port or gremlins.")),
                  "warn", kind="netWarn", line="network", src="network")
    if dh == "warn":
        return _V("DHCP is partly failing.", _ratio(ev, "dhcp", "DHCP checks"), "warn", kind="dhcpWarn",
                  line="dhcp", src="dhcp")
    if dn == "warn":
        return _V("DNS is partly failing.", _ratio(ev, "dns", "DNS checks"), "warn", kind="dnsWarn",
                  line="dns", src="dns")
    if apps == "warn" or inet == "warn":
        key = "apps" if apps == "warn" else "internet"
        n, nf, nd = _items(ev, key)
        win = _WINDOW_TEXT[key]
        label = "app" if key == "apps" else "path"
        if nf:
            return _V("Some apps are failing." if key == "apps" else "The internet is degraded.",
                      fin(f"{nf} of {n} {label} checks failed in the last {win}"), "warn",
                      kind="appsFail" if key == "apps" else "netSlow", line=key, src=key)
        return _V("The internet is slow.", fin(f"{nd} of {n} {label} checks were slow in the last {win}"), "warn",
                  kind="appsSlow", line=key, src=key)
    if wf == "warn":
        e = w.get("err") if w else None
        lead = fin(cap(clean(e, 160))) if e else _ratio(ev, "wifi", "Wi-Fi checks")
        return _V("Wi-Fi is degraded.", text(lead, fine("wifi")),
                  "warn", kind="wifiWarn", line="wifi", src="wifi")
    if path == "warn":
        return _V("The path is degraded.", _ratio(ev, "path", "path checks"), "warn", kind="pathWarn",
                  line="path", src="path")
    # A laptop that sleeps or leaves is a data gap, not a network fault: say so without hiding the wired answer.
    seen = {k for k, le in ev.lines.items() if le.beats or le.state != "unknown"}
    if wf == "unknown" and "wifi" in seen and all(S.get(k) == "ok" for k in S if k not in ("wifi",) and k in seen):
        lw = max((b.t for b in ev.lines["wifi"].beats if b.t <= t), default=None)
        since_txt = f"No Wi-Fi results since {hhmm(lw, tz)}" if lw else "No Wi-Fi results yet"
        return _V("All good on the wired network.", fin(since_txt + ": the test laptop isn't reporting"),
                  "unknown", kind="laptopAway", seed=lw or "")
    missing = [LABELS[k] for k, s in S.items() if s == "unknown" and k in seen]
    if missing:
        return _V("Waiting for results.",
                  text(fin(f"No recent {join_words(missing)} results"), sn("", "They'll turn up.")),
                  "unknown", kind="waiting", seed=t // 600_000)
    outs = [(k, le.last_outage) for k, le in ev.lines.items() if le.last_outage and le.last_outage.start is not None]
    if outs:
        k, o = max(outs, key=lambda x: x[1].end)
        if o is None or o.start is None:  # pragma: no cover - filtered above
            raise AssertionError("unreachable")
        d = dur(o.end - o.start)
        span = (f"until {hms(o.end, tz)} (since before {hhmm(o.start, tz)})" if o.open
                else f"for {d} ({hms(o.start, tz)}–{hms(o.end, tz)})")
        return _V("All good again.", text(fin(f"{LABELS[k]} was down {span}"), fin(f"Back for {dur(t - o.end)}")), "ok",
                  kind="recovered", seed=o.start, f={"dur": Raw(("over " if o.open else "") + d)})
    lt = local_time(t, tz)
    friday = lt.weekday() == 4 and lt.hour >= 15
    kind = "allGoodNight" if night else "allGoodFriday" if friday else "allGood"
    last = ev.store.last_fail_ts(t)
    sub = fin(f"No failed tests for {dur(t - last)}") if last is not None else "No failed tests in the last hour."
    return _V("All good.", sub, "ok", kind=kind, seed=t // 600_000)

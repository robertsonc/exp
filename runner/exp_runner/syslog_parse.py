"""Syslog line parsers (SR-24/SR-25): every input is hostile text, bounded, and only ever *read*.

A line is never executed, followed, fetched or used as a path/format string: parsing produces a
:class:`ParsedLine` of bounded strings and numbers, nothing else.

Formats and their sources (none of these is a local vendor reference; see the CR for the honest status):

* RFC 5424 (HEADER, STRUCTURED-DATA ``[id name="v"]`` with ``\\"`` ``\\\\`` ``\\]`` escapes) and RFC 3164 envelopes: public RFCs.
* CEF (ArcSight Common Event Format) and LEEF 1.0/2.0 (IBM QRadar): public specifications.
* key=value: the common ``k=v k2="v 2"`` shape.
* DHCP lease evidence: ISC dhcpd (``DHCPACK on <ip> to <mac> (<host>) via <if>``), Kea (``DHCP4_LEASE_ALLOC [hwtype=1 <mac>] ...
  lease <ip> has been allocated``), Microsoft DHCP audit CSV (event 10 assign / 11 renew / 12 release, MAC without separators).
* DNS query logs: BIND ``named`` (``client ... <ip>#<port> (<name>): query: <name> IN <type>``) and dnsmasq (``query[A] <name> from <ip>``)
  plus key=value lines carrying ``qname``/``rcode``.
* **EdgeConnect firewall / zone-policy lines: there is NO local vendor documentation** (pyedgeconnect documents only the syslog
  *configuration*, not the log text; HPE Aruba SSE has none either). They are parsed by the generic key=value / "ZBF <action> ..."
  forms by *key name*; unknown keys are ignored. This is not vendor ground truth.
"""
from __future__ import annotations

import dataclasses
import datetime
import ipaddress
import re
import time
from typing import Any

MAX_RAW = 1024           # raw text kept per line
MAX_VALUE = 256          # any single parsed value
MAX_PAIRS = 64           # key=value pairs read from one line
MAX_SD_ELEMENTS = 8
MAX_SD_PARAMS = 16
TS_SANITY_S = 3600.0     # a message time further than this from the receive time is distrusted

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_PRI = re.compile(r"<(\d{1,3})>")
_5424 = re.compile(r"(\d{1,2}) (\S{1,64}) (\S{1,255}) (\S{1,48}) (\S{1,128}) (\S{1,32}) ")
_3164 = re.compile(r"([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d\d):(\d\d):(\d\d) (\S{1,255}) ")
_ISO_HDR = re.compile(r"(\d{4}-\d\d-\d\dT[0-9:.]{8,16}(?:Z|[+-]\d\d:?\d\d)?) (\S{1,255}) ")
_TAG = re.compile(r"([\w\-./]{1,48})(?:\[\d{1,10}\])?: ?")
_KV = re.compile(r"""(?:^|[\s,;])([A-Za-z_][\w.\-]{0,40})=("(?:[^"\\]|\\.){0,512}"|[^\s,;"]{0,512})""")
_CEF_KEY = re.compile(r"(?:^|\s)([A-Za-z][A-Za-z0-9_]{0,40})=")
_FLOW = re.compile(
    r"(?:ZBF|FW|FIREWALL)\s+(\w{1,16})\s+(\w{1,16})\s+(\S{1,45}?):(\d{1,5})\s*->\s*(\S{1,45}?):(\d{1,5})"
    r"(?:\s+zones?\s+([^\s>]{1,64})->(\S{1,64}))?(?:\s+policy=(\S{1,128}))?", re.I)
_ISC = re.compile(r"DHCP(ACK|OFFER|RELEASE)\b.*?(?:\bon |\bto |\bof )(\d{1,3}(?:\.\d{1,3}){3})"
                  r"(?: to | \()([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})\)?(?: \(([^)]{0,253})\))?")
_ISC_RELEASE = re.compile(r"DHCPRELEASE of (\d{1,3}(?:\.\d{1,3}){3}) from ([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?: \(([^)]{0,253})\))?")
_KEA = re.compile(r"DHCP4_LEASE_(?:ALLOC|REUSE|ADVERT)\b.*?\[hwtype=\d{1,3} ([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\].*?"
                  r"lease (\d{1,3}(?:\.\d{1,3}){3}) has been (?:allocated|reused|advertised)")
_WIN = re.compile(r"(\d{1,2}),(\d\d/\d\d/(?:\d\d|\d{4})),(\d\d:\d\d:\d\d),([^,]{0,64}),(\d{1,3}(?:\.\d{1,3}){3}),([^,]{0,253}),"
                  r"([0-9A-Fa-f]{12}),")
_BIND = re.compile(r"client (?:@\S+ )?(\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]{2,39})#\d{1,5} \(([^)]{1,253})\): query: (\S{1,253}) IN (\w{1,8})")
_DNSMASQ = re.compile(r"query\[(\w{1,8})\] (\S{1,253}) from (\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]{2,39})")

_MONTHS = {m: i + 1 for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"))}

_SRC_KEYS = ("src", "srcip", "src_ip", "sourceip", "sourceaddress", "saddr", "srcaddr", "source_ip", "client_ip", "clientip")
_DST_KEYS = ("dst", "dstip", "dst_ip", "destinationip", "destinationaddress", "daddr", "dstaddr", "destination_ip")
_SPORT_KEYS = ("spt", "sport", "srcport", "src_port", "sourceport", "source_port")
_DPORT_KEYS = ("dpt", "dport", "dstport", "dst_port", "destinationport", "destination_port")
_PROTO_KEYS = ("proto", "protocol")
_ACTION_KEYS = ("act", "action", "deviceaction", "disposition", "verdict", "outcome")
_RULE_KEYS = ("rule", "rulename", "policy", "policyid", "policyname", "ruleid", "rule_name")
_ZFROM_KEYS = ("from_zone", "srczone", "src_zone", "fromzone", "zone_from", "sourcezone", "zonefrom")
_ZTO_KEYS = ("to_zone", "dstzone", "dst_zone", "tozone", "zone_to", "destinationzone", "zoneto")
_REASON_KEYS = ("reason", "msg", "message")
_HOST_KEYS = ("dhost", "dsthost", "host", "url_host", "domain", "hostname_dst")
_CAT_KEYS = ("cat", "category", "event", "type", "eventtype")
_QNAME_KEYS = ("qname", "query", "dns_query", "queryname")
_QTYPE_KEYS = ("qtype", "querytype")
_RCODE_KEYS = ("rcode", "responsecode")
_RTT_KEYS = ("rtt_ms", "rtt", "latency_ms", "duration_ms")

_ACTION_MAP = {
    "deny": "deny", "denied": "deny", "deny-by-policy": "deny",
    "drop": "drop", "dropped": "drop", "discard": "drop",
    "block": "block", "blocked": "block",
    "reset": "reset", "rst": "reset", "reset-both": "reset", "reset-client": "reset", "reset-server": "reset",
    "limit": "limit", "session-limit": "limit", "session_limit": "limit", "throttle": "limit", "limited": "limit",
    "alert": "alert", "detected": "alert", "alerted": "alert",
    "allow": "allow", "allowed": "allow", "accept": "allow", "accepted": "allow", "pass": "allow", "passed": "allow",
    "permit": "allow", "permitted": "allow",
}
ACTIONS = frozenset(_ACTION_MAP.values()) | {"other"}


@dataclasses.dataclass
class ParsedLine:
    ts: float                       # epoch seconds used for correlation
    fmt: str                        # rfc5424 | cef | leef | kv | dhcp | dns | raw
    kind: str                       # security | dhcp | dns | other
    raw: str
    fields: dict[str, Any] = dataclasses.field(default_factory=dict)
    ips: tuple[str, ...] = ()
    ts_source: str = "received"     # received | message
    header_host: str | None = None


def clean(text: str, limit: int = MAX_VALUE) -> str:
    """Bounded, control-free copy of untrusted text."""
    return _CTRL.sub("?", text)[:limit]


def _ip(text: str | None) -> str | None:
    if not text or len(text) > 45:
        return None
    try:
        return str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return None


def _port(text: Any) -> int | None:
    try:
        n = int(str(text))
    except (TypeError, ValueError):
        return None
    return n if 0 <= n <= 65535 else None


def _mac(text: str | None) -> str | None:
    if not text:
        return None
    h = re.sub(r"[:.\-\s]", "", text.strip().lower())
    if not re.fullmatch(r"[0-9a-f]{12}", h):
        return None
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def _unquote(v: str) -> str:
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return re.sub(r"\\(.)", r"\1", v[1:-1])
    return v


def parse_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for n, m in enumerate(_KV.finditer(text)):
        if n >= MAX_PAIRS:
            break
        out.setdefault(m.group(1).lower(), clean(_unquote(m.group(2))))
    return out


def _first(d: dict[str, str], keys: tuple[str, ...]) -> str | None:
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return None


def normalize_action(text: str | None) -> str | None:
    if not text:
        return None
    t = text.strip().lower()
    if t in _ACTION_MAP:
        return _ACTION_MAP[t]
    for tok in re.split(r"[^a-z_-]+", t):
        if tok in _ACTION_MAP:
            return _ACTION_MAP[tok]
    return "other"


def _category(d: dict[str, str], action: str | None, zones: bool) -> str:
    text = " ".join(x for x in (_first(d, _CAT_KEYS), d.get("reason"), d.get("msg"), d.get("name")) if x).lower()
    if re.search(r"\burl\b|web.?filter|urlfilter", text):
        return "url"
    if re.search(r"\bips\b|\bids\b|intrusion|signature", text):
        return "ips"
    if re.search(r"\bnat\b", text):
        return "nat"
    if re.search(r"session", text) and re.search(r"limit|max|exceed", text) or action == "limit":
        return "session_limit"
    if zones or re.search(r"\bzbf\b|zone", text):
        return "zbf"
    if action or re.search(r"firewall|\bfw\b", text):
        return "firewall"
    return "other"


def _normalize_flat(d: dict[str, str]) -> dict[str, Any]:
    """Map a flat lower-cased key/value dict to the normalized event fields (only recognised keys are read)."""
    f: dict[str, Any] = {}
    src = _ip(_first(d, _SRC_KEYS))
    dst = _ip(_first(d, _DST_KEYS))
    if src:
        f["src_ip"] = src
    if dst:
        f["dst_ip"] = dst
    for name, keys in (("src_port", _SPORT_KEYS), ("dst_port", _DPORT_KEYS)):
        p = _port(_first(d, keys))
        if p is not None:
            f[name] = p
    proto = _first(d, _PROTO_KEYS)
    if proto:
        f["proto"] = clean(proto, 16).lower()
    action = normalize_action(_first(d, _ACTION_KEYS))
    if action:
        f["action"] = action
    for name, keys, lim in (("rule", _RULE_KEYS, 128), ("zone_from", _ZFROM_KEYS, 64), ("zone_to", _ZTO_KEYS, 64),
                            ("reason", _REASON_KEYS, 128), ("host", _HOST_KEYS, 253)):
        v = _first(d, keys)
        if v:
            f[name] = clean(v, lim)
    # CEF-style custom string pairs: csNLabel=zone, csN="A->B"
    for k, v in list(d.items()):
        m = re.fullmatch(r"cs(\d)label", k)
        if m and "zone" in v.lower():
            zv = d.get(f"cs{m.group(1)}", "")
            a, sep, b = zv.partition("->")
            if sep:
                f.setdefault("zone_from", clean(a, 64))
                f.setdefault("zone_to", clean(b, 64))
    q = _first(d, _QNAME_KEYS)
    if q:
        f["qname"] = clean(q, 253)
        f["qtype"] = clean(_first(d, _QTYPE_KEYS) or "", 8)
    rc = _first(d, _RCODE_KEYS)
    if rc:
        f["rcode"] = clean(rc, 16).upper()
    rtt = _first(d, _RTT_KEYS)
    if rtt:
        try:
            v = float(rtt)
            if 0 <= v <= 60000:
                f["rtt_ms"] = v
        except ValueError:
            pass
    cat = _category(d, f.get("action"), bool(f.get("zone_from") and f.get("zone_to")))
    f["category"] = cat
    return f


def _unescape_cef_header(s: str) -> str:
    return s.replace("\\|", "|").replace("\\\\", "\\")


def parse_cef(text: str) -> dict[str, str] | None:
    """``CEF:ver|vendor|product|version|sigid|name|severity|extension`` -> flat lower-cased dict (header fields under cef_*)."""
    if not text.startswith("CEF:"):
        return None
    parts: list[str] = []
    cur: list[str] = []
    i, n = 4, len(text)
    while i < n and len(parts) < 7:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            cur.append(text[i:i + 2])
            i += 2
            continue
        if ch == "|":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    if len(parts) < 7:
        return None
    ext = text[i:]
    d: dict[str, str] = {"cef_sigid": clean(_unescape_cef_header(parts[3]), 64), "name": clean(_unescape_cef_header(parts[4]), 128)}
    marks = list(_CEF_KEY.finditer(ext))[:MAX_PAIRS]
    for idx, m in enumerate(marks):
        end = marks[idx + 1].start() if idx + 1 < len(marks) else len(ext)
        val = ext[m.end():end].strip()
        val = val.replace("\\=", "=").replace("\\n", " ").replace("\\r", " ").replace("\\\\", "\\")
        d.setdefault(m.group(1).lower(), clean(val))
    return d


def parse_leef(text: str) -> dict[str, str] | None:
    """LEEF 1.0 (tab) / 2.0 (``|delimiter|``) -> flat lower-cased dict."""
    m = re.match(r"LEEF:(1|2)\.0\|", text)
    if not m:
        return None
    ver = m.group(1)
    rest = text[m.end():]
    head = rest.split("|", 5 if ver == "2" else 4)
    if ver == "1":
        if len(head) < 5:
            return None
        event_id, attrs, delim = head[3], head[4], "\t"
    else:
        if len(head) < 6:
            return None
        event_id, attrs = head[3], head[5]
        dtok = head[4]
        if dtok == "":
            delim = "\t"
        elif re.fullmatch(r"0?x[0-9A-Fa-f]{1,2}", dtok):
            delim = chr(int(dtok.lower().split("x", 1)[1], 16))
        else:
            delim = dtok[:1]
    d: dict[str, str] = {"leef_event": clean(event_id, 64)}
    pieces = attrs.split(delim) if delim in attrs else None
    if pieces is None:
        d.update(parse_kv(attrs))
        return d
    for p in pieces[:MAX_PAIRS]:
        k, sep, v = p.partition("=")
        if sep and re.fullmatch(r"[A-Za-z_][\w.\-]{0,40}", k):
            d.setdefault(k.lower(), clean(v))
    return d


def parse_sd(text: str) -> tuple[dict[str, str], str]:
    """RFC 5424 STRUCTURED-DATA at the start of `text` -> (flat params, remainder = MSG). ``-`` is the NILVALUE."""
    if text.startswith("-"):
        return {}, text[1:].lstrip(" ")
    params: dict[str, str] = {}
    i, n, elements = 0, len(text), 0
    while i < n and text[i] == "[" and elements < MAX_SD_ELEMENTS:
        elements += 1
        i += 1
        j = i
        while j < n and text[j] not in " ]":
            j += 1
        i = j
        count = 0
        while i < n and text[i] == " ":
            i += 1
            m = re.compile(r"([^\s=\]\"]{1,32})=\"").match(text, i)
            if not m:
                break
            i = m.end()
            buf: list[str] = []
            while i < n:
                ch = text[i]
                if ch == "\\" and i + 1 < n and text[i + 1] in '"\\]':
                    buf.append(text[i + 1])
                    i += 2
                    continue
                if ch == '"':
                    i += 1
                    break
                buf.append(ch)
                i += 1
                if len(buf) > 1024:
                    break
            if count < MAX_SD_PARAMS:
                params.setdefault(m.group(1).lower(), clean("".join(buf)))
            count += 1
        while i < n and text[i] != "]":
            i += 1
        if i < n:
            i += 1
    return params, text[i:].lstrip(" ")


def _parse_iso(s: str) -> float | None:
    try:
        t = s.replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", t):
            t = t[:-2] + ":" + t[-2:]
        d = datetime.datetime.fromisoformat(t)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    return d.timestamp()


def _ts_3164(mon: str, day: str, hh: str, mm: str, ss: str, now: float) -> float | None:
    month = _MONTHS.get(mon)
    if month is None:
        return None
    year = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).year
    try:
        t = datetime.datetime(year, month, int(day), int(hh), int(mm), int(ss), tzinfo=datetime.timezone.utc).timestamp()
    except ValueError:
        return None
    if t > now + 86400:      # no year in 3164: a date far in the future belongs to the previous year
        try:
            t = datetime.datetime(year - 1, month, int(day), int(hh), int(mm), int(ss), tzinfo=datetime.timezone.utc).timestamp()
        except ValueError:
            return None
    return t


def _dhcp(content: str) -> dict[str, Any] | None:
    m = _KEA.search(content)
    if m:
        return {"dhcp_event": "ack", "mac": _mac(m.group(1)), "lease_ip": _ip(m.group(2))}
    m = _ISC_RELEASE.search(content)
    if m:
        return {"dhcp_event": "release", "mac": _mac(m.group(2)), "lease_ip": _ip(m.group(1)),
                "hostname": clean(m.group(3), 253) if m.group(3) else None}
    m = _ISC.search(content)
    if m and m.group(1) == "ACK":
        return {"dhcp_event": "ack", "mac": _mac(m.group(3)), "lease_ip": _ip(m.group(2)),
                "hostname": clean(m.group(4), 253) if m.group(4) else None}
    m = _WIN.match(content.strip())
    if m:
        ev = {"10": "ack", "11": "ack", "12": "release"}.get(m.group(1))
        if ev:
            return {"dhcp_event": ev, "mac": _mac(m.group(7)), "lease_ip": _ip(m.group(5)),
                    "hostname": clean(m.group(6), 253) if m.group(6) else None}
    return None


def _split_envelope(line: str, now: float) -> tuple[str, dict[str, str], float | None, str | None, bool]:
    """-> (content, sd params, message ts, header host, is_5424)."""
    s = line
    m = _PRI.match(s)
    if m:
        s = s[m.end():]
    h = _5424.match(s) if m else None
    if h and h.group(1) == "1":
        ts = None if h.group(2) == "-" else _parse_iso(h.group(2))
        host = None if h.group(3) == "-" else clean(h.group(3), 255)
        sd, msg = parse_sd(s[h.end():])
        return msg.lstrip("\ufeff"), sd, ts, host, True
    h3 = _3164.match(s)
    if h3:
        ts = _ts_3164(h3.group(1), h3.group(2), h3.group(3), h3.group(4), h3.group(5), now)
        rest = s[h3.end():]
        t = _TAG.match(rest)
        return (rest[t.end():] if t else rest), {}, ts, clean(h3.group(6), 255), False
    hi = _ISO_HDR.match(s)
    if hi and m:
        rest = s[hi.end():]
        t = _TAG.match(rest)
        return (rest[t.end():] if t else rest), {}, _parse_iso(hi.group(1)), clean(hi.group(2), 255), False
    return s, {}, None, None, False


def parse_line(line: str, now: float | None = None) -> ParsedLine:
    """Parse one syslog message (already decoded; any length - only the first MAX_RAW chars are kept raw)."""
    now = time.time() if now is None else now
    text = clean(line, 16384).strip()
    raw = text[:MAX_RAW]
    content, sd, mts, header_host, is5424 = _split_envelope(text, now)
    ts, ts_src = now, "received"
    if mts is not None and abs(mts - now) <= TS_SANITY_S:
        ts, ts_src = mts, "message"

    fields: dict[str, Any] = {}
    kind, fmt = "other", "raw"
    flat: dict[str, str] | None = None

    idx = content.find("CEF:", 0, 120)
    lidx = content.find("LEEF:", 0, 120)
    if idx >= 0 and (flat := parse_cef(content[idx:])) is not None:
        fmt = "cef"
    elif lidx >= 0 and (flat := parse_leef(content[lidx:])) is not None:
        fmt = "leef"
    else:
        flat = None
        dh = _dhcp(content)
        if dh and dh.get("mac") and dh.get("lease_ip"):
            fields = {k: v for k, v in dh.items() if v is not None}
            fields["src_ip"] = dh["lease_ip"]
            return ParsedLine(ts, "dhcp", "dhcp", raw, fields, (dh["lease_ip"],), ts_src, header_host)
        bm, dm = _BIND.search(content), _DNSMASQ.search(content)
        if bm or dm:
            ipv = _ip(bm.group(1) if bm else dm.group(3))     # type: ignore[union-attr]
            if ipv:
                fields = {"client_ip": ipv, "qname": clean((bm.group(3) if bm else dm.group(2)), 253),   # type: ignore[union-attr]
                          "qtype": clean((bm.group(4) if bm else dm.group(1)), 8)}
                return ParsedLine(ts, "dns", "dns", raw, fields, (ipv,), ts_src, header_host)
        fm = _FLOW.search(content)
        if fm:
            f2 = {"action": normalize_action(fm.group(1)) or "other", "proto": clean(fm.group(2), 16).lower()}
            for key, val in (("src_ip", _ip(fm.group(3))), ("dst_ip", _ip(fm.group(5)))):
                if val:
                    f2[key] = val
            for key, val in (("src_port", _port(fm.group(4))), ("dst_port", _port(fm.group(6)))):
                if val is not None:
                    f2[key] = val  # type: ignore[assignment]
            if fm.group(7):
                f2["zone_from"], f2["zone_to"] = clean(fm.group(7), 64), clean(fm.group(8) or "", 64)
            if fm.group(9):
                f2["rule"] = clean(fm.group(9), 128)
            f2["category"] = "zbf" if "zone_from" in f2 else "firewall"
            ips = tuple(dict.fromkeys(x for x in (f2.get("src_ip"), f2.get("dst_ip")) if x))
            return ParsedLine(ts, "kv", "security", raw, f2, ips, ts_src, header_host)
        kv = parse_kv(content)
        if len(kv) >= 2 or (kv and ("=" in content[:80])):
            flat, fmt = kv, "kv"
    if flat is None and sd:
        flat = {}
    if flat is not None or sd:
        merged = dict(sd)
        merged.update(flat or {})
        fields = _normalize_flat(merged)
        if fmt == "raw":
            fmt = "rfc5424" if (is5424 and sd) else "kv"
        elif fmt == "kv" and is5424 and sd and not flat:
            fmt = "rfc5424"
        if fields.get("qname") and not fields.get("action"):
            kind = "dns"
            ipv = fields.get("src_ip")
            if ipv:
                fields["client_ip"] = ipv
        elif fields.get("action") or (fields.get("src_ip") and fields.get("dst_ip") and fields.get("category") != "other"):
            kind = "security"
        else:
            kind = "other"
    ips = tuple(dict.fromkeys(x for x in (fields.get("src_ip"), fields.get("dst_ip"), fields.get("client_ip")) if x))
    if kind == "other" and not ips:
        # unknown format: bounded raw text with timestamp + any IPs found in the first bytes of the text
        found = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", raw[:300])
        ips = tuple(dict.fromkeys(x for x in (_ip(f) for f in found[:4]) if x))
        fields = {}
        fmt = "raw"
    return ParsedLine(ts, fmt, kind, raw, fields, ips, ts_src, header_host)

"""Alert messages and webhook delivery (03-collector.md section 6, SR-13, SR-15).

* ``build_message`` writes what the NOC reads: the line, what, since (site timezone), where + why, and a
  link ``<board_url>/probe/<probe>?at=<start>`` (ported from reference/exm/lib/exm/alert.py
  Alerter.message, HEAD / BACK / QUIP_*).
* ``payload`` renders it for Slack, Teams or plain JSON. ALL probe-supplied text is escaped so it cannot
  create links or mentions (ported from alert.py _slack/_teams and extended: URL schemes and ``@`` are
  defanged, angle brackets and ampersands are escaped, Teams markdown links lose their brackets).
* ``WebhookSender`` delivers from one worker thread: ``https`` only, destinations that resolve to
  private/loopback/link-local/reserved addresses are refused unless allowlisted (SR-15), redirects are
  never followed, 3 retries with backoff, and a failure is logged WITHOUT the URL (the URL is a secret).
"""
from __future__ import annotations

import collections
import datetime
import http.client
import ipaddress
import json
import logging
import queue
import re
import socket
import ssl
import threading
import urllib.parse
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from .rules import LABELS
from .verdict import cap, clean, dur, fin, fnv, hhmm, one, tidy, where_alert_text

log = logging.getLogger(__name__)

HEAD = {
    "fail": {"network": "The network is down", "dhcp": "DHCP is failing", "dns": "DNS is failing",
             "internet": "The internet is down", "apps": "Apps are failing", "wifi": "Wi-Fi is down",
             "path": "The path test is failing"},
    "warn": {"network": "The network is shaky", "dhcp": "DHCP is partly failing", "dns": "DNS is partly failing",
             "internet": "The internet is degraded", "apps": "Apps are degraded", "wifi": "Wi-Fi is degraded",
             "path": "The path is degraded"},
}
BACK = {"network": "The network is back", "dhcp": "DHCP is back", "dns": "DNS is back",
        "internet": "The internet is back", "apps": "Apps are back", "wifi": "Wi-Fi is back",
        "path": "The path test is back"}
QUIP_DOWN: dict[str, list[str]] = {
    "network": ["The gateway has left the building.", "Somebody unplugged something.",
                "The gateway has stopped taking calls."],
    "dhcp": ["DHCP is out of office.", "New arrivals are queueing at 169.254.", "DHCP has closed the doors."],
    "dns": ["It was DNS.", "It's always DNS.", "It's not DNS. There's no way it's DNS. It was DNS."],
    "internet": ["The internet is down. No, really.", "We're an intranet now.", "Just us and the LAN."],
    "apps": ["Some apps are broken. Not ours, presumably.", "A few apps are down. Not my circus."],
    "wifi": ["Wi-Fi has left the chat.", "The test laptop is sulking.", "Wi-Fi is down. The laptop is not amused."],
    "path": ["The path test has given up.", "Something between here and the collector is eating packets."],
}
QUIP_WIFI_OFF = ["The laptop wandered off to {sd}.", "The test laptop has eloped with {sd}.",
                 "The laptop is on {sd}. It was told not to."]
QUIP_BACK = ["Zero apologies.", "Nobody touch anything.", "Someone owes someone a beer.", "Act like it never happened.",
             "Write it down before you forget."]
QUIP_FLAP = "It can't make up its mind."

# --------------------------------------------------------------------------------------------- escaping
_SCHEME = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{1,15}):(?=//)")
_WWW = re.compile(r"(?i)\bwww\.")
ZWSP = "​"


def defang(s: str) -> str:
    """Make links and mentions impossible in text a chat client might auto-link: URL schemes lose their
    `//`, `www.` its dot-adjacency, and `@` is followed by a zero-width space."""
    s = _SCHEME.sub(lambda m: m.group(1) + ":" + ZWSP, str(s))
    s = _WWW.sub("www" + ZWSP + ".", s)
    return s.replace("@", "@" + ZWSP)


def slack_escape(s: object) -> str:
    """Slack mrkdwn treats & < > as control characters (<url|label> is a link, <!channel> a mention):
    escape them in anything dynamic. # ported from alert.py _slack"""
    return defang(str(s)).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def teams_escape(s: object) -> str:
    """Adaptive Card text is markdown: no [label](url) links, no <tags>. # ported from alert.py _teams"""
    t = defang(str(s)).replace("[", "(").replace("]", ")")
    return t.replace("<", "\u2039").replace(">", "\u203a")       # single angle quotes: no tags, no autolinks


def _jsonify(v: Any) -> Any:
    if isinstance(v, str):
        return slack_escape(v)
    if isinstance(v, Mapping):
        return {str(k): _jsonify(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonify(x) for x in v]
    return v


# ---------------------------------------------------------------------------------------------- message
def _pick(pool: Sequence[str], seed: object) -> str:
    return one(pool, seed)


def when(ms: int | None, tz: str) -> str:
    if not ms:
        return "?"
    from .verdict import _zone
    return datetime.datetime.fromtimestamp(ms / 1000, _zone(tz)).strftime("%H:%M:%S %Z")


def iso_z(ms: int) -> str:
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def board_link(board_url: str | None, probe: str, start_ms: int | None, now_ms: int) -> str | None:
    """`<board_url>/probe/<probe>?at=<start>`; None when no board URL is configured."""
    if not board_url:
        return None
    base = board_url.rstrip("/")
    return f"{base}/probe/{urllib.parse.quote(probe, safe='')}?at={iso_z(start_ms if start_ms else now_ms)}"


def build_message(kind: str, key: str, inc: Mapping[str, Any], t: int, *, probe: str, label: str = "",
                  tz: str = "UTC", voice: str = "sysadmin", edge_label: str = "EC", board_url: str | None = None,
                  incident_id: str | None = None) -> dict[str, Any]:
    """One alert message (kind: down | again | flapping | resolved | folded). `inc` is the incident state
    (start, end, flaps, facts{sev, what, since_open, where, also}); `t` is now. Pure."""
    f = inc.get("facts") or {}
    snark = voice != "plain"
    name = clean(label or probe, 64) or probe
    lines: list[str]
    if key == "probe":
        gone = kind != "resolved"
        title = "No results from the probe" if gone else "The probe is reporting again"
        if gone:
            lines = [fin(f"Nothing since {when(inc['start'], tz)}. Nothing on this screen is current")]
        else:
            lines = [fin(f"Silent for {dur(inc['end'] - inc['start'])}")]
        if snark:
            lines.insert(0, "Dead or sulking. Go and look." if gone else "It lives.")
    else:
        names = LABELS.get(key, key)
        sev = f.get("sev", "fail")
        if kind in ("down", "folded"):
            title = HEAD["warn" if sev == "warn" else "fail"].get(key, f"{names} is failing")
            since = ("before " if f.get("since_open") else "") + when(inc["start"], tz)
            what = clean(f.get("what"), 200)
            lines = [fin(f"{cap(what) if what else 'Failing'}, since {since}")]
            w = where_alert_text(f.get("where"), edge_label)
            if w:
                lines.append(w)
            if f.get("also"):
                also = ", ".join(LABELS.get(a, clean(a, 32)) for a in f["also"])
                lines.append(fin("Also failing, probably because of this: " + also))
            if snark:
                wh = f.get("where") or {}
                if key == "wifi" and wh.get("seg") == "ssid":
                    q = tidy(_pick(QUIP_WIFI_OFF, inc["start"]).replace("{sd}", clean(wh.get("sd")) or "nowhere"))
                else:
                    q = _pick(QUIP_DOWN.get(key, QUIP_DOWN["network"]), inc["start"])
                lines.insert(0, q)
        elif kind == "again":
            title = f"{names} is failing again"
            n = inc.get("flaps", 0) + 1
            lines = [fin(f"Failed again at {when(t, tz)}: {n} times since {when(inc['start'], tz)}")]
            if snark:
                lines.insert(0, "Spoke too soon.")
        elif kind == "flapping":
            title = f"{names} is flapping"
            lines = [fin(f"It has failed {inc.get('flaps', 0) + 1} times since {when(inc['start'], tz)}"),
                     "Going quiet until it has been fine for 10 minutes."]
            if snark:
                lines.insert(0, QUIP_FLAP)
        else:
            title = BACK.get(key, f"{names} is back")
            d = dur(inc["end"] - inc["start"])
            over = "over " if f.get("since_open") else ""
            lines = [fin(f"Down {over}{d}: {when(inc['start'], tz)} to {when(inc['end'], tz)}")]
            if inc.get("flaps"):
                lines.append(fin(f"It failed {inc['flaps'] + 1} times in all before settling"))
            if snark:
                lines.insert(0, tidy(f"Back. {d} down. " + _pick(QUIP_BACK, inc["start"])))
    return {"kind": kind, "line": "probe" if key == "probe" else key,
            "label": LABELS.get(key, "Probe") if key != "probe" else "Probe", "probe": name, "board": probe,
            "title": title, "lines": lines, "link": board_link(board_url, probe, inc.get("start"), t),
            "start": inc.get("start"), "end": inc.get("end"), "where": f.get("where"),
            "severity": (f.get("sev", "fail") if kind in ("down", "folded") else "ok"), "incident": incident_id}


# ---------------------------------------------------------------------------------------------- payloads
_ICON = {"down": ":red_circle:", "again": ":red_circle:", "flapping": ":large_orange_circle:",
         "resolved": ":large_green_circle:"}


def payload(fmt: str, m: Mapping[str, Any]) -> dict[str, Any]:
    """The webhook body for one message. Every dynamic string is escaped: probe data can't make links or
    mentions. The only link is the board link built from the configured board_url."""
    icon = _ICON.get(str(m["kind"]), ":white_circle:")
    if m["kind"] == "down" and m.get("severity") == "warn":
        icon = ":large_yellow_circle:"
    label = "Rewind to the start" if m["kind"] == "resolved" else "Open the board at the start"
    link = m.get("link")
    if fmt == "slack":
        text = f"{icon} *{slack_escape(m['title'])}* · {slack_escape(m['probe'])}\n"
        text += "\n".join(slack_escape(ln) for ln in m["lines"])
        if link:
            text += f"\n<{_link_safe(link)}|{label}>"
        return {"text": text}
    if fmt == "teams":
        body = [{"type": "TextBlock", "text": teams_escape(f"{m['title']} · {m['probe']}"), "weight": "Bolder",
                 "size": "Medium", "wrap": True}]
        body += [{"type": "TextBlock", "text": teams_escape(ln), "wrap": True, "spacing": "Small"} for ln in m["lines"]]
        card: dict[str, Any] = {"type": "AdaptiveCard", "version": "1.4", "body": body}
        if link:
            card["actions"] = [{"type": "Action.OpenUrl", "title": label, "url": _link_safe(link)}]
        return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
                                                    "content": card}]}
    out = {k: (v if k == "link" else _jsonify(v)) for k, v in m.items()}
    out["link"] = _link_safe(link) if link else None
    out["text"] = slack_escape(str(m["title"]) + ". " + " ".join(m["lines"]))
    return out


def _link_safe(link: str) -> str:
    """The board link carries only characters that cannot end a Slack link early or break a card."""
    return re.sub(r"[<>|\s\"']", lambda c: urllib.parse.quote(c.group(0)), str(link))


# ----------------------------------------------------------------------------------------- SR-15 guard
class WebhookRefused(Exception):
    """The destination is not allowed (not https, private address, ...). Never carries the URL."""


def _parse_allow(allow: Iterable[str]) -> tuple[set[str], list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    hosts: set[str] = set()
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for a in allow:
        a = str(a).strip().lower()
        if not a:
            continue
        try:
            nets.append(ipaddress.ip_network(a, strict=False))
        except ValueError:
            hosts.add(a.rstrip("."))
    return hosts, nets


def _public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return bool(ip.is_global and not ip.is_multicast and not ip.is_reserved and not ip.is_unspecified
                and not ip.is_loopback and not ip.is_link_local and not ip.is_private)


Resolver = Callable[[str, int], list[str]]


def default_resolver(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        raise WebhookRefused("the host name does not resolve") from None
    return sorted({str(i[4][0]) for i in infos})


def check_destination(url: str, allow: Iterable[str] = (), resolver: Resolver = default_resolver
                      ) -> tuple[str, int, str, str]:
    """SR-15: returns (host, port, path_and_query, ip_to_connect) or raises WebhookRefused. The URL must
    be https, carry no credentials, and every address it resolves to must be public unless the host (or
    the address) is explicitly allowlisted. The caller connects to the returned address (no re-resolve)."""
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port or 443
    except ValueError:
        raise WebhookRefused("the URL is malformed") from None
    if u.scheme != "https":
        raise WebhookRefused("webhook URLs must be https")
    host = (u.hostname or "").rstrip(".")
    if not host or u.username or u.password:
        raise WebhookRefused("the URL has no host or carries credentials")
    if not 0 < port < 65536:
        raise WebhookRefused("the URL port is invalid")
    hosts, nets = _parse_allow(allow)
    addrs = resolver(host, port)
    if not addrs:
        raise WebhookRefused("the host name does not resolve")
    for a in addrs:
        ip = ipaddress.ip_address(a)
        if _public(ip):
            continue
        if host.lower() in hosts or any(ip in n for n in nets if n.version == ip.version):
            continue
        raise WebhookRefused("the destination is a private, loopback or link-local address (not allowlisted)")
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    return host, port, path, addrs[0]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to the address that passed the SR-15 check (no second DNS lookup, so no rebinding), but
    verify the certificate against the URL's host name."""

    def __init__(self, host: str, port: int, ip: str, context: ssl.SSLContext, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)  # type: ignore[attr-defined]


class HttpsTransport:
    """POST a JSON body; returns the HTTP status. Never follows a redirect (a 3xx is a failure)."""

    def __init__(self, *, allow: Iterable[str] = (), ssl_context: ssl.SSLContext | None = None,
                 resolver: Resolver = default_resolver, timeout: float = 10.0) -> None:
        self.allow = tuple(allow)
        self.ssl_context = ssl_context
        self.resolver = resolver
        self.timeout = timeout

    def post(self, url: str, body: bytes) -> int:
        host, port, path, ip = check_destination(url, self.allow, self.resolver)
        ctx = self.ssl_context or ssl.create_default_context()
        conn = _PinnedHTTPSConnection(host, port, ip, ctx, self.timeout)
        try:
            conn.request("POST", path, body, {"Content-Type": "application/json", "Content-Length": str(len(body)),
                                              "User-Agent": "exp-collector", "Connection": "close"})
            resp = conn.getresponse()
            resp.read(65536)
            status = int(resp.status)
        finally:
            conn.close()
        if 300 <= status < 400:
            raise WebhookRefused("the endpoint answered with a redirect (not followed)")
        return status


# --------------------------------------------------------------------------------------------- sender
class WebhookSender:
    """Queues messages and delivers them from one thread so a slow webhook never blocks judgement."""

    def __init__(self, hooks: Callable[[], list[dict[str, str]]], transport: HttpsTransport | None = None, *,
                 backoff_s: Sequence[float] = (5.0, 15.0, 45.0), queue_size: int = 500,
                 on_result: Callable[[str, str, bool], None] | None = None) -> None:
        self._hooks = hooks
        self.transport = transport or HttpsTransport()
        self.backoff_s = tuple(backoff_s)
        self._q: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=queue_size)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.sent = 0
        self.failed = 0
        self.dropped = 0
        self.on_result = on_result
        self._failures: collections.deque[float] = collections.deque(maxlen=1000)

    def start(self) -> None:
        if self._thread is None:
            self._stop.clear()
            self._thread = threading.Thread(target=self._work, name="webhooks", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        try:
            self._q.put_nowait(None)
        except queue.Full:
            pass
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None

    def failures_last_hour(self, now: float | None = None) -> int:
        """Deliveries given up on (or refused) in the last hour: the health metric `webhook_failures_1h`."""
        import time
        t = time.time() if now is None else now
        return sum(1 for x in list(self._failures) if t - x <= 3600)

    def post(self, message: dict[str, Any]) -> None:
        try:
            self._q.put_nowait(message)
        except queue.Full:
            self.dropped += 1
            log.error("alert queue full, dropping a message")

    def drain(self, timeout: float = 10.0) -> bool:
        """Wait until the queue is empty and idle (tests)."""
        deadline = threading.Event()
        for _ in range(int(timeout * 100)):
            if self._q.unfinished_tasks == 0:
                return True
            deadline.wait(0.01)
        return self._q.unfinished_tasks == 0

    def _work(self) -> None:
        while not self._stop.is_set():
            m = self._q.get()
            try:
                if m is None:
                    return
                for hook in self._hooks():
                    self._deliver(hook, m)
            except Exception:  # noqa: BLE001 - judgement and other hooks must keep going
                log.exception("webhook worker error")
            finally:
                self._q.task_done()

    def _deliver(self, hook: Mapping[str, str], m: Mapping[str, Any]) -> None:
        hid = clean(hook.get("id"), 32) or "webhook"
        body = json.dumps(payload(hook.get("format", "slack"), m)).encode()
        attempts = 1 + len(self.backoff_s)
        for attempt in range(attempts):
            reason = ""
            try:
                status = self.transport.post(hook["url"], body)
                if 200 <= status < 300:
                    self.sent += 1
                    log.info("alert %s for %s delivered to %s", m["kind"], m["line"], hid)
                    if self.on_result:
                        self.on_result(hid, str(m["kind"]), True)
                    return
                reason = f"http {status}"
            except WebhookRefused as exc:
                # a refused destination will not get better by retrying; the reason has no URL in it
                self._note_failure()
                log.error("alert %s for %s refused for %s: %s", m["kind"], m["line"], hid, exc)
                if self.on_result:
                    self.on_result(hid, str(m["kind"]), False)
                return
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                reason = type(exc).__name__               # never str(exc): it can contain the URL
            log.warning("alert %s for %s: delivery to %s failed (%s), try %d/%d", m["kind"], m["line"], hid,
                        reason, attempt + 1, attempts)
            if attempt + 1 < attempts and self._stop.wait(self.backoff_s[attempt]):
                return
        self._note_failure()
        if self.on_result:
            self.on_result(hid, str(m["kind"]), False)

    def _note_failure(self) -> None:
        import time
        self.failed += 1
        self._failures.append(time.time())


def hash_seed(*parts: object) -> int:
    """Stable small hash for tests that want to predict a quip."""
    return fnv(":".join(str(p) for p in parts))


__all__ = ["BACK", "HEAD", "HttpsTransport", "WebhookRefused", "WebhookSender", "board_link", "build_message",
           "check_destination", "defang", "hhmm", "payload", "slack_escape", "teams_escape", "when"]

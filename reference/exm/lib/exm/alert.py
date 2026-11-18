"""Push alerts: tell the NOC when a Pulse line fails and when it comes back.

Runs on the collector as exm-alert.service, separate from the dashboard so a bad
webhook can never take the page down. Every board (probe) is judged on its own,
and each message names the probe and links to its board. It follows the results files like the page does, judges each
line with the board's own rules (pulse.py, kept equal to the page by
test/parity.sh), and posts to a webhook:

  down      a line has been failing for hold_fail_s (20 s): what, since when,
            where on the path, and a link to the board at that moment (?at=)
  resolved  it has been fine for hold_ok_s (60 s): how long it was down
  silent    no results at all for 90 s: the probe itself has stopped

Failing again within 5 minutes of recovering reopens the same incident: a short
"failing again" message (a re-failure is never silent), and from the third time
one "flapping" message, then quiet until it has been fine for 10 minutes.
Consequences fold into their cause: while Network fails, DHCP, DNS and Internet
failures ride along in its page ("Also failing") instead of paging on their own;
Internet folds into DNS the same way, and Wi-Fi into Network while the laptop is
on its own network (it lost the same gateway). A line still failing once its
cause has recovered pages then, after its own window has caught up, so the
internet line's slower window doesn't page for an outage that is already over.
A laptop on the wrong network (an AP down) pages on its own.
Open incidents are kept in the state directory, so a restart (exm apply) in the
middle of an outage does not page twice. Every message is also appended to the
board's incident log (/var/lib/exm-collector/incidents/<probe>.jsonl, served at
/api/incidents), webhook or not: the record an RCA starts from.

The webhook URL is a secret: it lives in /etc/exm/alert-webhook (root, 0600) and
reaches this unprivileged service through systemd's LoadCredential. It is never
logged. Formats: slack (also Mattermost and Google Chat), teams (Workflows
webhook, adaptive card), json (everything, for anything else).
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import os
import queue
import re
import socket
import threading
import time
import urllib.parse
import urllib.request
import zoneinfo

from . import collector as K
from . import pulse
from . import tail
from . import web

WEBHOOK_FILE = "/etc/exm/alert-webhook"
HISTORY_MS = 70 * 60000
SILENT_MS = 90000
REOPEN_MS = 5 * 60000
TICK_S = 2
PARENTS = {1: [0], 2: [0], 3: [0, 2]}     # a line's failure is a consequence while these fail (Wi-Fi: see tick)
CALM_MS = 10 * 60000                         # a flapping line is called back only after this long fine

HEAD = {"fail": ["The network is down", "DHCP is failing", "DNS is failing", "The internet is down", "Wi-Fi is down"],
        "warn": ["The network is shaky", "DHCP is partly failing", "DNS is partly failing", "The internet is degraded",
                 "Wi-Fi is degraded"]}
BACK = ["The network is back", "DHCP is back", "DNS is back", "The internet is back", "Wi-Fi is back"]
QUIP_DOWN = [
    ["The gateway has left the building.", "Somebody unplugged something.", "The gateway has stopped taking calls."],
    ["DHCP is out of office.", "New arrivals are queueing at 169.254.", "DHCP has closed the doors."],
    ["It was DNS.", "It's always DNS.", "It's not DNS. There's no way it's DNS. It was DNS."],
    ["The internet is down. No, really.", "We're an intranet now.", "Just us and the LAN."],
    ["Wi-Fi has left the chat.", "The test laptop is sulking.", "Wi-Fi is down. The laptop is not amused."],
]
QUIP_WIFI_OFF = ["The laptop wandered off to {sd}.", "The test laptop has eloped with {sd}.", "The laptop is on {sd}. It was told not to."]
QUIP_BACK = ["Zero apologies.", "Nobody touch anything.", "Someone owes someone a beer.", "Act like it never happened.",
             "Write it down before you forget."]
QUIP_FLAP = "It can't make up its mind."
WHERE = {
    "link": "Where: {ports}: no link. A cable or the switch.",
    "switch": "Where: the wired side. Wi-Fi reaches {ip}, the ports don't: the switch, its uplink or the VLAN.",
    "gateway": "Where: the gateway or the link to it. Neither wired nor Wi-Fi reach {ip}.",
    "lan": "Where: between the ports and {ip}: the switch or the gateway's LAN side.",
    "edge": "Where: the {edge}. The path stops after {lh} (hop {lt}); the management path reaches {target} around it.",
    "isp": "Where: upstream of the {edge}. The management path can't reach {target} either.",
    "wan": "Where: past the gateway. The path to {target} stops after {lh} (hop {lt}).",
    "resolver": "Where: the resolver. {sx} isn't answering, {ax} is.",
    "dns_path": "Where: DNS on the way out. The path is up, but neither {sx} nor {ax} answers.",
    "apps": "Where: the apps or their CDNs. The path and DNS are fine.",
    "dhcp": "Where: the DHCP server{sv}. The gateway answers, offers don't come.",
    "ssid": "Where: the AP or SSID. The laptop can't get on {tg}{sdpart}.",
    "wifi": "Where: the Wi-Fi side: the AP, its uplink or the WLAN. Wired reaches the gateway.",
}


def _addr(x) -> str:
    """An address from probe data, or "?" if it isn't one (it goes into chat messages)."""
    try:
        return str(ipaddress.ip_address(str(x)))
    except ValueError:
        return "?"


def _ident(x) -> str:
    return str(x) if re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", str(x)) else "?"


def _slack(s: str) -> str:
    """Slack mrkdwn treats & < > as control characters (<url|label> is a link): escape them in anything dynamic."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _teams(s: str) -> str:
    """Adaptive Card text is markdown: no [label](url) links from probe data."""
    return str(s).replace("[", "(").replace("]", ")")


def _pick(pool: list, seed) -> str:
    return pool[int(hashlib.sha1(str(seed).encode()).hexdigest(), 16) % len(pool)]


def _dur(ms_: float) -> str:
    s = max(0, round(ms_ / 1000))
    if s < 90:
        return f"{s} seconds"
    m = round(s / 60)
    if m < 90:
        return f"{m} minutes"
    h, r = divmod(m, 60)
    return f"{h} hour{'s' if h != 1 else ''}" + (f" {r} minutes" if r else "")


def webhook_url(cfg: dict) -> str | None:
    """The webhook URL from systemd's credential (the service) or the root-only file (a root shell).
    None when there is none (the unit's SetCredential fallback is empty): incidents are then only logged."""
    cred = os.environ.get("CREDENTIALS_DIRECTORY")
    paths = ([os.path.join(cred, "webhook")] if cred else []) + [cfg.get("alerts", {}).get("url_file", WEBHOOK_FILE)]
    for p in paths:
        try:
            with open(p) as fh:
                url = fh.read().strip()
        except (FileNotFoundError, PermissionError):
            continue
        if not url:
            return None
        u = urllib.parse.urlsplit(url)
        if u.scheme == "https" or (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1")):
            return url
        raise SystemExit(f"exm alert: the webhook in {p} must be https:// (http:// only to localhost)")
    return None


class Alerter:
    def __init__(self, cfg: dict, post, state_file: str):
        self.cfg = cfg
        a = cfg.get("alerts", {})
        self.post = post
        self.fmt = a.get("format", "slack")
        self.board = (a.get("board_url") or f"http://{socket.gethostname()}/").rstrip("/") + "/"
        self.tz = zoneinfo.ZoneInfo(a.get("timezone", "UTC"))
        self.voice = a.get("voice") or cfg.get("web", {}).get("voice", "sysadmin")
        self.edge = cfg.get("web", {}).get("edge_label", "WAN edge")
        names = a.get("lines", pulse.LANES)
        self.lanes = [i for i, n in enumerate(pulse.LANES) if n in names]
        self.on_warn = bool(a.get("warn", False))
        self.hold_fail = int(float(a.get("hold_fail_s", 20)) * 1000)
        self.hold_ok = int(float(a.get("hold_ok_s", 60)) * 1000)
        self.state_path = state_file
        self.pool: list[dict] = []
        self.keys: set = set()
        self.inc: dict[str, dict] = {}
        try:
            with open(self.state_path) as fh:
                self.inc = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    # ---- input
    def add(self, ev: dict, mtime: float | None = None) -> None:
        if ev.get("test") not in web.LIVE_TESTS:
            return
        try:
            c = web.compact(ev, mtime)
            k = (c["w"], c["k"], c["c"], c["g"], c["r"])
            pulse.ms(c["w"])
        except (TypeError, ValueError, AttributeError, KeyError):
            return                                  # a line the board would skip too
        if k not in self.keys:
            self.keys.add(k)
            self.pool.append(c)

    def trim(self, t: int) -> None:
        self.pool.sort(key=lambda c: c["w"])
        cut = next((i for i, c in enumerate(self.pool) if t - pulse.ms(c["w"]) <= HISTORY_MS), len(self.pool))
        if cut:
            for c in self.pool[:cut]:
                self.keys.discard((c["w"], c["k"], c["c"], c["g"], c["r"]))
            del self.pool[:cut]

    # ---- judgement
    def tick(self, t: int) -> None:
        pool = [c for c in self.pool if pulse.ms(c["w"]) <= t]
        newest = max((pulse.ms(c["w"]) for c in pool), default=None)
        self._step("probe", newest is not None and t - newest > SILENT_MS, newest is not None, t,
                   lambda: {"since": newest})
        if newest is None or t - newest > SILENT_MS:
            self._save()
            return
        bsets, st = pulse.states(pool, t)
        bad = {i: st[i]["s"] == "fail" or (self.on_warn and st[i]["s"] == "warn") for i in range(5)}
        w = pulse.find_last(pool, lambda c: c.get("k") == "wifi_hb" and t - pulse.ms(c["w"]) <= pulse.RECENT)
        wifi_home = bool(w and w.get("sd") and (not w.get("tg") or w.get("sd") == w.get("tg")))
        parents = {**PARENTS, **({4: [0]} if wifi_home else {})}
        for i in self.lanes:
            s = st[i]["s"]
            good = s == "ok" or (s == "warn" and not self.on_warn)
            blocked = any(bad[p] or self.inc.get(str(p), {}).get("phase") in ("pending", "open") for p in parents.get(i, []))
            also = [pulse.LANES[j] for j in self.lanes if bad[j] and i in parents.get(j, [])]
            self._step(str(i), bad[i], good, t, lambda i=i, s=s, also=also: dict(self._facts(i, s, pool, bsets, st, t, w), also=also),
                       blocked, pulse.STATE_WINDOW[i])
        self._save()

    def _step(self, key: str, bad: bool, good: bool, t: int, facts, blocked: bool = False, window: int = 0) -> None:
        inc = self.inc.get(key)
        if bad:
            if inc and inc["phase"] == "closed" and t - inc["end"] < REOPEN_MS:
                inc.update(phase="pending", bad_since=t, reopen=True)             # failing again soon after: same incident
            elif not inc or inc["phase"] == "closed":
                f = facts()
                self.inc[key] = {"phase": "pending", "bad_since": t, "start": f.get("since") or t, "facts": f}
                inc = self.inc[key]
            if inc["phase"] == "pending":
                if blocked:
                    inc["blocked_at"] = t                                           # its cause is paging for it
                held = t - inc["bad_since"] >= self.hold_fail
                caught_up = t - inc.get("blocked_at", 0) >= max(self.hold_fail, window)
                if held and caught_up and not blocked:
                    if inc.get("reopen"):
                        inc.update(phase="open", ok_since=None, reopen=False, flaps=inc.get("flaps", 0) + 1)
                        if inc["flaps"] >= 3 and not inc.get("muted"):
                            inc["muted"] = True
                            self.post(self.message("flapping", key, inc, t))
                        elif not inc.get("muted"):
                            self.post(self.message("again", key, inc, t))
                    else:
                        f = facts()
                        inc.update(phase="open", facts=f, ok_since=None, flaps=0, start=f.get("since") or inc["start"])
                        self.post(self.message("down", key, inc, t))
            else:
                inc["ok_since"] = None
        elif good:
            if inc and inc["phase"] == "pending":
                if inc.get("reopen"):
                    inc.update(phase="closed", reopen=False)                        # a blip after recovery: still closed
                else:
                    del self.inc[key]                                               # never paged: a blip
            elif inc and inc["phase"] == "open":
                if not inc.get("ok_since"):
                    inc["ok_since"] = t
                elif t - inc["ok_since"] >= (CALM_MS if inc.get("muted") else self.hold_ok):
                    inc.update(phase="closed", end=inc["ok_since"], muted=False)
                    self.post(self.message("resolved", key, inc, t))
            elif inc and inc["phase"] == "closed" and t - inc["end"] >= REOPEN_MS:
                del self.inc[key]
        # neither (no data for a line): an open incident stays open until it is seen to be fine

    def _facts(self, i: int, s: str, pool: list, bsets: list, st: list, t: int, w: dict | None = None) -> dict:
        since = pulse.since_of(bsets[i], s == "fail")
        f = {"lane": i, "sev": s, "since": since["t"], "since_open": since["open"]}
        recent = [c for c in pool if t - pulse.ms(c["w"]) <= 60000]
        g = pulse.find_last(recent, lambda c: c.get("k") == "gateway")
        if i == 0 and g:
            f["what"] = "; ".join([f"gateway {_addr(ip)} not answering on {int(bad)} of {int(n)} ports" for ip, bad, n in g.get("ug") or []]
                                  + ([f"no link on {', '.join(_ident(x) for x in g['nl'])}"] if g.get("nl") else [])) or None
        else:
            errs = [c for c in recent if c.get("l") == i and c.get("e") and c.get("o") != "ok"]
            e = pulse.find_last(errs, lambda c: str(c.get("k", "")).endswith("_hb")) or pulse.find_last(errs, lambda c: True)
            if e:
                f["what"] = re.sub(r"\b(\d{4,})(\.\d+)? ?milliseconds\b", lambda m: f"{round(int(m.group(1)) / 1000)} s",
                                   e["e"])[:200].rstrip(". ")
            else:
                x = st[i]
                f["what"] = f"{x['f']} of {x['n']} checks failed in the last {pulse.STATE_WINDOW[i] // 1000} s" if x["n"] else None
        if i == 4:                       # the laptop's own story, not the wired one
            home = bool(w and w.get("sd") and (not w.get("tg") or w.get("sd") == w.get("tg")))
            f["where"] = (None if not w else {"seg": "ssid", "tg": w.get("tg"), "sd": w.get("sd")} if not home
                          else {"seg": "wifi"} if not w.get("gk") and st[0]["s"] == "ok" else None)
        else:
            f["where"] = pulse.where_of(pool, t, st)
        return f

    # ---- words
    def _when(self, ms_: int | None) -> str:
        if not ms_:
            return "?"
        return datetime.datetime.fromtimestamp(ms_ / 1000, self.tz).strftime("%H:%M:%S %Z")

    def _link(self, ms_: int | None) -> str:
        at = datetime.datetime.fromtimestamp((ms_ or time.time() * 1000) / 1000, datetime.timezone.utc)
        return (self.board + "?probe=" + urllib.parse.quote(self.cfg["probe_id"]) + "&at="
                + at.strftime("%Y-%m-%dT%H:%M:%SZ"))

    def _where(self, w: dict | None) -> str | None:
        if not w:
            return None
        f = dict(w, edge=self.edge, ports=", ".join(w.get("ports") or []), sv=f" ({w['sv']})" if w.get("sv") else "",
                 sdpart=f" (it is on {w['sd']})" if w.get("sd") else "", lh=w.get("lh") or "the first hop", lt=w.get("lt") or "?")
        return re.sub(r"\{(\w+)\}", lambda m: str(f.get(m.group(1)) if f.get(m.group(1)) is not None else ""),
                      WHERE.get(w["seg"], ""))

    def message(self, kind: str, key: str, inc: dict, t: int) -> dict:
        probe = self.cfg.get("label") or self.cfg["probe_id"]
        f = inc.get("facts") or {}
        snark = self.voice != "plain"
        if key == "probe":
            gone = kind != "resolved"
            title = "No results from the probe" if gone else "The probe is reporting again"
            lines = ([f"Nothing since {self._when(inc['start'] if kind == 'down' else t)}. The board is not current."] if gone
                     else [f"Silent for {_dur(inc['end'] - inc['start'])}."])
            if snark:
                lines.insert(0, "Dead or sulking. Go and look." if gone else "It lives.")
        else:
            i = int(key)
            sev = f.get("sev", "fail")
            if kind == "down":
                title = HEAD[sev if sev in HEAD else "fail"][i]
                since = ("before " if f.get("since_open") else "") + self._when(inc["start"])
                lines = [(f["what"][0].upper() + f["what"][1:] if f.get("what") else "Failing") + f", since {since}."]
                w = self._where(f.get("where"))
                if w:
                    lines.append(w)
                if f.get("also"):
                    lines.append("Also failing, probably because of this: " + ", ".join(f["also"]) + ".")
                if snark:
                    wh = f.get("where") or {}
                    q = (_pick(QUIP_WIFI_OFF, inc["start"]).replace("{sd}", wh.get("sd") or "nowhere")
                         if i == 4 and wh.get("seg") == "ssid" else _pick(QUIP_DOWN[i], inc["start"]))
                    lines.insert(0, q)
            elif kind == "again":
                title = f"{pulse.LANES[i]} is failing again"
                lines = [f"Failed again at {self._when(t)}: {inc['flaps'] + 1} times since {self._when(inc['start'])}."]
                if snark:
                    lines.insert(0, "Spoke too soon.")
            elif kind == "flapping":
                title = f"{pulse.LANES[i]} is flapping"
                lines = [f"It has failed {inc['flaps'] + 1} times since {self._when(inc['start'])}. "
                         "Going quiet until it has been fine for 10 minutes."]
                if snark:
                    lines.insert(0, QUIP_FLAP)
            else:
                title = BACK[i]
                d = _dur(inc["end"] - inc["start"])
                lines = [f"Down {'over ' if f.get('since_open') else ''}{d}: {self._when(inc['start'])} to {self._when(inc['end'])}."]
                if inc.get("flaps"):
                    lines.append(f"It failed {inc['flaps'] + 1} times in all before settling.")
                if snark:
                    lines.insert(0, f"Back. {d} down. " + _pick(QUIP_BACK, inc["start"]))
        link = self._link(inc["start"])
        return {"kind": kind, "line": "probe" if key == "probe" else pulse.LANES[int(key)], "probe": probe,
                "board": self.cfg["probe_id"], "title": title,
                "lines": lines, "link": link, "start": inc["start"], "end": inc.get("end"),
                "where": f.get("where"), "severity": f.get("sev", "fail") if kind == "down" else "ok"}

    def _save(self) -> None:
        try:
            with open(self.state_path + ".tmp", "w") as fh:
                json.dump(self.inc, fh)
            os.replace(self.state_path + ".tmp", self.state_path)
        except OSError as exc:
            print(f"exm alert: cannot save state: {exc}", flush=True)


def payload(fmt: str, m: dict) -> dict:
    """The webhook body for one message in the configured format."""
    icon = {"down": ":red_circle:", "again": ":red_circle:", "flapping": ":large_orange_circle:",
            "resolved": ":large_green_circle:"}.get(m["kind"], ":white_circle:")
    if m["kind"] == "down" and m.get("severity") == "warn":
        icon = ":large_yellow_circle:"
    label = "Rewind to the start" if m["kind"] == "resolved" else "Open the board at the start"
    if fmt == "slack":         # every dynamic string is escaped: probe data can't make links or mentions
        return {"text": f"{icon} *{_slack(m['title'])}* · {_slack(m['probe'])}\n" + "\n".join(_slack(ln) for ln in m["lines"])
                + f"\n<{m['link']}|{label}>"}
    if fmt == "teams":
        body = [{"type": "TextBlock", "text": _teams(f"{m['title']} · {m['probe']}"), "weight": "Bolder", "size": "Medium", "wrap": True}]
        body += [{"type": "TextBlock", "text": _teams(ln), "wrap": True, "spacing": "Small"} for ln in m["lines"]]
        return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
            "type": "AdaptiveCard", "version": "1.4", "body": body,
            "actions": [{"type": "Action.OpenUrl", "title": label, "url": m["link"]}]}}]}
    return dict(m, text=m["title"] + ". " + " ".join(m["lines"]))


def sender(cfg: dict, url: str):
    """A post() that queues messages and delivers them from one thread, retrying, never blocking judgement."""
    fmt = cfg.get("alerts", {}).get("format", "slack")
    q: queue.Queue = queue.Queue(maxsize=500)

    def work():
        while True:
            m = q.get()
            body = json.dumps(payload(fmt, m)).encode()
            for attempt in range(4):
                try:
                    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
                    with urllib.request.urlopen(req, timeout=10) as r:
                        r.read()
                    print(f"exm alert: sent {m['kind']} for {m['line']}", flush=True)
                    break
                except Exception as exc:                 # the URL never goes in the log, only the reason
                    reason = getattr(exc, "code", None) or type(exc).__name__
                    print(f"exm alert: delivery of {m['kind']} for {m['line']} failed ({reason}), try {attempt + 1}/4", flush=True)
                    time.sleep(5 * 2 ** attempt)

    threading.Thread(target=work, daemon=True).start()

    def post(m: dict) -> None:
        try:
            q.put_nowait(m)
        except queue.Full:
            print("exm alert: queue full, dropping a message", flush=True)
    return post


def incident_logger(path: str, post=None):
    """A post() that appends each message to the board's incident log, then hands it to the webhook (if any)."""
    def log(m: dict) -> None:
        rec = {"ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")}
        rec.update(m)
        for k in ("start", "end"):
            if rec.get(k):
                rec[k + "_iso"] = datetime.datetime.fromtimestamp(rec[k] / 1000, datetime.timezone.utc).isoformat(
                    timespec="seconds").replace("+00:00", "Z")
        try:
            os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
            with open(path, "a") as fh:
                fh.write(json.dumps(rec, separators=(",", ":"), default=str) + "\n")
        except OSError as exc:
            print(f"exm alert: cannot log incident: {exc}", flush=True)
        if post:
            post(m)
    return log


def follow(cfg: dict, post=None) -> int:
    """cfg: the collector's configuration. One Alerter per board; every message is logged, and sent if there is a webhook."""
    if post is None:
        url = webhook_url(cfg)
        post = sender(cfg, url) if url else None
        print("exm alert: " + ("posting to the webhook and logging incidents" if url else
                                f"no webhook ({WEBHOOK_FILE}): logging incidents only"), flush=True)
    watch = []
    now = datetime.datetime.now(datetime.timezone.utc)
    since = now - datetime.timedelta(milliseconds=HISTORY_MS)
    for b in K.boards(cfg):
        bc = K.board_cfg(cfg, b)
        al = Alerter(bc, incident_logger(bc["incidents"], post), K.state_path(cfg, f"alert-{b['name']}.json"))
        followers = [tail.Follower(d, web.LIVE_TESTS) for d in bc["results_dirs"]]
        for d in bc["results_dirs"]:
            for day in sorted({since.date().isoformat(), now.date().isoformat()}):
                for test in web.LIVE_TESTS:
                    for ev in tail.lines_since(os.path.join(d, day, f"{test}.jsonl"), since):
                        al.add(ev)
        watch.append((al, followers))
        print(f"exm alert: watching {', '.join(pulse.LANES[i] for i in al.lanes)} on {b['name']}; "
              f"{len(al.pool)} results loaded, {sum(1 for x in al.inc.values() if x['phase'] == 'open')} incidents open", flush=True)
    if not watch:
        print("exm alert: no probes configured yet; waiting", flush=True)
    while True:
        for al, followers in watch:
            try:
                for f in followers:
                    for ev, mtime in f.poll():
                        al.add(ev, mtime)
                t = int(time.time() * 1000)
                al.trim(t)
                al.tick(t)
            except Exception as exc:                      # judgement must keep running, board by board
                print(f"exm alert: {al.cfg['probe_id']}: {type(exc).__name__}: {exc}", flush=True)
        time.sleep(TICK_S)


def test_message(cfg: dict, dry_run: bool) -> int:
    """Post (or print) a sample of each message, so the format can be checked in the channel."""
    bs = K.boards(cfg)
    bc = K.board_cfg(cfg, bs[0]) if bs else dict(K.board_cfg(cfg, {"name": "example-probe", "label": "example-probe",
                                                                   "results_dir": "/nonexistent"}))
    al = Alerter(bc, lambda m: None, "/nonexistent/alert-test.json")
    t = int(time.time() * 1000)
    start = t - 52 * 60000
    inc = {"start": start, "end": t - 60000, "flaps": 2, "facts": {
        "lane": 2, "sev": "fail", "since": start, "what": "no answer from 8.8.8.8 within 2 s",
        "where": {"seg": "resolver", "sx": "8.8.8.8", "ax": "1.1.1.1"}}}
    msgs = [al.message("down", "2", inc, t), al.message("resolved", "2", inc, t)]
    for m in msgs:
        m["title"] = "[TEST] " + m["title"]
    fmt = cfg.get("alerts", {}).get("format", "slack")
    if dry_run:
        for m in msgs:
            print(json.dumps(payload(fmt, m), indent=2))
        return 0
    url = webhook_url(cfg)
    if not url:
        raise SystemExit(f"exm alert: no webhook: put the URL in {WEBHOOK_FILE} (root, mode 0600)")
    for m in msgs:
        req = urllib.request.Request(url, data=json.dumps(payload(fmt, m)).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            print(f"exm alert: test {m['kind']} sent ({r.status})")
    return 0

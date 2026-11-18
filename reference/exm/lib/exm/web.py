"""The collector's read-only dashboard: one Pulse board per probe, and an overview of them all.

  GET /                 the overview with several boards, the board itself with one
  GET /?probe=NAME      a probe's Pulse board (static/pulse.html, its rules in static/pulse-core.js)
  GET /events?probe=    Server-Sent Events: each result the moment its line is written
  GET /api/history      N minutes of a board's results (?probe=&minutes=15), ending now or at ?at=<UTC time>
  GET /api/summary      a board's details tables: the probe's own summary, plus Wi-Fi from its laptops
  GET /api/boards       every board's lines right now, for the overview
  GET /api/incidents    a board's incident log (?probe=&hours=24): every down / again / flapping / back

Nothing here writes anywhere or runs a test. Each board follows its results
directories four times a second and pushes new lines to every open page, so a
result reaches the screen within about half a second of being stored.
"""
from __future__ import annotations

import datetime
import http.server
import json
import os
import queue
import re
import threading
import time
import urllib.parse

from . import collector as K
from . import config as C
from . import events
from . import pulse
from . import report
from . import tail

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
LIVE_TESTS = ("gateway", "dhcp_hb", "dhcp", "dns_hb", "dns", "app", "speedtest", "wifi_hb", "wifi_app", "wifi_speed",
              "trace", "trace_ctl")
VOICES = ("sysadmin", "plain")
POLL_S = 0.25
SUMMARY_EVERY_S = 30


def lane_of(ev: dict) -> int | None:
    """Which Pulse line a result belongs to: 0 network, 1 DHCP, 2 DNS, 3 internet, 4 Wi-Fi."""
    t = ev.get("test")
    if ev.get("outcome") == C.HARNESS:
        return None                                  # our own failures never count against the network
    if t == "gateway":
        return 0
    if t in ("dhcp", "dhcp_hb"):
        return 1
    if t in ("dns", "dns_hb"):
        # The resolver clients actually use: "dhcp", or "dhcp1" when DHCP hands out several (clients try the first).
        return 2 if ev.get("resolver") in ("dhcp", "dhcp1") else None
    if t == "app":
        return None if str(ev.get("target") or "").startswith("lab-server") else 3
    if t == "speedtest":
        return 3
    if t == "wifi_hb":
        return 4               # wifi_app and wifi_speed go to the details only, never mixed into a row
    return None


def _map(x) -> dict:
    return x if isinstance(x, dict) else {}


def _nums(xs) -> list:
    return [x for x in xs if isinstance(x, (int, float)) and not isinstance(x, bool)]


def _headline_ms(ev: dict):
    v, ph = _map(ev.get("value")), _map(ev.get("phase_ms"))
    t = ev.get("test")
    if t == "dhcp":
        return ph.get("total")
    if t == "dhcp_hb":
        return ph.get("offer")
    if t == "wifi_hb":
        return ph.get("gateway")
    if t == "dns_hb":
        return ph.get("rtt")
    if t == "dns":
        rtts = [row[3] for row in v.get("detail", []) if isinstance(row, list) and len(row) > 3
                and isinstance(row[3], (int, float))]
        return events.median(rtts)
    if t == "app":
        return v.get("sample_ms")
    if t == "gateway":
        return ph.get("rtt_p50")
    if t == "speedtest":
        return v.get("down_mbps")
    return None


def compact(ev: dict, written: float | None = None) -> dict:
    """The few fields the page needs. Text is passed as data and rendered with textContent."""
    out = {"t": ev.get("ts"), "w": ev.get("emitted") or (events.utc_iso(written) if written else ev.get("ts")),
           "k": ev.get("test"), "c": ev.get("client_id"), "g": ev.get("target"), "r": ev.get("resolver"),
           "o": ev.get("outcome"), "m": _headline_ms(ev), "l": lane_of(ev)}
    if ev.get("error"):
        out["e"] = str(ev["error"])[:160]
    if ev.get("test") == "gateway":
        v = _map(ev.get("value"))
        out["up"], out["n"] = v.get("up"), v.get("total")
        out["down"], out["flap"] = v.get("down", []), v.get("flapped", [])
        # Which gateway each port failed to reach, and ports with no link at all: the "why" for the Network line.
        gws, nolink = {}, []
        for pid, pr in sorted(_map(v.get("ports")).items()):
            pr = _map(pr)
            if pr.get("carrier") is False:
                nolink.append(pid)
            elif pr.get("gateway"):
                g = gws.setdefault(str(pr["gateway"]), [0, 0])
                g[1] += 1
                if not pr.get("ok"):
                    g[0] += 1
        out["ug"] = [[ip, bad, total] for ip, (bad, total) in sorted(gws.items()) if bad]
        out["nl"] = nolink
    if ev.get("test") == "dns_hb":
        v = _map(ev.get("value"))
        alt = _map(v.get("alt"))
        out["sx"] = v.get("server")
        if "ping_ms" in v:
            out["sp"] = v.get("ping_ms")                  # the resolver answers ping (ms), or None
        if alt:
            out["ax"], out["ao"] = alt.get("server"), alt.get("ok")
            if "ping_ms" in alt:
                out["ap"] = alt.get("ping_ms")
    if ev.get("test") == "dhcp_hb":
        out["sv"] = _map(ev.get("value")).get("server_id")
    if ev.get("test") in ("trace", "trace_ctl"):
        v = _map(ev.get("value"))
        hops = v.get("hops") if isinstance(v.get("hops"), list) else []
        out["rc"], out["lh"], out["lt"], out["dt"] = v.get("reached"), v.get("last_ip"), v.get("last_ttl"), v.get("dest_ttl")
        out["hp"] = [h[1] if isinstance(h, list) and len(h) > 1 else None for h in hops][:30]
    if ev.get("test") == "wifi_hb":
        v = _map(ev.get("value"))
        out["rs"], out["p"] = v.get("rssi"), ev.get("probe_id")
        out["sd"], out["tg"] = v.get("ssid"), v.get("target_ssid")
        out["gk"] = isinstance(_map(ev.get("phase_ms")).get("gateway"), (int, float))   # the gateway answered over Wi-Fi
    return out


def wifi_summary(cfg: dict, minutes: int) -> dict:
    """Per laptop attached to the board: the link now, and its checks over the window. One bad laptop costs only its row."""
    out = {}
    for r in cfg.get("remote", []):
        try:
            evs = report.load({"results_dir": r.get("results_dir", cfg["results_dir"])}, minutes,
                              tests={"wifi_hb", "wifi_app", "wifi_speed"})
            out[r["name"]] = _wifi_row(r, [e for e in evs if e.get("probe_id") == r["name"]])
        except Exception as exc:
            print(f"web: Wi-Fi summary error for {r['name']}: {exc}", flush=True)
            out[r["name"]] = {"label": r["label"], "seen": False, "error": "summary failed"}
    return out


def _wifi_row(r: dict, mine: list) -> dict:
    hb = [e for e in mine if e.get("test") == "wifi_hb"]
    row = {"label": r["label"], "seen": bool(mine), "want_ssid": r.get("ssid")}
    if hb:
        v = _map(hb[-1].get("value"))
        row.update({k: v.get(k) for k in ("ssid", "channel", "security", "rssi", "noise", "snr", "tx_rate", "ip",
                                          "gateway", "dns_server", "dhcp_server", "lease_s", "target_ssid")})
        ph = [_map(e.get("phase_ms")) for e in hb]
        rssi = _nums(_map(e.get("value")).get("rssi") for e in hb)
        row.update(beats=len(hb), ok_pct=round(100 * sum(e.get("outcome") in (C.OK, C.DEGRADED) for e in hb) / len(hb), 1),
                   gw_p50=events.pct(_nums(p.get("gateway") for p in ph), 50),
                   gw_p95=events.pct(_nums(p.get("gateway") for p in ph), 95),
                   dns_p50=events.pct(_nums(p.get("dns") for p in ph), 50),
                   rssi_min=min(rssi) if rssi else None, rssi_p50=events.median(rssi),
                   last=hb[-1].get("emitted") or hb[-1].get("ts"))
    apps = {}
    for e in mine:
        if e.get("test") == "wifi_app":
            apps.setdefault(str(e.get("target") or "?"), []).append(e)
    row["apps"] = {a: {"n": len(es), "ok_pct": round(100 * sum(e.get("outcome") == C.OK for e in es) / len(es), 1),
                       "p50": events.pct(_nums(_map(e.get("value")).get("sample_ms") for e in es), 50),
                       "last": es[-1].get("outcome")}
                   for a, es in sorted(apps.items())}
    sp = [e for e in mine if e.get("test") == "wifi_speed"]
    if sp:
        row["speed"] = dict(_map(sp[-1].get("value")), outcome=sp[-1].get("outcome"), ts=sp[-1].get("ts"))
    return row


class Hub:
    """One board: follows its results directories and fans new results out to every page showing it."""

    def __init__(self, cfg: dict, boards: int = 1):
        self.cfg, self.boards = cfg, boards
        self.dirs = cfg.get("results_dirs") or [cfg["results_dir"]]
        self.subs: set[queue.Queue] = set()
        self.lock = threading.Lock()
        self.last_fail: dict[int, str] = {}
        self.summary: dict = {}
        self._status, self._status_at = None, 0.0
        self.followers = [tail.Follower(d, LIVE_TESTS) for d in self.dirs]
        threading.Thread(target=self._scan_last_fail, daemon=True).start()
        threading.Thread(target=self._follow, daemon=True).start()
        threading.Thread(target=self._summarize, daemon=True).start()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=2000)
        with self.lock:
            self.subs.add(q)
        return q

    def unsubscribe(self, q) -> None:
        with self.lock:
            self.subs.discard(q)

    def _note_fail(self, c: dict) -> None:
        if c["l"] is not None and c["o"] in (C.FAIL, C.PORTAL):
            if c["w"] > self.last_fail.get(c["l"], ""):
                self.last_fail[c["l"]] = c["w"]

    def _scan_last_fail(self) -> None:
        """Newest failure per line in the last 24 h, so 'no failed tests for X' is true from the start."""
        now = datetime.datetime.now(datetime.timezone.utc)
        floor = now - datetime.timedelta(hours=24)
        days = sorted({floor.date().isoformat(), now.date().isoformat()}, reverse=True)
        for d in self.dirs:
            for test in LIVE_TESTS:
                for day in days:
                    path = os.path.join(d, day, f"{test}.jsonl")
                    ev = tail.newest_matching(path, lambda e: lane_of(e) is not None and e.get("outcome") in (C.FAIL, C.PORTAL), floor)
                    if ev:
                        self._note_fail(compact(ev))
                        break

    def _follow(self) -> None:
        while True:
            batch = []
            for f in self.followers:
                try:
                    batch += f.poll()
                except Exception as exc:                  # never let a bad line stop the stream
                    print(f"web: follower error: {exc}", flush=True)
            if batch:
                read_ms = int(time.time() * 1000)
                msgs = []
                for ev, mtime in batch:
                    if ev.get("test") not in LIVE_TESTS:
                        continue
                    try:                                  # a bad line costs only itself, never the stream
                        c = compact(ev, mtime)
                        c["s"] = read_ms
                        self._note_fail(c)
                        msgs.append(json.dumps(c, separators=(",", ":"), allow_nan=False))
                    except (TypeError, ValueError, AttributeError) as exc:
                        print(f"web: skipped a result: {exc}", flush=True)
                with self.lock:
                    subs = list(self.subs)
                for q in subs:
                    for m in msgs:
                        try:
                            q.put_nowait(m)
                        except queue.Full:
                            pass                          # a stalled page reloads history when it reconnects
            time.sleep(POLL_S)

    def _summarize(self) -> None:
        """The probe publishes its own details tables every minute (a "summary" result); Wi-Fi is added here."""
        while True:
            try:
                now = datetime.datetime.now(datetime.timezone.utc)
                ev = None
                for day in sorted({(now - datetime.timedelta(hours=1)).date().isoformat(), now.date().isoformat()}, reverse=True):
                    ev = tail.newest_matching(os.path.join(self.cfg["results_dir"], day, "summary.jsonl"),
                                              lambda e: isinstance(e.get("value"), dict), now - datetime.timedelta(minutes=15))
                    if ev:
                        break
                summary = dict(_map(ev.get("value"))) if ev else {
                    "generated": None, "clients": {}, "resolvers": {}, "apps": {}, "servers": {},
                    "note": "no summary from the probe in the last 15 minutes"}
                for k in ("clients", "resolvers", "apps", "servers"):
                    summary[k] = _map(summary.get(k))
                summary["probe"] = self.cfg["probe_id"]
                try:
                    summary["wifi"] = wifi_summary(self.cfg, 60)
                except Exception as exc:                  # the wired summary must not depend on the Wi-Fi one
                    print(f"web: Wi-Fi summary error: {exc}", flush=True)
                self.summary = summary
            except Exception as exc:
                print(f"web: summary error: {exc}", flush=True)
            time.sleep(SUMMARY_EVERY_S)

    def history(self, minutes: int, at: datetime.datetime | None = None) -> dict:
        now = datetime.datetime.now(datetime.timezone.utc)
        until = min(at, now) if at else now
        since = until - datetime.timedelta(minutes=minutes)
        days = sorted({since.date().isoformat(), until.date().isoformat()})
        evs = []
        for d in self.dirs:
            for day in days:
                for test in LIVE_TESTS:
                    path = os.path.join(d, day, f"{test}.jsonl")
                    evs.extend(tail.lines_between(path, since, until) if at else tail.lines_since(path, since))
        out = []
        for e in evs:
            try:
                c = compact(e)
                json.dumps(c, allow_nan=False)
            except (TypeError, ValueError, AttributeError):
                continue
            out.append(c)
        out.sort(key=lambda c: str(c["w"]))
        voice = self.cfg.get("web", {}).get("voice", "sysadmin")
        return {"now": int(time.time() * 1000), "probe": self.cfg["probe_id"], "label": self.cfg.get("label") or self.cfg["probe_id"],
                "boards": self.boards, "voice": voice if voice in VOICES else "sysadmin", "at": tail.iso(until) if at else None,
                "edge": str(self.cfg.get("web", {}).get("edge_label", "WAN edge"))[:40],
                "events": out, "last_fail": {} if at else {str(k): v for k, v in self.last_fail.items()}}

    def status(self) -> dict:
        """This board's lines right now, judged by the same rules as the page (pulse.py), for the overview."""
        if self._status and time.time() - self._status_at < 3:
            return self._status
        h = self.history(16)
        t = h["now"]
        _, st = pulse.states(h["events"], t)
        w = pulse.where_of(h["events"], t, st)
        newest = max((pulse.ms(c["w"]) for c in h["events"]), default=None)
        self._status = {"name": self.cfg["probe_id"], "label": h["label"], "lines": [x["s"] for x in st],
                        "where": w, "newest_s": None if newest is None else round((t - newest) / 1000)}
        self._status_at = time.time()
        return self._status


def _handler(hubs: dict):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = f"exm-web/{C.AGENT_VER}"
        sys_version = ""

        def log_message(self, fmt, *args):
            pass

        def _send(self, code: int, body: bytes, ctype: str):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code: int = 200):
            self._send(code, json.dumps(obj, separators=(",", ":"), default=str).encode(), "application/json")

        def _static(self, name: str, ctype: str):
            with open(os.path.join(STATIC, name), "rb") as fh:
                self._send(200, fh.read(), ctype)

        def _hub(self, qs):
            name = (qs.get("probe") or [None])[0]
            if name is None and len(hubs) == 1:
                return next(iter(hubs.values()))
            return hubs.get(name)

        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            qs = urllib.parse.parse_qs(u.query)
            try:
                if u.path in ("/", "/index.html"):
                    self._static("pulse.html" if qs.get("probe") or len(hubs) == 1 else "overview.html", "text/html; charset=utf-8")
                elif u.path == "/overview":
                    self._static("overview.html", "text/html; charset=utf-8")
                elif u.path == "/pulse-core.js":
                    self._static("pulse-core.js", "text/javascript; charset=utf-8")
                elif u.path == "/api/boards":
                    edge = next(iter(hubs.values())).cfg["web"].get("edge_label", "WAN edge") if hubs else "WAN edge"
                    self._json({"version": C.AGENT_VER, "edge": edge, "boards": [h.status() for h in hubs.values()]})
                elif u.path == "/healthz":
                    self._send(200, b"ok\n", "text/plain")
                elif u.path in ("/events", "/api/history", "/api/summary", "/api/incidents"):
                    hub = self._hub(qs)
                    if hub is None:
                        self._json({"error": "no such probe", "boards": sorted(hubs)}, 404)
                    elif u.path == "/events":
                        self._stream(hub)
                    elif u.path == "/api/history":
                        minutes = max(1, min(120, int((qs.get("minutes") or ["15"])[0])))
                        at = (qs.get("at") or [None])[0]
                        if at is not None:
                            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z", at):
                                raise ValueError("at must be a UTC time like 2026-10-27T03:10:00Z")
                            at = datetime.datetime.fromisoformat(at.replace("Z", "+00:00"))
                        self._json(hub.history(minutes, at))
                    elif u.path == "/api/incidents":
                        hours = max(1, min(24 * 31, int((qs.get("hours") or ["24"])[0])))
                        since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)
                        path = hub.cfg.get("incidents", "")
                        self._json({"probe": hub.cfg["probe_id"], "hours": hours,
                                    "incidents": tail.lines_since(path, since) if path else []})
                    else:
                        self._json(hub.summary or {"pending": True})
                else:
                    self._send(404, b"not found\n", "text/plain")
            except (BrokenPipeError, ConnectionResetError):
                pass
            except ValueError:
                self._send(400, b"bad request\n", "text/plain")

        def _stream(self, hub):
            q = hub.subscribe()
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()
                hello = json.dumps({"now": int(time.time() * 1000), "probe": hub.cfg["probe_id"]})
                self.wfile.write(f"event: hello\ndata: {hello}\n\n".encode())
                self.wfile.flush()
                while True:
                    try:
                        msg = q.get(timeout=15)
                        self.wfile.write(f"data: {msg}\n\n".encode())
                    except queue.Empty:
                        self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                hub.unsubscribe(q)

    return Handler


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(cfg: dict, bind: str, port: int) -> int:
    """cfg: the collector's configuration (collector.py). One hub per board."""
    bs = K.boards(cfg)
    if not bs:
        print("exm web: no probes configured yet (sudo exm-collector probe add ...); serving an empty overview", flush=True)
    hubs = {b["name"]: Hub(K.board_cfg(cfg, b), len(bs)) for b in bs}
    httpd = _Server((bind, port), _handler(hubs))
    print(f"exm web: http://{bind}:{port}/ (read-only), boards: {', '.join(hubs) or 'none'}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0

"""Offline unit tests: no network, no root, no containers. Run with test/unit.sh (about a minute).

The fixture is real: 02:40-04:30 UTC on 2026-10-27 from the lab probe (t430-srv-02), which
covers a 43-minute gateway outage, a DNS outage, an AP outage seen by the Wi-Fi laptop, and
two short egress drops. Each check prints PASS or FAIL; the exit status is the failure count.
"""
from __future__ import annotations

import datetime
import gzip
import http.client
import importlib.machinery
import importlib.util
import io
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "lib"))

from exm import alert, collector as K, config as C, pulse, remote, stream, tail, web  # noqa: E402

FIXTURE = os.path.join(ROOT, "test", "fixtures", "outage-2026-10-27.jsonl.gz")
RESULTS = {"pass": 0, "fail": 0}
TMP = tempfile.mkdtemp(prefix="exm-unit-")


def check(name, ok, detail=""):
    RESULTS["pass" if ok else "fail"] += 1
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok or not detail else f"\n      {detail}"))


def events():
    with gzip.open(FIXTURE, "rt") as fh:
        return [json.loads(ln) for ln in fh]


EVS = events()


def results_dir(evs, d):
    """Lay events out as a probe stores them: <dir>/<day>/<test>.jsonl, ts first, in emitted order."""
    for e in sorted(evs, key=lambda e: e.get("emitted") or e["ts"]):
        day = os.path.join(d, e["ts"][:10])
        os.makedirs(day, exist_ok=True)
        with open(os.path.join(day, e["test"] + ".jsonl"), "a") as fh:
            fh.write(json.dumps(e, separators=(",", ":")) + "\n")
    return d


# ---- configuration
c = C.load(os.path.join(ROOT, "etc", "probe", "exm.toml"))
check("probe example config loads, no legacy sections", c["probe_id"] == "probe-01" and c["_legacy"] == [])
c = C.load(os.path.join(ROOT, "deploy", "lab-srv02", "exm.toml"))
check("lab probe config loads: 9 clients, 3 Minis servers, nothing legacy", c["_legacy"] == []
      and len(C.clients(c)) == 9 and len(C.servers(c)) == 3)
old = os.path.join(TMP, "old.toml")
open(old, "w").write(open(os.path.join(ROOT, "deploy", "lab-srv02", "exm.toml")).read()
                     + '\n[web]\nport = 80\n[alerts]\nenabled = true\n[[remote]]\nname = "m"\nhost = "h"\nuser = "u"\n')
check("a pre-0.9 probe config still loads; [web] [alerts] [[remote]] flagged as moved", C.load(old)["_legacy"] == ["web", "alerts", "remote"])
lab = K.load(os.path.join(ROOT, "deploy", "lab-srv02", "collector.toml"), os.path.join(ROOT, "deploy", "lab-srv02", "probes.d"))
check("lab collector config loads: the local board with the Mac attached", [b["name"] for b in K.boards(lab)] == ["t430-srv-02"]
      and K.board_cfg(lab, K.boards(lab)[0])["remote"][0]["name"] == "corey-mac")
pd = os.path.join(TMP, "probes.d")
os.makedirs(pd)
for f in os.listdir(os.path.join(ROOT, "etc", "collector", "probes.d")):
    shutil.copy(os.path.join(ROOT, "etc", "collector", "probes.d", f), os.path.join(pd, f.replace(".example", "")))
cc = K.load(os.path.join(ROOT, "etc", "collector", "collector.toml"), pd)
check("collector example + probe examples load (linux, local, mac attached)",
      sorted(p["name"] for p in cc["probes"]) == ["aio-01", "hall-b-mac", "probe-01"]
      and K.board_cfg(cc, K.get(cc, "probe-01"))["remote"][0]["name"] == "hall-b-mac")
bad = 0
for body in ('name = "x"\nkind = "mac"\nhost = "h"\nuser = "u"\nattach_to = "nope"\n', 'name = "Bad"\nhost = "h"\n',
             'name = "y"\n', 'name = "z"\nhost = "h; rm -rf /"\n'):
    name = body.split('"')[1]
    p = os.path.join(pd, name + ".toml")
    open(p, "w").write(body)
    try:
        K.load(os.path.join(ROOT, "etc", "collector", "collector.toml"), pd)
    except K.ConfigError:
        bad += 1
    os.unlink(p)
check("collector refuses bad probe files (unknown board, bad name, no host, unsafe host)", bad == 4)

# ---- ingest: probe policy
out = os.path.join(TMP, "ingest")
ing = remote.Ingest(out, os.path.join(TMP, "ingest.json"), "renamed", "probe")
real = next(e for e in EVS if e["test"] == "gateway")
why = ing.line(json.dumps(real).encode())
stored = json.loads(open(os.path.join(out, real["ts"][:10], "gateway.jsonl")).readline())
check("probe line stored: ts first, renamed, nested value kept", why is None and list(stored)[0] == "ts"
      and stored["probe_id"] == "renamed" and stored["source"] == "probe:renamed" and stored["value"]["ports"] == real["value"]["ports"])
check("the same line again is a duplicate", ing.line(json.dumps(real).encode()) == "duplicate")
now = datetime.datetime.now(datetime.timezone.utc)
iso = lambda d: d.isoformat(timespec="milliseconds").replace("+00:00", "Z")
mk = lambda **kw: dict({"ts": iso(now), "emitted": iso(now), "test": "dns_hb", "outcome": "ok", "value": {}}, **kw)
hostile = {
    "NaN": b'{"ts":"%s","test":"dns_hb","outcome":"ok","value":{"x":NaN}}' % iso(now).encode(),
    "1e400": b'{"ts":"%s","test":"dns_hb","outcome":"ok","value":{"x":1e400}}' % iso(now).encode(),
    "deep": json.dumps(mk(value=json.loads("[" * 20 + "]" * 20))).encode(),
    "long string": json.dumps(mk(error="x" * 5000)).encode(),
    "path in test name": json.dumps(mk(test="../../etc/passwd")).encode(),
    "future": json.dumps(mk(ts=iso(now + datetime.timedelta(hours=1)), emitted=iso(now + datetime.timedelta(hours=1)))).encode(),
    "unknown outcome": json.dumps(mk(outcome="pwned")).encode(),
    "not an object": b"[1,2,3]",
    "too long": b'{"ts":"' + b"x" * 300000 + b'"}',
}
refused = {k: ing.line(v) for k, v in hostile.items()}
check("probe policy refuses hostile lines", all(refused.values()), str({k: v for k, v in refused.items() if not v}))
ing2 = remote.Ingest(os.path.join(TMP, "i2"), os.path.join(TMP, "i2.json"), "p", "probe")
t0 = now - datetime.timedelta(minutes=10)
a = mk(ts=iso(t0), emitted=iso(t0 + datetime.timedelta(seconds=60)), client_id="c01")
b = mk(ts=iso(t0), emitted=iso(t0 + datetime.timedelta(seconds=30)), client_id="c02")   # older, but within the window
old = mk(ts=iso(t0), emitted=iso(t0 - datetime.timedelta(seconds=600)), client_id="c03")
r = [ing2.line(json.dumps(x).encode()) for x in (a, b, old)]
check("interleaved files: a slightly older line is still stored, a much older one is a duplicate", r == [None, None, "duplicate"], str(r))
cur = ing2.cursor(24)
check("resume cursor is just before the newest stored line", cur == remote._iso_minus(a["emitted"], remote.RESUME_OVERLAP_S), cur)
ing2.save(force=True)
again = remote.Ingest(os.path.join(TMP, "i2"), os.path.join(TMP, "i2.json"), "p", "probe")
check("cursor survives a restart", again.hwm == a["emitted"])
check("after a restart, the resume overlap is not stored twice", [again.line(json.dumps(x).encode()) for x in (a, b)] == ["duplicate", "duplicate"])

flood = remote.Ingest(os.path.join(TMP, "fl"), os.path.join(TMP, "fl.json"), "p", "probe")
base = now - datetime.timedelta(minutes=2)
flood.line(json.dumps(mk(ts=iso(base), emitted=iso(base))).encode())
for i in range(remote.DEDUP_MAX + 500):                  # never advances the cursor, every key new
    flood._seen({"test": "dns_hb", "client_id": f"x{i}"}, iso(base - datetime.timedelta(seconds=1)))
check("ingest: duplicate memory stays capped whatever a probe sends", len(flood.recent) <= remote.DEDUP_MAX, str(len(flood.recent)))

# ---- ingest: laptop policy
w = remote.Ingest(os.path.join(TMP, "w"), os.path.join(TMP, "w.json"), "mac", "wifi")
wl = next(e for e in EVS if e["test"] == "wifi_hb")
check("laptop line stored (rebuilt from the schema)", w.line(json.dumps(wl).encode()) is None)
check("laptop may not send wired tests", "not accepted" in (w.line(json.dumps(mk(test="dhcp")).encode()) or ""))
check("laptop value must be flat", bool(w.line(json.dumps(mk(test="wifi_hb", value={"x": {"y": 1}})).encode())))

# ---- tail: windows by binary search
d = results_dir(EVS, os.path.join(TMP, "results"))
gw = os.path.join(d, "2026-10-27", "gateway.jsonl")
allg = [json.loads(ln) for ln in open(gw)]
ok = True
for _ in range(50):
    lo = datetime.datetime(2026, 10, 27, 2, 40, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=random.uniform(0, 6000))
    hi = lo + datetime.timedelta(seconds=random.uniform(0, 1800))
    want = [e["ts"] for e in allg if iso(lo) <= e["ts"] <= iso(hi)]
    ok &= sorted(want) == sorted(e["ts"] for e in tail.lines_between(gw, lo, hi))
check("lines_between is exact on 50 random windows", ok)

# ---- probe stream
since = datetime.datetime(2026, 10, 27, 3, 0, tzinfo=datetime.timezone.utc)
until = datetime.datetime(2026, 10, 27, 3, 30, tzinfo=datetime.timezone.utc)
buf = io.BytesIO()
n = stream.replay(d, since, until, buf)
em = [json.loads(ln).get("emitted") or json.loads(ln)["ts"] for ln in buf.getvalue().splitlines()]
want = sum(1 for e in EVS if iso(since) < (e.get("emitted") or e["ts"]) and e["ts"] <= iso(until + datetime.timedelta(seconds=300)))
check("stream replay: every line after the cursor, in emitted order", n == len(em) and em == sorted(em) and n > 1000, f"{n} lines")
refused = 0
for cmd in ("id", "stream; id", "stream since=yesterday", "stream since=2026-10-27T00:00:00Z && id", "bash -i"):
    try:
        stream.parse(cmd, 7, now)
    except SystemExit:
        refused += 1
check("stream refuses anything but `stream [since=UTC]`; since capped at retention", refused == 5
      and stream.parse("stream since=2020-01-01T00:00:00Z", 7, now) >= now - datetime.timedelta(days=7, seconds=1))

# ---- probe CLI: collector key check
loader = importlib.machinery.SourceFileLoader("exm_cli", os.path.join(ROOT, "bin", "exm"))
spec = importlib.util.spec_from_loader("exm_cli", loader)
cli = importlib.util.module_from_spec(spec)
loader.exec_module(cli)
good = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEm3fZb2Fr9J8yKr2s0h7xh6xJ1ZbA2c9x5w3q1v0yZ exm-collector@dc:probe-01"
evil = ['command="sh" ' + good, good + "\ncommand=x", 'ssh-ed25519 AAAA" ,command="/bin/sh']
check("authorize-collector takes one key line, nothing that could add options",
      bool(cli.PUBKEY.match(good)) and not any(cli.PUBKEY.match(e.strip()) for e in evil))

# ---- mac stream.sh (forced command on the laptop)
h = os.path.join(TMP, "machome")
os.makedirs(os.path.join(h, "exm-wifi", "results"))
open(os.path.join(h, "exm-wifi", "results", "current.jsonl"), "w").close()
rc = []
for cmd in ("stream ssid-hex=41434d45", "id", "stream; id", "stream ssid-hex=$(id)", "stream ssid-hex=41434D45"):
    p = subprocess.run(["timeout", "1", "sh", os.path.join(ROOT, "mac", "stream.sh")], env=dict(os.environ, HOME=h, SSH_ORIGINAL_COMMAND=cmd),
                       capture_output=True)
    rc.append(p.returncode)
check("laptop stream.sh: streams with a valid ssid, refuses everything else", rc == [124, 2, 2, 2, 2], str(rc))

# ---- where: every verdict from synthetic signals
wts = "2026-10-27T03:10:00.000Z"
t = pulse.ms(wts) + 5000
S = lambda *s: [{"s": x} for x in s]
g = lambda ug=(), nl=(): {"k": "gateway", "w": wts, "ug": [list(u) for u in ug], "nl": list(nl), "n": 4}
tr = lambda rc_, k="trace": {"k": k, "w": wts, "rc": rc_, "lh": "10.99.0.1", "lt": 1, "g": "8.8.8.8"}
dn = lambda ao: {"k": "dns_hb", "w": wts, "o": "fail", "sx": "10.99.0.1", "ax": "1.1.1.1", "ao": ao}
wf = lambda gk, sd="ACME", tg="ACME": {"k": "wifi_hb", "w": wts, "gk": gk, "sd": sd, "tg": tg}
cases = [("link", [g(nl=["c01", "c02", "c03"])], S("fail", "ok", "ok", "ok", "ok")),
         ("switch", [g(ug=[("10.99.0.1", 3, 3)]), wf(True)], S("fail", "ok", "fail", "fail", "ok")),
         ("gateway", [g(ug=[("10.99.0.1", 3, 3)]), wf(False)], S("fail", "ok", "fail", "fail", "fail")),
         ("lan", [g(ug=[("10.99.0.1", 3, 3)])], S("fail", "ok", "fail", "fail", "unk")),
         ("edge", [tr(False), tr(True, "trace_ctl")], S("ok", "ok", "ok", "fail", "ok")),
         ("isp", [tr(False), tr(False, "trace_ctl")], S("ok", "ok", "fail", "fail", "ok")),
         ("resolver", [tr(True), dn(True)], S("ok", "ok", "fail", "fail", "ok")),
         ("dns_path", [tr(True), dn(False)], S("ok", "ok", "fail", "fail", "ok")),
         ("apps", [tr(True)], S("ok", "ok", "ok", "fail", "ok")),
         ("dhcp", [{"k": "dhcp_hb", "w": wts, "sv": "10.99.0.1"}], S("ok", "fail", "ok", "ok", "ok")),
         ("ssid", [wf(False, sd="MistiFi")], S("ok", "ok", "ok", "ok", "fail"))]
miss = [(want, (pulse.where_of(V, t, st) or {}).get("seg")) for want, V, st in cases if (pulse.where_of(V, t, st) or {}).get("seg") != want]
check("where: every verdict (link, switch, gateway, lan, edge, isp, resolver, dns_path, apps, dhcp, ssid)", not miss, str(miss))
lost = [tr(True), dict(tr(False), w="2026-10-27T03:10:04.000Z"), tr(True, "trace_ctl")]
check("where: one lost traceroute does not blame the edge", (pulse.where_of(lost, t, S("ok", "ok", "fail", "fail", "ok")) or {}).get("seg") != "edge")
both_silent = lost + [dict(dn(False), w="2026-10-27T03:10:04.000Z")]
check("where: ...unless both resolvers are silent too (15:14 on 2026-10-27: it was the EC)",
      (pulse.where_of(both_silent, t, S("ok", "ok", "fail", "fail", "ok")) or {}).get("seg") == "edge")

# ---- alerts: this morning, replayed
st = os.path.join(TMP, "alert-state.json")
sent = []
bc = {"probe_id": "t430-srv-02", "label": "t430-srv-02", "web": {"voice": "sysadmin", "edge_label": "EC"}, "results_dir": d,
      "alerts": {"format": "slack", "board_url": "http://10.32.98.25/", "timezone": "America/Chicago"}}
al = alert.Alerter(bc, lambda m: sent.append(m), st)
order = sorted(EVS, key=lambda e: e.get("emitted") or e["ts"])
k = 0
for tt in range(pulse.ms("2026-10-27T02:55:00.000Z"), pulse.ms("2026-10-27T04:28:00.000Z"), 2000):
    while k < len(order) and pulse.ms(order[k].get("emitted") or order[k]["ts"]) <= tt:
        al.add(order[k])
        k += 1
    al.trim(tt)
    al.tick(tt)
got = [(m["kind"], m["line"]) for m in sent]
want = [("down", "Network"), ("resolved", "Network"), ("down", "DNS"), ("resolved", "DNS"), ("down", "Wi-Fi"),
        ("down", "DNS"), ("resolved", "DNS"), ("down", "DNS"), ("resolved", "DNS")]
check("alerts: the outage replays to 9 accurate messages (one page per cause)", got == want, str(got))
first = alert.payload("slack", sent[0])["text"]
check("alerts: the first page names the gateway, the time, where, and links to the board at the start",
      "10.1.0.1" in first and "22:00:21 CDT" in first and "Where: the gateway" in first and "?probe=t430-srv-02&at=2026-10-27T03:00:21Z" in first, first)
evil = dict(sent[0], lines=["no answer from <http://evil.example|click here to fix> & <!channel> [fix](http://evil.example)"],
            probe="<@U123> lab")
sl = alert.payload("slack", evil)["text"]
tm = json.dumps(alert.payload("teams", evil))
check("chat: probe text can't make links or mentions (Slack escaped, Teams without link brackets)",
      "<http://evil" not in sl and "<!channel>" not in sl and "<@U123>" not in sl and sl.count("<") == 1
      and "[fix](" not in tm, sl)
log = os.path.join(TMP, "incidents.jsonl")
alert.incident_logger(log)(sent[0])
rec = json.loads(open(log).readline())
check("incident log: ts first, start as UTC, board named", list(rec)[0] == "ts" and rec["start_iso"] == "2026-10-27T03:00:21Z"
      and rec["board"] == "t430-srv-02")

# ---- board and alerter agree: JS (the page) and Python (alerts) on the same real results
node = shutil.which("node")
if node:
    comp = []
    for e in EVS:
        try:
            comp.append(web.compact(e))
        except Exception:
            pass
    comp.sort(key=lambda c: c["w"])
    times = list(range(pulse.ms("2026-10-27T02:45:00.000Z"), pulse.ms("2026-10-27T04:28:00.000Z"), 60000))
    hist, tf = os.path.join(TMP, "h.json"), os.path.join(TMP, "t.json")
    json.dump({"events": comp}, open(hist, "w"))
    json.dump(times, open(tf, "w"))
    js = subprocess.run([node, "-e", """
const fs = require('fs'); const C = require(process.argv[1]);
const ev = JSON.parse(fs.readFileSync(process.argv[2])).events; const times = JSON.parse(fs.readFileSync(process.argv[3]));
process.stdout.write(JSON.stringify(times.map((t) => { const pool = ev.filter((e) => Date.parse(e.w) <= t);
  const b = [0,1,2,3,4].map((i) => C.beats(pool, i)); const st = b.map((bs, i) => C.stateOf(bs, i, t));
  return [st.map((x) => [x.s, x.n, x.f, x.d]), b.map((bs) => C.sinceOf(bs, true)), b.map((bs, i) => C.lastOutage(bs, i, t, 900000)),
          b.map((bs, i) => C.flaps(bs, i, t, 600000)), C.whereOf(pool, t, st)]; })));""",
                         os.path.join(ROOT, "lib", "exm", "static", "pulse-core.js"), hist, tf], capture_output=True, text=True)
    clean = lambda x: {k: clean(v) for k, v in x.items() if v is not None} if isinstance(x, dict) else [clean(v) for v in x] if isinstance(x, list) else x
    diffs = 0
    for tt, j in zip(times, json.loads(js.stdout)):
        pool = [c for c in comp if pulse.ms(c["w"]) <= tt]
        b = [pulse.beats(pool, i) for i in range(5)]
        st = [pulse.state_of(bs, i, tt) for i, bs in enumerate(b)]
        py = [[[x["s"], x["n"], x["f"], x["d"]] for x in st], [pulse.since_of(bs, True) for bs in b],
              [pulse.last_outage(bs, i, tt, 900000) for i, bs in enumerate(b)], [pulse.flaps(bs, i, tt, 600000) for i, bs in enumerate(b)],
              pulse.where_of(pool, tt, st)]
        diffs += clean(py) != clean(j)
    check(f"parity: page (JS) and alerter (Python) agree at {len(times)} moments of the outage", diffs == 0, f"{diffs} differ")
else:
    print("SKIP  parity (no node on this machine)")
    if os.environ.get("REQUIRE_NODE"):
        RESULTS["fail"] += 1

# ---- the collector's web server: overview, board, incidents
cdir = os.path.join(TMP, "collector")
os.makedirs(os.path.join(cdir, "probes.d"))
open(os.path.join(cdir, "collector.toml"), "w").write(f'data_dir = "{cdir}/data"\n[web]\nedge_label = "EC"\n')
open(os.path.join(cdir, "probes.d", "lab.toml"), "w").write(f'name = "lab"\nlocal = true\nresults_dir = "{d}"\n')
ccfg = K.load(os.path.join(cdir, "collector.toml"), os.path.join(cdir, "probes.d"))
os.makedirs(os.path.join(cdir, "data", "incidents"))
alert.incident_logger(os.path.join(cdir, "data", "incidents", "lab.jsonl"))(dict(sent[-1], start=pulse.ms(iso(now - datetime.timedelta(hours=1)))))
sock = socket.socket()
sock.bind(("127.0.0.1", 0))
port = sock.getsockname()[1]
sock.close()
threading.Thread(target=web.serve, args=(ccfg, "127.0.0.1", port), daemon=True).start()
time.sleep(1.0)


def get(path):
    con = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    con.request("GET", path)
    r = con.getresponse()
    return r.status, r.read()


s1, b1 = get("/")
s2, b2 = get("/api/boards")
s3, b3 = get("/api/history?probe=lab&minutes=10&at=2026-10-27T03:10:00Z")
s4, _ = get("/api/history?probe=nope")
s5, b5 = get("/api/incidents?probe=lab&hours=48")
s6, _ = get("/../../etc/passwd")
h3 = json.loads(b3)
check("web: one board serves the board itself; boards API answers", s1 == 200 and b"<title>EXM Pulse</title>" in b1 and s2 == 200
      and json.loads(b2)["boards"][0]["name"] == "lab")
check("web: history at 03:10 has the gateway outage (10.1.0.1, 12 of 12)", s3 == 200 and any(
      c["k"] == "gateway" and c.get("ug") == [["10.1.0.1", 12, 12]] for c in h3["events"]) and h3["edge"] == "EC")
check("web: unknown probe 404, incidents served, nothing outside the fixed routes", s4 == 404 and s5 == 200
      and len(json.loads(b5)["incidents"]) == 1 and s6 == 404)

shutil.rmtree(TMP, ignore_errors=True)
print(f"\nPASS {RESULTS['pass']}   FAIL {RESULTS['fail']}")
sys.exit(RESULTS["fail"])

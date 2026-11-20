"""The speedtest page in a real browser (Playwright + Chromium) against the real daemon, the fake collector and the fake Cloudflare.

Each scenario in ui/page_scenarios.js runs as its own node process; the world (exp-speedtest daemon in-process, fake collector,
fake Cloudflare over TLS) lives in this process and answers "@@NEED" requests from the script. The browser is pointed at the
fakes with --host-resolver-rules only: the page is ``http://speed.test.example/`` (a NON-secure origin, port 80, like a real event),
the DNS-leg names ``*.t.speed.test.example`` and ``speed.cloudflare.com`` are mapped to loopback ports. Skipped when node or
playwright are unavailable. Screenshots go to ``$EXP_PAGE_SHOTS`` (default: the m6 e2e artifact folder when it exists, else tmp).
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import dns.message
import dns.query
import fakes_common as fc
import pytest
from exp_common import speedtest as st
from stbox import Box, shared_tls

HERE = Path(__file__).resolve().parent
NODE = shutil.which("node")
HOST = "speed.test.example"
ZONE = "t.speed.test.example"
SCENARIOS = HERE / "ui" / "page_scenarios.js"
FIXTURES = fc.FIXTURES_DIR
ARTIFACTS = Path(os.environ.get("EXP_E2E_ARTIFACTS") or Path(tempfile.gettempdir()) / "exp-e2e-artifacts") / "m6" / "page"
XSS = "<img src=x onerror=alert(1)><script>alert(2)</script>\"'>${7*7}{{7*7}}"


def _have_playwright() -> bool:
    if not NODE:
        return False
    r = subprocess.run([NODE, "-e", "require('playwright')"], capture_output=True, timeout=60)
    return r.returncode == 0


pytestmark = pytest.mark.skipif(not _have_playwright(), reason="node + playwright are not available")


def shots_dir(tmp: Path) -> Path:
    env = os.environ.get("EXP_PAGE_SHOTS")
    if env:
        d = Path(env)
    elif ARTIFACTS.parent.exists():
        d = ARTIFACTS
    else:
        d = tmp / "shots"
    d.mkdir(parents=True, exist_ok=True)
    return d


class World:
    """daemon + fake collector + fake Cloudflare (TLS) + the helpers the scenarios ask for."""

    def __init__(self, tmp: Path, cfg_over: dict[str, Any] | None = None, cf: dict[str, Any] | None = None, dns_arrivals: bool = True) -> None:
        import cloudflare_speed.server as cfs
        over: dict[str, Any] = {"limits": {"bytes_local": 30_000_000, "bytes_internet": 30_000_000, "max_concurrent_per_ip": 3,
                                           "tests_per_10min_per_ip": 100},
                                "dns_leg": {"enabled": True, "zone": ZONE},
                                "serve": {"hostname": HOST, "client_subnets": ["127.0.0.0/8"]}}
        for k, v in (cfg_over or {}).items():
            over[k] = {**over[k], **v} if isinstance(v, dict) and isinstance(over.get(k), dict) else v
        self.tmp = tmp
        self.box = Box(tmp, cfg_over=over)
        cert, key, _ = shared_tls()
        # 50 / 25 Mb/s (the A6.10 reference link): the fake's pacer, not the host CPU, must set the rate, or the "steady link"
        # the stability assertions rely on is whatever a shared runner delivers. At 400 / 100 the download was CPU-bound on loopback
        # TLS (116-119 Mb/s here and on GitHub) with no pacing slack, and a CI run read internet cv 0.40; paced, cv is 0.01 here.
        self.cf = cfs.start(tls=(cert, key), **{"latency_ms": 15, "loaded_latency_ms": 40, "down_bps": 50_000_000, "up_bps": 25_000_000, **(cf or {})})
        self.box.start()
        self.stop_flag = threading.Event()
        self.threads: list[threading.Thread] = []
        if dns_arrivals:
            t = threading.Thread(target=self._dns_arrivals, daemon=True)
            t.start()
            self.threads.append(t)

    # ---- the venue's resolver, simulated: ask the box's DNS-leg authority for every nonce of every new session
    def _dns_arrivals(self) -> None:
        done: set[str] = set()
        while not self.stop_flag.is_set():
            try:
                for s in list(self.box.core._sessions.values()):
                    if s.id in done or not s.dns_nonces:
                        continue
                    done.add(s.id)
                    for n in s.dns_nonces:
                        q = dns.message.make_query(f"{n}.{ZONE}", "A")
                        dns.query.udp(q, "127.0.0.1", port=self.box.dns_port, timeout=1.0)
            except Exception:  # noqa: BLE001 - best effort helper thread
                pass
            time.sleep(0.01)

    def tests(self) -> list[Any]:
        return list(self.box.fake.app.tests.values())

    def correlate(self) -> None:
        """The runner's job, shortened: attach evidence to the newest stored test and complete it."""
        deadline = time.time() + 10
        while not self.tests() and time.time() < deadline:
            time.sleep(0.1)
        t = self.tests()[-1]
        app = self.box.fake.app
        for name in ("identity.mist", "wifi.ok", "wan.ok", "security.policy-block", "baseline.ok"):
            doc = copy.deepcopy(json.loads((FIXTURES / "evidence" / f"{name}.json").read_text()))
            doc["test_id"] = t.doc["id"]
            app.put_evidence(t, doc)
            time.sleep(0.15)
        app.complete(t, {"kinds": ["identity", "wifi", "wan", "security", "baseline"], "status": "ok"})

    def stop(self) -> None:
        self.stop_flag.set()
        for t in self.threads:
            t.join(2)
        self.box.stop()
        self.cf.stop()


@pytest.fixture()
def world(tmp_path: Path):
    w = World(tmp_path)
    yield w
    w.stop()


def run_scenario(w: World, scenario: str, opts: dict[str, Any] | None = None, timeout: float = 240) -> dict[str, Any]:
    cfg = {"host": HOST, "zone": ZONE, "boxPort": w.box.http_port, "cfPort": w.cf.port, "out": str(shots_dir(w.tmp)), "opts": opts or {}}
    cfg_path = w.tmp / "ui-config.json"
    cfg_path.write_text(json.dumps(cfg))
    # the sandbox's agent proxy variables must not reach Chromium: it would send speed.cloudflare.com to the REAL internet
    env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    p = subprocess.Popen([NODE, str(SCENARIOS), scenario, str(cfg_path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, cwd=str(w.tmp), env=env)
    assert p.stdin and p.stdout
    lines: list[str] = []
    result: list[dict[str, Any]] = []

    def pump() -> None:
        for line in p.stdout:  # type: ignore[union-attr]
            line = line.rstrip("\n")
            lines.append(line)
            if os.environ.get("EXP_PAGE_DEBUG"):
                print(line[:300], flush=True)
            if line.startswith("@@NEED "):
                req = json.loads(line[7:])
                reply: dict[str, Any] = {}
                if req["op"] == "correlate":
                    w.correlate()
                elif req["op"] == "box":           # the box's own view of on-network traffic: bytes moved, transfers in flight
                    reply = {"meter": w.box.core.meter.total(), "transfers": w.box.core._transfers}
                p.stdin.write("@@OK " + json.dumps(reply) + "\n")  # type: ignore[union-attr]
                p.stdin.flush()  # type: ignore[union-attr]
            elif line.startswith("@@RESULT "):
                result.append(json.loads(line[9:]))

    t = threading.Thread(target=pump, daemon=True)
    t.start()
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        raise
    t.join(5)
    assert result, "scenario produced no result:\n" + "\n".join(lines[-30:])
    return result[0]


# ======================================================================================================== the full test
def check_run(r: dict[str, Any], w: World) -> dict[str, Any]:
    """The invariants every complete run must satisfy (A6.1 / A6.10 / A6.11 page side)."""
    assert r["cspHeader"] and "script-src 'sha256-" in r["cspHeader"] and "unsafe-inline" not in r["cspHeader"]
    assert r["csp"] == [] and r["cspEvents"] == [], f"CSP violations: {r['csp']} {r['cspEvents']}"
    assert r["errors"] == [] and r["dialogs"] == []
    allowed = {HOST, "speed.cloudflare.com"}
    for host in r["hosts"]:
        assert host in allowed or (host.endswith("." + ZONE) and len(host.split(".")[0]) == 16), f"unexpected request host {host}"
    first = r["first"]
    assert first["scrollWidth"] <= first["clientWidth"] + 0, "horizontal scroll"
    cf = w.cf.app.snapshot()["stats"]
    assert cf["down"] > 0 and cf["up"] > 0 and cf["trace"] >= 1, f"the fake Cloudflare did not serve the internet leg: {cf}"
    assert cf["by_path"].get("/__results", 0) == 0, "nothing may be posted to Cloudflare's results endpoint"
    assert not any("/__results" in u for u in r["requests"])
    # as A6.10: aborting the in-flight streams at the end of a direction is by design (ERR_ABORTED), any other failure is not
    hard = [f for f in r["failed"] if "ERR_ABORTED" not in f]
    assert hard == [], hard[:5]
    if r["submissions"] and r["submissions"][-1].get("status") == 202:
        same_numbers(first, r["submissions"][-1])
    return first


ENGINE_PATH = "/st/assets/cf-engine.js"
LOCAL_PATH = "/st/assets/local-leg.js"      # the on-network transfer's worker file (CR-m6-speedtest-server item 26 follow-up)
START_MS = 6000          # app.js EngineHost: a worker silent this long after start is replaced by the main-thread fallback
LOCAL_START_MS = 4000    # app.js LocalHost: the same for the transfer worker (no 'ready' this long after it was created)
TRANSFER = ("/st/down", "/st/up")


def transfer_reqs(r: dict[str, Any]) -> list[str]:
    """Every on-network transfer request of the run: /st/down, /st/up and the loaded-latency pings (/st/ping?n=900...)."""
    out = []
    for u in r["requests"]:
        sp = urlsplit(u)
        if sp.path in TRANSFER or (sp.path == "/st/ping" and re.fullmatch(r"n=9[0-9]{2,}", sp.query or "")):
            out.append(u)
    return out


def on_main_thread(r: dict[str, Any], urls: list[str]) -> list[bool]:
    """Per URL: was it requested by the page's main thread? The page target's CDP Network domain (mainReqs) reports the
    main thread's requests only, Playwright's page.on("request") also those of dedicated workers."""
    main = set(r["mainReqs"])
    return [u in main for u in urls]


def displayed(snap: dict[str, Any]) -> dict[str, float | None]:
    """The numbers the results page shows, parsed (None for a dash)."""
    def num(t: str) -> float | None:
        m = re.search(r"[0-9]+(?:\.[0-9]+)?", t or "")
        return float(m.group(0)) if m else None
    sp = {x["k"]: num(x["v"]) for x in snap["speeds"]}
    legs = {k: num(v["val"]) for k, v in snap["legs"].items()}
    return {"score": num(snap["score"]), "local_down": sp["Local down"], "local_up": sp["Local up"], "internet_down": sp["Internet down"],
            "internet_up": sp["Internet up"], "local_idle": legs["Wi-Fi and venue network"], "cf_idle": legs["Cloudflare"]}


def same_numbers(snap: dict[str, Any], sub: dict[str, Any]) -> None:
    """A6.10 'same numbers', page side: every number the results show equals the number submitted (display rounding only)."""
    d, legs = displayed(snap), sub["req"]["legs"]
    loc, inet = legs["local"], legs.get("internet") or {}
    want = {"score": sub["res"]["score"]["total"], "local_down": loc.get("down_mbps"), "local_up": loc.get("up_mbps"),
            "internet_down": inet.get("down_mbps"), "internet_up": inet.get("up_mbps"), "local_idle": loc.get("idle_ms"), "cf_idle": inet.get("idle_ms")}
    for k, v in want.items():
        if v is None:
            assert d[k] is None or k in ("local_idle", "cf_idle"), f"{k}: page shows {d[k]}, nothing was submitted"
            continue
        assert d[k] is not None and abs(d[k] - v) <= (0.51 if abs(v) >= 10 else 0.06), f"{k}: page shows {d[k]}, submitted {v}"


def engine_start_ms(r: dict[str, Any]) -> float:
    """ms from "Timing Cloudflare" (set just before the trace request and the engine start) to the engine's first phase
    ("Timing Cloudflare <colo>", from the engine's own latency phase), from the page's phase-change timestamps."""
    at = r["phaseTimes"]
    t0 = next(t for t, v in at if v == "Timing Cloudflare")
    t1 = next(t for t, v in at if v.startswith("Timing Cloudflare ") and t >= t0)
    return t1 - t0


def test_full_test_390(world: World):
    r = run_scenario(world, "full", {"correlate": True, "shotPre": "01-start-390-light", "midShot": "02-running-390-light",
                                     "shotResults": "03-results-390-light", "shotFinal": "04-final-390-light", "share": True, "shotShared": "05-shared-390-light",
                                     "keyboard": True, "contrast": True, "report": "video calls freeze at my booth", "zoneFix": "Hall B, row 9", "copy": True,
                                     "timeout": 150000})
    first = check_run(r, world)
    # --- the on-network transfer and the internet engine ran in their dedicated workers (off the main thread), served by the box
    assert r["workers"] == [f"http://{HOST}{LOCAL_PATH}", f"http://{HOST}{ENGINE_PATH}"], r["workers"]
    assert any(u.endswith(ENGINE_PATH) for u in r["requests"]) and any(u.endswith(LOCAL_PATH) for u in r["requests"])
    # ... and neither fell back to the main thread (a silent fallback would pass everything else here): every fallback path
    # (no Worker, a worker error or 'fatal' before it got going, silence after start) inserts the same file as a classic
    # <script src>, which stays in the DOM; and the engine's first phase came well before the silent-worker fallback could fire
    assert first["scriptSrcs"] == [] and r["final"]["scriptSrcs"] == [], (first["scriptSrcs"], r["final"]["scriptSrcs"])
    # every on-network transfer request (down, up, loaded pings) came from the worker: none from the page's main thread
    xfer = transfer_reqs(r)
    assert any("/st/down?" in u for u in xfer) and any(u.endswith("/st/up") for u in xfer) and any("/st/ping?n=9" in u for u in xfer), xfer[:5]
    assert not any(on_main_thread(r, xfer)), [u for u in xfer if u in set(r["mainReqs"])][:5]
    assert any("/st/ping?n=1" in u for u in r["mainReqs"]), "control: the idle pings stay on the main thread and CDP sees them"
    started_ms = engine_start_ms(r)
    assert started_ms < START_MS * 2 / 3, f"the engine's first phase came {started_ms:.0f} ms after the internet leg started"
    # --- the engine really measured: server-recomputed score shown, every leg present
    sub = r["submissions"][-1]
    assert sub["status"] == 202 and sub["req"]["schema"] == "exp.speedtest.submission/1"
    legs = sub["req"]["legs"]
    assert legs["local"]["status"] == "ok" and legs["local"]["down_mbps"] > 0 and legs["local"]["up_mbps"] > 0
    local_leg_sane(sub)
    assert legs["internet"]["status"] == "ok" and legs["internet"]["colo"] == "FRA" and legs["internet"]["down_mbps"] > 0
    assert legs["dns"]["source"] == "browser" and "cold_ms" in legs["dns"]
    # regression: internet stability is measured on steady-state samples per direction, not across every request size
    # and both directions (that read CV >= 0.5 on a steady link and zeroed the stability part for nearly every user)
    assert legs["internet"]["cv"] is not None and legs["internet"]["cv"] < 0.3, legs["internet"]
    assert sub["res"]["score"]["stability"] >= 40, sub["res"]["score"]
    assert first["score"] == str(sub["res"]["score"]["total"])
    assert r["firstFocus"] == "go"
    # --- phases were walked through in order, animation ran (no reduced motion)
    ph = " | ".join(r["phases"])
    for want in ("Timing your Wi-Fi", "Timing name lookups", "On-network download", "On-network upload", "Internet download", "Internet upload"):
        assert want in ph, ph
    assert r["midAnimsMax"] > 0
    # --- results sections
    assert [s["k"] for s in first["speeds"]] == ["Local down", "Local up", "Internet down", "Internet up"]
    assert all(s["v"] != "—" for s in first["speeds"])
    assert first["colo"] == "FRA"
    assert [x.split(" (")[0] for x in first["goodFor"]] == ["Video calls", "HD streaming", "Web and email", "Large uploads"]
    assert not any("not checked" in x for x in first["goodFor"]), first["goodFor"]     # the internet leg measured
    assert first["share"].startswith(f"http://{HOST}/st/r/st_") and "#k=" in first["share"]
    # --- correlation flipped the checks from "checking..." to findings, zone shown with the correct-it affordance
    assert any("checking" in c for c in first["checks"])
    fl = r["flipped"]
    assert fl and not any("checking" in c for c in fl["checks"]), fl and fl["checks"]
    assert any("Wi-Fi signal" in c for c in fl["checks"]) and any("Security policy" in c and "checking" not in c for c in fl["checks"]), fl["checks"]
    assert fl["where"] and "You were in" in fl["where"] and "Hall B" in fl["where"]
    assert fl["why"], "final diagnosis text"
    # --- report + zone correction ride the comment route
    assert r["rDone"] == "Saved with your test." and r["zDone"].startswith("Thanks")
    comments = [t.comment for t in world.tests()]
    assert comments and "[where I was] Hall B, row 9" in comments[-1] and "video calls freeze at my booth" in comments[-1]
    # --- plain HTTP: clipboard + wake lock absent, the link is selected for copying
    assert first["secure"] is False and first["subtle"] == "undefined" and first["wakeLock"] == "undefined"
    assert r["selection"] == first["share"] and r["copyStat"] in ("Link copied.", "Link selected: press and hold, then choose Copy.")
    # --- share link: read-only view of the same result, wrong key looks like an unknown link
    sh = r["shared"]
    assert sh["score"] == first["score"] and sh["speeds"] == first["speeds"]
    assert r["sharedHidden"]["shareBox"] is True and r["sharedHidden"]["stageDisplay"] == "none"
    assert r["badKey"]["resultsHidden"] is True and "not valid" in r["badKey"]["notice"]
    # --- keyboard reachable, 44 px targets, contrast
    focus = [x for x in r["keyboard"] if x]
    assert len(focus) >= 6
    assert all(x["h"] >= 44 or x["id"] in ("shareLink",) for x in focus if x["id"] in ("reportBtn", "again", "copy", "cancel", "go")), focus
    assert r["contrast"]["fails"] == [], r["contrast"]["fails"]
    assert r["contrast"]["checked"] > 40


def local_leg_sane(sub: dict[str, Any], budget: int = 30_000_000) -> dict[str, Any]:
    """The on-network figures of a complete run: both directions measured over loopback, loaded latency for both, a stability
    figure, bytes within the session budget and agreeing with the box's own counters (no counters_disagree flag)."""
    loc = sub["req"]["legs"]["local"]
    assert loc["status"] == "ok" and loc["down_mbps"] > 1 and loc["up_mbps"] > 1, loc
    assert loc["loaded_down_ms"] is not None and loc["loaded_up_ms"] is not None and 0 <= loc["loaded_down_ms"] < 5000, loc
    assert loc["cv"] is not None and loc["failures"] <= 2 and 0 < loc["bytes"] <= budget, loc
    assert loc["idle_ms"] is not None and loc["rpm"] > 0, loc
    assert "counters_disagree" not in (sub["res"].get("flags") or []), sub["res"].get("flags")
    return loc


def test_view_proof_matches_the_server_contract(world: World):
    r = run_scenario(world, "viewproof")
    key = r["link"].split("#k=")[1]
    proof = st.view_proof(key, "st_" + "0" * 26)
    assert r["create"]["view_verifier"] == st.view_verifier(proof)
    assert r["proofs"] == [proof]
    assert r["create"]["consent"] == {"text_version": 3}
    # an independent HMAC / SHA-256 of the same inputs, in case exp_common ever changes in step with the page
    raw = base64.urlsafe_b64decode(key + "=")
    mac = hmac.new(raw, b"exp.st.view/1:st_" + b"0" * 26, hashlib.sha256).digest()
    assert proof == "expv_" + base64.urlsafe_b64encode(mac).rstrip(b"=").decode()


def test_insecure_context_facts(world: World):
    r = run_scenario(world, "insecure")
    assert r == {"secure": False, "subtle": "undefined"}


def test_plain_http_copy_falls_back_to_select_the_code(world: World):
    """No clipboard API on http:// and no execCommand either: the link is selected and the user is told how to copy it."""
    r = run_scenario(world, "full", {"copy": True, "noExec": True, "timeout": 150000})
    first = check_run(r, world)
    assert first["clipboard"] == "undefined" and first["wakeLock"] == "undefined" and first["secure"] is False
    assert r["selection"] == first["share"] and r["copyStat"] == "Link selected: press and hold, then choose Copy."
    assert first["score"] != "0"


# ============================================================================================ looks: dark, desktop, motion
def test_dark_and_desktop_layouts(world: World):
    d = run_scenario(world, "full", {"colorScheme": "dark", "shotPre": "10-start-390-dark", "shotResults": "11-results-390-dark", "contrast": True,
                                     "timeout": 150000})
    first = check_run(d, world)
    assert d["contrast"]["fails"] == [], d["contrast"]["fails"]
    assert first["score"] != "0"
    w = run_scenario(world, "full", {"viewport": {"width": 1280, "height": 900}, "shotPre": "20-start-1280-light", "shotResults": "21-results-1280-light",
                                     "contrast": True, "timeout": 150000})
    check_run(w, world)
    assert w["contrast"]["fails"] == [], w["contrast"]["fails"]
    cols = w["first"]
    assert cols["scrollWidth"] <= cols["clientWidth"]
    wd = run_scenario(world, "full", {"viewport": {"width": 1280, "height": 900}, "colorScheme": "dark", "shotResults": "22-results-1280-dark", "contrast": True,
                                      "timeout": 150000})
    assert wd["contrast"]["fails"] == []


def test_reduced_motion_keeps_every_number_and_runs_no_animation(world: World):
    r = run_scenario(world, "full", {"reducedMotion": "reduce", "shotResults": "30-results-390-reduced", "timeout": 150000})
    first = check_run(r, world)
    assert r["midAnimsMax"] == 0 and first["anims"] == 0, "no CSS animation may run with prefers-reduced-motion"
    sub = r["submissions"][-1]
    assert first["score"] == str(sub["res"]["score"]["total"])
    assert all(s["v"] != "—" and s["scale"].startswith("scaleX(") for s in first["speeds"])
    assert len(first["wf"]) >= 2 and first["parts"] and first["colo"] == "FRA"


# ====================================================================================================== internet leg states
def internet_status(r: dict[str, Any]) -> str:
    return r["submissions"][-1]["req"]["legs"].get("internet", {}).get("status", "absent")


def test_internet_paused_by_the_network_team(tmp_path: Path):
    w = World(tmp_path, cfg_over={"internet_leg": {"paused": True}})
    try:
        r = run_scenario(w, "full", {"timeout": 120000, "shotResults": "40-internet-paused"})
        first = r["first"]
        assert internet_status(r) == "paused" and r["csp"] == [] and r["errors"] == []
        assert "paused" in first["notice"].lower() and "network team" in first["notice"]
        assert first["legs"]["Cloudflare"]["val"] == "paused" and "paused" in first["flags"].lower()
        assert first["speeds"][2]["note"] == "Paused by the network" and first["speeds"][2]["v"] == "—"
        assert w.cf.app.snapshot()["stats"]["requests"] == 0, "no request may reach Cloudflare while paused"
        assert first["score"] != "0"
    finally:
        w.stop()


def test_internet_disabled_in_config(tmp_path: Path):
    w = World(tmp_path, cfg_over={"internet_leg": {"enabled": False}})
    try:
        r = run_scenario(w, "full", {"timeout": 120000, "share": True, "shotResults": "42-internet-off"})
        first = r["first"]
        assert "internet" not in r["submissions"][-1]["req"]["legs"]
        assert first["legs"]["Cloudflare"]["small"] == "not enabled here"
        assert w.cf.app.snapshot()["stats"]["requests"] == 0
        assert r["errors"] == [] and r["csp"] == [] and first["score"] not in ("0", "—")
        assert "not available at this event" in (first["notice"] or ""), first["notice"]
        # switched off by the operator is not an outage: the live result and the share link (stored result, flag internet_off)
        # say so ("not tested at this event" in the note, "covers the venue network only" in the verdict), never "until the
        # internet is back", and promise nothing that needs the internet
        for snap in (first, r["shared"]):
            v = snap["verdict"]
            assert "venue network itself" in v and "covers the venue network only" in v and "internet is back" not in v, v
            assert len(snap["goodFor"]) == 4 and all(x.endswith("(not checked)") for x in snap["goodFor"]), snap["goodFor"]
            assert "not tested at this event" in snap["flags"] and "not available" not in snap["flags"], snap["flags"]
        assert r["shared"]["score"] == first["score"]
    finally:
        w.stop()


def test_internet_queued_then_granted_shows_the_queue(tmp_path: Path):
    w = World(tmp_path, cfg_over={"limits": {"max_concurrent_internet": 1}})
    try:
        w.box.core.internet.acquire("st_" + "1" * 26)             # another test holds the only slot
        threading.Timer(3.0, lambda: w.box.core.internet.release("st_" + "1" * 26)).start()
        r = run_scenario(w, "full", {"timeout": 120000})
        ph = " | ".join(r["phases"])
        assert "Waiting for a free internet slot" in ph and "you are #1" in ph, ph
        assert internet_status(r) == "ok"
    finally:
        w.stop()


def test_cloudflare_unreachable_is_unavailable_not_a_failure(tmp_path: Path):
    w = World(tmp_path, cf={"fail": "reset"})
    try:
        r = run_scenario(w, "full", {"timeout": 120000, "shotResults": "41-internet-unavailable"})
        first = r["first"]
        assert internet_status(r) == "unavailable" and r["errors"] == []
        assert "could not be reached" in first["notice"] and first["score"] != "0"
        assert first["speeds"][0]["v"] != "—"
        assert not any("/__results" in u for u in r["requests"])
        # the score rests on the venue network alone: no promise of calls/streaming, which need the internet
        assert "venue network itself" in first["verdict"] and "video calls" not in first["verdict"].lower(), first["verdict"]
        assert "internet is back" in first["verdict"] and "not tested" not in first["verdict"], first["verdict"]
        assert len(first["goodFor"]) == 4 and all(x.endswith("(not checked)") for x in first["goodFor"]), first["goodFor"]
        assert first["flags"].count("not available") == 1 and "not tested" not in first["flags"], first["flags"]
    finally:
        w.stop()


# =================================================================================================================== inertness
def test_hostile_strings_are_inert(tmp_path: Path):
    w = World(tmp_path, cfg_over={"branding": {"title": XSS[:80], "copy": {"subtitle": XSS, "footer": XSS, "start_button": XSS[:40]}},
                                  "consent": {"text": XSS, "version": 3}})
    try:
        r = run_scenario(w, "full", {"report": XSS, "zoneFix": XSS, "share": True, "timeout": 120000})
        for key in ("first", "afterReport", "final", "shared"):
            snap = r[key]
            assert snap["scriptCount"] == 1 and snap["imgs"] == [], key
        assert r["dialogs"] == [] and r["errors"] == [] and r["csp"] == []
        assert r["first"]["title"] == XSS[:80] and r["first"]["docTitle"] == XSS[:80]
        assert r["started"]["consentText"] == XSS
        assert r["afterReport"]["note"] == "Your note: " + XSS
        assert r["shared"]["note"] and XSS[:30] in r["shared"]["note"]
        assert w.tests()[-1].comment is not None and XSS[:20] in w.tests()[-1].comment
    finally:
        w.stop()


def test_dns_leg_without_delegation_is_labelled_the_hall_sensor(tmp_path: Path):
    w = World(tmp_path, dns_arrivals=False)
    try:
        r = run_scenario(w, "full", {"timeout": 120000})
        dns = r["first"]["legs"]["Name lookup (DNS)"]
        assert dns["small"] == "measured by the hall sensor", dns
        assert "dns_fallback" in str(r["submissions"][-1]["res"]["flags"]) and "hall sensor" in r["first"]["flags"]
    finally:
        w.stop()


def test_full_test_without_workers_falls_back_to_the_main_thread(world: World):
    """No Worker available (init script deletes it): both worker files run as classic scripts, the page still produces a
    complete result with comparable figures (the fake Cloudflare is the same 50/25 Mb/s link, 15 ms; the on-network leg the
    same loopback box) and shows the numbers it submitted."""
    r = run_scenario(world, "full", {"noWorker": True, "timeout": 150000})
    first = check_run(r, world)
    assert r["workers"] == []
    assert sum(1 for u in r["requests"] if u.endswith(ENGINE_PATH)) == 1 and sum(1 for u in r["requests"] if u.endswith(LOCAL_PATH)) == 1
    # the opposite of test_full_test_390's worker-path proof: the fallbacks' classic script elements are in the DOM, once each
    assert first["scriptSrcs"] == [LOCAL_PATH, ENGINE_PATH], first["scriptSrcs"]
    xfer = transfer_reqs(r)
    assert xfer and all(on_main_thread(r, xfer)), "without workers every transfer request comes from the main thread"
    sub = r["submissions"][-1]
    assert sub["status"] == 202
    local_leg_sane(sub)
    net = sub["req"]["legs"]["internet"]
    assert net["status"] == "ok" and net["colo"] == "FRA" and net["down_mbps"] > 0 and net["up_mbps"] > 0
    assert net["cv"] is not None and net["cv"] < 0.3, net
    assert sub["res"]["score"]["stability"] >= 40, sub["res"]["score"]
    assert net["idle_ms"] is not None and net["loaded_down_ms"] is not None
    # comparable to the worker path: same order of magnitude as the fake's configured link
    assert 10 < net["down_mbps"] < 1000 and 5 < net["up_mbps"] < 1000, net


@pytest.mark.parametrize("mode", ["error_after_start", "fatal_after_snapshot", "fatal_before_snapshot"])
def test_engine_worker_misbehaving_ends_the_leg_or_falls_back_once(world: World, mode: str):
    """EngineHost robustness (CR-m6-speedtest-server item 26, follow-up 2026-11-20), with a scripted stand-in worker (init script,
    ui/page_scenarios.js fakeWorker; its late events reach the handlers the page set, as events queued before terminate() would):
    an error or a 'fatal' after the first snapshot ends the leg at once with that snapshot (one failure), the worker is terminated
    and what it still sends never reaches the UI; a 'fatal' before any snapshot falls back to the main thread exactly once,
    although a second 'fatal' and an error event follow it."""
    r = run_scenario(world, "full", {"fakeWorker": mode, "timeout": 150000})
    assert r["errors"] == [] and r["csp"] == [] and r["dialogs"] == []
    fw, first = r["fakeWorker"], r["first"]
    assert fw["made"] == 1 and fw["terminated"] == 1, fw
    sub = r["submissions"][-1]
    assert sub["status"] == 202
    net = sub["req"]["legs"]["internet"]
    if mode == "fatal_before_snapshot":
        assert first["scriptSrcs"] == [ENGINE_PATH], first["scriptSrcs"]
        assert sum(1 for u in r["requests"] if u.endswith(ENGINE_PATH)) == 1
        assert net["status"] == "ok" and net["colo"] == "FRA" and net["down_mbps"] > 0 and net["up_mbps"] > 0, net
        assert world.cf.app.snapshot()["stats"]["down"] > 0
        return
    assert first["scriptSrcs"] == [], first["scriptSrcs"]                  # ended, not fallen back
    assert net["status"] == "ok" and net["down_mbps"] == 50 and net["up_mbps"] == 20 and net["failures"] == 1, net
    assert fw["sentAfterTerminate"] >= 2, fw                               # the late phase + finish really arrived ...
    assert not any("Internet upload" in p for p in r["phases"]) and first["phase"] == "Done", (r["phases"], first["phase"])
    assert first["speeds"][2]["v"].startswith("50.0") and first["speeds"][3]["v"].startswith("20.0"), first["speeds"]


CANCEL_LINK = {"downKbps": 50_000, "upKbps": 25_000, "latencyMs": 5}     # A6.10's phone link: each direction lasts seconds


@pytest.mark.parametrize(("where", "mode"), [("On-network download", "worker"), ("On-network upload", "worker"),
                                             ("On-network download", "main"), ("On-network upload", "main")])
def test_cancel_during_the_on_network_leg_stops_its_traffic(world: World, where: str, mode: str):
    """Cancel while a direction of the on-network leg runs (in the transfer worker, or on the main thread without workers):
    no transfer request (down, up, loaded ping) starts after the click + 500 ms, the box has no transfer in flight 1 s after it
    and moves no byte between 1 s and 2.5 s after it (in-flight requests were aborted, not left to finish), nothing is submitted."""
    want = "/st/down" if "download" in where else "/st/up"
    r = run_scenario(world, "cancel", {"cancelIn": where, "cancelPath": want, "noWorker": mode == "main", "throttle": CANCEL_LINK, "timeout": 120000})
    assert r["errors"] == [] and r["csp"] == [] and r["dialogs"] == [], (r["errors"], r["csp"])
    c, snap = r["cancel"], r["snap"]
    assert c["phaseAtClick"] == where, (c["phaseAtClick"], r["phases"])
    assert snap["phase"] == "Test stopped" and "Nothing was sent" in (snap["notice"] or ""), (r["phases"], snap["notice"])
    xfer = [q for q in r["reqLog"] if q["u"] in set(transfer_reqs(r))]
    assert any(urlsplit(q["u"]).path == want and q["t"] <= c["tc"] for q in xfer), "the direction was moving data when Cancel was clicked"
    late = [q for q in xfer if q["t"] > c["tc"] + 500]
    assert late == [], late[:5]
    assert c["before"]["meter"] > 0 and c["b1"]["transfers"] == 0 and c["b2"]["meter"] == c["b1"]["meter"], c
    assert r["submissions"] == [] and not any(u.endswith("/result") for u in r["requests"])
    assert not any(u.endswith(ENGINE_PATH) or "speed.cloudflare.com" in u for u in r["requests"]), "the internet leg never started"
    if mode == "worker":
        assert r["workers"] == [f"http://{HOST}{LOCAL_PATH}"] and snap["scriptSrcs"] == [], (r["workers"], snap["scriptSrcs"])
        assert not any(on_main_thread(r, [q["u"] for q in xfer]))
    else:
        assert r["workers"] == [] and snap["scriptSrcs"] == [LOCAL_PATH], snap["scriptSrcs"]


@pytest.mark.parametrize("mode", ["throw", "silent", "fatal_mid"])
def test_local_worker_misbehaving_falls_back_once(world: World, mode: str):
    """LocalHost robustness, with a scripted stand-in for the transfer worker (ui/page_scenarios.js fakeLocalWorker; the internet
    engine's worker is the real one): new Worker throwing, or no 'ready' within LOCAL_START_MS, runs the whole on-network leg on
    the main thread from the same file (one classic script); a 'fatal' after the download reported progress ends the download
    with no figure and one failure (the malformed progress message and the late 'done' and error event change nothing) and the
    upload runs on the main thread. The worker is terminated every time; the internet leg still runs in its own worker."""
    r = run_scenario(world, "full", {"fakeLocal": mode, "timeout": 150000})
    assert r["errors"] == [] and r["csp"] == [] and r["dialogs"] == [], (r["errors"], r["csp"])
    fl, first = r["fakeLocal"], r["first"]
    assert r["workers"] == [f"http://{HOST}{ENGINE_PATH}"], r["workers"]
    assert first["scriptSrcs"] == [LOCAL_PATH], first["scriptSrcs"]                    # one fallback, never two
    assert sum(1 for u in r["requests"] if u.endswith(LOCAL_PATH)) == 1
    sub = r["submissions"][-1]
    assert sub["status"] == 202 and sub["req"]["legs"]["internet"]["status"] == "ok"
    same_numbers(first, sub)
    loc = sub["req"]["legs"]["local"]
    ups = [u for u in transfer_reqs(r) if u.endswith("/st/up")]
    assert ups and all(on_main_thread(r, ups)), "the upload ran on the main thread"
    if mode == "throw":
        assert fl["made"] == 0
        local_leg_sane(sub)
        return
    assert fl["made"] == 1 and fl["terminated"] == 1, fl
    if mode == "silent":
        assert fl["commands"] == [], fl                         # never ready: no transfer was ever handed to it
        local_leg_sane(sub)
        return
    # fatal_mid: the download ended at the 'fatal' with no figure; nothing the stand-in sent after it reached the page
    assert fl["commands"][:1] == ["transfer"] and fl["sentAfterTerminate"] >= 2, fl
    assert "down_mbps" not in loc and loc["up_mbps"] > 0 and loc["status"] == "ok" and loc["failures"] >= 1, loc
    assert first["speeds"][0]["v"] == "—" and first["speeds"][1]["v"] != "—", first["speeds"]
    assert not any("/st/down?" in u for u in r["requests"]), "the stand-in moved the download, the page never re-ran it"

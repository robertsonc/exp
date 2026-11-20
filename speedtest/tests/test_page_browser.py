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
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

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
        self.cf = cfs.start(tls=(cert, key), **{"latency_ms": 15, "loaded_latency_ms": 40, "down_bps": 400_000_000, "up_bps": 100_000_000, **(cf or {})})
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
                if req["op"] == "correlate":
                    w.correlate()
                p.stdin.write("@@OK {}\n")  # type: ignore[union-attr]
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
    return first


def test_full_test_390(world: World):
    r = run_scenario(world, "full", {"correlate": True, "shotPre": "01-start-390-light", "midShot": "02-running-390-light",
                                     "shotResults": "03-results-390-light", "shotFinal": "04-final-390-light", "share": True, "shotShared": "05-shared-390-light",
                                     "keyboard": True, "contrast": True, "report": "video calls freeze at my booth", "zoneFix": "Hall B, row 9", "copy": True,
                                     "timeout": 150000})
    first = check_run(r, world)
    # --- the internet engine ran in the dedicated worker (off the main thread), served by the box, with its own CSP
    assert r["workers"] == [f"http://{HOST}/st/assets/cf-engine.js"], r["workers"]
    assert any(u.endswith("/st/assets/cf-engine.js") for u in r["requests"])
    # --- the engine really measured: server-recomputed score shown, every leg present
    sub = r["submissions"][-1]
    assert sub["status"] == 202 and sub["req"]["schema"] == "exp.speedtest.submission/1"
    legs = sub["req"]["legs"]
    assert legs["local"]["status"] == "ok" and legs["local"]["down_mbps"] > 0 and legs["local"]["up_mbps"] > 0
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
        r = run_scenario(w, "full", {"timeout": 120000})
        assert "internet" not in r["submissions"][-1]["req"]["legs"]
        assert r["first"]["legs"]["Cloudflare"]["small"] == "not enabled here"
        assert w.cf.app.snapshot()["stats"]["requests"] == 0
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
        assert "internet is back" in first["verdict"], first["verdict"]
        assert len(first["goodFor"]) == 4 and all(x.endswith("(not checked)") for x in first["goodFor"]), first["goodFor"]
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
    """No Worker available (init script deletes it): the same asset file runs as a classic script, the page still produces a
    complete result with comparable internet figures (the fake Cloudflare is the same 400/100 Mb/s link, 15 ms)."""
    r = run_scenario(world, "full", {"noWorker": True, "timeout": 150000})
    check_run(r, world)
    assert r["workers"] == []
    assert sum(1 for u in r["requests"] if u.endswith("/st/assets/cf-engine.js")) == 1
    sub = r["submissions"][-1]
    assert sub["status"] == 202
    net = sub["req"]["legs"]["internet"]
    assert net["status"] == "ok" and net["colo"] == "FRA" and net["down_mbps"] > 0 and net["up_mbps"] > 0
    assert net["cv"] is not None and net["cv"] < 0.3, net
    assert sub["res"]["score"]["stability"] >= 40, sub["res"]["score"]
    assert net["idle_ms"] is not None and net["loaded_down_ms"] is not None
    # comparable to the worker path: same order of magnitude as the fake's configured link
    assert 10 < net["down_mbps"] < 1000 and 5 < net["up_mbps"] < 1000, net

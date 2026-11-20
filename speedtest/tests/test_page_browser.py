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
import threading
import time
from pathlib import Path
from typing import Any

import dns.message
import dns.query
import fakes_common as fc
import pytest
from exp_common import speedtest as st
from stbox import Box, free_port, shared_tls

HERE = Path(__file__).resolve().parent
NODE = shutil.which("node")
HOST = "speed.test.example"
ZONE = "t.speed.test.example"
SCENARIOS = HERE / "ui" / "page_scenarios.js"
FIXTURES = fc.FIXTURES_DIR
ARTIFACTS = Path("/tmp/claude-0/-home-user-exp/5fe304da-431d-56ac-8a9d-ec4bbb823c52/scratchpad/e2e-artifacts/m6/page")
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
        self.cf = cfs.start(tls=(cert, key), **(cf or {}))
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
    cf = w.cf.app.snapshot()
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
    # --- the engine really measured: server-recomputed score shown, every leg present
    sub = r["submissions"][-1]
    assert sub["status"] == 202 and sub["req"]["schema"] == "exp.speedtest.submission/1"
    legs = sub["req"]["legs"]
    assert legs["local"]["status"] == "ok" and legs["local"]["down_mbps"] > 0 and legs["local"]["up_mbps"] > 0
    assert legs["internet"]["status"] == "ok" and legs["internet"]["colo"] == "FRA" and legs["internet"]["down_mbps"] > 0
    assert legs["dns"]["source"] == "browser" and "cold_ms" in legs["dns"]
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
    assert any("good for" in x.lower() or x for x in first["goodFor"]) and len(first["goodFor"]) == 4
    assert first["share"].startswith(f"http://{HOST}/st/r/st_") and "#k=" in first["share"]
    # --- correlation flipped the checks from "checking..." to findings, zone shown with the correct-it affordance
    assert any("checking" in c for c in first["checks"])
    fl = r["flipped"]
    assert fl and not any("checking" in c for c in fl["checks"]), fl and fl["checks"]
    assert any("Wi-Fi signal" in c for c in fl["checks"]) and any("Security policy" in c and "worth a look" in c for c in fl["checks"])
    assert fl["where"] and "You were in" in fl["where"] and "Hall B" in fl["where"]
    assert fl["why"], "final diagnosis text"
    # --- report + zone correction ride the comment route
    assert r["rDone"] == "Saved with your test." and r["zDone"].startswith("Thanks")
    comments = [t.comment for t in world.tests()]
    assert comments and "[where I was] Hall B, row 9" in comments[-1] and "video calls freeze at my booth" in comments[-1]
    # --- plain HTTP: clipboard + wake lock absent, the link is selected for copying
    assert first["secure"] is False and first["subtle"] == "undefined" and first["wakeLock"] == "undefined"
    assert r["selection"] == first["share"] and "selected" in r["copyStat"].lower()
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

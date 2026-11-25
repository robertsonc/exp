"""SPA behaviour in a real browser (Playwright + Chromium) against the real dashboard and three fake collectors.

Each scenario in ui/scenarios.js runs as its own node process; the world (collectors, feeder, dashboard) lives in
this process and answers "@@NEED" requests from the script. Skipped when node/playwright are unavailable.
The 'no request leaves the LAN' capture of spec 7.7 needs a network namespace and belongs to the WP-8 harness.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest

import ui_world

HERE = Path(__file__).resolve().parent
NODE = shutil.which("node")


def _have_playwright() -> bool:
    if not NODE:
        return False
    r = subprocess.run([NODE, "-e", "require('playwright')"], capture_output=True, timeout=60)  # noqa: S603
    return r.returncode == 0


pytestmark = pytest.mark.skipif(not _have_playwright(), reason="node + playwright are not available")


class Driver:
    def __init__(self, world: Any, tmp: Path) -> None:
        self.world, self.tmp = world, tmp
        self.timeline = ui_world.seed(world)
        self.feeder: ui_world.Feeder = self.timeline["feeder"]
        self.lines: list[str] = []

    def config(self) -> dict[str, Any]:
        w = self.world
        return {"base": f"https://127.0.0.1:{w.port}", "passwords": w.pw, "noc_token": w.noc_token, "xss": ui_world.XSS,
                "t_mid": (self.timeline["fail_from"] + self.timeline["fail_to"]) // 2 // 1000 * 1000,
                "out": str(self.tmp / "shots"), "timeout_ms": 120000}

    def answer(self, req: dict[str, Any]) -> dict[str, Any]:
        op = req["op"]
        if op == "inject_fail":
            self.feeder.set(req["probe"], req["line"], "fail")
        elif op == "clear_fail":
            self.feeder.set(req["probe"], req["line"], None)
        elif op == "stop_feed":
            self.feeder.stop()
        elif op == "start_feed":
            self.feeder = ui_world.Feeder(self.world, ("probe-a1", "probe-c1"))
            self.feeder.start()
            self.feeder.beat("probe-c1")
        elif op == "stop_collector":
            self.world.fakes[req["collector"]].stop()
        elif op == "acked_by":
            for f in self.world.fakes.values():
                for i in f.app.incidents:
                    if i["id"] == req["id"]:
                        return {"acked_by": i["acked_by"]}
            return {"acked_by": None}
        else:
            return {"error": "unknown op"}
        return {"ok": True}

    def run(self, scenario: str, timeout: float = 150) -> str:
        cfg_path = self.tmp / "ui-config.json"
        cfg_path.write_text(json.dumps(self.config()))
        env = dict(os.environ, NODE_TLS_REJECT_UNAUTHORIZED="0")
        p = subprocess.Popen([NODE, str(HERE / "ui" / "scenarios.js"), scenario, str(cfg_path)], stdin=subprocess.PIPE,  # noqa: S603
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, cwd=str(self.tmp))
        assert p.stdin and p.stdout

        def pump() -> None:
            for line in p.stdout:  # type: ignore[union-attr]
                line = line.rstrip("\n")
                self.lines.append(line)
                if line.startswith("@@NEED "):
                    ans = self.answer(json.loads(line[7:]))
                    p.stdin.write("@@OK " + json.dumps(ans) + "\n")  # type: ignore[union-attr]
                    p.stdin.flush()  # type: ignore[union-attr]

        t = threading.Thread(target=pump, daemon=True)
        t.start()
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            rc = -9
        t.join(timeout=5)
        out = "\n".join(self.lines)
        assert rc == 0 and f"@@PASS {scenario}" in out, f"scenario {scenario} failed (rc={rc}):\n{out}"
        return out


@pytest.fixture()
def drv(world, tmp_path):
    d = Driver(world, tmp_path)
    yield d
    d.feeder.stop()


@pytest.mark.parametrize("scenario", ["xss", "rewind", "live", "incidents", "overview", "kiosk", "mobile", "login", "lines"])
def test_scenario(drv, scenario):
    drv.run(scenario)


def test_stale_banner(drv):
    drv.run("stale")


def test_noc_flow_and_token_never_in_server_logs(drv, caplog):
    caplog.set_level(logging.DEBUG)
    drv.run("noc")
    token = drv.world.noc_token
    assert token not in caplog.text, "NOC token leaked into a log record"
    assert not any(token in r.getMessage() or token in str(r.args) for r in caplog.records)
    # and the session exchange is the only trace: a viewer session of kind noc exists
    assert "noc session started" in caplog.text

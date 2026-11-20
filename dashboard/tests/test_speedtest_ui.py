"""Speedtest analytics views in a real browser (Playwright + Chromium) against the real dashboard and three fake
collectors serving the speedtest routes (st_fake). Screenshots go to the e2e artifacts directory."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest

import st_fake
import ui_world

HERE = Path(__file__).resolve().parent
NODE = shutil.which("node")
_ART = "/tmp/claude-0/-home-user-exp/5fe304da-431d-56ac-8a9d-ec4bbb823c52/scratchpad/e2e-artifacts/m6/dashboard"
SHOTS = Path(os.environ.get("EXP_ST_SHOTS", _ART))


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
        self.feeder = self.timeline["feeder"]
        self.lines: list[str] = []

    def config(self) -> dict[str, Any]:
        w = self.world
        SHOTS.mkdir(parents=True, exist_ok=True)
        return {"base": f"https://127.0.0.1:{w.port}", "passwords": w.pw, "noc_token": w.noc_token,
                "xss": st_fake.XSS, "xss_host": st_fake.XSS_HOST,
                "sso_tokens": [w.sso_token(role="admin") for _ in range(4)],
                "ids": {"normal": st_fake.st_id(1001), "hostile": st_fake.st_id(1037)},
                "raw": [st_fake.RAW_IP, st_fake.RAW_MAC, st_fake.RAW_USER, st_fake.RAW_HOST],
                "device_key": st_fake.DEVICE_KEY, "out": str(SHOTS), "timeout_ms": 150000}

    def answer(self, req: dict[str, Any]) -> dict[str, Any]:
        op = req["op"]
        if op == "stop_collector":
            self.world.fakes[req["collector"]].stop()
        elif op == "exists":
            return {"exists": any(r["id"] == req["id"] for s in self.world.st.values() for r in s.rows)}
        elif op == "count":
            return {"count": sum(len(s.rows) for s in self.world.st.values())}
        return {"ok": True}

    def run(self, scenario: str, timeout: float = 170) -> str:
        cfg_path = self.tmp / "st-ui-config.json"
        cfg_path.write_text(json.dumps(self.config()))
        env = dict(os.environ, NODE_TLS_REJECT_UNAUTHORIZED="0")
        p = subprocess.Popen([NODE, str(HERE / "ui" / "st_scenarios.js"), scenario, str(cfg_path)],  # noqa: S603
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             env=env, cwd=str(self.tmp))
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
def drv(make_world, monkeypatch, tmp_path):
    st_fake.install(monkeypatch)
    w = make_world()
    w.st = st_fake.attach(w)
    d = Driver(w, tmp_path)
    yield d
    d.feeder.stop()


@pytest.mark.parametrize("scenario", ["overview", "breakdowns", "detail", "xss", "support", "purge", "noc", "partial",
                                      "mobile"])
def test_scenario(drv, scenario):
    drv.run(scenario)

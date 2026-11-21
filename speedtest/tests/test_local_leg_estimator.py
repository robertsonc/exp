"""The on-network leg's speed estimator in node (CR-m6-speedtest-server item 27): js/local_leg_units.js loads ``local-leg.js``
(the built asset the page and its worker run, and its source) and reports one result per case.

"pure" cases call ``ExpLocalLeg.estimate`` / ``pushPoint`` on synthetic per-stream cumulative series; "sim" cases run the whole
``ExpLocalLeg.transfer`` on a virtual clock against a fake box behind a fluid link model (fetch for /st/down and /st/ping,
XMLHttpRequest with ~100-300 ms upload progress lumps for /st/up). Before item 27 the budget-limited cases read the byte
budget / one 250-ms sample (18 MB -> 576 Mb/s, 12 MB -> 384 Mb/s) or the drain tail, and a lumpy upload's p90 read ~+30 %.
Skipped without node.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
HARNESS = HERE / "js" / "local_leg_units.js"
FILES = {"built": ROOT / "exp_speedtest" / "static" / "assets" / "local-leg.js", "src": ROOT / "page" / "src" / "local-leg.js"}
NODE = shutil.which("node")
CASES = [
    "p90_steady_400", "budget_ends_at_300ms_2gbps", "budget_inside_one_bin_18mb", "budget_right_after_ramp_long_drain",
    "bursty_upload_budget_window", "bursty_upload_p90", "late_stream_does_not_collapse_the_window", "no_bytes",
    "series_is_bounded_and_exact",
    "sim_slow_down_p90", "sim_slow_up_p90_lumpy", "sim_fast_down_budget_window", "sim_fast_down_budget_one_bin",
    "sim_fast_up_budget_lumpy", "sim_fast_up_budget_one_bin",
]

pytestmark = pytest.mark.skipif(not NODE, reason="node is not available")

_RESULTS: dict[str, dict[str, Any]] = {}


def results(which: str) -> dict[str, Any]:
    if which not in _RESULTS:
        p = subprocess.run([NODE, str(HARNESS), str(FILES[which])], capture_output=True, text=True, timeout=120)
        line = next((ln for ln in p.stdout.splitlines() if ln.startswith("@@RESULT ")), None)
        assert line, f"harness produced no result (exit {p.returncode}):\n{p.stdout[-2000:]}\n{p.stderr[-2000:]}"
        _RESULTS[which] = {c["name"]: c for c in json.loads(line[len("@@RESULT "):])["cases"]}
    return _RESULTS[which]


def test_the_harness_runs_every_case_it_is_asked_for():
    assert sorted(results("built")) == sorted(CASES)


@pytest.mark.parametrize("which", sorted(FILES))
@pytest.mark.parametrize("case", CASES)
def test_estimator_case(which: str, case: str):
    c = results(which).get(case)
    assert c is not None, f"{case}: not reported by the harness"
    assert c["ok"] is True, f"{case} ({which}): got {json.dumps(c['got'])[:800]}, want {c['want']}"

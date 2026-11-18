"""The documented CLI replay of the EXM outage: nine pages from 02:55 (the window EXM's own replay used,
reference/exm/test/unit.py:231), and the earlier 02:45 DNS failure pages when the replay starts earlier."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "test" / "fixtures" / "exm" / "outage-2026-10-27.ndjson.gz"
BIN = ROOT / "collector" / "bin" / "exp-collector"


def _pages(*extra: str) -> list[str]:
    out = subprocess.run([sys.executable, str(BIN), "replay", str(FIXTURE), "--alerts", *extra],
                         capture_output=True, text=True, timeout=300, check=True).stdout
    return [ln for ln in out.splitlines() if re.match(r"^\[2026-", ln)]


def test_cli_replay_from_0255_emits_the_nine_expected_pages():
    pages = _pages("--from", "2026-10-27T02:55:00Z", "--to", "2026-10-27T04:28:00Z")
    kinds = [" ".join(p.split("] ", 1)[1].split(":")[0].split()[:2]) for p in pages]
    assert kinds == ["down Network", "resolved Network", "down DNS", "resolved DNS", "down Wi-Fi",
                     "down DNS", "resolved DNS", "down DNS", "resolved DNS"]


def test_cli_replay_from_the_start_also_pages_the_0245_dns_failure():
    pages = _pages()
    assert len(pages) == 11 and "down DNS" in pages[0] and "02:4" in pages[0]

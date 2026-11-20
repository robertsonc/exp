"""exp-speedtest: the on-network speedtest box (spec: docs/spec/12-speedtest-analytics.md, 01-contracts.md section 14)."""
from __future__ import annotations

from pathlib import Path

_PKG = Path(__file__).resolve().parent


def _read_version() -> str:
    # tarball: lib/exp_speedtest -> ../../VERSION ; dev tree: speedtest/exp_speedtest -> ../../VERSION (repo root)
    for cand in (_PKG / "VERSION", _PKG.parent.parent / "VERSION", _PKG.parent / "VERSION"):
        try:
            text = cand.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text and len(text) <= 64:
            return text
    return "0.1.0"


__version__ = _read_version()

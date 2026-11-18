"""exp-agent: the declarative host agent (docs/spec/06-agent.md). Python 3.10+, stdlib only."""

from __future__ import annotations

from pathlib import Path

_PKG = Path(__file__).resolve().parent


def _read_version() -> str:
    # dev tree: <repo>/agent/exp_agent -> <repo>/VERSION ; tarball: <prefix>/lib/exp_agent -> <prefix>/VERSION
    for cand in (_PKG / "VERSION", _PKG.parent.parent / "VERSION"):
        try:
            text = cand.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text and len(text) <= 64:
            return text
    return "0.1.0"


__version__ = _read_version()

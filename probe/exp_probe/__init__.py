"""exp-probe: a synthetic user on the event network (spec: docs/spec/02-probe.md)."""
from __future__ import annotations

from pathlib import Path

_PKG = Path(__file__).resolve().parent


def _read_version() -> str:
    # tarball: lib/exp_probe -> ../../VERSION ; dev tree: probe/exp_probe -> ../../VERSION (repo root)
    for cand in (_PKG / "VERSION", _PKG.parent.parent / "VERSION", _PKG.parent / "VERSION"):
        try:
            text = cand.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text and len(text) <= 64:
            return text
    return "0.1.0"


__version__ = _read_version()

"""exp-dashboard: auth, federation over collectors, and the Pulse board SPA (WP-3)."""
from __future__ import annotations

from pathlib import Path

_PKG = Path(__file__).resolve().parent


def _read_version() -> str:
    # Both layouts keep VERSION two levels above the package (tarball root or repo root).
    cand = _PKG.parent.parent / "VERSION"
    try:
        text = cand.read_text(encoding="utf-8").strip()
    except OSError:
        return "0.1.0"
    return text if text and len(text) <= 64 else "0.1.0"


__version__ = _read_version()
COMPONENT = "dashboard"

"""exp-collector: authenticated ingest, SQLite record store, VictoriaMetrics writer, health, CLI.

Spec: docs/spec/03-collector.md. Python 3.10+, stdlib only (plus exp_common).
"""
from __future__ import annotations

from pathlib import Path


def _read_version() -> str:
    # tarball layout ships <lib>/exp_collector/VERSION or <root>/VERSION; dev tree falls back to
    # exp_common (which reads <repo>/VERSION).
    here = Path(__file__).resolve().parent
    for cand in (here / "VERSION", here.parent.parent / "VERSION"):
        try:
            text = cand.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text and len(text) <= 64:
            return text
    try:
        from exp_common import __version__ as v
        return str(v)
    except ImportError:  # pragma: no cover
        return "0.1.0"


__version__ = _read_version()

"""exp-runner: correlation pipeline + syslog receiver (M6; no drills).

Spec: docs/spec/12-speedtest-analytics.md section 5, docs/spec/01-contracts.md sections 8.1 and 14.6.
Python 3.10+, stdlib only (plus exp_common).
"""
from __future__ import annotations

from pathlib import Path


def _read_version() -> str:
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

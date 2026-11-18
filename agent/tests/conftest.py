"""Test wiring: product code + shared exp_common + the WP-0 fakes on sys.path."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
for p in (
    REPO / "agent",
    REPO / "shared" / "python",
    REPO / "test" / "fakes",
    Path(__file__).resolve().parent,
):
    s = str(p)
    if s not in sys.path:
        sys.path.insert(0, s)

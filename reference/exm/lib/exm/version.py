"""The release version: the VERSION file shipped next to bin/ and lib/ (one source of truth)."""
from __future__ import annotations

import os


def version() -> str:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "VERSION")
    try:
        with open(path) as fh:
            return fh.read().strip() or "0.0.0-dev"
    except OSError:
        return "0.0.0-dev"

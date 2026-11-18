"""exp_common: contracts reference implementation shared by every exp component (stdlib only)."""
from __future__ import annotations

import os
from pathlib import Path

_PKG = Path(__file__).resolve().parent


def _read_version() -> str:
    # <repo>/VERSION when running from a checkout; packaged builds ship exp_common/VERSION.
    for cand in (_PKG / "VERSION", _PKG.parent.parent.parent / "VERSION"):
        try:
            text = cand.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text and len(text) <= 64:
            return text
    return "0.1.0"


__version__ = _read_version()


def schemas_dir() -> Path:
    """Directory holding *.schema.json: $EXP_SCHEMAS_DIR, else packaged exp_common/schemas,
    else <repo>/shared/schemas (relative to this package)."""
    env = os.environ.get("EXP_SCHEMAS_DIR")
    if env:
        return Path(env)
    packaged = _PKG / "schemas"
    if packaged.is_dir():
        return packaged
    return _PKG.parent.parent / "schemas"

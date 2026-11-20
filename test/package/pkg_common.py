"""Constants and helpers shared by the package tests (a module of its own: a second `conftest` elsewhere in the
session, e.g. agent/tests/container, would shadow `from conftest import ...`)."""
from __future__ import annotations

import hashlib
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PKG = REPO / "packaging"
BUILD = PKG / "build.sh"
VERIFY = PKG / "verify-release.sh"
EPOCH = "1700000000"
VERSION = "0.1.0"
COMPONENTS = ["agent", "probe", "collector", "dashboard", "runner", "speedtest"]

sys.path.insert(0, str(PKG))
sys.path.insert(0, str(REPO / "shared" / "python"))


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def make_wheel(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("dns/__init__.py", "VERSION = 'stub'\n")
        z.writestr("dns/__pycache__/junk.cpython-310.pyc", b"junk")
        z.writestr("stubdns-1.0.dist-info/METADATA", "Name: stubdns\n")
        z.writestr("stubdns-1.0.dist-info/licenses/LICENSE", "ISC stub license\n")

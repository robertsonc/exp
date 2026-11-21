#!/usr/bin/env python3
"""DEV-TIME ONLY: regenerate the page's subset fonts (never a product dependency; fonttools lives in a scratch venv).

    python3 -m venv /tmp/fontvenv && /tmp/fontvenv/bin/pip install fonttools brotli
    /tmp/fontvenv/bin/python speedtest/page/tools/subset_fonts.py --npm-root <dir holding x-archivo-5.3.0 ...>

Inputs: the @fontsource-variable 5.3.0 packages (OFL-1.1; tarball sha256 pins are in packaging/vendor.lock):
Archivo (wdth + wght variable, display / numerals), Inter (wght variable, text), JetBrains Mono (wght variable, codes).
Output: ``speedtest/exp_speedtest/static/assets/{archivo,inter,jetbrains-mono}.woff2`` (Latin + digits + UI punctuation,
variable axes kept) and the OFL texts ``OFL-*.txt`` beside them, then prints the sha256 of every output so that
``packaging/vendor.lock`` can be updated (a test compares them). Total budget: <= 120 KB.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from pathlib import Path

from fontTools import subset  # type: ignore[import-not-found]
from fontTools.ttLib import TTFont  # type: ignore[import-not-found]

OUT = Path(__file__).resolve().parents[2] / "exp_speedtest" / "static" / "assets"
# printable ASCII + nbsp, degree, middle dot, multiplication, minus, dashes, quotes, ellipsis, arrows, check/warn punctuation
UNICODES = list(range(0x20, 0x7F)) + [0xA0, 0xB0, 0xB7, 0xD7, 0x2013, 0x2014, 0x2018, 0x2019, 0x201C, 0x201D, 0x2026, 0x2192,
                                      0x2212]
FONTS = [("archivo", "x-archivo-5.3.0", "archivo-latin-wdth-normal.woff2"),
         ("inter", "x-inter-5.3.0", "inter-latin-wght-normal.woff2"),
         ("jetbrains-mono", "x-jetbrains-mono-5.3.0", "jetbrains-mono-latin-wght-normal.woff2")]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--npm-root", required=True, type=Path)
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    total = 0
    for name, pkg, fname in FONTS:
        src = a.npm_root / pkg / "package" / "files" / fname
        opts = subset.Options()
        opts.flavor = "woff2"
        opts.layout_features = ["kern", "liga", "calt", "tnum", "lnum", "ccmp", "mark", "mkmk"]
        opts.notdef_outline = True
        opts.name_IDs = [0, 1, 2, 3, 4, 6, 13, 14]       # keep the copyright + OFL licence records
        opts.hinting = False
        opts.desubroutinize = False
        font = TTFont(str(src))
        sub = subset.Subsetter(opts)
        sub.populate(unicodes=UNICODES)
        sub.subset(font)
        font.flavor = "woff2"
        dst = OUT / f"{name}.woff2"
        font.save(str(dst))
        data = dst.read_bytes()
        total += len(data)
        shutil.copyfile(a.npm_root / pkg / "package" / "LICENSE", OUT / f"OFL-{name}.txt")
        print(f"{name}.woff2 {len(data)} bytes sha256 {hashlib.sha256(data).hexdigest()}")
    print(f"total {total} bytes")
    return 0 if total <= 120 * 1024 else 1


if __name__ == "__main__":
    sys.exit(main())

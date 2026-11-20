#!/usr/bin/env python3
"""Build the self-contained speedtest page (WP-10, 12-speedtest-analytics.md section 4.3).

    python3 speedtest/page/build.py            # writes speedtest/exp_speedtest/static/{index.html,csp-hashes.json}
    python3 speedtest/page/build.py --check    # exit 1 if the committed output differs from a fresh build

stdlib only and deterministic: the same sources always give the same bytes (no timestamps, no ordering from sets or dicts
that are not sorted). Inputs (all under ``speedtest/page/``): ``src/index.html`` (template), ``src/style.css``, ``src/app.js``
and ``vendor/speedtest.js`` (the unmodified ``@cloudflare/speedtest`` 1.16.0 dist, MIT; see ``vendor/`` and
``packaging/vendor.lock``). The vendored ES module is wrapped into a classic script (its single ``export default`` becomes
``return``), preceded by its MIT licence header, so the page needs no module loading and no third-party host.

CSP: the page has exactly two inline ``<script>`` blocks and one ``<style>`` block; their sha256 hashes are written to
``csp-hashes.json`` (``exp.speedtest.csp/1``), which ``exp_speedtest/static.py`` reads to build ``script-src``/``style-src``.
Fonts are not inlined: they are the subset woff2 files in ``exp_speedtest/static/assets/`` served as ``/st/assets/<name>``
(``font-src 'self'``).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT_DIR = HERE.parent / "exp_speedtest" / "static"
LIB_EXPORT = "export { SpeedTestEngine as default };"
HASH_SCHEMA = "exp.speedtest.csp/1"


def csp_hash(text: str) -> str:
    """Same function as ``exp_speedtest.static.csp_hash`` (tests assert both agree on the built page)."""
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8").replace("\r\n", "\n")


def minify_css(css: str) -> str:
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    lines = [ln.strip() for ln in css.split("\n")]
    return "\n".join(ln for ln in lines if ln)


def tidy_js(js: str) -> str:
    """Drop the banner comment and whole-line ``//`` comments, trim trailing space: no renaming, no rewriting of code."""
    js = re.sub(r"\A\s*/\*.*?\*/", "", js, count=1, flags=re.S)
    out = [ln.rstrip() for ln in js.split("\n") if not ln.lstrip().startswith("//") and ln.strip()]
    return "\n".join(out)


def wrap_library(lib: str, license_text: str) -> str:
    if lib.count(LIB_EXPORT) != 1:
        raise SystemExit("vendor/speedtest.js: expected exactly one `export default` line (layout changed: re-check)")
    body = lib.replace(LIB_EXPORT, "return SpeedTestEngine;")
    # The library is embedded VERBATIM (only its export line is wrapped). Its rpki/msm reachability engines carry
    # `https://${host}` URL templates; the page never runs them (app.js plans latency/download/upload only) and the
    # CSP connect-src would block them anyway: see test_page_build.py::test_page_contacts_only_the_box_and_cloudflare.
    body = re.sub(r"\n//# sourceMappingURL=\S+\s*\Z", "\n", body)
    head = "/* @cloudflare/speedtest 1.16.0, vendored unmodified in a wrapper.\n" + \
        "\n".join(" " + ln if ln else "" for ln in license_text.strip().split("\n")).replace("*/", "* /") + "\n */"
    return head + "\nvar CFSpeedTest = (function () {\n" + body.strip() + "\n})();"


def build() -> dict[str, str]:
    tpl = _read(HERE / "src" / "index.html")
    css = minify_css(_read(HERE / "src" / "style.css"))
    app = tidy_js(_read(HERE / "src" / "app.js"))
    lib = wrap_library(_read(HERE / "vendor" / "speedtest.js"), _read(HERE / "vendor" / "LICENSE-cloudflare-speedtest.txt"))
    for name, text in (("style.css", css), ("app.js", app), ("speedtest.js", lib)):
        if "</script" in text.lower() or "</style" in text.lower() or "<!--" in text:
            raise SystemExit(f"{name}: contains a sequence that would end or confuse an inline block")
    for marker in ("@@CSS@@", "@@LIB@@", "@@APP@@"):
        if tpl.count(marker) != 1:
            raise SystemExit(f"src/index.html: marker {marker} must appear exactly once")
    html = tpl.replace("@@CSS@@", css).replace("@@LIB@@", lib).replace("@@APP@@", app)
    # the CSP hashes cover exactly the text between the tags, so compute them from the final document
    scripts = [m.group(1) for m in re.finditer(r"<script>(.*?)</script>", html, flags=re.S)]
    styles = [m.group(1) for m in re.finditer(r"<style>(.*?)</style>", html, flags=re.S)]
    if len(scripts) != 2 or len(styles) != 1 or re.search(r"<script[^>]*\ssrc=", html, flags=re.I):
        raise SystemExit("unexpected inline block layout")
    hashes = {"schema": HASH_SCHEMA, "script": [csp_hash(s) for s in scripts], "style": [csp_hash(s) for s in styles]}
    return {"index.html": html, "csp-hashes.json": json.dumps(hashes, indent=1, sort_keys=True) + "\n"}


def asset_files() -> dict[str, bytes]:
    """The committed subset fonts and their OFL texts (``static/assets/``): outputs of ``tools/subset_fonts.py``, pinned in
    ``packaging/vendor.lock``. ``--out DIR`` (the packaging hook) gets a copy so DIR is the whole static tree."""
    src = OUT_DIR / "assets"
    return {f"assets/{p.name}": p.read_bytes() for p in sorted(src.iterdir()) if p.is_file() and p.suffix in (".woff2", ".txt")}


def write(out_dir: Path = OUT_DIR) -> dict[str, str]:
    files = build()
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (out_dir / name).write_bytes(text.encode("utf-8"))
    if out_dir.resolve() != OUT_DIR.resolve():
        for rel, data in asset_files().items():
            (out_dir / rel).parent.mkdir(parents=True, exist_ok=True)
            (out_dir / rel).write_bytes(data)
    return files


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="fail when the committed output is stale")
    ap.add_argument("--out", type=Path, default=OUT_DIR)
    a = ap.parse_args()
    if a.check:
        stale = [n for n, t in build().items() if not (a.out / n).is_file() or (a.out / n).read_bytes() != t.encode("utf-8")]
        for n in stale:
            print(f"stale: {a.out / n}", file=sys.stderr)
        return 1 if stale else 0
    files = write(a.out)
    for n, t in files.items():
        print(f"{a.out / n}: {len(t.encode('utf-8'))} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())

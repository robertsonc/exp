"""SR-13: the static tree must not contain DOM-injection sinks, inline handlers/scripts/styles or external loads."""
from __future__ import annotations

import re
from pathlib import Path

from exp_dashboard import server

STATIC = Path(server.STATIC_DIR)
SINKS = re.compile(r"innerHTML|outerHTML|insertAdjacentHTML|document\s*\.\s*write|\beval\s*\(|new\s+Function\b|\bsetTimeout\s*\(\s*[\"'`]"
                   r"|\bsetInterval\s*\(\s*[\"'`]|srcdoc|createContextualFragment|\.\s*setAttribute\s*\(\s*[\"'](?:on|style)")
JS_HANDLER = re.compile(r"\.\s*on[a-z]+\s*=(?!=)")
HTML_HANDLER = re.compile(r"<[^>]*\s(on[a-z]+|style)\s*=", re.I)
EXTERNAL = re.compile(r"""(?:src|href|url\(|import\s*\(?|@import)\s*=?\s*["']?\s*(?:https?:)?//(?!www\.w3\.org)""", re.I)


def scan(text: str, suffix: str) -> list[str]:
    hits = [m.group(0) for m in SINKS.finditer(text)]
    if suffix in (".js", ".mjs"):
        hits += [m.group(0) for m in JS_HANDLER.finditer(text)]
    if suffix in (".html", ".svg"):
        hits += [m.group(0) for m in HTML_HANDLER.finditer(text)]
        hits += re.findall(r"<style\b", text, re.I)
        hits += [m for m in re.findall(r"<script\b([^>]*)>", text, re.I) if "src=" not in m]
    hits += [m.group(0) for m in EXTERNAL.finditer(text)]
    return hits


BAD_SAMPLES = [
    ("el.innerHTML = x", ".js"), ("a.outerHTML", ".js"), ("el.insertAdjacentHTML('x')", ".js"),
    ("document.write(1)", ".js"), ("eval(s)", ".js"), ("new Function('x')", ".js"),
    ("img.onerror = f", ".js"), ("n.setAttribute('onclick','x')", ".js"),
    ('<img onerror="x">', ".html"), ('<p style="color:red">', ".html"),
    ("<script>1</script>", ".html"), ("<style>a{}</style>", ".html"),
    ('<script src="https://cdn.example/x.js"></script>', ".html"),
    ("@import url(//x.example/a.css)", ".css"),
]


def test_scanner_detects_each_forbidden_pattern():
    for bad, suf in BAD_SAMPLES:
        assert scan(bad, suf), bad
    assert not scan("el.textContent = x; el.addEventListener('click', f)", ".js")


def test_static_tree_is_free_of_injection_sinks_and_inline_code():
    checked = 0
    for p in sorted(STATIC.rglob("*")):
        if p.is_file() and p.suffix in (".js", ".mjs", ".html", ".css", ".svg"):
            checked += 1
            hits = scan(p.read_text(encoding="utf-8"), p.suffix)
            assert not hits, f"{p.relative_to(STATIC)}: {hits}"
    assert checked > 20

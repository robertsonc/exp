"""The vendored copy of shared/ui must be identical to the source (scripts/sync-ui.sh refreshes it)."""
from __future__ import annotations

import filecmp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "shared" / "ui"
DST = ROOT / "dashboard" / "exp_dashboard" / "static" / "vendor" / "ui"


def _files(base: Path) -> set[str]:
    return {str(p.relative_to(base)) for p in base.rglob("*") if p.is_file()}


def test_vendored_ui_matches_shared_ui():
    want = {f for f in _files(SRC) if f != "README.md"}
    assert _files(DST) == want, "run dashboard/scripts/sync-ui.sh: file lists differ"
    drift = [f for f in sorted(want) if not filecmp.cmp(SRC / f, DST / f, shallow=False)]
    assert not drift, f"vendored copy drifted from shared/ui (run dashboard/scripts/sync-ui.sh): {drift}"


def test_every_vendored_icon_has_a_css_rule():
    css = (DST.parent.parent / "css" / "app.css").read_text()
    missing = [p.stem for p in (DST / "icons").glob("*.svg") if f".ico-{p.stem} " not in css]
    assert not missing, f"icons without a mask rule in css/app.css: {missing}"

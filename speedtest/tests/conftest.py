"""pytest bootstrap for the speedtest suite: import paths, the opt-in ``bench`` marker, shared fixtures."""
from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for p in (str(HERE), str(ROOT / "speedtest"), str(ROOT / "shared" / "python"), str(ROOT / "test" / "fakes")):
    if p not in sys.path:
        sys.path.insert(0, p)

from stbox import Box  # noqa: E402


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "bench: throughput benchmark (opt-in: pytest speedtest -m bench)")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """``bench`` tests only run when explicitly selected with ``-m bench``."""
    if "bench" in (config.getoption("-m") or ""):
        return
    skip = pytest.mark.skip(reason="benchmark: run with -m bench")
    for item in items:
        if "bench" in item.keywords:
            item.add_marker(skip)


@pytest.fixture()
def box(tmp_path: Path) -> Iterator[Box]:
    b = Box(tmp_path)
    b.start()
    yield b
    b.stop()

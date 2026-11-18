from __future__ import annotations

import logging
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from colhelpers import Env, FakeVM  # noqa: E402

from exp_collector.app import CollectorApp  # noqa: E402


@pytest.fixture()
def vm() -> Iterator[FakeVM]:
    v = FakeVM()
    yield v
    v.stop()


@pytest.fixture()
def env(tmp_path: Path, vm: FakeVM) -> Iterator[Env]:
    e = Env(tmp_path, vm.url)
    yield e
    e.stop_all()


@pytest.fixture()
def app(env: Env) -> CollectorApp:
    return env.start()


@pytest.fixture()
def port(app: CollectorApp) -> int:
    return app.address[1]


@pytest.fixture()
def log_capture() -> Iterator[Callable[[], str]]:
    """Capture everything logged (any level) as text. Installs the scrubbing handler's counterpart:
    a plain capture handler, so leaks are visible BEFORE the production scrub filter."""
    buf: list[str] = []

    class H(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            buf.append(self.format(record))

    h = H(level=logging.DEBUG)
    h.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    old = root.level
    root.addHandler(h)
    root.setLevel(logging.DEBUG)
    yield lambda: "\n".join(buf)
    root.removeHandler(h)
    root.setLevel(old)

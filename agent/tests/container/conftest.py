"""Fixtures for the systemd-container acceptance tests. Opt in with EXP_CONTAINER_TESTS=1 (the Makefile does)."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import harness
import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    here = str(Path(__file__).resolve().parent)
    off = os.environ.get("EXP_CONTAINER_TESTS") != "1"
    for item in items:
        if not str(item.path).startswith(here):
            continue
        item.add_marker(pytest.mark.harness)
        if off:
            item.add_marker(
                pytest.mark.skip(
                    reason="systemd-container tests are opt-in: set EXP_CONTAINER_TESTS=1 (make -C agent container-test)"
                )
            )


def ubuntu_versions() -> list[str]:
    """OS keys for the `host` matrix: Ubuntu versions ("24.04") or "debian12" (64-bit Raspberry Pi OS userland)."""
    keys = os.environ.get("EXP_CONTAINER_UBUNTU", "24.04,22.04,debian12")
    return [v.strip() for v in keys.split(",") if v.strip()]


def os_id(key: str) -> str:
    return key if key.startswith("debian") else f"ubuntu{key}"


@pytest.fixture(scope="session")
def docker_ok() -> None:
    reason = harness.docker_unavailable_reason()
    if reason:
        pytest.skip(reason)


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory, docker_ok: None) -> Iterator[harness.World]:
    w = harness.World(tmp_path_factory.mktemp("world"))
    w.serve_install_sh()
    try:
        yield w
    finally:
        w.stop()


def start_systemd_host(ubuntu: str, ca_pem: str | None) -> harness.Container:
    reason = harness.ensure_image(ubuntu)
    if reason:
        pytest.skip(reason)
    try:
        return harness.Container(ubuntu, systemd=True, ca_pem=ca_pem)
    except harness.SystemdUnavailable as exc:
        harness.sh(["docker", "rm", "-f", *_stale()], timeout=60)
        pytest.skip(str(exc))
    except RuntimeError as exc:
        pytest.skip(str(exc))
    raise AssertionError("unreachable")


def _stale() -> list[str]:
    r = harness.sh(["docker", "ps", "-aq", "--filter", f"name=exp-agent-test-{os.getpid()}-"], timeout=30)
    return r.stdout.split() or ["none"]


@pytest.fixture(scope="module", params=ubuntu_versions(), ids=os_id)
def host(request: pytest.FixtureRequest, world: harness.World) -> Iterator[harness.Container]:
    c = start_systemd_host(request.param, world.ca_pem)
    try:
        yield c
    finally:
        c.remove()


@pytest.fixture(scope="module")
def host24(world: harness.World) -> Iterator[harness.Container]:
    c = start_systemd_host("24.04", world.ca_pem)
    try:
        yield c
    finally:
        c.remove()

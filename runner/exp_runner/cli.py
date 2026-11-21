"""exp-runner command line: run, health, version, selftest.

``--config PATH`` (default /etc/exp/runner/config.json). An invalid config is refused with the reasons (exit 78).
stdout is program output; diagnostics go through ``logging`` (stderr)."""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import signal
import sqlite3
import sys
import tempfile
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from exp_common import config as exp_config
from exp_common import log as exp_log

from . import __version__
from . import health as health_mod
from .config import DEFAULT_CONFIG_PATH, CredStore, Paths, RunnerConfigError, load_config

log = logging.getLogger("exp-runner")
EX_CONFIG = 78


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="runner config (default %(default)s)")
    p.add_argument("--state-dir", help="state directory (default $STATE_DIRECTORY or /var/lib/exp/runner)")
    p.add_argument("--run-dir", help="runtime directory (default $RUNTIME_DIRECTORY or /run/exp/runner)")
    p.add_argument("--creds-dir", help="credentials directory (default $CREDENTIALS_DIRECTORY)")
    p.add_argument("--syslog-db", help="syslog ring database (default <state>/syslog.db)")
    p.add_argument("--log-level", default=os.environ.get("EXP_LOG_LEVEL", "INFO"))


def _paths(a: argparse.Namespace) -> Paths:
    return Paths.resolve(a.state_dir, a.run_dir, a.creds_dir, a.syslog_db)


def _load_or_exit(a: argparse.Namespace):
    try:
        return load_config(a.config)
    except (exp_config.ConfigError, exp_config.SchemaError, RunnerConfigError) as exc:
        print(f"exp-runner: refusing to start: {exc}", file=sys.stderr)
        raise SystemExit(EX_CONFIG) from exc


def cmd_run(a: argparse.Namespace) -> int:
    try:
        exp_log.setup_logging("exp-runner", a.log_level)
    except ValueError as exc:
        print(f"exp-runner: {exc}", file=sys.stderr)
        return 2
    cfg = _load_or_exit(a)
    from .app import RunnerApp
    paths = _paths(a)
    app = RunnerApp(cfg, paths, CredStore(paths.creds_dir))
    stop = threading.Event()
    try:
        app.start()
    except (OSError, sqlite3.Error, ValueError) as exc:
        log.error("cannot start: %s", exc)
        print(f"exp-runner: cannot start: {exc}", file=sys.stderr)
        return 1
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda _s, _f: stop.set())
    log.info("exp-runner %s started (runner %s, site %s)", __version__, cfg.runner_id, cfg.site)
    try:
        while not stop.wait(0.5):
            pass
    finally:
        log.info("shutting down")
        app.stop()
    return 0


def cmd_health(a: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.WARNING)
    paths = _paths(a)
    try:
        load_config(a.config)
    except (exp_config.ConfigError, exp_config.SchemaError, RunnerConfigError) as exc:
        doc: dict[str, Any] = health_mod.health_doc("fail", f"invalid config: {exc}", 0)
    else:
        doc = health_mod.read_health(paths.health_file)
    if a.json:
        print(json.dumps(doc, separators=(",", ":")))
    else:
        print(f"{doc['status']}: {doc['detail'] or 'all good'}")
        for k, v in doc["metrics"].items():
            print(f"  {k}: {v}")
    return 1 if doc["status"] == "fail" else 0


def cmd_version(_a: argparse.Namespace) -> int:
    print(f"exp-runner {__version__}")
    return 0


def cmd_selftest(a: argparse.Namespace) -> int:
    """Checks that this host can run the runner. Exits 1 if any check fails."""
    logging.basicConfig(level=logging.WARNING)
    failures = 0

    def report(name: str, ok: bool, note: str = "") -> None:
        nonlocal failures
        failures += 0 if ok else 1
        print(f"{'ok  ' if ok else 'FAIL'} {name}{': ' + note if note else ''}")

    report("python >= 3.10", sys.version_info >= (3, 10), sys.version.split()[0])
    cfg = None
    try:
        cfg = load_config(a.config)
        report("config", True, f"{a.config} is valid")
    except (exp_config.ConfigError, exp_config.SchemaError, RunnerConfigError, OSError) as exc:
        report("config", False, str(exc)[:300])
    paths = _paths(a)
    if cfg is not None:
        creds = CredStore(paths.creds_dir)
        missing = creds.missing_for(cfg)
        report("credentials", not missing, "all present" if not missing else "missing: " + ", ".join(missing))
        privileged = [p for _, p in cfg.syslog.listen if p < 1024]
        report("syslog ports unprivileged", not privileged, ",".join(f"{p}/{n}" for p, n in cfg.syslog.listen))
    try:
        from .ring import Ring
        from .syslog_parse import parse_line
        with tempfile.TemporaryDirectory(prefix="exp-runner-selftest-") as td:
            ring = Ring(Path(td) / "t.db").open()
            try:
                ring.insert_many([(parse_line("action=deny src=10.0.0.1 dst=10.0.0.2 dport=22", 1.0), "10.0.0.9", 1.0)])
                ok = ring.count() == 1 and len(ring.query("10.0.0.1", 0, 10)) == 1
            finally:
                ring.close()
        report("syslog ring (sqlite)", ok)
    except Exception as exc:  # noqa: BLE001
        report("syslog ring (sqlite)", False, f"{type(exc).__name__}: {exc}"[:300])
    free = 0
    try:
        existing = paths.state_dir
        while not existing.exists() and existing != existing.parent:
            existing = existing.parent
        free = shutil.disk_usage(existing).free
    except OSError:
        pass
    report("disk space", free > 256 * 1024 * 1024, f"{free / 2**30:.1f} GiB free")
    report("openssl (self-signed syslog TLS)", shutil.which("openssl") is not None)
    return 1 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="exp-runner", description="exp runner: speedtest correlation + syslog receiver")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("run", cmd_run), ("health", cmd_health), ("version", cmd_version), ("selftest", cmd_selftest)):
        sp = sub.add_parser(name)
        if name != "version":
            _common(sp)
        if name == "health":
            sp.add_argument("--json", action="store_true", help="exp.health/1 document on stdout")
        sp.set_defaults(fn=fn)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.fn(args))


_ = time  # noqa: F841 - kept for tests that monkeypatch cli.time

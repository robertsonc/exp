"""exp-dashboard command line: run, health, version, selftest, hash-password."""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
from pathlib import Path
from typing import Any

from exp_common import config as _cfg
from exp_common import log as _log

from . import __version__, health
from .auth import hash_password, parse_hash, verify_password
from .config import DEFAULT_CONFIG, Settings, load_settings

log = logging.getLogger("exp-dashboard")


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", default=DEFAULT_CONFIG, help="config file (default %(default)s)")
    p.add_argument("--state-dir", help="state directory (default $STATE_DIRECTORY or /var/lib/exp/dashboard)")
    p.add_argument("--creds-dir", help="credentials directory (default $CREDENTIALS_DIRECTORY)")
    p.add_argument("--run-dir", help="runtime directory (default $RUNTIME_DIRECTORY or /run/exp/dashboard)")
    p.add_argument("--tls-cert", help="dev/tests: certificate PEM overriding the tls.mode location")
    p.add_argument("--tls-key", help="dev/tests: private key PEM overriding the tls.mode location")


def _settings(a: argparse.Namespace) -> Settings:
    return load_settings(a.config, state_dir=a.state_dir, creds_dir=a.creds_dir, run_dir=a.run_dir,
                         tls_cert=a.tls_cert, tls_key=a.tls_key)


def _load_or_exit(a: argparse.Namespace) -> Settings:
    try:
        return _settings(a)
    except (_cfg.ConfigError, _cfg.SchemaError) as exc:
        print(f"exp-dashboard: refusing to start: {exc}", file=sys.stderr)
        raise SystemExit(_cfg.EX_CONFIG) from exc


def cmd_run(a: argparse.Namespace) -> int:
    from .server import DashboardApp
    _log.setup_logging("exp-dashboard", a.log_level, json=a.log_json)
    settings = _load_or_exit(a)
    try:
        app = DashboardApp(settings)
        app.start()
    except (RuntimeError, OSError) as exc:
        print(f"exp-dashboard: cannot start: {exc}", file=sys.stderr)
        return 1

    def _stop(signum: int, _frame: Any) -> None:
        log.info("signal %d: shutting down", signum)
        app.stopping.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    app.wait()
    app.stop()
    return 0


def cmd_health(a: argparse.Namespace) -> int:
    _log.setup_logging("exp-dashboard", "WARNING")
    settings = _load_or_exit(a)
    doc = health.query(settings.run_dir)
    if doc is None:
        doc = health.offline(settings, "service is not running (no answer on the health socket)")
    if a.json:
        print(json.dumps(doc, separators=(",", ":")))
    else:
        print(f"{doc['status']}: {doc.get('detail') or 'ok'}")
    # CR-wp1-health-exit: ok and degraded exit 0 (still serving); only fail exits 1.
    return 0 if doc.get("status") in ("ok", "degraded") else 1


def cmd_version(_a: argparse.Namespace) -> int:
    print(__version__)
    return 0


def cmd_hash_password(a: argparse.Namespace) -> int:
    pw = sys.stdin.readline().rstrip("\r\n")
    if not pw:
        print("exp-dashboard: no password on stdin", file=sys.stderr)
        return 2
    print(hash_password(pw, a.iterations))
    return 0


def need(cond: bool, why: str) -> None:
    if not cond:
        raise RuntimeError(why)


def cmd_selftest(a: argparse.Namespace) -> int:
    results: list[tuple[str, bool, str]] = []

    def check(name: str, fn) -> None:
        try:
            fn()
            results.append((name, True, ""))
        except Exception as exc:   # noqa: BLE001 - a selftest reports every failure
            results.append((name, False, f"{type(exc).__name__}: {exc}"[:200]))

    def python_ok() -> None:
        need(sys.version_info >= (3, 10), "Python 3.10+ required")

    def pbkdf2_ok() -> None:
        h = hash_password("selftest", 100_000)
        need(parse_hash(h) is not None and verify_password("selftest", h) and not verify_password("x", h),
             "pbkdf2 round trip failed")

    def sqlite_ok() -> None:
        import tempfile

        from .sessions import SessionStore
        with tempfile.TemporaryDirectory() as td:
            st = SessionStore(Path(td) / "s.db")
            sid, s = st.create(kind="local", subject="u", username="u", role="viewer", binding="b", ttl_s=60)
            need(st.get(sid) is not None, "session round trip failed")
            st.close()

    def static_ok() -> None:
        from .server import STATIC_DIR
        need((STATIC_DIR / "index.html").is_file(), "static/index.html missing")
        need((STATIC_DIR / "login.html").is_file(), "static/login.html missing")

    def tls_ok() -> None:
        import ssl
        need(ssl.HAS_TLSv1_2 and hasattr(ssl, "TLSVersion"), "TLS 1.2 unsupported")

    def config_ok() -> None:
        s = _settings(a)
        need(s.collectors is not None, "no collectors list")

    def state_ok() -> None:
        s = _settings(a)
        if s.state_dir.exists():
            probe = s.state_dir / ".selftest"
            probe.write_text("x")
            probe.unlink()

    def cert_ok() -> None:
        s = _settings(a)
        fp = health.tls_fingerprint(s)
        need(bool(fp), f"no usable TLS certificate at {s.tls_cert}")

    for name, fn in (("python", python_ok), ("pbkdf2", pbkdf2_ok), ("sqlite", sqlite_ok),
                     ("static", static_ok), ("tls-support", tls_ok), ("config", config_ok),
                     ("state-dir-writable", state_ok), ("tls-certificate", cert_ok)):
        check(name, fn)
    ok = all(r[1] for r in results)
    for name, good, why in results:
        print(f"{'ok  ' if good else 'FAIL'} {name}{': ' + why if why else ''}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="exp-dashboard", description="exp dashboard")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the service")
    _common(r)
    r.add_argument("--log-level", default="INFO")
    r.add_argument("--log-json", action="store_true")
    r.set_defaults(fn=cmd_run)
    h = sub.add_parser("health", help="print exp.health/1 (exit 0 for ok/degraded, 1 for fail)")
    _common(h)
    h.add_argument("--json", action="store_true")
    h.set_defaults(fn=cmd_health)
    v = sub.add_parser("version", help="print the version")
    v.add_argument("--config", help=argparse.SUPPRESS)
    v.set_defaults(fn=cmd_version)
    s = sub.add_parser("selftest", help="check the installation")
    _common(s)
    s.set_defaults(fn=cmd_selftest)
    hp = sub.add_parser("hash-password", help="read a password on stdin, print a pbkdf2_sha256 hash")
    hp.add_argument("--iterations", type=int, default=600_000)
    hp.set_defaults(fn=cmd_hash_password)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    return int(a.fn(a) or 0)


if __name__ == "__main__":
    sys.exit(main())

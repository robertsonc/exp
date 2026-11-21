"""exp-speedtest command line.

  run | health [--json] | version | pause-internet --on|--off | selftest

Every subcommand accepts ``--config PATH`` (default /etc/exp/speedtest/config.json) and, for stand-alone use, ``--creds-dir``,
``--state-dir``, ``--run-dir`` and ``--assets-dir``. ``run`` refuses to start on an invalid config, printing why (exit 78).
Diagnostics go to stderr via logging; stdout is program output.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import Any

from exp_common import log as exp_log
from exp_common.config import EX_CONFIG, ConfigError

from . import __version__, health
from .config import DEFAULT_CONFIG_PATH, load_speedtest_config, make_paths

log = logging.getLogger("exp-speedtest")


def _common(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--config", default=os.environ.get("EXP_SPEEDTEST_CONFIG", DEFAULT_CONFIG_PATH),
                    help="config file (default %(default)s)")
    sp.add_argument("--creds-dir", default=None, help="credentials directory (default $CREDENTIALS_DIRECTORY)")
    sp.add_argument("--state-dir", default=None, help="state directory (default $STATE_DIRECTORY or /var/lib/exp/speedtest)")
    sp.add_argument("--run-dir", default=None, help="runtime directory (default $RUNTIME_DIRECTORY or /run/exp/speedtest)")
    sp.add_argument("--assets-dir", default=None, help="branding assets directory (default /etc/exp/speedtest/assets)")
    sp.add_argument("--log-level", default="INFO", help=argparse.SUPPRESS)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="exp-speedtest", description="exp on-network speedtest box")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name: str, help_: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_)
        _common(sp)
        return sp

    add("run", "run the speedtest server (page, API, on-network leg, DNS-leg authority, path timer)")
    h = add("health", "print component health (exit 0 = healthy)")
    h.add_argument("--json", action="store_true", help="print exp.health/1")
    add("version", "print the version")
    p = add("pause-internet", "pause or resume the internet leg at runtime (the admin switch)")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--on", action="store_true", help="pause the internet leg")
    g.add_argument("--off", action="store_true", help="resume the internet leg")
    add("selftest", "offline self checks")
    ap.add_argument("--version", action="version", version=f"exp-speedtest {__version__}")
    return ap


def main(argv: list[str] | None = None, entry: str | None = None) -> int:
    args = build_parser().parse_args(argv)
    exp_log.setup_logging("exp-speedtest", args.log_level.upper() if args.cmd != "health" else "WARNING")
    try:
        return _dispatch(args)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        return 130


def _paths(args: argparse.Namespace) -> Any:
    return make_paths(args.state_dir, args.run_dir, args.assets_dir, args.creds_dir)


def _dispatch(args: argparse.Namespace) -> int:
    cmd = args.cmd
    if cmd == "version":
        print(f"exp-speedtest {__version__}")
        return 0
    if cmd == "selftest":
        return selftest()
    paths = _paths(args)
    if cmd == "health":
        cfg, err = health.load_for_health(args.config)
        doc = health.collect(cfg, err, paths)
        print(health.render(doc) if args.json else f"{doc['status']}: {doc['detail'] or 'all good'}")
        return health.exit_code(doc)
    if cmd == "pause-internet":
        from .slots import RuntimeState
        try:
            RuntimeState.write(paths.runtime_json, bool(args.on))
        except OSError as exc:
            print(f"exp-speedtest: cannot write {paths.runtime_json}: {exc.strerror}", file=sys.stderr)
            return 1
        print("internet leg paused" if args.on else "internet leg resumed")
        return 0
    try:
        cfg = load_speedtest_config(args.config)
    except (ConfigError, OSError, ValueError) as exc:
        print(f"exp-speedtest: refusing to start: {exc}", file=sys.stderr)
        raise SystemExit(EX_CONFIG) from exc
    if cmd == "run":
        from .daemon import Daemon
        d = Daemon(cfg, paths)
        d.install_signals()
        return d.run()
    raise AssertionError(cmd)  # pragma: no cover


# ------------------------------------------------------------------------------------------------ selftest
def _ensure(cond: bool, what: str) -> None:
    if not cond:
        raise RuntimeError(f"check failed: {what}")


def selftest() -> int:
    """Offline checks of the box's own logic; missing optional mechanisms are reported, not failed."""
    results: list[tuple[str, bool, str]] = []

    def check(name: str, fn: Any) -> None:
        try:
            fn()
            results.append((name, True, ""))
        except Exception as exc:
            results.append((name, False, f"{type(exc).__name__}: {exc}"))

    def c_tokens() -> None:
        from .tokens import LegTokens
        t = LegTokens()
        tok, nonce = t.mint("st_01M7R3X9G0QWCYM3A3S1DE8MT4", "10.0.0.1", 2_000_000_000)
        _ensure(t.verify(tok, "st_01M7R3X9G0QWCYM3A3S1DE8MT4", "10.0.0.1"), "token verifies")
        _ensure(not t.verify(tok, "st_01M7R3X9G0QWCYM3A3S1DE8MT4", "10.0.0.2"), "token is bound to the address")
        _ensure(len(nonce) == 12 and len(tok) == 48, "token shape")

    def c_score() -> None:
        from exp_common import speedtest as st
        s = st.compute_score({"local": {"down_mbps": 100, "up_mbps": 50, "loaded_down_ms": 20, "cv": 0.0}})
        _ensure(s is not None and s["total"] == 100, "score")

    def c_dns() -> None:
        import dns.message
        import dns.rcode

        from .dnsleg import DnsLegServer
        srv = DnsLegServer("t.speed.selftest.example", "127.0.0.1", 0)
        q = dns.message.make_query("0123456789abcdef.t.speed.selftest.example", "A")
        r = dns.message.from_wire(srv.process(q.to_wire(), "127.0.0.1") or b"")
        _ensure(r.rcode() == dns.rcode.NOERROR and r.answer, "in-zone answer")
        q = dns.message.make_query("example.com", "A")
        r = dns.message.from_wire(srv.process(q.to_wire(), "127.0.0.1") or b"")
        _ensure(r.rcode() == dns.rcode.REFUSED, "out-of-zone refused")

    def c_payload() -> None:
        import os as _os

        from .static import Payload
        p = Payload(None, size=65536)
        try:
            _ensure(_os.path.getsize(p.path) == 65536, "payload size")
        finally:
            _os.unlink(p.path)

    check("leg tokens", c_tokens)
    check("score", c_score)
    check("dns-leg authority", c_dns)
    check("download payload", c_payload)
    ok = True
    for name, passed, why in results:
        print(f"{'PASS' if passed else 'FAIL'} {name}{': ' + why if why else ''}")
        ok &= passed
    from .path import IcmpPinger
    print(f"icmp backend: {IcmpPinger().backend}")
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

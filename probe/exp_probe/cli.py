"""exp-probe command line (02-probe.md section 9).

  run | health [--json] | version | selftest | preflight | test <test> --port <id> [--once]
  spool stat | netns up|down | lease <port> | udhcpc-hook <event> | target set|clear|serve

Every subcommand accepts ``--config PATH`` (default /etc/exp/probe/config.json) and refuses to run on an
invalid config, printing why (exit 78). Diagnostics go to stderr via logging; stdout is program output.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from exp_common import log as exp_log
from exp_common.config import EX_CONFIG, ConfigError

from . import __version__, health, lease, netns, preflight, spool
from .config import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_ETC_NETNS,
    DEFAULT_RUN_DIR,
    DEFAULT_STATE_DIR,
    Paths,
    ProbeConfig,
    load_probe_config,
)
from .runner import CommandRunner

log = logging.getLogger("exp-probe")
M4_MESSAGE = "target ports arrive in M4: this build has no target server (role: target ports are not served yet)"
EX_UNAVAILABLE = 69


def _common(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--config", default=os.environ.get("EXP_PROBE_CONFIG", DEFAULT_CONFIG_PATH),
                    help="config file (default %(default)s)")
    sp.add_argument("--state-dir", default=os.environ.get("EXP_PROBE_STATE_DIR", DEFAULT_STATE_DIR),
                    help=argparse.SUPPRESS)
    sp.add_argument("--run-dir", default=os.environ.get("EXP_PROBE_RUN_DIR", DEFAULT_RUN_DIR),
                    help=argparse.SUPPRESS)
    sp.add_argument("--etc-netns", default=os.environ.get("EXP_PROBE_ETC_NETNS", DEFAULT_ETC_NETNS),
                    help=argparse.SUPPRESS)
    sp.add_argument("--log-level", default="INFO", help=argparse.SUPPRESS)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="exp-probe", description="exp synthetic-user probe")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name: str, help_: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_)
        _common(sp)
        return sp

    add("run", "run the probe daemon (scheduler, spool, shipper)")
    h = add("health", "print component health (exit 0 = healthy)")
    h.add_argument("--json", action="store_true", help="print exp.health/1")
    add("version", "print the version")
    add("selftest", "offline self checks")
    p = add("preflight", "check whether the configured ports may be taken over (read-only)")
    p.add_argument("--json", action="store_true")
    t = add("test", "run one test once and print its measurements (not spooled)")
    t.add_argument("test")
    t.add_argument("--port", required=True)
    t.add_argument("--once", action="store_true", help="accepted for clarity; a test always runs once here")
    t.add_argument("--path", choices=["test", "control", "both"], default=None,
                   help="trace only: the sweep from the test port, the management path, or both (default: "
                        "both when heartbeat.trace.control_path is on)")
    sp_ = add("spool", "spool tools")
    sp_.add_argument("action", choices=["stat"])
    sp_.add_argument("--json", action="store_true")
    n = add("netns", "create/remove the port namespaces")
    n.add_argument("action", choices=["up", "down"])
    n.add_argument("--wait-s", type=float, default=30.0, help="up: wait this long for ports to appear")
    le = add("lease", "hold the DHCP lease of a client port (execs busybox udhcpc)")
    le.add_argument("port")
    hk = add("udhcpc-hook", "udhcpc event handler (internal)")
    hk.add_argument("event")
    tg = add("target", "target-port fault controls (M4)")
    tg.add_argument("action", choices=["set", "clear", "serve"])
    tg.add_argument("port", nargs="?")
    tg.add_argument("--http-delay-ms", type=int)
    tg.add_argument("--http-status", type=int)
    tg.add_argument("--netem")
    tg.add_argument("--for", dest="duration")
    ap.add_argument("--version", action="version", version=f"exp-probe {__version__}")
    return ap


def _paths(args: argparse.Namespace) -> Paths:
    return Paths(state_dir=Path(args.state_dir), run_dir=Path(args.run_dir), etc_netns=Path(args.etc_netns))


def _load(args: argparse.Namespace) -> ProbeConfig:
    try:
        return load_probe_config(args.config)
    except (ConfigError, OSError) as exc:
        print(f"exp-probe: refusing to start: {exc}", file=sys.stderr)
        raise SystemExit(EX_CONFIG) from exc


def main(argv: list[str] | None = None, runner: Any = None, entry: str | None = None) -> int:
    args = build_parser().parse_args(argv)
    exp_log.setup_logging("exp-probe", args.log_level.upper() if args.cmd != "health" else "WARNING")
    runner = runner or CommandRunner()
    entry = entry or os.environ.get("EXP_PROBE_BIN") or os.path.realpath(sys.argv[0])
    try:
        return _dispatch(args, runner, entry)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        return 130


def _dispatch(args: argparse.Namespace, runner: Any, entry: str) -> int:
    cmd = args.cmd
    if cmd == "version":
        print(f"exp-probe {__version__}")
        return 0
    if cmd == "health":
        return _health(args, runner)
    if cmd == "selftest":
        return selftest()
    cfg = _load(args)
    paths = _paths(args)
    if cmd == "run":
        from .checks import register_all
        from .daemon import Daemon
        register_all()
        d = Daemon(cfg, runner, paths)
        d.install_signals()
        return d.run()
    if cmd == "preflight":
        return _preflight(cfg, runner, paths, args.json)
    if cmd == "netns":
        return _netns(cfg, runner, paths, args)
    if cmd == "lease":
        return lease.run_lease(cfg, args.port, runner, paths, args.config, entry)
    if cmd == "udhcpc-hook":
        return lease.hook(cfg, args.event, os.environ, runner, paths)
    if cmd == "spool":
        return _spool_stat(paths, args.json)
    if cmd == "test":
        return _test(cfg, runner, paths, args)
    if cmd == "target":
        print(f"exp-probe: {M4_MESSAGE}", file=sys.stderr)
        return EX_UNAVAILABLE
    raise AssertionError(cmd)  # pragma: no cover


# ----------------------------------------------------------------------------------- commands

def _health(args: argparse.Namespace, runner: Any) -> int:
    cfg, err = health.load_for_health(args.config)
    doc = health.collect(cfg, err, runner, _paths(args))
    if args.json:
        print(health.render(doc))
    else:
        print(f"{doc['status']}: {doc['detail'] or 'all good'}")
    return health.exit_code(doc)


def _preflight(cfg: ProbeConfig, runner: Any, paths: Paths, as_json: bool) -> int:
    res = preflight.check(cfg, runner, paths)
    if as_json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        for c in res.checks:
            print(f"{c.verdict:12s} {c.port_id} ({c.iface})")
    for line in res.reasons_text():
        print(line, file=sys.stderr)
    return res.exit_code()


def _netns(cfg: ProbeConfig, runner: Any, paths: Paths, args: argparse.Namespace) -> int:
    if args.action == "up":
        try:
            for line in netns.up(cfg, runner, paths, wait_s=args.wait_s):
                print(line, flush=True)
        except netns.PreflightRefused as exc:
            for line in exc.result.reasons_text():
                print(line, file=sys.stderr)
            print("exp-probe: preflight refused; nothing was changed", file=sys.stderr)
            return exc.result.exit_code()
        except OSError as exc:
            print(f"exp-probe: netns up failed: {exc}", file=sys.stderr)
            return 1
        return 0
    try:
        for line in netns.down(cfg, runner, paths):
            print(line, flush=True)
    except netns.TeardownIncomplete as exc:
        print(f"exp-probe: {exc}", file=sys.stderr)
        return 1
    return 0


def _spool_stat(paths: Paths, as_json: bool) -> int:
    st = spool.read_stat(paths.spool_db)
    if st is None:
        print(f"exp-probe: no spool at {paths.spool_db}", file=sys.stderr)
        return 1
    if as_json:
        print(json.dumps(st))
    else:
        print(f"depth={st['depth']} bytes={st['bytes']} oldest_ts={st['oldest_ts']} "
              f"dropped_total={st['dropped_total']}")
    return 0


def _test(cfg: ProbeConfig, runner: Any, paths: Paths, args: argparse.Namespace) -> int:
    import time

    from .checks import register_all
    from .scheduler import REGISTRY, TestContext
    register_all()
    spec = REGISTRY.get(args.test)
    if spec is None:
        print(f"exp-probe: test {args.test!r} is not available in this build "
              f"(available: {', '.join(sorted(REGISTRY)) or 'none'})", file=sys.stderr)
        return 2
    try:
        port = cfg.port(args.port)
    except ConfigError as exc:
        print(f"exp-probe: {exc}", file=sys.stderr)
        return 2
    if port.role not in spec.roles:
        print(f"exp-probe: test {args.test} does not run on a {port.role} port", file=sys.stderr)
        return 2
    paths_to_run = [""]
    if args.test == "trace":
        want = args.path or ("both" if cfg.control_path else "test")
        if want == "control" and not cfg.control_path:
            print("exp-probe: the control path is disabled (heartbeat.trace.control_path or allow_shared)",
                  file=sys.stderr)
            return 2
        paths_to_run = {"test": ["test"], "control": ["control"], "both": ["test", "control"]}[want]
    rc = 0
    for path in paths_to_run:
        ctx = TestContext(cfg, paths, runner, time.time, port, path, time.time(), explicit=True)
        try:
            out = spec.fn(ctx) or []
        except Exception as exc:        # a test bug is an `error` record, not a traceback
            log.exception("test %s crashed", args.test)
            print(f"exp-probe: test {args.test} crashed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        for m in ([out] if hasattr(out, "to_dict") else out):
            print(json.dumps(m.validate().to_dict(), sort_keys=True))
    return rc


def _ensure(cond: bool, what: str) -> None:
    if not cond:
        raise RuntimeError(f"check failed: {what}")


def selftest() -> int:
    """Offline checks of the probe's own logic; missing external tools are reported, not failed."""
    from exp_common.schema import Measurement  # noqa: F401  (import check)

    from .selftel import build_measurement
    from .shipper import build_batch
    results: list[tuple[str, bool, str]] = []

    def check(name: str, fn: Any) -> None:
        try:
            fn()
            results.append((name, True, ""))
        except Exception as exc:
            results.append((name, False, f"{type(exc).__name__}: {exc}"))

    def c_measure() -> None:
        cfg = ProbeConfig({"probe_id": "selftest", "site": "lab", "mode": "netns", "mgmt_iface": "mgmt0",
                           "collector": None, "ports": [{"id": "c01", "iface": "t0", "role": "client"}]})
        m = build_measurement(cfg, "gateway", "ok", metrics={"rtt_ms": 1.0}, labels={"port": "c01"})
        Measurement.from_dict(json.loads(json.dumps(m.to_dict())), require_id=True)

    def c_spool() -> None:
        d = tempfile.mkdtemp(prefix="exp-selftest-")
        try:
            from exp_common.ids import new_ulid
            from exp_common.schema import utcnow
            s = spool.Spool(Path(d) / "spool.db", 1, 1)
            ids = [new_ulid() for _ in range(3)]
            for i in ids:
                _ensure(s.add({"id": i, "ts": utcnow(), "x": 1}), "spool add")
            _ensure([r[0] for r in s.fetch(10)] == ids, "spool order")
            batch, body = build_batch(s.fetch(10))
            _ensure(len(batch) == 3 and body[:2] == b"\x1f\x8b", "batch gzip")
            s.delete(ids)
            _ensure(s.stat()["depth"] == 0, "spool delete")
            s.close()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def c_wire() -> None:
        from . import dhcpwire
        from .checks.app import apdex, parse_curl
        from .icmp import build_echo, checksum
        mac = bytes.fromhex("02aabbccdd01")
        d = dhcpwire.build_discover(mac, 7, hostname="selftest", vendor="exp-probe")
        _ensure(dhcpwire._decode_opts(d[240:])[53] == bytes([dhcpwire.MSG_DISCOVER]), "heartbeat builds DISCOVER only")
        _ensure(checksum(build_echo(1, 2)) == 0, "icmp checksum")
        r = parse_curl('{"exitcode":0,"response_code":204,"time_total":0.01,"size_download":0}', "", 0)
        _ensure(r.ok and r.status == 204 and apdex(r.total_ms, 500) == 1.0, "curl json")

    check("measurement round-trip", c_measure)
    check("dhcp discover / icmp / curl parsers", c_wire)
    check("spool order/delete + batch gzip", c_spool)
    ok = True
    for name, passed, why in results:
        print(f"{'PASS' if passed else 'FAIL'} {name}{': ' + why if why else ''}")
        ok &= passed
    for tool in ("ip", "busybox", "curl", "openssl"):
        print(f"{'found  ' if shutil.which(tool) else 'missing'} {tool} (external tool)")
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""exp-agent command line: run | status | reconcile --once | facts | enrol | uninstall | version | selftest
| health [--json] | rollback-check."""

from __future__ import annotations

import argparse
import io
import json
import logging
import os
import signal
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

from exp_common import config as exp_config
from exp_common.log import setup_logging

from . import __version__, decommission, selfupdate
from .client import ManagerClient
from .config import AgentConfig, AgentConfigError, load_agent_config, normalise_manager_url, save_agent_config
from .context import Context, build_context
from .errors import AgentError, ClientError, Refused, Transient, need
from .facts import collect_facts
from .loop import Agent
from .pathguard import Paths
from .reconcile import Reconciler

log = logging.getLogger("exp-agent")
EX_CONFIG = 78
DEFAULT_CONFIG = "/etc/exp/agent.json"


def _parser() -> argparse.ArgumentParser:
    def common() -> argparse.ArgumentParser:  # fresh actions each time: defaults must not be shared
        c = argparse.ArgumentParser(add_help=False)  # accepted before AND after the subcommand
        c.add_argument("--config", default=argparse.SUPPRESS, help=f"agent config (default {DEFAULT_CONFIG})")
        c.add_argument("--root", default=argparse.SUPPRESS, help=argparse.SUPPRESS)  # tests only: path prefix
        c.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS)
        return c

    ap = argparse.ArgumentParser(
        prog="exp-agent", description="exp host agent (declarative, bounded)", parents=[common()]
    )
    ap.set_defaults(config=DEFAULT_CONFIG, root="/", verbose=False)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", parents=[common()], help="poll the manager and converge the host")
    p = sub.add_parser("health", parents=[common()], help="print exp.health/1 for the agent")
    p.add_argument("--json", action="store_true")
    sub.add_parser("status", parents=[common()], help="local summary (versions, components, last error)")
    p = sub.add_parser("reconcile", parents=[common()], help="one reconcile pass")
    p.add_argument("--once", action="store_true", required=True)
    sub.add_parser("facts", parents=[common()], help="print host facts as JSON")
    p = sub.add_parser("enrol", parents=[common()], help="enrol this host with a one-time token")
    # the one-time token is a secret: never a positional argument (it would sit in /proc/<pid>/cmdline, SR-14)
    p.add_argument(
        "--token-file",
        metavar="PATH",
        help="read the token from PATH ('-' = stdin); default: $EXP_ENROL_TOKEN, else stdin",
    )
    p.add_argument("--manager", help="manager URL (https://host)")
    p = sub.add_parser("uninstall", parents=[common()], help="remove everything exp installed")
    p.add_argument("--local", action="store_true", help="do not contact the manager")
    sub.add_parser("version", parents=[common()])
    sub.add_parser("selftest", parents=[common()])
    sub.add_parser("rollback-check", parents=[common()], help="(timer) roll back an unconfirmed agent update")
    return ap


def _ctx(args: argparse.Namespace, need_cfg: bool = True) -> Context:
    test_root = os.path.abspath(args.root) != "/"
    ctx = build_context(args.root, uid=os.geteuid() if test_root else 0, gid=os.getegid() if test_root else 0)
    if need_cfg:
        cfg = load_agent_config(
            ctx.paths,
            args.config if not test_root or args.config != DEFAULT_CONFIG else None,
            allow_http=test_root,
        )
        ctx.attach_manager(cfg, ManagerClient(cfg.manager_url, cfg.agent_secret, allow_http=test_root))
    return ctx


def _fail_config(exc: Exception) -> int:
    print(f"exp-agent: refusing to start: {exc}", file=sys.stderr)
    return EX_CONFIG


# --------------------------------------------------------------------------- commands
def cmd_run(args: argparse.Namespace) -> int:
    try:
        ctx = _ctx(args)
    except (AgentConfigError, exp_config.ConfigError) as exc:
        return _fail_config(exc)
    agent = Agent(ctx)

    def _stop(_sig: int, _frm: Any) -> None:
        agent.stop.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    log.info("exp-agent %s starting (manager %s)", __version__, ctx.cfg.manager_url if ctx.cfg else "?")
    return agent.run()


def cmd_reconcile(args: argparse.Namespace) -> int:
    try:
        ctx = _ctx(args)
    except (AgentConfigError, exp_config.ConfigError) as exc:
        return _fail_config(exc)
    ctx.state.ensure_dir()
    ctx.state.load()
    client = need(ctx.client, "manager client")
    try:
        _code, doc, etag = client.get_desired(None)
    except AgentError as exc:
        print(f"exp-agent: cannot fetch desired state: {exc}", file=sys.stderr)
        return 1
    doc = need(doc, "desired state")
    ctx.state.cache_desired(doc)
    out = Reconciler(ctx).run(doc)
    if out.result == "ok":
        ctx.state.data["etag"] = etag
    ctx.state.save()
    print(f"reconcile: {out.result}" + (f": {out.error}" if out.error else ""))
    return 0 if out.result == "ok" else 1


def cmd_status(args: argparse.Namespace) -> int:
    ctx = _ctx(args, need_cfg=False)
    ctx.state.load()
    d = ctx.state.data
    print(f"agent {__version__}")
    print(f"desired version: {d.get('desired_version')}  applied version: {d.get('applied_version')}")
    print(f"last poll: {d.get('last_poll')}")
    lr = d.get("last_reconcile")
    if lr:
        print(
            f"last reconcile: {lr['result']} at {lr['at']}"
            + (f" -- {lr['error']}" if lr.get("error") else "")
        )
    for c, rec in sorted(d["components"].items()):
        print(f"component {c} {rec['version']} units: {', '.join(rec.get('units', [])) or '-'}")
    for ver, f in sorted(d["failed"].items()):
        print(f"desired version {ver} not retried ({f['result']}): {f['error']}")
    pend = selfupdate.read_pending(ctx)
    if pend:
        print(f"agent update pending confirmation: {pend['from']} -> {pend['to']}")
    return 0


def cmd_facts(args: argparse.Namespace) -> int:
    ctx = _ctx(args, need_cfg=False)
    ctx.state.load()
    print(json.dumps(collect_facts(ctx), indent=2, sort_keys=True))
    return 0


def _read_enrol_token(args: argparse.Namespace) -> str:
    """Token from --token-file, $EXP_ENROL_TOKEN or stdin; never from argv."""
    path = getattr(args, "token_file", None)
    if path and path != "-":
        with open(path, encoding="utf-8") as fh:
            raw = fh.read(4096)
    elif path == "-" or not os.environ.get("EXP_ENROL_TOKEN"):
        raw = sys.stdin.read(4096)
    else:
        raw = os.environ["EXP_ENROL_TOKEN"]
    return raw.strip()


def cmd_enrol(args: argparse.Namespace) -> int:
    test_root = os.path.abspath(args.root) != "/"
    ctx = _ctx(args, need_cfg=False)
    try:
        token = _read_enrol_token(args)
    except OSError as exc:
        print(f"exp-agent: cannot read the enrolment token: {exc.strerror or exc}", file=sys.stderr)
        return 2
    if not token:
        print("exp-agent: no enrolment token given (stdin, --token-file, $EXP_ENROL_TOKEN)", file=sys.stderr)
        return 2
    url = args.manager
    if not url:
        try:
            url = load_agent_config(
                ctx.paths, None if test_root else args.config, allow_http=test_root
            ).manager_url
        except AgentConfigError:
            print("exp-agent: --manager URL is required on a host that is not enrolled yet", file=sys.stderr)
            return 2
    try:
        url = normalise_manager_url(url, allow_http=test_root)
        client = ManagerClient(url, None, allow_http=test_root)
        doc = client.enrol(token, collect_facts(ctx))
    except (AgentError, AgentConfigError, exp_config.ConfigError) as exc:
        print(f"exp-agent: enrolment failed: {exc}", file=sys.stderr)
        return 1
    cfg = AgentConfig(url, doc["agent_id"], doc["agent_secret"], doc["release_pubkey_pem"])
    save_agent_config(ctx.fs, cfg)
    ctx.state.ensure_dir()
    ctx.state.load()
    ctx.state.data["etag"] = None
    ctx.state.save()
    print(f"enrolled as {cfg.agent_id}; components will be installed by the agent")
    if not test_root and ctx.fs.exists(ctx.paths.unit("exp-agent.service")):
        # a running agent holds the old secret in memory: make it pick up the new identity
        try:
            ctx.sysctl.restart_no_block("exp-agent.service")
            print("restarting exp-agent.service to use the new credentials")
        except AgentError as exc:
            print(f"note: could not restart exp-agent.service ({exc}); restart it manually", file=sys.stderr)
    return 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    local = args.local
    try:
        ctx = _ctx(args, need_cfg=not local)
    except (AgentConfigError, exp_config.ConfigError):
        ctx = _ctx(args, need_cfg=False)  # a broken config must not block a local uninstall
        local = True
    if (
        sys.stdin.isatty()
        and not input("Remove ALL exp components, data and the agent? type 'uninstall': ") == "uninstall"
    ):
        print("aborted")
        return 1
    ctx.state.ensure_dir()
    ctx.state.load()
    call = not local
    try:
        decommission.local_cleanup(ctx, dict(ctx.state.data["components"]))
        if call and ctx.client is not None:
            try:
                ctx.client.decommissioned()
            except (ClientError, Transient) as exc:
                print(f"note: manager was not told ({exc}); remove the host there", file=sys.stderr)
        decommission.remove_agent(ctx)
    except AgentError as exc:
        print(f"exp-agent: uninstall failed: {exc}", file=sys.stderr)
        return 1
    print("uninstalled")
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    started = time.monotonic()
    ctx = _ctx(args, need_cfg=False)
    ctx.state.load()
    detail, status = "", "ok"
    try:
        load_agent_config(
            ctx.paths,
            None if os.path.abspath(args.root) != "/" else args.config,
            allow_http=os.path.abspath(args.root) != "/",
        )
    except AgentConfigError as exc:
        status, detail = "fail", f"agent config: {exc.summary}"[:500]
    d = ctx.state.data
    lp = d.get("last_poll")
    age = None
    if lp:
        try:
            age = max(
                0.0, time.time() - time.mktime(time.strptime(lp[:19], "%Y-%m-%dT%H:%M:%S")) + time.timezone
            )
        except ValueError:
            age = None
    if status == "ok" and (age is None or age > 900):
        status, detail = "degraded", "no successful poll in the last 15 minutes"
    lr = d.get("last_reconcile") or {}
    doc = {
        "schema": "exp.health/1",
        "status": status,
        "detail": detail,
        "version": __version__,
        "uptime_s": round(time.monotonic() - started, 3),
        "metrics": {
            "last_poll_age_s": age,
            "desired_version": d.get("desired_version"),
            "applied_version": d.get("applied_version"),
            "components": len(d["components"]),
            "last_reconcile": lr.get("result"),
        },
        "facts": {},
    }
    if args.json:
        print(json.dumps(doc, sort_keys=True))
    else:
        print(f"{status}: {detail}" if detail else status)
    return 0 if status == "ok" else 1


def cmd_rollback_check(args: argparse.Namespace) -> int:
    ctx = _ctx(args, need_cfg=False)
    ctx.state.load()
    try:
        print(selfupdate.rollback_check(ctx))
    except AgentError as exc:
        print(f"exp-agent: rollback failed: {exc}", file=sys.stderr)
        return 1
    return 0


def _expect(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def cmd_selftest(args: argparse.Namespace) -> int:
    ctx = build_context(args.root if args.root != "/" else "/", uid=0)
    results: list[tuple[str, bool, str]] = []

    def check(name: str, fn: Any) -> None:
        try:
            msg = fn() or ""
            results.append((name, True, msg))
        except (AgentError, OSError, ValueError, AssertionError, exp_config.ConfigError) as exc:
            results.append((name, False, str(exc)[:200]))

    def python_ok() -> str:
        _expect(sys.version_info >= (3, 10), "python 3.10+ required")
        return sys.version.split()[0]

    def openssl_roundtrip() -> str:
        run = ctx.runner.run
        with tempfile.TemporaryDirectory(prefix="exp-selftest-") as td:
            t = Path(td)
            for argv in (
                ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(t / "k.pem")],
                ["openssl", "pkey", "-in", str(t / "k.pem"), "-pubout", "-out", str(t / "p.pem")],
            ):
                r = run(argv, timeout=30)
                _expect(r.rc == 0, f"openssl failed: {r.stderr.strip()[-100:]}")
            (t / "m").write_bytes(b"selftest")
            r = run(
                [
                    "openssl",
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    str(t / "k.pem"),
                    "-in",
                    str(t / "m"),
                    "-out",
                    str(t / "s"),
                ],
                timeout=30,
            )
            _expect(r.rc == 0, "openssl cannot make Ed25519 signatures")
            r = run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(t / "p.pem"),
                    "-rawin",
                    "-in",
                    str(t / "m"),
                    "-sigfile",
                    str(t / "s"),
                ],
                timeout=30,
            )
            _expect(r.rc == 0, "openssl cannot verify Ed25519 signatures (-rawin needs OpenSSL 3)")
            (t / "m").write_bytes(b"tampered")
            r = run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(t / "p.pem"),
                    "-rawin",
                    "-in",
                    str(t / "m"),
                    "-sigfile",
                    str(t / "s"),
                ],
                timeout=30,
            )
            _expect(r.rc != 0, "a tampered message verified")
        return "ed25519 sign/verify ok"

    def schemas() -> str:
        exp_config.validate(
            {
                "schema": "exp.health/1",
                "status": "ok",
                "detail": "",
                "version": "0.1.0",
                "uptime_s": 1,
                "metrics": {},
                "facts": {},
            },
            "health.schema.json",
        )
        return "schemas load"

    def guard() -> str:
        p = Paths("/")
        for bad in (
            "/etc/passwd",
            "/opt/exp/../etc/shadow",
            "relative/x",
            "/etc/systemd/system/evil.service",
        ):
            try:
                p.guard(bad)
            except Refused:
                continue
            raise AssertionError(f"path guard allowed {bad}")
        return "path guard ok"

    def unpack() -> str:
        from .artifacts import safe_unpack
        from .errors import UnsafeArchive

        with tempfile.TemporaryDirectory(prefix="exp-selftest-") as td:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                ti = tarfile.TarInfo("exp-x-1.0.0/../../evil")
                ti.size = 1
                tf.addfile(ti, io.BytesIO(b"x"))
            (Path(td) / "a.tgz").write_bytes(buf.getvalue())
            (Path(td) / "d").mkdir()
            try:
                safe_unpack(Path(td) / "a.tgz", Path(td) / "d", "exp-")
            except UnsafeArchive:
                return "tar-slip refused"
            raise AssertionError("tar-slip archive was unpacked")

    def tools() -> str:
        missing = [
            t
            for t in ("systemctl", "ip")
            if not any(os.access(os.path.join(d, t), os.X_OK) for d in os.environ.get("PATH", "").split(":"))
        ]
        if missing:
            raise AssertionError("missing tools: " + ", ".join(missing))
        return "systemctl, ip present"

    check("python", python_ok)
    check("openssl ed25519", openssl_roundtrip)
    check("schemas", schemas)
    check("path guard", guard)
    check("safe unpack", unpack)
    check("tools", tools)
    ok = True
    for name, passed, msg in results:
        print(f"{'ok  ' if passed else 'FAIL'} {name}" + (f": {msg}" if msg else ""))
        ok &= passed
    return 0 if ok else 1


COMMANDS = {
    "run": cmd_run,
    "status": cmd_status,
    "reconcile": cmd_reconcile,
    "facts": cmd_facts,
    "enrol": cmd_enrol,
    "uninstall": cmd_uninstall,
    "health": cmd_health,
    "selftest": cmd_selftest,
    "rollback-check": cmd_rollback_check,
}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.cmd == "version":
        print(__version__)
        return 0
    setup_logging("exp-agent", "DEBUG" if args.verbose else "INFO")
    try:
        return COMMANDS[args.cmd](args)
    except (AgentConfigError, exp_config.ConfigError) as exc:
        return _fail_config(exc)
    except AgentError as exc:
        print(f"exp-agent: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

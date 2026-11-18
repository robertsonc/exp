"""exp-collector command line: run, health, version, selftest, prune, vm-args, vm-exec,
iperf3-exec, reflector, rules eval, replay.

Every subcommand that needs configuration accepts ``--config PATH`` (default
/etc/exp/collector/config.json) and refuses to continue on an invalid one, saying why.
stdout is program output; diagnostics go through ``logging`` (stderr).
"""
from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import shutil
import signal
import sqlite3
import ssl
import sys
import tempfile
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from exp_common import config as exp_config
from exp_common import creds as exp_creds
from exp_common import log as exp_log
from exp_common import schema as exp_schema

from . import __version__
from .config import (
    DEFAULT_CONFIG_PATH,
    CollectorConfig,
    CollectorConfigError,
    CredStore,
    Paths,
    check_listen_address,
    load_config,
)

log = logging.getLogger("exp-collector")

EX_CONFIG = 78
IPERF3_CANDIDATES = ("/usr/bin/iperf3", "/usr/local/bin/iperf3")


# ------------------------------------------------------------------------------------------ helpers

def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="collector config (default %(default)s)")
    p.add_argument("--state-dir", help="state directory (default $STATE_DIRECTORY or /var/lib/exp/collector)")
    p.add_argument("--run-dir", help="runtime directory (default $RUNTIME_DIRECTORY or /run/exp/collector)")
    p.add_argument("--creds-dir", help="credentials directory (default $CREDENTIALS_DIRECTORY)")
    p.add_argument("--tls-key", help="TLS key (default <state>/tls/key.pem; dev/tests only)")
    p.add_argument("--tls-cert", help="TLS certificate (default <state>/tls/cert.pem; dev/tests only)")
    p.add_argument("--log-level", default=os.environ.get("EXP_LOG_LEVEL", "INFO"))


def _paths(args: argparse.Namespace) -> Paths:
    return Paths.resolve(args.state_dir, args.run_dir, args.creds_dir, args.tls_key, args.tls_cert)


def _load_or_exit(args: argparse.Namespace) -> CollectorConfig:
    try:
        return load_config(args.config)
    except (exp_config.ConfigError, exp_config.SchemaError, CollectorConfigError) as exc:
        print(f"exp-collector: refusing to start: {exc}", file=sys.stderr)
        raise SystemExit(EX_CONFIG) from exc


def _setup_logging(args: argparse.Namespace) -> None:
    try:
        exp_log.setup_logging("exp-collector", getattr(args, "log_level", "INFO"))
    except ValueError as exc:
        print(f"exp-collector: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


# --------------------------------------------------------------------------------------------- run

def cmd_run(args: argparse.Namespace) -> int:
    _setup_logging(args)
    cfg = _load_or_exit(args)
    paths = _paths(args)
    from .app import CollectorApp
    stop = threading.Event()
    try:
        app = CollectorApp(cfg, paths)
        app.start()
    except (OSError, ssl.SSLError, exp_creds.CredentialError, CollectorConfigError, sqlite3.Error) as exc:
        log.error("cannot start: %s", exc)
        print(f"exp-collector: cannot start: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - includes StoreError
        log.error("cannot start: %s", exc)
        print(f"exp-collector: cannot start: {exc}", file=sys.stderr)
        return 1
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda _s, _f: stop.set())
    reload_creds = threading.Event()
    signal.signal(signal.SIGHUP, lambda _s, _f: reload_creds.set())     # re-read credentials now
    try:
        while not stop.wait(0.5):
            if reload_creds.is_set():
                reload_creds.clear()
                log.info("SIGHUP: reloading credentials")
                app.creds.reload_if_changed(force=True)
    finally:
        log.info("shutting down")
        app.stop()
    return 0


# ------------------------------------------------------------------------------------------ health

def cmd_health(args: argparse.Namespace) -> int:
    from .health import build_health
    logging.basicConfig(level=logging.WARNING)
    try:
        cfg = load_config(args.config)
    except (exp_config.ConfigError, exp_config.SchemaError, CollectorConfigError) as exc:
        doc: dict[str, Any] = {"schema": "exp.health/1", "status": "fail",
                               "detail": f"invalid config: {exc}"[:1000], "version": __version__,
                               "uptime_s": 0, "metrics": {}, "facts": {}}
    else:
        doc = build_health(cfg, _paths(args))
    if args.json:
        print(json.dumps(doc, separators=(",", ":")))
    else:
        print(f"{doc['status']}: {doc['detail'] or 'all good'}")
        for k, v in doc["metrics"].items():
            print(f"  {k}: {v}")
        for k, v in doc["facts"].items():
            print(f"  {k}: {v}")
    return 0 if doc["status"] == "ok" else 1


def cmd_version(args: argparse.Namespace) -> int:
    print(f"exp-collector {__version__}")
    return 0


# ---------------------------------------------------------------------------------------- selftest

def cmd_selftest(args: argparse.Namespace) -> int:
    """Checks that this host can run the collector. Exits 1 if any check fails."""
    logging.basicConfig(level=logging.WARNING)
    failures = 0

    def report(name: str, ok: bool, note: str = "") -> None:
        nonlocal failures
        failures += 0 if ok else 1
        print(f"{'ok  ' if ok else 'FAIL'} {name}{': ' + note if note else ''}")

    report("python >= 3.10", sys.version_info >= (3, 10), sys.version.split()[0])
    cfg: CollectorConfig | None = None
    try:
        cfg = load_config(args.config)
        report("config", True, f"{args.config} is valid ({len(cfg.probes)} probes)")
    except (exp_config.ConfigError, exp_config.SchemaError, CollectorConfigError, OSError) as exc:
        report("config", False, str(exc)[:300])
    paths = _paths(args)
    if cfg is not None:
        try:
            check_listen_address(cfg.listen_host)
            report("listen address", True, cfg.listen)
        except CollectorConfigError as exc:
            report("listen address", False, str(exc))
    try:
        from .server import build_ssl_context
        build_ssl_context(paths.tls_cert, paths.tls_key)
        report("tls key/cert", True, str(paths.tls_cert))
    except (OSError, ssl.SSLError) as exc:
        report("tls key/cert", False, str(exc)[:300])
    try:
        store = CredStore(paths.creds_dir)
        store.load()
        report("credentials", True, f"{len(store.ingest)} ingest, {len(store.dashboard)} dashboard identities")
    except exp_creds.CredentialError as exc:
        report("credentials", False, str(exc)[:300])
    # exercise the storage + ingest path in a scratch database (never touches the real one)
    try:
        from .store import RecordRow, Store
        with tempfile.TemporaryDirectory(prefix="exp-selftest-") as td:
            st = Store(Path(td) / "t.db").open()
            try:
                m = exp_schema.measure("p", "ping", "ok", site="s", metrics={"rtt_ms": 1.0})
                row = RecordRow(m.probe, m.id, exp_schema.iso_to_ms(m.ts), m.site, m.test, m.outcome,
                                json.dumps(m.to_dict()))
                first, second = st.insert_records([row])[0], st.insert_records([row])[0]
                ok = first is True and second is False and st.schema_version() >= 1 and bool(m.series())
            finally:
                st.close()
        report("sqlite store + dedupe", ok)
    except Exception as exc:  # noqa: BLE001
        report("sqlite store + dedupe", False, f"{type(exc).__name__}: {exc}"[:300])
    free = 0
    with contextlib.suppress(OSError):
        existing = paths.state_dir
        while not existing.exists() and existing != existing.parent:
            existing = existing.parent
        free = shutil.disk_usage(existing).free
    report("disk space", free > 512 * 1024 * 1024, f"{free / 2**30:.1f} GiB free")
    vm_bin = _vm_binary(args.vm_binary)
    report("victoria-metrics binary", vm_bin.is_file() and os.access(vm_bin, os.X_OK), str(vm_bin))
    return 1 if failures else 0


# ---------------------------------------------------------------------------------------- prune

def cmd_prune(args: argparse.Namespace) -> int:
    from .prune import prune_once
    from .store import Store
    logging.basicConfig(level=logging.INFO)
    if not args.now:
        print("exp-collector prune: pass --now to prune immediately (the daemon prunes hourly)", file=sys.stderr)
        return 2
    cfg = _load_or_exit(args)
    paths = _paths(args)
    if not paths.db_path.exists():
        print(f"exp-collector prune: no database at {paths.db_path}", file=sys.stderr)
        return 1
    store = Store(paths.db_path).open()
    try:
        res = prune_once(store, cfg.records_days)
    finally:
        store.close()
    print(json.dumps(res))
    return 0


# ------------------------------------------------------------------------- VictoriaMetrics launch

def vm_args(cfg: CollectorConfig, state_dir: Path) -> list[str]:
    """VictoriaMetrics argv (without the binary), computed from the validated config. Values are
    integers/addresses already checked by the config schema -- no unit-file interpolation, no shell."""
    return [
        f"-httpListenAddr={cfg.vm_host}:{cfg.vm_port}",
        f"-retentionPeriod={cfg.metrics_days}d",
        f"-storageDataPath={state_dir / 'vm'}",
        f"-memory.allowedPercent={cfg.vm_memory_allowed_pct}",
        "-search.maxQueryDuration=10s",
        "-search.maxSeries=500",
    ]


def _vm_binary(override: str | None) -> Path:
    if override:
        return Path(override)
    # tarball: <root>/lib/exp_collector/cli.py -> <root>/vendor/victoria-metrics
    return Path(__file__).resolve().parents[2] / "vendor" / "victoria-metrics"


def cmd_vm_args(args: argparse.Namespace) -> int:
    cfg = _load_or_exit(args)
    for a in vm_args(cfg, _paths(args).state_dir):
        print(a)
    return 0


def cmd_vm_exec(args: argparse.Namespace) -> int:
    cfg = _load_or_exit(args)
    binary = _vm_binary(args.binary)
    if not (binary.is_file() and os.access(binary, os.X_OK)):
        print(f"exp-collector vm-exec: {binary} is not an executable file", file=sys.stderr)
        return 1
    argv = [str(binary), *vm_args(cfg, _paths(args).state_dir)]
    os.execv(str(binary), argv)  # noqa: S606 - argv list, validated config values, no shell


def cmd_iperf3_exec(args: argparse.Namespace) -> int:
    cfg = _load_or_exit(args)
    if not cfg.iperf3_enabled:
        print("iperf3 disabled in config")
        return 0
    check_listen_address(cfg.listen_host)
    binary = next((c for c in IPERF3_CANDIDATES if os.access(c, os.X_OK)), None)
    if binary is None:
        print("exp-collector iperf3-exec: iperf3 is not installed", file=sys.stderr)
        return 1
    os.execv(binary, [binary, "-s", "-p", str(cfg.iperf3_port), "-B", cfg.listen_host])  # noqa: S606


def cmd_reflector(args: argparse.Namespace) -> int:
    """M4-ready stub: the real reflector (02-probe.md section 7) is built in M4."""
    cfg = _load_or_exit(args)
    if not cfg.reflector_enabled:
        print("reflector disabled")
        return 0
    print("reflector enabled in config but not implemented in this build (M4); exiting")
    return 0



# ------------------------------------------------------------------------------- rules eval / replay

def _parse_at(text: str) -> int:
    import time as _time

    from .replay import ReplayError, parse_ts
    if text == "now":
        return int(_time.time() * 1000)
    try:
        return parse_ts(text)
    except ReplayError as exc:
        print(f"exp-collector: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def cmd_rules_eval(args: argparse.Namespace) -> int:
    """Print the State of one probe at a moment, evaluated purely from the records in SQLite."""
    from .engine import evaluate_from_store, state_doc
    from .store import Store
    logging.basicConfig(level=logging.WARNING)
    cfg = _load_or_exit(args)
    paths = _paths(args)
    entry = cfg.probes.get(args.probe)
    if entry is None:
        print(f"exp-collector: probe {args.probe[:64]!r} is not in the config", file=sys.stderr)
        return 2
    if not paths.db_path.exists():
        print(f"exp-collector: no database at {paths.db_path}", file=sys.stderr)
        return 1
    at = _parse_at(args.at)
    alerts = dict(cfg.alerts)
    voice = args.voice or alerts.get("voice", "sysadmin")
    store = Store(paths.db_path).open()
    try:
        ev = evaluate_from_store(store, args.probe, entry.site, at)
    finally:
        store.close()
    doc = state_doc(ev, voice=voice, tz=alerts.get("timezone", "UTC"), edge_label=cfg.edge_label, lines=cfg.lines)
    print(json.dumps(doc, indent=2, ensure_ascii=False))
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    """Run the rules (and with --alerts the incident engine) over an NDJSON recording."""
    from .incidents import IncidentConfig
    from .replay import ReplayError, load_ndjson, render_message, render_payload, replay
    logging.basicConfig(level=logging.WARNING)
    try:
        recs = load_ndjson(args.file)
    except ReplayError as exc:
        print(f"exp-collector: {exc}", file=sys.stderr)
        return 1
    if not recs:
        print("exp-collector: no measurements in the file", file=sys.stderr)
        return 1
    first = min(recs, key=lambda r: r.ts)
    probe = args.probe or first.probe or "replay"
    cfg = IncidentConfig(tz=args.tz, voice=args.voice, edge_label=args.edge_label, board_url=args.board_url,
                         hold_down_s=args.hold_down, hold_back_s=args.hold_back, reopen_s=args.reopen,
                         calm_s=args.calm)
    ats = [_parse_at(a) for a in args.at]
    if not ats and not args.alerts:
        ats = [max(r.ts for r in recs)]
    res = replay(recs, probe=probe, site=args.site or first.site or "lab", cfg=cfg, at=ats, alerts=args.alerts,
                 start_ms=_parse_at(args.start) if args.start else None,
                 end_ms=_parse_at(args.end) if args.end else None, voice=args.voice)
    for doc in res.states:
        print(json.dumps(doc, indent=2, ensure_ascii=False))
    for m, t in zip(res.messages, res.message_times, strict=True):
        print(render_message(m, t, args.tz) if args.format == "text" else render_payload(args.format, m))
    if args.alerts:
        print(f"# {len(res.messages)} messages, {len(res.rows)} incident rows from {len(recs)} records "
              f"(first record {first.ts} ms)", file=sys.stderr)
    return 0


# ------------------------------------------------------------------------------------------ main

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="exp-collector", description="exp collector")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("run", help="run the collector daemon")
    _common(p)
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("health", help="print component health (exp.health/1); exit 0 iff healthy")
    _common(p)
    p.add_argument("--json", action="store_true", help="machine-readable exp.health/1")
    p.set_defaults(fn=cmd_health)

    p = sub.add_parser("version", help="print the version")
    p.set_defaults(fn=cmd_version)

    p = sub.add_parser("selftest", help="check this host can run the collector")
    _common(p)
    p.add_argument("--vm-binary", help="VictoriaMetrics binary to check (default <root>/vendor/victoria-metrics)")
    p.set_defaults(fn=cmd_selftest)

    p = sub.add_parser("prune", help="delete expired records and incidents")
    _common(p)
    p.add_argument("--now", action="store_true", help="run immediately")
    p.set_defaults(fn=cmd_prune)

    p = sub.add_parser("vm-args", help="print the VictoriaMetrics arguments derived from the config")
    _common(p)
    p.set_defaults(fn=cmd_vm_args)

    p = sub.add_parser("vm-exec", help="exec VictoriaMetrics with arguments derived from the config")
    _common(p)
    p.add_argument("--binary", help="VictoriaMetrics binary (default <root>/vendor/victoria-metrics)")
    p.set_defaults(fn=cmd_vm_exec)

    p = sub.add_parser("iperf3-exec", help="exec iperf3 -s bound to the collector's management IP")
    _common(p)
    p.set_defaults(fn=cmd_iperf3_exec)

    p = sub.add_parser("reflector", help="path-test reflector (M4); disabled stub")
    _common(p)
    p.set_defaults(fn=cmd_reflector)

    p = sub.add_parser("rules", help="rules engine tools")
    rsub = p.add_subparsers(dest="rules_cmd", required=True)
    e = rsub.add_parser("eval", help="print the State of a probe at a moment (time travel from SQLite)")
    _common(e)
    e.add_argument("--probe", required=True, help="probe id")
    e.add_argument("--at", default="now", help="UTC ISO-8601 timestamp, or 'now' (default)")
    e.add_argument("--voice", choices=("plain", "sysadmin"), help="voice of the text (default: the config's)")
    e.set_defaults(fn=cmd_rules_eval)

    p = sub.add_parser("replay", help="run the rules and incident engine over an NDJSON recording")
    p.add_argument("file", help="measurements, NDJSON (.ndjson or .ndjson.gz)")
    p.add_argument("--at", action="append", default=[], metavar="TS",
                   help="print the State at this UTC moment (repeatable)")
    p.add_argument("--alerts", action="store_true",
                   help="run the incident engine and print the messages it would post")
    p.add_argument("--from", dest="start", metavar="TS",
                   help="first tick of the incident engine (default: first record)")
    p.add_argument("--to", dest="end", metavar="TS", help="last tick of the incident engine (default: last record)")
    p.add_argument("--probe", help="probe id used in links (default: the one in the file)")
    p.add_argument("--site", help="site (default: the one in the file)")
    p.add_argument("--tz", default="UTC", help="site timezone for times in messages")
    p.add_argument("--voice", choices=("plain", "sysadmin"), default="sysadmin")
    p.add_argument("--edge-label", default="EC", help="name of the WAN edge in texts")
    p.add_argument("--board-url", help="https board URL for message links")
    p.add_argument("--format", choices=("text", "slack", "teams", "json"), default="text",
                   help="how messages are printed")
    p.add_argument("--hold-down", type=float, default=20)
    p.add_argument("--hold-back", type=float, default=60)
    p.add_argument("--reopen", type=float, default=300)
    p.add_argument("--calm", type=float, default=600)
    p.set_defaults(fn=cmd_replay)
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

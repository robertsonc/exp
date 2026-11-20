"""The runner daemon: syslog receiver, correlation loop, speedtest channel loops, health snapshot."""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from exp_common import tlspin

from . import health as health_mod
from .baseline import BaselineConnector, SseConnector
from .channel import PausePublisher, SpeedtestChannel, WhereLoop, start_thread
from .collector_client import CollectorClient
from .config import CredStore, Paths, RunnerConfig
from .connectors import Connector, IdentityProvider, SpeedtestRef, SyslogConnector, Window
from .correlator import Correlator, StateStore
from .ec import EcConnector, EcService, WanUtilMonitor
from .evidence import _fmt
from .identity import Identity, IdentityResolver
from .mist import make_mist
from .receiver import SyslogReceiver
from .ring import Ring

log = logging.getLogger(__name__)

CRED_POLL_S = 10.0
PRUNE_S = 60.0
WHERE_POLL_S = 2.0
PAUSE_PUBLISH_DEFAULT_S = 30.0


def default_connectors(cfg: RunnerConfig, creds: CredStore, ring: Ring) -> tuple[list[Connector], IdentityProvider | None]:
    """The connector registry: syslog (security, dns), Mist (identity provider + wifi, wired), EdgeConnect (flows, wan), the probe
    baseline, and the SSE placeholder. Mist and EdgeConnect are registered only when configured *and* their credentials exist."""
    connectors: list[Connector] = [SyslogConnector(cfg)]
    provider: IdentityProvider | None = None
    ints = creds.integrations()
    pair = make_mist(cfg, ints.get("mist"))
    if pair is not None:
        connectors.append(pair[0])
        provider = pair[1]
    if cfg.ec is not None and ints.get("ec"):
        try:
            connectors.append(EcConnector(EcService(cfg.ec, ints["ec"])))
        except ValueError as exc:
            log.error("edgeconnect connector disabled: %s", exc)
    connectors.append(BaselineConnector())          # wired to the correlator's collector client by RunnerApp
    if bool((((cfg.raw.get("correlation") or {}).get("sources") or {}).get("sse") or {}).get("enabled")):
        connectors.append(SseConnector())
        log.warning("sse.enabled is set but %s", SseConnector.reason)
    return connectors, provider


def ensure_syslog_tls(cfg: RunnerConfig, creds: CredStore, paths: Paths) -> tuple[Path, Path] | None:
    if not any(p == "tls" for p, _ in cfg.syslog.listen):
        return None
    if cfg.syslog.tls_mode == "provided":
        files = creds.syslog_tls_files()
        if files is None:
            log.error("syslog tls mode is 'provided' but syslog_tls.crt/.key are missing: TLS listener disabled")
        return files
    cert, key = paths.tls_dir / "cert.pem", paths.tls_dir / "key.pem"
    if not (cert.is_file() and key.is_file()):
        try:
            tlspin.generate_self_signed_cert(paths.tls_dir, cn="exp-runner", days=3650, san=("DNS:exp-runner",))
        except (tlspin.TlsPinError, OSError, ValueError) as exc:
            log.error("cannot create the self-signed syslog certificate: %s: TLS listener disabled", exc)
            return None
    return cert, key


class RunnerApp:
    def __init__(self, cfg: RunnerConfig, paths: Paths, creds: CredStore, *, now_fn: Callable[[], float] = time.time,
                 connector_factory: Callable[[RunnerConfig, CredStore, Ring], tuple[list[Connector], IdentityProvider | None]] = default_connectors,
                 client_factory: Callable[[RunnerConfig, str], CollectorClient] | None = None) -> None:
        self.cfg, self.paths, self.creds, self.now = cfg, paths, creds, now_fn
        self.connector_factory = connector_factory
        self.client_factory = client_factory or (lambda c, tok: CollectorClient(c.collector_url, c.collector_pin, tok))
        self.started = now_fn()
        self.ring: Ring | None = None
        self.state: StateStore | None = None
        self.receiver: SyslogReceiver | None = None
        self.correlator: Correlator | None = None
        self.resolver: IdentityResolver | None = None
        self.channel: SpeedtestChannel | None = None
        self.where_loop: WhereLoop | None = None
        self.pause: PausePublisher | None = None
        self.monitor: health_mod.Monitor | None = None
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._token: str | None = None
        self._missing: list[str] = []
        self.connectors: list[Connector] = []

    # ------------------------------------------------------------------------------------ lifecycle
    def start(self) -> RunnerApp:
        self.paths.run_dir.mkdir(parents=True, exist_ok=True)
        self.monitor = health_mod.Monitor(self.paths.health_file, self.snapshot, self.started, self.now)
        if not self.cfg.correlation_enabled:
            log.info("correlation is disabled in the config: the runner idles (no drills in this build)")
            self.monitor.start()
            return self
        self.ring = Ring(self.paths.syslog_db, self.cfg.syslog.ring_minutes).open()
        self.state = StateStore(self.paths.work_db).open()
        connectors, provider = self.connector_factory(self.cfg, self.creds, self.ring)
        self.resolver = IdentityResolver(self.cfg, self.ring, self.creds.device_key_secret, provider)
        self.connectors = connectors
        for c in connectors:
            if isinstance(c, BaselineConnector):
                c.use_client(lambda: self.correlator.client if self.correlator is not None else None)
        self._missing = self.creds.missing_for(self.cfg)
        if self._missing:
            log.error("missing credentials: %s (running degraded; they are re-read every %ds)", ", ".join(self._missing), int(CRED_POLL_S))
        if self.cfg.syslog.allow and self.cfg.syslog.listen:
            self.receiver = SyslogReceiver(self.cfg.syslog, self.ring, tls_files=ensure_syslog_tls(self.cfg, self.creds, self.paths),
                                           now_fn=self.now).start()
        else:
            log.warning("syslog receiver not started: no source allowlist configured (an empty allowlist receives nothing)")
        self._setup_channel()
        self._threads.append(threading.Thread(target=self._main_loop, name="correlation", daemon=True))
        self._threads.append(start_thread("ring-prune", self._prune, PRUNE_S, self._stop))
        for t in self._threads:
            if not t.is_alive():
                t.start()
        self.monitor.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self.monitor:
            self.monitor.stop()
        for t in self._threads:
            t.join(timeout=3)
        if self.correlator:
            self.correlator.close()
        if self.receiver:
            self.receiver.flush(2.0)
            self.receiver.stop()
        for c in (self.ring, self.state):
            if c:
                c.close()

    # ----------------------------------------------------------------------------------- internals
    def _setup_channel(self) -> None:
        tok = self.creds.channel_token()
        if not (self.cfg.channel_url and tok):
            if self.cfg.channel_url:
                log.warning("speedtest channel configured but speedtest_channel_token is missing: where-cache and auto-pause disabled")
            return
        self.channel = SpeedtestChannel(self.cfg.channel_url, tok)
        self.where_loop = WhereLoop(self.channel, self.resolve_ip, self.now)
        self.pause = PausePublisher(self.channel, self.now)
        self._threads.append(start_thread("where", self.where_loop.poll_once, WHERE_POLL_S, self._stop))
        for c in self.connectors:
            if isinstance(c, EcConnector) and c.svc.wan_util_enabled:
                self.pause.set_source(WanUtilMonitor(c.svc, clock=self.now).value)
        interval = float(((self.cfg.ec or {}).get("wan_util") or {}).get("interval_s", PAUSE_PUBLISH_DEFAULT_S))
        self._threads.append(start_thread("pause", self.pause.publish_once, interval, self._stop))

    def resolve_ip(self, ip: str, now: float) -> Identity:
        """Identity for an IP "now" (the where-cache answers); never touches evidence."""
        if self.resolver is None:
            raise RuntimeError("runner not started")
        w = Window(now - self.cfg.window_before_s, now, _fmt(now - self.cfg.window_before_s), _fmt(now))
        ref = SpeedtestRef(id="", site=self.cfg.site, started=now, ended=now, client_ip=ip, window=w)
        return self.resolver.resolve(ref, w)

    def _ensure_correlator(self) -> None:
        tok = self.creds.collector_token()
        if tok is None:
            return
        if tok == self._token and self.correlator is not None:
            return
        if self.ring is None or self.state is None or self.resolver is None:
            raise RuntimeError("runner not started")
        old = self.correlator
        self._token = tok
        self._missing = self.creds.missing_for(self.cfg)
        self.correlator = Correlator(self.cfg, self.client_factory(self.cfg, tok), self.ring, self.resolver, self.connectors, self.state,
                                     now_fn=self.now)
        if old is not None:
            old.close()

    def _main_loop(self) -> None:
        interval = max(1, self.cfg.poll_interval_s)
        while not self._stop.is_set():
            try:
                self._ensure_correlator()
                if self.correlator is not None:
                    self.correlator.tick(wait=False)
            except Exception:  # noqa: BLE001
                log.exception("correlation loop error")
            self._stop.wait(interval)

    def _prune(self) -> None:
        if self.ring is not None:
            n = self.ring.prune(self.now())
            if n:
                log.debug("syslog ring: pruned %d lines", n)

    # ------------------------------------------------------------------------------------- health
    def snapshot(self) -> dict[str, Any]:
        metrics = health_mod.empty_metrics()
        facts: dict[str, Any] = {"inventory": []}
        reasons: list[str] = []
        if not self.cfg.correlation_enabled:
            return {"status": "ok", "detail": "correlation disabled", "metrics": metrics, "facts": facts}
        if self.correlator is not None:
            metrics.update(self.correlator.metrics())
            pullers = self.correlator.pullers()
            facts["collector_reachable"] = self.correlator.feed_error is None and self.correlator.feed_ok is not None
            if self.correlator.auth_failed:
                reasons.append("collector refused the runner token")
            elif self.correlator.feed_error:
                reasons.append("collector unreachable")
        else:
            pullers = []
            facts["collector_reachable"] = False
            reasons.append("no collector token yet")
        if self.receiver is not None:
            st = self.receiver.stats()
            metrics["syslog_lines_per_s"] = st["lines_per_s"]
            metrics["syslog_dropped_per_min"] = st["dropped_per_min"]
            metrics["syslog_refused_total"] = int(st["refused"])
            facts["syslog_ports"] = dict(self.receiver.ports)
            wanted = {p for p, _ in self.cfg.syslog.listen}
            if wanted - set(self.receiver.ports):
                reasons.append("syslog listener(s) not running: " + ",".join(sorted(wanted - set(self.receiver.ports))))
        if self.ring is not None:
            metrics["syslog_ring_lines"] = self.ring.count()
        metrics["pullers"] = pullers
        if self.channel is not None:
            facts["speedtest_channel"] = "ok" if self.channel.last_ok else "unreachable"
        for c in self.connectors:
            if isinstance(c, SseConnector):
                facts["sse"] = c.status()
        if self._missing:
            reasons.append("missing credentials: " + ", ".join(self._missing))
        return {"status": "degraded" if reasons else "ok", "detail": "; ".join(reasons), "metrics": metrics, "facts": facts}

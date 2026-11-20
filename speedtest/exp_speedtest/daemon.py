"""``exp-speedtest run``: wires the components and runs them until SIGTERM.

Threads: public HTTP(S) server, optional 80 -> 443 redirect (tls.mode = provided), the loopback runner channel, the DNS-leg
authority (UDP + TCP), the path timer, the collector forwarder and a one-second housekeeper (core-guard and throughput
samples, session pruning, channel-token refresh, the status file ``health`` reads). A failing DNS-leg bind degrades the DNS
leg (the page falls back to the probe's DNS figure) instead of killing the box; a failing HTTP bind is fatal.
"""
from __future__ import annotations

import logging
import os
import signal
import ssl
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from exp_common import tlspin
from exp_common.atomic import atomic_write_json

from . import __version__
from .channel import ChannelApp
from .config import Credentials, Paths, SpeedtestConfig
from .core import Core
from .dnsleg import DnsLegServer, NonceBook
from .forward import CollectorClient, Forwarder
from .httpd import HttpServer, Request, Response
from .path import IcmpPinger, PathTimer
from .routes import PublicApp
from .slots import InternetLeg, RuntimeState
from .static import Payload, StaticSite
from .store import Store

log = logging.getLogger(__name__)

STATUS_SCHEMA = "exp.speedtest.status/1"
STATUS_EVERY_S = 2.0
_SAFE_TARGET = r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]{0,2000}$"


class RedirectApp:
    """80 -> 443 (tls.mode = provided only). The Location host is the CONFIGURED hostname, never the Host header."""

    def __init__(self, hostname: str, https_port: int) -> None:
        self.base = f"https://{hostname}" + ("" if https_port == 443 else f":{https_port}")

    def handle(self, req: Request) -> Response:
        import re
        target = req.target if re.match(_SAFE_TARGET, req.target) else "/"
        return Response(301, [("Location", self.base + target), ("Cache-Control", "no-store"),
                              ("X-Content-Type-Options", "nosniff")], b"")


def make_ssl_context(crt: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(crt), str(key))
    return ctx


class Daemon:
    def __init__(self, cfg: SpeedtestConfig, paths: Paths, *, request: Callable[..., Any] = tlspin.request,
                 pinger: Any = None, clock: Callable[[], float] = time.time) -> None:
        self.cfg, self.paths, self.clock = cfg, paths, clock
        self.creds = Credentials(cfg, paths.creds_dir)
        self.stop_event = threading.Event()
        self.notes: list[str] = []
        self.store = Store(paths.db)
        self.client = CollectorClient(cfg.collector, self.creds.collector_token, request)
        self.forwarder = Forwarder(self.client, self.store, clock)
        runtime = RuntimeState(paths.runtime_json, clock)
        lim = cfg.limits
        internet = InternetLeg(enabled=cfg.internet_enabled, config_paused=cfg.internet_paused,
                               max_concurrent=lim.max_concurrent_internet, auto_pause_pct=cfg.auto_pause_wan_util_pct,
                               runtime=runtime, clock=clock)
        self.pinger = pinger if pinger is not None else IcmpPinger()
        self.core = Core(cfg, paths, self.store, forwarder=self.forwarder, client=self.client, internet=internet,
                         nonces=NonceBook(clock), clock=clock)
        self.path = PathTimer(gateway=cfg.path_gateway, edge=cfg.path_edge, edge1=cfg.path_edge1, pinger=self.pinger,
                              loaded=lambda: self.core.transfers_active > 0, clock=clock)
        self.core.path = self.path
        self.payload = Payload(paths.payload)
        self.site = StaticSite(cfg.dns_zone, cfg.tls_mode, paths.assets_dir)
        self.servers: list[HttpServer] = []
        self.public: HttpServer | None = None
        self.channel: HttpServer | None = None
        self.dns: DnsLegServer | None = None
        self.tls_fingerprint: str | None = None
        self._hk: threading.Thread | None = None
        self._channel_checked = 0.0
        self.started = clock()

    # ------------------------------------------------------------------------------------------- lifecycle
    def start(self) -> None:
        cfg = self.cfg
        ctx = None
        if cfg.tls_mode == "provided":
            crt, key = self.creds.tls_files()
            ctx = make_ssl_context(crt, key)
            self.tls_fingerprint = tlspin.fingerprint_of_pem_file(crt)
        self._refresh_channel_token()
        self.public = HttpServer(cfg.listen_ip, cfg.listen_port, PublicApp(self.core, self.site, self.payload),
                                 ssl_context=ctx, name="speedtest-http")
        self.public.start()
        self.servers.append(self.public)
        if cfg.redirect_port is not None:
            red = HttpServer(cfg.listen_ip, cfg.redirect_port, RedirectApp(cfg.hostname, cfg.listen_port),
                             max_connections=64, name="speedtest-redirect")
            try:
                red.start()
                self.servers.append(red)
            except OSError as exc:
                self.notes.append(f"80 -> 443 redirect not bound: {exc.strerror}")
                log.warning("redirect listener not bound: %s", exc)
        self.channel = HttpServer(cfg.channel_host, cfg.channel_port, ChannelApp(self.core), max_connections=16,
                                  max_per_ip=8, name="speedtest-channel")
        try:
            self.channel.start()
            self.servers.append(self.channel)
        except OSError as exc:
            self.channel = None
            self.notes.append(f"runner channel not bound: {exc.strerror}")
            log.error("runner channel not bound: %s", exc)
        if cfg.dns_enabled and cfg.dns_zone:
            self.dns = DnsLegServer(cfg.dns_zone, cfg.listen_ip, cfg.dns_port, book=self.core.nonces, clock=self.clock)
            try:
                self.dns.start()
            except OSError as exc:
                self.dns = None
                self.core.dns_active = False
                self.notes.append(f"dns-leg server not bound ({exc.strerror}); the page falls back to the probe's DNS figure")
                log.error("dns-leg server not bound: %s", exc)
        self.forwarder.start()
        self.path.start()
        self._hk = threading.Thread(target=self._housekeeper, name="housekeeper", daemon=True)
        self._hk.start()
        self.write_status()
        log.info("exp-speedtest %s serving %s (collector %s)", __version__, cfg.public_url(), cfg.collector.url)

    def stop(self) -> None:
        self.stop_event.set()
        for s in self.servers:
            s.stop()
        if self.dns:
            self.dns.stop()
        self.path.stop()
        self.forwarder.stop()
        if self._hk:
            self._hk.join(timeout=3)
        self.store.close()

    def run(self) -> int:
        self.start()
        self.stop_event.wait()
        self.stop()
        return 0

    def install_signals(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: self.stop_event.set())

    # ----------------------------------------------------------------------------------------- housekeeping
    def _refresh_channel_token(self) -> None:
        self.core.channel_sha256 = self.creds.channel_token_sha256()
        self._channel_checked = time.monotonic()

    def _housekeeper(self) -> None:
        last_status = 0.0
        while not self.stop_event.wait(1.0):
            try:
                self.core.guard.sample()
                self.core.meter.sample()
                self.core.housekeeping()
                if time.monotonic() - self._channel_checked > 10:
                    self._refresh_channel_token()
                if time.monotonic() - last_status >= STATUS_EVERY_S:
                    last_status = time.monotonic()
                    self.write_status()
            except Exception:
                log.exception("housekeeper cycle failed")

    def status_doc(self) -> dict[str, Any]:
        core = self.core
        backend = getattr(self.pinger, "backend", "none")
        return {"schema": STATUS_SCHEMA, "ts": self.clock(), "started": self.started, "pid": os.getpid(),
                "version": __version__, "metrics": core.metrics(),
                "listening": {"http": bool(self.public and self.public.port), "port": self.public.port if self.public else 0,
                              "channel": self.channel is not None, "dns": self.dns is not None,
                              "dns_enabled": self.cfg.dns_enabled, "tls_mode": self.cfg.tls_mode},
                "forwarder": self.forwarder.status(),
                "path": {"backend": backend, "hops": self.path.hop_addresses()},
                "guard": {"iface": self.cfg.core_guard.iface, "available": core.guard.available,
                          "utilization_pct": core.guard.utilization_pct, "cap_bytes": core.guard.effective_cap()},
                "tls_fingerprint_sha256": self.tls_fingerprint, "notes": list(self.notes),
                "dns_stats": dict(self.dns.stats) if self.dns else None}

    def write_status(self) -> None:
        try:
            self.paths.run_dir.mkdir(parents=True, exist_ok=True)
            atomic_write_json(self.paths.status_file, self.status_doc(), mode=0o644, indent=None)
        except OSError as exc:
            log.warning("cannot write the status file: %s", exc.strerror)

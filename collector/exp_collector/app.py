"""Wiring: builds and runs every part of the collector (store, VM writer, ingest, HTTP server,
monitor, pruner, self-telemetry). Later steps add the rules engine / incidents / SSE by
registering routes on ``app.router``, subscribing to ``app.ingestor`` and adding health sources
to ``app.monitor.extra_sources``."""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

from .alerts import HttpsTransport, WebhookSender
from .api import build_router
from .config import CollectorConfig, CredStore, Paths, check_listen_address
from .drills import DrillRegistry
from .engine import RulesEngine
from .health import Monitor
from .ingest import Ingestor
from .prune import Pruner
from .server import MAX_CONNECTIONS, ExpHTTPServer, Router, build_ssl_context
from .sse import Hub
from .store import Store
from .vmwriter import SelfTelemetry, VMWriter

log = logging.getLogger(__name__)


class CollectorApp:
    def __init__(self, config: CollectorConfig, paths: Paths, *, creds: CredStore | None = None,
                 vm_url: str | None = None, listen: tuple[str, int] | None = None,
                 max_connections: int = MAX_CONNECTIONS, header_timeout: float = 10.0,
                 monitor_interval_s: float = 5.0, clock: Callable[[], float] = time.time,
                 rules_wake: bool = True) -> None:
        self.config = config
        self.clock = clock
        self.paths = paths
        self._listen = listen or (config.listen_host, config.listen_port)
        check_listen_address(self._listen[0])
        self.creds = creds or CredStore(paths.creds_dir)
        self.store = Store(paths.db_path)
        self.vm = VMWriter(vm_url or config.vm_url, self.store)
        self.ingestor = Ingestor(config, self.store, self.vm, now=clock)
        allow = tuple(str(x) for x in (config.alerts.get("webhook_allow") or ()))
        self.webhooks = WebhookSender(self.creds.webhooks, HttpsTransport(allow=allow))
        self.rules = RulesEngine(config, self.store, clock=clock,
                                 sender=self.webhooks if config.alerts.get("enabled", True) else None,
                                 wake_on_ingest=rules_wake)
        self.ingestor.subscribe(self.rules.observe)
        self.hub = Hub(site_of=config.site_of, clock=clock)
        self.rules.subscribe(self.hub.publish)                # beat / state / incident events -> SSE
        self.drills = DrillRegistry()                         # M5 replaces this
        self.monitor = Monitor(self, interval_s=monitor_interval_s)
        self.pruner = Pruner(self.store, config.records_days)
        self.telemetry = SelfTelemetry(self.vm)
        self.router: Router = build_router(self)
        self.server: ExpHTTPServer | None = None
        self._max_connections = max_connections
        self._header_timeout = header_timeout
        self._serve_thread: threading.Thread | None = None
        self._auth_fail_log: dict[str, float] = {}
        self.auth_failures = 0
        self.started = False
        self.sse_clients: Callable[[], int] = self.hub.client_count
        self.rules_eval_ms: Callable[[], float] = lambda: self.rules.eval_ms
        self.telemetry.add_source(self._telemetry_series)
        self.monitor.extra_sources.append(self._rules_health)

    # --- lifecycle ----------------------------------------------------------------------------
    def start(self) -> None:
        try:
            self.paths.state_dir.mkdir(parents=True, exist_ok=True)
            self.paths.run_dir.mkdir(parents=True, exist_ok=True)
            ctx = build_ssl_context(self.paths.tls_cert, self.paths.tls_key)
            self.creds.load()
            self.store.open()
            self.creds.start()
            self.vm.start()
            self.webhooks.start()
            self.rules.start()
            self.server = ExpHTTPServer(self._listen, self, self.router, ctx,
                                        max_connections=self._max_connections,
                                        header_timeout=self._header_timeout)
            self._serve_thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.2},
                                                  name="http-serve", daemon=True)
            self._serve_thread.start()
            self.monitor.start()
            self.pruner.start()
            self.telemetry.start()
            self.started = True
            log.info("collector %s listening on %s:%d", self.config.collector_id, *self.address)
        except BaseException:
            self.stop()
            raise

    @property
    def address(self) -> tuple[str, int]:
        if self.server is None:
            return self._listen
        host, port = self.server.server_address[:2]
        return str(host), int(port)

    def stop(self, drain_s: float = 5.0) -> None:
        """Graceful shutdown (SIGTERM): stop accepting, let in-flight requests finish, then stop the parts in
        dependency order. Points still queued for VictoriaMetrics go to ``vm_backlog`` (never lost); the
        incident engine's state is checkpointed on every tick, so a restart does not page twice."""
        self.started = False
        self.hub.close()                                  # releases every open SSE connection thread
        if self.server is not None:
            if self._serve_thread is not None and self._serve_thread.is_alive():
                self.server.shutdown()          # blocks forever if serve_forever never started
            self.server.server_close()
            deadline = time.monotonic() + drain_s
            while self.server.active_connections > 0 and time.monotonic() < deadline:
                time.sleep(0.05)                          # in-flight ingest requests finish storing
        for part in (self.telemetry, self.pruner, self.rules, self.monitor, self.webhooks, self.creds):
            try:
                part.stop()
            except Exception:  # noqa: BLE001
                log.exception("error stopping %s", type(part).__name__)
        try:
            self.vm.stop()
        except Exception:  # noqa: BLE001
            log.exception("error stopping the VM writer")
        self.store.close()

    def healthy(self) -> bool:
        return self.started and self.store.alive

    # --- helpers ------------------------------------------------------------------------------
    def note_auth_failure(self, ip: str, scope: str) -> None:
        """Count a failed authentication; log (without any credential) at most once per 30 s per IP."""
        self.auth_failures += 1
        now = time.monotonic()
        if now - self._auth_fail_log.get(ip, -1e9) > 30.0:
            if len(self._auth_fail_log) > 1024:
                self._auth_fail_log.clear()
            self._auth_fail_log[ip] = now
            log.warning("authentication failed (%s route) from %s", scope, ip)

    def _rules_health(self) -> dict[str, float]:
        """Health metrics owned by the rules/incident/webhook parts (01-contracts.md section 8.1)."""
        return {"open_incidents": self.store.count_open_incidents() if self.store.alive else 0,
                "sse_clients": self.sse_clients(),
                "webhook_failures_1h": self.webhooks.failures_last_hour(),
                "rules_eval_ms_p95": self.rules.eval_ms_p95()}

    def _telemetry_series(self) -> list[tuple[str, dict[str, str], float]]:
        st = self.ingestor.stats
        out: list[tuple[str, dict[str, str], float]] = [
            ("exp_collector_ingest_records_total", {"result": k}, float(v)) for k, v in st.totals.items()]
        out.append(("exp_collector_ingest_bytes_total", {}, float(st.bytes_total)))
        out.append(("exp_collector_vm_backlog_points", {}, float(self.vm.backlog_points)))
        out.append(("exp_collector_sse_clients", {}, float(self.sse_clients())))
        out.append(("exp_collector_rules_eval_ms", {}, float(self.rules_eval_ms())))
        for probe, off in list(self.ingestor.clock_offset_ms.items()):
            out.append(("exp_collector_probe_clock_offset_ms", {"probe": probe}, off))
        return out

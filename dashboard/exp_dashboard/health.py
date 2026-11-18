"""exp.health/1 for the dashboard.

The running service answers on a unix socket in its runtime dir (``<run>/health.sock``, mode 0600,
owned by the service user; root -- the agent -- can connect). ``exp-dashboard health --json`` reads
it and, when the service is not running, reports ``fail`` with the facts it can compute offline.
No secrets are ever included.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any

from exp_common import tlspin

from . import __version__
from .config import Settings

log = logging.getLogger(__name__)
SOCK_NAME = "health.sock"
MAX_BYTES = 64 * 1024


def tls_fingerprint(settings: Settings) -> str | None:
    try:
        return tlspin.fingerprint_of_pem_file(settings.tls_cert)
    except (OSError, ValueError, tlspin.TlsPinError):
        return None


def facts(settings: Settings) -> dict[str, Any]:
    return {"tls_fingerprint_sha256": tls_fingerprint(settings), "url": settings.url}


def build(app: Any) -> dict[str, Any]:
    total, reachable = app.fed.reachability()
    polled = [s for s in app.fed.state.values() if s.ok is not None]
    down = sorted(cid for cid, s in app.fed.state.items() if s.ok is False)
    status, detail = "ok", ""
    if down:
        status, detail = "degraded", "collector unreachable: " + ", ".join(down)
    elif total and len(polled) < total:
        detail = "collectors not polled yet"
    return {
        "schema": "exp.health/1", "status": status, "detail": detail, "version": __version__,
        "uptime_s": int(time.monotonic() - app.started_mono),
        "metrics": {
            "sessions_active": app.sessions.count_active(),
            "requests_per_min": app.requests_last_minute(),
            "sse_clients": app.hub.client_count,
            "collectors_total": total,
            "collectors_reachable": reachable,
            "login_failures_1h": app.auth.throttle.failures_last_hour(),
        },
        "facts": facts(app.settings),
    }


def offline(settings: Settings, detail: str) -> dict[str, Any]:
    return {"schema": "exp.health/1", "status": "fail", "detail": detail, "version": __version__,
            "uptime_s": 0,
            "metrics": {"sessions_active": 0, "requests_per_min": 0, "sse_clients": 0,
                        "collectors_total": len(settings.collectors), "collectors_reachable": 0,
                        "login_failures_1h": 0},
            "facts": facts(settings)}


class HealthSocket:
    def __init__(self, app: Any, run_dir: Path) -> None:
        self.app, self.path = app, Path(run_dir) / SOCK_NAME
        self._srv: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.is_socket():
                self.path.unlink()
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            old = os.umask(0o177)
            try:
                srv.bind(str(self.path))
            finally:
                os.umask(old)
            srv.listen(8)
            srv.settimeout(0.5)
        except OSError as exc:
            log.warning("health socket unavailable (%s); `health` will report the service as down",
                        exc.strerror)
            return False
        self._srv = srv
        self._thread = threading.Thread(target=self._loop, name="health", daemon=True)
        self._thread.start()
        return True

    def _loop(self) -> None:
        if self._srv is None:
            return
        while not self.app.stopping.is_set():
            try:
                conn, _ = self._srv.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with conn:
                try:
                    conn.settimeout(2.0)
                    doc = json.dumps(build(self.app), separators=(",", ":")).encode()
                    conn.sendall(doc[:MAX_BYTES])
                except (OSError, ValueError):
                    log.debug("health reply failed", exc_info=True)

    def stop(self) -> None:
        if self._srv is not None:
            self._srv.close()
        try:
            self.path.unlink()
        except OSError:
            pass


def query(run_dir: Path, timeout: float = 3.0) -> dict[str, Any] | None:
    path = Path(run_dir) / SOCK_NAME
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(str(path))
        buf = b""
        while len(buf) <= MAX_BYTES:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk
        doc = json.loads(buf.decode("utf-8"))
    except (OSError, ValueError):
        return None
    finally:
        s.close()
    return doc if isinstance(doc, dict) and doc.get("schema") == "exp.health/1" else None

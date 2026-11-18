"""The manager Worker under `wrangler dev` with LOCAL D1 / R2 (no Cloudflare account), HTTPS, plus an admin client.

How the Worker is made to trust the test Access issuer (environment only, no production hook):
  * ACCESS_TEAM_DOMAIN / ACCESS_AUD / EXP_OWNER_EMAIL / RELEASE_PUBKEY_PEM / MANAGER_URL / EXP_MASTER_KEY come
    from an env file passed to `wrangler dev --env-file` (the same names deploy.sh sets);
  * the team domain is a local host name from the hosts file that points at the JWKS server;
  * workerd verifies that server's certificate against SSL_CERT_FILE, which holds the throwaway CA only.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import secrets
import signal
import socket
import ssl
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
MANAGER_DIR = REPO / "manager"
PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")


def clean_env(**extra: str) -> dict[str, str]:
    """os.environ without any proxy variables (the sandbox proxy must never see local test traffic)."""
    env = {k: v for k, v in os.environ.items() if k.lower() not in PROXY_VARS}
    env.update(extra)
    return env


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("0.0.0.0", 0))  # noqa: S104
        return int(s.getsockname()[1])


class ApiResponse:
    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status, self.headers, self.body = status, headers, body

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self) -> Any:
        return json.loads(self.body)

    def __repr__(self) -> str:
        return f"ApiResponse({self.status}, {self.text[:300]!r})"


class ManagerDev:
    """Start/stop `wrangler dev`, apply migrations, publish a signed release, talk to the admin API."""

    def __init__(
        self,
        tmp: Path,
        *,
        host: str,
        team_domain: str,
        aud: str,
        owner_email: str,
        ca_pem: Path,
        cert: Path,
        key: Path,
        release_pubkey: Path,
    ) -> None:
        self.tmp, self.host = tmp, host
        self.team_domain, self.aud, self.owner = team_domain, aud, owner_email
        self.ca_pem, self.cert, self.key, self.release_pubkey = ca_pem, cert, key, release_pubkey
        self.port = free_port()
        self.state = tmp / "wrangler-state"
        self.log_path = tmp / "wrangler-dev.log"
        self.master_key = base64.b64encode(secrets.token_bytes(32)).decode()
        self.proc: subprocess.Popen[bytes] | None = None

    @property
    def url(self) -> str:
        return f"https://{self.host}:{self.port}"

    # ---- env
    def _env(self) -> dict[str, str]:
        return clean_env(
            SSL_CERT_FILE=str(self.ca_pem),
            NODE_EXTRA_CA_CERTS=str(self.ca_pem),
            WRANGLER_SEND_METRICS="false",
            WRANGLER_LOG_PATH=str(self.tmp / "wrangler-logs"),
            CI="1",
            NO_COLOR="1",
            FORCE_COLOR="0",
        )

    def _env_file(self) -> Path:
        pem = self.release_pubkey.read_text().strip().replace("\n", "\\n")
        p = self.tmp / "manager.env"
        p.write_text(
            "\n".join(
                [
                    f"ACCESS_TEAM_DOMAIN={self.team_domain}",
                    f"ACCESS_AUD={self.aud}",
                    f"EXP_OWNER_EMAIL={self.owner}",
                    f'RELEASE_PUBKEY_PEM="{pem}"',
                    f"MANAGER_URL={self.url}",
                    "ORG_NAME=E2E Org",
                    f"EXP_MASTER_KEY={self.master_key}",
                    "",
                ]
            )
        )
        p.chmod(0o600)
        return p

    def wrangler(self, *args: str, timeout: float = 180) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            ["npx", "--no-install", "wrangler", *args],  # noqa: S607
            cwd=MANAGER_DIR,
            env=self._env(),
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            check=False,
        )

    # ---- lifecycle
    def prepare(self) -> None:
        self.state.mkdir(parents=True, exist_ok=True)
        r = self.wrangler("d1", "migrations", "apply", "DB", "--local", "--persist-to", str(self.state))
        if r.returncode != 0:
            raise RuntimeError(f"migrations failed: {(r.stdout + r.stderr)[-600:]}")

    def publish_release(self, dist: Path, pubkey: Path | None = None) -> subprocess.CompletedProcess[str]:
        """manager/scripts/publish-release.sh --local against this instance's local D1/R2."""
        return subprocess.run(  # noqa: S603
            [
                str(MANAGER_DIR / "scripts" / "publish-release.sh"),
                "--dist",
                str(dist),
                "--pubkey",
                str(pubkey or self.release_pubkey),
                "--config",
                str(MANAGER_DIR / "wrangler.toml"),
                "--local",
                "--persist-to",
                str(self.state),
            ],
            cwd=MANAGER_DIR,
            env=self._env(),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
            stdin=subprocess.DEVNULL,
        )

    def start(self, timeout: float = 120) -> None:
        env_file = self._env_file()
        self.log = open(self.log_path, "wb")  # noqa: SIM115
        self.proc = subprocess.Popen(  # noqa: S603
            [
                "npx",
                "--no-install",
                "wrangler",
                "dev",  # noqa: S607
                "--ip",
                "0.0.0.0",
                "--port",
                str(self.port),
                "--inspector-port",
                str(free_port()),
                "--local-protocol",
                "https",
                "--https-key-path",
                str(self.key),
                "--https-cert-path",
                str(self.cert),
                "--persist-to",
                str(self.state),
                "--env-file",
                str(env_file),
                "--show-interactive-dev-session=false",
                "--test-scheduled",
            ],
            cwd=MANAGER_DIR,
            env=self._env(),
            stdout=self.log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"wrangler dev exited early: {self.log_tail()}")
            try:
                if self.get("/healthz").status == 200:
                    return
            except (OSError, ssl.SSLError):
                pass
            time.sleep(0.5)
        raise RuntimeError(f"wrangler dev did not become healthy in {timeout:.0f}s: {self.log_tail()}")

    def log_tail(self, n: int = 1500) -> str:
        try:
            return self.log_path.read_text(errors="replace")[-n:]
        except OSError:
            return ""

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=15)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.proc = None

    # ---- HTTP
    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        timeout: float = 30,
    ) -> ApiResponse:
        ctx = ssl.create_default_context(cafile=str(self.ca_pem))
        conn = http.client.HTTPSConnection(self.host, self.port, context=ctx, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            r = conn.getresponse()
            return ApiResponse(r.status, {k.lower(): v for k, v in r.getheaders()}, r.read())
        finally:
            conn.close()

    def get(self, path: str, **kw: Any) -> ApiResponse:
        return self.request("GET", path, **kw)

    def run_cron(self, cron: str = "*/5 * * * *") -> ApiResponse:
        """Fire a scheduled event (wrangler dev --test-scheduled): the Worker's own `scheduled()` handler runs."""
        q = cron.replace("/", "%2F").replace(" ", "+")
        # workerd's built-in /cdn-cgi handlers only answer to a loopback Host header
        return self.get(f"/cdn-cgi/handler/scheduled?cron={q}", headers={"Host": f"localhost:{self.port}"}, timeout=60)

    # ---- D1 (direct, for the things the API cannot do: simulate time)
    def sql(self, statement: str) -> list[dict[str, Any]]:
        r = self.wrangler(
            "d1",
            "execute",
            "DB",
            "--local",
            "--persist-to",
            str(self.state),
            "--json",
            "--yes",
            "--command",
            statement,
        )
        if r.returncode != 0:
            raise RuntimeError(f"d1 execute failed: {(r.stdout + r.stderr)[-500:]}")
        out = r.stdout
        data = json.loads(out[out.index("[") :])
        return list(data[0].get("results", []))


class AdminClient:
    """The admin API as a signed-in admin (an Access JWT on every request)."""

    def __init__(self, mgr: ManagerDev, token_fn: Callable[[], str]) -> None:
        self.mgr, self.token_fn = mgr, token_fn

    def call(
        self, method: str, path: str, payload: Any = None, *, ok: tuple[int, ...] | None = None
    ) -> ApiResponse:
        headers = {"Cf-Access-Jwt-Assertion": self.token_fn(), "Accept": "application/json"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        r = self.mgr.request(method, f"/api/admin/v1{path}", headers=headers, body=body)
        if ok is not None and r.status not in ok:
            raise AssertionError(f"{method} {path} -> {r.status} {r.text[:500]}")
        return r

    def get(self, path: str, **kw: Any) -> Any:
        return self.call("GET", path, ok=(200,), **kw).json()

    def post(self, path: str, payload: Any = None, ok: tuple[int, ...] = (200, 201, 202)) -> Any:
        return self.call("POST", path, payload if payload is not None else None, ok=ok).json()

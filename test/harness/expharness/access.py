"""A stand-in for Cloudflare Access: RS256 JWT minting with a throwaway key, and a local HTTPS JWKS server.

The Worker verifies Access JWTs against https://<ACCESS_TEAM_DOMAIN>/cdn-cgi/access/certs. The harness makes it
reach THIS server by environment only: ACCESS_TEAM_DOMAIN is a local host name (resolved through the hosts
file) and the throwaway CA is trusted by the Worker runtime through SSL_CERT_FILE. No production code path has
an alternative JWKS source or a verification switch (SPEC A2.2 is an enforcement test)."""

from __future__ import annotations

import base64
import json
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .pki import openssl


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class AccessKey:
    """One RSA signing key + the JWKS document that publishes it."""

    def __init__(self, directory: Path, kid: str = "e2e-key-1") -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self.kid = kid
        self.path = directory / f"{kid}.pem"
        openssl("genrsa", "-out", str(self.path), "2048")
        self.path.chmod(0o600)
        mod = openssl("rsa", "-in", str(self.path), "-noout", "-modulus").decode().split("=", 1)[1].strip()
        self.jwks: dict[str, Any] = {
            "keys": [
                {
                    "kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
                    "n": _b64u(bytes.fromhex(mod)), "e": "AQAB",
                }
            ]
        }

    def sign(self, signing_input: bytes) -> bytes:
        r = subprocess.run(  # noqa: S603
            ["openssl", "dgst", "-sha256", "-sign", str(self.path)],  # noqa: S607
            input=signing_input, capture_output=True, timeout=30, check=False,
        )
        if r.returncode != 0:
            raise RuntimeError("openssl dgst -sign failed")
        return r.stdout


class AccessIssuer:
    """Mints Access-shaped JWTs (RS256, kid in the header, iss/aud/email/exp claims)."""

    def __init__(self, directory: Path, team_domain: str, aud: str) -> None:
        self.team_domain, self.aud = team_domain, aud
        self.key = AccessKey(directory)
        self.forger = AccessKey(directory / "forger", kid=self.key.kid)  # same kid, wrong key

    def mint(
        self,
        email: str,
        *,
        key: AccessKey | None = None,
        aud: str | list[str] | None = None,
        iss: str | None = None,
        exp_in: int = 300,
        nbf_in: int | None = None,
        alg: str = "RS256",
        extra: dict[str, Any] | None = None,
    ) -> str:
        key = key or self.key
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": iss or f"https://{self.team_domain}",
            "aud": [self.aud] if aud is None else aud,
            "email": email,
            "sub": "e2e-" + email,
            "iat": now,
            "exp": now + exp_in,
        }
        if nbf_in is not None:
            claims["nbf"] = now + nbf_in
        claims.update(extra or {})
        head = _b64u(json.dumps({"alg": alg, "kid": key.kid, "typ": "JWT"}).encode())
        body = _b64u(json.dumps(claims).encode())
        sig = key.sign(f"{head}.{body}".encode())
        return f"{head}.{body}.{_b64u(sig)}"


class JwksServer:
    """HTTPS server for /cdn-cgi/access/certs on `bind`:443 (a loopback address of its own, so it cannot clash)."""

    def __init__(self, jwks: dict[str, Any], cert: Path, key: Path, bind: str, port: int = 443) -> None:
        body = json.dumps(jwks).encode()
        hits: list[str] = []
        self.hits = hits

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                hits.append(self.path)
                ok = self.path == "/cdn-cgi/access/certs"
                data = body if ok else b"{}"
                self.send_response(200 if ok else 404)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a: Any) -> None:  # noqa: D102 - silence
                return

        self.httpd = ThreadingHTTPServer((bind, port), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(key))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def scratch(prefix: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix))

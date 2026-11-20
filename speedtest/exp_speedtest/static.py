"""The page, its CSP, the branding assets and the pre-generated download payload.

* ``static/index.html`` is the self-contained page (built by the page step). Its inline ``<script>``/``<style>`` blocks are
  allowed by CSP **hashes** that the page build writes to ``static/csp-hashes.json`` (``{"schema": "exp.speedtest.csp/1",
  "script": ["sha256-..."], "style": ["sha256-..."]}``). If that file is absent or invalid the box derives the same hashes
  from the inline blocks of ``index.html`` at load time (so a placeholder page works); a page that changes after the build
  simply stops being allowed to run, which is the point of hashing. There is never ``unsafe-inline``/``unsafe-eval``.
* Assets: ``/st/assets/<name>`` serves ``<assets_dir>/<name>`` (the branding ``logo`` the agent installs) and
  ``static/assets/<name>`` (fonts), only for known image/font types, never following symlinks, with a locked-down CSP.
* The payload for ``/st/down`` is a 32 MiB file of random (incompressible) bytes created once in the state directory.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import stat
import tempfile
import threading
import time
from pathlib import Path

log = logging.getLogger(__name__)

ENGINE_ASSET = "cf-engine.js"
JS_TYPE = "text/javascript; charset=utf-8"
STATIC_DIR = Path(__file__).resolve().parent / "static"
PAYLOAD_SIZE = 32 * 1024 * 1024
MAX_ASSET_BYTES = 1024 * 1024        # the engine file is ~63 KB
_ASSET_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_HASH = re.compile(r"sha256-[A-Za-z0-9+/]{43}=\Z")
_SCRIPT = re.compile(r"<script(?P<attrs>[^>]*)>(?P<body>.*?)</script>", re.I | re.S)
_STYLE = re.compile(r"<style(?P<attrs>[^>]*)>(?P<body>.*?)</style>", re.I | re.S)
_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".svg": "image/svg+xml", ".ico": "image/x-icon",
          ".woff2": "font/woff2", ".woff": "font/woff", ".webp": "image/webp"}


def csp_hash(text: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def inline_hashes(html: str) -> tuple[list[str], list[str]]:
    scripts = [csp_hash(m.group("body")) for m in _SCRIPT.finditer(html)
               if "src=" not in m.group("attrs").lower() and m.group("body").strip()]
    styles = [csp_hash(m.group("body")) for m in _STYLE.finditer(html) if m.group("body").strip()]
    return scripts, styles


def sniff_type(head: bytes) -> str | None:
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "image/webp"
    h = head.lstrip()[:512].lower()
    if h.startswith(b"<svg") or (h.startswith(b"<?xml") and b"<svg" in head.lower()):
        return "image/svg+xml"
    return None


class StaticSite:
    def __init__(self, dns_zone: str | None, tls_mode: str, assets_dir: Path, static_dir: Path = STATIC_DIR) -> None:
        self.dns_zone, self.tls_mode, self.assets_dir, self.static_dir = dns_zone, tls_mode, assets_dir, static_dir
        self._lock = threading.Lock()
        self._loaded_at = 0.0
        self._mtime: tuple[float, float] = (0.0, 0.0)
        self._page = b""
        self._csp = ""

    # ------------------------------------------------------------------------------------------------- CSP
    def connect_src(self) -> str:
        connect = ["'self'", "https://speed.cloudflare.com"]
        if self.dns_zone:
            connect.insert(1, f"http://*.{self.dns_zone}")
            if self.tls_mode == "provided":
                connect.insert(2, f"https://*.{self.dns_zone}")
        return "connect-src " + " ".join(connect)

    def build_csp(self, script: list[str], style: list[str]) -> str:
        """The page's policy. ``script-src 'self'`` + ``worker-src 'self'`` exist for the engine worker (and its main-thread
        fallback script) at ``/st/assets/cf-engine.js``: same-origin file only, never blob:/data:."""
        def quote(hs: list[str]) -> str:
            return " ".join(f"'{h}'" for h in hs)
        return "; ".join([
            "default-src 'self'", " ".join(x for x in ("script-src", quote(script), "'self'") if x), "worker-src 'self'",
            ("style-src 'self' " + quote(style)).strip(), self.connect_src(), "img-src 'self' data:",
            "font-src 'self'", "object-src 'none'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'"])

    def worker_csp(self) -> str:
        """A dedicated worker takes its policy from its OWN script response (CSP3), so the engine file carries one whose
        connect-src equals the page's: the worker may fetch the box, the DNS-leg names and Cloudflare, nothing else."""
        return f"default-src 'none'; {self.connect_src()}; frame-ancestors 'none'"

    def _load(self) -> None:
        idx = self.static_dir / "index.html"
        hashes_file = self.static_dir / "csp-hashes.json"
        try:
            st1 = idx.stat().st_mtime
            st2 = hashes_file.stat().st_mtime if hashes_file.exists() else 0.0
        except OSError:
            self._page, self._csp, self._mtime = b"", "", (0.0, 0.0)
            return
        if (st1, st2) == self._mtime and self._page:
            return
        html = idx.read_text(encoding="utf-8")
        script, style = inline_hashes(html)
        if hashes_file.exists():
            try:
                doc = json.loads(hashes_file.read_text(encoding="utf-8"))
                s2, y2 = doc["script"], doc["style"]
                if doc.get("schema") == "exp.speedtest.csp/1" and all(isinstance(h, str) and _HASH.match(h) for h in [*s2, *y2]):
                    script, style = s2, y2
                else:
                    log.error("csp-hashes.json is invalid: deriving hashes from the page")
            except (OSError, ValueError, KeyError, TypeError):
                log.error("csp-hashes.json is unreadable: deriving hashes from the page")
        self._page, self._csp, self._mtime = html.encode("utf-8"), self.build_csp(script, style), (st1, st2)

    def page(self) -> tuple[bytes, str]:
        """``(index.html bytes, Content-Security-Policy)``; re-checks the files at most once a second."""
        now = time.monotonic()
        with self._lock:
            if now - self._loaded_at > 1.0 or not self._page:
                self._loaded_at = now
                self._load()
            return self._page, self._csp

    # ----------------------------------------------------------------------------------------------- assets
    def asset(self, name: str) -> tuple[bytes, str] | None:
        if not _ASSET_NAME.match(name) or name.startswith("."):
            return None
        if name == ENGINE_ASSET:                      # built with the page; never taken from the operator's assets_dir
            return self._read(self.static_dir / "assets", name, JS_TYPE)
        for base in (self.assets_dir, self.static_dir / "assets"):
            hit = self._read(base, name, None)
            if hit is not None:
                return hit
        return None

    @staticmethod
    def _read(base: Path, name: str, fixed_type: str | None) -> tuple[bytes, str] | None:
        fd = None
        try:
            fd = os.open(os.path.join(base, name), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_ASSET_BYTES:
                return None
            data = os.read(fd, MAX_ASSET_BYTES + 1)
        except OSError:
            return None
        finally:
            if fd is not None:
                os.close(fd)
        if fixed_type is not None:
            return data, fixed_type
        ctype = _TYPES.get(os.path.splitext(name)[1]) if "." in name else None
        if name == "logo" or ctype is None or ctype.startswith("image/"):
            ctype = sniff_type(data[:512]) or (ctype if ctype and ctype.startswith("font/") else None)
        if ctype is None:
            return None
        return data, ctype


class Payload:
    """The incompressible download payload, served with sendfile. A fresh file object per request (no shared position)."""

    def __init__(self, path: Path | None, size: int = PAYLOAD_SIZE) -> None:
        self.size = size
        self.path = self._ensure(path)

    def _fill(self, fd: int) -> None:
        left = self.size
        while left:
            chunk = os.urandom(min(left, 1 << 20))
            os.write(fd, chunk)
            left -= len(chunk)

    def _ensure(self, path: Path | None) -> str:
        if path is not None:
            try:
                if path.is_file() and path.stat().st_size == self.size:
                    return str(path)
                path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(str(path) + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                try:
                    self._fill(fd)
                finally:
                    os.close(fd)
                os.replace(str(path) + ".tmp", path)
                return str(path)
            except OSError as exc:
                log.warning("cannot create the payload in %s (%s): using a temp file", path.parent, exc.strerror)
        fd, tmp = tempfile.mkstemp(prefix="exp-st-payload-")
        try:
            self._fill(fd)
        finally:
            os.close(fd)
        return tmp

    def open(self):  # noqa: ANN201 - a raw binary file
        return open(self.path, "rb", buffering=0)  # noqa: SIM115 - the caller closes it

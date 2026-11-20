"""Speedtest branding assets (M6, CR-m6-contracts item 6): `desired.components[speedtest].assets[]`.

Each asset is an artifact the manager stores (an operator-uploaded logo), referenced by the desired
state, so SR-6 ("only what the desired state references") holds. It is NOT in the signed release
manifest; the desired state (agent secret, TLS) carries its sha256 and size, which are checked on the
downloaded bytes. The content is then sniffed against the declared type (PNG / JPEG magic; SVG must
contain no script, event handler, foreign object, entity or external reference: the manager refuses those
at upload, this is defence in depth) and installed atomically as `/etc/exp/speedtest/assets/<name>`, root
`0644`. Anything that fails is skipped with an agent event: the box then serves without a logo. Assets no
longer in the desired state are removed."""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

from . import artifacts
from .context import Context
from .errors import AgentError, Unauthorized

log = logging.getLogger(__name__)

MAX_ASSET_BYTES = 256 * 1024
ASSET_NAMES = frozenset({"logo"})
_PNG = b"\x89PNG\r\n\x1a\n"
_JPEG = b"\xff\xd8\xff"
_SVG_BAD = re.compile(
    rb"<\s*script|<\s*foreignObject|<\s*iframe|<\s*object|<\s*embed|<\s*animate|<\s*set\b|<!\s*ENTITY|<!\s*DOCTYPE|"
    rb"\bon[a-z]+\s*=|javascript:|@import|url\(\s*[\"']?\s*(?!#)|"
    rb"(?:xlink:)?href\s*=\s*[\"']\s*(?!#|data:image/(?:png|jpeg|gif|webp);base64,)",
    re.I,
)


def assets_dir(ctx: Context):
    return ctx.paths.etc_dir("speedtest") / "assets"


def content_ok(data: bytes, content_type: str) -> bool:
    if len(data) == 0 or len(data) > MAX_ASSET_BYTES:
        return False
    if content_type == "image/png":
        return data.startswith(_PNG)
    if content_type == "image/jpeg":
        return data.startswith(_JPEG)
    if content_type == "image/svg+xml":
        head = data[:512].lstrip(b"\xef\xbb\xbf").lstrip()
        if not (head.startswith(b"<svg") or head.startswith(b"<?xml")):
            return False
        return b"<svg" in data[:2048].lower() and not _SVG_BAD.search(data)
    return False


def sync(ctx: Context, assets: list[dict[str, Any]]) -> bool:
    """Make assets/ hold exactly the verified desired assets. True if anything changed. Never raises for a
    bad asset (it is skipped and reported)."""
    fs = ctx.fs
    d = assets_dir(ctx)
    wanted: dict[str, dict[str, Any]] = {}
    for a in assets or []:
        if isinstance(a, dict) and a.get("name") in ASSET_NAMES and isinstance(a.get("artifact"), dict):
            wanted[a["name"]] = a
    changed = False
    for name, a in sorted(wanted.items()):
        art = a["artifact"]
        try:
            size = int(art["size"])
            if not 0 < size <= MAX_ASSET_BYTES:
                raise AgentError(f"asset {name} has an unacceptable size")
            target = d / name
            cur = fs.read_bytes(target, MAX_ASSET_BYTES + 1)
            if (
                cur is not None
                and hashlib.sha256(cur).hexdigest() == art["sha256"]
                and content_ok(cur, a["content_type"])
            ):
                continue
            path = artifacts.download_verified(ctx.client, fs, art, {"size": size, "sha256": art["sha256"]})
            try:
                data = fs.read_bytes(path, MAX_ASSET_BYTES + 1) or b""
            finally:
                fs.remove(path)
            if not content_ok(data, a["content_type"]):
                raise AgentError(f"asset {name} is not a valid {a['content_type']}")
            fs.mkdir(ctx.paths.etc, 0o755)
            fs.mkdir(ctx.paths.etc_dir("speedtest"), 0o755)
            fs.mkdir(d, 0o755)
            fs.write(target, data, 0o644)
            changed = True
            ctx.state.event("info", f"installed speedtest asset {name}")
        except Unauthorized:
            raise
        except (AgentError, OSError, KeyError, ValueError) as exc:
            log.warning("speedtest asset %s skipped: %s", name, exc)
            ctx.state.event("warn", f"speedtest asset {name} skipped: {exc}")
    for name in fs.listdir(d):
        if name not in wanted:
            p = d / name
            if fs.is_dir(p):
                fs.rmtree(p)
            else:
                fs.remove(p)
            changed = True
    return changed

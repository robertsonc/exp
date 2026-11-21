"""Coarse User-Agent parsing. The raw string is never stored: only ``os_family``, ``os_version``, ``browser`` and
``device_class`` (speedtest.schema.json ``ua``) survive."""
from __future__ import annotations

import re

MAX_UA = 512
_CTRL = re.compile(r"[\x00-\x1f\x7f]")

_OS = (
    (re.compile(r"(?:iPhone|iPad|iPod)[^)]*?OS (\d+)[_.](\d+)"), "iOS"),
    (re.compile(r"Android[ /](\d+(?:\.\d+)?)"), "Android"),
    (re.compile(r"Windows NT (\d+(?:\.\d+)?)"), "Windows"),
    (re.compile(r"Mac OS X (\d+)[_.](\d+)"), "macOS"),
    (re.compile(r"CrOS [^ ]+ (\d+)"), "ChromeOS"),
    (re.compile(r"(Linux|X11)"), "Linux"),
)
_BROWSERS = (          # order matters: the more specific tokens first
    (re.compile(r"SamsungBrowser/(\d+)"), "Samsung Internet"),
    (re.compile(r"(?:Edg|EdgA|EdgiOS)/(\d+)"), "Edge"),
    (re.compile(r"(?:OPR|Opera)/(\d+)"), "Opera"),
    (re.compile(r"(?:Firefox|FxiOS)/(\d+)"), "Firefox"),
    (re.compile(r"(?:Chrome|CriOS)/(\d+)"), "Chrome"),
    (re.compile(r"Version/(\d+)[^ ]* (?:Mobile/\w+ )?Safari/"), "Safari"),
)


def parse_ua(ua: str | None) -> dict[str, str]:
    """Descriptors for the schema. Unknown parts are omitted from the result except ``device_class`` (``other``)."""
    s = _CTRL.sub("", (ua or "")[:MAX_UA])
    out: dict[str, str] = {}
    for rx, fam in _OS:
        m = rx.search(s)
        if m:
            out["os_family"] = fam
            if m.groups() and m.group(1) not in ("Linux", "X11"):
                out["os_version"] = ".".join(g for g in m.groups() if g)[:32]
            break
    for rx, name in _BROWSERS:
        if rx.search(s):
            out["browser"] = name
            break
    fam = out.get("os_family")
    if fam == "iOS":
        out["device_class"] = "tablet" if "iPad" in s else "phone"
    elif fam == "Android":
        out["device_class"] = "phone" if "Mobile" in s else "tablet"
    elif fam in ("Windows", "macOS", "Linux", "ChromeOS"):
        out["device_class"] = "desktop"
    else:
        out["device_class"] = "other"
    return out

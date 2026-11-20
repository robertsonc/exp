"""Privacy transforms (12 section 9, SR-25): redact raw identifiers from evidence.

Raw identifiers are the client's IP, MAC, hostname and 802.1X / portal username. ``device_key`` (HMAC of the MAC
under the per-org secret) is kept: it is the join key. The same transform serves two purposes:

* the **scrub** (``scrub_after_diagnosis``, off by default): applied once to the stored rows after the final
  diagnosis, so the database no longer holds the identifiers;
* the **non-admin view**: ``GET speedtests/{id}`` without ``identifiers=true`` returns the evidence run through the
  same transform.

Schema validity is preserved: the two required IP fields of a flow row become ``0.0.0.0``, every other identifier
field is removed, and identifiers that appear inside free text (log lines, ``raw_refs``) are replaced by ``[scrubbed]``.
"""
from __future__ import annotations

import copy
import dataclasses
import re
from collections.abc import Iterable
from typing import Any

from exp_common import speedtest as st_helpers

MASK = "[scrubbed]"
ZERO_IP = "0.0.0.0"  # noqa: S104 - a placeholder that keeps a required ip field schema-valid, never bound
_MIN_TOKEN = 3


@dataclasses.dataclass
class Identifiers:
    ips: set[str] = dataclasses.field(default_factory=set)
    macs: set[str] = dataclasses.field(default_factory=set)
    names: set[str] = dataclasses.field(default_factory=set)       # hostname / dhcp fqdn / username

    def add_ip(self, v: Any) -> None:
        if isinstance(v, str) and v:
            self.ips.add(v.strip())

    def add_mac(self, v: Any) -> None:
        if isinstance(v, str) and v:
            try:
                self.macs.add(st_helpers.normalize_mac(v))
            except ValueError:
                pass

    def add_name(self, v: Any) -> None:
        if isinstance(v, str) and len(v.strip()) >= _MIN_TOKEN:
            self.names.add(v.strip())

    def tokens(self) -> list[str]:
        """Every spelling to look for in free text, longest first."""
        out: set[str] = set(self.ips) | set(self.names)
        for m in self.macs:
            bare = m.replace(":", "")
            out |= {m, m.upper(), m.replace(":", "-"), m.replace(":", "-").upper(), bare, bare.upper(),
                    ".".join(bare[i:i + 4] for i in range(0, 12, 4))}
        return sorted((t for t in out if t), key=len, reverse=True)

    def pattern(self) -> re.Pattern[str] | None:
        toks = self.tokens()
        if not toks:
            return None
        alt = "|".join(re.escape(t) for t in toks)
        return re.compile(r"(?<![0-9A-Za-z])(?:" + alt + r")(?![0-9A-Za-z])", re.IGNORECASE)


def collect(client_ip: str | None, mac: str | None, hostname: str | None, username: str | None,
            evidence: Iterable[dict[str, Any]]) -> Identifiers:
    """The identifiers of one test: its row columns plus whatever its evidence names for the client."""
    ids = Identifiers()
    ids.add_ip(client_ip)
    ids.add_mac(mac)
    ids.add_name(hostname)
    ids.add_name(username)
    for ev in evidence:
        data = ev.get("data") or {}
        kind = ev.get("kind")
        if kind == "identity":
            ids.add_ip(data.get("ip"))
            ids.add_mac(data.get("mac"))
            ids.add_name(data.get("hostname"))
            ids.add_name(data.get("username"))
        elif kind in ("wifi", "wired"):
            c = data.get("client") or {}
            ids.add_mac(c.get("mac"))
            for ip in (c.get("ip") or []) if isinstance(c.get("ip"), list) else [c.get("ip")]:
                ids.add_ip(ip)
            ids.add_name(c.get("dhcp_hostname"))
            ids.add_name(c.get("dhcp_fqdn"))
    return ids


def _sweep(value: Any, pat: re.Pattern[str] | None) -> Any:
    if pat is None:
        return value
    if isinstance(value, str):
        return pat.sub(MASK, value)
    if isinstance(value, list):
        return [_sweep(v, pat) for v in value]
    if isinstance(value, dict):
        return {k: _sweep(v, pat) for k, v in value.items()}
    return value


def redact_evidence(doc: dict[str, Any], ids: Identifiers) -> dict[str, Any]:
    """A copy of one ``exp.evidence/1`` document without raw client identifiers (device_key kept)."""
    out = copy.deepcopy(doc)
    kind = out.get("kind")
    data = out.get("data")
    if isinstance(data, dict):
        if kind == "identity":
            for k in ("ip", "mac", "hostname", "username"):
                data.pop(k, None)
            data["scrubbed"] = True
        elif kind in ("wifi", "wired"):
            c = data.get("client")
            if isinstance(c, dict):
                for k in ("mac", "ip", "dhcp_hostname", "dhcp_fqdn"):
                    c.pop(k, None)
        elif kind == "flows":
            for f in data.get("flows") or []:
                if isinstance(f, dict):
                    for k in ("ip1", "ip2"):
                        if f.get(k) in ids.ips:
                            f[k] = ZERO_IP
        elif kind == "security":
            for e in data.get("events") or []:
                if isinstance(e, dict):
                    for k in ("src_ip", "dst_ip"):
                        if e.get(k) in ids.ips:
                            e.pop(k, None)
        elif kind == "dns":
            for q in data.get("queries") or []:
                if isinstance(q, dict):
                    q.pop("client_ip", None)
    pat = ids.pattern()
    if pat is not None:
        out["data"] = _sweep(out.get("data"), pat)
        out["raw_refs"] = _sweep(out.get("raw_refs"), pat)
    return out

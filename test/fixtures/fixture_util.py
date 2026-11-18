"""Deterministic helpers shared by gen_fixtures.py and convert_exm.py (fixtures only, never product code)."""
from __future__ import annotations

import base64
import datetime
import hashlib

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def iso_to_ms(ts: str) -> int:
    dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return int(round(dt.timestamp() * 1000))


def ms_to_iso(ms: int) -> str:
    dt = datetime.datetime.fromtimestamp(ms / 1000.0, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (ms % 1000)


def ulid(ts_ms: int, seed: str) -> str:
    """26-char ULID: 48-bit big-endian time + 80 bits derived from sha256(seed)."""
    n = (ts_ms << 80) | int.from_bytes(hashlib.sha256(seed.encode()).digest()[:10], "big")
    out = []
    for _ in range(26):
        out.append(_CROCKFORD[n & 31])
        n >>= 5
    return "".join(reversed(out))


FIXTURE_EPOCH_MS = iso_to_ms("2026-11-18T20:00:00.000Z")


def fid(prefix: str, seed: str) -> str:
    """Prefixed ULID for a fixture entity, e.g. fid('h', 'host-1') -> h_01KB..."""
    return prefix + "_" + ulid(FIXTURE_EPOCH_MS, prefix + ":" + seed)


def token(prefix: str, seed: str) -> str:
    """Obviously fake token with the documented format: prefix_ + base64url(sha256('fixture:'+seed)) (43 chars)."""
    d = hashlib.sha256(("fixture:" + seed).encode()).digest()
    return prefix + "_" + base64.urlsafe_b64encode(d).decode().rstrip("=")


def sha256_hex(seed: str) -> str:
    return hashlib.sha256(("fixture:" + seed).encode()).hexdigest()


def fingerprint(seed: str) -> str:
    d = hashlib.sha256(("fixture-cert:" + seed).encode()).hexdigest().upper()
    return ":".join(d[i:i + 2] for i in range(0, 64, 2))

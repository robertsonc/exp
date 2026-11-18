"""Identifiers and secret tokens (01-contracts.md section 1).

* ULID: 26 chars, Crockford base32, 48-bit ms timestamp + 80-bit randomness, lexicographically
  time-ordered. Within the same millisecond (or if the clock steps backwards) the random part is
  incremented, so ids from one process are strictly monotonic.
* Prefixed internal ids: ``h_`` host, ``cmp_`` component, ``rel_`` release, ``art_`` artifact,
  ``usr_`` dashboard user, ``noc_`` NOC token id, ``drl_`` drill, ``run_`` drill run, ``evt_`` audit.
* Tokens: type prefix + base64url(32 random bytes, no padding) = 43 chars. ``expe_`` enrol,
  ``expa_`` agent secret, ``expi_`` probe ingest, ``expd_`` dashboard->collector, ``expn_`` NOC.
  Servers store only ``token_hash(token)`` (sha256 hex) and compare in constant time.
* Slugs: ``[a-z0-9][a-z0-9-]{0,63}``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time
from typing import Optional

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_DECODE = {c: i for i, c in enumerate(CROCKFORD)}

ULID_RE = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}\Z")
SLUG_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")

ID_PREFIXES = ("h_", "cmp_", "rel_", "art_", "usr_", "noc_", "drl_", "run_", "evt_")
TOKEN_PREFIXES = ("expe_", "expa_", "expi_", "expd_", "expn_")
TOKEN_BODY_LEN = 43  # base64url of 32 bytes without padding
_TOKEN_RE = re.compile(r"exp[aeidn]_[A-Za-z0-9_-]{43}\Z")

_MAX_MS = (1 << 48) - 1
_MAX_RAND = (1 << 80) - 1
_lock = threading.Lock()
_last_ms = -1
_last_rand = 0


def _encode(value: int, length: int) -> str:
    out = []
    for _ in range(length):
        out.append(CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(out))


def new_ulid(now_ms: Optional[int] = None) -> str:
    """A new ULID. Monotonic per process: same-ms calls increment the random part."""
    global _last_ms, _last_rand
    with _lock:
        ms = int(time.time() * 1000) if now_ms is None else int(now_ms)
        if not 0 <= ms <= _MAX_MS:
            raise ValueError("timestamp out of ULID range")
        if ms > _last_ms:
            _last_ms, _last_rand = ms, int.from_bytes(secrets.token_bytes(10), "big")
        else:  # same ms, or clock went backwards: keep ordering by incrementing
            _last_rand += 1
            if _last_rand > _MAX_RAND:
                _last_ms += 1
                if _last_ms > _MAX_MS:
                    raise OverflowError("ULID timestamp space exhausted")
                _last_rand = int.from_bytes(secrets.token_bytes(10), "big") >> 1
        return _encode(_last_ms, 10) + _encode(_last_rand, 16)


def is_ulid(value: object) -> bool:
    """True for a string matching the contract ULID pattern (26 Crockford chars)."""
    return isinstance(value, str) and ULID_RE.match(value) is not None


def ulid_timestamp_ms(ulid: str) -> int:
    """Epoch milliseconds encoded in a ULID. Raises ValueError if it is not a ULID."""
    if not is_ulid(ulid):
        raise ValueError("not a ULID")
    v = 0
    for ch in ulid[:10]:
        v = (v << 5) | _DECODE[ch]
    return v


def new_id(prefix: str) -> str:
    """Prefixed internal id, e.g. ``new_id("h_")`` -> ``h_01J...``."""
    if prefix not in ID_PREFIXES:
        raise ValueError(f"unknown id prefix {prefix!r}; expected one of {ID_PREFIXES}")
    return prefix + new_ulid()


def is_prefixed_id(value: object, prefix: Optional[str] = None) -> bool:
    """True if ``value`` is ``<known prefix><ULID>`` (and has ``prefix`` if one is given)."""
    if not isinstance(value, str):
        return False
    for p in ID_PREFIXES:
        if value.startswith(p):
            return (prefix is None or prefix == p) and is_ulid(value[len(p):])
    return False


def _token_prefix(kind: str) -> str:
    prefix = kind if kind.endswith("_") else kind + "_"
    if prefix not in TOKEN_PREFIXES:
        raise ValueError(f"unknown token kind {kind!r}; expected one of {TOKEN_PREFIXES}")
    return prefix


def new_token(kind: str) -> str:
    """New secret token: ``<prefix>`` + base64url(32 random bytes), no padding."""
    body = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    return _token_prefix(kind) + body


def is_token(value: object, kind: Optional[str] = None) -> bool:
    """Format check only (does not prove the token is valid)."""
    if not isinstance(value, str) or _TOKEN_RE.match(value) is None:
        return False
    return kind is None or value.startswith(_token_prefix(kind))


def token_hash(token: str) -> str:
    """sha256 hex of the token: the only form servers store."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    """Constant-time equality of two secrets (or two hashes). Non-strings are never equal."""
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def is_slug(value: object) -> bool:
    return isinstance(value, str) and SLUG_RE.match(value) is not None

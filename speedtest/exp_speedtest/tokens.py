"""Leg tokens (``expt_``): HMAC-signed, short-lived, one session, bound to the observed client address.

Wire form: ``expt_`` + base64url(32 bytes) (the contract's token shape). The 32 bytes are
``expiry(4, epoch seconds, big endian) || nonce(12 random) || mac(16)`` with
``mac = HMAC-SHA256(process_key, "exp.st.leg/1" || expiry || nonce || session_id || 0 || client_ip)[:16]``.
The key exists only in this process's memory, so a token never survives a restart and nothing needs storing; the nonce
indexes the live session. A token minted for one session or one address fails the MAC for any other.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct

PREFIX = "expt_"
_BODY = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class LegTokens:
    def __init__(self, key: bytes | None = None) -> None:
        self._key = key or secrets.token_bytes(32)

    def _mac(self, expiry: bytes, nonce: bytes, session_id: str, client_ip: str) -> bytes:
        msg = b"exp.st.leg/1" + expiry + nonce + session_id.encode("ascii") + b"\0" + client_ip.encode("ascii")
        return hmac.new(self._key, msg, hashlib.sha256).digest()[:16]

    def mint(self, session_id: str, client_ip: str, expires_at: int) -> tuple[str, bytes]:
        """-> (token, nonce). The nonce is the lookup key of the session."""
        expiry = struct.pack(">I", int(expires_at) & 0xFFFFFFFF)
        nonce = secrets.token_bytes(12)
        raw = expiry + nonce + self._mac(expiry, nonce, session_id, client_ip)
        return PREFIX + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"), nonce

    @staticmethod
    def parse(token: object) -> tuple[int, bytes, bytes] | None:
        """``(expiry, nonce, mac)`` of a well-formed token, else None (format check only)."""
        if not isinstance(token, str) or not token.startswith(PREFIX) or not _BODY.match(token[len(PREFIX):]):
            return None
        raw = base64.urlsafe_b64decode(token[len(PREFIX):] + "=")
        return struct.unpack(">I", raw[:4])[0], raw[4:16], raw[16:]

    def verify(self, token: str, session_id: str, client_ip: str) -> bool:
        parsed = self.parse(token)
        if parsed is None:
            return False
        expiry, nonce, mac = parsed
        want = self._mac(struct.pack(">I", expiry), nonce, session_id, client_ip)
        return hmac.compare_digest(want, mac)

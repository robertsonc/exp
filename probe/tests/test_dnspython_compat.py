"""Guard for the vendored dnspython on Python 3.10 (see the note on dnspython in packaging/vendor.lock).

dnspython 2.9.x declares requires_python >= 3.11, but exp still supports Ubuntu 22.04 (python3.10, SPEC D7)
and vendors 2.9.2 on purpose because it fixes GHSA-45c3-73f7-pv4m, which the probe can hit (it parses DNS
replies from resolvers on the untrusted event LAN). This test imports EVERY module of the dns package on the
running interpreter (CI runs it on 3.10 and 3.12), so a 3.11-only construct anywhere in the package fails CI
instead of failing on a 22.04 host. Optional third-party extras (cryptography, httpx, aioquic, trio, idna, ...)
are not vendored; a ModuleNotFoundError for one of those is expected and allowed — anything else is not.
"""
from __future__ import annotations

import importlib
import pkgutil

import dns
import pytest

# Optional extras of dnspython that exp does not vendor (the probe never uses DoH/DoQ/DNSSEC/trio paths).
_OPTIONAL = {"cryptography", "httpx", "httpcore", "h2", "aioquic", "trio", "anyio", "sniffio", "idna", "wmi", "curio"}


def _modules() -> list[str]:
    return sorted(m.name for m in pkgutil.walk_packages(dns.__path__, prefix="dns."))


def test_vendored_dnspython_is_the_pinned_version() -> None:
    import dns.version

    assert dns.version.version == "2.9.2"


@pytest.mark.parametrize("name", _modules())
def test_every_dnspython_module_imports_on_this_python(name: str) -> None:
    try:
        importlib.import_module(name)
    except ModuleNotFoundError as exc:  # an optional extra exp does not ship
        root = (exc.name or "").split(".")[0]
        if root not in _OPTIONAL:
            raise
    # SyntaxError / AttributeError / TypeError from a 3.11-only construct propagate and fail the test


def test_probe_dns_paths_work_end_to_end_on_this_python() -> None:
    """Exercise the exact dnspython surface the probe uses: build a query, render to wire, parse a reply
    with compressed names (the code path GHSA-45c3-73f7-pv4m concerns)."""
    import dns.message
    import dns.rdatatype
    import dns.rrset

    q = dns.message.make_query("www.example.com", dns.rdatatype.A)
    wire = q.to_wire()
    r = dns.message.make_response(dns.message.from_wire(wire))
    r.answer.append(dns.rrset.from_text("www.example.com.", 60, "IN", "A", "192.0.2.1"))
    r.answer.append(dns.rrset.from_text("www.example.com.", 60, "IN", "A", "192.0.2.2"))
    parsed = dns.message.from_wire(r.to_wire())
    assert [str(rd) for rd in parsed.answer[0]] == ["192.0.2.1", "192.0.2.2"]

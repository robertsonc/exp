"""Measurement test modules: gateway, dhcp (dhcp_hb + dhcp), dns (dns_hb + dns), trace, ping, app (M1);
wifi (wifi_hb + wifi_join, M4); throughput and path arrive later.

Each module registers its test functions with `exp_probe.scheduler.register_test`; `register_all` imports every
module that exists in this build. A configured test without a module is reported once in the log and skipped
(never emitted as a fake result). `common.py` holds the helpers they share (it registers nothing).
"""
from __future__ import annotations

import importlib
import logging

log = logging.getLogger(__name__)

MODULES = ("gateway", "dhcp", "dns", "trace", "ping", "app", "throughput", "path", "wifi")


def register_all() -> list[str]:
    """Import the available test modules; returns the names that loaded."""
    loaded: list[str] = []
    for name in MODULES:
        try:
            importlib.import_module(f"{__name__}.{name}")
        except ModuleNotFoundError as exc:
            if exc.name != f"{__name__}.{name}":
                raise                  # a missing dependency INSIDE an existing module is a real error
            log.debug("test module %s not present in this build", name)
        else:
            loaded.append(name)
    return loaded

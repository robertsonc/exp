"""Drill endpoints' backing registry (M5 fills this in; 10-drills-integrations.md).

The M1/M2 collector answers the three drill routes so the contract is wired end to end:

* ``GET  /api/v1/drills/control``       -> ``{"abort": [run_id, ...]}`` for an executor (ingest token auth)
* ``GET  /api/v1/drills/{run_id}``      -> 404 ``drill_not_found`` until M5 stores drill reports
* ``POST /api/v1/drills/{run_id}/abort``-> 404 ``drill_not_found`` until M5

M5 replaces ``app.drills`` with an object implementing ``DrillRegistry`` (same three methods); the HTTP
layer, auth and audit logging do not change.
"""
from __future__ import annotations

import re
from typing import Any

RUN_ID = re.compile(r"run_[0-9A-HJKMNP-TV-Z]{26}\Z")


def valid_run_id(value: str) -> bool:
    return bool(RUN_ID.match(value))


class DrillRegistry:
    """Default (M1/M2) registry: no drills are known."""

    def abort_list(self) -> list[str]:
        """Run ids executors must abort now (the LAN kill switch)."""
        return []

    def report(self, run_id: str) -> dict[str, Any] | None:
        """The drill report document, or None when the run is unknown."""
        return None

    def abort(self, run_id: str, user: str) -> bool:
        """Request an abort. False when the run is unknown."""
        return False

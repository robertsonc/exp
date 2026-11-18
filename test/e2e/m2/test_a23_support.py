"""Intent defaults the admin UI's add-host wizard sends (manager/ui/src/lib/intent.ts defaultIntent)."""

from __future__ import annotations

from typing import Any


def default_intent(shape: str, host_name: str) -> dict[str, Any]:
    if shape == "collector":
        return {
            "retention": {"metrics_days": 30, "records_days": 7},
            "alerts": {
                "enabled": True,
                "voice": "sysadmin",
                "hold_down_s": 20,
                "hold_back_s": 60,
                "reopen_s": 300,
                "calm_s": 600,
            },
        }
    if shape == "dashboard":
        return {
            "title": f"HPE EXP - {host_name}"[:128],
            "auth": {"session_hours": 12, "local_users": True, "noc_tokens": True},
            "tls": {"mode": "self_signed"},
        }
    raise ValueError(shape)

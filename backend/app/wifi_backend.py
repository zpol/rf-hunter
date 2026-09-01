"""Wi-Fi hardware backend stub — Pineapple / monitor-mode adapters (Phase 2)."""

from __future__ import annotations

import os
from typing import Any


PINEAPPLE_URL = os.environ.get("RF_HUNTER_PINEAPPLE_URL", "").strip()


class WifiHardwareBackend:
    """
    Placeholder for lab hardware that can execute active Wi-Fi assessments.
    Phase 1: always unavailable. Phase 2: bridge to Hak5 Pineapple REST/SSH
    via RF_HUNTER_PINEAPPLE_URL.
    """

    def status(self) -> dict[str, Any]:
        available = bool(PINEAPPLE_URL)
        return {
            "available": False,  # Phase 1: never execute via hardware
            "configured": available,
            "backend": "pineapple" if available else "none",
            "url_set": available,
            "message": (
                "Pineapple URL configured but active control is Phase 2 — not executed"
                if available
                else "No lab Wi-Fi hardware backend (set RF_HUNTER_PINEAPPLE_URL later)"
            ),
        }

    def capabilities(self) -> dict[str, Any]:
        st = self.status()
        return {
            **st,
            "supports": [],  # e.g. future: ["recon", "rogue_ap_lab"] — not enabled
        }


wifi_hardware = WifiHardwareBackend()

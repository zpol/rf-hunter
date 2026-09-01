from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class DetectedDevice:
    id: str
    device_type_id: str
    device_type_name: str
    radio: str
    freq_mhz: float | None = None
    mac: str | None = None
    name: str | None = None
    rssi_dbm: float | None = None
    snr_db: float | None = None
    power_dbm: float | None = None
    bandwidth_hz: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "device_type_id": self.device_type_id,
            "device_type_name": self.device_type_name,
            "radio": self.radio,
            "freq_mhz": self.freq_mhz,
            "mac": self.mac,
            "name": self.name,
            "rssi_dbm": self.rssi_dbm,
            "snr_db": self.snr_db,
            "power_dbm": self.power_dbm,
            "bandwidth_hz": self.bandwidth_hz,
            "metadata": self.metadata,
            "raw": self.raw,
            "detected_utc": datetime.now(timezone.utc).isoformat(),
        }

from __future__ import annotations

import asyncio
import re
from typing import Any

from .models import DetectedDevice
from . import fingerprint as fp_mod

# Legacy tiny table kept as last-resort; real OUI DB is in data/fp/oui.json
OUI_HINTS = {
    "38:54:39": "LG Electronics",
    "E0:03:6B": "Samsung",
    "4C:91:57": "Unknown POS/OEM",
    "10:5A:17": "Tuya Smart",
    "FC:04:1C": "Espressif",
    "DC:23:4D": "Espressif",
    "D9:A0:00": "ProtoArc / HID OEM",
    "60:AB:D2": "Bose",
    "66:C6:D2": "Epson",
}

TUYA_UUIDS = {"0000fd50", "0000a201"}
SENSOR_UUIDS = {"0000180a", "0000180f", "0000181a", "00001809"}


def _oui_hint(mac: str) -> str:
    return fp_mod.lookup_oui(mac) or OUI_HINTS.get(mac.upper()[:8], "") or ""


def _mfg_map(adv) -> dict[str, str]:
    return {hex(k): v.hex() for k, v in (adv.manufacturer_data or {}).items()}


def _looks_samsung(name: str, mfg: dict[str, str]) -> bool:
    if re.search(r"(?i)\[TV\]|samsung|UE\d{2}|Q\d{2}\s*Series|Tizen|Washer|Fridge", name or ""):
        return True
    return "0x75" in mfg or "0x0075" in mfg


def _looks_tuya_name(name: str) -> bool:
    n = (name or "").strip()
    return n.upper() == "TY" or n.lower().startswith("tuya") or n.lower().startswith("ty-")


async def scan_ble(duration_s: float, device_type: dict[str, Any]) -> list[DetectedDevice]:
    try:
        from bleak import BleakScanner
    except ImportError:
        return []

    devices = await BleakScanner.discover(timeout=duration_s, return_adv=True)
    results: list[DetectedDevice] = []
    profile = device_type.get("attack_profile", "ble_generic")

    for addr, (dev, adv) in devices.items():
        name = dev.name or ""
        uuids = [u.lower().replace("-0000-1000-8000-00805f9b34fb", "")[:8]
                 for u in (adv.service_uuids or [])]
        uuids_full = list(adv.service_uuids or [])
        mfg = _mfg_map(adv)
        sd = {str(k): v.hex() for k, v in (adv.service_data or {}).items()}
        samsungish = _looks_samsung(name, mfg)

        has_tuya_uuid = any("fd50" in u.lower() or "a201" in u.lower() for u in uuids_full)
        is_tuya = profile == "tuya_ble" and (
            has_tuya_uuid or _looks_tuya_name(name)
        )
        # Never classify Samsung SmartThings ads as Tuya
        if samsungish and not has_tuya_uuid:
            is_tuya = False

        is_sensor = profile == "ble_generic" and any(
            any(s in u for s in SENSOR_UUIDS) for u in uuids
        )
        is_av = profile in ("bt_av", "samsung_tv") and (
            samsungish
            or "tv" in name.lower()
            or "speaker" in name.lower()
            or any("110a" in u or "110b" in u or "110c" in u for u in uuids_full)
        )

        if profile == "tuya_ble" and not is_tuya:
            continue
        if profile == "ble_generic" and not is_sensor and not uuids_full and not name:
            continue
        if profile in ("bt_av", "samsung_tv") and not is_av and not name:
            continue

        import uuid as uuid_mod

        # Prefer smart_tv typing when Samsung TV-shaped, even if catalog row is tuya_ble
        out_type_id = device_type["id"]
        out_type_name = device_type["name"]
        out_profile = profile
        if samsungish and not has_tuya_uuid:
            out_type_id = "smart_tv_bt"
            out_type_name = "Smart TV / Audio BT"
            out_profile = "samsung_tv"

        meta = {
            "oui_hint": _oui_hint(addr),
            "service_uuids": uuids_full,
            "manufacturer_data": mfg,
            "service_data": sd,
            "connectable": adv.connectable if hasattr(adv, "connectable") else None,
            "tx_power": adv.tx_power if hasattr(adv, "tx_power") else None,
            "attack_profile": out_profile,
            "tuya_detected": has_tuya_uuid,
        }
        if samsungish:
            meta["samsung_family"] = True

        results.append(
            DetectedDevice(
                id=str(uuid_mod.uuid4())[:8],
                device_type_id=out_type_id,
                device_type_name=out_type_name,
                radio="ble",
                mac=addr,
                name=name or "(anonymous)",
                rssi_dbm=float(adv.rssi),
                metadata=meta,
                raw={"advertisement": {"local_name": name}},
            )
        )

    # No more "all named devices are Tuya" fallback — that mis-tagged every Samsung TV.
    # Optional: only TY*/tuya names without UUID still count (handled above).

    for d in results:
        fp = fp_mod.identify(d.to_dict())
        d.metadata = dict(d.metadata or {})
        d.metadata["fingerprint"] = fp
        if fp.get("oui_vendor"):
            d.metadata["oui_hint"] = fp["oui_vendor"]
        # Post-FP correction: samsung_tv rule wins over tuya catalog residue
        if str(fp.get("matched_rule") or "").startswith("samsung") or (
            str(fp.get("vendor") or "").lower().startswith("samsung")
        ):
            if not d.metadata.get("tuya_detected"):
                d.device_type_id = "smart_tv_bt"
                d.device_type_name = "Smart TV / Audio BT"
                d.metadata["attack_profile"] = "samsung_tv"
                d.metadata["samsung_family"] = True

    return sorted(results, key=lambda d: d.rssi_dbm or -999, reverse=True)


def run_ble_scan_sync(duration_s: float, device_type: dict) -> list[DetectedDevice]:
    return asyncio.run(scan_ble(duration_s, device_type))

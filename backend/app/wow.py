"""Wow-factor ranking for lab demos — which profiles look impressive on stage."""

from __future__ import annotations

from typing import Any

# Higher = more demo impact in an authorized lab walkthrough
WOW_PROFILES: dict[str, dict[str, Any]] = {
    "tuya_ble": {
        "score": 95,
        "tier": "wow",
        "headline": "Tuya BLE pairing / cloud token class",
        "demo": "Connect during EZ mode → GATT surface → WiFi/cloud creds narrative",
    },
    "samsung_tv": {
        "score": 96,
        "tier": "wow",
        "headline": "Samsung TV — BLE identity + LAN remote control",
        "demo": "Attack: MAC-in-mfg · GATT map · SSDP/:8001 · KEY_VOLDOWN lab proof",
    },
    "ble_generic": {
        "score": 80,
        "tier": "wow",
        "headline": "BLE sensor GATT — unauth read/write",
        "demo": "Deep dive + Attack: list writable chars / open reads",
    },
    "bt_av": {
        "score": 88,
        "tier": "wow",
        "headline": "Smart TV / AV BLE surface",
        "demo": "Prefer samsung_tv Attack — identity leak + LAN :8001 control",
    },
    "ism_433": {
        "score": 88,
        "tier": "wow",
        "headline": "Garage/gate remote — decode + replay surface",
        "demo": "Press button → rtl_433 decode → IQ replay prep",
    },
    "ism_315": {
        "score": 85,
        "tier": "wow",
        "headline": "US remote / keyfob — decode + replay",
        "demo": "Same as 433: capture on press, show plaintext frames",
    },
    "alarm_869": {
        "score": 65,
        "tier": "solid",
        "headline": "Alarm CW/FSK — trigger capture",
        "demo": "Monitor while arming sensor; show burst overlay",
    },
    "tpms_433": {
        "score": 55,
        "tier": "solid",
        "headline": "TPMS EU — decode pressure / temp / ID",
        "demo": "Deep dive while wheel moves → rtl_433 plaintext",
    },
    "tpms_315": {
        "score": 55,
        "tier": "solid",
        "headline": "TPMS US 315 — decode pressure / temp / ID",
        "demo": "Deep dive @ ~315 MHz while sensor TX",
    },
    "lora_eu": {"score": 35, "tier": "niche", "headline": "LoRa presence", "demo": "Detect only"},
    "ism_868": {"score": 45, "tier": "solid", "headline": "Home automation 868", "demo": "Capture bursts"},
    "cw_telemetry": {"score": 30, "tier": "niche", "headline": "CW telemetry", "demo": "Spectrum only"},
    "fm_voice": {"score": 25, "tier": "niche", "headline": "PMR voice", "demo": "Low demo value"},
    "dect": {"score": 30, "tier": "niche", "headline": "DECT base", "demo": "Presence"},
    "lband_video": {"score": 50, "tier": "solid", "headline": "Wireless AV", "demo": "Strong RF visual"},
    "ism_24": {"score": 35, "tier": "niche", "headline": "2.4 GHz soup", "demo": "Crowded band"},
    "spectrum_survey": {
        "score": 60,
        "tier": "solid",
        "headline": "Full-spectrum survey hit",
        "demo": "Focus → deep dive on strong / catalog-hinted peaks",
    },
    "adsb_1090": {
        "score": 92,
        "tier": "wow",
        "headline": "ADS-B aircraft — live position on map",
        "demo": "Select ADS-B → See on map · callsign / ICAO / alt",
    },
    "ais_marine": {
        "score": 88,
        "tier": "wow",
        "headline": "AIS vessel traffic",
        "demo": "Marine VHF presence → map when MMSI decoded",
    },
    "fpv_58": {
        "score": 78,
        "tier": "wow",
        "headline": "FPV 5.8 GHz video TX",
        "demo": "Strong carrier in race band — PortaPack FPV Detect class",
    },
    "aprs_vhf": {"score": 55, "tier": "solid", "headline": "APRS packet", "demo": "VHF burst presence"},
    "pocsag": {"score": 60, "tier": "solid", "headline": "POCSAG pager", "demo": "UHF/VHF decode path"},
    "acars_vhf": {"score": 70, "tier": "solid", "headline": "ACARS VHF", "demo": "Aviation datalink presence"},
    "epirb_406": {"score": 75, "tier": "wow", "headline": "EPIRB/ELT 406", "demo": "Distress beacon band"},
    "weather_433": {"score": 50, "tier": "solid", "headline": "Weather sensors", "demo": "rtl_433 class decode"},
}


def profile_of(device: dict[str, Any]) -> str:
    meta = device.get("metadata") or {}
    return meta.get("attack_profile") or device.get("attack_profile") or "generic"


def wow_info(device: dict[str, Any]) -> dict[str, Any]:
    from . import risk as risk_mod

    profile = profile_of(device)
    info = dict(WOW_PROFILES.get(profile) or {
        "score": 20,
        "tier": "niche",
        "headline": f"Profile `{profile}`",
        "demo": "Generic probe",
    })
    info["profile"] = profile
    # Boost if triage already found critical
    risk = device.get("risk") or {}
    sev = (risk.get("severity") or device.get("risk_status") or "").lower()
    if sev in ("critical", "vulnerable"):
        info["score"] = min(100, int(info["score"]) + 15)
        info["tier"] = "wow"
    elif sev == "high":
        info["score"] = min(100, int(info["score"]) + 8)
        if info["tier"] == "niche":
            info["tier"] = "solid"
    if (device.get("metadata") or {}).get("tuya_detected"):
        info["score"] = max(info["score"], 95)
        info["tier"] = "wow"
        info["headline"] = "Tuya fingerprint on air"

    # Jury pillars: identity leak + writable GATT
    if risk_mod.has_identity_leak_finding(risk) or risk_mod.detect_mac_in_manufacturer_data(device):
        info["score"] = min(100, max(int(info["score"]), 88) + 5)
        info["tier"] = "wow"
        if "Tuya" not in (info.get("headline") or ""):
            info["headline"] = "MAC leaked in manufacturer_data"
            info["demo"] = "Focus → Advertisement hex highlight · privacy finding"
    wcount = risk_mod.count_writable_from_risk(risk)
    if wcount:
        info["score"] = min(100, max(int(info["score"]), 90) + 5)
        info["tier"] = "wow"
        info["headline"] = f"{wcount} writable GATT characteristic(s)"
        info["demo"] = "Deep dive / Attack → writable surface"

    # Demote spectrum FPs so they don't float to the top of WOW sorts
    q = ((device.get("metadata") or {}).get("quality") or {})
    tier = str(q.get("tier") or "")
    if tier == "noise" or q.get("fp_likely"):
        info["score"] = min(int(info["score"]), 28)
        if info["tier"] == "wow":
            info["tier"] = "niche"
        info["headline"] = f"Low confidence · {q.get('summary') or 'likely FP'}"
    elif tier == "suspect":
        info["score"] = min(int(info["score"]), 48)
        if info["tier"] == "wow":
            info["tier"] = "solid"
    elif tier == "confirmed":
        info["score"] = min(100, int(info["score"]) + 6)

    return info


def enrich(device: dict[str, Any]) -> dict[str, Any]:
    from . import correlate
    from . import quality as quality_mod
    from . import wifi_scanner as wifi_mod

    try:
        aps = wifi_mod.wifi.snapshot()
    except Exception:
        aps = []
    out = correlate.enrich_device_full(device, aps)
    out = quality_mod.attach_quality(out)
    out["wow"] = wow_info(out)
    return out


def wow_catalog_type_ids() -> list[str]:
    """Device type ids worth pre-selecting for a wow demo wardrive."""
    return [
        "tuya_ble",
        "ble_sensors",
        "smart_tv_bt",
        "garage_433",
        "garage_315",
        "alarm_869",
    ]


def wow_ble_type_ids() -> list[str]:
    """BLE-only types for contest Demo Mode (no garage/alarm RF noise)."""
    return [
        "tuya_ble",
        "ble_sensors",
        "smart_tv_bt",
    ]

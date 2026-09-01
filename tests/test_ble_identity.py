"""BLE identity leak (MAC-in-mfg) and Tuya fingerprint gating."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("RF_HUNTER_CAPTURES", str(ROOT.parent / "captures" / "rf-hunter-v2"))

from backend.app import export as export_mod  # noqa: E402
from backend.app import risk as risk_mod  # noqa: E402
from backend.app import wow as wow_mod  # noqa: E402


def _samsung_like_device(mac: str = "F8:3F:51:8A:7A:B3") -> dict:
    # MAC hex embedded in manufacturer payload (common Samsung TV pattern)
    mac_hex = mac.replace(":", "").lower()
    return {
        "radio": "ble",
        "mac": mac,
        "name": "[TV] Samsung test",
        "device_type_id": "smart_tv_bt",
        "metadata": {
            "attack_profile": "bt_av",
            "manufacturer_data": {"0x75": f"0100{mac_hex}aabb"},
        },
    }


def test_detect_mac_in_manufacturer_data_positive():
    hit = risk_mod.detect_mac_in_manufacturer_data(_samsung_like_device())
    assert hit is not None
    assert hit["company_id"] == "0x75"
    assert hit["match_hex"] == "f83f518a7ab3"
    assert hit["byte_reversed"] is False


def test_detect_mac_in_manufacturer_data_reversed():
    mac = "AA:BB:CC:DD:EE:FF"
    rev = "ffeeddccbbaa"
    d = {
        "radio": "ble",
        "mac": mac,
        "metadata": {"manufacturer_data": {"0x1": f"00{rev}99"}},
    }
    hit = risk_mod.detect_mac_in_manufacturer_data(d)
    assert hit is not None
    assert hit["byte_reversed"] is True


def test_detect_mac_in_manufacturer_data_negative():
    d = {
        "radio": "ble",
        "mac": "11:22:33:44:55:66",
        "metadata": {"manufacturer_data": {"0x75": "deadbeefcafebabe"}},
    }
    assert risk_mod.detect_mac_in_manufacturer_data(d) is None


def test_assess_risk_quick_emits_identity_finding():
    r = risk_mod.assess_risk_quick(_samsung_like_device())
    titles = [f["finding"] for f in r["findings"]]
    assert any("manufacturer_data" in t for t in titles)
    assert r["severity"] in ("high", "critical", "medium")
    assert risk_mod.has_identity_leak_finding(r)


def test_tuya_gating_no_false_critical_on_catalog_only():
    """Mis-tagged Continuity-class: catalog tuya_ble without fingerprint → not Tuya critical."""
    d = {
        "radio": "ble",
        "mac": "5A:FC:5C:C6:FE:12",
        "device_type_id": "tuya_ble",
        "metadata": {
            "attack_profile": "tuya_ble",
            "tuya_detected": False,
            "service_uuids": ["7905f431-b5ce-4e99-a40f-4b1e122d00d0"],
        },
    }
    assert risk_mod.has_tuya_fingerprint(d) is False
    r = risk_mod.assess_risk_quick(d)
    titles = [f["finding"] for f in r["findings"]]
    assert "Tuya BLE fingerprint" not in titles


def test_tuya_gating_with_fd50():
    d = {
        "radio": "ble",
        "mac": "AA:BB:CC:00:11:22",
        "metadata": {
            "attack_profile": "ble_generic",
            "service_uuids": ["0000fd50-0000-1000-8000-00805f9b34fb"],
        },
    }
    assert risk_mod.has_tuya_fingerprint(d) is True
    r = risk_mod.assess_risk_quick(d)
    assert any(f["finding"] == "Tuya BLE fingerprint" for f in r["findings"])
    assert r["severity"] == "critical"


def test_wow_ble_type_ids_no_garage():
    ids = wow_mod.wow_ble_type_ids()
    assert ids == ["tuya_ble", "ble_sensors", "smart_tv_bt"]
    assert "garage_433" not in ids


def test_wow_boost_identity_leak():
    d = _samsung_like_device()
    d["risk"] = risk_mod.assess_risk_quick(d)
    info = wow_mod.wow_info(d)
    assert info["tier"] == "wow"
    assert info["score"] >= 88


def test_export_identity_columns():
    d = _samsung_like_device()
    d["risk"] = risk_mod.assess_risk_quick(d)
    d["key"] = "ble:F8:3F:51:8A:7A:B3"
    csv_text = export_mod.tracker_to_csv([d])
    assert "identity_leak" in csv_text.splitlines()[0]
    assert "writable_gatt_count" in csv_text
    assert "True" in csv_text or "true" in csv_text.lower()
    js = export_mod.tracker_to_json([d])
    assert js["devices"][0]["identity_leak"] is True


def test_assess_risk_quick_tpms_empty_not_high():
    d = {
        "radio": "hackrf",
        "freq_mhz": 433.92,
        "snr_db": 20,
        "device_type_id": "tpms_eu",
        "metadata": {
            "attack_profile": "tpms_433",
            "classification": "CW likely",
            "live_decode": {"ok": False, "kind": "tpms", "message": "No TPMS frames"},
        },
    }
    r = risk_mod.assess_risk_quick(d)
    assert r["severity"] in ("low", "medium")
    titles = " ".join(f["finding"] for f in r["findings"]).lower()
    assert "no frames" in titles or "cw" in titles or "candidate" in titles


def test_assess_risk_quick_uhf_live_ok_high():
    d = {
        "radio": "hackrf",
        "freq_mhz": 1709.3,
        "snr_db": 26,
        "device_type_id": "telemetry_1690",
        "metadata": {
            "attack_profile": "cw_telemetry",
            "live_decode": {"ok": True, "kind": "uhf", "message": "FM/FSK · ~515kbaud"},
        },
    }
    r = risk_mod.assess_risk_quick(d)
    assert r["severity"] in ("high", "critical")
    assert any("UHF" in f["finding"] or "telemetry" in f["finding"].lower() for f in r["findings"])


def test_assess_risk_quick_mac_in_mfg_samsung():
    d = {
        "radio": "ble",
        "mac": "8C:79:F5:0F:4C:77",
        "name": "[TV] tele habitacion",
        "device_type_id": "ble_sensors",
        "metadata": {
            "attack_profile": "ble_generic",
            "manufacturer_data": {
                "0x75": "42040180608c79f50f4c778e79f50f4c7601000000000000"
            },
        },
    }
    r = risk_mod.assess_risk_quick(d)
    assert any("manufacturer_data" in f["finding"] for f in r["findings"])
    assert r["severity"] in ("high", "critical", "medium")

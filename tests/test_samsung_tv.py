"""Samsung TV classification + attack gating."""

from __future__ import annotations

from backend.app import risk as risk_mod
from backend.app import samsung_tv as samsung_mod
from backend.app.fingerprint import identify


def _tv_device():
    return {
        "radio": "ble",
        "mac": "80:8A:BD:90:48:E9",
        "name": "[TV] Samsung Q74AA 65 TV",
        "device_type_id": "tuya_ble",  # legacy mis-tag
        "metadata": {
            "attack_profile": "tuya_ble",
            "tuya_detected": False,
            "manufacturer_data": {
                "0x75": "421f2000022b00808abd9048e9",
            },
            "service_uuids": [],
        },
    }


def test_samsung_tv_not_tuya_fingerprint():
    d = _tv_device()
    assert risk_mod.has_tuya_fingerprint(d) is False
    assert samsung_mod.is_samsung_tv(d) is True
    assert samsung_mod.is_samsung_family(d) is True


def test_samsung_fingerprint_company_and_name():
    d = _tv_device()
    fp = identify(d)
    assert str(fp.get("vendor") or "").lower().startswith("samsung")
    assert fp.get("matched_rule") in ("samsung_tv", "samsung_company")


def test_mac_in_mfg_vector():
    d = _tv_device()
    vecs = samsung_mod.ble_identity_vectors(d)
    names = [v["name"] for v in vecs]
    assert "samsung_mac_in_mfg" in names or "samsung_ble_advert" in names


def test_attack_is_tuya_gate_matches_risk():
    """Regression: attack must not treat attack_profile=tuya_ble as Tuya."""
    d = _tv_device()
    assert risk_mod.has_tuya_fingerprint(d) is False
    # Simulate old buggy predicate
    meta = d["metadata"]
    buggy = meta.get("tuya_detected") or "tuya" in str(meta).lower()
    assert buggy is True  # documents why the old bug fired
    assert risk_mod.has_tuya_fingerprint(d) is False

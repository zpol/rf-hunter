"""Wi-Fi assessment catalog + parser tests."""

from __future__ import annotations

from backend.app import attack, wifi_assess, wifi_backend
from backend.app.wifi_scanner import parse_iw_scan


SAMPLE_IW = """
BSS aa:bb:cc:dd:ee:01(on wlan1)
	freq: 2462
	capability: ESS ShortPreamble ShortSlotTime (0x0401)
	signal: -55.00 dBm
	SSID: lab-open-mistake
	DS Parameter set: channel 11
BSS aa:bb:cc:dd:ee:02(on wlan1)
	freq: 2437
	capability: ESS Privacy (0x0411)
	signal: -62.00 dBm
	SSID: lab-wpa2
	RSN:	 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: PSK
		 * Capabilities: 16-PTKSA-RC 1-GTKSA-RC (0x000c)
	WPS:	 * Version: 1.0
		 * Wi-Fi Protected Setup State: 2 (Configured)
BSS aa:bb:cc:dd:ee:03(on wlan1)
	freq: 5180
	capability: ESS Privacy (0x0411)
	signal: -70.00 dBm
	SSID: 
	RSN:	 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: SAE
		 * Capabilities: MFPC MFPR
"""


def test_parse_iw_security_flags():
    aps = parse_iw_scan(SAMPLE_IW)
    assert len(aps) == 3
    by = {a["bssid"]: a for a in aps}

    a1 = by["AA:BB:CC:DD:EE:01"]
    assert a1["ssid"] == "lab-open-mistake"
    assert a1["security_family"] == "open"
    assert a1["security"] == "open"

    a2 = by["AA:BB:CC:DD:EE:02"]
    assert a2["wifi_ies"]["rsn"] is True
    assert a2["wifi_ies"]["psk"] is True
    assert a2["wps"] is True
    assert a2["security_family"] == "wpa2"

    a3 = by["AA:BB:CC:DD:EE:03"]
    assert a3["hidden_ssid"] is True
    assert a3["wifi_ies"]["sae"] is True
    assert a3["security_family"] == "wpa3"
    assert a3["pmf"] is True


def test_catalog_loads():
    tech = wifi_assess.load_catalog()
    assert len(tech) >= 10
    ids = {t["id"] for t in tech}
    assert "open_network" in ids
    assert "krack_class" in ids
    assert "evil_twin_risk" in ids


def test_assess_open_and_wps():
    device = {
        "radio": "wifi",
        "mac": "AA:BB:CC:DD:EE:02",
        "name": "lab-wpa2",
        "key": "wifi:AA:BB:CC:DD:EE:02",
        "metadata": {
            "security": "WPA2",
            "security_family": "wpa2",
            "channel": 6,
            "wps": True,
            "wifi_ies": {
                "rsn": True,
                "psk": True,
                "wps": True,
                "pmf": None,
                "sae": False,
                "privacy": True,
            },
        },
        "vendor": "Test Vendor",
    }
    vectors = wifi_assess.assess_ap(device)
    names = {v["name"] for v in vectors}
    assert "wifi_inventory" in names
    assert "wps_exposure" in names
    assert "psk_offline_class" in names
    assert "krack_class" in names
    # pineapple-marked techniques present but not executed
    twin = next(v for v in vectors if v["name"] == "evil_twin_risk")
    assert twin.get("executed") is False
    assert twin.get("hardware") == "pineapple"


def test_attack_device_wifi(tmp_path, monkeypatch):
    monkeypatch.setenv("RF_HUNTER_CAPTURES", str(tmp_path))
    # reload CAPTURES path used inside attack module
    import backend.app.attack as atk

    monkeypatch.setattr(atk, "CAPTURES", tmp_path)
    device = {
        "radio": "wifi",
        "mac": "11:22:33:44:55:66",
        "name": "guest",
        "key": "wifi:11:22:33:44:55:66",
        "metadata": {
            "security": "open",
            "security_family": "open",
            "channel": 1,
            "wifi_ies": {"privacy": False},
        },
    }
    res = atk.attack_device(device)
    assert res["profile"] == "wifi_ap"
    assert res.get("assessment_only") is True
    assert res["exploitability"] in ("HIGH", "MEDIUM", "LOW")
    assert any(v["name"] == "open_network" for v in res["vectors"])
    assert (tmp_path / res["attack_id"] / "attack_report.json").is_file()


def test_wifi_backend_stub():
    st = wifi_backend.wifi_hardware.status()
    assert st["available"] is False
    caps = wifi_backend.wifi_hardware.capabilities()
    assert caps["supports"] == []

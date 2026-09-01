"""Swiss-watch isolation: categories, keys, and UI Wi‑Fi mix rules."""

from __future__ import annotations

from backend.app import catalog
from backend.app.tracker import DeviceTracker, device_key


def test_catalog_types_have_unique_ids_and_categories():
    types = catalog.get_device_types()
    cats = {c["id"] for c in catalog.get_categories()}
    ids = [t["id"] for t in types]
    assert len(ids) == len(set(ids)), "duplicate device_type ids"
    for t in types:
        assert t.get("category") in cats, f"{t['id']} bad category {t.get('category')}"
        assert t.get("radio") in ("hackrf", "ble", "adsb", "ais", "wifi") or t.get("radio")


def test_device_key_isolates_same_freq_different_types():
    a = {"radio": "hackrf", "freq_mhz": 433.92, "device_type_id": "garage_433"}
    b = {"radio": "hackrf", "freq_mhz": 433.92, "device_type_id": "weather_433"}
    c = {"radio": "hackrf", "freq_mhz": 433.92, "device_type_id": "tpms_eu"}
    assert device_key(a) != device_key(b) != device_key(c)
    assert device_key(a).endswith(":garage_433")
    assert "wifi" not in device_key(a)


def test_ble_and_rf_keys_never_collide():
    ble = {"radio": "ble", "mac": "AA:BB:CC:DD:EE:FF", "device_type_id": "ble_sensors"}
    rf = {"radio": "hackrf", "freq_mhz": 868.3, "device_type_id": "lora_eu868"}
    assert device_key(ble).startswith("ble:")
    assert device_key(rf).startswith("rf:")
    assert device_key(ble) != device_key(rf)


def test_tracker_upsert_keeps_types_separate():
    tr = DeviceTracker()
    tr.clear()
    tr.upsert({
        "radio": "hackrf",
        "freq_mhz": 868.3,
        "device_type_id": "lora_eu868",
        "device_type_name": "LoRa",
        "power_dbm": -40,
        "snr_db": 15,
    })
    tr.upsert({
        "radio": "hackrf",
        "freq_mhz": 868.3,
        "device_type_id": "ism_868_domotica",
        "device_type_name": "Domotica",
        "power_dbm": -38,
        "snr_db": 16,
    })
    snap = tr.snapshot()
    types = {d["device_type_id"] for d in snap}
    assert types == {"lora_eu868", "ism_868_domotica"}
    assert len(snap) == 2


def test_tracker_never_stores_live_wifi_ap_as_rf():
    """Live iw APs use wifi:BSSID keys — never rf:… collisions with spectrum types."""
    wifi = {
        "radio": "wifi",
        "bssid": "11:22:33:44:55:66",
        "freq_mhz": 2437,
        "device_type_id": "wifi_ap",
        "name": "TestSSID",
    }
    spectrum = {"radio": "hackrf", "freq_mhz": 2437.0, "device_type_id": "wifi_24"}
    assert device_key(wifi) == "wifi:11:22:33:44:55:66"
    assert device_key(spectrum).startswith("rf:")
    assert device_key(wifi) != device_key(spectrum)


def _wifi_list_wanted(filters: dict) -> bool:
    """Mirror of frontend wifiListWanted() — keep in sync with app.js."""
    radio = (filters.get("radio") or "").lower()
    if radio == "wifi":
        return True
    if radio and radio != "wifi":
        return False
    t = filters.get("type") or ""
    tl = t.lower()
    if t == "Wi‑Fi AP" or t == "wifi_ap" or "wi-fi" in tl or "wifi" in tl or "wi‑fi" in tl:
        return True
    q = (filters.get("text") or "").strip().lower()
    if q in ("wifi", "wi-fi", "wi‑fi") or q.startswith("wifi:"):
        return True
    return False


def _filter_display(devices: list, wifi_aps: list, filters: dict) -> list:
    """Minimal mirror of filteredDevices Wi‑Fi gating."""
    want_wifi = _wifi_list_wanted(filters)
    wifi_devs = [
        {
            "radio": "wifi",
            "device_type_id": "wifi_ap",
            "device_type_name": "Wi‑Fi AP",
            "name": a.get("ssid") or a.get("bssid"),
            "key": f"wifi:{a.get('bssid')}",
        }
        for a in wifi_aps
    ]
    pool = list(devices)
    if want_wifi:
        pool = pool + wifi_devs

    q = (filters.get("text") or "").strip().lower()
    out = []
    for d in pool:
        is_wifi = (d.get("radio") or "").lower() == "wifi" or d.get("device_type_id") == "wifi_ap"
        if is_wifi and not want_wifi:
            continue
        if filters.get("type") and (d.get("device_type_name") or d.get("device_type_id")) != filters["type"]:
            continue
        if filters.get("radio") and (d.get("radio") or "").lower() != filters["radio"].lower():
            continue
        if q:
            hay = " ".join(
                str(x or "")
                for x in (d.get("name"), d.get("device_type_name"), d.get("device_type_id"), d.get("key"))
            ).lower()
            if q not in hay:
                continue
        out.append(d)
    return out


def test_ui_wifi_hidden_when_browsing_lora():
    devices = [
        {
            "radio": "hackrf",
            "device_type_id": "lora_eu868",
            "device_type_name": "LoRa / LoRaWAN EU868",
            "name": "LoRa 868.300",
            "freq_mhz": 868.3,
        }
    ]
    wifi = [{"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "HomeAP"}]
    # Default filters — Wi‑Fi must NOT mix in
    shown = _filter_display(devices, wifi, {"radio": "", "type": "", "text": ""})
    assert all(d["device_type_id"] != "wifi_ap" for d in shown)
    assert len(shown) == 1
    # Explicit Wi‑Fi radio
    shown_w = _filter_display(devices, wifi, {"radio": "wifi", "type": "", "text": ""})
    assert any(d["device_type_id"] == "wifi_ap" for d in shown_w)
    assert all(d["radio"] == "wifi" for d in shown_w)
    # Type LoRa — still no Wi‑Fi
    shown_t = _filter_display(
        devices, wifi, {"radio": "", "type": "LoRa / LoRaWAN EU868", "text": ""}
    )
    assert len(shown_t) == 1 and shown_t[0]["device_type_id"] == "lora_eu868"
    # Text lora — no Wi‑Fi
    shown_q = _filter_display(devices, wifi, {"radio": "", "type": "", "text": "lora"})
    assert len(shown_q) == 1
    assert shown_q[0]["device_type_id"] == "lora_eu868"


def test_ui_hackrf_radio_filter_excludes_ble_and_wifi():
    devices = [
        {"radio": "hackrf", "device_type_id": "garage_433", "device_type_name": "Garage"},
        {"radio": "ble", "device_type_id": "ble_sensors", "device_type_name": "BLE", "mac": "AA:BB:CC:00:00:01"},
    ]
    wifi = [{"bssid": "11:22:33:44:55:66", "ssid": "X"}]
    shown = _filter_display(devices, wifi, {"radio": "hackrf", "type": "", "text": ""})
    radios = {d["radio"] for d in shown}
    assert radios == {"hackrf"}


def test_every_category_has_at_least_one_type():
    by = {}
    for t in catalog.get_device_types():
        by.setdefault(t["category"], []).append(t["id"])
    for c in catalog.get_categories():
        assert by.get(c["id"]), f"empty category {c['id']}"

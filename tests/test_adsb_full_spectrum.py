from backend.app.adsb_decode import is_adsb_target


def test_full_spectrum_adsb_catalog_hint_is_decodable():
    assert is_adsb_target(
        {
            "device_type_id": "full_spectrum",
            "radio": "hackrf",
            "freq_mhz": 1090.0,
            "metadata": {
                "attack_profile": "spectrum_survey",
                "catalog_hint": {
                    "device_type_id": "adsb_1090",
                    "attack_profile": "adsb_1090",
                },
            },
        }
    )


def test_unhinted_full_spectrum_peak_is_not_adsb():
    assert not is_adsb_target(
        {
            "device_type_id": "full_spectrum",
            "radio": "hackrf",
            "freq_mhz": 1090.0,
            "metadata": {"attack_profile": "spectrum_survey"},
        }
    )


def test_decoded_adsb_device_remains_decodable():
    assert is_adsb_target({"device_type_id": "adsb_1090", "radio": "adsb"})

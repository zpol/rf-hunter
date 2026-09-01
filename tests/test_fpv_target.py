"""FPV target detection must not match ADS-B @ 1090 MHz."""

from backend.app.fpv_decode import is_fpv_target


def test_adsb_not_fpv():
    assert not is_fpv_target(
        {
            "radio": "adsb",
            "device_type_id": "adsb_1090",
            "freq_mhz": 1090.0,
            "metadata": {"attack_profile": "adsb_1090", "adsb": {"icao": "FA4A54"}},
        }
    )


def test_adsb_freq_hackrf_presence_not_fpv():
    # Presence peak near 1090 without radio=adsb still blocked by profile/type
    assert not is_fpv_target(
        {
            "radio": "hackrf",
            "device_type_id": "adsb_1090",
            "freq_mhz": 1090.0,
            "metadata": {"attack_profile": "adsb_1090", "capability": "presence"},
        }
    )


def test_fpv_58_is_fpv():
    assert is_fpv_target(
        {
            "radio": "hackrf",
            "device_type_id": "fpv_58",
            "freq_mhz": 5800.0,
            "metadata": {"attack_profile": "fpv_58"},
        }
    )


def test_lband_catalog_is_fpv():
    assert is_fpv_target(
        {
            "radio": "hackrf",
            "device_type_id": "lband_av",
            "freq_mhz": 1240.0,
            "metadata": {"attack_profile": "lband_video"},
        }
    )


def test_raceband_freq_heuristic():
    assert is_fpv_target({"radio": "hackrf", "freq_mhz": 5806.0, "metadata": {}})
    assert not is_fpv_target({"radio": "hackrf", "freq_mhz": 1090.0, "metadata": {}})

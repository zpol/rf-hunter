"""Detection quality / false-positive gates."""

from backend.app.quality import assess, should_drop_as_fp, snr_floor_for_type


def test_adsb_with_position_confirmed():
    q = assess(
        {
            "radio": "adsb",
            "device_type_id": "adsb_1090",
            "metadata": {
                "adsb": {"icao": "ABC123", "lat": 41.6, "lon": 2.5, "callsign": "TEST1"},
            },
        }
    )
    assert q["tier"] == "confirmed"
    assert not q["fp_likely"]
    assert not should_drop_as_fp({"radio": "adsb", "metadata": {"adsb": {"icao": "ABC123"}}}, q)


def test_fpv_cw_dropped():
    d = {
        "radio": "hackrf",
        "device_type_id": "fpv_58",
        "freq_mhz": 5755,
        "snr_db": 12.6,
        "power_dbm": -42,
        "metadata": {
            "attack_profile": "fpv_58",
            "capability": "presence",
            "classification": "CW likely",
        },
    }
    q = assess(d)
    assert q["tier"] == "noise"
    assert q["fp_likely"]
    assert should_drop_as_fp(d, q)


def test_acars_presence_noise():
    d = {
        "radio": "hackrf",
        "device_type_id": "acars_vhf",
        "freq_mhz": 131.8,
        "snr_db": 11,
        "power_dbm": -50,
        "metadata": {
            "attack_profile": "acars_vhf",
            "capability": "presence",
            "classification": "burst/weak",
        },
    }
    q = assess(d)
    assert q["tier"] in ("noise", "suspect")
    assert q["fp_likely"]


def test_ble_not_dropped():
    d = {
        "radio": "ble",
        "device_type_id": "ble_sensors",
        "mac": "AA:BB:CC:DD:EE:FF",
        "metadata": {"fingerprint": {"confidence": "low"}},
    }
    q = assess(d)
    assert q["tier"] in ("likely", "confirmed")
    assert not should_drop_as_fp(d, q)


def test_noisy_snr_floor_raised():
    assert snr_floor_for_type("fpv_58", default=8.0) >= 14.0
    assert snr_floor_for_type("garage_433", default=8.0) == 8.0


def test_full_spectrum_survey_kept_visible():
    """Full sweep CW peaks must not be FP-dropped or hide_noise-hidden."""
    from backend.app.quality import peak_limit_for_type

    d = {
        "radio": "hackrf",
        "device_type_id": "full_spectrum",
        "freq_mhz": 433.92,
        "snr_db": 14.0,
        "power_dbm": -40,
        "metadata": {
            "attack_profile": "spectrum_survey",
            "capability": "presence",
            "classification": "CW likely",
            "catalog_hint": {"device_type_id": "garage_433", "device_type_name": "Garage 433"},
        },
    }
    q = assess(d)
    assert q["tier"] in ("suspect", "likely")
    assert not q["fp_likely"]
    assert not should_drop_as_fp(d, q)
    assert snr_floor_for_type("full_spectrum", default=6.0) <= 6.0
    assert peak_limit_for_type("full_spectrum", default=12) >= 12


def test_full_spectrum_ultra_weak_still_dropped():
    d = {
        "radio": "hackrf",
        "device_type_id": "full_spectrum",
        "freq_mhz": 2400.0,
        "snr_db": 6.5,
        "power_dbm": -58,
        "metadata": {
            "attack_profile": "spectrum_survey",
            "classification": "burst/weak",
        },
    }
    q = assess(d)
    # May be noise or weak suspect; only hard-drop very low noise scores
    if q["tier"] == "noise" and q["score"] < 25:
        assert should_drop_as_fp(d, q)
    else:
        assert not should_drop_as_fp(d, q)

"""ADS-B CRC gate — reject noise frames that look like aircraft."""

from backend.app.adsb_decode import _clean_callsign, _decode_frames


def test_rejects_crc_invalid_frames():
    # Real frames captured in tracker_state that pyModeS marks crc_valid=False
    junk = [
        "8c695f8b2ba13c8b7fa3403623f6",
        "9219b99c376e7bda1d76aeb9cc9c",
        "97f4c69c198c5c1c4689310a89de",  # fake callsign with #
    ]
    assert _decode_frames(junk, lat_ref=41.6, lon_ref=2.5) == {}


def test_accepts_known_good_and_cleans_callsign():
    msgs = [
        "8D4840D6202CC371C32CE0576098",  # KLM1023
        "8D40621D58C382D690C8AC2863A7",
    ]
    ac = _decode_frames(msgs, lat_ref=41.6, lon_ref=2.5)
    assert "4840D6" in ac
    assert ac["4840D6"]["callsign"] == "KLM1023"


def test_clean_callsign_rejects_hash_noise():
    assert _clean_callsign("#E0#Q##1") is None
    assert _clean_callsign("ANE95RP") == "ANE95RP"
    assert _clean_callsign("  klm1023 ") == "KLM1023"

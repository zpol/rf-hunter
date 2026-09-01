"""ADS-B pyModeS v3 decode enrichment."""

from backend.app.adsb_decode import _decode_frames


def test_decode_callsign_and_position():
    # Known vectors from pyModeS examples
    msgs = [
        "8D4840D6202CC371C32CE0576098",  # KLM1023
        "8D40621D58C382D690C8AC2863A7",  # position + alt
    ]
    ac = _decode_frames(msgs, lat_ref=41.6, lon_ref=2.5)
    assert "4840D6" in ac
    assert ac["4840D6"].get("callsign") == "KLM1023"
    assert "40621D" in ac
    assert ac["40621D"].get("alt_ft") == 38000
    assert ac["40621D"].get("lat") is not None
    assert ac["40621D"].get("lon") is not None
    # rich fields bag present
    assert isinstance(ac["4840D6"].get("fields"), dict)
    assert ac["4840D6"]["fields"].get("callsign") == "KLM1023"

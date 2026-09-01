"""ADS-B tracker must keep altitude/speed across partial Mode-S updates."""

from pathlib import Path

from backend.app.tracker import DeviceTracker


def _fresh_tracker(tmp_path: Path) -> DeviceTracker:
    t = DeviceTracker()
    t._persist_path = tmp_path / "tracker_test.json"
    t._devices.clear()
    t._dirty = False
    return t


def test_adsb_partial_update_keeps_kinematics(tmp_path):
    t = _fresh_tracker(tmp_path)
    t.upsert(
        {
            "radio": "adsb",
            "mac": "ABC123",
            "device_type_id": "adsb_1090",
            "name": "TEST123",
            "lat": 41.6,
            "lon": 2.5,
            "metadata": {
                "geo_source": "signal",
                "adsb": {
                    "icao": "ABC123",
                    "callsign": "TEST123",
                    "lat": 41.6,
                    "lon": 2.5,
                    "alt_ft": 35000,
                    "speed_kts": 420,
                    "track_deg": 270,
                    "messages": 2,
                },
            },
        }
    )
    # Later frame: identity-only (no kinematics) must not wipe prior alt/speed
    out = t.upsert(
        {
            "radio": "adsb",
            "mac": "ABC123",
            "device_type_id": "adsb_1090",
            "name": "TEST123",
            "metadata": {
                "geo_source": "none",
                "adsb": {
                    "icao": "ABC123",
                    "callsign": "TEST123",
                    "messages": 1,
                },
            },
        }
    )
    adsb = (out.get("metadata") or {}).get("adsb") or {}
    assert adsb.get("alt_ft") == 35000
    assert adsb.get("speed_kts") == 420
    assert adsb.get("track_deg") == 270
    assert adsb.get("lat") == 41.6
    assert adsb.get("callsign") == "TEST123"
    assert adsb.get("messages") == 3
    assert out.get("lat") == 41.6
    assert (out.get("metadata") or {}).get("geo_source") == "signal"


def test_adsb_without_position_not_hunter_pinned(tmp_path):
    t = _fresh_tracker(tmp_path)
    out = t.upsert(
        {
            "radio": "adsb",
            "mac": "DEF456",
            "device_type_id": "adsb_1090",
            "name": "ICAO DEF456",
            "metadata": {
                "geo_source": "none",
                "adsb": {"icao": "DEF456", "callsign": "NOFIX1", "messages": 1},
            },
        }
    )
    assert out.get("lat") is None
    assert out.get("lon") is None

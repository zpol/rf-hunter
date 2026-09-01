"""ADS-B kinematics from successive positions."""

from backend.app.tracker import DeviceTracker


def test_position_delta_fills_speed_track(tmp_path):
    t = DeviceTracker()
    t._persist_path = tmp_path / "t.json"
    t._devices.clear()
    t.upsert(
        {
            "radio": "adsb",
            "mac": "AABBCC",
            "device_type_id": "adsb_1090",
            "lat": 41.6,
            "lon": 2.5,
            "metadata": {
                "geo_source": "signal",
                "adsb": {"icao": "AABBCC", "lat": 41.6, "lon": 2.5, "messages": 1},
            },
        }
    )
    # ~10 NM east in 60s ≈ 600 kt — use smaller move: 0.1 deg lat ≈ 11 km in 60s ≈ 360 kt
    # 0.05 deg lat ≈ 5.5 km in 60s ≈ 178 kt
    import time

    key = "adsb:AABBCC"
    with t._lock:
        t._devices[key]["last_seen_ts"] = time.time() - 60.0
    out = t.upsert(
        {
            "radio": "adsb",
            "mac": "AABBCC",
            "device_type_id": "adsb_1090",
            "lat": 41.65,
            "lon": 2.5,
            "metadata": {
                "geo_source": "signal",
                "adsb": {"icao": "AABBCC", "lat": 41.65, "lon": 2.5, "messages": 1},
            },
        }
    )
    adsb = (out.get("metadata") or {}).get("adsb") or {}
    assert adsb.get("speed_kts") is not None
    assert adsb["speed_kts"] > 100
    assert adsb.get("track_deg") is not None
    assert adsb.get("kinematics_source") == "position_delta"

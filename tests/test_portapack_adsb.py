"""ADS-B / PortaPack catalog helpers."""

from backend.app.adsb_decode import _extract_messages, _mag_from_iq_sc8
from backend.app.catalog import get_device_by_id, get_categories
from backend.app.tracker import device_key
import numpy as np


def test_portapack_catalog_types_exist():
    for tid in ("adsb_1090", "ais_marine", "fpv_58", "aprs_vhf", "pocsag_pager", "epirb_406"):
        dt = get_device_by_id(tid)
        assert dt is not None, tid
        assert dt.get("icon")
        assert dt.get("bands")


def test_aviation_maritime_categories():
    ids = {c["id"] for c in get_categories()}
    assert "aviation" in ids
    assert "maritime" in ids


def test_adsb_device_key():
    d = {
        "radio": "adsb",
        "mac": "ABCDEF",
        "device_type_id": "adsb_1090",
        "freq_mhz": 1090.0,
    }
    assert device_key(d) == "adsb:ABCDEF"


def test_mag_and_extract_empty():
    mag = _mag_from_iq_sc8(b"\x00\x00" * 100)
    assert mag.size == 100
    assert _extract_messages(np.zeros(500, dtype=np.float32)) == []

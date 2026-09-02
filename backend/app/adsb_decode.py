"""ADS-B / Mode-S RX via HackRF IQ + pyModeS (PortaPack ADS-B class)."""

from __future__ import annotations

import os
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any

import numpy as np

from .models import DetectedDevice
from . import radio as radio_mod

SAMPLE_RATE = 2_000_000
FREQ_HZ = 1_090_000_000
# Process IQ in short chunks to keep RAM + stop responsive
CHUNK_S = 0.5
HACKRF_SERIAL = os.environ.get("HACKRF_SERIAL", "").strip()


def is_adsb_target(device: dict[str, Any] | None) -> bool:
    """Recognize catalog ADS-B entries and full-sweep peaks hinted as ADS-B."""
    if not device:
        return False
    meta = device.get("metadata") or {}
    hint = meta.get("catalog_hint") or {}
    identifiers = {
        str(device.get("device_type_id") or "").lower(),
        str(meta.get("attack_profile") or "").lower(),
        str(hint.get("device_type_id") or "").lower(),
        str(hint.get("attack_profile") or "").lower(),
    }
    if "adsb_1090" in identifiers:
        return True
    return str(device.get("radio") or "").lower() == "adsb"


def _mag_from_iq_sc8(raw: bytes) -> np.ndarray:
    """HackRF default: interleaved signed int8 I/Q → magnitude."""
    if len(raw) < 4:
        return np.zeros(0, dtype=np.float32)
    iq = np.frombuffer(raw, dtype=np.int8)
    if iq.size % 2:
        iq = iq[:-1]
    i = iq[0::2].astype(np.float32)
    q = iq[1::2].astype(np.float32)
    return np.sqrt(i * i + q * q)


def _capture_iq(
    path: str,
    *,
    duration_s: float,
    lna_db: int,
    vga_db: int,
    stop: threading.Event | None = None,
) -> bool:
    n_samples = int(SAMPLE_RATE * max(0.2, duration_s))
    try:
        capture = radio_mod.capture_iq(
            path, freq_hz=FREQ_HZ, sample_rate=SAMPLE_RATE,
            num_samples=n_samples, lna_db=lna_db, vga_db=vga_db,
            timeout=duration_s + 3.0, stop_event=stop,
        )
        return capture.ok and os.path.exists(path) and os.path.getsize(path) > 10_000
    except Exception:
        return False


def _extract_messages(mag: np.ndarray, threshold: float | None = None) -> list[str]:
    """
    Detect Mode-S preambles in magnitude samples @ 2 Msps and return hex frames.
    Based on dump1090-style preamble + Manchester decode (simplified).
    """
    if mag.size < 480:
        return []
    # Adaptive threshold
    if threshold is None:
        med = float(np.median(mag))
        threshold = med * 1.8 + 8.0

    msgs: list[str] = []
    i = 0
    n = mag.size
    # Preamble peaks at samples 0,2,7,9 (relative) for 2 Msps
    while i < n - 240:
        if mag[i] < threshold:
            i += 1
            continue
        # Preamble check
        if not (
            mag[i] > threshold
            and mag[i + 2] > threshold
            and mag[i + 7] > threshold
            and mag[i + 9] > threshold
            and mag[i + 1] < mag[i]
            and mag[i + 3] < mag[i + 2]
            and mag[i + 8] < mag[i + 7]
            and mag[i + 10] < mag[i + 9]
        ):
            i += 1
            continue

        # Data starts at sample 16 relative to preamble start (dump1090)
        bits: list[int] = []
        ok = True
        base = i + 16
        for b in range(112):
            # Each bit: 1 µs = 2 samples; Manchester high-low = 1
            s0 = base + b * 2
            s1 = s0 + 1
            if s1 >= n:
                ok = False
                break
            bits.append(1 if mag[s0] > mag[s1] else 0)
        if not ok or len(bits) < 56:
            i += 2
            continue

        # Pack to hex (MSB first)
        nbytes = 14 if len(bits) >= 112 else 7
        raw_bits = bits[: nbytes * 8]
        val = 0
        for bit in raw_bits:
            val = (val << 1) | bit
        hexmsg = f"{val:0{nbytes * 2}x}"
        msgs.append(hexmsg)
        i = base + nbytes * 8 * 2  # skip past frame
    return msgs


_BAD_ICAOS = frozenset({"000000", "FFFFFF", "AAAAAA", "ABCABC"})
_CALLSIGN_OK = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ")


def _crc_ok(msg: str, dec: dict[str, Any] | None = None) -> bool:
    """Strict Mode-S CRC — never trust DF17/18 without it (noise → fake ICAOs)."""
    if dec is not None and dec.get("crc_valid") is False:
        return False
    if dec is not None and dec.get("crc_valid") is True:
        return True
    try:
        from pyModeS.util import crc as pms_crc

        return int(pms_crc(msg)) == 0
    except Exception:
        return False


def _clean_callsign(raw: Any) -> str | None:
    if raw is None:
        return None
    s = str(raw).upper().replace("_", " ").strip()
    if not s or any(ch not in _CALLSIGN_OK for ch in s):
        return None
    # Need at least one alphanumeric (reject all-spaces)
    if not any(ch.isalnum() for ch in s):
        return None
    return s


def _plausible_latlon(
    lat: float | None,
    lon: float | None,
    *,
    lat_ref: float | None,
    lon_ref: float | None,
) -> bool:
    if lat is None or lon is None:
        return False
    try:
        lat_f, lon_f = float(lat), float(lon)
    except (TypeError, ValueError):
        return False
    if not (-90.0 <= lat_f <= 90.0 and -180.0 <= lon_f <= 180.0):
        return False
    if lat_ref is None or lon_ref is None:
        return True
    # CPR decode with wrong odd/even pair can land ~anywhere; keep near hunter
    if abs(lat_f - float(lat_ref)) > 8.0 or abs(lon_f - float(lon_ref)) > 10.0:
        return False
    return True


def _decode_frames(
    hex_msgs: list[str],
    *,
    lat_ref: float | None,
    lon_ref: float | None,
) -> dict[str, dict[str, Any]]:
    """Decode Mode-S/ADS-B with pyModeS v3 `decode()` — rich field dict per ICAO."""
    try:
        import pyModeS as pms
    except ImportError:
        return {}

    aircraft: dict[str, dict[str, Any]] = {}
    reference = None
    if lat_ref is not None and lon_ref is not None:
        reference = (float(lat_ref), float(lon_ref))

    for msg in hex_msgs:
        msg = msg.lower().strip()
        if len(msg) not in (14, 28):
            continue
        if not _crc_ok(msg):
            continue
        try:
            dec = pms.decode(msg, reference=reference, full_dict=True)
        except Exception:
            continue
        if not isinstance(dec, dict):
            continue
        if not _crc_ok(msg, dec):
            continue
        df = dec.get("df")
        if df not in (17, 18):
            continue
        icao = str(dec.get("icao") or "").upper()
        if len(icao) != 6 or icao in _BAD_ICAOS:
            continue
        if not all(c in "0123456789ABCDEF" for c in icao):
            continue

        ac = aircraft.setdefault(
            icao,
            {
                "icao": icao,
                "callsign": None,
                "lat": None,
                "lon": None,
                "alt_ft": None,
                "alt_m": None,
                "speed_kts": None,
                "speed_kmh": None,
                "track_deg": None,
                "heading_deg": None,
                "vertical_rate_fpm": None,
                "category": None,
                "wake_vortex": None,
                "squawk": None,
                "emergency_state": None,
                "nac_p": None,
                "sil": None,
                "typecode": None,
                "bds": None,
                "messages": 0,
                "last_msg": msg,
                "fields": {},  # last non-null extras
            },
        )
        ac["messages"] += 1
        ac["last_msg"] = msg

        def _set(dst: str, *keys: str, scale: float | None = None) -> None:
            for k in keys:
                v = dec.get(k)
                if v is None or v == "":
                    continue
                try:
                    if scale is not None:
                        ac[dst] = float(v) * scale
                    else:
                        ac[dst] = v if not isinstance(v, float) else float(v)
                except (TypeError, ValueError):
                    ac[dst] = v
                return

        cs = _clean_callsign(dec.get("callsign"))
        if cs:
            ac["callsign"] = cs
        lat = dec.get("latitude")
        lon = dec.get("longitude")
        if lat is not None and lon is not None:
            try:
                lat_f, lon_f = float(lat), float(lon)
            except (TypeError, ValueError):
                lat_f = lon_f = None  # type: ignore[assignment]
            if lat_f is not None and _plausible_latlon(
                lat_f, lon_f, lat_ref=lat_ref, lon_ref=lon_ref
            ):
                ac["lat"] = lat_f
                ac["lon"] = lon_f
        _set("alt_ft", "altitude")
        if ac.get("alt_ft") is not None:
            try:
                alt = float(ac["alt_ft"])
                if alt < -2000 or alt > 60000:
                    ac["alt_ft"] = None
                else:
                    ac["alt_m"] = round(alt * 0.3048, 1)
            except (TypeError, ValueError):
                ac["alt_ft"] = None
        # velocity — groundspeed preferred, else airspeed
        spd = None
        if dec.get("groundspeed") is not None:
            try:
                spd = float(dec["groundspeed"])
            except (TypeError, ValueError):
                spd = None
        elif dec.get("airspeed") is not None:
            try:
                spd = float(dec["airspeed"])
            except (TypeError, ValueError):
                spd = None
        if spd is not None and 0 <= spd <= 700:
            ac["speed_kts"] = spd
            ac["speed_kmh"] = round(spd * 1.852, 1)
        _set("track_deg", "track", "true_track")
        if ac.get("track_deg") is not None:
            try:
                trk = float(ac["track_deg"]) % 360.0
                ac["track_deg"] = trk
            except (TypeError, ValueError):
                ac["track_deg"] = None
        _set("heading_deg", "heading", "magnetic_heading")
        _set("vertical_rate_fpm", "vertical_rate", "baro_vertical_rate", "inertial_vertical_rate")
        if ac.get("vertical_rate_fpm") is not None:
            try:
                vs = float(ac["vertical_rate_fpm"])
                if abs(vs) > 12000:
                    ac["vertical_rate_fpm"] = None
            except (TypeError, ValueError):
                ac["vertical_rate_fpm"] = None
        _set("category", "category")
        _set("wake_vortex", "wake_vortex")
        _set("squawk", "squawk")
        _set("emergency_state", "emergency_state")
        _set("nac_p", "nac_p")
        _set("sil", "sil")
        _set("typecode", "typecode")
        _set("bds", "bds")

        # Keep a flat dump of interesting non-null fields for UI "all data"
        interesting = (
            "callsign", "latitude", "longitude", "altitude", "groundspeed", "airspeed",
            "track", "heading", "vertical_rate", "category", "wake_vortex", "squawk",
            "emergency_state", "nac_p", "sil", "typecode", "bds", "subtype",
            "selected_altitude", "mach", "roll", "true_airspeed", "indicated_airspeed",
            "baro_pressure_setting", "autopilot", "vnav_mode", "lnav_mode",
            "tcas_operational", "version", "capability_text", "flight_status_text",
        )
        extras = dict(ac.get("fields") or {})
        for k in interesting:
            v = dec.get(k)
            if v is not None and v != "":
                if k == "callsign":
                    v = _clean_callsign(v)
                    if not v:
                        continue
                extras[k] = v
        ac["fields"] = extras

    return aircraft


def listen(
    *,
    duration_s: float = 8.0,
    lna_db: int = 32,
    vga_db: int = 40,
    lat_ref: float | None = None,
    lon_ref: float | None = None,
    stop: threading.Event | None = None,
    device_type: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Capture IQ chunks and return ADS-B aircraft as device dicts."""
    dt = device_type or {}
    deadline = time.time() + max(2.0, float(duration_s))
    all_hex: list[str] = []

    with tempfile.TemporaryDirectory(prefix="adsb_") as tmp:
        while time.time() < deadline:
            if stop and stop.is_set():
                break
            remain = deadline - time.time()
            chunk = min(CHUNK_S, remain)
            if chunk < 0.15:
                break
            path = os.path.join(tmp, "chunk.iq")
            ok = _capture_iq(
                path, duration_s=chunk, lna_db=lna_db, vga_db=vga_db, stop=stop
            )
            if not ok:
                continue
            try:
                raw = open(path, "rb").read()
            except OSError:
                continue
            mag = _mag_from_iq_sc8(raw)
            all_hex.extend(_extract_messages(mag))

    ac_map = _decode_frames(all_hex, lat_ref=lat_ref, lon_ref=lon_ref)
    out: list[dict[str, Any]] = []
    for icao, ac in ac_map.items():
        callsign = (ac.get("callsign") or "").strip() or None
        name = callsign or f"ICAO {icao}"
        wake = ac.get("wake_vortex")
        if wake and "no category" in str(wake).lower():
            wake = None
        if wake:
            name = f"{name} · {wake}" if callsign else name
        cat = ac.get("category")
        if cat in (0, "0", None, ""):
            cat = None
        model = wake or (f"Emitter cat {cat}" if cat is not None else None)
        # Only emit keys we actually know — avoids wiping tracker state with nulls
        adsb_meta: dict[str, Any] = {
            "icao": icao,
            "messages": ac.get("messages") or 1,
            "last_msg": ac.get("last_msg"),
            "fields": ac.get("fields") or {},
        }
        for k, v in (
            ("callsign", callsign),
            ("lat", ac.get("lat")),
            ("lon", ac.get("lon")),
            ("alt_ft", ac.get("alt_ft")),
            ("alt_m", ac.get("alt_m")),
            ("speed_kts", ac.get("speed_kts")),
            ("speed_kmh", ac.get("speed_kmh")),
            ("track_deg", ac.get("track_deg")),
            ("heading_deg", ac.get("heading_deg")),
            ("vertical_rate_fpm", ac.get("vertical_rate_fpm")),
            ("category", cat),
            ("wake_vortex", wake),
            ("model", model),
            ("squawk", ac.get("squawk")),
            ("emergency_state", ac.get("emergency_state")),
            ("nac_p", ac.get("nac_p")),
            ("sil", ac.get("sil")),
            ("typecode", ac.get("typecode")),
            ("bds", ac.get("bds")),
        ):
            if v is not None and v != "":
                adsb_meta[k] = v
        has_pos = ac.get("lat") is not None and ac.get("lon") is not None
        meta = {
            **(dt.get("metadata") or {}),
            "attack_profile": dt.get("attack_profile") or "adsb_1090",
            "capability": "decode",
            "geo_source": "signal" if has_pos else "none",
            "see_on_map": bool(has_pos),
            "adsb": adsb_meta,
            "portapack": "ADS-B",
        }
        power = -45.0
        dev = DetectedDevice(
            id=icao.lower()[:8],
            device_type_id=dt.get("id") or "adsb_1090",
            device_type_name=dt.get("name") or "ADS-B Aircraft",
            radio="adsb",
            freq_mhz=1090.0,
            mac=icao,
            name=name,
            power_dbm=power,
            snr_db=12.0,
            metadata=meta,
            raw={"adsb": ac},
        )
        d = dev.to_dict()
        if ac.get("lat") is not None and ac.get("lon") is not None:
            d["lat"] = float(ac["lat"])
            d["lon"] = float(ac["lon"])
            d["gps"] = {
                "lat": float(ac["lat"]),
                "lon": float(ac["lon"]),
                "alt_m": ac.get("alt_m"),
                "speed_mps": (
                    float(ac["speed_kts"]) * 0.514444 if ac.get("speed_kts") is not None else None
                ),
                "track_deg": ac.get("track_deg"),
                "source": "adsb",
                "fix_utc": datetime.now(timezone.utc).isoformat(),
            }
        out.append(d)
    return out

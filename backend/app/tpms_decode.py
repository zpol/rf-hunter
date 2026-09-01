"""Decode TPMS frames from HackRF IQ via rtl_433 (US 315 / EU 433)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from shutil import which
from typing import Any

import numpy as np

# rtl_433 protocol IDs for common TPMS families (US 315 + EU 433)
TPMS_PROTOCOL_IDS: tuple[int, ...] = (
    59,   # Steelmate
    60,   # Schrader
    82,   # Citroen
    88,   # Toyota
    89,   # Ford
    90,   # Renault
    95,   # Schrader EG53MA4
    110,  # PMV-107J Toyota
    123,  # Jansite TY02S
    140,  # Elantra2012
    156,  # Abarth
    168,  # Schrader SMD3MA4
    180,  # Jansite Solar
    186,  # Hyundai VDO
    201,  # SolarTPMS trucks
    203,  # Porsche
    208,  # AVE
    212,  # Renault 0435R
    225,  # TyreGuard 400
    226,  # Kia
    241,  # EezTire / Carchet
    248,  # Nissan
    252,  # BMW Gen4-5 / Audi / multi-brand
    257,  # BMW Gen2-3
    275,  # GM aftermarket
)


def has_rtl433() -> bool:
    return which("rtl_433") is not None


def is_tpms_target(device: dict[str, Any] | None) -> bool:
    if not device:
        return False
    tid = (device.get("device_type_id") or "").lower()
    profile = ((device.get("metadata") or {}).get("attack_profile") or "").lower()
    return tid in ("tpms_us", "tpms_eu") or profile in ("tpms_315", "tpms_433")


def hackrf_cs8_to_cu8(src: Path, dst: Path) -> Path:
    """hackrf_transfer writes signed int8 IQ; rtl_433 prefers unsigned cu8."""
    raw = np.fromfile(src, dtype=np.int8)
    if raw.size == 0:
        dst.write_bytes(b"")
        return dst
    cu8 = (raw.astype(np.int16) + 128).clip(0, 255).astype(np.uint8)
    cu8.tofile(dst)
    return dst


def decode_tpms_iq(
    iq_path: Path,
    freq_mhz: float,
    sample_rate: int = 2_000_000,
    out_dir: Path | None = None,
) -> dict[str, Any]:
    """
    Run rtl_433 TPMS decoders on a HackRF IQ capture.
    Returns normalized sensors + raw frames.
    """
    result: dict[str, Any] = {
        "ok": False,
        "freq_mhz": float(freq_mhz),
        "sample_rate": sample_rate,
        "frames": [],
        "sensors": [],
        "message": "",
        "rtl433": has_rtl433(),
    }
    if not has_rtl433():
        result["message"] = "rtl_433 not installed"
        return result
    if not iq_path.exists() or iq_path.stat().st_size < 1000:
        result["message"] = "IQ capture missing or too small"
        return result

    work = out_dir or iq_path.parent
    # Filename encodes format + rate + center for rtl_433 auto-detect
    cu8_name = f"g{freq_mhz:.3f}M_{sample_rate}sps.cu8"
    cu8_path = work / cu8_name
    try:
        hackrf_cs8_to_cu8(iq_path, cu8_path)
    except Exception as e:
        result["message"] = f"IQ convert failed: {e}"
        return result

    cmd = [
        "rtl_433",
        "-r", str(cu8_path),
        "-s", str(sample_rate),
        "-f", f"{freq_mhz}M",
        "-F", "json",
        "-M", "level",
        "-M", "time:unix",
    ]
    for rid in TPMS_PROTOCOL_IDS:
        cmd.extend(["-R", str(rid)])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        result["message"] = "rtl_433 timeout"
        return result
    except Exception as e:
        result["message"] = str(e)
        return result

    frames: list[dict[str, Any]] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            frames.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    sensors = _normalize_sensors(frames)
    result["frames"] = frames[:50]
    result["sensors"] = sensors
    result["ok"] = bool(sensors) or bool(frames)
    result["frame_count"] = len(frames)
    result["sensor_count"] = len(sensors)
    result["cu8_file"] = cu8_path.name
    result["stderr_tail"] = (proc.stderr or "")[-300:]

    if sensors:
        result["message"] = f"Decoded {len(sensors)} TPMS sensor(s) from {len(frames)} frame(s)"
    elif frames:
        result["message"] = f"{len(frames)} frame(s) but no TPMS fields parsed"
    else:
        result["message"] = (
            "No TPMS frames — spin the wheel / wait for sensor TX, "
            "or retune closer to 315.000 MHz"
        )
    return result


def _normalize_sensors(frames: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for fr in frames:
        sensor = _normalize_frame(fr)
        if not sensor:
            continue
        sid = str(sensor["id"])
        prev = by_id.get(sid)
        if not prev:
            by_id[sid] = sensor
            continue
        # Keep newest / richest reading
        for k, v in sensor.items():
            if v is not None and v != "":
                prev[k] = v
        prev["frame_count"] = int(prev.get("frame_count") or 1) + 1

    out = list(by_id.values())
    out.sort(key=lambda s: str(s.get("id")))
    return out


def _normalize_frame(fr: dict[str, Any]) -> dict[str, Any] | None:
    model = fr.get("model") or fr.get("type") or fr.get("protocol")
    # Skip non-TPMS if somehow slipped in
    blob = json.dumps(fr).lower()
    if model and "tpms" not in str(model).lower() and "tpms" not in blob and "pressure" not in blob:
        # Still accept if pressure fields exist
        if not any(k in fr for k in ("pressure_PSI", "pressure_kPa", "pressure_bar", "pressure")):
            return None

    sid = fr.get("id")
    if sid is None:
        sid = fr.get("ID") or fr.get("sensor_id")
    if sid is None:
        # last resort: use model+channel
        sid = f"{model or 'unk'}:{fr.get('channel', '?')}"

    pressure_psi = _as_float(fr.get("pressure_PSI") or fr.get("pressure_psi"))
    pressure_kpa = _as_float(fr.get("pressure_kPa") or fr.get("pressure_kpa"))
    pressure_bar = _as_float(fr.get("pressure_bar"))
    if pressure_psi is None and pressure_kpa is not None:
        pressure_psi = round(pressure_kpa * 0.145038, 2)
    if pressure_kpa is None and pressure_psi is not None:
        pressure_kpa = round(pressure_psi / 0.145038, 1)
    if pressure_psi is None and pressure_bar is not None:
        pressure_psi = round(pressure_bar * 14.5038, 2)
        pressure_kpa = round(pressure_bar * 100.0, 1)

    temp_c = _as_float(
        fr.get("temperature_C")
        or fr.get("temp_C")
        or fr.get("temperature")
    )

    return {
        "id": sid,
        "model": model or "TPMS",
        "pressure_psi": pressure_psi,
        "pressure_kpa": pressure_kpa,
        "temperature_c": temp_c,
        "battery_ok": fr.get("battery_ok", fr.get("battery")),
        "flags": fr.get("flags") or fr.get("status"),
        "raw_level": fr.get("mod") or fr.get("snr") or fr.get("rssi"),
        "frame_count": 1,
        "raw": {k: fr[k] for k in list(fr)[:20]},
    }


def _as_float(v: Any) -> float | None:
    if v is None or v == "":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def sensors_summary_lines(tpms: dict[str, Any]) -> list[str]:
    lines = []
    for s in tpms.get("sensors") or []:
        bits = [f"id={s.get('id')}", str(s.get("model") or "TPMS")]
        if s.get("pressure_psi") is not None:
            bits.append(f"{s['pressure_psi']} PSI")
        if s.get("pressure_kpa") is not None:
            bits.append(f"{s['pressure_kpa']} kPa")
        if s.get("temperature_c") is not None:
            bits.append(f"{s['temperature_c']} °C")
        lines.append(" · ".join(bits))
    return lines


def select_tpms_targets(
    devices: list[dict[str, Any]],
    *,
    max_devices: int = 16,
    skip_decoded: bool = True,
    band: str = "all",
) -> list[dict[str, Any]]:
    """
    Rank TPMS tracker hits for bulk decode.
    Prefers freqs near 315.0 (US) / 433.92 (EU), stronger SNR, more hits.
    """
    band = (band or "all").lower()
    nominal = {"tpms_us": 315.0, "tpms_eu": 433.92}
    scored: list[tuple[float, dict[str, Any]]] = []

    for d in devices:
        if not is_tpms_target(d):
            continue
        tid = (d.get("device_type_id") or "").lower()
        if band == "us" and tid != "tpms_us":
            continue
        if band == "eu" and tid != "tpms_eu":
            continue
        if skip_decoded:
            sensors = ((d.get("metadata") or {}).get("tpms_decode") or {}).get("sensors") or []
            if sensors:
                continue

        freq = d.get("freq_mhz")
        if freq is None:
            continue
        freq_f = float(freq)
        center = nominal.get(tid, 315.0 if tid == "tpms_us" else 433.92)
        # Reject absurd outliers far from catalog band
        if tid == "tpms_us" and not (300.0 <= freq_f <= 340.0):
            continue
        if tid == "tpms_eu" and not (420.0 <= freq_f <= 450.0):
            continue

        dist = abs(freq_f - center)
        snr = float(d.get("snr_db") or 0.0)
        level = float(d.get("signal_level") or 0.0)
        hits = float(d.get("hit_count") or 1)
        stale_pen = 8.0 if d.get("stale") else 0.0
        # Higher score = better candidate
        score = (snr * 1.5) + (level * 2.0) + (hits * 0.3) - (dist * 3.0) - stale_pen
        scored.append((score, d))

    scored.sort(key=lambda x: -x[0])
    max_devices = max(1, min(int(max_devices), 40))
    return [d for _, d in scored[:max_devices]]


def tpms_inventory(devices: list[dict[str, Any]]) -> dict[str, Any]:
    """Counts for UI: tracked / decoded / pending."""
    tracked = [d for d in devices if is_tpms_target(d)]
    decoded = [
        d for d in tracked
        if ((d.get("metadata") or {}).get("tpms_decode") or {}).get("sensors")
    ]
    return {
        "tracked": len(tracked),
        "decoded": len(decoded),
        "pending": len(tracked) - len(decoded),
        "us": sum(1 for d in tracked if d.get("device_type_id") == "tpms_us"),
        "eu": sum(1 for d in tracked if d.get("device_type_id") == "tpms_eu"),
    }

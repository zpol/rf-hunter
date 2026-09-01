from __future__ import annotations

import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from . import risk as risk_mod
from . import tpms_decode
from . import tracker as tracker_mod

_DEFAULT_CAPTURES = Path(__file__).resolve().parents[2].parent / "captures" / "rf-hunter-v2"
CAPTURES = Path(os.environ.get("RF_HUNTER_CAPTURES", str(_DEFAULT_CAPTURES)))
HACKRF_SERIAL = os.environ.get("HACKRF_SERIAL", "")


def deep_dive(device: dict[str, Any]) -> dict[str, Any]:
    """Extended analysis — IQ capture, spectrogram stats, BLE GATT + risk assessment."""
    from .radio_gate import exclusive

    dive_id = f"DIVE-{uuid.uuid4().hex[:8]}"
    out_dir = CAPTURES / dive_id
    out_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {
        "dive_id": dive_id,
        "target": device,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "artifacts": [],
        "analysis": {},
    }

    radio = device.get("radio", "hackrf")

    if radio == "ble" and device.get("mac"):
        result["analysis"]["ble"] = _ble_deep_dive(device["mac"], out_dir)
    elif radio == "hackrf" and device.get("freq_mhz"):
        from . import fpv_decode

        is_tpms = tpms_decode.is_tpms_target(device)
        is_fpv = fpv_decode.is_fpv_target(device)
        with exclusive("deep_dive"):
            if is_fpv:
                # Wideband IQ for FM video (not the 2 Msps ISM path)
                fpv = fpv_decode.listen_and_decode(
                    float(device["freq_mhz"]),
                    out_dir,
                    sample_rate=10_000_000,
                    duration_s=0.6,
                    lna_db=40,
                    vga_db=50,
                    device=device,
                )
                result["analysis"]["fpv"] = fpv
                result["analysis"]["rf"] = {
                    "freq_mhz": float(device["freq_mhz"]),
                    "iq_file": fpv.get("iq_file"),
                    "signal_type": "fm_video" if fpv.get("ok") else (fpv.get("rf") or {}).get("kind") or "unknown",
                    "bandwidth_3db_hz": (
                        int(round(float((fpv.get("rf") or {}).get("bw3db_mhz") or 0) * 1e6))
                        if (fpv.get("rf") or {}).get("bw3db_mhz") is not None
                        else None
                    ),
                    "fpv": {
                        "ok": fpv.get("ok"),
                        "message": fpv.get("message"),
                        "frames": len(fpv.get("frames") or []),
                        "channel": fpv.get("channel"),
                        "viability": fpv.get("viability"),
                        "rf": fpv.get("rf"),
                        "sync": fpv.get("sync"),
                    },
                }
                for fr in fpv.get("frames") or []:
                    if fr.get("file"):
                        result["artifacts"].append(fr["file"])
                key = tracker_mod.device_key(device)
                entry = tracker_mod.tracker.get(key)
                if entry is not None:
                    entry_meta = dict((entry or {}).get("metadata") or {})
                    # Keep base64 thumbs for focus UI (trim to 2)
                    thumbs = []
                    for fr in (fpv.get("frames") or [])[:2]:
                        thumbs.append({
                            "file": fr.get("file"),
                            "width": fr.get("width"),
                            "height": fr.get("height"),
                            "png_base64": fr.get("png_base64"),
                            "dive_id": dive_id,
                        })
                    fpv_meta = {
                        "ok": fpv.get("ok"),
                        "message": fpv.get("message"),
                        "channel": fpv.get("channel"),
                        "viability": fpv.get("viability"),
                        "sync": fpv.get("sync"),
                        "frames": thumbs,
                        "dive_id": dive_id,
                    }
                    patch: dict[str, Any] = {"metadata": {**entry_meta, "fpv_decode": fpv_meta}}
                    ch = fpv.get("channel") or {}
                    if fpv.get("ok"):
                        freq_s = f"{float(device['freq_mhz']):.3f} MHz"
                        patch["name"] = f"FPV {ch.get('channel') or freq_s} · {len(thumbs)} frame(s)"
                    tracker_mod.tracker.patch(key, patch)
            else:
                result["analysis"]["rf"] = _rf_deep_dive(
                    float(device["freq_mhz"]),
                    out_dir,
                    duration_s=20 if is_tpms else 15,
                )
        if is_fpv:
            pass
        elif is_tpms and result["analysis"].get("rf", {}).get("iq_file"):
            iq_path = out_dir / result["analysis"]["rf"]["iq_file"]
            tpms = tpms_decode.decode_tpms_iq(
                iq_path,
                float(device["freq_mhz"]),
                sample_rate=2_000_000,
                out_dir=out_dir,
            )
            result["analysis"]["tpms"] = tpms
            result["analysis"]["rf"]["tpms"] = {
                "ok": tpms.get("ok"),
                "sensor_count": tpms.get("sensor_count", 0),
                "message": tpms.get("message"),
            }
            # Persist last decode on tracker for the focus card
            key = tracker_mod.device_key(device)
            entry = tracker_mod.tracker.get(key)
            if entry is not None:
                meta = dict(entry.get("metadata") or {})
                meta["tpms_decode"] = {
                    "sensors": tpms.get("sensors") or [],
                    "message": tpms.get("message"),
                    "dive_id": dive_id,
                }
                entry["metadata"] = meta
                if tpms.get("sensors"):
                    s0 = tpms["sensors"][0]
                    label_bits = []
                    if s0.get("pressure_psi") is not None:
                        label_bits.append(f"{s0['pressure_psi']} PSI")
                    if s0.get("temperature_c") is not None:
                        label_bits.append(f"{s0['temperature_c']}°C")
                    if s0.get("id") is not None:
                        label_bits.append(f"id {s0['id']}")
                    if label_bits:
                        entry["name"] = f"TPMS {' · '.join(label_bits)}"
        else:
            from . import live_decode
            from . import uhf_decode

            iq_name = result["analysis"]["rf"].get("iq_file")
            if iq_name:
                iq_path = out_dir / iq_name
                freq = float(device["freq_mhz"])
                if uhf_decode.is_uhf_telemetry_target(device):
                    uhf = uhf_decode.decode_uhf_iq(
                        iq_path, freq, sample_rate=2_000_000, out_dir=out_dir
                    )
                    result["analysis"]["uhf"] = uhf
                    wav_name = uhf.get("wav_file")
                    if wav_name and (out_dir / wav_name).is_file():
                        result["artifacts"].append(wav_name)
                    result["analysis"]["rf"]["uhf"] = {
                        "ok": uhf.get("ok"),
                        "summary": uhf.get("summary"),
                        "methods": uhf.get("methods"),
                        "message": uhf.get("message"),
                        "wav_file": wav_name,
                    }
                    key = tracker_mod.device_key(device)
                    entry = tracker_mod.tracker.get(key)
                    if entry is not None:
                        meta = dict(entry.get("metadata") or {})
                        meta["uhf_decode"] = uhf
                        entry["metadata"] = meta
                        if uhf.get("ok") and uhf.get("summary"):
                            entry["name"] = uhf["summary"]
                else:
                    # ISM remotes — attach rtl_433 + fixed/rolling class when possible
                    frames = live_decode._rtl433_generic(
                        iq_path, freq, 2_000_000, out_dir
                    )
                    code = live_decode.classify_remote_frames(frames)
                    result["analysis"]["rtl433"] = {
                        "frames": frames[:12],
                        "frame_count": len(frames),
                        "code_class": code,
                    }
                    key = tracker_mod.device_key(device)
                    entry = tracker_mod.tracker.get(key)
                    if entry is not None and frames:
                        meta = dict(entry.get("metadata") or {})
                        meta["rtl433_frames"] = frames[:8]
                        meta["code_class"] = code
                        entry["metadata"] = meta
                        model = frames[0].get("model") or frames[0].get("protocol") or "remote"
                        rid = frames[0].get("id") or frames[0].get("ID")
                        entry["name"] = f"{model}" + (f" id={rid}" if rid is not None else "")
    else:
        result["analysis"]["error"] = "Insufficient target data for deep dive"

    risk_report = risk_mod.assess_risk(device, result["analysis"])
    # Persist GATT snapshot so focus panel can re-list UUIDs later
    if result.get("analysis", {}).get("ble"):
        risk_report = dict(risk_report)
        ble = result["analysis"]["ble"]
        risk_report["gatt_snapshot"] = {
            "mac": ble.get("mac"),
            "connected": ble.get("connected"),
            "services": ble.get("services") or [],
        }
    result["risk"] = risk_report

    key = tracker_mod.device_key(device)
    tracker_mod.tracker.set_risk(key, risk_report["status"], risk_report)

    result["completed_utc"] = datetime.now(timezone.utc).isoformat()
    (out_dir / "deep_dive.json").write_text(json.dumps(result, indent=2, default=str))
    return result


def _rf_deep_dive(freq_mhz: float, out_dir: Path, duration_s: int = 15) -> dict[str, Any]:
    iq_path = out_dir / f"iq_{freq_mhz:.3f}MHz.raw"
    rate = 2_000_000
    samples = rate * duration_s
    freq_hz = int(freq_mhz * 1e6)

    cmd = [
        "hackrf_transfer", "-r", str(iq_path),
        "-f", str(freq_hz), "-s", str(rate),
        "-l", "40", "-g", "44", "-a", "0", "-b", "1750000",
        "-n", str(samples),
    ]
    if HACKRF_SERIAL:
        cmd[1:1] = ["-d", HACKRF_SERIAL]

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration_s + 30)
    analysis: dict[str, Any] = {
        "freq_mhz": freq_mhz,
        "iq_file": iq_path.name,
        "hackrf_exit": proc.returncode,
        "stderr_tail": (proc.stderr or "")[-500:],
        "duration_s_request": duration_s,
    }

    if iq_path.exists() and iq_path.stat().st_size > 1000:
        analysis.update(_analyze_iq(iq_path, rate))
    return analysis


def _analyze_iq(path: Path, rate: float) -> dict[str, Any]:
    raw = np.fromfile(path, dtype=np.int8)
    raw = raw[: len(raw) // 2 * 2]
    z = raw[0::2].astype(np.float64) / 127 + 1j * raw[1::2].astype(np.float64) / 127
    nfft = 65536
    chunk = z[: min(nfft, len(z))] * np.hanning(min(nfft, len(z)))
    spec = np.fft.fftshift(np.fft.fft(chunk))
    freqs = np.fft.fftshift(np.fft.fftfreq(len(chunk), 1 / rate))
    psd = 20 * np.log10(np.abs(spec) + 1e-15)
    noise = float(np.median(psd))
    peak_i = int(np.argmax(psd))
    peak_off = float(freqs[peak_i])
    peak_db = float(psd[peak_i])
    mask = psd >= peak_db - 3
    bw_hz = float(np.sum(mask) * (rate / len(chunk)))

    # Downsample PSD for UI chart (~96 bins around peak ±500 kHz, else full span)
    spectrum = _downsample_spectrum(freqs, psd, peak_off, bins=96)

    return {
        "duration_s": len(z) / rate,
        "mean_dbfs": float(10 * np.log10(np.mean(np.abs(z) ** 2) + 1e-20)),
        "peak_offset_hz": peak_off,
        "peak_dbfs": round(peak_db, 1),
        "noise_floor_dbfs": round(noise, 1),
        "snr_db": round(peak_db - noise, 1),
        "bandwidth_3db_hz": round(bw_hz, 1),
        "signal_type": "CW" if bw_hz < 5000 else "modulated/wide",
        "spectrum": spectrum,
    }


def _downsample_spectrum(
    freqs: Any,
    psd: Any,
    peak_off: float,
    bins: int = 96,
    window_hz: float = 500_000.0,
) -> list[dict[str, float]]:
    """Return compact spectrum points for SVG charting."""
    lo = peak_off - window_hz
    hi = peak_off + window_hz
    mask = (freqs >= lo) & (freqs <= hi)
    if int(np.sum(mask)) < 16:
        mask = np.ones(len(freqs), dtype=bool)
    f = freqs[mask]
    p = psd[mask]
    if len(f) == 0:
        return []
    if len(f) <= bins:
        idx = np.arange(len(f))
    else:
        idx = np.linspace(0, len(f) - 1, bins).astype(int)
    out: list[dict[str, float]] = []
    for i in idx:
        out.append({
            "hz": round(float(f[i]), 1),
            "khz": round(float(f[i]) / 1000.0, 2),
            "db": round(float(p[i]), 2),
        })
    return out


def _ble_deep_dive(mac: str, out_dir: Path) -> dict[str, Any]:
    import asyncio

    async def _gatt():
        from bleak import BleakClient

        out: dict[str, Any] = {"mac": mac, "services": [], "connected": False}
        try:
            async with BleakClient(mac, timeout=25.0) as client:
                out["connected"] = client.is_connected
                for svc in client.services:
                    svc_d = {
                        "uuid": str(svc.uuid),
                        "description": (getattr(svc, "description", None) or "") or None,
                        "characteristics": [],
                    }
                    for char in svc.characteristics:
                        cd = {
                            "uuid": str(char.uuid),
                            "properties": list(char.properties),
                            "description": (getattr(char, "description", None) or "") or None,
                            "handle": getattr(char, "handle", None),
                        }
                        if "read" in char.properties:
                            try:
                                data = await client.read_gatt_char(char.uuid)
                                cd["value_hex"] = data.hex()
                                cd["value_ascii"] = data.decode("utf-8", errors="replace")[:200]
                            except Exception as e:
                                cd["read_error"] = str(e)
                        svc_d["characteristics"].append(cd)
                    out["services"].append(svc_d)
        except Exception as e:
            out["error"] = str(e)
        return out

    return asyncio.run(_gatt())

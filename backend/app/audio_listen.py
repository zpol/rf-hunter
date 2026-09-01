"""Live FM listen — HackRF RX → quadrature FM → WAV for browser playback."""

from __future__ import annotations

import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from .procutil import pkill_rf_tools
from .radio_gate import exclusive
from .uhf_decode import _write_wav_fm, is_uhf_telemetry_target

_DEFAULT_CAPTURES = Path(__file__).resolve().parents[2].parent / "captures" / "rf-hunter-v2"
CAPTURES = Path(os.environ.get("RF_HUNTER_CAPTURES", str(_DEFAULT_CAPTURES)))
HACKRF_SERIAL = os.environ.get("HACKRF_SERIAL", "")


def can_listen(device: dict[str, Any]) -> bool:
    """True when FM demod listen is a reasonable action for this target."""
    radio = (device.get("radio") or "hackrf").lower()
    if radio == "ble":
        return False
    if device.get("freq_mhz") is None:
        return False
    if is_uhf_telemetry_target(device):
        return True
    meta = device.get("metadata") or {}
    methods = meta.get("uhf_decode", {}).get("methods") or []
    if "fm_demod" in methods:
        return True
    profile = (meta.get("attack_profile") or device.get("attack_profile") or "").lower()
    return profile in ("uhf_telemetry", "cw_telemetry", "pocsag", "aprs_vhf", "nbfm", "fm_voice")


def listen_fm(device: dict[str, Any], duration_s: int = 8) -> dict[str, Any]:
    """
    Capture IQ on target freq, FM-demodulate to WAV, return artifact URL path.
    Pauses wardrive via radio_gate.exclusive (same as dive/replay).
    """
    freq = device.get("freq_mhz")
    if freq is None:
        return {"ok": False, "error": "No freq_mhz on target"}
    radio = (device.get("radio") or "hackrf").lower()
    if radio == "ble":
        return {"ok": False, "error": "Listen is RF-only (HackRF)"}

    duration_s = max(3, min(int(duration_s), 20))
    rate = 2_000_000
    listen_id = f"LISTEN-{uuid.uuid4().hex[:8]}"
    out_dir = CAPTURES / listen_id
    out_dir.mkdir(parents=True, exist_ok=True)
    iq_path = out_dir / "listen.raw"
    wav_path = out_dir / "listen_fm.wav"
    freq_hz = int(float(freq) * 1e6)
    samples = int(rate * duration_s)

    started = datetime.now(timezone.utc).isoformat()
    with exclusive("audio_listen"):
        pkill_rf_tools()
        cmd = [
            "hackrf_transfer",
            "-r", str(iq_path),
            "-f", str(freq_hz),
            "-s", str(rate),
            "-l", "40",
            "-g", "44",
            "-a", "0",
            "-n", str(samples),
        ]
        if HACKRF_SERIAL:
            cmd[1:1] = ["-d", HACKRF_SERIAL]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=duration_s + 25
            )
        except subprocess.TimeoutExpired as e:
            return {"ok": False, "error": f"hackrf_transfer timeout: {e}"}
        except FileNotFoundError:
            return {"ok": False, "error": "hackrf_transfer not found — install hackrf tools"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    if not iq_path.is_file() or iq_path.stat().st_size < 4000:
        return {
            "ok": False,
            "error": "IQ capture empty — check HackRF / stop other RF tools",
            "listen_id": listen_id,
            "hackrf_exit": getattr(proc, "returncode", None),
        }

    try:
        _iq_to_fm_wav(iq_path, rate, wav_path)
    except Exception as e:
        return {"ok": False, "error": f"FM demod failed: {e}", "listen_id": listen_id}

    hint = (
        "FM demod of this band is often data/FSK (hiss/bursts), not voice — "
        "useful to ear-check activity."
    )
    return {
        "ok": True,
        "listen_id": listen_id,
        "freq_mhz": float(freq),
        "duration_s": duration_s,
        "wav_file": wav_path.name,
        "wav_url": f"/api/artifact/{listen_id}/{wav_path.name}",
        "iq_file": iq_path.name,
        "started_utc": started,
        "completed_utc": datetime.now(timezone.utc).isoformat(),
        "hint": hint,
        "hackrf_exit": proc.returncode,
    }


def _iq_to_fm_wav(iq_path: Path, rate: int, wav_path: Path) -> None:
    raw = np.fromfile(iq_path, dtype=np.int8)
    raw = raw[: len(raw) // 2 * 2]
    max_samp = min(len(raw) // 2, rate * 20)
    i = raw[0 : max_samp * 2 : 2].astype(np.float64) / 127.0
    q = raw[1 : max_samp * 2 : 2].astype(np.float64) / 127.0
    z = i + 1j * q
    d = z[1:] * np.conj(z[:-1])
    fm = np.angle(d)
    _write_wav_fm(fm, rate, wav_path, out_rate=48000)

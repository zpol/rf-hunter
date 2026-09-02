"""UHF telemetry decode (~350–370 MHz and similar CW/FSK industrial bands)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from . import tpms_decode
from . import radio as radio_mod

HACKRF_SERIAL = os.environ.get("HACKRF_SERIAL", "")


def is_uhf_telemetry_target(device: dict[str, Any]) -> bool:
    tid = (device.get("device_type_id") or "").lower()
    profile = ((device.get("metadata") or {}).get("attack_profile") or "").lower()
    if tid in ("industrial_360", "telemetry_1690") or profile in ("uhf_telemetry", "cw_telemetry"):
        return True
    freq = device.get("freq_mhz")
    if freq is None:
        return False
    f = float(freq)
    # Private PMR / industrial telemetry pockets often seen in EU labs
    return 350.0 <= f <= 380.0 or 1690.0 <= f <= 1710.0


def decode_uhf_iq(
    iq_path: Path,
    freq_mhz: float,
    *,
    sample_rate: int = 2_000_000,
    out_dir: Path | None = None,
) -> dict[str, Any]:
    """
    Best-effort decode for UHF industrial / PMR-adjacent telemetry.
    Tries: rtl_433 @ freq, FM-demod + printable strings, multimon-ng (POCSAG/FLEX) if installed.
    """
    out_dir = out_dir or iq_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {
        "ok": False,
        "freq_mhz": freq_mhz,
        "family": "UHF telemetry",
        "confidence": "low",
        "methods": [],
        "message": "",
        "at": datetime.now(timezone.utc).isoformat(),
    }

    if not iq_path.exists() or iq_path.stat().st_size < 2000:
        result["message"] = "IQ too short / missing"
        return result

    # 1) rtl_433 — sometimes sensors drift into this band or share OOK/FSK styles
    frames = _try_rtl433(iq_path, freq_mhz, sample_rate, out_dir)
    if frames:
        result["methods"].append("rtl_433")
        result["rtl433_frames"] = frames[:12]
        model = frames[0].get("model") or frames[0].get("protocol")
        result["ok"] = True
        result["confidence"] = "high"
        result["summary"] = f"rtl_433 · {model}" if model else f"rtl_433 ×{len(frames)}"
        result["model_guess"] = str(model) if model else None
        result["message"] = result["summary"]

    # 2) FM demod analysis + printable / baud guess
    demod = _fm_analyze(iq_path, sample_rate, out_dir)
    result["demod"] = {
        k: demod[k]
        for k in ("ok", "baud_hz", "deviation_hz", "snr_db", "printable", "burst_count", "message")
        if k in demod
    }
    if demod.get("wav_path"):
        result["wav_file"] = Path(demod["wav_path"]).name
    if demod.get("ok"):
        result["methods"].append("fm_demod")
        if not result["ok"]:
            result["ok"] = True
            result["confidence"] = "medium" if demod.get("printable") else "low"
            bits = []
            if demod.get("baud_hz"):
                bits.append(f"~{demod['baud_hz']:.0f} baud")
            if demod.get("printable"):
                bits.append(f"text={demod['printable'][:40]!r}")
            if demod.get("burst_count"):
                bits.append(f"{demod['burst_count']} burst(s)")
            result["summary"] = "FM/FSK · " + (" · ".join(bits) if bits else "carrier activity")
            result["message"] = result["summary"]
            result["family"] = "UHF FSK/FM telemetry"

    # 3) multimon-ng for pager-class digital (POCSAG/FLEX) if present
    mm = _try_multimon(demod.get("wav_path") if demod else None)
    if mm.get("lines"):
        result["methods"].append("multimon-ng")
        result["pocsag"] = mm["lines"][:20]
        result["ok"] = True
        result["confidence"] = "high"
        result["family"] = "POCSAG/FLEX pager"
        result["summary"] = mm["lines"][0][:120]
        result["message"] = f"multimon-ng · {len(mm['lines'])} line(s)"

    if not result["ok"]:
        result["message"] = (
            demod.get("message")
            or "No known decoder matched — IQ kept for offline analysis "
            "(industrial SCADA/PMR often needs vendor-specific tools)"
        )
    (out_dir / "uhf_decode.json").write_text(json.dumps(result, indent=2, default=str))
    return result


def capture_and_decode(
    freq_mhz: float,
    out_dir: Path,
    *,
    duration_s: int = 8,
    sample_rate: int = 2_000_000,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    iq = out_dir / f"uhf_{freq_mhz:.3f}MHz.raw"
    try:
        capture = radio_mod.capture_iq(
            iq, freq_hz=int(freq_mhz * 1e6), sample_rate=sample_rate,
            num_samples=sample_rate * duration_s, lna_db=40, vga_db=44,
            timeout=duration_s + 25,
        )
        if not capture.ok:
            return {"ok": False, "message": capture.error or "capture failed", "freq_mhz": freq_mhz}
    except Exception as exc:
        return {"ok": False, "message": f"capture failed: {exc}", "freq_mhz": freq_mhz}
    return decode_uhf_iq(iq, freq_mhz, sample_rate=sample_rate, out_dir=out_dir)


def _try_rtl433(iq: Path, freq: float, rate: int, out: Path) -> list[dict[str, Any]]:
    if not tpms_decode.has_rtl433():
        return []
    cu8 = out / f"uhf_{freq:.3f}M_{rate}sps.cu8"
    try:
        tpms_decode.hackrf_cs8_to_cu8(iq, cu8)
    except Exception:
        return []
    try:
        r = subprocess.run(
            [
                "rtl_433", "-r", str(cu8), "-s", str(rate),
                "-f", f"{freq}M", "-F", "json", "-M", "level",
            ],
            capture_output=True, text=True, timeout=35,
        )
    except Exception:
        return []
    frames = []
    for line in (r.stdout or "").splitlines():
        if line.startswith("{"):
            try:
                frames.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return frames


def _fm_analyze(iq_path: Path, rate: int, out_dir: Path) -> dict[str, Any]:
    raw = np.fromfile(iq_path, dtype=np.int8)
    raw = raw[: len(raw) // 2 * 2]
    if len(raw) < 4000:
        return {"ok": False, "message": "IQ too short for FM demod"}
    # Limit work to ~2 s
    max_samp = min(len(raw) // 2, rate * 2)
    i = raw[0 : max_samp * 2 : 2].astype(np.float64) / 127.0
    q = raw[1 : max_samp * 2 : 2].astype(np.float64) / 127.0
    z = i + 1j * q
    # Quadrature demod
    d = z[1:] * np.conj(z[:-1])
    fm = np.angle(d)
    # Power / SNR-ish
    power = np.abs(z) ** 2
    snr = float(10 * np.log10((np.percentile(power, 90) + 1e-12) / (np.median(power) + 1e-12)))
    # Burst detect via envelope
    env = np.abs(z)
    thr = np.median(env) + 1.5 * (np.percentile(env, 75) - np.median(env) + 1e-9)
    active = env > thr
    # count rising edges of activity windows (~ms)
    win = max(1, rate // 200)
    down = active[: len(active) - len(active) % win].reshape(-1, win).mean(axis=1) > 0.4
    bursts = int(np.sum(np.diff(down.astype(np.int8)) == 1))

    # Baud estimate: zero-crossing rate of centered FM during active samples
    fm_a = fm[: len(active) - 1][active[:-1]]
    baud = None
    deviation = None
    if len(fm_a) > 500:
        fm_c = fm_a - np.median(fm_a)
        zc = np.sum(np.diff(np.signbit(fm_c)))
        dur = len(fm_c) / rate
        if dur > 0:
            baud = float(zc / (2 * dur))
        deviation = float(np.std(fm_c) * (rate / (2 * np.pi)))

    # Printable-ish: coarse bit slice at guessed baud → ASCII search
    printable = ""
    if baud and 300 <= baud <= 9600:
        step = max(1, int(round(rate / baud)))
        bits = (fm_a[::step] > 0).astype(np.uint8)
        # pack bits to bytes MSB first
        nbytes = len(bits) // 8
        if nbytes >= 4:
            packed = np.packbits(bits[: nbytes * 8])
            text = bytes(packed).decode("ascii", errors="ignore")
            runs = re_findall_printable(text)
            if runs:
                printable = max(runs, key=len)

    # Write wav for multimon (48 kHz mono)
    wav_path = out_dir / "uhf_fm.wav"
    try:
        _write_wav_fm(fm, rate, wav_path, out_rate=48000)
    except Exception:
        wav_path = None  # type: ignore

    ok = bursts >= 1 or (baud is not None and baud > 200) or bool(printable)
    msg = "FM activity" if ok else "No clear FM/FSK bursts"
    return {
        "ok": ok,
        "baud_hz": round(baud, 1) if baud else None,
        "deviation_hz": round(deviation, 1) if deviation else None,
        "snr_db": round(snr, 1),
        "burst_count": bursts,
        "printable": printable or None,
        "wav_path": str(wav_path) if wav_path else None,
        "message": msg,
    }


def re_findall_printable(text: str) -> list[str]:
    import re

    return re.findall(r"[ -~]{4,}", text)


def _write_wav_fm(fm: np.ndarray, in_rate: int, path: Path, out_rate: int = 48000) -> None:
    # Decimate
    decim = max(1, int(round(in_rate / out_rate)))
    x = fm[::decim]
    # Normalize to int16
    x = x - np.mean(x)
    peak = np.max(np.abs(x)) + 1e-9
    audio = (x / peak * 20000).astype(np.int16)
    import wave

    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(int(in_rate / decim))
        w.writeframes(audio.tobytes())


def _try_multimon(wav_path: str | None) -> dict[str, Any]:
    if not wav_path or not Path(wav_path).is_file():
        return {}
    if not shutil.which("multimon-ng"):
        return {}
    try:
        r = subprocess.run(
            [
                "multimon-ng", "-t", "wav",
                "-a", "POCSAG512", "-a", "POCSAG1200", "-a", "POCSAG2400",
                "-a", "FLEX", "-a", "AFSK1200",
                "-q", wav_path,
            ],
            capture_output=True, text=True, timeout=20,
        )
    except Exception:
        return {}
    lines = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
    # Filter noise
    lines = [ln for ln in lines if not ln.lower().startswith("multimon")]
    return {"lines": lines}

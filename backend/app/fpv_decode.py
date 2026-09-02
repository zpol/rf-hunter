"""Analog FPV / wireless AV — FM video snapshot (NTSC/PAL grayscale frames)."""

from __future__ import annotations

import base64
import io
import os
import subprocess
from pathlib import Path
from typing import Any

import numpy as np
from . import radio as radio_mod

HACKRF_SERIAL = os.environ.get("HACKRF_SERIAL", "").strip()

# Common analog FPV channel tables (MHz)
CHANNEL_TABLES: dict[str, dict[str, float]] = {
    "Raceband": {
        "R1": 5658, "R2": 5695, "R3": 5732, "R4": 5769,
        "R5": 5806, "R6": 5843, "R7": 5880, "R8": 5917,
    },
    "Boscam A": {
        "A1": 5865, "A2": 5845, "A3": 5825, "A4": 5805,
        "A5": 5785, "A6": 5765, "A7": 5745, "A8": 5725,
    },
    "Boscam B": {
        "B1": 5733, "B2": 5752, "B3": 5771, "B4": 5790,
        "B5": 5809, "B6": 5828, "B7": 5847, "B8": 5866,
    },
    "Fatshark E": {
        "E1": 5705, "E2": 5685, "E3": 5665, "E4": 5645,
        "E5": 5885, "E6": 5905, "E7": 5925, "E8": 5945,
    },
    "L-band": {
        "L1": 1080, "L2": 1120, "L3": 1160, "L4": 1200,
        "L5": 1240, "L6": 1280, "L7": 1320, "L8": 1360,
    },
}

# HackRF sample rates that work well for FM video (~8–14 MHz occupied)
DEFAULT_RATE = 10_000_000
DEFAULT_DURATION_S = 0.55


def is_fpv_target(device: dict[str, Any]) -> bool:
    """True only for analog FPV / L-band AV targets — never ADS-B/AIS/ACARS."""
    radio = (device.get("radio") or "").lower()
    if radio in ("adsb", "ais", "ble"):
        return False
    tid = (device.get("device_type_id") or "").lower()
    meta = device.get("metadata") or {}
    profile = (meta.get("attack_profile") or "").lower()
    hint = ((meta.get("catalog_hint") or {}).get("device_type_id") or "").lower()
    # Explicit non-FPV aviation / traffic types
    blocked = {
        "adsb_1090",
        "ais_marine",
        "acars_vhf",
        "aprs_vhf",
        "pocsag_pager",
        "epirb_406",
    }
    if tid in blocked or profile in blocked or hint in blocked:
        return False
    if tid in ("fpv_58", "lband_av") or profile in ("fpv_58", "lband_video") or hint in (
        "fpv_58",
        "lband_av",
    ):
        return True
    f = device.get("freq_mhz")
    if f is None:
        return False
    f = float(f)
    # 5.8 GHz analog VTX only for frequency heuristic.
    # Do NOT use 1080–1360 here — that overlaps ADS-B 1090 MHz.
    return 5640.0 <= f <= 5955.0


def nearest_channel(freq_mhz: float) -> dict[str, Any] | None:
    best: dict[str, Any] | None = None
    best_df = 1e9
    for band, chans in CHANNEL_TABLES.items():
        for name, mhz in chans.items():
            df = abs(float(freq_mhz) - mhz)
            if df < best_df:
                best_df = df
                best = {"band": band, "channel": name, "center_mhz": mhz, "offset_mhz": round(df, 3)}
    if best and best["offset_mhz"] <= 12:
        return best
    return None


def viability(device: dict[str, Any]) -> dict[str, Any]:
    """Estimate if a tracked peak is worth an FM-video attempt."""
    snr = device.get("snr_db")
    pwr = device.get("power_dbm")
    freq = device.get("freq_mhz")
    meta = device.get("metadata") or {}
    classification = str(
        meta.get("classification")
        or ((device.get("raw") or {}).get("peak") or {}).get("classification")
        or ""
    ).lower()
    snr_f = float(snr) if snr is not None else None
    pwr_f = float(pwr) if pwr is not None else None
    ch = nearest_channel(float(freq)) if freq is not None else None
    score = 0
    notes: list[str] = []
    if snr_f is not None:
        if snr_f >= 20:
            score += 40
            notes.append(f"SNR {snr_f:.1f} dB — strong")
        elif snr_f >= 12:
            score += 25
            notes.append(f"SNR {snr_f:.1f} dB — usable")
        elif snr_f >= 8:
            score += 10
            notes.append(f"SNR {snr_f:.1f} dB — marginal")
        else:
            notes.append(f"SNR {snr_f:.1f} dB — weak")
    if pwr_f is not None:
        if pwr_f >= -30:
            score += 35
            notes.append(f"power {pwr_f:.1f} dBm — excellent")
        elif pwr_f >= -40:
            score += 25
            notes.append(f"power {pwr_f:.1f} dBm — good")
        elif pwr_f >= -48:
            score += 12
            notes.append(f"power {pwr_f:.1f} dBm — borderline")
        else:
            notes.append(f"power {pwr_f:.1f} dBm — likely too weak")
    if ch:
        score += 15
        notes.append(f"near {ch['band']} {ch['channel']} ({ch['center_mhz']} MHz)")
    if 5640 <= float(freq or 0) <= 5955:
        notes.append("5.8 GHz analog FPV class")
    elif 1080 <= float(freq or 0) <= 1360:
        notes.append("L-band AV / FPV class")
    # Narrow CW / burst peaks are rarely analog FM video
    if "cw" in classification:
        score -= 30
        notes.append(f"sweep class '{classification}' — often carrier/noise, not wide FM video")
    if "burst" in classification or "weak" in classification:
        score -= 10
        notes.append(f"sweep class '{classification}' — weak evidence of video")
    level = "good" if score >= 55 else "maybe" if score >= 28 else "poor"
    return {
        "level": level,
        "score": max(0, score),
        "snr_db": snr_f,
        "power_dbm": pwr_f,
        "channel": ch,
        "notes": notes,
        "recommend": level in ("good", "maybe"),
        "classification": classification or None,
    }


def _read_iq_sc8(path: Path) -> np.ndarray:
    raw = np.fromfile(path, dtype=np.int8)
    if raw.size % 2:
        raw = raw[:-1]
    i = raw[0::2].astype(np.float32) / 128.0
    q = raw[1::2].astype(np.float32) / 128.0
    return i + 1j * q


def _fm_demod(x: np.ndarray) -> np.ndarray:
    # quadrature discriminator
    d = np.angle(x[1:] * np.conj(x[:-1]))
    d = d - np.mean(d)
    return d.astype(np.float32)


def _boxcar_lpf(x: np.ndarray, win: int) -> np.ndarray:
    win = max(3, int(win) | 1)
    ker = np.ones(win, dtype=np.float32) / win
    return np.convolve(x, ker, mode="same")


def _extract_frames(
    demod: np.ndarray,
    sample_rate: float,
    *,
    standard: str = "auto",
    max_frames: int = 3,
) -> tuple[list[np.ndarray], dict[str, Any]]:
    """Best-effort line sync → grayscale frames (NTSC ~525 / PAL ~625)."""
    meta: dict[str, Any] = {"standard": standard}
    # Prefer PAL in EU labs; auto picks by sync quality
    candidates = []
    if standard == "ntsc":
        candidates = [("ntsc", 15734.26, 525)]
    elif standard == "pal":
        candidates = [("pal", 15625.0, 625)]
    else:
        candidates = [("ntsc", 15734.26, 525), ("pal", 15625.0, 625)]

    # Sync tips = darkest samples
    thr = float(np.percentile(demod, 8))
    sync = demod < thr

    best_frames: list[np.ndarray] = []
    best_score = -1.0
    best_meta: dict[str, Any] = meta

    for name, line_hz, n_lines in candidates:
        spp = int(round(sample_rate / line_hz))  # samples per line
        if spp < 200 or spp > 2000:
            continue
        # find sync run starts
        edges = np.where(np.diff(sync.astype(np.int8)) == 1)[0]
        if edges.size < 40:
            continue
        # keep edges spaced ~1 line apart
        kept = [int(edges[0])]
        for e in edges[1:]:
            if e - kept[-1] >= int(spp * 0.85):
                kept.append(int(e))
        if len(kept) < n_lines:
            continue
        # Build frames from consecutive lines
        frames: list[np.ndarray] = []
        i = 0
        while i + n_lines < len(kept) and len(frames) < max_frames:
            rows = []
            ok = True
            for j in range(n_lines):
                a = kept[i + j]
                b = a + spp
                if b >= len(demod):
                    ok = False
                    break
                line = demod[a:b]
                # crop blanking ~12% left, ~5% right
                left = int(spp * 0.12)
                right = int(spp * 0.95)
                row = line[left:right]
                rows.append(row)
            if ok and len(rows) == n_lines:
                img = np.vstack(rows)
                # contrast stretch
                lo, hi = np.percentile(img, [5, 95])
                if hi - lo < 1e-6:
                    i += n_lines // 2
                    continue
                img = (img - lo) / (hi - lo)
                img = np.clip(img, 0, 1)
                # Invert so video is bright (sync was dark)
                # Actually after stretch, active video is usually higher than sync which we cropped
                frames.append(img)
            i += max(1, n_lines // 3)

        if not frames:
            continue
        # Score: structured video has row-to-row correlation; snow does not
        mid = frames[len(frames) // 2]
        row_corr = 0.0
        try:
            a = mid[::2].astype(np.float64)
            b = mid[1::2].astype(np.float64)
            n = min(len(a), len(b), 200)
            if n > 20:
                aa = a[:n].ravel()
                bb = b[:n].ravel()
                # subsample columns
                aa = aa[:: max(1, aa.size // 2000)]
                bb = bb[:: max(1, bb.size // 2000)]
                if aa.size > 10 and bb.size == aa.size:
                    row_corr = float(np.corrcoef(aa, bb)[0, 1])
                    if not np.isfinite(row_corr):
                        row_corr = 0.0
        except Exception:
            row_corr = 0.0
        # Horizontal edge energy (real video has H structure)
        hx = float(np.mean(np.abs(np.diff(mid, axis=1))))
        score = float(abs(row_corr) * 100 + hx * 50 + np.var(mid) * 20)
        if score > best_score:
            best_score = score
            best_frames = frames
            best_meta = {
                "standard": name,
                "line_hz": line_hz,
                "samples_per_line": spp,
                "n_lines": n_lines,
                "sync_threshold": thr,
                "structure_score": round(score, 2),
                "row_corr": round(row_corr, 3),
            }

    # Reject snow / unlocked noise
    if best_frames:
        rc = float(best_meta.get("row_corr") or 0)
        if abs(rc) < 0.08 and float(best_meta.get("structure_score") or 0) < 40:
            return [], {**best_meta, "rejected": "noise_like", "message": "Sync candidate looks like snow"}
    return best_frames, best_meta


def _frame_to_png_b64(frame: np.ndarray) -> tuple[bytes, str]:
    try:
        from PIL import Image
    except ImportError:
        # PPM fallback → still return bytes; UI may not render
        h, w = frame.shape
        pix = (frame * 255).astype(np.uint8)
        header = f"P5\n{w} {h}\n255\n".encode()
        raw = header + pix.tobytes()
        return raw, base64.b64encode(raw).decode("ascii")

    pix = (frame * 255).astype(np.uint8)
    img = Image.fromarray(pix, mode="L")
    # Upscale a bit for UI readability
    img = img.resize((max(320, img.width), max(240, img.height)), Image.NEAREST)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    data = buf.getvalue()
    return data, base64.b64encode(data).decode("ascii")


def capture_iq(
    freq_mhz: float,
    out_path: Path,
    *,
    sample_rate: int = DEFAULT_RATE,
    duration_s: float = DEFAULT_DURATION_S,
    lna_db: int = 40,
    vga_db: int = 48,
) -> dict[str, Any]:
    n = int(sample_rate * duration_s)
    freq_hz = int(round(float(freq_mhz) * 1e6))
    # Baseband filter ~0.75 * rate, capped
    bb = min(int(sample_rate * 0.75), 14_000_000)
    try:
        capture = radio_mod.capture_iq(
            out_path, freq_hz=freq_hz, sample_rate=sample_rate,
            num_samples=n, lna_db=lna_db, vga_db=vga_db,
            bandwidth_hz=bb, timeout=duration_s + 25,
        )
        ok = out_path.exists() and out_path.stat().st_size > 100_000
        return {
            "ok": ok and capture.ok,
            "exit": capture.returncode,
            "bytes": out_path.stat().st_size if out_path.exists() else 0,
            "stderr_tail": capture.stderr[-400:],
            "radio_backend": capture.backend,
            **({"error": capture.error} if capture.error else {}),
            "sample_rate": sample_rate,
            "duration_s": duration_s,
            "freq_mhz": freq_mhz,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "freq_mhz": freq_mhz}


def _iq_rf_diagnostics(x: np.ndarray, sample_rate: float) -> dict[str, Any]:
    """Rough occupied-bandwidth / CW vs wideband hint from a short FFT."""
    n = min(x.size, 1 << 18)
    if n < 4096:
        return {}
    chunk = x[:n]
    spec = np.fft.fftshift(np.abs(np.fft.fft(chunk)) ** 2)
    freqs = np.fft.fftshift(np.fft.fftfreq(chunk.size, 1.0 / sample_rate)) / 1e6
    peak = float(spec.max())
    if peak <= 0:
        return {}
    idx = int(spec.argmax())
    half = peak * 0.5
    i0 = idx
    while i0 > 0 and spec[i0] >= half:
        i0 -= 1
    i1 = idx
    while i1 < len(spec) - 1 and spec[i1] >= half:
        i1 += 1
    bw3 = float(freqs[i1] - freqs[i0])
    c = np.cumsum(spec)
    c = c / (c[-1] + 1e-20)
    lo = int(np.searchsorted(c, 0.005))
    hi = int(np.searchsorted(c, 0.995))
    obw99 = float(freqs[min(hi, len(freqs) - 1)] - freqs[max(lo, 0)])
    # Narrow peak → CW/noise spur; analog FPV FM video is typically several MHz wide
    kind = "narrow_cw" if bw3 < 0.35 else "wideband_like" if bw3 >= 2.0 else "moderate"
    return {
        "bw3db_mhz": round(bw3, 3),
        "occupied99_mhz": round(obw99, 2),
        "kind": kind,
    }


def decode_iq_file(
    iq_path: Path,
    *,
    sample_rate: float = DEFAULT_RATE,
    out_dir: Path | None = None,
    standard: str = "auto",
    max_frames: int = 3,
) -> dict[str, Any]:
    if not iq_path.exists():
        return {"ok": False, "message": "IQ file missing"}
    x = _read_iq_sc8(iq_path)
    if x.size < sample_rate * 0.05:
        return {"ok": False, "message": "IQ too short"}

    power = float(10 * np.log10(np.mean(np.abs(x) ** 2) + 1e-20))
    rf = _iq_rf_diagnostics(x, sample_rate)
    demod = _fm_demod(x)
    # ~3 MHz video LPF at sample_rate
    win = max(5, int(sample_rate / 3e6))
    demod = _boxcar_lpf(demod, win)

    frames, sync_meta = _extract_frames(demod, sample_rate, standard=standard, max_frames=max_frames)
    if frames:
        msg = f"{len(frames)} frame(s)"
    elif sync_meta.get("rejected") == "noise_like":
        msg = "No video lock — IQ looks like snow/noise (no stable H-sync structure)"
    elif rf.get("kind") == "narrow_cw":
        msg = (
            f"No video lock — RF peak looks like narrow CW (~{rf.get('bw3db_mhz')} MHz), "
            "not wideband analog FM video"
        )
    else:
        msg = "No sync / no structured video — no analog VTX picture in this capture"
    out: dict[str, Any] = {
        "ok": bool(frames),
        "message": msg,
        "iq_power_dbfs": round(power, 1),
        "rf": rf,
        "sync": sync_meta,
        "frames": [],
    }
    out_dir = out_dir or iq_path.parent
    for i, fr in enumerate(frames):
        png_bytes, b64 = _frame_to_png_b64(fr)
        name = f"fpv_frame_{i + 1}.png"
        path = out_dir / name
        # Only write real PNGs (Pillow). PPM fallback keeps .ppm
        if png_bytes[:8] == b"\x89PNG\r\n\x1a\n":
            path.write_bytes(png_bytes)
        else:
            name = f"fpv_frame_{i + 1}.ppm"
            path = out_dir / name
            path.write_bytes(png_bytes)
            b64 = base64.b64encode(png_bytes).decode("ascii")
        out["frames"].append({
            "file": name,
            "width": int(fr.shape[1]),
            "height": int(fr.shape[0]),
            "png_base64": b64 if name.endswith(".png") else None,
        })
    return out


def listen_and_decode(
    freq_mhz: float,
    out_dir: Path,
    *,
    sample_rate: int = DEFAULT_RATE,
    duration_s: float = DEFAULT_DURATION_S,
    lna_db: int = 40,
    vga_db: int = 48,
    standard: str = "auto",
    device: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    iq_path = out_dir / f"fpv_{freq_mhz:.3f}MHz.iq"
    cap = capture_iq(
        freq_mhz,
        iq_path,
        sample_rate=sample_rate,
        duration_s=duration_s,
        lna_db=lna_db,
        vga_db=vga_db,
    )
    result: dict[str, Any] = {
        "ok": False,
        "freq_mhz": freq_mhz,
        "channel": nearest_channel(freq_mhz),
        "viability": viability(device) if device else None,
        "capture": cap,
    }
    if not cap.get("ok"):
        result["message"] = "IQ capture failed"
        return result
    dec = decode_iq_file(
        iq_path,
        sample_rate=sample_rate,
        out_dir=out_dir,
        standard=standard,
    )
    result.update(dec)
    result["iq_file"] = iq_path.name
    return result

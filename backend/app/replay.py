"""Lab RF listen → decode → IQ replay (HackRF TX). Authorized use only."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import uuid
import wave
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from shutil import which
from typing import Any

import numpy as np

from .procutil import pkill_rf_tools
from .radio_gate import exclusive
from . import tx_safety
from .live_decode import classify_remote_frames

_DEFAULT_CAPTURES = Path(__file__).resolve().parents[2].parent / "captures" / "rf-hunter-v2"
CAPTURES = Path(os.environ.get("RF_HUNTER_CAPTURES", str(_DEFAULT_CAPTURES)))
HACKRF_SERIAL = os.environ.get("HACKRF_SERIAL", "")

_lock = threading.Lock()
_sessions: dict[str, dict[str, Any]] = {}


def listen(
    device: dict[str, Any],
    duration_s: int = 8,
    *,
    lna_db: int = 24,
    vga_db: int = 28,
) -> dict[str, Any]:
    """
    Put HackRF in RX on the target frequency, capture IQ, try rtl_433 decode,
    and mark the capture as replay-ready if energy / frames look usable.
    """
    radio = (device.get("radio") or "hackrf").lower()
    if radio == "ble":
        return {
            "ok": False,
            "error": "Replay listen is RF-only — pick a HackRF target (e.g. garage remote).",
        }
    freq = device.get("freq_mhz")
    if freq is None:
        return {"ok": False, "error": "No freq_mhz on target"}
    freq = float(freq)
    if not tx_safety.in_allowlist(freq):
        snapped = tx_safety.nearest_allowlist_mhz(freq)
        if snapped is None:
            return {
                "ok": False,
                "error": (
                    f"{freq} MHz outside lab bands (315/433/868). "
                    "Use Find freq again and lock a peak inside those bands."
                ),
            }
        # e.g. GSM clutter 881.9 → record on 868.35 instead
        device = {**device, "freq_mhz": float(snapped)}
        freq = float(snapped)

    duration_s = max(4, min(int(duration_s), 30))
    lna_db = max(0, min(int(lna_db), 40))
    vga_db = max(0, min(int(vga_db), 62))
    rate = 2_000_000
    capture_id = f"CAP-{uuid.uuid4().hex[:8]}"
    out_dir = CAPTURES / capture_id
    out_dir.mkdir(parents=True, exist_ok=True)
    iq_path = out_dir / "listen.raw"
    freq_hz = int(float(freq) * 1e6)
    samples = int(rate * duration_s)

    started = datetime.now(timezone.utc).isoformat()
    with exclusive("replay_listen"):
        pkill_rf_tools()
        cmd = [
            "hackrf_transfer",
            "-r", str(iq_path),
            "-f", str(freq_hz),
            "-s", str(rate),
            "-l", str(lna_db),
            "-g", str(vga_db),
            "-a", "0",
            "-n", str(samples),
        ]
        if HACKRF_SERIAL:
            cmd[1:1] = ["-d", HACKRF_SERIAL]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=duration_s + 25
            )
            hackrf_exit = proc.returncode
            stderr_tail = (proc.stderr or "")[-400:]
        except subprocess.TimeoutExpired as e:
            return {"ok": False, "error": f"hackrf_transfer timeout: {e}"}
        except FileNotFoundError:
            return {"ok": False, "error": "hackrf_transfer not found — install hackrf tools"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    size = iq_path.stat().st_size if iq_path.exists() else 0
    analysis = _analyze_listen_iq(iq_path, rate, float(freq)) if size > 1000 else {
        "energy_dbfs": None,
        "burst_count": 0,
        "peak_dbfs": None,
        "usable": False,
        "note": "IQ file missing or too small",
    }
    artifacts = _write_listen_artifacts(iq_path, rate, analysis) if size > 1000 else {}
    decoded = _try_rtl433(iq_path, rate, float(freq)) if size > 1000 else []
    pwm = _decode_ook_pwm(iq_path, rate) if size > 1000 else None
    if pwm and pwm.get("bits"):
        decoded = [
            {
                "protocol": "ook_pwm_lab",
                "bits": pwm["bits"],
                "hex": pwm.get("hex"),
                "repeats": pwm.get("repeat_count"),
                "model": "OOK/PWM",
            },
            *decoded,
        ]
        (out_dir / "decode.json").write_text(json.dumps(pwm, indent=2, default=str))
    code_class = classify_remote_frames(decoded)
    code_class = _apply_code_hint(code_class, device)
    if pwm and pwm.get("unique_frames") == 1 and pwm.get("repeat_count", 0) >= 3:
        if code_class.get("class") in (None, "unknown"):
            code_class = {
                "class": "likely_fixed",
                "detail": f"OOK/PWM same frame ×{pwm['repeat_count']}",
                "replay_advice": "Fixed-looking PWM — IQ replay is the gate test",
            }

    offset_hz = analysis.get("freq_offset_hz")
    tuned_mhz, applied_off, tune_note = tx_safety.safe_tx_freq(float(freq), offset_hz)
    if applied_off is not None:
        analysis["freq_offset_applied_hz"] = int(applied_off)
    if tune_note:
        analysis["tune_note"] = tune_note

    replay_ready = bool(
        size > rate * 2  # >1s of samples
        and (analysis.get("usable") or decoded)
    )

    meta = {
        "capture_id": capture_id,
        "device_key": device.get("key"),
        "freq_mhz": float(freq),
        "tx_freq_mhz": tuned_mhz,
        "freq_offset_hz": offset_hz,
        "sample_rate": rate,
        "lna_db": lna_db,
        "vga_db": vga_db,
        "duration_s": duration_s,
        "iq_file": str(iq_path),
        "iq_burst_file": artifacts.get("iq_burst_file"),
        "iq_best_file": artifacts.get("iq_best_file"),
        "wav_am_file": artifacts.get("wav_am_file"),
        "iq_bytes": size,
        "hackrf_exit": hackrf_exit,
        "stderr_tail": stderr_tail,
        "analysis": analysis,
        "decoded": decoded[:12],
        "decoded_count": len(decoded),
        "pwm_decode": pwm,
        "code_class": code_class,
        "replay_ready": replay_ready,
        "started_utc": started,
        "completed_utc": datetime.now(timezone.utc).isoformat(),
        "target": {
            "name": device.get("name") or device.get("device_type_name"),
            "device_type_id": device.get("device_type_id"),
            "freq_mhz": float(freq),
            "radio": radio,
        },
    }
    (out_dir / "listen.json").write_text(json.dumps(meta, indent=2, default=str))

    with _lock:
        _sessions[capture_id] = meta

    msg = _listen_message(replay_ready, analysis, decoded, size, tuned_mhz, float(freq))
    if code_class.get("class") in ("rolling", "likely_rolling"):
        msg += f" · code={code_class['class']} (replay usually will not unlock)"
        if code_class.get("replay_advice"):
            msg += f" — {code_class['replay_advice']}"
    elif code_class.get("class") in ("fixed", "likely_fixed"):
        msg += f" · code={code_class['class']} — good TX candidate"
    return {"ok": True, **meta, "message": msg}


def transmit(
    capture_id: str,
    confirm: bool = False,
    tx_gain: int = 20,
    *,
    iq_source: str = "burst",
    use_corrected_freq: bool = True,
    repeats: int = 1,
) -> dict[str, Any]:
    """Retransmit a previously listened IQ capture (HackRF TX). Requires confirm=True + arm."""
    with _lock:
        meta = _sessions.get(capture_id)
    if not meta:
        meta = _load_from_disk(capture_id)
    if not meta:
        return {"ok": False, "error": f"Unknown capture_id {capture_id}"}

    iq_path = _resolve_tx_iq(meta, iq_source)
    if not iq_path or not iq_path.exists():
        return {"ok": False, "error": f"IQ missing for source={iq_source}"}

    # Weak RX (low LNA/VGA) → quiet IQ; scale up for TX or the gate never hears it
    iq_path, tx_scale = _normalize_iq_for_tx(iq_path)

    rx_mhz = float(meta["freq_mhz"])
    if not tx_safety.in_allowlist(rx_mhz):
        hint = tx_safety.nearest_allowlist_mhz(rx_mhz)
        return {
            "ok": False,
            "error": (
                f"Capture was RX @ {rx_mhz} MHz (outside lab TX bands — often GSM clutter). "
                f"Re-run Find freq / Record on {hint or '315 / 433.92 / 868.35'} MHz."
            ),
            "capture_id": capture_id,
        }

    offset = meta.get("freq_offset_hz")
    # Tiny FFT jitter (<10 kHz) is noise for OOK garage — stay on RX center
    if offset is not None and abs(float(offset)) < 10_000:
        offset = None
    if use_corrected_freq:
        tune_mhz, _, _ = tx_safety.safe_tx_freq(rx_mhz, offset)
        stored = meta.get("tx_freq_mhz")
        if (
            stored is not None
            and tx_safety.in_allowlist(float(stored))
            and offset is not None
            and abs(float(stored) - rx_mhz) >= 0.01
        ):
            tune_mhz = float(stored)
            tune_mhz, _, _ = tx_safety.safe_tx_freq(tune_mhz, None)
        else:
            # Prefer exact listen center when offset was discarded
            tune_mhz, _, _ = tx_safety.safe_tx_freq(rx_mhz, offset)
    else:
        tune_mhz, _, _ = tx_safety.safe_tx_freq(rx_mhz, None)

    rate = int(meta.get("sample_rate") or 2_000_000)
    tx_gain = max(0, min(int(tx_gain), tx_safety.MAX_TX_GAIN))
    repeats = max(1, min(int(repeats), 5))

    blocked = tx_safety.assert_tx_allowed(tune_mhz, tx_gain, confirm)
    if blocked:
        return blocked

    code = meta.get("code_class") or {}
    freq_hz = int(round(tune_mhz * 1e6))

    exits: list[int] = []
    stderr_tail = ""
    with exclusive("replay_tx"):
        pkill_rf_tools()
        for _ in range(repeats):
            cmd = [
                "hackrf_transfer",
                "-t", str(iq_path),
                "-f", str(freq_hz),
                "-s", str(rate),
                "-x", str(tx_gain),
                "-a", "1",
            ]
            if HACKRF_SERIAL:
                cmd[1:1] = ["-d", HACKRF_SERIAL]

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            except Exception as e:
                return {"ok": False, "error": str(e), "capture_id": capture_id}
            exits.append(proc.returncode)
            stderr_tail = (proc.stderr or "")[-400:]
            if proc.returncode != 0:
                break

    ok = bool(exits) and all(c == 0 for c in exits)
    result = {
        "ok": ok,
        "capture_id": capture_id,
        "freq_mhz": tune_mhz,
        "rx_center_mhz": float(meta["freq_mhz"]),
        "freq_offset_hz": meta.get("freq_offset_hz"),
        "tx_gain": tx_gain,
        "iq_tx_file": str(iq_path.name),
        "iq_source": iq_source,
        "tx_iq_scale": tx_scale,
        "repeats": repeats,
        "hackrf_exit": exits[-1] if exits else -1,
        "stderr_tail": stderr_tail,
        "code_class": code,
        "message": (
            f"TX complete @ {tune_mhz:.6f} MHz (gain {tx_gain}, {iq_path.name}"
            f"{f', ×{repeats}' if repeats > 1 else ''}"
            f"{f', amp×{tx_scale}' if tx_scale and tx_scale > 1.05 else ''})"
            if ok
            else f"TX failed (exit {exits[-1] if exits else 'n/a'})"
        ),
    }
    if code.get("class") in ("rolling", "likely_rolling"):
        result["message"] += " — rolling-code target: car usually ignores replay"
    tx_safety.record_tx({
        "capture_id": capture_id,
        "freq_mhz": tune_mhz,
        "tx_gain": tx_gain,
        "ok": result["ok"],
        "code_class": code.get("class"),
        "iq_tx_file": iq_path.name,
        "repeats": repeats,
        "iq_source": iq_source,
    })
    out_dir = CAPTURES / capture_id
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        (out_dir / "tx_last.json").write_text(json.dumps(result, indent=2))
    except Exception:
        pass
    return result


def get_capture(capture_id: str) -> dict[str, Any] | None:
    with _lock:
        meta = _sessions.get(capture_id)
    return meta or _load_from_disk(capture_id)


def reanalyze_capture(capture_id: str) -> dict[str, Any]:
    """Recompute offset / WAV / best-burst for an existing CAP (no new RX)."""
    meta = get_capture(capture_id)
    if not meta:
        return {"ok": False, "error": f"Unknown capture_id {capture_id}"}
    iq_path = Path(meta["iq_file"])
    # Host path may differ from container path written in JSON
    if not iq_path.exists():
        alt = CAPTURES / capture_id / "listen.raw"
        if alt.exists():
            iq_path = alt
            meta["iq_file"] = str(alt)
        else:
            return {"ok": False, "error": f"IQ missing: {iq_path}"}
    rate = int(meta.get("sample_rate") or 2_000_000)
    center = float(meta["freq_mhz"])
    analysis = _analyze_listen_iq(iq_path, rate, center)
    artifacts = _write_listen_artifacts(iq_path, rate, analysis)
    offset_hz = analysis.get("freq_offset_hz")
    tuned, applied, note = tx_safety.safe_tx_freq(center, offset_hz)
    meta["analysis"] = analysis
    meta["tx_freq_mhz"] = tuned
    meta["freq_offset_hz"] = offset_hz if applied is not None else analysis.get("freq_offset_hz")
    if note:
        analysis["tune_note"] = note
    meta["iq_burst_file"] = artifacts.get("iq_burst_file") or meta.get("iq_burst_file")
    meta["iq_best_file"] = artifacts.get("iq_best_file")
    meta["wav_am_file"] = artifacts.get("wav_am_file")
    if not meta.get("code_class") or meta["code_class"].get("class") == "unknown":
        device = {
            "key": meta.get("device_key"),
            "device_type_id": (meta.get("target") or {}).get("device_type_id"),
            "metadata": {"code_hint": "rolling"} if str(meta.get("device_key") or "").startswith("clone:car") else {},
        }
        meta["code_class"] = _apply_code_hint(meta.get("code_class") or {"class": "unknown"}, device)
    out_dir = iq_path.parent
    (out_dir / "listen.json").write_text(json.dumps(meta, indent=2, default=str))
    with _lock:
        _sessions[capture_id] = meta
    return {"ok": True, **meta}


def _resolve_tx_iq(meta: dict[str, Any], iq_source: str) -> Path | None:
    src = (iq_source or "auto").lower()
    candidates: list[str] = []
    if src == "best":
        candidates = ["iq_best_file", "iq_burst_file", "iq_file"]
    elif src == "burst":
        candidates = ["iq_burst_file", "iq_file"]
    elif src == "full":
        candidates = ["iq_file"]
    else:  # auto — prefer burst window (all presses), then best, then full
        candidates = ["iq_burst_file", "iq_best_file", "iq_file"]
    for key in candidates:
        p = meta.get(key)
        if not p:
            continue
        path = Path(p)
        if not path.exists():
            # rewrite container /data/... → local CAPTURES
            alt = CAPTURES / meta["capture_id"] / path.name
            if alt.exists():
                path = alt
                meta[key] = str(alt)
        if path.exists():
            return path
    return None


def _normalize_iq_for_tx(iq_path: Path, target_peak: int = 110) -> tuple[Path, float]:
    """
    Scale weak int8 IQ toward full-scale for louder HackRF TX.
    Timing / OOK duty unchanged; only amplitude. Returns (path, scale).
    """
    try:
        raw = np.fromfile(iq_path, dtype=np.int8)
        if len(raw) < 4096:
            return iq_path, 1.0
        peak = int(np.max(np.abs(raw.astype(np.int16))))
        if peak < 8 or peak >= target_peak:
            return iq_path, 1.0
        scale = float(target_peak) / float(peak)
        out = np.clip(np.round(raw.astype(np.float32) * scale), -127, 127).astype(np.int8)
        dest = iq_path.parent / f"{iq_path.stem}_txnorm.raw"
        out.tofile(dest)
        return dest, round(scale, 2)
    except Exception:
        return iq_path, 1.0


def _load_from_disk(capture_id: str) -> dict[str, Any] | None:
    path = CAPTURES / capture_id / "listen.json"
    if not path.exists():
        return None
    try:
        meta = json.loads(path.read_text())
        with _lock:
            _sessions[capture_id] = meta
        return meta
    except Exception:
        return None


def _apply_code_hint(code_class: dict[str, Any], device: dict[str, Any]) -> dict[str, Any]:
    """Preset / metadata hint when rtl_433 cannot classify (typical for car fobs)."""
    if code_class.get("class") not in (None, "unknown"):
        return code_class
    meta = device.get("metadata") or {}
    hint = (meta.get("code_hint") or "").lower()
    key = (device.get("key") or "").lower()
    dtype = (device.get("device_type_id") or "").lower()
    if hint == "rolling" or key.startswith("clone:car") or "car" in dtype:
        return {
            "class": "rolling",
            "detail": hint or "car-key preset (no protocol decode)",
            "replay_advice": (
                meta.get("clone_note")
                or "Capture far from the car (codes unused), then TX — still often fails on Hitag AES / rolling"
            ),
        }
    return code_class


def _analyze_listen_iq(path: Path, rate: float, center_mhz: float) -> dict[str, Any]:
    raw = np.fromfile(path, dtype=np.int8)
    raw = raw[: len(raw) // 2 * 2]
    if len(raw) < 4096:
        return {"usable": False, "burst_count": 0, "note": "too short"}

    i = raw[0::2].astype(np.float64) / 127.0
    q = raw[1::2].astype(np.float64) / 127.0
    power = i * i + q * q

    # ~2 ms windows — better for short OOK frames
    win = max(256, int(rate * 0.002))
    n = (len(power) // win) * win
    frames = power[:n].reshape(-1, win).mean(axis=1)
    if len(frames) == 0:
        return {"usable": False, "burst_count": 0}

    noise = float(np.median(frames))
    thr = max(noise * 10.0, 1e-4)
    above = frames > thr
    edges = np.diff(above.astype(np.int8))
    burst_count = int(np.sum(edges == 1))
    peak = float(np.max(frames))
    energy_dbfs = float(10 * np.log10(np.mean(power) + 1e-20))
    peak_dbfs = float(10 * np.log10(peak + 1e-20))
    usable = burst_count >= 1 or peak > thr * 2

    bursts: list[tuple[int, int]] = []
    in_b = False
    s0 = 0
    for k, a in enumerate(above):
        if a and not in_b:
            in_b = True
            s0 = k
        elif not a and in_b:
            in_b = False
            bursts.append((s0, k))
    if in_b:
        bursts.append((s0, len(above)))

    margin_frames = max(2, int(0.05 * rate / win))  # ~50 ms
    idxs = np.where(above)[0]
    burst_start_s = None
    burst_end_s = None
    if len(idxs):
        f0 = max(0, int(idxs[0]) - margin_frames)
        f1 = min(len(frames) - 1, int(idxs[-1]) + margin_frames)
        burst_start_s = int(f0 * win)
        burst_end_s = int(min(len(power), (f1 + 1) * win))

    presses: list[dict[str, Any]] = []
    gap_max = max(1, int(0.12 * rate / win))
    if bursts:
        g0, g1 = bursts[0]
        for a, b in bursts[1:]:
            if a - g1 <= gap_max:
                g1 = b
            else:
                presses.append(_press_info(g0, g1, win, rate, frames))
                g0, g1 = a, b
        presses.append(_press_info(g0, g1, win, rate, frames))

    best_press = None
    if presses:
        peak_max = max(p["peak_dbfs"] for p in presses)
        # Prefer longest press among those near peak (avoid tiny noise spikes)
        strong = [p for p in presses if p["peak_dbfs"] >= peak_max - 3.0 and p["duration_ms"] >= 80]
        pool = strong or presses
        best_press = max(pool, key=lambda p: (p["duration_ms"], p["peak_dbfs"]))

    offset_hz = None
    if best_press is not None:
        offset_hz = _estimate_offset_hz(i, q, rate, best_press["start_sample"], best_press["end_sample"])

    # Clip / saturation warning — high RX gain destroys OOK edges for replay
    raw_i8 = np.fromfile(path, dtype=np.int8)
    raw_i8 = raw_i8[: len(raw_i8) // 2 * 2]
    clip_frac = float(np.mean(np.abs(raw_i8) >= 120)) if len(raw_i8) else 0.0
    clipped = clip_frac > 0.05 or peak_dbfs > 0.5

    note = (
        f"{burst_count} burst(s) / {len(presses)} press(es)"
        if burst_count
        else ("energy present" if usable else "quiet — press remote during listen")
    )
    if clipped:
        note += " · CLIPPED IQ (lower LNA/VGA next record)"

    return {
        "energy_dbfs": round(energy_dbfs, 1),
        "peak_dbfs": round(peak_dbfs, 1),
        "noise_floor": round(float(10 * np.log10(noise + 1e-20)), 1),
        "burst_count": burst_count,
        "press_count": len(presses),
        "threshold": thr,
        "usable": usable,
        "burst_start_sample": burst_start_s,
        "burst_end_sample": burst_end_s,
        "best_press": best_press,
        "presses": presses[:8],
        "freq_offset_hz": int(offset_hz) if offset_hz is not None else None,
        "center_mhz": float(center_mhz),
        "clip_frac": round(clip_frac, 3),
        "clipped": clipped,
        "note": note,
    }


def _press_info(f0: int, f1: int, win: int, rate: float, frames: np.ndarray) -> dict[str, Any]:
    peak = float(np.max(frames[f0:f1])) if f1 > f0 else 0.0
    return {
        "start_sample": int(f0 * win),
        "end_sample": int(f1 * win),
        "duration_ms": round((f1 - f0) * win / rate * 1000, 1),
        "t0_s": round(f0 * win / rate, 3),
        "peak_dbfs": round(float(10 * np.log10(peak + 1e-20)), 1),
    }


def _decode_ook_pwm(path: Path, rate: float) -> dict[str, Any] | None:
    """Lab OOK/PWM bit extract (short/long ON pulses). Returns None if not PWM-like."""
    try:
        raw = np.fromfile(path, dtype=np.uint8)
        raw = raw[: len(raw) // 2 * 2]
        if len(raw) < int(rate * 0.2) * 2:
            return None
        iq = (raw.astype(np.float32) - 127.5) / 127.5
        c = iq[0::2] + 1j * iq[1::2]
        bin_s = 50e-6
        win = max(8, int(rate * bin_s))
        n = (len(c) // win) * win
        p = (np.abs(c[:n]) ** 2).reshape(-1, win).mean(axis=1)
        db = 10 * np.log10(p + 1e-12)
        if float(np.percentile(db, 90) - np.percentile(db, 10)) < 6.0:
            return None
        thr = -5.0
        # Adaptive thr between quiet/loud modes when dynamic range is large
        thr = float((np.percentile(db, 15) + np.percentile(db, 85)) / 2.0)
        on = db > thr
        chg = np.where(np.diff(on.astype(np.int8)))[0]
        if len(chg) < 16:
            return None
        state = bool(on[0])
        start = 0
        segs: list[tuple[bool, float]] = []
        for i in list(chg) + [len(on) - 1]:
            w_ms = (i - start + 1) * bin_s * 1000.0
            segs.append((state, float(w_ms)))
            state = not state
            start = i + 1
        ons = [w for s, w in segs if s and 0.15 < w < 6.0]
        if len(ons) < 32:
            return None
        short_ms = float(np.percentile(ons, 25))
        long_ms = float(np.percentile(ons, 75))
        if long_ms < short_ms * 2.5:
            return None
        boundary = (short_ms + long_ms) / 2.0

        frames: list[list[tuple[bool, float]]] = []
        cur: list[tuple[bool, float]] = []
        for s, w in segs:
            if (s and w >= 8.0) or ((not s) and w >= 5.0):
                if len(cur) >= 8:
                    frames.append(cur)
                cur = []
                continue
            if 0.15 < w < 8.0:
                cur.append((s, w))
        if len(cur) >= 8:
            frames.append(cur)

        def bits_of(frame: list[tuple[bool, float]]) -> str:
            out: list[str] = []
            i = 0
            while i < len(frame) and not frame[i][0]:
                i += 1
            while i < len(frame) - 1:
                a, b = frame[i], frame[i + 1]
                if a[0] and not b[0]:
                    out.append("1" if a[1] > boundary else "0")
                    i += 2
                else:
                    i += 1
            return "".join(out)

        counts: Counter[str] = Counter()
        for fr in frames:
            b = bits_of(fr)
            if 12 <= len(b) <= 256:
                counts[b] += 1
        if not counts:
            return None
        bits, nrep = counts.most_common(1)[0]
        pad = bits + "0" * ((4 - len(bits) % 4) % 4)
        inv = "".join("1" if x == "0" else "0" for x in bits)
        pad_i = inv + "0" * ((4 - len(inv) % 4) % 4)
        return {
            "modulation": "OOK/PWM",
            "short_on_ms": round(short_ms, 2),
            "long_on_ms": round(long_ms, 2),
            "boundary_ms": round(boundary, 2),
            "frames": len(frames),
            "unique_frames": len(counts),
            "repeat_count": int(nrep),
            "bits": bits,
            "hex": hex(int(pad, 2)),
            "bits_inverted": inv,
            "hex_inverted": hex(int(pad_i, 2)),
            "top": [
                {
                    "bits": b,
                    "count": c,
                    "len": len(b),
                    "hex": hex(int(b + "0" * ((4 - len(b) % 4) % 4), 2)),
                }
                for b, c in counts.most_common(8)
            ],
        }
    except Exception:
        return None


def _estimate_offset_hz(
    i: np.ndarray, q: np.ndarray, rate: float, start: int, end: int
) -> float | None:
    """Median STFT peak of high-power frames in the press window (OOK/ASK tolerant)."""
    if end - start < int(rate * 0.01):
        return None
    nfft = 2048
    if end - start < nfft:
        return None
    hop = nfft // 2
    # Power gate relative to this window
    win_pwr = (i[start:end] ** 2 + q[start:end] ** 2)
    thr = max(float(np.median(win_pwr)) * 6.0, 1e-4)
    peaks: list[float] = []
    for k in range(start, end - nfft, hop):
        chunk_i = i[k : k + nfft]
        chunk_q = q[k : k + nfft]
        pwr = float(np.mean(chunk_i * chunk_i + chunk_q * chunk_q))
        if pwr < thr:
            continue
        seg = (chunk_i + 1j * chunk_q) * np.hanning(nfft)
        spec = np.abs(np.fft.fftshift(np.fft.fft(seg))) ** 2
        freqs = np.fft.fftshift(np.fft.fftfreq(nfft, d=1.0 / rate))
        # Ignore DC / LO leakage
        spec = spec.copy()
        spec[np.abs(freqs) < 2_000.0] = 0.0
        peak_f = float(freqs[int(np.argmax(spec))])
        # Ignore FFT edges (aliases)
        if abs(peak_f) > rate * 0.45:
            continue
        peaks.append(peak_f)
    if len(peaks) < 3:
        return None
    med = float(np.median(peaks))
    if abs(med) < 1500:
        return 0.0
    return med


def _write_listen_artifacts(
    iq_path: Path, rate: float, analysis: dict[str, Any]
) -> dict[str, Any]:
    """Write burst trim, best-press IQ, and AM WAV for offline analysis."""
    out: dict[str, Any] = {}
    try:
        raw = np.fromfile(iq_path, dtype=np.int8)
        raw = raw[: len(raw) // 2 * 2]
    except Exception:
        return out

    burst = _slice_iq(raw, analysis.get("burst_start_sample"), analysis.get("burst_end_sample"), rate)
    if burst is not None:
        bp = iq_path.parent / "listen_burst.raw"
        burst.tofile(bp)
        analysis["burst_bytes"] = int(len(burst))
        analysis["burst_trimmed"] = True
        out["iq_burst_file"] = str(bp)

    best = analysis.get("best_press") or {}
    if best.get("start_sample") is not None and best.get("end_sample") is not None:
        pad = int(rate * 0.03) * 2
        s = max(0, int(best["start_sample"]) * 2 - pad)
        e = min(len(raw), int(best["end_sample"]) * 2 + pad)
        chunk = raw[s:e]
        if len(chunk) >= 4096:
            bp = iq_path.parent / "listen_best.raw"
            chunk.tofile(bp)
            analysis["best_bytes"] = int(len(chunk))
            out["iq_best_file"] = str(bp)

    wav_path = _write_am_wav(raw, rate, iq_path.parent / "listen_am.wav")
    if wav_path:
        out["wav_am_file"] = str(wav_path)
        analysis["wav_am"] = wav_path.name

    return out


def _slice_iq(
    raw: np.ndarray,
    start: Any,
    end: Any,
    rate: float,
    min_s: float = 0.25,
) -> np.ndarray | None:
    if start is None or end is None or end <= start:
        return None
    byte_start = int(start) * 2
    byte_end = int(end) * 2
    if byte_end > len(raw) or byte_end <= byte_start:
        return None
    if byte_end - byte_start < int(rate * min_s) * 2:
        return None
    chunk = raw[byte_start:byte_end]
    if len(chunk) < 4096:
        return None
    if len(chunk) > 0.92 * len(raw):
        return None
    return chunk


def _write_am_wav(raw: np.ndarray, rate: float, path: Path) -> Path | None:
    """Downsampled AM envelope → ~48 kHz mono WAV (Audacity / UI)."""
    try:
        i = raw[0::2].astype(np.float32) / 127.0
        q = raw[1::2].astype(np.float32) / 127.0
        env = np.sqrt(i * i + q * q)
        target_sr = 48_000
        decim = max(1, int(round(rate / target_sr)))
        env = env[::decim]
        if len(env) < 64:
            return None
        peak = float(np.max(env)) or 1.0
        audio = np.clip(env / peak, 0, 1)
        pcm = (audio * 30000).astype(np.int16)
        with wave.open(str(path), "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(int(rate / decim))
            w.writeframes(pcm.tobytes())
        return path
    except Exception:
        return None


def _try_rtl433(iq_path: Path, rate: int, freq_mhz: float) -> list[dict[str, Any]]:
    if not which("rtl_433"):
        return []
    try:
        r = subprocess.run(
            [
                "rtl_433",
                "-r", str(iq_path),
                "-s", str(rate),
                "-f", f"{freq_mhz}M",
                "-F", "json",
                "-M", "level",
            ],
            capture_output=True,
            text=True,
            timeout=45,
        )
    except Exception:
        return []

    out: list[dict[str, Any]] = []
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"raw": line[:200]})
    return out


def _listen_message(
    replay_ready: bool,
    analysis: dict[str, Any],
    decoded: list,
    size: int,
    tuned_mhz: float,
    center_mhz: float,
) -> str:
    if size < 1000:
        return "Listen failed — no IQ captured (is HackRF free?)"
    off = analysis.get("freq_offset_hz")
    tune_note = ""
    if off is not None and abs(int(off)) >= 2000:
        tune_note = (
            f" · TX tune {tuned_mhz:.6f} MHz "
            f"(offset {int(off)/1e3:+.1f} kHz vs {center_mhz:.3f})"
        )
    if decoded:
        return f"Decoded {len(decoded)} frame(s) — ready to replicate{tune_note}"
    if analysis.get("burst_count", 0) > 0:
        presses = analysis.get("press_count") or 0
        return (
            f"Heard {analysis['burst_count']} burst(s) / {presses} press(es) — "
            f"IQ + AM WAV saved{tune_note}"
        )
    if analysis.get("usable"):
        return "Energy on frequency — IQ saved; try again while pressing the remote for a cleaner capture"
    return "Quiet capture — press the remote button during Record and try again"

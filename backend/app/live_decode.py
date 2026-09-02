"""Live decode helpers — short IQ + rtl_433 during wardrive for ISM/TPMS wow."""

from __future__ import annotations

import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import tpms_decode
from . import tracker as tracker_mod
from .procutil import pkill_rf_tools
from .radio_gate import exclusive
from . import radio as radio_mod
import os

_DEFAULT_CAPTURES = Path(__file__).resolve().parents[2].parent / "captures" / "rf-hunter-v2"
CAPTURES = Path(os.environ.get("RF_HUNTER_CAPTURES", str(_DEFAULT_CAPTURES)))
HACKRF_SERIAL = os.environ.get("HACKRF_SERIAL", "")

# Profiles worth live-decoding on stage
_LIVE_PROFILES = {
    "tpms_315", "tpms_433", "ism_315", "ism_433", "ism_868", "alarm_869",
    "uhf_telemetry", "cw_telemetry",
}


def should_live_decode(device: dict[str, Any]) -> bool:
    from . import uhf_decode

    profile = ((device.get("metadata") or {}).get("attack_profile") or "").lower()
    tid = (device.get("device_type_id") or "").lower()
    if profile in _LIVE_PROFILES:
        return True
    if tid.startswith("tpms_") or tid.startswith("garage_") or tid == "industrial_360":
        return True
    return uhf_decode.is_uhf_telemetry_target(device)


def enrich_pass(
    devices: list[dict[str, Any]],
    session_dir: Path,
    *,
    max_n: int = 2,
    duration_s: int = 4,
) -> list[dict[str, Any]]:
    """
    After a wardrive pass, decode up to max_n strong undecoded ISM/TPMS hits.
    Returns list of update summaries for logging.
    """
    candidates = _rank(devices)[:max_n]
    if not candidates:
        return []

    updates: list[dict[str, Any]] = []
    with exclusive("live_decode", pause_scan=False):
        # scan already between passes; just kill stray transfer
        pkill_rf_tools()
        for d in candidates:
            try:
                summary = _decode_one(d, session_dir, duration_s=duration_s)
                if summary:
                    updates.append(summary)
            except Exception as e:
                updates.append({"key": d.get("key"), "ok": False, "error": str(e)})
    return updates


def _rank(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from . import uhf_decode

    scored: list[tuple[float, dict]] = []
    for d in devices:
        if not should_live_decode(d):
            continue
        if d.get("radio") != "hackrf" or d.get("freq_mhz") is None:
            continue
        meta = d.get("metadata") or {}
        if meta.get("live_decode") or meta.get("tpms_decode", {}).get("sensors"):
            continue
        if meta.get("rtl433_frames") or meta.get("uhf_decode"):
            continue
        snr = float(d.get("snr_db") or 0)
        level = float(d.get("signal_level") or 0)
        # UHF telemetry: slightly lower SNR bar (often CW-ish)
        min_snr = 4 if uhf_decode.is_uhf_telemetry_target(d) else 6
        if snr < min_snr and level < 4:
            continue
        boost = 3 if uhf_decode.is_uhf_telemetry_target(d) else 0
        scored.append((snr * 2 + level + boost, d))
    scored.sort(key=lambda x: -x[0])
    return [d for _, d in scored]


def _decode_one(device: dict[str, Any], session_dir: Path, duration_s: int = 4) -> dict[str, Any]:
    freq = float(device["freq_mhz"])
    rate = 2_000_000
    out = session_dir / f"live_{uuid.uuid4().hex[:6]}"
    out.mkdir(parents=True, exist_ok=True)
    iq = out / "live.raw"
    radio_mod.capture_iq(
        iq, freq_hz=int(freq * 1e6), sample_rate=rate,
        num_samples=rate * duration_s, lna_db=40, vga_db=44,
        timeout=duration_s + 20,
    )

    key = device.get("key") or tracker_mod.device_key(device)
    entry = tracker_mod.tracker.get(key) or device
    meta = dict(entry.get("metadata") or {})

    result: dict[str, Any] = {
        "key": key,
        "freq_mhz": freq,
        "ok": False,
        "frames": 0,
    }

    from . import uhf_decode

    if uhf_decode.is_uhf_telemetry_target(device):
        uhf = uhf_decode.decode_uhf_iq(iq, freq, sample_rate=rate, out_dir=out)
        meta["uhf_decode"] = uhf
        meta["live_decode"] = {
            "ok": bool(uhf.get("ok")),
            "kind": "uhf",
            "message": uhf.get("message") or uhf.get("summary"),
            "at": datetime.now(timezone.utc).isoformat(),
        }
        if uhf.get("ok"):
            entry["name"] = uhf.get("summary") or entry.get("name") or f"UHF {freq:.3f} MHz"
            result["ok"] = True
            result["frames"] = len(uhf.get("rtl433_frames") or uhf.get("pocsag") or []) or 1
            result["uhf"] = {
                "summary": uhf.get("summary"),
                "methods": uhf.get("methods"),
                "confidence": uhf.get("confidence"),
            }
        entry["metadata"] = meta
        tracker_mod.tracker.upsert(entry)
        (out / "live_decode.json").write_text(json.dumps({**result, "meta": meta}, indent=2, default=str))
        return result

    if tpms_decode.is_tpms_target(device):
        tpms = tpms_decode.decode_tpms_iq(iq, freq, sample_rate=rate, out_dir=out)
        meta["tpms_decode"] = {
            "sensors": tpms.get("sensors") or [],
            "message": tpms.get("message"),
            "live": True,
            "at": datetime.now(timezone.utc).isoformat(),
        }
        meta["live_decode"] = {
            "ok": bool(tpms.get("sensors")),
            "kind": "tpms",
            "message": tpms.get("message"),
        }
        if tpms.get("sensors"):
            s0 = tpms["sensors"][0]
            bits = []
            if s0.get("pressure_psi") is not None:
                bits.append(f"{s0['pressure_psi']} PSI")
            if s0.get("id") is not None:
                bits.append(f"id {s0['id']}")
            if bits:
                entry["name"] = f"TPMS {' · '.join(bits)}"
            result["ok"] = True
            result["frames"] = tpms.get("frame_count") or len(tpms.get("sensors") or [])
            result["sensors"] = tpms.get("sensors")
    else:
        frames = _rtl433_generic(iq, freq, rate, out)
        meta["rtl433_frames"] = frames[:8]
        meta["live_decode"] = {
            "ok": bool(frames),
            "kind": "ism",
            "message": f"{len(frames)} frame(s)" if frames else "No frames",
            "at": datetime.now(timezone.utc).isoformat(),
        }
        code_class = classify_remote_frames(frames)
        meta["code_class"] = code_class
        if frames:
            model = frames[0].get("model") or frames[0].get("protocol") or "remote"
            rid = frames[0].get("id") or frames[0].get("ID")
            entry["name"] = f"{model}" + (f" id={rid}" if rid is not None else "")
            result["ok"] = True
            result["frames"] = len(frames)
            result["code_class"] = code_class

    entry["metadata"] = meta
    tracker_mod.tracker.upsert(entry)

    (out / "live_decode.json").write_text(json.dumps({**result, "meta": meta}, indent=2, default=str))
    return result


def _rtl433_generic(iq: Path, freq: float, rate: int, out: Path) -> list[dict[str, Any]]:
    if not tpms_decode.has_rtl433() or not iq.exists() or iq.stat().st_size < 1000:
        return []
    cu8 = out / f"g{freq:.3f}M_{rate}sps.cu8"
    tpms_decode.hackrf_cs8_to_cu8(iq, cu8)
    try:
        r = subprocess.run(
            ["rtl_433", "-r", str(cu8), "-s", str(rate), "-f", f"{freq}M", "-F", "json"],
            capture_output=True, text=True, timeout=30,
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


def classify_remote_frames(frames: list[dict[str, Any]]) -> dict[str, Any]:
    """Heuristic fixed vs rolling based on rtl_433 model / fields."""
    if not frames:
        return {"class": "unknown", "detail": "no frames"}

    blob = json.dumps(frames[:5]).lower()
    rolling_hints = (
        "keeloq", "rolling", "hopping", "somfy", "nice flo", "hormann",
        "secure", "encrypted", "aes", "challenge",
    )
    fixed_hints = (
        "came", "fixed", "static", "simple", "princeton", "ev1527",
        "sc2262", "ht12", "generic_remote",
    )
    for h in rolling_hints:
        if h in blob:
            return {
                "class": "rolling",
                "detail": f"hint:{h}",
                "replay_advice": "Replay of one capture usually fails — need rolling window / jam-intercept lab setup",
            }
    for h in fixed_hints:
        if h in blob:
            return {
                "class": "fixed",
                "detail": f"hint:{h}",
                "replay_advice": "Fixed-code — IQ replay is a strong lab demo",
            }

    # id present + no counter → lean fixed
    fr = frames[0]
    if fr.get("id") is not None and fr.get("counter") is None and fr.get("rolling") is None:
        return {
            "class": "likely_fixed",
            "detail": "stable id, no counter field",
            "replay_advice": "Try IQ replay; verify with target",
        }
    if fr.get("counter") is not None or fr.get("rolling") is not None:
        return {
            "class": "likely_rolling",
            "detail": "counter/rolling field present",
            "replay_advice": "Single-shot replay unlikely to work",
        }
    return {"class": "unknown", "detail": "decoded but unclassified", "replay_advice": "Capture + analyze"}

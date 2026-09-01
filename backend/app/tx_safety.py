"""TX safety interlock for HackRF replay — arm flag + band allowlist + audit."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_DEFAULT_CAPTURES = Path(__file__).resolve().parents[2].parent / "captures" / "rf-hunter-v2"
CAPTURES = Path(os.environ.get("RF_HUNTER_CAPTURES", str(_DEFAULT_CAPTURES)))

# Lab-safe bands (MHz) where TX demos are expected
ALLOWLIST_MHZ: list[tuple[float, float, str]] = [
    (240.0, 360.0, "EU garage low / 315"),
    (420.0, 450.0, "ISM 433 EU"),
    (863.0, 870.0, "EU868 / alarm"),
]

# Max fine-tune offset from RX center (crystal / IF error). Larger = bogus FFT.
MAX_TUNE_OFFSET_HZ = 250_000

_lock = threading.Lock()
_armed = False
_arm_note = ""
_audit: list[dict[str, Any]] = []
MAX_TX_GAIN = 20


def status() -> dict[str, Any]:
    with _lock:
        return {
            "armed": _armed,
            "arm_note": _arm_note,
            "max_tx_gain": MAX_TX_GAIN,
            "allowlist_mhz": [
                {"lo": a, "hi": b, "label": lab} for a, b, lab in ALLOWLIST_MHZ
            ],
            "audit_tail": list(_audit[-20:]),
        }


def set_armed(armed: bool, note: str = "") -> dict[str, Any]:
    global _armed, _arm_note
    with _lock:
        _armed = bool(armed)
        _arm_note = (note or "").strip()[:200]
        _audit.append({
            "utc": datetime.now(timezone.utc).isoformat(),
            "event": "arm" if _armed else "disarm",
            "note": _arm_note,
        })
        _audit[:] = _audit[-200:]
    return status()


def in_allowlist(freq_mhz: float) -> bool:
    f = float(freq_mhz)
    return any(lo <= f <= hi for lo, hi, _ in ALLOWLIST_MHZ)


def allowlist_band_for(freq_mhz: float) -> tuple[float, float, str] | None:
    f = float(freq_mhz)
    for lo, hi, lab in ALLOWLIST_MHZ:
        if lo <= f <= hi:
            return lo, hi, lab
    return None


def nearest_allowlist_mhz(freq_mhz: float) -> float | None:
    """
    Snap a out-of-band hunt peak into a lab band when it's a known false neighbor
    (e.g. GSM ~880–890 → EU868 868.35). Far-away peaks return None.
    """
    f = float(freq_mhz)
    if in_allowlist(f):
        return round(f, 3)
    # Cellular downlink/uplink clutter next to 868
    if 870.0 < f <= 915.0:
        return 868.35
    centers = (315.0, 330.0, 433.92, 868.35)
    best = min(centers, key=lambda c: abs(c - f))
    if abs(best - f) <= 20.0:
        return best
    return None


def safe_tx_freq(
    rx_center_mhz: float, offset_hz: float | None
) -> tuple[float, float | None, str | None]:
    """
    Apply fine IF offset, clamp into the same allowlist band as RX.
    Returns (tx_mhz, applied_offset_hz_or_none, note).
    """
    center = float(rx_center_mhz)
    if not in_allowlist(center):
        mapped = nearest_allowlist_mhz(center)
        if mapped is None:
            return center, None, "rx center outside TX allowlist"
        center = float(mapped)

    band = allowlist_band_for(center)
    off = None if offset_hz is None else float(offset_hz)
    if off is not None and abs(off) > MAX_TUNE_OFFSET_HZ:
        return (
            round(center, 6),
            None,
            f"offset {off / 1e3:.0f} kHz ignored (>{MAX_TUNE_OFFSET_HZ / 1e3:.0f} kHz max)",
        )
    if off is None or abs(off) < 2_000:
        return round(center, 6), (0.0 if off == 0 else None), None

    tuned = center + off / 1e6
    if band:
        lo, hi, _ = band
        tuned = min(max(tuned, lo), hi)
    if not in_allowlist(tuned):
        return round(center, 6), None, "corrected freq left allowlist — using RX center"
    return round(tuned, 6), off, None


def assert_tx_allowed(freq_mhz: float, tx_gain: int, confirm: bool) -> dict[str, Any] | None:
    """Return error dict if TX blocked, else None."""
    if not confirm:
        return {"ok": False, "error": "TX requires confirm=true"}
    with _lock:
        armed = _armed
    if not armed:
        return {
            "ok": False,
            "error": "TX disarmed — enable Arm TX in the UI (lab safety interlock)",
        }
    if tx_gain > MAX_TX_GAIN:
        return {"ok": False, "error": f"tx_gain capped at {MAX_TX_GAIN} for lab demos"}
    if not in_allowlist(freq_mhz):
        hint = nearest_allowlist_mhz(freq_mhz)
        extra = f" — use {hint:.3f} MHz (lab band)" if hint else ""
        return {
            "ok": False,
            "error": f"{freq_mhz} MHz outside lab TX allowlist (315/433/868 bands){extra}",
        }
    return None


def record_tx(event: dict[str, Any]) -> None:
    with _lock:
        _audit.append({
            "utc": datetime.now(timezone.utc).isoformat(),
            "event": "tx",
            **event,
        })
        _audit[:] = _audit[-200:]
        try:
            CAPTURES.mkdir(parents=True, exist_ok=True)
            (CAPTURES / "tx_audit.jsonl").open("a").write(
                json.dumps(_audit[-1], default=str) + "\n"
            )
        except Exception:
            pass

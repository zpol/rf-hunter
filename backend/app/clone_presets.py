"""RF CLONE presets — garage / car / fob / 868 lab remotes."""

from __future__ import annotations

import csv
import os
import subprocess
import time
from typing import Any

from .procutil import kill_process_tree, pkill_rf_tools
from .radio_gate import exclusive
from . import tx_safety

HACKRF_SERIAL = os.environ.get("HACKRF_SERIAL", "")

# Fixed lab presets (TX allowlist: 315 / 433 / 868).
PRESETS: list[dict[str, Any]] = [
    {
        "id": "garage_low",
        "label": "Garage low ~294",
        "center_mhz": 294.0,
        "span_mhz": 12.0,
        "band_lo_mhz": 240.0,
        "band_hi_mhz": 360.0,
        "icon": "gate",
        "device_type_id": "garage_315",
        "attack_profile": "ism_315",
        "code_hint": "likely_fixed",
        "note": "PC ROLL V48 lab hit @ ~294.0 MHz (OOK/PWM). Record → listen_am.wav for Audacity; offset ~+80 kHz from 293.92.",
    },
    {
        "id": "garage_433",
        "label": "Garage / gate 433.92",
        "center_mhz": 433.92,
        "span_mhz": 12.0,
        "band_lo_mhz": 420.0,
        "band_hi_mhz": 450.0,
        "icon": "gate",
        "device_type_id": "garage_433",
        "attack_profile": "ism_433",
        "code_hint": "likely_fixed",
        "note": "Most common EU fixed/rolling garage remotes. If Live stays flat while pressing, use Find freq (many are 868).",
    },
    {
        "id": "garage_868",
        "label": "Garage / gate 868",
        "center_mhz": 868.35,
        "span_mhz": 8.0,
        "band_lo_mhz": 863.0,
        "band_hi_mhz": 870.0,
        "icon": "gate",
        "device_type_id": "ism_868_domotica",
        "attack_profile": "ism_868",
        "code_hint": "likely_fixed",
        "note": "Somfy / Nice / Hörmann / many EU gates use ~868.3–868.95 MHz.",
    },
    {
        "id": "car_433",
        "label": "Car key 433",
        "center_mhz": 433.92,
        "span_mhz": 10.0,
        "band_lo_mhz": 420.0,
        "band_hi_mhz": 450.0,
        "icon": "car",
        "device_type_id": "garage_433",
        "attack_profile": "ism_433",
        "code_hint": "rolling",
        "note": "Most 2012+ car fobs (e.g. Renault Clio Hitag AES) use rolling codes — IQ replay rarely unlocks. Capture out of car range to validate RF; use a fixed garage remote to prove the TX path.",
    },
    {
        "id": "remote_315",
        "label": "Remote / fob 315",
        "center_mhz": 315.0,
        "span_mhz": 8.0,
        "band_lo_mhz": 310.0,
        "band_hi_mhz": 320.0,
        "icon": "fob",
        "device_type_id": "garage_315",
        "attack_profile": "ism_315",
        "code_hint": "likely_fixed",
        "note": "US ISM — uncommon in EU lab kits.",
    },
    {
        "id": "domotica_868",
        "label": "Home / IoT 868",
        "center_mhz": 868.3,
        "span_mhz": 8.0,
        "band_lo_mhz": 863.0,
        "band_hi_mhz": 870.0,
        "icon": "home",
        "device_type_id": "ism_868_domotica",
        "attack_profile": "ism_868",
    },
]

_BY_ID = {p["id"]: p for p in PRESETS}


def list_presets() -> list[dict[str, Any]]:
    return [dict(p) for p in PRESETS]


def get_preset(preset_id: str) -> dict[str, Any] | None:
    return dict(_BY_ID[preset_id]) if preset_id in _BY_ID else None


def synthetic_device(preset: dict[str, Any]) -> dict[str, Any]:
    """Device dict for /api/replay/listen without a tracker focus."""
    return {
        "radio": "hackrf",
        "freq_mhz": float(preset["center_mhz"]),
        "name": preset["label"],
        "device_type_id": preset.get("device_type_id") or preset["id"],
        "device_type_name": preset["label"],
        "key": f"clone:{preset['id']}",
        "metadata": {
            "attack_profile": preset.get("attack_profile"),
            "capability": "presence",
            "clone_preset": preset["id"],
            "code_hint": preset.get("code_hint"),
            "clone_note": preset.get("note"),
        },
    }


def spectrum(
    *,
    preset_id: str | None = None,
    freq_mhz: float | None = None,
    span_mhz: float | None = None,
) -> dict[str, Any]:
    """
    One narrow hackrf_sweep around a clone center — bins for the live analyzer.
    """
    preset = get_preset(preset_id) if preset_id else None
    if preset:
        center = float(preset["center_mhz"])
        span = float(span_mhz if span_mhz is not None else preset.get("span_mhz") or 10.0)
    elif freq_mhz is not None:
        center = float(freq_mhz)
        span = float(span_mhz if span_mhz is not None else 10.0)
    else:
        return {"ok": False, "error": "preset_id or freq_mhz required"}

    span = max(2.0, min(span, 40.0))
    f_lo = int(center - span / 2)
    f_hi = int(center + span / 2) + 1
    if f_hi <= f_lo:
        f_hi = f_lo + 1

    bins: list[dict[str, Any]] = []
    peak_dbm: float | None = None
    noise_dbm: float | None = None

    with exclusive("clone_spectrum"):
        pkill_rf_tools()
        cmd = [
            "hackrf_sweep",
            "-f", f"{f_lo}:{f_hi}",
            "-a", "1",
            "-p", "1",
            "-l", "32",
            "-g", "40",
            "-w", "100000",
            "-N", "2",
        ]
        if HACKRF_SERIAL:
            cmd = ["hackrf_sweep", "-d", HACKRF_SERIAL] + cmd[1:]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                preexec_fn=os.setsid,
            )
        except FileNotFoundError:
            return {"ok": False, "error": "hackrf_sweep not found"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

        chunks: list[str] = []
        deadline = time.time() + 12
        try:
            while proc.poll() is None:
                if time.time() > deadline:
                    kill_process_tree(proc, grace_s=0.2)
                    break
                time.sleep(0.05)
            if proc.stdout is not None:
                try:
                    out, _ = proc.communicate(timeout=1)
                    if out:
                        chunks.append(out)
                except Exception:
                    kill_process_tree(proc, grace_s=0.1)
        except Exception as exc:
            kill_process_tree(proc, grace_s=0.2)
            return {"ok": False, "error": str(exc)}

        stdout = "".join(chunks)

    # Aggregate max power per ~coarse bin
    acc: dict[int, float] = {}
    powers: list[float] = []
    for row in csv.reader(stdout.splitlines()):
        if len(row) < 7:
            continue
        try:
            hz_low = float(row[2])
            bin_w = float(row[4])
            dbs = [float(x) for x in row[6:]]
        except ValueError:
            continue
        for i, db in enumerate(dbs):
            if not (-120.0 < db < 5.0):
                continue
            f_mhz = (hz_low + i * bin_w) / 1e6
            if abs(f_mhz - center) > span / 2 + 0.5:
                continue
            powers.append(db)
            # ~200 kHz display buckets
            key = int(round(f_mhz / 0.2))
            prev = acc.get(key)
            if prev is None or db > prev:
                acc[key] = db

    if not acc:
        return {
            "ok": True,
            "preset_id": preset_id,
            "freq_mhz": center,
            "span_mhz": span,
            "peak_dbm": None,
            "noise_dbm": None,
            "bins": [],
            "note": "No sweep bins — is HackRF connected?",
        }

    items = sorted(((k * 0.2, v) for k, v in acc.items()), key=lambda x: x[0])
    # Downsample to ~60 bars max
    step = max(1, len(items) // 60)
    bins = [
        {"freq_mhz": round(f, 3), "power_dbm": round(p, 1)}
        for f, p in items[::step]
    ]
    peak_dbm = round(max(p for _, p in items), 1)
    noise_dbm = round(float(sorted(powers)[len(powers) // 2]), 1) if powers else None

    return {
        "ok": True,
        "preset_id": preset_id,
        "freq_mhz": center,
        "span_mhz": span,
        "peak_dbm": peak_dbm,
        "noise_dbm": noise_dbm,
        "bins": bins,
    }


# EU lab hunt bands (MHz ranges for hackrf_sweep -f lo:hi) — stay inside TX allowlist
_HUNT_BANDS: list[tuple[int, int, str]] = [
    (240, 360, "garage low / 315"),
    (420, 450, "433 ISM / garage"),
    (863, 870, "868 garage / IoT"),
]


def hunt(*, hold_s: float = 8.0) -> dict[str, Any]:
    """
    Wide sweep while the user repeatedly presses the remote.
    Returns candidate peaks above local noise (likely the fob TX).
    """
    hold_s = max(4.0, min(float(hold_s), 20.0))
    # Collect max-hold per ~100 kHz bucket across bands
    acc: dict[int, float] = {}  # key = round(mhz * 10) → 0.1 MHz
    powers: list[float] = []
    sweeps = 0
    notes: list[str] = []

    deadline = time.time() + hold_s
    with exclusive("clone_hunt"):
        pkill_rf_tools()
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining < 0.4:
                break
            for lo, hi, _label in _HUNT_BANDS:
                if time.time() >= deadline:
                    break
                cmd = [
                    "hackrf_sweep",
                    "-f", f"{lo}:{hi}",
                    "-a", "1",
                    "-p", "1",
                    "-l", "32",
                    "-g", "40",
                    "-w", "100000",
                    "-N", "1",
                ]
                if HACKRF_SERIAL:
                    cmd = ["hackrf_sweep", "-d", HACKRF_SERIAL] + cmd[1:]
                try:
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=min(8.0, max(2.0, remaining)),
                    )
                except FileNotFoundError:
                    return {"ok": False, "error": "hackrf_sweep not found"}
                except subprocess.TimeoutExpired as e:
                    out = (e.stdout or "") if isinstance(e.stdout, str) else ""
                    _accumulate_sweep(out, acc, powers)
                    sweeps += 1
                    continue
                except Exception as exc:
                    notes.append(str(exc))
                    continue
                _accumulate_sweep(proc.stdout or "", acc, powers)
                sweeps += 1

    if not acc:
        return {
            "ok": True,
            "candidates": [],
            "sweeps": sweeps,
            "note": "No sweep data — is HackRF free/connected? Press the remote during Find.",
        }

    items = [(k / 10.0, v) for k, v in acc.items()]
    noise = float(sorted(p for _, p in items)[len(items) // 2])
    # Candidates: well above noise
    cands = [
        {"freq_mhz": round(f, 3), "power_dbm": round(p, 1), "snr_db": round(p - noise, 1)}
        for f, p in items
        if p >= noise + 8.0
    ]
    cands.sort(key=lambda c: -c["power_dbm"])
    # Dedupe near neighbors (keep strongest within 0.3 MHz)
    picked: list[dict[str, Any]] = []
    for c in cands:
        if any(abs(c["freq_mhz"] - p["freq_mhz"]) < 0.3 for p in picked):
            continue
        picked.append(c)
        if len(picked) >= 8:
            break

    best = picked[0] if picked else None
    # Snap cellular-adjacent false peaks into EU868 and drop anything still OOB
    cleaned: list[dict[str, Any]] = []
    for c in picked:
        f = float(c["freq_mhz"])
        if tx_safety.in_allowlist(f):
            cleaned.append(c)
            continue
        snapped = tx_safety.nearest_allowlist_mhz(f)
        if snapped is None:
            continue
        cleaned.append({
            **c,
            "freq_mhz": round(float(snapped), 3),
            "snapped_from_mhz": round(f, 3),
            "note": f"snapped {f:.1f}→{snapped:.2f} (reject GSM/out-of-band)",
        })
    # Dedupe again after snap
    picked2: list[dict[str, Any]] = []
    for c in cleaned:
        if any(abs(c["freq_mhz"] - p["freq_mhz"]) < 0.3 for p in picked2):
            continue
        picked2.append(c)
        if len(picked2) >= 8:
            break
    picked = picked2
    best = picked[0] if picked else None

    suggested_preset = None
    if best:
        f = best["freq_mhz"]
        if 310 <= f <= 320:
            suggested_preset = "remote_315"
        elif 863 <= f <= 870:
            suggested_preset = "garage_868"
        elif 420 <= f <= 450:
            suggested_preset = "garage_433"

    return {
        "ok": True,
        "sweeps": sweeps,
        "noise_dbm": round(noise, 1),
        "hold_s": hold_s,
        "candidates": picked,
        "best": best,
        "suggested_preset": suggested_preset,
        "note": (
            f"Best {best['freq_mhz']} MHz ({best['snr_db']:+.0f} dB SNR) — lock & Record"
            + (f" (was {best['snapped_from_mhz']} clutter)" if best.get("snapped_from_mhz") else "")
            if best
            else "No strong peak in lab bands — hold the button closer; ignore GSM ~880 MHz clutter"
        ),
        "hints": notes[:3],
        "allowlist_mhz": [
            {"lo": a, "hi": b, "label": lab} for a, b, lab in tx_safety.ALLOWLIST_MHZ
        ],
    }


def _accumulate_sweep(stdout: str, acc: dict[int, float], powers: list[float]) -> None:
    for row in csv.reader(stdout.splitlines()):
        if len(row) < 7:
            continue
        try:
            hz_low = float(row[2])
            bin_w = float(row[4])
            dbs = [float(x) for x in row[6:]]
        except ValueError:
            continue
        for i, db in enumerate(dbs):
            if not (-120.0 < db < 5.0):
                continue
            f_mhz = (hz_low + i * bin_w) / 1e6
            # Lab allowlist ONLY — never promote GSM ~880 as "868"
            if not tx_safety.in_allowlist(f_mhz):
                continue
            powers.append(db)
            key = int(round(f_mhz * 10))  # 0.1 MHz
            prev = acc.get(key)
            if prev is None or db > prev:
                acc[key] = db

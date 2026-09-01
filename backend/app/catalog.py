from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

CATALOG_PATH = Path(__file__).resolve().parents[1] / "data" / "device_catalog.yaml"

# Official HackRF One RX range (MHz). Below ~10 MHz sensitivity is poor but still swept.
HACKRF_FMIN_MHZ = 1
HACKRF_FMAX_MHZ = 6000
FULL_SWEEP_CHUNK_MHZ = 100


def load_catalog() -> dict[str, Any]:
    with CATALOG_PATH.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_device_types() -> list[dict[str, Any]]:
    cat = load_catalog()
    return cat.get("device_types", [])


def get_categories() -> list[dict[str, Any]]:
    cat = load_catalog()
    return cat.get("categories", [])


def build_full_spectrum_bands(
    fmin: float = HACKRF_FMIN_MHZ,
    fmax: float = HACKRF_FMAX_MHZ,
    chunk_mhz: float = FULL_SWEEP_CHUNK_MHZ,
) -> list[dict[str, Any]]:
    """Chunk HackRF range for hackrf_sweep (one CSV / sweep call per chunk)."""
    bands: list[dict[str, Any]] = []
    f = float(fmin)
    end = float(fmax)
    while f < end - 0.001:
        f2 = min(f + chunk_mhz, end)
        # Coarser FFT at higher freq → faster full survey
        bw = 250_000 if f >= 1000 else 100_000
        bands.append({
            "freq_min_mhz": int(round(f)),
            "freq_max_mhz": int(round(f2)),
            "bin_width_hz": bw,
            "center_mhz": round((f + f2) / 2, 1),
        })
        f = f2
    return bands


def expand_device_type(dt: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with runtime-expanded bands (full_spectrum)."""
    out = dict(dt)
    if out.get("id") == "full_spectrum" and not out.get("bands"):
        out["bands"] = build_full_spectrum_bands()
    return out


def get_device_by_id(device_id: str) -> dict[str, Any] | None:
    for dt in get_device_types():
        if dt["id"] == device_id:
            return expand_device_type(dt)
    return None


def catalog_band_hint(freq_mhz: float) -> dict[str, Any] | None:
    """If freq falls in a known catalog band (not full_spectrum), return a hint."""
    for dt in get_device_types():
        if dt.get("id") == "full_spectrum" or dt.get("radio") != "hackrf":
            continue
        for band in dt.get("bands") or []:
            lo = float(band.get("freq_min_mhz") or 0)
            hi = float(band.get("freq_max_mhz") or 0)
            if lo <= freq_mhz <= hi:
                return {
                    "device_type_id": dt["id"],
                    "device_type_name": dt.get("name"),
                    "attack_profile": dt.get("attack_profile"),
                    "band_mhz": f"{lo}-{hi}",
                }
    return None

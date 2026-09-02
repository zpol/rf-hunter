"""Full HackRF spectrum sweep helpers."""

from backend.app.catalog import (
    HACKRF_FMAX_MHZ,
    HACKRF_FMIN_MHZ,
    build_full_spectrum_bands,
    expand_device_type,
    get_device_by_id,
)
from backend.app.scanner import exclude_frequency_range


def test_build_full_spectrum_covers_hackrf_range():
    bands = build_full_spectrum_bands()
    assert bands
    assert bands[0]["freq_min_mhz"] == HACKRF_FMIN_MHZ
    assert bands[-1]["freq_max_mhz"] == HACKRF_FMAX_MHZ
    # Contiguous chunks
    for a, b in zip(bands, bands[1:]):
        assert a["freq_max_mhz"] == b["freq_min_mhz"]
    # ~60 chunks of 100 MHz
    assert 55 <= len(bands) <= 65


def test_full_spectrum_type_expands_bands():
    dt = get_device_by_id("full_spectrum")
    assert dt is not None
    assert dt["bands"]
    assert len(dt["bands"]) == len(build_full_spectrum_bands())
    # expand is idempotent if bands already filled
    again = expand_device_type(dt)
    assert len(again["bands"]) == len(dt["bands"])


def test_exclude_fm_broadcast_splits_overlapping_sweep_chunks():
    bands = [
        {"freq_min_mhz": 24, "freq_max_mhz": 124, "bin_width_hz": 100000, "center_mhz": 74},
        {"freq_min_mhz": 124, "freq_max_mhz": 224, "bin_width_hz": 100000, "center_mhz": 174},
    ]
    filtered = exclude_frequency_range(bands, 87.5, 108.0)
    assert [(b["freq_min_mhz"], b["freq_max_mhz"]) for b in filtered] == [
        (24.0, 87.5),
        (108.0, 124.0),
        (124, 224),
    ]
    assert all(
        float(b["freq_max_mhz"]) <= 87.5 or float(b["freq_min_mhz"]) >= 108.0
        for b in filtered
    )


def test_exclude_range_can_remove_entire_band():
    bands = [{"freq_min_mhz": 90, "freq_max_mhz": 100, "bin_width_hz": 100000}]
    assert exclude_frequency_range(bands, 87.5, 108.0) == []

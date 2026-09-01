"""Full HackRF spectrum sweep helpers."""

from backend.app.catalog import (
    HACKRF_FMAX_MHZ,
    HACKRF_FMIN_MHZ,
    build_full_spectrum_bands,
    expand_device_type,
    get_device_by_id,
)


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

"""Unit tests for replay IQ analysis / artifacts (no HackRF)."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from backend.app import replay


def _synth_iq(path: Path, rate: int = 2_000_000, duration_s: float = 0.8, offset_hz: float = 40_000.0):
    """OOK-ish tone bursts at baseband offset (several frames for STFT)."""
    n = int(rate * duration_s)
    t = np.arange(n) / rate
    env = np.zeros(n)
    # three ~40 ms bursts
    for t0 in (0.15, 0.28, 0.41):
        a = int(t0 * rate)
        b = a + int(0.04 * rate)
        env[a:b] = 1.0
    carrier = env * np.exp(2j * np.pi * offset_hz * t)
    i = np.clip(np.real(carrier) * 110, -127, 127).astype(np.int8)
    q = np.clip(np.imag(carrier) * 110, -127, 127).astype(np.int8)
    interleaved = np.empty(n * 2, dtype=np.int8)
    interleaved[0::2] = i
    interleaved[1::2] = q
    interleaved.tofile(path)


def test_analyze_detects_offset_and_wav(tmp_path: Path):
    iq = tmp_path / "listen.raw"
    _synth_iq(iq, offset_hz=35_000)
    analysis = replay._analyze_listen_iq(iq, 2_000_000, 433.92)
    assert analysis["usable"] is True
    assert analysis["burst_count"] >= 1
    assert analysis["freq_offset_hz"] is not None
    assert abs(analysis["freq_offset_hz"] - 35_000) < 5_000

    arts = replay._write_listen_artifacts(iq, 2_000_000, analysis)
    assert arts.get("wav_am_file")
    assert Path(arts["wav_am_file"]).is_file()
    assert Path(arts["wav_am_file"]).stat().st_size > 100


def test_apply_code_hint_car_preset():
    cc = replay._apply_code_hint(
        {"class": "unknown", "detail": "no frames"},
        {
            "key": "clone:car_433",
            "metadata": {"code_hint": "rolling", "clone_note": "lab note"},
        },
    )
    assert cc["class"] == "rolling"
    assert "lab note" in cc.get("replay_advice", "")


def test_reanalyze_writes_meta(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(replay, "CAPTURES", tmp_path)
    cap = "CAP-test0001"
    d = tmp_path / cap
    d.mkdir()
    iq = d / "listen.raw"
    _synth_iq(iq, offset_hz=40_000)
    meta = {
        "capture_id": cap,
        "device_key": "clone:car_433",
        "freq_mhz": 433.92,
        "sample_rate": 2_000_000,
        "iq_file": str(iq),
        "code_class": {"class": "unknown"},
        "target": {"device_type_id": "garage_433"},
    }
    (d / "listen.json").write_text(json.dumps(meta))
    out = replay.reanalyze_capture(cap)
    assert out["ok"] is True
    assert out["tx_freq_mhz"] > 433.92
    assert Path(out["wav_am_file"]).is_file()
    assert out["code_class"]["class"] == "rolling"

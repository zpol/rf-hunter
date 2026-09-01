#!/usr/bin/env python3
"""Basic tests for research triage helpers."""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "research"))
from generate_research_report import parse_cu8_name, parse_since, quality_score


def test_parse_since_relative():
    now = datetime(2026, 7, 31, 18, 0, tzinfo=timezone.utc)
    t0 = parse_since("6 hours ago", now)
    assert t0 == now - timedelta(hours=6)


def test_cu8_name():
    d = parse_cu8_name("g445.784M_2000000sps.cu8")
    assert d["sample_rate_sps"] == 2_000_000
    assert abs(d["center_frequency_hz"] - 445.784e6) < 1


def test_quality_cw_penalty():
    q, why = quality_score(
        {
            "kind": "deep_dive_json",
            "snr_db": 42,
            "signal_type": "CW",
            "rtl433_frames": 0,
        }
    )
    assert "cw_no_frames" in why
    assert 0 <= q <= 100

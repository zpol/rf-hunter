"""Tests for RF Hunter v2 TUI, tracker, and risk."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("RF_HUNTER_CAPTURES", str(ROOT.parent / "captures" / "rf-hunter-v2"))

from tui.app import (  # noqa: E402
    RFHunterApp,
    dtype_ids_for_tab,
    hackrf_status,
    label_for_device,
    parse_int,
)
from backend.app import catalog  # noqa: E402
from backend.app import risk as risk_mod  # noqa: E402
from backend.app.tracker import (  # noqa: E402
    DeviceTracker,
    colored_bar,
    device_key,
    signal_bar,
    signal_color,
    signal_level,
)


# ── unit helpers ──────────────────────────────────────────────


def test_catalog_has_types_and_categories():
    types = catalog.get_device_types()
    cats = catalog.get_categories()
    assert len(types) >= 10
    assert len(cats) >= 3
    ids = {t["id"] for t in types}
    assert "tpms_eu" in ids
    assert "tuya_ble" in ids


def test_label_for_device_hackrf():
    dt = catalog.get_device_by_id("tpms_eu")
    assert dt is not None
    label = label_for_device(dt)
    assert "TPMS" in label
    assert "HACKRF" in label


def test_label_for_device_ble():
    dt = catalog.get_device_by_id("tuya_ble")
    assert dt is not None
    label = label_for_device(dt)
    assert "BLE" in label


def test_parse_int_clamps_and_defaults():
    assert parse_int("40", 40, 5, 600) == 40
    assert parse_int("0", 40, 5, 600) == 5
    assert parse_int("9999", 40, 5, 600) == 600
    assert parse_int("", 40, 5, 600) == 40
    assert parse_int("abc", 40, 5, 600) == 40


def test_dtype_ids_for_tab_all_and_category():
    types = catalog.get_device_types()
    cats = catalog.get_categories()
    all_ids = dtype_ids_for_tab("tab-all", types, cats)
    assert len(all_ids) == len(types)
    auto = dtype_ids_for_tab("tab-automotive", types, cats)
    assert "tpms_eu" in auto
    assert "tuya_ble" not in auto


def test_hackrf_status_returns_tuple():
    ok, detail = hackrf_status()
    assert isinstance(ok, bool)
    assert isinstance(detail, str)


# ── tracker / signal bars ─────────────────────────────────────


def test_signal_level_and_bar_colors():
    assert signal_level(db=-90) == 0
    assert signal_level(db=-20) == 10
    assert signal_color(2) == "red"
    assert signal_color(5) == "yellow"
    assert signal_color(9) == "green"
    bar = signal_bar(5, 10)
    assert len(bar) == 10
    assert "█" in bar and "░" in bar
    rich = colored_bar(8, 10)
    assert "[green]" in rich


def test_device_tracker_upsert_and_sort():
    t = DeviceTracker(stale_after_s=999)
    weak = {
        "id": "a",
        "radio": "ble",
        "mac": "AA:BB:CC:DD:EE:01",
        "rssi_dbm": -80,
        "device_type_id": "tuya_ble",
        "device_type_name": "Tuya",
        "metadata": {"attack_profile": "tuya_ble"},
    }
    strong = {
        "id": "b",
        "radio": "ble",
        "mac": "AA:BB:CC:DD:EE:02",
        "rssi_dbm": -40,
        "device_type_id": "tuya_ble",
        "device_type_name": "Tuya",
        "metadata": {"attack_profile": "tuya_ble"},
    }
    t.upsert(weak)
    t.upsert(strong)
    # update weak with stronger signal
    weak2 = {**weak, "rssi_dbm": -35}
    e = t.upsert(weak2)
    assert e["hit_count"] == 2
    assert len(e["signal_history"]) == 2
    snap = t.snapshot()
    assert snap[0]["mac"] == "AA:BB:CC:DD:EE:01"  # now strongest
    assert snap[0]["risk_status"] == "suspected"


def test_device_key_stable():
    assert device_key({"radio": "ble", "mac": "aa:bb:cc:dd:ee:ff"}) == "ble:AA:BB:CC:DD:EE:FF"
    assert device_key({"radio": "hackrf", "freq_mhz": 433.92, "device_type_id": "tpms_eu"}).startswith(
        "rf:433.920:tpms_eu"
    )


def test_assess_risk_tuya_and_rf():
    ble_dev = {
        "radio": "ble",
        "mac": "AA:BB:CC:00:00:01",
        "metadata": {"attack_profile": "tuya_ble", "tuya_detected": True},
    }
    analysis = {
        "ble": {
            "connected": True,
            "services": [
                {
                    "uuid": "00001812-0000-1000-8000-00805f9b34fb",
                    "characteristics": [
                        {"uuid": "x", "properties": ["write"], "value_hex": None},
                    ],
                }
            ],
        }
    }
    r = risk_mod.assess_risk(ble_dev, analysis)
    assert r["status"] == "critical"
    assert r["severity"] == "critical"
    assert r["exploitability"] == "CRITICAL"

    rf = risk_mod.assess_risk(
        {"radio": "hackrf", "freq_mhz": 433.9, "metadata": {"attack_profile": "tpms_433"}},
        {"rf": {"snr_db": 20, "signal_type": "modulated/wide"}},
    )
    assert rf["status"] in ("medium", "high", "critical")
    assert rf["summary"]


def test_assess_risk_quick_classifies():
    r = risk_mod.assess_risk_quick(
        {
            "radio": "ble",
            "mac": "AA:BB:CC:00:00:02",
            "metadata": {"attack_profile": "tuya_ble", "tuya_detected": True},
        }
    )
    assert r["severity"] == "critical"
    assert r["mode"] == "quick"


# ── Textual app ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_app_mounts_with_wardrive_controls():
    app = RFHunterApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        assert len(app._types) >= 10
        assert app.query_one("#btn-wardrive")
        assert app.query_one("#btn-monitor")
        assert app.query_one("#btn-dive")
        assert app.query_one("#detail")


@pytest.mark.asyncio
async def test_select_all_and_refuse_empty_scan():
    app = RFHunterApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        app.action_select_all()
        await pilot.pause()
        assert len(app._selected) >= 5

        app.action_clear_selection()
        await pilot.pause()
        assert app.selected_count == 0
        with patch.object(app, "_log") as log:
            app.action_start_wardrive()
            await pilot.pause()
            assert app.scan_status == "idle"
            assert any("Nothing selected" in str(c) for c in log.call_args_list)


@pytest.mark.asyncio
async def test_wardrive_start_mocked():
    app = RFHunterApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        app._selected = {"tpms_eu", "tuya_ble"}
        app._apply_selected_to_lists()
        app.selected_count = 2
        await pilot.pause()

        mock_session = MagicMock()
        mock_session.start.return_value = "WD-TEST"
        mock_session.subscribe = MagicMock()

        with patch("tui.app.scanner.session", mock_session):
            app.action_start_wardrive()
            await pilot.pause()

        mock_session.start.assert_called_once()
        args, kwargs = mock_session.start.call_args
        assert kwargs.get("mode") == "wardrive" or (len(args) >= 6 and args[5] == "wardrive")
        assert app.scan_status == "running"


@pytest.mark.asyncio
async def test_tracker_snapshot_refreshes_table():
    from tui.app import ScanEvent

    app = RFHunterApp()
    async with app.run_test(size=(160, 45)) as pilot:
        await pilot.pause()
        from backend.app import tracker as tracker_mod

        tracker_mod.tracker.clear()
        tracker_mod.tracker.upsert(
            {
                "id": "x1",
                "radio": "ble",
                "mac": "11:22:33:44:55:66",
                "name": "Probe",
                "rssi_dbm": -55,
                "device_type_id": "tuya_ble",
                "device_type_name": "Tuya BLE",
                "metadata": {"attack_profile": "tuya_ble"},
            }
        )
        app.post_message(ScanEvent({"type": "tracker_snapshot", **tracker_mod.tracker.to_dict()}))
        await pilot.pause()
        assert len(app._row_keys) == 1
        assert "ble:11:22:33:44:55:66" in app._row_keys

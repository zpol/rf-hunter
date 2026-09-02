"""Focused real-time monitor for one RF frequency or BLE MAC."""

from __future__ import annotations

import asyncio
import os
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from . import tracker as tracker_mod
from . import radio as radio_mod
from .procutil import kill_process_tree, pkill_rf_tools

HACKRF_SERIAL = os.environ.get("HACKRF_SERIAL", "")


def _bar(db: float, floor: float = -90.0, ceil: float = -20.0, width: int = 28) -> str:
    x = (db - floor) / (ceil - floor)
    x = max(0.0, min(1.0, x))
    n = int(round(x * width))
    return "[" + "#" * n + "." * (width - n) + "]"


def _hint(db: float, baseline: float | None) -> str:
    if baseline is None:
        return "baseline…"
    delta = db - baseline
    if delta >= 8:
        return ">>> VERY CLOSE"
    if delta >= 3:
        return ">> closer / stronger"
    if delta <= -5:
        return "<< moving away"
    return "~ steady"


def sweep_peak(
    center_mhz: float,
    span_mhz: float = 0.5,
    sweeps: int = 4,
    stop_event: threading.Event | None = None,
) -> float | None:
    """Peak dBFS near center via normalized IQ from either receiver."""
    try:
        import numpy as np

        rate = 2_000_000
        sample_count = max(131_072, int(sweeps) * 65_536)
        with tempfile.TemporaryDirectory(prefix="rf-hunter-monitor-") as tmp:
            path = os.path.join(tmp, "monitor.cs8")
            capture = radio_mod.capture_iq(
                path, freq_hz=int(center_mhz * 1e6), sample_rate=rate,
                num_samples=sample_count, lna_db=32, vga_db=40,
                timeout=8, stop_event=stop_event,
            )
            if not capture.ok:
                return None
            raw = np.fromfile(path, dtype=np.int8)
    except Exception:
        return None
    raw = raw[: raw.size // 2 * 2]
    if raw.size < 4096:
        return None
    z = (raw[0::2].astype(np.float32) + 1j * raw[1::2].astype(np.float32)) / 128.0
    n = min(z.size, 262_144)
    spectrum = np.abs(np.fft.fftshift(np.fft.fft(z[:n] * np.hanning(n)))) / n
    freqs = np.fft.fftshift(np.fft.fftfreq(n, 1.0 / rate))
    mask = np.abs(freqs) <= span_mhz * 500_000.0
    if not np.any(mask):
        return None
    return float(20.0 * np.log10(float(np.max(spectrum[mask])) + 1e-12))


class MonitorSession:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.status: str = "idle"
        self.device_key: str | None = None
        self.target: dict[str, Any] | None = None
        self.last_sample: dict[str, Any] | None = None
        self._listeners: list[Callable[[dict], None]] = []
        self._baseline: float | None = None

    def subscribe(self, cb: Callable[[dict], None]) -> None:
        self._listeners.append(cb)

    def _emit(self, event: dict) -> None:
        for cb in self._listeners:
            try:
                cb(event)
            except Exception:
                pass

    def is_running(self) -> bool:
        return self.status == "running"

    def start(self, device: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if self.status == "running":
                self._stop.set()
                if self._thread and self._thread.is_alive():
                    self._thread.join(timeout=2.0)
            self._stop.clear()
            self.device_key = tracker_mod.device_key(device)
            self.target = dict(device)
            self.status = "running"
            self.last_sample = None
            self._baseline = None

        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return {"ok": True, "device_key": self.device_key, "status": self.status}

    def stop(self) -> None:
        self._stop.set()
        self.status = "stopped"
        pkill_rf_tools()
        self._emit({"type": "monitor_stop", "device_key": self.device_key})

    def _run(self) -> None:
        target = self.target or {}
        radio = (target.get("radio") or "hackrf").lower()
        try:
            if radio == "ble":
                self._run_ble(target)
            else:
                self._run_rf(target)
        except Exception as e:
            self.status = "error"
            self._emit({"type": "error", "message": f"monitor: {e}"})
        finally:
            if self.status == "running":
                self.status = "stopped"

    def _emit_sample(self, db: float, extra: dict | None = None) -> None:
        if self._baseline is None:
            self._baseline = db
        level = tracker_mod.signal_level(db=db)
        sample = {
            "type": "monitor_sample",
            "device_key": self.device_key,
            "db": round(db, 1),
            "level": level,
            "bar": _bar(db),
            "color": tracker_mod.signal_color(level),
            "hint": _hint(db, self._baseline),
            "utc": datetime.now(timezone.utc).isoformat(),
            **(extra or {}),
        }
        self.last_sample = sample
        # Keep tracker signal fresh
        if self.target:
            patched = dict(self.target)
            if patched.get("radio") == "ble":
                patched["rssi_dbm"] = db
            else:
                patched["power_dbm"] = db
            tracker_mod.tracker.upsert(patched)
        self._emit(sample)

    def _run_rf(self, target: dict[str, Any]) -> None:
        freq = target.get("freq_mhz")
        if freq is None:
            self.status = "error"
            self._emit({"type": "error", "message": "monitor: no freq_mhz"})
            return
        center = float(freq)
        while not self._stop.is_set():
            peak = sweep_peak(center, span_mhz=0.6, sweeps=4, stop_event=self._stop)
            if peak is not None:
                self._emit_sample(peak, {"freq_mhz": center})
            else:
                self._emit({
                    "type": "monitor_sample",
                    "device_key": self.device_key,
                    "db": None,
                    "level": 0,
                    "bar": "[............................]",
                    "hint": "no peak",
                    "utc": datetime.now(timezone.utc).isoformat(),
                })
            # brief pause between samples
            for _ in range(5):
                if self._stop.is_set():
                    break
                time.sleep(0.1)

    def _run_ble(self, target: dict[str, Any]) -> None:
        mac = (target.get("mac") or "").upper()
        if not mac:
            self.status = "error"
            self._emit({"type": "error", "message": "monitor: no mac"})
            return
        while not self._stop.is_set():
            rssi = asyncio.run(self._ble_rssi(mac, timeout=2.5))
            if rssi is not None:
                self._emit_sample(float(rssi), {"mac": mac})
            else:
                self._emit({
                    "type": "monitor_sample",
                    "device_key": self.device_key,
                    "db": None,
                    "level": 0,
                    "bar": "[............................]",
                    "hint": "no adv",
                    "mac": mac,
                    "utc": datetime.now(timezone.utc).isoformat(),
                })
            for _ in range(3):
                if self._stop.is_set():
                    break
                time.sleep(0.15)

    async def _ble_rssi(self, mac: str, timeout: float = 2.5) -> float | None:
        try:
            from bleak import BleakScanner
        except ImportError:
            return None
        found: dict[str, float] = {}

        def _cb(device: Any, adv: Any) -> None:
            addr = (device.address or "").upper()
            if addr == mac:
                found[addr] = float(adv.rssi)

        scanner = BleakScanner(detection_callback=_cb)
        await scanner.start()
        await asyncio.sleep(timeout)
        await scanner.stop()
        return found.get(mac)


monitor = MonitorSession()

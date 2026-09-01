from __future__ import annotations

import asyncio
import json
import os
import statistics
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .catalog import get_device_by_id
from . import ble_scanner
from . import tracker as tracker_mod
from .models import DetectedDevice
from .procutil import kill_process_tree, pkill_rf_tools

# Default to sibling captures dir (bare metal). Docker sets RF_HUNTER_CAPTURES=/data/...
_DEFAULT_CAPTURES = Path(__file__).resolve().parents[2].parent / "captures" / "rf-hunter-v2"
CAPTURES = Path(os.environ.get("RF_HUNTER_CAPTURES", str(_DEFAULT_CAPTURES)))
HACKRF_SERIAL = os.environ.get("HACKRF_SERIAL", "")


class ScanSession:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._active_proc: subprocess.Popen | None = None
        self.session_id: str | None = None
        self.status: str = "idle"
        self.mode: str = "once"
        self.progress: float = 0.0
        self.message: str = ""
        self.current_band: dict[str, Any] | None = None
        self.band_index: int = 0
        self.band_total: int = 0
        self.devices: list[dict[str, Any]] = []
        self.logs: list[str] = []
        self.pass_count: int = 0
        self._listeners: list[Callable[[dict], None]] = []
        self._paused = threading.Event()
        self._pause_reason = ""
        self.live_decode = True
        self._restore_last_report()

    def subscribe(self, cb: Callable[[dict], None]) -> None:
        self._listeners.append(cb)

    def _emit_progress(
        self,
        *,
        fmin: float | None = None,
        fmax: float | None = None,
        peaks: int | None = None,
        label: str | None = None,
    ) -> None:
        if fmin is not None and fmax is not None:
            self.current_band = {
                "freq_min_mhz": float(fmin),
                "freq_max_mhz": float(fmax),
            }
            self.message = label or f"Sweeping {fmin:g}–{fmax:g} MHz…"
        elif label:
            self.message = label
        payload: dict[str, Any] = {
            "type": "progress",
            "progress": self.progress,
            "pass": self.pass_count,
            "message": self.message,
            "mode": self.mode,
            "band_index": self.band_index,
            "band_total": self.band_total,
            "current_band": self.current_band,
        }
        if peaks is not None:
            payload["peaks"] = peaks
        self._emit(payload)

    def _emit(self, event: dict) -> None:
        for cb in self._listeners:
            try:
                cb(event)
            except Exception:
                pass

    def _log(self, msg: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        self.logs.append(line)
        self._emit({"type": "log", "message": line})

    def is_running(self) -> bool:
        return self.status == "running"

    def is_paused(self) -> bool:
        return self._paused.is_set()

    def pause(self, reason: str = "HackRF busy") -> None:
        """Pause wardrive between passes and kill active sweep immediately."""
        self._pause_reason = reason
        self._paused.set()
        self.message = f"Paused — {reason}"
        with self._lock:
            proc = self._active_proc
        if proc and proc.poll() is None:
            kill_process_tree(proc)
        self._log(f"Paused — {reason}")
        self._emit({"type": "scan_paused", "reason": reason})

    def resume(self) -> None:
        if not self._paused.is_set():
            return
        self._paused.clear()
        self._pause_reason = ""
        if self.status == "running":
            self.message = "Resuming wardrive…"
        self._log("Resumed wardrive")
        self._emit({"type": "scan_resumed"})

    def _wait_if_paused(self) -> None:
        while self._paused.is_set() and not self._stop.is_set():
            self.message = f"Paused — {self._pause_reason or 'HackRF busy'}"
            time.sleep(0.2)

    def _restore_last_report(self) -> None:
        if not CAPTURES.is_dir():
            return

        latest: tuple[float, Path] | None = None
        for session_dir in CAPTURES.iterdir():
            if not session_dir.is_dir():
                continue
            report_path = session_dir / "report.json"
            if not report_path.is_file():
                continue
            try:
                mtime = report_path.stat().st_mtime
            except OSError:
                continue
            if latest is None or mtime > latest[0]:
                latest = (mtime, report_path)

        if latest is None:
            return

        try:
            data = json.loads(latest[1].read_text())
        except (OSError, json.JSONDecodeError):
            return

        devices = data.get("devices")
        if not isinstance(devices, list):
            return

        self.session_id = data.get("session_id") or latest[1].parent.name
        self.devices = devices
        self.status = "completed"
        self.progress = 100.0
        n = len(devices)
        self.message = f"Restored — {n} detection(s) from {self.session_id}"
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.logs = [f"[{ts}] Restored last scan ({self.session_id}, {n} hits)"]
        for d in devices:
            try:
                tracker_mod.tracker.upsert(d)
            except Exception:
                pass

    def start(
        self,
        device_type_ids: list[str],
        duration_s: int,
        lna_db: int,
        vga_db: int,
        passes: int,
        mode: str = "once",
        live_decode: bool = True,
        clear_results: bool = False,
    ) -> str:
        with self._lock:
            if self.status == "running":
                raise RuntimeError("Scan already running")
            self._stop.clear()
            self._paused.clear()
            self.live_decode = bool(live_decode)
            if mode == "full_sweep":
                self.mode = "full_sweep"
                device_type_ids = ["full_spectrum"]
                # Full 1–6 GHz is slow — keep sweeps per chunk low
                passes = max(2, min(int(passes), 6))
            elif mode == "wardrive":
                self.mode = "wardrive"
            else:
                self.mode = "once"
            prefix = (
                "FULL" if self.mode == "full_sweep"
                else "WD" if self.mode == "wardrive"
                else "SCAN"
            )
            self.session_id = datetime.now(timezone.utc).strftime(f"{prefix}-%Y%m%dT%H%M%SZ")
            self.status = "running"
            self.progress = 0.0
            self.logs = []
            self.pass_count = 0
            self.current_band = None
            self.band_index = 0
            self.band_total = 0
            if clear_results:
                self.devices = []
                if self.mode == "full_sweep":
                    self.message = "Starting full spectrum sweep (fresh)…"
                elif self.mode == "wardrive":
                    self.message = "Starting wardrive (fresh)…"
                else:
                    self.message = "Starting scan (fresh)…"
            else:
                # Keep prior detections — seed session list from tracker
                self.devices = list(tracker_mod.tracker.snapshot())
                n = len(self.devices)
                if self.mode == "full_sweep":
                    self.message = f"Full sweep — keeping {n} device(s)…"
                elif self.mode == "wardrive":
                    self.message = f"Resuming wardrive — keeping {n} device(s)…"
                else:
                    self.message = f"Starting scan — keeping {n} device(s)…"

        if clear_results:
            tracker_mod.tracker.clear()
            self.devices = []
            try:
                from . import gps as gps_mod

                gps_mod.gps.clear_trail()
            except Exception:
                pass
            try:
                from . import wifi_scanner as wifi_mod

                wifi_mod.wifi.clear_and_notify()
            except Exception:
                pass
        else:
            tracker_mod.tracker.clear_stale_flags()

        out_dir = CAPTURES / self.session_id
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            with self._lock:
                self.status = "error"
                self.message = f"Cannot create captures dir: {exc}"
            raise RuntimeError(f"Cannot create captures dir {out_dir}: {exc}") from exc

        self._log(
            f"Session {self.session_id} — "
            + ("cleared tracker" if clear_results else f"keeping {len(self.devices)} prior hit(s)")
        )

        self._thread = threading.Thread(
            target=self._run,
            args=(device_type_ids, duration_s, lna_db, vga_db, passes, out_dir),
            daemon=True,
        )
        self._thread.start()
        return self.session_id

    def stop(self) -> None:
        """Request stop and force-kill any active HackRF child immediately."""
        self._stop.set()
        self._paused.clear()
        self.message = "Stopped"
        # Flip to stopped right away so UI does not stick on Stopping…
        self.status = "stopped"
        self._log("Stop requested — killing RF processes")
        with self._lock:
            proc = self._active_proc
        kill_process_tree(proc, grace_s=0.25)
        killed = pkill_rf_tools()
        if killed:
            self._log(f"Force-killed: {', '.join(killed)}")
        # Clear stale flags — after stop everything would look "dead" otherwise
        tracker_mod.tracker.clear_stale_flags()
        self._emit({"type": "complete", "status": "stopped", "devices": tracker_mod.tracker.snapshot()})
        self._emit_snapshot()
        tracker_mod.tracker.persist(force=True)

    def _ingest(self, device: dict[str, Any]) -> dict[str, Any] | None:
        from . import quality as quality_mod

        device = quality_mod.attach_quality(device)
        q = (device.get("metadata") or {}).get("quality") or {}
        if quality_mod.should_drop_as_fp(device, q):
            freq = device.get("freq_mhz")
            self._log(
                f"FP drop · {device.get('device_type_id')} "
                f"{freq if freq is not None else '?'} MHz · "
                f"{q.get('tier', '?')} — {q.get('summary', 'noise')}"
            )
            return None
        entry = tracker_mod.tracker.upsert(device)
        entry = tracker_mod.tracker.refresh_quality(entry["key"])
        key = entry["key"]
        replaced = False
        for i, d in enumerate(self.devices):
            if tracker_mod.device_key(d) == key:
                self.devices[i] = entry
                replaced = True
                break
        if not replaced:
            self.devices.append(entry)
        self._emit({"type": "device", "device": entry})
        self._emit({"type": "device_update", "device": entry})
        return entry

    def _emit_snapshot(self) -> None:
        from . import wow as wow_mod

        snap = tracker_mod.tracker.to_dict()
        snap["devices"] = [wow_mod.enrich(d) for d in snap.get("devices") or []]
        self._emit({"type": "tracker_snapshot", **snap})

    def _run(
        self,
        device_type_ids: list[str],
        duration_s: int,
        lna_db: int,
        vga_db: int,
        passes: int,
        out_dir: Path,
    ) -> None:
        try:
            types = [get_device_by_id(d) for d in device_type_ids]
            types = [t for t in types if t]
            if not types:
                raise ValueError("No valid device types selected")

            # Wardrive: short passes for walking feedback
            if self.mode == "wardrive":
                passes = max(8, min(passes, 40))
                ble_cap = min(duration_s, 8)
            elif self.mode == "full_sweep":
                passes = max(2, min(passes, 6))
                ble_cap = None
                n_bands = sum(len(t.get("bands") or []) for t in types)
                self._log(
                    f"Full spectrum sweep — {n_bands} chunk(s), "
                    f"{passes} sweep(s)/chunk, HackRF 1–6000 MHz"
                )
            else:
                ble_cap = None

            self._log(
                f"Session {self.session_id} — mode={self.mode}, "
                f"{len(types)} type(s), {duration_s}s, passes={passes}"
            )

            loop_n = 0
            while not self._stop.is_set():
                self._wait_if_paused()
                if self._stop.is_set():
                    break
                loop_n += 1
                self.pass_count = loop_n
                self._log(
                    f"Pass {loop_n}"
                    + (
                        " (wardrive)" if self.mode == "wardrive"
                        else " (full sweep)" if self.mode == "full_sweep"
                        else ""
                    )
                )
                self._run_pass(types, duration_s, lna_db, vga_db, passes, out_dir, ble_cap)
                self._emit_snapshot()

                # Live decode wow — short IQ on top ISM/TPMS hits between passes
                # Skip during full_sweep (too many unknown peaks; use focused dive later)
                if (
                    self.live_decode
                    and self.mode != "full_sweep"
                    and not self._stop.is_set()
                    and not self._paused.is_set()
                ):
                    try:
                        from . import live_decode

                        updates = live_decode.enrich_pass(
                            tracker_mod.tracker.snapshot(),
                            out_dir,
                            max_n=2 if self.mode == "wardrive" else 4,
                            duration_s=4,
                        )
                        for u in updates:
                            if u.get("ok"):
                                self._log(
                                    f"Live decode {u.get('key')}: "
                                    f"{u.get('frames', 0)} frame(s)"
                                    + (f" · {u.get('code_class', {}).get('class')}" if u.get("code_class") else "")
                                )
                            elif u.get("error"):
                                self._log(f"Live decode skip: {u.get('error')}")
                        if updates:
                            self._emit_snapshot()
                            for u in updates:
                                key = u.get("key")
                                if key:
                                    ent = tracker_mod.tracker.get(key)
                                    if ent:
                                        self._emit({"type": "device_update", "device": ent})
                    except Exception as e:
                        self._log(f"Live decode error: {e}")

                # full_sweep and once: single pass through bands
                if self.mode != "wardrive":
                    break

                # Brief pause between wardrive loops so monitor can breathe
                for _ in range(10):
                    if self._stop.is_set():
                        break
                    self._wait_if_paused()
                    time.sleep(0.1)

            report = {
                "session_id": self.session_id,
                "mode": self.mode,
                "device_types": device_type_ids,
                "duration_s": duration_s,
                "passes_completed": self.pass_count,
                "devices": tracker_mod.tracker.snapshot(),
                "completed_utc": datetime.now(timezone.utc).isoformat(),
            }
            (out_dir / "report.json").write_text(json.dumps(report, indent=2))

            self.status = "stopped" if self._stop.is_set() else "completed"
            self.progress = 100.0
            self.current_band = None
            n = len(tracker_mod.tracker.snapshot())
            self.message = f"Done — {n} device(s) tracked"
            self._log(self.message)
            self._emit_progress(label=self.message)
            self._emit({
                "type": "complete",
                "status": self.status,
                "devices": tracker_mod.tracker.snapshot(),
            })
            self._emit_snapshot()
        except Exception as e:
            self.status = "error"
            self.message = str(e)
            self.current_band = None
            self._log(f"ERROR: {e}")
            self._emit({"type": "error", "message": str(e)})

    def _run_pass(
        self,
        types: list[dict],
        duration_s: int,
        lna_db: int,
        vga_db: int,
        passes: int,
        out_dir: Path,
        ble_cap: int | None,
    ) -> None:
        t0 = time.time()
        step = 0
        total_steps = sum(
            len(t.get("bands", [])) if t.get("radio") == "hackrf" else 1 for t in types
        )
        total_steps = max(total_steps, 1)
        self.band_total = total_steps
        self.band_index = 0

        for dt in types:
            if self._stop.is_set():
                break
            radio = dt.get("radio", "hackrf")
            if radio == "ble":
                if self._stop.is_set():
                    break
                scan_s = ble_cap if ble_cap is not None else min(duration_s, dt["bands"][0].get("ble_scan_seconds", 20))
                if self.mode == "wardrive":
                    scan_s = min(scan_s, 4)
                self.band_index = step + 1
                self.progress = min(99, 100.0 * step / total_steps)
                self._log(f"BLE scan: {dt['name']} ({scan_s}s)")
                self._emit_progress(label=f"BLE · {dt['name']} ({scan_s}s)")
                if self._stop.is_set():
                    break
                ble_devs = asyncio.run(
                    ble_scanner.scan_ble(duration_s=scan_s, device_type=dt)
                )
                if self._stop.is_set():
                    break
                for bd in ble_devs:
                    self._ingest(bd.to_dict())
                step += 1
                self.band_index = step
                self.progress = min(99, 100.0 * step / total_steps)
                self._emit_progress(label=f"BLE done · {len(ble_devs)} hit(s)", peaks=len(ble_devs))
                continue

            if dt.get("id") == "adsb_1090" or dt.get("attack_profile") == "adsb_1090":
                from . import adsb_decode
                from . import gps as gps_mod

                # Longer listen so CPR + velocity frames accumulate; wardrive keeps refreshing
                listen_s = 22.0 if self.mode == "wardrive" else min(max(float(duration_s), 20.0), 40.0)
                # If this pass is ADS-B-heavy, dwell even longer
                if len(types) <= 3:
                    listen_s = max(listen_s, 28.0)
                self.band_index = step + 1
                self.progress = min(99, 100.0 * step / total_steps)
                self._log(f"ADS-B listen: {dt['name']} ({listen_s:.0f}s @ 1090 MHz)")
                self._emit_progress(
                    fmin=1085, fmax=1095, label=f"ADS-B listen @ 1090 MHz ({listen_s:.0f}s)"
                )
                fix = gps_mod.gps.current() or {}
                aircraft = adsb_decode.listen(
                    duration_s=listen_s,
                    lna_db=lna_db,
                    vga_db=max(vga_db, 40),
                    lat_ref=fix.get("lat"),
                    lon_ref=fix.get("lon"),
                    stop=self._stop,
                    device_type=dt,
                )
                self._log(f"ADS-B: {len(aircraft)} aircraft")
                for ac in aircraft:
                    self._ingest(ac)
                for band in dt.get("bands", [])[:1]:
                    if self._stop.is_set():
                        break
                    fmin, fmax = band["freq_min_mhz"], band["freq_max_mhz"]
                    bw = band.get("bin_width_hz", 100000)
                    csv_path = out_dir / f"sweep_{dt['id']}_{int(round(fmin))}_{int(round(fmax))}_p{self.pass_count}.csv"
                    peaks = self._hackrf_sweep(
                        fmin, fmax, max(4, min(passes, 12)), bw, lna_db, vga_db, csv_path
                    )
                    meta_base = dt.get("metadata", {})
                    for pk in peaks[:3]:
                        if aircraft:
                            break
                        meta = {
                            **meta_base,
                            "band_mhz": f"{fmin}-{fmax}",
                            "attack_profile": "adsb_1090",
                            "classification": pk.get("classification", "unknown"),
                            "capability": "presence",
                        }
                        dev = DetectedDevice(
                            id=str(uuid.uuid4())[:8],
                            device_type_id=dt["id"],
                            device_type_name=dt["name"],
                            radio="hackrf",
                            freq_mhz=pk["freq_mhz"],
                            snr_db=pk["snr_db"],
                            power_dbm=pk["power_dbm"],
                            metadata=meta,
                            raw={"peak": pk, "sweep_file": str(csv_path.name)},
                        )
                        self._ingest(dev.to_dict())
                step += 1
                self.band_index = step
                self.progress = min(99, 100.0 * step / total_steps)
                self._emit_progress(
                    fmin=1090, fmax=1090, peaks=len(aircraft),
                    label=f"ADS-B · {len(aircraft)} aircraft",
                )
                continue

            for band in dt.get("bands", []):
                if self._stop.is_set():
                    break
                fmin = band["freq_min_mhz"]
                fmax = band["freq_max_mhz"]
                bw = band.get("bin_width_hz", 100000)
                csv_path = out_dir / (
                    f"sweep_{dt['id']}_{int(round(float(fmin)))}_{int(round(float(fmax)))}_p{self.pass_count}.csv"
                )
                self.band_index = step + 1
                self.progress = min(99, 100.0 * step / total_steps)
                self._log(f"HackRF sweep {dt['name']}: {float(fmin):g}–{float(fmax):g} MHz")
                self._emit_progress(
                    fmin=float(fmin),
                    fmax=float(fmax),
                    label=(
                        f"Sweeping {float(fmin):g}–{float(fmax):g} MHz · "
                        f"{self.band_index}/{self.band_total}"
                    ),
                )
                snr_floor = 6.0 if dt.get("id") == "full_spectrum" else 8.0
                from . import quality as quality_mod

                snr_floor = quality_mod.snr_floor_for_type(dt.get("id"), default=snr_floor)
                peaks = self._hackrf_sweep(
                    fmin, fmax, passes, bw, lna_db, vga_db, csv_path, snr_min=snr_floor
                )
                meta_base = dt.get("metadata", {})
                peak_limit = quality_mod.peak_limit_for_type(
                    dt.get("id"),
                    default=12 if dt.get("id") == "full_spectrum" else 10,
                )
                from .catalog import catalog_band_hint

                for pk in peaks[:peak_limit]:
                    hint = catalog_band_hint(float(pk["freq_mhz"]))
                    meta = {
                        **meta_base,
                        "band_mhz": f"{float(fmin):g}-{float(fmax):g}",
                        "attack_profile": dt.get("attack_profile"),
                        "modulation_hint": meta_base.get("modulation"),
                        "classification": pk.get("classification", "unknown"),
                        "temporal": pk.get("temporal"),
                        "capability": meta_base.get("capability") or "presence",
                    }
                    if hint:
                        meta["catalog_hint"] = hint
                    name = dt["name"]
                    if hint and hint.get("device_type_name"):
                        name = f"{dt['name']} · ~{hint['device_type_name']}"
                    elif dt.get("id") == "full_spectrum":
                        name = f"RF {pk['freq_mhz']:.3f} MHz"
                    dev = DetectedDevice(
                        id=str(uuid.uuid4())[:8],
                        device_type_id=dt["id"],
                        device_type_name=name,
                        radio="hackrf",
                        freq_mhz=pk["freq_mhz"],
                        snr_db=pk["snr_db"],
                        power_dbm=pk["power_dbm"],
                        metadata=meta,
                        raw={"peak": pk, "sweep_file": str(csv_path.name)},
                    )
                    self._ingest(dev.to_dict())

                step += 1
                self.band_index = step
                self.progress = min(99, 100.0 * step / total_steps)
                top = ""
                if peaks:
                    top = f" · top {peaks[0]['freq_mhz']:.3f} MHz +{peaks[0]['snr_db']} dB"
                self._log(f"  → {len(peaks)} peak(s) @ {float(fmin):g}–{float(fmax):g} MHz{top}")
                self._emit_progress(
                    fmin=float(fmin),
                    fmax=float(fmax),
                    peaks=len(peaks),
                    label=(
                        f"{float(fmin):g}–{float(fmax):g} MHz · {len(peaks)} peak(s) · "
                        f"{self.band_index}/{self.band_total}"
                    ),
                )

                elapsed = time.time() - t0
                if self.mode == "once" and elapsed < duration_s and not self._stop.is_set():
                    wait = min(2.0, duration_s - elapsed)
                    time.sleep(wait)

    def _hackrf_sweep(
        self,
        fmin: float,
        fmax: float,
        passes: int,
        bin_width: int,
        lna: int,
        vga: int,
        out_csv: Path,
        snr_min: float = 8.0,
    ) -> list[dict[str, Any]]:
        if self._stop.is_set():
            return []

        # hackrf_sweep rejects floats like "1101.0:1201.0" — integers only
        f1 = int(round(float(fmin)))
        f2 = int(round(float(fmax)))
        if f2 <= f1:
            f2 = f1 + 1

        cmd = [
            "hackrf_sweep",
            "-f", f"{f1}:{f2}",
            "-N", str(passes),
            "-w", str(bin_width),
            "-l", str(lna),
            "-g", str(vga),
            "-a", "0",
            "-r", str(out_csv),
        ]

        if HACKRF_SERIAL:
            cmd = ["hackrf_sweep", "-d", HACKRF_SERIAL] + cmd[1:]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        with self._lock:
            self._active_proc = proc

        # Wide chunks need more wall time than tiny ISM windows
        span = max(1.0, float(fmax) - float(fmin))
        deadline = time.time() + max(180, passes * 4 + span * 0.5)
        try:
            while proc.poll() is None:
                if self._stop.is_set():
                    kill_process_tree(proc, grace_s=0.2)
                    break
                if time.time() > deadline:
                    kill_process_tree(proc, grace_s=0.2)
                    break
                time.sleep(0.05)  # snappier stop polling
        finally:
            with self._lock:
                if self._active_proc is proc:
                    self._active_proc = None

        if self._stop.is_set() or not out_csv.exists():
            return []

        return _parse_sweep_peaks(out_csv, snr_min=snr_min)


def _parse_sweep_peaks(path: Path, snr_min: float = 8.0) -> list[dict[str, Any]]:
    rows: list[tuple[float, float]] = []
    with path.open() as f:
        for line in f:
            parts = line.strip().split(", ")
            if len(parts) < 7:
                continue
            hz_low = int(float(parts[2]))
            bin_w = float(parts[4])
            for i, p in enumerate([float(x) for x in parts[6:]]):
                rows.append(((hz_low + i * bin_w) / 1e6, p))

    if not rows:
        return []

    noise = statistics.median([p for _, p in rows])
    peaks: list[dict[str, Any]] = []
    for i, (freq, pwr) in enumerate(rows):
        snr = pwr - noise
        if snr < snr_min:
            continue
        left = rows[i - 1][1] if i > 0 else -999
        right = rows[i + 1][1] if i < len(rows) - 1 else -999
        if pwr >= left and pwr >= right:
            peaks.append({
                "freq_mhz": round(freq, 4),
                "power_dbm": round(pwr, 1),
                "snr_db": round(snr, 1),
                "noise_floor_dbm": round(noise, 1),
            })

    merged: list[dict[str, Any]] = []
    for pk in sorted(peaks, key=lambda x: -x["snr_db"]):
        if any(abs(pk["freq_mhz"] - m["freq_mhz"]) < 0.3 for m in merged):
            continue
        pk["classification"] = "CW likely" if pk["snr_db"] > 12 else "burst/weak"
        merged.append(pk)
    return merged[:15]


# Global session singleton
session = ScanSession()

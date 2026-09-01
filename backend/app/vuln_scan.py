"""Bulk vulnerability assessment over tracked devices."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Literal

from . import deep_dive, risk as risk_mod, scanner, tracker as tracker_mod

Mode = Literal["quick", "full"]

_SEV_ORDER = ("critical", "high", "medium", "low")


def _normalize_severity(sev: str | None) -> str:
    s = (sev or "low").lower()
    if s in ("vulnerable", "critical"):
        return "critical"
    if s == "info":
        return "low"
    if s in _SEV_ORDER:
        return s
    if s == "suspected":
        return "medium"
    if s == "unknown":
        return "low"
    return "low"


class VulnScanSession:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.status: str = "idle"
        self.mode: Mode = "quick"
        self.progress: float = 0.0
        self.message: str = ""
        self.total: int = 0
        self.done: int = 0
        self.results: list[dict[str, Any]] = []
        self.counts: dict[str, int] = {k: 0 for k in _SEV_ORDER}
        self._listeners: list[Callable[[dict], None]] = []

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

    def start(
        self,
        mode: Mode = "quick",
        device_keys: list[str] | None = None,
        label: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            if self.status == "running":
                return {"ok": False, "error": "Vuln scan already running"}
            devices = tracker_mod.tracker.snapshot()
            if device_keys:
                keyset = set(device_keys)
                devices = [d for d in devices if d.get("key") in keyset]
            if not devices:
                return {"ok": False, "error": "No tracked devices to assess"}

            self._stop.clear()
            self.status = "running"
            self.mode = mode
            self.progress = 0.0
            self.done = 0
            self.total = len(devices)
            self.results = []
            self.counts = {k: 0 for k in _SEV_ORDER}
            self._job_label = label or ("Deep dive" if mode == "full" else "Quick triage")
            self.message = f"{self._job_label}: {self.total} device(s)"

        self._thread = threading.Thread(
            target=self._run, args=(devices, mode), daemon=True
        )
        self._thread.start()
        return {"ok": True, "total": self.total, "mode": mode, "label": self._job_label}

    def stop(self) -> None:
        self._stop.set()
        self.message = "Stopping vuln scan…"
        self._emit({"type": "log", "message": f"[{_ts()}] Vuln scan stop requested"})

    def status_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "mode": self.mode,
            "progress": self.progress,
            "message": self.message,
            "total": self.total,
            "done": self.done,
            "counts": dict(self.counts),
            "results": self.results[-100:],
        }

    def _run(self, devices: list[dict[str, Any]], mode: Mode) -> None:
        try:
            self._emit({
                "type": "log",
                "message": f"[{_ts()}] Vuln scan start — {len(devices)} device(s), mode={mode}",
            })
            self._emit({"type": "vuln_scan_start", "total": len(devices), "mode": mode})

            for i, device in enumerate(devices):
                if self._stop.is_set():
                    break
                key = device.get("key") or tracker_mod.device_key(device)
                name = device.get("name") or device.get("device_type_name") or key
                self.message = f"{getattr(self, '_job_label', 'Assessing')} {name} ({i + 1}/{len(devices)})"
                self._emit({
                    "type": "log",
                    "message": f"[{_ts()}] {getattr(self, '_job_label', 'Vuln')} [{i + 1}/{len(devices)}] {name}",
                })

                try:
                    if mode == "full":
                        dive = deep_dive.deep_dive(device)
                        risk = dive.get("risk") or risk_mod.assess_risk(device, dive.get("analysis"))
                    else:
                        risk = risk_mod.assess_risk_quick(device)

                    sev = _normalize_severity(risk.get("severity") or risk.get("status"))
                    risk["severity"] = sev
                    risk["status"] = sev  # align status with severity bucket

                    entry = tracker_mod.tracker.set_risk(key, sev, risk) or {
                        **device,
                        "risk_status": sev,
                        "risk": risk,
                    }
                    row = {
                        "key": key,
                        "name": name,
                        "severity": sev,
                        "summary": risk.get("summary") or [],
                        "exploitability": risk.get("exploitability"),
                        "device_type_id": device.get("device_type_id"),
                        "device_type_name": device.get("device_type_name"),
                        "radio": device.get("radio"),
                    }
                    self.results.append(row)
                    self.counts[sev] = self.counts.get(sev, 0) + 1
                    self.done = i + 1
                    self.progress = 100.0 * self.done / max(self.total, 1)

                    self._emit({"type": "device_update", "device": entry})
                    self._emit({
                        "type": "vuln_finding",
                        "finding": row,
                        "progress": self.progress,
                        "counts": dict(self.counts),
                    })
                    scanner.session._emit({"type": "device_update", "device": entry})
                except Exception as e:
                    self._emit({
                        "type": "log",
                        "message": f"[{_ts()}] Vuln error on {key}: {e}",
                    })
                    self.done = i + 1
                    self.progress = 100.0 * self.done / max(self.total, 1)

                # tiny yield so UI can breathe
                time.sleep(0.05)

            self.status = "stopped" if self._stop.is_set() else "completed"
            self.progress = 100.0
            self.message = (
                f"Vuln scan {self.status} — "
                + ", ".join(f"{k}:{self.counts.get(k, 0)}" for k in _SEV_ORDER)
            )
            self._emit({"type": "log", "message": f"[{_ts()}] {self.message}"})
            snap = tracker_mod.tracker.to_dict()
            self._emit({
                "type": "vuln_scan_complete",
                "status": self.status,
                "counts": dict(self.counts),
                "results": self.results,
            })
            self._emit({"type": "tracker_snapshot", **snap})
            scanner.session._emit({"type": "tracker_snapshot", **snap})
        except Exception as e:
            self.status = "error"
            self.message = str(e)
            self._emit({"type": "error", "message": f"vuln scan: {e}"})


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def dashboard_stats(devices: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Aggregate pie-chart friendly stats from tracker."""
    devices = devices if devices is not None else tracker_mod.tracker.snapshot()
    by_type: dict[str, int] = {}
    by_radio: dict[str, int] = {}
    by_severity: dict[str, int] = {k: 0 for k in _SEV_ORDER}
    by_severity["unknown"] = 0

    for d in devices:
        tname = d.get("device_type_name") or d.get("device_type_id") or "unknown"
        by_type[tname] = by_type.get(tname, 0) + 1
        radio = (d.get("radio") or "unknown").lower()
        by_radio[radio] = by_radio.get(radio, 0) + 1
        sev = _normalize_severity(
            (d.get("risk") or {}).get("severity") or d.get("risk_status")
        )
        if d.get("risk_status") in (None, "unknown", "suspected") and not d.get("risk"):
            by_severity["unknown"] = by_severity.get("unknown", 0) + 1
        else:
            by_severity[sev] = by_severity.get(sev, 0) + 1

    def to_slices(mapping: dict[str, int]) -> list[dict[str, Any]]:
        total = sum(mapping.values()) or 1
        return [
            {"label": k, "count": v, "pct": round(100.0 * v / total, 1)}
            for k, v in sorted(mapping.items(), key=lambda x: -x[1])
            if v > 0
        ]

    return {
        "total": len(devices),
        "by_type": to_slices(by_type),
        "by_radio": to_slices(by_radio),
        "by_severity": to_slices(by_severity),
        "updated_utc": datetime.now(timezone.utc).isoformat(),
    }


vuln_scan = VulnScanSession()

"""GPS via gpsd (u-blox / NMEA) — live fix + wardrive trail."""

from __future__ import annotations

import json
import math
import os
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

GPSD_HOST = os.environ.get("GPSD_HOST", "127.0.0.1")
GPSD_PORT = int(os.environ.get("GPSD_PORT", "2947"))
# Record trail point when moved at least this many meters
TRAIL_MIN_M = float(os.environ.get("GPS_TRAIL_MIN_M", "4"))
TRAIL_MAX = 2000


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


class GpsService:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._fix: dict[str, Any] | None = None
        self._trail: list[dict[str, Any]] = []
        self._status = "idle"
        self._error = ""
        self._listeners: list[Callable[[dict], None]] = []
        self._last_emit = 0.0

    def subscribe(self, cb: Callable[[dict], None]) -> None:
        self._listeners.append(cb)

    def _emit(self, event: dict) -> None:
        for cb in self._listeners:
            try:
                cb(event)
            except Exception:
                pass

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="gpsd-reader")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def clear_trail(self) -> None:
        with self._lock:
            self._trail.clear()

    def current(self) -> dict[str, Any] | None:
        with self._lock:
            return dict(self._fix) if self._fix else None

    def status_dict(self) -> dict[str, Any]:
        with self._lock:
            fix = dict(self._fix) if self._fix else None
            trail_n = len(self._trail)
            return {
                "status": self._status,
                "error": self._error,
                "fix": fix,
                "has_fix": bool(fix and fix.get("lat") is not None),
                "trail_points": trail_n,
                "host": f"{GPSD_HOST}:{GPSD_PORT}",
            }

    def trail(self, limit: int = 500) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._trail[-max(1, min(limit, TRAIL_MAX)) :])

    def stamp_device(self, device: dict[str, Any]) -> dict[str, Any]:
        """Attach current GPS fix onto a device dict (mutates + returns)."""
        fix = self.current()
        if not fix or fix.get("lat") is None or fix.get("lon") is None:
            return device
        device["lat"] = fix["lat"]
        device["lon"] = fix["lon"]
        device["gps"] = {
            "lat": fix["lat"],
            "lon": fix["lon"],
            "alt_m": fix.get("alt"),
            "speed_mps": fix.get("speed"),
            "track_deg": fix.get("track"),
            "mode": fix.get("mode"),
            "fix_utc": fix.get("time"),
            "hdop": fix.get("hdop"),
            "sats": fix.get("sats"),
        }
        return device

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._status = "connecting"
                self._error = ""
                with socket.create_connection((GPSD_HOST, GPSD_PORT), timeout=3) as sock:
                    sock.settimeout(3)
                    sock.sendall(b'?WATCH={"enable":true,"json":true}\n')
                    self._status = "listening"
                    buf = ""
                    while not self._stop.is_set():
                        try:
                            chunk = sock.recv(4096)
                        except socket.timeout:
                            continue
                        if not chunk:
                            raise ConnectionError("gpsd closed")
                        buf += chunk.decode("utf-8", errors="ignore")
                        while "\n" in buf:
                            line, buf = buf.split("\n", 1)
                            line = line.strip()
                            if line:
                                self._handle_line(line)
            except Exception as e:
                self._status = "error"
                self._error = str(e)
                # backoff then retry
                for _ in range(20):
                    if self._stop.is_set():
                        return
                    time.sleep(0.25)

    def _handle_line(self, line: str) -> None:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            return
        if msg.get("class") != "TPV":
            return
        mode = int(msg.get("mode") or 0)
        lat = msg.get("lat")
        lon = msg.get("lon")
        if mode < 2 or lat is None or lon is None:
            with self._lock:
                # keep last good fix but note mode
                if self._fix:
                    self._fix = {**self._fix, "mode": mode, "stale": True}
            return

        fix = {
            "lat": float(lat),
            "lon": float(lon),
            "alt": float(msg["alt"]) if msg.get("alt") is not None else None,
            "speed": float(msg["speed"]) if msg.get("speed") is not None else None,
            "track": float(msg["track"]) if msg.get("track") is not None else None,
            "mode": mode,
            "time": msg.get("time") or datetime.now(timezone.utc).isoformat(),
            "hdop": msg.get("hdop"),
            "sats": msg.get("satellites") or msg.get("sats"),
            "stale": False,
            "received_utc": datetime.now(timezone.utc).isoformat(),
        }

        trail_added = False
        with self._lock:
            prev = self._trail[-1] if self._trail else None
            if prev is None or _haversine_m(prev["lat"], prev["lon"], fix["lat"], fix["lon"]) >= TRAIL_MIN_M:
                self._trail.append({
                    "lat": fix["lat"],
                    "lon": fix["lon"],
                    "alt": fix.get("alt"),
                    "t": fix["time"],
                })
                if len(self._trail) > TRAIL_MAX:
                    self._trail = self._trail[-TRAIL_MAX:]
                trail_added = True
            self._fix = fix
            self._status = "fix"

        now = time.time()
        if trail_added or now - self._last_emit > 1.0:
            self._last_emit = now
            self._emit({"type": "gps_fix", "fix": fix, "trail_points": len(self.trail())})


gps = GpsService()

"""Live device tracker for wardrive mode — upsert by stable key, signal history, GPS pins."""

from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# dBm floor/ceil for bar mapping (BLE RSSI / HackRF power)
POWER_FLOOR = -90.0
POWER_CEIL = -20.0
# SNR mapping for HackRF when power missing
SNR_FLOOR = 0.0
SNR_CEIL = 30.0
HISTORY_LEN = 24
STALE_AFTER_S = 45.0

_DEFAULT_CAPTURES = Path(__file__).resolve().parents[2].parent / "captures" / "rf-hunter-v2"
CAPTURES = Path(os.environ.get("RF_HUNTER_CAPTURES", str(_DEFAULT_CAPTURES)))
TRACKER_FILE = CAPTURES / "tracker_state.json"
PERSIST_MIN_INTERVAL_S = 2.0


from . import gps as gps_mod


def device_key(device: dict[str, Any]) -> str:
    radio = (device.get("radio") or "").lower()
    mac = device.get("mac")
    if radio == "ble" and mac:
        return f"ble:{str(mac).upper()}"
    if radio == "wifi":
        bssid = mac or device.get("bssid") or (device.get("key") or "").removeprefix("wifi:")
        if bssid:
            return f"wifi:{str(bssid).upper()}"
    if radio == "adsb" and mac:
        return f"adsb:{str(mac).upper()}"
    if radio == "ais" and mac:
        return f"ais:{str(mac).upper()}"
    meta = device.get("metadata") or {}
    adsb = meta.get("adsb") or {}
    if adsb.get("icao"):
        return f"adsb:{str(adsb['icao']).upper()}"
    ais = meta.get("ais") or {}
    if ais.get("mmsi"):
        return f"ais:{str(ais['mmsi'])}"
    freq = device.get("freq_mhz")
    dtype = device.get("device_type_id") or "unknown"
    if freq is not None:
        return f"rf:{float(freq):.3f}:{dtype}"
    did = device.get("id") or "unknown"
    return f"id:{did}"


def signal_db(device: dict[str, Any]) -> float | None:
    if device.get("rssi_dbm") is not None:
        return float(device["rssi_dbm"])
    if device.get("power_dbm") is not None:
        return float(device["power_dbm"])
    return None


def signal_level(device: dict[str, Any] | None = None, *, db: float | None = None, snr: float | None = None) -> int:
    """Return 0–10 coverage level from dBm or SNR."""
    if db is None and device is not None:
        db = signal_db(device)
        if snr is None:
            snr = device.get("snr_db")
            snr = float(snr) if snr is not None else None
    if db is not None:
        x = (db - POWER_FLOOR) / (POWER_CEIL - POWER_FLOOR)
    elif snr is not None:
        x = (float(snr) - SNR_FLOOR) / (SNR_CEIL - SNR_FLOOR)
    else:
        return 0
    return max(0, min(10, int(round(x * 10))))


def signal_color(level: int) -> str:
    """Textual/Rich color name for coverage level."""
    if level <= 0:
        return "dim"
    if level <= 3:
        return "red"
    if level <= 6:
        return "yellow"
    return "green"


def signal_bar(level: int, width: int = 10) -> str:
    filled = max(0, min(width, level if width == 10 else int(round(level / 10 * width))))
    if width != 10:
        filled = max(0, min(width, int(round(level / 10 * width))))
    return "█" * filled + "░" * (width - filled)


def colored_bar(level: int, width: int = 10) -> str:
    color = signal_color(level)
    return f"[{color}]{signal_bar(level, width)}[/]"


def baseline_risk(device: dict[str, Any]) -> str:
    """Suspected risk from catalog attack_profile before deep dive."""
    meta = device.get("metadata") or {}
    profile = meta.get("attack_profile") or ""
    high = {"tuya_ble", "tpms_433", "tpms_315", "ism_433", "ism_315", "alarm_869"}
    medium = {"ble_generic", "bt_av", "lora_eu", "ism_868", "cw_telemetry", "dect"}
    if profile in high:
        return "suspected"
    if profile in medium:
        return "unknown"
    return "unknown"


def _has_coords(obj: dict[str, Any] | None, lat_k: str = "lat", lon_k: str = "lon") -> bool:
    if not obj:
        return False
    lat, lon = obj.get(lat_k), obj.get(lon_k)
    if lat is None or lon is None:
        return False
    try:
        float(lat)
        float(lon)
        return True
    except (TypeError, ValueError):
        return False


class DeviceTracker:
    def __init__(self, stale_after_s: float = STALE_AFTER_S) -> None:
        self._lock = threading.Lock()
        self._devices: dict[str, dict[str, Any]] = {}
        self.stale_after_s = stale_after_s
        self._persist_path = TRACKER_FILE
        self._last_persist_ts = 0.0
        self._dirty = False

    def clear(self) -> None:
        with self._lock:
            self._devices.clear()
            self._dirty = True
        self.persist(force=True)

    @staticmethod
    def _merge_traffic_block(
        old_b: dict[str, Any] | None, new_b: dict[str, Any] | None
    ) -> dict[str, Any]:
        """Merge ADS-B/AIS blobs without wiping known fields with nulls from partial frames."""
        merged: dict[str, Any] = dict(old_b or {})
        new_b = new_b or {}
        for k, v in new_b.items():
            if k == "fields":
                continue
            if k == "messages":
                continue
            if v is None or v == "":
                continue
            # Drop useless wake/category placeholders
            if k in ("wake_vortex", "model") and (
                "no category" in str(v).lower() or str(v).strip() in ("0", "None")
            ):
                continue
            merged[k] = v
        of = (old_b or {}).get("fields") if isinstance(old_b, dict) else None
        nf = new_b.get("fields")
        if isinstance(of, dict) or isinstance(nf, dict):
            fields = dict(of or {})
            for fk, fv in (nf or {}).items():
                if fv is None or fv == "":
                    continue
                fields[fk] = fv
            merged["fields"] = fields
        try:
            merged["messages"] = int((old_b or {}).get("messages") or 0) + int(
                new_b.get("messages") or 0
            )
        except (TypeError, ValueError):
            merged["messages"] = (old_b or {}).get("messages") or new_b.get("messages")
        return merged

    @staticmethod
    def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        from math import asin, cos, radians, sin, sqrt

        r = 6371000.0
        p1, p2 = radians(lat1), radians(lat2)
        dp = radians(lat2 - lat1)
        dl = radians(lon2 - lon1)
        a = sin(dp / 2) ** 2 + cos(p1) * cos(p2) * sin(dl / 2) ** 2
        return 2 * r * asin(sqrt(min(1.0, a)))

    @staticmethod
    def _bearing_deg(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        from math import atan2, cos, degrees, radians, sin

        p1, p2 = radians(lat1), radians(lat2)
        dl = radians(lon2 - lon1)
        y = sin(dl) * cos(p2)
        x = cos(p1) * sin(p2) - sin(p1) * cos(p2) * cos(dl)
        return (degrees(atan2(y, x)) + 360.0) % 360.0

    @classmethod
    def _enrich_adsb_kinematics(
        cls,
        merged: dict[str, Any],
        old_b: dict[str, Any] | None,
        *,
        dt_s: float,
    ) -> dict[str, Any]:
        """If velocity DF missing, estimate speed/track from successive CPR positions."""
        if not isinstance(merged, dict):
            return merged
        old_b = old_b or {}
        try:
            o_lat, o_lon = float(old_b["lat"]), float(old_b["lon"])
            n_lat, n_lon = float(merged["lat"]), float(merged["lon"])
        except (KeyError, TypeError, ValueError):
            return merged
        dist = cls._haversine_m(o_lat, o_lon, n_lat, n_lon)
        if dist < 40 or dt_s < 0.8:
            return merged
        # Ignore CPR zone jumps / bad fixes
        if dist > 80_000:
            return merged
        speed_mps = dist / dt_s
        speed_kts = speed_mps / 0.514444
        if speed_kts < 40 or speed_kts > 650:
            return merged
        track = cls._bearing_deg(o_lat, o_lon, n_lat, n_lon)
        if merged.get("speed_kts") is None:
            merged["speed_kts"] = round(speed_kts, 1)
            merged["speed_kmh"] = round(speed_kts * 1.852, 1)
            merged["kinematics_source"] = "position_delta"
        if merged.get("track_deg") is None:
            merged["track_deg"] = round(track, 1)
            merged.setdefault("kinematics_source", "position_delta")
        return merged

    def upsert(self, device: dict[str, Any]) -> dict[str, Any]:
        # ADS-B/AIS must keep emitter coords only — never pin them to the hunter GPS.
        radio0 = (device.get("radio") or "").lower()
        meta0 = device.get("metadata") or {}
        geo_src = str(meta0.get("geo_source") or "").lower()
        is_traffic = radio0 in ("adsb", "ais") or bool(meta0.get("adsb") or meta0.get("ais"))
        if is_traffic:
            if device.get("lat") is not None and device.get("lon") is not None:
                meta0 = {**meta0, "geo_source": "signal"}
                device["metadata"] = meta0
            # else: leave without hunter stamp so they don't false-pin on the map
        elif geo_src != "signal":
            try:
                gps_mod.gps.stamp_device(device)
            except Exception:
                pass

        key = device_key(device)
        now = datetime.now(timezone.utc).isoformat()
        now_ts = time.time()
        db = signal_db(device)
        snr = device.get("snr_db")
        level = signal_level(device)

        with self._lock:
            existing = self._devices.get(key)
            if existing is None:
                history: deque[float] = deque(maxlen=HISTORY_LEN)
                if db is not None:
                    history.append(db)
                elif snr is not None:
                    history.append(float(snr))
                # Strip nulls from traffic blocks on first insert
                meta_new = dict(device.get("metadata") or {})
                for blk in ("adsb", "ais"):
                    if isinstance(meta_new.get(blk), dict):
                        meta_new[blk] = self._merge_traffic_block(None, meta_new[blk])
                device = {**device, "metadata": meta_new}
                entry = {
                    **device,
                    "key": key,
                    "first_seen": now,
                    "last_seen": now,
                    "last_seen_ts": now_ts,
                    "hit_count": 1,
                    "signal_history": list(history),
                    "signal_level": level,
                    "stale": False,
                    "risk_status": device.get("risk_status") or baseline_risk(device),
                    "risk": device.get("risk"),
                }
                self._apply_gps(entry, device, existing=None)
                self._devices[key] = entry
                self._dirty = True
                out = dict(entry)
            else:
                history = deque(existing.get("signal_history") or [], maxlen=HISTORY_LEN)
                if db is not None:
                    history.append(db)
                elif snr is not None:
                    history.append(float(snr))

                # Preserve first_seen, risk from dive, merge metadata
                merged_meta = {**(existing.get("metadata") or {}), **(device.get("metadata") or {})}
                # Deep-merge traffic blocks so partial ADS-B/AIS updates keep prior fields
                for blk in ("adsb", "ais"):
                    old_b = (existing.get("metadata") or {}).get(blk)
                    new_b = (device.get("metadata") or {}).get(blk)
                    if isinstance(old_b, dict) or isinstance(new_b, dict):
                        merged_meta[blk] = self._merge_traffic_block(
                            old_b if isinstance(old_b, dict) else None,
                            new_b if isinstance(new_b, dict) else None,
                        )
                # Estimate speed/track from successive ADS-B positions when velocity DF missing
                if isinstance(merged_meta.get("adsb"), dict):
                    old_adsb = (existing.get("metadata") or {}).get("adsb")
                    dt_s = max(
                        0.5,
                        now_ts - float(existing.get("last_seen_ts") or now_ts),
                    )
                    merged_meta["adsb"] = self._enrich_adsb_kinematics(
                        merged_meta["adsb"],
                        old_adsb if isinstance(old_adsb, dict) else None,
                        dt_s=dt_s,
                    )
                # Prefer previous geo_source=signal if new hit lacked a position
                old_geo = str((existing.get("metadata") or {}).get("geo_source") or "").lower()
                new_geo = str(merged_meta.get("geo_source") or "").lower()
                if old_geo == "signal" and new_geo != "signal":
                    merged_meta["geo_source"] = "signal"
                entry = {
                    **existing,
                    **device,
                    "key": key,
                    "metadata": merged_meta,
                    "first_seen": existing["first_seen"],
                    "last_seen": now,
                    "last_seen_ts": now_ts,
                    "hit_count": int(existing.get("hit_count", 0)) + 1,
                    "signal_history": list(history),
                    "signal_level": level,
                    "stale": False,
                    "risk_status": existing.get("risk_status") or baseline_risk(device),
                    "risk": existing.get("risk") or device.get("risk"),
                }
                # GPS must never be wiped by a hit that lacked a fix
                self._apply_gps(entry, device, existing=existing)
                # Prefer fresh signal fields
                if db is not None:
                    if device.get("rssi_dbm") is not None:
                        entry["rssi_dbm"] = device["rssi_dbm"]
                    if device.get("power_dbm") is not None:
                        entry["power_dbm"] = device["power_dbm"]
                if snr is not None:
                    entry["snr_db"] = snr
                self._devices[key] = entry
                self._dirty = True
                out = dict(entry)

        self.persist()
        return out

    @staticmethod
    def _apply_gps(
        entry: dict[str, Any],
        device: dict[str, Any],
        *,
        existing: dict[str, Any] | None,
    ) -> None:
        """Merge GPS so first pin sticks and last coords refresh only when we have a fix."""
        meta = device.get("metadata") or entry.get("metadata") or {}
        moving = (
            str(meta.get("geo_source") or "").lower() == "signal"
            or (device.get("radio") or entry.get("radio") or "").lower() in ("adsb", "ais")
        )

        # Fresh stamp on this hit?
        if _has_coords(device):
            entry["lat"] = float(device["lat"])
            entry["lon"] = float(device["lon"])
            if device.get("gps"):
                entry["gps"] = device["gps"]
        elif existing and _has_coords(existing):
            entry["lat"] = existing["lat"]
            entry["lon"] = existing["lon"]
            if existing.get("gps") and not entry.get("gps"):
                entry["gps"] = existing["gps"]
        else:
            # Do not leave explicit nulls from a partial merge
            entry.pop("lat", None)
            entry.pop("lon", None)

        # first_* is the map pin — stick for wardrive; follow emitter for ADS-B/AIS
        if moving and _has_coords(entry):
            entry["first_lat"] = float(entry["lat"])
            entry["first_lon"] = float(entry["lon"])
        elif existing and _has_coords(existing, "first_lat", "first_lon"):
            entry["first_lat"] = float(existing["first_lat"])
            entry["first_lon"] = float(existing["first_lon"])
        elif _has_coords(entry):
            entry["first_lat"] = float(entry["lat"])
            entry["first_lon"] = float(entry["lon"])
        elif existing and _has_coords(existing):
            entry["first_lat"] = float(existing["lat"])
            entry["first_lon"] = float(existing["lon"])

    def set_risk(self, key: str, risk_status: str, risk: dict[str, Any] | None = None) -> dict[str, Any] | None:
        with self._lock:
            entry = self._devices.get(key)
            if not entry:
                return None
            entry["risk_status"] = risk_status
            if risk is not None:
                entry["risk"] = risk
            self._dirty = True
            out = dict(entry)
        self.persist()
        return out

    def patch(self, key: str, fields: dict[str, Any]) -> dict[str, Any] | None:
        """Merge fields into a tracked device (metadata deep-merged)."""
        with self._lock:
            entry = self._devices.get(key)
            if not entry:
                return None
            if "metadata" in fields and isinstance(fields["metadata"], dict):
                entry["metadata"] = {**(entry.get("metadata") or {}), **fields["metadata"]}
                fields = {k: v for k, v in fields.items() if k != "metadata"}
            for k, v in fields.items():
                entry[k] = v
            self._dirty = True
            out = dict(entry)
        self.persist()
        return out

    def refresh_quality(self, key: str) -> dict[str, Any]:
        """Recompute metadata.quality after merge without bumping hit_count."""
        from . import quality as quality_mod

        with self._lock:
            entry = self._devices.get(key)
            if not entry:
                return {}
            q = quality_mod.assess(entry)
            meta = dict(entry.get("metadata") or {})
            meta["quality"] = q
            if not meta.get("capability"):
                meta["capability"] = quality_mod.infer_capability(entry)
            entry["metadata"] = meta
            self._dirty = True
            out = dict(entry)
        self.persist()
        return out

    def get(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            entry = self._devices.get(key)
            return dict(entry) if entry else None

    def mark_stale(self) -> None:
        now = time.time()
        with self._lock:
            for entry in self._devices.values():
                age = now - float(entry.get("last_seen_ts") or 0)
                entry["stale"] = age > self.stale_after_s

    def clear_stale_flags(self) -> None:
        """After stop: keep last snapshot fully visible (no mass-dim)."""
        with self._lock:
            for entry in self._devices.values():
                entry["stale"] = False

    def snapshot(self, *, sort_by_signal: bool = True) -> list[dict[str, Any]]:
        self.mark_stale()
        with self._lock:
            items = [dict(v) for v in self._devices.values()]

        def sort_key(d: dict[str, Any]) -> tuple:
            level = int(d.get("signal_level") or 0)
            stale = 1 if d.get("stale") else 0
            return (stale, -level, -(d.get("hit_count") or 0))

        if sort_by_signal:
            items.sort(key=sort_key)
        return items

    def to_dict(self) -> dict[str, Any]:
        devices = self.snapshot()
        return {
            "count": len(devices),
            "devices": devices,
            "updated_utc": datetime.now(timezone.utc).isoformat(),
        }

    def persist(self, *, force: bool = False) -> None:
        """Debounced write of tracker (incl. GPS pins) so restarts keep the map."""
        now = time.time()
        with self._lock:
            if not self._dirty and not force:
                return
            if not force and (now - self._last_persist_ts) < PERSIST_MIN_INTERVAL_S:
                return
            payload = {
                "saved_utc": datetime.now(timezone.utc).isoformat(),
                "count": len(self._devices),
                "devices": list(self._devices.values()),
            }
            self._dirty = False
            self._last_persist_ts = now
            path = self._persist_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, indent=2, default=str))
            tmp.replace(path)
        except OSError:
            with self._lock:
                self._dirty = True

    def load(self) -> int:
        """Restore devices (and GPS pins) from disk. Returns count loaded."""
        path = self._persist_path
        if not path.is_file():
            return 0
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return 0
        devices = data.get("devices") or []
        if not isinstance(devices, list):
            return 0
        n = 0
        with self._lock:
            for d in devices:
                if not isinstance(d, dict):
                    continue
                key = d.get("key") or device_key(d)
                d = dict(d)
                d["key"] = key
                # Normalize GPS types
                if _has_coords(d):
                    d["lat"] = float(d["lat"])
                    d["lon"] = float(d["lon"])
                if _has_coords(d, "first_lat", "first_lon"):
                    d["first_lat"] = float(d["first_lat"])
                    d["first_lon"] = float(d["first_lon"])
                elif _has_coords(d):
                    d["first_lat"] = float(d["lat"])
                    d["first_lon"] = float(d["lon"])
                self._devices[key] = d
                n += 1
            self._dirty = False
        return n


# Global singleton
tracker = DeviceTracker()

"""Wi-Fi parallel capture — iw scan on a dedicated iface (prefer second NIC)."""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from . import fingerprint as fp_mod
from . import gps as gps_mod

WIFI_IFACE = os.environ.get("RF_HUNTER_WIFI_IFACE", "wlan1")
WIFI_SCAN_INTERVAL_S = float(os.environ.get("RF_HUNTER_WIFI_INTERVAL", "8"))
STALE_AFTER_S = 90.0


def list_wifi_ifaces() -> list[dict[str, Any]]:
    """Return wireless interfaces via `iw dev`."""
    try:
        out = subprocess.check_output(["iw", "dev"], text=True, timeout=5)
    except Exception:
        return []
    ifaces: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for line in out.splitlines():
        m = re.match(r"^\s*Interface\s+(\S+)", line)
        if m:
            if cur:
                ifaces.append(cur)
            cur = {"iface": m.group(1), "type": "managed"}
            continue
        if not cur:
            continue
        if "type" in line:
            cur["type"] = line.split()[-1]
        if "addr" in line:
            cur["mac"] = line.split()[-1]
        if "ssid" in line.lower() and "SSID" in line:
            parts = line.split(None, 1)
            if len(parts) > 1:
                cur["ssid"] = parts[-1].strip()
        if "channel" in line:
            cur["channel_line"] = line.strip()
    if cur:
        ifaces.append(cur)
    return ifaces


def pick_iface(preferred: str | None = None) -> str | None:
    preferred = preferred or WIFI_IFACE
    ifaces = list_wifi_ifaces()
    names = [i["iface"] for i in ifaces]
    if preferred in names:
        return preferred
    # Prefer non-wlan0 secondary
    for n in names:
        if n != "wlan0":
            return n
    return names[0] if names else None


def _run_iw_scan(iface: str) -> str:
    """Trigger + dump scan. Needs CAP_NET_ADMIN (Docker privileged/host)."""
    try:
        subprocess.run(
            ["iw", "dev", iface, "scan", "trigger"],
            capture_output=True, text=True, timeout=8,
        )
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["iw", "dev", iface, "scan", "dump"],
            capture_output=True, text=True, timeout=20,
        )
        if r.returncode == 0 and (r.stdout or "").strip():
            return r.stdout or ""
    except Exception:
        pass
    # Fallback: blocking scan
    try:
        r = subprocess.run(
            ["iw", "dev", iface, "scan"],
            capture_output=True, text=True, timeout=25,
        )
        return r.stdout or ""
    except Exception:
        return ""


_BSS_RE = re.compile(r"^BSS\s+([0-9a-fA-F:]{17})")
_SIGNAL_RE = re.compile(r"signal:\s*([-\d.]+)\s*dBm")
_FREQ_RE = re.compile(r"freq:\s*(\d+)")
_DS_RE = re.compile(r"DS Parameter set:\s*channel\s*(\d+)", re.I)
_RSN_RE = re.compile(r"^\s*RSN:")
_WPA_RE = re.compile(r"^\s*WPA:")
_WPS_RE = re.compile(r"^\s*WPS:")
_COUNTRY_RE = re.compile(r"Country:\s*([A-Z]{2})", re.I)


def _empty_ap(bssid: str) -> dict[str, Any]:
    return {
        "bssid": bssid,
        "ssid": "",
        "signal_dbm": None,
        "freq_mhz": None,
        "channel": None,
        "security": "open",
        "security_family": "open",
        "vendor": fp_mod.lookup_oui(bssid),
        "wifi_ies": {
            "privacy": False,
            "rsn": False,
            "wpa": False,
            "wps": False,
            "pmf": None,  # True / False / None unknown
            "owe": False,
            "sae": False,
            "psk": False,
            "tkip": False,
            "ccmp": False,
            "wep": False,
            "ht": False,
            "vht": False,
            "he": False,
            "country": None,
            "akm": [],
        },
    }


def _finalize_ap(ap: dict[str, Any]) -> dict[str, Any]:
    """Normalize security label + security_family from wifi_ies flags."""
    ies = ap.setdefault("wifi_ies", {})
    ssid = (ap.get("ssid") or "").strip()
    ap["hidden_ssid"] = not bool(ssid)

    # WEP heuristic: Privacy without WPA/RSN
    if ies.get("privacy") and not ies.get("rsn") and not ies.get("wpa"):
        ies["wep"] = True

    family = "open"
    label = "open"
    if ies.get("wep"):
        family, label = "wep", "WEP"
    elif ies.get("rsn") and ies.get("wpa"):
        family, label = "mixed", "WPA/WPA2 mixed"
    elif ies.get("sae") and ies.get("psk"):
        family, label = "mixed", "WPA2/WPA3 transition"
    elif ies.get("sae") or ies.get("owe"):
        family = "wpa3"
        label = "OWE" if ies.get("owe") and not ies.get("sae") else "WPA3"
    elif ies.get("rsn"):
        family, label = "wpa2", "WPA2"
    elif ies.get("wpa"):
        family, label = "wpa", "WPA"
    elif ies.get("privacy"):
        family, label = "unknown", "encrypted"

    if ies.get("tkip") and family in ("wpa", "wpa2", "mixed"):
        label = f"{label}+TKIP"

    ap["security"] = label
    ap["security_family"] = family
    ap["wps"] = bool(ies.get("wps"))
    ap["pmf"] = ies.get("pmf")
    return ap


def parse_iw_scan(text: str) -> list[dict[str, Any]]:
    aps: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    in_rsn = False
    in_wpa = False
    for line in text.splitlines():
        m = re.match(r"^BSS\s+([0-9a-fA-F:]{17})", line)
        if m:
            if cur and cur.get("bssid"):
                aps.append(_finalize_ap(cur))
            cur = _empty_ap(m.group(1).upper())
            in_rsn = in_wpa = False
            continue
        if not cur:
            continue
        ies = cur["wifi_ies"]
        stripped = line.strip()

        # Leave RSN/WPA blocks when indentation drops to top-level IE
        if in_rsn and line.startswith("\t") and not line.startswith("\t\t") and not _RSN_RE.match(line):
            if not stripped.lower().startswith("*"):
                in_rsn = False
        if in_wpa and line.startswith("\t") and not line.startswith("\t\t") and not _WPA_RE.match(line):
            if not stripped.lower().startswith("*"):
                in_wpa = False

        sm = _SIGNAL_RE.search(line)
        if sm:
            cur["signal_dbm"] = float(sm.group(1))
            continue
        fm = _FREQ_RE.search(line)
        if fm:
            hz = int(fm.group(1))
            cur["freq_mhz"] = round(hz / 1000.0, 3) if hz > 10000 else float(hz)
            if 2412 <= hz <= 2484:
                cur["channel"] = max(1, min(14, int(round((hz - 2412) / 5)) + 1))
            elif 5000 <= hz <= 5900:
                cur["channel"] = int(round((hz - 5000) / 5))
            continue
        dm = _DS_RE.search(line)
        if dm:
            cur["channel"] = int(dm.group(1))
            continue
        if "SSID:" in line:
            ssid = line.split("SSID:", 1)[-1].strip()
            if ssid and not ssid.startswith("\\x"):
                cur["ssid"] = ssid[:64]
            continue
        if "capability:" in line.lower():
            if "Privacy" in line:
                ies["privacy"] = True
            continue
        if _RSN_RE.match(line):
            ies["rsn"] = True
            in_rsn = True
            in_wpa = False
            continue
        if _WPA_RE.match(line):
            ies["wpa"] = True
            in_wpa = True
            in_rsn = False
            continue
        if _WPS_RE.match(line) or "WPS:" in line:
            ies["wps"] = True
            continue
        cm = _COUNTRY_RE.search(line)
        if cm:
            ies["country"] = cm.group(1).upper()
            continue
        low = stripped.lower()
        if "ht capabilities" in low or low.startswith("ht operation"):
            ies["ht"] = True
        if "vht capabilities" in low or low.startswith("vht operation"):
            ies["vht"] = True
        if "he capabilities" in low or "he operation" in low:
            ies["he"] = True
        # AKM / cipher hints (RSN/WPA blocks or free-standing suite lines)
        if "PSK" in stripped and ("suite" in low or "authentication" in low or in_rsn or in_wpa):
            ies["psk"] = True
            if "PSK" not in ies["akm"]:
                ies["akm"].append("PSK")
        if "SAE" in stripped and ("suite" in low or "authentication" in low or in_rsn or in_wpa or ies.get("rsn")):
            ies["sae"] = True
            if "SAE" not in ies["akm"]:
                ies["akm"].append("SAE")
        if "OWE" in stripped:
            ies["owe"] = True
            if "OWE" not in ies["akm"]:
                ies["akm"].append("OWE")
        if in_rsn or in_wpa or ies.get("rsn") or ies.get("wpa"):
            if "TKIP" in stripped:
                ies["tkip"] = True
            if "CCMP" in stripped or "GCMP" in stripped:
                ies["ccmp"] = True
            if "Management Frame Protection" in stripped or "MFP" in stripped or "MFPR" in stripped or "MFPC" in stripped:
                if "Required" in stripped or "MFPR" in stripped:
                    ies["pmf"] = True
                elif "Capable" in stripped or "MFPC" in stripped:
                    if ies.get("pmf") is not True:
                        ies["pmf"] = True
                elif "Disabled" in stripped:
                    ies["pmf"] = False
        if "MFPC" in stripped and "MFPR" in stripped:
            ies["pmf"] = True
        if stripped in ("* Capabilities: MFPC MFPR",) or (
            "Capabilities:" in stripped and "MFPC" in stripped
        ):
            ies["pmf"] = True
    if cur and cur.get("bssid"):
        aps.append(_finalize_ap(cur))
    return aps


class WifiService:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._run_id = 0  # invalidate in-flight iw scans on stop/restart
        self._aps: dict[str, dict[str, Any]] = {}
        self._iface: str | None = None
        self._status = "idle"
        self._error = ""
        self._listeners: list[Callable[[dict], None]] = []
        self._last_scan_utc: str | None = None
        self._scan_count = 0

    def subscribe(self, cb: Callable[[dict], None]) -> None:
        self._listeners.append(cb)

    def _emit(self, event: dict) -> None:
        for cb in self._listeners:
            try:
                cb(event)
            except Exception:
                pass

    def _alive_for(self, run_id: int) -> bool:
        return (not self._stop.is_set()) and self._run_id == run_id

    def start(self, iface: str | None = None) -> dict[str, Any]:
        chosen = pick_iface(iface)
        if not chosen:
            self._status = "error"
            self._error = "No Wi-Fi interface found"
            return self.status_dict()
        with self._lock:
            if (
                self._thread
                and self._thread.is_alive()
                and self._iface == chosen
                and self._status in ("running", "starting")
                and not self._stop.is_set()
            ):
                return self.status_dict()
            # Bump run_id so any blocked iw scan from an old thread is discarded.
            self._run_id += 1
            run_id = self._run_id
            self._stop.set()
            self._iface = chosen
            self._status = "starting"
            self._error = ""
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run,
                args=(run_id,),
                daemon=True,
                name=f"wifi-scan-{chosen}",
            )
            self._thread.start()
        return self.status_dict()

    def stop(self) -> None:
        with self._lock:
            self._run_id += 1  # discard in-flight iw result
            self._stop.set()
            self._status = "stopped"
        self._emit({"type": "wifi_status", **self.status_dict()})

    def clear(self) -> None:
        with self._lock:
            self._aps.clear()

    def clear_and_notify(self) -> None:
        """Wipe APs and push empty snapshot to WebSocket clients."""
        self.clear()
        self._emit({"type": "wifi_status", **self.status_dict()})
        self._emit({
            "type": "wifi_snapshot",
            "aps": [],
            "count": 0,
            "iface": self._iface,
        })

    def status_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "status": self._status,
                "error": self._error,
                "iface": self._iface,
                "ap_count": len(self._aps),
                "scan_count": self._scan_count,
                "last_scan_utc": self._last_scan_utc,
                "ifaces": list_wifi_ifaces(),
            }

    def snapshot(self, *, max_age_s: float = STALE_AFTER_S) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            items = []
            for ap in self._aps.values():
                age = now - float(ap.get("last_seen_ts") or 0)
                row = dict(ap)
                row["stale"] = age > max_age_s
                row["age_s"] = round(age, 1)
                items.append(row)
        items.sort(key=lambda a: (1 if a.get("stale") else 0, -(a.get("signal_dbm") or -999)))
        return items

    def _run(self, run_id: int) -> None:
        iface = self._iface or WIFI_IFACE
        if not self._alive_for(run_id):
            return
        self._status = "running"
        self._emit({"type": "wifi_status", **self.status_dict()})
        while self._alive_for(run_id):
            try:
                raw = _run_iw_scan(iface)
                # iw can block for many seconds — drop result if we were stopped meanwhile
                if not self._alive_for(run_id):
                    break
                if not raw.strip():
                    self._error = f"Empty scan on {iface} (need NET_ADMIN / iface up)"
                    self._status = "running"
                else:
                    aps = parse_iw_scan(raw)
                    self._ingest(aps)
                    self._error = ""
                    self._status = "running"
                    self._scan_count += 1
                    self._last_scan_utc = datetime.now(timezone.utc).isoformat()
                    self._emit({
                        "type": "wifi_snapshot",
                        "aps": self.snapshot(),
                        "count": len(self._aps),
                        "iface": iface,
                    })
            except Exception as exc:
                if not self._alive_for(run_id):
                    break
                self._error = str(exc)
                self._status = "error"
                self._emit({"type": "wifi_status", **self.status_dict()})
            # sleep in slices for fast stop
            for _ in range(int(max(1, WIFI_SCAN_INTERVAL_S * 2))):
                if not self._alive_for(run_id):
                    break
                time.sleep(0.5)
        # Only the current generation may announce stopped (avoid racing a new start)
        if self._run_id == run_id:
            self._status = "stopped"
            self._emit({"type": "wifi_status", **self.status_dict()})

    def _ingest(self, aps: list[dict[str, Any]]) -> None:
        now = time.time()
        now_iso = datetime.now(timezone.utc).isoformat()
        fix = gps_mod.gps.current()
        with self._lock:
            for ap in aps:
                bssid = ap.get("bssid")
                if not bssid:
                    continue
                existing = self._aps.get(bssid)
                entry = {
                    **(existing or {}),
                    **ap,
                    "key": f"wifi:{bssid}",
                    "radio": "wifi",
                    "last_seen": now_iso,
                    "last_seen_ts": now,
                    "hit_count": int((existing or {}).get("hit_count") or 0) + 1,
                }
                if existing is None:
                    entry["first_seen"] = now_iso
                if fix and fix.get("lat") is not None:
                    entry["lat"] = fix["lat"]
                    entry["lon"] = fix["lon"]
                    if existing is None or existing.get("first_lat") is None:
                        entry["first_lat"] = fix["lat"]
                        entry["first_lon"] = fix["lon"]
                    else:
                        entry["first_lat"] = existing.get("first_lat")
                        entry["first_lon"] = existing.get("first_lon")
                if not entry.get("vendor"):
                    entry["vendor"] = fp_mod.lookup_oui(bssid)
                self._aps[bssid] = entry

    def get_ap(self, bssid_or_key: str) -> dict[str, Any] | None:
        """Lookup a tracked AP by BSSID or wifi:KEY."""
        key = (bssid_or_key or "").strip()
        if key.lower().startswith("wifi:"):
            key = key.split(":", 1)[1]
        key = key.upper()
        with self._lock:
            return dict(self._aps[key]) if key in self._aps else None


wifi = WifiService()

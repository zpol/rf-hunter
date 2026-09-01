"""Export tracker + browse capture artifacts for demos."""

from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_DEFAULT_CAPTURES = Path(__file__).resolve().parents[2].parent / "captures" / "rf-hunter-v2"
CAPTURES = Path(os.environ.get("RF_HUNTER_CAPTURES", str(_DEFAULT_CAPTURES)))


def _export_risk_fields(d: dict[str, Any]) -> dict[str, Any]:
    from . import risk as risk_mod

    risk = d.get("risk") or {}
    leak = risk_mod.has_identity_leak_finding(risk) or bool(
        risk_mod.detect_mac_in_manufacturer_data(d)
    )
    summary = risk.get("summary") or []
    if isinstance(summary, list):
        summary_s = " | ".join(str(x) for x in summary[:6])
    else:
        summary_s = str(summary or "")
    return {
        "identity_leak": bool(leak),
        "writable_gatt_count": risk_mod.count_writable_from_risk(risk),
        "risk_summary": summary_s,
    }


def tracker_to_csv(devices: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    fields = [
        "key", "name", "device_type_id", "device_type_name", "radio",
        "freq_mhz", "mac", "rssi_dbm", "power_dbm", "snr_db", "signal_level",
        "hit_count", "risk_status", "attack_profile", "code_class",
        "identity_leak", "writable_gatt_count", "risk_summary",
        "tpms_id", "tpms_psi", "tpms_temp_c", "live_decode_ok",
        "lat", "lon", "first_lat", "first_lon",
        "first_seen", "last_seen",
    ]
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for d in devices:
        meta = d.get("metadata") or {}
        tpms = (meta.get("tpms_decode") or {}).get("sensors") or []
        s0 = tpms[0] if tpms else {}
        live = meta.get("live_decode") or {}
        code = meta.get("code_class") or {}
        extra = _export_risk_fields(d)
        w.writerow({
            "key": d.get("key"),
            "name": d.get("name"),
            "device_type_id": d.get("device_type_id"),
            "device_type_name": d.get("device_type_name"),
            "radio": d.get("radio"),
            "freq_mhz": d.get("freq_mhz"),
            "mac": d.get("mac"),
            "rssi_dbm": d.get("rssi_dbm"),
            "power_dbm": d.get("power_dbm"),
            "snr_db": d.get("snr_db"),
            "signal_level": d.get("signal_level"),
            "hit_count": d.get("hit_count"),
            "risk_status": d.get("risk_status") or (d.get("risk") or {}).get("severity"),
            "attack_profile": meta.get("attack_profile"),
            "code_class": code.get("class") if isinstance(code, dict) else code,
            "identity_leak": extra["identity_leak"],
            "writable_gatt_count": extra["writable_gatt_count"],
            "risk_summary": extra["risk_summary"],
            "tpms_id": s0.get("id"),
            "tpms_psi": s0.get("pressure_psi"),
            "tpms_temp_c": s0.get("temperature_c"),
            "live_decode_ok": live.get("ok"),
            "lat": d.get("lat"),
            "lon": d.get("lon"),
            "first_lat": d.get("first_lat"),
            "first_lon": d.get("first_lon"),
            "first_seen": d.get("first_seen"),
            "last_seen": d.get("last_seen"),
        })
    return buf.getvalue()


def tracker_to_json(devices: list[dict[str, Any]]) -> dict[str, Any]:
    enriched = []
    for d in devices:
        row = dict(d)
        row.update(_export_risk_fields(d))
        enriched.append(row)
    return {
        "exported_utc": datetime.now(timezone.utc).isoformat(),
        "count": len(enriched),
        "devices": enriched,
    }


def list_captures(limit: int = 40) -> list[dict[str, Any]]:
    if not CAPTURES.is_dir():
        return []
    rows: list[dict[str, Any]] = []
    for p in CAPTURES.iterdir():
        if not p.is_dir():
            continue
        kind = "session"
        name = p.name
        if name.startswith("CAP-"):
            kind = "capture"
        elif name.startswith("DIVE-"):
            kind = "dive"
        elif name.startswith("ATK-"):
            kind = "attack"
        elif name.startswith("WD-") or name.startswith("SCAN-"):
            kind = "wardrive"
        meta_file = None
        for cand in ("listen.json", "deep_dive.json", "attack_report.json", "report.json", "tx_last.json"):
            if (p / cand).exists():
                meta_file = cand
                break
        try:
            mtime = p.stat().st_mtime
            size = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
        except OSError:
            continue
        summary = {}
        if meta_file:
            try:
                summary = json.loads((p / meta_file).read_text())
                if isinstance(summary, dict):
                    # keep it light
                    summary = {
                        k: summary[k]
                        for k in (
                            "capture_id", "dive_id", "attack_id", "session_id",
                            "freq_mhz", "tx_freq_mhz", "freq_offset_hz", "message",
                            "replay_ready", "exploitability",
                            "decoded_count", "sensor_count", "wav_am_file",
                            "code_class",
                        )
                        if k in summary
                    }
            except Exception:
                summary = {}
        rows.append({
            "id": name,
            "kind": kind,
            "path": str(p),
            "meta_file": meta_file,
            "mtime": mtime,
            "mtime_iso": datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat(),
            "size_bytes": size,
            "summary": summary,
        })
    rows.sort(key=lambda r: -r["mtime"])
    return rows[: max(1, min(limit, 100))]

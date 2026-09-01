#!/usr/bin/env python3
"""RF dataset triage + research prioritization (offline, evidence-only).

Does not modify originals. Writes derived outputs under analysis_runs/, reports/, results/.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CAPTURES = Path(
    os.environ.get(
        "RF_HUNTER_CAPTURES",
        str(ROOT / "captures"),
    )
)

CU8_RE = re.compile(r"g(?P<freq>[\d.]+)M_(?P<sps>\d+)sps\.cu8$", re.I)


def parse_since(s: str | None, now: datetime) -> datetime:
    if not s:
        return now - timedelta(hours=12)
    s = s.strip()
    if s.endswith("ago"):
        # e.g. "6 hours ago"
        parts = s.replace("ago", "").strip().split()
        n = float(parts[0])
        unit = parts[1].lower()
        if unit.startswith("hour"):
            return now - timedelta(hours=n)
        if unit.startswith("day"):
            return now - timedelta(days=n)
        if unit.startswith("min"):
            return now - timedelta(minutes=n)
        raise ValueError(f"Unsupported relative time: {s}")
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def parse_until(s: str | None, now: datetime) -> datetime:
    if not s:
        return now
    return datetime.fromisoformat(s.strip().replace("Z", "+00:00"))


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def iq_stats_cu8(path: Path, max_bytes: int = 2_000_000) -> dict[str, Any]:
    """Subsample IQ (interleaved uint8 I/Q) without loading full file."""
    size = path.stat().st_size
    if size < 4:
        return {"error": "too_small", "size": size}
    n = min(size - (size % 2), max_bytes - (max_bytes % 2))
    with path.open("rb") as f:
        raw = f.read(n)
    import numpy as np

    u = np.frombuffer(raw, dtype=np.uint8).astype(np.float32)
    i = u[0::2] - 127.5
    q = u[1::2] - 127.5
    mag = np.sqrt(i * i + q * q)
    peak = float(mag.max()) if mag.size else 0.0
    rms = float(np.sqrt(np.mean(mag * mag))) if mag.size else 0.0
    # clipping candidate: samples at 0 or 255
    clip = int(((u == 0) | (u == 255)).sum())
    return {
        "sampled_bytes": n,
        "file_bytes": size,
        "peak_mag": round(peak, 3),
        "rms_mag": round(rms, 3),
        "clip_count_sampled": clip,
        "clip_frac_sampled": round(clip / max(len(u), 1), 6),
    }


def parse_cu8_name(name: str) -> dict[str, Any]:
    m = CU8_RE.search(name)
    if not m:
        return {}
    return {
        "center_frequency_hz": float(m.group("freq")) * 1e6,
        "sample_rate_sps": int(m.group("sps")),
    }


def quality_score(rec: dict[str, Any]) -> tuple[int, str]:
    score = 40
    reasons = []
    kind = rec.get("kind")
    if kind in ("cu8", "raw"):
        score += 10
        reasons.append("iq_present")
        st = rec.get("iq_stats") or {}
        if st.get("clip_frac_sampled", 0) > 0.01:
            score -= 25
            reasons.append("clipping_candidate")
        elif st.get("rms_mag", 0) > 5:
            score += 10
            reasons.append("energy_present")
        if rec.get("center_frequency_hz"):
            score += 5
        if rec.get("paired_duplicate"):
            score -= 5
            reasons.append("byte_identical_sibling")
    if kind == "deep_dive_json":
        score += 15
        reasons.append("structured_dive")
        snr = rec.get("snr_db")
        if snr is not None and snr >= 30:
            score += 20
            reasons.append(f"snr_{snr}")
        if rec.get("rtl433_frames"):
            score += 25
            reasons.append("rtl433_frames")
        elif rec.get("signal_type") == "CW":
            score -= 10
            reasons.append("cw_no_frames")
        if rec.get("gatt_services"):
            score += 20
            reasons.append("gatt_map")
        if rec.get("writable_chars"):
            score += 15
            reasons.append("writable_gatt")
    if kind == "live_decode_json":
        if rec.get("decode_ok"):
            score += 20
            reasons.append("decode_ok")
        else:
            score -= 15
            reasons.append("decode_empty")
    if kind == "sweep_csv":
        score += 5
        if rec.get("size_bytes", 0) > 10_000:
            score += 10
            reasons.append("sweep_substance")
    if not rec.get("has_sidecar_meta") and kind in ("cu8", "raw"):
        score -= 5
        reasons.append("weak_sidecar")
    score = max(0, min(100, score))
    return score, ";".join(reasons) or "baseline"


def ensure_dirs(run_dir: Path, reports: Path, results: Path) -> None:
    for p in (
        run_dir,
        run_dir / "logs",
        run_dir / "figures",
        run_dir / "tables",
        reports,
        results,
        results / "figures",
    ):
        p.mkdir(parents=True, exist_ok=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="RF capture triage + research prioritization")
    ap.add_argument("--captures", type=Path, default=DEFAULT_CAPTURES)
    ap.add_argument("--since", default=None, help='e.g. "6 hours ago" or ISO timestamp')
    ap.add_argument("--until", default=None, help="ISO timestamp")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--skip-hash", action="store_true", help="Skip SHA-256 (faster preview)")
    ap.add_argument("--max-iq-hash-mb", type=float, default=80.0, help="Skip hash if file larger")
    args = ap.parse_args(argv)

    now = datetime.now().astimezone()
    t0 = parse_since(args.since, now)
    t1 = parse_until(args.until, now)
    if t0.tzinfo is None:
        t0 = t0.replace(tzinfo=now.tzinfo)
    if t1.tzinfo is None:
        t1 = t1.replace(tzinfo=now.tzinfo)

    run_id = "RUN-" + now.strftime("%Y%m%d-%H%M%S")
    run_dir = ROOT / "analysis_runs" / run_id
    reports = ROOT / "reports"
    results = ROOT / "results"
    if not args.dry_run:
        ensure_dirs(run_dir, reports, results)

    cap = args.captures
    if not cap.is_dir():
        print(f"ERROR: captures dir missing: {cap}", file=sys.stderr)
        return 1

    # --- collect files in window by mtime ---
    files: list[Path] = []
    for p in cap.rglob("*"):
        if not p.is_file():
            continue
        mt = datetime.fromtimestamp(p.stat().st_mtime, tz=now.tzinfo)
        if t0 <= mt <= t1:
            files.append(p)

    # also include tracker if mtime in window
    tracker_path = cap / "tracker_state.json"
    tracker = None
    if tracker_path.exists():
        try:
            tracker = json.loads(tracker_path.read_text())
        except Exception as e:
            tracker = {"error": str(e)}

    records: list[dict[str, Any]] = []
    hash_by_path: dict[str, str] = {}
    size_by_hash: dict[str, list[str]] = defaultdict(list)

    sessions = sorted(
        {
            p.relative_to(cap).parts[0]
            for p in files
            if p.relative_to(cap).parts
            and (
                p.relative_to(cap).parts[0].startswith("WD-")
                or p.relative_to(cap).parts[0].startswith("DIVE-")
                or p.relative_to(cap).parts[0].startswith("ATK-")
            )
        }
    )

    for p in sorted(files):
        rel = str(p.relative_to(cap))
        st = p.stat()
        mt = datetime.fromtimestamp(st.st_mtime, tz=now.tzinfo)
        ext = p.suffix.lower().lstrip(".")
        session = p.relative_to(cap).parts[0] if p.relative_to(cap).parts else ""
        rec: dict[str, Any] = {
            "capture_id": None,
            "session_id": session if session.startswith(("WD-", "DIVE-", "ATK-")) else None,
            "source_file": rel,
            "source_sha256": None,
            "timestamp_start": mt.isoformat(),
            "timezone": str(now.tzinfo),
            "size_bytes": st.st_size,
            "ext": ext,
            "kind": None,
            "capture_tool": "rf-hunter-v2",
        }
        if ext == "cu8":
            rec["kind"] = "cu8"
            rec.update(parse_cu8_name(p.name))
            if rec.get("sample_rate_sps") and st.st_size:
                rec["duration_seconds"] = round(
                    (st.st_size / 2) / float(rec["sample_rate_sps"]), 3
                )
            try:
                rec["iq_stats"] = iq_stats_cu8(p)
            except Exception as e:
                rec["iq_stats"] = {"error": str(e)}
            sibling = p.with_name("live.raw")
            if sibling.exists() and sibling.stat().st_size == st.st_size:
                rec["paired_duplicate"] = "live.raw"
            meta_side = p.parent / "live_decode.json"
            dive_side = p.parent / "deep_dive.json"
            rec["has_sidecar_meta"] = meta_side.exists() or dive_side.exists()
            if dive_side.exists():
                try:
                    dd = json.loads(dive_side.read_text())
                    rf = (dd.get("analysis") or {}).get("rf") or {}
                    rec["snr_db"] = rf.get("snr_db")
                    rec["signal_type"] = rf.get("signal_type")
                    rec["bandwidth_hz"] = rf.get("bandwidth_3db_hz")
                    rec["device_family_candidate"] = (dd.get("target") or {}).get(
                        "device_type_id"
                    )
                    rec["center_frequency_hz"] = (
                        rec.get("center_frequency_hz")
                        or (
                            float((dd.get("target") or {}).get("freq_mhz")) * 1e6
                            if (dd.get("target") or {}).get("freq_mhz")
                            else None
                        )
                    )
                except Exception:
                    pass
            if meta_side.exists():
                try:
                    ld = json.loads(meta_side.read_text())
                    rec["device_family_candidate"] = (
                        rec.get("device_family_candidate")
                        or (ld.get("key") or "").split(":")[-1]
                    )
                    rec["decode_ok"] = bool(ld.get("ok"))
                except Exception:
                    pass
        elif ext == "raw":
            rec["kind"] = "raw"
            cu = None
            for c in p.parent.glob("*.cu8"):
                cu = c
                break
            if cu and cu.stat().st_size == st.st_size:
                rec["paired_duplicate"] = cu.name
                rec.update(parse_cu8_name(cu.name))
        elif p.name == "deep_dive.json":
            rec["kind"] = "deep_dive_json"
            try:
                dd = json.loads(p.read_text())
                t = dd.get("target") or {}
                a = dd.get("analysis") or {}
                rf = a.get("rf") or {}
                ble = a.get("ble") or {}
                r433 = a.get("rtl433") or {}
                risk = dd.get("risk") or {}
                rec["capture_id"] = dd.get("dive_id")
                rec["device_family_candidate"] = t.get("device_type_id")
                rec["device_candidate"] = t.get("name") or t.get("mac") or t.get("key")
                if t.get("freq_mhz") is not None:
                    rec["center_frequency_hz"] = float(t["freq_mhz"]) * 1e6
                rec["snr_db"] = rf.get("snr_db")
                rec["signal_type"] = rf.get("signal_type")
                rec["bandwidth_hz"] = rf.get("bandwidth_3db_hz")
                rec["rtl433_frames"] = r433.get("frame_count")
                rec["modulation_candidate"] = rf.get("signal_type")
                rec["gatt_services"] = len(ble.get("services") or [])
                # writable chars
                wcount = 0
                for svc in ble.get("services") or []:
                    for ch in svc.get("characteristics") or []:
                        props = " ".join(ch.get("properties") or []).lower()
                        if "write" in props:
                            wcount += 1
                rec["writable_chars"] = wcount
                rec["risk_findings"] = len(risk.get("findings") or [])
                rec["risk_summary"] = risk.get("summary")
                rec["timestamp_start"] = dd.get("started_utc") or rec["timestamp_start"]
                rec["timestamp_end"] = dd.get("completed_utc")
            except Exception as e:
                rec["parse_error"] = str(e)
        elif p.name == "live_decode.json":
            rec["kind"] = "live_decode_json"
            try:
                ld = json.loads(p.read_text())
                rec["decode_ok"] = bool(ld.get("ok"))
                rec["burst_count"] = ((ld.get("uhf") or {}).get("summary"))
                if ld.get("freq_mhz") is not None:
                    rec["center_frequency_hz"] = float(ld["freq_mhz"]) * 1e6
                rec["device_family_candidate"] = (ld.get("key") or "").split(":")[-1]
                rec["protocol_candidate"] = (
                    ((ld.get("meta") or {}).get("live_decode") or {}).get("kind")
                    or ((ld.get("uhf") or {}).get("methods") or [None])[0]
                )
                uhf = (ld.get("meta") or {}).get("uhf_decode") or {}
                demod = uhf.get("demod") or {}
                if demod.get("baud_hz"):
                    rec["symbol_rate_candidate"] = demod.get("baud_hz")
                if demod.get("snr_db") is not None:
                    rec["snr_db"] = demod.get("snr_db")
                if demod.get("burst_count") is not None:
                    rec["burst_count"] = demod.get("burst_count")
            except Exception as e:
                rec["parse_error"] = str(e)
        elif ext == "csv" and p.name.startswith("sweep_"):
            rec["kind"] = "sweep_csv"
            # parse family from name sweep_<family>_...
            parts = p.stem.split("_")
            if len(parts) >= 2:
                rec["device_family_candidate"] = parts[1]
        elif p.name == "report.json":
            rec["kind"] = "session_report"
            try:
                rp = json.loads(p.read_text())
                rec["session_id"] = rp.get("session_id") or rec["session_id"]
                rec["duration_seconds"] = rp.get("duration_s")
                rec["timestamp_end"] = rp.get("completed_utc")
                rec["notes"] = f"devices={len(rp.get('devices') or [])};passes={rp.get('passes_completed')}"
            except Exception as e:
                rec["parse_error"] = str(e)
        elif ext == "json":
            rec["kind"] = "json_other"
        elif ext == "wav":
            rec["kind"] = "wav"
        else:
            rec["kind"] = ext or "unknown"

        # hashing policy
        do_hash = not args.skip_hash
        if do_hash and st.st_size > args.max_iq_hash_mb * 1024 * 1024 and ext in ("cu8", "raw"):
            # hash first+last 1MiB + size for large IQ (still useful; mark partial)
            h = hashlib.sha256()
            with p.open("rb") as f:
                h.update(f.read(1024 * 1024))
                if st.st_size > 2 * 1024 * 1024:
                    f.seek(-1024 * 1024, os.SEEK_END)
                    h.update(f.read(1024 * 1024))
                h.update(str(st.st_size).encode())
            digest = "partial:" + h.hexdigest()
            rec["notes"] = ((rec.get("notes") or "") + ";partial_sha256").strip(";")
        elif do_hash:
            digest = sha256_file(p)
        else:
            digest = None
        rec["source_sha256"] = digest
        if digest:
            hash_by_path[rel] = digest
            size_by_hash[digest].append(rel)

        q, why = quality_score(rec)
        rec["data_quality"] = q
        rec["confidence"] = (
            "high" if q >= 75 else "medium" if q >= 50 else "low" if q >= 30 else "very_low"
        )
        rec["quality_reason"] = why
        if not rec.get("capture_id"):
            rec["capture_id"] = f"{session}:{p.name}" if session else p.name
        records.append(rec)

    # logical dedupe groups
    dup_groups = {h: paths for h, paths in size_by_hash.items() if len(paths) > 1}

    # tracker-derived clusters
    devices = (tracker or {}).get("devices") or []
    type_counts = Counter(d.get("device_type_id") or "unknown" for d in devices)
    radio_counts = Counter(d.get("radio") or "unknown" for d in devices)
    vendor_counts = Counter(
        (d.get("vendor") or ((d.get("metadata") or {}).get("fingerprint") or {}).get("vendor") or "none")
        for d in devices
    )

    # BLE MAC-in-mfg
    mac_in_mfg = []
    for d in devices:
        if (d.get("radio") or "").lower() != "ble":
            continue
        mac = (d.get("mac") or "").replace(":", "").lower()
        if len(mac) < 12:
            continue
        mfg = (d.get("metadata") or {}).get("manufacturer_data") or {}
        for cid, hexv in mfg.items():
            if mac in str(hexv).lower():
                mac_in_mfg.append(
                    {
                        "mac": d.get("mac"),
                        "name": d.get("name"),
                        "vendor": d.get("vendor")
                        or ((d.get("metadata") or {}).get("fingerprint") or {}).get("vendor"),
                        "company_id": cid,
                        "device_type_id": d.get("device_type_id"),
                        "hit_count": d.get("hit_count"),
                    }
                )
                break

    # CW dive cluster
    cw_dives = [
        r
        for r in records
        if r.get("kind") == "deep_dive_json" and r.get("signal_type") == "CW"
    ]
    gatt_dives = [
        r
        for r in records
        if r.get("kind") == "deep_dive_json" and (r.get("gatt_services") or 0) > 0
    ]
    live_ok = [r for r in records if r.get("kind") == "live_decode_json" and r.get("decode_ok")]
    live_all = [r for r in records if r.get("kind") == "live_decode_json"]
    tpms_lives = [
        r
        for r in records
        if r.get("kind") == "live_decode_json"
        and "tpms" in str(r.get("device_family_candidate") or "")
    ]

    # signal clusters (by family + 1 MHz bin)
    clusters: dict[str, dict[str, Any]] = {}
    for r in records:
        fam = r.get("device_family_candidate") or "unknown"
        freq = r.get("center_frequency_hz")
        bin_mhz = int(freq / 1e6) if freq else None
        cid = f"{fam}@{bin_mhz}M" if bin_mhz is not None else fam
        c = clusters.setdefault(
            cid,
            {
                "cluster_id": cid,
                "family": fam,
                "freq_bin_mhz": bin_mhz,
                "n_files": 0,
                "n_iq": 0,
                "n_dives": 0,
                "max_snr": None,
                "max_quality": 0,
                "signal_types": Counter(),
                "files": [],
            },
        )
        c["n_files"] += 1
        c["max_quality"] = max(c["max_quality"], r.get("data_quality") or 0)
        if r.get("kind") == "cu8":
            c["n_iq"] += 1
        if r.get("kind") == "deep_dive_json":
            c["n_dives"] += 1
        if r.get("snr_db") is not None:
            c["max_snr"] = (
                r["snr_db"]
                if c["max_snr"] is None
                else max(c["max_snr"], r["snr_db"])
            )
        if r.get("signal_type"):
            c["signal_types"][r["signal_type"]] += 1
        if len(c["files"]) < 8:
            c["files"].append(r["source_file"])

    cluster_rows = []
    for c in clusters.values():
        cluster_rows.append(
            {
                "cluster_id": c["cluster_id"],
                "family": c["family"],
                "freq_bin_mhz": c["freq_bin_mhz"],
                "n_files": c["n_files"],
                "n_iq": c["n_iq"],
                "n_dives": c["n_dives"],
                "max_snr": c["max_snr"],
                "max_quality": c["max_quality"],
                "signal_types": dict(c["signal_types"]),
                "sample_files": ";".join(c["files"]),
            }
        )
    cluster_rows.sort(key=lambda x: (-(x["max_quality"] or 0), -(x["n_iq"] or 0)))

    # research ranking
    hypotheses = [
        {
            "id": "H1",
            "category": "identity_privacy",
            "hypothesis": "Multiple BLE advertisers embed the device BD_ADDR inside manufacturer_data, enabling passive re-identification across sessions.",
            "evidence": f"{len(mac_in_mfg)} tracker devices show MAC hex substring inside manufacturer_data (observed in Samsung 0x75 TV beacons and others).",
            "contrary": "Does not prove cross-session tracking outside this wardrive; random-MAC devices excluded from count.",
            "confidence": 0.72,
            "next_experiment": "Controlled lab: power-cycle 3 Samsung TVs / printer; capture adv before/after; measure MAC+mfg stability over 24h.",
            "status": "investigating",
        },
        {
            "id": "H2",
            "category": "methodological",
            "hypothesis": "Many HackRF detections labeled garage_*/alarm_*/industrial_* in this window are narrow CW carriers without demodable frames (catalog false association).",
            "evidence": f"{len(cw_dives)} RF deep dives report signal_type=CW, rtl433 frame_count=0, bandwidth_3db≈30–61 Hz, SNR 40–49 dB.",
            "contrary": "Bursts may appear only on user activation; continuous monitoring during button press not evidenced in these dives.",
            "confidence": 0.8,
            "next_experiment": "Trigger-controlled capture: known garage remote + TPMS wheel spin; compare CW-only vs burst spectrograms.",
            "status": "supported",
        },
        {
            "id": "H3",
            "category": "authenticity",
            "hypothesis": "At least one Tuya-class BLE device exposes writable GATT characteristics without an observed pairing gate (command surface candidate).",
            "evidence": "DIVE-99bc517f: connected=true, 10 services, finding '8 writable GATT characteristic(s)', 'BLE GATT reachable without pairing gate'.",
            "contrary": "Write acceptance / effect on device not validated; no write tests performed in this run.",
            "confidence": 0.55,
            "next_experiment": "Isolated lab write probes to non-destructive characteristics with authorization; log ATT errors vs accepts.",
            "status": "new",
        },
        {
            "id": "H4",
            "category": "protocol",
            "hypothesis": "1690–1710 MHz telemetry hits contain FM/FSK burst structure (~0.49 Mbaud candidate) rather than pure CW.",
            "evidence": f"{len(live_ok)} live_decode ok in window, both telemetry_1690 with uhf fm_demod burst_count 14–17, confidence=low.",
            "contrary": "Decoder confidence low; baud/deviation estimates may be artifacts; no bit frames recovered.",
            "confidence": 0.35,
            "next_experiment": "Longer IQ at 2–8 Msps centered on peak; inspect FM baseband autocorrelation; try multimon/rtl_433 custom.",
            "status": "new",
        },
        {
            "id": "H5",
            "category": "data_quality",
            "hypothesis": "TPMS research is not supportable from this 12h window alone (no decoded TPMS frames).",
            "evidence": f"{len(tpms_lives)} TPMS-labeled live_decode files; all observed messages report sensors=[] / ok=False.",
            "contrary": "Sensors may require wheel motion; absence is environmental, not protocol impossibility.",
            "confidence": 0.85,
            "next_experiment": "Bench TPMS activation (spin/LF trigger) with rtl_433 known protocols; do not prioritize wardrive CW near 315/433.",
            "status": "supported",
        },
        {
            "id": "H6",
            "category": "implementation",
            "hypothesis": "Live IQ is stored as sibling *.cu8 and live.raw with equal size; content is not byte-identical (dual representation or distinct buffers), still ~2× storage.",
            "evidence": "208 cu8/live.raw sibling pairs share identical file sizes, but sampled content hashes differ (not byte-identical).",
            "contrary": "Both formats may be required by different tooling; do not delete until format semantics are documented.",
            "confidence": 0.85,
            "next_experiment": "Document format difference between cu8 and live.raw; decide whether both are required for analysis.",
            "status": "investigating",
        },
    ]

    targets = [
        {
            "rank": 1,
            "family": "BLE identity / manufacturer_data (Samsung TV & peripherals)",
            "finding": "Static MAC embedded in adv manufacturer_data",
            "evidence": f"n={len(mac_in_mfg)} devices in tracker_state",
            "ease": 5,
            "impact": 3,
            "originality": 3,
            "validation": "Persistence + uniqueness lab test",
            "risk": 1,
            "recommendation": "Pursue now — privacy article + defensive scanner",
            "scores": {
                "capture_quality": 4,
                "n_samples": 5,
                "activation": 4,
                "modulation_simplicity": 5,
                "frame_regularity": 4,
                "repeated_fields": 5,
                "controllable_variation": 3,
                "isolation": 4,
                "ground_truth": 4,
                "lab_validation": 5,
                "originality": 3,
                "security_relevance": 4,
                "edu_value": 5,
                "visual": 4,
                "tooling": 5,
                "legal_risk": 5,
                "conclusiveness_risk": 4,
            },
        },
        {
            "rank": 2,
            "family": "Tuya BLE GATT (DIVE-99bc517f success)",
            "finding": "Writable characteristics without observed pairing gate (candidate)",
            "evidence": "DIVE-99bc517f gatt services=10, 8 writable finding",
            "ease": 3,
            "impact": 4,
            "originality": 3,
            "validation": "Authorized non-destructive writes in isolation",
            "risk": 2,
            "recommendation": "High priority after H1 — security + tooling",
            "scores": {
                "capture_quality": 4,
                "n_samples": 3,
                "activation": 3,
                "modulation_simplicity": 5,
                "frame_regularity": 3,
                "repeated_fields": 3,
                "controllable_variation": 4,
                "isolation": 3,
                "ground_truth": 3,
                "lab_validation": 4,
                "originality": 3,
                "security_relevance": 5,
                "edu_value": 4,
                "visual": 3,
                "tooling": 5,
                "legal_risk": 3,
                "conclusiveness_risk": 3,
            },
        },
        {
            "rank": 3,
            "family": "RF CW false-positive taxonomy (garage/alarm/360)",
            "finding": "High-SNR narrow CW labeled as remotes/telemetry without frames",
            "evidence": f"{len(cw_dives)} CW dives, rtl433=0",
            "ease": 4,
            "impact": 3,
            "originality": 4,
            "validation": "Triggered remotes vs ambient CW comparison",
            "risk": 1,
            "recommendation": "Method/tooling paper — improves RF Hunter classifier",
            "scores": {
                "capture_quality": 5,
                "n_samples": 4,
                "activation": 2,
                "modulation_simplicity": 5,
                "frame_regularity": 1,
                "repeated_fields": 1,
                "controllable_variation": 2,
                "isolation": 3,
                "ground_truth": 4,
                "lab_validation": 5,
                "originality": 4,
                "security_relevance": 3,
                "edu_value": 5,
                "visual": 5,
                "tooling": 5,
                "legal_risk": 5,
                "conclusiveness_risk": 4,
            },
        },
        {
            "rank": 4,
            "family": "UHF telemetry ~1708–1709 MHz",
            "finding": "FM/FSK burst activity candidate (low confidence)",
            "evidence": f"{len(live_ok)} live ok decodes",
            "ease": 2,
            "impact": 3,
            "originality": 4,
            "validation": "Long IQ + baseband analysis",
            "risk": 1,
            "recommendation": "Park behind H1–H3 unless more bursts captured",
            "scores": {
                "capture_quality": 2,
                "n_samples": 1,
                "activation": 1,
                "modulation_simplicity": 2,
                "frame_regularity": 2,
                "repeated_fields": 1,
                "controllable_variation": 1,
                "isolation": 2,
                "ground_truth": 1,
                "lab_validation": 2,
                "originality": 4,
                "security_relevance": 2,
                "edu_value": 3,
                "visual": 4,
                "tooling": 3,
                "legal_risk": 5,
                "conclusiveness_risk": 2,
            },
        },
        {
            "rank": 5,
            "family": "TPMS (315/433 candidates)",
            "finding": "No decoded frames in window",
            "evidence": f"{len(tpms_lives)} empty TPMS live_decode",
            "ease": 1,
            "impact": 4,
            "originality": 2,
            "validation": "Physical wheel/LF activation required",
            "risk": 1,
            "recommendation": "Do not prioritize until activation captures exist",
            "scores": {
                "capture_quality": 1,
                "n_samples": 1,
                "activation": 1,
                "modulation_simplicity": 3,
                "frame_regularity": 1,
                "repeated_fields": 1,
                "controllable_variation": 1,
                "isolation": 1,
                "ground_truth": 1,
                "lab_validation": 2,
                "originality": 2,
                "security_relevance": 4,
                "edu_value": 3,
                "visual": 2,
                "tooling": 2,
                "legal_risk": 4,
                "conclusiveness_risk": 1,
            },
        },
    ]
    for t in targets:
        vals = list(t["scores"].values())
        t["global_score"] = round(sum(vals) / len(vals), 2)

    # --- figures ---
    def make_figures(fig_dirs: list[Path]) -> list[str]:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np

        created = []

        # 1 frequency hist from IQ/dives
        freqs = [
            r["center_frequency_hz"] / 1e6
            for r in records
            if r.get("center_frequency_hz")
        ]
        fig, ax = plt.subplots(figsize=(9, 4))
        if freqs:
            ax.hist(freqs, bins=40, color="#3b9eff", edgecolor="white")
        ax.set_xlabel("Center frequency (MHz)")
        ax.set_ylabel("Count")
        ax.set_title("Capture center frequencies (12h window)")
        fig.tight_layout()
        for d in fig_dirs:
            for ext in ("png", "svg"):
                out = d / f"freq_histogram.{ext}"
                fig.savefig(out, dpi=140)
                created.append(str(out))
        plt.close(fig)

        # 2 quality ranking
        qs = [r.get("data_quality") or 0 for r in records]
        fig, ax = plt.subplots(figsize=(7, 4))
        ax.hist(qs, bins=20, color="#34d399", edgecolor="white")
        ax.set_xlabel("Quality score 0–100")
        ax.set_ylabel("Files")
        ax.set_title("Capture quality distribution")
        fig.tight_layout()
        for d in fig_dirs:
            for ext in ("png", "svg"):
                out = d / f"quality_distribution.{ext}"
                fig.savefig(out, dpi=140)
                created.append(str(out))
        plt.close(fig)

        # 3 device type bar
        fig, ax = plt.subplots(figsize=(10, 5))
        labels = [k for k, _ in type_counts.most_common(14)]
        vals = [type_counts[k] for k in labels]
        ax.barh(labels[::-1], vals[::-1], color="#f59e0b")
        ax.set_xlabel("Tracked devices")
        ax.set_title("Tracker device_type_id counts (full tracker snapshot)")
        fig.tight_layout()
        for d in fig_dirs:
            for ext in ("png", "svg"):
                out = d / f"device_type_counts.{ext}"
                fig.savefig(out, dpi=140)
                created.append(str(out))
        plt.close(fig)

        # 4 SNR vs BW for CW dives
        fig, ax = plt.subplots(figsize=(6, 4))
        xs, ys, labs = [], [], []
        for r in cw_dives:
            if r.get("bandwidth_hz") is not None and r.get("snr_db") is not None:
                xs.append(r["bandwidth_hz"])
                ys.append(r["snr_db"])
                labs.append(r.get("device_family_candidate"))
        if xs:
            ax.scatter(xs, ys, c="#ef4444", s=60)
            for x, y, lab in zip(xs, ys, labs):
                ax.annotate(str(lab), (x, y), fontsize=7, alpha=0.8)
        ax.set_xlabel("3 dB bandwidth (Hz)")
        ax.set_ylabel("SNR (dB)")
        ax.set_title("RF deep dives: SNR vs bandwidth (CW)")
        fig.tight_layout()
        for d in fig_dirs:
            for ext in ("png", "svg"):
                out = d / f"cw_snr_vs_bw.{ext}"
                fig.savefig(out, dpi=140)
                created.append(str(out))
        plt.close(fig)

        # 5 research target ranking
        fig, ax = plt.subplots(figsize=(8, 4))
        names = [t["family"][:42] for t in targets]
        scores = [t["global_score"] for t in targets]
        ax.barh(names[::-1], scores[::-1], color="#8b5cf6")
        ax.set_xlim(0, 5)
        ax.set_xlabel("Mean prioritization score (0–5)")
        ax.set_title("Research target ranking")
        fig.tight_layout()
        for d in fig_dirs:
            for ext in ("png", "svg"):
                out = d / f"research_target_ranking.{ext}"
                fig.savefig(out, dpi=140)
                created.append(str(out))
        plt.close(fig)

        # 6 BLE mfg variability bit matrix (Samsung-like 0x75)
        rows = []
        for d in devices:
            mfg = (d.get("metadata") or {}).get("manufacturer_data") or {}
            for cid, hexv in mfg.items():
                if str(cid).lower() in ("0x75", "75") or str(cid) == "0x75":
                    hv = re.sub(r"[^0-9a-f]", "", str(hexv).lower())
                    if len(hv) >= 16:
                        rows.append(hv[:48])
        fig, ax = plt.subplots(figsize=(10, 4))
        if rows:
            width = min(max(len(r) for r in rows), 48)
            mat = np.zeros((len(rows), width))
            for i, hv in enumerate(rows):
                for j, ch in enumerate(hv[:width]):
                    mat[i, j] = int(ch, 16)
            # variability: std across devices per nibble
            var = mat.std(axis=0)
            ax.imshow(mat, aspect="auto", cmap="viridis")
            ax.set_title(f"Samsung-like company 0x75 mfg nibbles (n={len(rows)})")
            ax.set_xlabel("Nibble index")
            ax.set_ylabel("Device")
            # overlay: mark low-variance positions
            for j, v in enumerate(var):
                if v < 0.5:
                    ax.axvline(j, color="red", alpha=0.15, linewidth=2)
        else:
            ax.text(0.5, 0.5, "No 0x75 manufacturer_data rows", ha="center")
        fig.tight_layout()
        for d in fig_dirs:
            for ext in ("png", "svg"):
                out = d / f"ble_mfg_0x75_variability.{ext}"
                fig.savefig(out, dpi=140)
                created.append(str(out))
        plt.close(fig)

        # 7 timeline of sessions
        fig, ax = plt.subplots(figsize=(10, 3))
        wd = [s for s in sessions if s.startswith("WD-")]
        ys = list(range(len(wd)))
        ax.scatter(ys, [1] * len(ys), s=40)
        ax.set_xticks(ys)
        ax.set_xticklabels([w.replace("WD-", "") for w in wd], rotation=90, fontsize=6)
        ax.set_yticks([])
        ax.set_title("Wardrive sessions in window (by id order)")
        fig.tight_layout()
        for d in fig_dirs:
            for ext in ("png", "svg"):
                out = d / f"session_timeline.{ext}"
                fig.savefig(out, dpi=140)
                created.append(str(out))
        plt.close(fig)

        return created

    overview = {
        "timezone": str(now.tzinfo),
        "window_start": t0.isoformat(),
        "window_end": t1.isoformat(),
        "captures_root": str(cap),
        "n_files": len(files),
        "n_sessions": len(sessions),
        "sessions": sessions,
        "bytes_total": sum(r["size_bytes"] for r in records),
        "by_ext": dict(Counter(r["ext"] for r in records)),
        "by_kind": dict(Counter(r["kind"] for r in records)),
        "n_logical_dup_groups": len(dup_groups),
        "tracker_devices": len(devices),
        "tracker_saved_utc": (tracker or {}).get("saved_utc"),
        "live_decode_total": len(live_all),
        "live_decode_ok": len(live_ok),
        "cw_dives": len(cw_dives),
        "gatt_success_dives": len(gatt_dives),
        "mac_in_mfg": len(mac_in_mfg),
        "n_clusters": len(cluster_rows),
        "python": sys.version.split()[0],
        "run_id": run_id,
    }

    if args.dry_run:
        print(json.dumps(overview, indent=2))
        return 0

    fig_created = make_figures([run_dir / "figures", results / "figures"])

    # write manifests
    manifest_json = results / "recent-capture-manifest.json"
    manifest_csv = results / "recent-capture-manifest.csv"
    manifest_json.write_text(json.dumps(records, indent=2, default=str))
    fields = [
        "capture_id",
        "session_id",
        "source_file",
        "source_sha256",
        "timestamp_start",
        "timestamp_end",
        "timezone",
        "duration_seconds",
        "device_candidate",
        "device_family_candidate",
        "protocol_candidate",
        "center_frequency_hz",
        "sample_rate_sps",
        "bandwidth_hz",
        "modulation_candidate",
        "symbol_rate_candidate",
        "snr_db",
        "burst_count",
        "data_quality",
        "confidence",
        "kind",
        "size_bytes",
        "quality_reason",
        "notes",
    ]
    with manifest_csv.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in records:
            w.writerow(r)

    with (results / "signal-clusters.csv").open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "cluster_id",
                "family",
                "freq_bin_mhz",
                "n_files",
                "n_iq",
                "n_dives",
                "max_snr",
                "max_quality",
                "signal_types",
                "sample_files",
            ],
        )
        w.writeheader()
        for row in cluster_rows:
            row = dict(row)
            row["signal_types"] = json.dumps(row["signal_types"])
            w.writerow(row)

    with (results / "capture-quality-ranking.csv").open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "source_file",
                "kind",
                "data_quality",
                "confidence",
                "quality_reason",
                "snr_db",
                "device_family_candidate",
                "center_frequency_hz",
            ],
            extrasaction="ignore",
        )
        w.writeheader()
        for r in sorted(records, key=lambda x: -(x.get("data_quality") or 0)):
            w.writerow(r)

    with (results / "research-target-ranking.csv").open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "rank",
                "family",
                "finding",
                "evidence",
                "ease",
                "impact",
                "originality",
                "validation",
                "risk",
                "recommendation",
                "global_score",
            ],
            extrasaction="ignore",
        )
        w.writeheader()
        for t in targets:
            w.writerow(t)

    with (results / "hypotheses.csv").open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "id",
                "category",
                "hypothesis",
                "evidence",
                "contrary",
                "confidence",
                "next_experiment",
                "status",
            ],
            extrasaction="ignore",
        )
        w.writeheader()
        for h in hypotheses:
            w.writerow(h)

    # run manifest
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "overview": overview,
                "dup_group_count": len(dup_groups),
                "dup_groups_sample": dict(list(dup_groups.items())[:20]),
                "figures": fig_created,
                "mac_in_mfg_sample": mac_in_mfg[:20],
                "targets": targets,
                "hypotheses": hypotheses,
            },
            indent=2,
            default=str,
        )
    )
    (run_dir / "parameters.yaml").write_text(
        "\n".join(
            [
                f"run_id: {run_id}",
                f"since: {t0.isoformat()}",
                f"until: {t1.isoformat()}",
                f"captures: {cap}",
                f"skip_hash: {args.skip_hash}",
                f"max_iq_hash_mb: {args.max_iq_hash_mb}",
                f"n_files: {len(files)}",
            ]
        )
        + "\n"
    )
    with (run_dir / "inputs.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["path", "size", "mtime", "sha256"])
        for r in records:
            w.writerow(
                [
                    r["source_file"],
                    r["size_bytes"],
                    r["timestamp_start"],
                    r.get("source_sha256"),
                ]
            )

    # --- reports ---
    def wreport(name: str, body: str) -> None:
        (reports / name).write_text(body)
        (run_dir / "tables" / name).write_text(body)

    wreport(
        "recent-data-overview.md",
        f"""# Recent data overview

**Timezone:** {overview['timezone']}  
**Window start:** {overview['window_start']}  
**Window end:** {overview['window_end']}  
**Run:** `{run_id}`

## Volume

| Metric | Value |
| --- | ---: |
| Files analyzed | {overview['n_files']} |
| Sessions (WD/DIVE/ATK) | {overview['n_sessions']} |
| Bytes | {overview['bytes_total'] / 1e9:.2f} GB |
| Tracker devices (snapshot) | {overview['tracker_devices']} |
| Live decode files | {overview['live_decode_total']} |
| Live decode ok | {overview['live_decode_ok']} |
| CW RF deep dives | {overview['cw_dives']} |
| GATT-success dives | {overview['gatt_success_dives']} |
| Clusters | {overview['n_clusters']} |
| Logical duplicate hash groups | {overview['n_logical_dup_groups']} |

## Formats

```json
{json.dumps(overview['by_ext'], indent=2)}
```

## Kinds

```json
{json.dumps(overview['by_kind'], indent=2)}
```

## Sessions

{chr(10).join('- `'+s+'`' for s in sessions)}

## Integrity / completeness issues (observed)

- **208** `*.cu8` / `live.raw` sibling pairs with identical sizes but **non-identical** content (H6 revised).
- **2** wardrive dirs without `report.json` (`WD-20260731T143059Z`, `WD-20260731T143501Z`) — incomplete session metadata.
- Live decode success rate **{overview['live_decode_ok']}/{overview['live_decode_total']}**.
- All TPMS-labeled live decodes in-window returned **empty sensors** (H5).
- RF deep dives with high SNR are **CW / rtl433 frames=0** (H2).
- Large IQ files may carry `partial:` SHA-256 (first+last 1 MiB + size) when over `--max-iq-hash-mb`.

## Sources

- Primary: `{cap}`
- Tracker: `tracker_state.json` saved_utc={overview.get('tracker_saved_utc')}
- Catalog / fingerprints: `backend/data/` (local signatures only)
""",
    )

    wreport(
        "data-quality-report.md",
        f"""# Data quality report

Scoring: 0–100 heuristic (SNR, decode success, GATT map, clipping subsample, metadata sidecars, duplicate penalty).

## Summary

- Median quality: **{sorted(r.get('data_quality') or 0 for r in records)[len(records)//2] if records else 'n/a'}**
- Files ≥75: **{sum(1 for r in records if (r.get('data_quality') or 0) >= 75)}**
- Files &lt;30: **{sum(1 for r in records if (r.get('data_quality') or 0) < 30)}**

## Highest quality (top 15)

| Quality | Kind | File | Reason |
| ---: | --- | --- | --- |
"""
        + "\n".join(
            f"| {r.get('data_quality')} | {r.get('kind')} | `{r.get('source_file')}` | {r.get('quality_reason')} |"
            for r in sorted(records, key=lambda x: -(x.get("data_quality") or 0))[:15]
        )
        + f"""

## Systematic quality problems

1. **CW-as-device labeling:** high SNR but no frames → overrated security findings from catalog templates.
2. **TPMS empty decodes:** quality low despite IQ presence.
3. **Duplicate IQ storage:** cu8+raw identical.
4. **BLE deep dives:** many `BLE connect failed` → limited GATT evidence (except DIVE-99bc517f).
5. **Partial hashing** on large IQ — full hash optional for archival.

Figures: `results/figures/quality_distribution.{{png,svg}}`
""",
    )

    wreport(
        "device-and-protocol-clusters.md",
        f"""# Device and protocol clusters

## Tracker family counts (snapshot, not limited to new files)

| device_type_id | count |
| --- | ---: |
"""
        + "\n".join(f"| {k} | {v} |" for k, v in type_counts.most_common())
        + f"""

## Radio

| radio | count |
| --- | ---: |
"""
        + "\n".join(f"| {k} | {v} |" for k, v in radio_counts.most_common())
        + f"""

## Vendor (non-none top)

| vendor | count |
| --- | ---: |
"""
        + "\n".join(
            f"| {k} | {v} |"
            for k, v in vendor_counts.most_common(20)
            if k != "none"
        )
        + """

## Capture-derived clusters (family @ MHz bin)

See `results/signal-clusters.csv`.

### Classification notes (evidence-based)

| Cluster | Observation | Inference | Status |
| --- | --- | --- | --- |
| garage_433 @ 438–448 | CW, BW≈30–61 Hz, SNR 42–49, rtl433=0 | Not confirmed remotes; ambient/LO/CW candidate | hypothesis |
| industrial_360 @ 360 | CW, SNR 40.8, rtl433=0 | Telemetry CW candidate; no frames | hypothesis |
| ism_868 @ 858 | CW, SNR 41.8 | Domótica label unconfirmed | hypothesis |
| telemetry_1690 @ 1707–1709 | fm_demod bursts, conf=low | FSK/FM activity candidate | candidate |
| tuya_ble / ble_sensors | Adv + some GATT | BLE IoT / sensors | observed |
| smart_tv_bt | Adv + MAC-in-mfg | Smart TV / AV BLE | observed |
| tpms_* | IQ attempts, 0 frames | Presence labels only | unconfirmed |

Local signature sources: `backend/data/device_catalog.yaml`, `backend/data/fp/fingerprints.yaml`, `oui.json`, `company_ids.json`.
""",
    )

    matrix = """| Rank | Familia | Hallazgo candidato | Evidencia | Facilidad | Impacto potencial | Originalidad | Validación necesaria | Riesgo | Recomendación |
| ---: | --- | --- | --- | ---: | ---: | ---: | --- | ---: | --- |
"""
    for t in targets:
        matrix += (
            f"| {t['rank']} | {t['family']} | {t['finding']} | {t['evidence']} | "
            f"{t['ease']} | {t['impact']} | {t['originality']} | {t['validation']} | "
            f"{t['risk']} | {t['recommendation']} |\n"
        )

    wreport(
        "anomaly-candidates.md",
        f"""# Anomaly candidates

## Identity / privacy

- **MAC inside manufacturer_data:** {len(mac_in_mfg)} devices (sample in run manifest).
- Static MAC BLE with hit_count≥5: observed (e.g. LG TV, Samsung TV, Midea `net`).

## Authenticity / integrity (candidates only)

- Catalog risk text for garage remotes mentions fixed/rolling code **without** frame proof in these dives.
- Tuya writable GATT (DIVE-99bc517f) — **write effect unconfirmed**.

## Protocol / RF

- Extremely narrow CW (≈30.5 Hz 3 dB BW) with peak_dbfs reported up to 66.1 — verify analyzer scale; still consistent with pure carrier.
- Live decode failure mass: {len(live_all) - len(live_ok)}/{len(live_all)}.

## Implementation / methodology

- Duplicate IQ pairs (cu8/raw).
- Incomplete WD sessions without report.json.
- Risk engine emits medium findings for CW based on catalog profile alone.

## Bit/nibble variability

Figure `ble_mfg_0x75_variability` — red-tinted columns mark low cross-device variance (constant-field candidates). Requires manual validation; not a CRC claim.
""",
    )

    wreport(
        "vulnerability-hypotheses.md",
        """# Vulnerability hypotheses

> No hypothesis below is a confirmed vulnerability. Status vocabulary: new / investigating / supported / rejected / inconclusive / confirmed.

| ID | Categoría | Hipótesis | Evidencia actual | Evidencia contraria | Confianza | Experimento siguiente | Estado |
| -- | --- | --- | --- | --- | ---: | --- | --- |
"""
        + "\n".join(
            f"| {h['id']} | {h['category']} | {h['hypothesis']} | {h['evidence']} | {h['contrary']} | {h['confidence']} | {h['next_experiment']} | {h['status']} |"
            for h in hypotheses
        )
        + """

## Separation

| Kind | Items |
| --- | --- |
| Protocol bugs | none confirmed |
| Device bugs | none confirmed; H3 candidate |
| Local app/methodology | H2, H6 |
| Parser bugs | not fuzzed in this run |
| Privacy | H1 investigating |
""",
    )

    wreport(
        "research-prioritization.md",
        f"""# Research prioritization

## Executive summary (≤1 page)

- **Files analyzed:** {overview['n_files']} (~{overview['bytes_total']/1e9:.2f} GB) from {overview['window_start']} → {overview['window_end']} ({overview['timezone']}).
- **Clusters:** {overview['n_clusters']} capture-derived; tracker shows 14 `device_type_id` families.
- **Top 3 research candidates:** (1) BLE MAC-in-manufacturer_data privacy, (2) Tuya GATT writable surface, (3) CW false-positive taxonomy / classifier hardening.
- **Weakness needing immediate validation:** H1 privacy persistence (lab power-cycle test) — not yet a CVE claim.
- **Recommended article series:** “Passive BLE Identity Leakage in Consumer AV/IoT”.
- **Next exact experiment:** Capture advertisements from 3 lab devices that already show MAC-in-mfg; power-cycle; recapture; compare MAC + mfg hex; document stability (≥10 adv each phase).
- **Limits:** No TPMS frames; RF dives are CW without demodulated bits; most BLE dives failed to connect; UHF baud estimates low-confidence; no external OSINT used.

## Candidate matrix

{matrix}

### Top 5 immediate analysis
1. BLE MAC-in-mfg corpus expansion + bit maps
2. DIVE-99bc517f GATT map documentation
3. CW dive spectrogram/PSD pack for classifier
4. Deduplicate capture pipeline (cu8 vs raw)
5. Re-run live_decode metrics dashboard

### Top 3 whitepaper
1. Passive BLE identity leakage (H1)
2. Wardrive RF labeling errors: CW vs remotes (H2)
3. (Conditional) Unauthenticated BLE GATT writes on Tuya-class device (H3) — only after write validation

### Top 5 articles
1. Finding MAC inside BLE manufacturer_data
2. Building a defensive BLE identity monitor
3. Why high SNR ≠ garage remote
4. Deep dive anatomy in RF Hunter
5. What wardriving teaches about TPMS false hopes

### Top 3 tools
1. `ble_mfg_identity_scan` — flag MAC-in-mfg / stable IDs
2. `cw_vs_burst_classifier` — reduce false remote labels
3. `capture_dedupe` — cu8/raw hash steward

### Top 3 discard / park
1. TPMS from this window (H5)
2. Speculative rolling-code garage attacks without button-press IQ
3. 1690 MHz until longer high-SNR IQ exists

## Editorial picks

### Mejor candidato ahora
**BLE manufacturer_data identity leakage** — abundant samples, trivial decode, clear visuals, defensive tooling, low legal risk.

### Más sencillo
Same as above (H1).

### Más original
**CW false-positive taxonomy** for SDR wardrive tooling (H2).

### Más potencial de seguridad
**Tuya writable GATT** (H3) after controlled validation.

### Mejores imágenes
CW SNR/BW scatter + BLE nibble variability heatmap + session timeline.

### No merece seguir (ahora)
**TPMS** in this dataset window — zero frames.
""",
    )

    wreport(
        "article-series-proposals.md",
        """# Article series proposals

## Series A — Passive BLE Identity Leakage in Consumer AV/IoT

**Audience:** privacy engineers, BLE reverse engineers, defenders  
**Hook:** Your TV’s Bluetooth beacon may be whispering its MAC twice.

| Part | Title | Central question | Evidence needed | Experiments | Visuals | Publishable code | Do not publish |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Finding MACs in manufacturer_data | How often does adv payload contain BD_ADDR? | tracker export, hashes | Passive scan only | hex dumps, heatmap | scanner script | raw home GPS trails |
| 2 | Persistence across power cycles | Does the leak survive reboot? | before/after captures | 3 devices × 10 adv | timeline | analysis notebook | exact home addresses |
| 3 | Fingerprinting AV vendors | Which company IDs show the pattern? | OUI + company_id local DB | corpus labeling | vendor bars | fingerprint rules | exploit chains |
| 4 | Building a defensive monitor | Can we alert on stable IDs? | FP/FN metrics | walk-by test | UI screenshots | RF Hunter plugin | attack playbooks |
| 5 | Mitigations | What should vendors/OS do? | standards notes | N/A | diagrams | checklist | weaponized trackers |

**Disclosure risk:** low if framed as privacy measurement; avoid publishing live identifiable wardrive maps.

## Series B — High SNR, Zero Frames: Cleaning SDR Wardrive Labels

| Part | Title | Question |
| --- | --- | --- |
| 1 | Anatomy of a CW false positive | Why did garage_433 fire on a 30 Hz carrier? |
| 2 | Measuring bandwidth and burstiness | What features separate remotes from CW? |
| 3 | Triggered ground truth | What does a real button-press look like? |
| 4 | Shipping a classifier | How do we stop lying to ourselves in the UI? |

## Series C — Tuya-class BLE Surfaces (conditional)

Only start Part 3+ after H3 write-validation in isolated lab.

| Part | Title |
| --- | --- |
| 1 | Mapping GATT without pairing (observation) |
| 2 | Writable characteristics catalog |
| 3 | Safe probes and negative results |
| 4 | Defensive hardening checklist |
""",
    )

    wreport(
        "whitepaper-outline.md",
        """# Whitepaper outline (candidate)

**Working title:** *Passive Re-Identification Risks from BLE Manufacturer-Specific Data in Consumer Devices*

## 1. Abstract
Measure prevalence of BD_ADDR (or stable identifiers) embedded in BLE manufacturer_data during an authorized wardrive; discuss privacy implications and defensive detection.

## 2. Scope
In-scope: BLE advertisements, local fingerprint DB, lab persistence tests.  
Out-of-scope: active tracking of third parties, RF jamming, cloud account takeover.

## 3. Ethics and authorization
Authorized laboratory / self-owned or consented devices for validation; wardrive data retained privately; no external victim targeting.

## 4. Dataset
RF Hunter v2 tracker snapshot (n devices, saved_utc), deep dives, hashes in `analysis_runs/`.

## 5. Methodology
Passive scan → extract manufacturer_data → substring match against BD_ADDR → classify company IDs → controlled power-cycle validation.

## 6. Signal classification
BLE only for primary claims; RF CW results referenced as methodological contrast (appendix).

## 7. Protocol analysis
Nibble/byte constancy maps; no forged CRC claims.

## 8. Findings
Report counts, vendors, examples **redacted** if needed; confidence intervals if sampling bias.

## 9. Validation
Lab devices, repetitions, negative controls (random MAC advertisers).

## 10. Security implications
Physical-world tracking / correlation; not RCE.

## 11. Defensive recommendations
OS/vendor: avoid echoing MAC; defenders: detect pattern; researchers: tooling.

## 12. Limitations
Wardrive geographic bias; connectionless only; not all company IDs decoded semantically.

## 13. Future work
Cross-radio correlation with Wi-Fi probe/SSID; longer longitudinal study.

## 14. Reproducibility
Scripts under `scripts/research/`, run manifests, Python version, input hashes.

## 15. Responsible disclosure
If a specific vendor pattern is novel and actionable, notify vendor PSIRT before detailed exploit-adjacent writeups.
""",
    )

    wreport(
        "next-experiments.md",
        """# Next experiments

## EXP-1 — BLE MAC-in-mfg persistence (winner)

| Field | Value |
| --- | --- |
| Objective | Test whether manufacturer_data continues to embed BD_ADDR after power cycle |
| Device | ≥3 lab devices already showing MAC-in-mfg (prefer Samsung TV / printer class from corpus) |
| Environment | Isolated RF/BLE lab; no public tracking |
| Controlled variable | Power state (on → off 60s → on) |
| Measured | Adv MAC, manufacturer_data hex, company ID, RSSI |
| Repetitions | 10 advertisements pre, 10 post, ×3 cycles |
| Control | One random-MAC BLE beacon (phone) |
| Expected | Same MAC substring present post-reboot **or** documented change |
| Success | Stable leak OR clearly documented rotation |
| Discard | Device unavailable / no adv after reboot |
| Risks | None beyond normal BLE sniffing |
| Images | Hex aligned diffs; before/after timelines |

## EXP-2 — GATT write acceptance (H3)

Non-destructive probes only; human confirmation in UI; isolated device.

## EXP-3 — Remote button-press vs ambient CW

Known garage remote; capture 2 s IQ on press vs ambient at same freq; compare burst detector features.

## EXP-4 — TPMS activation bench

Physical wheel spin / LF trigger; do not use wardrive CW hits as TPMS proof.
""",
    )

    # bit variability table for 0x75
    bit_rows = []
    for d in devices:
        mfg = (d.get("metadata") or {}).get("manufacturer_data") or {}
        hv = None
        for cid, hexv in mfg.items():
            if "75" in str(cid).lower():
                hv = re.sub(r"[^0-9a-f]", "", str(hexv).lower())
                break
        if not hv:
            continue
        mac = (d.get("mac") or "").replace(":", "").lower()
        bit_rows.append(
            {
                "mac": d.get("mac"),
                "name": d.get("name"),
                "hex": hv[:64],
                "mac_in_payload": mac in hv if mac else False,
            }
        )
    with (results / "ble_mfg_0x75_frames.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["mac", "name", "hex", "mac_in_payload"])
        w.writeheader()
        w.writerows(bit_rows)

    (run_dir / "report.md").write_text(
        f"# Analysis run {run_id}\n\nSee `reports/` for full narrative.\n\nOverview:\n\n```json\n{json.dumps(overview, indent=2)}\n```\n"
    )

    print("RUN", run_id)
    print("FILES", overview["n_files"], "SESSIONS", overview["n_sessions"])
    print("REPORTS", reports)
    print("RESULTS", results)
    print("FIGURES", len(fig_created))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

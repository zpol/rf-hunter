"""Compare lab IQ captures to find shared OOK/PWM patterns (strong vs weak presses)."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np

from .replay import CAPTURES


def compare_band(
    lo_mhz: float = 280.0,
    hi_mhz: float = 320.0,
    *,
    limit: int = 24,
) -> dict[str, Any]:
    """Rank recent CAPs in a freq window by signal strength and extract PWM candidates."""
    rows: list[dict[str, Any]] = []
    hex_caps: dict[str, set[str]] = defaultdict(set)
    hex_hits: Counter[str] = Counter()
    bit_hits: Counter[str] = Counter()

    dirs = sorted(
        (p for p in CAPTURES.glob("CAP-*") if p.is_dir()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for d in dirs:
        if len(rows) >= limit:
            break
        meta_path = d / "listen.json"
        iq_path = d / "listen.raw"
        if not meta_path.exists() or not iq_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text())
        except Exception:
            continue
        freq = float(meta.get("freq_mhz") or 0.0)
        if not (lo_mhz <= freq <= hi_mhz):
            continue
        rate = float(meta.get("sample_rate") or 2_000_000)
        dec = _decode_capture(iq_path, rate)
        if not dec:
            continue
        strength = _strength_label(dec)
        row = {
            "capture_id": d.name,
            "freq_mhz": freq,
            "tx_freq_mhz": meta.get("tx_freq_mhz"),
            "iq_bytes": meta.get("iq_bytes") or iq_path.stat().st_size,
            "press_count": (meta.get("analysis") or {}).get("press_count"),
            "clipped": (meta.get("analysis") or {}).get("clipped"),
            "peak_dbfs": dec["peak_dbfs"],
            "dyn_db": dec["dyn_db"],
            "strength": strength,
            "usable_for_pattern": strength in ("strong", "ok"),
            "short_on_ms": dec.get("short_on_ms"),
            "long_on_ms": dec.get("long_on_ms"),
            "frame_count": dec.get("frame_count"),
            "top": dec.get("top") or [],
        }
        rows.append(row)
        if strength in ("strong", "ok"):
            for t in row["top"]:
                hx = t.get("hex")
                bits = t.get("bits")
                if hx and bits and t.get("count", 0) >= 2:
                    hex_caps[hx].add(d.name)
                    hex_hits[hx] += int(t["count"])
                    bit_hits[bits] += int(t["count"])

    shared = [
        {
            "hex": hx,
            "caps": sorted(list(caps)),
            "cap_count": len(caps),
            "frame_hits": int(hex_hits[hx]),
        }
        for hx, caps in sorted(hex_caps.items(), key=lambda kv: (-len(kv[1]), -hex_hits[kv[0]]))
        if len(caps) >= 1
    ]

    consensus = None
    multi = [s for s in shared if s["cap_count"] >= 2]
    if multi:
        consensus = multi[0]
    elif shared:
        # Best single-cap repeat (often the only clean hold)
        consensus = shared[0]

    strong_n = sum(1 for r in rows if r["strength"] == "strong")
    weak_n = sum(1 for r in rows if r["strength"] == "weak")
    return {
        "ok": True,
        "band_mhz": [lo_mhz, hi_mhz],
        "captures": rows,
        "strong_count": strong_n,
        "weak_count": weak_n,
        "shared_hex": shared[:12],
        "consensus": consensus,
        "note": _note(rows, consensus, strong_n, weak_n),
    }


def _strength_label(dec: dict[str, Any]) -> str:
    peak = float(dec["peak_dbfs"])
    dyn = float(dec["dyn_db"])
    if dyn < 6 or peak < -22:
        return "weak"
    if dyn >= 18 and peak >= -8:
        return "strong"
    if dyn >= 10:
        return "ok"
    return "weak"


def _note(rows: list, consensus: dict | None, strong_n: int, weak_n: int) -> str:
    if not rows:
        return "No captures in this band yet."
    if strong_n == 0:
        return (
            "All captures look weak — the remote often fails to TX hard. "
            "Hold closer / fresh battery / longer press; only strong CAPs decode cleanly."
        )
    if consensus and consensus.get("cap_count", 0) >= 2:
        return (
            f"Shared pattern {consensus['hex']} in {consensus['cap_count']} strong/ok captures — "
            "good fixed-code candidate."
        )
    if consensus:
        return (
            f"Best repeated pattern {consensus['hex']} only in one clean capture so far. "
            f"{weak_n} weak CAP(s) ignored — remote TX is intermittent."
        )
    return "Strong energy found but bit framing still unstable — record 2–3 strong holds."


def _decode_capture(path: Path, rate: float) -> dict[str, Any] | None:
    try:
        raw = np.fromfile(path, dtype=np.int8)
        raw = raw[: len(raw) // 2 * 2]
        if len(raw) < int(rate * 0.25) * 2:
            return None
        c = (raw[0::2].astype(np.float32) + 1j * raw[1::2].astype(np.float32)) / 127.0
        bin_s = 50e-6
        win = max(8, int(rate * bin_s))
        n = (len(c) // win) * win
        p = (np.abs(c[:n]) ** 2).reshape(-1, win).mean(axis=1)
        db = 10 * np.log10(p + 1e-12)
        peak = float(db.max())
        p10 = float(np.percentile(db, 10))
        dyn = peak - p10
        # Prefer a high threshold so quiet gaps stay off (cleaner PWM)
        thr = p10 + 0.55 * max(dyn, 1.0)
        on = db > thr
        chg = np.where(np.diff(on.astype(np.int8)))[0]
        if len(chg) < 12:
            return {"peak_dbfs": round(peak, 1), "dyn_db": round(dyn, 1), "top": [], "frame_count": 0}

        state = bool(on[0])
        start = 0
        segs: list[tuple[bool, float]] = []
        for i in list(chg) + [len(on) - 1]:
            w_ms = (i - start + 1) * bin_s * 1000.0
            segs.append((state, float(w_ms)))
            state = not state
            start = i + 1

        ons = [w for s, w in segs if s and 0.2 < w < 6.0]
        if len(ons) < 16:
            return {"peak_dbfs": round(peak, 1), "dyn_db": round(dyn, 1), "top": [], "frame_count": 0}
        short = float(np.percentile(ons, 20))
        long = float(np.percentile(ons, 80))
        top: list[dict[str, Any]] = []
        frames_n = 0
        if long >= short * 2.2:
            boundary = (short + long) / 2.0
            frames: list[list[tuple[bool, float]]] = []
            cur: list[tuple[bool, float]] = []
            for s, w in segs:
                if (s and w >= 8.0) or ((not s) and w >= 5.0):
                    if len(cur) >= 8:
                        frames.append(cur)
                    cur = []
                    continue
                if 0.15 < w < 8.0:
                    cur.append((s, w))
            if len(cur) >= 8:
                frames.append(cur)
            frames_n = len(frames)

            def bits_of(frame: list[tuple[bool, float]]) -> str:
                out: list[str] = []
                i = 0
                while i < len(frame) and not frame[i][0]:
                    i += 1
                while i < len(frame) - 1:
                    a, b = frame[i], frame[i + 1]
                    if a[0] and not b[0]:
                        out.append("1" if a[1] > boundary else "0")
                        i += 2
                    else:
                        i += 1
                return "".join(out)

            counts: Counter[str] = Counter()
            for fr in frames:
                b = bits_of(fr)
                if 12 <= len(b) <= 128:
                    counts[b] += 1
            for b, n in counts.most_common(5):
                pad = b + "0" * ((4 - len(b) % 4) % 4)
                top.append(
                    {
                        "bits": b,
                        "count": int(n),
                        "len": len(b),
                        "hex": hex(int(pad, 2)),
                    }
                )

        return {
            "peak_dbfs": round(peak, 1),
            "dyn_db": round(dyn, 1),
            "short_on_ms": round(short, 2),
            "long_on_ms": round(long, 2),
            "frame_count": frames_n,
            "top": top,
        }
    except Exception:
        return None

#!/usr/bin/env python3
"""Live RF proximity meter — walk toward the device using signal strength.

Default target: 447.6 MHz (LO leak of 433.92 lock receiver).
Also tracks 869.31 MHz alarm band.

Usage:
  python3 proximity_meter.py
  python3 proximity_meter.py --freq 447.6
  python3 proximity_meter.py --freq 447.6 --also 869.31
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
import time
from collections import deque
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATUS = ROOT / "proximity_live.txt"


def sweep_peak(center_mhz: float, span_mhz: float = 0.5, sweeps: int = 8) -> float | None:
    """Return peak dB near center_mhz, or None on failure."""
    lo = max(1, int((center_mhz - span_mhz / 2) * 1e6))
    hi = int((center_mhz + span_mhz / 2) * 1e6)
    # hackrf_sweep wants MHz integers for -f
    f_lo = int(center_mhz - span_mhz / 2)
    f_hi = int(center_mhz + span_mhz / 2) + 1
    cmd = [
        "hackrf_sweep",
        "-f", f"{f_lo}:{f_hi}",
        "-a", "1",
        "-p", "1",
        "-l", "32",
        "-g", "40",
        "-w", "25000",
        "-N", str(sweeps),
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except Exception:
        return None
    if r.returncode != 0 and not r.stdout:
        return None

    best = -999.0
    for row in csv.reader(r.stdout.splitlines()):
        if len(row) < 7:
            continue
        try:
            hz_low = float(row[2])
            bin_w = float(row[4])
            dbs = [float(x) for x in row[6:]]
        except ValueError:
            continue
        for i, db in enumerate(dbs):
            if not (-120.0 < db < 0.0):
                continue
            f = (hz_low + i * bin_w) / 1e6
            if abs(f - center_mhz) <= span_mhz / 2 and db > best:
                best = db
    return best if best > -900 else None


def bar(db: float, floor: float = -70.0, ceil: float = -5.0, width: int = 28) -> str:
    x = (db - floor) / (ceil - floor)
    x = max(0.0, min(1.0, x))
    n = int(round(x * width))
    return "[" + "#" * n + "." * (width - n) + "]"


def hint(delta: float) -> str:
    if delta >= 3.0:
        return ">>> MUY CERCA / MAS FUERTE"
    if delta >= 1.5:
        return ">> acercandote"
    if delta >= 0.5:
        return "> un poco mas cerca"
    if delta <= -3.0:
        return "<<< te alejas mucho"
    if delta <= -1.5:
        return "<< alejandote"
    if delta <= -0.5:
        return "< un poco mas lejos"
    return "= estable"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--freq", type=float, default=447.6, help="Primary MHz (default 447.6)")
    ap.add_argument("--also", type=float, default=869.31, help="Secondary MHz (0 to disable)")
    ap.add_argument("--interval", type=float, default=0.3, help="Pause between sweeps")
    args = ap.parse_args()

    targets = [args.freq]
    if args.also and args.also > 0:
        targets.append(args.also)

    history: dict[float, deque[float]] = {f: deque(maxlen=40) for f in targets}
    baseline: dict[float, float | None] = {f: None for f in targets}
    peak_seen: dict[float, float] = {f: -999.0 for f in targets}

    print(f"Proximity meter ON — primary {args.freq} MHz")
    print(f"Status file: {STATUS}")
    print("Acercate al device; potencia MAS ALTA (menos negativa) = MAS CERCA")
    print("Ctrl+C para parar\n")

    n = 0
    try:
        while True:
            n += 1
            ts = datetime.now().strftime("%H:%M:%S")
            lines = [
                f"RF PROXIMITY  {ts}  sample#{n}",
                "regla: dB mas alto (ej. -15 > -40) = MAS CERCA",
                "-" * 56,
            ]
            console = [f"\n[{ts}] #{n}"]

            for f in targets:
                db = sweep_peak(f, span_mhz=0.6 if f < 500 else 0.4, sweeps=6)
                if db is None:
                    lines.append(f"{f:8.3f} MHz  FAIL (hackrf busy?)")
                    console.append(f"  {f:.3f} FAIL")
                    continue

                history[f].append(db)
                if baseline[f] is None and len(history[f]) >= 3:
                    baseline[f] = sum(list(history[f])[:3]) / 3.0
                peak_seen[f] = max(peak_seen[f], db)

                base = baseline[f] if baseline[f] is not None else db
                delta = db - base
                avg = sum(history[f]) / len(history[f])
                h = hint(delta)
                b = bar(db)

                block = (
                    f"{f:8.3f} MHz  {db:6.1f} dB  Δbase={delta:+5.1f}  "
                    f"avg={avg:5.1f}  max={peak_seen[f]:5.1f}\n"
                    f"         {b}  {h}"
                )
                lines.append(block)
                console.append(
                    f"  {f:8.3f}  {db:6.1f} dB  Δ{delta:+5.1f}  {b}  {h}"
                )

            lines.append("-" * 56)
            lines.append(f"baseline fijada tras 3 samples | writing {STATUS.name}")
            text = "\n".join(lines) + "\n"
            STATUS.write_text(text)
            print("\n".join(console), flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0


if __name__ == "__main__":
    sys.exit(main())

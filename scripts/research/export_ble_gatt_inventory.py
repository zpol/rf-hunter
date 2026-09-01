#!/usr/bin/env python3
"""Export BLE GATT writable inventory from deep_dive.json captures."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def _ble_block(dive: dict) -> dict:
    analysis = dive.get("analysis") or {}
    return analysis.get("ble") or dive.get("ble") or {}


def iter_writables(captures: Path):
    for path in sorted(captures.glob("DIVE-*/deep_dive.json")):
        try:
            dive = json.loads(path.read_text())
        except Exception:
            continue
        ble = _ble_block(dive)
        if not ble:
            continue
        target = dive.get("target") or {}
        mac = ble.get("mac") or target.get("mac") or ""
        risk = (dive.get("analysis") or {}).get("risk") or dive.get("risk") or {}
        for svc in ble.get("services") or []:
            su = svc.get("uuid") or ""
            for char in svc.get("characteristics") or []:
                props = [str(p).lower() for p in (char.get("properties") or [])]
                if not any("write" in p for p in props):
                    continue
                yield {
                    "dive_id": path.parent.name,
                    "mac": mac,
                    "adv_name": target.get("name") or "",
                    "device_type_id": target.get("device_type_id") or "",
                    "attack_profile": (target.get("metadata") or {}).get("attack_profile")
                    or "",
                    "connected": bool(ble.get("connected")),
                    "severity": risk.get("severity") or risk.get("status") or "",
                    "service_uuid": su,
                    "char_uuid": char.get("uuid") or "",
                    "properties": "|".join(props),
                    "value_hex": char.get("value_hex") or "",
                }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--captures",
        type=Path,
        default=Path(__file__).resolve().parents[3] / "captures" / "rf-hunter-v2",
    )
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "results" / "ble_gatt_writable.csv",
    )
    args = ap.parse_args()

    rows = list(iter_writables(args.captures))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "dive_id",
        "mac",
        "adv_name",
        "device_type_id",
        "attack_profile",
        "connected",
        "severity",
        "service_uuid",
        "char_uuid",
        "properties",
        "value_hex",
    ]
    with args.output.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    by_dive: dict[str, int] = {}
    for r in rows:
        by_dive[r["dive_id"]] = by_dive.get(r["dive_id"], 0) + 1
    print(f"wrote {len(rows)} writable rows → {args.output}")
    for dive_id, n in sorted(by_dive.items(), key=lambda x: -x[1]):
        print(f"  {dive_id}: {n}")


if __name__ == "__main__":
    main()

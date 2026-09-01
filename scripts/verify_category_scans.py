#!/usr/bin/env python3
"""Run short once-scans per catalog category and assert type isolation.

Usage (API must be up, HackRF free):
  ../.venv/bin/python scripts/verify_category_scans.py
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8081"

# Skip ultra-long / always-on radios in this smoke pass
SKIP_TYPES = {"full_spectrum"}  # 1–6 GHz survey — too slow for isolation smoke


def api(method: str, path: str, body: dict | None = None, timeout: float = 120) -> dict:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def wait_scan_done(timeout_s: float = 180) -> dict:
    t0 = time.time()
    last = {}
    while time.time() - t0 < timeout_s:
        last = api("GET", "/api/scan/status")
        st = last.get("status")
        if st in ("completed", "stopped", "idle", "error"):
            return last
        time.sleep(1.2)
    return last


def main() -> int:
    health = api("GET", "/api/health")
    if not health.get("hackrf"):
        print("FAIL: HackRF not available")
        return 2

    cat = api("GET", "/api/catalog")
    types = cat.get("device_types") or []
    categories = cat.get("categories") or []
    by_cat: dict[str, list[dict]] = defaultdict(list)
    for t in types:
        if t["id"] in SKIP_TYPES:
            continue
        # Prefer HackRF presence types for RF isolation; keep BLE in iot
        by_cat[t.get("category") or "?"].append(t)

    print(f"== Category isolation smoke @ {BASE} ==")
    print(f"hackrf={health.get('hackrf')} wifi={health.get('wifi', {}).get('status')}")

    failures: list[str] = []
    results: list[tuple[str, list[str], set[str], int]] = []

    for c in categories:
        cid = c["id"]
        group = by_cat.get(cid) or []
        if not group:
            print(f"[{cid}] SKIP (no types after filters)")
            continue

        # One representative RF type + at most one BLE if present (faster, still checks mix)
        hackrf = [t for t in group if t.get("radio") == "hackrf"]
        ble = [t for t in group if t.get("radio") == "ble"]
        pick = (hackrf[:1] or group[:1]) + ble[:1]
        ids = [t["id"] for t in pick]
        allowed = set(ids)

        print(f"\n[{cid}] clear + once scan → {ids}")
        api("POST", "/api/tracker/clear")
        # Stop wifi so live APs don't confuse humans; isolation is frontend+tracker
        try:
            api("POST", "/api/wifi/stop")
        except Exception:
            pass

        start = api(
            "POST",
            "/api/scan/start",
            {
                "device_type_ids": ids,
                "duration_s": 12,
                "lna_db": 32,
                "vga_db": 36,
                "passes": 3,
                "mode": "once",
                "live_decode": False,
                "clear_results": True,
            },
            timeout=30,
        )
        if not start.get("ok"):
            failures.append(f"{cid}: start failed {start}")
            print(f"  START FAIL {start}")
            continue

        status = wait_scan_done(210)
        print(f"  status={status.get('status')} progress={status.get('progress')} msg={status.get('message')}")

        snap = api("GET", "/api/devices") if False else None
        # Prefer tracker export
        try:
            export = api("GET", "/api/export/devices.json")
            devices = export.get("devices") or []
        except Exception:
            st = api("GET", "/api/scan/status")
            devices = st.get("devices") or []

        found_types = {d.get("device_type_id") for d in devices if d.get("device_type_id")}
        wifi_leaks = [d for d in devices if (d.get("radio") or "").lower() == "wifi" or d.get("device_type_id") == "wifi_ap"]
        foreign = found_types - allowed

        results.append((cid, ids, found_types, len(devices)))

        if wifi_leaks:
            failures.append(f"{cid}: wifi rows in tracker ({len(wifi_leaks)})")
            print(f"  FAIL wifi leak: {wifi_leaks[:2]}")
        if foreign:
            failures.append(f"{cid}: foreign types {sorted(foreign)} (allowed {sorted(allowed)})")
            print(f"  FAIL foreign types {sorted(foreign)}")
        else:
            print(f"  OK types={sorted(found_types) or '∅'} n={len(devices)}")

        # Ensure keys don't collide across types at same freq
        keys = [d.get("key") for d in devices if d.get("key")]
        if len(keys) != len(set(keys)):
            failures.append(f"{cid}: duplicate keys")
            print("  FAIL duplicate keys")

        api("POST", "/api/scan/stop")
        time.sleep(0.5)

    print("\n== Summary ==")
    for cid, ids, found, n in results:
        print(f"  {cid:12} scanned={ids} → found={sorted(found) or []} ({n})")

    if failures:
        print("\nISOLATION FAILURES:")
        for f in failures:
            print(" -", f)
        return 1
    print("\nALL CATEGORY SCANS ISOLATED (no foreign types / no wifi in tracker)")
    return 0


if __name__ == "__main__":
    # devices endpoint may not exist — fix export path
    try:
        sys.exit(main())
    except urllib.error.URLError as e:
        print("API error:", e)
        sys.exit(2)

"""Correlate Wi-Fi APs with RF/BLE devices (identity + RSSI; historical GPS pins)."""

from __future__ import annotations

import math
import re
import time
from typing import Any

from . import fingerprint as fp_mod


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _norm(s: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


_SSID_VENDOR_HINTS = [
    (r"(?i)tuya|smartlife|smart[_-]?life", "Tuya"),
    (r"(?i)samsung|smarttv|\[tv\]", "Samsung"),
    (r"(?i)\bjbl\b|harman", "Harman / JBL"),
    (r"(?i)xiaomi|miot|xiaoyi|yeelight", "Xiaomi"),
    (r"(?i)espressif|esp[_-]?_", "Espressif"),
    (r"(?i)google|nest|chromecast", "Google"),
    (r"(?i)\bairport\b|macbook", "Apple"),
    (r"(?i)byd", "BYD"),
    (r"(?i)tp[_-]?link|tplink", "TP-Link"),
    (r"(?i)huawei|honor", "Huawei"),
]


def ssid_vendor_guess(ssid: str | None) -> str | None:
    for pat, vendor in _SSID_VENDOR_HINTS:
        if re.search(pat, ssid or ""):
            return vendor
    return None


def _is_hotspot_ssid(ssid: str | None) -> bool:
    s = (ssid or "").lower()
    if not s.strip():
        return True  # hidden — weak for identity
    return any(x in s for x in ("iphone", "android", "galaxy", "pixel", "'s ", "’s ", "hotspot"))


def _device_point(d: dict[str, Any]) -> tuple[float, float] | None:
    # Prefer first_* (wardrive breadcrumb) over last (often = hunter stamp)
    for lat_k, lon_k in (("first_lat", "first_lon"), ("lat", "lon")):
        if d.get(lat_k) is not None and d.get(lon_k) is not None:
            try:
                return float(d[lat_k]), float(d[lon_k])
            except (TypeError, ValueError):
                pass
    return None


def _vendor_tokens(device: dict[str, Any]) -> set[str]:
    """Brand/identity tokens only — skip chip OUI when it conflicts with vendor."""
    meta = device.get("metadata") or {}
    fp = meta.get("fingerprint") or {}
    brand = device.get("vendor") or fp.get("vendor")
    brand_n = _norm(brand)
    parts = [
        brand,
        device.get("name"),
        fp.get("family"),
    ]
    for cn in fp.get("company_names") or []:
        parts.append(cn)
    # Chip OUI (e.g. TI silicon in Apple Continuity) is only useful when
    # we have no stronger brand identity yet.
    oui = fp.get("oui_vendor") or meta.get("oui_hint")
    if oui and (not brand_n or _norm(oui) == brand_n or brand_n in _norm(oui) or _norm(oui) in brand_n):
        parts.append(oui)
    toks = set()
    for p in parts:
        n = _norm(str(p) if p else "")
        if len(n) >= 3:
            toks.add(n)
            if len(n) > 8:
                toks.add(n[:6])
    return toks


def score_ap_for_device(
    device: dict[str, Any],
    ap: dict[str, Any],
    *,
    max_m: float = 120.0,
    hunter: dict[str, Any] | None = None,
) -> tuple[float, list[str]]:
    """
    Wi-Fi APs are stamped with hunter GPS at scan time — so 'distance to hunter'
    is meaningless for live correlation. Score by vendor/SSID/RSSI; use GPS only
    when both sides have distinct historical pins (>5 m apart).
    """
    _ = hunter  # reserved
    reasons: list[str] = []
    score = 0.0

    dp = _device_point(device)
    ap_lat = ap.get("first_lat", ap.get("lat"))
    ap_lon = ap.get("first_lon", ap.get("lon"))
    dist = None
    geo_ok = False
    if dp and ap_lat is not None and ap_lon is not None:
        dist = _haversine_m(dp[0], dp[1], float(ap_lat), float(ap_lon))
        # Ignore collapsed hunter stamps (~0 m)
        if 5.0 < dist <= max_m:
            geo_ok = True
            score += max(0.0, 35.0 * (1.0 - dist / max_m))
            reasons.append(f"{dist:.0f}m")
        elif max_m < dist <= max_m * 2.5:
            geo_ok = True
            score += max(0.0, 10.0 * (1.0 - dist / (max_m * 2.5)))
            reasons.append(f"{dist:.0f}m~")

    dv = _vendor_tokens(device)
    ap_vendor = ap.get("vendor") or ssid_vendor_guess(ap.get("ssid"))
    ap_tok = _norm(ap_vendor)
    ssid_tok = _norm(ap.get("ssid"))
    vendor_hit = False
    name_hit = False

    if ap_tok and len(ap_tok) >= 5:
        for t in dv:
            if len(t) < 5:
                continue
            if ap_tok == t or (len(t) >= 6 and (ap_tok.startswith(t) or t.startswith(ap_tok))):
                score += 35.0
                vendor_hit = True
                reasons.append(f"vendor={ap_vendor}")
                break

    name = _norm(device.get("name") or device.get("model_guess") or "")
    if name and len(name) >= 4 and ssid_tok and (name in ssid_tok or ssid_tok in name):
        score += 32.0
        vendor_hit = True
        name_hit = True
        reasons.append("ssid≈name")

    sg = ssid_vendor_guess(ap.get("ssid"))
    if sg and _norm(sg) and any(_norm(sg) in t or t in _norm(sg) for t in dv):
        score += 22.0
        vendor_hit = True
        reasons.append(f"ssid→{sg}")

    rssi_hit = False
    if (device.get("radio") or "").lower() == "ble" and device.get("rssi_dbm") is not None:
        br = float(device["rssi_dbm"])
        ar = float(ap.get("signal_dbm") or -999)
        if br > -65 and ar > -55:
            score += 16.0
            rssi_hit = True
            reasons.append("rssi-copresent")
        elif br > -72 and ar > -65:
            score += 6.0
            reasons.append("rssi-weak")

    hotspotish = _is_hotspot_ssid(ap.get("ssid"))

    # Decision
    if name_hit:
        pass
    elif vendor_hit and geo_ok:
        pass
    elif vendor_hit and not hotspotish:
        reasons.append("identity")
    elif vendor_hit and hotspotish and name_hit:
        pass
    elif vendor_hit and hotspotish:
        return 0.0, []
    elif geo_ok and rssi_hit and not hotspotish:
        reasons.append("geo+rssi")
    elif rssi_hit and not hotspotish and (ap.get("ssid") or "").strip() and score >= 22:
        reasons.append("rssi-named")
    else:
        return 0.0, []

    if score < 22:
        return 0.0, []
    return score, reasons


def correlate_device(
    device: dict[str, Any],
    aps: list[dict[str, Any]],
    *,
    max_m: float = 120.0,
    max_age_s: float = 180.0,
    limit: int = 6,
    hunter: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    from . import gps as gps_mod

    if hunter is None:
        try:
            hunter = gps_mod.gps.current()
        except Exception:
            hunter = None

    now = time.time()
    scored: list[tuple[float, dict[str, Any]]] = []
    for ap in aps:
        age = now - float(ap.get("last_seen_ts") or 0)
        if age > max_age_s:
            continue
        score, reasons = score_ap_for_device(device, ap, max_m=max_m, hunter=hunter)
        if score < 22:
            continue
        dist = None
        dp = _device_point(device)
        ap_lat = ap.get("first_lat", ap.get("lat"))
        ap_lon = ap.get("first_lon", ap.get("lon"))
        if dp and ap_lat is not None and ap_lon is not None:
            try:
                dist = round(_haversine_m(dp[0], dp[1], float(ap_lat), float(ap_lon)), 1)
            except (TypeError, ValueError):
                dist = None
        scored.append((
            score,
            {
                "bssid": ap.get("bssid"),
                "ssid": ap.get("ssid") or "(hidden)",
                "vendor": ap.get("vendor") or ssid_vendor_guess(ap.get("ssid")),
                "signal_dbm": ap.get("signal_dbm"),
                "channel": ap.get("channel"),
                "freq_mhz": ap.get("freq_mhz"),
                "security": ap.get("security"),
                "dist_m": dist,
                "score": round(score, 1),
                "reasons": reasons,
                "lat": ap.get("first_lat") or ap.get("lat"),
                "lon": ap.get("first_lon") or ap.get("lon"),
            },
        ))
    scored.sort(key=lambda x: -x[0])
    return [row for _, row in scored[:limit]]


def enrich_with_wifi(device: dict[str, Any], aps: list[dict[str, Any]]) -> dict[str, Any]:
    out = dict(device)
    nearby = correlate_device(out, aps)
    out["wifi_nearby"] = nearby
    if nearby:
        meta = dict(out.get("metadata") or {})
        meta["wifi_nearby"] = nearby
        top = nearby[0]
        # Only boost BLE identity from a non-hotspot AP
        if (
            (out.get("radio") or "").lower() == "ble"
            and not out.get("vendor")
            and top.get("vendor")
            and not _is_hotspot_ssid(top.get("ssid"))
        ):
            out["vendor"] = top["vendor"]
            fp = dict(meta.get("fingerprint") or {})
            fp["vendor"] = fp.get("vendor") or top["vendor"]
            fp["wifi_boost"] = top.get("ssid")
            meta["fingerprint"] = fp
        out["metadata"] = meta
    return out


def enrich_device_full(device: dict[str, Any], aps: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Fingerprint + Wi-Fi correlation for API/UI."""
    out = fp_mod.enrich_device(device)
    if aps is not None:
        out = enrich_with_wifi(out, aps)
    return out

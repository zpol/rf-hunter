"""Wi-Fi Attack assessment — catalog-driven findings (no active exploits)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from . import wifi_backend
from . import wifi_scanner

CATALOG_PATH = Path(__file__).resolve().parents[1] / "data" / "wifi_attacks.yaml"

_PRED_ALIASES = {
    "open": "open",
    "wep": "wep",
    "wpa1_or_tkip": "wpa1_or_tkip",
    "wps": "wps",
    "psk": "psk",
    "any_infra": "any_infra",
    "hidden_ssid": "hidden_ssid",
    "wpa2_family": "wpa2_family",
    "sae": "sae",
    "wpa3_transition": "wpa3_transition",
    "no_pmf": "no_pmf",
    "mixed_wpa": "mixed_wpa",
    "known_vendor": "known_vendor",
    "band_24": "band_24",
    "band_5": "band_5",
    "he": "he",
}


@lru_cache(maxsize=1)
def load_catalog() -> list[dict[str, Any]]:
    raw = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8")) or {}
    techniques = raw.get("techniques") or []
    return list(techniques)


def build_facts(ap: dict[str, Any]) -> dict[str, bool]:
    """Boolean predicates used by catalog applies_when."""
    ies = ap.get("wifi_ies") or {}
    family = (ap.get("security_family") or "").lower()
    sec = (ap.get("security") or "").lower()
    freq = ap.get("freq_mhz")
    try:
        freq_f = float(freq) if freq is not None else None
    except (TypeError, ValueError):
        freq_f = None

    open_net = family == "open" or sec == "open"
    wep = family == "wep" or bool(ies.get("wep"))
    wpa1 = family == "wpa" or bool(ies.get("wpa")) and not ies.get("rsn")
    tkip = bool(ies.get("tkip"))
    sae = bool(ies.get("sae"))
    psk = bool(ies.get("psk")) or family in ("wpa", "wpa2", "mixed")
    rsn = bool(ies.get("rsn")) or family in ("wpa2", "wpa3", "mixed")
    pmf = ies.get("pmf")
    hidden = bool(ap.get("hidden_ssid")) or not (ap.get("ssid") or "").strip()

    return {
        "open": open_net,
        "wep": wep,
        "wpa1_or_tkip": wpa1 or tkip,
        "wps": bool(ap.get("wps") or ies.get("wps")),
        "psk": psk and not open_net and not wep,
        "any_infra": True,
        "hidden_ssid": hidden,
        "wpa2_family": family in ("wpa2", "mixed") or (rsn and not sae),
        "sae": sae,
        "wpa3_transition": family == "mixed" or (sae and psk),
        "no_pmf": (not open_net) and (pmf is False or pmf is None),
        "mixed_wpa": family == "mixed" or (bool(ies.get("wpa")) and bool(ies.get("rsn"))),
        "known_vendor": bool(ap.get("vendor")),
        "band_24": freq_f is not None and 2400 <= freq_f <= 2500,
        "band_5": freq_f is not None and 5000 <= freq_f <= 5900,
        "he": bool(ies.get("he")),
    }


def _resolve_ap(device: dict[str, Any]) -> dict[str, Any]:
    """Merge live scanner AP (if any) with device/metadata from UI."""
    meta = device.get("metadata") or {}
    bssid = (device.get("mac") or "").upper()
    key = device.get("key") or ""
    live = wifi_scanner.wifi.get_ap(bssid or key) or {}
    ap = {
        **live,
        "bssid": live.get("bssid") or bssid,
        "ssid": live.get("ssid") if live.get("ssid") is not None else (device.get("name") or ""),
        "signal_dbm": live.get("signal_dbm", device.get("rssi_dbm")),
        "freq_mhz": live.get("freq_mhz", device.get("freq_mhz")),
        "channel": live.get("channel", meta.get("channel")),
        "security": live.get("security") or meta.get("security") or "unknown",
        "security_family": live.get("security_family") or meta.get("security_family"),
        "vendor": live.get("vendor") or device.get("vendor"),
        "wifi_ies": live.get("wifi_ies") or meta.get("wifi_ies") or {},
        "wps": live.get("wps", meta.get("wps")),
        "pmf": live.get("pmf", meta.get("pmf")),
        "hidden_ssid": live.get("hidden_ssid", meta.get("hidden_ssid")),
    }
    # If UI name is "(hidden Wi‑Fi)", treat as hidden
    name = (device.get("name") or "").strip()
    if name.startswith("(hidden"):
        ap["ssid"] = ""
        ap["hidden_ssid"] = True
    if not ap.get("security_family"):
        # Derive coarse family from security string
        s = (ap.get("security") or "").lower()
        if "wep" in s:
            ap["security_family"] = "wep"
        elif "wpa3" in s or "owe" in s:
            ap["security_family"] = "wpa3"
        elif "wpa2" in s or "wpa2/3" in s:
            ap["security_family"] = "wpa2"
        elif s == "wpa" or s.startswith("wpa "):
            ap["security_family"] = "wpa"
        elif s == "open":
            ap["security_family"] = "open"
        else:
            ap["security_family"] = "unknown"
    return ap


def assess_ap(device: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Return attack-report vectors for a Wi-Fi AP device.
    Assessment only — does not run active attacks or Pineapple actions.
    """
    ap = _resolve_ap(device)
    facts = build_facts(ap)
    hw = wifi_backend.wifi_hardware.status()
    vectors: list[dict[str, Any]] = []

    # Inventory vector always first
    vectors.append({
        "name": "wifi_inventory",
        "success": True,
        "severity": "info",
        "finding": f"Wi‑Fi AP · {ap.get('ssid') or '(hidden)'} · {ap.get('security')}",
        "detail": "Passive assessment from scan facts (no active exploit executed)",
        "evidence": [
            f"bssid={ap.get('bssid')}",
            f"security={ap.get('security')}",
            f"family={ap.get('security_family')}",
            f"channel={ap.get('channel')}",
            f"vendor={ap.get('vendor') or '—'}",
            f"signal={ap.get('signal_dbm')} dBm",
        ],
        "era": "modern",
        "category": "config",
        "remediation": "Use this inventory baseline in the client report.",
        "wow": False,
    })

    for tech in load_catalog():
        preds = tech.get("applies_when") or []
        if not preds:
            continue
        if not all(facts.get(_PRED_ALIASES.get(p, p), False) for p in preds):
            continue
        needs_hw = tech.get("hardware")
        evidence = [
            f"technique={tech.get('id')}",
            f"era={tech.get('era')}",
            f"category={tech.get('category')}",
        ]
        for p in preds:
            evidence.append(f"fact.{p}=true")
        detail = tech.get("summary") or ""
        if needs_hw:
            detail = (
                f"{detail} — Requires lab hardware ({needs_hw}); "
                f"not executed ({hw.get('message')})"
            )
            evidence.append(f"hardware={needs_hw}:not_executed")
        for ref in (tech.get("references") or [])[:4]:
            evidence.append(f"ref={ref}")

        vectors.append({
            "name": tech.get("id") or tech.get("name"),
            "success": True,
            "severity": tech.get("severity") or "medium",
            "finding": tech.get("name"),
            "detail": detail,
            "evidence": evidence,
            "era": tech.get("era"),
            "category": tech.get("category"),
            "client_impact": tech.get("client_impact"),
            "remediation": tech.get("remediation"),
            "references": tech.get("references") or [],
            "demo_note": tech.get("demo_note"),
            "hardware": needs_hw,
            "executed": False,
            "wow": (tech.get("severity") in ("critical", "high")) or bool(tech.get("demo_note")),
        })

    return vectors

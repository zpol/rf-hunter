"""Device fingerprinting — OUI + Bluetooth Company ID + rule DB (nmap-style)."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_FP_DIR = Path(__file__).resolve().parents[1] / "data" / "fp"


@lru_cache(maxsize=1)
def _oui_table() -> dict[str, str]:
    path = _FP_DIR / "oui.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


@lru_cache(maxsize=1)
def _company_table() -> dict[int, str]:
    path = _FP_DIR / "company_ids.json"
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict[int, str] = {}
    if isinstance(raw, list):
        for row in raw:
            try:
                out[int(row["code"])] = str(row["name"])
            except (KeyError, TypeError, ValueError):
                continue
    elif isinstance(raw, dict):
        for k, v in raw.items():
            try:
                out[int(k, 0) if isinstance(k, str) else int(k)] = str(v)
            except (TypeError, ValueError):
                continue
    return out


@lru_cache(maxsize=1)
def _rules() -> list[dict[str, Any]]:
    path = _FP_DIR / "fingerprints.yaml"
    if not path.is_file():
        return []
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return []
    rules = data.get("rules") or []
    rules.sort(key=lambda r: -int(r.get("priority") or 0))
    return rules


def lookup_oui(mac: str | None) -> str | None:
    if not mac:
        return None
    compact = mac.upper().replace(":", "").replace("-", "")
    if len(compact) < 6:
        return None
    return _oui_table().get(compact[:6])


def mac_is_random(mac: str | None) -> bool:
    if not mac:
        return False
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0x02)


def _parse_company_ids(meta: dict[str, Any]) -> list[int]:
    ids: list[int] = []
    mfg = meta.get("manufacturer_data") or {}
    for k in mfg:
        try:
            ids.append(int(str(k), 0))
        except ValueError:
            continue
    # Also accept explicit list
    for k in meta.get("company_ids") or []:
        try:
            ids.append(int(k, 0) if isinstance(k, str) else int(k))
        except (TypeError, ValueError):
            continue
    # dedupe preserve order
    seen: set[int] = set()
    out: list[int] = []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def _uuid_blob(meta: dict[str, Any]) -> str:
    parts = []
    for u in meta.get("service_uuids") or []:
        parts.append(str(u).lower())
    for k in meta.get("service_data") or {}:
        parts.append(str(k).lower())
    return " ".join(parts)


def _rule_matches(rule: dict[str, Any], *, name: str, meta: dict[str, Any], oui_vendor: str | None) -> bool:
    m = rule.get("match") or {}
    if not m:
        return False

    cids = _parse_company_ids(meta)
    if "company_id_any" in m:
        want = {int(x, 0) if isinstance(x, str) else int(x) for x in m["company_id_any"]}
        if not want.intersection(cids):
            return False

    if "service_uuid_contains_any" in m:
        blob = _uuid_blob(meta)
        needles = [str(x).lower() for x in m["service_uuid_contains_any"]]
        if not any(n in blob for n in needles):
            return False

    if "name_regex" in m:
        try:
            if not re.search(m["name_regex"], name or ""):
                return False
        except re.error:
            return False

    if "oui_vendor_regex" in m:
        try:
            if not re.search(m["oui_vendor_regex"], oui_vendor or ""):
                return False
        except re.error:
            return False

    return True


def _model_from_name(name: str) -> str | None:
    n = (name or "").strip()
    if not n or n in ("(anonymous)", "(unknown)", "TY", "TUYA_"):
        return None
    # Strip common noise prefixes
    n = re.sub(r"^\[TV\]\s*", "", n, flags=re.I).strip()
    if len(n) < 3:
        return None
    return n[:80]


def identify(device: dict[str, Any]) -> dict[str, Any]:
    """
    Return fingerprint dict:
      vendor, family, model_guess, confidence, oui_vendor, company_ids,
      company_names, matched_rule, random_mac
    """
    meta = device.get("metadata") or {}
    name = device.get("name") or ""
    mac = device.get("mac")
    random_mac = mac_is_random(mac)
    oui_vendor = None if random_mac else lookup_oui(mac)
    company_ids = _parse_company_ids(meta)
    companies = _company_table()
    company_names = [companies[i] for i in company_ids if i in companies]

    matched = None
    for rule in _rules():
        if _rule_matches(rule, name=name, meta=meta, oui_vendor=oui_vendor):
            matched = rule
            break

    ident = (matched or {}).get("identify") or {}
    vendor = ident.get("vendor") or (company_names[0] if company_names else None) or oui_vendor
    family = ident.get("family")
    confidence = ident.get("confidence") or (
        "medium" if vendor else "low" if oui_vendor or company_names else "none"
    )
    model = ident.get("model_guess") or _model_from_name(name)

    # If rule didn't set vendor but OUI/company did, keep medium
    if vendor and confidence == "none":
        confidence = "low"

    return {
        "vendor": vendor,
        "family": family,
        "model_guess": model,
        "confidence": confidence,
        "oui_vendor": oui_vendor,
        "company_ids": [f"0x{i:04X}" for i in company_ids],
        "company_names": company_names,
        "matched_rule": (matched or {}).get("id"),
        "random_mac": random_mac,
    }


def enrich_device(device: dict[str, Any]) -> dict[str, Any]:
    """Attach fingerprint + top-level vendor/family/model_guess for UI/API."""
    out = dict(device)
    radio = (out.get("radio") or "").lower()
    meta = dict(out.get("metadata") or {})

    if radio == "ble" or out.get("mac"):
        fp = identify(out)
        meta["fingerprint"] = fp
        # Keep legacy oui_hint filled from real OUI table
        if fp.get("oui_vendor"):
            meta["oui_hint"] = fp["oui_vendor"]
        out["vendor"] = fp.get("vendor")
        out["family"] = fp.get("family")
        out["model_guess"] = fp.get("model_guess")
    else:
        # RF: light identity from decode / catalog type
        fp = _rf_identity(out)
        if fp:
            meta["fingerprint"] = fp
            out["vendor"] = fp.get("vendor")
            out["family"] = fp.get("family")
            out["model_guess"] = fp.get("model_guess")

    out["metadata"] = meta
    return out


def _rf_identity(device: dict[str, Any]) -> dict[str, Any] | None:
    meta = device.get("metadata") or {}
    # TPMS / rtl_433 frames
    sensors = (meta.get("tpms_decode") or {}).get("sensors") or []
    if sensors:
        s0 = sensors[0]
        model = s0.get("model") or s0.get("type")
        return {
            "vendor": None,
            "family": "TPMS",
            "model_guess": str(model) if model else device.get("name"),
            "confidence": "high",
            "matched_rule": "tpms_decode",
        }
    frames = meta.get("rtl433_frames") or []
    if frames:
        fr = frames[0]
        model = fr.get("model") or fr.get("protocol")
        return {
            "vendor": None,
            "family": "rtl_433",
            "model_guess": str(model) if model else device.get("name"),
            "confidence": "high",
            "matched_rule": "rtl433",
        }
    uhf = meta.get("uhf_decode") or {}
    if uhf.get("ok"):
        return {
            "vendor": uhf.get("vendor"),
            "family": uhf.get("family") or "UHF telemetry",
            "model_guess": uhf.get("summary") or device.get("name"),
            "confidence": uhf.get("confidence") or "medium",
            "matched_rule": "uhf_decode",
        }
    # Catalog type as weak family
    dtype = device.get("device_type_name") or device.get("device_type_id")
    if dtype:
        return {
            "vendor": None,
            "family": str(dtype),
            "model_guess": device.get("name"),
            "confidence": "low",
            "matched_rule": "catalog_type",
        }
    return None

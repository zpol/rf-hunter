"""Detection quality scoring — demote / drop spectrum false positives."""

from __future__ import annotations

from typing import Any

# Presence-only profiles that flood the tracker with CW / noise spurs.
# NOTE: full_spectrum / spectrum_survey is intentionally NOT here — a survey
# must keep RF peaks visible; FPV/ACARS-style FP gating would hide the sweep.
NOISY_PRESENCE_TYPES = frozenset(
    {
        "fpv_58",
        "lband_av",
        "acars_vhf",
        "aprs_vhf",
        "pocsag_pager",
        "epirb_406",
        "weather_433",
        "pmr446",
        "dect",
        "wifi_24",
        "telemetry_1690",
        "industrial_360",
        "ism_868_domotica",
    }
)


TIER_RANK = {"noise": 0, "suspect": 1, "likely": 2, "confirmed": 3}


def _profile(device: dict[str, Any]) -> str:
    meta = device.get("metadata") or {}
    return str(
        meta.get("attack_profile")
        or device.get("device_type_id")
        or ((meta.get("catalog_hint") or {}).get("device_type_id"))
        or ""
    ).lower()


def _tid(device: dict[str, Any]) -> str:
    meta = device.get("metadata") or {}
    return str(
        device.get("device_type_id")
        or ((meta.get("catalog_hint") or {}).get("device_type_id"))
        or ""
    ).lower()


def _is_spectrum_survey(device: dict[str, Any]) -> bool:
    return _tid(device) == "full_spectrum" or _profile(device) == "spectrum_survey"


def infer_capability(device: dict[str, Any]) -> str:
    meta = device.get("metadata") or {}
    if meta.get("capability"):
        return str(meta["capability"]).lower()
    radio = (device.get("radio") or "").lower()
    if radio == "adsb" and (meta.get("adsb") or {}).get("icao"):
        return "decode"
    if radio == "ais" and (meta.get("ais") or {}).get("mmsi"):
        return "decode"
    if meta.get("adsb") or meta.get("ais"):
        adsb = meta.get("adsb") or {}
        ais = meta.get("ais") or {}
        if adsb.get("lat") is not None or ais.get("lat") is not None:
            return "decode"
        if adsb.get("icao") or ais.get("mmsi"):
            return "decode"
    if (meta.get("live_decode") or {}).get("ok") or (meta.get("tpms_decode") or {}).get("sensors"):
        return "decode"
    if (meta.get("fpv_decode") or {}).get("ok"):
        return "decode"
    if radio == "ble":
        return "ble"
    return str(meta.get("capability") or "presence").lower()


def assess(device: dict[str, Any]) -> dict[str, Any]:
    """
    Return quality blob:
      tier: confirmed | likely | suspect | noise
      score: 0–100
      fp_likely: bool
      summary: short reason
      reasons: list[str]
    """
    meta = device.get("metadata") or {}
    radio = (device.get("radio") or "").lower()
    tid = _tid(device)
    profile = _profile(device)
    classification = str(
        meta.get("classification")
        or ((device.get("raw") or {}).get("peak") or {}).get("classification")
        or ""
    ).lower()
    snr = device.get("snr_db")
    pwr = device.get("power_dbm")
    snr_f = float(snr) if snr is not None else None
    pwr_f = float(pwr) if pwr is not None else None

    reasons: list[str] = []
    adsb = meta.get("adsb") or {}
    ais = meta.get("ais") or {}

    # --- Traffic / decode evidence (early exits) ---
    if radio == "adsb" or adsb:
        msgs = int(adsb.get("messages") or 0)
        cs = str(adsb.get("callsign") or "")
        # Callsigns with '#' / garbage = demod noise that slipped through older builds
        if cs and any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 " for ch in cs.upper()):
            return _pack("noise", 15, True, ["ADS-B callsign charset invalid (CRC/noise)"])
        icao = str(adsb.get("icao") or "").upper()
        if icao in ("000000", "FFFFFF"):
            return _pack("noise", 10, True, ["ADS-B null ICAO"])
        if adsb.get("lat") is not None and adsb.get("lon") is not None:
            score = 88 if msgs >= 2 else 78
            reasons.append("ADS-B position decoded")
            if adsb.get("callsign"):
                score = min(100, score + 6)
                reasons.append("callsign")
            if adsb.get("alt_ft") is not None or adsb.get("speed_kts") is not None:
                score = min(100, score + 4)
            return _pack("confirmed", score, False, reasons)
        if adsb.get("icao") and msgs >= 2:
            return _pack("likely", 65, False, ["ADS-B ICAO (no CPR yet)"])
        if adsb.get("icao"):
            return _pack(
                "suspect",
                45,
                True,
                ["Single Mode-S frame — wait for more ADS-B msgs"],
            )
        return _pack(
            "noise",
            20,
            True,
            ["ADS-B band presence without Mode-S decode"],
        )

    if radio == "ais" or ais:
        if ais.get("lat") is not None and (ais.get("mmsi") or ais.get("shipname")):
            return _pack("confirmed", 90, False, ["AIS position + identity"])
        if ais.get("mmsi"):
            return _pack("likely", 68, False, ["AIS MMSI without position"])
        return _pack("noise", 22, True, ["AIS band presence without decode"])

    if (meta.get("tpms_decode") or {}).get("sensors"):
        return _pack("confirmed", 88, False, ["TPMS sensors decoded"])
    if (meta.get("live_decode") or {}).get("ok"):
        return _pack("confirmed", 85, False, ["Live RF decode ok"])
    if (meta.get("fpv_decode") or {}).get("ok"):
        return _pack("confirmed", 80, False, ["FPV frames extracted"])

    fp = meta.get("fingerprint") or {}
    fp_conf = str(fp.get("confidence") or "").lower()
    if radio == "ble":
        reasons.append("BLE advertisement")
        if fp_conf == "high" or meta.get("tuya_detected"):
            return _pack("confirmed", 86, False, reasons + ["strong BLE fingerprint"])
        if fp_conf == "medium":
            return _pack("likely", 72, False, reasons + ["medium fingerprint"])
        return _pack("likely", 58, False, reasons)

    # --- Full-spectrum survey: keep peaks visible (not FPV-style FP gating) ---
    if _is_spectrum_survey(device):
        score = 52
        fp_likely = False
        reasons.append("full-spectrum survey peak")
        hint = meta.get("catalog_hint") or {}
        if hint.get("device_type_name"):
            score += 10
            reasons.append(f"near catalog band · {hint.get('device_type_name')}")
        if "cw" in classification:
            score -= 6
            reasons.append(f"class '{classification}' (survey CW ok)")
        elif "burst" in classification or "weak" in classification:
            score -= 4
            reasons.append(f"class '{classification}'")
        if snr_f is not None:
            if snr_f >= 18:
                score += 20
                reasons.append(f"SNR {snr_f:.0f} dB strong")
            elif snr_f >= 12:
                score += 12
            elif snr_f >= 8:
                score += 4
            else:
                score -= 10
                reasons.append(f"SNR {snr_f:.0f} dB weak")
                fp_likely = True
        if pwr_f is not None:
            if pwr_f >= -35:
                score += 10
            elif pwr_f < -55:
                score -= 8
        score = int(max(0, min(100, score)))
        if score >= 70:
            tier = "likely"
        elif score >= 40:
            tier = "suspect"
        else:
            tier = "noise"
            fp_likely = True
        # Survey peaks must pass hide_noise unless truly noise-tier.
        return _pack(tier, score, fp_likely and tier == "noise", reasons)

    # --- Presence / spectrum peaks ---
    score = 45
    fp_likely = False
    reasons.append("RF presence peak")
    noisy = tid in NOISY_PRESENCE_TYPES or profile in NOISY_PRESENCE_TYPES

    if (meta.get("fpv_decode") or {}).get("ok") is False:
        score -= 15
        reasons.append("FPV decode — no video lock")
        fp_likely = True

    if "cw" in classification:
        score -= 22
        reasons.append(f"class '{classification}' (often carrier/spur)")
        fp_likely = True
    elif "burst" in classification or "weak" in classification:
        score -= 12
        reasons.append(f"class '{classification}'")

    if snr_f is not None:
        if snr_f >= 20:
            score += 18
            reasons.append(f"SNR {snr_f:.0f} dB strong")
        elif snr_f >= 14:
            score += 8
        elif snr_f < 10:
            score -= 15
            reasons.append(f"SNR {snr_f:.0f} dB weak")
            fp_likely = True

    if pwr_f is not None:
        if pwr_f >= -35:
            score += 12
        elif pwr_f < -48:
            score -= 12
            reasons.append(f"power {pwr_f:.0f} dBm weak")
            fp_likely = True

    if noisy:
        score -= 8
        reasons.append(f"noisy presence profile ({tid or profile})")

    if (tid in ("fpv_58", "lband_av") or profile in ("fpv_58", "lband_video")) and "cw" in classification:
        score = min(score, 18)
        fp_likely = True
        reasons.append("FPV CW peak ≠ analog video")

    if tid == "acars_vhf" or profile == "acars_vhf":
        score = min(score, 28)
        fp_likely = True
        reasons.append("ACARS sweep presence (not aircraft track)")

    score = int(max(0, min(100, score)))
    if score >= 80:
        tier = "confirmed"
    elif score >= 55:
        tier = "likely"
    elif score >= 30:
        tier = "suspect"
    else:
        tier = "noise"
        fp_likely = True

    return _pack(tier, score, fp_likely, reasons)


def _pack(tier: str, score: int, fp_likely: bool, reasons: list[str]) -> dict[str, Any]:
    summary = reasons[0] if reasons else tier
    return {
        "tier": tier,
        "score": int(score),
        "fp_likely": bool(fp_likely),
        "summary": summary,
        "reasons": reasons[:8],
    }


def should_drop_as_fp(device: dict[str, Any], quality: dict[str, Any] | None = None) -> bool:
    """
    Hard-drop the worst spectrum FPs so they never enter the tracker.
    Decoded / BLE / real traffic are never dropped.
    """
    q = quality or assess(device)
    radio = (device.get("radio") or "").lower()
    if radio in ("adsb", "ais", "ble"):
        return False
    meta = device.get("metadata") or {}
    if meta.get("adsb") or meta.get("ais"):
        return False
    if (meta.get("live_decode") or {}).get("ok") or (meta.get("tpms_decode") or {}).get("sensors"):
        return False
    if (meta.get("fpv_decode") or {}).get("ok"):
        return False

    tid = _tid(device)
    profile = _profile(device)
    # Full sweep must retain survey peaks; only drop ultra-weak noise tier.
    if _is_spectrum_survey(device):
        if q.get("tier") == "noise" and q.get("score", 0) < 25:
            return True
        return False

    noisy = tid in NOISY_PRESENCE_TYPES or profile in NOISY_PRESENCE_TYPES
    if not noisy:
        # Still drop ultra-weak generic CW
        if q.get("tier") == "noise" and q.get("score", 0) < 15:
            return True
        return False

    # Noisy presence profiles: drop noise tier entirely
    if q.get("tier") == "noise":
        return True
    # Also drop weak CW on FPV/ACARS even if scored suspect
    classification = str(meta.get("classification") or "").lower()
    snr = device.get("snr_db")
    snr_f = float(snr) if snr is not None else None
    if "cw" in classification and (snr_f is None or snr_f < 18):
        if tid in ("fpv_58", "lband_av", "acars_vhf") or profile in (
            "fpv_58",
            "lband_video",
            "acars_vhf",
        ):
            return True
    return False


def attach_quality(device: dict[str, Any]) -> dict[str, Any]:
    """Mutate a copy-friendly device dict with metadata.quality + capability."""
    meta = dict(device.get("metadata") or {})
    q = assess(device)
    meta["quality"] = q
    if not meta.get("capability"):
        meta["capability"] = infer_capability(device)
    out = {**device, "metadata": meta}
    return out


def snr_floor_for_type(device_type_id: str | None, *, default: float = 8.0) -> float:
    tid = (device_type_id or "").lower()
    if tid == "full_spectrum":
        return min(default, 6.0)
    if tid in ("fpv_58", "acars_vhf", "lband_av"):
        return 14.0
    if tid in NOISY_PRESENCE_TYPES:
        return max(default, 12.0)
    return default


def peak_limit_for_type(device_type_id: str | None, *, default: int = 10) -> int:
    tid = (device_type_id or "").lower()
    if tid == "full_spectrum":
        return max(default, 12)
    if tid in ("fpv_58", "acars_vhf", "lband_av"):
        return 3
    if tid in NOISY_PRESENCE_TYPES:
        return 5
    return default

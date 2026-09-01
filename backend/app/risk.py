"""Risk assessment from deep-dive analysis + catalog attack_profile (no offensive probes)."""

from __future__ import annotations

import re
from typing import Any

from .gatt_names import format_uuid_line

# Profiles that are inherently interesting for lab exploit surfaces
PROFILE_BASELINE: dict[str, str] = {
    "tuya_ble": "high",
    "tpms_433": "medium",
    "tpms_315": "medium",
    "ism_433": "medium",
    "ism_315": "medium",
    "alarm_869": "medium",
    "cw_telemetry": "medium",
    "uhf_telemetry": "medium",
    "ble_generic": "low",
    "bt_av": "low",
    "lora_eu": "low",
    "ism_868": "low",
    "dect": "low",
    "lband_video": "low",
    "fm_voice": "low",
    "ism_24": "low",
    "spectrum_survey": "low",
    "adsb_1090": "low",
    "ais_marine": "low",
    "fpv_58": "low",
    "aprs_vhf": "low",
    "pocsag": "low",
    "acars_vhf": "low",
    "epirb_406": "medium",
    "weather_433": "low",
}

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_TUYA_UUID_MARKERS = ("fd50", "a201")


def _mac_hex_forms(mac: str | None) -> list[str]:
    """Normalized MAC hex forms (forward + reversed) without separators."""
    if not mac:
        return []
    raw = re.sub(r"[^0-9a-fA-F]", "", str(mac)).lower()
    if len(raw) != 12:
        return []
    forms = [raw]
    rev = "".join(raw[i : i + 2] for i in range(10, -1, -2))
    if rev != raw:
        forms.append(rev)
    return forms


def detect_mac_in_manufacturer_data(device: dict[str, Any]) -> dict[str, Any] | None:
    """
    Detect BD_ADDR (or byte-reversed) embedded in BLE manufacturer_data hex.
    Returns match metadata or None.
    """
    mac = device.get("mac")
    forms = _mac_hex_forms(mac)
    if not forms:
        return None
    meta = device.get("metadata") or {}
    mfg = meta.get("manufacturer_data") or {}
    if not isinstance(mfg, dict) or not mfg:
        return None
    for cid, hex_val in mfg.items():
        blob = re.sub(r"[^0-9a-fA-F]", "", str(hex_val)).lower()
        if not blob:
            continue
        for form in forms:
            idx = blob.find(form)
            if idx >= 0:
                return {
                    "mac": mac,
                    "company_id": str(cid),
                    "offset": idx // 2,
                    "match_hex": form,
                    "byte_reversed": form != forms[0],
                    "manufacturer_hex": blob,
                }
    return None


def has_tuya_fingerprint(
    device: dict[str, Any],
    ble: dict[str, Any] | None = None,
) -> bool:
    """True only with explicit Tuya signal — not bare catalog mis-tags."""
    meta = device.get("metadata") or {}
    if meta.get("tuya_detected"):
        return True
    uuids: list[str] = []
    for u in meta.get("service_uuids") or []:
        uuids.append(str(u))
    ble = ble or {}
    for u in ble.get("service_uuids") or []:
        uuids.append(str(u))
    for svc in ble.get("services") or []:
        uuids.append(str(svc.get("uuid") or ""))
    joined = " ".join(u.lower() for u in uuids)
    return any(m in joined for m in _TUYA_UUID_MARKERS)


def _identity_leak_evidence(hit: dict[str, Any]) -> list[str]:
    order = "byte-reversed" if hit.get("byte_reversed") else "forward"
    return [
        f"MAC {hit.get('mac')}",
        f"company_id {hit.get('company_id')}",
        f"offset_byte {hit.get('offset')} ({order})",
        f"match {hit.get('match_hex')}",
    ]


def count_writable_from_risk(risk: dict[str, Any] | None) -> int:
    """Best-effort writable GATT count from risk findings / gatt_snapshot."""
    if not risk:
        return 0
    for f in risk.get("findings") or []:
        title = str(f.get("finding") or "")
        m = re.search(r"(\d+)\s+writable GATT", title, re.I)
        if m:
            return int(m.group(1))
    snap = risk.get("gatt_snapshot") or {}
    n = 0
    for svc in snap.get("services") or []:
        for char in svc.get("characteristics") or []:
            props = {str(p).lower() for p in (char.get("properties") or [])}
            if "write" in props or "write-without-response" in props:
                n += 1
    return n


def has_identity_leak_finding(risk: dict[str, Any] | None) -> bool:
    if not risk:
        return False
    for f in risk.get("findings") or []:
        title = str(f.get("finding") or "").lower()
        if "manufacturer_data" in title or "bd_addr embedded" in title:
            return True
    return False


def assess_risk(device: dict[str, Any], analysis: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Build a risk report from catalog profile + deep-dive findings.
    Does not run attack vectors — only interprets analysis / metadata.
    Severity buckets: critical | high | medium | low
    """
    analysis = analysis or {}
    meta = device.get("metadata") or {}
    profile = meta.get("attack_profile") or "generic"
    findings: list[dict[str, Any]] = []
    max_sev = "info"

    def bump(
        sev: str,
        finding: str,
        detail: str = "",
        evidence: list[str] | None = None,
    ) -> None:
        nonlocal max_sev
        entry: dict[str, Any] = {"severity": sev, "finding": finding, "detail": detail}
        if evidence:
            entry["evidence"] = evidence
        findings.append(entry)
        if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(max_sev, 0):
            max_sev = sev

    base = PROFILE_BASELINE.get(profile, "low")
    bump(
        base if base != "low" else "info",
        f"Catalog profile `{profile}`",
        "Baseline from device catalog attack_profile",
    )

    ble = analysis.get("ble") or {}
    rf = analysis.get("rf") or {}

    if ble:
        if ble.get("connected"):
            bump(
                "medium",
                "BLE GATT reachable without pairing gate",
                "Deep dive connected successfully — no pairing gate observed",
                evidence=[f"MAC {ble.get('mac') or device.get('mac') or '?'}"],
            )
        services = ble.get("services") or []
        writable_ev: list[str] = []
        readable_ev: list[str] = []
        hid_ev: list[str] = []
        for svc in services:
            su = str(svc.get("uuid", ""))
            su_l = su.lower()
            svc_desc = svc.get("description")
            if "1812" in su_l:
                hid_ev.append(
                    format_uuid_line(su, description=svc_desc or "Human Interface Device")
                )
            for char in svc.get("characteristics") or []:
                props = list(char.get("properties") or [])
                propset = set(props)
                cu = str(char.get("uuid", ""))
                cdesc = char.get("description")
                if "write" in propset or "write-without-response" in propset:
                    write_props = [
                        p for p in props if p in ("write", "write-without-response")
                    ]
                    writable_ev.append(
                        format_uuid_line(
                            cu,
                            description=cdesc,
                            properties=write_props,
                            service_uuid=su,
                        )
                    )
                if "read" in propset and char.get("value_hex"):
                    preview = char.get("value_ascii") or char.get("value_hex") or ""
                    preview = str(preview).replace("\n", " ")[:48]
                    readable_ev.append(
                        format_uuid_line(
                            cu,
                            description=cdesc,
                            properties=["read"],
                            service_uuid=su,
                            extra=f"val={preview!r}" if preview else None,
                        )
                    )
                if "1812" in su_l:
                    hid_ev.append(
                        format_uuid_line(
                            cu,
                            description=cdesc,
                            properties=props,
                            service_uuid=su,
                        )
                    )
        if writable_ev:
            bump(
                "critical",
                f"{len(writable_ev)} writable GATT characteristic(s)",
                "Command injection surface — characteristics accepting write / write-without-response",
                evidence=writable_ev,
            )
        if readable_ev:
            bump(
                "high",
                f"{len(readable_ev)} unauthenticated GATT read(s)",
                "Data exposure — reads succeeded without pairing",
                evidence=readable_ev,
            )
        if hid_ev:
            bump(
                "critical",
                "HID service exposed",
                "CVE-2023-45866 class if host discoverable — HID chars listed below",
                evidence=hid_ev,
            )
        if has_tuya_fingerprint(device, ble):
            uuids = meta.get("service_uuids") or ble.get("service_uuids") or []
            bump(
                "critical",
                "Tuya BLE fingerprint",
                "Pairing-window MITM / cloud token risk",
                evidence=[str(u) for u in uuids[:8]] or ["tuya_detected"],
            )
        if ble.get("error") and not ble.get("connected"):
            bump("info", "BLE connect failed", str(ble.get("error")))

    # Passive privacy: MAC inside manufacturer_data (works without GATT connect)
    if device.get("radio") == "ble" or meta.get("manufacturer_data"):
        leak = detect_mac_in_manufacturer_data(device)
        if leak:
            bump(
                "high",
                "BD_ADDR embedded in manufacturer_data",
                "Passive re-identification — advertisement leaks stable identity",
                evidence=_identity_leak_evidence(leak),
            )

    if rf:
        snr = rf.get("snr_db")
        sig = rf.get("signal_type")
        rf_ev: list[str] = []
        if rf.get("freq_mhz") is not None:
            rf_ev.append(f"freq {rf['freq_mhz']} MHz")
        if snr is not None:
            rf_ev.append(f"SNR {snr} dB")
        if rf.get("peak_offset_hz") is not None:
            rf_ev.append(f"peak offset {rf['peak_offset_hz']:.0f} Hz")
        if rf.get("bw_hz") is not None:
            rf_ev.append(f"≈{rf['bw_hz']:.0f} Hz @ -3 dB")
        if rf.get("iq_file"):
            rf_ev.append(f"IQ {rf['iq_file']}")
        if snr is not None and float(snr) >= 12:
            bump(
                "medium",
                f"Strong RF carrier (SNR {snr} dB)",
                "Capture/replay surface",
                evidence=rf_ev or None,
            )
        if sig == "CW":
            bump(
                "medium",
                "Narrow CW signal",
                "Jamming / replay if modulated bursts appear",
                evidence=rf_ev or None,
            )
        elif sig == "modulated/wide":
            bump(
                "high",
                "Modulated RF traffic",
                "Protocol decode / replay candidate",
                evidence=rf_ev or None,
            )
        if profile in ("ism_433", "ism_315"):
            bump(
                "medium",
                "Fixed/rolling-code remote class",
                "Replay if fixed-code; capture on press if rolling",
                evidence=rf_ev or None,
            )
        if profile in ("tpms_433", "tpms_315"):
            bump(
                "high",
                "TPMS band — plaintext sensor class",
                "Deep dive extracts pressure/temp/ID via rtl_433",
                evidence=rf_ev or None,
            )
        if profile in ("alarm_869", "cw_telemetry", "uhf_telemetry"):
            bump(
                "medium",
                "Alarm/telemetry / UHF band",
                "Monitor during trigger for FSK overlay · deep dive runs FM/rtl_433/POCSAG probes",
                evidence=rf_ev or None,
            )

    uhf = analysis.get("uhf") or {}
    if uhf.get("ok"):
        ev = []
        for m in uhf.get("methods") or []:
            ev.append(f"method={m}")
        if uhf.get("summary"):
            ev.append(str(uhf["summary"]))
        for fr in (uhf.get("rtl433_frames") or [])[:4]:
            ev.append(str(fr.get("model") or fr.get("protocol") or fr)[:80])
        for ln in (uhf.get("pocsag") or [])[:4]:
            ev.append(str(ln)[:100])
        bump(
            "high",
            f"UHF telemetry decode · {uhf.get('family') or 'signal'}",
            uhf.get("message") or uhf.get("summary") or "Decoded activity",
            evidence=ev or None,
        )
    elif uhf and not uhf.get("ok"):
        bump("info", "UHF decode empty", uhf.get("message") or "No frames")

    tpms = analysis.get("tpms") or {}
    sensors = tpms.get("sensors") or []
    if sensors:
        sensor_ev: list[str] = []
        for s in sensors[:8]:
            bits = []
            if s.get("pressure_psi") is not None:
                bits.append(f"{s['pressure_psi']} PSI")
            if s.get("pressure_kpa") is not None:
                bits.append(f"{s['pressure_kpa']} kPa")
            if s.get("temperature_c") is not None:
                bits.append(f"{s['temperature_c']} °C")
            detail = " · ".join(bits) if bits else "fields present"
            line = f"{s.get('model', 'sensor')} id={s.get('id')} · {detail}"
            sensor_ev.append(line)
            bump(
                "high",
                f"TPMS decode · {s.get('model', 'sensor')} id={s.get('id')}",
                detail,
            )
        bump(
            "critical",
            f"Cleartext TPMS telemetry ({len(sensors)} sensor(s))",
            tpms.get("message") or "Pressure/temp/ID in the clear",
            evidence=sensor_ev,
        )
    elif tpms and tpms.get("rtl433") and not tpms.get("ok"):
        bump("info", "TPMS decode empty", tpms.get("message") or "No frames")

    rtl = analysis.get("rtl433") or {}
    code = rtl.get("code_class") or {}
    if rtl.get("frame_count"):
        frames = rtl.get("frames") or []
        rtl_ev = []
        for fr in frames[:8]:
            model = fr.get("model") or fr.get("protocol") or "?"
            rid = fr.get("id") if fr.get("id") is not None else fr.get("ID")
            rtl_ev.append(f"{model}" + (f" id={rid}" if rid is not None else ""))
        if code.get("class"):
            rtl_ev.insert(0, f"code_class={code.get('class')} · {code.get('reason') or ''}".strip(" ·"))
        bump(
            "critical" if code.get("class") in ("fixed", "likely_fixed") else "high",
            f"rtl_433 frames ×{rtl.get('frame_count')} · code={code.get('class', '?')}",
            code.get("replay_advice") or "",
            evidence=rtl_ev or None,
        )

    if analysis.get("error"):
        bump("info", "Deep dive incomplete", str(analysis["error"]))

    # Normalize info → low for UI buckets
    if max_sev == "info":
        max_sev = "low"
    status = _status_from_severity(max_sev)
    summary = [f["finding"] for f in findings if f["severity"] in ("critical", "high", "medium")]

    return {
        "status": status,
        "severity": max_sev,
        "profile": profile,
        "findings": findings,
        "summary": summary[:8],
        "exploitability": (
            "CRITICAL" if max_sev == "critical"
            else "HIGH" if max_sev == "high"
            else "MEDIUM" if max_sev == "medium"
            else "LOW"
        ),
    }


def _rf_meta_evidence(device: dict[str, Any]) -> list[str]:
    meta = device.get("metadata") or {}
    ev: list[str] = []
    if device.get("freq_mhz") is not None:
        ev.append(f"freq {device['freq_mhz']} MHz")
    if device.get("snr_db") is not None:
        ev.append(f"SNR {device['snr_db']} dB")
    if device.get("power_dbm") is not None:
        ev.append(f"power {device['power_dbm']} dBm")
    if device.get("bandwidth_hz") is not None:
        ev.append(f"bw≈{device['bandwidth_hz']} Hz")
    if meta.get("classification"):
        ev.append(f"class {meta['classification']}")
    return ev


def _live_decode_state(meta: dict[str, Any]) -> tuple[dict[str, Any] | None, bool, bool]:
    """Return (live_decode dict, has_attempt, ok)."""
    ld = meta.get("live_decode")
    if not isinstance(ld, dict):
        return None, False, False
    return ld, True, bool(ld.get("ok"))


def assess_risk_quick(device: dict[str, Any]) -> dict[str, Any]:
    """
    Fast triage without GATT/IQ — catalog profile + advertisement / live_decode metadata.
    Avoids marking empty CW peaks as confirmed remote/TPMS vulns.
    """
    meta = device.get("metadata") or {}
    profile = meta.get("attack_profile") or "generic"
    findings: list[dict[str, Any]] = []
    # Soft baseline — evidence bumps severity; empty RF stays low/medium
    soft_baseline = {
        "tuya_ble": "medium",
        "tpms_433": "low",
        "tpms_315": "low",
        "ism_433": "low",
        "ism_315": "low",
        "alarm_869": "low",
        "cw_telemetry": "low",
        "uhf_telemetry": "low",
        "ble_generic": "low",
        "bt_av": "low",
        "lora_eu": "low",
        "ism_868": "low",
        "dect": "low",
        "lband_video": "low",
        "fm_voice": "low",
        "ism_24": "low",
        "spectrum_survey": "low",
        "adsb_1090": "low",
        "ais_marine": "low",
        "fpv_58": "low",
        "aprs_vhf": "low",
        "pocsag": "low",
        "acars_vhf": "low",
        "epirb_406": "medium",
        "weather_433": "low",
    }
    max_sev = soft_baseline.get(profile, PROFILE_BASELINE.get(profile, "low"))

    def bump(
        sev: str,
        finding: str,
        detail: str = "",
        evidence: list[str] | None = None,
    ) -> None:
        nonlocal max_sev
        entry: dict[str, Any] = {"severity": sev, "finding": finding, "detail": detail}
        if evidence:
            entry["evidence"] = evidence
        findings.append(entry)
        if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(max_sev, 0):
            max_sev = sev

    bump(
        max_sev if max_sev != "low" else "low",
        f"Catalog profile `{profile}`",
        "Quick triage — severity rises with decode / identity evidence",
    )

    rf_ev = _rf_meta_evidence(device)
    ld, ld_attempted, ld_ok = _live_decode_state(meta)
    tpms = meta.get("tpms_decode") or {}
    tpms_sensors = tpms.get("sensors") or []
    rtl_frames = meta.get("rtl433_frames") or []
    code = meta.get("code_class") or {}
    fp = meta.get("fingerprint") or {}
    snr = device.get("snr_db")
    snr_f = float(snr) if snr is not None else None
    classification = str(meta.get("classification") or "")

    # ── BLE identity / IoT ──────────────────────────────────────
    if has_tuya_fingerprint(device):
        bump("critical", "Tuya BLE fingerprint", "Pairing-window / cloud token class")
    leak = detect_mac_in_manufacturer_data(device)
    if leak:
        bump(
            "high",
            "BD_ADDR embedded in manufacturer_data",
            "Passive re-identification — advertisement leaks stable identity",
            evidence=_identity_leak_evidence(leak),
        )
    elif device.get("radio") == "ble" and meta.get("manufacturer_data"):
        cids = list((meta.get("manufacturer_data") or {}).keys())
        bump(
            "low",
            "BLE manufacturer_data present",
            "No BD_ADDR substring match — still useful for fingerprinting",
            evidence=[f"company_ids {cids[:6]}"],
        )
    if device.get("radio") == "ble" and meta.get("connectable"):
        bump("medium", "BLE connectable advertisement", "GATT surface if no auth")
    if profile in ("bt_av", "ble_generic") and device.get("radio") == "ble":
        vendor = fp.get("vendor") or fp.get("company_names") or meta.get("oui_hint")
        bump(
            "medium",
            "BLE peripheral — GATT dive/attack candidate",
            "Printer/AV/sensor class — enumerate writable chars when in range",
            evidence=[str(vendor)] if vendor else [f"name {device.get('name') or '?'}"],
        )
    if meta.get("service_uuids") and device.get("radio") == "ble":
        uuids = [str(u) for u in (meta.get("service_uuids") or [])[:6]]
        bump("low", f"{len(meta.get('service_uuids') or [])} BLE service UUID(s) in adv", evidence=uuids)

    # ── Confirmed RF decode evidence (upgrade) ──────────────────
    if tpms_sensors:
        bump(
            "critical",
            f"Cleartext TPMS telemetry ({len(tpms_sensors)} sensor(s))",
            "Pressure/temp/ID decoded — lab replay surface",
            evidence=[
                f"{s.get('model')} id={s.get('id')}" for s in tpms_sensors[:6]
            ],
        )
    elif profile in ("tpms_433", "tpms_315"):
        if ld_attempted and not ld_ok:
            bump(
                "low",
                "TPMS band peak — no frames decoded",
                "Need wheel motion / LF trigger; SNR alone is not a vuln",
                evidence=rf_ev + [str(ld.get("message") or "")[:80]],
            )
        else:
            bump(
                "medium",
                "TPMS band candidate",
                "Typically plaintext when transmitting — validate with live decode",
                evidence=rf_ev or None,
            )

    if rtl_frames or (isinstance(code, dict) and code.get("class") in ("fixed", "likely_fixed")):
        cls = code.get("class") if isinstance(code, dict) else "?"
        bump(
            "critical" if cls in ("fixed", "likely_fixed") else "high",
            f"Remote frames decoded · code={cls}",
            (code.get("replay_advice") if isinstance(code, dict) else None) or "rtl_433 / live decode hit",
            evidence=rf_ev + [str(f)[:80] for f in (rtl_frames[:4] if isinstance(rtl_frames, list) else [])],
        )
    elif profile in ("ism_433", "ism_315"):
        if ld_attempted and not ld_ok:
            bump(
                "low",
                "ISM remote band — no frames (CW/noise likely)",
                "Press the physical remote while monitoring; catalog label ≠ vuln",
                evidence=rf_ev + [str((ld or {}).get("message") or "empty decode")[:80]],
            )
        else:
            bump(
                "medium",
                "ISM remote / keyfob band candidate",
                "Fixed-code replay only after button-press decode",
                evidence=rf_ev or None,
            )

    if profile == "alarm_869":
        if ld_attempted and not ld_ok:
            bump("low", "Alarm 869 peak — no burst decode yet", evidence=rf_ev or None)
        else:
            bump(
                "medium",
                "Alarm 869 band candidate",
                "Trigger sensor while monitoring for FSK overlay",
                evidence=rf_ev or None,
            )

    if profile in ("uhf_telemetry", "cw_telemetry") or device.get("device_type_id") in (
        "industrial_360",
        "telemetry_1690",
    ):
        if ld_ok:
            bump(
                "high",
                "UHF/telemetry activity decoded",
                str((ld or {}).get("message") or (ld or {}).get("summary") or "FM/FSK activity"),
                evidence=rf_ev + [f"kind={(ld or {}).get('kind')}"],
            )
        elif ld_attempted:
            bump("low", "Telemetry peak — decode empty", evidence=rf_ev or None)
        elif snr_f is not None and snr_f >= 18:
            bump("medium", "Strong telemetry-band carrier", "Deep dive / longer IQ for demod", evidence=rf_ev)

    if profile == "dect" or device.get("device_type_id") == "dect":
        bump(
            "medium" if snr_f and snr_f >= 15 else "low",
            "DECT base / cordless presence",
            "Presence only — not a remote replay finding",
            evidence=rf_ev or None,
        )
    if profile == "lband_video" or device.get("device_type_id") == "lband_av":
        bump(
            "medium" if snr_f and snr_f >= 20 else "low",
            "L-band AV / FPV carrier",
            "Strong energy — video-link class presence",
            evidence=rf_ev or None,
        )
    if profile == "fpv_58" or device.get("device_type_id") == "fpv_58":
        bump(
            "medium" if snr_f and snr_f >= 15 else "low",
            "FPV 5.8 GHz video TX",
            "PortaPack FPV Detect class — race-band carrier",
            evidence=rf_ev or None,
        )
    if profile == "adsb_1090" or device.get("device_type_id") == "adsb_1090" or (device.get("radio") or "").lower() == "adsb":
        adsb = meta.get("adsb") or {}
        if adsb.get("icao"):
            bump(
                "medium",
                f"ADS-B aircraft {adsb.get('callsign') or adsb.get('icao')}",
                "Decoded Mode-S — use See on map for position",
                evidence=[
                    f"icao={adsb.get('icao')}",
                    f"alt_ft={adsb.get('alt_ft')}",
                    f"msgs={adsb.get('messages')}",
                ],
            )
        else:
            bump("low", "ADS-B band energy @ 1090 MHz", "Presence — listen longer for frames", evidence=rf_ev or None)
    if profile == "ais_marine" or device.get("device_type_id") == "ais_marine":
        bump("low", "AIS marine VHF presence", "PortaPack AIS class — vessel traffic band", evidence=rf_ev or None)
    if profile == "epirb_406" or device.get("device_type_id") == "epirb_406":
        bump("medium", "EPIRB/ELT 406 MHz band activity", "Distress beacon class — verify before assuming alert", evidence=rf_ev or None)
    if profile in ("lora_eu", "ism_868") or device.get("device_type_id") in (
        "lora_eu868",
        "ism_868_domotica",
    ):
        bump(
            "medium" if snr_f and snr_f >= 16 else "low",
            "868 MHz IoT / LoRa-adjacent peak",
            "Presence — confirm with button/sensor activity",
            evidence=rf_ev or None,
        )
    if profile == "fm_voice" or device.get("device_type_id") == "pmr446":
        bump("low", "PMR/FRS voice-band energy", "Presence / eavesdrop class only", evidence=rf_ev or None)

    if profile == "spectrum_survey" or device.get("device_type_id") == "full_spectrum":
        hint = meta.get("catalog_hint") or {}
        if hint.get("device_type_name"):
            bump(
                "medium",
                f"Full-sweep peak near {hint['device_type_name']}",
                "Catalog band overlap — good deep-dive / monitor target",
                evidence=rf_ev + [f"hint {hint.get('device_type_id')}"],
            )
        elif snr_f is not None and snr_f >= 15:
            bump(
                "medium",
                "Full-sweep strong carrier",
                "Unknown band energy — prioritize by SNR for dive",
                evidence=rf_ev,
            )
        else:
            bump("low", "Full-sweep spectrum hit", "Presence from 1–6000 MHz survey", evidence=rf_ev or None)

    # Narrow CW without decode = methodological caution (H2), not exploit
    if device.get("radio") == "hackrf" and (
        classification == "CW likely" or (snr_f is not None and snr_f >= 15)
    ):
        if not (ld_ok or tpms_sensors or rtl_frames):
            bump(
                "low",
                "Strong / CW RF peak without frames",
                "High SNR ≠ garage/TPMS vuln — needs triggered capture",
                evidence=rf_ev or None,
            )

    if max_sev == "info":
        max_sev = "low"
    status = _status_from_severity(max_sev)
    summary = [
        f["finding"]
        for f in findings
        if f["severity"] in ("critical", "high", "medium", "low")
    ]

    return {
        "status": status,
        "severity": max_sev,
        "profile": profile,
        "findings": findings,
        "summary": summary[:8],
        "mode": "quick",
        "exploitability": (
            "CRITICAL" if max_sev == "critical"
            else "HIGH" if max_sev == "high"
            else "MEDIUM" if max_sev == "medium"
            else "LOW"
        ),
    }


def _status_from_severity(sev: str) -> str:
    """Map severity to tracker risk_status (critical/high/medium/low)."""
    if sev == "critical":
        return "critical"
    if sev == "high":
        return "high"
    if sev == "medium":
        return "medium"
    if sev in ("low", "info"):
        return "low"
    return "unknown"

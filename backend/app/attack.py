from __future__ import annotations

import asyncio
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import tpms_decode
from .gatt_names import format_uuid_line

_DEFAULT_CAPTURES = Path(__file__).resolve().parents[2].parent / "captures" / "rf-hunter-v2"
CAPTURES = Path(os.environ.get("RF_HUNTER_CAPTURES", str(_DEFAULT_CAPTURES)))
HACKRF_SERIAL = os.environ.get("HACKRF_SERIAL", "")


def attack_device(device: dict[str, Any]) -> dict[str, Any]:
    """
    Authorized-lab offensive probes — GATT write tests, rtl_433 decode, IQ replay prep.
    """
    attack_id = f"ATK-{uuid.uuid4().hex[:8]}"
    out_dir = CAPTURES / attack_id
    out_dir.mkdir(parents=True, exist_ok=True)

    profile = (device.get("metadata") or {}).get("attack_profile") or "generic"
    radio = device.get("radio", "hackrf")
    try:
        from . import samsung_tv as samsung_mod

        if radio == "ble" and samsung_mod.is_samsung_tv(device):
            profile = "samsung_tv"
        elif radio == "ble" and samsung_mod.is_samsung_family(device):
            profile = "samsung_tv"
    except Exception:
        pass

    result: dict[str, Any] = {
        "attack_id": attack_id,
        "target": device,
        "profile": profile,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "vectors": [],
        "risk_summary": [],
    }

    if radio == "ble":
        result["vectors"].extend(_attack_ble(device, out_dir))
    elif radio == "wifi":
        from . import wifi_assess

        result["profile"] = "wifi_ap"
        result["vectors"].extend(wifi_assess.assess_ap(device))
    else:
        result["vectors"].extend(_attack_rf(device, out_dir, profile))

    for v in result["vectors"]:
        if v.get("success") and v.get("severity") == "critical":
            result["risk_summary"].append(v.get("finding", v.get("name")))
        elif v.get("success") and v.get("severity") == "high" and radio == "wifi":
            result["risk_summary"].append(v.get("finding", v.get("name")))

    if radio == "wifi":
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        best = max(
            (sev_rank.get(str(v.get("severity") or "").lower(), 0) for v in result["vectors"]),
            default=0,
        )
        result["exploitability"] = (
            "HIGH" if best >= 3 else "MEDIUM" if best >= 2 else "LOW"
        )
        result["assessment_only"] = True
        result["note"] = (
            "Wi‑Fi Attack is a catalog-driven assessment from passive scan facts. "
            "Active exploits and Pineapple control are not executed in this phase."
        )
    else:
        result["exploitability"] = (
            "HIGH" if any(v.get("severity") == "critical" for v in result["vectors"])
            else "MEDIUM" if any(v.get("success") for v in result["vectors"])
            else "LOW"
        )
    result["completed_utc"] = datetime.now(timezone.utc).isoformat()
    (out_dir / "attack_report.json").write_text(json.dumps(result, indent=2, default=str))
    return result


def _attack_rf(device: dict, out_dir: Path, profile: str) -> list[dict]:
    vectors = []
    freq = device.get("freq_mhz")
    if not freq:
        return [{"name": "rf_skip", "success": False, "detail": "No frequency"}]

    iq = out_dir / "attack_capture.raw"
    rate = 2_000_000
    is_tpms = profile in ("tpms_315", "tpms_433") or tpms_decode.is_tpms_target(device)
    duration_s = 20 if is_tpms else 12
    from .radio_gate import exclusive

    cmd = [
        "hackrf_transfer", "-r", str(iq),
        "-f", str(int(float(freq) * 1e6)), "-s", str(rate),
        "-l", "40", "-g", "44", "-a", "0", "-n", str(duration_s * rate),
    ]
    if HACKRF_SERIAL:
        cmd = ["hackrf_transfer", "-d", HACKRF_SERIAL] + cmd[1:]

    try:
        with exclusive("attack_rf"):
            subprocess.run(cmd, capture_output=True, timeout=duration_s + 25, check=False)
        vectors.append({
            "name": "iq_capture",
            "success": iq.exists(),
            "detail": f"{duration_s}s IQ @ {freq} MHz",
            "artifact": str(iq.name),
        })
    except Exception as e:
        vectors.append({"name": "iq_capture", "success": False, "detail": str(e)})

    if iq.exists() and is_tpms:
        tpms = tpms_decode.decode_tpms_iq(iq, float(freq), sample_rate=rate, out_dir=out_dir)
        sensors = tpms.get("sensors") or []
        if sensors:
            for s in sensors:
                bits = []
                if s.get("pressure_psi") is not None:
                    bits.append(f"{s['pressure_psi']} PSI")
                if s.get("temperature_c") is not None:
                    bits.append(f"{s['temperature_c']} °C")
                vectors.append({
                    "name": "tpms_decode",
                    "success": True,
                    "severity": "critical",
                    "wow": True,
                    "finding": f"TPMS {s.get('model')} id={s.get('id')} — {', '.join(bits) or 'fields'}",
                    "detail": s,
                })
        else:
            vectors.append({
                "name": "tpms_decode",
                "success": False,
                "severity": "info",
                "finding": "No TPMS frames decoded",
                "detail": tpms.get("message"),
            })
    elif iq.exists() and _has_rtl433():
        try:
            r = subprocess.run(
                ["rtl_433", "-r", str(iq), "-s", str(rate), "-f", f"{freq}M", "-F", "json"],
                capture_output=True, text=True, timeout=60,
            )
            decoded = [l for l in (r.stdout or "").splitlines() if l.startswith("{")]
            vectors.append({
                "name": "rtl_433_decode",
                "success": len(decoded) > 0,
                "severity": "critical" if decoded else "info",
                "finding": "Protocol frames decoded — data exposed" if decoded else "No frames",
                "detail": decoded[:5] if decoded else (r.stderr or "")[-300:],
            })
        except Exception as e:
            vectors.append({"name": "rtl_433_decode", "success": False, "detail": str(e)})
    else:
        vectors.append({
            "name": "rtl_433_decode",
            "success": False,
            "detail": "rtl_433 not available or no IQ",
        })

    if profile in ("alarm_869", "cw_telemetry"):
        vectors.append({
            "name": "cw_carrier_analysis",
            "success": True,
            "severity": "medium",
            "finding": "CW carrier — jamming/replay surface if modulated bursts appear on trigger",
            "detail": "Monitor during sensor activation for FSK overlay",
        })

    if profile in ("tpms_433", "tpms_315"):
        vectors.append({
            "name": "tpms_surface",
            "success": True,
            "severity": "high",
            "finding": "TPMS typically plaintext — pressure/temp/ID via rtl_433",
            "detail": "Deep dive or Attack while sensor transmits (wheel motion / relearn)",
            "wow": True,
        })

    if profile in ("ism_433", "ism_315"):
        vectors.append({
            "name": "replay_surface",
            "success": True,
            "severity": "critical",
            "finding": "WOW: fixed-code remotes — capture on button press → replay candidate",
            "detail": "Lab demo: rtl_433 decode frames, then IQ replay prep with HackRF TX (authorized only)",
            "wow": True,
        })

    return vectors


def _attack_ble(device: dict, out_dir: Path) -> list[dict]:
    mac = device.get("mac")
    if not mac:
        return [{"name": "ble_skip", "success": False}]

    return asyncio.run(_attack_ble_async(mac, device))


async def _attack_ble_async(mac: str, device: dict) -> list[dict]:
    vectors: list[dict] = []
    try:
        from bleak import BleakClient
    except ImportError:
        return [{"name": "bleak_missing", "success": False}]

    from . import risk as risk_mod
    from . import samsung_tv as samsung_mod

    is_tuya = risk_mod.has_tuya_fingerprint(device)
    is_samsung = samsung_mod.is_samsung_family(device)
    is_tv = samsung_mod.is_samsung_tv(device)

    # Passive Samsung identity (works even if GATT connect fails)
    if is_samsung:
        vectors.extend(samsung_mod.ble_identity_vectors(device))

    try:
        async with BleakClient(mac, timeout=25.0) as client:
            vectors.append({
                "name": "ble_connect",
                "success": client.is_connected,
                "severity": "medium" if client.is_connected else "info",
                "detail": "Direct BLE connection established",
            })

            if is_samsung:
                gatt_map = samsung_mod.summarize_gatt_services(client.services)
                vectors.extend(samsung_mod.gatt_profile_vectors(gatt_map))

            writable = []
            readable = []
            for svc in client.services:
                su = str(svc.uuid)
                for char in svc.characteristics:
                    props = list(char.properties)
                    propset = set(props)
                    if "write" in propset or "write-without-response" in propset:
                        write_props = [
                            p for p in props if p in ("write", "write-without-response")
                        ]
                        writable.append(
                            format_uuid_line(
                                str(char.uuid),
                                description=getattr(char, "description", None),
                                properties=write_props,
                                service_uuid=su,
                            )
                        )
                    if "read" in propset:
                        readable.append(str(char.uuid))
                        try:
                            val = await client.read_gatt_char(char.uuid)
                            vectors.append({
                                "name": f"gatt_read_{str(char.uuid)[:8]}",
                                "success": True,
                                "severity": "high" if len(val) > 0 else "info",
                                "finding": f"Unauthenticated read {char.uuid}",
                                "detail": val.hex()[:120],
                                "evidence": [
                                    format_uuid_line(
                                        str(char.uuid),
                                        description=getattr(char, "description", None),
                                        properties=["read"],
                                        service_uuid=su,
                                    )
                                ],
                            })
                        except Exception as e:
                            vectors.append({
                                "name": f"gatt_read_{str(char.uuid)[:8]}",
                                "success": False,
                                "detail": str(e),
                            })

            if writable:
                finding = (
                    f"{len(writable)} writable GATT chars — Samsung/OCF or vendor command surface"
                    if is_samsung
                    else f"{len(writable)} writable GATT chars — WOW: command injection surface"
                )
                vectors.append({
                    "name": "gatt_write_surface",
                    "success": True,
                    "severity": "critical",
                    "finding": finding,
                    "detail": "Characteristics accepting write / write-without-response",
                    "evidence": writable,
                    "wow": True,
                })
                # Lab-safe marker write so we can identify RF Hunter probes
                marker = b"RFHUNTERv2"
                written = 0
                for svc in client.services:
                    for char in svc.characteristics:
                        props = set(char.properties)
                        if "write" not in props and "write-without-response" not in props:
                            continue
                        # Skip classic HID report / bond management UUIDs that can brick UX
                        cu = str(char.uuid).lower()
                        if any(x in cu for x in ("2a4d", "2a4c", "2a4b", "2902")):
                            continue
                        try:
                            await client.write_gatt_char(
                                char.uuid,
                                marker,
                                response="write" in props,
                            )
                            written += 1
                            detail: dict[str, Any] = {
                                "uuid": str(char.uuid),
                                "marker": "RFHUNTERv2",
                                "bytes": marker.hex(),
                                "with_response": "write" in props,
                            }
                            if "read" in props:
                                try:
                                    back = await client.read_gatt_char(char.uuid)
                                    detail["readback_hex"] = back.hex()[:64]
                                    detail["readback_ascii"] = back.decode(
                                        "utf-8", errors="replace"
                                    )[:32]
                                    detail["marker_confirmed"] = marker in back or b"RFHUNTER" in back
                                except Exception as re:
                                    detail["readback_error"] = str(re)
                            vectors.append({
                                "name": "gatt_write_marker",
                                "success": True,
                                "severity": "critical",
                                "wow": True,
                                "finding": f"Wrote lab marker RFHUNTERv2 → {char.uuid}",
                                "detail": detail,
                            })
                            if written >= 3:
                                break
                        except Exception as e:
                            vectors.append({
                                "name": "gatt_write_marker",
                                "success": False,
                                "severity": "medium",
                                "finding": f"Writable but write rejected: {char.uuid}",
                                "detail": str(e),
                            })
                    if written >= 3:
                        break
                if written:
                    vectors.append({
                        "name": "rfhunter_marker",
                        "success": True,
                        "severity": "critical",
                        "wow": True,
                        "finding": f"Lab fingerprint planted on {written} char(s): RFHUNTERv2",
                        "detail": "Search device memory / GATT reads for ASCII RFHUNTERv2",
                    })

            if is_tuya:
                vectors.append({
                    "name": "tuya_pairing_hijack",
                    "success": True,
                    "severity": "critical",
                    "finding": "WOW: Tuya pairing window — WiFi creds + cloud token class",
                    "detail": "FD50/A201 fingerprint present — EZ-mode pairing class",
                    "wow": True,
                })

            # HID injection check
            for svc in client.services:
                if "1812" in str(svc.uuid).lower():
                    vectors.append({
                        "name": "hid_injection",
                        "success": True,
                        "severity": "critical",
                        "finding": "WOW: HID service exposed — keyboard injection class",
                        "detail": "CVE-2023-45866 class if host discoverable",
                        "wow": True,
                    })
    except Exception as e:
        vectors.append({
            "name": "ble_connect",
            "success": False,
            "severity": "info",
            "detail": str(e),
            "finding": "Device intermittent — retry closer / TV Bluetooth on",
        })

    # Real TV control is usually LAN remote API — always try for Samsung TVs
    if is_tv or is_samsung:
        try:
            vectors.extend(await samsung_mod.lan_probe_and_actuate(device))
        except Exception as e:
            vectors.append({
                "name": "samsung_lan_discover",
                "success": False,
                "severity": "info",
                "finding": "LAN probe error",
                "detail": str(e)[:200],
            })

    return vectors


def _has_rtl433() -> bool:
    from shutil import which
    return which("rtl_433") is not None

"""Samsung Smart TV lab probes — BLE identity + local remote API (:8001/:8002).

Authorized lab only. LAN actuation sends a single harmless KEY_VOLDOWN as proof-of-control
when the TV remote WebSocket accepts the session (may require on-screen Allow once).
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import socket
import time
from typing import Any
from urllib.request import Request, urlopen

from . import risk as risk_mod

_OCF_SVC = "ade3d529-c784-4f63-a987-eb69f70ee816"
_AV_UUID_MARKERS = ("110a", "110b", "110c", "111e", "1200")


def company_ids(device: dict[str, Any]) -> set[str]:
    meta = device.get("metadata") or {}
    out: set[str] = set()
    for k in (meta.get("manufacturer_data") or {}):
        out.add(str(k).lower())
    fp = meta.get("fingerprint") or {}
    for c in fp.get("company_ids") or []:
        out.add(str(c).lower())
    return out


def _has_samsung_company_id(device: dict[str, Any]) -> bool:
    for c in company_ids(device):
        c_norm = c.lower().replace("0x", "")
        if c_norm in ("75", "0075") or c in ("0x75", "0x0075"):
            return True
    return False


def is_samsung_family(device: dict[str, Any]) -> bool:
    """Samsung TV / appliance heuristic (company 0x75, name, fingerprint)."""
    name = str(device.get("name") or "")
    meta = device.get("metadata") or {}
    fp = meta.get("fingerprint") or {}
    if str(fp.get("matched_rule") or "").startswith("samsung"):
        return True
    if str(fp.get("vendor") or "").lower().startswith("samsung"):
        return True
    if re.search(r"(?i)\[TV\]|samsung|UE\d{2}|Q\d{2}\s*Series|Tizen", name):
        return True
    return _has_samsung_company_id(device)


def is_samsung_tv(device: dict[str, Any]) -> bool:
    name = str(device.get("name") or "")
    if re.search(r"(?i)\[TV\]|UE\d{2}|Q\d{2}\s*Series|Tizen\s*OS\s*TV", name):
        return True
    if is_samsung_family(device) and re.search(r"(?i)\btv\b", name):
        return True
    tid = str(device.get("device_type_id") or "")
    profile = str((device.get("metadata") or {}).get("attack_profile") or "")
    if tid == "smart_tv_bt" or profile in ("bt_av", "samsung_tv"):
        return is_samsung_family(device) and not re.search(
            r"(?i)washer|fridge|oven|dryer|dishwasher", name
        )
    return False


def ble_identity_vectors(device: dict[str, Any]) -> list[dict[str, Any]]:
    """Passive + metadata findings before/alongside GATT."""
    vectors: list[dict[str, Any]] = []
    leak = risk_mod.detect_mac_in_manufacturer_data(device)
    if leak:
        vectors.append(
            {
                "name": "samsung_mac_in_mfg",
                "success": True,
                "severity": "high",
                "wow": True,
                "finding": (
                    f"Samsung identity leak — BD_ADDR in manufacturer_data "
                    f"({leak.get('company_id')})"
                ),
                "detail": leak,
            }
        )
    meta = device.get("metadata") or {}
    mfg = meta.get("manufacturer_data") or {}
    if "0x75" in mfg or "0x0075" in mfg:
        payload = mfg.get("0x75") or mfg.get("0x0075") or ""
        vectors.append(
            {
                "name": "samsung_ble_advert",
                "success": True,
                "severity": "info",
                "finding": "Samsung company id 0x0075 advertisement present",
                "detail": {"payload_hex": str(payload)[:64], "len": len(str(payload)) // 2},
            }
        )
    return vectors


def summarize_gatt_services(client_services) -> dict[str, Any]:
    """Build a structured GATT map for Samsung TV lab reports."""
    services: list[dict[str, Any]] = []
    writable = 0
    av_hits: list[str] = []
    ocf = False
    hid = False
    for svc in client_services:
        su = str(svc.uuid).lower()
        chars = []
        for char in svc.characteristics:
            props = list(char.properties)
            if "write" in props or "write-without-response" in props:
                writable += 1
            chars.append({"uuid": str(char.uuid), "properties": props})
        services.append({"uuid": str(svc.uuid), "characteristics": chars})
        if any(m in su for m in _AV_UUID_MARKERS):
            av_hits.append(str(svc.uuid))
        if _OCF_SVC in su:
            ocf = True
        if "1812" in su:
            hid = True
    return {
        "service_count": len(services),
        "writable_count": writable,
        "av_services": av_hits,
        "ocf_coap_tunnel": ocf,
        "hid_1812": hid,
        "services": services[:20],
    }


def gatt_profile_vectors(gatt_map: dict[str, Any]) -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    vectors.append(
        {
            "name": "samsung_gatt_map",
            "success": True,
            "severity": "medium",
            "finding": (
                f"GATT map — {gatt_map.get('service_count', 0)} services, "
                f"{gatt_map.get('writable_count', 0)} writable"
            ),
            "detail": {
                k: gatt_map[k]
                for k in (
                    "service_count",
                    "writable_count",
                    "av_services",
                    "ocf_coap_tunnel",
                    "hid_1812",
                )
                if k in gatt_map
            },
        }
    )
    if gatt_map.get("av_services"):
        vectors.append(
            {
                "name": "samsung_av_profile",
                "success": True,
                "severity": "high",
                "wow": True,
                "finding": "Bluetooth AV / A2DP-class services exposed over BLE/GATT path",
                "detail": gatt_map["av_services"],
            }
        )
    if gatt_map.get("ocf_coap_tunnel"):
        vectors.append(
            {
                "name": "samsung_ocf_surface",
                "success": True,
                "severity": "high",
                "wow": True,
                "finding": "OCF/IoTivity CoAP-over-BLE request characteristic present",
                "detail": "Writes go to CoAP tunnel — not raw TV IR keys; map resources via OCF",
            }
        )
    # Honest lab guidance: real day-to-day control is usually LAN websocket
    vectors.append(
        {
            "name": "samsung_control_path",
            "success": True,
            "severity": "info",
            "finding": "Primary TV control path is usually LAN :8001/:8002 remote API (not BLE keys)",
            "detail": "Attack also probes SSDP + websocket for lab actuation",
        }
    )
    return vectors


def _local_ipv4s() -> list[str]:
    ips: list[str] = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip not in ips:
            ips.append(ip)
    except Exception:
        pass
    return ips


def _ssdp_search(timeout_s: float = 3.0) -> list[dict[str, str]]:
    """Discover Samsung RemoteControlReceiver via SSDP M-SEARCH."""
    msg = "\r\n".join(
        [
            "M-SEARCH * HTTP/1.1",
            "HOST: 239.255.255.250:1900",
            'MAN: "ssdp:discover"',
            "MX: 2",
            "ST: urn:samsung.com:device:RemoteControlReceiver:1",
            "",
            "",
        ]
    ).encode()
    found: dict[str, dict[str, str]] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(0.5)
    try:
        sock.sendto(msg, ("239.255.255.250", 1900))
        generic = msg.replace(
            b"urn:samsung.com:device:RemoteControlReceiver:1",
            b"ssdp:all",
        )
        sock.sendto(generic, ("239.255.255.250", 1900))
        end = time.time() + timeout_s
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            text = data.decode("utf-8", errors="replace")
            if "samsung" not in text.lower() and "RemoteControl" not in text:
                continue
            loc = ""
            for line in text.splitlines():
                if line.lower().startswith("location:"):
                    loc = line.split(":", 1)[1].strip()
            ip = addr[0]
            found[ip] = {"ip": ip, "location": loc, "from": "ssdp"}
    finally:
        sock.close()
    return list(found.values())


def _http_tv_api(ip: str, port: int = 8001, timeout: float = 2.5) -> dict[str, Any] | None:
    url = f"http://{ip}:{port}/api/v2/"
    try:
        req = Request(url, headers={"User-Agent": "RFHUNTERv2-lab"})
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body) if body.strip().startswith("{") else {"raw": body[:500]}
            return {"ip": ip, "port": port, "http_ok": True, "info": data}
    except Exception as e:
        return {"ip": ip, "port": port, "http_ok": False, "error": str(e)[:160]}


def _scan_subnet_ports(ports: tuple[int, ...] = (8001, 8002), limit: int = 64) -> list[dict[str, Any]]:
    """Quick TCP connect sweep of /24 for Samsung remote ports (lab LAN)."""
    hits: list[dict[str, Any]] = []
    for local in _local_ipv4s():
        parts = local.split(".")
        if len(parts) != 4:
            continue
        base = ".".join(parts[:3])
        # Prefer .1 gateway side and common DHCP range — sample evenly
        candidates = list(range(1, 255))
        # Prioritize own /24 last octet neighborhood
        own = int(parts[3])
        candidates.sort(key=lambda x: abs(x - own))
        checked = 0
        for last in candidates:
            if checked >= limit:
                break
            ip = f"{base}.{last}"
            if ip == local:
                continue
            checked += 1
            for port in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.12)
                    if s.connect_ex((ip, port)) == 0:
                        hits.append({"ip": ip, "port": port, "from": "tcp"})
                        s.close()
                        break
                    s.close()
                except Exception:
                    pass
        break  # one interface is enough for lab
    return hits


async def _ws_send_key(ip: str, port: int, key: str = "KEY_VOLDOWN") -> dict[str, Any]:
    """Send one remote key via Samsung TV websocket API (lab proof)."""
    try:
        import websockets  # type: ignore
    except ImportError:
        # Fallback: raw HTTP won't work for keys; report dependency
        return {"ok": False, "error": "websockets package missing"}

    name_b64 = base64.b64encode(b"RFHUNTERv2").decode()
    # Try token-less path first; newer Tizen may need token from prior pairing
    paths = [
        f"/api/v2/channels/samsung.remote.control?name={name_b64}",
        f"/api/v2/channels/samsung.remote.control?name={name_b64}&token=0",
    ]
    last_err = ""
    for path in paths:
        uri = f"ws://{ip}:{port}{path}"
        try:
            async with websockets.connect(
                uri, open_timeout=3, close_timeout=2, ping_interval=None
            ) as ws:
                # Some TVs push ms.channel.connect first
                try:
                    hello = await asyncio.wait_for(ws.recv(), timeout=2.5)
                except Exception:
                    hello = ""
                payload = {
                    "method": "ms.remote.control",
                    "params": {
                        "Cmd": "Click",
                        "DataOfCmd": key,
                        "Option": "false",
                        "TypeOfRemote": "SendRemoteKey",
                    },
                }
                await ws.send(json.dumps(payload))
                try:
                    reply = await asyncio.wait_for(ws.recv(), timeout=2.0)
                except Exception:
                    reply = ""
                return {
                    "ok": True,
                    "ip": ip,
                    "port": port,
                    "key": key,
                    "hello": str(hello)[:300],
                    "reply": str(reply)[:300],
                    "uri": uri,
                }
        except Exception as e:
            last_err = str(e)[:200]
            continue
    return {"ok": False, "ip": ip, "port": port, "error": last_err or "connect failed"}


async def lan_probe_and_actuate(device: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Discover lab Samsung TVs on LAN and send one KEY_VOLDOWN as proof-of-control."""
    vectors: list[dict[str, Any]] = []
    hosts: dict[str, dict[str, Any]] = {}

    for h in await asyncio.to_thread(_ssdp_search, 3.0):
        hosts[h["ip"]] = h
    for h in await asyncio.to_thread(_scan_subnet_ports, (8001, 8002), 48):
        hosts.setdefault(h["ip"], {**h, "port": h.get("port") or 8001})

    if not hosts:
        vectors.append(
            {
                "name": "samsung_lan_discover",
                "success": False,
                "severity": "info",
                "finding": "No Samsung remote API hosts on LAN (SSDP/TCP :8001/:8002)",
                "detail": "Ensure TV is ON + same Wi‑Fi/LAN as hunter (host network)",
            }
        )
        return vectors

    vectors.append(
        {
            "name": "samsung_lan_discover",
            "success": True,
            "severity": "high",
            "wow": True,
            "finding": f"Found {len(hosts)} Samsung remote candidate(s) on LAN",
            "detail": list(hosts.values())[:8],
        }
    )

    actuated = False
    for ip, meta in list(hosts.items())[:6]:
        port = int(meta.get("port") or 8001)
        info = await asyncio.to_thread(_http_tv_api, ip, port)
        if info and info.get("http_ok"):
            name = ""
            try:
                raw = info.get("info") or {}
                name = (raw.get("device") or {}).get("name") or raw.get("name") or ""
            except Exception:
                name = ""
            vectors.append(
                {
                    "name": "samsung_lan_api",
                    "success": True,
                    "severity": "critical",
                    "wow": True,
                    "finding": f"TV remote HTTP API open — {ip}:{port}"
                    + (f" ({name})" if name else ""),
                    "detail": info,
                }
            )
            if not actuated:
                result = await _ws_send_key(ip, port, "KEY_VOLDOWN")
                if result.get("ok"):
                    actuated = True
                    vectors.append(
                        {
                            "name": "samsung_lab_key",
                            "success": True,
                            "severity": "critical",
                            "wow": True,
                            "finding": f"Lab actuation — sent KEY_VOLDOWN to {ip}:{port}",
                            "detail": result,
                        }
                    )
                else:
                    vectors.append(
                        {
                            "name": "samsung_lab_key",
                            "success": False,
                            "severity": "high",
                            "finding": (
                                f"Remote API up but key send blocked — approve "
                                f"'RFHUNTERv2' on TV ({ip})"
                            ),
                            "detail": result,
                        }
                    )
        else:
            vectors.append(
                {
                    "name": "samsung_lan_api",
                    "success": False,
                    "severity": "medium",
                    "finding": f"Host candidate but /api/v2/ failed — {ip}:{port}",
                    "detail": info,
                }
            )
    return vectors

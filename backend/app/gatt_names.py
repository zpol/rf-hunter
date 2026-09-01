"""Well-known Bluetooth SIG 16-bit UUID short names (services + characteristics)."""

from __future__ import annotations

# Subset of assigned numbers — enough for lab triage labels
_SIG_NAMES: dict[str, str] = {
    # Services
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    "180a": "Device Information",
    "180f": "Battery Service",
    "1812": "Human Interface Device",
    "1815": "Bond Management",
    "181c": "User Data",
    "181e": "Bond Management",
    "1822": "Pulse Oximeter",
    "1843": "Audio Input Control",
    "1844": "Volume Control",
    "1845": "Volume Offset Control",
    "1846": "Coordinated Set Identification",
    "1848": "Media Control",
    "1849": "Microphone Control",
    "1850": "Audio Stream Control",
    "1851": "Broadcast Audio Scan",
    "1853": "Published Audio Capabilities",
    "1855": "Common Audio",
    "1858": "Telephone Bearer",
    "1859": "Generic Telephone Bearer",
    "185a": "Microphone Control",
    "185b": "Audio Stream Control",
    "fe59": "Nordic DFU",
    "fe95": "Xiaomi Mi",
    "fd50": "Tuya",
    "110a": "Audio Source",
    "110b": "Audio Sink",
    "110c": "A/V Remote Control Target",
    "111e": "Handsfree",
    "1200": "PnP Information",
    # Characteristics
    "2a00": "Device Name",
    "2a01": "Appearance",
    "2a04": "Peripheral Preferred Connection Parameters",
    "2a05": "Service Changed",
    "2a19": "Battery Level",
    "2a23": "System ID",
    "2a24": "Model Number String",
    "2a25": "Serial Number String",
    "2a26": "Firmware Revision String",
    "2a27": "Hardware Revision String",
    "2a28": "Software Revision String",
    "2a29": "Manufacturer Name String",
    "2a4a": "HID Information",
    "2a4b": "Report Map",
    "2a4c": "HID Control Point",
    "2a4d": "Report",
    "2a4e": "Protocol Mode",
    "2a50": "PnP ID",
    "2b29": "Client Supported Features",
    "2b3a": "Server Supported Features",
    "2b3c": "Volume State",
    "2b3e": "Volume Offset State",
    "2b3f": "Audio Input State",
    "2b7d": "Volume Control Point",
    "2b7e": "Volume Flags",
    "2b7f": "Volume Offset Control Point",
    "2b80": "Audio Input Control Point",
    "2b84": "Audio Input Description",
    "2b98": "Status Flags",
    "2b99": "Set Identity Resolving Key",
    "2b9a": "Size Characteristic",
    "2b9b": "Lock Characteristic",
    "2b9c": "Rank",
    "2bc4": "Sink ASE",
    "2bc5": "Source ASE",
    "2bc6": "ASE Control Point",
    "2bc8": "Sink PAC",
    "2bc9": "Sink Audio Locations",
    "2bca": "Source PAC",
    "2bcb": "Source Audio Locations",
    "2bcc": "Available Audio Contexts",
    "2bcd": "Supported Audio Contexts",
    "2bba": "Bearer Provider Name",
    "2bbb": "Bearer UCI",
    "2bbc": "Bearer Technology",
    "2bbd": "Bearer URI Schemes Supported List",
    "2bbe": "Bearer Signal Strength",
    "2bbf": "Bearer Signal Strength Reporting Interval",
    "2bc0": "Bearer List Current Calls",
    "2bc1": "Content Control ID",
    "2bc2": "Status Flags",
    "2bc3": "Incoming Call Target Bearer URI",
    "2bc7": "Call Control Point",
    "2bd1": "Call Control Point Optional Opcodes",
    "2bd4": "Incoming Call",
    "2bd5": "Call Friendly Name",
}


def short_uuid(uuid_str: str) -> str | None:
    """Extract 16-bit assigned number from a 128-bit Bluetooth base UUID, if any."""
    u = (uuid_str or "").lower().strip()
    if not u:
        return None
    # Compact form
    compact = u.replace("-", "")
    # Standard base: 0000XXXX-0000-1000-8000-00805f9b34fb
    if len(compact) == 32 and compact.startswith("0000") and compact.endswith("00001000800000805f9b34fb"):
        return compact[4:8]
    parts = u.split("-")
    if len(parts) == 5 and parts[0].startswith("0000") and len(parts[0]) == 8:
        if parts[1:] == ["0000", "1000", "8000", "00805f9b34fb"]:
            return parts[0][4:8]
    # Already a 16-bit hex
    if len(u) == 4 and all(c in "0123456789abcdef" for c in u):
        return u
    return None


def label_uuid(uuid_str: str, description: str | None = None) -> str:
    """Human label: optional bleak description, else SIG name, else short hex."""
    desc = (description or "").strip()
    if desc and desc.lower() not in ("unknown", "none"):
        return desc
    short = short_uuid(uuid_str)
    if short and short in _SIG_NAMES:
        return _SIG_NAMES[short]
    if short:
        return f"0x{short}"
    return "vendor"


def format_uuid_line(
    uuid_str: str,
    *,
    description: str | None = None,
    properties: list[str] | None = None,
    service_uuid: str | None = None,
    extra: str | None = None,
) -> str:
    """One-line evidence entry for findings UI."""
    name = label_uuid(uuid_str, description)
    bits = [f"{name}", str(uuid_str)]
    props = [p for p in (properties or []) if p]
    if props:
        bits.append(",".join(props))
    if service_uuid:
        svc_name = label_uuid(service_uuid)
        bits.append(f"svc {svc_name} ({service_uuid})")
    if extra:
        bits.append(extra)
    return " · ".join(bits)

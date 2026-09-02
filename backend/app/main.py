from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Literal

from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import (
    attack,
    audio_listen,
    catalog,
    clone_presets,
    deep_dive,
    export,
    gps,
    monitor,
    replay,
    scanner,
    tracker,
    tpms_decode,
    tx_safety,
    vuln_scan,
    wifi_scanner,
    wow,
    radio,
)

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    n = tracker.tracker.load()
    if n:
        print(f"[rf-hunter] restored {n} tracked device(s) from disk (GPS pins kept)", flush=True)
    gps.gps.start()
    wifi_info = wifi_scanner.wifi.start()
    print(
        f"[rf-hunter] wifi scan on {wifi_info.get('iface') or '?'} status={wifi_info.get('status')}",
        flush=True,
    )
    try:
        yield
    finally:
        wifi_scanner.wifi.stop()
        tracker.tracker.persist(force=True)
        gps.gps.stop()


app = FastAPI(
    title="RF Hunter v2",
    version="2.1.0",
    description="Wardriving RF lab scanner — HackRF + BLE + GPS",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    device_type_ids: list[str] = Field(default_factory=list)
    duration_s: int = Field(30, ge=5, le=600)
    lna_db: int = Field(32, ge=0, le=40)
    vga_db: int = Field(36, ge=0, le=62)
    passes: int = Field(40, ge=2, le=500)
    mode: Literal["once", "wardrive", "full_sweep"] = "wardrive"
    live_decode: bool = True
    clear_results: bool = False  # False = keep tracked devices across stop/start
    exclude_fm_broadcast: bool = False


class TargetRequest(BaseModel):
    device: dict[str, Any]


class MonitorRequest(BaseModel):
    device: dict[str, Any] | None = None
    device_key: str | None = None


class VulnScanRequest(BaseModel):
    mode: Literal["quick", "full"] = "quick"
    device_keys: list[str] | None = None


class ReplayListenRequest(BaseModel):
    device: dict[str, Any]
    duration_s: int = Field(8, ge=4, le=30)
    lna_db: int = Field(24, ge=0, le=40)
    vga_db: int = Field(28, ge=0, le=62)


class AudioListenRequest(BaseModel):
    device: dict[str, Any]
    duration_s: int = Field(8, ge=3, le=20)


class ReplayTxRequest(BaseModel):
    capture_id: str
    confirm: bool = False
    tx_gain: int = Field(20, ge=0, le=47)
    iq_source: Literal["auto", "best", "burst", "full"] = "burst"
    use_corrected_freq: bool = True
    repeats: int = Field(1, ge=1, le=5)


class TpmsDecodeAllRequest(BaseModel):
    max_devices: int = Field(16, ge=1, le=40)
    skip_decoded: bool = True
    band: Literal["all", "us", "eu"] = "all"
    force: bool = False


class TxArmRequest(BaseModel):
    armed: bool
    note: str = ""


class CloneSpectrumRequest(BaseModel):
    preset_id: str | None = None
    freq_mhz: float | None = None
    span_mhz: float | None = None


class CloneHuntRequest(BaseModel):
    hold_s: float = Field(8.0, ge=4.0, le=20.0)


@app.get("/api/health")
def health() -> dict:
    radio_status = radio.status()
    hackrf = radio_status["available"].get("hackrf", False)
    tx_status = tx_safety.status()
    if not radio_status.get("tx_capable") and tx_status.get("armed"):
        tx_status = tx_safety.set_armed(False, "Auto-disarmed: selected receiver is RX-only")
    return {
        "status": "ok",
        "version": "2.2.0",
        "hackrf": hackrf,
        "radio": radio_status,
        "scan_status": scanner.session.status,
        "scan_mode": scanner.session.mode,
        "monitor_status": monitor.monitor.status,
        "vuln_status": vuln_scan.vuln_scan.status,
        "tracked": len(tracker.tracker.snapshot()),
        "tx_armed": tx_status["armed"],
        "scan_paused": scanner.session.is_paused(),
        "gps": gps.gps.status_dict(),
        "wifi": wifi_scanner.wifi.status_dict(),
    }


def _hackrf_ok() -> bool:
    return bool(radio.available_backends(probe=True).get("hackrf"))


@app.get("/api/catalog")
def get_catalog() -> dict:
    types = catalog.get_device_types()
    radio_status = radio.status()
    selected = radio_status.get("selected")
    limits = radio_status.get("frequency_range_mhz")
    for t in types:
        if t.get("id") == "full_spectrum" and selected == "rtl_sdr" and limits:
            lo, hi = limits
            t["name"] = f"Full spectrum (RTL-SDR {lo:g}–{hi:g} MHz)"
            t["description"] = "Full receive-range survey using rtl_power"
        t["wow"] = wow.wow_info({
            "metadata": {"attack_profile": t.get("attack_profile")},
            "attack_profile": t.get("attack_profile"),
        })
    return {
        "categories": catalog.get_categories(),
        "device_types": types,
        "wow_type_ids": wow.wow_catalog_type_ids(),
        "wow_ble_type_ids": wow.wow_ble_type_ids(),
    }


@app.get("/api/scan/status")
def scan_status() -> dict:
    s = scanner.session
    return {
        "session_id": s.session_id,
        "status": s.status,
        "mode": s.mode,
        "progress": s.progress,
        "pass_count": s.pass_count,
        "message": s.message,
        "current_band": s.current_band,
        "band_index": s.band_index,
        "band_total": s.band_total,
        "devices": [wow.enrich(d) for d in tracker.tracker.snapshot()],
        "logs": s.logs[-50:],
        "vuln": vuln_scan.vuln_scan.status_dict(),
    }


@app.get("/api/tracker")
def api_tracker() -> dict:
    data = tracker.tracker.to_dict()
    data["devices"] = [wow.enrich(d) for d in data.get("devices") or []]
    return data


@app.post("/api/tracker/clear")
def tracker_clear() -> dict:
    """Stop any running jobs and wipe tracked devices (fresh start)."""
    from datetime import datetime, timezone

    from .procutil import pkill_rf_tools

    scanner.session.stop()
    monitor.monitor.stop()
    vuln_scan.vuln_scan.stop()
    killed = pkill_rf_tools()
    n = len(tracker.tracker.snapshot())
    tracker.tracker.clear()
    gps.gps.clear_trail()
    # Stop Wi-Fi scan too — otherwise iw loop refills APs within seconds.
    wifi_scanner.wifi.stop()
    wifi_scanner.wifi.clear_and_notify()
    scanner.session.devices = []
    scanner.session.message = "Cleared — ready for a new wardrive"
    if scanner.session.status in ("running", "stopping", "stopped", "completed"):
        scanner.session.status = "idle"
    snap = tracker.tracker.to_dict()
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    scanner.session._emit({"type": "tracker_snapshot", **snap})
    scanner.session._emit({
        "type": "log",
        "message": f"[{ts}] Cleanup — removed {n} device(s)",
    })
    return {"ok": True, "cleared": n, "killed": killed, **snap}


@app.get("/api/stats")
def api_stats() -> dict:
    return vuln_scan.dashboard_stats()


@app.post("/api/scan/start")
def scan_start(req: ScanRequest) -> dict:
    if scanner.session.is_running():
        return {"ok": False, "error": "Scan already running"}
    if vuln_scan.vuln_scan.is_running():
        return {"ok": False, "error": "Vuln scan running — stop it first"}
    ids = list(req.device_type_ids or [])
    if req.mode == "full_sweep":
        ids = ["full_spectrum"]
    elif not ids:
        return {"ok": False, "error": "Select at least one device type (or use Full sweep)"}
    if req.clear_results:
        gps.gps.clear_trail()
    try:
        sid = scanner.session.start(
            ids,
            req.duration_s,
            req.lna_db,
            req.vga_db,
            req.passes,
            mode=req.mode,
            live_decode=req.live_decode and req.mode != "full_sweep",
            clear_results=req.clear_results,
            exclude_fm_broadcast=req.exclude_fm_broadcast,
        )
    except RuntimeError as exc:
        return {"ok": False, "error": str(exc)}
    kept = len(tracker.tracker.snapshot())
    return {
        "ok": True,
        "session_id": sid,
        "mode": req.mode,
        "live_decode": req.live_decode and req.mode != "full_sweep",
        "clear_results": req.clear_results,
        "exclude_fm_broadcast": req.exclude_fm_broadcast and req.mode == "full_sweep",
        "tracked": kept,
    }


@app.post("/api/scan/stop")
def scan_stop() -> dict:
    """Stop wardrive/scan, monitor, vuln, and Wi‑Fi — force-kill RF tools."""
    scanner.session.stop()
    monitor.monitor.stop()
    vuln_scan.vuln_scan.stop()
    wifi_scanner.wifi.stop()
    wifi_scanner.wifi.clear_and_notify()
    # Extra pkill in case a child escaped tracking
    from .procutil import pkill_rf_tools

    killed = pkill_rf_tools()
    return {
        "ok": True,
        "scan": scanner.session.status,
        "monitor": monitor.monitor.status,
        "vuln": vuln_scan.vuln_scan.status,
        "wifi": wifi_scanner.wifi.status_dict().get("status"),
        "killed": killed,
    }


@app.post("/api/stop-all")
def stop_all() -> dict:
    return scan_stop()


@app.post("/api/monitor/start")
def monitor_start(req: MonitorRequest) -> dict:
    device = req.device
    if device is None and req.device_key:
        device = tracker.tracker.get(req.device_key)
    if not device:
        return {"ok": False, "error": "Device not found"}
    return monitor.monitor.start(device)


@app.post("/api/monitor/stop")
def monitor_stop() -> dict:
    monitor.monitor.stop()
    return {"ok": True, "status": monitor.monitor.status}


@app.get("/api/monitor/status")
def monitor_status() -> dict:
    m = monitor.monitor
    return {
        "status": m.status,
        "device_key": m.device_key,
        "last_sample": m.last_sample,
    }


@app.get("/api/tpms/stats")
def api_tpms_stats() -> dict:
    snap = tracker.tracker.snapshot()
    inv = tpms_decode.tpms_inventory(snap)
    return {"ok": True, **inv}


@app.post("/api/tpms/decode-all")
def api_tpms_decode_all(req: TpmsDecodeAllRequest) -> dict:
    """Bulk deep-dive ranked TPMS targets to extract pressure/temp/ID."""
    if scanner.session.is_running():
        return {"ok": False, "error": "Stop wardrive first — HackRF is busy"}
    if vuln_scan.vuln_scan.is_running():
        return {"ok": False, "error": "Another scan is already running — stop it first"}
    if monitor.monitor.status == "running":
        monitor.monitor.stop()

    snap = tracker.tracker.snapshot()
    inv = tpms_decode.tpms_inventory(snap)
    targets = tpms_decode.select_tpms_targets(
        snap,
        max_devices=req.max_devices,
        skip_decoded=(req.skip_decoded and not req.force),
        band=req.band,
    )
    if not targets:
        return {
            "ok": False,
            "error": (
                "No TPMS candidates to decode "
                f"(tracked={inv['tracked']}, decoded={inv['decoded']}). "
                "Wardrive tpms_us/tpms_eu first, or set force=true."
            ),
            **inv,
        }

    keys = [d.get("key") or tracker.device_key(d) for d in targets]
    started = vuln_scan.vuln_scan.start(
        mode="full",
        device_keys=keys,
        label="TPMS decode",
    )
    if not started.get("ok"):
        return started
    return {
        "ok": True,
        "total": started["total"],
        "selected": len(keys),
        "keys": keys,
        "candidates": [
            {
                "key": d.get("key"),
                "freq_mhz": d.get("freq_mhz"),
                "device_type_id": d.get("device_type_id"),
                "snr_db": d.get("snr_db"),
                "signal_level": d.get("signal_level"),
            }
            for d in targets
        ],
        **inv,
        "message": (
            f"Decoding {len(keys)} TPMS target(s) "
            f"(~{len(keys) * 20}s worst-case). Stop with Stop all."
        ),
    }


@app.post("/api/vuln-scan/start")
def vuln_scan_start(req: VulnScanRequest) -> dict:
    if scanner.session.is_running():
        return {"ok": False, "error": "Stop wardrive first (HackRF busy)"}
    return vuln_scan.vuln_scan.start(mode=req.mode, device_keys=req.device_keys)


@app.post("/api/vuln-scan/stop")
def vuln_scan_stop() -> dict:
    vuln_scan.vuln_scan.stop()
    return {"ok": True}


@app.get("/api/vuln-scan/status")
def vuln_scan_status() -> dict:
    return vuln_scan.vuln_scan.status_dict()


@app.get("/api/export/devices.csv")
def api_export_csv():
    from fastapi.responses import Response

    devices = [wow.enrich(d) for d in tracker.tracker.snapshot()]
    csv_text = export.tracker_to_csv(devices)
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=rf-hunter-devices.csv"},
    )


@app.get("/api/export/devices.json")
def api_export_json() -> dict:
    devices = [wow.enrich(d) for d in tracker.tracker.snapshot()]
    return export.tracker_to_json(devices)


@app.get("/api/captures")
def api_captures(limit: int = 40) -> dict:
    return {"ok": True, "captures": export.list_captures(limit=limit)}


@app.get("/api/artifact/{dive_id}/{filename}")
def api_artifact(dive_id: str, filename: str):
    """Serve a capture artifact (e.g. FPV frame PNG, FM WAV)."""
    from .deep_dive import CAPTURES as DIVE_CAPTURES

    safe_id = dive_id.replace("..", "").replace("/", "")
    safe_name = Path(filename).name
    path = DIVE_CAPTURES / safe_id / safe_name
    if not path.is_file():
        return {"ok": False, "error": "not found"}
    media = None
    if safe_name.lower().endswith(".wav"):
        media = "audio/wav"
    elif safe_name.lower().endswith(".png"):
        media = "image/png"
    return FileResponse(path, media_type=media)


@app.get("/api/tx/status")
def api_tx_status() -> dict:
    selected = radio.selected_backend(probe=True)
    state = tx_safety.status()
    if selected != "hackrf" and state.get("armed"):
        state = tx_safety.set_armed(False, "Auto-disarmed: selected receiver is RX-only")
    return {
        "ok": True,
        "tx_capable": selected == "hackrf",
        "radio_backend": selected,
        **state,
    }


@app.get("/api/gps/status")
def api_gps_status() -> dict:
    return {"ok": True, **gps.gps.status_dict()}


@app.get("/api/gps/trail")
def api_gps_trail(limit: int = 500) -> dict:
    return {
        "ok": True,
        "fix": gps.gps.current(),
        "trail": gps.gps.trail(limit=limit),
    }


@app.post("/api/gps/trail/clear")
def api_gps_trail_clear() -> dict:
    gps.gps.clear_trail()
    return {"ok": True}


@app.get("/api/wifi/status")
def api_wifi_status() -> dict:
    return {"ok": True, **wifi_scanner.wifi.status_dict()}


@app.get("/api/wifi/aps")
def api_wifi_aps(limit: int = 200) -> dict:
    aps = wifi_scanner.wifi.snapshot()[: max(1, min(limit, 500))]
    return {
        "ok": True,
        "count": len(aps),
        "aps": aps,
        **{k: v for k, v in wifi_scanner.wifi.status_dict().items() if k != "ifaces"},
        "ifaces": wifi_scanner.wifi.status_dict().get("ifaces"),
    }


@app.post("/api/wifi/start")
def api_wifi_start(iface: str | None = None) -> dict:
    return {"ok": True, **wifi_scanner.wifi.start(iface)}


@app.post("/api/wifi/stop")
def api_wifi_stop() -> dict:
    wifi_scanner.wifi.stop()
    # Freeze UI: drop any APs that an in-flight iw was about to push.
    wifi_scanner.wifi.clear_and_notify()
    return {"ok": True, **wifi_scanner.wifi.status_dict()}


@app.post("/api/wifi/clear")
def api_wifi_clear() -> dict:
    wifi_scanner.wifi.clear_and_notify()
    return {"ok": True, "cleared": True}


@app.post("/api/tx/arm")
def api_tx_arm(req: TxArmRequest) -> dict:
    selected = radio.selected_backend(probe=True)
    if req.armed and selected != "hackrf":
        state = tx_safety.set_armed(False, f"TX rejected: {selected or 'no receiver'} is RX-only")
        return {
            "ok": False,
            "error": "TX requires an active HackRF; RTL-SDR is receive-only",
            "tx_capable": False,
            "radio_backend": selected,
            **state,
        }
    return {"ok": True, **tx_safety.set_armed(req.armed, req.note)}


@app.post("/api/deep-dive")
def api_deep_dive(req: TargetRequest) -> dict:
    result = deep_dive.deep_dive(req.device)
    key = tracker.device_key(req.device)
    entry = tracker.tracker.get(key)
    if entry:
        enriched = wow.enrich(entry)
        scanner.session._emit({"type": "device_update", "device": enriched})
        scanner.session._emit({
            "type": "tracker_snapshot",
            "count": len(tracker.tracker.snapshot()),
            "devices": [wow.enrich(d) for d in tracker.tracker.snapshot()],
        })
    return result


@app.get("/api/replay/compare")
def api_replay_compare(lo_mhz: float = 280.0, hi_mhz: float = 320.0, limit: int = 24) -> dict:
    """Compare CAP IQ in a band — rank strong vs weak and find shared PWM hex."""
    from . import capture_compare

    return capture_compare.compare_band(lo_mhz, hi_mhz, limit=limit)


@app.post("/api/replay/listen")
def api_replay_listen(req: ReplayListenRequest) -> dict:
    """SDR RX on target frequency — capture IQ and optionally decode it."""
    if scanner.session.is_running():
        return {"ok": False, "error": "Stop wardrive first — the SDR receiver is busy"}
    if monitor.monitor.status == "running":
        monitor.monitor.stop()
    return replay.listen(
        req.device,
        duration_s=req.duration_s,
        lna_db=req.lna_db,
        vga_db=req.vga_db,
    )


@app.post("/api/listen/audio")
def api_listen_audio(req: AudioListenRequest) -> dict:
    """HackRF RX → FM demod WAV (browser playback). Pauses wardrive while capturing."""
    if monitor.monitor.status == "running":
        monitor.monitor.stop()
    return audio_listen.listen_fm(req.device, duration_s=req.duration_s)


@app.post("/api/replay/transmit")
def api_replay_transmit(req: ReplayTxRequest) -> dict:
    """Retransmit a captured IQ (requires confirm=true)."""
    if scanner.session.is_running():
        return {"ok": False, "error": "Stop wardrive first — HackRF is busy"}
    if monitor.monitor.status == "running":
        monitor.monitor.stop()
    return replay.transmit(
        req.capture_id,
        confirm=req.confirm,
        tx_gain=req.tx_gain,
        iq_source=req.iq_source,
        use_corrected_freq=req.use_corrected_freq,
        repeats=req.repeats,
    )


@app.post("/api/replay/{capture_id}/reanalyze")
def api_replay_reanalyze(capture_id: str) -> dict:
    """Recompute freq offset / best burst / AM WAV for an existing CAP."""
    return replay.reanalyze_capture(capture_id)


@app.get("/api/replay/{capture_id}")
def api_replay_get(capture_id: str) -> dict:
    meta = replay.get_capture(capture_id)
    if not meta:
        return {"ok": False, "error": "not found"}
    return {"ok": True, **meta}


@app.get("/api/clone/presets")
def api_clone_presets() -> dict:
    return {"ok": True, "presets": clone_presets.list_presets()}


@app.post("/api/clone/spectrum")
def api_clone_spectrum(req: CloneSpectrumRequest) -> dict:
    """Narrow hackrf_sweep for RF CLONE live analyzer."""
    if scanner.session.is_running():
        return {"ok": False, "error": "Stop wardrive first — HackRF is busy"}
    if monitor.monitor.status == "running":
        monitor.monitor.stop()
    return clone_presets.spectrum(
        preset_id=req.preset_id,
        freq_mhz=req.freq_mhz,
        span_mhz=req.span_mhz,
    )


@app.post("/api/clone/hunt")
def api_clone_hunt(req: CloneHuntRequest) -> dict:
    """Wide max-hold hunt — press the remote repeatedly during the window."""
    if scanner.session.is_running():
        return {"ok": False, "error": "Stop wardrive first — HackRF is busy"}
    if monitor.monitor.status == "running":
        monitor.monitor.stop()
    return clone_presets.hunt(hold_s=req.hold_s)


@app.post("/api/attack")
def api_attack(req: TargetRequest) -> dict:
    result = attack.attack_device(req.device)
    result["wow"] = wow.wow_info(req.device)
    sev = "low"
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for v in result.get("vectors") or []:
        s = (v.get("severity") or "info").lower()
        if rank.get(s, 0) > rank.get(sev, 0):
            sev = s if s != "info" else sev
    if result.get("exploitability") == "HIGH":
        sev = "critical"
    key = tracker.device_key(req.device)
    risk = {
        "status": sev,
        "severity": sev,
        "summary": result.get("risk_summary") or [],
        "findings": [
            {
                "severity": v.get("severity") or "info",
                "finding": v.get("finding") or v.get("name"),
                "detail": str(v.get("detail") or "")[:200],
            }
            for v in (result.get("vectors") or [])
            if v.get("finding") or v.get("success")
        ],
        "exploitability": result.get("exploitability"),
        "source": "attack",
    }
    tracker.tracker.set_risk(key, sev, risk)
    entry = tracker.tracker.get(key)
    if entry:
        enriched = wow.enrich(entry)
        scanner.session._emit({"type": "device_update", "device": enriched})
        scanner.session._emit({
            "type": "tracker_snapshot",
            "count": len(tracker.tracker.snapshot()),
            "devices": [wow.enrich(d) for d in tracker.tracker.snapshot()],
        })
    return result


@app.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket) -> None:
    await websocket.accept()
    queue: asyncio.Queue[dict] = asyncio.Queue()

    def on_event(ev: dict) -> None:
        try:
            queue.put_nowait(ev)
        except Exception:
            pass

    scanner.session.subscribe(on_event)
    monitor.monitor.subscribe(on_event)
    vuln_scan.vuln_scan.subscribe(on_event)
    gps.gps.subscribe(on_event)
    wifi_scanner.wifi.subscribe(on_event)

    snap = tracker.tracker.to_dict()
    snap["devices"] = [wow.enrich(d) for d in snap.get("devices") or []]
    await websocket.send_json({"type": "tracker_snapshot", **snap})
    await websocket.send_json({"type": "stats", **vuln_scan.dashboard_stats()})
    await websocket.send_json({"type": "gps_status", **gps.gps.status_dict()})
    await websocket.send_json({
        "type": "gps_trail",
        "trail": gps.gps.trail(),
        "fix": gps.gps.current(),
    })
    await websocket.send_json({"type": "wifi_status", **wifi_scanner.wifi.status_dict()})
    await websocket.send_json({
        "type": "wifi_snapshot",
        "aps": wifi_scanner.wifi.snapshot(),
        "count": len(wifi_scanner.wifi.snapshot()),
        "iface": wifi_scanner.wifi.status_dict().get("iface"),
    })

    async def sender() -> None:
        while True:
            ev = await queue.get()
            await websocket.send_json(ev)

    task = asyncio.create_task(sender())
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        task.cancel()


@app.get("/")
def index() -> FileResponse:
    return FileResponse(FRONTEND / "index.html")


if FRONTEND.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND), name="static")

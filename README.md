# RF Hunter

**RF security research platform for authorized lab use** — wardrive-style scanning with HackRF or RTL-SDR, BLE, GPS-backed map, optional Wi‑Fi correlation, live monitoring, protocol decode, and RF replay workflows.

Dual interface: **web dashboard** (FastAPI + static frontend) and **terminal UI** (Textual). Built for field labs, capture triage, and structured device tracking — not for unauthorized spectrum use.

> Use only on networks, devices, and frequency bands you own or have explicit written permission to test.

---

## Screenshots

| Web UI — wardrive map & live tracker | Web UI — device focus & decode |
|:---:|:---:|
| ![Wardrive map](doc/webui-screenshot1.png) | ![Device focus](doc/webui-screenshot2.png) |

| Web UI — scan & triage | Web UI — RF clone / replay lab |
|:---:|:---:|
| ![Scan triage](doc/webui-screenshot3.png) | ![RF clone lab](doc/webui-screenshot5.png) |

| Terminal UI (TUI) |
|:---:|
| ![RF Hunter TUI](doc/tui-screenshot.png) |

---

## What it detects

Device types are driven by [`backend/data/device_catalog.yaml`](backend/data/device_catalog.yaml). The scanner sweeps catalog bands, upserts hits into a live tracker, and runs decode / fingerprint pipelines where supported.

| Category | Device types | Typical bands | Capability |
|----------|--------------|---------------|------------|
| **Automotive** | TPMS EU (433.92 MHz), TPMS US (315 MHz) | 315 / 433 MHz | Decode sensor IDs, pressure, temperature |
| **Access & remotes** | Garage / gate 433 MHz, US 315 MHz remotes, wireless alarms 869 MHz | 315 / 433 / 869 MHz | Presence, rtl_433-class decode, RF replay lab |
| **IoT & smart home** | LoRa / LoRaWAN EU868, home automation 868 MHz, Tuya BLE, generic BLE sensors, weather stations 433 MHz, Wi‑Fi / Zigbee 2.4 GHz | 433 / 868 / 2.4 GHz + BLE | Decode (433/868), BLE GATT map, presence |
| **Industrial / telemetry** | UHF telemetry ~360 MHz, telemetry 1690 MHz, POCSAG pagers, full spectrum survey | 169–470 / 360 / 1690 MHz / receiver range | Decode (POCSAG, rtl_433), spectrum presence |
| **Comms & AV** | PMR446 / FRS, DECT phones, L‑band wireless AV, Smart TV / audio BLE, APRS 144 MHz | 144 / 446 / 1.2 GHz / 1.8 GHz + BLE | Presence, BLE identity, LAN remote hints |
| **Aviation** | ADS‑B 1090 MHz, ACARS VHF, FPV video 5.8 GHz | 131 / 1090 / 5.8 GHz | ADS‑B decode + map pins, FPV frame detect |
| **Maritime** | AIS ships 162 MHz, EPIRB / ELT 406 MHz | 162 / 406 MHz | AIS presence, distress beacon presence |

**Capability legend**

- **Decode** — structured frames or identifiers (TPMS, ADS‑B, rtl_433, POCSAG, BLE GATT, etc.)
- **BLE** — Bluetooth advertisement + optional GATT / manufacturer data
- **Presence** — energy / burst detection and band classification without full protocol parse

Fingerprinting uses OUI, BLE company IDs, and YAML rules to refine vendor and device class beyond raw spectrum hits.

---

## Features

- **Wardrive mode** — continuous catalog-driven sweeps; devices upsert with signal history and GPS pins when available
- **Pluggable SDR integration** — HackRF (`hackrf_sweep` / `hackrf_transfer`) or receive-only RTL-SDR (`rtl_power` / `rtl_sdr`), normalized to one signed 8-bit IQ format
- **BLE discovery** — advertisements, company ID / OUI rules, deep GATT dive on selected targets
- **Wi‑Fi correlation** — parallel AP scan on a second NIC, map overlay, device correlation
- **Live monitor** — focused RSSI / narrow RF sampling on one tracker entry
- **Risk triage** — severity labels and structured findings from catalog profiles + dive output
- **RF clone lab** — listen → IQ capture → optional PWM decode on either receiver; gated TX replay on HackRF only (lab allowlist bands)
- **Research pipeline** — offline capture manifests, clustering, quality scoring (`scripts/research/`; outputs gitignored)

---

## Requirements

### Hardware

- One supported receiver: **HackRF One** with `hackrf_info`, `hackrf_sweep`, and `hackrf_transfer`; or a **receive-only RTL-SDR** with `rtl_test`, `rtl_power`, and `rtl_sdr`.
- **GPS receiver** (USB or serial, u-blox / NMEA) running through **`gpsd`** — **required for the wardrive map** (hunter trail, live position, device geolocation pins). Without a GPS fix the map stays on a neutral world view and pins cannot be placed on your route.
- Optional: second Wi‑Fi NIC (`wlan1` by default) for AP scan and correlation.

### Software

- Linux or macOS
- Python **3.11+**
- **Decode / companion stack** — install as many modules as your targets need: `rtl_433`, `multimon-ng`, BlueZ/BLE, `iw` (Wi‑Fi scan). More modules = broader catalog coverage (TPMS, POCSAG, ADS‑B helpers, BLE GATT, etc.).
- Docker optional — privileged, USB passthrough, host network (see `docker-compose.yml`)

---

## Quick start

### Clone and virtualenv

```bash
git clone https://github.com/zpol/rf-hunter.git
cd rf-hunter
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Captures directory

Sweep data, IQ captures, and tracker state are written under `captures/` (gitignored):

```bash
mkdir -p captures
export RF_HUNTER_CAPTURES="$(pwd)/captures"
```

### macOS with RTL-SDR

Install the RTL-SDR command-line tools, verify the USB receiver, and start RF
Hunter with the RTL backend selected:

```bash
brew install librtlsdr
rtl_test -t
export RF_HUNTER_RADIO=rtl_sdr
export RF_HUNTER_CAPTURES="${RF_HUNTER_CAPTURES:-$(pwd)/captures}"
python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8081
```

Open **http://localhost:8081**, then confirm the selected receiver:

```bash
curl -s http://localhost:8081/api/health | python3 -m json.tool
```

The response should contain `"selected": "rtl_sdr"`, `"rx_only": true`, and
`"rtl_sdr": true` under `radio.available`. The web header will show
**RTL-SDR OK · RX #0**, and all transmit controls will be disabled.

For an R820T/R820T2 stick, `rtl_test -t` may finish with `No E4000 tuner found,
aborting.` after it has already reported the RTL2832U and R820T tuner. That
message only means the optional E4000-specific test is not applicable; the
earlier `Found 1 device(s)` and `Found Rafael Micro R820T tuner` lines confirm
that the receiver was detected.

Start the backend normally on port 8081. RTL-SDR captures arrive as unsigned
8-bit IQ; RF Hunter converts them in bounded NumPy chunks to the signed
interleaved IQ used by its existing HackRF analysis paths. SoX is not required
for this conversion.

Receiver settings live in
[`backend/data/radio_backends.yaml`](backend/data/radio_backends.yaml). It
contains backend priority, enable flags, command names, tuner frequency limits,
sample-rate limits, device index, and gain. New receivers can be added to this
configuration and registered behind the same capture/sweep contract in
`backend/app/radio.py`; downstream analyzers continue to receive normalized
`cs8` IQ. Set `RF_HUNTER_RADIO_CONFIG` to use another YAML file, or use
`RF_HUNTER_RADIO=auto|hackrf|rtl_sdr` to override the selection.
`RTL_SDR_DEVICE`, `RTL_SDR_GAIN`, `RTL_SDR_MIN_MHZ`,
`RTL_SDR_MAX_MHZ`, and `RTL_SDR_MAX_SAMPLE_RATE` are deployment overrides.

RTL-SDR cannot transmit or tune to the 5.8 GHz FPV bands directly. Unsupported
catalog bands are skipped, replay TX remains HackRF-only, and **Full sweep**
automatically uses the configured RTL-SDR range (24–1766 MHz by default) rather
than the HackRF 1–6000 MHz range.

### Terminal UI

```bash
./rf-hunter-v2
```

| Key | Action |
|-----|--------|
| `w` | Start wardrive |
| `s` | One-shot scan |
| `x` | Stop scan / monitor |
| `Enter` | Focus row |
| `m` | Monitor focused device |
| `d` | Deep dive + risk |
| `c` | Clear tracker |
| `r` | Refresh receiver status |
| `q` | Quit |

### Web UI

```bash
export RF_HUNTER_CAPTURES="${RF_HUNTER_CAPTURES:-$(pwd)/captures}"
python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8081
```

Open **http://localhost:8081**

To start a scan:

- **Wardrive** and **Once** scan the device types selected in the left sidebar.
  Choose at least one item under **Device Types**; the checkboxes in the center
  results pane are only for selecting existing detections for vulnerability
  triage.
- **Full sweep** needs no device-type selection and surveys the usable range of
  the active receiver. When a peak is labeled `~ADS-B Aircraft (1090 MHz)`,
  focus it and press **Decode ADS-B** for a dedicated 20-second Mode-S listen;
  valid aircraft are added as separate decoded tracker entries. Enable
  **Exclude FM broadcast** to omit 87.5–108 MHz from the actual sweep commands.
- **Cards**, **List**, and **Table** display the same detections in different
  layouts. On desktop, only this center results pane scrolls; the scan and focus
  sidebars remain visible and scroll independently when their contents overflow.

The wardrive map uses **VersaTiles / OpenStreetMap** raster tiles (no API key). It needs a **GPS fix via `gpsd`** to center on your position, draw the hunter trail, and pin devices to your route — start `gpsd` against your receiver before wardriving. Basemap falls back automatically if a tile provider blocks requests.

### Docker

```bash
mkdir -p captures
docker compose up --build
```

Service listens on **8081** with `network_mode: host`, USB bind-mount, and D‑Bus for SDR + BLE access.

---

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `RF_HUNTER_CAPTURES` | `./captures` | Sweeps, IQ, tracker JSON, replay CAPs |
| `RF_HUNTER_CATALOG` | `backend/data/device_catalog.yaml` | Device type catalog |
| `RF_HUNTER_RADIO` | `auto` | Receiver selection: `auto`, `hackrf`, or `rtl_sdr` |
| `RF_HUNTER_RADIO_CONFIG` | `backend/data/radio_backends.yaml` | Alternate receiver-backend YAML configuration |
| `HACKRF_SERIAL` | *(empty)* | Lock to one HackRF when several are connected |
| `RTL_SDR_DEVICE` | `0` | RTL-SDR device index or serial accepted by the command-line tools |
| `RTL_SDR_GAIN` | *(unset)* | Force a numeric RTL tuner gain in dB; otherwise the UI LNA/VGA values are mapped to the tuner gain range |
| `RTL_SDR_MIN_MHZ` / `RTL_SDR_MAX_MHZ` | `24` / `1766` | Configured RTL tuning range used for validation and full sweep |
| `RTL_SDR_MAX_SAMPLE_RATE` | `3200000` | Maximum accepted RTL capture sample rate |
| `RF_HUNTER_WIFI_IFACE` | `wlan1` | Interface for parallel Wi‑Fi scan |
| `GPSD_HOST` / `GPSD_PORT` | `127.0.0.1` / `2947` | GPS fix via `gpsd` — required for map trail and device pins |

See also [`AGENTS.md`](AGENTS.md) for architecture notes and lab gotchas.

---

## API (selection)

| Method | Path | Role |
|--------|------|------|
| `GET` | `/api/health` | Selected receiver/capabilities, GPS, Wi‑Fi, and scan status |
| `POST` | `/api/scan/start` | `{ "mode": "wardrive" \| "once" \| "full_sweep", ... }` |
| `GET` | `/api/tracker` | Live device snapshot |
| `POST` | `/api/monitor/start` | Focused live samples |
| `POST` | `/api/replay/listen` | IQ capture + decode (RF clone lab) |
| `WS` | `/ws/scan` | `device_update`, `tracker_snapshot`, … |

---

## Tests

```bash
python3 -m pytest tests/ -v
```

Most unit and TUI tests run without SDR hardware.

---

## RTL-SDR troubleshooting

- **Header says no receiver:** stop any other `rtl_sdr`, `rtl_power`,
  `rtl_test`, or SDR application using the dongle, reconnect it, and restart the
  backend. One process can own the USB receiver at a time.
- **Start scan asks for a device type:** select targets in the left **Device
  Types** section, or choose **Full sweep**. Selecting a row in the center table
  controls triage only and does not select scan targets.
- **Listen fails:** check the live log and backend terminal for the detailed
  capture error. Confirm the target frequency is within the configured RTL range
  and the requested sample rate does not exceed `RTL_SDR_MAX_SAMPLE_RATE`.
- **UI still shows old labels or layout:** perform a hard refresh so the browser
  reloads the versioned JavaScript and CSS assets.
- **Wi-Fi or GPS badge is in error:** these are optional integrations. Configure
  the Wi-Fi interface and `gpsd` only when you need correlation or map pins.

---

## Project layout

```
backend/app/     FastAPI, radio abstraction, scanner, tracker, decode, risk, replay
backend/data/    Radio configuration, device catalog, fingerprint DB (OUI, rules)
frontend/        Static web UI
tui/             Textual terminal UI
doc/             Screenshots for README / docs
scripts/         Deploy helpers, research triage (offline)
tests/
captures/        Local evidence (not in git)
```

---

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Disclaimer

This software is for **security research and education** in controlled environments. Transmitting or intercepting RF without authorization may violate local law. You are responsible for compliance with spectrum regulations and permission requirements.

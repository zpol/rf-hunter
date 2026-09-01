# RF Hunter

RF security research platform for **authorized lab use**: wardrive-style RF/BLE scanning with a HackRF, optional GPS, Wi‑Fi correlation, device fingerprinting, live monitoring, and triage/deep-dive workflows.

**Web UI + terminal UI (TUI).** Python backend (FastAPI), static frontend.

> Use only on networks and devices you own or have explicit permission to test.

## Features

- **Wardrive mode** — continuous scan loop; devices upsert into a live tracker with signal history
- **HackRF sweeps** — catalog-driven bands (433 MHz remotes, 868 MHz ISM, TPMS candidates, LoRa, ADS‑B, etc.)
- **BLE discovery** — advertisements, fingerprinting (OUI / company ID / rules), optional GATT deep dive
- **Wi‑Fi scan** — parallel AP discovery and correlation with BLE/RF hits (optional second NIC)
- **GPS trail** — map pins use first-seen device locations; hunter trail when `gpsd` is available
- **Focus + monitor** — live RSSI / narrow RF sampling on one target
- **Risk triage** — severity labels and structured findings from catalog + dive results
- **Research scripts** — offline capture manifest, clustering, quality scoring (outputs stay local; see `.gitignore`)

## Requirements

- Linux (tested on Debian/Kali-style systems)
- Python **3.11+**
- [HackRF](https://greatscottgadgets.com/hackrf/) tools: `hackrf_sweep`, `hackrf_transfer`
- Optional: `rtl_433`, `multimon-ng`, BlueZ/BLE, `gpsd`, `iw` (Wi‑Fi scan)
- Docker optional (privileged, USB + host network for hardware passthrough)

## Quick start

### 1. Clone and Python env

```bash
git clone https://github.com/zpol/rf-hunter.git
cd rf-hunter
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Captures directory

Sweep data, IQ snippets, and tracker state are written under `captures/` (gitignored):

```bash
mkdir -p captures
export RF_HUNTER_CAPTURES="$(pwd)/captures"
```

### 3. Terminal UI

```bash
./rf-hunter-v2
```

| Key | Action |
|-----|--------|
| `w` | Start **wardrive** |
| `s` | One-shot scan |
| `x` | Stop scan / monitor |
| `Enter` | Focus row |
| `m` | Monitor focused device |
| `d` | Deep dive + risk |
| `c` | Clear tracker |
| `r` | Refresh HackRF status |
| `q` | Quit |

### 4. Web UI

```bash
export RF_HUNTER_CAPTURES="${RF_HUNTER_CAPTURES:-$(pwd)/captures}"
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8081
```

Open **http://localhost:8081**

### 5. Docker

```bash
mkdir -p captures
docker compose up --build
```

Requires USB passthrough, `privileged: true`, and `network_mode: host` (see `docker-compose.yml`).

## Configuration (environment)

| Variable | Default | Purpose |
|----------|---------|---------|
| `RF_HUNTER_CAPTURES` | `./captures` | Output directory for sweeps, IQ, tracker JSON |
| `RF_HUNTER_CATALOG` | `backend/data/device_catalog.yaml` | Device type catalog |
| `HACKRF_SERIAL` | *(empty)* | Lock to one HackRF when multiple are connected |
| `RF_HUNTER_WIFI_IFACE` | `wlan1` | Interface for parallel Wi‑Fi scan |
| `GPSD_HOST` / `GPSD_PORT` | `127.0.0.1` / `2947` | GPS fix source |

## API (selection)

| Method | Path | Role |
|--------|------|------|
| `GET` | `/api/health` | HackRF, GPS, Wi‑Fi, scan status |
| `POST` | `/api/scan/start` | `{ "mode": "wardrive" \| "once", ... }` |
| `GET` | `/api/tracker` | Live device snapshot |
| `POST` | `/api/monitor/start` | Focused live samples |
| `WS` | `/ws/scan` | `device_update`, `tracker_snapshot`, … |

## Tests

```bash
python -m pytest tests/ -v
```

Hardware is not required for most unit/TUI tests.

## Project layout

```
backend/app/     FastAPI, scanner, tracker, BLE, Wi‑Fi, decode, risk
backend/data/    Device catalog, fingerprint DB (OUI, rules)
frontend/        Static web UI
tui/             Textual terminal UI
scripts/         Deploy helpers, research triage (offline)
tests/
captures/        Local evidence (not in git)
```

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Disclaimer

This software is for **security research and education** in controlled environments. Misuse against third-party systems or spectrum may be illegal. You are responsible for compliance with local regulations and authorization requirements.

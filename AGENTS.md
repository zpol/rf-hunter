# Agents — RF Hunter

## Environment

- Python: project venv at `.venv/bin/python` (or system `python3`)
- Launcher: `./rf-hunter-v2` → TUI
- `RF_HUNTER_CAPTURES` → `./captures` by default (gitignored)
- `RF_HUNTER_CATALOG` → `backend/data/device_catalog.yaml`
- Web default port: **8081**

## How to run

```bash
# TUI
./rf-hunter-v2

# Backend + static frontend
export RF_HUNTER_CAPTURES="${RF_HUNTER_CAPTURES:-$(pwd)/captures}"
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8081

# Docker
docker compose up --build

# Tests
python -m pytest tests/ -v
```

## Architecture

| Entry | File | Role |
|-------|------|------|
| TUI | `tui/app.py` | Wardrive panel: bars, focus, monitor, dive |
| Backend | `backend/app/main.py` | FastAPI HTTP + WS |
| Scan | `backend/app/scanner.py` | `mode=once\|wardrive` continuous loop |
| Tracker | `backend/app/tracker.py` | Upsert devices, signal history, GPS pins |
| Monitor | `backend/app/monitor.py` | Live RF peak / BLE RSSI for one target |
| Risk | `backend/app/risk.py` | Triage from dive + catalog profiles |
| Deep dive | `backend/app/deep_dive.py` | IQ/GATT analysis |
| Wi‑Fi | `backend/app/wifi_scanner.py`, `correlate.py` | AP scan + device correlation |
| Fingerprint | `backend/app/fingerprint.py` | OUI / BLE company ID / YAML rules |

## Gotchas

1. Wardrive and focused **monitor** both use HackRF — prefer BLE-only monitor while wardrive is running, or stop the sweep first.
2. Tests cover TUI, replay safety, ADS‑B/BLE helpers, etc.; no HackRF required for pytest.
3. **Never commit** `captures/`, IQ binaries, or generated `analysis_runs/` / `results/`.
4. Docker needs privileged + USB + D-Bus for HackRF and BLE.
5. Map initial view follows GPS fix when available; otherwise a neutral world view until fix or device pins arrive.

# Agents — RF Hunter

## Environment

- Python: project venv at `.venv/bin/python` (or system `python3`)
- Launcher: `./rf-hunter-v2` → TUI
- `RF_HUNTER_CAPTURES` → `./captures` by default (gitignored)
- `RF_HUNTER_CATALOG` → `backend/data/device_catalog.yaml`
- `RF_HUNTER_RADIO` → `auto` by default; accepts `hackrf` or `rtl_sdr`
- Receiver config → `backend/data/radio_backends.yaml` (override with `RF_HUNTER_RADIO_CONFIG`)
- Web default port: **8081**

## How to run

```bash
# TUI
./rf-hunter-v2

# Backend + static frontend
export RF_HUNTER_CAPTURES="${RF_HUNTER_CAPTURES:-$(pwd)/captures}"
python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8081

# Force RTL-SDR on macOS/Linux
RF_HUNTER_RADIO=rtl_sdr python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8081

# Docker
docker compose up --build

# Tests
python3 -m pytest tests/ -v
```

## Architecture

| Entry | File | Role |
|-------|------|------|
| TUI | `tui/app.py` | Wardrive panel: bars, focus, monitor, dive |
| Backend | `backend/app/main.py` | FastAPI HTTP + WS |
| Radio | `backend/app/radio.py` | Pluggable HackRF/RTL-SDR probing, commands, IQ normalization, capabilities |
| Radio config | `backend/data/radio_backends.yaml` | Backend priority, commands, tuner limits, RTL device and gain |
| Scan | `backend/app/scanner.py` | `mode=once\|wardrive\|full_sweep` scan loop |
| Tracker | `backend/app/tracker.py` | Upsert devices, signal history, GPS pins |
| Monitor | `backend/app/monitor.py` | Live RF peak / BLE RSSI for one target |
| Risk | `backend/app/risk.py` | Triage from dive + catalog profiles |
| Deep dive | `backend/app/deep_dive.py` | IQ/GATT analysis |
| Wi‑Fi | `backend/app/wifi_scanner.py`, `correlate.py` | AP scan + device correlation |
| Fingerprint | `backend/app/fingerprint.py` | OUI / BLE company ID / YAML rules |

## Gotchas

1. A scan and focused RF **monitor** compete for the selected SDR — prefer BLE-only monitor while scanning, or stop the sweep first.
2. RTL-SDR is RX-only (24–1766 MHz by default). TX controls must remain disabled, unsupported catalog bands are skipped, and full sweep uses the receiver's configured range.
3. RTL-SDR `cu8` capture is normalized to signed `cs8` by `radio.py`; downstream analysis should consume the normalized format rather than call `rtl_sdr` directly.
4. Tests cover TUI, radio adapters, replay safety, ADS‑B/BLE helpers, etc.; no SDR hardware is required for pytest.
5. **Never commit** `captures/`, IQ binaries, or generated `analysis_runs/` / `results/`.
6. Docker needs privileged + USB + D-Bus for SDR and BLE.
7. Map initial view follows GPS fix when available; otherwise a neutral world view until fix or device pins arrive.
8. Wardrive/Once targets come from the left Device Types list. Center result checkboxes select detections for triage; Full Sweep requires no target selection.

## Adding a receiver backend

1. Add its enabled flag, priority, command names, limits, and device options to `backend/data/radio_backends.yaml`.
2. Register its stable backend name in `BACKEND_REGISTRY` and implement probing plus capture/sweep command construction in `backend/app/radio.py`.
3. Normalize captures to interleaved signed 8-bit IQ (`cs8`) before returning them, and report frequency, sample-rate, RX-only, and TX capabilities centrally.
4. Keep scanner, monitor, decode, and replay modules behind the radio helpers; do not add direct receiver-specific subprocess calls to consumers.
5. Add adapter tests that use fake executables or fixture IQ. Hardware must not be required for the unit suite.

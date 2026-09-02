from pathlib import Path

import numpy as np

from backend.app import radio


def test_cu8_to_cs8_normalizes_rtl_samples(tmp_path: Path):
    source = tmp_path / "rtl.cu8"
    destination = tmp_path / "normalized.cs8"
    np.array([0, 127, 128, 255], dtype=np.uint8).tofile(source)

    assert radio.cu8_to_cs8(source, destination) == 4
    assert np.fromfile(destination, dtype=np.int8).tolist() == [-128, -1, 0, 127]


def test_default_config_has_registered_backends():
    config = radio.load_config()
    assert config["selected"] == "auto"
    assert set(config["backends"]) >= {"hackrf", "rtl_sdr"}
    assert set(radio.BACKEND_REGISTRY) >= {"hackrf", "rtl_sdr"}


def test_rtl_sweep_command_uses_config(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(radio, "selected_backend", lambda **_kwargs: "rtl_sdr")
    backend, command = radio.sweep_command(
        433.0, 434.0, passes=2, bin_width_hz=25_000,
        lna_db=20, vga_db=30, out_csv=tmp_path / "sweep.csv",
    )
    assert backend == "rtl_sdr"
    assert command[0] == "rtl_power"
    assert "433000000:434000000:25000" in command


def test_rtl_frequency_and_rate_limits(monkeypatch):
    monkeypatch.delenv("RTL_SDR_MIN_MHZ", raising=False)
    monkeypatch.delenv("RTL_SDR_MAX_MHZ", raising=False)
    monkeypatch.delenv("RTL_SDR_MAX_SAMPLE_RATE", raising=False)
    assert radio.supports_frequency(433_920_000, "rtl_sdr")
    assert not radio.supports_frequency(5_800_000_000, "rtl_sdr")
    assert radio.supports_sample_rate(2_000_000, "rtl_sdr")
    assert not radio.supports_sample_rate(10_000_000, "rtl_sdr")


def test_rtl_capture_is_returned_as_cs8(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(radio, "selected_backend", lambda **_kwargs: "rtl_sdr")

    class FakeProcess:
        returncode = 0

        def __init__(self, command, **_kwargs):
            np.tile(np.array([0, 128, 255, 127], dtype=np.uint8), 300).tofile(command[-1])

        def poll(self):
            return self.returncode

        def communicate(self, timeout=None):
            return "", ""

    monkeypatch.setattr(radio.subprocess, "Popen", FakeProcess)
    output = tmp_path / "capture.cs8"
    result = radio.capture_iq(
        output, freq_hz=433_920_000, sample_rate=2_000_000,
        num_samples=600, lna_db=20, vga_db=30,
    )
    assert result.ok
    assert result.backend == "rtl_sdr"
    assert np.fromfile(output, dtype=np.int8)[:4].tolist() == [-128, 0, 127, -1]


def test_replay_listen_api_route_is_registered():
    from backend.app.main import app

    routes = {(method, route.path) for route in app.routes for method in getattr(route, "methods", set())}
    assert ("POST", "/api/replay/listen") in routes

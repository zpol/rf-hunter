"""Receive-radio compatibility layer.

The rest of RF Hunter consumes HackRF-compatible ``cs8`` files: signed,
interleaved I/Q bytes.  HackRF already produces that format.  rtl_sdr produces
offset-binary ``cu8`` samples, which are converted here so analysis code does
not need to know which receiver made a capture.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import yaml

from .procutil import kill_process_tree


DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "data" / "radio_backends.yaml"
# Backend names are deliberately registered in one place. A future receiver
# implements these same capture/sweep contracts and adds one registry entry.
BACKEND_REGISTRY = {"hackrf": "cs8_native", "rtl_sdr": "cu8_to_cs8"}
_PROBE_CACHE: tuple[float, tuple[str, str], dict[str, bool]] | None = None


def load_config() -> dict[str, Any]:
    path = Path(os.environ.get("RF_HUNTER_RADIO_CONFIG", str(DEFAULT_CONFIG)))
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except (OSError, yaml.YAMLError):
        data = {}
    data.setdefault("selected", "auto")
    data.setdefault("backends", {})
    return data


def _backend_config(name: str) -> dict[str, Any]:
    return dict(load_config().get("backends", {}).get(name) or {})


def _command(name: str, role: str, fallback: str) -> str:
    return str((_backend_config(name).get("commands") or {}).get(role) or fallback)


def _rtl_device() -> str:
    configured = _backend_config("rtl_sdr").get("device", "0")
    return os.environ.get("RTL_SDR_DEVICE", str(configured)).strip() or "0"


@dataclass(frozen=True)
class CaptureResult:
    ok: bool
    backend: str
    returncode: int
    stderr: str = ""
    bytes: int = 0
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "backend": self.backend,
            "returncode": self.returncode,
            "stderr_tail": self.stderr[-500:],
            "bytes": self.bytes,
            **({"error": self.error} if self.error else {}),
        }


def _requested_backend() -> str:
    configured = load_config().get("selected", "auto")
    value = os.environ.get("RF_HUNTER_RADIO", str(configured)).strip().lower().replace("-", "_")
    aliases = {"rtl": "rtl_sdr", "rtlsdr": "rtl_sdr", "hack_rf": "hackrf"}
    value = aliases.get(value, value)
    return value if value in {"auto", "hackrf", "rtl_sdr"} else "auto"


def _command_works(cmd: list[str], marker: bytes | None = None) -> bool:
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5)
    except Exception:
        return False
    stdout = result.stdout or b""
    stderr = result.stderr or b""
    if isinstance(stdout, str):
        stdout = stdout.encode()
    if isinstance(stderr, str):
        stderr = stderr.encode()
    output = stdout + stderr
    return result.returncode == 0 and (marker is None or marker in output)


def available_backends(*, probe: bool = True) -> dict[str, bool]:
    """Return receiver availability. Probe USB devices unless ``probe=False``."""
    global _PROBE_CACHE
    cache_key = (str(Path(os.environ.get("RF_HUNTER_RADIO_CONFIG", str(DEFAULT_CONFIG)))), _rtl_device())
    if probe and _PROBE_CACHE is not None:
        cached_at, cached_key, cached = _PROBE_CACHE
        if cached_key == cache_key and time.monotonic() - cached_at < 15.0:
            return dict(cached)
    hc = _backend_config("hackrf")
    rc = _backend_config("rtl_sdr")
    hackrf_capture = _command("hackrf", "capture", "hackrf_transfer")
    hackrf_sweep = _command("hackrf", "sweep", "hackrf_sweep")
    rtl_capture = _command("rtl_sdr", "capture", "rtl_sdr")
    rtl_sweep = _command("rtl_sdr", "sweep", "rtl_power")
    hackrf = bool(hc.get("enabled", True) and shutil.which(hackrf_capture) and shutil.which(hackrf_sweep))
    rtl = bool(rc.get("enabled", True) and shutil.which(rtl_capture) and shutil.which(rtl_sweep))
    if probe and hackrf:
        info = _command("hackrf", "info", "hackrf_info")
        hackrf = bool(shutil.which(info)) and _command_works(
            [info], b"Found HackRF"
        )
    if probe and rtl:
        # rtl_test reports device discovery on stderr. Some versions return a
        # non-zero status after the tuner probe, so the marker is authoritative.
        try:
            result = subprocess.run(
                [_command("rtl_sdr", "info", "rtl_test"), "-t", "-d", _rtl_device()], capture_output=True, timeout=6
            )
            stdout = result.stdout or b""
            stderr = result.stderr or b""
            if isinstance(stdout, str):
                stdout = stdout.encode()
            if isinstance(stderr, str):
                stderr = stderr.encode()
            output = stdout + stderr
            rtl = b"Found " in output and b"device" in output.lower()
        except Exception:
            rtl = False
    found = {"hackrf": hackrf, "rtl_sdr": rtl}
    if probe:
        _PROBE_CACHE = (time.monotonic(), cache_key, dict(found))
    return found


def selected_backend(*, probe: bool = True) -> str | None:
    requested = _requested_backend()
    available = available_backends(probe=probe)
    if requested != "auto":
        return requested if available.get(requested) else None
    candidates = [name for name in BACKEND_REGISTRY if available.get(name)]
    if candidates:
        return min(candidates, key=lambda name: int(_backend_config(name).get("priority", 100)))
    return None


def status() -> dict[str, Any]:
    available = available_backends(probe=True)
    selected = selected_backend(probe=True)
    return {
        "requested": _requested_backend(),
        "selected": selected,
        "available": available,
        "rx_only": selected == "rtl_sdr",
        "tx_capable": selected == "hackrf",
        "sample_format": "cs8",
        "frequency_range_mhz": frequency_range_mhz(selected) if selected else None,
        "rtl_device": _rtl_device() if selected == "rtl_sdr" else None,
        "config_file": str(Path(os.environ.get("RF_HUNTER_RADIO_CONFIG", str(DEFAULT_CONFIG)))),
        "registered": sorted(BACKEND_REGISTRY),
    }


def supports_frequency(freq_hz: int | float, backend: str | None = None) -> bool:
    backend = backend or selected_backend(probe=True)
    if backend == "rtl_sdr":
        cfg = _backend_config("rtl_sdr")
        low = float(os.environ.get("RTL_SDR_MIN_MHZ", cfg.get("freq_min_mhz", 24))) * 1e6
        high = float(os.environ.get("RTL_SDR_MAX_MHZ", cfg.get("freq_max_mhz", 1766))) * 1e6
        return low <= float(freq_hz) <= high
    if backend == "hackrf":
        cfg = _backend_config("hackrf")
        return float(cfg.get("freq_min_mhz", 1)) * 1e6 <= float(freq_hz) <= float(cfg.get("freq_max_mhz", 6000)) * 1e6
    return False


def frequency_range_mhz(backend: str | None = None) -> tuple[float, float] | None:
    backend = backend or selected_backend(probe=True)
    if backend not in BACKEND_REGISTRY:
        return None
    cfg = _backend_config(backend)
    if backend == "rtl_sdr":
        low = float(os.environ.get("RTL_SDR_MIN_MHZ", cfg.get("freq_min_mhz", 24)))
        high = float(os.environ.get("RTL_SDR_MAX_MHZ", cfg.get("freq_max_mhz", 1766)))
        return low, high
    return float(cfg.get("freq_min_mhz", 1)), float(cfg.get("freq_max_mhz", 6000))


def supports_sample_rate(sample_rate: int, backend: str | None = None) -> bool:
    backend = backend or selected_backend(probe=True)
    if backend == "rtl_sdr":
        cfg = _backend_config("rtl_sdr")
        low = int(cfg.get("sample_rate_min", 225_001))
        high = int(os.environ.get("RTL_SDR_MAX_SAMPLE_RATE", cfg.get("sample_rate_max", 3_200_000)))
        return low <= int(sample_rate) <= high
    return backend == "hackrf"


def _rtl_gain(lna_db: int, vga_db: int) -> float:
    override = os.environ.get("RTL_SDR_GAIN")
    if override:
        return max(0.0, min(float(override), 49.6))
    configured = _backend_config("rtl_sdr").get("gain_db", "auto")
    if str(configured).lower() != "auto":
        return max(0.0, min(float(configured), 49.6))
    # Preserve the user's low/high gain intent; RTL tuners expose one combined gain.
    ratio = (max(0, min(lna_db, 40)) + max(0, min(vga_db, 62))) / 102.0
    return round(ratio * 49.6, 1)


def cu8_to_cs8(source: Path, destination: Path) -> int:
    """Convert RTL unsigned offset I/Q to HackRF signed I/Q, in bounded chunks."""
    written = 0
    with source.open("rb") as src, destination.open("wb") as dst:
        while True:
            block = src.read(4 * 1024 * 1024)
            if not block:
                break
            # Subtracting 128 modulo 256 is a sign-bit flip. The byte payload can
            # then be read directly as np.int8 by every existing analyzer.
            converted = np.frombuffer(block, dtype=np.uint8) ^ np.uint8(0x80)
            dst.write(converted.tobytes())
            written += converted.size
    return written


def capture_iq(
    out_path: str | Path,
    *,
    freq_hz: int,
    sample_rate: int,
    num_samples: int,
    lna_db: int = 40,
    vga_db: int = 44,
    amp: int = 0,
    bandwidth_hz: int | None = None,
    timeout: float | None = None,
    stop_event: threading.Event | None = None,
) -> CaptureResult:
    """Capture normalized cs8 IQ from the selected receiver."""
    backend = selected_backend(probe=True)
    path = Path(out_path)
    if backend is None:
        return CaptureResult(False, "none", -1, error="No HackRF or RTL-SDR receiver found")
    if not supports_frequency(freq_hz, backend):
        return CaptureResult(
            False, backend, -1,
            error=f"{freq_hz / 1e6:g} MHz is outside the configured {backend} receive range",
        )
    if not supports_sample_rate(sample_rate, backend):
        return CaptureResult(
            False, backend, -1,
            error=f"{sample_rate} samples/s is unsupported by {backend}",
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    rtl_temp = path.with_name(f".{path.name}.rtl-cu8-{os.getpid()}")
    if backend == "hackrf":
        cfg = _backend_config("hackrf")
        serial = os.environ.get("HACKRF_SERIAL", str(cfg.get("serial", ""))).strip()
        cmd = [
            _command("hackrf", "capture", "hackrf_transfer"), "-r", str(path), "-f", str(int(freq_hz)),
            "-s", str(int(sample_rate)), "-n", str(int(num_samples)),
            "-l", str(int(lna_db)), "-g", str(int(vga_db)), "-a", str(int(amp)),
        ]
        if bandwidth_hz:
            cmd += ["-b", str(int(bandwidth_hz))]
        if serial:
            cmd[1:1] = ["-d", serial]
    else:
        cmd = [
            _command("rtl_sdr", "capture", "rtl_sdr"), "-d", _rtl_device(), "-f", str(int(freq_hz)),
            "-s", str(int(sample_rate)), "-g", str(_rtl_gain(lna_db, vga_db)),
            "-n", str(int(num_samples)), str(rtl_temp),
        ]

    stderr = ""
    returncode = -1
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, preexec_fn=os.setsid,
        )
        deadline = time.time() + (timeout or max(10.0, num_samples / sample_rate + 20.0))
        while proc.poll() is None:
            if stop_event is not None and stop_event.is_set():
                kill_process_tree(proc, grace_s=0.2)
                break
            if time.time() > deadline:
                kill_process_tree(proc, grace_s=0.2)
                break
            time.sleep(0.05)
        _, stderr = proc.communicate(timeout=2)
        returncode = proc.returncode if proc.returncode is not None else -1
        if backend == "rtl_sdr" and rtl_temp.exists():
            cu8_to_cs8(rtl_temp, path)
    except FileNotFoundError as exc:
        return CaptureResult(False, backend, -1, error=f"{exc.filename} not found")
    except Exception as exc:
        return CaptureResult(False, backend, returncode, stderr=stderr, error=str(exc))
    finally:
        if rtl_temp.exists():
            rtl_temp.unlink()

    size = path.stat().st_size if path.exists() else 0
    return CaptureResult(size > 1000, backend, returncode, stderr=stderr, bytes=size)


def sweep_command(
    fmin_mhz: float,
    fmax_mhz: float,
    *,
    passes: int,
    bin_width_hz: int,
    lna_db: int,
    vga_db: int,
    out_csv: Path,
) -> tuple[str, list[str]]:
    """Build the native sweep command; both outputs use rtl_power CSV columns."""
    backend = selected_backend(probe=True)
    if backend is None:
        raise RuntimeError("No HackRF or RTL-SDR receiver found")
    if not supports_frequency(float(fmin_mhz) * 1e6, backend) or not supports_frequency(
        float(fmax_mhz) * 1e6, backend
    ):
        raise ValueError(f"{fmin_mhz:g}-{fmax_mhz:g} MHz is outside the {backend} range")
    if backend == "hackrf":
        cfg = _backend_config("hackrf")
        serial = os.environ.get("HACKRF_SERIAL", str(cfg.get("serial", ""))).strip()
        f1, f2 = int(round(fmin_mhz)), int(round(fmax_mhz))
        if f2 <= f1:
            f2 = f1 + 1
        cmd = [
            _command("hackrf", "sweep", "hackrf_sweep"), "-f", f"{f1}:{f2}", "-N", str(int(passes)),
            "-w", str(int(bin_width_hz)), "-l", str(int(lna_db)),
            "-g", str(int(vga_db)), "-a", "0", "-r", str(out_csv),
        ]
        if serial:
            cmd = [cmd[0], "-d", serial] + cmd[1:]
        return backend, cmd

    lo = int(round(float(fmin_mhz) * 1e6))
    hi = int(round(float(fmax_mhz) * 1e6))
    if hi <= lo:
        hi = lo + max(int(bin_width_hz), 1000)
    cmd = [
        _command("rtl_sdr", "sweep", "rtl_power"), "-d", _rtl_device(),
        "-f", f"{lo}:{hi}:{max(1000, int(bin_width_hz))}",
        "-g", str(_rtl_gain(lna_db, vga_db)), "-i", "1", "-1", str(out_csv),
    ]
    return backend, cmd

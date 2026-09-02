"""Force-kill HackRF / child RF processes for responsive Stop."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from typing import Any


def kill_process_tree(proc: subprocess.Popen[Any] | None, grace_s: float = 0.4) -> None:
    """SIGTERM process group, then SIGKILL if still alive."""
    if proc is None or proc.poll() is not None:
        return
    pid = proc.pid
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.terminate()
        except Exception:
            pass

    deadline = time.time() + grace_s
    while proc.poll() is None and time.time() < deadline:
        time.sleep(0.05)

    if proc.poll() is None:
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except Exception:
                pass
        try:
            proc.wait(timeout=1.0)
        except Exception:
            pass


def pkill_rf_tools() -> list[str]:
    """
    Nuclear option: kill stray hackrf_sweep / hackrf_transfer / rtl_433
    started by this lab stack. Returns names that were signalled.
    """
    killed: list[str] = []
    for name in ("hackrf_sweep", "hackrf_transfer", "rtl_sdr", "rtl_power", "rtl_fm", "rtl_adsb", "rtl_433"):
        try:
            r = subprocess.run(
                ["pkill", "-TERM", "-x", name],
                capture_output=True,
                timeout=2,
            )
            # pkill returns 0 if signalled, 1 if no match
            if r.returncode == 0:
                killed.append(name)
        except Exception:
            pass
    time.sleep(0.15)
    for name in killed:
        try:
            subprocess.run(["pkill", "-KILL", "-x", name], capture_output=True, timeout=2)
        except Exception:
            pass
    return killed

"""Exclusive HackRF access — auto-pause wardrive while dive/replay/listen runs."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator

_lock = threading.RLock()
_owner: str | None = None
_depth = 0


@contextmanager
def exclusive(owner: str, *, pause_scan: bool = True) -> Iterator[None]:
    """
    Serialize HackRF users. Optionally pause an active wardrive/scan so
    IQ capture / TX does not collide with hackrf_sweep.
    """
    global _owner, _depth
    from . import scanner

    paused = False
    with _lock:
        if _depth == 0:
            _owner = owner
            if pause_scan and scanner.session.is_running():
                scanner.session.pause(f"HackRF loaned to {owner}")
                paused = True
        _depth += 1
    try:
        yield
    finally:
        with _lock:
            _depth = max(0, _depth - 1)
            if _depth == 0:
                _owner = None
                if paused:
                    scanner.session.resume()


def owner() -> str | None:
    return _owner

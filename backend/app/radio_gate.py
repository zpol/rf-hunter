"""Exclusive SDR access — auto-pause wardrive while dive/replay/listen runs."""

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
    Serialize SDR users. Optionally pause an active wardrive/scan so an IQ
    capture does not collide with the active receiver's sweep process.
    """
    global _owner, _depth
    from . import scanner

    paused = False
    with _lock:
        if _depth == 0:
            _owner = owner
            if pause_scan and scanner.session.is_running():
                scanner.session.pause(f"SDR receiver loaned to {owner}")
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

from __future__ import annotations

import threading
import time

from ...core import events
from .runner import run_due_schedules

_started = False
_lock = threading.Lock()
_stop = threading.Event()


def ensure_started(interval_sec: int = 30) -> None:
    global _started
    with _lock:
        if _started:
            return
        _started = True
        _stop.clear()
        threading.Thread(target=_loop, args=(interval_sec,), daemon=True).start()


def stop() -> None:
    _stop.set()


def tick() -> list[int]:
    started = run_due_schedules()
    if started:
        events.emit("scheduler", {"phase": "started-runs", "run_ids": started})
    return started


def _loop(interval_sec: int) -> None:
    while not _stop.is_set():
        try:
            tick()
        except Exception as exc:
            events.emit("scheduler", {"phase": "failed", "reason": str(exc)})
        _stop.wait(max(5, interval_sec))

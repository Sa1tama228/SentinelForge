"""Tiny thread-safe pub/sub used to push notifications to the UI.

Background threads (honeypot servers, scan workers) `emit` events; the
Flet views `subscribe` and refresh themselves. Keeps UI code decoupled
from worker code without dragging in asyncio.
"""
from __future__ import annotations

import threading
import logging
from collections import deque
from typing import Callable

Listener = Callable[[dict], None]

_bus_lock = threading.Lock()
_listeners: dict[str, list[Listener]] = {}
_recent: deque[dict] = deque(maxlen=500)
logger = logging.getLogger(__name__)


def subscribe(channel: str, fn: Listener) -> Callable[[], None]:
    with _bus_lock:
        _listeners.setdefault(channel, []).append(fn)

    def _unsub() -> None:
        with _bus_lock:
            if fn in _listeners.get(channel, []):
                _listeners[channel].remove(fn)

    return _unsub


def emit(channel: str, payload: dict) -> None:
    with _bus_lock:
        _recent.append({"channel": channel, "payload": payload})
        listeners = list(_listeners.get(channel, []))
    for fn in listeners:
        try:
            fn(payload)
        except Exception:
            # Never let a UI listener break the worker.
            logger.exception("Event listener failed on channel %s", channel)


def recent(channel: str | None = None, limit: int = 100) -> list[dict]:
    with _bus_lock:
        items = list(_recent)
    if channel:
        items = [i for i in items if i["channel"] == channel]
    return items[-limit:]

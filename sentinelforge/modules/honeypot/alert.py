"""Local sound alerts for honeypot activity."""
from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

from ...core import config

_MIN_INTERVAL_SEC = 3.0
_last_played = 0.0
_lock = threading.Lock()


def play_warning() -> None:
    global _last_played
    hp = config.load().get("honeypot", {})
    if not hp.get("alert_sound_enabled", True):
        return
    path = Path(hp.get("alert_sound_path") or "").expanduser()
    if not path.is_file():
        return
    if sys.platform != "win32":
        return
    now = time.monotonic()
    with _lock:
        if now - _last_played < _MIN_INTERVAL_SEC:
            return
        _last_played = now
    _play_with_powershell(path)


def _play_with_powershell(path: Path) -> None:
    uri = path.resolve().as_uri()
    script = (
        "Add-Type -AssemblyName PresentationCore;"
        f"$p=New-Object System.Windows.Media.MediaPlayer;"
        f"$p.Open([Uri]'{uri}');"
        "$p.Volume=1;"
        "$p.Play();"
        "Start-Sleep -Milliseconds 2500"
    )
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    try:
        subprocess.Popen(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            startupinfo=startupinfo,
            close_fds=True,
        )
    except OSError:
        pass

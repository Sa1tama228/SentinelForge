"""Project health checks for local environment, config, and storage."""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .scanner import nikto
from .analysis import source_quality
from ..core import config, db


def run() -> dict:
    cfg = config.load()
    db_path = Path(cfg["db_path"])
    data_dir = db_path.parent
    conn = db.connect()
    checks = []

    def add(name: str, ok: bool, detail: str = "", severity: str = "info") -> None:
        checks.append({"name": name, "ok": bool(ok), "severity": severity, "detail": detail})

    add("python", sys.version_info >= (3, 11), sys.version.replace("\n", " "))
    add("data_dir", data_dir.is_dir() and os.access(data_dir, os.W_OK), str(data_dir), "error")
    add("database", db_path.exists(), str(db_path), "error")
    try:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    except Exception as exc:
        integrity = str(exc)
    add("sqlite_integrity", integrity == "ok", str(integrity), "error")
    add("sqlite_wal", _pragma("journal_mode").lower() == "wal", f"journal_mode={_pragma('journal_mode')}", "warn")
    add("nmap", shutil.which("nmap") is not None, shutil.which("nmap") or "not found", "info")
    add("nikto", nikto.available(cfg.get("scanner", {}).get("nikto_path", "")), nikto.status(cfg.get("scanner", {}).get("nikto_path", "")), "info")
    add("perl", nikto._perl_command() is not None, nikto._perl_command() or "not found", "info")
    add("git", shutil.which("git") is not None, shutil.which("git") or "not found", "info")
    for package in ("httpx", "dns", "flet", "scapy", "pyshark"):
        add(f"python_package:{package}", _package_available(package), "available" if _package_available(package) else "not importable", "info")

    scanner_cfg = cfg.get("scanner", {})
    if scanner_cfg.get("nikto_enabled") and not nikto.available(scanner_cfg.get("nikto_path", "")):
        add("config:nikto_enabled", False, "Nikto is enabled but not runnable", "warn")
    if scanner_cfg.get("block_public_targets", True):
        add("config:block_public_targets", True, "public target scans blocked by default")
    else:
        add("config:block_public_targets", False, "public target scans are allowed", "warn")

    counts = _counts()
    return {
        "ok": all(check["ok"] or check["severity"] in {"info", "warn"} for check in checks),
        "checks": checks,
        "counts": counts,
        "vulnerability_sources": source_quality.vulnerability_source_scores(),
    }


def _pragma(name: str) -> str:
    row = db.connect().execute(f"PRAGMA {name}").fetchone()
    return str(row[0]) if row else ""


def _counts() -> dict[str, int]:
    tables = [
        "assets",
        "findings",
        "scan_runs",
        "scan_results",
        "service_fingerprints",
        "vulnerability_matches",
        "recon_targets",
        "recon_findings",
        "honeypot_events",
    ]
    out = {}
    conn = db.connect()
    for table in tables:
        out[table] = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    return out


def _package_available(name: str) -> bool:
    try:
        __import__(name)
        return True
    except Exception:
        return False

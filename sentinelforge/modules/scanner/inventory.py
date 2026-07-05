"""Authenticated inventory import helpers.

These parsers consume files produced outside SentinelForge, such as `dpkg -l`,
`rpm -qa`, Windows software CSV exports, or CycloneDX JSON SBOMs.
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from ...core import db


def import_inventory(asset_id: int, path: str | Path, *, source: str = "inventory") -> int:
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    suffix = path.suffix.lower()
    if suffix == ".json":
        packages = _parse_cyclonedx_json(text)
    elif suffix == ".csv":
        packages = _parse_software_csv(text)
    else:
        packages = _parse_dpkg(text) or _parse_rpm_qa(text)
    imported = 0
    for name, version in packages:
        if not name:
            continue
        db.upsert_asset_package(asset_id, package_name=name, version=version, source=source)
        imported += 1
    return imported


def _parse_dpkg(text: str) -> list[tuple[str, str]]:
    rows = []
    for line in text.splitlines():
        if not line.startswith("ii "):
            continue
        parts = re.split(r"\s+", line.strip(), maxsplit=4)
        if len(parts) >= 3:
            rows.append((parts[1].split(":", 1)[0], parts[2]))
    return rows


def _parse_rpm_qa(text: str) -> list[tuple[str, str]]:
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or " " in line:
            continue
        match = re.match(r"(.+)-([0-9][^-]*-[^-]+)(?:\.[^.]+)?$", line)
        if match:
            rows.append((match.group(1), match.group(2)))
    return rows


def _parse_software_csv(text: str) -> list[tuple[str, str]]:
    rows = []
    reader = csv.DictReader(text.splitlines())
    for row in reader:
        lower = {str(k).lower(): v for k, v in row.items()}
        name = lower.get("name") or lower.get("displayname") or lower.get("package") or lower.get("software")
        version = lower.get("version") or lower.get("displayversion") or ""
        if name:
            rows.append((str(name).strip(), str(version or "").strip()))
    return rows


def _parse_cyclonedx_json(text: str) -> list[tuple[str, str]]:
    payload = json.loads(text)
    rows = []
    for component in payload.get("components", []):
        name = component.get("name") or component.get("purl") or ""
        version = component.get("version") or ""
        if name:
            rows.append((str(name), str(version)))
    return rows

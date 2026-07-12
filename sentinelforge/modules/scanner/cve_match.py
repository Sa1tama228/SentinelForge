from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

_DB_PATH = Path(__file__).parent / "cve_db.json"


@lru_cache(maxsize=1)
def _db() -> list[dict]:
    return json.loads(_DB_PATH.read_text(encoding="utf-8"))


def _parse_ver(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) or (0,)


def match(service: str, version: str) -> list[dict]:
    """Return matching CVE entries for a (service, version) pair.

    ``version`` may be like "OpenSSH 8.9p1" or "Apache/2.4.52" — we scan
    it for the product token and a numeric version.
    """
    if not version:
        return []
    out: list[dict] = []
    vlow = version.lower()
    for entry in _db():
        if entry["service"] != service:
            continue
        product = entry.get("product", "").lower()
        # Enforce the product token only when the version string actually
        # carries one (e.g. "OpenSSH 8.9p1"). Pure-numeric versions such as
        # "10.0.17763" (RDP build) rely on the service+range match alone.
        if product and re.search(r"[a-z]", vlow) and product not in vlow:
            continue
        m = re.search(r"(\d+(?:\.\d+)+)", version)
        if not m:
            continue
        ver = _parse_ver(m.group(1))
        lo = _parse_ver(entry.get("min", "0"))
        hi = _parse_ver(entry.get("max", "9999"))
        if lo <= ver <= hi:
            out.append({"cve": entry["cve"], "desc": entry["desc"]})
    return out

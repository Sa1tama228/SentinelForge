"""Distribution and vendor advisory cache helpers.

The importer accepts a compact JSON document so Ubuntu/Debian/RHEL-style
package advisory data can be loaded without network access:

{
  "source": "ubuntu-usn",
  "advisories": [
    {
      "cve_id": "CVE-2024-6387",
      "distribution": "Ubuntu",
      "package": "openssh",
      "fixed_version": "1:8.9p1-3ubuntu0.10",
      "status": "fixed",
      "reference_url": "https://..."
    }
  ]
}
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ....core import db
from .version_matcher import compare_versions


def import_format_help() -> dict:
    return {
        "label": "Vendor/distribution advisory JSON",
        "path": "JSON file; accepts a list, {'advisories': [...]}, {'vulnerabilities': [...]}, {'items': [...]}, or OSV-like records",
        "accepted_rows": [
            "{'source':'ubuntu-usn','advisories':[{'cve_id','distribution','package','fixed_version','status','reference_url'}]}",
            "{'vulnerabilities':[{'cve','os|distribution','package|product','fixed|fixed_version','status','url'}]}",
            "OSV-like: {'id'|'aliases':[CVE...], 'affected':[{'package':{'ecosystem','name'}, 'ranges':[{'events':[{'fixed':'1.2.3'}]}]}]}",
        ],
        "minimum_fields": ["CVE ID", "package/product name"],
    }


def import_advisory_json(path: str | Path) -> int:
    payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    advisories = _advisory_items(payload)
    if not isinstance(advisories, list):
        raise ValueError("Advisory JSON must contain an advisories array")
    source = str(payload.get("source") or "vendor-advisory") if isinstance(payload, dict) else "vendor-advisory"
    imported = 0
    with db.cursor() as c:
        for raw_item in advisories:
            for item in _expand_advisory(raw_item):
                cve_id = _first_value(item, "cve_id", "cve", "cveID", "id").upper()
                package = _first_value(item, "package", "product", "package_name", "name")
                if not cve_id.startswith("CVE-") or not package:
                    continue
                c.execute(
                    "INSERT INTO distribution_advisories(cve_id,distribution,package_name,fixed_version,status,reference_url,source_name,raw_json) "
                    "VALUES (?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(cve_id, distribution, package_name, source_name) DO UPDATE SET "
                    "fixed_version=excluded.fixed_version,status=excluded.status,reference_url=excluded.reference_url,raw_json=excluded.raw_json",
                    (
                        cve_id,
                        _first_value(item, "distribution", "os", "ecosystem", "vendor", "distro"),
                        package,
                        _first_value(item, "fixed_version", "fixed", "patched_version", "version_fixed"),
                        _first_value(item, "status", "state"),
                        _first_value(item, "reference_url", "url", "link", "advisory_url"),
                        str(item.get("source") or source),
                        json.dumps(raw_item, ensure_ascii=False),
                    ),
                )
                imported += 1
    db.update_vulnerability_source("vendor_advisories", status="synced", record_count=imported, success=True)
    return imported


def validate_advisory_json(path: str | Path) -> dict:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        rows = _advisory_items(payload)
        expanded = [item for row in rows for item in _expand_advisory(row)]
        importable = sum(
            1
            for item in expanded
            if _first_value(item, "cve_id", "cve", "cveID", "id").upper().startswith("CVE-")
            and _first_value(item, "package", "product", "package_name", "name")
        )
        return {
            "kind": "vendor_advisory_json",
            "path": str(path),
            "ok": importable > 0,
            "total_rows": len(expanded),
            "importable_rows": importable,
            "skipped_rows": len(expanded) - importable,
            "format": import_format_help(),
        }
    except Exception as exc:
        return {"kind": "vendor_advisory_json", "path": str(path), "ok": False, "error": str(exc)}


def _advisory_items(payload) -> list[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("advisories", "vulnerabilities", "items", "records", "vulns"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return [payload]


def _expand_advisory(item: dict) -> list[dict]:
    if not isinstance(item, dict):
        return []
    affected = item.get("affected")
    if not isinstance(affected, list):
        return [item]
    cves = _cves_for(item)
    refs = item.get("references") if isinstance(item.get("references"), list) else []
    reference_url = ""
    for ref in refs:
        if isinstance(ref, dict) and ref.get("url"):
            reference_url = str(ref["url"])
            break
    out: list[dict] = []
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        package_info = entry.get("package") if isinstance(entry.get("package"), dict) else {}
        package = _first_value(package_info, "name") or _first_value(entry, "package_name", "product", "name")
        distribution = (
            _first_value(entry, "distribution", "os", "ecosystem")
            or _first_value(package_info, "ecosystem", "distribution", "os")
        )
        fixed_versions = _fixed_versions(entry)
        if not fixed_versions:
            fixed_versions = [""]
        for cve in cves:
            for fixed in fixed_versions:
                out.append(
                    {
                        **item,
                        "cve_id": cve,
                        "package": package,
                        "distribution": distribution,
                        "fixed_version": fixed,
                        "status": "fixed" if fixed else _first_value(item, "status", "database_specific.status"),
                        "reference_url": reference_url,
                    }
                )
    return out or [item]


def _cves_for(item: dict) -> list[str]:
    values = []
    for key in ("cve_id", "cve", "id", "aliases", "related", "upstream"):
        value = item.get(key)
        if isinstance(value, list):
            values.extend(str(v) for v in value)
        elif value:
            values.append(str(value))
    out = []
    seen = set()
    for value in values:
        for cve in re.findall(r"CVE-\d{4}-\d{4,}", value.upper()):
            if cve not in seen:
                seen.add(cve)
                out.append(cve)
    return out


def _fixed_versions(entry: dict) -> list[str]:
    fixed = _first_value(entry, "fixed_version", "fixed", "patched_version")
    out = [fixed] if fixed else []
    ranges = entry.get("ranges") if isinstance(entry.get("ranges"), list) else []
    for rng in ranges:
        events = rng.get("events") if isinstance(rng, dict) and isinstance(rng.get("events"), list) else []
        for event in events:
            if isinstance(event, dict) and event.get("fixed"):
                out.append(str(event["fixed"]).strip())
    return list(dict.fromkeys(v for v in out if v))


def _first_value(mapping: dict, *keys: str) -> str:
    if not isinstance(mapping, dict):
        return ""
    for key in keys:
        value = _value_at_path(mapping, key)
        if value is not None:
            return str(value).strip()
    lower = {_norm_key(k): v for k, v in mapping.items()}
    for key in keys:
        value = lower.get(_norm_key(key))
        if value is not None:
            return str(value).strip()
    return ""


def _value_at_path(mapping: dict, path: str):
    current = mapping
    for part in str(path).split("."):
        if not isinstance(current, dict):
            return None
        if part in current:
            current = current[part]
            continue
        normalized = _norm_key(part)
        found = False
        for key, value in current.items():
            if _norm_key(key) == normalized:
                current = value
                found = True
                break
        if not found:
            return None
    return current


def _norm_key(value) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).lower())


def advisory_state(cve_id: str, *, distribution: str, product: str, package_revision: str) -> dict:
    rows = db.distribution_advisories_for(cve_id, distribution=distribution, package_name=product)
    if not rows:
        return {}
    best = dict(rows[0])
    fixed = best.get("fixed_version") or ""
    if package_revision and fixed:
        cmp = compare_versions(package_revision, fixed)
        if cmp is not None and cmp >= 0:
            best["local_status"] = "patched_by_distribution_advisory"
        elif cmp is not None:
            best["local_status"] = "below_distribution_fixed_version"
        else:
            best["local_status"] = "distribution_advisory_uncomparable"
    else:
        best["local_status"] = "distribution_advisory_present"
    return best

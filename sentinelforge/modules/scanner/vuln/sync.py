from __future__ import annotations

import csv
import gzip
import json
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from ....core import config, db
from . import advisories
from . import correlation

CVE_ALIASES = ("cve", "cve_id", "cveID", "CVE", "id", "CVE_data_meta.ID", "cve.id")
DATE_ALIASES = ("date", "score_date", "published", "date_published", "published_ts", "timestamp")

IMPORT_FORMATS = {
    "nvd_json": {
        "label": "NVD / generic vulnerability JSON",
        "path": "File or directory containing .json/.json.gz",
        "accepted_rows": [
            "NVD 2.0: {'vulnerabilities':[{'cve': {'id', 'descriptions', 'metrics', 'configurations'}}]}",
            "NVD 1.x: {'CVE_Items':[{'cve': {'CVE_data_meta': {'ID'}}, 'impact', 'configurations'}]}",
            "Generic: {'vulnerabilities'|'items'|'records': [{'cve_id', 'title|summary|description', 'published|modified', 'cvss_score|severity', 'cpes':[...]}]}",
        ],
        "minimum_fields": ["cve_id or cve or id", "at least one CPE under configurations/cpes/affected"],
    },
    "cisa_kev": {
        "label": "CISA KEV / generic exploited vulnerability JSON",
        "path": "JSON file",
        "accepted_rows": [
            "{'vulnerabilities':[{'cveID','dateAdded','vendorProject','product','requiredAction','dueDate','notes'}]}",
            "Generic list/object with cve_id/cve, vendor/vendor_project, product/package, action/remediation, due_date",
        ],
        "minimum_fields": ["cve_id or cveID"],
    },
    "epss_csv": {
        "label": "FIRST EPSS / generic EPSS CSV",
        "path": "CSV file; comment metadata such as #score_date:2026-01-01 is accepted",
        "accepted_rows": ["cve,epss,percentile,date", "cve_id,score,percentile,score_date"],
        "minimum_fields": ["cve or cve_id", "epss or score"],
    },
    "exploitdb_csv": {
        "label": "Exploit reference CSV",
        "path": "CSV file",
        "accepted_rows": [
            "id,file,description,date_published,author,type,platform,verified,codes",
            "edb_id,url,title,published,cve_id,exploit_type,platform,verified",
        ],
        "minimum_fields": ["a CVE in cve/cve_id/codes/any text column", "title or description recommended"],
    },
}


def import_format_help() -> dict:
    out = {key: dict(value) for key, value in IMPORT_FORMATS.items()}
    out["vendor_advisory_json"] = advisories.import_format_help()
    return out


def validate_configured_sources() -> dict[str, dict]:
    cfg = config.load().get("scanner", {})
    checks = {}
    for key, kind in (
        ("nvd_json_path", "nvd_json"),
        ("cisa_kev_path", "cisa_kev"),
        ("epss_csv_path", "epss_csv"),
        ("exploitdb_csv_path", "exploitdb_csv"),
        ("vendor_advisory_json_path", "vendor_advisory_json"),
    ):
        path = str(cfg.get(key, "") or "").strip()
        if path:
            checks[kind] = validate_import(kind, path)
    return checks


def validate_import(kind: str, path: str | Path, *, sample_limit: int = 25) -> dict:
    try:
        if kind == "nvd_json":
            total = 0
            importable = 0
            skipped = 0
            for payload in _json_payloads(path, suffixes=(".json", ".json.gz")):
                for item in _vulnerability_items(payload):
                    total += 1
                    cve = item.get("cve", item)
                    cve_id = (_first_value(cve, *CVE_ALIASES) or _first_value(item, *CVE_ALIASES)).upper()
                    if _is_cve(cve_id):
                        importable += 1
                    else:
                        skipped += 1
            return _validation_result(kind, path, total, importable, skipped)
        if kind == "cisa_kev":
            payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
            rows = _json_records(payload, "vulnerabilities", "items", "records", "kev")
            return _validation_result(kind, path, len(rows), sum(1 for row in rows if _is_cve(_first_value(row, "cveID", "cve_id", "cve", "id"))), 0)
        if kind == "epss_csv":
            rows = list(_csv_rows(path))
            importable = sum(1 for row in rows if _is_cve(_first_value(row, "cve", "cve_id", "CVE", "id")))
            return _validation_result(kind, path, len(rows), importable, len(rows) - importable)
        if kind == "exploitdb_csv":
            rows = list(_csv_rows(path))
            importable = sum(1 for row in rows if _cves_from_row(row))
            return _validation_result(kind, path, len(rows), importable, len(rows) - importable)
        if kind == "vendor_advisory_json":
            return advisories.validate_advisory_json(path)
        raise ValueError(f"Unsupported import kind: {kind}")
    except Exception as exc:
        return {"kind": kind, "path": str(path), "ok": False, "error": str(exc), "sample_limit": sample_limit}


def _validation_result(kind: str, path: str | Path, total: int, importable: int, skipped: int) -> dict:
    return {
        "kind": kind,
        "path": str(path),
        "ok": importable > 0,
        "total_rows": total,
        "importable_rows": importable,
        "skipped_rows": skipped,
        "format": import_format_help().get(kind, {}),
    }


def sync_configured_sources() -> dict[str, int]:
    cfg = config.load().get("scanner", {})
    counts: dict[str, int] = {}
    nvd_disabled = False
    for key, source_name, importer in (
        ("nvd_json_path", "nvd", import_nvd_json),
        ("cisa_kev_path", "cisa_kev", import_cisa_kev),
        ("epss_csv_path", "first_epss", import_epss_csv),
        ("exploitdb_csv_path", "exploit_db", import_exploitdb_csv),
        ("vendor_advisory_json_path", "vendor_advisories", advisories.import_advisory_json),
    ):
        if not _source_enabled(source_name):
            db.update_vulnerability_source(source_name, status="disabled", sync_progress=0.0)
            if source_name == "nvd":
                nvd_disabled = True
            continue
        path = str(cfg.get(key, "") or "").strip()
        if not path:
            continue
        counts[source_name] = _run_with_retries(source_name, importer, path)
    if "nvd" not in counts and not nvd_disabled:
        counts["bundled-demo"] = correlation.seed_demo_cache()
    return counts


def set_source_enabled(name: str, enabled: bool) -> None:
    db.update_vulnerability_source(
        name,
        enabled=enabled,
        status="enabled" if enabled else "disabled",
        sync_progress=0.0,
    )

# TODO: switch to sqlalchemy
def import_nvd_json(path: str | Path) -> int:
    source = "nvd"
    try:
        db.update_vulnerability_source(source, status="syncing", sync_progress=0.05)
        imported = 0
        source_versions: set[str] = set()
        with db.cursor() as c:
            for payload in _json_payloads(path, suffixes=(".json", ".json.gz")):
                vulnerabilities = _vulnerability_items(payload)
                if not vulnerabilities:
                    continue
                if isinstance(payload, dict):
                    source_versions.add(_payload_source_version(payload))
                for item in vulnerabilities:
                    cve = item.get("cve", item)
                    cve_id = (_first_value(cve, *CVE_ALIASES) or _first_value(item, *CVE_ALIASES)).upper()
                    if not _is_cve(cve_id):
                        continue
                    descriptions = cve.get("descriptions") or []
                    description = (
                        _nvd_lang_value(descriptions, "en")
                        or _first_legacy_description(cve)
                        or _first_value(cve, "description", "summary", "details")
                        or _first_value(item, "description", "summary", "details")
                    )
                    title = description.split(".", 1)[0][:180] if description else cve_id
                    c.execute(
                        "INSERT INTO cves(cve_id,title,description,status,published_ts,modified_ts,source_name,raw_json) "
                        "VALUES (?,?,?,?,?,?,?,?) "
                        "ON CONFLICT(cve_id) DO UPDATE SET title=excluded.title,description=excluded.description,"
                        "status=excluded.status,published_ts=excluded.published_ts,modified_ts=excluded.modified_ts,"
                        "source_name=excluded.source_name,raw_json=excluded.raw_json",
                        (
                            cve_id,
                            title,
                            description,
                            _first_value(cve, "vulnStatus", "status") or _first_value(item, "status"),
                            _first_value(cve, "published", "publishedDate") or _first_value(item, "published", "publishedDate"),
                            _first_value(cve, "lastModified", "lastModifiedDate", "modified", "modified_ts")
                            or _first_value(item, "lastModified", "lastModifiedDate", "modified", "modified_ts"),
                            source,
                            json.dumps(item, ensure_ascii=False),
                        ),
                    )
                    c.execute("DELETE FROM cve_cpe_ranges WHERE cve_id=?", (cve_id,))
                    _insert_nvd_metrics(c, cve_id, cve)
                    _insert_generic_metric(c, cve_id, item)
                    for cpe_match in _cpe_matches(item, cve):
                        criteria = _first_value(cpe_match, "criteria", "cpe23Uri", "cpe_uri", "cpe", "uri")
                        vendor = _first_value(cpe_match, "vendor", "vendor_project")
                        product = _first_value(cpe_match, "product", "package", "package_name", "name")
                        base_cpe, cpe_vendor, cpe_product, exact_version = _base_cpe_uri(criteria)
                        vendor = cpe_vendor or vendor
                        product = cpe_product or product
                        if not base_cpe and vendor and product:
                            base_cpe = _generic_cpe_uri(vendor, product)
                        if not base_cpe or not vendor or not product:
                            continue
                        c.execute(
                            "INSERT OR IGNORE INTO cpe_products(vendor,product,cpe_uri,title,aliases_json) VALUES (?,?,?,?,?)",
                            (vendor, product, base_cpe, f"{vendor}:{product}", "[]"),
                        )
                        c.execute(
                            "INSERT INTO cve_cpe_ranges(cve_id,cpe_uri,vulnerable,version_start_including,"
                            "version_start_excluding,version_end_including,version_end_excluding,exact_version) "
                            "VALUES (?,?,?,?,?,?,?,?)",
                            (
                                cve_id,
                                base_cpe,
                                1 if cpe_match.get("vulnerable", True) else 0,
                                _first_value(cpe_match, "versionStartIncluding", "version_start_including", "introduced"),
                                _first_value(cpe_match, "versionStartExcluding", "version_start_excluding"),
                                _first_value(cpe_match, "versionEndIncluding", "version_end_including", "fixed"),
                                _first_value(cpe_match, "versionEndExcluding", "version_end_excluding", "limit"),
                                _first_value(cpe_match, "exact_version", "version") or exact_version,
                            ),
                        )
                    imported += 1
        if imported == 0:
            raise ValueError("NVD JSON did not contain importable vulnerabilities")
        db.update_vulnerability_source(
            source,
            source_version=", ".join(sorted(source_versions)) or "nvd-json",
            status="synced",
            record_count=imported,
            sync_progress=1.0,
            success=True,
        )
        return imported
    except Exception as exc:
        db.update_vulnerability_source(source, status="failed", last_error=str(exc))
        raise


def import_cisa_kev(path: str | Path) -> int:
    source = "cisa_kev"
    try:
        db.update_vulnerability_source(source, status="syncing", sync_progress=0.05)
        payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        vulnerabilities = _json_records(payload, "vulnerabilities", "items", "records", "kev")
        if not isinstance(vulnerabilities, list):
            raise ValueError("KEV JSON must contain a vulnerabilities array")
        imported = 0
        with db.cursor() as c:
            for item in vulnerabilities:
                cve_id = _first_value(item, "cveID", "cve_id", "cve", "CVE", "id")
                if not _is_cve(cve_id):
                    continue
                c.execute(
                    "INSERT INTO kev_entries(cve_id,date_added,vendor_project,product,required_action,due_date,notes) "
                    "VALUES (?,?,?,?,?,?,?) "
                    "ON CONFLICT(cve_id) DO UPDATE SET date_added=excluded.date_added,"
                    "vendor_project=excluded.vendor_project,product=excluded.product,"
                    "required_action=excluded.required_action,due_date=excluded.due_date,notes=excluded.notes",
                    (
                        cve_id.upper(),
                        _first_value(item, "dateAdded", "date_added", "date"),
                        _first_value(item, "vendorProject", "vendor_project", "vendor", "vendor_name"),
                        _first_value(item, "product", "package", "package_name"),
                        _first_value(item, "requiredAction", "required_action", "action", "remediation"),
                        _first_value(item, "dueDate", "due_date", "deadline"),
                        _first_value(item, "notes", "shortDescription", "description", "summary"),
                    ),
                )
                imported += 1
        db.update_vulnerability_source(source, status="synced", record_count=imported, sync_progress=1.0, success=True)
        return imported
    except Exception as exc:
        db.update_vulnerability_source(source, status="failed", last_error=str(exc))
        raise


def import_epss_csv(path: str | Path) -> int:
    source = "first_epss"
    try:
        db.update_vulnerability_source(source, status="syncing", sync_progress=0.05)
        imported = 0
        metadata = _csv_comment_metadata(path)
        score_date = metadata.get("score_date", "")
        with db.cursor() as c:
            for row in _csv_rows(path):
                cve_id = _first_value(row, "cve", "cve_id", "CVE", "id")
                if not _is_cve(cve_id):
                    continue
                c.execute(
                    "INSERT INTO epss_scores(cve_id,score,percentile,score_date) VALUES (?,?,?,?) "
                    "ON CONFLICT(cve_id) DO UPDATE SET score=excluded.score,"
                    "percentile=excluded.percentile,score_date=excluded.score_date",
                    (
                        cve_id.upper(),
                        _float_or_none(_first_value(row, "epss", "score", "epss_score")),
                        _float_or_none(_first_value(row, "percentile", "epss_percentile")),
                        _first_value(row, "date", "score_date", "published") or score_date,
                    ),
                )
                imported += 1
        db.update_vulnerability_source(source, status="synced", record_count=imported, sync_progress=1.0, success=True)
        return imported
    except Exception as exc:
        db.update_vulnerability_source(source, status="failed", last_error=str(exc))
        raise


def import_exploitdb_csv(path: str | Path) -> int:
    source = "exploit_db"
    try:
        db.update_vulnerability_source(source, status="syncing", sync_progress=0.05)
        imported = 0
        with db.cursor() as c:
            c.execute("SELECT cve_id,edb_id,title,source FROM exploit_references")
            seen = {
                (row["cve_id"], row["edb_id"] or "", row["title"] or "", row["source"] or "")
                for row in c.fetchall()
            }
            for row in _csv_rows(path):
                cves = _cves_from_row(row)
                if not cves:
                    continue
                edb_id = _first_value(row, "id", "edb_id", "EDB-ID", "exploit_id")
                title = _first_value(row, "description", "title", "Description", "name")
                platform = _first_value(row, "platform", "Platform", "os")
                exploit_type = _first_value(row, "type", "Type", "exploit_type")
                verified = _bool_or_none(_first_value(row, "verified", "Verified"))
                verified_value = None if verified is None else (1 if verified else 0)
                published_ts = _first_value(row, "date_published", "date", "published", "Date", "published_ts")
                reference_url = _first_value(row, "file", "url", "path", "reference_url")
                for cve_id in cves:
                    key = (cve_id, edb_id, title, source)
                    if key in seen:
                        continue
                    seen.add(key)
                    c.execute(
                        "INSERT INTO exploit_references(cve_id,edb_id,title,platform,exploit_type,verified,"
                        "published_ts,reference_url,source) VALUES (?,?,?,?,?,?,?,?,?)",
                        (cve_id, edb_id, title, platform, exploit_type, verified_value, published_ts, reference_url, source),
                    )
                    imported += 1
        db.update_vulnerability_source(source, status="synced", record_count=imported, sync_progress=1.0, success=True)
        return imported
    except Exception as exc:
        db.update_vulnerability_source(source, status="failed", last_error=str(exc))
        raise


def _csv_rows(path: str | Path) -> Iterable[dict[str, str]]:
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        sample_lines = []
        while len("".join(sample_lines)) < 4096:
            line = handle.readline()
            if not line:
                break
            if line.strip() and not line.lstrip().startswith("#"):
                sample_lines.append(line)
        sample = "".join(sample_lines)
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample) if sample.strip() else csv.excel
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader((line for line in handle if not line.lstrip().startswith("#")), dialect=dialect)
        yield from reader


def _csv_comment_metadata(path: str | Path) -> dict[str, str]:
    metadata: dict[str, str] = {}
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            if not stripped.startswith("#"):
                break
            for key, value in re.findall(r"([A-Za-z0-9_.-]+):([^,\s]+)", stripped.lstrip("#")):
                metadata[key.strip().lower()] = value.strip()
    return metadata


def _source_enabled(name: str) -> bool:
    for source in db.vulnerability_sources():
        if source["name"] == name:
            return bool(source["enabled"])
    return True


def _run_with_retries(source_name: str, importer, path: str) -> int:
    attempts = 0
    max_attempts = 3
    last_error = ""
    last_exception: Exception | None = None
    while attempts < max_attempts:
        attempts += 1
        db.update_vulnerability_source(
            source_name,
            status=f"syncing-attempt-{attempts}",
            sync_attempts=attempts,
            sync_progress=0.05,
        )
        try:
            return importer(path)
        except Exception as exc:
            last_exception = exc
            last_error = str(exc)
            if attempts >= max_attempts:
                break
            delay = min(0.2, 0.05 * (2 ** (attempts - 1)))
            next_retry = datetime.now(timezone.utc) + timedelta(seconds=delay)
            db.update_vulnerability_source(
                source_name,
                status="retrying",
                last_error=last_error,
                sync_attempts=attempts,
                next_retry_ts=next_retry.strftime("%Y-%m-%d %H:%M:%S"),
                sync_progress=0.0,
            )
            time.sleep(delay)
    db.update_vulnerability_source(
        source_name,
        status="failed",
        last_error=last_error,
        sync_attempts=attempts,
        sync_progress=0.0,
    )
    raise RuntimeError(f"{source_name} sync failed after {attempts} attempts: {last_error}") from last_exception


def _json_payloads(path: str | Path, *, suffixes: tuple[str, ...]) -> Iterable[dict]:
    source_path = Path(path)
    files = _source_files(source_path, suffixes=suffixes)
    if not files:
        raise FileNotFoundError(f"No supported JSON files found at {source_path}")
    for file_path in files:
        payload = json.loads(_read_text(file_path))
        if not isinstance(payload, dict):
            raise ValueError(f"{file_path} did not contain a JSON object")
        yield payload


def _source_files(path: Path, *, suffixes: tuple[str, ...]) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(
            item for item in path.iterdir()
            if item.is_file() and any(str(item).lower().endswith(suffix) for suffix in suffixes)
        )
    return []


def _read_text(path: Path) -> str:
    if str(path).lower().endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8-sig") as handle:
            return handle.read()
    return path.read_text(encoding="utf-8-sig")


def _json_records(payload, *keys: str) -> list[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in keys:
        value = _value_at_path(payload, key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return [payload] if any(_first_value(payload, *CVE_ALIASES) for _ in [0]) else []


def _payload_source_version(payload: dict) -> str:
    timestamp = _first_value(
        payload,
        "timestamp",
        "lastModifiedDate",
        "lastModified",
        "dateModified",
        "metadata.timestamp",
    )
    if timestamp:
        return timestamp
    return str(payload.get("version") or payload.get("format") or "vulnerability-json")


def _vulnerability_items(payload) -> list[dict]:
    if isinstance(payload, dict) and isinstance(payload.get("CVE_Items"), list):
        return payload["CVE_Items"]
    items = _json_records(
        payload,
        "vulnerabilities",
        "items",
        "records",
        "vulns",
        "data.vulnerabilities",
        "data.items",
    )
    if items:
        return items
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _nvd_lang_value(values: list[dict], lang: str) -> str:
    for item in values:
        if str(item.get("lang", "")).lower() == lang:
            return str(item.get("value") or "").strip()
    return str(values[0].get("value") or "").strip() if values else ""


def _first_legacy_description(cve: dict) -> str:
    descriptions = cve.get("description", {}).get("description_data", [])
    if isinstance(descriptions, list) and descriptions:
        return str(descriptions[0].get("value") or "").strip()
    return ""


def _insert_nvd_metrics(c, cve_id: str, cve: dict) -> None:
    weaknesses = cve.get("weaknesses") or []
    cwes = []
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = str(desc.get("value") or "")
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value)
    for source, metric in _nvd_metrics(cve):
        c.execute(
            "INSERT INTO cve_metrics(cve_id,source,severity,score,vector,cwe_refs) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(cve_id, source) DO UPDATE SET severity=excluded.severity,"
            "score=excluded.score,vector=excluded.vector,cwe_refs=excluded.cwe_refs",
            (
                cve_id,
                source,
                metric.get("severity", ""),
                _float_or_none(str(metric.get("score", ""))),
                metric.get("vector", ""),
                json.dumps(cwes, ensure_ascii=False),
            ),
        )


def _nvd_metrics(cve: dict) -> list[tuple[str, dict]]:
    metrics = cve.get("metrics") or {}
    out: list[tuple[str, dict]] = []
    for key, source in (
        ("cvssMetricV40", "nvd-cvss-v4.0"),
        ("cvssMetricV31", "nvd-cvss-v3.1"),
        ("cvssMetricV30", "nvd-cvss-v3.0"),
        ("cvssMetricV2", "nvd-cvss-v2"),
    ):
        for item in metrics.get(key, []) or []:
            cvss = item.get("cvssData") or {}
            out.append(
                (
                    source,
                    {
                        "severity": item.get("baseSeverity") or cvss.get("baseSeverity") or "",
                        "score": cvss.get("baseScore"),
                        "vector": cvss.get("vectorString") or "",
                    },
                )
            )
    legacy = cve.get("impact") or {}
    if not out and legacy:
        for key, source in (("baseMetricV3", "nvd-cvss-v3"), ("baseMetricV2", "nvd-cvss-v2")):
            metric = legacy.get(key) or {}
            cvss = metric.get("cvssV3") or metric.get("cvssV2") or {}
            if cvss:
                out.append(
                    (
                        source,
                        {
                            "severity": metric.get("severity") or cvss.get("baseSeverity") or "",
                            "score": cvss.get("baseScore"),
                            "vector": cvss.get("vectorString") or "",
                        },
                    )
                )
    return out


def _nvd_cpe_matches(cve: dict) -> list[dict]:
    configs = cve.get("configurations") or []
    if isinstance(configs, dict):
        configs = configs.get("nodes", [])
    matches: list[dict] = []
    stack = list(configs)
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        matches.extend(match for match in node.get("cpeMatch", []) if isinstance(match, dict))
        matches.extend(match for match in node.get("cpe_match", []) if isinstance(match, dict))
        for child_key in ("nodes", "children"):
            stack.extend(child for child in node.get(child_key, []) if isinstance(child, dict))
    return matches


def _cpe_matches(item: dict, cve: dict) -> list[dict]:
    matches = _nvd_cpe_matches(cve)
    for source in (item, cve):
        for key in ("cpes", "cpe_matches", "affected_cpes", "affected.products", "affected"):
            value = _value_at_path(source, key)
            if isinstance(value, list):
                for entry in value:
                    if isinstance(entry, str):
                        matches.append({"cpe": entry})
                    elif isinstance(entry, dict):
                        matches.extend(_expand_cpe_entry(entry))
            elif isinstance(value, str):
                matches.append({"cpe": value})
    return matches


def _expand_cpe_entry(entry: dict) -> list[dict]:
    cpe = _first_value(entry, "criteria", "cpe23Uri", "cpe_uri", "cpe", "uri")
    if cpe:
        return [entry]
    ranges = entry.get("ranges") if isinstance(entry.get("ranges"), list) else []
    package = _first_value(entry, "package", "package_name", "product", "name")
    vendor = _first_value(entry, "vendor", "vendor_project")
    out: list[dict] = []
    for rng in ranges:
        if isinstance(rng, dict):
            row = dict(rng)
            row.setdefault("package", package)
            row.setdefault("vendor", vendor)
            out.append(row)
    return out or [entry]


def _insert_generic_metric(c, cve_id: str, item: dict) -> None:
    score = _float_or_none(_first_value(item, "cvss_score", "cvss", "score", "severity_score"))
    severity = _first_value(item, "severity", "baseSeverity", "cvss_severity")
    vector = _first_value(item, "cvss_vector", "vector", "vectorString")
    if score is None and not severity and not vector:
        return
    c.execute(
        "INSERT INTO cve_metrics(cve_id,source,severity,score,vector,cwe_refs) VALUES (?,?,?,?,?,?) "
        "ON CONFLICT(cve_id, source) DO UPDATE SET severity=excluded.severity,"
        "score=excluded.score,vector=excluded.vector,cwe_refs=excluded.cwe_refs",
        (cve_id, "generic-json", severity, score, vector, "[]"),
    )


def _base_cpe_uri(cpe_uri: str) -> tuple[str, str, str, str]:
    if not cpe_uri.startswith("cpe:2.3:"):
        return "", "", "", ""
    parts = cpe_uri.split(":")
    if len(parts) < 6:
        return "", "", "", ""
    vendor = _cpe_unescape(parts[3])
    product = _cpe_unescape(parts[4])
    version = _cpe_unescape(parts[5])
    base_parts = parts[:]
    base_parts[5] = "*"
    while len(base_parts) < 13:
        base_parts.append("*")
    base_cpe = ":".join(base_parts[:13])
    exact_version = "" if version in {"*", "-", ""} else version
    return base_cpe, vendor, product, exact_version


def _cpe_unescape(value: str) -> str:
    return value.replace("\\:", ":").replace("\\_", "_").strip()


def _generic_cpe_uri(vendor: str, product: str) -> str:
    return f"cpe:2.3:a:{_cpe_token(vendor)}:{_cpe_token(product)}:*:*:*:*:*:*:*:*"


def _cpe_token(value: str) -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "_", (value or "").strip().lower())
    return token or "*"


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
    parts = str(path).split(".")
    for part in parts:
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


def _is_cve(value: str) -> bool:
    return bool(re.fullmatch(r"CVE-\d{4}-\d{4,}", (value or "").upper()))


def _float_or_none(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _bool_or_none(value: str) -> bool | None:
    value = (value or "").strip().lower()
    if value in {"1", "true", "yes", "y", "verified"}:
        return True
    if value in {"0", "false", "no", "n", "unverified"}:
        return False
    return None


def _cves_from_row(row: dict[str, str]) -> list[str]:
    values = [
        _first_value(row, "cve", "cve_id", "codes", "CVE"),
        " ".join(str(value) for value in row.values() if value),
    ]
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        for match in re.findall(r"CVE-\d{4}-\d{4,}", value.upper()):
            if match not in seen:
                seen.add(match)
                out.append(match)
    return out

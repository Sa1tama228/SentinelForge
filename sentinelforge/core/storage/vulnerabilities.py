from __future__ import annotations

import json
import re
import sqlite3

from .. import config
from .connection import FINDING_STATUSES, _json_dump, _json_load, _merge_list, cursor, now

def vulnerability_sources() -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute("SELECT * FROM vulnerability_sources ORDER BY name")
        return c.fetchall()


def vulnerability_source_freshness(max_age_hours: int = 48) -> list[dict]:
    from datetime import datetime, timezone

    out: list[dict] = []
    current = datetime.now(timezone.utc)
    for row in vulnerability_sources():
        source_timestamp = _parse_source_version_timestamp(row["source_version"] or "")
        last_success = row["last_success_ts"] or ""
        age_hours = None
        stale = True
        freshness_basis = "source_version" if source_timestamp is not None else "last_success_ts"
        if source_timestamp is not None:
            age_hours = round((current - source_timestamp).total_seconds() / 3600, 2)
            stale = age_hours > max_age_hours
        elif last_success:
            try:
                parsed = datetime.strptime(last_success, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                age_hours = round((current - parsed).total_seconds() / 3600, 2)
                stale = age_hours > max_age_hours
            except ValueError:
                stale = True
        out.append({**dict(row), "age_hours": age_hours, "stale": stale, "freshness_basis": freshness_basis})
    return out


def _parse_source_version_timestamp(value: str):
    from datetime import datetime, timezone

    candidates = []
    for match in re.finditer(
        r"\d{4}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
        value or "",
    ):
        raw = match.group(0).replace(" ", "T")
        raw = re.sub(r"(\.\d{6})\d+", r"\1", raw)
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        candidates.append(parsed.astimezone(timezone.utc))
    return max(candidates) if candidates else None


def update_vulnerability_source(name: str, *, enabled: bool | None = None,
                                source_version: str | None = None,
                                status: str | None = None,
                                last_error: str | None = None,
                                record_count: int | None = None,
                                sync_progress: float | None = None,
                                sync_attempts: int | None = None,
                                next_retry_ts: str | None = None,
                                success: bool = False) -> None:
    existing = {row["name"] for row in vulnerability_sources()}
    if name not in existing:
        with cursor() as c:
            c.execute("INSERT OR IGNORE INTO vulnerability_sources(name) VALUES (?)", (name,))
    assignments: list[str] = []
    values: list = []
    if enabled is not None:
        assignments.append("enabled=?")
        values.append(1 if enabled else 0)
    if source_version is not None:
        assignments.append("source_version=?")
        values.append(source_version)
    if status is not None:
        assignments.append("status=?")
        values.append(status)
    if last_error is not None:
        assignments.append("last_error=?")
        values.append(last_error)
    if record_count is not None:
        assignments.append("record_count=?")
        values.append(record_count)
    if sync_progress is not None:
        assignments.append("sync_progress=?")
        values.append(max(0.0, min(float(sync_progress), 1.0)))
    if sync_attempts is not None:
        assignments.append("sync_attempts=?")
        values.append(max(0, int(sync_attempts)))
    if next_retry_ts is not None:
        assignments.append("next_retry_ts=?")
        values.append(next_retry_ts)
    assignments.append("last_sync_ts=?")
    values.append(now())
    if success:
        assignments.append("last_success_ts=?")
        values.append(now())
        assignments.append("last_error=?")
        values.append("")
        assignments.append("sync_attempts=?")
        values.append(0)
        assignments.append("next_retry_ts=?")
        values.append("")
        assignments.append("sync_progress=?")
        values.append(1.0)
    if not assignments:
        return
    values.append(name)
    with cursor() as c:
        c.execute(
            f"UPDATE vulnerability_sources SET {', '.join(assignments)} WHERE name=?",
            tuple(values),
        )


def vulnerability_record_counts() -> dict[str, int]:
    tables = {
        "cves": "cves",
        "cpe_products": "cpe_products",
        "cve_cpe_ranges": "cve_cpe_ranges",
        "kev_entries": "kev_entries",
        "epss_scores": "epss_scores",
        "exploit_references": "exploit_references",
        "service_fingerprints": "service_fingerprints",
        "vulnerability_matches": "vulnerability_matches",
        "distribution_advisories": "distribution_advisories",
        "asset_inventory_packages": "asset_inventory_packages",
    }
    out: dict[str, int] = {}
    with cursor() as c:
        for label, table in tables.items():
            c.execute(f"SELECT COUNT(*) AS n FROM {table}")
            out[label] = int(c.fetchone()["n"])
    return out


def add_service_fingerprint(*, scan_result_id: int | None = None,
                            asset_id: int | None = None,
                            ip: str = "", port: int = 0, proto: str = "tcp",
                            vendor: str = "", product: str = "", version: str = "",
                            distribution: str = "", package_revision: str = "",
                            confidence: float = 0.0, detection_method: str = "",
                            evidence: dict | None = None) -> int:
    with cursor() as c:
        c.execute(
            "INSERT INTO service_fingerprints(scan_result_id,asset_id,ip,port,proto,vendor,product,"
            "version,distribution,package_revision,confidence,detection_method,evidence_json,created_ts) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                scan_result_id,
                asset_id,
                ip,
                port,
                proto,
                vendor,
                product,
                version,
                distribution,
                package_revision,
                confidence,
                detection_method,
                json.dumps(evidence or {}, ensure_ascii=False),
                now(),
            ),
        )
        return c.lastrowid or 0


def service_fingerprints_for_asset(asset_id: int) -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute(
            "SELECT * FROM service_fingerprints WHERE asset_id=? ORDER BY created_ts DESC, port",
            (asset_id,),
        )
        return c.fetchall()


def upsert_cve(*, cve_id: str, title: str = "", description: str = "",
               status: str = "", published_ts: str = "", modified_ts: str = "",
               source_name: str = "nvd", raw: dict | None = None) -> int:
    with cursor() as c:
        c.execute("SELECT id FROM cves WHERE cve_id=?", (cve_id,))
        row = c.fetchone()
        payload = json.dumps(raw or {}, ensure_ascii=False)
        if row is None:
            c.execute(
                "INSERT INTO cves(cve_id,title,description,status,published_ts,modified_ts,source_name,raw_json) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (cve_id, title, description, status, published_ts, modified_ts, source_name, payload),
            )
            return c.lastrowid or 0
        c.execute(
            "UPDATE cves SET title=?,description=?,status=?,published_ts=?,modified_ts=?,"
            "source_name=?,raw_json=? WHERE cve_id=?",
            (title, description, status, published_ts, modified_ts, source_name, payload, cve_id),
        )
        return row["id"]


def upsert_cve_metric(*, cve_id: str, source: str, severity: str = "",
                      score: float | None = None, vector: str = "",
                      cwe_refs: list[str] | None = None) -> int:
    with cursor() as c:
        c.execute("SELECT id FROM cve_metrics WHERE cve_id=? AND source=?", (cve_id, source))
        row = c.fetchone()
        refs = json.dumps(cwe_refs or [], ensure_ascii=False)
        if row is None:
            c.execute(
                "INSERT INTO cve_metrics(cve_id,source,severity,score,vector,cwe_refs) VALUES (?,?,?,?,?,?)",
                (cve_id, source, severity, score, vector, refs),
            )
            return c.lastrowid or 0
        c.execute(
            "UPDATE cve_metrics SET severity=?,score=?,vector=?,cwe_refs=? WHERE id=?",
            (severity, score, vector, refs, row["id"]),
        )
        return row["id"]


def upsert_cpe_product(*, vendor: str, product: str, cpe_uri: str,
                       title: str = "", aliases: list[str] | None = None) -> int:
    with cursor() as c:
        c.execute("SELECT id FROM cpe_products WHERE cpe_uri=?", (cpe_uri,))
        row = c.fetchone()
        aliases_json = json.dumps(aliases or [], ensure_ascii=False)
        if row is None:
            c.execute(
                "INSERT INTO cpe_products(vendor,product,cpe_uri,title,aliases_json) VALUES (?,?,?,?,?)",
                (vendor, product, cpe_uri, title, aliases_json),
            )
            return c.lastrowid or 0
        c.execute(
            "UPDATE cpe_products SET vendor=?,product=?,title=?,aliases_json=? WHERE id=?",
            (vendor, product, title, aliases_json, row["id"]),
        )
        return row["id"]


def upsert_cve_cpe_range(*, cve_id: str, cpe_uri: str, vulnerable: bool = True,
                         version_start_including: str = "",
                         version_start_excluding: str = "",
                         version_end_including: str = "",
                         version_end_excluding: str = "",
                         exact_version: str = "") -> int:
    with cursor() as c:
        c.execute(
            "SELECT id FROM cve_cpe_ranges WHERE cve_id=? AND cpe_uri=? AND vulnerable=? "
            "AND COALESCE(version_start_including,'')=? AND COALESCE(version_start_excluding,'')=? "
            "AND COALESCE(version_end_including,'')=? AND COALESCE(version_end_excluding,'')=? "
            "AND COALESCE(exact_version,'')=?",
            (
                cve_id,
                cpe_uri,
                1 if vulnerable else 0,
                version_start_including,
                version_start_excluding,
                version_end_including,
                version_end_excluding,
                exact_version,
            ),
        )
        row = c.fetchone()
        if row:
            return row["id"]
        c.execute(
            "INSERT INTO cve_cpe_ranges(cve_id,cpe_uri,vulnerable,version_start_including,"
            "version_start_excluding,version_end_including,version_end_excluding,exact_version) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                cve_id,
                cpe_uri,
                1 if vulnerable else 0,
                version_start_including,
                version_start_excluding,
                version_end_including,
                version_end_excluding,
                exact_version,
            ),
        )
        return c.lastrowid or 0


def upsert_kev_entry(*, cve_id: str, date_added: str = "",
                     vendor_project: str = "", product: str = "",
                     required_action: str = "", due_date: str = "",
                     notes: str = "") -> None:
    with cursor() as c:
        c.execute(
            "INSERT INTO kev_entries(cve_id,date_added,vendor_project,product,required_action,due_date,notes) "
            "VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(cve_id) DO UPDATE SET date_added=excluded.date_added,"
            "vendor_project=excluded.vendor_project,product=excluded.product,"
            "required_action=excluded.required_action,due_date=excluded.due_date,notes=excluded.notes",
            (cve_id, date_added, vendor_project, product, required_action, due_date, notes),
        )


def upsert_epss_score(*, cve_id: str, score: float | None = None,
                      percentile: float | None = None, score_date: str = "") -> None:
    with cursor() as c:
        c.execute(
            "INSERT INTO epss_scores(cve_id,score,percentile,score_date) VALUES (?,?,?,?) "
            "ON CONFLICT(cve_id) DO UPDATE SET score=excluded.score,"
            "percentile=excluded.percentile,score_date=excluded.score_date",
            (cve_id, score, percentile, score_date),
        )


def upsert_exploit_reference(*, cve_id: str, edb_id: str = "", title: str = "",
                             platform: str = "", exploit_type: str = "",
                             verified: bool | None = None,
                             published_ts: str = "", reference_url: str = "",
                             source: str = "exploit-db") -> int:
    with cursor() as c:
        c.execute(
            "SELECT id FROM exploit_references WHERE cve_id=? AND edb_id=? AND title=? AND source=?",
            (cve_id, edb_id, title, source),
        )
        row = c.fetchone()
        verified_value = None if verified is None else (1 if verified else 0)
        if row is None:
            c.execute(
                "INSERT INTO exploit_references(cve_id,edb_id,title,platform,exploit_type,verified,"
                "published_ts,reference_url,source) VALUES (?,?,?,?,?,?,?,?,?)",
                (cve_id, edb_id, title, platform, exploit_type, verified_value, published_ts, reference_url, source),
            )
            return c.lastrowid or 0
        c.execute(
            "UPDATE exploit_references SET platform=?,exploit_type=?,verified=?,published_ts=?,"
            "reference_url=? WHERE id=?",
            (platform, exploit_type, verified_value, published_ts, reference_url, row["id"]),
        )
        return row["id"]


def vulnerability_ranges_for_cpes(cpe_uris: list[str]) -> list[sqlite3.Row]:
    if not cpe_uris:
        return []
    placeholders = ",".join("?" for _ in cpe_uris)
    with cursor() as c:
        c.execute(
            f"SELECT r.*, cv.title, cv.description, cv.status AS cve_status, cv.published_ts, cv.modified_ts "
            f"FROM cve_cpe_ranges r LEFT JOIN cves cv ON cv.cve_id=r.cve_id "
            f"WHERE r.cpe_uri IN ({placeholders}) ORDER BY r.cve_id",
            tuple(cpe_uris),
        )
        return c.fetchall()


def cpe_products_for_product(product: str, *, vendor: str = "", limit: int = 25) -> list[sqlite3.Row]:
    product = (product or "").strip().lower()
    vendor = (vendor or "").strip().lower()
    if not product:
        return []
    with cursor() as c:
        if vendor:
            c.execute(
                "SELECT * FROM cpe_products WHERE lower(product)=? AND lower(vendor)=? "
                "ORDER BY cpe_uri LIMIT ?",
                (product, vendor, limit),
            )
        else:
            c.execute(
                "SELECT * FROM cpe_products WHERE lower(product)=? ORDER BY cpe_uri LIMIT ?",
                (product, limit),
            )
        return c.fetchall()


def vulnerability_enrichment(cve_id: str) -> dict:
    with cursor() as c:
        c.execute("SELECT * FROM cve_metrics WHERE cve_id=? ORDER BY source", (cve_id,))
        metrics = [dict(row) for row in c.fetchall()]
        c.execute("SELECT * FROM kev_entries WHERE cve_id=?", (cve_id,))
        kev = c.fetchone()
        c.execute("SELECT * FROM epss_scores WHERE cve_id=?", (cve_id,))
        epss = c.fetchone()
        c.execute("SELECT * FROM exploit_references WHERE cve_id=? ORDER BY published_ts DESC", (cve_id,))
        exploits = [dict(row) for row in c.fetchall()]
    return {
        "metrics": metrics,
        "kev": dict(kev) if kev else None,
        "epss": dict(epss) if epss else None,
        "exploits": exploits,
    }


def vulnerability_enrichment_bulk(cve_ids: list[str]) -> dict[str, dict]:
    ids = sorted({cve_id for cve_id in cve_ids if cve_id})
    if not ids:
        return {}
    placeholders = ",".join("?" for _ in ids)
    out = {
        cve_id: {"metrics": [], "kev": None, "epss": None, "exploits": []}
        for cve_id in ids
    }
    with cursor() as c:
        c.execute(
            f"SELECT * FROM cve_metrics WHERE cve_id IN ({placeholders}) ORDER BY cve_id, source",
            tuple(ids),
        )
        for row in c.fetchall():
            out[row["cve_id"]]["metrics"].append(dict(row))
        c.execute(f"SELECT * FROM kev_entries WHERE cve_id IN ({placeholders})", tuple(ids))
        for row in c.fetchall():
            out[row["cve_id"]]["kev"] = dict(row)
        c.execute(f"SELECT * FROM epss_scores WHERE cve_id IN ({placeholders})", tuple(ids))
        for row in c.fetchall():
            out[row["cve_id"]]["epss"] = dict(row)
        c.execute(
            f"SELECT * FROM exploit_references WHERE cve_id IN ({placeholders}) ORDER BY cve_id, published_ts DESC",
            tuple(ids),
        )
        for row in c.fetchall():
            out[row["cve_id"]]["exploits"].append(dict(row))
    return out


def upsert_vulnerability_match(*, finding_id: int | None = None, cve_id: str,
                               asset_id: int | None = None,
                               service_fingerprint_id: int | None = None,
                               matched_cpe: str = "", match_status: str,
                               confidence_score: float = 0.0,
                               confidence_explanation: str = "",
                               priority_score: float = 0.0,
                               priority_explanation: str = "",
                               evidence: dict | None = None) -> int:
    with cursor() as c:
        c.execute(
            "SELECT id FROM vulnerability_matches WHERE cve_id=? AND asset_id IS ? "
            "AND service_fingerprint_id IS ? AND matched_cpe=?",
            (cve_id, asset_id, service_fingerprint_id, matched_cpe),
        )
        row = c.fetchone()
        payload = json.dumps(evidence or {}, ensure_ascii=False)
        if row is None:
            c.execute(
                "INSERT INTO vulnerability_matches(finding_id,cve_id,asset_id,service_fingerprint_id,"
                "matched_cpe,match_status,confidence_score,confidence_explanation,priority_score,"
                "priority_explanation,evidence_json,created_ts) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    finding_id,
                    cve_id,
                    asset_id,
                    service_fingerprint_id,
                    matched_cpe,
                    match_status,
                    confidence_score,
                    confidence_explanation,
                    priority_score,
                    priority_explanation,
                    payload,
                    now(),
                ),
            )
            return c.lastrowid or 0
        c.execute(
            "UPDATE vulnerability_matches SET finding_id=?,match_status=?,confidence_score=?,"
            "confidence_explanation=?,priority_score=?,priority_explanation=?,evidence_json=? WHERE id=?",
            (
                finding_id,
                match_status,
                confidence_score,
                confidence_explanation,
                priority_score,
                priority_explanation,
                payload,
                row["id"],
            ),
        )
        return row["id"]


# --- assets / findings ------------------------------------------------------

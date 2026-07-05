from __future__ import annotations

import json
import sqlite3

from .. import config
from .connection import FINDING_STATUSES, _json_dump, _json_load, _merge_list, cursor, now

def upsert_asset(hostname: str, *, ips: list[str] | None = None, source: str = "",
                 tags: list[str] | None = None, open_services: list[dict] | None = None,
                 dns_records: dict | None = None, certificates: list[dict] | None = None,
                 technologies: list[str] | None = None, notes: str | None = None) -> int:
    hostname = hostname.strip().lower()
    ts = now()
    with cursor() as c:
        c.execute("SELECT * FROM assets WHERE hostname=?", (hostname,))
        row = c.fetchone()
        if row is None:
            c.execute(
                "INSERT INTO assets(hostname,normalized_ips,first_seen,last_seen,source,tags,"
                "open_services,dns_records,certificates,technologies,notes) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    hostname,
                    _json_dump(sorted(set(ips or []))),
                    ts,
                    ts,
                    source,
                    _json_dump(tags or []),
                    _json_dump(open_services or []),
                    _json_dump(dns_records or {}),
                    _json_dump(certificates or []),
                    _json_dump(technologies or []),
                    notes or "",
                ),
            )
            return c.lastrowid or 0

        merged_ips = sorted(set(_json_load(row["normalized_ips"], []) + (ips or [])))
        merged_tags = _merge_list(_json_load(row["tags"], []), tags or [])
        merged_services = _merge_list(_json_load(row["open_services"], []), open_services or [])
        merged_certs = _merge_list(_json_load(row["certificates"], []), certificates or [])
        merged_tech = sorted(set(_json_load(row["technologies"], []) + (technologies or [])))
        merged_dns = _json_load(row["dns_records"], {})
        if dns_records:
            merged_dns.update(dns_records)
        next_notes = notes if notes is not None else row["notes"]
        c.execute(
            "UPDATE assets SET normalized_ips=?,last_seen=?,source=?,tags=?,open_services=?,"
            "dns_records=?,certificates=?,technologies=?,notes=? WHERE id=?",
            (
                _json_dump(merged_ips),
                ts,
                source or row["source"],
                _json_dump(merged_tags),
                _json_dump(merged_services),
                _json_dump(merged_dns),
                _json_dump(merged_certs),
                _json_dump(merged_tech),
                next_notes,
                row["id"],
            ),
        )
        return row["id"]


def add_asset_scan_history(asset_id: int, *, scan_run_id: int | None = None,
                           source: str = "", summary: str = "") -> None:
    with cursor() as c:
        c.execute(
            "INSERT INTO asset_scan_history(asset_id,scan_run_id,source,summary,ts) VALUES (?,?,?,?,?)",
            (asset_id, scan_run_id, source, summary, now()),
        )


def assets(limit: int = 500) -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute("SELECT * FROM assets ORDER BY last_seen DESC LIMIT ?", (limit,))
        return c.fetchall()


def asset_by_id(asset_id: int) -> sqlite3.Row | None:
    with cursor() as c:
        c.execute("SELECT * FROM assets WHERE id=?", (asset_id,))
        return c.fetchone()


def asset_findings(asset_id: int) -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute("SELECT * FROM findings WHERE asset_id=? ORDER BY last_seen DESC", (asset_id,))
        return c.fetchall()


def asset_findings_for_assets(asset_ids: list[int]) -> dict[int, list[sqlite3.Row]]:
    ids = sorted({int(asset_id) for asset_id in asset_ids if asset_id})
    if not ids:
        return {}
    placeholders = ",".join("?" for _ in ids)
    out = {asset_id: [] for asset_id in ids}
    with cursor() as c:
        c.execute(
            f"SELECT * FROM findings WHERE asset_id IN ({placeholders}) ORDER BY asset_id, last_seen DESC",
            tuple(ids),
        )
        for row in c.fetchall():
            out.setdefault(int(row["asset_id"]), []).append(row)
    return out


def asset_scan_history(asset_id: int) -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute("SELECT * FROM asset_scan_history WHERE asset_id=? ORDER BY id DESC", (asset_id,))
        return c.fetchall()


def asset_scan_history_for_assets(asset_ids: list[int]) -> dict[int, list[sqlite3.Row]]:
    ids = sorted({int(asset_id) for asset_id in asset_ids if asset_id})
    if not ids:
        return {}
    placeholders = ",".join("?" for _ in ids)
    out = {asset_id: [] for asset_id in ids}
    with cursor() as c:
        c.execute(
            f"SELECT * FROM asset_scan_history WHERE asset_id IN ({placeholders}) ORDER BY asset_id, id DESC",
            tuple(ids),
        )
        for row in c.fetchall():
            out.setdefault(int(row["asset_id"]), []).append(row)
    return out


def update_asset_notes(asset_id: int, notes: str) -> None:
    with cursor() as c:
        c.execute("UPDATE assets SET notes=? WHERE id=?", (notes, asset_id))


def upsert_finding(*, title: str, severity: str, confidence: str, status: str = "New",
                   asset_id: int | None = None, evidence: str = "", source_module: str = "",
                   remediation: str = "", fingerprint: str) -> int:
    if status not in FINDING_STATUSES:
        raise ValueError(f"Invalid finding status: {status}")
    ts = now()
    with cursor() as c:
        c.execute("SELECT id,status FROM findings WHERE fingerprint=?", (fingerprint,))
        row = c.fetchone()
        if row is None:
            c.execute(
                "INSERT INTO findings(title,severity,confidence,status,asset_id,evidence,source_module,"
                "remediation,first_seen,last_seen,fingerprint) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    title,
                    severity,
                    confidence,
                    status,
                    asset_id,
                    evidence,
                    source_module,
                    remediation,
                    ts,
                    ts,
                    fingerprint,
                ),
            )
            return c.lastrowid or 0
        next_status = "Reopened" if row["status"] == "Resolved" else row["status"]
        c.execute(
            "UPDATE findings SET title=?,severity=?,confidence=?,status=?,asset_id=?,evidence=?,"
            "source_module=?,remediation=?,last_seen=? WHERE id=?",
            (
                title,
                severity,
                confidence,
                next_status,
                asset_id,
                evidence,
                source_module,
                remediation,
                ts,
                row["id"],
            ),
        )
        return row["id"]


def findings(limit: int = 500, status: str | None = None) -> list[sqlite3.Row]:
    with cursor() as c:
        if status:
            c.execute(
                "SELECT f.*, a.hostname AS asset_hostname FROM findings f "
                "LEFT JOIN assets a ON a.id=f.asset_id WHERE f.status=? "
                "ORDER BY f.last_seen DESC LIMIT ?",
                (status, limit),
            )
        else:
            c.execute(
                "SELECT f.*, a.hostname AS asset_hostname FROM findings f "
                "LEFT JOIN assets a ON a.id=f.asset_id ORDER BY f.last_seen DESC LIMIT ?",
                (limit,),
            )
        return c.fetchall()


def update_finding_status(finding_id: int, status: str) -> None:
    if status not in FINDING_STATUSES:
        raise ValueError(f"Invalid finding status: {status}")
    with cursor() as c:
        c.execute("UPDATE findings SET status=?,last_seen=? WHERE id=?", (status, now(), finding_id))


def vulnerability_matches_for_finding(finding_id: int) -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute(
            "SELECT * FROM vulnerability_matches WHERE finding_id=? ORDER BY priority_score DESC, confidence_score DESC",
            (finding_id,),
        )
        return c.fetchall()


def vulnerability_matches_for_findings(finding_ids: list[int]) -> dict[int, list[sqlite3.Row]]:
    ids = sorted({int(finding_id) for finding_id in finding_ids if finding_id})
    if not ids:
        return {}
    placeholders = ",".join("?" for _ in ids)
    out = {finding_id: [] for finding_id in ids}
    with cursor() as c:
        c.execute(
            f"SELECT * FROM vulnerability_matches WHERE finding_id IN ({placeholders}) "
            "ORDER BY finding_id, priority_score DESC, confidence_score DESC",
            tuple(ids),
        )
        for row in c.fetchall():
            out.setdefault(int(row["finding_id"]), []).append(row)
    return out


def add_vulnerability_suppression(*, cve_id: str = "", asset_id: int | None = None,
                                  product: str = "", matched_cpe: str = "",
                                  match_status: str = "", reason: str = "",
                                  expires_ts: str = "") -> int:
    with cursor() as c:
        c.execute(
            "INSERT INTO vulnerability_suppressions(cve_id,asset_id,product,matched_cpe,match_status,reason,expires_ts,created_ts) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (cve_id, asset_id, product, matched_cpe, match_status, reason, expires_ts, now()),
        )
        return c.lastrowid or 0


def vulnerability_suppressions() -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute("SELECT * FROM vulnerability_suppressions ORDER BY id DESC")
        return c.fetchall()


def distribution_advisories_for(cve_id: str, *, distribution: str = "", package_name: str = "") -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute(
            "SELECT * FROM distribution_advisories WHERE cve_id=? "
            "AND (distribution='' OR lower(distribution)=lower(?) OR ?='') "
            "AND (lower(package_name)=lower(?) OR ?='') "
            "ORDER BY source_name",
            (cve_id, distribution, distribution, package_name, package_name),
        )
        return c.fetchall()


def upsert_asset_package(asset_id: int, *, package_name: str, version: str = "", source: str = "inventory") -> int:
    with cursor() as c:
        c.execute(
            "INSERT INTO asset_inventory_packages(asset_id,package_name,version,source,imported_ts) VALUES (?,?,?,?,?) "
            "ON CONFLICT(asset_id, package_name, source) DO UPDATE SET version=excluded.version,imported_ts=excluded.imported_ts",
            (asset_id, package_name, version, source, now()),
        )
        c.execute(
            "SELECT id FROM asset_inventory_packages WHERE asset_id=? AND package_name=? AND source=?",
            (asset_id, package_name, source),
        )
        return int(c.fetchone()["id"])


def add_cpe_product_override(*, raw_product: str, vendor: str, product: str, cpe_uri: str,
                             confidence: float = 0.99) -> int:
    raw_product = (raw_product or "").strip().lower()
    with cursor() as c:
        c.execute(
            "INSERT INTO cpe_product_overrides(raw_product,vendor,product,cpe_uri,confidence,created_ts) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(raw_product, cpe_uri) DO UPDATE SET vendor=excluded.vendor,product=excluded.product,confidence=excluded.confidence",
            (raw_product, vendor, product, cpe_uri, confidence, now()),
        )
        c.execute("SELECT id FROM cpe_product_overrides WHERE raw_product=? AND cpe_uri=?", (raw_product, cpe_uri))
        return int(c.fetchone()["id"])


def cpe_product_overrides(raw_product: str) -> list[sqlite3.Row]:
    raw_product = (raw_product or "").strip().lower()
    if not raw_product:
        return []
    with cursor() as c:
        c.execute(
            "SELECT * FROM cpe_product_overrides WHERE raw_product=? ORDER BY confidence DESC",
            (raw_product,),
        )
        return c.fetchall()


def asset_packages(asset_id: int) -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute("SELECT * FROM asset_inventory_packages WHERE asset_id=? ORDER BY package_name", (asset_id,))
        return c.fetchall()


def asset_packages_for_assets(asset_ids: list[int]) -> dict[int, list[sqlite3.Row]]:
    ids = sorted({int(asset_id) for asset_id in asset_ids if asset_id})
    if not ids:
        return {}
    placeholders = ",".join("?" for _ in ids)
    out = {asset_id: [] for asset_id in ids}
    with cursor() as c:
        c.execute(
            f"SELECT * FROM asset_inventory_packages WHERE asset_id IN ({placeholders}) "
            "ORDER BY asset_id, package_name",
            tuple(ids),
        )
        for row in c.fetchall():
            out.setdefault(int(row["asset_id"]), []).append(row)
    return out


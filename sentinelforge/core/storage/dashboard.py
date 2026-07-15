from __future__ import annotations

import sqlite3

from .connection import cursor


def _escape_like(value: str) -> str:
    return value.replace("!", "!!").replace("%", "!%").replace("_", "!_")


def dashboard_counts() -> dict[str, int | float]:
    """Return Dashboard KPI aggregates without loading inventory rows."""
    with cursor() as c:
        # Review items follow the same High threshold as the displayed risk score.
        c.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM assets) AS assets, "
            "(SELECT COUNT(*) FROM findings) AS findings, "
            "(SELECT COUNT(*) FROM scan_runs) AS scan_runs, "
            "(SELECT COUNT(*) FROM scan_runs WHERE lower(status) IN ('queued','running','cancelling')) AS running_scans, "
            "(SELECT COUNT(DISTINCT f.id) FROM findings f "
            " LEFT JOIN vulnerability_matches vm ON vm.finding_id=f.id "
            " WHERE f.status NOT IN ('Resolved','False positive') "
            " AND (lower(f.severity) IN ('critical','high') OR vm.priority_score >= 60)) AS review_items, "
            "COALESCE((SELECT MAX(CASE lower(severity) "
            " WHEN 'critical' THEN 100 WHEN 'high' THEN 80 WHEN 'medium' THEN 55 "
            " WHEN 'low' THEN 30 ELSE 10 END) FROM findings "
            " WHERE status NOT IN ('Resolved','False positive')), 0) AS severity_score, "
            "COALESCE((SELECT MAX(vm.priority_score) FROM vulnerability_matches vm "
            " JOIN findings f ON f.id=vm.finding_id "
            " WHERE f.status NOT IN ('Resolved','False positive')), 0) AS priority_score"
        )
        row = c.fetchone()
    return {
        "assets": int(row["assets"] or 0),
        "findings": int(row["findings"] or 0),
        "scan_runs": int(row["scan_runs"] or 0),
        "running_scans": int(row["running_scans"] or 0),
        "review_items": int(row["review_items"] or 0),
        "severity_score": float(row["severity_score"] or 0.0),
        "priority_score": float(row["priority_score"] or 0.0),
    }


def dashboard_active_scan() -> sqlite3.Row | None:
    """Return the newest active run without hiding older work behind completed rows."""
    with cursor() as c:
        c.execute(
            "SELECT * FROM scan_runs WHERE lower(status) IN ('queued','running','cancelling') ORDER BY id DESC LIMIT 1"
        )
        return c.fetchone()


def dashboard_activity(
    *,
    activity_type: str = "",
    severity: str = "",
    search: str = "",
    limit: int = 10,
) -> list[sqlite3.Row]:
    """Query the unified finding/signal stream with filtering and a hard row limit."""
    clean_type = activity_type.strip().lower()
    clean_severity = severity.strip().lower()
    clean_search = search.strip().lower()
    # Escape LIKE metacharacters so search always treats user input literally.
    like = f"%{_escape_like(clean_search)}%"
    safe_limit = max(1, min(int(limit), 50))
    # Normalize findings and operational events before filtering in SQLite.
    sql = """
        WITH activity AS (
            SELECT
                f.last_seen AS timestamp,
                CASE lower(f.severity)
                    WHEN 'critical' THEN 'Critical'
                    WHEN 'high' THEN 'High'
                    WHEN 'medium' THEN 'Medium'
                    WHEN 'low' THEN 'Low'
                    ELSE 'Info'
                END AS severity,
                'finding' AS item_type,
                f.title AS title,
                COALESCE(a.hostname, '-') AS asset,
                COALESCE(NULLIF(f.source_module, ''), 'Correlation') AS source,
                CAST(f.id AS TEXT) AS source_id,
                COALESCE(GROUP_CONCAT(DISTINCT vm.cve_id), '') AS cve_id,
                COALESCE(f.evidence, '') || ' ' || COALESCE(f.fingerprint, '') AS search_blob
            FROM findings f
            LEFT JOIN assets a ON a.id=f.asset_id
            LEFT JOIN vulnerability_matches vm ON vm.finding_id=f.id
            GROUP BY f.id

            UNION ALL

            SELECT
                h.ts AS timestamp,
                CASE
                    WHEN lower(COALESCE(h.classification, '')) LIKE '%exploit%' THEN 'High'
                    WHEN lower(COALESCE(h.classification, '')) LIKE '%credential%' THEN 'High'
                    WHEN lower(COALESCE(h.classification, '')) LIKE '%scanner%' THEN 'Low'
                    ELSE 'Info'
                END AS severity,
                'signal' AS item_type,
                CASE
                    WHEN COALESCE(h.classification, '') NOT IN ('', 'connection')
                        THEN 'Honeypot ' || h.classification
                    ELSE upper(h.hp_type) || ' honeypot activity'
                END AS title,
                h.src_ip AS asset,
                'Honeypot' AS source,
                'honeypot:' || CAST(h.id AS TEXT) AS source_id,
                '' AS cve_id,
                COALESCE(h.method, '') || ' ' || COALESCE(h.path, '') || ' ' || COALESCE(h.body, '') AS search_blob
            FROM honeypot_events h

            UNION ALL

            SELECT
                COALESCE(s.finished_ts, s.started_ts, s.ts) AS timestamp,
                CASE
                    WHEN lower(s.status) IN ('failed','error','dns-failed','invalid') THEN 'Medium'
                    ELSE 'Info'
                END AS severity,
                'signal' AS item_type,
                CASE
                    WHEN lower(s.status) IN ('queued','running','cancelling') THEN 'Scan in progress'
                    WHEN lower(s.status) IN ('failed','error','dns-failed','invalid') THEN 'Scan failed'
                    WHEN lower(s.status)='cancelled' THEN 'Scan cancelled'
                    ELSE 'Scan completed'
                END AS title,
                s.target AS asset,
                'Scanner' AS source,
                'scan:' || CAST(s.id AS TEXT) AS source_id,
                '' AS cve_id,
                COALESCE(s.ports, '') || ' ' || COALESCE(s.error, '') || ' ' || COALESCE(s.status, '') AS search_blob
            FROM scan_runs s

            UNION ALL

            SELECT
                r.found_ts AS timestamp,
                CASE WHEN lower(r.kind) IN ('exposure','takeover') THEN 'Medium' ELSE 'Info' END AS severity,
                'signal' AS item_type,
                'Recon ' || replace(r.kind, '_', ' ') AS title,
                t.domain AS asset,
                'Recon' AS source,
                'recon:' || CAST(r.id AS TEXT) AS source_id,
                '' AS cve_id,
                COALESCE(r.data_json, '') AS search_blob
            FROM recon_findings r
            JOIN recon_targets t ON t.id=r.target_id
        )
        SELECT timestamp, severity, item_type, title, asset, source, source_id, cve_id
        FROM activity
        WHERE (?='' OR item_type=?)
          AND (?='' OR lower(severity)=?)
          AND (?='' OR lower(title || ' ' || asset || ' ' || source || ' ' || cve_id || ' ' || search_blob)
              LIKE ? ESCAPE '!')
        ORDER BY datetime(timestamp) DESC, source_id DESC
        LIMIT ?
    """
    with cursor() as c:
        c.execute(
            sql,
            (
                clean_type,
                clean_type,
                clean_severity,
                clean_severity,
                clean_search,
                like,
                safe_limit,
            ),
        )
        return c.fetchall()


def dashboard_honeypot_summary() -> sqlite3.Row:
    with cursor() as c:
        c.execute(
            "SELECT COUNT(*) AS events, COUNT(DISTINCT src_ip) AS source_ips, "
            "MAX(ts) AS last_event_ts FROM honeypot_events"
        )
        return c.fetchone()


def dashboard_service_candidates(limit: int = 200) -> list[sqlite3.Row]:
    """Return a bounded, risk-ordered set of assets that expose services."""
    safe_limit = max(1, min(int(limit), 1000))
    with cursor() as c:
        c.execute(
            "SELECT a.id, a.hostname, a.normalized_ips, a.open_services, a.last_seen, "
            "COALESCE(MAX(vm.priority_score), 0) AS priority_score, "
            "COALESCE(MAX(CASE lower(f.severity) WHEN 'critical' THEN 5 WHEN 'high' THEN 4 "
            "WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END), 0) AS severity_rank "
            "FROM assets a "
            "LEFT JOIN findings f ON f.asset_id=a.id AND f.status NOT IN ('Resolved','False positive') "
            "LEFT JOIN vulnerability_matches vm ON vm.finding_id=f.id "
            "WHERE a.open_services IS NOT NULL AND a.open_services NOT IN ('', '[]') "
            "GROUP BY a.id "
            "ORDER BY priority_score DESC, severity_rank DESC, a.last_seen DESC, a.id DESC "
            "LIMIT ?",
            (safe_limit,),
        )
        return c.fetchall()

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .. import config

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None
SCHEMA_VERSION = 6

SCHEMA = """
CREATE TABLE IF NOT EXISTS honeypot_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    hp_type    TEXT NOT NULL,
    src_ip     TEXT NOT NULL,
    src_port   INTEGER,
    method     TEXT,
    path       TEXT,
    headers    TEXT,
    body       TEXT,
    classification TEXT,
    iocs_json      TEXT NOT NULL DEFAULT '{}',
    geo_json       TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    target  TEXT NOT NULL,
    ports   TEXT,
    status  TEXT NOT NULL,
    started_ts TEXT,
    finished_ts TEXT,
    error TEXT NOT NULL DEFAULT '',
    check_vulns INTEGER NOT NULL DEFAULT 0,
    profile_key TEXT NOT NULL DEFAULT 'custom',
    progress REAL NOT NULL DEFAULT 0.0,
    cancel_requested INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_results (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id    INTEGER NOT NULL,
    port      INTEGER NOT NULL,
    proto     TEXT,
    service   TEXT,
    version   TEXT,
    banner    TEXT,
    cve_refs  TEXT,
    FOREIGN KEY(run_id) REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS recon_targets (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    domain    TEXT UNIQUE NOT NULL,
    added_ts  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recon_findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id  INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    data_json  TEXT NOT NULL,
    found_ts   TEXT NOT NULL,
    FOREIGN KEY(target_id) REFERENCES recon_targets(id)
);

CREATE TABLE IF NOT EXISTS assets (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname           TEXT UNIQUE NOT NULL,
    normalized_ips     TEXT NOT NULL DEFAULT '[]',
    first_seen         TEXT NOT NULL,
    last_seen          TEXT NOT NULL,
    source             TEXT,
    tags               TEXT NOT NULL DEFAULT '[]',
    open_services      TEXT NOT NULL DEFAULT '[]',
    dns_records        TEXT NOT NULL DEFAULT '{}',
    certificates       TEXT NOT NULL DEFAULT '[]',
    technologies       TEXT NOT NULL DEFAULT '[]',
    notes              TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL,
    confidence     TEXT NOT NULL,
    status         TEXT NOT NULL,
    asset_id       INTEGER,
    evidence       TEXT,
    source_module  TEXT,
    remediation    TEXT,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    fingerprint    TEXT UNIQUE NOT NULL,
    FOREIGN KEY(asset_id) REFERENCES assets(id)
);

CREATE TABLE IF NOT EXISTS asset_scan_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL,
    scan_run_id INTEGER,
    source      TEXT,
    summary     TEXT,
    ts          TEXT NOT NULL,
    FOREIGN KEY(asset_id) REFERENCES assets(id)
);

CREATE INDEX IF NOT EXISTS idx_hp_ts   ON honeypot_events(ts);
CREATE INDEX IF NOT EXISTS idx_hp_ip   ON honeypot_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_scan_run ON scan_results(run_id);
CREATE INDEX IF NOT EXISTS idx_recon_t  ON recon_findings(target_id);
CREATE INDEX IF NOT EXISTS idx_asset_seen ON assets(last_seen);
CREATE INDEX IF NOT EXISTS idx_finding_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_finding_asset ON findings(asset_id);
"""

FINDING_STATUSES = {
    "New",
    "Confirmed",
    "False positive",
    "Accepted risk",
    "Resolved",
    "Reopened",
}


def connect() -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is None:
            cfg = config.load()
            Path(cfg["db_path"]).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(cfg["db_path"], check_same_thread=False)
            conn.row_factory = sqlite3.Row
            _configure_connection(conn)
            conn.executescript(SCHEMA)
            _ensure_columns(conn)
            _run_migrations(conn)
            _ensure_vulnerability_indexes(conn)
            conn.commit()
            _conn = conn
    return _conn


def _configure_connection(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")


def _schema_version(conn: sqlite3.Connection) -> int:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_ts TEXT NOT NULL)")
    row = conn.execute("SELECT MAX(version) AS version FROM schema_migrations").fetchone()
    return int(row["version"] or 0) if row else 0


def _run_migrations(conn: sqlite3.Connection) -> None:
    current = _schema_version(conn)
    migrations = {
        1: _migration_001_vulnerability_cache,
        2: _migration_002_vulnerability_source_progress,
        3: _migration_003_vulnerability_suppressions,
        4: _migration_004_advisories_inventory_schedules,
        5: _migration_005_cpe_overrides,
        6: _migration_006_recon_source_status,
    }
    for version in range(current + 1, SCHEMA_VERSION + 1):
        migrations[version](conn)
        conn.execute(
            "INSERT INTO schema_migrations(version, applied_ts) VALUES (?, ?)",
            (version, now()),
        )


def _migration_001_vulnerability_cache(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS vulnerability_sources (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            name                TEXT UNIQUE NOT NULL,
            enabled             INTEGER NOT NULL DEFAULT 1,
            source_version      TEXT,
            last_sync_ts        TEXT,
            last_success_ts     TEXT,
            status              TEXT NOT NULL DEFAULT 'never-synced',
            last_error          TEXT,
            record_count        INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS cves (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id          TEXT UNIQUE NOT NULL,
            title           TEXT,
            description     TEXT,
            status          TEXT,
            published_ts    TEXT,
            modified_ts     TEXT,
            source_name     TEXT NOT NULL DEFAULT 'nvd',
            raw_json        TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS cve_metrics (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id      TEXT NOT NULL,
            source      TEXT NOT NULL,
            severity    TEXT,
            score       REAL,
            vector      TEXT,
            cwe_refs    TEXT NOT NULL DEFAULT '[]',
            UNIQUE(cve_id, source)
        );

        CREATE TABLE IF NOT EXISTS cpe_products (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor          TEXT NOT NULL,
            product         TEXT NOT NULL,
            cpe_uri         TEXT NOT NULL UNIQUE,
            title           TEXT,
            aliases_json    TEXT NOT NULL DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS cve_cpe_ranges (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id                  TEXT NOT NULL,
            cpe_uri                 TEXT NOT NULL,
            vulnerable              INTEGER NOT NULL DEFAULT 1,
            version_start_including TEXT,
            version_start_excluding TEXT,
            version_end_including   TEXT,
            version_end_excluding   TEXT,
            exact_version           TEXT
        );

        CREATE TABLE IF NOT EXISTS kev_entries (
            cve_id                  TEXT PRIMARY KEY,
            date_added              TEXT,
            vendor_project          TEXT,
            product                 TEXT,
            required_action         TEXT,
            due_date                TEXT,
            notes                   TEXT
        );

        CREATE TABLE IF NOT EXISTS epss_scores (
            cve_id          TEXT PRIMARY KEY,
            score           REAL,
            percentile      REAL,
            score_date      TEXT
        );

        CREATE TABLE IF NOT EXISTS exploit_references (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id          TEXT NOT NULL,
            edb_id          TEXT,
            title           TEXT,
            platform        TEXT,
            exploit_type    TEXT,
            verified        INTEGER,
            published_ts    TEXT,
            reference_url   TEXT,
            source          TEXT NOT NULL DEFAULT 'exploit-db'
        );

        CREATE TABLE IF NOT EXISTS service_fingerprints (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_result_id      INTEGER,
            asset_id            INTEGER,
            ip                  TEXT,
            port                INTEGER,
            proto               TEXT,
            vendor              TEXT,
            product             TEXT,
            version             TEXT,
            distribution        TEXT,
            package_revision    TEXT,
            confidence          REAL,
            detection_method    TEXT,
            evidence_json       TEXT NOT NULL DEFAULT '{}',
            created_ts          TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vulnerability_matches (
            id                      INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id              INTEGER,
            cve_id                  TEXT NOT NULL,
            asset_id                INTEGER,
            service_fingerprint_id  INTEGER,
            matched_cpe             TEXT,
            match_status            TEXT NOT NULL,
            confidence_score        REAL,
            confidence_explanation  TEXT,
            priority_score          REAL,
            priority_explanation    TEXT,
            evidence_json           TEXT NOT NULL DEFAULT '{}',
            created_ts              TEXT NOT NULL,
            UNIQUE(cve_id, asset_id, service_fingerprint_id, matched_cpe)
        );

        CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id);
        CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product ON cpe_products(vendor, product);
        CREATE INDEX IF NOT EXISTS idx_cve_cpe_ranges_cve ON cve_cpe_ranges(cve_id);
        CREATE INDEX IF NOT EXISTS idx_vuln_matches_cve ON vulnerability_matches(cve_id);
        CREATE INDEX IF NOT EXISTS idx_vuln_matches_asset ON vulnerability_matches(asset_id);
        """
    )
    for name in ("nvd", "cisa_kev", "first_epss", "exploit_db"):
        conn.execute(
            "INSERT OR IGNORE INTO vulnerability_sources(name,status) VALUES (?, 'never-synced')",
            (name,),
        )


def _migration_002_vulnerability_source_progress(conn: sqlite3.Connection) -> None:
    cols = {row[1] for row in conn.execute("PRAGMA table_info(vulnerability_sources)").fetchall()}
    additions = {
        "sync_progress": "REAL NOT NULL DEFAULT 0",
        "sync_attempts": "INTEGER NOT NULL DEFAULT 0",
        "next_retry_ts": "TEXT",
    }
    for name, ddl in additions.items():
        if name not in cols:
            conn.execute(f"ALTER TABLE vulnerability_sources ADD COLUMN {name} {ddl}")


def _migration_003_vulnerability_suppressions(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS vulnerability_suppressions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id          TEXT,
            asset_id        INTEGER,
            product         TEXT,
            matched_cpe     TEXT,
            match_status    TEXT,
            reason          TEXT,
            expires_ts      TEXT,
            created_ts      TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_vuln_suppressions_cve ON vulnerability_suppressions(cve_id);
        CREATE INDEX IF NOT EXISTS idx_vuln_suppressions_asset ON vulnerability_suppressions(asset_id);
        """
    )


def _migration_004_advisories_inventory_schedules(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS distribution_advisories (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id          TEXT NOT NULL,
            distribution    TEXT,
            package_name    TEXT NOT NULL,
            fixed_version   TEXT,
            status          TEXT,
            reference_url   TEXT,
            source_name     TEXT NOT NULL,
            raw_json        TEXT NOT NULL DEFAULT '{}',
            UNIQUE(cve_id, distribution, package_name, source_name)
        );
        CREATE INDEX IF NOT EXISTS idx_dist_adv_cve ON distribution_advisories(cve_id);
        CREATE INDEX IF NOT EXISTS idx_dist_adv_pkg ON distribution_advisories(distribution, package_name);

        CREATE TABLE IF NOT EXISTS asset_inventory_packages (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id        INTEGER NOT NULL,
            package_name    TEXT NOT NULL,
            version         TEXT,
            source          TEXT,
            imported_ts     TEXT NOT NULL,
            UNIQUE(asset_id, package_name, source)
        );
        CREATE INDEX IF NOT EXISTS idx_asset_pkg_asset ON asset_inventory_packages(asset_id);
        CREATE INDEX IF NOT EXISTS idx_asset_pkg_name ON asset_inventory_packages(package_name);

        CREATE TABLE IF NOT EXISTS scan_schedules (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            target          TEXT NOT NULL,
            ports           TEXT NOT NULL,
            profile_key     TEXT NOT NULL DEFAULT 'custom',
            check_vulns     INTEGER NOT NULL DEFAULT 0,
            interval_hours  INTEGER NOT NULL DEFAULT 24,
            enabled         INTEGER NOT NULL DEFAULT 1,
            last_run_ts     TEXT,
            next_run_ts     TEXT,
            created_ts      TEXT NOT NULL
        );
        """
    )
    conn.execute("INSERT OR IGNORE INTO vulnerability_sources(name,status) VALUES ('vendor_advisories', 'never-synced')")


def _migration_005_cpe_overrides(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS cpe_product_overrides (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_product     TEXT NOT NULL,
            vendor          TEXT NOT NULL,
            product         TEXT NOT NULL,
            cpe_uri         TEXT NOT NULL,
            confidence      REAL NOT NULL DEFAULT 0.99,
            created_ts      TEXT NOT NULL,
            UNIQUE(raw_product, cpe_uri)
        );
        CREATE INDEX IF NOT EXISTS idx_cpe_override_raw ON cpe_product_overrides(raw_product);
        """
    )


def _migration_006_recon_source_status(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS recon_source_status (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id       INTEGER NOT NULL,
            source_name     TEXT NOT NULL,
            status          TEXT NOT NULL,
            record_count    INTEGER NOT NULL DEFAULT 0,
            last_error      TEXT,
            updated_ts      TEXT NOT NULL,
            UNIQUE(target_id, source_name)
        );
        CREATE INDEX IF NOT EXISTS idx_recon_source_target ON recon_source_status(target_id);
        """
    )


def _ensure_columns(conn: sqlite3.Connection) -> None:
    cols = {row[1] for row in conn.execute("PRAGMA table_info(honeypot_events)").fetchall()}
    additions = {
        "classification": "TEXT",
        "iocs_json": "TEXT NOT NULL DEFAULT '{}'",
        "geo_json": "TEXT NOT NULL DEFAULT '{}'",
    }
    for name, ddl in additions.items():
        if name not in cols:
            conn.execute(f"ALTER TABLE honeypot_events ADD COLUMN {name} {ddl}")
    scan_cols = {row[1] for row in conn.execute("PRAGMA table_info(scan_runs)").fetchall()}
    scan_additions = {
        "started_ts": "TEXT",
        "finished_ts": "TEXT",
        "error": "TEXT NOT NULL DEFAULT ''",
        "check_vulns": "INTEGER NOT NULL DEFAULT 0",
        "profile_key": "TEXT NOT NULL DEFAULT 'custom'",
        "progress": "REAL NOT NULL DEFAULT 0.0",
        "cancel_requested": "INTEGER NOT NULL DEFAULT 0",
    }
    for name, ddl in scan_additions.items():
        if name not in scan_cols:
            conn.execute(f"ALTER TABLE scan_runs ADD COLUMN {name} {ddl}")


def _ensure_vulnerability_indexes(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_cve_metrics_cve ON cve_metrics(cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_cpe_ranges_cpe ON cve_cpe_ranges(cpe_uri);
        CREATE INDEX IF NOT EXISTS idx_kev_cve ON kev_entries(cve_id);
        CREATE INDEX IF NOT EXISTS idx_epss_cve ON epss_scores(cve_id);
        CREATE INDEX IF NOT EXISTS idx_exploit_refs_cve ON exploit_references(cve_id);
        CREATE INDEX IF NOT EXISTS idx_exploit_refs_key ON exploit_references(cve_id, edb_id, title, source);
        CREATE INDEX IF NOT EXISTS idx_service_fingerprints_asset ON service_fingerprints(asset_id);
        CREATE INDEX IF NOT EXISTS idx_service_fingerprints_scan_result ON service_fingerprints(scan_result_id);
        CREATE INDEX IF NOT EXISTS idx_vuln_matches_finding ON vulnerability_matches(finding_id);
        CREATE INDEX IF NOT EXISTS idx_vuln_matches_fp ON vulnerability_matches(service_fingerprint_id);
        CREATE INDEX IF NOT EXISTS idx_scan_runs_status ON scan_runs(status);
        CREATE INDEX IF NOT EXISTS idx_scan_runs_started ON scan_runs(started_ts);
        CREATE INDEX IF NOT EXISTS idx_asset_scan_history_asset ON asset_scan_history(asset_id);
        CREATE INDEX IF NOT EXISTS idx_asset_scan_history_run ON asset_scan_history(scan_run_id);
        CREATE INDEX IF NOT EXISTS idx_hp_type_ts ON honeypot_events(hp_type, ts);
        CREATE INDEX IF NOT EXISTS idx_hp_classification_ts ON honeypot_events(classification, ts);
        """
    )


@contextmanager
def cursor() -> Iterator[sqlite3.Cursor]:
    conn = connect()
    with _lock:
        cur = conn.cursor()
        try:
            yield cur
            if conn.in_transaction:
                conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _json_load(value: str | None, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _json_dump(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _merge_list(existing: list, incoming: list) -> list:
    seen = {str(item) for item in existing}
    out = list(existing)
    for item in incoming:
        key = str(item)
        if key not in seen:
            out.append(item)
            seen.add(key)
    return out


# --- vulnerability source cache --------------------------------------------

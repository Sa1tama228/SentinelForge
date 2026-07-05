from __future__ import annotations

import json
import sqlite3

from .. import config
from .connection import FINDING_STATUSES, _json_dump, _json_load, _merge_list, cursor, now

def get_or_create_target(domain: str) -> int:
    with cursor() as c:
        c.execute("SELECT id FROM recon_targets WHERE domain=?", (domain,))
        row = c.fetchone()
        if row:
            return row["id"]
        c.execute(
            "INSERT INTO recon_targets(domain,added_ts) VALUES (?,?)",
            (domain, now()),
        )
        return c.lastrowid or 0


def add_recon_finding(target_id: int, kind: str, data: dict) -> None:
    with cursor() as c:
        c.execute(
            "INSERT INTO recon_findings(target_id,kind,data_json,found_ts) VALUES (?,?,?,?)",
            (target_id, kind, json.dumps(data, ensure_ascii=False), now()),
        )


def clear_recon_findings(target_id: int) -> None:
    with cursor() as c:
        c.execute("DELETE FROM recon_findings WHERE target_id=?", (target_id,))


def recon_findings_for(target_id: int) -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute(
            "SELECT * FROM recon_findings WHERE target_id=? ORDER BY id",
            (target_id,),
        )
        return c.fetchall()


def update_recon_source_status(target_id: int, source_name: str, *,
                               status: str, record_count: int = 0,
                               last_error: str = "") -> None:
    with cursor() as c:
        c.execute(
            "INSERT INTO recon_source_status(target_id,source_name,status,record_count,last_error,updated_ts) "
            "VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(target_id, source_name) DO UPDATE SET status=excluded.status,"
            "record_count=excluded.record_count,last_error=excluded.last_error,updated_ts=excluded.updated_ts",
            (target_id, source_name, status, record_count, last_error, now()),
        )


def recon_source_status(target_id: int) -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute(
            "SELECT * FROM recon_source_status WHERE target_id=? ORDER BY source_name",
            (target_id,),
        )
        return c.fetchall()


def recent_targets(limit: int = 50) -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute(
            "SELECT * FROM recon_targets ORDER BY id DESC LIMIT ?", (limit,)
        )
        return c.fetchall()


def target_by_id(target_id: int) -> sqlite3.Row | None:
    with cursor() as c:
        c.execute("SELECT * FROM recon_targets WHERE id=?", (target_id,))
        return c.fetchone()

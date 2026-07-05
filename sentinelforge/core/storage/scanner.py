from __future__ import annotations

import json
import sqlite3

from .. import config
from .connection import FINDING_STATUSES, _json_dump, _json_load, _merge_list, cursor, now

def add_scan_schedule(*, target: str, ports: str, profile_key: str = "custom",
                      check_vulns: bool = False, interval_hours: int = 24,
                      next_run_ts: str = "") -> int:
    with cursor() as c:
        c.execute(
            "INSERT INTO scan_schedules(target,ports,profile_key,check_vulns,interval_hours,enabled,created_ts) "
            "VALUES (?,?,?,?,?,?,?)",
            (target, ports, profile_key, 1 if check_vulns else 0, interval_hours, 1, now()),
        )
        schedule_id = c.lastrowid or 0
        if next_run_ts:
            c.execute("UPDATE scan_schedules SET next_run_ts=? WHERE id=?", (next_run_ts, schedule_id))
        return schedule_id


def scan_schedules() -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute("SELECT * FROM scan_schedules ORDER BY id DESC")
        return c.fetchall()


def due_scan_schedules(ts: str | None = None) -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute(
            "SELECT * FROM scan_schedules WHERE enabled=1 AND (next_run_ts IS NULL OR next_run_ts='' OR next_run_ts<=?) "
            "ORDER BY next_run_ts, id",
            (ts or now(),),
        )
        return c.fetchall()


def update_scan_schedule(schedule_id: int, *, enabled: bool | None = None,
                         next_run_ts: str | None = None, last_run_ts: str | None = None) -> None:
    assignments = []
    values = []
    if enabled is not None:
        assignments.append("enabled=?")
        values.append(1 if enabled else 0)
    if next_run_ts is not None:
        assignments.append("next_run_ts=?")
        values.append(next_run_ts)
    if last_run_ts is not None:
        assignments.append("last_run_ts=?")
        values.append(last_run_ts)
    if not assignments:
        return
    values.append(schedule_id)
    with cursor() as c:
        c.execute(f"UPDATE scan_schedules SET {', '.join(assignments)} WHERE id=?", tuple(values))


def delete_scan_schedule(schedule_id: int) -> None:
    with cursor() as c:
        c.execute("DELETE FROM scan_schedules WHERE id=?", (schedule_id,))


def clear_scan_history() -> None:
    with cursor() as c:
        c.execute("DELETE FROM vulnerability_matches")
        c.execute("DELETE FROM service_fingerprints")
        c.execute("DELETE FROM scan_results")
        c.execute("DELETE FROM scan_runs")
        c.execute("DELETE FROM asset_scan_history")


def prune_scan_history(max_runs: int = 5000) -> int:
    max_runs = max(0, int(max_runs))
    with cursor() as c:
        c.execute(
            "SELECT id FROM scan_runs ORDER BY id DESC LIMIT -1 OFFSET ?",
            (max_runs,),
        )
        old_ids = [int(row["id"]) for row in c.fetchall()]
        if not old_ids:
            return 0
        placeholders = ",".join("?" for _ in old_ids)
        c.execute(f"DELETE FROM vulnerability_matches WHERE service_fingerprint_id IN "
                  f"(SELECT id FROM service_fingerprints WHERE scan_result_id IN "
                  f"(SELECT id FROM scan_results WHERE run_id IN ({placeholders})))", tuple(old_ids))
        c.execute(f"DELETE FROM service_fingerprints WHERE scan_result_id IN "
                  f"(SELECT id FROM scan_results WHERE run_id IN ({placeholders}))", tuple(old_ids))
        c.execute(f"DELETE FROM scan_results WHERE run_id IN ({placeholders})", tuple(old_ids))
        c.execute(f"DELETE FROM asset_scan_history WHERE scan_run_id IN ({placeholders})", tuple(old_ids))
        c.execute(f"DELETE FROM scan_runs WHERE id IN ({placeholders})", tuple(old_ids))
        return len(old_ids)


def clear_findings() -> None:
    with cursor() as c:
        c.execute("DELETE FROM vulnerability_matches")
        c.execute("DELETE FROM findings")


def clear_assets() -> None:
    with cursor() as c:
        c.execute("DELETE FROM vulnerability_matches")
        c.execute("DELETE FROM service_fingerprints")
        c.execute("DELETE FROM asset_inventory_packages")
        c.execute("DELETE FROM asset_scan_history")
        c.execute("DELETE FROM findings")
        c.execute("DELETE FROM assets")


def vulnerability_match_suppressed(*, cve_id: str, asset_id: int | None,
                                   product: str, matched_cpe: str, match_status: str) -> bool:
    with cursor() as c:
        c.execute(
            "SELECT * FROM vulnerability_suppressions "
            "WHERE (expires_ts IS NULL OR expires_ts='' OR expires_ts>?) "
            "AND (cve_id IS NULL OR cve_id='' OR cve_id=?) "
            "AND (asset_id IS NULL OR asset_id=?) "
            "AND (product IS NULL OR product='' OR lower(product)=lower(?)) "
            "AND (matched_cpe IS NULL OR matched_cpe='' OR matched_cpe=?) "
            "AND (match_status IS NULL OR match_status='' OR match_status=?) "
            "LIMIT 1",
            (now(), cve_id, asset_id, product, matched_cpe, match_status),
        )
        return c.fetchone() is not None


# --- honeypot ---------------------------------------------------------------

def create_scan_run(target: str, ports: str, *, check_vulns: bool = False, profile_key: str = "custom") -> int:
    with cursor() as c:
        c.execute(
            "INSERT INTO scan_runs(ts,target,ports,status,started_ts,check_vulns,profile_key,progress) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (now(), target, ports, "running", now(), 1 if check_vulns else 0, profile_key or "custom", 0.0),
        )
        return c.lastrowid or 0


def update_scan_run_progress(run_id: int, *, status: str | None = None, progress: float | None = None,
                             error: str | None = None, cancel_requested: bool | None = None) -> None:
    assignments = []
    values = []
    if status is not None:
        assignments.append("status=?")
        values.append(status)
    if progress is not None:
        assignments.append("progress=?")
        values.append(max(0.0, min(float(progress), 1.0)))
    if error is not None:
        assignments.append("error=?")
        values.append(error)
    if cancel_requested is not None:
        assignments.append("cancel_requested=?")
        values.append(1 if cancel_requested else 0)
    if not assignments:
        return
    values.append(run_id)
    with cursor() as c:
        c.execute(f"UPDATE scan_runs SET {', '.join(assignments)} WHERE id=?", tuple(values))


def add_scan_result(run_id: int, port: int, *, proto: str = "tcp",
                    service: str = "", version: str = "", banner: str = "",
                    cve_refs: str = "") -> int:
    with cursor() as c:
        c.execute(
            "INSERT INTO scan_results(run_id,port,proto,service,version,banner,cve_refs) "
            "VALUES (?,?,?,?,?,?,?)",
            (run_id, port, proto, service, version, banner, cve_refs),
        )
        return c.lastrowid or 0


def finish_scan_run(run_id: int, status: str = "done", *, error: str = "") -> None:
    with cursor() as c:
        c.execute(
            "UPDATE scan_runs SET status=?,finished_ts=?,progress=?,error=? WHERE id=?",
            (status, now(), 1.0, error, run_id),
        )


def scan_results_for_run(run_id: int) -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute(
            "SELECT * FROM scan_results WHERE run_id=? ORDER BY port", (run_id,)
        )
        return c.fetchall()


def recent_scan_runs(limit: int = 50) -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute(
            "SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,)
        )
        return c.fetchall()


# --- recon ------------------------------------------------------------------

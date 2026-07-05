from __future__ import annotations

import json
import sqlite3

from .. import config
from .connection import FINDING_STATUSES, _json_dump, _json_load, _merge_list, cursor, now

def add_honeypot_event(hp_type: str, src_ip: str, src_port: int, *,
                       method: str = "", path: str = "", headers: str = "",
                       body: str = "", classification: str = "",
                       iocs: dict | None = None, geo: dict | None = None) -> int:
    with cursor() as c:
        c.execute(
            "INSERT INTO honeypot_events(ts,hp_type,src_ip,src_port,method,path,headers,body,"
            "classification,iocs_json,geo_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                now(),
                hp_type,
                src_ip,
                src_port,
                method,
                path,
                headers,
                body,
                classification,
                json.dumps(iocs or {}, ensure_ascii=False),
                json.dumps(geo or {}, ensure_ascii=False),
            ),
        )
        return c.lastrowid or 0


def recent_honeypot_events(limit: int = 200) -> list[sqlite3.Row]:
    with cursor() as c:
        c.execute(
            "SELECT * FROM honeypot_events ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return c.fetchall()


def search_honeypot_events(*, query: str = "", classification: str = "", hp_type: str = "",
                           limit: int = 500) -> list[sqlite3.Row]:
    clauses = []
    values = []
    if query:
        like = f"%{query}%"
        clauses.append("(src_ip LIKE ? OR method LIKE ? OR path LIKE ? OR headers LIKE ? OR body LIKE ?)")
        values.extend([like, like, like, like, like])
    if classification:
        clauses.append("classification=?")
        values.append(classification)
    if hp_type:
        clauses.append("hp_type=?")
        values.append(hp_type)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    values.append(limit)
    with cursor() as c:
        c.execute(f"SELECT * FROM honeypot_events{where} ORDER BY id DESC LIMIT ?", tuple(values))
        return c.fetchall()


def honeypot_classification_counts() -> dict[str, int]:
    with cursor() as c:
        c.execute("SELECT classification, COUNT(*) AS n FROM honeypot_events GROUP BY classification ORDER BY n DESC")
        return {row["classification"] or "unclassified": int(row["n"]) for row in c.fetchall()}


def honeypot_sessions(limit: int = 100) -> list[dict]:
    rows = recent_honeypot_events(limit=1000)
    sessions: dict[tuple[str, str], dict] = {}
    for row in rows:
        sid = _session_from_headers(row["headers"] or "") or f"{row['src_ip']}:{row['hp_type']}"
        key = (row["src_ip"], sid)
        item = sessions.setdefault(
            key,
            {
                "src_ip": row["src_ip"],
                "session": sid,
                "types": set(),
                "count": 0,
                "first_ts": row["ts"],
                "last_ts": row["ts"],
                "classifications": set(),
            },
        )
        item["types"].add(row["hp_type"])
        item["classifications"].add(row["classification"] or "connection")
        item["count"] += 1
        item["first_ts"] = min(item["first_ts"], row["ts"])
        item["last_ts"] = max(item["last_ts"], row["ts"])
    out = []
    for item in sessions.values():
        item["types"] = sorted(item["types"])
        item["classifications"] = sorted(item["classifications"])
        out.append(item)
    return sorted(out, key=lambda item: item["last_ts"], reverse=True)[:limit]


def _session_from_headers(headers: str) -> str:
    for line in headers.splitlines():
        if line.startswith("session="):
            return line.split("=", 1)[1].strip()
    return ""


def clear_honeypot_events() -> None:
    with cursor() as c:
        c.execute("DELETE FROM honeypot_events")


def prune_honeypot_events(max_events: int = 50000) -> int:
    max_events = max(0, int(max_events))
    with cursor() as c:
        c.execute(
            "SELECT id FROM honeypot_events ORDER BY id DESC LIMIT -1 OFFSET ?",
            (max_events,),
        )
        old_ids = [int(row["id"]) for row in c.fetchall()]
        if not old_ids:
            return 0
        placeholders = ",".join("?" for _ in old_ids)
        c.execute(f"DELETE FROM honeypot_events WHERE id IN ({placeholders})", tuple(old_ids))
        return len(old_ids)


def apply_retention() -> dict[str, int]:
    from .scanner import prune_scan_history

    cfg = config.load().get("retention", {})
    return {
        "honeypot_events": prune_honeypot_events(int(cfg.get("honeypot_max_events", 50000) or 50000)),
        "scan_runs": prune_scan_history(int(cfg.get("scan_history_max_runs", 5000) or 5000)),
    }


def honeypot_stats() -> dict:
    with cursor() as c:
        c.execute("SELECT COUNT(*) AS n FROM honeypot_events")
        total = c.fetchone()["n"]
        c.execute(
            "SELECT hp_type, COUNT(*) AS n FROM honeypot_events GROUP BY hp_type"
        )
        by_type = {r["hp_type"]: r["n"] for r in c.fetchall()}
        c.execute(
            "SELECT src_ip, COUNT(*) AS n FROM honeypot_events "
            "GROUP BY src_ip ORDER BY n DESC LIMIT 10"
        )
        top_ips = [(r["src_ip"], r["n"]) for r in c.fetchall()]
    return {"total": total, "by_type": by_type, "top_ips": top_ips}


# --- scanner ----------------------------------------------------------------

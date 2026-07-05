"""Synthetic data generation and benchmark helpers."""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

from .analysis import attack_paths, evidence_graph, honeypot_campaigns
from .reports import exporter
from ..core import db

PREFIX = "sf-stress-"


def seed(*, assets: int = 200, findings_per_asset: int = 3,
         honeypot_events: int = 1000, recon_targets: int = 50) -> dict:
    assets = max(0, int(assets))
    findings_per_asset = max(0, int(findings_per_asset))
    honeypot_events = max(0, int(honeypot_events))
    recon_targets = max(0, int(recon_targets))
    started = time.perf_counter()
    conn = db.connect()
    with db.cursor() as c:
        for idx in range(assets):
            hostname = f"{PREFIX}asset-{idx:05d}.example.test"
            ip = f"10.{(idx // 65536) % 255}.{(idx // 256) % 255}.{idx % 255 or 1}"
            services = _services_for(idx)
            c.execute("SELECT id FROM assets WHERE hostname=?", (hostname,))
            row = c.fetchone()
            payload = (
                json.dumps([ip], ensure_ascii=False),
                db.now(),
                "stress",
                json.dumps(["stress"], ensure_ascii=False),
                json.dumps(services, ensure_ascii=False),
                json.dumps({}, ensure_ascii=False),
                json.dumps([], ensure_ascii=False),
                json.dumps(sorted({tech for svc in services for tech in svc.get("technologies", [])}), ensure_ascii=False),
                "synthetic stress asset",
            )
            if row:
                asset_id = int(row["id"])
                c.execute(
                    "UPDATE assets SET normalized_ips=?,last_seen=?,source=?,tags=?,open_services=?,dns_records=?,certificates=?,technologies=?,notes=? WHERE id=?",
                    (*payload, asset_id),
                )
                if c.rowcount == 0:
                    c.execute(
                        "INSERT INTO assets(hostname,normalized_ips,first_seen,last_seen,source,tags,open_services,dns_records,certificates,technologies,notes) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            hostname,
                            json.dumps([ip], ensure_ascii=False),
                            db.now(),
                            db.now(),
                            "stress",
                            json.dumps(["stress"], ensure_ascii=False),
                            json.dumps(services, ensure_ascii=False),
                            json.dumps({}, ensure_ascii=False),
                            json.dumps([], ensure_ascii=False),
                            json.dumps(sorted({tech for svc in services for tech in svc.get("technologies", [])}), ensure_ascii=False),
                            "synthetic stress asset",
                        ),
                    )
                    asset_id = int(c.lastrowid or 0)
            else:
                c.execute(
                    "INSERT INTO assets(hostname,normalized_ips,first_seen,last_seen,source,tags,open_services,dns_records,certificates,technologies,notes) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        hostname,
                        json.dumps([ip], ensure_ascii=False),
                        db.now(),
                        db.now(),
                        "stress",
                        json.dumps(["stress"], ensure_ascii=False),
                        json.dumps(services, ensure_ascii=False),
                        json.dumps({}, ensure_ascii=False),
                        json.dumps([], ensure_ascii=False),
                        json.dumps(sorted({tech for svc in services for tech in svc.get("technologies", [])}), ensure_ascii=False),
                        "synthetic stress asset",
                    ),
                )
                asset_id = int(c.lastrowid or 0)
            c.execute(
                "INSERT INTO asset_scan_history(asset_id,source,summary,ts) VALUES (?,?,?,?)",
                (asset_id, "stress", f"{len(services)} synthetic services; delta added={len(services)}", db.now()),
            )
            for finding_idx in range(findings_per_asset):
                finding_id = _upsert_stress_finding(c, asset_id, idx, finding_idx)
                if finding_idx % 2 == 0:
                    _upsert_stress_match(c, asset_id, finding_id, idx, finding_idx)

        for idx in range(recon_targets):
            domain = f"{PREFIX}recon-{idx:05d}.example.test"
            c.execute("INSERT OR IGNORE INTO recon_targets(domain,added_ts) VALUES (?,?)", (domain, db.now()))
            c.execute("SELECT id FROM recon_targets WHERE domain=?", (domain,))
            target_id = int(c.fetchone()["id"])
            c.execute(
                "INSERT INTO recon_findings(target_id,kind,data_json,found_ts) VALUES (?,?,?,?)",
                (
                    target_id,
                    "exposure",
                    json.dumps({"checks": [{"path": "/.env", "url": f"https://{domain}/.env", "status": 200, "severity": "High", "title": "Potential exposed environment file", "sample": "KEY=value", "confidence": "medium"}], "count": 1}, ensure_ascii=False),
                    db.now(),
                ),
            )
            c.execute(
                "INSERT INTO recon_source_status(target_id,source_name,status,record_count,last_error,updated_ts) VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(target_id, source_name) DO UPDATE SET status=excluded.status,record_count=excluded.record_count,last_error=excluded.last_error,updated_ts=excluded.updated_ts",
                (target_id, "exposure", "ok", 1, "", db.now()),
            )

        for idx in range(honeypot_events):
            classification = "exploit-probe" if idx % 11 == 0 else "login-probe" if idx % 5 == 0 else "connection"
            path = "/../../etc/passwd?cmd=wget" if classification == "exploit-probe" else "/wp-login.php" if classification == "login-probe" else "/"
            iocs = {"alerts": ["suspicious-payload"] if classification == "exploit-probe" else [], "credentials": []}
            c.execute(
                "INSERT INTO honeypot_events(ts,hp_type,src_ip,src_port,method,path,headers,body,classification,iocs_json,geo_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    db.now(),
                    "http",
                    f"198.51.100.{idx % 250 + 1}",
                    30000 + (idx % 20000),
                    "GET",
                    path,
                    f"user_agent=stress/{idx % 13}",
                    "",
                    classification,
                    json.dumps(iocs, ensure_ascii=False),
                    "{}",
                ),
            )
    return {
        "assets": assets,
        "findings": assets * findings_per_asset,
        "honeypot_events": honeypot_events,
        "recon_targets": recon_targets,
        "elapsed_sec": round(time.perf_counter() - started, 3),
        "counts": _stress_counts(conn),
    }


def benchmark(*, report_format: str = "json") -> dict:
    timings = {}
    details = {}

    started = time.perf_counter()
    graph = evidence_graph.build()
    timings["graph_sec"] = round(time.perf_counter() - started, 4)
    details["graph"] = graph.as_dict()["summary"]

    started = time.perf_counter()
    paths = attack_paths.analyze(limit=100)
    timings["attack_paths_sec"] = round(time.perf_counter() - started, 4)
    details["attack_paths"] = paths["summary"]

    started = time.perf_counter()
    campaigns = honeypot_campaigns.cluster(limit=5000, max_campaigns=50)
    timings["honeypot_campaigns_sec"] = round(time.perf_counter() - started, 4)
    details["honeypot_campaigns"] = {"count": len(campaigns), "top_score": campaigns[0]["score"] if campaigns else 0}

    with tempfile.TemporaryDirectory(prefix="sentinelforge-stress-report-") as tmp:
        started = time.perf_counter()
        path = exporter.export_inventory(report_format, out_dir=tmp)
        timings["report_sec"] = round(time.perf_counter() - started, 4)
        details["report"] = {"format": report_format, "bytes": Path(path).stat().st_size}

    return {
        "timings": timings,
        "details": details,
        "counts": _stress_counts(db.connect()),
        "thresholds": _thresholds(timings),
    }


def clear() -> dict:
    conn = db.connect()
    with db.cursor() as c:
        c.execute("SELECT id FROM assets WHERE hostname LIKE ?", (PREFIX + "%",))
        asset_ids = [int(row["id"]) for row in c.fetchall()]
        c.execute("SELECT id FROM recon_targets WHERE domain LIKE ?", (PREFIX + "%",))
        target_ids = [int(row["id"]) for row in c.fetchall()]
        if asset_ids:
            placeholders = ",".join("?" for _ in asset_ids)
            c.execute(f"DELETE FROM vulnerability_matches WHERE asset_id IN ({placeholders})", tuple(asset_ids))
            c.execute(f"DELETE FROM service_fingerprints WHERE asset_id IN ({placeholders})", tuple(asset_ids))
            c.execute(f"DELETE FROM asset_inventory_packages WHERE asset_id IN ({placeholders})", tuple(asset_ids))
            c.execute(f"DELETE FROM asset_scan_history WHERE asset_id IN ({placeholders})", tuple(asset_ids))
            c.execute(f"DELETE FROM findings WHERE asset_id IN ({placeholders})", tuple(asset_ids))
            c.execute(f"DELETE FROM assets WHERE id IN ({placeholders})", tuple(asset_ids))
        if target_ids:
            placeholders = ",".join("?" for _ in target_ids)
            c.execute(f"DELETE FROM recon_source_status WHERE target_id IN ({placeholders})", tuple(target_ids))
            c.execute(f"DELETE FROM recon_findings WHERE target_id IN ({placeholders})", tuple(target_ids))
            c.execute(f"DELETE FROM recon_targets WHERE id IN ({placeholders})", tuple(target_ids))
        c.execute("DELETE FROM honeypot_events WHERE headers LIKE 'user_agent=stress/%'")
    return {"removed_assets": len(asset_ids), "removed_recon_targets": len(target_ids), "counts": _stress_counts(conn)}


def _services_for(idx: int) -> list[dict]:
    services = [{"port": 80, "proto": "tcp", "service": "http", "version": "nginx 1.24", "technologies": ["nginx"]}]
    if idx % 2 == 0:
        services.append({"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 8.9p1", "technologies": ["OpenSSH"]})
    if idx % 5 == 0:
        services.append({"port": 3306, "proto": "tcp", "service": "mysql", "version": "MariaDB 11.8.8", "technologies": ["MariaDB"]})
    if idx % 7 == 0:
        services.append({"port": 6379, "proto": "tcp", "service": "redis", "version": "Redis 7.2", "technologies": ["Redis"]})
    return services


def _upsert_stress_finding(c, asset_id: int, asset_idx: int, finding_idx: int) -> int:
    fingerprint = f"{PREFIX}finding:{asset_idx}:{finding_idx}"
    severity = "High" if finding_idx % 3 == 0 else "Medium" if finding_idx % 3 == 1 else "Low"
    title = f"Stress finding {asset_idx}-{finding_idx}"
    c.execute("SELECT id FROM findings WHERE fingerprint=?", (fingerprint,))
    row = c.fetchone()
    if row:
        return int(row["id"])
    c.execute(
        "INSERT INTO findings(title,severity,confidence,status,asset_id,evidence,source_module,remediation,first_seen,last_seen,fingerprint) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            title,
            severity,
            "High" if finding_idx % 2 == 0 else "Medium",
            "New",
            asset_id,
            f"stress evidence for asset {asset_idx}",
            "stress",
            "synthetic remediation",
            db.now(),
            db.now(),
            fingerprint,
        ),
    )
    return int(c.lastrowid or 0)


def _upsert_stress_match(c, asset_id: int, finding_id: int, asset_idx: int, finding_idx: int) -> None:
    cve = f"CVE-2099-{asset_idx % 10000:04d}{finding_idx % 10}"
    evidence = {
        "service": "http" if finding_idx % 3 else "ssh",
        "product": "nginx" if finding_idx % 3 else "OpenSSH",
        "version": "1.24" if finding_idx % 3 else "8.9p1",
        "cvss_score": 7.5 + (finding_idx % 3),
        "kev": finding_idx % 11 == 0,
        "epss": {"score": 0.2 + ((asset_idx + finding_idx) % 8) / 10},
        "public_exploit_count": 1 if finding_idx % 5 == 0 else 0,
    }
    c.execute(
        "INSERT INTO vulnerability_matches(finding_id,cve_id,asset_id,service_fingerprint_id,matched_cpe,match_status,confidence_score,confidence_explanation,priority_score,priority_explanation,evidence_json,created_ts) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(cve_id, asset_id, service_fingerprint_id, matched_cpe) DO UPDATE SET finding_id=excluded.finding_id,match_status=excluded.match_status,confidence_score=excluded.confidence_score,evidence_json=excluded.evidence_json",
        (
            finding_id,
            cve,
            asset_id,
            0,
            "cpe:2.3:a:stress:synthetic:*:*:*:*:*:*:*:*",
            "confirmed_candidate" if finding_idx % 4 == 0 else "likely_candidate",
            0.72 + ((finding_idx % 3) * 0.08),
            "synthetic stress match",
            60 + finding_idx,
            "synthetic priority",
            json.dumps(evidence, ensure_ascii=False),
            db.now(),
        ),
    )


def _stress_counts(conn) -> dict[str, int]:
    return {
        "assets": int(conn.execute("SELECT COUNT(*) FROM assets WHERE hostname LIKE ?", (PREFIX + "%",)).fetchone()[0]),
        "findings": int(conn.execute("SELECT COUNT(*) FROM findings WHERE fingerprint LIKE ?", (PREFIX + "%",)).fetchone()[0]),
        "recon_targets": int(conn.execute("SELECT COUNT(*) FROM recon_targets WHERE domain LIKE ?", (PREFIX + "%",)).fetchone()[0]),
        "honeypot_events": int(conn.execute("SELECT COUNT(*) FROM honeypot_events WHERE headers LIKE 'user_agent=stress/%'").fetchone()[0]),
    }


def _thresholds(timings: dict) -> dict:
    return {
        "graph_ok": timings.get("graph_sec", 0) <= 5.0,
        "attack_paths_ok": timings.get("attack_paths_sec", 0) <= 5.0,
        "report_ok": timings.get("report_sec", 0) <= 8.0,
        "campaigns_ok": timings.get("honeypot_campaigns_sec", 0) <= 3.0,
    }

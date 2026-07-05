"""Quality scoring for vulnerability and recon evidence sources."""
from __future__ import annotations

from ...core import db

_VULN_BASE = {
    "nvd": 0.78,
    "cisa_kev": 0.95,
    "first_epss": 0.82,
    "exploit_db": 0.68,
    "vendor_advisories": 0.88,
}

_RECON_BASE = {
    "dns": 0.8,
    "whois": 0.72,
    "crtsh": 0.75,
    "hackertarget": 0.62,
    "dnsdumpster": 0.65,
    "techstack": 0.68,
    "exposure": 0.7,
    "takeover": 0.55,
}


def vulnerability_source_scores(max_age_hours: int = 48) -> list[dict]:
    rows = db.vulnerability_source_freshness(max_age_hours=max_age_hours)
    out = []
    for row in rows:
        name = row["name"]
        score = _VULN_BASE.get(name, 0.55)
        reasons = [f"base={score:.2f}"]
        if not row["enabled"]:
            score *= 0.5
            reasons.append("disabled")
        if not row["last_success_ts"]:
            score *= 0.45
            reasons.append("never synced")
        elif row.get("stale"):
            score *= 0.75
            reasons.append("stale")
        if row["status"] not in {"ok", "synced", "success", "never-synced"} and row["last_error"]:
            score *= 0.7
            reasons.append("last sync error")
        if int(row["record_count"] or 0) == 0:
            score *= 0.7
            reasons.append("empty")
        out.append({**dict(row), "quality_score": round(score, 2), "quality_reasons": reasons})
    return sorted(out, key=lambda item: item["quality_score"], reverse=True)


def recon_source_scores(target_id: int | None = None) -> list[dict]:
    statuses = []
    if target_id is not None:
        statuses = [dict(row) for row in db.recon_source_status(target_id)]
    else:
        for target in db.recent_targets(limit=100):
            statuses.extend(dict(row) for row in db.recon_source_status(int(target["id"])))
    out = []
    for row in statuses:
        name = row["source_name"]
        score = _RECON_BASE.get(name, 0.55)
        reasons = [f"base={score:.2f}"]
        if row["status"] != "ok":
            score *= 0.65
            reasons.append(f"status={row['status']}")
        if int(row["record_count"] or 0) == 0:
            score *= 0.75
            reasons.append("empty")
        if row.get("last_error"):
            score *= 0.75
            reasons.append("last error")
        out.append({**row, "quality_score": round(score, 2), "quality_reasons": reasons})
    return sorted(out, key=lambda item: item["quality_score"], reverse=True)

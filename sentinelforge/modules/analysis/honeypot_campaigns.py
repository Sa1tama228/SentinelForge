from __future__ import annotations

import json
from collections import Counter, defaultdict

from ...core import db


def cluster(limit: int = 1000, *, max_campaigns: int = 20) -> list[dict]:
    groups: dict[str, list] = defaultdict(list)
    for row in db.recent_honeypot_events(limit=limit):
        # Group first by source IP so campaign summaries describe one actor's
        # behavior instead of mixing unrelated scans together.
        groups[row["src_ip"]].append(row)
    campaigns = []
    for src_ip, rows in groups.items():
        classes = Counter(row["classification"] or "connection" for row in rows)
        services = Counter(row["hp_type"] or "unknown" for row in rows)
        paths = [row["path"] or "" for row in rows if row["path"]]
        iocs = [_loads(row["iocs_json"], {}) for row in rows]
        intent = _intent(classes, paths, iocs)
        score = _score(classes, services, iocs, len(rows))
        campaigns.append(
            {
                "src_ip": src_ip,
                "event_count": len(rows),
                "first_ts": min(row["ts"] for row in rows),
                "last_ts": max(row["ts"] for row in rows),
                "services": dict(services),
                "classifications": dict(classes),
                "intent": intent,
                "score": score,
                "top_paths": [path for path, _n in Counter(paths).most_common(5)],
                "credentials_seen": sum(len(ioc.get("credentials", [])) for ioc in iocs if isinstance(ioc, dict)),
                "alerts": sorted({alert for ioc in iocs if isinstance(ioc, dict) for alert in (ioc.get("alerts") or [])}),
            }
        )
    campaigns.sort(key=lambda item: (item["score"], item["event_count"]), reverse=True)
    return campaigns[:max_campaigns]


def _intent(classes: Counter, paths: list[str], iocs: list[dict]) -> str:
    if classes.get("exploit-probe"):
        return "exploit probing"
    if classes.get("credential-attempt"):
        return "credential harvesting"
    if classes.get("mail-relay-probe"):
        return "mail relay probing"
    if classes.get("login-probe") or any("login" in path.lower() or "admin" in path.lower() for path in paths):
        return "admin/login discovery"
    if any(ioc.get("credentials") for ioc in iocs if isinstance(ioc, dict)):
        return "credential attempt"
    if classes.get("scanner"):
        return "automated scanning"
    return "connection noise"


def _score(classes: Counter, services: Counter, iocs: list[dict], count: int) -> int:
    score = min(20, count)
    # Intent-specific activity is weighted higher than raw event volume; a
    # repeated connection loop should not outrank exploit or credential probes.
    score += classes.get("exploit-probe", 0) * 12
    score += classes.get("credential-attempt", 0) * 10
    score += classes.get("mail-relay-probe", 0) * 8
    score += classes.get("login-probe", 0) * 6
    score += max(0, len(services) - 1) * 5
    score += sum(len(ioc.get("credentials", [])) for ioc in iocs if isinstance(ioc, dict)) * 4
    if any("suspicious-payload" in (ioc.get("alerts") or []) for ioc in iocs if isinstance(ioc, dict)):
        score += 12
    return min(score, 100)


def _loads(value: str, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default

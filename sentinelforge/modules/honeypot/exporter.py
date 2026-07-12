from __future__ import annotations

import json
from pathlib import Path

from ...core import config, db


def export_honeypot(fmt: str = "json", out_dir: str | None = None) -> Path:
    fmt = fmt.lower()
    base = Path(out_dir or config.load()["recon"].get("export_dir") or "data/exports")
    base.mkdir(parents=True, exist_ok=True)
    path = base / f"sentinelforge-honeypot.{fmt}"
    events = [dict(row) for row in db.recent_honeypot_events(limit=10000)]
    payload = {
        "stats": db.honeypot_stats(),
        "classifications": db.honeypot_classification_counts(),
        "sessions": db.honeypot_sessions(limit=1000),
        "events": events,
    }
    if fmt == "txt":
        lines = ["SentinelForge honeypot export", "", json.dumps(payload["stats"], indent=2)]
        for event in events:
            lines.append(
                f"{event['ts']} {event['hp_type']} {event['src_ip']}:{event['src_port']} "
                f"{event['classification']} {event['method']} {event['path']}"
            )
        path.write_text("\n".join(lines), encoding="utf-8")
        return path
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path

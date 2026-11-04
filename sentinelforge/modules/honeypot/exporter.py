from __future__ import annotations

import json
import tempfile
from collections import Counter
from pathlib import Path

from ...core import config, db


def export_honeypot(fmt: str = "json", out_dir: str | None = None) -> Path:
    fmt = fmt.lower().strip()
    if fmt not in {"json", "txt"}:
        raise ValueError(f"Unsupported honeypot export format: {fmt}")
    base = Path(out_dir or config.load()["recon"].get("export_dir") or "data/exports")
    base.mkdir(parents=True, exist_ok=True)
    path = base / f"sentinelforge-honeypot.{fmt}"
    events = [dict(row) for row in db.recent_honeypot_events(limit=None)]
    payload = {
        "stats": {
            "total": len(events),
            "by_type": dict(Counter(event["hp_type"] for event in events)),
            "top_ips": Counter(event["src_ip"] for event in events).most_common(),
        },
        "classifications": dict(Counter(event["classification"] or "unclassified" for event in events)),
        "sessions": db.group_honeypot_sessions(events),
        "events": events,
    }
    if fmt == "txt":
        lines = ["SentinelForge honeypot export", "", json.dumps(payload["stats"], indent=2)]
        for event in events:
            lines.append(
                f"{event['ts']} {event['hp_type']} {event['src_ip']}:{event['src_port']} "
                f"{event['classification']} {event['method']} {event['path']}"
            )
        text = "\n".join(lines)
    else:
        text = json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False)
    with tempfile.NamedTemporaryFile(
        dir=base, prefix=".sentinelforge-honeypot-", suffix=f".{fmt}", delete=False
    ) as temporary:
        staged = Path(temporary.name)
    try:
        staged.write_text(text, encoding="utf-8")
        staged.replace(path)
    finally:
        staged.unlink(missing_ok=True)
    return path

"""Export recon findings to plain text files."""
from __future__ import annotations

import json
from pathlib import Path

from ...core import config, db


def export_target(target_id: int, out_dir: str | None = None) -> Path:
    target = db.target_by_id(target_id)
    if target is None:
        raise ValueError(f"Unknown target id: {target_id}")
    domain = target["domain"]
    base = Path(out_dir or config.load()["recon"].get("export_dir") or "data/exports")
    base.mkdir(parents=True, exist_ok=True)
    safe = "".join(ch if ch.isalnum() or ch in ".-" else "_" for ch in domain)
    path = base / f"recon-{safe}-{target_id}.txt"

    lines = [
        f"SentinelForge recon export",
        f"Target: {domain}",
        f"Target id: {target_id}",
        f"Created: {target['added_ts']}",
        "",
    ]
    for finding in db.recon_findings_for(target_id):
        lines.append(f"## {finding['kind']} ({finding['found_ts']})")
        try:
            data = json.loads(finding["data_json"])
        except json.JSONDecodeError:
            data = finding["data_json"]
        if finding["kind"] == "subdomains" and isinstance(data, dict):
            names = data.get("names", [])
            lines.append(f"Count: {len(names)}")
            lines.extend(str(name) for name in names)
        else:
            lines.append(json.dumps(data, indent=2, ensure_ascii=False))
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path

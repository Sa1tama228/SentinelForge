"""Export asset and finding inventory in analyst-friendly formats."""
from __future__ import annotations

import csv
import html
import json
import uuid
from pathlib import Path

from ...core import config, db
from ..analysis import attack_paths

FORMATS = ["txt", "json", "csv", "html", "sarif", "stix", "md"]


def export_inventory(fmt: str, out_dir: str | None = None, filters: dict | None = None) -> Path:
    fmt = fmt.lower().strip()
    if fmt == "markdown":
        fmt = "md"
    if fmt not in FORMATS:
        raise ValueError(f"Unsupported export format: {fmt}")
    payload = inventory_payload(filters=filters)
    base = Path(out_dir or config.load()["recon"].get("export_dir") or "data/exports")
    base.mkdir(parents=True, exist_ok=True)
    path = base / f"sentinelforge-report.{fmt}"
    writers = {
        "txt": _write_txt,
        "json": _write_json,
        "csv": _write_csv,
        "html": _write_html,
        "sarif": _write_sarif,
        "stix": _write_stix,
        "md": _write_markdown,
    }
    writers[fmt](path, payload)
    return path


def inventory_payload(filters: dict | None = None) -> dict:
    filters = filters or {}
    all_finding_rows = db.findings(limit=10000)
    match_cache = db.vulnerability_matches_for_findings([int(row["id"]) for row in all_finding_rows])
    included_findings = [
        _finding_dict(row, match_cache)
        for row in all_finding_rows
        if _include_finding(row, filters, match_cache)
    ]
    findings_by_asset: dict[int, list[dict]] = {}
    for finding in included_findings:
        asset_id = finding.get("asset_id")
        if asset_id is not None:
            findings_by_asset.setdefault(int(asset_id), []).append(finding)
    asset_rows = db.assets(limit=10000)
    asset_ids = [int(row["id"]) for row in asset_rows]
    packages_by_asset = db.asset_packages_for_assets(asset_ids)
    history_by_asset = db.asset_scan_history_for_assets(asset_ids)
    assets = []
    for row in asset_rows:
        asset_id = row["id"]
        assets.append(
            {
                "id": asset_id,
                "hostname": row["hostname"],
                "normalized_ips": _loads(row["normalized_ips"], []),
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "source": row["source"],
                "tags": _loads(row["tags"], []),
                "open_services": _loads(row["open_services"], []),
                "dns_records": _loads(row["dns_records"], {}),
                "certificates": _loads(row["certificates"], []),
                "technologies": _loads(row["technologies"], []),
                "notes": row["notes"],
                "packages": [dict(pkg) for pkg in packages_by_asset.get(int(asset_id), [])],
                "findings": findings_by_asset.get(int(asset_id), []),
                "scan_history": [dict(h) for h in history_by_asset.get(int(asset_id), [])],
            }
        )
    return {
        "tool": "SentinelForge",
        "summary": _summary(assets, included_findings),
        "assets": assets,
        "findings": included_findings,
        "attack_paths": attack_paths.analyze(limit=50),
    }


def _include_finding(row, filters: dict, match_cache: dict[int, list] | None = None) -> bool:
    if filters.get("status") and row["status"] != filters["status"]:
        return False
    if filters.get("severity") and row["severity"] != filters["severity"]:
        return False
    finding = _finding_dict(row, match_cache)
    matches = finding.get("vulnerability_matches", [])
    if filters.get("kev_only"):
        if not any((m.get("evidence") or {}).get("kev") for m in matches):
            return False
    if filters.get("min_epss") is not None:
        threshold = float(filters["min_epss"])
        if not any(_epss_score((m.get("evidence") or {}).get("epss")) >= threshold for m in matches):
            return False
    if filters.get("confirmed_or_likely"):
        if not any(m.get("match_status") in {"confirmed_candidate", "likely_candidate"} for m in matches):
            return False
    if filters.get("newly_seen"):
        if row["first_seen"] != row["last_seen"]:
            return False
    return True


def _epss_score(value) -> float:
    if not isinstance(value, dict):
        return 0.0
    try:
        return float(value.get("score") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _loads(value: str, default):
    try:
        return json.loads(value or "")
    except json.JSONDecodeError:
        return default


def _csv_cell(value) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _md_text(value) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r\n", "<br>")
        .replace("\n", "<br>")
        .replace("\r", "<br>")
    )


def _finding_dict(row, match_cache: dict[int, list] | None = None) -> dict:
    out = dict(row)
    out.pop("asset_hostname", None)
    if match_cache is not None:
        matches = match_cache.get(int(row["id"]), [])
    else:
        matches = db.vulnerability_matches_for_finding(int(row["id"]))
    out["vulnerability_matches"] = [
        {
            **dict(match),
            "evidence": _loads(match["evidence_json"], {}),
        }
        for match in matches
    ]
    return out


def _summary(assets: list[dict], findings: list[dict]) -> dict:
    severities: dict[str, int] = {}
    statuses: dict[str, int] = {}
    for finding in findings:
        severities[finding["severity"]] = severities.get(finding["severity"], 0) + 1
        statuses[finding["status"]] = statuses.get(finding["status"], 0) + 1
    public_assets = [
        asset for asset in assets
        if any(_is_public_ip(ip) for ip in asset.get("normalized_ips", []))
    ]
    changed_assets = [
        asset for asset in assets
        if any("delta " in str(item.get("summary", "")) and "none" not in str(item.get("summary", "")).lower()
               for item in asset.get("scan_history", [])[:3])
    ]
    return {
        "asset_count": len(assets),
        "public_asset_count": len(public_assets),
        "finding_count": len(findings),
        "severity_counts": severities,
        "status_counts": statuses,
        "changed_asset_count": len(changed_assets),
        "changed_assets": [asset["hostname"] for asset in changed_assets[:10]],
    }


def _summary_lines(payload: dict) -> list[str]:
    summary = payload.get("summary", {})
    attack_summary = payload.get("attack_paths", {}).get("summary", {})
    severity_counts = summary.get("severity_counts", {}) or {}
    lines = [
        f"Assets: {summary.get('asset_count', 0)} ({summary.get('public_asset_count', 0)} public)",
        f"Findings: {summary.get('finding_count', 0)}",
        "Severity: " + (", ".join(f"{k}={v}" for k, v in sorted(severity_counts.items())) or "-"),
        f"Attack paths: {attack_summary.get('total', 0)} "
        f"(high={attack_summary.get('high_confidence', 0)}, medium={attack_summary.get('medium_confidence', 0)}, low={attack_summary.get('low_confidence', 0)})",
        f"Changed assets: {summary.get('changed_asset_count', 0)}",
    ]
    changed = summary.get("changed_assets") or []
    if changed:
        lines.append("Recently changed: " + ", ".join(changed))
    return lines


def _is_public_ip(value: str) -> bool:
    import ipaddress

    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved)


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _write_txt(path: Path, payload: dict) -> None:
    lines = ["SentinelForge report", "", *_summary_lines(payload), ""]
    for asset in payload["assets"]:
        lines.extend([
            f"Asset: {asset['hostname']}",
            f"IPs: {', '.join(asset['normalized_ips']) or '-'}",
            f"Seen: {asset['first_seen']} -> {asset['last_seen']}",
            f"Tags: {', '.join(asset['tags']) or '-'}",
            f"Technologies: {', '.join(asset['technologies']) or '-'}",
            f"Open services: {len(asset['open_services'])}",
            f"Findings: {len(asset['findings'])}",
            "",
        ])
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_markdown(path: Path, payload: dict) -> None:
    lines = ["# SentinelForge Report", "", "## Executive Summary", ""]
    for line in _summary_lines(payload):
        lines.append(f"- {_md_text(line)}")
    graph_summary = payload.get("attack_paths", {}).get("summary", {}).get("graph", {})
    if graph_summary:
        lines.extend(
            [
                "",
                "## Evidence Graph Coverage",
                "",
                f"- Nodes: {_md_text(graph_summary.get('nodes', 0))}",
                f"- Edges: {_md_text(graph_summary.get('edges', 0))}",
                f"- Node types: {_md_text(', '.join(f'{k}={v}' for k, v in sorted((graph_summary.get('by_type') or {}).items())))}",
            ]
        )
    attack_path_items = payload.get("attack_paths", {}).get("paths", [])
    if attack_path_items:
        lines.extend(["", "## Top Attack Paths", ""])
        for attack_path in attack_path_items[:10]:
            lines.extend(
                [
                    f"### {_md_text(attack_path.get('title'))}",
                    f"- Asset: {_md_text(attack_path.get('asset') or '-')}",
                    f"- Score: {_md_text(attack_path.get('score'))}",
                    f"- Confidence: {_md_text(attack_path.get('confidence'))}",
                    f"- Chain: {_md_text(' -> '.join(attack_path.get('chain') or []))}",
                    f"- Why: {_md_text('; '.join(attack_path.get('why_it_matters') or []))}",
                    f"- Validate: {_md_text('; '.join(attack_path.get('recommended_validation') or []))}",
                    "",
                ]
            )
    lines.extend(["## Assets", ""])
    for asset in payload["assets"]:
        lines.extend([
            f"### {_md_text(asset['hostname'])}",
            f"- IPs: {_md_text(', '.join(asset['normalized_ips']) or '-')}",
            f"- First seen: {_md_text(asset['first_seen'])}",
            f"- Last seen: {_md_text(asset['last_seen'])}",
            f"- Source: {_md_text(asset['source'] or '-')}",
            f"- Tags: {_md_text(', '.join(asset['tags']) or '-')}",
            f"- Technologies: {_md_text(', '.join(asset['technologies']) or '-')}",
            "",
        ])
        if asset["open_services"]:
            lines.append("| Port | Proto | Service | Version |")
            lines.append("| --- | --- | --- | --- |")
            for svc in asset["open_services"]:
                lines.append(
                    f"| {_md_text(svc.get('port', ''))} | {_md_text(svc.get('proto', ''))} | "
                    f"{_md_text(svc.get('service', ''))} | {_md_text(svc.get('version', ''))} |"
                )
            lines.append("")
    lines.extend(["## Findings", "", "| Severity | Status | Title | Asset | Confidence |", "| --- | --- | --- | --- | --- |"])
    for finding in payload["findings"]:
        asset = next((a["hostname"] for a in payload["assets"] if a["id"] == finding.get("asset_id")), "-")
        lines.append(
            f"| {_md_text(finding['severity'])} | {_md_text(finding['status'])} | "
            f"{_md_text(finding['title'])} | {_md_text(asset)} | {_md_text(finding['confidence'])} |"
        )
    lines.append("")
    lines.extend(["## Vulnerability Exposure Details", ""])
    for finding in payload["findings"]:
        for match in finding.get("vulnerability_matches", []):
            evidence = match.get("evidence", {})
            lines.extend(
                [
                    f"### {_md_text(match.get('cve_id', finding['title']))}",
                    f"- Finding: {_md_text(finding['title'])}",
                    f"- Match status: {_md_text(match.get('match_status') or '-')}",
                    f"- Matched CPE: {_md_text(match.get('matched_cpe') or '-')}",
                    f"- Confidence: {_md_text(match.get('confidence_score') or '-')}",
                    f"- Priority: {_md_text(match.get('priority_score') or '-')}",
                    f"- CVSS: {_md_text(evidence.get('cvss_score', '-'))}",
                    f"- EPSS: {_md_text((evidence.get('epss') or {}).get('score', '-') if isinstance(evidence.get('epss'), dict) else '-')}",
                    f"- KEV: {_md_text(evidence.get('kev', False))}",
                    f"- Public exploit count: {_md_text(evidence.get('public_exploit_count', 0))}",
                    f"- Verification: {_md_text(evidence.get('verification_warning', '-'))}",
                    "",
                ]
            )
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_csv(path: Path, payload: dict) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["type", "asset", "title", "severity", "confidence", "status", "source", "evidence"])
        for asset in payload["assets"]:
            writer.writerow([_csv_cell(v) for v in ["asset", asset["hostname"], "", "", "", "", asset["source"], ""]])
        asset_names = {a["id"]: a["hostname"] for a in payload["assets"]}
        for finding in payload["findings"]:
            writer.writerow([_csv_cell(v) for v in [
                "finding",
                asset_names.get(finding.get("asset_id"), ""),
                finding["title"],
                finding["severity"],
                finding["confidence"],
                finding["status"],
                finding["source_module"],
                finding["evidence"],
            ]])


def _write_html(path: Path, payload: dict) -> None:
    rows = []
    asset_names = {a["id"]: a["hostname"] for a in payload["assets"]}
    for finding in payload["findings"]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(finding['severity'])}</td>"
            f"<td>{html.escape(finding['status'])}</td>"
            f"<td>{html.escape(finding['title'])}</td>"
            f"<td>{html.escape(asset_names.get(finding.get('asset_id'), '-'))}</td>"
            f"<td>{html.escape(finding['confidence'])}</td>"
            "</tr>"
        )
    body = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>SentinelForge Report</title>
<style>
body{{font-family:Arial,sans-serif;background:#08110f;color:#edf7f3;margin:24px}}
table{{border-collapse:collapse;width:100%;margin-top:12px}}td,th{{border:1px solid #263834;padding:8px}}
th{{background:#14231f}}.card{{border:1px solid #263834;padding:12px;margin:8px 0;background:#101d1a}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px}}
</style></head><body>
<h1>SentinelForge Report</h1>
<h2>Executive Summary</h2>
<div class="grid">{''.join(f"<div class='card'>{html.escape(line)}</div>" for line in _summary_lines(payload))}</div>
<h2>Assets</h2>
{''.join(f"<div class='card'><b>{html.escape(a['hostname'])}</b><br>IPs: {html.escape(', '.join(a['normalized_ips']) or '-')}<br>Technologies: {html.escape(', '.join(a['technologies']) or '-')}</div>" for a in payload['assets'])}
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Status</th><th>Title</th><th>Asset</th><th>Confidence</th></tr>{''.join(rows)}</table>
<h2>Attack Paths</h2>
{''.join(f"<div class='card'><b>{html.escape(str(p.get('title', '-')))}</b><br>Asset: {html.escape(str(p.get('asset') or '-'))}<br>Score: {html.escape(str(p.get('score', '-')))} | Confidence: {html.escape(str(p.get('confidence', '-')))}<br>Chain: {html.escape(' -> '.join(p.get('chain') or []))}<br>Evidence: {html.escape('; '.join(p.get('why_it_matters') or []))}</div>" for p in payload.get('attack_paths', {}).get('paths', []))}
</body></html>"""
    path.write_text(body, encoding="utf-8")


def _write_sarif(path: Path, payload: dict) -> None:
    rules = {}
    results = []
    asset_names = {a["id"]: a["hostname"] for a in payload["assets"]}
    for finding in payload["findings"]:
        rule_id = finding["fingerprint"]
        rules[rule_id] = {
            "id": rule_id,
            "name": finding["title"],
            "shortDescription": {"text": finding["title"]},
            "help": {"text": finding.get("remediation") or ""},
        }
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(finding["severity"]),
                "message": {"text": finding.get("evidence") or finding["title"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"asset://{asset_names.get(finding.get('asset_id'), 'unknown')}"}
                        }
                    }
                ],
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "SentinelForge", "rules": list(rules.values())}}, "results": results}],
    }
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def _sarif_level(severity: str) -> str:
    return {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}.get(severity, "note")


def _write_stix(path: Path, payload: dict) -> None:
    objects = []
    ns = uuid.UUID("7c7af1de-60f6-48f0-a9ec-6b138c2a4e3f")
    for asset in payload["assets"]:
        obj_type = "domain-name"
        if asset["normalized_ips"]:
            obj_type = "ipv6-addr" if ":" in asset["normalized_ips"][0] else "ipv4-addr"
        objects.append(
            {
                "type": obj_type,
                "spec_version": "2.1",
                "id": f"{obj_type}--{uuid.uuid5(ns, 'asset:' + str(asset['id']))}",
                "value": asset["hostname"] if not asset["normalized_ips"] else asset["normalized_ips"][0],
            }
        )
    for finding in payload["findings"]:
        objects.append(
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": f"vulnerability--{uuid.uuid5(ns, 'finding:' + str(finding['id']))}",
                "name": finding["title"],
                "description": finding.get("evidence") or "",
            }
        )
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid5(ns, 'report')}", "objects": objects}
    path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")

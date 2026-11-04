from __future__ import annotations

import csv
import html
import ipaddress
import json
import re
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

import idna

from ... import __version__
from ...core import config, db
from ..analysis import attack_paths

FORMATS = ["txt", "json", "csv", "html", "sarif", "stix", "md"]
_STIX_SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


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
    with tempfile.NamedTemporaryFile(dir=base, prefix=".sentinelforge-", suffix=f".{fmt}", delete=False) as temporary:
        staged = Path(temporary.name)
    try:
        writers[fmt](staged, payload)
        staged.replace(path)
    finally:
        staged.unlink(missing_ok=True)
    return path


def inventory_payload(filters: dict | None = None) -> dict:
    filters = filters or {}
    all_finding_rows = db.findings(limit=None)
    match_cache = db.vulnerability_matches_for_findings([int(row["id"]) for row in all_finding_rows])
    included_findings = [
        _finding_dict(row, match_cache) for row in all_finding_rows if _include_finding(row, filters, match_cache)
    ]
    findings_by_asset: dict[int, list[dict]] = {}
    for finding in included_findings:
        asset_id = finding.get("asset_id")
        if asset_id is not None:
            findings_by_asset.setdefault(int(asset_id), []).append(finding)
    asset_rows = db.assets(limit=None)
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
                "normalized_ips": _loads(row["normalized_ips"], [], label=f"asset #{asset_id} normalized_ips"),
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "source": row["source"],
                "tags": _loads(row["tags"], [], label=f"asset #{asset_id} tags"),
                "open_services": _loads(row["open_services"], [], label=f"asset #{asset_id} open_services"),
                "dns_records": _loads(row["dns_records"], {}, label=f"asset #{asset_id} dns_records"),
                "certificates": _loads(row["certificates"], [], label=f"asset #{asset_id} certificates"),
                "technologies": _loads(row["technologies"], [], label=f"asset #{asset_id} technologies"),
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
        "attack_paths": attack_paths.analyze(limit=None),
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


def _loads(value: str, default, *, label: str):
    if not value:
        return default
    try:
        result = json.loads(value, parse_constant=_invalid_json_constant, object_pairs_hook=_unique_json_object)
    except ValueError as exc:
        raise ValueError(f"Invalid {label}: {exc}") from exc
    if not isinstance(result, type(default)):
        raise ValueError(f"Invalid {label}: expected a {type(default).__name__}")
    return result


def _invalid_json_constant(value: str):
    raise ValueError(f"Non-finite JSON number: {value}")


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _html_text(value) -> str:
    text = "" if value is None else str(value)
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ud800-\udfff\ufdd0-\ufdef]", text) or any(
        ord(char) & 0xFFFF in {0xFFFE, 0xFFFF} for char in text
    ):
        raise ValueError("HTML and Markdown cannot represent this control character; use JSON to preserve the data")
    return html.escape(text, quote=False)


def _csv_cell(value) -> str:
    text = "" if value is None else str(value)
    if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def _md_text(value) -> str:
    text = _html_text(value)
    text = re.sub(r"([\\`*_{}\[\]()#+.!|>~-])", r"\\\1", text)
    return text.replace("\r\n", "<br>").replace("\n", "<br>").replace("\r", "<br>")


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
            "evidence": _loads(match["evidence_json"], {}, label=f"vulnerability match #{match['id']} evidence_json"),
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
    public_assets = [asset for asset in assets if any(_is_public_ip(ip) for ip in asset.get("normalized_ips", []))]
    changed_assets = [
        asset
        for asset in assets
        if any(
            "delta " in str(item.get("summary", "")) and "none" not in str(item.get("summary", "")).lower()
            for item in asset.get("scan_history", [])[:3]
        )
    ]
    return {
        "asset_count": len(assets),
        "public_asset_count": len(public_assets),
        "finding_count": len(findings),
        "severity_counts": severities,
        "status_counts": statuses,
        "changed_asset_count": len(changed_assets),
        "changed_assets": [asset["hostname"] for asset in changed_assets],
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
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved)


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")


def _write_txt(path: Path, payload: dict) -> None:
    lines = ["SentinelForge report", "", *_summary_lines(payload), ""]
    for asset in payload["assets"]:
        lines.extend(
            [
                f"Asset: {asset['hostname']}",
                f"IPs: {', '.join(asset['normalized_ips']) or '-'}",
                f"Seen: {asset['first_seen']} -> {asset['last_seen']}",
                f"Tags: {', '.join(asset['tags']) or '-'}",
                f"Technologies: {', '.join(asset['technologies']) or '-'}",
                f"Open services: {len(asset['open_services'])}",
                f"Findings: {len(asset['findings'])}",
                "",
            ]
        )
    asset_names = {asset["id"]: asset["hostname"] for asset in payload["assets"]}
    for finding in payload["findings"]:
        lines.extend(
            [
                f"Finding SF-{finding['id']}: {finding['title']}",
                f"Asset: {asset_names.get(finding.get('asset_id'), '-')}",
                f"Severity: {finding['severity']} | Status: {finding['status']} | Confidence: {finding['confidence']}",
                "Evidence:",
                finding.get("evidence") or "",
                "Remediation:",
                finding.get("remediation") or "",
                "",
            ]
        )
        if finding.get("vulnerability_matches"):
            lines.extend(
                [
                    "Advisory matches:",
                    json.dumps(finding["vulnerability_matches"], ensure_ascii=False, allow_nan=False),
                    "",
                ]
            )
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
        lines.extend(["", "## Attack Paths", ""])
        for attack_path in attack_path_items:
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
        lines.extend(
            [
                f"### {_md_text(asset['hostname'])}",
                f"- IPs: {_md_text(', '.join(asset['normalized_ips']) or '-')}",
                f"- First seen: {_md_text(asset['first_seen'])}",
                f"- Last seen: {_md_text(asset['last_seen'])}",
                f"- Source: {_md_text(asset['source'] or '-')}",
                f"- Tags: {_md_text(', '.join(asset['tags']) or '-')}",
                f"- Technologies: {_md_text(', '.join(asset['technologies']) or '-')}",
                "",
            ]
        )
        if asset["open_services"]:
            lines.append("| Port | Proto | Service | Version |")
            lines.append("| --- | --- | --- | --- |")
            for svc in asset["open_services"]:
                lines.append(
                    f"| {_md_text(svc.get('port', ''))} | {_md_text(svc.get('proto', ''))} | "
                    f"{_md_text(svc.get('service', ''))} | {_md_text(svc.get('version', ''))} |"
                )
            lines.append("")
    lines.extend(
        ["## Findings", "", "| Severity | Status | Title | Asset | Confidence |", "| --- | --- | --- | --- | --- |"]
    )
    asset_names = {asset["id"]: asset["hostname"] for asset in payload["assets"]}
    for finding in payload["findings"]:
        asset = asset_names.get(finding.get("asset_id"), "-")
        lines.append(
            f"| {_md_text(finding['severity'])} | {_md_text(finding['status'])} | "
            f"{_md_text(finding['title'])} | {_md_text(asset)} | {_md_text(finding['confidence'])} |"
        )
    lines.append("")
    lines.extend(["## Finding Evidence", ""])
    for finding in payload["findings"]:
        lines.extend(
            [
                f"### SF-{finding['id']}: {_md_text(finding['title'])}",
                "",
                _md_text(finding.get("evidence") or "No evidence recorded"),
                "",
                f"Remediation: {_md_text(finding.get('remediation') or 'No remediation recorded')}",
                "",
            ]
        )
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
    details = []
    asset_names = {a["id"]: a["hostname"] for a in payload["assets"]}
    for finding in payload["findings"]:
        rows.append(
            "<tr>"
            f"<td>{_html_text(finding['severity'])}</td>"
            f"<td>{_html_text(finding['status'])}</td>"
            f"<td>{_html_text(finding['title'])}</td>"
            f"<td>{_html_text(asset_names.get(finding.get('asset_id'), '-'))}</td>"
            f"<td>{_html_text(finding['confidence'])}</td>"
            "</tr>"
        )
        matches = finding.get("vulnerability_matches") or []
        details.append(
            f"<details><summary>SF-{finding['id']}: {_html_text(finding['title'])}</summary>"
            f"<h3>Observed evidence</h3><pre>{_html_text(finding.get('evidence'))}</pre>"
            f"<h3>Remediation</h3><pre>{_html_text(finding.get('remediation'))}</pre>"
            + (
                f"<h3>Advisory matches</h3><pre>{_html_text(json.dumps(matches, ensure_ascii=False, allow_nan=False))}</pre>"
                if matches
                else ""
            )
            + "</details>"
        )
    body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>SentinelForge Report</title>
<style>
body{{font-family:Arial,sans-serif;background:#08110f;color:#edf7f3;margin:24px}}
table{{border-collapse:collapse;width:100%;margin-top:12px}}td,th{{border:1px solid #263834;padding:8px}}
th{{background:#14231f}}.card{{border:1px solid #263834;padding:12px;margin:8px 0;background:#101d1a}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px}}
</style></head><body>
<h1>SentinelForge Report</h1>
<h2>Executive Summary</h2>
<div class="grid">{"".join(f"<div class='card'>{_html_text(line)}</div>" for line in _summary_lines(payload))}</div>
<h2>Assets</h2>
{"".join(f"<div class='card'><b>{_html_text(a['hostname'])}</b><br>IPs: {_html_text(', '.join(a['normalized_ips']) or '-')}<br>Technologies: {_html_text(', '.join(a['technologies']) or '-')}</div>" for a in payload["assets"])}
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Status</th><th>Title</th><th>Asset</th><th>Confidence</th></tr>{"".join(rows)}</table>
<h2>Finding Evidence</h2>
{"".join(details)}
<h2>Attack Paths</h2>
{"".join(f"<div class='card'><b>{_html_text(str(p.get('title', '-')))}</b><br>Asset: {_html_text(str(p.get('asset') or '-'))}<br>Score: {_html_text(str(p.get('score', '-')))} | Confidence: {_html_text(str(p.get('confidence', '-')))}<br>Chain: {_html_text(' -> '.join(p.get('chain') or []))}<br>Evidence: {_html_text('; '.join(p.get('why_it_matters') or []))}</div>" for p in payload.get("attack_paths", {}).get("paths", []))}
</body></html>"""
    path.write_text(body, encoding="utf-8")


def _write_sarif(path: Path, payload: dict) -> None:
    rules = {}
    results = []
    asset_names = {a["id"]: a["hostname"] for a in payload["assets"]}
    asset_indexes = {asset["id"]: index for index, asset in enumerate(payload["assets"])}
    for finding in payload["findings"]:
        rule_id = f"SF-{finding['id']}"
        rules[rule_id] = {
            "id": rule_id,
            "name": f"Finding{finding['id']}",
            "shortDescription": {"text": finding["title"] or rule_id},
        }
        if finding.get("remediation"):
            rules[rule_id]["help"] = {"text": finding["remediation"]}
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(finding["severity"]),
                "message": {"text": finding.get("evidence") or finding["title"] or rule_id},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"sentinelforge://asset/{finding['asset_id']}",
                                "index": asset_indexes[finding["asset_id"]],
                            }
                        }
                    }
                ]
                if finding.get("asset_id") in asset_names
                else [],
                "properties": {
                    "finding": finding,
                    "asset": asset_names.get(finding.get("asset_id"), ""),
                },
            }
        )
    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {
                    "name": "SentinelForge", "semanticVersion": __version__,
                    "informationUri": "https://github.com/Sa1tama228/SentinelForge",
                    "rules": list(rules.values()),
                }},
                "results": results,
                "artifacts": [
                    {
                        "location": {"uri": f"sentinelforge://asset/{asset['id']}"},
                        "properties": {"asset": {key: value for key, value in asset.items() if key != "findings"}},
                    }
                    for asset in payload["assets"]
                ],
                "properties": {"summary": payload["summary"], "attackPaths": payload["attack_paths"]},
            }
        ],
    }
    path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")


def _sarif_level(severity: str) -> str:
    return {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}.get(severity, "note")


def _stix_observable(kind: str, value: str) -> dict:
    # Only value contributes to IDs for these three SCO types
    canonical = json.dumps({"value": value}, ensure_ascii=False, separators=(",", ":"))
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": f"{kind}--{uuid.uuid5(_STIX_SCO_NAMESPACE, canonical)}",
        "value": value,
    }


def _write_stix(path: Path, payload: dict) -> None:
    timestamp = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    common = {"spec_version": "2.1", "created": timestamp, "modified": timestamp}
    creator_id = f"identity--{uuid.uuid4()}"
    objects = [{"type": "identity", "id": creator_id, **common, "name": "SentinelForge", "identity_class": "system"}]
    observables: dict[str, dict] = {}
    asset_refs: dict[int, list[str]] = {}
    for asset in payload["assets"]:
        refs = []
        addresses = list(asset["normalized_ips"])
        try:
            host_ip = (
                ipaddress.ip_network(asset["hostname"], strict=False)
                if "/" in asset["hostname"]
                else ipaddress.ip_address(asset["hostname"])
            )
        except ValueError:
            host_ip = None
        if host_ip is not None:
            addresses.append(str(host_ip))
        for value in addresses:
            try:
                if "%" in value:
                    raise ValueError("Scoped IPv6 addresses are not STIX address values")
                address = ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError(f"Invalid STIX address for asset #{asset['id']}: {value}") from exc
            observable = _stix_observable(f"ipv{address.version}-addr", str(address))
            observables[observable["id"]] = observable
            refs.append(observable["id"])
        refs = list(dict.fromkeys(refs))
        if host_ip is None:
            try:
                domain = idna.encode(asset["hostname"].removesuffix("."), uts46=True).decode("ascii").lower()
            except idna.IDNAError:
                domain = ""
            if domain:
                observable = _stix_observable("domain-name", domain)
                if refs:
                    observable["resolves_to_refs"] = refs.copy()
                observables[observable["id"]] = observable
                refs.append(observable["id"])
        asset_refs[asset["id"]] = refs
        objects.append(
            {
                "type": "note",
                "id": f"note--{uuid.uuid4()}",
                **common,
                "created_by_ref": creator_id,
                "abstract": f"Asset #{asset['id']}: {asset['hostname']}",
                "content": json.dumps(
                    {key: value for key, value in asset.items() if key != "findings"},
                    ensure_ascii=False,
                    allow_nan=False,
                ),
                "object_refs": refs or [creator_id],
                "labels": ["sentinelforge-asset"],
            }
        )
    objects.extend(observables.values())
    vulnerabilities: dict[str, str] = {}
    for finding in payload["findings"]:
        refs = asset_refs.get(finding.get("asset_id"), []).copy()
        for match in finding.get("vulnerability_matches", []):
            cve = str(match["cve_id"]).upper()
            if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve):
                raise ValueError(f"Invalid CVE identifier linked to finding #{finding['id']}: {cve}")
            if cve not in vulnerabilities:
                vuln_id = f"vulnerability--{uuid.uuid4()}"
                vulnerabilities[cve] = vuln_id
                objects.append(
                    {
                        "type": "vulnerability",
                        "id": vuln_id,
                        **common,
                        "created_by_ref": creator_id,
                        "name": cve,
                        "external_references": [{"source_name": "cve", "external_id": cve}],
                    }
                )
            refs.append(vulnerabilities[cve])
        objects.append(
            {
                "type": "note",
                "id": f"note--{uuid.uuid4()}",
                **common,
                "created_by_ref": creator_id,
                "abstract": finding["title"] or f"Finding #{finding['id']}",
                "content": json.dumps(finding, ensure_ascii=False, allow_nan=False),
                "object_refs": list(dict.fromkeys(refs)) or [creator_id],
                "labels": ["sentinelforge-finding"],
            }
        )
    objects.append(
        {
            "type": "note",
            "id": f"note--{uuid.uuid4()}",
            **common,
            "created_by_ref": creator_id,
            "abstract": "SentinelForge report summary",
            "content": json.dumps(
                {"summary": payload["summary"], "attack_paths": payload["attack_paths"]},
                ensure_ascii=False,
                allow_nan=False,
            ),
            "object_refs": [creator_id],
            "labels": ["sentinelforge-report"],
        }
    )
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")

"""Graph-backed attack-path and entry-point analysis."""
from __future__ import annotations

import hashlib
import json

from . import evidence_graph
from .evidence_graph import EvidenceGraph, EvidenceNode

STRONG_MATCH_STATUSES = {"confirmed_candidate", "likely_candidate"}


def analyze(limit: int = 25, *, include_low: bool = True) -> dict:
    graph = evidence_graph.build()
    paths = []
    for context in evidence_graph.asset_contexts(graph):
        paths.extend(_vulnerability_paths(graph, context))
        paths.extend(_surface_paths(context))
        paths.extend(_control_gap_paths(graph, context))
        paths.extend(_recon_exposure_paths(context))
        paths.extend(_web_audit_paths(graph, context))
        paths.extend(_honeypot_pressure_paths(context))

    paths = _dedupe_paths(paths)
    paths = [path for path in paths if include_low or path["confidence"] != "Low"]
    paths.sort(key=lambda item: (item["score"], _confidence_rank(item["confidence"])), reverse=True)
    paths = paths[:limit]
    return {
        "summary": {
            **_summary(paths),
            "graph": graph.as_dict()["summary"],
        },
        "paths": paths,
    }


def graph_payload() -> dict:
    return evidence_graph.build().as_dict()


def _vulnerability_paths(graph: EvidenceGraph, context: dict) -> list[dict]:
    asset = context["asset"]
    out = []
    for edge in context["vulnerability_edges"]:
        vuln = graph.nodes.get(edge.target)
        finding = graph.nodes.get(edge.source)
        if not vuln or not finding:
            continue
        evidence = edge.evidence.get("evidence") or vuln.data.get("evidence") or {}
        status = edge.evidence.get("match_status") or vuln.data.get("match_status") or ""
        confidence = float(edge.confidence or vuln.data.get("confidence_score") or 0.0)
        cvss = _float(evidence.get("cvss_score"))
        epss = _epss_score(evidence.get("epss"))
        kev = bool(evidence.get("kev"))
        exploit_count = int(evidence.get("public_exploit_count") or 0)
        advisory = evidence.get("distribution_advisory") if isinstance(evidence.get("distribution_advisory"), dict) else {}
        local_status = advisory.get("local_status") or ""
        if local_status == "patched_by_distribution_advisory":
            continue
        if status not in STRONG_MATCH_STATUSES and not (kev and confidence >= 0.45) and not (epss >= 0.7 and confidence >= 0.5):
            continue
        score = 35 + (cvss * 4.0) + (confidence * 20.0)
        reasons = [f"{status.replace('_', ' ')}", f"confidence {confidence:.2f}", f"CVSS {cvss:.1f}"]
        if asset.data.get("internet_exposed"):
            score += 10
            reasons.append("public IP observed")
        if kev:
            score += 18
            reasons.append("CISA KEV")
        if epss >= 0.5:
            score += min(12, epss * 12)
            reasons.append(f"EPSS {epss:.2f}")
        if exploit_count:
            score += min(12, exploit_count * 2)
            reasons.append(f"{exploit_count} public exploit references")
        if local_status:
            reasons.append(f"advisory {local_status}")
            if local_status == "below_distribution_fixed_version":
                score += 8
            elif local_status == "distribution_advisory_uncomparable":
                score -= 4
        hp = _honeypot_signal(context)
        if hp:
            score += hp["score"]
            reasons.append(hp["reason"])
        recon = _recon_signal(context, "exposure")
        if recon:
            score += 4
            reasons.append(recon)
        confidence_label = "High" if confidence >= 0.8 and status == "confirmed_candidate" else "Medium"
        out.append(
            _path(
                asset,
                "Vulnerability-backed attack path",
                score,
                confidence_label,
                [
                    "Internet exposure" if asset.data.get("internet_exposed") else "Observed asset",
                    evidence.get("service") or finding.data.get("source_module") or "service",
                    vuln.label,
                    "Threat activity signal" if hp else "Manual validation",
                ],
                reasons,
                {
                    "finding_id": finding.data.get("id"),
                    "finding_title": finding.label,
                    "cve_id": vuln.label,
                    "matched_cpe": edge.evidence.get("matched_cpe"),
                    "service": evidence.get("service"),
                    "product": evidence.get("product"),
                    "version": evidence.get("version"),
                    "distribution_advisory": advisory,
                    "graph_edges": ["asset->finding", "finding->vulnerability"],
                },
                [
                    "Confirm service/version from authenticated package data when possible.",
                    "Check vendor/distribution advisory state before treating banner-only evidence as vulnerable.",
                    "Prioritize patching or compensating controls if KEV/EPSS/public exploits are present.",
                ],
            )
        )
    return out


def _surface_paths(context: dict) -> list[dict]:
    asset = context["asset"]
    vuln_service_names = _vuln_service_names(context)
    out = []
    for svc in context["services"]:
        category = svc.data.get("category") or "general"
        if category == "general":
            continue
        service = svc.data.get("service") or "unknown"
        port = int(svc.data.get("port") or 0)
        if service in vuln_service_names or str(port) in vuln_service_names:
            continue
        score = 18
        reasons = [f"{service} on port {port}", f"category {category}"]
        if asset.data.get("internet_exposed"):
            score += 12
            reasons.append("public IP observed")
        if category in {"remote-admin", "database", "insecure-or-abused-service"}:
            score += 8
            reasons.append("service class commonly abused when exposed")
        hp = _honeypot_signal(context, service=service, port=port, category=category)
        if hp:
            score += hp["score"]
            reasons.append(hp["reason"])
        confidence = "Medium" if asset.data.get("internet_exposed") and category != "web" else "Low"
        out.append(
            _path(
                asset,
                _surface_title(category),
                score,
                confidence,
                [
                    "Observed exposure",
                    f"{service}:{port}",
                    "No strong CVE match",
                    "Access-control validation",
                ],
                reasons,
                {
                    "service": service,
                    "port": port,
                    "proto": svc.data.get("proto"),
                    "version": svc.data.get("version") or "",
                    "category": category,
                    "graph_edges": ["asset->service"],
                },
                [
                    "Verify the service is intentionally reachable from this network segment.",
                    "Check authentication, allowlists, MFA, and service hardening.",
                    "Treat this as an exposure review unless independent vulnerability evidence appears.",
                ],
            )
        )
    return out


def _control_gap_paths(graph: EvidenceGraph, context: dict) -> list[dict]:
    asset = context["asset"]
    out = []
    for edge in context["control_gap_edges"]:
        gap = graph.nodes.get(edge.target)
        finding = graph.nodes.get(edge.source)
        if not gap or not finding:
            continue
        out.append(
            _path(
                asset,
                _control_gap_title(gap.data.get("gap_type")),
                12,
                "Low",
                ["Recon finding", gap.label, "Control validation", "Remediation planning"],
                [finding.label],
                {
                    "finding_id": finding.data.get("id"),
                    "finding_title": finding.label,
                    "gap_type": gap.data.get("gap_type"),
                    "graph_edges": ["asset->finding", "finding->control_gap"],
                },
                ["Validate the finding manually and apply the relevant control if missing."],
            )
        )
    return out


def _recon_exposure_paths(context: dict) -> list[dict]:
    asset = context["asset"]
    out = []
    for obs in context["recon"]:
        kind = obs.data.get("kind")
        data = obs.data.get("data") or {}
        if kind != "exposure":
            continue
        checks = [item for item in data.get("checks", []) if isinstance(item, dict)]
        high_value = [item for item in checks if item.get("severity") in {"High", "Medium"}]
        for item in high_value:
            score = 26 if item.get("severity") == "High" else 18
            if asset.data.get("internet_exposed"):
                score += 8
            out.append(
                _path(
                    asset,
                    "Recon-confirmed exposed endpoint",
                    score,
                    "Medium" if item.get("severity") == "High" else "Low",
                    ["Recon observation", item.get("path") or item.get("url") or "endpoint", "Sensitive endpoint", "Manual validation"],
                    [f"{item.get('title')} status={item.get('status')}", f"confidence {item.get('confidence', '-')}" ],
                    {
                        "url": item.get("url"),
                        "path": item.get("path"),
                        "status": item.get("status"),
                        "sample": item.get("sample"),
                        "graph_edges": ["asset->recon_observation"],
                    },
                    [
                        "Open the endpoint only in authorized scope and verify whether sensitive content is exposed.",
                        "Remove public access or require authentication if exposure is unintended.",
                    ],
                )
            )
    return out


def _web_audit_paths(graph: EvidenceGraph, context: dict) -> list[dict]:
    asset = context["asset"]
    out = []
    audit_edges = []
    for finding_node in context["findings"]:
        audit_edges.extend(graph.outgoing(finding_node.id, "indicates_web_audit_issue"))
    for edge in audit_edges:
        signal = graph.nodes.get(edge.target)
        finding = graph.nodes.get(edge.source)
        if not signal or not finding:
            continue
        evidence = signal.data.get("evidence") or {}
        score = 18
        if finding.data.get("severity") == "High":
            score += 14
        elif finding.data.get("severity") == "Medium":
            score += 8
        if asset.data.get("internet_exposed"):
            score += 7
        hp = _honeypot_signal(context, category="web")
        reasons = [finding.label, "external web-audit engine signal"]
        if hp:
            score += hp["score"]
            reasons.append(hp["reason"])
        out.append(
            _path(
                asset,
                "Web audit signal path",
                score,
                "Low",
                ["Web service", "Nikto audit signal", "Manual validation", "Hardening/remediation"],
                reasons,
                {
                    "finding_id": finding.data.get("id"),
                    "engine": "nikto",
                    "target": evidence.get("target"),
                    "uri": evidence.get("uri"),
                    "osvdb": evidence.get("osvdb"),
                    "graph_edges": ["asset->finding", "finding->web_audit_signal"],
                },
                [
                    "Validate the Nikto result manually before marking it confirmed.",
                    "Correlate with headers, application version, and safe endpoint checks.",
                    "Treat this as web hardening evidence unless a CVE or exploit precondition is independently confirmed.",
                ],
            )
        )
    return out


def _honeypot_pressure_paths(context: dict) -> list[dict]:
    asset = context["asset"]
    if not context["honeypot_edges"]:
        return []
    relevant_services = [
        svc for svc in context["services"]
        if svc.data.get("category") in {"web", "remote-admin", "insecure-or-abused-service"}
    ]
    if not relevant_services:
        return []
    strongest = max(context["honeypot_edges"], key=lambda edge: edge.confidence)
    service_labels = [svc.label for svc in relevant_services[:4]]
    score = 15 + strongest.confidence * 18
    if asset.data.get("internet_exposed"):
        score += 8
    return [
        _path(
            asset,
            "Threat-pressure entry surface",
            score,
            "Medium" if strongest.confidence >= 0.7 and asset.data.get("internet_exposed") else "Low",
            ["Honeypot signal", ", ".join(service_labels), "Observed service", "Prioritize hardening"],
            [strongest.evidence.get("reason", "honeypot activity relevant to asset surface")],
            {
                "services": service_labels,
                "honeypot_confidence": strongest.confidence,
                "graph_edges": ["honeypot_signal->asset", "asset->service"],
            },
            [
                "Review whether similar exposed services are intentionally reachable.",
                "Prioritize hardening if honeypot activity matches exposed admin or web surfaces.",
            ],
        )
    ]


def _path(asset: EvidenceNode, title: str, score: float, confidence: str, chain: list[str],
          reasons: list[str], evidence: dict, validation: list[str]) -> dict:
    path_id = hashlib.sha256(
        json.dumps([asset.data.get("id"), title, chain, evidence], sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:16]
    return {
        "id": path_id,
        "title": title,
        "asset_id": asset.data.get("id"),
        "asset": asset.label,
        "internet_exposed": bool(asset.data.get("internet_exposed")),
        "score": round(min(score, 100.0), 1),
        "confidence": confidence,
        "chain": chain,
        "why_it_matters": reasons,
        "evidence": evidence,
        "false_positive_controls": [
            "Every path is built from explicit graph evidence edges.",
            "CVE-backed paths require confirmed/likely correlation or KEV/EPSS support.",
            "Exposure and honeypot pressure paths stay lower confidence unless independent vulnerability evidence appears.",
        ],
        "recommended_validation": validation,
    }


def _dedupe_paths(paths: list[dict]) -> list[dict]:
    deduped: dict[str, dict] = {}
    for path in paths:
        existing = deduped.get(path["id"])
        if existing is None or path["score"] > existing["score"]:
            deduped[path["id"]] = path
    return list(deduped.values())


def _honeypot_signal(context: dict, *, service: str = "", port: int = 0, category: str = "") -> dict:
    if not context["honeypot_edges"]:
        return {}
    candidates = []
    for edge in context["honeypot_edges"]:
        reason = str(edge.evidence.get("reason") or "").lower()
        if category == "web" and "web" in reason:
            candidates.append(edge)
        elif service == "ssh" and "ssh" in reason:
            candidates.append(edge)
        elif service == "ftp" and "ftp" in reason:
            candidates.append(edge)
        elif category == "remote-admin" and ("ssh" in reason or "admin" in reason):
            candidates.append(edge)
    if category in {"database"}:
        candidates = []
    if not candidates and not any((service, port, category)):
        candidates = context["honeypot_edges"]
    if not candidates:
        return {}
    best = max(candidates, key=lambda edge: edge.confidence)
    score = 4 if best.confidence < 0.7 else 7
    reason = best.evidence.get("reason") or "honeypot activity relevant to this surface"
    return {"score": score, "reason": reason}


def _recon_signal(context: dict, kind: str) -> str:
    for obs in context["recon"]:
        if obs.data.get("kind") == kind:
            return f"recon {kind} evidence observed"
    return ""


def _vuln_service_names(context: dict) -> set[str]:
    out = set()
    for edge in context["vulnerability_edges"]:
        evidence = edge.evidence.get("evidence") or {}
        for key in ("service", "port"):
            if evidence.get(key) is not None:
                out.add(str(evidence.get(key)).lower())
    return out


def _surface_title(category: str) -> str:
    return {
        "web": "Web edge surface",
        "remote-admin": "Remote administration surface",
        "database": "Data service exposure",
        "insecure-or-abused-service": "High-abuse service exposure",
    }.get(category, "Observed exposure")


def _control_gap_title(gap_type: str | None) -> str:
    return {
        "email-spoofing-control-gap": "Email spoofing control gap",
        "web-transport-hardening-gap": "Web transport hardening gap",
        "web-client-hardening-gap": "Web client-side hardening gap",
    }.get(gap_type or "", "Security control gap")


def _summary(paths: list[dict]) -> dict:
    return {
        "total": len(paths),
        "high_confidence": sum(1 for path in paths if path["confidence"] == "High"),
        "medium_confidence": sum(1 for path in paths if path["confidence"] == "Medium"),
        "low_confidence": sum(1 for path in paths if path["confidence"] == "Low"),
        "top_score": paths[0]["score"] if paths else 0,
    }


def _confidence_rank(value: str) -> int:
    return {"High": 3, "Medium": 2, "Low": 1}.get(value, 0)


def _epss_score(value) -> float:
    if not isinstance(value, dict):
        return 0.0
    return _float(value.get("score"))


def _float(value) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0

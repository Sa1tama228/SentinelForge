"""In-memory evidence graph for cross-module security analysis."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from typing import Any

from ...core import db

RISKY_REMOTE_ADMIN_PORTS = {22, 23, 3389, 5900, 5985, 5986}
RISKY_DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 9300}
RISKY_WEB_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888}
RISKY_SERVICE_NAMES = {"ftp", "telnet", "redis", "mongodb", "elasticsearch"}
CONTROL_GAP_MARKERS = {
    "Missing SPF": "email-spoofing-control-gap",
    "Missing DMARC": "email-spoofing-control-gap",
    "Missing Strict-Transport-Security": "web-transport-hardening-gap",
    "Missing Content-Security-Policy": "web-client-hardening-gap",
}


@dataclass
class EvidenceNode:
    id: str
    type: str
    label: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceEdge:
    source: str
    target: str
    type: str
    confidence: float = 1.0
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceGraph:
    nodes: dict[str, EvidenceNode] = field(default_factory=dict)
    edges: list[EvidenceEdge] = field(default_factory=list)
    _out_edges: dict[str, list[EvidenceEdge]] = field(default_factory=dict, init=False, repr=False)
    _in_edges: dict[str, list[EvidenceEdge]] = field(default_factory=dict, init=False, repr=False)

    def add_node(self, node_type: str, key: str | int, label: str, **data) -> EvidenceNode:
        node_id = f"{node_type}:{key}"
        node = self.nodes.get(node_id)
        if node is None:
            node = EvidenceNode(node_id, node_type, label, data)
            self.nodes[node_id] = node
        else:
            node.data.update({k: v for k, v in data.items() if v not in (None, "", [], {})})
        return node

    def add_edge(self, source: EvidenceNode | str, target: EvidenceNode | str,
                 edge_type: str, *, confidence: float = 1.0, **evidence) -> None:
        source_id = source.id if isinstance(source, EvidenceNode) else source
        target_id = target.id if isinstance(target, EvidenceNode) else target
        self.edges.append(
            edge := EvidenceEdge(
                    source_id,
                    target_id,
                    edge_type,
                    max(0.0, min(float(confidence), 1.0)),
                    {k: v for k, v in evidence.items() if v not in (None, "", [], {})},
                )
        )
        self._out_edges.setdefault(source_id, []).append(edge)
        self._in_edges.setdefault(target_id, []).append(edge)

    def outgoing(self, node_id: str, edge_type: str | None = None) -> list[EvidenceEdge]:
        return [
            edge for edge in self._out_edges.get(node_id, [])
            if edge_type is None or edge.type == edge_type
        ]

    def incoming(self, node_id: str, edge_type: str | None = None) -> list[EvidenceEdge]:
        return [
            edge for edge in self._in_edges.get(node_id, [])
            if edge_type is None or edge.type == edge_type
        ]

    def as_dict(self) -> dict:
        return {
            "summary": {
                "nodes": len(self.nodes),
                "edges": len(self.edges),
                "by_type": _count_by_type(self.nodes.values()),
            },
            "nodes": [
                {"id": node.id, "type": node.type, "label": node.label, "data": node.data}
                for node in self.nodes.values()
            ],
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "type": edge.type,
                    "confidence": edge.confidence,
                    "evidence": edge.evidence,
                }
                for edge in self.edges
            ],
        }


def build(limit_assets: int = 10000, *, honeypot_limit: int = 500) -> EvidenceGraph:
    graph = EvidenceGraph()
    asset_rows = db.assets(limit=limit_assets)
    asset_ids = [int(row["id"]) for row in asset_rows]
    finding_rows = db.findings(limit=10000)
    matches_by_finding = db.vulnerability_matches_for_findings([int(row["id"]) for row in finding_rows])
    packages_by_asset = db.asset_packages_for_assets(asset_ids)
    recon_targets = db.recent_targets(limit=1000)

    asset_nodes: dict[int, EvidenceNode] = {}
    asset_by_host: dict[str, EvidenceNode] = {}
    service_nodes: dict[tuple[int, str, int], EvidenceNode] = {}
    for row in asset_rows:
        asset = _asset_dict(row)
        node = graph.add_node(
            "asset",
            asset["id"],
            asset["hostname"],
            **asset,
        )
        asset_nodes[int(asset["id"])] = node
        asset_by_host[str(asset["hostname"]).lower()] = node
        for ip in asset.get("normalized_ips", []):
            ip_node = graph.add_node("ip", ip, ip, public=_is_public_ip(ip))
            graph.add_edge(node, ip_node, "resolves_to", confidence=0.95)
            if ip_node.data.get("public"):
                graph.add_edge(ip_node, node, "internet_exposes", confidence=0.9)
        for svc in asset.get("open_services", []):
            service_node = _add_service(graph, node, svc)
            service_nodes[(int(asset["id"]), str(svc.get("proto") or "tcp"), int(svc.get("port") or 0))] = service_node
        for pkg in packages_by_asset.get(int(asset["id"]), []):
            pkg_node = graph.add_node(
                "package",
                f"{asset['id']}:{pkg['package_name']}:{pkg['source']}",
                pkg["package_name"],
                asset_id=asset["id"],
                version=pkg["version"],
                source=pkg["source"],
            )
            graph.add_edge(node, pkg_node, "has_package", confidence=0.85)

    for row in finding_rows:
        finding = dict(row)
        asset_node = asset_nodes.get(int(finding["asset_id"])) if finding.get("asset_id") is not None else None
        finding_node = graph.add_node(
            "finding",
            finding["id"],
            finding["title"],
            **finding,
        )
        if asset_node:
            graph.add_edge(asset_node, finding_node, "has_finding", confidence=_confidence_label_score(finding.get("confidence")))
        for match_row in matches_by_finding.get(int(finding["id"]), []):
            _add_vulnerability_match(graph, asset_node, finding_node, dict(match_row))
        _add_control_gap_edges(graph, asset_node, finding_node, finding)
        _add_web_audit_edges(graph, asset_node, finding_node, finding)

    for target in recon_targets:
        target_node = graph.add_node("recon_target", target["id"], target["domain"], domain=target["domain"])
        asset_node = asset_by_host.get(str(target["domain"]).lower())
        if asset_node:
            graph.add_edge(asset_node, target_node, "has_recon", confidence=0.8)
        for finding in db.recon_findings_for(int(target["id"])):
            data = _loads(finding["data_json"], {})
            recon_node = graph.add_node(
                "recon_observation",
                finding["id"],
                finding["kind"],
                target_id=target["id"],
                kind=finding["kind"],
                data=data,
                found_ts=finding["found_ts"],
            )
            graph.add_edge(target_node, recon_node, "observed", confidence=_recon_confidence(finding["kind"], data))
            if asset_node:
                graph.add_edge(asset_node, recon_node, "recon_evidence", confidence=_recon_confidence(finding["kind"], data))

    _add_honeypot_signals(graph, honeypot_limit=honeypot_limit)
    return graph


def asset_contexts(graph: EvidenceGraph) -> list[dict]:
    contexts = []
    honeypot_surface_signals = _honeypot_surface_signals(graph)
    for asset in [node for node in graph.nodes.values() if node.type == "asset"]:
        services = [graph.nodes[e.target] for e in graph.outgoing(asset.id, "offers_service")]
        findings = [graph.nodes[e.target] for e in graph.outgoing(asset.id, "has_finding")]
        vuln_edges = []
        control_edges = []
        for finding in findings:
            vuln_edges.extend(graph.outgoing(finding.id, "matches_vulnerability"))
            control_edges.extend(graph.outgoing(finding.id, "indicates_control_gap"))
        recon = [graph.nodes[e.target] for e in graph.outgoing(asset.id, "recon_evidence")]
        honeypot_edges = _relevant_honeypot_edges(asset, services, honeypot_surface_signals)
        contexts.append(
            {
                "asset": asset,
                "services": services,
                "findings": findings,
                "vulnerability_edges": vuln_edges,
                "control_gap_edges": control_edges,
                "recon": recon,
                "honeypot_edges": honeypot_edges,
            }
        )
    return contexts


def asset_neighborhood(asset_id: int, *, graph: EvidenceGraph | None = None, limit: int = 40) -> dict:
    graph = graph or build()
    node_id = f"asset:{asset_id}"
    asset = graph.nodes.get(node_id)
    if asset is None:
        return {"asset": None, "summary": {}, "neighbors": []}
    edges = graph.outgoing(node_id) + graph.incoming(node_id)
    neighbors = []
    for edge in edges[:limit]:
        other_id = edge.target if edge.source == node_id else edge.source
        other = graph.nodes.get(other_id)
        if other is None:
            continue
        neighbors.append(
            {
                "id": other.id,
                "type": other.type,
                "label": other.label,
                "edge": edge.type,
                "confidence": edge.confidence,
                "data": _compact_node_data(other),
            }
        )
    return {
        "asset": {"id": asset.id, "label": asset.label, "data": _compact_node_data(asset)},
        "summary": {
            "services": sum(1 for item in neighbors if item["type"] == "service"),
            "findings": sum(1 for item in neighbors if item["type"] == "finding"),
            "vulnerabilities": sum(1 for item in neighbors if item["type"] == "vulnerability"),
            "recon": sum(1 for item in neighbors if item["type"] == "recon_observation"),
            "control_gaps": sum(1 for item in neighbors if item["type"] == "control_gap"),
            "web_audit_signals": sum(1 for item in neighbors if item["type"] == "web_audit_signal"),
            "honeypot_signals": sum(1 for item in neighbors if item["type"] == "honeypot_signal"),
        },
        "neighbors": neighbors,
    }


def _add_service(graph: EvidenceGraph, asset_node: EvidenceNode, svc: dict) -> EvidenceNode:
    port = int(svc.get("port") or 0)
    proto = str(svc.get("proto") or "tcp")
    service = str(svc.get("service") or "").lower()
    key = f"{asset_node.data.get('id')}:{proto}:{port}"
    category = _service_category(port, service)
    node = graph.add_node(
        "service",
        key,
        f"{service or 'unknown'}:{port}/{proto}",
        asset_id=asset_node.data.get("id"),
        port=port,
        proto=proto,
        service=service,
        version=svc.get("version") or "",
        banner=svc.get("banner") or "",
        technologies=svc.get("technologies") or [],
        metadata=svc.get("metadata") or {},
        category=category,
        risky=category != "general",
    )
    graph.add_edge(asset_node, node, "offers_service", confidence=0.9)
    if category != "general":
        graph.add_edge(node, asset_node, "increases_entry_surface", confidence=0.65, category=category)
    return node


def _add_vulnerability_match(graph: EvidenceGraph, asset_node: EvidenceNode | None,
                             finding_node: EvidenceNode, match: dict) -> None:
    evidence = _loads(match.get("evidence_json"), {})
    cve_id = match.get("cve_id") or "unknown"
    vuln_node = graph.add_node(
        "vulnerability",
        cve_id,
        cve_id,
        cve_id=cve_id,
        matched_cpe=match.get("matched_cpe") or "",
        match_status=match.get("match_status") or "",
        confidence_score=float(match.get("confidence_score") or 0.0),
        priority_score=float(match.get("priority_score") or 0.0),
        evidence=evidence,
    )
    graph.add_edge(
        finding_node,
        vuln_node,
        "matches_vulnerability",
        confidence=float(match.get("confidence_score") or 0.0),
        match_status=match.get("match_status") or "",
        matched_cpe=match.get("matched_cpe") or "",
        evidence=evidence,
    )
    if asset_node:
        graph.add_edge(asset_node, vuln_node, "affected_by", confidence=float(match.get("confidence_score") or 0.0))


def _add_control_gap_edges(graph: EvidenceGraph, asset_node: EvidenceNode | None,
                           finding_node: EvidenceNode, finding: dict) -> None:
    title = str(finding.get("title") or "")
    for marker, gap_type in CONTROL_GAP_MARKERS.items():
        if marker not in title:
            continue
        gap_node = graph.add_node(
            "control_gap",
            f"{finding['id']}:{marker}",
            marker,
            gap_type=gap_type,
            title=title,
        )
        graph.add_edge(finding_node, gap_node, "indicates_control_gap", confidence=0.65)
        if asset_node:
            graph.add_edge(asset_node, gap_node, "has_control_gap", confidence=0.65)


def _add_web_audit_edges(graph: EvidenceGraph, asset_node: EvidenceNode | None,
                         finding_node: EvidenceNode, finding: dict) -> None:
    if str(finding.get("source_module") or "").lower() != "nikto":
        return
    evidence = _loads(finding.get("evidence"), {})
    audit_node = graph.add_node(
        "web_audit_signal",
        finding["id"],
        finding["title"],
        engine="nikto",
        severity=finding.get("severity"),
        confidence=finding.get("confidence"),
        evidence=evidence,
    )
    graph.add_edge(finding_node, audit_node, "indicates_web_audit_issue", confidence=0.45, engine="nikto", evidence=evidence)
    if asset_node:
        graph.add_edge(asset_node, audit_node, "has_web_audit_signal", confidence=0.45, engine="nikto")


def _add_honeypot_signals(graph: EvidenceGraph, *, honeypot_limit: int) -> None:
    for row in db.recent_honeypot_events(limit=honeypot_limit):
        iocs = _loads(row["iocs_json"], {})
        signal = graph.add_node(
            "honeypot_signal",
            row["id"],
            row["classification"] or row["hp_type"],
            hp_type=row["hp_type"],
            src_ip=row["src_ip"],
            method=row["method"] or "",
            path=row["path"] or "",
            classification=row["classification"] or "connection",
            iocs=iocs,
            ts=row["ts"],
        )
        class_node = graph.add_node("threat_activity", row["classification"] or "connection", row["classification"] or "connection")
        graph.add_edge(signal, class_node, "indicates_activity", confidence=_honeypot_confidence(row["classification"] or "connection"))


def _honeypot_surface_signals(graph: EvidenceGraph) -> dict[str, EvidenceEdge]:
    out: dict[str, EvidenceEdge] = {}
    for signal in [node for node in graph.nodes.values() if node.type == "honeypot_signal"]:
        hp_type = signal.data.get("hp_type")
        classification = signal.data.get("classification")
        path = str(signal.data.get("path") or "").lower()
        candidates: list[tuple[str, float, str]] = []
        if hp_type in {"http", "https"}:
            candidates.append(("web", 0.55, "web honeypot activity relevant to exposed web surface"))
        if classification in {"login-probe", "exploit-probe", "write-probe"}:
            candidates.append(("web", 0.72, f"{classification} activity relevant to exposed web surface"))
        if hp_type == "ssh":
            candidates.append(("ssh", 0.7, "SSH honeypot activity relevant to SSH surface"))
        if hp_type == "ftp":
            candidates.append(("ftp", 0.65, "FTP honeypot activity relevant to FTP surface"))
        if any(token in path for token in ("wp-login", "phpmyadmin", "admin", "login")):
            candidates.append(("web", 0.75, "honeypot observed web admin/login probing"))
        for key, confidence, reason in candidates:
            edge = EvidenceEdge(signal.id, "*", "activity_relevant_to_surface", confidence, {"reason": reason})
            if key not in out or edge.confidence > out[key].confidence:
                out[key] = edge
    return out


def _relevant_honeypot_edges(asset: EvidenceNode, services: list[EvidenceNode],
                             surface_signals: dict[str, EvidenceEdge]) -> list[EvidenceEdge]:
    ports = {int(svc.data.get("port") or 0) for svc in services}
    service_names = {str(svc.data.get("service") or "").lower() for svc in services}
    relevant = []
    if ports & RISKY_WEB_PORTS and "web" in surface_signals:
        signal = surface_signals["web"]
        relevant.append(EvidenceEdge(signal.source, asset.id, "activity_relevant_to_asset", signal.confidence, signal.evidence))
    if (22 in ports or "ssh" in service_names) and "ssh" in surface_signals:
        signal = surface_signals["ssh"]
        relevant.append(EvidenceEdge(signal.source, asset.id, "activity_relevant_to_asset", signal.confidence, signal.evidence))
    if (21 in ports or "ftp" in service_names) and "ftp" in surface_signals:
        signal = surface_signals["ftp"]
        relevant.append(EvidenceEdge(signal.source, asset.id, "activity_relevant_to_asset", signal.confidence, signal.evidence))
    return relevant


def _asset_dict(row) -> dict:
    out = dict(row)
    for key, default in (
        ("normalized_ips", []),
        ("open_services", []),
        ("technologies", []),
        ("tags", []),
        ("dns_records", {}),
        ("certificates", []),
    ):
        out[key] = _loads(out.get(key), default)
    out["internet_exposed"] = any(_is_public_ip(ip) for ip in out.get("normalized_ips", []))
    return out


def _compact_node_data(node: EvidenceNode) -> dict:
    keep = (
        "id",
        "hostname",
        "internet_exposed",
        "port",
        "proto",
        "service",
        "version",
        "category",
        "risky",
        "severity",
        "confidence",
        "status",
        "source_module",
        "cve_id",
        "match_status",
        "confidence_score",
        "priority_score",
        "engine",
        "kind",
        "gap_type",
    )
    return {key: node.data.get(key) for key in keep if key in node.data and node.data.get(key) not in (None, "", [], {})}


def _service_category(port: int, service: str) -> str:
    if port in RISKY_WEB_PORTS:
        return "web"
    if port in RISKY_REMOTE_ADMIN_PORTS:
        return "remote-admin"
    if port in RISKY_DATABASE_PORTS:
        return "database"
    if service in RISKY_SERVICE_NAMES:
        return "insecure-or-abused-service"
    return "general"


def _recon_confidence(kind: str, data: dict) -> float:
    if kind in {"dns", "whois"}:
        return 0.75
    if kind in {"techstack", "exposure"} and data:
        return 0.68
    if kind == "takeover":
        return 0.55
    return 0.5


def _honeypot_confidence(classification: str) -> float:
    return {
        "exploit-probe": 0.85,
        "credential-attempt": 0.75,
        "mail-relay-probe": 0.72,
        "login-probe": 0.7,
        "write-probe": 0.68,
        "scanner": 0.45,
        "connection": 0.25,
    }.get(classification, 0.35)


def _confidence_label_score(value: str | None) -> float:
    return {"High": 0.9, "Medium": 0.65, "Low": 0.35}.get(str(value or ""), 0.5)


def _loads(value: Any, default):
    if not value:
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved)


def _count_by_type(nodes) -> dict[str, int]:
    out: dict[str, int] = {}
    for node in nodes:
        out[node.type] = out.get(node.type, 0) + 1
    return out

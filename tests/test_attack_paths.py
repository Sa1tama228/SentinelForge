import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinelforge.core import db
from sentinelforge.modules.analysis import attack_paths
from sentinelforge.modules.analysis import evidence_graph


def test_strong_vulnerability_match_becomes_attack_path():
    asset_id = db.upsert_asset(
        "attack-path-strong.local",
        ips=["8.8.8.8"],
        source="test",
        open_services=[{"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 8.9p1"}],
    )
    finding_id = db.upsert_finding(
        title="OpenSSH vulnerable package",
        severity="Critical",
        confidence="High",
        asset_id=asset_id,
        evidence="ssh:22 OpenSSH 8.9p1",
        source_module="test",
        remediation="Patch OpenSSH",
        fingerprint="attack-path-strong-finding",
    )
    db.upsert_vulnerability_match(
        finding_id=finding_id,
        cve_id="CVE-2099-0001",
        asset_id=asset_id,
        matched_cpe="cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*",
        match_status="confirmed_candidate",
        confidence_score=0.92,
        priority_score=95.0,
        evidence={
            "service": "ssh",
            "product": "OpenSSH",
            "version": "8.9p1",
            "cvss_score": 9.8,
            "kev": True,
            "epss": {"score": 0.88},
            "public_exploit_count": 2,
        },
    )

    data = attack_paths.analyze(limit=20, include_low=False)
    paths = [
        path
        for path in data["paths"]
        if path["asset"] == "attack-path-strong.local" and path["evidence"].get("cve_id") == "CVE-2099-0001"
    ]

    assert paths
    assert paths[0]["title"] == "Vulnerability-backed attack path"
    assert paths[0]["confidence"] == "High"
    assert paths[0]["score"] >= 90
    assert data["summary"]["graph"]["nodes"] > 0
    assert "graph_edges" in paths[0]["evidence"]


def test_weak_vulnerability_match_is_not_promoted_to_attack_path():
    asset_id = db.upsert_asset(
        "attack-path-weak.local",
        ips=["8.8.4.4"],
        source="test",
    )
    finding_id = db.upsert_finding(
        title="Weak banner-only candidate",
        severity="Medium",
        confidence="Low",
        asset_id=asset_id,
        evidence="service banner without version",
        source_module="test",
        remediation="Validate manually",
        fingerprint="attack-path-weak-finding",
    )
    db.upsert_vulnerability_match(
        finding_id=finding_id,
        cve_id="CVE-2099-0002",
        asset_id=asset_id,
        matched_cpe="cpe:2.3:a:example:service:*:*:*:*:*:*:*:*",
        match_status="unknown",
        confidence_score=0.25,
        priority_score=30.0,
        evidence={
            "service": "example",
            "product": "ExampleService",
            "cvss_score": 9.8,
            "kev": False,
            "epss": {"score": 0.2},
        },
    )

    data = attack_paths.analyze(limit=50, include_low=True)
    promoted = [
        path
        for path in data["paths"]
        if path["asset"] == "attack-path-weak.local" and path["evidence"].get("cve_id") == "CVE-2099-0002"
    ]

    assert promoted == []


def test_distribution_patched_advisory_suppresses_vulnerability_path():
    asset_id = db.upsert_asset(
        "attack-path-patched.local",
        ips=["8.8.8.11"],
        source="test",
        open_services=[{"port": 22, "proto": "tcp", "service": "ssh"}],
    )
    finding_id = db.upsert_finding(
        title="Patched distro candidate",
        severity="Critical",
        confidence="High",
        asset_id=asset_id,
        evidence="ssh patched package",
        source_module="test",
        remediation="None",
        fingerprint="attack-path-patched-finding",
    )
    db.upsert_vulnerability_match(
        finding_id=finding_id,
        cve_id="CVE-2099-0004",
        asset_id=asset_id,
        matched_cpe="cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*",
        match_status="confirmed_candidate",
        confidence_score=0.95,
        priority_score=95.0,
        evidence={
            "service": "ssh",
            "product": "OpenSSH",
            "version": "8.9p1",
            "cvss_score": 9.8,
            "kev": True,
            "distribution_advisory": {"local_status": "patched_by_distribution_advisory"},
        },
    )

    data = attack_paths.analyze(limit=50, include_low=True)
    promoted = [
        path
        for path in data["paths"]
        if path["asset"] == "attack-path-patched.local" and path["evidence"].get("cve_id") == "CVE-2099-0004"
    ]

    assert promoted == []


def test_evidence_graph_links_asset_service_finding_and_vulnerability():
    asset_id = db.upsert_asset(
        "evidence-graph.local",
        ips=["8.8.4.4"],
        source="test",
        open_services=[{"port": 8080, "proto": "tcp", "service": "http", "version": "nginx"}],
    )
    finding_id = db.upsert_finding(
        title="Graph CVE candidate",
        severity="High",
        confidence="High",
        asset_id=asset_id,
        evidence="http:8080 nginx",
        source_module="test",
        remediation="Patch",
        fingerprint="evidence-graph-finding",
    )
    db.upsert_vulnerability_match(
        finding_id=finding_id,
        cve_id="CVE-2099-0003",
        asset_id=asset_id,
        matched_cpe="cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*",
        match_status="likely_candidate",
        confidence_score=0.7,
        priority_score=75.0,
        evidence={"service": "http", "version": "1.0", "cvss_score": 8.0},
    )

    graph = evidence_graph.build()
    payload = graph.as_dict()
    edge_types = {edge["type"] for edge in payload["edges"]}

    assert payload["summary"]["by_type"]["asset"] >= 1
    assert "offers_service" in edge_types
    assert "has_finding" in edge_types
    assert "matches_vulnerability" in edge_types

    neighborhood = evidence_graph.asset_neighborhood(asset_id, graph=graph)
    assert neighborhood["summary"]["services"] >= 1
    assert neighborhood["summary"]["findings"] >= 1
    assert any(item["type"] == "service" for item in neighborhood["neighbors"])


def test_nikto_findings_become_web_audit_graph_paths():
    asset_id = db.upsert_asset(
        "nikto-graph.local",
        ips=["8.8.8.9"],
        source="test",
        open_services=[{"port": 80, "proto": "tcp", "service": "http", "version": "nginx"}],
    )
    finding_id = db.upsert_finding(
        title="Nikto: /.git/HEAD Git metadata found",
        severity="High",
        confidence="Low",
        asset_id=asset_id,
        evidence='{"engine":"nikto","target":"http://nikto-graph.local","uri":"/.git/HEAD","osvdb":"3092"}',
        source_module="nikto",
        remediation="Validate and remove exposed Git metadata",
        fingerprint="nikto-graph-finding",
    )

    graph = evidence_graph.build()
    assert any(node.type == "web_audit_signal" and node.data.get("engine") == "nikto" for node in graph.nodes.values())

    data = attack_paths.analyze(limit=50, include_low=True)
    paths = [
        path
        for path in data["paths"]
        if path["asset"] == "nikto-graph.local" and path["title"] == "Web audit signal path"
    ]

    assert finding_id > 0
    assert paths
    assert paths[0]["confidence"] == "Low"
    assert paths[0]["evidence"]["engine"] == "nikto"

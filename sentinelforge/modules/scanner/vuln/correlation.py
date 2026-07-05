"""Offline CVE exposure correlation against local CPE/version data."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from ....core import db
from .cpe import CPECandidate, candidates_for
from .fingerprint_model import ServiceFingerprint
from .advisories import advisory_state
from .verification import recommended_steps, warning as verification_warning
from .version_matcher import MatchResult, VersionRange, evaluate_range

_DEMO_CVE_DB = Path(__file__).parents[1] / "cve_db.json"


@dataclass(frozen=True)
class CorrelationMatch:
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    matched_cpe: str
    match_status: str
    confidence_score: float
    confidence_label: str
    confidence_explanation: str
    priority_score: float
    priority_explanation: str
    remediation: str
    epss_score: float | None
    epss_percentile: float | None
    kev: dict | None
    public_exploits: list[dict]
    published_ts: str
    modified_ts: str
    recommended_verification: list[str]
    verification_warning: str
    evidence: dict


def seed_demo_cache() -> None:
    """Load the bundled demo CVEs into the normalized vulnerability cache.

    This is intentionally local and idempotent. It gives the new correlation
    engine useful offline data until a full NVD synchronizer is wired in.
    """
    entries = _demo_entries()
    imported = 0
    for entry in entries:
        cve_id = entry["cve"]
        description = entry.get("desc", "")
        title = description.split(":", 1)[0] if ":" in description else cve_id
        product = entry.get("product", "")
        candidates = candidates_for(product, raw_service=entry.get("service", ""))
        if not candidates:
            continue
        db.upsert_cve(
            cve_id=cve_id,
            title=title,
            description=description,
            status="demo-cache",
            source_name="bundled-demo",
            raw=entry,
        )
        severity, score = _demo_metric(entry)
        db.upsert_cve_metric(
            cve_id=cve_id,
            source="bundled-demo",
            severity=severity,
            score=score,
            vector="",
            cwe_refs=[],
        )
        for candidate in candidates:
            db.upsert_cpe_product(
                vendor=candidate.vendor,
                product=candidate.product,
                cpe_uri=candidate.cpe_uri,
                title=candidate.display_name,
                aliases=[product, entry.get("service", "")],
            )
            db.upsert_cve_cpe_range(
                cve_id=cve_id,
                cpe_uri=candidate.cpe_uri,
                version_start_including=entry.get("min", ""),
                version_end_including=entry.get("max", ""),
            )
        imported += 1
    db.update_vulnerability_source(
        "nvd",
        source_version="bundled-demo",
        status="offline-cache-ready",
        record_count=imported,
        success=True,
    )


def correlate_fingerprint(
    fingerprint: ServiceFingerprint,
    *,
    asset_id: int | None = None,
    service_fingerprint_id: int | None = None,
    ensure_seeded: bool = True,
    minimum_confidence: float = 0.0,
    include_unknown: bool = True,
    limit: int | None = None,
) -> list[CorrelationMatch]:
    if ensure_seeded:
        seed_demo_cache()
    cpe_candidates = candidates_for(
        fingerprint.product or fingerprint.raw_version,
        raw_service=fingerprint.service or fingerprint.raw_service,
    )
    if not cpe_candidates:
        return []
    by_cpe = {candidate.cpe_uri: candidate for candidate in cpe_candidates}
    ranges = db.vulnerability_ranges_for_cpes(list(by_cpe))
    enrichment_by_cve = db.vulnerability_enrichment_bulk([row["cve_id"] for row in ranges])
    out: list[CorrelationMatch] = []
    seen: set[tuple] = set()
    for row in ranges:
        if not row["vulnerable"]:
            continue
        candidate = by_cpe.get(row["cpe_uri"])
        if not candidate:
            continue
        version_range = VersionRange(
            start_including=row["version_start_including"] or "",
            start_excluding=row["version_start_excluding"] or "",
            end_including=row["version_end_including"] or "",
            end_excluding=row["version_end_excluding"] or "",
            exact=row["exact_version"] or "",
        )
        range_result = evaluate_range(fingerprint.version, version_range)
        if range_result == MatchResult.NOT_VULNERABLE:
            continue
        if range_result == MatchResult.UNKNOWN and not include_unknown:
            continue
        key = (
            row["cve_id"],
            row["cpe_uri"],
            row["version_start_including"] or "",
            row["version_start_excluding"] or "",
            row["version_end_including"] or "",
            row["version_end_excluding"] or "",
            row["exact_version"] or "",
        )
        if key in seen:
            continue
        seen.add(key)
        enrichment = enrichment_by_cve.get(row["cve_id"], {"metrics": [], "kev": None, "epss": None, "exploits": []})
        metric = _best_metric(enrichment["metrics"])
        status = _classify(range_result, fingerprint, candidate)
        advisory = advisory_state(
            row["cve_id"],
            distribution=fingerprint.distribution,
            product=fingerprint.product,
            package_revision=fingerprint.package_revision,
        )
        if advisory.get("local_status") == "patched_by_distribution_advisory":
            status = "not_applicable"
        confidence_score = _confidence_score(range_result, fingerprint, candidate)
        if confidence_score < minimum_confidence:
            continue
        priority_score, priority_explanation = _priority(metric, confidence_score, enrichment)
        explanation = _confidence_explanation(range_result, fingerprint, candidate, version_range)
        evidence = {
            "service_fingerprint_id": service_fingerprint_id,
            "asset_id": asset_id,
            "service": fingerprint.service,
            "vendor": fingerprint.vendor,
            "product": fingerprint.product,
            "version": fingerprint.version,
            "distribution": fingerprint.distribution,
            "package_revision": fingerprint.package_revision,
            "detection_method": fingerprint.detection_method,
            "fingerprint_confidence": fingerprint.confidence,
            "matched_cpe": row["cpe_uri"],
            "version_range": version_range.__dict__,
            "range_result": range_result.value,
            "cvss_score": metric["score"],
            "severity": metric["severity"],
            "kev": bool(enrichment["kev"]),
            "epss": enrichment["epss"],
            "public_exploit_count": len(enrichment["exploits"]),
            "distribution_advisory": advisory,
            "recommended_verification": recommended_steps(fingerprint.service, row["cve_id"]),
            "verification_warning": verification_warning(),
        }
        out.append(
            CorrelationMatch(
                cve_id=row["cve_id"],
                title=row["title"] or row["cve_id"],
                description=row["description"] or "",
                severity=metric["severity"],
                cvss_score=metric["score"],
                matched_cpe=row["cpe_uri"],
                match_status=status,
                confidence_score=confidence_score,
                confidence_label=_confidence_label(confidence_score),
                confidence_explanation=explanation,
                priority_score=priority_score,
                priority_explanation=priority_explanation,
                remediation=_remediation(enrichment, row["cve_id"]),
                epss_score=_epss_value(enrichment["epss"], "score"),
                epss_percentile=_epss_value(enrichment["epss"], "percentile"),
                kev=enrichment["kev"],
                public_exploits=enrichment["exploits"],
                published_ts=row["published_ts"] or "",
                modified_ts=row["modified_ts"] or "",
                recommended_verification=recommended_steps(fingerprint.service, row["cve_id"]),
                verification_warning=verification_warning(),
                evidence=evidence,
            )
        )
    sorted_matches = sorted(out, key=lambda item: (item.priority_score, item.confidence_score), reverse=True)
    if limit is not None and limit > 0:
        return sorted_matches[:limit]
    return sorted_matches


def persist_match(
    match: CorrelationMatch,
    *,
    asset_id: int,
    service_fingerprint_id: int,
    finding_id: int | None = None,
) -> int:
    return db.upsert_vulnerability_match(
        finding_id=finding_id,
        cve_id=match.cve_id,
        asset_id=asset_id,
        service_fingerprint_id=service_fingerprint_id,
        matched_cpe=match.matched_cpe,
        match_status=match.match_status,
        confidence_score=match.confidence_score,
        confidence_explanation=match.confidence_explanation,
        priority_score=match.priority_score,
        priority_explanation=match.priority_explanation,
        evidence=match.evidence,
    )


def finding_fingerprint(target: str, port: int, cve_id: str, matched_cpe: str) -> str:
    raw = f"scanner-vce|{target.lower()}|{port}|{cve_id}|{matched_cpe}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@lru_cache(maxsize=1)
def _demo_entries() -> list[dict]:
    return json.loads(_DEMO_CVE_DB.read_text(encoding="utf-8"))


def _demo_metric(entry: dict) -> tuple[str, float]:
    text = f"{entry.get('cve', '')} {entry.get('desc', '')}".lower()
    if "rce" in text or "pre-auth" in text:
        return "Critical", 9.8
    if "denial-of-service" in text or "enumeration" in text:
        return "Medium", 5.3
    return "High", 7.5


def _best_metric(metrics: list[dict]) -> dict:
    if not metrics:
        return {"severity": "Unknown", "score": 0.0}
    return max(metrics, key=lambda item: float(item.get("score") or 0.0))


def _classify(result: MatchResult, fingerprint: ServiceFingerprint, candidate: CPECandidate) -> str:
    if result == MatchResult.UNKNOWN:
        return "unknown"
    if fingerprint.confidence >= 0.82 and candidate.confidence >= 0.9 and fingerprint.version:
        return "confirmed_candidate"
    if fingerprint.confidence >= 0.65 and candidate.confidence >= 0.75:
        return "likely_candidate"
    return "weak_candidate"


def _confidence_score(result: MatchResult, fingerprint: ServiceFingerprint, candidate: CPECandidate) -> float:
    if result == MatchResult.UNKNOWN:
        return round(min(0.49, fingerprint.confidence * candidate.confidence), 2)
    score = (fingerprint.confidence * 0.65) + (candidate.confidence * 0.25) + 0.1
    if not fingerprint.version:
        score -= 0.3
    if fingerprint.distribution and fingerprint.package_revision:
        score -= 0.05
    return round(max(0.05, min(score, 0.98)), 2)


def _confidence_label(score: float) -> str:
    if score >= 0.8:
        return "High"
    if score >= 0.55:
        return "Medium"
    return "Low"


def _confidence_explanation(
    result: MatchResult,
    fingerprint: ServiceFingerprint,
    candidate: CPECandidate,
    version_range: VersionRange,
) -> str:
    parts = [
        f"Product mapped to {candidate.vendor}:{candidate.product} via {candidate.reason}.",
        f"Detected version: {fingerprint.version or 'unknown'}.",
    ]
    if result == MatchResult.VULNERABLE:
        parts.append(f"Version is inside affected range {version_range}.")
    elif result == MatchResult.UNKNOWN:
        parts.append("Version could not be safely compared; manual verification required.")
    if fingerprint.distribution and fingerprint.package_revision:
        parts.append(
            f"{fingerprint.distribution} package revision {fingerprint.package_revision} may include vendor backports."
        )
    return " ".join(parts)


def _priority(metric: dict, confidence_score: float, enrichment: dict) -> tuple[float, str]:
    cvss = float(metric.get("score") or 0.0)
    score = cvss
    reasons = [f"CVSS {cvss:.1f}"]
    if enrichment["kev"]:
        score += 2.0
        reasons.append("CISA KEV listed")
    epss = enrichment["epss"]
    if epss and epss.get("score") is not None:
        epss_score = float(epss["score"])
        score += min(1.5, epss_score * 1.5)
        reasons.append(f"EPSS {epss_score:.3f}")
    if enrichment["exploits"]:
        score += 1.0
        reasons.append("public exploit metadata available")
    score *= max(0.35, confidence_score)
    return round(min(score, 10.0), 2), "; ".join(reasons)


def _remediation(enrichment: dict, cve_id: str) -> str:
    kev = enrichment["kev"]
    if kev and kev.get("required_action"):
        return kev["required_action"]
    return f"Validate exposure for {cve_id}, then upgrade or apply the vendor remediation."


def _epss_value(epss: dict | None, key: str) -> float | None:
    if not epss or epss.get(key) is None:
        return None
    try:
        return float(epss[key])
    except (TypeError, ValueError):
        return None

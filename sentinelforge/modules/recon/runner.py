"""Recon orchestration: run all passive collectors for a domain, persist
findings, and emit events for the UI."""
from __future__ import annotations

import re
import threading
import hashlib
from concurrent.futures import ThreadPoolExecutor

from ...core import config, db, events, jobs
from . import dns_records, exposure, subdomains, takeover, whois_rdap, techstack
from . import diff as recon_diff


def run_all(domain: str) -> int:
    """Run synchronously and return the target id."""
    domain = _normalize_domain(domain)
    target_id = db.get_or_create_target(domain)
    previous = _previous_recon_data(target_id)
    db.clear_recon_findings(target_id)
    asset_id = db.upsert_asset(domain, source="recon", tags=["recon"])
    cfg = config.load()
    recon_cfg = cfg["recon"]
    resolvers = recon_cfg["resolvers"]
    ua = recon_cfg["user_agent"]
    source_timeout = float(recon_cfg.get("source_timeout_sec", 20))
    endpoint_timeout = float(recon_cfg.get("safe_endpoint_timeout_sec", 5))
    endpoint_checks = bool(recon_cfg.get("safe_endpoint_checks", True))

    events.emit("recon", {"target_id": target_id, "phase": "started",
                          "domain": domain, "progress": 0.05})

    collectors = {
        "dns": lambda: dns_records.resolve(domain, resolvers),
        "whois": lambda: whois_rdap.lookup(domain),
        "subdomains": lambda: subdomains.enumerate_with_sources(domain, timeout=source_timeout),
        "techstack": lambda: techstack.detect(domain, timeout=min(source_timeout, 10), ua=ua),
        "exposure": lambda: exposure.check(domain, ua=ua, timeout=endpoint_timeout) if endpoint_checks else {"checks": [], "count": 0, "disabled": True},
    }

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {kind: pool.submit(_guard, kind, fn) for kind, fn in collectors.items()}

            dns_data = futures["dns"].result()
            db.add_recon_finding(target_id, "dns", dns_data)
            _source_status(target_id, "dns", dns_data, _count_records(dns_data))
            db.upsert_asset(
                domain,
                ips=(dns_data.get("A", []) + dns_data.get("AAAA", [])) if isinstance(dns_data, dict) else [],
                source="recon",
                tags=["recon"],
                dns_records=dns_data if isinstance(dns_data, dict) else {},
            )
            _dns_findings(asset_id, domain, dns_data)
            dns_delta = recon_diff.diff_dns(previous.get("dns", {}), dns_data if isinstance(dns_data, dict) else {})
            if dns_delta:
                db.add_recon_finding(target_id, "dns_diff", dns_delta)
            events.emit("recon", {"target_id": target_id, "phase": "dns",
                                  "data": dns_data, "progress": 0.25})

            whois_data = futures["whois"].result()
            db.add_recon_finding(target_id, "whois", whois_data)
            _source_status(target_id, "whois", whois_data, 1 if whois_data and not whois_data.get("error") else 0)
            events.emit("recon", {"target_id": target_id, "phase": "whois",
                                  "data": whois_data, "progress": 0.50})

            sub_data = futures["subdomains"].result()
            names = sub_data.get("names", []) if isinstance(sub_data, dict) else []
            db.add_recon_finding(target_id, "subdomains", {"count": len(names), **sub_data})
            _subdomain_source_status(target_id, sub_data)
            sub_delta = recon_diff.diff_lists(previous.get("subdomains", {}).get("names", []), names)
            if sub_delta["added"] or sub_delta["removed"]:
                db.add_recon_finding(target_id, "subdomain_diff", sub_delta)
                _subdomain_delta_findings(asset_id, domain, sub_delta)
            events.emit("recon", {"target_id": target_id, "phase": "subdomains",
                                  "count": len(names), "progress": 0.75})

            tech = futures["techstack"].result()
            db.add_recon_finding(target_id, "techstack", tech)
            _source_status(target_id, "techstack", tech, len(tech.get("technologies", [])) if isinstance(tech, dict) else 0)
            if isinstance(tech, dict):
                db.upsert_asset(
                    domain,
                    source="recon",
                    tags=["recon"],
                    technologies=tech.get("technologies", []) or [],
                )
                _tech_findings(asset_id, domain, tech)
                tech_delta = recon_diff.diff_technologies(previous.get("techstack", {}), tech)
                if tech_delta["added"] or tech_delta["removed"]:
                    db.add_recon_finding(target_id, "tech_diff", tech_delta)
            events.emit("recon", {"target_id": target_id, "phase": "techstack",
                                  "data": tech, "progress": 0.95})

            exposure_data = futures["exposure"].result()
            db.add_recon_finding(target_id, "exposure", exposure_data)
            _source_status(target_id, "exposure", exposure_data, exposure_data.get("count", 0) if isinstance(exposure_data, dict) else 0)
            if isinstance(exposure_data, dict):
                _exposure_findings(asset_id, domain, exposure_data)

            takeover_data = {"hints": takeover.takeover_hints(dns_data if isinstance(dns_data, dict) else {}, names)}
            db.add_recon_finding(target_id, "takeover", takeover_data)
            _source_status(target_id, "takeover", takeover_data, len(takeover_data["hints"]))
            _takeover_findings(asset_id, domain, takeover_data)
    except Exception as exc:
        db.add_recon_finding(target_id, "error", {"error": str(exc)})
        events.emit("recon", {"target_id": target_id, "phase": "failed",
                              "domain": domain, "error": str(exc), "progress": 1.0})
    finally:
        db.add_asset_scan_history(asset_id, source="recon", summary=f"Passive recon target #{target_id}")
        events.emit("recon", {"target_id": target_id, "phase": "done",
                              "domain": domain, "progress": 1.0})
    return target_id


def _previous_recon_data(target_id: int) -> dict:
    out = {}
    for row in db.recon_findings_for(target_id):
        try:
            out[row["kind"]] = __import__("json").loads(row["data_json"])
        except Exception:
            continue
    return out


def _guard(kind: str, fn) -> dict:
    try:
        return fn()
    except Exception as exc:
        return {"error": f"{kind}: {exc}"}


def _source_status(target_id: int, name: str, data: dict, count: int) -> None:
    error = data.get("error", "") if isinstance(data, dict) else ""
    db.update_recon_source_status(
        target_id,
        name,
        status="failed" if error else "synced",
        record_count=0 if error else count,
        last_error=error,
    )


def _subdomain_source_status(target_id: int, sub_data: dict) -> None:
    sources = sub_data.get("sources", {}) if isinstance(sub_data, dict) else {}
    for name, meta in sources.items():
        db.update_recon_source_status(
            target_id,
            f"subdomains:{name}",
            status="failed" if meta.get("error") else "synced",
            record_count=int(meta.get("count") or 0),
            last_error=meta.get("error") or "",
        )


def _count_records(data: dict) -> int:
    if not isinstance(data, dict):
        return 0
    return sum(len(value) for key, value in data.items() if isinstance(value, list) and key != "posture")


def _normalize_domain(value: str) -> str:
    domain = value.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/", 1)[0].split("?", 1)[0].strip(".")
    if not domain or len(domain) > 253:
        raise ValueError("Enter a valid domain")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Domain contains invalid IDN characters") from exc
    labels = domain.split(".")
    valid_labels = all(
        0 < len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and re.fullmatch(r"[a-z0-9-]+", label)
        for label in labels
    )
    if not valid_labels or len(labels) < 2:
        raise ValueError("Enter a valid domain")
    return domain


def _dns_findings(asset_id: int, domain: str, dns_data: dict) -> None:
    if not isinstance(dns_data, dict):
        return
    posture = dns_data.get("posture") or {}
    if not posture.get("spf_present"):
        _finding(
            asset_id,
            domain,
            "Missing SPF record",
            "Medium",
            "High",
            "DNS TXT records did not include an SPF policy.",
            "Publish an SPF TXT record that authorizes legitimate mail senders.",
            "recon:dns:spf",
        )
    if not posture.get("dmarc_present"):
        _finding(
            asset_id,
            domain,
            "Missing DMARC record",
            "Medium",
            "High",
            "No DMARC TXT record was found at _dmarc.%s." % domain,
            "Publish a DMARC policy and monitor aggregate reports before enforcement.",
            "recon:dns:dmarc",
        )


def _tech_findings(asset_id: int, domain: str, tech: dict) -> None:
    headers = tech.get("security_headers") or {}
    for header, present in headers.items():
        if present:
            continue
        severity = "Medium" if header in {"Strict-Transport-Security", "Content-Security-Policy"} else "Low"
        _finding(
            asset_id,
            domain,
            f"Missing {header} header",
            severity,
            "Medium",
            f"{tech.get('final_url', domain)} did not return {header}.",
            f"Set an appropriate {header} response header for this application.",
            f"recon:http-header:{header.lower()}",
        )


def _exposure_findings(asset_id: int, domain: str, exposure_data: dict) -> None:
    for item in exposure_data.get("checks", []):
        _finding(
            asset_id,
            domain,
            item.get("title") or f"Exposed endpoint {item.get('path')}",
            item.get("severity") or "Low",
            item.get("confidence") or "Medium",
            f"{item.get('url')} returned HTTP {item.get('status')}. Sample: {item.get('sample') or '-'}",
            "Review whether this endpoint should be public; restrict access or remove sensitive files.",
            f"recon:exposure:{item.get('path')}",
        )


def _takeover_findings(asset_id: int, domain: str, takeover_data: dict) -> None:
    for item in takeover_data.get("hints", []):
        _finding(
            asset_id,
            domain,
            f"Potential dangling CNAME to {item.get('provider', 'hosted service')}",
            "Medium",
            "Low",
            f"{item.get('name') or domain} points at {item.get('cname')}; {item.get('warning', '')}",
            "Verify the provider resource exists and is owned by you; remove stale DNS records.",
            f"recon:takeover:{item.get('provider')}:{item.get('cname')}",
        )


def _subdomain_delta_findings(asset_id: int, domain: str, delta: dict) -> None:
    if delta.get("added"):
        _finding(
            asset_id,
            domain,
            "New subdomains discovered",
            "Low",
            "Medium",
            ", ".join(delta["added"][:20]),
            "Review newly observed subdomains for ownership, exposure, and expected services.",
            "recon:subdomain-delta:added",
        )


def _finding(asset_id: int, domain: str, title: str, severity: str, confidence: str,
             evidence: str, remediation: str, key: str) -> None:
    raw = f"{key}|{domain.lower()}"
    db.upsert_finding(
        title=title,
        severity=severity,
        confidence=confidence,
        asset_id=asset_id,
        evidence=evidence,
        source_module="recon",
        remediation=remediation,
        fingerprint=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    )


def run_async(domain: str) -> int:
    domain = _normalize_domain(domain)
    target_id = db.get_or_create_target(domain)
    def _run(cancel_event: threading.Event) -> None:
        if cancel_event.is_set():
            return
        jobs.update(f"recon:{target_id}", status="running", progress=0.05, label=f"Recon #{target_id} {domain}")
        run_all(domain)
        jobs.update(f"recon:{target_id}", status="done", progress=1.0)
    jobs.start(f"recon:{target_id}", "recon", f"Recon #{target_id} {domain}", _run)
    return target_id

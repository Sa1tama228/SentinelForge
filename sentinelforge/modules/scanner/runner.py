"""Scan orchestration: discovery + fingerprint + CVE match, persisted to DB
with events emitted for the UI. ``run_async`` is the UI entry point."""
from __future__ import annotations

import json
import fnmatch
import ipaddress
import socket
import threading
from pathlib import Path
from datetime import datetime, timedelta, timezone

from ...core import config, db, events, jobs
from . import delta as scan_delta
from . import discovery, fingerprint, nikto, probe, protocols, tech, udp_probe
from .profiles import resolve_profile
from .vuln import correlation
from .vuln.fingerprint_model import from_scan_result

_cancel_events: dict[int, threading.Event] = {}
_cancel_lock = threading.Lock()


def _json_load(value: str | None, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def _target_policy_error(target: str, ip: str | None = None) -> str:
    cfg = config.load().get("scanner", {})
    allowlist = [str(item).strip().lower() for item in cfg.get("target_allowlist", []) if str(item).strip()]
    allowlist.extend(_scope_file_patterns(str(cfg.get("scope_file_path", "") or "")))
    target_l = (target or "").strip().lower()
    if allowlist and not any(fnmatch.fnmatch(target_l, pattern) for pattern in allowlist):
        return "target is outside scanner target_allowlist"
    if ip:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ""
        if addr.is_private and bool(cfg.get("block_private_targets", False)):
            return "private targets are blocked by scanner policy"
        if not addr.is_private and bool(cfg.get("block_public_targets", False)):
            return "public targets are blocked by scanner policy"
    return ""


def _scope_file_patterns(path_value: str) -> list[str]:
    path_value = (path_value or "").strip()
    if not path_value:
        return []
    path = Path(path_value).expanduser()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    patterns = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip().lower()
        if line:
            patterns.append(line)
    return patterns


def _execute(run_id: int, target: str, ports_spec: str, check_vulns: bool = False,
             profile_key: str = "custom") -> int:
    try:
        return _execute_impl(run_id, target, ports_spec, check_vulns, profile_key)
    except Exception as exc:
        db.finish_scan_run(run_id, "failed", error=str(exc))
        jobs.update(f"scan:{run_id}", status="failed", progress=1.0, error=str(exc))
        events.emit(
            "scanner",
            {"run_id": run_id, "phase": "failed", "reason": str(exc), "progress": 1.0},
        )
        return run_id
    finally:
        with _cancel_lock:
            _cancel_events.pop(run_id, None)


def _execute_impl(run_id: int, target: str, ports_spec: str, check_vulns: bool = False,
                  profile_key: str = "custom") -> int:
    cancel_event = _cancel_events.setdefault(run_id, threading.Event())
    cfg = config.load()
    profile = resolve_profile(profile_key, ports_spec)
    ports_spec = profile.ports or ports_spec
    timeout = float(cfg["scanner"]["timeout_sec"])
    max_threads = int(cfg["scanner"]["max_threads"])
    if profile.low_rate:
        max_threads = min(max_threads, int(cfg["scanner"].get("low_rate_max_threads", 25)))
    engine = str(cfg["scanner"].get("engine", "auto"))
    nmap_extra_flags = str(cfg["scanner"].get("nmap_extra_flags", ""))
    nikto_enabled = bool(cfg["scanner"].get("nikto_enabled", False))
    host_probe = str(cfg["scanner"].get("host_probe", "auto"))
    try:
        ports = discovery.parse_ports(ports_spec)
    except ValueError as exc:
        db.finish_scan_run(run_id, "invalid-ports", error=str(exc))
        jobs.update(f"scan:{run_id}", status="failed", progress=1.0, error=str(exc))
        events.emit(
            "scanner",
            {"run_id": run_id, "phase": "invalid", "reason": str(exc), "progress": 1.0},
        )
        return run_id
    events.emit(
        "scanner",
        {
            "run_id": run_id,
            "phase": "started",
            "target": target,
            "check_vulns": check_vulns,
            "profile": profile.key,
            "progress": 0.05,
        },
    )
    jobs.update(f"scan:{run_id}", status="running", progress=0.05, label=f"Scan #{run_id} {target}")
    db.update_scan_run_progress(run_id, progress=0.05)
    if cancel_event.is_set():
        return _cancelled(run_id)

    ip = _resolve(target)
    if ip is None:
        db.finish_scan_run(run_id, "dns-failed", error="dns")
        jobs.update(f"scan:{run_id}", status="failed", progress=1.0, error="dns")
        events.emit("scanner", {"run_id": run_id, "phase": "failed", "reason": "dns", "progress": 1.0})
        return run_id
    policy_error = _target_policy_error(target, ip)
    if policy_error:
        db.finish_scan_run(run_id, "blocked", error=policy_error)
        jobs.update(f"scan:{run_id}", status="failed", progress=1.0, error=policy_error)
        events.emit("scanner", {"run_id": run_id, "phase": "failed", "reason": policy_error, "progress": 1.0})
        return run_id

    asset_id = db.upsert_asset(target, ips=[ip], source="scanner", tags=["scanner"])
    existing_asset = db.asset_by_id(asset_id)
    previous_services = _json_load(existing_asset["open_services"] if existing_asset else "", [])

    probe_data = {"engine": "off", "ok": None}
    if host_probe in {"auto", "scapy"}:
        probe_data = probe.scapy_ping(ip, timeout=min(timeout, 1.5))
        if host_probe == "auto" and not probe_data.get("available"):
            probe_data = probe.tcp_probe(ip, ports, timeout=min(timeout, 0.75))
    elif host_probe == "tcp":
        probe_data = probe.tcp_probe(ip, ports, timeout=min(timeout, 0.75))
    events.emit(
        "scanner",
        {
            "run_id": run_id,
            "phase": "probe",
            "target": target,
            "probe": probe_data,
            "progress": 0.10,
        },
    )
    db.update_scan_run_progress(run_id, progress=0.10)
    jobs.update(f"scan:{run_id}", progress=0.10)

    events.emit(
        "scanner",
        {"run_id": run_id, "phase": "scanning", "target": target, "progress": 0.15},
    )
    db.update_scan_run_progress(run_id, progress=0.15)
    jobs.update(f"scan:{run_id}", progress=0.15)
    open_ports = discovery.scan_ports(
        ip,
        ports,
        timeout=timeout,
        max_threads=max_threads,
        engine=engine,
        server_name=target,
        nmap_extra_flags=nmap_extra_flags,
        cancel_event=cancel_event,
    )
    if cancel_event.is_set():
        return _cancelled(run_id)
    udp_rows = []
    if profile.include_udp or bool(cfg["scanner"].get("udp_light_enabled", False)):
        udp_rows = udp_probe.scan_udp(ip, ports, timeout=timeout, max_threads=min(max_threads, 50))
    services: list[dict] = []
    all_results = [(port, "tcp", banner) for port, banner in open_ports] + [
        (port, "udp", banner) for port, banner in udp_rows
    ]
    total_results = max(len(all_results), 1)
    for idx, (port, proto, banner) in enumerate(all_results, start=1):
        if cancel_event.is_set():
            return _cancelled(run_id)
        service, version = fingerprint.identify(port, banner)
        vuln_matches = []
        protocol_meta = protocols.extract_metadata(port, service, banner)
        services.append(
            {
                "port": port,
                "proto": proto,
                "service": service,
                "version": version,
                "banner": banner[:300],
                "technologies": tech.technologies_from_banner(banner),
                "metadata": protocol_meta,
            }
        )
        scan_result_id = db.add_scan_result(
            run_id, port, proto=proto, service=service,
            version=version, banner=banner[:300],
            cve_refs="",
        )
        structured_fp = from_scan_result(port, proto, banner)
        service_fingerprint_id = db.add_service_fingerprint(
            scan_result_id=scan_result_id,
            asset_id=asset_id,
            ip=ip,
            port=port,
            proto=proto,
            vendor=structured_fp.vendor,
            product=structured_fp.product,
            version=structured_fp.version,
            distribution=structured_fp.distribution,
            package_revision=structured_fp.package_revision,
            confidence=structured_fp.confidence,
            detection_method=structured_fp.detection_method,
            evidence={
                "target": target,
                "ip": ip,
                "port": port,
                "proto": proto,
                "banner": banner[:1000],
                "service": service,
                "version": version,
                "protocol_metadata": protocol_meta,
                "fingerprint": structured_fp.as_dict(),
            },
        )
        if check_vulns:
            vuln_matches = correlation.correlate_fingerprint(
                structured_fp,
                asset_id=asset_id,
                service_fingerprint_id=service_fingerprint_id,
                ensure_seeded=bool(cfg["scanner"].get("seed_demo_cache_on_scan", True)),
                minimum_confidence=float(cfg["scanner"].get("minimum_candidate_confidence", 0.0)),
                include_unknown=bool(cfg["scanner"].get("include_unknown_version_candidates", False)),
                limit=int(cfg["scanner"].get("max_vulnerability_matches_per_service", 25)),
            )
            if vuln_matches:
                with db.cursor() as c:
                    c.execute(
                        "UPDATE scan_results SET cve_refs=? WHERE id=?",
                        (",".join(match.cve_id for match in vuln_matches), scan_result_id),
                    )
        if nikto_enabled and proto == "tcp" and _is_web_service(port, service):
            _run_nikto_audit(
                run_id,
                target,
                port,
                service,
                asset_id=asset_id,
                cfg=cfg["scanner"],
                cancel_event=cancel_event,
            )
        for match in vuln_matches:
            if db.vulnerability_match_suppressed(
                cve_id=match.cve_id,
                asset_id=asset_id,
                product=structured_fp.product,
                matched_cpe=match.matched_cpe,
                match_status=match.match_status,
            ):
                continue
            evidence_text = _finding_evidence_text(target, port, service, version, banner, match)
            finding_id = db.upsert_finding(
                title=f"{match.cve_id} {match.match_status.replace('_', ' ')} on {service}:{port}",
                severity=match.severity,
                confidence=match.confidence_label,
                asset_id=asset_id,
                evidence=evidence_text,
                source_module="scanner",
                remediation=match.remediation,
                fingerprint=correlation.finding_fingerprint(target, port, match.cve_id, match.matched_cpe),
            )
            correlation.persist_match(
                match,
                asset_id=asset_id,
                service_fingerprint_id=service_fingerprint_id,
                finding_id=finding_id,
            )
        events.emit("scanner", {"run_id": run_id, "phase": "result",
                                "port": port, "service": service,
                                "version": version,
                                "cves": [match.cve_id for match in vuln_matches],
                                "vulnerability_matches": [
                                    {
                                        "cve": match.cve_id,
                                        "status": match.match_status,
                                        "confidence": match.confidence_label,
                                        "priority": match.priority_score,
                                    }
                                    for match in vuln_matches
                                ],
                                 "progress": 0.15 + (idx / total_results) * 0.75})
        progress = 0.15 + (idx / total_results) * 0.75
        db.update_scan_run_progress(run_id, progress=progress)
        jobs.update(f"scan:{run_id}", progress=progress)
    technologies = sorted({item for svc in services for item in svc.get("technologies", [])})
    db.upsert_asset(
        target,
        ips=[ip],
        source="scanner",
        tags=["scanner"],
        open_services=services,
        technologies=technologies,
    )
    delta = scan_delta.service_delta(previous_services, services)
    db.add_asset_scan_history(
        asset_id,
        scan_run_id=run_id,
        source="scanner",
        summary=(
            f"{len(open_ports)} open TCP service(s), {len(udp_rows)} responsive UDP service(s) "
            f"across {len(ports)} requested port(s); delta {scan_delta.summarize_delta(delta)}"
        ),
    )
    db.finish_scan_run(run_id, "done")
    jobs.update(f"scan:{run_id}", status="done", progress=1.0)
    events.emit("scanner", {"run_id": run_id, "phase": "done",
                            "open": len(open_ports) + len(udp_rows),
                            "delta": delta,
                            "progress": 1.0})
    return run_id


def _cancelled(run_id: int) -> int:
    db.finish_scan_run(run_id, "cancelled")
    jobs.update(f"scan:{run_id}", status="cancelled", progress=1.0)
    events.emit("scanner", {"run_id": run_id, "phase": "cancelled", "progress": 1.0})
    return run_id


def _finding_evidence_text(target: str, port: int, service: str, version: str, banner: str,
                           match: correlation.CorrelationMatch) -> str:
    label = {
        "confirmed_candidate": "Potentially affected",
        "likely_candidate": "Likely affected",
        "weak_candidate": "Manual verification required",
        "unknown": "Insufficient version evidence",
    }.get(match.match_status, "Manual verification required")
    return (
        f"{label}: {service} {version or 'unknown'} on {target} tcp/{port}. "
        f"Matched CPE: {match.matched_cpe}. "
        f"Confidence: {match.confidence_score:.2f} ({match.confidence_label}). "
        f"Priority: {match.priority_score:.2f}. "
        f"CVSS: {match.cvss_score:.1f}; EPSS: {_fmt_optional(match.epss_score)}; "
        f"CISA KEV: {'yes' if match.kev else 'no'}; public exploits: {len(match.public_exploits)}. "
        f"{match.confidence_explanation} "
        f"Priority factors: {match.priority_explanation}. "
        f"Banner: {banner[:500]}"
    )


def _fmt_optional(value: float | None) -> str:
    return "-" if value is None else f"{value:.3f}"


def _is_web_service(port: int, service: str) -> bool:
    return port in {80, 443, 8000, 8080, 8081, 8443, 8888} or str(service or "").lower() in nikto.WEB_SERVICES


def _run_nikto_audit(run_id: int, target: str, port: int, service: str, *,
                     asset_id: int, cfg: dict, cancel_event) -> None:
    if cancel_event is not None and cancel_event.is_set():
        return
    events.emit(
        "scanner",
        {"run_id": run_id, "phase": "nikto", "target": target, "port": port, "progress": 0.9},
    )
    result = nikto.run(
        target,
        port,
        service=service,
        timeout=int(cfg.get("nikto_timeout_sec", 120) or 120),
        path_value=str(cfg.get("nikto_path", "") or ""),
        tuning=str(cfg.get("nikto_tuning", "") or ""),
        max_findings=int(cfg.get("nikto_max_findings", 25) or 25),
    )
    if not result.get("ok"):
        events.emit(
            "scanner",
            {
                "run_id": run_id,
                "phase": "nikto-skipped",
                "target": target,
                "port": port,
                "reason": result.get("error", "Nikto did not run"),
                "progress": 0.9,
            },
        )
        return
    for idx, item in enumerate(result.get("findings") or [], start=1):
        title = str(item.get("title") or "Nikto web audit finding").strip()
        evidence = {
            "engine": "nikto",
            "target": result.get("target"),
            "port": port,
            "service": service,
            "uri": item.get("uri", ""),
            "method": item.get("method", ""),
            "osvdb": item.get("osvdb", ""),
            "confidence_note": "External Nikto signal; validate manually before treating as confirmed.",
        }
        db.upsert_finding(
            title=f"Nikto: {title}",
            severity=item.get("severity") or "Medium",
            confidence=item.get("confidence") or "Low",
            asset_id=asset_id,
            evidence=json.dumps(evidence, ensure_ascii=False),
            source_module="nikto",
            remediation="Validate the Nikto result, then harden or patch the affected web endpoint.",
            fingerprint=correlation.finding_fingerprint(target, port, "nikto", f"{idx}:{title}:{item.get('uri', '')}"),
        )


def run_scan(target: str, ports_spec: str) -> int:
    """Run synchronously and return the run id (blocking)."""
    run_id = db.create_scan_run(target, ports_spec)
    return _execute(run_id, target, ports_spec)


def run_async(target: str, ports_spec: str, check_vulns: bool = False, profile_key: str = "custom") -> int:
    """Create the run id immediately, then scan on a daemon thread."""
    running_scans = jobs.list_jobs("scan", include_finished=False)
    max_concurrent = int(config.load().get("scanner", {}).get("max_concurrent_scans", 3) or 3)
    if len(running_scans) >= max(1, max_concurrent):
        run_id = db.create_scan_run(target, ports_spec, check_vulns=check_vulns, profile_key=profile_key)
        reason = f"max concurrent scans reached ({max_concurrent})"
        db.finish_scan_run(run_id, "blocked", error=reason)
        events.emit("scanner", {"run_id": run_id, "phase": "failed", "reason": reason, "progress": 1.0})
        return run_id
    pre_policy_error = _target_policy_error(target)
    run_id = db.create_scan_run(target, ports_spec, check_vulns=check_vulns, profile_key=profile_key)
    if pre_policy_error:
        db.finish_scan_run(run_id, "blocked", error=pre_policy_error)
        events.emit("scanner", {"run_id": run_id, "phase": "failed", "reason": pre_policy_error, "progress": 1.0})
        return run_id
    with _cancel_lock:
        _cancel_events[run_id] = threading.Event()
    def _run(cancel_event: threading.Event) -> None:
        with _cancel_lock:
            _cancel_events[run_id] = cancel_event
        _execute(run_id, target, ports_spec, check_vulns, profile_key)
    jobs.start(f"scan:{run_id}", "scan", f"Scan #{run_id} {target}", _run)
    return run_id


def cancel_scan(run_id: int) -> bool:
    with _cancel_lock:
        event = _cancel_events.get(run_id)
        if event is None:
            return False
        event.set()
        db.update_scan_run_progress(run_id, cancel_requested=True)
        jobs.cancel(f"scan:{run_id}")
        return True


def run_due_schedules() -> list[int]:
    started = []
    current = db.now()
    for schedule in db.due_scan_schedules(current):
        run_id = run_async(
            schedule["target"],
            schedule["ports"],
            check_vulns=bool(schedule["check_vulns"]),
            profile_key=schedule["profile_key"] or "custom",
        )
        started.append(run_id)
        next_run = _next_run_ts(int(schedule["interval_hours"] or 24))
        db.update_scan_schedule(int(schedule["id"]), last_run_ts=current, next_run_ts=next_run)
    return started


def _next_run_ts(interval_hours: int) -> str:
    ts = datetime.now(timezone.utc) + timedelta(hours=max(1, interval_hours))
    return ts.strftime("%Y-%m-%d %H:%M:%S")

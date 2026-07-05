"""Application settings: scanner/recon engines and proxy configuration."""
from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import threading
from pathlib import Path

import flet as ft

from ...core import config, db, net
from ...modules.analysis import source_quality
from ...modules.honeypot import personas
from ...modules.scanner import nikto
from ...modules.scanner.vuln import correlation, sync
from .. import theme as ui


def _tool_status() -> ft.Control:
    nmap = "available" if shutil.which("nmap") else "not found"
    nikto_status = nikto.status(config.load().get("scanner", {}).get("nikto_path", ""))
    tshark = ("available" if shutil.which("tshark") else "not found") + " (WIP)"
    httpx = _package_status("httpx")
    scapy = _package_status("scapy")
    pyshark = _package_status("pyshark")
    pyshark_runtime = (
        "ready for future capture features"
        if shutil.which("tshark") and _active_package_available("pyshark")
        else "WIP; needs active PyShark + TShark for future capture features"
    )
    return ft.Container(
        padding=12,
        border_radius=8,
        bgcolor=ui.PANEL,
        border=ui.border(),
        content=ft.Column(
            [
                ft.Text("Optional tool status", size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                ft.Text(f"Active Python: {sys.executable}", size=10, color=ui.MUTED, selectable=True),
                ft.Text(f"Nmap: {nmap}", size=11, color=ui.MUTED),
                ft.Text(f"Nikto: {nikto_status} (optional web audit engine; disabled by default)", size=11, color=ui.MUTED),
                ft.Text(f"TShark/Wireshark CLI: {tshark}", size=11, color=ui.MUTED),
                ft.Text(f"httpx: {httpx}", size=11, color=ui.MUTED),
                ft.Text(f"Scapy: {scapy}", size=11, color=ui.MUTED),
                ft.Text(f"PyShark: {pyshark} ({pyshark_runtime})", size=11, color=ui.MUTED),
            ],
            spacing=4,
        ),
    )


def _active_package_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _venv_package_available(name: str) -> bool:
    root = config.ROOT / ".venv"
    candidates = [
        root / "Lib" / "site-packages",
        root / "lib",
    ]
    normalized = name.replace("-", "_").lower()
    for base in candidates:
        if not base.exists():
            continue
        if base.name == "lib":
            site_roots = list(base.glob("python*/site-packages"))
        else:
            site_roots = [base]
        for site in site_roots:
            if (site / normalized).exists() or any(site.glob(f"{normalized}-*.dist-info")):
                return True
    return False


def _package_status(name: str) -> str:
    active = _active_package_available(name)
    venv = _venv_package_available(name)
    if active:
        return "available in active Python"
    if venv:
        return "installed in .venv, not active Python"
    return "not installed"


def _vulnerability_import_help_panel() -> ft.Control:
    controls: list[ft.Control] = [
        ft.Text("Accepted Vulnerability Feed Shapes", size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT)
    ]
    for key, meta in sync.import_format_help().items():
        rows = meta.get("accepted_rows", [])
        minimum = meta.get("minimum_fields", [])
        controls.extend(
            [
                ft.Text(str(meta.get("label") or key), size=12, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                ft.Text(f"Path: {meta.get('path', '-')}", size=10, color=ui.MUTED, selectable=True),
                ft.Text("Minimum: " + ", ".join(str(item) for item in minimum), size=10, color=ui.MUTED, selectable=True),
                ft.Text("Examples: " + " | ".join(str(item) for item in rows[:2]), size=10, color=ui.MUTED, selectable=True),
            ]
        )
    return ft.Container(
        padding=12,
        border_radius=8,
        bgcolor=ui.PANEL_2,
        border=ui.border(),
        content=ft.Column(controls, spacing=5),
    )


def _source_status_panel() -> ft.Control:
    try:
        sources = source_quality.vulnerability_source_scores(max_age_hours=48)
        counts = db.vulnerability_record_counts()
    except Exception as exc:
        return ui.panel(
            ft.Text(f"Vulnerability source status unavailable: {exc}", size=11, color=ui.WARN, selectable=True),
            padding=12,
        )
    rows: list[ft.Control] = [
        ft.Text("Vulnerability sources", size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT),
    ]
    if not sources:
        rows.append(ft.Text("No sources initialized yet.", size=11, color=ui.MUTED))
    for source in sources:
        rows.append(
            ft.Container(
                padding=8,
                border_radius=8,
                bgcolor=ui.PANEL_2,
                border=ui.border(),
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Text(source["name"], size=12, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                                ft.Text(source["status"] or "-", size=11, color=ui.ACCENT if source["last_success_ts"] else ui.WARN),
                            ],
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        ),
                        ft.Text(
                            f"Records: {source['record_count']}  Last success: {source['last_success_ts'] or '-'}",
                            size=10,
                            color=ui.WARN if source.get("stale") else ui.MUTED,
                        ),
                        ft.Text(
                            f"Enabled: {'yes' if source['enabled'] else 'no'}  "
                            f"Progress: {float(source['sync_progress'] or 0) * 100:.0f}%  "
                            f"Attempts: {source['sync_attempts'] or 0}  "
                            f"Next retry: {source['next_retry_ts'] or '-'}",
                            size=10,
                            color=ui.MUTED,
                            selectable=True,
                        ),
                        ft.Text(
                            "Freshness: "
                            + ("never synced" if source.get("age_hours") is None else f"{source['age_hours']:.1f} hours old")
                            + (" (stale)" if source.get("stale") else ""),
                            size=10,
                            color=ui.WARN if source.get("stale") else ui.MUTED,
                        ),
                        ft.Text(
                            f"Quality: {float(source.get('quality_score', 0)):.2f}  "
                            f"Reasons: {', '.join(source.get('quality_reasons') or [])}",
                            size=10,
                            color=ui.MUTED,
                            selectable=True,
                        ),
                        ft.Text(
                            f"Version: {source['source_version'] or '-'}  Error: {source['last_error'] or '-'}",
                            size=10,
                            color=ui.MUTED,
                            selectable=True,
                        ),
                    ],
                    spacing=3,
                ),
            )
        )
    rows.append(
        ft.Text(
            "Local cache counts: "
            + ", ".join(f"{key}={value}" for key, value in sorted(counts.items())),
            size=10,
            color=ui.MUTED,
            selectable=True,
        )
    )
    return ui.panel(ft.Column(rows, spacing=8), padding=12)


def _cycle_button(label: str, values: list[str], state: dict, key: str, width: int = 160, on_change=None) -> ft.Control:
    def _click(e):
        current = state[key]
        idx = values.index(current) if current in values else 0
        state[key] = values[(idx + 1) % len(values)]
        e.control.content.controls[1].value = state[key]
        if on_change:
            on_change(state[key])
        e.control.update()

    def _hover(e):
        e.control.bgcolor = "#3b2f72" if e.data == "true" else ui.PANEL_SELECTED
        e.control.scale = 1.018 if e.data == "true" else 1
        e.control.shadow = ui.SHADOW_SOFT if e.data == "true" else None
        e.control.update()

    return ft.Container(
        width=width,
        height=42,
        padding=ft.Padding(left=12, top=0, right=12, bottom=0),
        border_radius=8,
        bgcolor=ui.PANEL_SELECTED,
        border=ui.border(ui.ACCENT),
        animate=ui.MOTION_FAST,
        animate_scale=ui.MOTION_FAST,
        ink=True,
        ink_color="#6d28d99f",
        on_hover=_hover,
        on_click=_click,
        content=ft.Row(
            [
                ft.Text(label, size=12, color=ui.MUTED),
                ft.Text(state[key], size=13, weight=ft.FontWeight.BOLD, color=ui.TEXT),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        ),
    )


def render(page: ft.Page) -> ft.Control:
    cfg = config.load()
    scanner = cfg["scanner"]
    recon = cfg["recon"]
    honeypot = cfg["honeypot"]
    network = cfg["network"]
    retention = cfg.get("retention", {})
    state = {
        "use_proxy": "on" if network.get("use_proxy") else "off",
        "engine": scanner.get("engine", "auto"),
        "nikto_enabled": "on" if scanner.get("nikto_enabled", False) else "off",
        "host_probe": scanner.get("host_probe", "auto"),
        "udp_light_enabled": "on" if scanner.get("udp_light_enabled", False) else "off",
        "vulnerability_check_default": "on" if scanner.get("vulnerability_check_default", False) else "off",
        "seed_demo_cache_on_scan": "on" if scanner.get("seed_demo_cache_on_scan", True) else "off",
        "include_unknown_version_candidates": "on" if scanner.get("include_unknown_version_candidates", False) else "off",
        "block_public_targets": "on" if scanner.get("block_public_targets", True) else "off",
        "block_private_targets": "on" if scanner.get("block_private_targets", False) else "off",
        "http_client": recon.get("http_client", "auto"),
        "safe_endpoint_checks": "on" if recon.get("safe_endpoint_checks", True) else "off",
        "wordlist_enabled": "on" if recon.get("wordlist_enabled") else "off",
        "src_crtsh": "on" if "crtsh" in recon.get("subdomain_sources", []) else "off",
        "src_hackertarget": "on" if "hackertarget" in recon.get("subdomain_sources", []) else "off",
        "src_dnsdumpster": "on" if "dnsdumpster" in recon.get("subdomain_sources", []) else "off",
        "persona": honeypot.get("persona", "apache_ubuntu"),
        "alert_sound_enabled": "on" if honeypot.get("alert_sound_enabled", True) else "off",
        "http_login_enabled": "on" if honeypot.get("http_login_enabled", True) else "off",
        "geoip_enabled": "on" if honeypot.get("geoip_enabled", False) else "off",
        "proxy_scheme": net.normalize_proxy_scheme(network.get("proxy_scheme", "http")),
    }

    default_ports = ft.TextField(label="Default scanner ports", value=scanner["default_ports"], width=620, dense=True, **ui.input_kwargs())
    nmap_extra_flags = ft.TextField(
        label="Nmap extra flags",
        hint_text="Example: -T3 --top-ports 1000 --reason",
        value=scanner.get("nmap_extra_flags", ""),
        width=620,
        dense=True,
        **ui.input_kwargs(),
    )
    nmap_hint = ft.Text(
        "Applied only when engine is auto/nmap. SentinelForge filters conflicting -o*, -p, and input-file flags.",
        size=10,
        color=ui.MUTED,
        selectable=True,
    )
    nikto_path = ft.TextField(
        label="Nikto path",
        hint_text="Optional: nikto executable or nikto.pl; tools/nikto/program/nikto.pl is auto-detected",
        value=scanner.get("nikto_path", ""),
        width=620,
        dense=True,
        **ui.input_kwargs(),
    )
    nikto_timeout = ft.TextField(
        label="Nikto timeout seconds",
        value=str(scanner.get("nikto_timeout_sec", 120)),
        width=190,
        dense=True,
        **ui.input_kwargs(),
    )
    nikto_tuning = ft.TextField(
        label="Nikto tuning",
        hint_text="Optional Nikto -Tuning value",
        value=scanner.get("nikto_tuning", ""),
        width=220,
        dense=True,
        **ui.input_kwargs(),
    )
    nikto_max_findings = ft.TextField(
        label="Nikto max findings",
        value=str(scanner.get("nikto_max_findings", 25)),
        width=190,
        dense=True,
        **ui.input_kwargs(),
    )
    nikto_hint = ft.Text(
        "Nikto runs only after a web service is found. Results are imported as low-confidence web-audit evidence.",
        size=10,
        color=ui.MUTED,
        selectable=True,
    )
    timeout = ft.TextField(label="Scanner timeout seconds", value=str(scanner["timeout_sec"]), width=190, dense=True, **ui.input_kwargs())
    target_allowlist = ft.TextField(
        label="Scanner target allowlist, comma-separated wildcards",
        value=", ".join(scanner.get("target_allowlist", [])),
        width=620,
        dense=True,
        **ui.input_kwargs(),
    )
    scope_file_path = ft.TextField(
        label="Scope file path",
        value=scanner.get("scope_file_path", ""),
        width=620,
        dense=True,
        **ui.input_kwargs(),
    )
    max_threads = ft.TextField(label="Scanner max threads", value=str(scanner["max_threads"]), width=190, dense=True, **ui.input_kwargs())
    low_rate_max_threads = ft.TextField(
        label="Low-rate max threads",
        value=str(scanner.get("low_rate_max_threads", 25)),
        width=190,
        dense=True,
        **ui.input_kwargs(),
    )
    min_candidate_conf = ft.TextField(
        label="Minimum candidate confidence",
        value=str(scanner.get("minimum_candidate_confidence", 0.35)),
        width=220,
        dense=True,
        **ui.input_kwargs(),
    )
    sync_interval = ft.TextField(
        label="Source sync interval hours",
        value=str(scanner.get("source_sync_interval_hours", 24)),
        width=220,
        dense=True,
        **ui.input_kwargs(),
    )
    max_vuln_matches = ft.TextField(
        label="Max matches per service",
        value=str(scanner.get("max_vulnerability_matches_per_service", 25)),
        width=210,
        dense=True,
        **ui.input_kwargs(),
    )
    nvd_json_path = ft.TextField(
        label="NVD JSON file/directory path (.json or .json.gz)",
        value=scanner.get("nvd_json_path", ""),
        width=620,
        dense=True,
        **ui.input_kwargs(),
    )
    cisa_kev_path = ft.TextField(
        label="CISA KEV JSON path",
        value=scanner.get("cisa_kev_path", ""),
        width=620,
        dense=True,
        **ui.input_kwargs(),
    )
    epss_csv_path = ft.TextField(
        label="FIRST EPSS CSV path",
        value=scanner.get("epss_csv_path", ""),
        width=620,
        dense=True,
        **ui.input_kwargs(),
    )
    exploitdb_csv_path = ft.TextField(
        label="Exploit-DB CSV path",
        value=scanner.get("exploitdb_csv_path", ""),
        width=620,
        dense=True,
        **ui.input_kwargs(),
    )
    vendor_advisory_json_path = ft.TextField(
        label="Vendor/distribution advisory JSON path",
        value=scanner.get("vendor_advisory_json_path", ""),
        width=620,
        dense=True,
        **ui.input_kwargs(),
    )
    resolvers = ft.TextField(label="DNS resolvers, comma-separated", value=", ".join(recon.get("resolvers", [])), width=420, dense=True, **ui.input_kwargs())
    user_agent = ft.TextField(label="Recon User-Agent", value=recon.get("user_agent", ""), width=620, dense=True, **ui.input_kwargs())
    wordlist_path = ft.TextField(label="Subdomain wordlist path", value=recon.get("wordlist_path", ""), width=620, dense=True, **ui.input_kwargs())
    wordlist_limit = ft.TextField(label="Wordlist max entries", value=str(recon.get("wordlist_limit", 2000)), width=190, dense=True, **ui.input_kwargs())
    source_timeout = ft.TextField(label="Recon source timeout seconds", value=str(recon.get("source_timeout_sec", 20)), width=230, dense=True, **ui.input_kwargs())
    endpoint_timeout = ft.TextField(label="Safe endpoint timeout seconds", value=str(recon.get("safe_endpoint_timeout_sec", 5)), width=230, dense=True, **ui.input_kwargs())
    export_dir = ft.TextField(label="Recon export directory", value=recon.get("export_dir", ""), width=620, dense=True, **ui.input_kwargs())
    html_path = ft.TextField(label="HTTP custom .html path", value=honeypot.get("http_html_path", ""), width=420, dense=True, **ui.input_kwargs())
    cert_path = ft.TextField(label="TLS certificate path", value=honeypot.get("http_tls_cert_path", ""), width=420, dense=True, **ui.input_kwargs())
    key_path = ft.TextField(label="TLS private key path", value=honeypot.get("http_tls_key_path", ""), width=420, dense=True, **ui.input_kwargs())
    server_header = ft.TextField(label="HTTP Server header", value=honeypot.get("http_server_header", ""), width=420, dense=True, **ui.input_kwargs())
    http_status = ft.TextField(label="HTTP status", value=honeypot.get("http_status", "200 OK"), width=190, dense=True, **ui.input_kwargs())
    http_content_type = ft.TextField(label="HTTP Content-Type", value=honeypot.get("http_content_type", "text/html; charset=utf-8"), width=270, dense=True, **ui.input_kwargs())
    http_extra_headers = ft.TextField(
        label="HTTP extra headers JSON",
        value=json.dumps(honeypot.get("http_extra_headers", {}), ensure_ascii=False),
        width=620,
        dense=True,
        **ui.input_kwargs(),
    )
    http_body = ft.TextField(
        label="Persona HTTP body",
        value=honeypot.get("http_body", ""),
        width=620,
        multiline=True,
        min_lines=3,
        max_lines=6,
        dense=True,
        **ui.input_kwargs(),
    )
    ssh_banner = ft.TextField(label="SSH banner", value=honeypot.get("ssh_banner", ""), width=420, dense=True, **ui.input_kwargs())
    ftp_banner = ft.TextField(label="FTP banner", value=honeypot.get("ftp_banner", ""), width=420, dense=True, **ui.input_kwargs())
    ftp_user = ft.TextField(label="FTP USER reply", value=honeypot.get("ftp_user_reply", ""), width=420, dense=True, **ui.input_kwargs())
    ftp_pass = ft.TextField(label="FTP PASS reply", value=honeypot.get("ftp_pass_reply", ""), width=420, dense=True, **ui.input_kwargs())
    telnet_banner = ft.TextField(label="Telnet banner", value=honeypot.get("telnet_banner", ""), width=420, dense=True, **ui.input_kwargs())
    telnet_fail = ft.TextField(label="Telnet failure reply", value=honeypot.get("telnet_fail_reply", ""), width=420, dense=True, **ui.input_kwargs())
    smtp_banner = ft.TextField(label="SMTP banner", value=honeypot.get("smtp_banner", ""), width=420, dense=True, **ui.input_kwargs())
    smtp_relay = ft.TextField(label="SMTP relay denied reply", value=honeypot.get("smtp_relay_denied", ""), width=420, dense=True, **ui.input_kwargs())
    login_paths = ft.TextField(
        label="HTTP fake login paths, comma-separated",
        value=", ".join(honeypot.get("http_login_paths", [])),
        width=620,
        dense=True,
        **ui.input_kwargs(),
    )
    login_html_path = ft.TextField(
        label="Fake login form .html path",
        value=honeypot.get("http_login_html_path", ""),
        width=620,
        dense=True,
        **ui.input_kwargs(),
    )
    http_routes = ft.TextField(
        label="Extra HTTP routes JSON (route supports path,status,content_type,body,html_path,headers)",
        value=json.dumps(honeypot.get("http_routes", []), ensure_ascii=False),
        width=620,
        multiline=True,
        min_lines=3,
        max_lines=6,
        dense=True,
        **ui.input_kwargs(),
    )
    geoip_path = ft.TextField(
        label="Local GeoIP/ASN DB path (JSON/CSV with cidr,country,asn,org)",
        value=honeypot.get("geoip_db_path", ""),
        width=620,
        dense=True,
        **ui.input_kwargs(),
    )
    alert_sound_path = ft.TextField(
        label="Honeypot alert sound path",
        value=honeypot.get("alert_sound_path", ""),
        width=620,
        dense=True,
        **ui.input_kwargs(),
    )
    http_proxy = ft.TextField(label="HTTP proxy", value=network.get("http_proxy", ""), width=420, dense=True, **ui.input_kwargs())
    https_proxy = ft.TextField(label="HTTPS proxy", value=network.get("https_proxy", ""), width=420, dense=True, **ui.input_kwargs())
    proxy_list_path = ft.TextField(label="Proxy list .txt path", value=network.get("proxy_list_path", ""), width=620, dense=True, **ui.input_kwargs())
    no_proxy = ft.TextField(label="No proxy hosts", value=network.get("no_proxy", ""), width=420, dense=True, **ui.input_kwargs())
    honeypot_max_events = ft.TextField(label="Keep honeypot events", value=str(retention.get("honeypot_max_events", 50000)), width=210, dense=True, **ui.input_kwargs())
    scan_history_max_runs = ft.TextField(label="Keep scan runs", value=str(retention.get("scan_history_max_runs", 5000)), width=190, dense=True, **ui.input_kwargs())
    cleanup_status = ft.Text("", size=11, color=ui.MUTED, selectable=True)
    persona_select = ft.Dropdown(
        label="Honeypot persona",
        value=state["persona"] if state["persona"] in personas.PRESETS else "apache_ubuntu",
        width=300,
        dense=True,
        options=[ft.dropdown.Option(key=key, text=label) for key, label in personas.preset_options()],
        **ui.dropdown_kwargs(),
    )
    persona_summary = ft.Text(size=11, color=ui.MUTED, selectable=True)
    source_mount = ft.Column([_source_status_panel()])
    sync_status = ft.Text("", size=11, color=ui.MUTED, selectable=True)
    sync_state = {"running": False}

    def _refresh_engine_settings(_value: str | None = None) -> None:
        show_nmap = state.get("engine") in {"auto", "nmap"}
        nmap_extra_flags.visible = show_nmap
        nmap_hint.visible = show_nmap
        show_nikto = state.get("nikto_enabled") == "on"
        nikto_path.visible = show_nikto
        nikto_timeout.visible = show_nikto
        nikto_tuning.visible = show_nikto
        nikto_max_findings.visible = show_nikto
        nikto_hint.visible = show_nikto
        try:
            page.update()
        except Exception:
            pass

    _refresh_engine_settings(state["engine"])

    def _fill_persona_fields(key: str) -> None:
        preset = personas.get_preset(key)
        state["persona"] = key
        server_header.value = preset["http_server_header"]
        http_status.value = preset["http_status"]
        http_content_type.value = preset["http_content_type"]
        http_extra_headers.value = json.dumps(preset["http_extra_headers"], ensure_ascii=False)
        http_body.value = preset["http_body"]
        ssh_banner.value = preset["ssh_banner"]
        ftp_banner.value = preset["ftp_banner"]
        ftp_user.value = preset["ftp_user_reply"]
        ftp_pass.value = preset["ftp_pass_reply"]
        telnet_banner.value = preset["telnet_banner"]
        telnet_fail.value = preset["telnet_fail_reply"]
        smtp_banner.value = preset["smtp_banner"]
        smtp_relay.value = preset["smtp_relay_denied"]
        persona_summary.value = f"{preset['label']}: {preset['summary']}"

    def _persona_selected(e) -> None:
        _fill_persona_fields(e.control.value or "apache_ubuntu")
        page.update()

    persona_select.on_select = _persona_selected
    if state["persona"] in personas.PRESETS:
        preset = personas.PRESETS[state["persona"]]
        persona_summary.value = f"{preset['label']}: {preset['summary']}"

    def _save(_):
        try:
            next_cfg = config.load()
            next_cfg["scanner"]["default_ports"] = (default_ports.value or "").strip()
            next_cfg["scanner"]["timeout_sec"] = float(timeout.value or "1.5")
            next_cfg["scanner"]["max_threads"] = int(max_threads.value or "200")
            next_cfg["scanner"]["low_rate_max_threads"] = int(low_rate_max_threads.value or "25")
            next_cfg["scanner"]["engine"] = state["engine"]
            next_cfg["scanner"]["nmap_extra_flags"] = (nmap_extra_flags.value or "").strip()
            next_cfg["scanner"]["nikto_enabled"] = state["nikto_enabled"] == "on"
            next_cfg["scanner"]["nikto_path"] = (nikto_path.value or "").strip()
            next_cfg["scanner"]["nikto_timeout_sec"] = int(nikto_timeout.value or "120")
            next_cfg["scanner"]["nikto_tuning"] = (nikto_tuning.value or "").strip()
            next_cfg["scanner"]["nikto_max_findings"] = int(nikto_max_findings.value or "25")
            next_cfg["scanner"]["host_probe"] = state["host_probe"]
            next_cfg["scanner"]["udp_light_enabled"] = state["udp_light_enabled"] == "on"
            next_cfg["scanner"]["vulnerability_check_default"] = state["vulnerability_check_default"] == "on"
            next_cfg["scanner"]["seed_demo_cache_on_scan"] = state["seed_demo_cache_on_scan"] == "on"
            next_cfg["scanner"]["include_unknown_version_candidates"] = state["include_unknown_version_candidates"] == "on"
            next_cfg["scanner"]["target_allowlist"] = [item.strip() for item in (target_allowlist.value or "").split(",") if item.strip()]
            next_cfg["scanner"]["scope_file_path"] = (scope_file_path.value or "").strip()
            next_cfg["scanner"]["block_public_targets"] = state["block_public_targets"] == "on"
            next_cfg["scanner"]["block_private_targets"] = state["block_private_targets"] == "on"
            next_cfg["scanner"]["minimum_candidate_confidence"] = float(min_candidate_conf.value or "0.35")
            next_cfg["scanner"]["max_vulnerability_matches_per_service"] = int(max_vuln_matches.value or "25")
            next_cfg["scanner"]["source_sync_interval_hours"] = int(sync_interval.value or "24")
            next_cfg["scanner"]["nvd_json_path"] = (nvd_json_path.value or "").strip()
            next_cfg["scanner"]["cisa_kev_path"] = (cisa_kev_path.value or "").strip()
            next_cfg["scanner"]["epss_csv_path"] = (epss_csv_path.value or "").strip()
            next_cfg["scanner"]["exploitdb_csv_path"] = (exploitdb_csv_path.value or "").strip()
            next_cfg["scanner"]["vendor_advisory_json_path"] = (vendor_advisory_json_path.value or "").strip()
            next_cfg["recon"]["resolvers"] = [
                item.strip() for item in (resolvers.value or "").split(",") if item.strip()
            ]
            next_cfg["recon"]["user_agent"] = (user_agent.value or "").strip() or "SentinelForge-Recon/0.1"
            next_cfg["recon"]["http_client"] = state["http_client"]
            next_cfg["recon"]["subdomain_sources"] = [
                name
                for name, key in (
                    ("crtsh", "src_crtsh"),
                    ("hackertarget", "src_hackertarget"),
                    ("dnsdumpster", "src_dnsdumpster"),
                )
                if state[key] == "on"
            ]
            next_cfg["recon"]["wordlist_enabled"] = state["wordlist_enabled"] == "on"
            next_cfg["recon"]["safe_endpoint_checks"] = state["safe_endpoint_checks"] == "on"
            next_cfg["recon"]["source_timeout_sec"] = float(source_timeout.value or "20")
            next_cfg["recon"]["safe_endpoint_timeout_sec"] = float(endpoint_timeout.value or "5")
            next_cfg["recon"]["wordlist_path"] = (wordlist_path.value or "").strip()
            next_cfg["recon"]["wordlist_limit"] = int(wordlist_limit.value or "2000")
            next_cfg["recon"]["export_dir"] = (export_dir.value or "").strip()
            hp = next_cfg["honeypot"]
            hp["persona"] = state["persona"] if state["persona"] in personas.PRESETS else "custom"
            hp["persona_tags"] = personas.PRESETS.get(state["persona"], {}).get("tags", [])
            hp["http_html_path"] = (html_path.value or "").strip()
            hp["http_tls_cert_path"] = (cert_path.value or "").strip()
            hp["http_tls_key_path"] = (key_path.value or "").strip()
            hp["http_server_header"] = (server_header.value or "").strip() or "Apache/2.4.52 (Ubuntu)"
            hp["http_status"] = (http_status.value or "").strip() or "200 OK"
            hp["http_content_type"] = (http_content_type.value or "").strip() or "text/html; charset=utf-8"
            try:
                extra_headers = json.loads(http_extra_headers.value or "{}")
            except json.JSONDecodeError as exc:
                raise ValueError(f"HTTP extra headers must be valid JSON: {exc}") from exc
            if not isinstance(extra_headers, dict):
                raise ValueError("HTTP extra headers must be a JSON object")
            hp["http_extra_headers"] = extra_headers
            hp["http_body"] = http_body.value or ""
            hp["ssh_banner"] = (ssh_banner.value or "").strip() or "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
            hp["ftp_banner"] = (ftp_banner.value or "").strip() or "220 (vsFTPd 3.0.5)"
            hp["ftp_user_reply"] = (ftp_user.value or "").strip() or "331 Please specify the password."
            hp["ftp_pass_reply"] = (ftp_pass.value or "").strip() or "530 Login incorrect."
            hp["telnet_banner"] = (telnet_banner.value or "").strip() or "Ubuntu 22.04 LTS"
            hp["telnet_fail_reply"] = (telnet_fail.value or "").strip() or "Login incorrect"
            hp["smtp_banner"] = (smtp_banner.value or "").strip() or "220 mail.local ESMTP Postfix"
            hp["smtp_relay_denied"] = (smtp_relay.value or "").strip() or "554 5.7.1 Relay access denied"
            hp["http_login_enabled"] = state["http_login_enabled"] == "on"
            hp["http_login_paths"] = [p.strip() for p in (login_paths.value or "").split(",") if p.strip()]
            hp["http_login_html_path"] = (login_html_path.value or "").strip()
            try:
                routes = json.loads(http_routes.value or "[]")
            except json.JSONDecodeError as exc:
                raise ValueError(f"Extra HTTP routes must be valid JSON: {exc}") from exc
            if not isinstance(routes, list):
                raise ValueError("Extra HTTP routes must be a JSON array")
            hp["http_routes"] = routes
            hp["geoip_enabled"] = state["geoip_enabled"] == "on"
            hp["geoip_db_path"] = (geoip_path.value or "").strip()
            hp["alert_sound_enabled"] = state["alert_sound_enabled"] == "on"
            hp["alert_sound_path"] = (alert_sound_path.value or "").strip()
            next_cfg["network"]["use_proxy"] = state["use_proxy"] == "on"
            next_cfg["network"]["http_proxy"] = (http_proxy.value or "").strip()
            next_cfg["network"]["https_proxy"] = (https_proxy.value or "").strip()
            next_cfg["network"]["proxy_list_path"] = (proxy_list_path.value or "").strip()
            next_cfg["network"]["proxy_scheme"] = net.normalize_proxy_scheme(state["proxy_scheme"])
            next_cfg["network"]["no_proxy"] = (no_proxy.value or "").strip()
            next_cfg.setdefault("retention", {})
            next_cfg["retention"]["honeypot_max_events"] = int(honeypot_max_events.value or "50000")
            next_cfg["retention"]["scan_history_max_runs"] = int(scan_history_max_runs.value or "5000")
            if next_cfg["scanner"]["timeout_sec"] <= 0:
                raise ValueError("Scanner timeout must be positive")
            if next_cfg["scanner"]["max_threads"] < 1:
                raise ValueError("Scanner max threads must be at least 1")
            if next_cfg["scanner"]["low_rate_max_threads"] < 1:
                raise ValueError("Low-rate max threads must be at least 1")
            if next_cfg["scanner"]["nikto_timeout_sec"] < 10:
                raise ValueError("Nikto timeout must be at least 10 seconds")
            if next_cfg["scanner"]["nikto_max_findings"] < 1:
                raise ValueError("Nikto max findings must be at least 1")
            if not 0 <= next_cfg["scanner"]["minimum_candidate_confidence"] <= 1:
                raise ValueError("Minimum candidate confidence must be between 0 and 1")
            if next_cfg["scanner"]["source_sync_interval_hours"] < 1:
                raise ValueError("Source sync interval must be at least 1 hour")
            if next_cfg["scanner"]["max_vulnerability_matches_per_service"] < 1:
                raise ValueError("Max matches per service must be at least 1")
            if next_cfg["recon"]["wordlist_limit"] < 1:
                raise ValueError("Wordlist max entries must be at least 1")
            if next_cfg["recon"]["source_timeout_sec"] <= 0:
                raise ValueError("Recon source timeout must be positive")
            if next_cfg["recon"]["safe_endpoint_timeout_sec"] <= 0:
                raise ValueError("Safe endpoint timeout must be positive")
            if next_cfg["retention"]["honeypot_max_events"] < 0 or next_cfg["retention"]["scan_history_max_runs"] < 0:
                raise ValueError("Retention values must be zero or positive")
            config.save(next_cfg)
        except ValueError as exc:
            ui.notify(page, str(exc))
            return
        ui.notify(page, "Settings saved")

    def _run_cleanup(_):
        try:
            next_cfg = config.load()
            next_cfg.setdefault("retention", {})
            next_cfg["retention"]["honeypot_max_events"] = int(honeypot_max_events.value or "50000")
            next_cfg["retention"]["scan_history_max_runs"] = int(scan_history_max_runs.value or "5000")
            config.save(next_cfg)
            removed = db.apply_retention()
            cleanup_status.value = "Cleanup removed: " + ", ".join(f"{k}={v}" for k, v in sorted(removed.items()))
            page.update()
        except Exception as exc:
            ui.notify(page, f"Cleanup failed: {exc}")

    def _refresh_vuln_cache(_):
        try:
            correlation.seed_demo_cache()
            source_mount.controls = [_source_status_panel()]
            ui.notify(page, "Vulnerability cache refreshed")
            page.update()
        except Exception as exc:
            ui.notify(page, f"Vulnerability cache refresh failed: {exc}")

    def _sync_sources(_):
        if sync_state["running"]:
            ui.notify(page, "Source sync is already running")
            return
        nvd_path_value = (nvd_json_path.value or "").strip()
        kev_path_value = (cisa_kev_path.value or "").strip()
        epss_path_value = (epss_csv_path.value or "").strip()
        exploitdb_path_value = (exploitdb_csv_path.value or "").strip()
        vendor_advisory_path_value = (vendor_advisory_json_path.value or "").strip()
        sync_state["running"] = True
        sync_status.value = "Source sync running in background..."
        try:
            page.update()
        except Exception:
            pass

        def _worker() -> None:
            try:
                next_cfg = config.load()
                next_cfg["scanner"]["nvd_json_path"] = nvd_path_value
                next_cfg["scanner"]["cisa_kev_path"] = kev_path_value
                next_cfg["scanner"]["epss_csv_path"] = epss_path_value
                next_cfg["scanner"]["exploitdb_csv_path"] = exploitdb_path_value
                next_cfg["scanner"]["vendor_advisory_json_path"] = vendor_advisory_path_value
                config.save(next_cfg)
                counts = sync.sync_configured_sources()
                sync_status.value = "Synced sources: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
            except Exception as exc:
                sync_status.value = f"Source sync failed: {exc}"
            finally:
                sync_state["running"] = False
                source_mount.controls = [_source_status_panel()]
                try:
                    page.update()
                except Exception:
                    pass

        threading.Thread(target=_worker, daemon=True).start()

    return ft.Column(
        [
            ft.Text("Settings", size=18, weight=ft.FontWeight.BOLD, color=ui.TEXT),
            ft.Container(
                padding=14,
                border_radius=8,
                bgcolor=ui.PANEL,
                border=ui.border(),
                content=ft.Column(
                    [
                        ft.Text("Scanner", size=15, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                        ft.Row(
                            [
                                _cycle_button("Engine", ["auto", "socket", "nmap"], state, "engine", on_change=_refresh_engine_settings),
                                _cycle_button("Nikto", ["off", "on"], state, "nikto_enabled", width=140, on_change=_refresh_engine_settings),
                                _cycle_button("Host probe", ["auto", "off", "scapy", "tcp"], state, "host_probe", width=180),
                                timeout,
                                max_threads,
                                low_rate_max_threads,
                            ],
                            spacing=10,
                            wrap=True,
                        ),
                        nmap_extra_flags,
                        nmap_hint,
                        ft.Row([nikto_timeout, nikto_tuning, nikto_max_findings], spacing=10, wrap=True),
                        nikto_path,
                        nikto_hint,
                        default_ports,
                        ft.Text("Scan scope", size=13, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                        ft.Row(
                            [
                                _cycle_button("Block public", ["on", "off"], state, "block_public_targets", width=170),
                                _cycle_button("Block private", ["off", "on"], state, "block_private_targets", width=170),
                            ],
                            spacing=10,
                            wrap=True,
                        ),
                        target_allowlist,
                        scope_file_path,
                        ft.Divider(color=ui.BORDER),
                        ft.Text("CVE exposure assessment", size=13, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                        ft.Row(
                            [
                                _cycle_button("Default CVE mode", ["off", "on"], state, "vulnerability_check_default", width=190),
                                _cycle_button("UDP light", ["off", "on"], state, "udp_light_enabled", width=150),
                                _cycle_button("Seed demo cache", ["on", "off"], state, "seed_demo_cache_on_scan", width=180),
                                _cycle_button("Unknown versions", ["off", "on"], state, "include_unknown_version_candidates", width=190),
                                min_candidate_conf,
                                max_vuln_matches,
                                sync_interval,
                            ],
                            spacing=10,
                            wrap=True,
                        ),
                        ft.Row(
                            [
                                ui.action_button("Refresh vulnerability cache", "REFRESH", _refresh_vuln_cache, width=190),
                                ui.action_button("Sync configured sources", "SYNC", _sync_sources, width=170),
                                ft.Text(
                                    "Current source sync is offline/local. External NVD/KEV/EPSS import can be added on top of this cache.",
                                    size=11,
                                    color=ui.MUTED,
                                ),
                            ],
                            spacing=10,
                            wrap=True,
                        ),
                        sync_status,
                        nvd_json_path,
                        cisa_kev_path,
                        epss_csv_path,
                        exploitdb_csv_path,
                        vendor_advisory_json_path,
                        _vulnerability_import_help_panel(),
                        source_mount,
                    ],
                    spacing=10,
                ),
            ),
            ft.Container(
                padding=14,
                border_radius=8,
                bgcolor=ui.PANEL,
                border=ui.border(),
                content=ft.Column(
                    [
                        ft.Text("Recon", size=15, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                        ft.Row([_cycle_button("HTTP client", ["auto", "urllib", "httpx"], state, "http_client"), resolvers], spacing=10),
                        ft.Row(
                            [
                                _cycle_button("crt.sh", ["on", "off"], state, "src_crtsh", width=120),
                                _cycle_button("HackerTarget", ["on", "off"], state, "src_hackertarget", width=160),
                                _cycle_button("DNSDumpster", ["on", "off"], state, "src_dnsdumpster", width=160),
                                _cycle_button("Wordlist", ["off", "on"], state, "wordlist_enabled", width=140),
                                _cycle_button("Safe endpoints", ["on", "off"], state, "safe_endpoint_checks", width=180),
                                wordlist_limit,
                                source_timeout,
                                endpoint_timeout,
                            ],
                            spacing=10,
                            wrap=True,
                        ),
                        wordlist_path,
                        export_dir,
                        user_agent,
                    ],
                    spacing=10,
                ),
            ),
            ft.Container(
                padding=14,
                border_radius=8,
                bgcolor=ui.PANEL,
                border=ui.border(),
                content=ft.Column(
                    [
                        ft.Text("Advanced honeypot", size=15, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                        ft.Row([persona_select, ft.Text("Presets fill the fields below; edit after selecting if needed.", size=11, color=ui.MUTED)], spacing=10),
                        persona_summary,
                        ft.Row([html_path, server_header], spacing=10),
                        ft.Row([http_status, http_content_type], spacing=10),
                        http_extra_headers,
                        http_body,
                        ft.Row(
                            [
                                _cycle_button("Fake logins", ["on", "off"], state, "http_login_enabled", width=160),
                                login_paths,
                            ],
                            spacing=10,
                        ),
                        login_html_path,
                        http_routes,
                        ft.Row([cert_path, key_path], spacing=10),
                        ft.Row([ssh_banner, ftp_banner], spacing=10),
                        ft.Row([ftp_user, ftp_pass], spacing=10),
                        ft.Row([telnet_banner, telnet_fail], spacing=10),
                        ft.Row([smtp_banner, smtp_relay], spacing=10),
                        ft.Row(
                            [
                                _cycle_button("GeoIP/ASN", ["off", "on"], state, "geoip_enabled", width=150),
                                geoip_path,
                            ],
                            spacing=10,
                        ),
                        ft.Row(
                            [
                                _cycle_button("Alert sound", ["on", "off"], state, "alert_sound_enabled", width=160),
                                alert_sound_path,
                            ],
                            spacing=10,
                        ),
                    ],
                    spacing=10,
                ),
            ),
            ft.Container(
                padding=14,
                border_radius=8,
                bgcolor=ui.PANEL,
                border=ui.border(),
                content=ft.Column(
                    [
                        ft.Text("Proxy", size=15, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                        _cycle_button("Proxy", ["off", "on"], state, "use_proxy", width=130),
                        ft.Row([http_proxy, https_proxy], spacing=10),
                        ft.Row([proxy_list_path, _cycle_button("Proxy scheme", ["http", "https", "socks4", "socks5"], state, "proxy_scheme", width=190)], spacing=10, wrap=True),
                        ft.Text("Proxy list format: ip:port or ip:port:login:password. List entries are used before single proxy fields.", size=11, color=ui.MUTED),
                        no_proxy,
                    ],
                    spacing=10,
                ),
            ),
            _tool_status(),
            ft.Container(
                padding=14,
                border_radius=8,
                bgcolor=ui.PANEL,
                border=ui.border(),
                content=ft.Column(
                    [
                        ft.Text("Retention", size=15, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                        ft.Row([honeypot_max_events, scan_history_max_runs, ui.action_button("Run cleanup", "CLEAN", _run_cleanup, width=130)], spacing=10, wrap=True),
                        cleanup_status,
                    ],
                    spacing=10,
                ),
            ),
            ui.action_button("Save settings", "SAVE", _save, width=150),
        ],
        expand=True,
        spacing=14,
        scroll=ft.ScrollMode.AUTO,
    )

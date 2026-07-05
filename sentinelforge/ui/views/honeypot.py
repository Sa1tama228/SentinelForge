"""Honeypot control panel: start/stop servers, live attack feed, stats."""
from __future__ import annotations

import json

import flet as ft

from ...core import config, db, events
from ...modules.analysis import honeypot_campaigns
from ...modules.honeypot import exporter
from ...modules.honeypot.server import manager as get_mgr
from .. import theme as ui

_KINDS = [
    ("http", "HTTP", "http_port", "HT"),
    ("ssh", "SSH", "ssh_port", "SH"),
    ("ftp", "FTP", "ftp_port", "FP"),
    ("telnet", "Telnet", "telnet_port", "TN"),
    ("smtp", "SMTP", "smtp_port", "SM"),
]

_NOISY_CLASSES = {"", "connection", "scanner"}
_LOG_LIMIT_COMPACT = 60
_LOG_LIMIT_DETAILED = 200


def _status_chip(running: bool) -> ft.Control:
    return ft.Container(
        padding=ft.Padding(left=10, top=4, right=10, bottom=4),
        border_radius=10,
        bgcolor=ui.PANEL_SELECTED if running else ui.PANEL_2,
        content=ft.Text(
            "RUNNING" if running else "STOPPED",
            size=10, color=ui.ACCENT if running else ui.MUTED,
            weight=ft.FontWeight.BOLD,
        ),
    )


def _kind_card(mgr, kind: str, label: str,
               port_key: str, icon: str, on_change) -> ft.Control:
    port = int(config.load()["honeypot"][port_key])
    status = mgr.status()[kind]
    running = status["running"]
    chip = _status_chip(running)
    btn = ui.action_button(
        "Stop" if running else "Start",
        "STOP" if running else "GO",
        lambda _: on_change(kind),
        accent=ui.DANGER if running else ui.ACCENT,
        width=96,
    )
    return ui.panel(
        width=220,
        height=132,
        padding=16,
        content=ft.Container(
            content=ft.Column(
                [
                    ft.Row([ui.badge(icon), ft.Text(label, size=18, weight=ft.FontWeight.BOLD, color=ui.TEXT)],
                           alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ft.Text(f"Bind {status.get('host', '0.0.0.0')}:{port}", size=12, color=ui.MUTED),
                    ft.Text(mgr.error(kind), size=10, color=ui.DANGER),
                    ft.Row([chip, btn], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ],
                spacing=6,
            ),
        ),
    )


def _json(value: str, default):
    try:
        return json.loads(value or "")
    except json.JSONDecodeError:
        return default


def _class_color(classification: str) -> str:
    return {
        "exploit-probe": ui.DANGER,
        "credential-attempt": ui.WARN,
        "mail-relay-probe": ui.WARN,
        "login-probe": ui.WARN,
        "write-probe": ui.WARN,
        "scanner": ui.INFO,
        "connection": ui.MUTED,
    }.get(classification or "connection", ui.MUTED)


def _short(value: str, limit: int = 96) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "..."


def _event_summary(row, iocs: dict, geo: dict) -> str:
    method = row["method"] or "connect"
    path = row["path"] or "-"
    bits = [f"{row['classification'] or 'connection'}", f"{method} {_short(path, 72)}"]
    if isinstance(iocs, dict):
        alerts = iocs.get("alerts") or []
        creds = iocs.get("credentials") or []
        cves = iocs.get("cves") or []
        urls = iocs.get("urls") or []
        if alerts:
            bits.append("alerts=" + ",".join(alerts[:3]))
        if creds:
            bits.append(f"credentials={len(creds)}")
        if cves:
            bits.append("cve=" + ",".join(cves[:2]))
        if urls:
            bits.append(f"urls={len(urls)}")
    if geo:
        bits.append(f"geo={geo.get('country', '-')}/{geo.get('asn', '-')}")
    return "  |  ".join(bits)


def _event_details(row, iocs: dict, geo: dict) -> str:
    detail = []
    if row["headers"]:
        detail.append(f"headers: {_short(row['headers'], 180)}")
    if row["body"]:
        detail.append(f"body: {_short(row['body'], 180)}")
    if isinstance(iocs, dict) and any(iocs.values()):
        compact_iocs = {
            key: value
            for key, value in iocs.items()
            if value and key not in {"severity"}
        }
        detail.append(f"iocs: {_short(json.dumps(compact_iocs, ensure_ascii=False), 220)}")
    if geo:
        detail.append(f"geo: {geo.get('country', '-')}/{geo.get('asn', '-')} {geo.get('org', '')}".strip())
    return "\n".join(detail)


def render(page: ft.Page) -> ft.Control:
    mgr = get_mgr()
    cfg = config.load()
    hp_cfg = cfg["honeypot"]

    cards_row = ft.Row(spacing=12, wrap=True, run_spacing=12)
    stats_text = ft.Text(size=12, color=ui.MUTED)
    class_text = ft.Text(size=12, color=ui.MUTED, selectable=True)
    credential_text = ft.Text(size=11, color=ui.MUTED, selectable=True)
    feed = ft.ListView(expand=True, spacing=6, auto_scroll=True)
    campaigns_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO)
    sessions_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO)
    search_in = ft.TextField(label="Search events", width=260, dense=True, **ui.input_kwargs())
    class_filter = ft.Dropdown(
        label="Class",
        width=210,
        dense=True,
        options=[ft.dropdown.Option(key="", text="All classes")],
        **ui.dropdown_kwargs(),
    )
    signal_only = ft.Checkbox(
        label="Signal only",
        value=True,
        fill_color=ui.PANEL_SELECTED,
        check_color=ui.ACCENT,
        label_style=ft.TextStyle(color=ui.MUTED, size=12),
    )
    show_details = ft.Checkbox(
        label="Details",
        value=False,
        fill_color=ui.PANEL_SELECTED,
        check_color=ui.ACCENT,
        label_style=ft.TextStyle(color=ui.MUTED, size=12),
    )
    type_filter = ft.Dropdown(
        label="Service",
        width=160,
        dense=True,
        options=[ft.dropdown.Option(key="", text="All services")] + [ft.dropdown.Option(key=k, text=label) for k, label, *_ in _KINDS],
        **ui.dropdown_kwargs(),
    )
    http_port = ft.TextField(label="HTTP/HTTPS port", value=str(hp_cfg["http_port"]), width=150, dense=True, **ui.input_kwargs())
    ssh_port = ft.TextField(label="SSH port", value=str(hp_cfg["ssh_port"]), width=150, dense=True, **ui.input_kwargs())
    ftp_port = ft.TextField(label="FTP port", value=str(hp_cfg["ftp_port"]), width=150, dense=True, **ui.input_kwargs())
    telnet_port = ft.TextField(label="Telnet port", value=str(hp_cfg["telnet_port"]), width=150, dense=True, **ui.input_kwargs())
    smtp_port = ft.TextField(label="SMTP port", value=str(hp_cfg["smtp_port"]), width=150, dense=True, **ui.input_kwargs())
    persona_text = ft.Text(size=11, color=ui.MUTED, selectable=True)

    def _rebuild_cards() -> None:
        cards_row.controls.clear()
        for kind, label, port_key, icon in _KINDS:
            cards_row.controls.append(
                _kind_card(mgr, kind, label, port_key, icon, _on_toggle)
            )

    def _refresh(_payload: dict | None = None) -> None:
        current_cfg = config.load()["honeypot"]
        persona_text.value = (
            f"Active persona: {current_cfg.get('persona', 'custom')}  |  "
            f"HTTP: {current_cfg.get('http_server_header', '-')}"
        )
        st = db.honeypot_stats()
        classes = db.honeypot_classification_counts()
        by_type = "  |  ".join(f"{k}:{v}" for k, v in st["by_type"].items()) or "-"
        top = ", ".join(f"{ip}x{n}" for ip, n in st["top_ips"][:5]) or "-"
        stats_text.value = (
            f"Total events: {st['total']}    |    By type: {by_type}    |    Top IPs: {top}"
        )
        class_text.value = "Classifications: " + (", ".join(f"{k}:{v}" for k, v in classes.items()) or "-")
        class_filter.options = [ft.dropdown.Option(key="", text="All classes")] + [
            ft.dropdown.Option(key=k, text=k) for k in classes
        ]
        feed.controls.clear()
        explicit_filter = bool((search_in.value or "").strip() or class_filter.value or type_filter.value)
        query_limit = _LOG_LIMIT_DETAILED if show_details.value or explicit_filter else _LOG_LIMIT_COMPACT
        rows = db.search_honeypot_events(
            query=(search_in.value or "").strip(),
            classification=class_filter.value or "",
            hp_type=type_filter.value or "",
            limit=query_limit,
        )
        if signal_only.value and not explicit_filter:
            rows = [row for row in rows if (row["classification"] or "") not in _NOISY_CLASSES]
        credentials = []
        for row in rows:
            iocs = _json(row["iocs_json"], {})
            for cred in iocs.get("credentials", []) if isinstance(iocs, dict) else []:
                credentials.append(f"{row['src_ip']} {cred.get('service')} user={cred.get('username') or '-'}")
            geo = _json(row["geo_json"], {})
            detail_text = _event_details(row, iocs, geo) if show_details.value else ""
            summary_text = _event_summary(row, iocs, geo)
            class_label = row["classification"] or "connection"
            feed.controls.append(
                ui.panel(
                    padding=8,
                    content=ft.Column(
                        [
                            ft.Row(
                                [
                                    ui.badge(class_label[:2].upper(), color=_class_color(class_label), width=34),
                                    ft.Column(
                                        [
                                            ft.Text(
                                                summary_text,
                                                size=11,
                                                selectable=True,
                                                color=ui.TEXT,
                                            ),
                                            ft.Text(
                                                f"{row['ts']}  |  {row['hp_type'].upper()}  |  {row['src_ip']}:{row['src_port']}",
                                                size=10,
                                                selectable=True,
                                                color=ui.MUTED,
                                            ),
                                        ],
                                        spacing=1,
                                        expand=True,
                                    ),
                                ],
                                spacing=8,
                                vertical_alignment=ft.CrossAxisAlignment.START,
                            ),
                            ft.Text(detail_text, size=10, selectable=True, color=ui.MUTED)
                            if detail_text
                            else ft.Container(),
                        ],
                        spacing=3,
                    ),
                )
            )
        if not feed.controls:
            feed.controls.append(ft.Text("No signal events match the current filters.", size=11, color=ui.MUTED))
        credential_text.value = "Credential attempts: " + (", ".join(credentials[:12]) or "-")
        _render_campaigns()
        _render_sessions()
        try:
            page.update()
        except Exception:
            pass

    def _render_sessions() -> None:
        sessions_list.controls.clear()
        for item in db.honeypot_sessions(limit=30):
            sessions_list.controls.append(
                ui.panel(
                    padding=8,
                    content=ft.Column(
                        [
                            ft.Text(f"{item['src_ip']}  events={item['count']}  services={','.join(item['types'])}", size=11, color=ui.TEXT, selectable=True),
                            ft.Text(f"{item['first_ts']} -> {item['last_ts']}  {','.join(item['classifications'])}", size=10, color=ui.MUTED, selectable=True),
                        ],
                        spacing=2,
                    ),
                )
            )
        if not sessions_list.controls:
            sessions_list.controls.append(ft.Text("No sessions yet", size=11, color=ui.MUTED))

    def _render_campaigns() -> None:
        campaigns_list.controls.clear()
        for campaign in honeypot_campaigns.cluster(limit=1000, max_campaigns=8):
            color = ui.DANGER if campaign["score"] >= 60 else ui.WARN if campaign["score"] >= 30 else ui.MUTED
            campaigns_list.controls.append(
                ui.panel(
                    padding=8,
                    content=ft.Column(
                        [
                            ft.Row(
                                [
                                    ui.badge(str(campaign["score"]), color=color, width=42),
                                    ft.Text(
                                        f"{campaign['src_ip']}  {campaign['intent']}  events={campaign['event_count']}",
                                        size=11,
                                        color=ui.TEXT,
                                        selectable=True,
                                        expand=True,
                                    ),
                                ],
                                spacing=8,
                            ),
                            ft.Text(
                                f"Services: {campaign['services']}  Classes: {campaign['classifications']}",
                                size=10,
                                color=ui.MUTED,
                                selectable=True,
                            ),
                            ft.Text(
                                f"Paths: {', '.join(campaign['top_paths']) or '-'}  Alerts: {', '.join(campaign['alerts']) or '-'}",
                                size=10,
                                color=ui.MUTED,
                                selectable=True,
                            ),
                        ],
                        spacing=3,
                    ),
                )
            )
        if not campaigns_list.controls:
            campaigns_list.controls.append(ft.Text("No campaigns yet", size=11, color=ui.MUTED))

    def _on_toggle(kind: str) -> None:
        if mgr.status()[kind]["running"]:
            mgr.stop(kind)
        else:
            ok = mgr.start(kind)
            if not ok:
                ui.notify(page, mgr.error(kind) or f"Port busy or unavailable for {kind}")
        _rebuild_cards()
        _refresh()

    def _as_port(field: ft.TextField, name: str) -> int:
        try:
            port = int((field.value or "").strip())
        except ValueError as exc:
            raise ValueError(f"{name} must be a number") from exc
        if port < 1 or port > 65535:
            raise ValueError(f"{name} must be between 1 and 65535")
        return port

    def _save_settings(_):
        try:
            next_cfg = config.load()
            hp = next_cfg["honeypot"]
            hp["http_port"] = _as_port(http_port, "HTTP port")
            hp["ssh_port"] = _as_port(ssh_port, "SSH port")
            hp["ftp_port"] = _as_port(ftp_port, "FTP port")
            hp["telnet_port"] = _as_port(telnet_port, "Telnet port")
            hp["smtp_port"] = _as_port(smtp_port, "SMTP port")
            config.save(next_cfg)
        except ValueError as exc:
            ui.notify(page, str(exc))
            return
        _rebuild_cards()
        _refresh()
        ui.notify(page, "Honeypot ports saved. Restart running honeypots to apply changes.")

    def _clear_logs(_):
        db.clear_honeypot_events()
        _refresh()
        events.emit("honeypot", {"phase": "cleared"})
        ui.notify(page, "Honeypot logs cleared")

    def _export(fmt: str):
        def _inner(_):
            try:
                path = exporter.export_honeypot(fmt)
            except Exception as exc:
                ui.notify(page, f"Export failed: {exc}")
                return
            ui.notify(page, f"Exported: {path}")
        return _inner

    def _filter_changed(_):
        _refresh()

    ports_panel = ft.Container(
        padding=14,
        border_radius=8,
        bgcolor=ui.PANEL,
        border=ui.border(),
        content=ft.Column(
            [
                ft.Text("Honeypot ports", size=15, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                ft.Row([http_port, ssh_port, ftp_port, telnet_port, smtp_port], spacing=10, wrap=True),
                ui.action_button("Save ports", "SAVE", _save_settings, width=126),
            ],
            spacing=10,
        ),
    )

    unsub = events.subscribe("honeypot", _refresh)
    page._sf_cleanups = getattr(page, "_sf_cleanups", [])
    page._sf_cleanups.append(unsub)

    _rebuild_cards()
    search_in.on_submit = _filter_changed
    class_filter.on_select = _filter_changed
    type_filter.on_select = _filter_changed
    signal_only.on_change = _filter_changed
    show_details.on_change = _filter_changed
    _refresh()

    return ft.Column(
        [
            ft.Text("Honeypot servers", size=18, weight=ft.FontWeight.BOLD, color=ui.TEXT),
            ft.Text(
                "Low-interaction honeypots. Deploy only on hosts you own. "
                "Captured connections are stored locally.",
                size=11, color=ui.MUTED,
            ),
            cards_row,
            persona_text,
            ports_panel,
            stats_text,
            class_text,
            credential_text,
            ft.Divider(color=ui.BORDER),
            ft.Row(
                [ft.Text("Detailed activity logs", size=15, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                 ft.Row(
                     [
                         ui.action_button("Export JSON", "JSON", _export("json"), width=126),
                         ui.action_button("Export TXT", "TXT", _export("txt"), width=116),
                         ui.action_button("Clear logs", "CLR", _clear_logs, width=126),
                         ui.action_button("Refresh", "REF", lambda _: _refresh(), width=116),
                     ],
                     spacing=8,
                 )],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ),
            ft.Row([search_in, class_filter, type_filter, signal_only, show_details], spacing=10, wrap=True),
            ui.panel(
                ft.Column(
                    [
                        ft.Text("Campaigns", size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                        campaigns_list,
                        ft.Divider(color=ui.BORDER),
                        ft.Text("Sessions", size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                        sessions_list,
                    ],
                    spacing=8,
                ),
                padding=12,
            ),
            feed,
        ],
        expand=True,
        scroll=ft.ScrollMode.AUTO,
    )

from __future__ import annotations

import json

import flet as ft

from ...core import db, events
from ...modules.reports import exporter
from .. import theme as ui

_STATUSES = [
    "New",
    "Confirmed",
    "False positive",
    "Accepted risk",
    "Resolved",
    "Reopened",
]

_SEVERITY_COLOR = {
    "Critical": ui.DANGER,
    "High": ui.HIGH,
    "Medium": ui.WARN,
    "Low": ui.BRAND,
}


def render(page: ft.Page) -> ft.Control:
    state = {"status": "", "query": "", "selected": getattr(page, "_sf_selected_finding_id", None), "narrow": False}
    status_filter = ft.Dropdown(
        label="Status filter",
        width=220,
        dense=True,
        options=[ft.dropdown.Option(key="", text="All statuses")]
        + [ft.dropdown.Option(key=s, text=s) for s in _STATUSES],
        **ui.dropdown_kwargs(),
    )
    rows = ft.ListView(expand=True, spacing=0, auto_scroll=False)
    detail = ft.Column(
        expand=True, spacing=16, scroll=ft.ScrollMode.AUTO, horizontal_alignment=ft.CrossAxisAlignment.STRETCH
    )
    context = ft.Column(spacing=16, scroll=ft.ScrollMode.AUTO, expand=True)
    count = ft.Text("", size=12, color=ui.TEXT_MUTED)
    search = ft.TextField(label="Search findings", dense=True, text_size=14, **ui.input_kwargs())
    match_cache: dict[int, list] = {}

    def _row(f) -> ft.Control:
        severity = f["severity"] or "Info"
        selected = state["selected"] == int(f["id"])
        return ft.Container(
            border=ft.Border(
                bottom=ft.BorderSide(1, ui.BORDER),
                left=ft.BorderSide(2, ui.BRAND if selected else ft.Colors.TRANSPARENT),
            ),
            content=ft.Button(
                height=112,
                data=int(f["id"]),
                tooltip=f["title"],
                on_click=_select,
                style=ui.button_style(background=ui.SURFACE_ACTIVE if selected else ui.BACKGROUND, outlined=False),
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ft.Icons.SQUARE, size=12, color=_SEVERITY_COLOR.get(severity, ui.MUTED)),
                                ft.Text(f"SF-{int(f['id']):03d} · {severity}", size=12, color=ui.TEXT_SECONDARY),
                            ],
                            spacing=8,
                        ),
                        ft.Text(f["title"], size=14, color=ui.TEXT, max_lines=2, overflow=ft.TextOverflow.ELLIPSIS),
                        ft.Text(f["asset_hostname"] or "No linked asset", size=12, color=ui.TEXT_MUTED, no_wrap=True),
                    ],
                    spacing=6,
                    alignment=ft.MainAxisAlignment.CENTER,
                ),
            ),
        )

    def _render_detail(f) -> None:
        severity = f["severity"] or "Info"
        status = f["status"] or "New"
        matches = match_cache.get(int(f["id"]), [])
        status_dd = ft.Dropdown(
            value=status,
            dense=True,
            width=170,
            options=[ft.dropdown.Option(key=s, text=s) for s in _STATUSES],
            data=f["id"],
            on_select=_status_changed,
            **ui.dropdown_kwargs(),
        )
        detail.controls = [
            ft.Row(
                [
                    ui.badge(severity, color=_SEVERITY_COLOR.get(severity, ui.MUTED), width=90),
                    ft.Column(
                        [
                            ft.Text(
                                f"SF-{int(f['id']):03d} · {f['title']}",
                                size=22,
                                weight=ft.FontWeight.W_600,
                                color=ui.TEXT,
                                selectable=True,
                            ),
                            ft.Text(
                                f"Asset: {f['asset_hostname'] or '-'}  |  Confidence: {f['confidence']}  |  Source: {f['source_module']}",
                                size=12,
                                color=ui.MUTED,
                                selectable=True,
                            ),
                        ],
                        spacing=2,
                        expand=True,
                    ),
                    status_dd,
                ],
                vertical_alignment=ft.CrossAxisAlignment.START,
            ),
            ft.Container(
                padding=ft.Padding(left=0, top=12, right=0, bottom=12),
                border=ft.Border(bottom=ft.BorderSide(2, ui.BRAND)),
                content=ft.Text("Evidence & assessment", size=14, color=ui.TEXT),
            ),
            ui.section(
                "Observed evidence",
                ft.Text(f["evidence"] or "No evidence recorded", size=14, color=ui.TEXT, selectable=True),
            ),
            ui.section(
                "Advisory matches",
                _vuln_details(matches)
                if matches
                else ft.Text("No linked advisory matches", size=14, color=ui.TEXT_MUTED),
            ),
            ui.section(
                "Remediation",
                ft.Text(
                    f["remediation"] or "No remediation recorded", size=14, color=ui.TEXT_SECONDARY, selectable=True
                ),
            ),
        ]
        context.controls = [
            ui.section(
                "Affected asset",
                ft.Text(f["asset_hostname"] or "No linked asset", size=14, color=ui.TEXT, selectable=True),
            ),
            ui.section(
                "Assessment",
                ft.Column(
                    [
                        ft.Text(f"Severity: {severity}", size=14, color=ui.TEXT),
                        ft.Text(f"Confidence: {f['confidence'] or 'Unknown'}", size=14, color=ui.TEXT_SECONDARY),
                        ft.Text(f"Status: {status}", size=14, color=ui.TEXT_SECONDARY),
                        ft.Text(
                            "Status combines review and verification in this version", size=12, color=ui.TEXT_MUTED
                        ),
                    ],
                    spacing=12,
                ),
            ),
            ui.section(
                "Provenance",
                ft.Column(
                    [
                        ft.Text(f"Source: {f['source_module']}", size=14, color=ui.TEXT_SECONDARY),
                        ft.Text(f"First seen\n{f['first_seen']}", size=12, color=ui.TEXT_MUTED),
                        ft.Text(f"Last seen\n{f['last_seen']}", size=12, color=ui.TEXT_MUTED),
                        ft.Text(f"Fingerprint\n{f['fingerprint']}", size=12, color=ui.TEXT_MUTED, selectable=True),
                    ],
                    spacing=12,
                ),
            ),
        ]
        if state["narrow"]:
            detail.controls.append(context)

    def _select(event) -> None:
        state["selected"] = int(event.control.data)
        page._sf_selected_finding_id = state["selected"]
        _refresh()

    def _vuln_details(matches: list) -> ft.Control:
        blocks: list[ft.Control] = []
        for match in matches:
            evidence = _json_load(match["evidence_json"], {})
            suppress_btn = ui.action_button(
                "Suppress",
                "SUP",
                _suppress_match,
                width=106,
            )
            approve_cpe_btn = ui.action_button(
                "Approve CPE",
                "CPE",
                _approve_cpe,
                width=122,
            )
            suppress_btn.data = {
                "cve_id": match["cve_id"],
                "asset_id": evidence.get("asset_id"),
                "product": evidence.get("product", ""),
                "matched_cpe": match["matched_cpe"] or "",
                "match_status": match["match_status"] or "",
            }
            approve_cpe_btn.data = {
                "raw_product": evidence.get("product", ""),
                "vendor": evidence.get("vendor", ""),
                "product": evidence.get("product", ""),
                "matched_cpe": match["matched_cpe"] or "",
            }
            blocks.append(
                ft.Container(
                    padding=ft.Padding(left=0, top=12, right=0, bottom=12),
                    border=ft.Border(bottom=ft.BorderSide(1, ui.BORDER)),
                    content=ft.Column(
                        [
                            ft.Column(
                                [
                                    ft.Text(match["match_status"].replace("_", " ").title(), size=12, color=ui.ACCENT),
                                    ft.Text(
                                        f"{match['cve_id']}  Priority {_fmt_score(match['priority_score'])}  Confidence {_fmt_score(match['confidence_score'])}",
                                        size=12,
                                        weight=ft.FontWeight.BOLD,
                                        color=ui.TEXT,
                                        selectable=True,
                                    ),
                                ],
                                spacing=8,
                                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
                            ),
                            ft.Row(
                                [
                                    approve_cpe_btn,
                                    suppress_btn,
                                ],
                                spacing=8,
                            ),
                            ft.Text(
                                f"Matched CPE: {match['matched_cpe'] or '-'}", size=12, color=ui.MUTED, selectable=True
                            ),
                            ft.Text(
                                f"Match: {match['match_status']}  |  {match['confidence_explanation']}",
                                size=12,
                                color=ui.MUTED,
                                selectable=True,
                            ),
                            ft.Text(
                                f"Priority factors: {match['priority_explanation'] or '-'}",
                                size=12,
                                color=ui.MUTED,
                                selectable=True,
                            ),
                            ft.Text(
                                "Evidence: "
                                + f"{evidence.get('product', '-')}/{evidence.get('version', '-')} "
                                + f"via {evidence.get('detection_method', '-')}; "
                                + f"range={evidence.get('range_result', '-')}; "
                                + f"CVSS={_fmt_score(evidence.get('cvss_score'))}; "
                                + f"EPSS={_epss_text(evidence.get('epss'))}; "
                                + f"KEV={evidence.get('kev', False)} exploits={evidence.get('public_exploit_count', 0)}",
                                size=12,
                                color=ui.MUTED,
                                selectable=True,
                            ),
                        ],
                        spacing=4,
                    ),
                )
            )
        return ft.Column(blocks, spacing=6)

    def _suppress_match(e) -> None:
        data = e.control.data or {}
        try:
            db.add_vulnerability_suppression(
                cve_id=data.get("cve_id", ""),
                asset_id=data.get("asset_id"),
                product=data.get("product", ""),
                matched_cpe=data.get("matched_cpe", ""),
                match_status=data.get("match_status", ""),
                reason="Suppressed from finding card",
            )
        except Exception as exc:
            ui.notify(page, f"Suppression failed: {exc}")
            return
        ui.notify(page, "Suppression added for future matches")

    def _approve_cpe(e) -> None:
        data = e.control.data or {}
        try:
            db.add_cpe_product_override(
                raw_product=data.get("raw_product", ""),
                vendor=data.get("vendor", ""),
                product=data.get("product", ""),
                cpe_uri=data.get("matched_cpe", ""),
            )
        except Exception as exc:
            ui.notify(page, f"CPE approval failed: {exc}")
            return
        ui.notify(page, "CPE mapping approved for future scans")

    def _refresh(_payload: dict | None = None) -> None:
        nonlocal match_cache
        rows.controls.clear()
        findings = db.findings(limit=500, status=state["status"] or None)
        findings = filter_findings(findings, state["query"])
        match_cache = db.vulnerability_matches_for_findings([int(f["id"]) for f in findings])
        count.value = f"{len(findings)} findings · up to 500 records"
        ids = {int(f["id"]) for f in findings}
        if state["selected"] not in ids:
            state["selected"] = int(findings[0]["id"]) if findings else None
        if not findings:
            rows.controls.append(ft.Text("No matching findings", size=14, color=ui.MUTED))
            detail.controls = [
                ft.Text("Select a finding", size=22, color=ui.TEXT),
                ft.Text("Run a scan or adjust the filters to inspect recorded evidence", size=14, color=ui.MUTED),
            ]
            context.controls = []
        else:
            rows.controls.extend(_row(f) for f in findings)
            _render_detail(next(f for f in findings if int(f["id"]) == state["selected"]))
        try:
            page.update()
        except RuntimeError:
            # Worker events can arrive after the page closes
            pass

    def _status_changed(e) -> None:
        try:
            db.update_finding_status(int(e.control.data), e.control.value)
        except Exception as exc:
            ui.notify(page, f"Status update failed: {exc}")
            return
        ui.notify(page, "Finding status updated")
        _refresh()

    def _filter_changed(e) -> None:
        state["status"] = e.control.value or ""
        _refresh()

    def _export(fmt: str):
        def _inner(_):
            try:
                path = exporter.export_inventory(fmt)
            except Exception as exc:
                ui.notify(page, f"Export failed: {exc}")
                return
            ui.notify(page, f"Exported: {path}")

        return _inner

    def _clear_findings(_):
        try:
            db.clear_findings()
        except Exception as exc:
            ui.notify(page, f"Clear findings failed: {exc}")
            return
        ui.notify(page, "Findings cleared")
        _refresh()

    status_filter.on_select = _filter_changed

    def _search_changed(event):
        state["query"] = event.control.value or ""
        _refresh()

    search.on_change = _search_changed
    unsub_scan = events.subscribe("scanner", _refresh)
    unsub_recon = events.subscribe("recon", _refresh)
    page._sf_cleanups = getattr(page, "_sf_cleanups", [])
    page._sf_cleanups.extend([unsub_scan, unsub_recon])

    export_row = ft.Row(
        [
            ui.export_menu(_export),
            ui.action_button("Clear findings", "CLR", _clear_findings, width=126),
        ],
        spacing=8,
        wrap=True,
    )

    context_pane = ft.Container(
        content=context,
        width=280,
        padding=ft.Padding(left=16, top=0, right=0, bottom=0),
        border=ft.Border(left=ft.BorderSide(1, ui.BORDER)),
    )

    def adapt(event):
        visible = event.width >= 1100
        if context_pane.visible == visible:
            return
        context_pane.visible = visible
        state["narrow"] = not visible
        context.expand = True if visible else None
        if visible:
            if context in detail.controls:
                detail.controls.remove(context)
            context_pane.content = context
        else:
            context_pane.content = None
            detail.controls.append(context)
        page.update()

    _refresh()
    return ft.Row(
        [
            ft.Container(
                width=268,
                padding=ft.Padding(left=0, top=0, right=16, bottom=0),
                border=ft.Border(right=ft.BorderSide(1, ui.BORDER)),
                content=ft.Column([search, status_filter, count, export_row, rows], spacing=16, expand=True),
            ),
            ft.Container(content=detail, expand=True, padding=ft.Padding(left=24, top=0, right=24, bottom=0)),
            context_pane,
        ],
        spacing=0,
        expand=True,
        on_size_change=adapt,
    )


def filter_findings(findings, query: str) -> list:
    """Filter loaded records without changing their order"""
    query = query.strip().casefold()
    return [
        row
        for row in findings
        if not query
        or query
        in " ".join(str(row[key] or "") for key in ("title", "asset_hostname", "evidence", "source_module")).casefold()
    ]


def _json_load(value: str | None, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _fmt_score(value) -> str:
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "-"


def _epss_text(value) -> str:
    if not isinstance(value, dict):
        return "-"
    return _fmt_score(value.get("score"))

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
    "High": ui.DANGER,
    "Medium": ui.WARN,
    "Low": ui.INFO,
}


def render(page: ft.Page) -> ft.Control:
    state = {"status": ""}
    status_filter = ft.Dropdown(
        label="Status filter",
        width=220,
        dense=True,
        options=[ft.dropdown.Option(key="", text="All statuses")]
        + [ft.dropdown.Option(key=s, text=s) for s in _STATUSES],
        **ui.dropdown_kwargs(),
    )
    rows = ft.ListView(expand=True, spacing=8, auto_scroll=False)
    match_cache: dict[int, list] = {}

    def _row(f) -> ft.Control:
        severity = f["severity"] or "Info"
        status = f["status"] or "New"
        vuln_details = _vuln_details(int(f["id"]), match_cache.get(int(f["id"]), []))
        status_dd = ft.Dropdown(
            value=status,
            dense=True,
            width=170,
            options=[ft.dropdown.Option(key=s, text=s) for s in _STATUSES],
            data=f["id"],
            on_select=_status_changed,
            **ui.dropdown_kwargs(),
        )
        return ui.panel(
            padding=12,
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ui.badge(severity[:2].upper(), color=_SEVERITY_COLOR.get(severity, ui.MUTED), width=38),
                            ft.Column(
                                [
                                    ft.Text(f["title"], size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT, selectable=True),
                                    ft.Text(
                                        f"Asset: {f['asset_hostname'] or '-'}  |  Confidence: {f['confidence']}  |  Source: {f['source_module']}",
                                        size=11,
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
                    ft.Text(f"Evidence: {f['evidence'] or '-'}", size=11, color=ui.TEXT, selectable=True),
                    vuln_details,
                    ft.Text(f"Remediation: {f['remediation'] or '-'}", size=11, color=ui.MUTED, selectable=True),
                    ft.Text(
                        f"First seen: {f['first_seen']}  |  Last seen: {f['last_seen']}  |  Fingerprint: {f['fingerprint']}",
                        size=10,
                        color=ui.MUTED,
                        selectable=True,
                    ),
                ],
                spacing=6,
            ),
        )

    def _vuln_details(finding_id: int, matches: list) -> ft.Control:
        if not matches:
            return ft.Container()
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
                    padding=8,
                    border_radius=8,
                    bgcolor=ui.PANEL_2,
                    border=ui.border(),
                    content=ft.Column(
                        [
                            ft.Row(
                                [
                                    ui.badge(match["match_status"][:2].upper(), color=ui.ACCENT, width=34),
                                    ft.Text(
                                        f"{match['cve_id']}  Priority {_fmt_score(match['priority_score'])}  Confidence {_fmt_score(match['confidence_score'])}",
                                        size=11,
                                        weight=ft.FontWeight.BOLD,
                                        color=ui.TEXT,
                                        selectable=True,
                                        expand=True,
                                    ),
                                ],
                                spacing=8,
                            ),
                            ft.Row(
                                [
                                    approve_cpe_btn,
                                    suppress_btn,
                                ],
                                spacing=8,
                            ),
                            ft.Text(f"Matched CPE: {match['matched_cpe'] or '-'}", size=10, color=ui.MUTED, selectable=True),
                            ft.Text(f"Match: {match['match_status']}  |  {match['confidence_explanation']}", size=10, color=ui.MUTED, selectable=True),
                            ft.Text(f"Priority factors: {match['priority_explanation'] or '-'}", size=10, color=ui.MUTED, selectable=True),
                            ft.Text(
                                "Evidence: "
                                + f"{evidence.get('product', '-')}/{evidence.get('version', '-')} "
                                + f"via {evidence.get('detection_method', '-')}; "
                                + f"range={evidence.get('range_result', '-')}; "
                                + f"CVSS={_fmt_score(evidence.get('cvss_score'))}; "
                                + f"EPSS={_epss_text(evidence.get('epss'))}; "
                                + f"KEV={evidence.get('kev', False)} exploits={evidence.get('public_exploit_count', 0)}",
                                size=10,
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
        match_cache = db.vulnerability_matches_for_findings([int(f["id"]) for f in findings])
        if not findings:
            rows.controls.append(ft.Text("No findings yet", color=ui.MUTED))
        else:
            rows.controls.extend(_row(f) for f in findings)
        try:
            page.update()
        except Exception:
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
    unsub_scan = events.subscribe("scanner", _refresh)
    unsub_recon = events.subscribe("recon", _refresh)
    page._sf_cleanups = getattr(page, "_sf_cleanups", [])
    page._sf_cleanups.extend([unsub_scan, unsub_recon])

    export_row = ft.Row(
        [
            ui.action_button("TXT", "TXT", _export("txt"), width=74),
            ui.action_button("JSON", "JS", _export("json"), width=82),
            ui.action_button("CSV", "CSV", _export("csv"), width=78),
            ui.action_button("HTML", "HT", _export("html"), width=86),
            ui.action_button("SARIF", "SA", _export("sarif"), width=88),
            ui.action_button("STIX", "ST", _export("stix"), width=82),
            ui.action_button("MD", "MD", _export("md"), width=72),
            ui.action_button("Clear findings", "CLR", _clear_findings, width=126),
        ],
        spacing=8,
        wrap=True,
    )

    _refresh()
    return ft.Column(
        [
            ft.Row(
                [ft.Text("Findings", size=18, weight=ft.FontWeight.BOLD, color=ui.TEXT), export_row],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                wrap=True,
            ),
            status_filter,
            rows,
        ],
        expand=True,
        spacing=12,
    )


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

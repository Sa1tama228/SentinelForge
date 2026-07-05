"""Asset inventory view."""
from __future__ import annotations

import json

import flet as ft

from ...core import db, events
from ...modules.analysis import evidence_graph
from ...modules.reports import exporter
from ...modules.scanner import inventory
from .. import theme as ui


def _loads(value: str, default):
    try:
        return json.loads(value or "")
    except json.JSONDecodeError:
        return default


def _kv(title: str, value) -> ft.Control:
    text = json.dumps(value, indent=2, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value or "-")
    return ft.Column(
        [
            ft.Text(title, size=12, weight=ft.FontWeight.BOLD, color=ui.MUTED),
            ft.Text(text, size=11, selectable=True, color=ui.TEXT),
        ],
        spacing=2,
    )


def _graph_panel(asset_id: int) -> ft.Control:
    ctx = evidence_graph.asset_neighborhood(asset_id)
    summary = ctx.get("summary") or {}
    neighbors = ctx.get("neighbors") or []
    rows: list[ft.Control] = [
        ft.Text("Evidence graph", size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT),
        ft.Row(
            [
                ui.badge(f"S{summary.get('services', 0)}", width=42),
                ui.badge(f"F{summary.get('findings', 0)}", width=42, color=ui.WARN),
                ui.badge(f"V{summary.get('vulnerabilities', 0)}", width=42, color=ui.DANGER),
                ui.badge(f"R{summary.get('recon', 0)}", width=42, color=ui.INFO),
                ui.badge(f"W{summary.get('web_audit_signals', 0)}", width=42, color=ui.ACCENT),
            ],
            spacing=6,
            wrap=True,
        ),
    ]
    for item in neighbors[:12]:
        data = item.get("data") or {}
        detail = ", ".join(f"{k}={v}" for k, v in data.items() if k not in {"id"}) or item.get("edge", "")
        rows.append(
            ft.Container(
                padding=8,
                border_radius=8,
                bgcolor=ui.PANEL_2,
                border=ui.border(),
                content=ft.Column(
                    [
                        ft.Text(
                            f"{item['type']}  |  {item['label']}",
                            size=11,
                            weight=ft.FontWeight.BOLD,
                            color=ui.TEXT,
                            selectable=True,
                        ),
                        ft.Text(
                            f"{item['edge']}  confidence={float(item['confidence']):.2f}  {detail}",
                            size=10,
                            color=ui.MUTED,
                            selectable=True,
                        ),
                    ],
                    spacing=2,
                ),
            )
        )
    if not neighbors:
        rows.append(ft.Text("No graph evidence yet", size=11, color=ui.MUTED))
    return ui.panel(ft.Column(rows, spacing=8), padding=12)


def render(page: ft.Page) -> ft.Control:
    state = {"asset_id": None}
    asset_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO, expand=True)
    detail = ft.Column(spacing=10, scroll=ft.ScrollMode.AUTO, expand=True)
    notes = ft.TextField(label="Notes", multiline=True, min_lines=3, max_lines=6, dense=True, **ui.input_kwargs())
    inventory_path = ft.TextField(label="Inventory/SBOM file path", width=520, dense=True, **ui.input_kwargs())

    def _asset_card(row) -> ft.Control:
        ips = _loads(row["normalized_ips"], [])
        services = _loads(row["open_services"], [])
        findings = db.asset_findings(row["id"])
        selected = row["id"] == state["asset_id"]
        return ui.panel(
            padding=10,
            selected=selected,
            data=row["id"],
            on_click=_select,
            content=ft.Column(
                [
                    ft.Text(row["hostname"], size=13, weight=ft.FontWeight.BOLD, color=ui.TEXT, selectable=True),
                    ft.Text(f"IPs: {', '.join(ips) or '-'}", size=10, color=ui.MUTED, selectable=True),
                    ft.Text(f"Services: {len(services)}  Findings: {len(findings)}", size=10, color=ui.MUTED),
                ],
                spacing=3,
            ),
        )

    def _refresh(_payload: dict | None = None) -> None:
        rows = db.assets(limit=500)
        if state["asset_id"] is None and rows:
            state["asset_id"] = rows[0]["id"]
        asset_list.controls = [_asset_card(row) for row in rows] or [ft.Text("No assets yet", color=ui.MUTED)]
        _render_detail()
        try:
            page.update()
        except Exception:
            pass

    def _render_detail() -> None:
        detail.controls.clear()
        if state["asset_id"] is None:
            detail.controls.append(ft.Text("Run scanner or recon to create assets.", color=ui.MUTED))
            return
        row = db.asset_by_id(int(state["asset_id"]))
        if row is None:
            detail.controls.append(ft.Text("Selected asset no longer exists.", color=ui.MUTED))
            return
        notes.value = row["notes"] or ""
        findings = db.asset_findings(row["id"])
        history = db.asset_scan_history(row["id"])
        detail.controls.extend(
            [
                ft.Text(row["hostname"], size=20, weight=ft.FontWeight.BOLD, color=ui.TEXT, selectable=True),
                ft.Row(
                    [
                        ui.badge(row["source"] or "asset", width=72),
                        ft.Text(f"First seen: {row['first_seen']}", size=11, color=ui.MUTED),
                        ft.Text(f"Last seen: {row['last_seen']}", size=11, color=ui.MUTED),
                    ],
                    spacing=10,
                ),
                _kv("Normalized IPs", _loads(row["normalized_ips"], [])),
                _graph_panel(int(row["id"])),
                _kv("Tags", _loads(row["tags"], [])),
                _kv("Open services", _loads(row["open_services"], [])),
                _kv("DNS records", _loads(row["dns_records"], {})),
                _kv("Certificates", _loads(row["certificates"], [])),
                _kv("Technologies", _loads(row["technologies"], [])),
                _kv("Imported packages", [dict(pkg) for pkg in db.asset_packages(row["id"])]),
                _kv("Findings", [dict(f) for f in findings]),
                notes,
                ft.Row(
                    [
                        ui.action_button("Save notes", "SAVE", _save_notes, width=130),
                        inventory_path,
                        ui.action_button("Import inventory", "IMP", _import_inventory, width=150),
                    ],
                    spacing=8,
                    wrap=True,
                ),
                _kv("Scan history", [dict(h) for h in history]),
            ]
        )

    def _select(e) -> None:
        state["asset_id"] = int(e.control.data)
        _refresh()

    def _save_notes(_):
        if state["asset_id"] is None:
            return
        db.update_asset_notes(int(state["asset_id"]), notes.value or "")
        ui.notify(page, "Asset notes saved")
        _refresh()

    def _import_inventory(_):
        if state["asset_id"] is None:
            return
        path = (inventory_path.value or "").strip()
        if not path:
            ui.notify(page, "Enter an inventory or SBOM path")
            return
        try:
            count = inventory.import_inventory(int(state["asset_id"]), path)
        except Exception as exc:
            ui.notify(page, f"Inventory import failed: {exc}")
            return
        ui.notify(page, f"Imported {count} package(s)")
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

    def _clear_assets(_):
        try:
            db.clear_assets()
        except Exception as exc:
            ui.notify(page, f"Clear assets failed: {exc}")
            return
        state["asset_id"] = None
        ui.notify(page, "Assets and related findings cleared")
        _refresh()

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
            ui.action_button("Clear assets", "CLR", _clear_assets, width=112),
        ],
        spacing=8,
        wrap=True,
    )
    _refresh()
    inventory_panel = ui.panel(
        ft.Column(
            [
                ft.Text("Inventory", size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                asset_list,
            ],
            spacing=8,
            expand=True,
        ),
        width=340,
        padding=14,
    )
    detail_panel = ui.panel(
        detail,
        expand=True,
        padding=14,
    )
    return ft.Column(
        [
            ft.Row(
                [ft.Text("Assets", size=18, weight=ft.FontWeight.BOLD, color=ui.TEXT), export_row],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ),
            ft.Row(
                [
                    inventory_panel,
                    detail_panel,
                ],
                expand=True,
                spacing=12,
            ),
        ],
        expand=True,
        spacing=12,
    )

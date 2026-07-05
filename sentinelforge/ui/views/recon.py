"""Recon view: passive OSINT launcher + per-collector result cards."""
from __future__ import annotations

import json
import time

import flet as ft

from ...core import db, events
from ...modules.analysis import source_quality
from ...modules.recon import exporter
from ...modules.reports import exporter as report_exporter
from ...modules.recon.runner import run_async
from .. import theme as ui

_KIND_TITLE = {
    "dns": "DNS records",
    "dns_diff": "DNS changes",
    "whois": "WHOIS / RDAP",
    "subdomains": "Subdomains (CT logs)",
    "subdomain_diff": "Subdomain changes",
    "techstack": "Technology stack",
    "tech_diff": "Technology changes",
    "exposure": "Safe exposure checks",
    "takeover": "Takeover heuristics",
    "error": "Run errors",
}


def _fmt(kind: str, data: dict) -> ft.Control:
    if kind == "dns":
        if not data:
            return ft.Text("No records.", color=ui.MUTED)
        rows = []
        for t, vals in data.items():
            if t == "posture" and isinstance(vals, dict):
                rows.append(ft.Text("Mail posture:", size=12, weight=ft.FontWeight.BOLD, color=ui.TEXT))
                rows.append(
                    ft.Text(
                        f"  SPF: {'present' if vals.get('spf_present') else 'missing'}\n"
                        f"  DMARC: {'present' if vals.get('dmarc_present') else 'missing'}",
                        size=12, selectable=True, color=ui.TEXT,
                    )
                )
                continue
            rows.append(ft.Text(f"{t}:", size=12, weight=ft.FontWeight.BOLD, color=ui.TEXT))
            rows.append(ft.Text("  " + "\n  ".join(vals), size=12, selectable=True, color=ui.TEXT))
        return ft.Column(rows, spacing=2)

    if kind == "whois":
        if data.get("error"):
            return ft.Text(f"RDAP error: {data['error']}",
                           color=ui.MUTED, size=12)
        rows = []
        for k in ("registrar", "registered", "updated", "expires"):
            rows.append(ft.Text(f"{k.capitalize()}: {data.get(k) or '-'}",
                                size=12, selectable=True, color=ui.TEXT))
        rows.append(ft.Text(f"Status: {', '.join(data.get('status') or []) or '-'}",
                            size=12, selectable=True, color=ui.TEXT))
        ns = data.get("nameservers") or []
        rows.append(ft.Text(f"Nameservers: {', '.join(ns) or '-'}",
                            size=12, selectable=True, color=ui.TEXT))
        return ft.Column(rows, spacing=2)

    if kind == "subdomains":
        names = data.get("names", [])
        sources = data.get("sources", {})
        return ft.Column(
            [
                ft.Text(f"Found {data.get('count', 0)} unique names",
                        size=12, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                ft.Text(f"Sources: {sources}", size=11, selectable=True, color=ui.MUTED),
                ft.Text("\n".join(names[:200]) or "-",
                        size=11, selectable=True, color=ui.TEXT),
            ],
            spacing=2,
        )

    if kind in {"subdomain_diff", "tech_diff"}:
        return ft.Column(
            [
                ft.Text(f"Added: {', '.join(data.get('added', [])[:50]) or '-'}", size=11, selectable=True, color=ui.TEXT),
                ft.Text(f"Removed: {', '.join(data.get('removed', [])[:50]) or '-'}", size=11, selectable=True, color=ui.MUTED),
                ft.Text(f"Unchanged: {data.get('unchanged', 0)}", size=11, color=ui.MUTED),
            ],
            spacing=3,
        )

    if kind == "dns_diff":
        rows = []
        for rtype, delta in data.items():
            rows.append(ft.Text(rtype, size=12, weight=ft.FontWeight.BOLD, color=ui.TEXT))
            rows.append(ft.Text(f"  Added: {', '.join(delta.get('added', [])) or '-'}", size=11, selectable=True, color=ui.TEXT))
            rows.append(ft.Text(f"  Removed: {', '.join(delta.get('removed', [])) or '-'}", size=11, selectable=True, color=ui.MUTED))
        return ft.Column(rows or [ft.Text("No DNS changes", color=ui.MUTED)], spacing=2)

    if kind == "exposure":
        checks = data.get("checks", [])
        if data.get("disabled"):
            return ft.Text("Safe endpoint checks disabled", size=12, color=ui.MUTED)
        if not checks:
            return ft.Text("No notable exposed endpoints detected.", size=12, color=ui.MUTED)
        return ft.Column(
            [
                ft.Text(
                    f"{item.get('severity')}  {item.get('path')}  HTTP {item.get('status')}  {item.get('title')}",
                    size=11,
                    selectable=True,
                    color=ui.TEXT,
                )
                for item in checks
            ],
            spacing=3,
        )

    if kind == "takeover":
        hints = data.get("hints", [])
        if not hints:
            return ft.Text("No takeover heuristics matched.", size=12, color=ui.MUTED)
        return ft.Column(
            [
                ft.Text(
                    f"{item.get('provider')}  {item.get('cname')}  confidence={item.get('confidence')}",
                    size=11,
                    selectable=True,
                    color=ui.WARN,
                )
                for item in hints
            ],
            spacing=3,
        )

    if kind == "error":
        return ft.Text(data.get("error", "Unknown error"), size=12, selectable=True, color=ui.DANGER)

    # techstack
    if data.get("error"):
        return ft.Text(f"HTTP error: {data['error']}",
                       color=ui.MUTED, size=12)
    return ft.Column(
        [
            ft.Text(f"Final URL: {data.get('final_url', '-')}", size=12, selectable=True, color=ui.TEXT),
            ft.Text(f"Status: {data.get('status', '-')}", size=12, color=ui.TEXT),
            ft.Text(f"Title: {data.get('title') or '-'}", size=12, selectable=True, color=ui.TEXT),
            ft.Text(f"Server: {data.get('server') or '-'}", size=12, selectable=True, color=ui.TEXT),
            ft.Text(f"X-Powered-By: {data.get('powered_by') or '-'}", size=12, selectable=True, color=ui.TEXT),
            ft.Text(f"Generator: {data.get('generator') or '-'}", size=12, selectable=True, color=ui.TEXT),
            ft.Text(f"Cookies: {', '.join(data.get('cookies') or []) or '-'}", size=12, selectable=True, color=ui.TEXT),
            ft.Text(f"Technologies: {', '.join(data.get('technologies') or []) or '-'}",
                    size=12, weight=ft.FontWeight.BOLD, color=ui.ACCENT,
                    selectable=True),
            ft.Text(f"Security headers: {data.get('security_headers') or {}}",
                    size=11, selectable=True, color=ui.MUTED),
        ],
        spacing=2,
    )


def _card_for(kind: str, data_json: str) -> ft.Control:
    try:
        data = json.loads(data_json)
    except json.JSONDecodeError:
        data = {}
    return ui.panel(
        padding=12,
        content=ft.Container(
            content=ft.Column(
                [
                    ft.Text(_KIND_TITLE.get(kind, kind),
                            size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                    _fmt(kind, data),
                ],
                spacing=4,
            ),
        ),
    )


def render(page: ft.Page) -> ft.Control:
    domain_in = ft.TextField(
        label="Domain (e.g. example.com)", value="example.com",
        width=360, dense=True, **ui.input_kwargs()
    )
    status = ft.Text(size=12, color=ui.MUTED)
    history = ft.Dropdown(
        label="Target history",
        width=700,
        dense=True,
        menu_height=320,
        **ui.dropdown_kwargs(),
    )
    results = ft.ListView(expand=True, spacing=8, auto_scroll=True)
    source_status = ft.Column(spacing=4)
    page._sf_recon_tasks = getattr(page, "_sf_recon_tasks", {})
    state = {"target_id": None, "tasks": page._sf_recon_tasks}
    selected_progress = ft.ProgressBar(
        value=0,
        width=360,
        bar_height=6,
        color=ui.ACCENT,
        bgcolor=ui.BORDER,
        border_radius=3,
    )
    active_mount = ft.Column()

    def _load_history() -> None:
        rows = db.recent_targets(limit=30)
        if not rows:
            history.options = [ft.dropdown.Option(key="", text="No saved recon targets")]
            history.value = ""
            return
        history.options = [
            ft.dropdown.Option(
                key=str(r["id"]),
                text=f"#{r['id']}  {r['domain']}  {r['added_ts']}",
            )
            for r in rows
        ]
        if state["target_id"] is not None:
            history.value = str(state["target_id"])

    def _render_results(target_id: int | None) -> None:
        results.controls.clear()
        if target_id is None:
            results.controls.append(
                ft.Text("No target selected", color=ui.MUTED))
            return
        findings = db.recon_findings_for(target_id)
        if not findings:
            results.controls.append(
                ft.Text("No findings yet - run a recon.", color=ui.MUTED))
            return
        for f in findings:
            results.controls.append(_card_for(f["kind"], f["data_json"]))

    def _refresh(_payload: dict | None = None) -> None:
        payload = _payload or {}
        phase = payload.get("phase")
        target_id = payload.get("target_id")
        if target_id is not None:
            task_id = f"recon:{target_id}"
            task = state["tasks"].setdefault(
                task_id,
                {
                    "id": target_id,
                    "label": f"Recon #{target_id}",
                    "phase": "queued",
                    "progress": 0.0,
                    "status": "running",
                    "created": time.time(),
                },
            )
            if payload.get("domain"):
                task["label"] = f"Recon #{target_id}  {payload['domain']}"
            task["phase"] = phase or task["phase"]
            task["progress"] = float(payload.get("progress", task["progress"]))
            if phase in {"done", "failed"}:
                task["progress"] = 1.0
                task["status"] = "done"
        if target_id == state["target_id"]:
            selected_progress.value = float(payload.get("progress", selected_progress.value or 0))
            if phase == "started":
                status.value = f"Running passive recon on {payload.get('domain', domain_in.value)}..."
            elif phase in {"dns", "whois", "subdomains", "techstack"}:
                status.value = f"Recon phase complete: {phase}"
            elif phase == "done":
                status.value = f"Recon complete for {payload.get('domain', domain_in.value)}"
            elif phase == "failed":
                status.value = f"Recon failed: {payload.get('error', 'unknown error')}"
        _load_history()
        _render_results(state["target_id"])
        _render_source_status(state["target_id"])
        active_mount.controls = [ui.task_panel("Active recon", state["tasks"], _select_task)]
        try:
            page.update()
        except Exception:
            pass

    def _render_source_status(target_id: int | None) -> None:
        source_status.controls.clear()
        source_status.controls.append(ft.Text("Source status", size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT))
        if target_id is None:
            source_status.controls.append(ft.Text("No target selected", size=11, color=ui.MUTED))
            return
        rows = source_quality.recon_source_scores(target_id)
        if not rows:
            source_status.controls.append(ft.Text("No source status yet", size=11, color=ui.MUTED))
            return
        for row in rows:
            color = ui.DANGER if row["status"] == "failed" else ui.ACCENT
            source_status.controls.append(
                ft.Text(
                    f"{row['source_name']}: quality={float(row.get('quality_score', 0)):.2f} "
                    f"status={row['status']} records={row['record_count']} "
                    f"reasons={','.join(row.get('quality_reasons') or [])} error={row['last_error'] or '-'}",
                    size=10,
                    color=color if row["status"] == "failed" else ui.MUTED,
                    selectable=True,
                )
            )

    def _on_run(_):
        domain = domain_in.value.strip()
        if not domain:
            ui.notify(page, "Enter a domain")
            return
        status.value = f"Running passive recon on {domain}..."
        try:
            state["target_id"] = run_async(domain)
        except ValueError as exc:
            ui.notify(page, str(exc))
            return
        state["tasks"][f"recon:{state['target_id']}"] = {
            "id": state["target_id"],
            "label": f"Recon #{state['target_id']}  {domain}",
            "phase": "queued",
            "progress": 0.0,
            "status": "running",
            "created": time.time(),
        }
        selected_progress.value = 0
        _refresh()
        page.update()

    def _on_history_select(e):
        if not e.control.value:
            return
        state["target_id"] = int(e.control.value)
        _load_history()
        _render_results(state["target_id"])
        task = state["tasks"].get(f"recon:{state['target_id']}")
        selected_progress.value = float(task.get("progress", 0)) if task else 1
        page.update()

    def _select_task(e):
        if e.control.data is not None:
            state["target_id"] = int(e.control.data)
            _load_history()
            _render_results(state["target_id"])
            task = state["tasks"].get(f"recon:{state['target_id']}")
            selected_progress.value = float(task.get("progress", 0)) if task else 1
            page.update()

    run_btn = ui.action_button("Run recon", "RC", _on_run, width=132)

    def _export(_):
        if state["target_id"] is None:
            ui.notify(page, "Select or run a recon target first")
            return
        try:
            path = exporter.export_target(int(state["target_id"]))
        except Exception as exc:
            ui.notify(page, f"Export failed: {exc}")
            return
        ui.notify(page, f"Exported: {path}")

    export_btn = ui.action_button("Export TXT", "TXT", _export, width=128)
    def _export_report(fmt: str):
        def _inner(_):
            try:
                path = report_exporter.export_inventory(fmt)
            except Exception as exc:
                ui.notify(page, f"Export failed: {exc}")
                return
            ui.notify(page, f"Exported: {path}")
        return _inner

    report_exports = ft.Row(
        [
            ui.action_button("JSON", "JS", _export_report("json"), width=82),
            ui.action_button("CSV", "CSV", _export_report("csv"), width=78),
            ui.action_button("HTML", "HT", _export_report("html"), width=86),
            ui.action_button("SARIF", "SA", _export_report("sarif"), width=88),
            ui.action_button("STIX", "ST", _export_report("stix"), width=82),
            ui.action_button("MD", "MD", _export_report("md"), width=72),
        ],
        spacing=8,
        wrap=True,
    )
    history.on_select = _on_history_select

    unsub = events.subscribe("recon", _refresh)
    page._sf_cleanups = getattr(page, "_sf_cleanups", [])
    page._sf_cleanups.append(unsub)

    active_mount.controls = [ui.task_panel("Active recon", state["tasks"], _select_task)]
    _refresh()
    return ft.Column(
        [
            ft.Row(
                [
                    ft.Text("Passive recon (OSINT)", size=18, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                    active_mount,
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                vertical_alignment=ft.CrossAxisAlignment.START,
            ),
            ft.Text(
                "Passive only: DNS, RDAP, certificate-transparency subdomains and a "
                "single HTTP GET for tech detection. No active exploitation.",
                size=11, color=ui.MUTED,
            ),
            ft.Row([domain_in, run_btn, export_btn], spacing=10),
            report_exports,
            ui.panel(source_status, padding=12),
            history,
            status,
            selected_progress,
            ft.Divider(color=ui.BORDER),
            ft.Text("Findings", size=15, weight=ft.FontWeight.BOLD, color=ui.TEXT),
            results,
        ],
        expand=True,
        scroll=ft.ScrollMode.AUTO,
    )

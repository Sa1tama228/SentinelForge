from __future__ import annotations

from datetime import datetime, timezone
import time

import flet as ft

from ...core import config, db, events
from ...modules.scanner import scheduler
from ...modules.scanner.profiles import PROFILES, profile_options, resolve_profile
from ...modules.scanner.runner import cancel_scan, run_async
from .. import theme as ui

_TABLE_COLUMNS = ["Port", "Proto", "Service", "Version", "CVE refs", "Banner"]


def _results_table(rows: list) -> ft.Control:
    table = ft.DataTable(
        columns=[ft.DataColumn(ft.Text(c, color=ui.TEXT, weight=ft.FontWeight.BOLD)) for c in _TABLE_COLUMNS],
        rows=[],
        bgcolor=ui.PANEL,
        border=ui.border(),
        border_radius=8,
        heading_row_color=ui.PANEL_2,
        data_row_color=ui.PANEL,
        horizontal_margin=8,
        column_spacing=14,
        heading_row_height=34,
        data_row_min_height=30,
        data_row_max_height=34,
    )
    for row in rows:
        cve = row["cve_refs"] or ""
        table.rows.append(
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text(str(row["port"]), selectable=True, color=ui.TEXT)),
                    ft.DataCell(ft.Text(row["proto"] or "tcp", selectable=True, color=ui.TEXT)),
                    ft.DataCell(ft.Text(row["service"] or "?", selectable=True, color=ui.TEXT)),
                    ft.DataCell(ft.Text(row["version"] or "-", selectable=True, color=ui.TEXT)),
                    ft.DataCell(ft.Text(cve, size=12, color=ui.DANGER if cve else ui.TEXT, selectable=True)),
                    ft.DataCell(ft.Text((row["banner"] or "")[:90], size=11, selectable=True, color=ui.TEXT)),
                ]
            )
        )
    return table


def render(page: ft.Page) -> ft.Control:
    scheduler.ensure_started()
    cfg = config.load()
    scanner_cfg = cfg["scanner"]

    target_in = ft.TextField(
        label="Target",
        value="127.0.0.1",
        width=300,
        dense=True,
        **ui.input_kwargs(),
    )
    ports_in = ft.TextField(
        label="Ports",
        value=scanner_cfg["default_ports"],
        width=540,
        dense=True,
        **ui.input_kwargs(),
    )
    profile_select = ft.Dropdown(
        label="Profile",
        value=scanner_cfg.get("default_profile", "custom"),
        width=210,
        dense=True,
        options=[ft.dropdown.Option(key=key, text=label) for key, label in profile_options()],
        **ui.dropdown_kwargs(),
    )
    scan_type = ft.Dropdown(
        label="Scan type",
        value="vuln" if scanner_cfg.get("vulnerability_check_default", False) else "ports",
        width=190,
        dense=True,
        options=[
            ft.dropdown.Option(key="ports", text="Ports only"),
            ft.dropdown.Option(key="vuln", text="CVE exposure"),
        ],
        **ui.dropdown_kwargs(),
    )
    start_time = ft.TextField(
        label="Start time UTC",
        hint_text="YYYY-MM-DD HH:MM or blank = now",
        width=230,
        dense=True,
        **ui.input_kwargs(),
    )
    interval_hours = ft.TextField(
        label="Repeat hours",
        value="24",
        width=150,
        dense=True,
        **ui.input_kwargs(),
    )
    status = ft.Text("", size=12, color=ui.MUTED, selectable=True)
    selected_progress = ui.progress_bar(0, width=360)
    history = ft.Dropdown(label="Run history", expand=True, dense=True, menu_height=320, **ui.dropdown_kwargs())
    table_wrap = ft.Column([ft.Text("No results yet", color=ui.MUTED)], scroll=ft.ScrollMode.AUTO, expand=True)
    active_mount = ft.Column(spacing=8)
    schedule_mount = ft.Column(spacing=8)

    page._sf_scan_tasks = getattr(page, "_sf_scan_tasks", {})
    state = {
        "run_id": None,
        "profile": profile_select.value or "custom",
        "tasks": page._sf_scan_tasks,
    }

    def _scan_kwargs() -> tuple[str, str, bool, str]:
        target = (target_in.value or "").strip()
        ports = (ports_in.value or scanner_cfg["default_ports"]).strip()
        profile = resolve_profile(state["profile"], ports)
        effective_ports = profile.ports or ports
        return target, effective_ports, scan_type.value == "vuln", profile.key

    def _start_scan(*, target: str, ports: str, check_vulns: bool, profile_key: str) -> int:
        run_id = run_async(target, ports, check_vulns=check_vulns, profile_key=profile_key)
        state["run_id"] = run_id
        state["tasks"][f"scan:{run_id}"] = {
            "id": run_id,
            "label": f"Scan #{run_id}  {target}",
            "phase": "queued",
            "progress": 0.0,
            "status": "running",
            "created": time.time(),
        }
        return run_id

    def _load_history() -> None:
        rows = db.recent_scan_runs(limit=30)
        history.options = [
            ft.dropdown.Option(
                key=str(row["id"]),
                text=f"#{row['id']}  {row['target']}  ports={row['ports']}  {row['status']}  {row['ts']}",
            )
            for row in rows
        ] or [ft.dropdown.Option(key="", text="No saved scan runs")]
        history.value = str(state["run_id"]) if state["run_id"] else ""

    def _render_results() -> None:
        table_wrap.controls.clear()
        run_id = state["run_id"]
        if not run_id:
            table_wrap.controls.append(ft.Text("No run selected", color=ui.MUTED))
            return
        rows = db.scan_results_for_run(int(run_id))
        table_wrap.controls.append(_results_table(rows) if rows else ft.Text(f"Run #{run_id}: no open services", color=ui.MUTED))

    def _render_active() -> None:
        active_mount.controls = [
            ft.Text("Active Runs", size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT),
        ]
        active = [task for task in state["tasks"].values() if task.get("status") == "running"]
        if not active:
            active_mount.controls.append(ft.Text("No active scans", size=11, color=ui.MUTED))
            return
        for task in sorted(active, key=lambda item: item.get("created", 0), reverse=True)[:8]:
            cancel_btn = ui.action_button("Cancel", "X", _cancel_active, width=70, accent=ui.DANGER)
            cancel_btn.data = task["id"]
            active_mount.controls.append(
                ui.panel(
                    padding=8,
                    content=ft.Row(
                        [
                            ft.Column(
                                [
                                    ft.Text(task.get("label", "scan"), size=11, color=ui.TEXT, no_wrap=True),
                                    ui.progress_bar(float(task.get("progress", 0)), width=190),
                                    ft.Text(task.get("phase", "running"), size=10, color=ui.MUTED),
                                ],
                                spacing=4,
                                expand=True,
                            ),
                            cancel_btn,
                        ],
                        spacing=8,
                    ),
                )
            )

    def _render_schedules() -> None:
        schedule_mount.controls = [ft.Text("Schedules", size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT)]
        schedules = db.scan_schedules()
        if not schedules:
            schedule_mount.controls.append(ft.Text("No schedules", size=11, color=ui.MUTED))
            return
        for row in schedules:
            run_btn = ui.action_button("Run now", "RUN", _run_schedule_now, width=72)
            toggle_btn = ui.action_button("Disable" if row["enabled"] else "Enable", "ON" if not row["enabled"] else "OFF", _toggle_schedule, width=72)
            delete_btn = ui.action_button("Delete", "DEL", _delete_schedule, width=72, accent=ui.DANGER)
            for button in (run_btn, toggle_btn, delete_btn):
                button.data = int(row["id"])
            schedule_mount.controls.append(
                ui.panel(
                    padding=8,
                    content=ft.Column(
                        [
                            ft.Column(
                                [
                                    ft.Text(f"#{row['id']} {row['target']}  {row['profile_key']}  {'CVE' if row['check_vulns'] else 'Ports'}", size=12, color=ui.TEXT, selectable=True),
                                    ft.Text(
                                        f"Ports: {row['ports']} | every {row['interval_hours']}h | next: {row['next_run_ts'] or 'now'} | enabled: {bool(row['enabled'])}",
                                        size=10,
                                        color=ui.MUTED,
                                        selectable=True,
                                    ),
                                ],
                                spacing=2,
                            ),
                            ft.Row([run_btn, toggle_btn, delete_btn], spacing=8, wrap=True),
                        ],
                        spacing=8,
                    ),
                )
            )

    def _refresh(payload: dict | None = None) -> None:
        payload = payload or {}
        run_id = payload.get("run_id")
        phase = payload.get("phase")
        if run_id is not None:
            task = state["tasks"].setdefault(
                f"scan:{run_id}",
                {"id": run_id, "label": f"Scan #{run_id}", "phase": "queued", "progress": 0.0, "status": "running", "created": time.time()},
            )
            if payload.get("target"):
                task["label"] = f"Scan #{run_id}  {payload['target']}"
            task["phase"] = phase or task.get("phase", "running")
            task["progress"] = float(payload.get("progress", task.get("progress", 0)))
            if phase in {"done", "failed", "invalid", "cancelled"}:
                task["status"] = "done"
                task["progress"] = 1.0
        if run_id == state["run_id"]:
            selected_progress.value = float(payload.get("progress", selected_progress.value or 0))
            status.value = _status_text(payload)
        _load_history()
        _render_results()
        _render_active()
        _render_schedules()
        try:
            page.update()
        except Exception:
            pass

    def _status_text(payload: dict) -> str:
        phase = payload.get("phase")
        if phase == "done":
            delta = payload.get("delta") or {}
            return (
                f"Scan complete: {payload.get('open', 0)} open service(s); "
                f"added={len(delta.get('added', []))} removed={len(delta.get('removed', []))} changed={len(delta.get('changed', []))}"
            )
        if phase == "cancelled":
            return "Scan cancelled"
        if phase == "failed":
            return f"Scan failed: {payload.get('reason', 'unknown')}"
        if phase == "probe":
            probe = payload.get("probe") or {}
            return f"Host probe via {probe.get('engine', 'unknown')}: {probe.get('ok')}"
        if phase:
            return f"Scan {phase}"
        return status.value or ""

    def _scan_now(_):
        target, ports, check_vulns, profile_key = _scan_kwargs()
        if not target:
            ui.notify(page, "Enter a target")
            return
        run_id = _start_scan(target=target, ports=ports, check_vulns=check_vulns, profile_key=profile_key)
        status.value = f"Queued scan #{run_id}"
        _refresh({"run_id": run_id, "phase": "queued", "progress": 0.0})

    def _schedule_scan(_):
        target, ports, check_vulns, profile_key = _scan_kwargs()
        if not target:
            ui.notify(page, "Enter a target")
            return
        try:
            interval = int(interval_hours.value or "24")
            next_run = _parse_start_time(start_time.value or "")
            db.add_scan_schedule(
                target=target,
                ports=ports,
                profile_key=profile_key,
                check_vulns=check_vulns,
                interval_hours=interval,
                next_run_ts=next_run,
            )
        except Exception as exc:
            ui.notify(page, f"Schedule failed: {exc}")
            return
        ui.notify(page, "Schedule saved")
        _refresh()

    def _parse_start_time(value: str) -> str:
        value = value.strip()
        if not value:
            return db.now()
        for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
                return parsed.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
        raise ValueError("Start time must be YYYY-MM-DD HH:MM UTC")

    def _run_schedule_now(e) -> None:
        schedule_id = int(e.control.data)
        row = next((item for item in db.scan_schedules() if int(item["id"]) == schedule_id), None)
        if row is None:
            return
        run_id = _start_scan(
            target=row["target"],
            ports=row["ports"],
            check_vulns=bool(row["check_vulns"]),
            profile_key=row["profile_key"] or "custom",
        )
        db.update_scan_schedule(schedule_id, last_run_ts=db.now())
        ui.notify(page, f"Started scan #{run_id}")
        _refresh({"run_id": run_id, "phase": "queued", "progress": 0})

    def _toggle_schedule(e) -> None:
        schedule_id = int(e.control.data)
        row = next((item for item in db.scan_schedules() if int(item["id"]) == schedule_id), None)
        if row:
            db.update_scan_schedule(schedule_id, enabled=not bool(row["enabled"]))
            _refresh()

    def _delete_schedule(e) -> None:
        db.delete_scan_schedule(int(e.control.data))
        ui.notify(page, "Schedule deleted")
        _refresh()

    def _cancel_active(e) -> None:
        run_id = int(e.control.data)
        if cancel_scan(run_id):
            state["tasks"].setdefault(f"scan:{run_id}", {"id": run_id})["phase"] = "cancelling"
            ui.notify(page, f"Cancel requested for scan #{run_id}")
        else:
            ui.notify(page, "Scan is no longer cancellable")
        _refresh()

    def _clear_history(_):
        db.clear_scan_history()
        state["run_id"] = None
        state["tasks"].clear()
        ui.notify(page, "Scan history cleared")
        _refresh()

    def _profile_changed(e) -> None:
        state["profile"] = e.control.value or "custom"
        profile = PROFILES.get(state["profile"])
        if profile and profile.ports:
            ports_in.value = profile.ports
        page.update()

    def _history_selected(e) -> None:
        if e.control.value:
            state["run_id"] = int(e.control.value)
            _refresh()

    profile_select.on_select = _profile_changed
    history.on_select = _history_selected

    unsub_scan = events.subscribe("scanner", _refresh)
    unsub_sched = events.subscribe("scheduler", lambda _payload: _refresh())
    page._sf_cleanups = getattr(page, "_sf_cleanups", [])
    page._sf_cleanups.extend([unsub_scan, unsub_sched])

    _refresh()
    scan_setup_panel = ui.panel(
        padding=14,
        expand=True,
        height=260,
        content=ft.Column(
            [
                ft.Text("Scan Setup", size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                ft.Row([target_in, profile_select, scan_type], spacing=10, wrap=True),
                ports_in,
                ft.Row(
                    [
                        ui.action_button("Run scan", "RUN", _scan_now, width=108),
                        ui.action_button("Clear history", "CLR", _clear_history, width=124, accent=ui.WARN),
                    ],
                    spacing=10,
                ),
                selected_progress,
                status,
            ],
            spacing=10,
        ),
    )
    scheduling_panel = ui.panel(
        padding=14,
        expand=True,
        height=260,
        content=ft.Column(
            [
                ft.Text("Scheduling", size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                ft.Row(
                    [start_time, interval_hours, ui.action_button("Save schedule", "SAVE", _schedule_scan, width=128)],
                    spacing=10,
                    wrap=True,
                ),
                ft.Container(
                    height=155,
                    content=ft.Column([schedule_mount], scroll=ft.ScrollMode.AUTO, expand=True),
                ),
            ],
            spacing=10,
        ),
    )
    active_panel = ui.panel(active_mount, padding=14, expand=True, height=260)
    history_panel = ui.panel(
        ft.Column(
            [
                ft.Text("History", size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                history,
            ],
            spacing=8,
            expand=True,
        ),
        padding=14,
        expand=True,
        height=260,
    )
    return ft.Column(
        [
            ft.Row(
                [
                    ft.Text("Scanner", size=18, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                    ft.Text("Authorized targets only", size=12, color=ui.WARN),
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ),
            ft.Row([scan_setup_panel, scheduling_panel], spacing=12),
            ft.Row(
                [
                    active_panel,
                    history_panel,
                ],
                spacing=12,
            ),
            ui.panel(
                padding=12,
                expand=True,
                content=ft.Column(
                    [
                        ft.Text("Results", size=14, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                        table_wrap,
                    ],
                    spacing=8,
                    expand=True,
                ),
            ),
        ],
        expand=True,
        spacing=12,
        scroll=ft.ScrollMode.AUTO,
    )

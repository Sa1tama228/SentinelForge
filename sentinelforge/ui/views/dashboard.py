from __future__ import annotations

import logging
import threading
from collections.abc import Callable

import flet as ft

from ...core import events
from .. import theme as ui
from ..components import ActivityTable, MetricCard, OperationalSummaryPanel
from ..dashboard_service import DashboardActivityItem, DashboardService, DashboardSummary, OperationalSummary

logger = logging.getLogger(__name__)

_ACTIVITY_LIMIT = 5


def render(page: ft.Page, service: DashboardService | None = None) -> ft.Control:
    dashboard = service or DashboardService()
    state: dict[str, object] = {
        "activity_type": "",
        "severity": "",
        "search": "",
        "disposed": False,
        "refreshing": False,
        "pending_summary": False,
        "pending_activity": False,
        "search_timer": None,
        "event_timer": None,
    }
    state_lock = threading.Lock()

    metrics_row = ft.ResponsiveRow(spacing=12, run_spacing=12)
    metrics_row.controls = [MetricCard(metric) for metric in DashboardService._unavailable_metrics()]

    def _navigate(view: str) -> None:
        navigate = getattr(page, "_sf_navigate", None)
        if callable(navigate):
            navigate(view)

    def _select_activity(item: DashboardActivityItem) -> None:
        source_id = item.source_id or ""

        def _selected_id(prefix: str = "") -> int | None:
            value = source_id.removeprefix(prefix) if prefix else source_id
            try:
                return int(value)
            except ValueError:
                return None

        # Missing record IDs must not block navigation
        if item.item_type == "finding":
            page._sf_selected_finding_id = _selected_id()
            _navigate("findings")
            return
        if source_id.startswith("honeypot:"):
            page._sf_selected_honeypot_event_id = _selected_id("honeypot:")
            _navigate("honeypot")
        elif source_id.startswith("scan:"):
            page._sf_selected_scan_run_id = _selected_id("scan:")
            _navigate("scanner")
        elif source_id.startswith("recon:"):
            page._sf_selected_recon_finding_id = _selected_id("recon:")
            _navigate("recon")

    def _type_changed(value: str) -> None:
        state["activity_type"] = value
        _request_refresh(summary=False, activity=True)

    def _severity_changed(value: str) -> None:
        state["severity"] = value
        _request_refresh(summary=False, activity=True)

    def _search_changed(value: str) -> None:
        state["search"] = value
        timer = state.get("search_timer")
        if isinstance(timer, threading.Timer):
            timer.cancel()
        next_timer = threading.Timer(0.3, lambda: _request_refresh(summary=False, activity=True))
        next_timer.daemon = True
        state["search_timer"] = next_timer
        next_timer.start()

    activity_table = ActivityTable(
        on_type_change=_type_changed,
        on_severity_change=_severity_changed,
        on_search_change=_search_changed,
        on_select=_select_activity,
        on_new_scan=lambda _e: _navigate("scanner"),
    )
    operational = OperationalSummaryPanel(
        on_open_scanner=lambda _event: _navigate("scanner"),
        on_open_attack_paths=lambda _event: _navigate("attack_paths"),
    )

    def _mounted() -> bool:
        return not bool(state["disposed"]) and getattr(page, "_sf_current_view", "dashboard") == "dashboard"

    def _update_controls(*controls: ft.Control) -> None:
        if not _mounted():
            return
        try:
            for control in controls:
                control.update()
        except RuntimeError:
            try:
                page.update()
            except RuntimeError:
                logger.debug("Dashboard refresh skipped because controls are no longer mounted")

    def _apply_summary(summary: DashboardSummary) -> None:
        if not _mounted():
            return
        metrics_row.controls = [MetricCard(metric) for metric in summary.metrics]
        operational.set_summary(summary.operational)
        _update_controls(metrics_row, operational)

    def _unavailable_summary() -> DashboardSummary:
        message = "Dashboard data is currently unavailable"
        return DashboardSummary(
            metrics=DashboardService._unavailable_metrics(),
            operational=OperationalSummary(
                errors={key: message for key in ("active_scan", "exposed_service", "attack_paths", "honeypot")}
            ),
            errors={"metrics": message},
        )

    def _load(*, include_summary: bool, include_activity: bool) -> None:
        if not _mounted():
            return
        try:
            if include_summary:
                try:
                    _apply_summary(dashboard.get_summary())
                except Exception:
                    logger.exception("Dashboard summary refresh failed")
                    _apply_summary(_unavailable_summary())
            if include_activity and _mounted():
                try:
                    items = dashboard.get_activity(
                        activity_type=str(state["activity_type"]),
                        severity=str(state["severity"]),
                        search=str(state["search"]),
                        limit=_ACTIVITY_LIMIT,
                    )
                    activity_table.set_items(items)
                except Exception:
                    logger.exception("Dashboard activity refresh failed")
                    activity_table.set_error(
                        "Recent activity is unavailable; other Overview data remains usable"
                    )
                _update_controls(activity_table)
        finally:
            with state_lock:
                state["refreshing"] = False
                pending_summary = bool(state["pending_summary"])
                pending_activity = bool(state["pending_activity"])
                state["pending_summary"] = False
                state["pending_activity"] = False
            if (pending_summary or pending_activity) and _mounted():
                _request_refresh(summary=pending_summary, activity=pending_activity)

    def _request_refresh(*, summary: bool, activity: bool) -> None:
        if not _mounted():
            return
        with state_lock:
            if bool(state["refreshing"]):
                # Coalesce event bursts into one follow-up storage refresh
                state["pending_summary"] = bool(state["pending_summary"]) or summary
                state["pending_activity"] = bool(state["pending_activity"]) or activity
                return
            state["refreshing"] = True
        try:
            page.run_thread(_load, include_summary=summary, include_activity=activity)
        except Exception:
            with state_lock:
                state["refreshing"] = False
            raise

    def _event_refresh(_payload: dict | None = None) -> None:
        if not _mounted():
            return
        timer = state.get("event_timer")
        if isinstance(timer, threading.Timer):
            timer.cancel()
        next_timer = threading.Timer(0.15, lambda: _request_refresh(summary=True, activity=True))
        next_timer.daemon = True
        state["event_timer"] = next_timer
        next_timer.start()

    def _cleanup() -> None:
        state["disposed"] = True
        for key in ("search_timer", "event_timer"):
            timer = state.get(key)
            if isinstance(timer, threading.Timer):
                timer.cancel()

    unsubs: list[Callable[[], None]] = [
        events.subscribe(channel, _event_refresh) for channel in ("scanner", "recon", "honeypot", "jobs")
    ]

    def _full_cleanup() -> None:
        _cleanup()
        for unsubscribe in unsubs:
            unsubscribe()

    page._sf_cleanups = getattr(page, "_sf_cleanups", [])
    page._sf_cleanups.append(_full_cleanup)

    header = ft.ResponsiveRow(
        [
            ft.Container(
                col={"xs": 12, "lg": 4},
                content=ft.Row(
                    [
                        ft.Icon(ft.Icons.FOLDER_OUTLINED, size=28, color=ui.TEXT_SECONDARY),
                        ft.Column(
                            [
                                ft.Text("Local workspace", size=24, weight=ft.FontWeight.W_600, color=ui.TEXT),
                                ft.Text("Local findings and recorded activity", size=12, color=ui.TEXT_MUTED),
                            ],
                            spacing=4,
                        ),
                    ],
                    spacing=16,
                ),
            ),
            ft.Container(col={"xs": 12, "lg": 8}, content=metrics_row),
        ],
        spacing=24,
        run_spacing=16,
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
    )

    root = ft.Column(
        [
            header,
            ft.Divider(height=1, color=ui.BORDER),
            activity_table,
            ft.Divider(height=1, color=ui.BORDER),
            ft.ResponsiveRow(
                [
                    operational,
                    ft.Container(
                        col={"xs": 12, "lg": 6},
                        padding=ft.Padding(left=24, top=0, right=0, bottom=0),
                        content=ft.Column(
                            [
                                ft.Row(
                                    [
                                        ft.Icon(ft.Icons.PSYCHOLOGY_OUTLINED, size=24, color=ui.BRAND),
                                        ft.Text("AI observations", size=18, weight=ft.FontWeight.W_600, color=ui.TEXT),
                                    ],
                                    spacing=12,
                                ),
                                ft.Text("Local AI is not available in this build", size=14, color=ui.TEXT_SECONDARY),
                                ft.Text(
                                    "Inspect source records in Findings and Correlations", size=14, color=ui.TEXT_MUTED
                                ),
                            ],
                            spacing=16,
                        ),
                    ),
                ],
                spacing=24,
                run_spacing=12,
                vertical_alignment=ft.CrossAxisAlignment.START,
            ),
        ],
        spacing=14,
        expand=True,
        scroll=ft.ScrollMode.AUTO,
    )
    _request_refresh(summary=True, activity=True)
    return root

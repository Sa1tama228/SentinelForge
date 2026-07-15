from __future__ import annotations

from collections.abc import Callable

import flet as ft

from .. import theme as ui
from ..dashboard_service import DashboardActivityItem, DashboardMetric, OperationalSummary


def _accent(name: str) -> str:
    return {
        "critical": ui.CRITICAL,
        "brand": ui.BRAND,
        "info": ui.INFO_BLUE,
        "success": ui.SUCCESS_TEAL,
    }.get(name, ui.TEXT_SECONDARY)


class MetricCard(ft.Container):
    def __init__(self, metric: DashboardMetric) -> None:
        accent = _accent(metric.accent)
        super().__init__(
            height=128,
            padding=17,
            border_radius=ui.RADIUS_PANEL,
            bgcolor=ui.SURFACE,
            border=ui.border(),
            col={"xs": 12, "sm": 6, "md": 3},
            content=ft.Column(
                [
                    ft.Text(metric.title, size=12, color=ui.TEXT_SECONDARY, no_wrap=True),
                    ft.Text(metric.value, size=29, weight=ft.FontWeight.W_600, color=ui.TEXT_PRIMARY, no_wrap=True),
                    ft.Container(
                        width=48,
                        height=3,
                        border_radius=2,
                        bgcolor=accent if metric.available else ui.BORDER_STRONG,
                    ),
                    ft.Text(
                        metric.subtitle, size=11, color=accent if metric.available else ui.TEXT_MUTED, no_wrap=True
                    ),
                ],
                spacing=5,
            ),
        )


class StatusBadge(ft.Container):
    def __init__(self, label: str) -> None:
        normalized = label.strip().lower()
        color, background = {
            "critical": (ui.CRITICAL, ui.CRITICAL_SURFACE),
            "high": (ui.CRITICAL, ui.CRITICAL_SURFACE),
            "medium": (ui.WARNING, ui.WARNING_SURFACE),
            "low": (ui.INFO_BLUE, ui.INFO_SURFACE),
            "info": (ui.SUCCESS_TEAL, ui.SUCCESS_SURFACE),
            "running": (ui.SUCCESS_TEAL, ui.SUCCESS_SURFACE),
            "queued": (ui.INFO_BLUE, ui.INFO_SURFACE),
            "cancelling": (ui.WARNING, ui.WARNING_SURFACE),
        }.get(normalized, (ui.TEXT_SECONDARY, ui.SURFACE_ACTIVE))
        super().__init__(
            height=26,
            padding=ft.Padding(left=9, top=0, right=9, bottom=0),
            border_radius=7,
            bgcolor=background,
            alignment=ft.Alignment(0, 0),
            content=ft.Text(label.upper(), size=10, weight=ft.FontWeight.W_600, color=color, no_wrap=True),
        )


class LoadingState(ft.Container):
    def __init__(self, label: str = "Loading dashboard data...") -> None:
        super().__init__(
            height=180,
            alignment=ft.Alignment(0, 0),
            content=ft.Column(
                [
                    ft.ProgressRing(width=24, height=24, stroke_width=2, color=ui.BRAND),
                    ft.Text(label, size=12, color=ui.TEXT_MUTED),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                tight=True,
                spacing=12,
            ),
        )


class EmptyState(ft.Container):
    def __init__(self, title: str, message: str) -> None:
        super().__init__(
            height=190,
            alignment=ft.Alignment(0, 0),
            content=ft.Column(
                [
                    ft.Text("--", size=17, weight=ft.FontWeight.BOLD, color=ui.TEXT_MUTED),
                    ft.Text(title, size=13, weight=ft.FontWeight.W_600, color=ui.TEXT_PRIMARY),
                    ft.Text(message, size=11, color=ui.TEXT_MUTED, text_align=ft.TextAlign.CENTER),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                tight=True,
                spacing=7,
            ),
        )


def _pill(label: str, value: str, selected: bool, on_select: Callable[[str], None]) -> ft.Control:
    def _clicked(_event) -> None:
        on_select(value)

    return ft.Container(
        height=28,
        padding=ft.Padding(left=11, top=0, right=11, bottom=0),
        border_radius=7,
        bgcolor=ui.SURFACE_ACTIVE if selected else ui.SURFACE_SECONDARY,
        alignment=ft.Alignment(0, 0),
        ink=True,
        ink_color="#228B7CF6",
        on_click=_clicked,
        content=ft.Text(
            label.upper(),
            size=10,
            weight=ft.FontWeight.W_600,
            color=ui.TEXT_PRIMARY if selected else ui.TEXT_SECONDARY,
            no_wrap=True,
        ),
    )


def _cell(control: ft.Control, flex: int, *, padding: int = 0) -> ft.Control:
    return ft.Container(content=control, expand=flex, padding=ft.Padding(left=padding, top=0, right=padding, bottom=0))


class ActivityTable(ft.Container):
    def __init__(
        self,
        *,
        on_type_change: Callable[[str], None],
        on_severity_change: Callable[[str], None],
        on_search_change: Callable[[str], None],
        on_select: Callable[[DashboardActivityItem], None],
    ) -> None:
        self._on_type_change = on_type_change
        self._on_select = on_select
        self._selected_type = ""
        self._tabs = ft.Row(spacing=6)
        self._rows = ft.Column(spacing=0)
        self._footer = ft.Text("", size=10, color=ui.TEXT_MUTED)
        self._search = ft.TextField(
            hint_text="Search activity...",
            height=36,
            dense=True,
            text_size=11,
            on_change=lambda event: on_search_change(event.control.value or ""),
            **ui.input_kwargs(),
        )
        self._severity = ft.Dropdown(
            value="",
            height=38,
            dense=True,
            text_size=11,
            on_select=lambda event: on_severity_change(event.control.value or ""),
            options=[
                ft.dropdown.Option(key="", text="Severity: all"),
                ft.dropdown.Option(key="Critical", text="Critical"),
                ft.dropdown.Option(key="High", text="High"),
                ft.dropdown.Option(key="Medium", text="Medium"),
                ft.dropdown.Option(key="Low", text="Low"),
                ft.dropdown.Option(key="Info", text="Info"),
            ],
            **ui.dropdown_kwargs(),
        )
        self._render_tabs()
        toolbar = ft.ResponsiveRow(
            [
                ft.Container(content=self._tabs, col={"xs": 12, "md": 6}),
                ft.Container(content=self._search, col={"xs": 8, "md": 4}),
                ft.Container(content=self._severity, col={"xs": 4, "md": 2}),
            ],
            spacing=8,
            run_spacing=8,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )
        super().__init__(
            padding=0,
            border_radius=ui.RADIUS_PANEL,
            bgcolor=ui.SURFACE,
            border=ui.border(),
            col=12,
            content=ft.Column(
                [
                    ft.Container(
                        padding=ft.Padding(left=18, top=16, right=18, bottom=10),
                        content=ft.Column(
                            [
                                ft.Text(
                                    "Activity & findings",
                                    size=16,
                                    weight=ft.FontWeight.W_600,
                                    color=ui.TEXT_PRIMARY,
                                ),
                                toolbar,
                            ],
                            spacing=10,
                        ),
                    ),
                    ft.Divider(height=1, color=ui.BORDER),
                    self._table_header(),
                    self._rows,
                    ft.Container(
                        padding=ft.Padding(left=18, top=12, right=18, bottom=12),
                        content=self._footer,
                    ),
                ],
                spacing=0,
            ),
        )
        self.set_loading()

    def _render_tabs(self) -> None:
        self._tabs.controls = [
            _pill(label, value, self._selected_type == value, self._set_type)
            for label, value in (("All", ""), ("Signals", "signal"), ("Findings", "finding"))
        ]

    def _set_type(self, value: str) -> None:
        self._selected_type = value
        self._render_tabs()
        self._on_type_change(value)

    @staticmethod
    def _table_header() -> ft.Control:
        labels = (("TIME", 10), ("SEVERITY", 13), ("TYPE", 11), ("TITLE", 29), ("ASSET", 24), ("SOURCE", 13))
        return ft.Container(
            height=34,
            padding=ft.Padding(left=18, top=0, right=18, bottom=0),
            alignment=ft.Alignment(-1, 0),
            content=ft.Row(
                [
                    _cell(
                        ft.Text(label, size=9, weight=ft.FontWeight.W_600, color=ui.TEXT_MUTED, no_wrap=True),
                        flex,
                    )
                    for label, flex in labels
                ],
                spacing=6,
            ),
        )

    def set_loading(self) -> None:
        self._rows.controls = [LoadingState("Loading recent activity...")]
        self._footer.value = ""

    def set_error(self, message: str) -> None:
        self._rows.controls = [EmptyState("Activity unavailable", message)]
        self._footer.value = ""

    def set_items(self, items: list[DashboardActivityItem]) -> None:
        if not items:
            self._rows.controls = [
                EmptyState("No matching activity", "New findings and operational signals will appear here."),
            ]
            self._footer.value = "No recent items"
            return
        self._rows.controls = [self._activity_row(item) for item in items]
        self._footer.value = f"Showing {len(items)} most recent item{'s' if len(items) != 1 else ''}"

    def _activity_row(self, item: DashboardActivityItem) -> ft.Control:
        def _selected(_event) -> None:
            self._on_select(item)

        time_label = item.timestamp.strftime("%H:%M") if item.timestamp is not None else "--:--"
        return ft.Container(
            height=49,
            padding=ft.Padding(left=18, top=0, right=18, bottom=0),
            border=ft.Border(bottom=ft.BorderSide(1, ui.BORDER)),
            alignment=ft.Alignment(-1, 0),
            ink=True,
            ink_color="#168B7CF6",
            on_click=_selected,
            tooltip=f"Open {item.item_type} context",
            content=ft.Row(
                [
                    _cell(ft.Text(time_label, size=10, color=ui.TEXT_MUTED), 10),
                    _cell(ft.Row([StatusBadge(item.severity)], spacing=0), 13),
                    _cell(ft.Text(item.item_type.title(), size=10, color=ui.TEXT_SECONDARY, no_wrap=True), 11),
                    _cell(
                        ft.Text(item.title, size=11, weight=ft.FontWeight.W_500, color=ui.TEXT_PRIMARY, no_wrap=True),
                        29,
                    ),
                    _cell(ft.Text(item.asset, size=10, color=ui.TEXT_SECONDARY, no_wrap=True), 24),
                    _cell(ft.Text(item.source, size=10, color=ui.TEXT_MUTED, no_wrap=True), 13),
                ],
                spacing=6,
            ),
        )


def _summary_section(label: str, primary: ft.Control, secondary: str = "") -> ft.Control:
    controls: list[ft.Control] = [
        ft.Text(label, size=10, weight=ft.FontWeight.W_500, color=ui.TEXT_MUTED),
        primary,
    ]
    if secondary:
        controls.append(ft.Text(secondary, size=10, color=ui.TEXT_SECONDARY, no_wrap=True))
    return ft.Container(
        padding=ft.Padding(left=0, top=15, right=0, bottom=15),
        border=ft.Border(bottom=ft.BorderSide(1, ui.BORDER)),
        content=ft.Column(controls, spacing=6),
    )


def _panel_button(label: str, on_click: Callable, *, primary: bool = False) -> ft.Control:
    return ft.Container(
        height=38,
        expand=True,
        border_radius=ui.RADIUS_CONTROL,
        bgcolor=ui.BRAND_DARK if primary else ui.SURFACE_SECONDARY,
        border=ui.border(ui.BRAND if primary else ui.BORDER_STRONG),
        alignment=ft.Alignment(0, 0),
        ink=True,
        ink_color="#338B7CF6",
        on_click=on_click,
        content=ft.Text(
            label,
            size=11,
            weight=ft.FontWeight.W_600,
            color=ui.TEXT_PRIMARY if primary else ui.TEXT_SECONDARY,
            no_wrap=True,
        ),
    )


class OperationalSummaryPanel(ft.Container):
    def __init__(self, *, on_open_scanner: Callable, on_open_attack_paths: Callable) -> None:
        self._sections = ft.Column(spacing=0)
        self._on_open_scanner = on_open_scanner
        self._on_open_attack_paths = on_open_attack_paths
        super().__init__(
            padding=17,
            border_radius=ui.RADIUS_PANEL,
            bgcolor=ui.SURFACE,
            border=ui.border(),
            col={"xs": 12, "xl": 3},
            content=ft.Column(
                [
                    ft.Text("Operational summary", size=15, weight=ft.FontWeight.W_600, color=ui.TEXT_PRIMARY),
                    ft.Text("Current environment health", size=10, color=ui.TEXT_MUTED),
                    ft.Divider(height=1, color=ui.BORDER),
                    self._sections,
                    ft.Row(
                        [
                            _panel_button("Open scanner", on_open_scanner, primary=True),
                            _panel_button("View attack paths", on_open_attack_paths),
                        ],
                        spacing=10,
                    ),
                ],
                spacing=10,
            ),
        )
        self.set_loading()

    def set_loading(self) -> None:
        self._sections.controls = [LoadingState("Loading operational context...")]

    def set_summary(self, summary: OperationalSummary) -> None:
        self._sections.controls = [
            self._active_scan(summary),
            self._exposed_service(summary),
            self._attack_paths(summary),
            self._honeypot(summary),
        ]

    @staticmethod
    def _error(summary: OperationalSummary, key: str) -> ft.Control | None:
        message = summary.errors.get(key)
        if not message:
            return None
        return ft.Text(message, size=11, color=ui.TEXT_SECONDARY)

    def _active_scan(self, summary: OperationalSummary) -> ft.Control:
        error = self._error(summary, "active_scan")
        if error is not None:
            return _summary_section("Active scan", error)
        scan = summary.active_scan
        if scan is None:
            return _summary_section(
                "Active scan",
                ft.Text("No scan is currently running", size=12, color=ui.TEXT_SECONDARY),
            )
        progress = f"{int(scan.progress * 100)}% complete" if scan.progress is not None else "Progress unavailable"
        return _summary_section(
            "Active scan",
            ft.Row(
                [
                    ft.Text(
                        scan.target,
                        size=12,
                        weight=ft.FontWeight.W_600,
                        color=ui.TEXT_PRIMARY,
                        no_wrap=True,
                        expand=True,
                    ),
                    StatusBadge(scan.status),
                ],
                spacing=8,
            ),
            progress,
        )

    def _exposed_service(self, summary: OperationalSummary) -> ft.Control:
        error = self._error(summary, "exposed_service")
        if error is not None:
            return _summary_section("Top exposed service", error)
        service = summary.exposed_service
        if service is None:
            return _summary_section(
                "Top exposed service",
                ft.Text("No public service exposure observed", size=12, color=ui.TEXT_SECONDARY),
            )
        detail = f"{service.detail} - {service.asset}" if service.asset else service.detail
        return _summary_section(
            "Top exposed service",
            ft.Text(service.title, size=14, weight=ft.FontWeight.W_600, color=ui.TEXT_PRIMARY, no_wrap=True),
            detail,
        )

    def _attack_paths(self, summary: OperationalSummary) -> ft.Control:
        error = self._error(summary, "attack_paths")
        if error is not None:
            return _summary_section("Attack path pressure", error)
        pressure = summary.attack_paths
        if pressure is None or (pressure.high_confidence == 0 and pressure.highest_score == 0):
            return _summary_section(
                "Attack path pressure",
                ft.Text("No attack paths generated", size=12, color=ui.TEXT_SECONDARY),
            )
        return _summary_section(
            "Attack path pressure",
            ft.Text(
                f"{pressure.high_confidence} high-confidence path{'s' if pressure.high_confidence != 1 else ''}",
                size=13,
                weight=ft.FontWeight.W_600,
                color=ui.TEXT_PRIMARY,
            ),
            f"Highest score: {pressure.highest_score:.1f}",
        )

    def _honeypot(self, summary: OperationalSummary) -> ft.Control:
        error = self._error(summary, "honeypot")
        if error is not None:
            return _summary_section("Honeypot activity", error)
        activity = summary.honeypot
        if activity is None or activity.events == 0:
            return _summary_section(
                "Honeypot activity",
                ft.Text("No honeypot events recorded", size=12, color=ui.TEXT_SECONDARY),
            )
        return _summary_section(
            "Honeypot activity",
            ft.Text(
                f"{activity.events} events - {activity.source_ips} source IP{'s' if activity.source_ips != 1 else ''}",
                size=13,
                weight=ft.FontWeight.W_600,
                color=ui.TEXT_PRIMARY,
            ),
            activity.last_event,
        )

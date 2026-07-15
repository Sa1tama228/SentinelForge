from __future__ import annotations

import logging
from collections.abc import Callable

import flet as ft

from ..core import config
from . import theme as ui

logger = logging.getLogger(__name__)

VIEWS = [
    ("dashboard", "Dashboard", "DB", "DB"),
    ("assets", "Assets", "AS", "AS"),
    ("findings", "Findings", "FN", "FN"),
    ("attack_paths", "Attack Paths", "AP", "AP"),
    ("honeypot", "Honeypot", "HP", "HP"),
    ("scanner", "Scanner", "SC", "SC"),
    ("recon", "Recon", "RC", "RC"),
    ("settings", "Settings", "ST", "ST"),
]


def _cleanup_view(page: ft.Page) -> None:
    cleanups = getattr(page, "_sf_cleanups", [])
    page._sf_cleanups = []
    for cleanup in cleanups:
        try:
            cleanup()
        except Exception:
            logger.exception("SentinelForge view cleanup failed")


def _view_factory(key: str, page: ft.Page) -> ft.Control:
    module = __import__(f"sentinelforge.ui.views.{key}", fromlist=["render"])
    return module.render(page)


def _sidebar_header(collapsed: bool) -> ft.Control:
    if collapsed:
        return ft.Container(
            height=68,
            alignment=ft.Alignment(0, 0),
            border=ft.Border(bottom=ft.BorderSide(1, ui.BORDER)),
            content=ft.Text("SF", size=13, weight=ft.FontWeight.BOLD, color=ui.BRAND),
        )
    return ft.Container(
        height=68,
        padding=ft.Padding(left=18, top=13, right=14, bottom=10),
        border=ft.Border(bottom=ft.BorderSide(1, ui.BORDER)),
        content=ft.Column(
            [
                ft.Row(
                    [
                        ft.Text("SF", size=13, weight=ft.FontWeight.BOLD, color=ui.BRAND),
                        ft.Text("SentinelForge", size=18, weight=ft.FontWeight.BOLD, color=ui.TEXT_PRIMARY),
                    ],
                    spacing=16,
                ),
                ft.Text("defensive security workspace", size=9, color=ui.TEXT_MUTED),
            ],
            spacing=1,
        ),
    )


def _nav_button(
    idx: int,
    *,
    selected: bool,
    collapsed: bool,
    on_click: Callable,
) -> ft.Control:
    _key, label, icon, _selected_icon = VIEWS[idx]

    def _hover(event) -> None:
        if selected:
            return
        event.control.bgcolor = ui.SURFACE_SECONDARY if event.data == "true" else None
        event.control.update()

    controls: list[ft.Control] = [
        ft.Text(
            icon,
            size=10,
            weight=ft.FontWeight.W_600,
            color=ui.BRAND if selected else ui.TEXT_MUTED,
            no_wrap=True,
        )
    ]
    if not collapsed:
        controls.append(
            ft.Text(
                label,
                size=12,
                weight=ft.FontWeight.W_600 if selected else ft.FontWeight.NORMAL,
                color=ui.TEXT_PRIMARY if selected else ui.TEXT_SECONDARY,
                no_wrap=True,
            )
        )
    return ft.Container(
        height=42,
        margin=ft.Margin(left=10, top=0, right=10, bottom=0),
        padding=ft.Padding(left=16 if not collapsed else 0, top=0, right=10, bottom=0),
        alignment=ft.Alignment(0 if collapsed else -1, 0),
        border_radius=8,
        bgcolor=ui.SURFACE_ACTIVE if selected else None,
        ink=True,
        ink_color="#228B7CF6",
        data=idx,
        tooltip=label if collapsed else None,
        on_hover=_hover,
        on_click=on_click,
        content=ft.Row(
            controls,
            spacing=20,
            alignment=ft.MainAxisAlignment.CENTER if collapsed else ft.MainAxisAlignment.START,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
    )


def _workspace_selector(collapsed: bool) -> ft.Control:
    if collapsed:
        return ft.Container(
            height=52,
            margin=10,
            border_radius=9,
            bgcolor=ui.SURFACE,
            border=ui.border(),
            alignment=ft.Alignment(0, 0),
            tooltip="Workspace: Local lab",
            content=ft.Text("LL", size=10, weight=ft.FontWeight.W_600, color=ui.TEXT_SECONDARY),
        )
    return ft.Container(
        padding=ft.Padding(left=12, top=0, right=12, bottom=18),
        content=ft.Column(
            [
                ft.Text("WORKSPACE", size=9, weight=ft.FontWeight.W_600, color=ui.TEXT_MUTED),
                ft.Container(
                    height=52,
                    padding=ft.Padding(left=16, top=0, right=14, bottom=0),
                    border_radius=9,
                    bgcolor=ui.SURFACE,
                    border=ui.border(),
                    content=ft.Row(
                        [
                            ft.Text("Local lab", size=12, color=ui.TEXT_SECONDARY),
                            ft.Text("v", size=10, color=ui.TEXT_MUTED),
                        ],
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    ),
                ),
            ],
            spacing=7,
        ),
    )


def _top_action(label: str, on_click: Callable | None, *, tooltip: str) -> ft.Control:
    return ft.Container(
        width=34,
        height=34,
        border_radius=8,
        alignment=ft.Alignment(0, 0),
        ink=on_click is not None,
        ink_color="#228B7CF6",
        on_click=on_click,
        tooltip=tooltip,
        content=ft.Text(label, size=14, color=ui.TEXT_SECONDARY if on_click else ui.TEXT_MUTED),
    )


def _new_scan_button(on_click: Callable) -> ft.Control:
    return ft.Container(
        width=110,
        height=38,
        border_radius=8,
        bgcolor=ui.BRAND_DARK,
        border=ui.border(ui.BRAND),
        alignment=ft.Alignment(0, 0),
        ink=True,
        ink_color="#338B7CF6",
        on_click=on_click,
        content=ft.Text("New scan", size=11, weight=ft.FontWeight.W_600, color=ui.TEXT_PRIMARY),
    )


def _main(page: ft.Page) -> None:
    config.load()
    page.title = "SentinelForge"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = ui.BACKGROUND
    page.padding = 0
    page.spacing = 0
    page.window.min_width = 1180
    page.window.min_height = 680
    page.window.width = 1600
    page.window.height = 1000

    state = {"selected": 0, "collapsed": False}
    nav_items = ft.Column(spacing=4)
    sidebar = ft.Container(
        width=220,
        bgcolor=ui.SIDEBAR_BACKGROUND,
        border=ft.Border(right=ft.BorderSide(1, ui.BORDER)),
    )
    content = ft.Container(
        expand=True,
        padding=ui.SPACE_PAGE,
        alignment=ft.Alignment(-1, -1),
        bgcolor=ui.BACKGROUND,
    )
    top_bar = ft.Container(
        height=64,
        bgcolor=ui.TOPBAR_BACKGROUND,
        border=ft.Border(bottom=ft.BorderSide(1, "#101522")),
        padding=ft.Padding(left=18, top=0, right=18, bottom=0),
    )
    workspace = ft.Column([top_bar, content], spacing=0, expand=True)
    body = ft.Row([sidebar, workspace], expand=True, spacing=0)

    def _rebuild_sidebar() -> None:
        collapsed = bool(state["collapsed"])
        sidebar.width = 72 if collapsed else 220
        sidebar_toggle.tooltip = "Expand sidebar" if collapsed else "Collapse sidebar"
        nav_items.controls = [
            _nav_button(
                idx,
                selected=idx == state["selected"],
                collapsed=collapsed,
                on_click=_on_nav,
            )
            for idx in range(len(VIEWS))
        ]
        sidebar.content = ft.Column(
            [
                _sidebar_header(collapsed),
                ft.Container(padding=ft.Padding(left=0, top=16, right=0, bottom=0), content=nav_items),
                ft.Container(expand=True),
                _workspace_selector(collapsed),
            ],
            spacing=0,
            expand=True,
        )

    def _render(idx: int) -> None:
        _cleanup_view(page)
        key = VIEWS[idx][0]
        page._sf_current_view = key
        try:
            control = _view_factory(key, page)
        except Exception as exc:  # pragma: no cover - last-resort UI guard
            logger.exception("Failed to render SentinelForge view %s", key)
            # Release listeners or timers registered before the failed render.
            _cleanup_view(page)
            control = ft.Container(
                padding=16,
                border_radius=ui.RADIUS_CONTROL,
                bgcolor=ui.CRITICAL_SURFACE,
                content=ft.Text(
                    f"Failed to load '{key}': {exc}",
                    color=ui.TEXT_PRIMARY,
                    selectable=True,
                ),
            )
        content.content = ft.Container(key=f"view:{key}", content=control, expand=True, bgcolor=ui.BACKGROUND)
        page.update()

    def _navigate(view: str | int) -> None:
        if isinstance(view, int):
            idx = view
        else:
            idx = next((i for i, item in enumerate(VIEWS) if item[0] == view), 0)
        state["selected"] = max(0, min(idx, len(VIEWS) - 1))
        _rebuild_sidebar()
        _render(int(state["selected"]))

    def _on_nav(event) -> None:
        _navigate(int(event.control.data))

    def _toggle_sidebar(_event) -> None:
        state["collapsed"] = not state["collapsed"]
        _rebuild_sidebar()
        page.update()

    def _go_scanner(_event) -> None:
        _navigate("scanner")

    def _go_settings(_event) -> None:
        _navigate("settings")

    global_search = ft.TextField(
        hint_text="Search assets, findings, scans...",
        read_only=True,
        height=36,
        dense=True,
        text_size=11,
        tooltip="Global search is planned; Dashboard activity search is available below.",
        **ui.input_kwargs(),
    )
    sidebar_toggle = _top_action("☰", _toggle_sidebar, tooltip="Collapse sidebar")
    top_bar.content = ft.Row(
        [
            sidebar_toggle,
            ft.Container(content=global_search, width=430),
            ft.Container(expand=True),
            _new_scan_button(_go_scanner),
            _top_action("?", None, tooltip="Help is not available yet"),
            _top_action("⚙", _go_settings, tooltip="Settings"),
            ft.Container(
                width=34,
                height=34,
                border_radius=17,
                bgcolor=ui.SURFACE_SECONDARY,
                alignment=ft.Alignment(0, 0),
                content=ft.Text("AR", size=9, weight=ft.FontWeight.W_600, color=ui.TEXT_SECONDARY),
            ),
        ],
        spacing=12,
        vertical_alignment=ft.CrossAxisAlignment.CENTER,
    )

    page._sf_navigate = _navigate
    page.on_close = lambda _event: _cleanup_view(page)
    page.add(body)
    _rebuild_sidebar()
    _render(0)


def run() -> None:
    ft.run(_main, view=ft.AppView.FLET_APP)


if __name__ == "__main__":
    run()

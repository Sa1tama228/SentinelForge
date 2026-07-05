"""Main Flet shell: sidebar navigation that swaps between module views."""
from __future__ import annotations

import os

import flet as ft

from ..core import config
from . import theme as ui

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


def _build_header() -> ft.Control:
    return ft.Container(
        padding=ft.Padding(left=18, top=18, right=18, bottom=12),
        height=92,
        content=ft.Column(
            [
                ft.Row(
                    [
                        ui.badge("SF", width=36),
                        ft.Text(
                            "SentinelForge",
                            size=22,
                            weight=ft.FontWeight.BOLD,
                            color=ui.TEXT,
                        ),
                    ],
                    spacing=10,
                ),
                ft.Text(
                    "honeypot - vuln-scan - recon  (authorized use only)",
                    size=11,
                    color=ui.MUTED,
                ),
            ],
            spacing=2,
        ),
    )


def _cleanup_view(page: ft.Page) -> None:
    cleanups = getattr(page, "_sf_cleanups", [])
    for cleanup in cleanups:
        try:
            cleanup()
        except Exception:
            pass
    page._sf_cleanups = []


def _nav_button(idx: int, selected: bool, on_click) -> ft.Control:
    _key, label, icon, _sel_icon = VIEWS[idx]
    def _hover(e):
        if selected:
            return
        e.control.bgcolor = ui.PANEL_2 if e.data == "true" else ui.PANEL
        e.control.scale = 1.018 if e.data == "true" else 1
        e.control.border = ui.border(ui.ACCENT if e.data == "true" else ui.BORDER)
        e.control.update()

    return ft.Container(
        height=46,
        padding=ft.Padding(left=14, top=0, right=14, bottom=0),
        border_radius=8,
        bgcolor=ui.PANEL_SELECTED if selected else ui.PANEL,
        border=ui.border(ui.ACCENT if selected else ui.BORDER),
        animate=ui.MOTION,
        animate_scale=ui.MOTION_FAST,
        ink=True,
        ink_color="#6d28d99f",
        data=idx,
        on_hover=_hover,
        on_click=on_click,
        content=ft.Row(
            [
                ft.Text(
                    icon,
                    size=11,
                    weight=ft.FontWeight.BOLD,
                    color=ui.ACCENT if selected else ui.MUTED,
                ),
                ft.Text(
                    label,
                    size=13,
                    weight=ft.FontWeight.BOLD if selected else None,
                    color=ui.TEXT if selected else ui.MUTED,
                ),
            ],
            spacing=10,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
    )


def _view_factory(key: str, page: ft.Page) -> ft.Control:
    # Lazy import so a broken module never breaks the whole app.
    mod = __import__(f"sentinelforge.ui.views.{key}", fromlist=["render"])
    return mod.render(page)


def _main(page: ft.Page) -> None:
    config.load()
    page.title = "SentinelForge"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = ui.BG
    page.padding = 0
    page.spacing = 0

    state = {"selected": 0}
    nav_items = ft.Column(spacing=4)

    sidebar = ft.Container(
        width=230,
        bgcolor=ui.PANEL,
        border=ft.Border(right=ft.BorderSide(1, ui.BORDER)),
        content=ft.Column(
            [
                _build_header(),
                ft.Container(
                    padding=ft.Padding(left=10, top=0, right=10, bottom=10),
                    content=nav_items,
                ),
            ],
            spacing=0,
        ),
    )

    content = ft.Container(
        expand=True,
        padding=20,
        alignment=ft.Alignment(-1, -1),
        bgcolor=ui.BG,
    )
    body = ft.Row([sidebar, content], expand=True, spacing=0)
    page.add(body)

    def _rebuild_nav() -> None:
        nav_items.controls = [
            _nav_button(i, i == state["selected"], _on_nav)
            for i in range(len(VIEWS))
        ]

    def _render(idx: int) -> None:
        _cleanup_view(page)
        key = VIEWS[idx][0]
        try:
            control = _view_factory(key, page)
        except Exception as exc:  # pragma: no cover - UI guard
            control = ft.Container(
                padding=16,
                border_radius=8,
                bgcolor="#2a1224",
                content=ft.Text(
                    f"Failed to load '{key}': {exc}",
                    color="#ffe4f1",
                    selectable=True,
                ),
            )
        content.content = ft.Container(
            key=f"view:{key}",
            content=control,
            expand=True,
            bgcolor=ui.BG,
        )
        page.update()

    def _on_nav(e) -> None:
        idx = int(e.control.data)
        if idx == state["selected"]:
            return
        state["selected"] = idx
        _rebuild_nav()
        _render(idx)

    # Initial view.
    _rebuild_nav()
    _render(0)


def run() -> None:
    view = ft.AppView.WEB_BROWSER if os.environ.get("SF_VIEW") == "web" else ft.AppView.FLET_APP
    ft.run(_main, view=view)


if __name__ == "__main__":
    run()

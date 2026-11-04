from __future__ import annotations

import logging
from pathlib import Path

import flet as ft

from ..core import config, events, jobs
from . import theme as ui
from .workspace import WorkspaceTabs

logger = logging.getLogger(__name__)
ASSETS_DIR = Path(__file__).resolve().parents[1] / "resources"
VIEWS = [
    ("dashboard", "Overview", "DB", "DB"),
    ("scanner", "Scanner", "SC", "SC"),
    ("findings", "Findings", "FN", "FN"),
    ("assets", "Assets", "AS", "AS"),
    ("attack_paths", "Correlations", "AP", "AP"),
    ("ai_workspace", "AI Workspace", "AI", "AI"),
    ("honeypot", "Honeypots", "HP", "HP"),
    ("recon", "Recon", "RC", "RC"),
    ("settings", "Settings", "ST", "ST"),
]
_NAV_ICONS = {
    "dashboard": ft.Icons.HOME_OUTLINED,
    "scanner": ft.Icons.PLAY_ARROW_OUTLINED,
    "findings": ft.Icons.BUG_REPORT_OUTLINED,
    "assets": ft.Icons.LAYERS_OUTLINED,
    "attack_paths": ft.Icons.ACCOUNT_TREE_OUTLINED,
    "ai_workspace": ft.Icons.PSYCHOLOGY_OUTLINED,
    "honeypot": ft.Icons.SHIELD_OUTLINED,
    "recon": ft.Icons.TRAVEL_EXPLORE,
    "settings": ft.Icons.SETTINGS_OUTLINED,
}


def _cleanup_view(page: ft.Page) -> None:
    """Release view listeners and timers without cancelling background jobs"""
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


def _main(page: ft.Page) -> None:
    config.load()
    page.title = "SentinelForge"
    page.fonts = {"Inter": "fonts/Inter.ttf"}
    page.theme_mode = ft.ThemeMode.DARK
    page.theme = ft.Theme(
        font_family="Inter",
        color_scheme_seed=ui.BRAND,
        text_theme=ft.TextTheme(
            body_large=ft.TextStyle(size=16),
            body_medium=ft.TextStyle(size=14),
            body_small=ft.TextStyle(size=12),
            label_large=ft.TextStyle(size=14),
        ),
    )
    page.bgcolor, page.padding, page.spacing = ui.BACKGROUND, 0, 0
    page.window.min_width, page.window.min_height = 1180, 680
    page.window.width, page.window.height = 1672, 960
    page.window.title_bar_hidden = True
    # The shell owns tab keys; each mounted view owns its form state
    tabs = WorkspaceTabs()
    state = {"collapsed": False, "palette": None}
    sidebar = ft.Container(
        width=160, bgcolor=ui.SIDEBAR_BACKGROUND, border=ft.Border(right=ft.BorderSide(1, ui.BORDER))
    )
    tab_row = ft.Row(spacing=0, scroll=ft.ScrollMode.AUTO, expand=True)
    content = ft.Container(expand=True, padding=24, alignment=ft.Alignment(-1, -1), bgcolor=ui.BACKGROUND)
    task_label = ft.Text("Background tasks: 0", size=12, color=ui.TEXT_SECONDARY)
    status_label = ft.Text("Ready", size=12, color=ui.TEXT_SECONDARY)

    def icon_button(icon, tooltip, callback):
        return ft.IconButton(
            icon=icon,
            tooltip=tooltip,
            width=44,
            height=44,
            on_click=callback,
            style=ui.button_style(background=ui.BACKGROUND, outlined=False, padding=0),
        )

    def rebuild_sidebar():
        collapsed = state["collapsed"]
        sidebar.width = 64 if collapsed else 160

        def destination(index, key, label):
            selected = key == tabs.active
            parts = [ft.Icon(_NAV_ICONS[key], size=20, color=ui.TEXT_SECONDARY)]
            if not collapsed:
                parts.append(ft.Text(label, size=14, color=ui.TEXT, no_wrap=True))
            return ft.Container(
                height=44,
                margin=ft.Margin(left=6, top=0, right=6, bottom=0),
                border=ft.Border(left=ft.BorderSide(3, ui.BRAND if selected else ft.Colors.TRANSPARENT)),
                content=ft.Button(
                    height=44,
                    expand=True,
                    elevation=0,
                    data=index,
                    tooltip=label,
                    on_click=lambda e: navigate(int(e.control.data)),
                    style=ui.button_style(
                        background=ui.SURFACE_ACTIVE if selected else ui.SIDEBAR_BACKGROUND, outlined=False, padding=8
                    ),
                    content=ft.Row(
                        parts,
                        spacing=10,
                        alignment=ft.MainAxisAlignment.CENTER if collapsed else ft.MainAxisAlignment.START,
                    ),
                ),
            )

        primary, tools = [], []
        for i, (key, label, *_) in enumerate(VIEWS):
            (tools if key in {"settings", "honeypot", "recon"} else primary).append(destination(i, key, label))
        sidebar.content = ft.Column(
            [
                ft.Container(height=12),
                *primary,
                ft.Container(padding=12, content=ft.Divider(height=1, color=ui.BORDER)),
                *tools,
                ft.Container(expand=True),
                icon_button(
                    ft.Icons.KEYBOARD_DOUBLE_ARROW_RIGHT if collapsed else ft.Icons.KEYBOARD_DOUBLE_ARROW_LEFT,
                    "Expand sidebar" if collapsed else "Collapse sidebar",
                    toggle_sidebar,
                ),
            ],
            spacing=4,
            expand=True,
        )

    def rebuild_tabs():
        labels = {key: label for key, label, *_ in VIEWS}
        controls = []
        for key in tabs.opened:
            active = key == tabs.active
            background = ui.SURFACE_ACTIVE if active else ui.BACKGROUND
            controls.append(
                ft.Container(
                    height=44,
                    bgcolor=background,
                    border=ft.Border(
                        bottom=ft.BorderSide(2, ui.BRAND if active else ft.Colors.TRANSPARENT),
                        right=ft.BorderSide(1, ui.BORDER),
                    ),
                    content=ft.Row(
                        [
                            ft.Button(
                                content=labels[key],
                                height=42,
                                data=key,
                                on_click=lambda e: navigate(e.control.data),
                                style=ui.button_style(background=background, outlined=False, padding=16),
                            ),
                            # Capture this tab's key before the next loop iteration
                            icon_button(ft.Icons.CLOSE, f"Close {labels[key]}", lambda _e, k=key: close_tab(k)),
                        ],
                        spacing=0,
                        tight=True,
                    ),
                )
            )
        controls.append(icon_button(ft.Icons.ADD, "Open tool (Ctrl+K)", open_palette))
        tab_row.controls = controls

    def render():
        _cleanup_view(page)
        key = tabs.active
        page._sf_current_view = key
        try:
            control = _view_factory(key, page)
        except Exception as exc:
            logger.exception("Failed to render SentinelForge view %s", key)
            _cleanup_view(page)
            control = ft.Text(f"Failed to load '{key}': {exc}", color=ui.CRITICAL, selectable=True)
        content.content = ft.Container(key=f"view:{key}", content=control, expand=True, bgcolor=ui.BACKGROUND)
        rebuild_sidebar()
        rebuild_tabs()
        page.update()

    def navigate(view: str | int):
        key = VIEWS[max(0, min(view, len(VIEWS) - 1))][0] if isinstance(view, int) else view
        if key not in {v[0] for v in VIEWS}:
            key = "dashboard"
        if key == tabs.active:
            return
        tabs.select(key)
        render()

    def close_tab(key):
        previous = tabs.active
        tabs.close(key)
        if previous != tabs.active or previous == key:
            render()
        else:
            rebuild_tabs()
            page.update()

    def toggle_sidebar(_event):
        state["collapsed"] = not state["collapsed"]
        rebuild_sidebar()
        page.update()

    def dismiss_palette():
        dialog = state["palette"]
        if dialog is not None:
            # Flet retains the dialog until its native dismissal animation ends
            page.pop_dialog()
            state["palette"] = None

    def open_palette(_event=None):
        if state["palette"] is not None:
            return
        results = ft.Column(spacing=0, height=400, scroll=ft.ScrollMode.AUTO)

        def choose(key):
            dismiss_palette()
            navigate(key)

        def filter_commands(event=None):
            query = (search.value or "").strip().casefold()
            results.controls = [
                ft.Button(
                    content=f"Open {label}",
                    icon=_NAV_ICONS[key],
                    height=44,
                    on_click=lambda _e, k=key: choose(k),
                    style=ui.button_style(background=ui.SURFACE, outlined=False),
                )
                for key, label, *_ in VIEWS
                if query in label.casefold()
            ] or [ft.Text("No matching commands", color=ui.TEXT_MUTED)]
            if event is not None:
                page.update()

        search = ft.TextField(
            label="Search tools",
            autofocus=True,
            on_change=filter_commands,
            on_submit=lambda _e: (
                results.controls[0].on_click(None) if isinstance(results.controls[0], ft.Button) else None
            ),
            **ui.input_kwargs(),
        )
        filter_commands()
        dialog = ft.AlertDialog(
            title=ft.Text("Commands", size=18),
            bgcolor=ui.SURFACE,
            shape=ft.RoundedRectangleBorder(radius=8),
            content=ft.Container(width=500, content=ft.Column([search, results], tight=True)),
            on_dismiss=lambda _e: state.update(palette=None) if state["palette"] is dialog else None,
        )
        state["palette"] = dialog
        page.show_dialog(dialog)

    def keyboard(event):
        key = event.key.lower()
        if key == "escape":
            dismiss_palette()
        elif event.ctrl and key == "k":
            open_palette()
        elif event.ctrl and key == "w" and state["palette"] is None:
            close_tab(tabs.active)
        elif event.ctrl and key == "tab" and state["palette"] is None:
            tabs.cycle(backwards=event.shift)
            render()

    def refresh_status(_payload=None):
        count = len(jobs.list_jobs(include_finished=False))
        task_label.value = f"Background tasks: {count}"
        status_label.value = "Working" if count else "Ready"
        try:
            task_label.update()
            status_label.update()
        except RuntimeError:
            pass

    unsubscribe = events.subscribe("jobs", refresh_status)

    def close(_event):
        _cleanup_view(page)
        unsubscribe()

    def minimize(_event):
        page.window.minimized = True
        page.update()

    def maximize(_event):
        page.window.maximized = not page.window.maximized
        page.update()

    async def exit_app(_event):
        close(_event)
        await page.window.close()

    header = ft.Container(
        height=58,
        bgcolor=ui.TOPBAR_BACKGROUND,
        padding=ft.Padding(left=20, top=0, right=24, bottom=0),
        border=ft.Border(bottom=ft.BorderSide(1, ui.BORDER)),
        content=ft.Row(
            [
                ft.WindowDragArea(
                    expand=True,
                    content=ft.Row(
                        [
                            ft.Icon(ft.Icons.SHIELD_OUTLINED, size=28, color=ui.BRAND),
                            ft.Column(
                                [
                                    ft.Text("SentinelForge", size=20, weight=ft.FontWeight.W_600, color=ui.TEXT),
                                    ft.Text("Evidence-first Security Analysis", size=12, color=ui.TEXT_SECONDARY),
                                ],
                                spacing=0,
                            ),
                        ],
                        spacing=16,
                    ),
                ),
                ft.Text("Workspace", size=12, color=ui.TEXT_MUTED),
                ft.Container(
                    width=180,
                    padding=10,
                    border=ui.border(),
                    border_radius=6,
                    tooltip="Local workspace; project isolation is not available yet",
                    content=ft.Row(
                        [
                            ft.Icon(ft.Icons.FOLDER_OUTLINED, size=18, color=ui.TEXT_MUTED),
                            ft.Text("Local workspace", size=14, color=ui.TEXT_SECONDARY),
                        ],
                        spacing=8,
                    ),
                ),
                icon_button(ft.Icons.SEARCH, "Commands (Ctrl+K)", open_palette),
                icon_button(ft.Icons.REMOVE, "Minimize", minimize),
                icon_button(ft.Icons.CROP_SQUARE, "Maximize or restore", maximize),
                icon_button(ft.Icons.CLOSE, "Close SentinelForge", exit_app),
            ],
            spacing=12,
        ),
    )
    status_bar = ft.Container(
        height=34,
        bgcolor=ui.TOPBAR_BACKGROUND,
        padding=ft.Padding(left=24, top=0, right=24, bottom=0),
        border=ft.Border(top=ft.BorderSide(1, ui.BORDER)),
        content=ft.Row(
            [
                ft.Icon(ft.Icons.CIRCLE, size=9, color=ui.SUCCESS_TEAL),
                status_label,
                ft.VerticalDivider(width=24, color=ui.BORDER),
                ft.Text("Local workspace", size=12, color=ui.TEXT_SECONDARY),
                ft.VerticalDivider(width=24, color=ui.BORDER),
                task_label,
                ft.VerticalDivider(width=24, color=ui.BORDER),
                ft.Icon(ft.Icons.PSYCHOLOGY_OUTLINED, size=18, color=ui.TEXT_MUTED),
                ft.Text("Local AI: unavailable", size=12, color=ui.TEXT_MUTED),
                ft.Container(expand=True),
                ft.Text("SQLite · Local storage", size=12, color=ui.TEXT_MUTED),
            ],
            spacing=8,
        ),
    )
    workspace = ft.Column(
        [
            ft.Container(height=44, border=ft.Border(bottom=ft.BorderSide(1, ui.BORDER)), content=tab_row),
            content,
            status_bar,
        ],
        spacing=0,
        expand=True,
    )
    page._sf_navigate, page._sf_tabs, page._sf_close_tab = navigate, tabs, close_tab
    page._sf_open_palette = open_palette
    page.on_keyboard_event, page.on_close = keyboard, close
    page.add(ft.Column([header, ft.Row([sidebar, workspace], spacing=0, expand=True)], spacing=0, expand=True))
    render()
    refresh_status()


def run() -> None:
    ft.run(_main, view=ft.AppView.FLET_APP, assets_dir=str(ASSETS_DIR))


if __name__ == "__main__":
    run()

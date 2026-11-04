from __future__ import annotations

from collections.abc import Callable

import flet as ft

BACKGROUND = "#15151D"
SIDEBAR_BACKGROUND = "#18171F"
TOPBAR_BACKGROUND = "#1D1D27"

SURFACE = "#24202B"
SURFACE_SECONDARY = "#2A2532"
SURFACE_ACTIVE = "#302938"

BORDER = "#393240"
BORDER_STRONG = "#54495F"
CONTROL_BORDER = "#84778E"

TEXT_PRIMARY = "#E5DFEB"
TEXT_SECONDARY = "#BEB4C7"
TEXT_MUTED = "#AAA0B3"

BRAND = "#BC91E2"
BRAND_DARK = "#55476B"
FOCUS = BRAND
CRITICAL = "#F0808A"
HIGH = "#F0A478"
WARNING = "#E2BA70"
INFO_BLUE = "#8CB7F2"
SUCCESS_TEAL = "#78C5B7"

CRITICAL_SURFACE = "#37212A"
WARNING_SURFACE = "#352C20"
INFO_SURFACE = "#202B3C"
SUCCESS_SURFACE = "#1E332F"

# Existing views still import these token names
BG = BACKGROUND
PANEL = SURFACE
PANEL_2 = SURFACE_SECONDARY
PANEL_SELECTED = SURFACE_ACTIVE
TEXT = TEXT_PRIMARY
MUTED = TEXT_SECONDARY
ACCENT = BRAND
DANGER = CRITICAL
WARN = WARNING
INFO = INFO_BLUE

RADIUS_PANEL = 6
RADIUS_CONTROL = 6
SPACE_PAGE = 24
SPACE_SECTION = 16
TEXT_BODY = 14
TEXT_SMALL = 12
CONTROL_HEIGHT = 44

MOTION = ft.Animation(140, ft.AnimationCurve.EASE_OUT_CUBIC)


def border(color: str = BORDER, width: int = 1) -> ft.Border:
    side = ft.BorderSide(width, color)
    return ft.Border(top=side, right=side, bottom=side, left=side)


def input_kwargs() -> dict:
    return {
        "bgcolor": PANEL,
        "fill_color": PANEL,
        "filled": True,
        "color": TEXT,
        "border_color": CONTROL_BORDER,
        "focused_border_color": FOCUS,
        "focused_color": TEXT,
        "cursor_color": BRAND,
        "label_style": ft.TextStyle(size=TEXT_BODY, color=MUTED),
        "hint_style": ft.TextStyle(size=TEXT_BODY, color=MUTED),
        "border_radius": RADIUS_CONTROL,
        "content_padding": ft.Padding(left=12, top=10, right=12, bottom=10),
    }


def dropdown_kwargs() -> dict:
    return {
        "bgcolor": PANEL,
        "fill_color": PANEL,
        "filled": True,
        "color": TEXT,
        "border_color": CONTROL_BORDER,
        "focused_border_color": FOCUS,
        "label_style": ft.TextStyle(size=TEXT_BODY, color=MUTED),
        "text_style": ft.TextStyle(size=TEXT_BODY, color=TEXT),
        "hint_style": ft.TextStyle(size=TEXT_BODY, color=MUTED),
        "border_radius": RADIUS_CONTROL,
        "content_padding": ft.Padding(left=12, top=8, right=12, bottom=8),
    }


def button_style(
    *,
    color: str = TEXT,
    background: str = SURFACE,
    outlined: bool = True,
    padding: int = 12,
) -> ft.ButtonStyle:
    return ft.ButtonStyle(
        color={ft.ControlState.DEFAULT: color, ft.ControlState.DISABLED: TEXT_MUTED},
        bgcolor={
            ft.ControlState.FOCUSED: SURFACE_ACTIVE,
            ft.ControlState.HOVERED: SURFACE_SECONDARY,
            ft.ControlState.DEFAULT: background,
        },
        side={
            ft.ControlState.FOCUSED: ft.BorderSide(2, FOCUS),
            ft.ControlState.DEFAULT: ft.BorderSide(1, CONTROL_BORDER if outlined else ft.Colors.TRANSPARENT),
        },
        shape=ft.RoundedRectangleBorder(radius=RADIUS_CONTROL),
        padding=ft.Padding(left=padding, top=0, right=padding, bottom=0),
        text_style=ft.TextStyle(size=TEXT_BODY, weight=ft.FontWeight.W_500),
        icon_size=18,
        overlay_color=ft.Colors.TRANSPARENT,
        elevation=0,
        animation_duration=110,
    )


def action_button(
    label: str,
    icon: str | ft.IconData,
    on_click: Callable,
    *,
    accent: str = ACCENT,
    width: int | None = None,
) -> ft.Control:
    # Old callers pass abbreviation strings. Only IconData renders an icon
    return ft.Button(
        content=label,
        icon=icon if isinstance(icon, ft.IconData) else None,
        width=width,
        height=CONTROL_HEIGHT,
        elevation=0,
        style=button_style(color=accent),
        data=label,
        tooltip=label,
        on_click=on_click,
    )


def badge(label: str, *, color: str = ACCENT, width: int = 36) -> ft.Control:
    return ft.Container(
        width=width,
        height=28,
        border_radius=6,
        bgcolor=SURFACE_ACTIVE,
        border=border(BORDER),
        alignment=ft.Alignment(0, 0),
        animate=MOTION,
        content=ft.Text(label, size=12, weight=ft.FontWeight.W_500, color=color),
    )


def notify(page: ft.Page, message: str) -> None:
    snack = ft.SnackBar(ft.Text(message, color=TEXT), bgcolor=PANEL_SELECTED)
    page.show_dialog(snack)


def progress_bar(value: float | None = None, *, width: int = 210) -> ft.Control:
    return ft.ProgressBar(
        value=value,
        width=width,
        bar_height=6,
        color=ACCENT,
        bgcolor=BORDER,
        border_radius=3,
        animate_size=MOTION,
    )


def panel(
    content: ft.Control,
    *,
    padding=12,
    expand=None,
    width=None,
    height=None,
    selected: bool = False,
    on_click: Callable | None = None,
    data=None,
) -> ft.Control:
    def _hover(e):
        e.control.bgcolor = SURFACE_ACTIVE if selected or e.data else None
        e.control.update()

    return ft.Container(
        width=width,
        height=height,
        expand=expand,
        padding=padding,
        border_radius=0,
        bgcolor=SURFACE_ACTIVE if selected else None,
        border=ft.Border(bottom=ft.BorderSide(1, BORDER)),
        animate=MOTION,
        on_hover=_hover if on_click else None,
        on_click=on_click,
        data=data,
        ink=on_click is not None,
        ink_color="#228B7CF6",
        content=content,
    )


def section(title: str, content: ft.Control, *, expand=None, width=None) -> ft.Control:
    return ft.Container(
        expand=expand,
        width=width,
        padding=ft.Padding(left=0, top=16, right=0, bottom=16),
        border=ft.Border(top=ft.BorderSide(1, BORDER)),
        content=ft.Column(
            [ft.Text(title, size=16, weight=ft.FontWeight.W_600, color=TEXT), content],
            spacing=16,
            expand=expand,
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
        ),
    )


def export_menu(
    on_export: Callable[[str], Callable],
    formats: tuple[str, ...] = (
        "txt",
        "json",
        "csv",
        "html",
        "sarif",
        "stix",
        "md",
    ),
) -> ft.Control:
    return ft.PopupMenuButton(
        tooltip="Export full inventory report; view filters do not apply",
        bgcolor=SURFACE,
        elevation=0,
        content=ft.Container(
            height=CONTROL_HEIGHT,
            padding=ft.Padding(left=12, top=0, right=12, bottom=0),
            content=ft.Row(
                [
                    ft.Icon(ft.Icons.FILE_DOWNLOAD_OUTLINED, size=18, color=TEXT_SECONDARY),
                    ft.Text("Export", size=TEXT_BODY, color=TEXT),
                    ft.Icon(ft.Icons.EXPAND_MORE, size=16, color=TEXT_MUTED),
                ],
                spacing=8,
                tight=True,
            ),
        ),
        items=[ft.PopupMenuItem(content=fmt.upper(), on_click=on_export(fmt)) for fmt in formats],
    )


def task_panel(title: str, tasks: dict[str, dict], on_select: Callable | None = None) -> ft.Control:
    rows: list[ft.Control] = [
        ft.Text(title, size=14, weight=ft.FontWeight.BOLD, color=TEXT),
    ]
    active = [t for t in tasks.values() if t.get("status") == "running"]
    if not active:
        rows.append(ft.Text("No active tasks", size=12, color=MUTED))
    else:
        for task in sorted(active, key=lambda t: t.get("created", 0), reverse=True)[:6]:
            value = float(task.get("progress", 0.0))
            label = task.get("label", "task")
            phase = task.get("phase", "running")
            rows.append(
                panel(
                    padding=8,
                    data=task.get("id"),
                    on_click=on_select,
                    content=ft.Column(
                        [
                            ft.Text(label, size=12, color=TEXT, no_wrap=True),
                            progress_bar(value, width=190),
                            ft.Text(f"{int(value * 100)}% - {phase}", size=12, color=MUTED),
                        ],
                        spacing=4,
                    ),
                )
            )
    return panel(
        width=230,
        padding=12,
        selected=True,
        content=ft.Column(rows, spacing=8),
    )

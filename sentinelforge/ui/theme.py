from __future__ import annotations

from collections.abc import Callable

import flet as ft

BACKGROUND = "#090B12"
SIDEBAR_BACKGROUND = "#0D1019"
TOPBAR_BACKGROUND = "#0B0E16"

SURFACE = "#111521"
SURFACE_SECONDARY = "#151A28"
SURFACE_ACTIVE = "#181E2F"

BORDER = "#252B3C"
BORDER_STRONG = "#31384D"

TEXT_PRIMARY = "#E7EAF2"
TEXT_SECONDARY = "#A5ADBD"
TEXT_MUTED = "#737D91"

BRAND = "#8B7CF6"
BRAND_DARK = "#5D52B8"
CRITICAL = "#D85C67"
WARNING = "#D7A644"
INFO_BLUE = "#5B9CF6"
SUCCESS_TEAL = "#43B7AE"

CRITICAL_SURFACE = "#2A171C"
WARNING_SURFACE = "#2A2415"
INFO_SURFACE = "#132235"
SUCCESS_SURFACE = "#11302D"

# Compatibility aliases keep the existing destination pages visually coherent
# while the Dashboard adopts the expanded token vocabulary.
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

RADIUS_PANEL = 12
RADIUS_CONTROL = 8
SPACE_PAGE = 28
SPACE_SECTION = 14

MOTION = ft.Animation(180, ft.AnimationCurve.EASE_OUT_CUBIC)
MOTION_FAST = ft.Animation(110, ft.AnimationCurve.EASE_OUT)
SHADOW_SOFT = ft.BoxShadow(
    spread_radius=0,
    blur_radius=14,
    color="#18000000",
    offset=ft.Offset(0, 6),
)
SHADOW_LIFT = ft.BoxShadow(
    spread_radius=0,
    blur_radius=18,
    color="#24000000",
    offset=ft.Offset(0, 8),
)


def border(color: str = BORDER, width: int = 1) -> ft.Border:
    side = ft.BorderSide(width, color)
    return ft.Border(top=side, right=side, bottom=side, left=side)


def input_kwargs() -> dict:
    return {
        "bgcolor": PANEL,
        "fill_color": PANEL,
        "filled": True,
        "color": TEXT,
        "border_color": BORDER,
        "focused_border_color": BORDER_STRONG,
        "focused_color": TEXT,
        "cursor_color": BRAND,
        "label_style": ft.TextStyle(color=MUTED),
        "hint_style": ft.TextStyle(color=MUTED),
        "border_radius": RADIUS_CONTROL,
        "content_padding": ft.Padding(left=12, top=10, right=12, bottom=10),
    }


def dropdown_kwargs() -> dict:
    return {
        "bgcolor": PANEL,
        "fill_color": PANEL,
        "filled": True,
        "color": TEXT,
        "border_color": BORDER,
        "focused_border_color": BORDER_STRONG,
        "label_style": ft.TextStyle(color=MUTED),
        "text_style": ft.TextStyle(color=TEXT),
        "hint_style": ft.TextStyle(color=MUTED),
        "border_radius": RADIUS_CONTROL,
        "content_padding": ft.Padding(left=12, top=8, right=12, bottom=8),
    }


def action_button(
    label: str,
    icon: str,
    on_click: Callable,
    *,
    accent: str = ACCENT,
    width: int | None = None,
) -> ft.Control:
    def _hover(e):
        e.control.bgcolor = SURFACE_SECONDARY if e.data == "true" else SURFACE_ACTIVE
        e.control.border = border(accent if e.data == "true" else BORDER_STRONG)
        e.control.scale = 1.012 if e.data == "true" else 1
        e.control.shadow = SHADOW_SOFT if e.data == "true" else None
        e.control.update()

    token = _button_token(label, icon)
    return ft.Container(
        width=width,
        height=42,
        padding=ft.Padding(left=10, top=0, right=10, bottom=0),
        border_radius=RADIUS_CONTROL,
        bgcolor=SURFACE_ACTIVE,
        border=border(BORDER_STRONG),
        animate=MOTION_FAST,
        animate_scale=MOTION_FAST,
        ink=True,
        ink_color="#338B7CF6",
        on_hover=_hover,
        data=label,
        tooltip=label,
        on_click=on_click,
        content=ft.Row(
            [
                ft.Text(
                    token,
                    size=12,
                    weight=ft.FontWeight.BOLD,
                    color=accent,
                    no_wrap=True,
                    text_align=ft.TextAlign.CENTER,
                ),
            ],
            spacing=0,
            alignment=ft.MainAxisAlignment.CENTER,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        ),
    )


def _button_token(label: str, icon: str) -> str:
    clean_icon = (icon or "").strip().upper()
    clean_label = (label or "").strip()
    if clean_icon and len(clean_icon) >= 3 and clean_icon not in {"GO"}:
        return clean_icon[:6]
    words = [w for w in clean_label.replace("/", " ").replace("-", " ").split() if w]
    if not words:
        return clean_icon or "?"
    first = words[0].upper()
    if len(first) >= 3:
        return first[:6]
    if len(words) > 1:
        return "".join(w[0].upper() for w in words[:4])
    return first


def badge(label: str, *, color: str = ACCENT, width: int = 36) -> ft.Control:
    return ft.Container(
        width=width,
        height=28,
        border_radius=6,
        bgcolor=SURFACE_ACTIVE,
        border=border(BORDER),
        alignment=ft.Alignment(0, 0),
        animate=MOTION,
        animate_scale=MOTION,
        content=ft.Text(label, size=11, weight=ft.FontWeight.BOLD, color=color),
    )


def notify(page: ft.Page, message: str) -> None:
    snack = ft.SnackBar(ft.Text(message, color=TEXT), bgcolor=PANEL_SELECTED)
    if hasattr(page, "open"):
        page.open(snack)
        return
    page.overlay.append(snack)
    snack.open = True
    page.update()


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
        if on_click is None:
            return
        e.control.bgcolor = SURFACE_ACTIVE if e.data == "true" else (SURFACE_ACTIVE if selected else SURFACE)
        e.control.scale = 1.006 if e.data == "true" else 1
        e.control.shadow = SHADOW_SOFT if e.data == "true" else None
        e.control.update()

    return ft.Container(
        width=width,
        height=height,
        expand=expand,
        padding=padding,
        border_radius=RADIUS_PANEL,
        bgcolor=SURFACE_ACTIVE if selected else SURFACE,
        border=border(BORDER_STRONG if selected else BORDER),
        animate=MOTION,
        animate_scale=MOTION_FAST,
        animate_opacity=MOTION,
        on_hover=_hover if on_click else None,
        on_click=on_click,
        data=data,
        ink=on_click is not None,
        ink_color="#228B7CF6",
        content=content,
    )


def task_panel(title: str, tasks: dict[str, dict], on_select: Callable | None = None) -> ft.Control:
    rows: list[ft.Control] = [
        ft.Text(title, size=14, weight=ft.FontWeight.BOLD, color=TEXT),
    ]
    active = [t for t in tasks.values() if t.get("status") == "running"]
    if not active:
        rows.append(ft.Text("No active tasks", size=11, color=MUTED))
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
                            ft.Text(label, size=11, color=TEXT, no_wrap=True),
                            progress_bar(value, width=190),
                            ft.Text(f"{int(value * 100)}% - {phase}", size=10, color=MUTED),
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

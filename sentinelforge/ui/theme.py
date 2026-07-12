from __future__ import annotations

from collections.abc import Callable

import flet as ft

BG = "#090712"
PANEL = "#141125"
PANEL_2 = "#1d1834"
PANEL_SELECTED = "#2a2250"
BORDER = "#3b3264"
TEXT = "#f7f4ff"
MUTED = "#b9b0d4"
ACCENT = "#a78bfa"
DANGER = "#fb7185"
WARN = "#facc15"
INFO = "#c4b5fd"

MOTION = ft.Animation(180, ft.AnimationCurve.EASE_OUT_CUBIC)
MOTION_FAST = ft.Animation(110, ft.AnimationCurve.EASE_OUT)
SHADOW_SOFT = ft.BoxShadow(
    spread_radius=0,
    blur_radius=18,
    color="#22000000",
    offset=ft.Offset(0, 8),
)
SHADOW_LIFT = ft.BoxShadow(
    spread_radius=0,
    blur_radius=26,
    color="#33000000",
    offset=ft.Offset(0, 12),
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
        "focused_border_color": ACCENT,
        "focused_color": TEXT,
        "cursor_color": ACCENT,
        "label_style": ft.TextStyle(color=MUTED),
        "hint_style": ft.TextStyle(color=MUTED),
        "border_radius": 8,
        "content_padding": ft.Padding(left=12, top=10, right=12, bottom=10),
    }


def dropdown_kwargs() -> dict:
    return {
        "bgcolor": PANEL,
        "fill_color": PANEL,
        "filled": True,
        "color": TEXT,
        "border_color": BORDER,
        "focused_border_color": ACCENT,
        "label_style": ft.TextStyle(color=MUTED),
        "text_style": ft.TextStyle(color=TEXT),
        "hint_style": ft.TextStyle(color=MUTED),
        "border_radius": 8,
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
        e.control.bgcolor = "#3b2f72" if e.data == "true" else PANEL_SELECTED
        e.control.border = border(accent, 2 if e.data == "true" else 1)
        e.control.scale = 1.025 if e.data == "true" else 1
        e.control.shadow = SHADOW_LIFT if e.data == "true" else None
        e.control.update()

    token = _button_token(label, icon)
    return ft.Container(
        width=width,
        height=42,
        padding=ft.Padding(left=10, top=0, right=10, bottom=0),
        border_radius=8,
        bgcolor=PANEL_SELECTED,
        border=border(accent),
        animate=MOTION_FAST,
        animate_scale=MOTION_FAST,
        ink=True,
        ink_color="#6d28d99f",
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
        bgcolor=PANEL_SELECTED,
        border=border(color),
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


def panel(content: ft.Control, *, padding=12, expand=None, width=None, height=None,
          selected: bool = False, on_click: Callable | None = None, data=None) -> ft.Control:
    def _hover(e):
        if on_click is None:
            return
        e.control.bgcolor = PANEL_SELECTED if e.data == "true" else (PANEL_SELECTED if selected else PANEL)
        e.control.scale = 1.012 if e.data == "true" else 1
        e.control.shadow = SHADOW_SOFT if e.data == "true" else None
        e.control.update()

    return ft.Container(
        width=width,
        height=height,
        expand=expand,
        padding=padding,
        border_radius=8,
        bgcolor=PANEL_SELECTED if selected else PANEL,
        border=border(ACCENT if selected else BORDER),
        animate=MOTION,
        animate_scale=MOTION_FAST,
        animate_opacity=MOTION,
        on_hover=_hover if on_click else None,
        on_click=on_click,
        data=data,
        ink=on_click is not None,
        ink_color="#6d28d99f",
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

"""Attack-path prioritization view."""
from __future__ import annotations

import flet as ft

from ...core import events
from ...modules.analysis import attack_paths
from .. import theme as ui

_CONF_COLOR = {
    "High": ui.DANGER,
    "Medium": ui.WARN,
    "Low": ui.INFO,
}


def render(page: ft.Page) -> ft.Control:
    state = {"include_low": True}
    rows = ft.ListView(expand=True, spacing=8, auto_scroll=False)
    summary_row = ft.Row(spacing=12, wrap=True)

    include_low = ft.Checkbox(
        label="Low confidence",
        value=True,
        fill_color=ui.PANEL_SELECTED,
        check_color=ui.ACCENT,
        label_style=ft.TextStyle(color=ui.MUTED, size=12),
    )

    def _summary_card(title: str, value: str, color: str) -> ft.Control:
        return ui.panel(
            width=150,
            height=74,
            padding=12,
            content=ft.Column(
                [
                    ft.Text(title, size=11, color=ui.MUTED, no_wrap=True),
                    ft.Text(value, size=22, weight=ft.FontWeight.BOLD, color=color),
                ],
                spacing=0,
            ),
        )

    def _path_card(path: dict) -> ft.Control:
        confidence = path.get("confidence") or "Low"
        color = _CONF_COLOR.get(confidence, ui.MUTED)
        chain = " -> ".join(path.get("chain") or [])
        evidence = "; ".join(path.get("why_it_matters") or [])
        controls = "; ".join(path.get("false_positive_controls") or [])
        validation = "; ".join(path.get("recommended_validation") or [])
        exposed = "Public exposure" if path.get("internet_exposed") else "Internal/observed exposure"
        return ui.panel(
            padding=12,
            content=ft.Column(
                [
                    ft.Row(
                        [
                            ui.badge(confidence[:2].upper(), color=color, width=38),
                            ft.Column(
                                [
                                    ft.Text(
                                        path.get("title") or "Attack path",
                                        size=14,
                                        weight=ft.FontWeight.BOLD,
                                        color=ui.TEXT,
                                        selectable=True,
                                    ),
                                    ft.Text(
                                        f"{path.get('asset') or '-'}  |  Score {path.get('score')}  |  {exposed}",
                                        size=11,
                                        color=ui.MUTED,
                                        selectable=True,
                                    ),
                                ],
                                spacing=2,
                                expand=True,
                            ),
                        ],
                        vertical_alignment=ft.CrossAxisAlignment.START,
                    ),
                    ft.Text(f"Chain: {chain or '-'}", size=11, color=ui.TEXT, selectable=True),
                    ft.Text(f"Evidence: {evidence or '-'}", size=11, color=ui.TEXT, selectable=True),
                    ft.Text(f"False-positive controls: {controls or '-'}", size=10, color=ui.MUTED, selectable=True),
                    ft.Text(f"Validate: {validation or '-'}", size=10, color=ui.MUTED, selectable=True),
                ],
                spacing=6,
            ),
        )

    def _refresh(_payload: dict | None = None) -> None:
        rows.controls.clear()
        summary_row.controls.clear()
        data = attack_paths.analyze(limit=50, include_low=state["include_low"])
        summary = data.get("summary", {})
        summary_row.controls.extend(
            [
                _summary_card("Paths", str(summary.get("total", 0)), ui.ACCENT),
                _summary_card("High", str(summary.get("high_confidence", 0)), ui.DANGER),
                _summary_card("Medium", str(summary.get("medium_confidence", 0)), ui.WARN),
                _summary_card("Low", str(summary.get("low_confidence", 0)), ui.INFO),
                _summary_card("Top score", str(summary.get("top_score", 0)), ui.TEXT),
            ]
        )
        paths = data.get("paths", [])
        if not paths:
            rows.controls.append(
                ui.panel(
                    padding=14,
                    content=ft.Text(
                        "No attack paths found from current evidence.",
                        color=ui.MUTED,
                        selectable=True,
                    ),
                )
            )
        else:
            rows.controls.extend(_path_card(path) for path in paths)
        try:
            page.update()
        except Exception:
            pass

    def _include_low_changed(e) -> None:
        state["include_low"] = bool(e.control.value)
        _refresh()

    include_low.on_change = _include_low_changed
    unsub_scan = events.subscribe("scanner", _refresh)
    unsub_recon = events.subscribe("recon", _refresh)
    unsub_hp = events.subscribe("honeypot", _refresh)
    page._sf_cleanups = getattr(page, "_sf_cleanups", [])
    page._sf_cleanups.extend([unsub_scan, unsub_recon, unsub_hp])

    refresh_button = ui.action_button("Refresh", "REF", lambda _: _refresh(), width=92)
    _refresh()
    return ft.Column(
        [
            ft.Row(
                [
                    ft.Text("Attack Paths", size=18, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                    ft.Row([include_low, refresh_button], spacing=10),
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                wrap=True,
            ),
            summary_row,
            rows,
        ],
        expand=True,
        spacing=12,
    )

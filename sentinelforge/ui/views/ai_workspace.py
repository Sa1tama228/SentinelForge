from __future__ import annotations

import flet as ft

from .. import theme as ui


def render(page: ft.Page) -> ft.Control:
    tools = ft.Column(
        [
            ft.Text("Agent tools", size=16, weight=ft.FontWeight.W_600, color=ui.TEXT),
            ft.Text("No agent connected", size=12, color=ui.TEXT_MUTED),
            *[
                ui.section(
                    title, ft.Column([ft.Text(label, size=14, color=ui.TEXT_MUTED) for label in labels], spacing=16)
                )
                for title, labels in (
                    ("Reconnaissance", ["Port scan", "Service fingerprint", "Web enumeration"]),
                    ("Analysis", ["CVE correlation", "Evidence analysis", "Potential attack paths"]),
                )
            ],
            ui.section("Context", ft.Text("Local workspace\nNo finding selected", size=14, color=ui.TEXT_SECONDARY)),
        ],
        spacing=16,
        scroll=ft.ScrollMode.AUTO,
    )
    main = ft.Column(
        [
            ft.Row(
                [
                    ft.Icon(ft.Icons.PSYCHOLOGY_OUTLINED, size=32, color=ui.BRAND),
                    ft.Text("AI Workspace", size=24, weight=ft.FontWeight.W_600, color=ui.TEXT),
                ],
                spacing=16,
            ),
            ft.Text("Review findings with a local analyst agent", size=14, color=ui.TEXT_SECONDARY),
            ft.Divider(color=ui.BORDER),
            ft.Text("Local AI is not available", size=18, weight=ft.FontWeight.W_600, color=ui.TEXT),
            ft.Text(
                "This build does not include local AI\nYou can investigate records in Findings and Correlations",
                size=14,
                color=ui.TEXT_SECONDARY,
            ),
            ft.Container(expand=True),
            ft.TextField(
                label="Message", hint_text="Local AI is unavailable in this build", disabled=True, **ui.input_kwargs()
            ),
        ],
        spacing=16,
        expand=True,
        horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
    )
    context = ft.Column(
        [
            ft.Text("Investigation context", size=16, weight=ft.FontWeight.W_600, color=ui.TEXT),
            ui.section("Summary", ft.Text("No active conversation", size=14, color=ui.TEXT_MUTED)),
            ui.section(
                "Evidence", ft.Text("Select a finding to inspect its recorded evidence", size=14, color=ui.TEXT_MUTED)
            ),
        ],
        spacing=16,
    )
    return ft.Row(
        [
            ft.Container(
                content=tools,
                width=220,
                padding=ft.Padding(left=0, top=0, right=20, bottom=0),
                border=ft.Border(right=ft.BorderSide(1, ui.BORDER)),
            ),
            ft.Container(content=main, expand=True, padding=ft.Padding(left=24, top=0, right=24, bottom=0)),
            ft.Container(
                content=context,
                width=260,
                padding=ft.Padding(left=20, top=0, right=0, bottom=0),
                border=ft.Border(left=ft.BorderSide(1, ui.BORDER)),
            ),
        ],
        expand=True,
        spacing=0,
    )

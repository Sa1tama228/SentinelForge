from __future__ import annotations

import json

import flet as ft

from ...core import events
from ...modules.analysis import attack_paths
from .. import theme as ui


def render(page: ft.Page) -> ft.Control:
    state = {"selected": None, "query": "", "include_low": True, "paths": [], "narrow": False}
    path_list = ft.ListView(expand=True, spacing=0)
    detail = ft.Column(
        spacing=20, expand=True, scroll=ft.ScrollMode.AUTO, horizontal_alignment=ft.CrossAxisAlignment.STRETCH
    )
    context = ft.Column(spacing=16, expand=True, scroll=ft.ScrollMode.AUTO)
    count = ft.Text("", size=12, color=ui.TEXT_MUTED)
    search = ft.TextField(label="Search paths or assets", text_size=14, dense=True, **ui.input_kwargs())
    include_low = ft.Checkbox(
        label="Include low confidence", value=True, label_style=ft.TextStyle(size=12, color=ui.TEXT_SECONDARY)
    )

    def select(event):
        state["selected"] = event.control.data
        display()
        page.update()

    def display():
        paths = [
            p for p in state["paths"] if state["query"] in (p.get("title", "") + " " + p.get("asset", "")).casefold()
        ]
        count.value = f"{len(paths)} potential paths · up to 50"
        selected = next((p for p in paths if p["id"] == state["selected"]), paths[0] if paths else None)
        state["selected"] = selected["id"] if selected else None
        path_list.controls = [
            ft.Container(
                border=ft.Border(bottom=ft.BorderSide(1, ui.BORDER)),
                content=ft.Button(
                    height=112,
                    data=p["id"],
                    on_click=select,
                    style=ui.button_style(
                        background=ui.SURFACE_ACTIVE if p is selected else ui.BACKGROUND, outlined=False
                    ),
                    content=ft.Column(
                        [
                            ft.Text(p["title"], size=14, color=ui.TEXT, max_lines=2, overflow=ft.TextOverflow.ELLIPSIS),
                            ft.Text(p.get("asset", ""), size=12, color=ui.TEXT_MUTED),
                            ft.Text(f"{p.get('confidence', 'Low')} confidence", size=12, color=ui.TEXT_SECONDARY),
                        ],
                        spacing=8,
                        alignment=ft.MainAxisAlignment.CENTER,
                    ),
                ),
            )
            for p in paths
        ]
        if selected is None:
            detail.controls = [
                ft.Text("Evidence paths", size=22, weight=ft.FontWeight.W_600, color=ui.TEXT),
                ft.Text("No potential paths match the current evidence and filters", size=14, color=ui.TEXT_MUTED),
            ]
            context.controls = [
                ui.section(
                    "Validation",
                    ft.Text(
                        "A potential path links observations and still needs independent validation",
                        size=14,
                        color=ui.TEXT_MUTED,
                    ),
                )
            ]
            if state["narrow"]:
                detail.controls.append(context)
            return
        chain = selected.get("chain") or []
        nodes = []
        for i, label in enumerate(chain):
            if i:
                nodes.append(ft.Icon(ft.Icons.ARROW_FORWARD, color=ui.BRAND, size=20))
            nodes.append(
                ft.Container(
                    width=144,
                    padding=16,
                    border=ui.border(ui.BORDER_STRONG),
                    border_radius=6,
                    content=ft.Column(
                        [
                            ft.Text(f"Step {i + 1}", size=12, color=ui.TEXT_MUTED),
                            ft.Text(str(label), size=14, color=ui.TEXT, selectable=True),
                        ],
                        spacing=8,
                    ),
                )
            )
        detail.controls = [
            ft.Text(selected["title"], size=22, weight=ft.FontWeight.W_600, color=ui.TEXT),
            ft.Text(f"{selected.get('asset', 'Unknown asset')} · Potential path", size=14, color=ui.TEXT_SECONDARY),
            ui.section("Evidence path", ft.Row(nodes, scroll=ft.ScrollMode.AUTO, spacing=16)),
            ui.section(
                "Supporting observations",
                ft.Column(
                    [
                        ft.Text(str(reason), size=14, color=ui.TEXT_SECONDARY, selectable=True)
                        for reason in selected.get("why_it_matters", [])
                    ],
                    spacing=12,
                ),
            ),
            ui.section(
                "Source data",
                ft.Text(
                    json.dumps(selected.get("evidence") or {}, indent=2, ensure_ascii=False),
                    size=12,
                    font_family="Consolas",
                    color=ui.TEXT_SECONDARY,
                    selectable=True,
                ),
            ),
        ]
        context.controls = [
            ui.section(
                "Path assessment",
                ft.Column(
                    [
                        ft.Text(f"Confidence: {selected.get('confidence', 'Unknown')}", size=14, color=ui.TEXT),
                        ft.Text(f"Ranking score: {selected.get('score', 'Unknown')}", size=14, color=ui.TEXT_SECONDARY),
                        ft.Text("This ranking is not an exploitation probability", size=12, color=ui.TEXT_MUTED),
                    ],
                    spacing=12,
                ),
            ),
            ui.section(
                "Recommended validation",
                ft.Column(
                    [
                        ft.Text(str(item), size=14, color=ui.TEXT_SECONDARY)
                        for item in selected.get("recommended_validation", [])
                    ],
                    spacing=12,
                ),
            ),
            ui.section(
                "False-positive controls",
                ft.Column(
                    [
                        ft.Text(str(item), size=12, color=ui.TEXT_MUTED)
                        for item in selected.get("false_positive_controls", [])
                    ],
                    spacing=12,
                ),
            ),
        ]
        if state["narrow"]:
            detail.controls.append(context)

    def refresh(_payload=None):
        data = attack_paths.analyze(limit=50, include_low=state["include_low"])
        state["paths"] = data.get("paths", [])
        display()
        try:
            page.update()
        except RuntimeError:
            # Worker events can arrive after the page closes
            pass

    def query_changed(event):
        state["query"] = (event.control.value or "").strip().casefold()
        display()
        page.update()

    def confidence_changed(event):
        state["include_low"] = bool(event.control.value)
        refresh()

    search.on_change = query_changed
    include_low.on_change = confidence_changed
    page._sf_cleanups = getattr(page, "_sf_cleanups", [])
    page._sf_cleanups.extend(events.subscribe(channel, refresh) for channel in ("scanner", "recon", "honeypot"))
    refresh()
    context_pane = ft.Container(
        content=context,
        width=268,
        padding=ft.Padding(left=16, top=0, right=0, bottom=0),
        border=ft.Border(left=ft.BorderSide(1, ui.BORDER)),
    )

    def adapt(event):
        visible = event.width >= 1180
        if context_pane.visible == visible:
            return
        context_pane.visible = visible
        state["narrow"] = not visible
        context.expand = True if visible else None
        if visible:
            if context in detail.controls:
                detail.controls.remove(context)
            context_pane.content = context
        else:
            context_pane.content = None
            detail.controls.append(context)
        page.update()

    return ft.Column(
        [
            ft.Row(
                [
                    ft.Text("Correlations", size=22, weight=ft.FontWeight.W_600, color=ui.TEXT),
                    ui.action_button("Refresh", ft.Icons.REFRESH, lambda _e: refresh()),
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ),
            ft.Row(
                [
                    ft.Container(
                        width=268,
                        padding=ft.Padding(left=0, top=0, right=16, bottom=0),
                        border=ft.Border(right=ft.BorderSide(1, ui.BORDER)),
                        content=ft.Column(
                            [
                                ft.Text("Correlation explorer", size=16, color=ui.TEXT),
                                search,
                                include_low,
                                count,
                                path_list,
                            ],
                            spacing=16,
                            expand=True,
                        ),
                    ),
                    ft.Container(content=detail, expand=True, padding=24),
                    context_pane,
                ],
                spacing=0,
                expand=True,
                on_size_change=adapt,
            ),
        ],
        spacing=16,
        expand=True,
    )

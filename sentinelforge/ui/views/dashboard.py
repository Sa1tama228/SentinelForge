from __future__ import annotations

import flet as ft

from ...core import db, events
from .. import theme as ui


def _stat_card(title: str, value: str, icon: str, color: str) -> ft.Control:
    return ui.panel(
        expand=True,
        height=104,
        padding=16,
        content=ft.Container(
            content=ft.Row(
                [
                    ui.badge(icon, color=color),
                    ft.Column(
                        [
                            ft.Text(title, size=12, color=ui.MUTED),
                            ft.Text(value, size=24, weight=ft.FontWeight.BOLD, color=ui.TEXT),
                        ],
                        spacing=0,
                    ),
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ),
        ),
    )


def render(page: ft.Page) -> ft.Control:
    hp = db.honeypot_stats()
    runs = db.recent_scan_runs(limit=1000)
    targets = db.recent_targets(limit=1000)
    assets = db.assets(limit=10000)
    findings = db.findings(limit=10000)

    cards = ft.Row(
        [
            _stat_card("Honeypot events", str(hp["total"]), "HP", ui.DANGER),
            _stat_card("Scan runs", str(len(runs)), "SC", ui.WARN),
            _stat_card("Recon targets", str(len(targets)), "RC", ui.INFO),
            _stat_card("Assets", str(len(assets)), "AS", ui.ACCENT),
            _stat_card("Findings", str(len(findings)), "FN", ui.DANGER),
        ],
        spacing=12,
    )

    feed_title = ft.Text("Recent signals", size=16, weight=ft.FontWeight.BOLD, color=ui.TEXT)
    feed = ft.ListView(expand=True, spacing=4, auto_scroll=True, padding=0)

    def _refresh(_payload: dict | None = None) -> None:
        hp2 = db.honeypot_stats()
        runs2 = db.recent_scan_runs(limit=1000)
        targets2 = db.recent_targets(limit=1000)
        assets2 = db.assets(limit=10000)
        findings2 = db.findings(limit=10000)
        cards.controls[0].content.content.controls[1].controls[1].value = str(hp2["total"])
        cards.controls[1].content.content.controls[1].controls[1].value = str(len(runs2))
        cards.controls[2].content.content.controls[1].controls[1].value = str(len(targets2))
        cards.controls[3].content.content.controls[1].controls[1].value = str(len(assets2))
        cards.controls[4].content.content.controls[1].controls[1].value = str(len(findings2))
        feed.controls.clear()
        signal_rows = [
            row
            for row in db.recent_honeypot_events(limit=80)
            if (row["classification"] or "") not in {"", "connection", "scanner"}
        ][:8]
        for row in signal_rows:
            feed.controls.append(
                ft.Text(
                    f"[{row['ts']}] HP  {row['classification']}  {row['src_ip']}  "
                    f"{row['method'] or 'connect'} {row['path'] or '-'}",
                    size=12, selectable=True, color=ui.TEXT,
                )
            )
        for r in db.recent_scan_runs(limit=5):
            if r["status"] not in {"done", "error", "cancelled"}:
                continue
            feed.controls.append(
                ft.Text(
                    f"[{r['ts']}] SCAN  {r['target']}  ports={r['ports']}  {r['status']}",
                    size=12, selectable=True, color=ui.WARN,
                )
            )
        if not feed.controls:
            feed.controls.append(ft.Text("No high-signal activity yet", size=12, color=ui.MUTED))
        try:
            page.update()
        except Exception:
            pass

    unsub = events.subscribe("honeypot", _refresh)
    unsub_scan = events.subscribe("scanner", _refresh)
    unsub_recon = events.subscribe("recon", _refresh)
    # Store unsubscribe on page so it can be cleaned if view is replaced.
    _cleanup = getattr(page, "_sf_cleanups", [])
    _cleanup.extend([unsub, unsub_scan, unsub_recon])
    page._sf_cleanups = _cleanup

    _refresh()
    return ft.Column(
        [cards, ft.Divider(color=ui.BORDER), feed_title, feed],
        expand=True,
        spacing=14,
    )

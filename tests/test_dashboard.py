from __future__ import annotations

import json
from datetime import UTC, datetime

from sentinelforge.core import db
from sentinelforge.ui import shell
from sentinelforge.ui.components.dashboard import ActivityTable, MetricCard, OperationalSummaryPanel
from sentinelforge.ui.dashboard_service import (
    DashboardActivityItem,
    DashboardService,
    OperationalSummary,
)
from sentinelforge.ui.views import dashboard as dashboard_view


def _empty_counts() -> dict[str, int | float]:
    return {
        "assets": 0,
        "findings": 0,
        "scan_runs": 0,
        "running_scans": 0,
        "review_items": 0,
        "severity_score": 0.0,
        "priority_score": 0.0,
    }


def _seed_searchable_finding(token: str, cve_id: str) -> None:
    asset_id = db.upsert_asset(f"{token}.local", source="test")
    finding_id = db.upsert_finding(
        title=f"Critical {token} finding",
        severity="Critical",
        confidence="High",
        asset_id=asset_id,
        evidence="dashboard evidence",
        source_module="test",
        remediation="Fix it",
        fingerprint=f"{token}-finding",
    )
    db.upsert_vulnerability_match(
        finding_id=finding_id,
        cve_id=cve_id,
        asset_id=asset_id,
        match_status="likely_candidate",
        confidence_score=0.8,
        priority_score=72.0,
        evidence={"service": "https"},
    )


def test_dashboard_components_construct_with_empty_data(monkeypatch):
    monkeypatch.setattr(db, "dashboard_counts", _empty_counts)
    monkeypatch.setattr(db, "recent_scan_runs", lambda limit=25: [])
    monkeypatch.setattr(db, "dashboard_service_candidates", lambda limit=200: [])
    monkeypatch.setattr(
        db,
        "dashboard_honeypot_summary",
        lambda: {"events": 0, "source_ips": 0, "last_event_ts": None},
    )
    monkeypatch.setattr(
        "sentinelforge.ui.dashboard_service.attack_paths.analyze",
        lambda **_kwargs: {"summary": {}, "paths": []},
    )

    summary = DashboardService().get_summary()
    cards = [MetricCard(metric) for metric in summary.metrics]
    operational = OperationalSummaryPanel(on_open_scanner=lambda _event: None, on_open_attack_paths=lambda _event: None)
    operational.set_summary(summary.operational)
    activity = ActivityTable(
        on_type_change=lambda _value: None,
        on_severity_change=lambda _value: None,
        on_search_change=lambda _value: None,
        on_select=lambda _item: None,
    )
    activity.set_items([])

    assert len(cards) == 4
    assert summary.metrics[1].value == "0"
    assert summary.operational.active_scan is None


def test_dashboard_components_construct_with_finding():
    item = DashboardActivityItem(
        timestamp=datetime.now(UTC),
        severity="High",
        item_type="finding",
        title="Dashboard construction finding",
        asset="dashboard-construction.local",
        source="test",
        source_id="42",
    )
    selected: list[DashboardActivityItem] = []
    activity = ActivityTable(
        on_type_change=lambda _value: None,
        on_severity_change=lambda _value: None,
        on_search_change=lambda _value: None,
        on_select=selected.append,
    )
    activity.set_items([item])

    assert len(activity._rows.controls) == 1


def test_unified_activity_merges_findings_and_signals_and_filters():
    token = "dashboard-merge-activity"
    _seed_searchable_finding(token, "CVE-2098-4242")
    db.add_honeypot_event(
        "http",
        "198.51.100.42",
        4242,
        classification="scanner",
        body=token,
    )
    service = DashboardService()

    all_items = service.get_activity(search=token, limit=10)
    signals = service.get_activity(activity_type="signal", search=token, limit=10)
    findings = service.get_activity(activity_type="finding", search=token, limit=10)
    critical = service.get_activity(severity="Critical", search=token, limit=10)

    assert {item.item_type for item in all_items} == {"signal", "finding"}
    assert signals and all(item.item_type == "signal" for item in signals)
    assert findings and all(item.item_type == "finding" for item in findings)
    assert critical and all(item.severity == "Critical" for item in critical)


def test_activity_search_matches_title_asset_and_cve():
    _seed_searchable_finding("dashboard-merge-activity", "CVE-2098-4242")
    service = DashboardService()

    assert any(
        "dashboard-merge-activity" in item.title for item in service.get_activity(search="dashboard-merge-activity")
    )
    assert any(
        "dashboard-merge-activity.local" == item.asset
        for item in service.get_activity(search="dashboard-merge-activity.local")
    )
    assert any("CVE-2098-4242" in item.cve_id for item in service.get_activity(search="CVE-2098-4242"))


def test_activity_search_treats_like_wildcards_as_literal_text():
    asset_id = db.upsert_asset("dashboard-literal-search.local", source="test")
    expected_title = "Literal search 100%_match"
    db.upsert_finding(
        title=expected_title,
        severity="Low",
        confidence="High",
        asset_id=asset_id,
        evidence="literal search target",
        source_module="test",
        remediation="Review",
        fingerprint="dashboard-literal-search-target",
    )
    db.upsert_finding(
        title="Decoy search 100percentXmatch",
        severity="Low",
        confidence="High",
        asset_id=asset_id,
        evidence="literal search decoy",
        source_module="test",
        remediation="Review",
        fingerprint="dashboard-literal-search-decoy",
    )

    items = DashboardService().get_activity(search="100%_match", limit=50)

    assert [item.title for item in items] == [expected_title]


def test_activity_query_respects_render_limit():
    items = DashboardService().get_activity(limit=3)

    assert len(items) <= 3


def test_risk_posture_uses_strongest_existing_score():
    counts = _empty_counts()
    counts.update({"severity_score": 55.0, "priority_score": 72.4, "review_items": 2})

    metric = DashboardService()._metrics(counts)[0]

    assert metric.value == "72 / 100"
    assert metric.subtitle == "High - review 2 items"


def test_risk_posture_does_not_claim_zero_review_items():
    counts = _empty_counts()
    counts.update({"severity_score": 55.0, "review_items": 0})

    metric = DashboardService()._metrics(counts)[0]

    assert metric.subtitle == "Medium current risk evidence"


def test_review_count_includes_high_priority_medium_findings():
    before = int(db.dashboard_counts()["review_items"])
    asset_id = db.upsert_asset("dashboard-priority-review.local", source="test")
    finding_id = db.upsert_finding(
        title="Dashboard priority review",
        severity="Medium",
        confidence="High",
        asset_id=asset_id,
        evidence="priority evidence",
        source_module="test",
        remediation="Review",
        fingerprint="dashboard-priority-review",
    )
    db.upsert_vulnerability_match(
        finding_id=finding_id,
        cve_id="CVE-2098-5151",
        asset_id=asset_id,
        match_status="likely_candidate",
        confidence_score=0.8,
        priority_score=72.0,
        evidence={"service": "https"},
    )

    assert int(db.dashboard_counts()["review_items"]) == before + 1


def test_operational_summary_has_neutral_no_scan_state(monkeypatch):
    monkeypatch.setattr(db, "dashboard_active_scan", lambda: None)

    assert DashboardService()._active_scan() is None


def test_operational_summary_uses_real_active_scan():
    run_id = db.create_scan_run("dashboard-active-scan.local", "22,443")
    db.update_scan_run_progress(run_id, progress=0.62)
    try:
        active = DashboardService()._active_scan()
        assert active is not None
        assert active.target == "dashboard-active-scan.local"
        assert active.progress == 0.62
    finally:
        db.finish_scan_run(run_id, status="cancelled")


def test_active_scan_is_not_hidden_by_newer_completed_runs():
    active_id = db.create_scan_run("dashboard-long-running.local", "443")
    try:
        for index in range(30):
            completed_id = db.create_scan_run(f"dashboard-completed-{index}.local", "80")
            db.finish_scan_run(completed_id, status="done")

        active = DashboardService()._active_scan()

        assert active is not None
        assert active.target == "dashboard-long-running.local"
    finally:
        db.finish_scan_run(active_id, status="cancelled")


def test_exposed_service_skips_malformed_ports_and_invalid_preference():
    row = {
        "hostname": "dashboard-service.local",
        "normalized_ips": json.dumps(["8.8.8.8"]),
        "open_services": json.dumps(
            [
                {"port": "invalid", "proto": "tcp", "service": "broken"},
                {"port": 443, "proto": "tcp", "service": "https", "version": "1.2.3"},
            ]
        ),
    }

    service = DashboardService._service_candidate(row, preferred_port="invalid")

    assert service is not None
    assert service.title == "HTTPS - 443/tcp"
    assert DashboardService._service_candidate(row, preferred_port=22) is None


def test_malformed_optional_values_use_neutral_dashboard_states(monkeypatch):
    monkeypatch.setattr(
        db,
        "dashboard_active_scan",
        lambda: {"target": "dashboard-progress.local", "status": "running", "progress": "invalid"},
    )
    active = DashboardService()._active_scan()
    activity = DashboardService._activity_item(
        {
            "timestamp": "not-a-date",
            "severity": "Info",
            "item_type": "signal",
            "title": "Malformed time",
            "asset": "dashboard-time.local",
            "source": "test",
            "source_id": "scan:1",
            "cve_id": "",
        }
    )

    assert active is not None
    assert active.progress is None
    assert activity.timestamp is None


def test_one_summary_source_failure_is_isolated(monkeypatch):
    def _raise():
        raise RuntimeError("honeypot unavailable")

    monkeypatch.setattr(db, "dashboard_honeypot_summary", _raise)

    summary = DashboardService().get_summary()

    assert len(summary.metrics) == 4
    assert summary.operational.honeypot is None
    assert "honeypot" in summary.operational.errors


def test_malformed_attack_path_result_is_not_reported_as_empty_success(monkeypatch):
    monkeypatch.setattr("sentinelforge.ui.dashboard_service.attack_paths.analyze", lambda **_kwargs: {})
    monkeypatch.setattr(db, "dashboard_service_candidates", lambda limit=200: [])

    summary = DashboardService().get_summary()

    assert summary.operational.attack_paths is None
    assert "attack_paths" in summary.operational.errors


def test_dashboard_render_uses_explicit_unavailable_state_on_summary_failure(monkeypatch):
    applied: list[OperationalSummary] = []
    original_set_summary = OperationalSummaryPanel.set_summary

    def _capture_summary(self, summary):
        applied.append(summary)
        original_set_summary(self, summary)

    class FailingService:
        @staticmethod
        def get_summary():
            raise RuntimeError("summary unavailable")

        @staticmethod
        def get_activity(**_kwargs):
            return []

    class ImmediatePage:
        _sf_current_view = "dashboard"
        _sf_cleanups: list = []

        @staticmethod
        def run_thread(callback, **kwargs):
            callback(**kwargs)

        @staticmethod
        def update():
            return None

    monkeypatch.setattr(OperationalSummaryPanel, "set_summary", _capture_summary)
    page = ImmediatePage()

    control = dashboard_view.render(page, service=FailingService())

    assert control is not None
    assert applied
    assert set(applied[-1].errors) == {"active_scan", "exposed_service", "attack_paths", "honeypot"}
    for cleanup in page._sf_cleanups:
        cleanup()


def test_sidebar_preserves_existing_navigation_and_new_scan_callback():
    assert [view[1] for view in shell.VIEWS] == [
        "Dashboard",
        "Assets",
        "Findings",
        "Attack Paths",
        "Honeypot",
        "Scanner",
        "Recon",
        "Settings",
    ]
    navigated: list[str] = []
    button = shell._new_scan_button(lambda _event: navigated.append("scanner"))

    button.on_click(None)

    assert navigated == ["scanner"]


def test_operational_panel_accepts_partial_unavailable_state():
    panel = OperationalSummaryPanel(on_open_scanner=lambda _event: None, on_open_attack_paths=lambda _event: None)
    panel.set_summary(
        OperationalSummary(
            errors={
                "active_scan": "Active scan data is currently unavailable",
                "attack_paths": "Attack path data is currently unavailable",
            }
        )
    )

    assert len(panel._sections.controls) == 4

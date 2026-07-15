from __future__ import annotations

import ipaddress
import json
import logging
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from ..core import db
from ..modules.analysis import attack_paths

logger = logging.getLogger(__name__)

ActivityType = Literal["signal", "finding"]


@dataclass(slots=True, frozen=True)
class DashboardActivityItem:
    timestamp: datetime | None
    severity: str
    item_type: ActivityType
    title: str
    asset: str
    source: str
    source_id: str | None = None
    cve_id: str = ""


@dataclass(slots=True, frozen=True)
class DashboardMetric:
    title: str
    value: str
    subtitle: str
    accent: str
    available: bool = True


@dataclass(slots=True, frozen=True)
class ActiveScanSummary:
    target: str = ""
    status: str = ""
    progress: float | None = None


@dataclass(slots=True, frozen=True)
class ExposedServiceSummary:
    title: str = ""
    detail: str = ""
    asset: str = ""


@dataclass(slots=True, frozen=True)
class AttackPathPressure:
    high_confidence: int = 0
    highest_score: float = 0.0


@dataclass(slots=True, frozen=True)
class HoneypotActivity:
    events: int = 0
    source_ips: int = 0
    last_event: str = ""


@dataclass(slots=True, frozen=True)
class OperationalSummary:
    active_scan: ActiveScanSummary | None = None
    exposed_service: ExposedServiceSummary | None = None
    attack_paths: AttackPathPressure | None = None
    honeypot: HoneypotActivity | None = None
    errors: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True, frozen=True)
class DashboardSummary:
    metrics: tuple[DashboardMetric, ...]
    operational: OperationalSummary
    errors: dict[str, str] = field(default_factory=dict)


class DashboardService:
    """Compose bounded storage queries and existing analyzers for the Dashboard."""

    def get_summary(self) -> DashboardSummary:
        errors: dict[str, str] = {}
        operational_errors: dict[str, str] = {}

        try:
            counts = db.dashboard_counts()
            metrics = self._metrics(counts)
        except Exception:
            logger.exception("Dashboard KPI query failed")
            errors["metrics"] = "Dashboard metrics are currently unavailable"
            metrics = self._unavailable_metrics()

        try:
            active_scan = self._active_scan()
        except Exception:
            logger.exception("Dashboard active scan query failed")
            operational_errors["active_scan"] = "Active scan data is currently unavailable"
            active_scan = None

        try:
            path_data = attack_paths.analyze(limit=50, include_low=True)
            if not isinstance(path_data, dict) or not isinstance(path_data.get("summary"), dict):
                raise TypeError("Attack path analyzer returned an invalid summary")
            path_summary = path_data["summary"]
            path_pressure = AttackPathPressure(
                high_confidence=int(path_summary.get("high_confidence", 0) or 0),
                highest_score=float(path_summary.get("top_score", 0.0) or 0.0),
            )
        except Exception:
            logger.exception("Dashboard attack path analysis failed")
            operational_errors["attack_paths"] = "Attack path data is currently unavailable"
            path_data = {"paths": []}
            path_pressure = None

        try:
            raw_paths = path_data.get("paths", []) if isinstance(path_data, dict) else []
            exposed_service = self._top_exposed_service(raw_paths if isinstance(raw_paths, list) else [])
        except Exception:
            logger.exception("Dashboard exposed service query failed")
            operational_errors["exposed_service"] = "Exposed service data is currently unavailable"
            exposed_service = None

        try:
            honeypot = self._honeypot_activity()
        except Exception:
            logger.exception("Dashboard honeypot summary failed")
            operational_errors["honeypot"] = "Honeypot data is currently unavailable"
            honeypot = None

        return DashboardSummary(
            metrics=metrics,
            operational=OperationalSummary(
                active_scan=active_scan,
                exposed_service=exposed_service,
                attack_paths=path_pressure,
                honeypot=honeypot,
                errors=operational_errors,
            ),
            errors=errors,
        )

    def get_activity(
        self,
        *,
        activity_type: str = "",
        severity: str = "",
        search: str = "",
        limit: int = 10,
    ) -> list[DashboardActivityItem]:
        rows = db.dashboard_activity(
            activity_type=activity_type,
            severity=severity,
            search=search,
            limit=limit,
        )
        return [self._activity_item(row) for row in rows]

    def _metrics(self, counts: dict[str, int | float]) -> tuple[DashboardMetric, ...]:
        severity_score = float(counts.get("severity_score", 0.0) or 0.0)
        priority_score = float(counts.get("priority_score", 0.0) or 0.0)
        # This adapter reports the strongest current risk evidence. It deliberately
        # leaves correlation priority and severity formulas unchanged.
        risk_score = max(0, min(100, round(max(severity_score, priority_score))))
        review_items = int(counts.get("review_items", 0) or 0)
        risk_label = self._risk_label(risk_score)
        if review_items:
            risk_subtitle = f"{risk_label} - review {review_items} item{'s' if review_items != 1 else ''}"
        elif risk_score:
            risk_subtitle = f"{risk_label} current risk evidence"
        else:
            risk_subtitle = "No current risk evidence"
        scan_runs = int(counts.get("scan_runs", 0) or 0)
        running_scans = int(counts.get("running_scans", 0) or 0)
        scan_subtitle = (
            f"{running_scans} running now - {scan_runs} recorded"
            if running_scans
            else f"{scan_runs} recorded run{'s' if scan_runs != 1 else ''}"
        )
        return (
            DashboardMetric("Risk posture", f"{risk_score} / 100", risk_subtitle, "critical"),
            DashboardMetric(
                "Findings",
                str(int(counts.get("findings", 0) or 0)),
                "Current finding inventory",
                "brand",
            ),
            DashboardMetric(
                "Assets",
                str(int(counts.get("assets", 0) or 0)),
                "Known asset inventory",
                "info",
            ),
            DashboardMetric("Active scans", str(running_scans), scan_subtitle, "success"),
        )

    @staticmethod
    def _unavailable_metrics() -> tuple[DashboardMetric, ...]:
        return tuple(
            DashboardMetric(title, "-", "Temporarily unavailable", accent, available=False)
            for title, accent in (
                ("Risk posture", "critical"),
                ("Findings", "brand"),
                ("Assets", "info"),
                ("Active scans", "success"),
            )
        )

    @staticmethod
    def _risk_label(score: int) -> str:
        if score >= 90:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 35:
            return "Medium"
        return "Low"

    @staticmethod
    def _active_scan() -> ActiveScanSummary | None:
        row = db.dashboard_active_scan()
        if row is None:
            return None
        status = str(row["status"] or "").lower()
        return ActiveScanSummary(
            target=str(row["target"] or "Unknown target"),
            status=status.upper(),
            progress=_bounded_progress(row["progress"]),
        )

    def _top_exposed_service(self, paths: list[dict]) -> ExposedServiceSummary | None:
        candidates = db.dashboard_service_candidates(limit=200)
        rows_by_asset = {str(row["hostname"] or ""): row for row in candidates}
        # Prefer the exact service named by the strongest attack-path evidence.
        for path in paths:
            if not isinstance(path, dict):
                continue
            asset = str(path.get("asset") or "")
            if not path.get("internet_exposed") or asset not in rows_by_asset:
                continue
            evidence = path.get("evidence") if isinstance(path.get("evidence"), dict) else {}
            match = self._service_candidate(
                rows_by_asset[asset],
                preferred_port=evidence.get("port"),
                preferred_proto=str(evidence.get("proto") or ""),
                preferred_service=str(evidence.get("service") or ""),
            )
            if match is not None:
                return match

        # The storage query provides a deterministic risk-ordered fallback.
        for row in candidates:
            match = self._service_candidate(row)
            if match is not None:
                return match
        return None

    @staticmethod
    def _service_candidate(
        row,
        *,
        preferred_port: object = None,
        preferred_proto: str = "",
        preferred_service: str = "",
    ) -> ExposedServiceSummary | None:
        try:
            ips = json.loads(row["normalized_ips"] or "[]")
            services = json.loads(row["open_services"] or "[]")
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        if not isinstance(ips, list) or not isinstance(services, list):
            return None
        if not any(_is_public_ip(ip) for ip in ips):
            return None
        valid_services = []
        for service in services:
            if not isinstance(service, dict):
                continue
            try:
                port = int(service.get("port"))
            except (TypeError, ValueError, OverflowError):
                continue
            if not 1 <= port <= 65535:
                continue
            valid_services.append({**service, "port": port})
        if not valid_services:
            return None
        ordered_services = sorted(
            valid_services,
            key=lambda item: (
                int(item.get("port") or 0),
                str(item.get("proto") or "tcp"),
                str(item.get("service") or "service"),
            ),
        )
        try:
            preferred_port_number = int(preferred_port) if preferred_port is not None else None
        except (TypeError, ValueError, OverflowError):
            preferred_port_number = None
        preferred_proto = preferred_proto.strip().lower()
        preferred_service = preferred_service.strip().lower()
        has_preference = preferred_port_number is not None or bool(preferred_proto or preferred_service)
        matching_services = [
            item
            for item in ordered_services
            if (preferred_port_number is None or int(item.get("port") or 0) == preferred_port_number)
            and (not preferred_proto or str(item.get("proto") or "tcp").lower() == preferred_proto)
            and (not preferred_service or str(item.get("service") or "service").lower() == preferred_service)
        ]
        if has_preference and not matching_services:
            return None
        service = matching_services[0] if matching_services else ordered_services[0]
        name = str(service.get("service") or "service").upper()
        port = int(service.get("port") or 0)
        proto = str(service.get("proto") or "tcp").lower()
        version = str(service.get("version") or "").strip()
        if not version:
            version = str(service.get("banner") or "").splitlines()[0].strip()[:72]
        detail = f"{version + ' - ' if version else ''}public exposure"
        return ExposedServiceSummary(
            title=f"{name} - {port}/{proto}",
            detail=detail,
            asset=str(row["hostname"] or ""),
        )

    @staticmethod
    def _honeypot_activity() -> HoneypotActivity:
        row = db.dashboard_honeypot_summary()
        return HoneypotActivity(
            events=int(row["events"] or 0),
            source_ips=int(row["source_ips"] or 0),
            last_event=_relative_time(row["last_event_ts"]),
        )

    @staticmethod
    def _activity_item(row) -> DashboardActivityItem:
        item_type: ActivityType = "finding" if row["item_type"] == "finding" else "signal"
        return DashboardActivityItem(
            timestamp=_parse_datetime(row["timestamp"]),
            severity=str(row["severity"] or "Info"),
            item_type=item_type,
            title=str(row["title"] or "Activity"),
            asset=str(row["asset"] or "-"),
            source=str(row["source"] or "-"),
            source_id=str(row["source_id"]) if row["source_id"] is not None else None,
            cve_id=str(row["cve_id"] or ""),
        )


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=parsed.tzinfo or UTC)


def _relative_time(value: str | None) -> str:
    if not value:
        return "No events recorded"
    parsed = _parse_datetime(value)
    if parsed is None:
        return "Last event time unavailable"
    elapsed = max(0, int((datetime.now(UTC) - parsed).total_seconds()))
    if elapsed < 60:
        return "Last event just now"
    if elapsed < 3600:
        minutes = elapsed // 60
        return f"Last event {minutes} minute{'s' if minutes != 1 else ''} ago"
    if elapsed < 86400:
        hours = elapsed // 3600
        return f"Last event {hours} hour{'s' if hours != 1 else ''} ago"
    days = elapsed // 86400
    return f"Last event {days} day{'s' if days != 1 else ''} ago"


def _is_public_ip(value: object) -> bool:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return address.is_global


def _bounded_progress(value: object) -> float | None:
    try:
        progress = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(progress):
        return None
    return max(0.0, min(progress, 1.0))

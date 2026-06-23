"""Centralized domain operations for HomeInfra."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from .collector_service import CollectorService
from .audit import AuditService
from .monitoring import MonitoringService
from .errors import ValidationError
from .mock_data import utc_now


class HomeInfraService:
    def __init__(self, store, *, collector_service: CollectorService | None = None) -> None:
        self.store = store
        self.audit = AuditService(store)
        self.monitoring = MonitoringService(store, collector_service=collector_service)

    def dashboard(self) -> dict[str, Any]:
        snapshot = self.store.snapshot()
        monitoring = self.monitoring.overview()
        return {
            "summary": {
                "total_devices": monitoring["summary"]["total_devices"],
                "healthy_devices": monitoring["summary"]["online_devices"],
                "degraded_devices": monitoring["summary"]["warning_devices"],
                "offline_devices": monitoring["summary"]["offline_devices"],
                "open_alerts": monitoring["summary"]["active_alerts"],
                "groups": monitoring["summary"]["groups"],
                "average_cpu_percent": monitoring["summary"]["average_cpu_percent"],
                "average_memory_percent": monitoring["summary"]["average_memory_percent"],
                "storage_pool_risks": monitoring["summary"]["storage_pool_risks"],
                "latest_collection_at": monitoring["summary"]["latest_collection_at"],
                "health_score": monitoring["summary"]["health_score"],
            },
            "monitoring": monitoring,
            "recent_audit": self.audit.list_recent(limit=10),
        }

    def get_retention_settings(self) -> dict[str, Any]:
        return self.store.read("retention_settings")

    def get_collection_settings(self) -> dict[str, Any]:
        try:
            return self.store.read("collection_settings")
        except KeyError:
            return {"default_collection_interval": 30}

    def update_collection_settings(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValidationError("采集设置请求体必须是对象")
        validated: dict[str, int] = {}
        if "default_collection_interval" in payload:
            value = payload.get("default_collection_interval")
            if not isinstance(value, int) or value < 30:
                raise ValidationError("default_collection_interval 必须是不小于 30 的整数")
            validated["default_collection_interval"] = value
        if not validated:
            raise ValidationError("采集设置更新至少需要一个字段")

        def mutate(state):
            current = state.get("collection_settings") or {"default_collection_interval": 30}
            current.update(validated)
            state["collection_settings"] = current
            return dict(current)

        return self.store.update(mutate)

    def update_retention_settings(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValidationError("保留策略请求体必须是对象")
        validated: dict[str, int] = {}
        for field in ("collection_history_days", "audit_log_days", "resolved_alert_days"):
            if field not in payload:
                continue
            value = payload.get(field)
            if not isinstance(value, int) or value <= 0 or value > 3650:
                raise ValidationError(f"{field} 必须是 1-3650 之间的整数")
            validated[field] = value
        if not validated:
            raise ValidationError("保留策略更新至少需要一个字段")

        def mutate(state):
            state["retention_settings"].update(validated)
            return dict(state["retention_settings"])

        return self.store.update(mutate)

    def cleanup_retention(self) -> dict[str, Any]:
        def mutate(state):
            now = utc_now()
            settings = state["retention_settings"]
            history_cutoff = now - timedelta(days=settings["collection_history_days"])
            audit_cutoff = now - timedelta(days=settings["audit_log_days"])
            resolved_alert_cutoff = now - timedelta(days=settings["resolved_alert_days"])
            protected_record_ids = {
                alert.get("last_record_id")
                for alert in state["alerts"]
                if alert.get("status") == "active" and alert.get("last_record_id")
            }

            before_records = len(state["collection_records"])
            before_logs = len(state["audit_logs"])
            before_alerts = len(state["alerts"])

            state["collection_records"] = [
                record
                for record in state["collection_records"]
                if record.get("id") in protected_record_ids
                or self._keep_timestamp(record.get("collected_at"), history_cutoff)
            ]
            state["audit_logs"] = [
                entry
                for entry in state["audit_logs"]
                if self._keep_timestamp(entry.get("timestamp"), audit_cutoff)
            ]
            state["alerts"] = [
                alert
                for alert in state["alerts"]
                if alert.get("status") == "active"
                or self._keep_timestamp(
                    alert.get("resolved_at") or alert.get("updated_at") or alert.get("created_at"),
                    resolved_alert_cutoff,
                )
            ]

            return {
                "retention_settings": dict(settings),
                "deleted": {
                    "collection_records": before_records - len(state["collection_records"]),
                    "audit_logs": before_logs - len(state["audit_logs"]),
                    "resolved_alerts": before_alerts - len(state["alerts"]),
                },
                "active_alerts_preserved": sum(
                    1 for alert in state["alerts"] if alert.get("status") == "active"
                ),
            }

        return self.store.update(mutate)

    def _keep_timestamp(self, raw_timestamp: str | None, cutoff: datetime) -> bool:
        if not raw_timestamp:
            return True
        try:
            value = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
        except ValueError:
            return True
        return value >= cutoff

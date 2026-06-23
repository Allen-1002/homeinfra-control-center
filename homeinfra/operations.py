"""Centralized domain operations for mock HomeInfra resources."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from .collector_service import CollectorService
from .automation import AutomationService
from .audit import AuditService
from .monitoring import MonitoringService
from .errors import ConflictError, NotFoundError, ValidationError
from .mock_data import isoformat, utc_now
from .risk import build_nas_risks, build_vpn_risks


class HomeInfraService:
    def __init__(self, store, *, collector_service: CollectorService | None = None) -> None:
        self.store = store
        self.audit = AuditService(store)
        self.automation = AutomationService(store)
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
                "running_containers": sum(
                    1 for container in snapshot["docker"]["containers"] if container["state"] == "running"
                ),
                "paused_tasks": sum(
                    1 for task in snapshot["automation"]["tasks"] if task["state"] == "paused"
                ),
                "nas_risks": len(build_nas_risks(snapshot["nas"])),
                "vpn_risks": len(build_vpn_risks(snapshot["vpn"])),
            },
            "monitoring": monitoring,
            "nas": self.get_nas(),
            "vpn": self.get_vpn(),
            "docker": self.get_docker(),
            "automation": self.automation.list_tasks(),
            "recent_audit": self.audit.list_recent(limit=10),
        }

    def get_nas(self) -> dict[str, Any]:
        nas = self.store.read("nas")
        nas["risks"] = build_nas_risks(nas)
        return nas

    def start_backup(self) -> dict[str, Any]:
        def mutate(state):
            state["nas"]["backup"]["last_success_at"] = isoformat(utc_now())
            state["nas"]["backup"]["status"] = "healthy"
            state["metrics"]["backup_runs_total"] += 1
            return state["nas"]["backup"]

        return self.store.update(mutate)

    def set_sync_state(self, sync_id: str, target_state: str) -> dict[str, Any]:
        def mutate(state):
            for job in state["nas"]["sync_jobs"]:
                if job["id"] == sync_id:
                    if job["state"] == target_state:
                        raise ConflictError("同步任务已经处于目标状态", {"sync_id": sync_id})
                    job["state"] = target_state
                    job["updated_at"] = isoformat(utc_now())
                    return job
            raise NotFoundError("nas sync job", sync_id)

        return self.store.update(mutate)

    def get_vpn(self) -> dict[str, Any]:
        vpn = self.store.read("vpn")
        vpn["risks"] = build_vpn_risks(vpn)
        return vpn

    def disconnect_vpn_client(self, client_id: str) -> dict[str, Any]:
        def mutate(state):
            for client in state["vpn"]["clients"]:
                if client["id"] == client_id:
                    if client["state"] == "disconnected":
                        raise ConflictError("VPN 客户端已经断开", {"client_id": client_id})
                    client["state"] = "disconnected"
                    client["last_seen_at"] = isoformat(utc_now())
                    state["metrics"]["vpn_disconnects_total"] += 1
                    return client
            raise NotFoundError("vpn client", client_id)

        return self.store.update(mutate)

    def create_fake_vpn_config(self, client_id: str) -> dict[str, Any]:
        snapshot = self.store.read("vpn")
        for client in snapshot["clients"]:
            if client["id"] == client_id:
                return {
                    "client_id": client_id,
                    "format": "wireguard",
                    "download_name": f"{client_id}.conf",
                    "config_preview": [
                        "[Interface]",
                        "PrivateKey = MOCK_PRIVATE_KEY_NOT_REAL",
                        "Address = 10.8.0.99/32",
                        "[Peer]",
                        "PublicKey = MOCK_PUBLIC_KEY_NOT_REAL",
                        "Endpoint = vpn.mock.homeinfra:51820",
                    ],
                }
        raise NotFoundError("vpn client", client_id)

    def get_docker(self) -> dict[str, Any]:
        return self.store.read("docker")

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

    def change_container_state(self, container_id: str, action: str) -> dict[str, Any]:
        desired_state = "running" if action == "start" else "stopped"

        def mutate(state):
            for container in state["docker"]["containers"]:
                if container["id"] == container_id:
                    if action == "restart":
                        container["logs"].insert(0, f"{isoformat(utc_now())} container restarted in mock mode")
                        container["state"] = "running"
                    else:
                        if container["state"] == desired_state:
                            raise ConflictError(
                                "容器已经处于目标状态",
                                {"container_id": container_id, "state": desired_state},
                            )
                        container["state"] = desired_state
                        container["logs"].insert(
                            0,
                            f"{isoformat(utc_now())} container {action} requested in mock mode",
                        )
                    container["logs"] = container["logs"][:50]
                    state["metrics"]["container_operations_total"] += 1
                    return container
            raise NotFoundError("docker container", container_id)

        return self.store.update(mutate)

    def container_logs(self, container_id: str) -> dict[str, Any]:
        snapshot = self.store.read("docker")
        for container in snapshot["containers"]:
            if container["id"] == container_id:
                return {"id": container_id, "logs": container["logs"]}
        raise NotFoundError("docker container", container_id)

    def _keep_timestamp(self, raw_timestamp: str | None, cutoff: datetime) -> bool:
        if not raw_timestamp:
            return True
        try:
            value = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
        except ValueError:
            return True
        return value >= cutoff

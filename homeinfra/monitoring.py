"""Device monitoring domain logic for groups, devices, collections, and alerts."""

from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime
from typing import Any

from .collector_service import CollectorService
from .collectors import (
    CollectorError,
    DisabledCollector,
    MockCommandCollector,
    EXTERNAL_SECRET_SENTINEL,
    allow_stored_password_auth,
)
from .errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from .mock_data import isoformat, utc_now


UNGROUPED_GROUP_ID = "grp-ungrouped"
VALID_DEVICE_STATUSES = {"online", "offline", "warning", "unknown", "disabled", "unavailable"}
VALID_AUTH_TYPES = {"password", "private_key", "none"}
VALID_DEVICE_TYPES = {"linux_server", "nas", "openwrt", "docker_host", "proxmox_host", "router", "mini_pc", "other"}
OPERATOR_EDITABLE_DEVICE_FIELDS = {
    "name",
    "group_id",
    "tags",
    "enabled",
    "collection_interval",
}
OPERATOR_PROTECTED_DEVICE_FIELDS = {
    "host",
    "port",
    "device_type",
    "username",
    "auth_type",
    "password",
    "inline_private_key",
    "private_key_path",
    "key_path",
    "encrypted_private_key",
}
CONNECTION_RELATED_FIELDS = {
    "host",
    "port",
    "username",
    "auth_type",
    "password",
    "inline_private_key",
    "private_key_path",
    "key_path",
    "encrypted_private_key",
}

OBSERVABLE_COLLECTION_KEYS = (
    "hostname",
    "uname",
    "cpu_percent",
    "cpu_cores",
    "memory_percent",
    "memory_total_mb",
    "memory_used_mb",
    "disk_percent",
    "network_rx_mbps",
    "network_tx_mbps",
    "load_average",
    "uptime",
    "partitions",
    "network_interfaces",
    "block_devices",
    "nas_pools",
    "nas_volumes",
    "nas_snapshots",
    "nas_raid",
    "btrfs_filesystems",
    "btrfs_device_stats",
    "btrfs_usage",
    "pve_version",
    "pve_storage",
    "pve_vms",
    "pve_lxcs",
    "pve_interfaces",
    "docker_info",
)


def _slugify(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.strip().lower())
    normalized = normalized.strip("-")
    return normalized or "item"


def _parse_last_seen(value):
    if not value:
        return None
    try:
        from datetime import datetime
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _next_numbered_id(prefix: str, items: list[dict[str, Any]]) -> str:
    highest = 0
    for item in items:
        item_id = str(item.get("id", ""))
        if not item_id.startswith(prefix + "-"):
            continue
        try:
            highest = max(highest, int(item_id.rsplit("-", 1)[1]))
        except ValueError:
            continue
    return f"{prefix}-{highest + 1:05d}"


def _has_observable_collection_data(payload: dict[str, Any]) -> bool:
    for key in OBSERVABLE_COLLECTION_KEYS:
        value = payload.get(key)
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, (list, dict)) and not value:
            continue
        return True
    return False


def _is_successful_collection_record(record: dict[str, Any]) -> bool:
    return record.get("error_message") in {None, ""}


def _enrich_collection_record(record: dict[str, Any]) -> dict[str, Any]:
    enriched = deepcopy(record)
    payload = enriched.get("payload", {}) or {}
    if "detail_code" not in enriched:
        enriched["detail_code"] = payload.get("__collection_detail_code") or (
            "collection_failed" if enriched.get("error_message") else "collection_succeeded"
        )
    if "detail_message" not in enriched:
        enriched["detail_message"] = payload.get("__collection_detail_message") or (
            enriched.get("error_message") or enriched.get("summary")
        )
    if "data_source" not in enriched and payload.get("__data_source") is not None:
        enriched["data_source"] = payload.get("__data_source")
    if "is_real_data" not in enriched and payload.get("__is_real_data") is not None:
        enriched["is_real_data"] = payload.get("__is_real_data")
    return enriched


def monitoring_penalty(*, offline: int, warning: int, alerts: int) -> int:
    return offline * 25 + warning * 10 + alerts * 5


def is_ssh_command_allowed(command: str) -> bool:
    banned = ("rm ", "dd ", "mkfs", "reboot", "shutdown", "iptables ", "poweroff", ":(){")
    normalized = (command or "").strip().lower()
    return not any(token in normalized for token in banned)


def collect_mock_metrics() -> dict[str, Any]:
    service = CollectorService(
        MockCommandCollector(),
        sample_interval=1.0,
        data_source="mock",
        is_real_data=False,
    )
    payload = service.collect(
        {
            "name": "mock-device",
            "host": "192.0.2.20",
            "device_type": "nas",
            "status": "online",
            "enabled": True,
        },
        timeout=5,
        purpose="test",
    ).payload
    payload["nas"] = {"storage_pool": payload.get("storage_pool")}
    payload["alerts"] = []
    return payload


def generate_collection_failure_alert(device_id: str, error: str) -> dict[str, Any]:
    return {
        "device_id": device_id,
        "severity": "critical",
        "type": "collection_failed",
        "message": error,
    }


def evaluate_threshold_alerts(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []

    cpu_pct = metrics.get("cpu_percent", 0)
    if cpu_pct > 90:
        alerts.append({
            "severity": "warning",
            "type": "cpu_high",
            "title": "CPU 使用率过高",
            "message": f"CPU 使用率 {cpu_pct}% 超过 90%",
        })

    for core in metrics.get("per_core_cpu", []):
        core_pct = core.get("percent", 0)
        if core_pct > 95:
            alerts.append({
                "severity": "warning",
                "type": "cpu_core_high",
                "title": f"CPU 核心 {core.get('core', '?')} 使用率过高",
                "message": f"核心 {core.get('core', '?')} 使用率 {core_pct}% 超过 95%",
            })

    mem_pct = metrics.get("memory_percent", 0)
    if mem_pct > 90:
        alerts.append({
            "severity": "warning",
            "type": "memory_high",
            "title": "内存使用率过高",
            "message": f"内存使用率 {mem_pct}% 超过 90%",
        })

    disk_pct = metrics.get("disk_percent", 0)
    if disk_pct > 85:
        alerts.append({
            "severity": "warning",
            "type": "disk_high",
            "title": "磁盘使用率过高",
            "message": f"根分区使用率 {disk_pct}% 超过 85%",
        })

    for part in metrics.get("partitions", []):
        part_pct = part.get("percent", 0)
        mount = part.get("mount", "?")
        if part_pct > 90:
            alerts.append({
                "severity": "critical",
                "type": "partition_critical",
                "title": f"分区 {mount} 使用率严重过高",
                "message": f"分区 {mount} 使用率 {part_pct}% 超过 90%",
            })
        elif part_pct > 85:
            alerts.append({
                "severity": "warning",
                "type": "partition_high",
                "title": f"分区 {mount} 使用率过高",
                "message": f"分区 {mount} 使用率 {part_pct}% 超过 85%",
            })

    for sensor in metrics.get("temperatures", []):
        temp_c = sensor.get("temp_c", 0)
        label = sensor.get("sensor", "unknown")
        if temp_c > 85:
            alerts.append({
                "severity": "critical",
                "type": "temperature_critical",
                "title": f"传感器 {label} 温度严重过高",
                "message": f"{label} 温度 {temp_c}C 超过 85C",
            })
        elif temp_c > 75:
            alerts.append({
                "severity": "warning",
                "type": "temperature_high",
                "title": f"传感器 {label} 温度过高",
                "message": f"{label} 温度 {temp_c}C 超过 75C",
            })

    max_temp = metrics.get("temperature_c", 0)
    if max_temp > 80:
        alerts.append({
            "severity": "critical",
            "type": "temperature_max_high",
            "title": "设备最高温度过高",
            "message": f"设备最高温度 {max_temp}C 超过 80C",
        })

    for pool in metrics.get("nas_pools", []):
        pool_pct = pool.get("usage_percent", 0)
        pool_name = pool.get("name", "?")
        if pool_pct > 90:
            alerts.append({
                "severity": "critical",
                "type": "nas_pool_critical",
                "title": f"NAS 存储池 {pool_name} 使用率严重过高",
                "message": f"存储池 {pool_name} 使用率 {pool_pct}% 超过 90%",
            })
        elif pool_pct > 85:
            alerts.append({
                "severity": "warning",
                "type": "nas_pool_high",
                "title": f"NAS 存储池 {pool_name} 使用率过高",
                "message": f"存储池 {pool_name} 使用率 {pool_pct}% 超过 85%",
            })
        if pool.get("health_state", "").upper() not in {"", "ONLINE", "HEALTHY"}:
            alerts.append({
                "severity": "critical",
                "type": "nas_pool_degraded",
                "title": f"NAS 存储池 {pool_name} 状态异常",
                "message": f"存储池 {pool_name} 状态: {pool.get('health_state')}",
            })

    for raid in metrics.get("nas_raid", []):
        degraded = raid.get("degraded_drives", 0)
        if degraded > 0:
            alerts.append({
                "severity": "critical",
                "type": "nas_raid_degraded",
                "title": f"RAID {raid.get('name', '?')} 降级",
                "message": f"RAID {raid.get('name', '?')} 有 {degraded} 个降级磁盘",
            })
        if raid.get("state", "").upper() not in {"", "ONLINE", "HEALTHY", "OK"}:
            alerts.append({
                "severity": "critical",
                "type": "nas_raid_abnormal",
                "title": f"RAID {raid.get('name', '?')} 状态异常",
                "message": f"RAID {raid.get('name', '?')} 状态: {raid.get('state')}",
            })

    return alerts


SMART_CRITICAL_ATTRS = {
    "reallocated_sector_ct": "重新分配扇区数",
    "current_pending_sector": "当前待处理扇区",
    "offline_uncorrectable": "离线不可纠正扇区",
    "reallocated_event_count": "重新分配事件计数",
    "spin_retry_count": "自旋重试次数",
    "end_to_end_error": "端到端错误",
    "reported_uncorrect": "报告不可纠正错误",
    "command_timeout": "命令超时",
    "high_fly_writes": "高飞写入",
}

SMART_WARNING_ATTRS = {
    "temperature_celsius": "磁盘温度",
    "seek_error_rate": "寻道错误率",
    "read_error_rate": "读取错误率",
    "write_error_rate": "写入错误率",
    "hardware_ecc_recovered": "硬件 ECC 恢复",
}


def evaluate_smart_alert(metrics: dict[str, Any]) -> dict[str, Any] | None:
    smart_status = metrics.get("smart_status")
    if smart_status and smart_status not in {"healthy", "ok"}:
        return {
            "severity": "critical",
            "type": "smart_abnormal",
            "title": "SMART 状态异常",
            "message": f"SMART 状态异常：{smart_status}",
        }

    for attr in metrics.get("smart_attributes", []):
        name = attr.get("attr_name", "")
        raw_val = attr.get("raw", 0)
        if name in SMART_CRITICAL_ATTRS and raw_val > 0:
            return {
                "severity": "critical",
                "type": f"smart_{name}",
                "title": f"SMART {SMART_CRITICAL_ATTRS[name]} 异常",
                "message": f"{SMART_CRITICAL_ATTRS[name]} = {raw_val}，磁盘可能出现故障",
            }
        if name in SMART_WARNING_ATTRS and raw_val > 0:
            threshold = attr.get("threshold", 0)
            if isinstance(threshold, (int, float)) and raw_val > threshold:
                return {
                    "severity": "warning",
                    "type": f"smart_{name}",
                    "title": f"SMART {SMART_WARNING_ATTRS[name]} 偏高",
                    "message": f"{SMART_WARNING_ATTRS[name]} = {raw_val}，超过阈值 {threshold}",
                }

    for attr in metrics.get("smart_attributes", []):
        if attr.get("status") and attr["status"] not in {"", "ok", "healthy", "PASSED"}:
            return {
                "severity": "critical",
                "type": f"smart_{attr.get('attr_name', 'unknown')}",
                "title": f"SMART 属性 {attr.get('attr_name')} 告警",
                "message": f"SMART {attr.get('attr_name')} 状态: {attr.get('status')}",
            }

    return None


def init_sqlite(path: str) -> Any:
    from .persistence import SQLiteStore

    return SQLiteStore(path)


def save_device(path: str, device: dict[str, Any]) -> dict[str, Any]:
    from .persistence import SQLiteStore

    store = SQLiteStore(path)
    service = MonitoringService(store)
    return service.create_device(
        {
            "id": device["id"],
            "name": device["name"],
            "host": device["host"],
            "port": device.get("port", 22),
            "username": device.get("username", "monitor"),
            "auth_type": device.get("auth_type", "none"),
            "private_key_path": device.get("private_key_path"),
            "device_type": device.get("device_type", "other"),
            "group_id": device.get("group_id", UNGROUPED_GROUP_ID),
            "tags": device.get("tags", []),
            "enabled": device.get("enabled", True),
            "collection_interval": device.get("collection_interval", device.get("poll_interval", 60)),
            "status": device.get("status", "unknown"),
            "verified": bool(device.get("verified", False)),
        }
    )


def get_device(path: str, device_id: str) -> dict[str, Any]:
    from .persistence import SQLiteStore

    store = SQLiteStore(path)
    service = MonitoringService(store)
    return service.get_device(device_id)


class MonitoringService:
    def __init__(self, store, collector_service: CollectorService | None = None) -> None:
        self.store = store
        self.collector_service = collector_service

    def overview(self) -> dict[str, Any]:
        snapshot = self.store.snapshot()
        devices = snapshot["devices"]
        alerts = snapshot["alerts"]
        groups = snapshot["device_groups"]
        active_alerts = [alert for alert in alerts if alert["status"] == "active"]
        latest_collection = snapshot["collection_records"][0]["collected_at"] if snapshot["collection_records"] else None
        cpu_values = [
            float(record.get("payload", {}).get("cpu_percent", 0))
            for record in snapshot["collection_records"]
            if "cpu_percent" in record.get("payload", {})
        ]
        memory_values = [
            float(record.get("payload", {}).get("memory_percent", 0))
            for record in snapshot["collection_records"]
            if "memory_percent" in record.get("payload", {})
        ]
        storage_pool_risks = sum(
            1
            for record in snapshot["collection_records"]
            if record.get("payload", {}).get("storage_pool", {}).get("usage_percent", 0) > 85
        )
        group_summaries = []
        for group in groups:
            group_devices = [device for device in devices if device.get("group_id") == group["id"]]
            group_alerts = [alert for alert in active_alerts if alert.get("group_id") == group["id"]]
            group_summaries.append(
                {
                    **deepcopy(group),
                    "device_count": len(group_devices),
                    "online_count": sum(1 for device in group_devices if device["status"] == "online"),
                    "offline_count": sum(1 for device in group_devices if device["status"] == "offline"),
                    "warning_count": sum(1 for device in group_devices if device["status"] == "warning"),
                    "active_alert_count": len(group_alerts),
                }
            )

        summary = {
            "total_devices": len(devices),
            "enabled_devices": sum(1 for device in devices if device["enabled"]),
            "online_devices": sum(1 for device in devices if device["status"] == "online"),
            "warning_devices": sum(1 for device in devices if device["status"] == "warning"),
            "offline_devices": sum(1 for device in devices if device["status"] == "offline"),
            "groups": len(groups),
            "active_alerts": len(active_alerts),
            "average_cpu_percent": round(sum(cpu_values) / len(cpu_values), 1) if cpu_values else 0.0,
            "average_memory_percent": round(sum(memory_values) / len(memory_values), 1) if memory_values else 0.0,
            "storage_pool_risks": storage_pool_risks,
            "latest_collection_at": latest_collection,
        }
        summary["health_score"] = max(
            0,
            100
            - monitoring_penalty(
                offline=summary["offline_devices"],
                warning=summary["warning_devices"],
                alerts=summary["active_alerts"],
            ),
        )
        return {
            "summary": summary,
            "groups": group_summaries,
            "devices": [self._public_device(device) for device in devices],
            "recent_collections": deepcopy(snapshot["collection_records"][:10]),
            "alerts": deepcopy(active_alerts[:10]),
        }

    def list_groups(self) -> dict[str, Any]:
        snapshot = self.store.snapshot()
        return {"groups": self.overview()["groups"]}

    def get_group(self, group_id: str) -> dict[str, Any]:
        snapshot = self.store.snapshot()
        group = deepcopy(self._find_group(snapshot, group_id))
        group["devices"] = [
            self._public_device(device)
            for device in snapshot["devices"]
            if device.get("group_id") == group_id
        ]
        group["active_alerts"] = [
            deepcopy(alert)
            for alert in snapshot["alerts"]
            if alert.get("group_id") == group_id and alert["status"] == "active"
        ]
        return group

    def create_group(self, payload: dict[str, Any]) -> dict[str, Any]:
        validated = self._validate_group_payload(payload, partial=False)

        def mutate(state):
            group_id = validated.get("id") or f"grp-{_slugify(validated['name'])}"
            if any(group["id"] == group_id for group in state["device_groups"]):
                raise ConflictError("设备分组 ID 已存在", {"group_id": group_id})
            if any(group["name"] == validated["name"] for group in state["device_groups"]):
                raise ConflictError("设备分组名称已存在", {"name": validated["name"]})
            now = isoformat(utc_now())
            group = {
                "id": group_id,
                "name": validated["name"],
                "description": validated.get("description", ""),
                "color": validated.get("color", "#7da38f"),
                "icon": validated.get("icon", "server"),
                "sort_order": validated.get("sort_order", 100),
                "created_at": now,
                "updated_at": now,
            }
            state["device_groups"].append(group)
            state["device_groups"].sort(key=lambda item: (item.get("sort_order", 9999), item["name"]))
            state["metrics"]["device_group_writes_total"] += 1
            return deepcopy(group)

        return self.store.update(mutate)

    def update_group(self, group_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        validated = self._validate_group_payload(payload, partial=True)

        def mutate(state):
            group = self._find_group(state, group_id)
            if "name" in validated and any(
                candidate["name"] == validated["name"] and candidate["id"] != group_id
                for candidate in state["device_groups"]
            ):
                raise ConflictError("设备分组名称已存在", {"name": validated["name"]})
            group.update(validated)
            group["updated_at"] = isoformat(utc_now())
            state["device_groups"].sort(key=lambda item: (item.get("sort_order", 9999), item["name"]))
            state["metrics"]["device_group_writes_total"] += 1
            return deepcopy(group)

        return self.store.update(mutate)

    def delete_group(self, group_id: str) -> dict[str, Any]:
        def mutate(state):
            self._find_group(state, group_id)
            if group_id == UNGROUPED_GROUP_ID:
                raise ConflictError("默认未分组不能删除", {"group_id": group_id})
            self._ensure_group_exists(state, UNGROUPED_GROUP_ID)
            state["device_groups"] = [group for group in state["device_groups"] if group["id"] != group_id]
            for device in state["devices"]:
                if device.get("group_id") == group_id:
                    device["group_id"] = UNGROUPED_GROUP_ID
                    device["updated_at"] = isoformat(utc_now())
            for alert in state["alerts"]:
                if alert.get("group_id") == group_id:
                    alert["group_id"] = UNGROUPED_GROUP_ID
                    alert["updated_at"] = isoformat(utc_now())
            state["metrics"]["device_group_writes_total"] += 1
            return {"deleted": True, "group_id": group_id, "reassigned_group_id": UNGROUPED_GROUP_ID}

        return self.store.update(mutate)

    def list_devices(self, filters: dict[str, Any] | None = None) -> dict[str, Any]:
        filters = filters or {}
        snapshot = self.store.snapshot()
        devices = snapshot["devices"]
        group_filter = filters.get("group_id") or filters.get("group")
        if group_filter:
            devices = [device for device in devices if device.get("group_id") == group_filter]
        if filters.get("device_type"):
            devices = [device for device in devices if device.get("device_type") == filters["device_type"]]
        if filters.get("status"):
            devices = [device for device in devices if device.get("status") == filters["status"]]
        if filters.get("enabled") is not None:
            devices = [device for device in devices if device.get("enabled") is filters["enabled"]]
        return {"devices": [self._public_device(device, snapshot=snapshot) for device in devices]}

    def get_device(self, device_id: str) -> dict[str, Any]:
        snapshot = self.store.snapshot()
        device = self._find_device(snapshot, device_id)
        payload = self._public_device(device, snapshot=snapshot)
        payload["recent_collections"] = [
            _enrich_collection_record(record)
            for record in snapshot["collection_records"]
            if record["device_id"] == device_id
        ][:10]
        payload["alerts"] = [
            deepcopy(alert)
            for alert in snapshot["alerts"]
            if alert.get("device_id") == device_id
        ]
        return payload

    def create_device(self, payload: dict[str, Any]) -> dict[str, Any]:
        validated = self._validate_device_payload(payload, partial=False)
        stored = deepcopy(validated)
        self._normalize_stored_credentials(stored)
        # Inherit the global default_collection_interval when not explicitly set.
        if "collection_interval" not in payload and "poll_interval" not in payload:
            stored["collection_interval"] = self._default_collection_interval()

        def mutate(state):
            self._ensure_group_exists(state, stored["group_id"])
            device_id = stored.get("id") or f"dev-{_slugify(stored['name'])}"
            if any(device["id"] == device_id for device in state["devices"]):
                raise ConflictError("设备 ID 已存在", {"device_id": device_id})
            now = isoformat(utc_now())
            device = {
                "id": device_id,
                "name": stored["name"],
                "host": stored["host"],
                "port": stored["port"],
                "username": stored["username"],
                "auth_type": stored["auth_type"],
                "password": stored.get("password"),
                "private_key_path": stored.get("private_key_path"),
                "device_type": stored["device_type"],
                "group_id": stored["group_id"],
                "tags": stored["tags"],
                "enabled": stored["enabled"],
                "collection_interval": stored["collection_interval"],
                "last_seen": stored.get("last_seen"),
                "status": stored.get("status", "unknown"),
                "verified": bool(stored.get("verified", False)),
                "created_at": now,
                "updated_at": now,
            }
            state["devices"].append(device)
            state["devices"].sort(key=lambda item: item["name"])
            state["metrics"]["device_writes_total"] += 1
            return self._public_device(device, snapshot=state)

        return self.store.update(mutate)

    def _default_collection_interval(self) -> int:
        try:
            settings = self.store.read("collection_settings")
            if settings is None:
                return 30
            return int(settings.get("default_collection_interval", 30))
        except Exception:
            return 30

    def update_device(
        self,
        device_id: str,
        payload: dict[str, Any],
        *,
        allow_sensitive_fields: bool = True,
    ) -> dict[str, Any]:
        if not allow_sensitive_fields and OPERATOR_PROTECTED_DEVICE_FIELDS.intersection(payload):
            raise ForbiddenError("operator 不能修改 SSH 凭据或受保护字段")
        validated = self._validate_device_payload(payload, partial=True)
        if not allow_sensitive_fields:
            disallowed_fields = sorted(set(validated) - OPERATOR_EDITABLE_DEVICE_FIELDS)
            if disallowed_fields:
                raise ForbiddenError(
                    "operator 不能修改 SSH 凭据或受保护字段"
                )

        def mutate(state):
            device = self._find_device(state, device_id)
            merged = deepcopy(device)
            merged.update(validated)
            if "group_id" in validated:
                self._ensure_group_exists(state, merged["group_id"])
            if CONNECTION_RELATED_FIELDS.intersection(validated.keys()):
                merged["verified"] = False
                if merged.get("status") != "disabled":
                    merged["status"] = "unknown"
                merged["last_seen"] = None
            self._enforce_auth_shape(merged)
            self._normalize_stored_credentials(merged)
            device.update(merged)
            device["updated_at"] = isoformat(utc_now())
            state["metrics"]["device_writes_total"] += 1
            return self._public_device(device, snapshot=state)

        return self.store.update(mutate)

    def delete_device(self, device_id: str) -> dict[str, Any]:
        def mutate(state):
            self._find_device(state, device_id)
            state["devices"] = [device for device in state["devices"] if device["id"] != device_id]
            state["collection_records"] = [
                record for record in state["collection_records"] if record["device_id"] != device_id
            ]
            state["alerts"] = [
                alert for alert in state["alerts"] if alert.get("device_id") != device_id
            ]
            state["metrics"]["device_writes_total"] += 1
            return {"deleted": True, "device_id": device_id}

        return self.store.update(mutate)

    def list_collection_records(
        self,
        *,
        device_id: str | None = None,
        group_id: str | None = None,
        status: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        snapshot = self.store.snapshot()
        records = snapshot["collection_records"]
        if device_id:
            records = [record for record in records if record["device_id"] == device_id]
        if group_id:
            records = [record for record in records if self._record_group_id(record, snapshot) == group_id]
        if status:
            records = [record for record in records if record.get("status") == status]
        since_dt = self._parse_iso_timestamp(since, field="since")
        until_dt = self._parse_iso_timestamp(until, field="until")
        if since_dt:
            records = [
                record
                for record in records
                if self._parse_iso_timestamp(record.get("collected_at")) is None
                or self._parse_iso_timestamp(record.get("collected_at")) >= since_dt
            ]
        if until_dt:
            records = [
                record
                for record in records
                if self._parse_iso_timestamp(record.get("collected_at")) is None
                or self._parse_iso_timestamp(record.get("collected_at")) <= until_dt
            ]
        return {"records": [_enrich_collection_record(record) for record in records[:limit]]}

    def list_alerts(self, filters: dict[str, Any] | None = None) -> dict[str, Any]:
        filters = filters or {}
        snapshot = self.store.snapshot()
        alerts = snapshot["alerts"]
        if filters.get("device_id"):
            alerts = [alert for alert in alerts if alert.get("device_id") == filters["device_id"]]
        group_filter = filters.get("group_id") or filters.get("group")
        if group_filter:
            alerts = [alert for alert in alerts if alert.get("group_id") == group_filter]
        if filters.get("status"):
            alerts = [alert for alert in alerts if alert.get("status") == filters["status"]]
        return {"alerts": deepcopy(alerts)}

    def resolve_alert(self, alert_id: str, *, actor: str) -> dict[str, Any]:
        def mutate(state):
            for alert in state["alerts"]:
                if alert["id"] != alert_id:
                    continue
                if alert["status"] == "resolved":
                    raise ConflictError("告警已经处理完成", {"alert_id": alert_id})
                now = isoformat(utc_now())
                alert["status"] = "resolved"
                alert["resolved_at"] = now
                alert["resolved_by"] = actor
                alert["updated_at"] = now
                state["metrics"]["alert_resolved_total"] += 1
                return deepcopy(alert)
            raise NotFoundError("alert", alert_id)

        return self.store.update(mutate)

    def test_device_connection(self, device_id: str, *, timeout: int = 5) -> dict[str, Any]:
        return self._collect(device_id, timeout=timeout, purpose="test", metric_name="device_test_total")

    def refresh_device(self, device_id: str, *, timeout: int = 5) -> dict[str, Any]:
        return self._collect(device_id, timeout=timeout, purpose="refresh", metric_name="device_refresh_total")

    def run_scheduled_collection(self, *, timeout: int = 10) -> int:
        """Collect all enabled devices whose interval has elapsed.

        Called by the background scheduler. Returns the number of devices
        collected. Errors per device are swallowed so one failure does not stop
        the rest. Manual refresh (``refresh_device``) is unaffected and always
        triggers an immediate collection regardless of interval.
        """
        snapshot = self.store.snapshot()
        now = utc_now()
        collected = 0
        for device in snapshot.get("devices", []):
            if not device.get("enabled", True):
                continue
            if device.get("status") == "disabled":
                continue
            if isinstance(self.collector_service.collector, DisabledCollector):
                continue
            interval = int(
                device.get("collection_interval", device.get("poll_interval", 30)) or 30
            )
            interval = max(interval, 30)
            last_seen = _parse_last_seen(device.get("last_seen"))
            if last_seen is not None and (now - last_seen).total_seconds() < interval:
                continue
            try:
                self._collect(
                    device["id"], timeout=timeout, purpose="scheduled",
                    metric_name="device_scheduled_total",
                )
                collected += 1
            except Exception:
                continue
        return collected

    def _collect(self, device_id: str, *, timeout: int, purpose: str, metric_name: str) -> dict[str, Any]:
        snapshot = self.store.snapshot()
        device = deepcopy(self._find_device(snapshot, device_id))
        if timeout <= 0:
            raise ValidationError("timeout 必须大于 0")
        if self.collector_service is None:
            raise ValidationError("采集器未配置")
        if isinstance(self.collector_service.collector, DisabledCollector):
            raise ValidationError("全局采集已禁用，当前无可用数据")
        if device.get("status") == "disabled":
            raise ValidationError("设备采集已禁用，当前无可用数据")

        try:
            result = self.collector_service.collect(device, timeout=timeout, purpose=purpose)
            return self.store.update(
                lambda state: self._apply_collection_success(
                    state,
                    device_id=device_id,
                    result=result,
                    purpose=purpose,
                    metric_name=metric_name,
                )
            )
        except CollectorError as exc:
            return self.store.update(
                lambda state: self._apply_collection_failure(
                    state,
                    device_id=device_id,
                    error=exc,
                    purpose=purpose,
                    metric_name=metric_name,
                )
            )

    def _apply_collection_success(self, state, *, device_id: str, result, purpose: str, metric_name: str):
        now = isoformat(utc_now())
        device = self._find_device(state, device_id)
        payload = dict(result.payload)
        has_observable_data = _has_observable_collection_data(payload)
        payload["__data_source"] = result.data_source
        payload["__is_real_data"] = result.is_real_data
        payload["__collection_empty"] = not has_observable_data
        payload["__collection_detail_code"] = (
            "collection_succeeded_empty" if not has_observable_data else "collection_succeeded"
        )
        record = {
            "id": _next_numbered_id("col", state["collection_records"]),
            "device_id": device_id,
            "group_id": device.get("group_id"),
            "device_name": device.get("name"),
            "purpose": purpose,
            "collector": result.collector,
            "command": result.command,
            "collected_at": now,
            "status": result.status,
            "summary": result.summary,
            "payload": payload,
            "error_message": None,
            "detail_code": "collection_succeeded_empty" if not has_observable_data else "collection_succeeded",
            "detail_message": "采集成功但未返回可展示数据" if not has_observable_data else result.summary,
            "data_source": result.data_source,
            "is_real_data": result.is_real_data,
        }
        state["collection_records"].insert(0, record)
        state["collection_records"] = state["collection_records"][:5000]
        device["last_seen"] = now
        device["status"] = "online" if result.status == "healthy" else "warning"
        device["verified"] = True
        device["online_status"] = "online"
        device["health_status"] = "normal" if result.status == "healthy" else "warning"
        device["updated_at"] = now
        self._reconcile_alerts(state, device=device, record=record)
        state["metrics"][metric_name] = state["metrics"].get(metric_name, 0) + 1
        return {
            "device": self._public_device(device, snapshot=state),
            "record": deepcopy(record),
            "alerts": self._device_alerts(state, device_id),
            "purpose": purpose,
        }

    def _apply_collection_failure(self, state, *, device_id: str, error: CollectorError, purpose: str, metric_name: str):
        now = isoformat(utc_now())
        device = self._find_device(state, device_id)
        detail_code = error.reason or "collection_failed"
        record = {
            "id": _next_numbered_id("col", state["collection_records"]),
            "device_id": device_id,
            "group_id": device.get("group_id"),
            "device_name": device.get("name"),
            "purpose": purpose,
            "collector": getattr(self.collector_service.collector, "name", "collector"),
            "command": "ssh probe",
            "collected_at": now,
            "status": error.status,
            "summary": error.message,
            "payload": {
                "purpose": purpose,
                "__collection_detail_code": detail_code,
                "__collection_detail_message": error.message,
            },
            "error_message": error.message,
            "detail_code": detail_code,
            "detail_message": error.message,
            "data_source": getattr(self.collector_service, "_data_source", "unknown"),
            "is_real_data": getattr(self.collector_service, "_is_real_data", False),
        }
        state["collection_records"].insert(0, record)
        state["collection_records"] = state["collection_records"][:5000]
        if error.status == "critical":
            device["status"] = "offline"
            device["verified"] = False
            device["online_status"] = "offline"
            device["health_status"] = "critical"
        elif error.status == "disabled":
            device["status"] = "disabled"
            device["verified"] = False
            device["online_status"] = "disabled"
            device["health_status"] = "critical"
        else:
            device["status"] = "warning"
            device["online_status"] = "online"
            device["health_status"] = "warning"
        device["updated_at"] = now
        self._reconcile_alerts(state, device=device, record=record)
        state["metrics"][metric_name] = state["metrics"].get(metric_name, 0) + 1
        return {
            "device": self._public_device(device, snapshot=state),
            "record": deepcopy(record),
            "alerts": self._device_alerts(state, device_id),
            "purpose": purpose,
        }

    def _reconcile_alerts(self, state, *, device: dict[str, Any], record: dict[str, Any]) -> None:
        now = isoformat(utc_now())
        self._resolve_existing_alerts(state, device["id"], now)
        if record["status"] == "healthy":
            self._create_threshold_alerts(state, device=device, payload=record.get("payload", {}), record=record)
            return

        code = "device_offline" if record["status"] == "critical" else "collection_failed"
        severity = "critical" if record["status"] == "critical" else "warning"
        title = f"{device['name']} {'离线' if severity == 'critical' else '采集异常'}"
        message = record["summary"]
        self._upsert_alert(
            state,
            device=device,
            code=code,
            severity=severity,
            title=title,
            message=message,
            record_id=record["id"],
            now=now,
        )

    def _resolve_existing_alerts(self, state, device_id: str, now: str) -> None:
        for alert in state["alerts"]:
            if alert.get("device_id") == device_id and alert["status"] == "active":
                alert["status"] = "resolved"
                alert["resolved_at"] = now
                alert["resolved_by"] = "system:auto-recovery"
                alert["updated_at"] = now

    def _create_threshold_alerts(self, state, *, device: dict[str, Any], payload: dict[str, Any], record: dict[str, Any]) -> None:
        checks = evaluate_threshold_alerts(payload)
        smart_alert = evaluate_smart_alert(payload)
        if smart_alert:
            checks.append(smart_alert)
        for check in checks:
            self._upsert_alert(
                state,
                device=device,
                code=check["type"],
                severity=check["severity"],
                title=check["title"],
                message=check["message"],
                record_id=record["id"],
                now=isoformat(utc_now()),
            )

    def _upsert_alert(
        self,
        state,
        *,
        device: dict[str, Any],
        code: str,
        severity: str,
        title: str,
        message: str,
        record_id: str,
        now: str,
    ) -> None:
        for alert in state["alerts"]:
            if alert.get("device_id") == device["id"] and alert["code"] == code and alert["status"] == "active":
                alert["severity"] = severity
                alert["title"] = title
                alert["message"] = message
                alert["updated_at"] = now
                alert["last_record_id"] = record_id
                return
        state["alerts"].insert(
            0,
            {
                "id": _next_numbered_id("alert", state["alerts"]),
                "device_id": device["id"],
                "group_id": device.get("group_id"),
                "severity": severity,
                "status": "active",
                "type": code,
                "code": code,
                "title": title,
                "message": message,
                "created_at": now,
                "updated_at": now,
                "resolved_at": None,
                "resolved_by": None,
                "last_record_id": record_id,
            },
        )

    def _device_alerts(self, state, device_id: str) -> list[dict[str, Any]]:
        return [deepcopy(alert) for alert in state["alerts"] if alert.get("device_id") == device_id]

    def _record_group_id(self, record: dict[str, Any], snapshot: dict[str, Any]) -> str | None:
        if record.get("group_id"):
            return record.get("group_id")
        try:
            device = self._find_device(snapshot, record["device_id"])
            return device.get("group_id")
        except NotFoundError:
            return None

    def _parse_iso_timestamp(self, value: str | None, *, field: str = "timestamp"):
        if value in {None, ""}:
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"{field} 必须是 ISO 时间字符串") from exc

    def _find_group(self, state: dict[str, Any], group_id: str) -> dict[str, Any]:
        for group in state["device_groups"]:
            if group["id"] == group_id:
                return group
        raise NotFoundError("device group", group_id)

    def _find_device(self, state: dict[str, Any], device_id: str) -> dict[str, Any]:
        for device in state["devices"]:
            if device["id"] == device_id:
                return device
        raise NotFoundError("device", device_id)

    def _runtime_collection_mode(self) -> str:
        if self.collector_service is None:
            return "unknown"
        if isinstance(self.collector_service.collector, DisabledCollector):
            return "disabled"
        return "ssh"

    def _credential_detail(self, device: dict[str, Any]) -> tuple[str, str, str] | None:
        auth_type = device.get("auth_type", "none")
        if auth_type == "password":
            password = device.get("password")
            if password in {None, "", EXTERNAL_SECRET_SENTINEL}:
                return (
                    "credential_missing",
                    "missing_ssh_credential",
                    "密码认证需要提供 SSH 凭据",
                )
            if not allow_stored_password_auth():
                return (
                    "password_auth_blocked",
                    "password_auth_disabled",
                    "密码认证已被配置禁用；如需启用，请设置 ALLOW_STORED_PASSWORD_AUTH=1",
                )
            return None
        if auth_type == "private_key":
            if not device.get("private_key_path"):
                return (
                    "credential_missing",
                    "missing_ssh_credential",
                    "使用私钥认证时必须提供 SSH 私钥路径",
                )
            return None
        return (
            "credential_missing",
            "missing_ssh_credential",
            "未配置可用的 SSH 凭据",
        )

    def _ensure_group_exists(self, state: dict[str, Any], group_id: str | None) -> None:
        if not group_id:
            raise ValidationError("group_id 不能为空")
        self._find_group(state, group_id)

    def _public_device(self, device: dict[str, Any], snapshot: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = deepcopy(device)
        payload.pop("password", None)
        payload.pop("inline_private_key", None)
        payload.pop("private_key_path", None)
        payload.pop("key_path", None)
        payload.pop("encrypted_private_key", None)
        payload["collection_interval"] = payload.get("collection_interval", payload.get("poll_interval", 60))
        payload["verified"] = bool(payload.get("verified", False))
        if snapshot is not None:
            runtime_mode = self._runtime_collection_mode()
            device_records = [
                record for record in snapshot["collection_records"] if record["device_id"] == payload["id"]
            ]
            successful_records = [
                record for record in device_records if _is_successful_collection_record(record)
            ]
            try:
                group = self._find_group(snapshot, payload["group_id"])
                payload["group"] = {"id": group["id"], "name": group["name"]}
            except NotFoundError:
                payload["group"] = {"id": payload.get("group_id"), "name": "未分组"}
            latest_record = _enrich_collection_record(device_records[0]) if device_records else None
            if latest_record:
                latest_payload = latest_record.get("payload", {})
                payload["latest_record"] = deepcopy(latest_record)
                payload["hostname"] = latest_payload.get("hostname")
                payload["uname"] = latest_payload.get("uname")
                payload["cpu_percent"] = latest_payload.get("cpu_percent")
                payload["cpu_cores"] = latest_payload.get("cpu_cores")
                payload["per_core_cpu"] = deepcopy(latest_payload.get("per_core_cpu", []))
                payload["memory_percent"] = latest_payload.get("memory_percent")
                payload["memory_total_mb"] = latest_payload.get("memory_total_mb")
                payload["memory_used_mb"] = latest_payload.get("memory_used_mb")
                payload["disk_percent"] = latest_payload.get("disk_percent")
                payload["network_rx_mbps"] = latest_payload.get("network_rx_mbps")
                payload["network_tx_mbps"] = latest_payload.get("network_tx_mbps")
                payload["load_average"] = latest_payload.get("load_average")
                payload["uptime"] = latest_payload.get("uptime")
                payload["data_source"] = latest_record.get("data_source") or latest_payload.get("__data_source", "unknown")
                payload["is_real_data"] = latest_record.get("is_real_data") if "is_real_data" in latest_record else latest_payload.get("__is_real_data", False)
                payload["collector_errors"] = deepcopy(latest_payload.get("errors", []))
                payload["unavailable_metrics"] = deepcopy(latest_payload.get("unavailable_metrics", []))
                payload["critical_errors"] = deepcopy(latest_payload.get("critical_errors", []))
                payload["permission_warnings"] = deepcopy(latest_payload.get("permission_warnings", []))
                payload["optional_warnings"] = deepcopy(latest_payload.get("optional_warnings", []))
                payload["unavailable_indicators"] = deepcopy(latest_payload.get("unavailable_indicators", []))
                payload["not_applicable_indicators"] = deepcopy(latest_payload.get("not_applicable_indicators", []))
                payload["probe_summary"] = deepcopy(latest_payload.get("probe_summary", {}))
                payload["smart_status"] = latest_payload.get("smart_status")
                payload["smart_attributes"] = deepcopy(latest_payload.get("smart_attributes", []))
                payload["temperature_c"] = latest_payload.get("temperature_c")
                payload["temperatures"] = deepcopy(latest_payload.get("temperatures", []))
                payload["storage_pool"] = deepcopy(latest_payload.get("storage_pool"))
                payload["partitions"] = deepcopy(latest_payload.get("partitions", []))
                payload["network_interfaces"] = deepcopy(latest_payload.get("network_interfaces", []))
                payload["nas_pools"] = deepcopy(latest_payload.get("nas_pools", []))
                payload["nas_volumes"] = deepcopy(latest_payload.get("nas_volumes", []))
                payload["nas_snapshots"] = deepcopy(latest_payload.get("nas_snapshots", []))
                payload["nas_raid"] = deepcopy(latest_payload.get("nas_raid", []))
                payload["block_devices"] = deepcopy(latest_payload.get("block_devices", []))
                payload["docker_info"] = latest_payload.get("docker_info")
                # PVE fields
                payload["pve_version"] = latest_payload.get("pve_version")
                payload["pve_storage"] = deepcopy(latest_payload.get("pve_storage", []))
                payload["pve_vms"] = deepcopy(latest_payload.get("pve_vms", []))
                payload["pve_vm_total"] = latest_payload.get("pve_vm_total", 0)
                payload["pve_vm_running"] = latest_payload.get("pve_vm_running", 0)
                payload["pve_vm_stopped"] = latest_payload.get("pve_vm_stopped", 0)
                payload["pve_lxcs"] = deepcopy(latest_payload.get("pve_lxcs", []))
                payload["pve_lxc_total"] = latest_payload.get("pve_lxc_total", 0)
                payload["pve_lxc_running"] = latest_payload.get("pve_lxc_running", 0)
                payload["pve_lxc_stopped"] = latest_payload.get("pve_lxc_stopped", 0)
                payload["pve_interfaces"] = deepcopy(latest_payload.get("pve_interfaces", []))
                payload["last_collection_at"] = latest_record.get("collected_at")
            elif payload.get("status") == "disabled":
                payload["data_source"] = "disabled"
                payload["is_real_data"] = False
                payload["collector_errors"] = []
                payload["unavailable_metrics"] = []
                payload["critical_errors"] = []
                payload["permission_warnings"] = []
                payload["optional_warnings"] = []
                payload["unavailable_indicators"] = []
                payload["not_applicable_indicators"] = []
                payload["probe_summary"] = {}
            payload["collection_runtime_mode"] = runtime_mode
            payload["allow_stored_password_auth"] = allow_stored_password_auth()
            payload["has_collection_history"] = bool(device_records)
            payload["has_successful_collection_history"] = bool(successful_records)
            payload["last_successful_collection_at"] = (
                successful_records[0].get("collected_at") if successful_records else None
            )
            if runtime_mode == "disabled":
                payload["collection_state"] = "global_disabled"
                payload["collection_detail_code"] = "global_collector_disabled"
                payload["collection_detail_message"] = "全局采集已禁用"
            elif payload.get("status") == "disabled":
                payload["collection_state"] = "device_disabled"
                payload["collection_detail_code"] = "device_disabled"
                payload["collection_detail_message"] = "设备采集已禁用"
            else:
                credential_detail = self._credential_detail(device)
                if credential_detail is not None:
                    state_name, detail_code, detail_message = credential_detail
                    payload["collection_state"] = state_name
                    payload["collection_detail_code"] = detail_code
                    payload["collection_detail_message"] = detail_message
                elif latest_record and latest_record.get("error_message"):
                    payload["collection_state"] = "failed"
                    payload["collection_detail_code"] = latest_record.get("detail_code", "collection_failed")
                    payload["collection_detail_message"] = (
                        latest_record.get("detail_message")
                        or latest_record.get("error_message")
                        or latest_record.get("summary")
                    )
                    if not successful_records:
                        payload["collection_history_state"] = "failed_no_history"
                elif latest_record and latest_record.get("detail_code") == "collection_succeeded_empty":
                    payload["collection_state"] = "succeeded_empty"
                    payload["collection_detail_code"] = "collection_succeeded_empty"
                    payload["collection_detail_message"] = latest_record.get(
                        "detail_message",
                        "采集成功但未返回可展示数据",
                    )
                elif latest_record:
                    payload["collection_state"] = "succeeded"
                    payload["collection_detail_code"] = latest_record.get("detail_code", "collection_succeeded")
                    payload["collection_detail_message"] = latest_record.get("detail_message", "采集成功")
                else:
                    payload["collection_state"] = "no_history"
                    payload["collection_detail_code"] = "no_collection_history"
                    payload["collection_detail_message"] = "设备尚无可用采集历史"
                    payload["collection_history_state"] = "no_history"
            # Surface derived health/online status (additive, backward compatible)
            payload["health_status"] = payload.get("health_status") or (
                "critical" if payload.get("status") == "offline"
                else "critical" if payload.get("status") == "disabled"
                else "warning" if payload.get("status") == "warning"
                else "normal"
            )
            payload["online_status"] = payload.get("online_status") or (
                "offline" if payload.get("status") == "offline"
                else "disabled" if payload.get("status") == "disabled"
                else "online"
            )
            payload["active_alert_count"] = sum(
                1
                for alert in snapshot["alerts"]
                if alert.get("device_id") == payload["id"] and alert.get("status") == "active"
            )
        return payload

    def _validate_group_payload(self, payload: dict[str, Any], *, partial: bool) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValidationError("设备分组请求体必须是对象")
        validated: dict[str, Any] = {}
        if not partial or "id" in payload:
            group_id = payload.get("id")
            if group_id is not None and (not isinstance(group_id, str) or not group_id.strip()):
                raise ValidationError("设备分组 id 必须是非空字符串")
            if group_id is not None:
                validated["id"] = group_id.strip()
        if not partial or "name" in payload:
            name = payload.get("name")
            if not isinstance(name, str) or not name.strip():
                raise ValidationError("设备分组 name 必须是非空字符串")
            validated["name"] = name.strip()
        if "description" in payload:
            description = payload.get("description")
            if description is None:
                description = ""
            if not isinstance(description, str):
                raise ValidationError("设备分组 description 必须是字符串")
            validated["description"] = description.strip()
        for field, default in (("color", "#7da38f"), ("icon", "server")):
            if field in payload:
                value = payload.get(field)
                if value is None:
                    value = default
                if not isinstance(value, str):
                    raise ValidationError(f"设备分组 {field} 必须是字符串")
                validated[field] = value.strip() or default
        if "sort_order" in payload:
            sort_order = payload.get("sort_order")
            if not isinstance(sort_order, int):
                raise ValidationError("设备分组 sort_order 必须是整数")
            validated["sort_order"] = sort_order
        if not validated and partial:
            raise ValidationError("设备分组更新至少需要一个字段")
        return validated

    def _validate_device_payload(self, payload: dict[str, Any], *, partial: bool) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValidationError("设备请求体必须是对象")
        validated: dict[str, Any] = {}
        required_fields = (
            "name",
            "host",
            "port",
            "username",
            "auth_type",
            "device_type",
            "group_id",
            "tags",
            "enabled",
            "collection_interval",
        )
        for field in required_fields:
            if not partial or field in payload:
                defaults = {
                    "port": 22,
                    "username": "monitor",
                    "auth_type": "none",
                    "device_type": "other",
                    "group_id": UNGROUPED_GROUP_ID,
                    "tags": [],
                    "enabled": True,
                    "collection_interval": 30,
                }
                value = payload.get(field, defaults.get(field))
                if field in {"name", "host", "username", "group_id"}:
                    if not isinstance(value, str) or not value.strip():
                        raise ValidationError(f"{field} 必须是非空字符串")
                    validated[field] = value.strip()
                elif field == "device_type":
                    if not isinstance(value, str) or value.strip() not in VALID_DEVICE_TYPES:
                        raise ValidationError("device_type 不受支持", {"allowed": sorted(VALID_DEVICE_TYPES)})
                    validated[field] = value.strip()
                elif field == "port":
                    if not isinstance(value, int) or not (1 <= value <= 65535):
                        raise ValidationError("port 必须是 1-65535 之间的整数")
                    validated[field] = value
                elif field == "auth_type":
                    if value not in VALID_AUTH_TYPES:
                        raise ValidationError("auth_type 不受支持", {"allowed": sorted(VALID_AUTH_TYPES)})
                    validated[field] = value
                elif field == "tags":
                    if not isinstance(value, list) or not all(isinstance(tag, str) for tag in value):
                        raise ValidationError("tags 必须是字符串数组")
                    validated[field] = [tag.strip() for tag in value if tag.strip()]
                elif field == "enabled":
                    if not isinstance(value, bool):
                        raise ValidationError("enabled 必须是布尔值")
                    validated[field] = value
                elif field == "collection_interval":
                    if not isinstance(value, int) or value < 30:
                        raise ValidationError("collection_interval 必须是不小于 30 的整数")
                    validated[field] = value
        if "poll_interval" in payload and "collection_interval" not in payload:
            value = payload.get("poll_interval")
            if not isinstance(value, int) or value <= 0:
                raise ValidationError("collection_interval 必须是正整数")
            validated["collection_interval"] = value

        if "key_path" in payload and "private_key_path" not in payload:
            payload = dict(payload)
            payload["private_key_path"] = payload.get("key_path")

        if "encrypted_private_key" in payload and "inline_private_key" not in payload:
            payload = dict(payload)
            payload["inline_private_key"] = payload.get("encrypted_private_key")

        for optional_field in ("id", "password", "private_key_path", "inline_private_key", "last_seen", "status", "verified"):
            if optional_field not in payload:
                continue
            value = payload.get(optional_field)
            if optional_field == "id":
                if not isinstance(value, str) or not value.strip():
                    raise ValidationError("id 必须是非空字符串")
                validated["id"] = value.strip()
            elif optional_field == "password":
                if value is not None and (not isinstance(value, str) or not value.strip()):
                    raise ValidationError("SSH 密码必须是字符串或 null")
                validated["password"] = value.strip() if isinstance(value, str) else None
            elif optional_field == "private_key_path":
                if value is not None and (not isinstance(value, str) or not value.strip()):
                    raise ValidationError("SSH 私钥路径必须是字符串或 null")
                validated["private_key_path"] = value.strip() if isinstance(value, str) else None
            elif optional_field == "inline_private_key":
                if value not in {None, ""}:
                    raise ValidationError("系统不接受内联 SSH 私钥，请改用外部私钥文件路径")
                validated["inline_private_key"] = None
            elif optional_field == "last_seen":
                if value is not None and (not isinstance(value, str) or not value.strip()):
                    raise ValidationError("last_seen 必须是 ISO 时间字符串或 null")
                validated["last_seen"] = value.strip() if isinstance(value, str) else None
            elif optional_field == "status":
                if not isinstance(value, str) or value not in VALID_DEVICE_STATUSES:
                    raise ValidationError("status 不受支持", {"allowed": sorted(VALID_DEVICE_STATUSES)})
                validated["status"] = value
            elif optional_field == "verified":
                if not isinstance(value, bool):
                    raise ValidationError("verified 必须是布尔值")
                validated["verified"] = value

        if not validated and partial:
            raise ValidationError("设备更新至少需要一个字段")
        self._enforce_auth_shape(validated, partial=partial)
        return validated

    def _enforce_auth_shape(self, payload: dict[str, Any], *, partial: bool = False) -> None:
        auth_type = payload.get("auth_type")
        if partial and auth_type is None:
            return
        if auth_type == "password":
            if not payload.get("password"):
                raise ValidationError("使用密码认证时必须提供 SSH 凭据")
            payload["private_key_path"] = None
            payload["inline_private_key"] = None
        if auth_type == "private_key":
            if payload.get("inline_private_key"):
                raise ValidationError("系统不接受内联 SSH 私钥，请改用外部私钥文件路径")
            if not payload.get("private_key_path"):
                raise ValidationError("使用私钥认证时必须提供 SSH 私钥路径")
            payload["password"] = None
            payload["inline_private_key"] = None
        if auth_type == "none":
            payload["password"] = None
            payload["private_key_path"] = None
            payload["inline_private_key"] = None

    def _normalize_stored_credentials(self, payload: dict[str, Any]) -> None:
        auth_type = payload.get("auth_type")
        if auth_type == "password":
            if payload.get("password") in {None, ""}:
                payload["password"] = None
            payload["private_key_path"] = None
            payload["inline_private_key"] = None
            payload["encrypted_private_key"] = None
        elif auth_type == "private_key":
            payload["password"] = None
            payload["inline_private_key"] = None
            payload["encrypted_private_key"] = None
        else:
            payload["password"] = None
            payload["private_key_path"] = None
            payload["inline_private_key"] = None
            payload["encrypted_private_key"] = None

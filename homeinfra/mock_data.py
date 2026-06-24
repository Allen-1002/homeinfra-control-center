"""Seed state and in-memory store for HomeInfra."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any

UNGROUPED_GROUP_ID = "grp-ungrouped"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def age_seconds(timestamp: str) -> int:
    value = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return int((utc_now() - value).total_seconds())


def build_monitoring_seed(now: datetime | None = None) -> dict[str, Any]:
    now = now or utc_now()
    recent_seen = isoformat(now - timedelta(seconds=75))
    warning_seen = isoformat(now - timedelta(minutes=8))
    stale_seen = isoformat(now - timedelta(minutes=45))
    old_seen = isoformat(now - timedelta(hours=2))
    return {
        "device_groups": [
            {
                "id": UNGROUPED_GROUP_ID,
                "name": "未分组",
                "description": "尚未归类的设备",
                "color": "#94a3b8",
                "icon": "folder",
                "sort_order": 999,
                "created_at": isoformat(now - timedelta(days=120)),
                "updated_at": isoformat(now - timedelta(days=2)),
            },
            {
                "id": "grp-nas",
                "name": "NAS",
                "description": "家庭 NAS 与存储设备",
                "color": "#2f855a",
                "icon": "hard-drive",
                "sort_order": 10,
                "created_at": isoformat(now - timedelta(days=80)),
                "updated_at": isoformat(now - timedelta(days=3)),
            },
            {
                "id": "grp-servers",
                "name": "服务器",
                "description": "家庭服务器与迷你主机",
                "color": "#2563eb",
                "icon": "server",
                "sort_order": 20,
                "created_at": isoformat(now - timedelta(days=70)),
                "updated_at": isoformat(now - timedelta(days=4)),
            },
            {
                "id": "grp-router",
                "name": "软路由",
                "description": "网关与路由设备",
                "color": "#d97706",
                "icon": "router",
                "sort_order": 30,
                "created_at": isoformat(now - timedelta(days=60)),
                "updated_at": isoformat(now - timedelta(days=5)),
            },
            {
                "id": "grp-vm",
                "name": "虚拟机",
                "description": "长期运行的实验环境虚拟机",
                "color": "#7c3aed",
                "icon": "boxes",
                "sort_order": 40,
                "created_at": isoformat(now - timedelta(days=50)),
                "updated_at": isoformat(now - timedelta(days=6)),
            },
            {
                "id": "grp-other",
                "name": "其他设备",
                "description": "其他需要观测的 Linux 主机",
                "color": "#6b7280",
                "icon": "monitor",
                "sort_order": 50,
                "created_at": isoformat(now - timedelta(days=40)),
                "updated_at": isoformat(now - timedelta(days=7)),
            },
        ],
        "devices": [
            {
                "id": "dev-nas-01",
                "name": "群晖 NAS",
                "host": "192.0.2.20",
                "port": 22,
                "username": "monitor",
                "auth_type": "private_key",
                "password": None,
                "private_key_path": "/keys/homeinfra-monitor",
                "device_type": "nas",
                "group_id": "grp-nas",
                "tags": ["存储", "关键设备"],
                "enabled": True,
                "poll_interval": 60,
                "last_seen": warning_seen,
                "status": "warning",
                "created_at": isoformat(now - timedelta(days=20)),
                "updated_at": warning_seen,
            },
            {
                "id": "dev-server-01",
                "name": "Home Assistant 主机",
                "host": "192.0.2.30",
                "port": 22,
                "username": "monitor",
                "auth_type": "private_key",
                "password": None,
                "private_key_path": "/keys/homeassistant-monitor",
                "device_type": "linux_server",
                "group_id": "grp-servers",
                "tags": ["自动化", "应用"],
                "enabled": True,
                "poll_interval": 45,
                "last_seen": recent_seen,
                "status": "online",
                "created_at": isoformat(now - timedelta(days=14)),
                "updated_at": recent_seen,
            },
            {
                "id": "dev-router-01",
                "name": "OpenWrt 网关",
                "host": "192.0.2.1",
                "port": 22,
                "username": "root",
                "auth_type": "private_key",
                "password": None,
                "private_key_path": "/keys/openwrt-monitor",
                "device_type": "router",
                "group_id": "grp-router",
                "tags": ["网络", "边界"],
                "enabled": True,
                "poll_interval": 30,
                "last_seen": recent_seen,
                "status": "online",
                "created_at": isoformat(now - timedelta(days=10)),
                "updated_at": recent_seen,
            },
            {
                "id": "dev-mini-pc-01",
                "name": "Lab Mini PC",
                "host": "192.0.2.250",
                "port": 22,
                "username": "monitor",
                "auth_type": "private_key",
                "password": None,
                "private_key_path": "/keys/lab-monitor",
                "device_type": "mini_pc",
                "group_id": "grp-other",
                "tags": ["实验", "计算"],
                "enabled": True,
                "poll_interval": 90,
                "last_seen": stale_seen,
                "status": "offline",
                "created_at": isoformat(now - timedelta(days=8)),
                "updated_at": stale_seen,
            },
            {
                "id": "dev-vm-01",
                "name": "Ubuntu VM",
                "host": "192.0.2.60",
                "port": 22,
                "username": "monitor",
                "auth_type": "password",
                "password": "__external_secret__",
                "private_key_path": None,
                "device_type": "other",
                "group_id": "grp-vm",
                "tags": ["虚拟机", "测试"],
                "enabled": False,
                "poll_interval": 120,
                "last_seen": old_seen,
                "status": "unknown",
                "created_at": isoformat(now - timedelta(days=6)),
                "updated_at": old_seen,
            },
        ],
        "collection_records": [
            {
                "id": "col-00001",
                "device_id": "dev-nas-01",
                "collector": "mock",
                "command": "cat /proc/stat && df -h && lsblk",
                "collected_at": warning_seen,
                "status": "warning",
                "summary": "存储池使用率 92%，RAID 状态降级",
                "payload": {
                    "cpu_percent": 61.0,
                    "per_core_cpu": [
                        {"core": 0, "percent": 55},
                        {"core": 1, "percent": 82},
                        {"core": 2, "percent": 47},
                        {"core": 3, "percent": 60},
                    ],
                    "memory_percent": 72.0,
                    "load_average": "1.42 1.18 0.96",
                    "uptime": "15 days, 03:14",
                    "disk_percent": 88.0,
                    "partitions": [
                        {"mount": "/", "device": "/dev/sda2", "total_gb": 50.0, "used_gb": 32.5, "free_gb": 17.5, "percent": 65.0, "filesystem": "ext4"},
                        {"mount": "/data", "device": "/dev/sda3", "total_gb": 4000.0, "used_gb": 3520.0, "free_gb": 480.0, "percent": 88.0, "filesystem": "xfs"},
                    ],
                    "network_rx_mbps": 31.4,
                    "network_tx_mbps": 12.2,
                    "network_interfaces": [
                        {"name": "eth0", "state": "UP", "rx_mbps": 31.4, "tx_mbps": 12.2, "ipv4": "192.0.2.10", "mac": "aa:bb:cc:dd:ee:01"},
                        {"name": "eth1", "state": "UP", "rx_mbps": 2.1, "tx_mbps": 0.5, "ipv4": "198.51.100.10", "mac": "aa:bb:cc:dd:ee:02"},
                    ],
                    "smart_attributes": [
                        {"attr_name": "reallocated_sector_ct", "value": 98, "threshold": 36, "raw": 12, "status": "PASSED"},
                        {"attr_name": "current_pending_sector", "value": 100, "threshold": 0, "raw": 3, "status": "FAILED"},
                        {"attr_name": "temperature_celsius", "value": 54, "threshold": 0, "raw": 54, "status": "PASSED"},
                        {"attr_name": "offline_uncorrectable", "value": 100, "threshold": 0, "raw": 0, "status": "PASSED"},
                    ],
                    "temperature_c": 54,
                    "temperatures": [
                        {"sensor": "CPU", "temp_c": 54},
                        {"sensor": "HDD1", "temp_c": 42},
                        {"sensor": "HDD2", "temp_c": 44},
                    ],
                    "storage_pool": {
                        "name": "storage_pool_1",
                        "total_tb": 48,
                        "used_tb": 44,
                        "usage_percent": 92,
                        "raid_status": "degraded",
                        "volume_status": "warning",
                        "disk_count": 4,
                        "disk_health": "warning",
                    },
                    "nas_pools": [
                        {"name": "tank", "size_gb": 49152.0, "used_gb": 45056.0, "free_gb": 4096.0, "usage_percent": 92, "health_state": "DEGRADED", "compression_ratio": 1.42, "dedup_ratio": 1.0},
                    ],
                    "nas_volumes": [
                        {"name": "tank/media", "pool": "tank", "used_gb": 15000.0, "available_gb": 4096.0, "referenced_gb": 15000.0},
                        {"name": "tank/backups", "pool": "tank", "used_gb": 28000.0, "available_gb": 4096.0, "referenced_gb": 28000.0},
                    ],
                    "nas_snapshots": [
                        {"name": "tank/media@daily", "pool": "tank", "used_gb": 2.5, "creation": "2025-06-21 03:00"},
                        {"name": "tank/media@weekly", "pool": "tank", "used_gb": 8.1, "creation": "2025-06-15 03:00"},
                    ],
                    "nas_raid": [
                        {"name": "raidz2-0", "type": "raidz2", "state": "DEGRADED", "drives": 6, "degraded_drives": 1},
                    ],
                    "smart_status": "warning",
                },
                "error_message": None,
            },
            {
                "id": "col-00002",
                "device_id": "dev-server-01",
                "collector": "mock",
                "command": "uptime && free -m && df -h",
                "collected_at": recent_seen,
                "status": "healthy",
                "summary": "设备在线，资源使用正常",
                "payload": {
                    "cpu_percent": 28.0,
                    "per_core_cpu": [
                        {"core": 0, "percent": 32},
                        {"core": 1, "percent": 24},
                        {"core": 2, "percent": 18},
                        {"core": 3, "percent": 38},
                    ],
                    "memory_percent": 47.0,
                    "load_average": "0.42 0.38 0.33",
                    "uptime": "6 days, 11:02",
                    "disk_percent": 51.0,
                    "partitions": [
                        {"mount": "/", "device": "/dev/nvme0n1p2", "total_gb": 250.0, "used_gb": 127.5, "free_gb": 122.5, "percent": 51.0, "filesystem": "ext4"},
                        {"mount": "/home", "device": "/dev/nvme0n1p3", "total_gb": 750.0, "used_gb": 330.0, "free_gb": 420.0, "percent": 44.0, "filesystem": "ext4"},
                    ],
                    "network_rx_mbps": 6.2,
                    "network_tx_mbps": 3.8,
                    "network_interfaces": [
                        {"name": "enp2s0", "state": "UP", "rx_mbps": 6.2, "tx_mbps": 3.8, "ipv4": "192.0.2.20", "mac": "aa:bb:cc:dd:ee:11"},
                    ],
                    "temperature_c": 41,
                    "temperatures": [
                        {"sensor": "CPU Package", "temp_c": 41},
                        {"sensor": "NVMe", "temp_c": 35},
                    ],
                    "smart_status": "healthy",
                },
                "error_message": None,
            },
            {
                "id": "col-00003",
                "device_id": "dev-router-01",
                "collector": "mock",
                "command": "cat /proc/loadavg && ip -s link",
                "collected_at": recent_seen,
                "status": "healthy",
                "summary": "网关负载稳定，接口正常",
                "payload": {
                    "cpu_percent": 16.0,
                    "per_core_cpu": [
                        {"core": 0, "percent": 18},
                        {"core": 1, "percent": 14},
                    ],
                    "memory_percent": 35.0,
                    "load_average": "0.12 0.20 0.18",
                    "uptime": "22 days, 05:11",
                    "disk_percent": 23.0,
                    "partitions": [
                        {"mount": "/", "device": "/dev/mmcblk0p2", "total_gb": 28.0, "used_gb": 6.4, "free_gb": 21.6, "percent": 23.0, "filesystem": "squashfs"},
                    ],
                    "network_rx_mbps": 95.4,
                    "network_tx_mbps": 21.0,
                    "network_interfaces": [
                        {"name": "br-lan", "state": "UP", "rx_mbps": 75.2, "tx_mbps": 18.5, "ipv4": "192.0.2.1", "mac": "aa:bb:cc:dd:ee:21"},
                        {"name": "eth0", "state": "UP", "rx_mbps": 20.2, "tx_mbps": 2.5, "ipv4": "", "mac": "aa:bb:cc:dd:ee:20"},
                    ],
                    "temperature_c": 45,
                    "temperatures": [
                        {"sensor": "CPU", "temp_c": 45},
                        {"sensor": "PHY", "temp_c": 52},
                    ],
                    "smart_status": "healthy",
                },
                "error_message": None,
            },
            {
                "id": "col-00004",
                "device_id": "dev-mini-pc-01",
                "collector": "mock",
                "command": "uptime",
                "collected_at": stale_seen,
                "status": "critical",
                "summary": "SSH 连接超时，设备离线",
                "payload": {"host": "192.0.2.250"},
                "error_message": "timeout",
            },
        ],
        "alerts": [
            {
                "id": "alert-00001",
                "device_id": "dev-nas-01",
                "group_id": "grp-nas",
                "severity": "warning",
                "status": "active",
                "type": "pool_high",
                "code": "pool_high",
                "title": "存储池使用率过高",
                "message": "存储池使用率超过 85%",
                "created_at": warning_seen,
                "updated_at": warning_seen,
                "resolved_at": None,
                "resolved_by": None,
                "last_record_id": "col-00001",
            },
            {
                "id": "alert-00002",
                "device_id": "dev-mini-pc-01",
                "group_id": "grp-other",
                "severity": "critical",
                "status": "active",
                "type": "device_offline",
                "code": "device_offline",
                "title": "Lab Mini PC 离线",
                "message": "最近一次采集超时",
                "created_at": stale_seen,
                "updated_at": stale_seen,
                "resolved_at": None,
                "resolved_by": None,
                "last_record_id": "col-00004",
            },
        ],
    }


def build_initial_state() -> dict[str, Any]:
    now = utc_now()
    monitoring = build_monitoring_seed(now)
    return {
        "started_at": isoformat(now),
        "audit_logs": [],
        "users": [],
        "sessions": [],
        "retention_settings": {
            "collection_history_days": 30,
            "audit_log_days": 90,
            "resolved_alert_days": 30,
        },
        "collection_settings": {
            "default_collection_interval": 30,
        },
        "metrics": {
            "requests_total": 0,
            "errors_total": 0,
            "audit_events_total": 0,
            "high_risk_denied_total": 0,
            "device_group_writes_total": 0,
            "device_writes_total": 0,
            "device_test_total": 0,
            "device_refresh_total": 0,
            "device_scheduled_total": 0,
            "alert_resolved_total": 0,
        },
        **monitoring,
    }


def build_empty_state() -> dict[str, Any]:
    """Return initial state without demo devices, alerts, or history."""
    now = utc_now()
    state = build_initial_state()
    state["device_groups"] = [
        {
            "id": UNGROUPED_GROUP_ID,
            "name": "未分组",
            "description": "尚未归类的设备",
            "color": "#94a3b8",
            "icon": "folder",
            "sort_order": 999,
            "created_at": isoformat(now),
            "updated_at": isoformat(now),
        },
    ]
    state["devices"] = []
    state["collection_records"] = []
    state["alerts"] = []
    return state


def build_mock_data() -> dict[str, Any]:
    state = build_initial_state()
    return {
        "summary": {
            "device_groups": len(state["device_groups"]),
            "devices": len(state["devices"]),
            "alerts": len(state["alerts"]),
        },
        "device_groups": state["device_groups"],
        "devices": state["devices"],
        "collection_records": state["collection_records"],
        "alerts": state["alerts"],
        "audit_logs": state["audit_logs"],
    }


get_mock_data = build_mock_data
load_mock_data = build_mock_data
MOCK_DATA = build_mock_data()


class MockStore:
    def __init__(self) -> None:
        self._lock = RLock()
        self._state = build_initial_state()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return deepcopy(self._state)

    def read(self, key: str) -> Any:
        with self._lock:
            return deepcopy(self._state[key])

    def update(self, mutator):
        with self._lock:
            result = mutator(self._state)
            return deepcopy(result)

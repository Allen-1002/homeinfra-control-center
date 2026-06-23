"""Metrics and health views for the monitoring backend."""

from __future__ import annotations

from typing import Any

from .monitoring import monitoring_penalty


class MetricsService:
    def __init__(self, store) -> None:
        self.store = store

    def live(self) -> dict[str, Any]:
        snapshot = self.store.snapshot()
        return {"status": "live", "started_at": snapshot["started_at"]}

    def ready(self) -> dict[str, Any]:
        snapshot = self.store.snapshot()
        open_alerts = sum(1 for alert in snapshot["alerts"] if alert["status"] == "active")
        online_devices = sum(1 for device in snapshot["devices"] if device["status"] == "online")
        warning_devices = sum(1 for device in snapshot["devices"] if device["status"] == "warning")
        offline_devices = sum(1 for device in snapshot["devices"] if device["status"] == "offline")
        return {
            "status": "ready",
            "checks": {
                "seed_state_loaded": True,
                "device_inventory_loaded": len(snapshot["devices"]) > 0,
                "open_monitoring_alerts": open_alerts,
                "online_devices": online_devices,
                "warning_devices": warning_devices,
                "offline_devices": offline_devices,
            },
            "health_score": max(
                0,
                100 - monitoring_penalty(offline=offline_devices, warning=warning_devices, alerts=open_alerts),
            ),
        }

    def metrics(self) -> dict[str, Any]:
        snapshot = self.store.snapshot()
        return {
            "service": "homeinfra-api",
            "counters": snapshot["metrics"],
            "inventory": {
                "device_groups": len(snapshot["device_groups"]),
                "devices": len(snapshot["devices"]),
                "collection_records": len(snapshot["collection_records"]),
                "active_alerts": sum(1 for alert in snapshot["alerts"] if alert["status"] == "active"),
            },
        }

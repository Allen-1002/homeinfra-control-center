"""Alert generation from monitored infrastructure snapshots."""

from __future__ import annotations

from typing import Any

from .risk import assess_nas_risk


def generate_alerts(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    nas = snapshot.get("nas")
    if isinstance(nas, dict):
        result = assess_nas_risk(nas)
        if result["severity"] not in {"ok", "low", "healthy", "none"}:
            alerts.append(
                {
                    "id": "alert-nas-risk",
                    "source": "nas",
                    "severity": result["severity"],
                    "title": "NAS risk detected",
                    "message": "; ".join(result["reasons"]),
                }
            )

    return alerts


evaluate_alerts = generate_alerts
build_alerts = generate_alerts

"""Risk detection for monitored infrastructure state."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def build_nas_risks(nas: dict[str, Any]) -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    risks: list[dict[str, Any]] = []
    if nas["capacity_percent"] >= 90:
        risks.append(
            {
                "severity": "critical",
                "code": "nas_capacity_high",
                "message": f"NAS 容量已达到 {nas['capacity_percent']}%",
            }
        )
    if nas["raid_status"] != "healthy":
        risks.append(
            {
                "severity": "critical",
                "code": "nas_raid_degraded",
                "message": f"RAID 状态为 {nas['raid_status']}",
            }
        )
    last_backup = _parse_timestamp(nas["backup"]["last_success_at"])
    if (now - last_backup).days > 7:
        risks.append(
            {
                "severity": "critical",
                "code": "backup_stale",
                "message": "最近一次 NAS 备份已超过 7 天",
            }
        )
    return risks


def assess_nas_risk(nas: dict[str, Any]) -> dict[str, Any]:
    """Return a compact NAS risk envelope for tests and API consumers."""
    reasons: list[str] = []
    severity = "ok"
    capacity = float(nas.get("capacity_percent", 0))
    if capacity >= 90:
        severity = "critical"
        reasons.append(f"容量 {capacity:g}% 已超过严重阈值 (capacity critical)")
    elif capacity >= 80:
        severity = "warning"
        reasons.append(f"容量 {capacity:g}% 已超过告警阈值 (capacity warning)")

    raid = nas.get("raid_status", "healthy")
    if raid != "healthy":
        severity = "critical"
        reasons.append(f"RAID 状态为 {raid} (raid degraded)")

    backup_age = nas.get("last_backup_age_days")
    if backup_age is None:
        backup_age = nas.get("backup_age_days")
    if backup_age is None and "backup" in nas:
        backup = nas["backup"]
        if isinstance(backup, dict) and backup.get("last_success_at"):
            backup_age = (datetime.now(timezone.utc) - _parse_timestamp(backup["last_success_at"])).days
    if backup_age is not None and int(backup_age) > 7:
        severity = "critical"
        reasons.append(f"备份已过期 {backup_age} 天 (backup stale)")

    return {"severity": severity, "reasons": reasons}


evaluate_nas_risk = assess_nas_risk
nas_risk = assess_nas_risk

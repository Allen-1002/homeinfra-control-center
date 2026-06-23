"""Unified data contracts for collection results and structured metrics."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CommandError:
    command_id: str
    command: str
    exit_code: int | None = None
    stderr: str = ""
    stdout: str = ""
    error_type: str = "non_zero_exit"
    error_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "command": self.command,
            "exit_code": self.exit_code,
            "stderr": self.stderr[:500],
            "stdout": self.stdout[:500],
            "error_type": self.error_type,
            "error_message": self.error_message,
        }


@dataclass
class LinuxHostMetrics:
    hostname: str | None = None
    uname: str | None = None
    uptime_seconds: float | None = None
    load_1m: float | None = None
    load_5m: float | None = None
    load_15m: float | None = None
    cpu_percent: float | None = None
    cpu_cores: int | None = None
    memory_total_mb: float | None = None
    memory_used_mb: float | None = None
    memory_percent: float | None = None
    memory_buffers_mb: float | None = None
    memory_cached_mb: float | None = None
    memory_swap_total_mb: float | None = None
    memory_swap_used_mb: float | None = None
    disk_partitions: list[dict[str, Any]] = field(default_factory=list)
    network_interfaces: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    unavailable_metrics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "hostname": self.hostname,
            "uname": self.uname,
            "uptime": _format_uptime(self.uptime_seconds),
            "load_average": (
                f"{self.load_1m} {self.load_5m} {self.load_15m}"
                if all(v is not None for v in (self.load_1m, self.load_5m, self.load_15m))
                else None
            ),
            "cpu_percent": self.cpu_percent,
            "cpu_cores": self.cpu_cores,
            "memory_percent": round(self.memory_percent, 1) if self.memory_percent is not None else None,
            "memory_total_mb": round(self.memory_total_mb, 1) if self.memory_total_mb is not None else None,
            "memory_used_mb": round(self.memory_used_mb, 1) if self.memory_used_mb is not None else None,
            "memory_buffers_mb": round(self.memory_buffers_mb, 1) if self.memory_buffers_mb is not None else None,
            "memory_cached_mb": round(self.memory_cached_mb, 1) if self.memory_cached_mb is not None else None,
            "memory_swap_total_mb": round(self.memory_swap_total_mb, 1) if self.memory_swap_total_mb is not None else None,
            "memory_swap_used_mb": round(self.memory_swap_used_mb, 1) if self.memory_swap_used_mb is not None else None,
            "partitions": self.disk_partitions,
            "network_interfaces": self.network_interfaces,
            "errors": self.errors,
            "unavailable_metrics": self.unavailable_metrics,
        }
        return {k: v for k, v in result.items() if v is not None}


@dataclass
class CollectionResult:
    collector: str
    command: str
    status: str
    summary: str
    payload: dict[str, Any]
    data_source: str = "unknown"
    is_real_data: bool = False
    retry_attempt: int = 0
    connection_duration_ms: float = 0.0


def _format_uptime(total_seconds: float | None) -> str | None:
    if total_seconds is None:
        return None
    remaining = int(total_seconds)
    days = remaining // 86400
    hours = (remaining % 86400) // 3600
    minutes = (remaining % 3600) // 60
    seconds = remaining % 60
    parts = []
    if days > 0:
        parts.append(f"{days} day{'s' if days > 1 else ''}")
    parts.append(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
    return " ".join(parts)

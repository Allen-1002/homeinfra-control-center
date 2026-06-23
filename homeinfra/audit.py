"""Audit log recording helpers."""

from __future__ import annotations

from typing import Any

from .mock_data import isoformat, utc_now


MAX_AUDIT_LOGS = 5000


class AuditService:
    def __init__(self, store) -> None:
        self.store = store

    def record(
        self,
        *,
        actor: str,
        role: str,
        action: str,
        resource: str,
        outcome: str,
        request_id: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        def mutate(state):
            entry = {
                "id": f"audit-{state['metrics']['audit_events_total'] + 1:05d}",
                "timestamp": isoformat(utc_now()),
                "actor": actor,
                "role": role,
                "action": action,
                "resource": resource,
                "outcome": outcome,
                "request_id": request_id,
                "details": details or {},
            }
            state["audit_logs"].insert(0, entry)
            state["audit_logs"] = state["audit_logs"][:MAX_AUDIT_LOGS]
            state["metrics"]["audit_events_total"] += 1
            return entry

        return self.store.update(mutate)

    def list_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        logs = self.store.read("audit_logs")
        return logs[:limit]

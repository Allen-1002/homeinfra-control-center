"""Automation task state transitions and retry metadata."""

from __future__ import annotations

from typing import Any

from .errors import ConflictError, NotFoundError
from .mock_data import isoformat, utc_now


VALID_TRANSITIONS = {
    ("pending", "start"): "running",
    ("idle", "start"): "running",
    ("running", "succeed"): "succeeded",
    ("running", "success"): "succeeded",
    ("running", "fail"): "failed",
    ("pending", "cancel"): "cancelled",
    ("paused", "resume"): "idle",
}


def transition_task_state(state: str, event: str) -> str:
    """Pure state transition helper for automation tests and service code."""
    normalized = (state or "").lower()
    normalized_event = (event or "").lower()
    if normalized in {"succeeded", "success", "completed", "failed", "cancelled"}:
        raise ConflictError(
            "终态自动化任务不能再次流转",
            {"state": state, "event": event},
        )
    try:
        return VALID_TRANSITIONS[(normalized, normalized_event)]
    except KeyError as exc:
        raise ConflictError(
            "Invalid automation task transition",
            {"state": state, "event": event},
        ) from exc


class AutomationService:
    def __init__(self, store) -> None:
        self.store = store

    def list_tasks(self) -> dict[str, Any]:
        return self.store.read("automation")

    def _mutate_task(self, task_id: str, handler):
        def mutate(state):
            for task in state["automation"]["tasks"]:
                if task["id"] == task_id:
                    handler(task, state)
                    return task
            raise NotFoundError("automation task", task_id)

        return self.store.update(mutate)

    def run_task(self, task_id: str) -> dict[str, Any]:
        def handler(task, state):
            transition_task_state(task["state"], "start")
            if task["state"] == "paused":
                if task["retry_count"] >= task["max_retries"]:
                    raise ConflictError(
                        "任务重试次数已耗尽",
                        {"task_id": task_id, "max_retries": task["max_retries"]},
                    )
                task["retry_count"] += 1
            task["state"] = "running"
            task["run_count"] += 1
            task["last_run_at"] = isoformat(utc_now())
            task["last_error"] = None
            state["metrics"]["task_runs_total"] += 1

        return self._mutate_task(task_id, handler)

    def pause_task(self, task_id: str) -> dict[str, Any]:
        def handler(task, _state):
            if task["state"] == "paused":
                raise ConflictError("任务已经处于暂停状态", {"task_id": task_id})
            if task["state"] in {"succeeded", "failed", "cancelled"}:
                raise ConflictError("终态任务不能被暂停", {"task_id": task_id})
            task["state"] = "paused"
            if task["run_count"] > 0:
                task["last_error"] = "由操作员暂停"

        return self._mutate_task(task_id, handler)

    def resume_task(self, task_id: str) -> dict[str, Any]:
        def handler(task, _state):
            if task["state"] != "paused":
                raise ConflictError("只有已暂停任务才能恢复", {"task_id": task_id})
            task["state"] = "idle"

        return self._mutate_task(task_id, handler)

"""Application error types and JSON envelope helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any


@dataclass
class ApiError(Exception):
    code: str
    message: str
    status: int = HTTPStatus.BAD_REQUEST
    details: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        payload = {"code": self.code, "message": self.message}
        if self.details:
            payload["details"] = self.details
        return payload


class AuthError(ApiError):
    def __init__(self, message: str = "需要认证") -> None:
        super().__init__("auth_required", message, HTTPStatus.UNAUTHORIZED)


class ForbiddenError(ApiError):
    def __init__(self, message: str = "权限不足") -> None:
        super().__init__("forbidden", message, HTTPStatus.FORBIDDEN)


class NotFoundError(ApiError):
    def __init__(self, resource: str, identifier: str) -> None:
        super().__init__(
            "not_found",
            f"{resource} 不存在",
            HTTPStatus.NOT_FOUND,
            {"resource": resource, "id": identifier},
        )


class ConflictError(ApiError):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__("conflict", message, HTTPStatus.CONFLICT, details or {})


class ValidationError(ApiError):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            "validation_error",
            message,
            HTTPStatus.UNPROCESSABLE_ENTITY,
            details or {},
        )


class ConfirmationRequiredError(ApiError):
    def __init__(self, action: str) -> None:
        super().__init__(
            "confirmation_required",
            f"{action} 需要二次确认",
            HTTPStatus.PRECONDITION_REQUIRED,
            {"action": action},
        )


def json_envelope(
    *,
    data: Any = None,
    error: dict[str, Any] | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {"data": data, "error": error, "meta": meta or {}}

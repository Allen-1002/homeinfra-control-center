"""Small public API helpers shared by HTTP and tests."""

from __future__ import annotations

from typing import Any

from .errors import json_envelope


def error_response(code: str, message: str, status: int = 400, details: dict[str, Any] | None = None):
    error = {"code": code, "message": message}
    if details:
        error["details"] = details
    return json_envelope(data=None, error=error, meta={}), status


build_error_response = error_response
api_error = error_response

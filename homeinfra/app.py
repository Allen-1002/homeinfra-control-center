"""HTTP entry point for the stdlib-only HomeInfra API."""

from __future__ import annotations

import json
import mimetypes
import posixpath
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from itertools import count
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .auth import AuthService, require_permission, require_role
from .collector_service import CollectorService
from .collectors import DisabledCollector, ParamikoSSHCollector, RetryStrategy, CollectorError
from .errors import (
    ApiError,
    ConfirmationRequiredError,
    NotFoundError,
    ValidationError,
    json_envelope,
)
from .metrics import MetricsService
from .mock_data import MockStore
from .operations import HomeInfraService
from .persistence import SQLiteStore


REQUEST_COUNTER = count(1)
MAX_JSON_BODY_BYTES = 1_048_576
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store, max-age=0",
}
SENSITIVE_AUDIT_KEYS = {
    "authorization",
    "encrypted_private_key",
    "inline_private_key",
    "key_path",
    "new_password",
    "password",
    "password_hash",
    "password_salt",
    "private_key_path",
    "token",
    "token_hash",
}


def build_security_headers(*, retry_after: int | None = None) -> dict[str, str]:
    headers = dict(SECURITY_HEADERS)
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return headers


def sanitize_ssh_validation_message(message: str) -> str:
    lowered = (message or "").lower()
    if "private_key_path" in lowered or "私钥文件不存在" in message:
        return "SSH 私钥文件不存在或不可访问"
    return message


def parse_json_object_body(raw: bytes, *, content_length: int) -> dict[str, Any]:
    if content_length < 0:
        raise ValidationError("Content-Length 非法", {"header": str(content_length)})
    if content_length == 0:
        return {}
    if content_length > MAX_JSON_BODY_BYTES:
        raise ApiError(
            "payload_too_large",
            f"JSON 请求体不能超过 {MAX_JSON_BODY_BYTES} 字节",
            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            {"max_bytes": MAX_JSON_BODY_BYTES, "received_bytes": content_length},
        )
    if not raw:
        return {}
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError("JSON 请求体格式错误", {"reason": str(exc)}) from exc
    if not isinstance(decoded, dict):
        raise ValidationError("JSON 请求体必须是对象")
    return decoded


class HomeInfraApp:
    def __init__(
        self,
        *,
        static_dir: str | None = None,
        store_mode: str = "sqlite",
        db_path: str | None = None,
        collector_mode: str = "disabled",
        ssh_known_hosts: str | None = None,
        ssh_auto_accept_host_key: bool = False,
        ssh_retry_max: int = 3,
        ssh_retry_base_delay: float = 1.0,
        collector_service_override: CollectorService | None = None,
    ) -> None:
        if store_mode == "mock":
            self.store = MockStore()
        elif store_mode == "sqlite":
            self.store = SQLiteStore(db_path)
        else:
            raise ValueError(f"unsupported store_mode: {store_mode}")

        if collector_mode not in {"ssh", "disabled"}:
            raise ValueError(f"unsupported collector_mode: {collector_mode}")

        self._collector_mode = collector_mode

        if collector_service_override is not None:
            self._collector_service = collector_service_override
        elif collector_mode == "ssh":
            retry = RetryStrategy(
                max_retries=ssh_retry_max,
                base_delay_seconds=ssh_retry_base_delay,
            )
            ssh_collector = ParamikoSSHCollector(
                retry=retry,
                known_hosts_path=ssh_known_hosts,
                auto_accept_host_key=ssh_auto_accept_host_key,
            )
            self._collector_service = CollectorService(
                ssh_collector, sample_interval=1.0, data_source="ssh", is_real_data=True
            )
        else:
            self._collector_service = CollectorService(
                DisabledCollector(), sample_interval=0.0, data_source="disabled", is_real_data=False
            )

        self.auth = AuthService(self.store)
        self.service = HomeInfraService(self.store, collector_service=self._collector_service)
        self.metrics = MetricsService(self.store)
        self.static_dir = Path(static_dir).resolve() if static_dir else None

    def mark_request(self) -> str:
        request_id = f"req-{next(REQUEST_COUNTER):06d}"

        def mutate(state):
            state["metrics"]["requests_total"] += 1
            return state["metrics"]["requests_total"]

        self.store.update(mutate)
        return request_id

    def mark_error(self) -> None:
        def mutate(state):
            state["metrics"]["errors_total"] += 1
            return state["metrics"]["errors_total"]

        self.store.update(mutate)

    def mark_high_risk_denied(self) -> None:
        def mutate(state):
            state["metrics"]["high_risk_denied_total"] += 1
            return state["metrics"]["high_risk_denied_total"]

        self.store.update(mutate)

    def record_api_error(
        self,
        *,
        method: str,
        path: str,
        request_id: str,
        error: ApiError,
        principal=None,
    ) -> None:
        if not path.startswith("/api/v1/"):
            return
        actor = principal.subject if principal else "anonymous"
        role = principal.role if principal else "anonymous"
        self.service.audit.record(
            actor=actor,
            role=role,
            action=f"http.{method.lower()}",
            resource=path,
            outcome=error.code,
            request_id=request_id,
            details={"message": error.message},
        )

    def handle_api_request(
        self,
        *,
        method: str,
        path: str,
        headers: dict[str, str],
        body: dict[str, Any] | None = None,
        query: dict[str, list[str]] | None = None,
        client_ip: str | None = None,
        request_id: str | None = None,
    ) -> tuple[dict[str, Any], str]:
        request_id = request_id or self.mark_request()
        lowered_headers = {key.lower(): value for key, value in headers.items()}
        normalized_client_ip = self.extract_client_ip(lowered_headers, fallback=client_ip)
        principal = None
        try:
            principal = self.resolve_request_principal(method=method, path=path, headers=lowered_headers)
            data = self.dispatch_api(
                method=method,
                path=path,
                body=body or {},
                query=query or {},
                principal=principal,
                headers=lowered_headers,
                request_id=request_id,
                client_ip=normalized_client_ip,
            )
            return data, request_id
        except ApiError as exc:
            self.record_api_error(
                method=method,
                path=path,
                request_id=request_id,
                error=exc,
                principal=principal,
            )
            raise

    def is_public_api_route(self, method: str, path: str) -> bool:
        return (method, path) in {
            ("GET", "/api/v1/health/live"),
            ("GET", "/api/v1/ready"),
            ("GET", "/api/v1/health/ready"),
            ("GET", "/api/v1/auth/bootstrap"),
            ("POST", "/api/v1/auth/bootstrap"),
            ("POST", "/api/v1/auth/login"),
        }

    def resolve_request_principal(self, *, method: str, path: str, headers: dict[str, str]):
        if self.is_public_api_route(method, path):
            return None
        return self.auth.resolve_principal(headers)

    def dispatch_api(
        self,
        *,
        method: str,
        path: str,
        body: dict[str, Any],
        query: dict[str, list[str]],
        principal,
        headers: dict[str, str],
        request_id: str,
        client_ip: str | None = None,
    ) -> Any:
        service = self.service
        metrics = self.metrics
        if method == "GET" and path == "/api/v1/health/live":
            return metrics.live()
        if method == "GET" and path in {"/api/v1/ready", "/api/v1/health/ready"}:
            return metrics.ready()
        if method == "GET" and path == "/api/v1/auth/bootstrap":
            return self.auth.bootstrap_status()
        if method == "POST" and path == "/api/v1/auth/bootstrap":
            result = self.auth.bootstrap_admin(body)
            service.audit.record(
                actor=result["user"]["username"],
                role=result["user"]["role"],
                action="auth.bootstrap",
                resource="auth/bootstrap",
                outcome="success",
                request_id=request_id,
                details={"user_id": result["user"]["id"]},
            )
            return result
        if method == "POST" and path == "/api/v1/auth/login":
            result = self.auth.login(body, client_ip=client_ip)
            service.audit.record(
                actor=result["user"]["username"],
                role=result["user"]["role"],
                action="auth.login",
                resource="auth/login",
                outcome="success",
                request_id=request_id,
            )
            return result

        require_role(principal, "viewer")
        role = principal.role
        actor = principal.username

        if method == "POST" and path == "/api/v1/auth/logout":
            result = self.auth.logout(principal.session_id)
            service.audit.record(
                actor=actor,
                role=role,
                action="auth.logout",
                resource="auth/logout",
                outcome="success",
                request_id=request_id,
            )
            return result
        if method == "GET" and path == "/api/v1/metrics":
            return metrics.metrics()
        if method == "GET" and path == "/api/v1/dashboard":
            return service.dashboard()
        if method == "GET" and path == "/api/v1/device-groups":
            return service.monitoring.list_groups()
        if method == "POST" and path == "/api/v1/device-groups":
            require_permission(principal, "groups", "write")
            result = service.monitoring.create_group(body)
            service.audit.record(
                actor=actor,
                role=role,
                action="device_group.create",
                resource=f"device-groups/{result['id']}",
                outcome="success",
                request_id=request_id,
                details=self.safe_audit_payload(body),
            )
            return result
        if method == "GET" and path == "/api/v1/devices":
            enabled_filter = self.parse_bool_query(query.get("enabled", [None])[0])
            return service.monitoring.list_devices(
                {
                    "group_id": query.get("group_id", [None])[0],
                    "group": query.get("group", [None])[0],
                    "device_type": query.get("device_type", [None])[0],
                    "status": query.get("status", [None])[0],
                    "enabled": enabled_filter,
                }
            )
        if method == "POST" and path == "/api/v1/devices":
            require_permission(principal, "devices", "write")
            body = dict(body)
            body.update(self._prepare_device_creation_state(body))
            result = service.monitoring.create_device(body)
            service.audit.record(
                actor=actor,
                role=role,
                action="device.create",
                resource=f"devices/{result['id']}",
                outcome="success",
                request_id=request_id,
                details=self.safe_audit_payload(body),
            )
            return result
        if method == "GET" and path == "/api/v1/collections":
            return service.monitoring.list_collection_records(
                device_id=query.get("device_id", [None])[0],
                group_id=query.get("group_id", [None])[0] or query.get("group", [None])[0],
                status=query.get("status", [None])[0],
                since=query.get("since", [None])[0] or query.get("start_at", [None])[0],
                until=query.get("until", [None])[0] or query.get("end_at", [None])[0],
                limit=self.parse_limit(query.get("limit", ["50"])[0], maximum=200),
            )
        if method == "GET" and path == "/api/v1/alerts":
            return service.monitoring.list_alerts(
                {
                    "device_id": query.get("device_id", [None])[0],
                    "group_id": query.get("group_id", [None])[0],
                    "group": query.get("group", [None])[0],
                    "status": query.get("status", [None])[0],
                }
            )
        if method == "GET" and path == "/api/v1/audit":
            require_permission(principal, "audit", "read")
            try:
                limit = int(query.get("limit", ["50"])[0])
            except ValueError as exc:
                raise ValidationError("审计查询的 limit 参数必须是整数") from exc
            return {"entries": service.audit.list_recent(limit=max(1, min(limit, 100)))}
        if method == "GET" and path == "/api/v1/auth/me":
            return self.auth.build_me(principal)
        if method == "GET" and path == "/api/v1/users":
            require_permission(principal, "users", "read")
            return self.auth.list_users()
        if method == "POST" and path == "/api/v1/users":
            require_permission(principal, "users", "write")
            result = self.auth.create_user(body)
            service.audit.record(
                actor=actor,
                role=role,
                action="user.create",
                resource=f"users/{result['id']}",
                outcome="success",
                request_id=request_id,
                details=self.safe_audit_payload(body),
            )
            return result
        if method == "GET" and path == "/api/v1/settings/retention":
            require_permission(principal, "settings", "read")
            return service.get_retention_settings()
        if method == "GET" and path == "/api/v1/settings/collection":
            require_permission(principal, "settings", "read")
            return service.get_collection_settings()
        if method == "PATCH" and path == "/api/v1/settings/collection":
            require_permission(principal, "settings", "write")
            result = service.update_collection_settings(body)
            service.audit.record(
                actor=actor,
                role=role,
                action="collection.update",
                resource="settings/collection",
                outcome="success",
                request_id=request_id,
                details=self.safe_audit_payload(body),
            )
            return result
        if method == "PATCH" and path == "/api/v1/settings/retention":
            require_permission(principal, "settings", "write")
            result = service.update_retention_settings(body)
            service.audit.record(
                actor=actor,
                role=role,
                action="retention.update",
                resource="settings/retention",
                outcome="success",
                request_id=request_id,
                details=self.safe_audit_payload(body),
            )
            return result
        if method == "POST" and path == "/api/v1/settings/retention/cleanup":
            require_permission(principal, "settings", "write")
            result = service.cleanup_retention()
            service.audit.record(
                actor=actor,
                role=role,
                action="retention.cleanup",
                resource="settings/retention/cleanup",
                outcome="success",
                request_id=request_id,
                details=result["deleted"],
            )
            return result

        parts = [part for part in path.split("/") if part]
        if parts[:2] != ["api", "v1"]:
            raise NotFoundError("route", path)

        if len(parts) >= 3 and parts[2] == "device-groups":
            if len(parts) == 4:
                group_id = parts[3]
                if method == "GET":
                    return service.monitoring.get_group(group_id)
                if method == "PATCH":
                    require_permission(principal, "groups", "write")
                    result = service.monitoring.update_group(group_id, body)
                    service.audit.record(
                        actor=actor,
                        role=role,
                        action="device_group.update",
                        resource=f"device-groups/{group_id}",
                        outcome="success",
                        request_id=request_id,
                        details=self.safe_audit_payload(body),
                    )
                    return result
                if method == "DELETE":
                    require_permission(principal, "groups", "delete")
                    result = service.monitoring.delete_group(group_id)
                    service.audit.record(
                        actor=actor,
                        role=role,
                        action="device_group.delete",
                        resource=f"device-groups/{group_id}",
                        outcome="success",
                        request_id=request_id,
                    )
                    return result

        if len(parts) >= 3 and parts[2] == "users":
            require_permission(principal, "users", "write")
            if len(parts) == 4:
                user_id = parts[3]
                if method == "PATCH":
                    result = self.auth.update_user(user_id, body)
                    service.audit.record(
                        actor=actor,
                        role=role,
                        action="user.update",
                        resource=f"users/{user_id}",
                        outcome="success",
                        request_id=request_id,
                        details=self.safe_audit_payload(body),
                    )
                    return result
            if len(parts) == 5 and method == "POST" and parts[4] == "reset-password":
                user_id = parts[3]
                result = self.auth.reset_password(user_id, body)
                service.audit.record(
                    actor=actor,
                    role=role,
                    action="user.password.reset",
                    resource=f"users/{user_id}",
                    outcome="success",
                    request_id=request_id,
                    details=self.safe_audit_payload(body),
                )
                return result

        if len(parts) >= 3 and parts[2] == "devices":
            if len(parts) == 4:
                device_id = parts[3]
                if method == "GET":
                    return service.monitoring.get_device(device_id)
                if method == "PATCH":
                    require_permission(principal, "devices", "write")
                    result = service.monitoring.update_device(
                        device_id,
                        body,
                        allow_sensitive_fields=role == "admin",
                    )
                    service.audit.record(
                        actor=actor,
                        role=role,
                        action="device.update",
                        resource=f"devices/{device_id}",
                        outcome="success",
                        request_id=request_id,
                        details=self.safe_audit_payload(body),
                    )
                    return result
                if method == "DELETE":
                    require_permission(principal, "devices", "delete")
                    result = service.monitoring.delete_device(device_id)
                    service.audit.record(
                        actor=actor,
                        role=role,
                        action="device.delete",
                        resource=f"devices/{device_id}",
                        outcome="success",
                        request_id=request_id,
                    )
                    return result
            if len(parts) == 5:
                device_id, action = parts[3], parts[4]
                if method == "POST" and action == "test":
                    require_permission(principal, "devices", "test")
                    timeout = self.parse_timeout(body, query)
                    result = service.monitoring.test_device_connection(
                        device_id,
                        timeout=timeout,
                    )
                    service.audit.record(
                        actor=actor,
                        role=role,
                        action="device.test",
                        resource=f"devices/{device_id}",
                        outcome=result["record"]["status"],
                        request_id=request_id,
                        details={"timeout": timeout},
                    )
                    return result
                if method == "POST" and action == "refresh":
                    require_permission(principal, "devices", "refresh")
                    timeout = self.parse_timeout(body, query)
                    result = service.monitoring.refresh_device(
                        device_id,
                        timeout=timeout,
                    )
                    service.audit.record(
                        actor=actor,
                        role=role,
                        action="device.refresh",
                        resource=f"devices/{device_id}",
                        outcome=result["record"]["status"],
                        request_id=request_id,
                        details={"timeout": timeout},
                    )
                    return result
                if method == "GET" and action == "collections":
                    return service.monitoring.list_collection_records(
                        device_id=device_id,
                        group_id=query.get("group_id", [None])[0] or query.get("group", [None])[0],
                        status=query.get("status", [None])[0],
                        since=query.get("since", [None])[0] or query.get("start_at", [None])[0],
                        until=query.get("until", [None])[0] or query.get("end_at", [None])[0],
                        limit=self.parse_limit(query.get("limit", ["20"])[0], maximum=200),
                    )

        if len(parts) >= 3 and parts[2] == "alerts":
            if len(parts) == 5 and method == "POST" and parts[4] == "resolve":
                require_permission(principal, "alerts", "write")
                alert_id = parts[3]
                result = service.monitoring.resolve_alert(alert_id, actor=actor)
                service.audit.record(
                    actor=actor,
                    role=role,
                    action="alert.resolve",
                    resource=f"alerts/{alert_id}",
                    outcome="success",
                    request_id=request_id,
                )
                return result

        raise NotFoundError("route", path)

    def ensure_confirmation(
        self,
        body: dict[str, Any],
        headers: dict[str, str],
        action: str,
    ) -> None:
        confirmed = bool(body.get("confirm")) or headers.get("x-confirm", "").lower() == "true"
        if not confirmed:
            self.mark_high_risk_denied()
            raise ConfirmationRequiredError(action)

    def safe_audit_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        def sanitize(value: Any):
            if isinstance(value, dict):
                sanitized: dict[str, Any] = {}
                for key, item in value.items():
                    if key.lower() in SENSITIVE_AUDIT_KEYS:
                        continue
                    sanitized[key] = sanitize(item)
                return sanitized
            if isinstance(value, list):
                return [sanitize(item) for item in value]
            return value

        return sanitize(payload)

    def _prepare_device_creation_state(self, body: dict[str, Any]) -> dict[str, Any]:
        if self._collector_mode == "disabled":
            return {
                "verified": False,
                "status": "disabled",
            }

        svc = self._collector_service
        if svc is None:
            raise ValidationError("SSH 采集器未初始化")
        collector = svc.collector
        if not isinstance(collector, ParamikoSSHCollector):
            return {
                "verified": False,
                "status": "unknown",
            }
        auth_type = body.get("auth_type", "none")
        if auth_type == "none":
            raise ValidationError("SSH 模式下必须提供可用的认证方式")
        try:
            results = collector.quick_verify(body, timeout=10)
            hostname = results.get("hostname", "").strip()
            uname = results.get("uname", "").strip()
            if not hostname and not uname:
                raise ValidationError("SSH 验证失败：无法获取 hostname 或 uname")
        except CollectorError as exc:
            safe_message = sanitize_ssh_validation_message(exc.message)
            raise ValidationError(f"SSH 验证失败：{safe_message}") from exc
        return {
            "verified": True,
            "status": "online",
        }

    def parse_limit(self, raw_value: str | None, *, maximum: int) -> int:
        if raw_value is None:
            return min(50, maximum)
        try:
            value = int(raw_value)
        except ValueError as exc:
            raise ValidationError("limit 参数必须是整数") from exc
        return max(1, min(value, maximum))

    def parse_bool_query(self, raw_value: str | None) -> bool | None:
        if raw_value is None:
            return None
        normalized = raw_value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False
        raise ValidationError("enabled 查询参数必须是布尔值")

    def parse_timeout(self, body: dict[str, Any], query: dict[str, list[str]]) -> int:
        raw = body.get("timeout")
        if raw is None:
            raw_values = query.get("timeout", [])
            raw = raw_values[0] if raw_values else 5
        try:
            timeout = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValidationError("timeout 必须是整数") from exc
        if timeout <= 0 or timeout > 30:
            raise ValidationError("timeout 必须在 1-30 秒之间")
        return timeout

    def extract_client_ip(self, headers: dict[str, str], *, fallback: str | None = None) -> str:
        return (fallback or "unknown").strip() or "unknown"


def create_server(
    host: str,
    port: int,
    *,
    static_dir: str | None = None,
    store_mode: str = "sqlite",
    db_path: str | None = None,
    collector_mode: str = "disabled",
    ssh_known_hosts: str | None = None,
    ssh_auto_accept_host_key: bool = False,
    ssh_retry_max: int = 3,
    ssh_retry_base_delay: float = 1.0,
    collector_service_override: CollectorService | None = None,
) -> ThreadingHTTPServer:
    app = HomeInfraApp(
        static_dir=static_dir,
        store_mode=store_mode,
        db_path=db_path,
        collector_mode=collector_mode,
        ssh_known_hosts=ssh_known_hosts,
        ssh_auto_accept_host_key=ssh_auto_accept_host_key,
        ssh_retry_max=ssh_retry_max,
        ssh_retry_base_delay=ssh_retry_base_delay,
        collector_service_override=collector_service_override,
    )

    class Handler(BaseHTTPRequestHandler):
        server_version = "HomeInfraMock/1.0"

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

        def do_PATCH(self) -> None:
            self._handle("PATCH")

        def do_DELETE(self) -> None:
            self._handle("DELETE")

        def log_message(self, _format: str, *_args: Any) -> None:
            return

        @property
        def app(self) -> HomeInfraApp:
            return self.server.app  # type: ignore[attr-defined]

        def _handle(self, method: str) -> None:
            request_id = self.app.mark_request()
            principal = None
            path = self.path
            try:
                parsed = urlparse(self.path)
                path = parsed.path
                query = parse_qs(parsed.query)
                body = self._parse_json_body()
                headers = {key.lower(): value for key, value in self.headers.items()}
                client_ip = self.app.extract_client_ip(headers, fallback=self.client_address[0] if self.client_address else None)

                if path.startswith("/api/v1/"):
                    data, request_id = self.app.handle_api_request(
                        method=method,
                        path=path,
                        headers=headers,
                        body=body,
                        query=query,
                        client_ip=client_ip,
                        request_id=request_id,
                    )
                    self._write_json(HTTPStatus.OK, json_envelope(data=data, meta={"request_id": request_id}))
                    return

                self._serve_static(path)
            except ApiError as exc:
                self.app.mark_error()
                if not path.startswith("/api/v1/"):
                    self.app.record_api_error(
                        method=method,
                        path=path,
                        request_id=request_id,
                        error=exc,
                        principal=principal,
                    )
                self._write_json(
                    exc.status,
                    json_envelope(error=exc.to_payload(), meta={"request_id": request_id}),
                    retry_after=(
                        int(exc.details.get("retry_after_seconds", 0))
                        if exc.status == HTTPStatus.TOO_MANY_REQUESTS and exc.details.get("retry_after_seconds")
                        else None
                    ),
                )
            except Exception as exc:  # pragma: no cover - defensive fallback
                self.app.mark_error()
                self._write_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    json_envelope(
                        error={
                            "code": "internal_error",
                            "message": "服务器发生未预期错误",
                        },
                        meta={"request_id": request_id},
                    ),
                )

        def _parse_json_body(self) -> dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ValidationError("Content-Length 非法", {"header": self.headers.get("Content-Length", "")}) from exc
            if length < 0:
                raise ValidationError("Content-Length 非法", {"header": str(length)})
            if length == 0:
                return {}
            if length > MAX_JSON_BODY_BYTES:
                raise ApiError(
                    "payload_too_large",
                    f"JSON 请求体不能超过 {MAX_JSON_BODY_BYTES} 字节",
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    {"max_bytes": MAX_JSON_BODY_BYTES, "received_bytes": length},
                )
            raw = self.rfile.read(length)
            return parse_json_object_body(raw, content_length=length)

        def _serve_static(self, request_path: str) -> None:
            static_dir = self.app.static_dir
            if not static_dir or not static_dir.exists():
                raise NotFoundError("route", request_path)
            normalized = posixpath.normpath(unquote(request_path)).lstrip("/")
            target = (static_dir / normalized).resolve()
            if static_dir not in target.parents and target != static_dir:
                raise NotFoundError("static file", request_path)
            if target.is_dir():
                target = target / "index.html"
            if not target.exists() or not target.is_file():
                raise NotFoundError("static file", request_path)
            content = target.read_bytes()
            mime_type, _ = mimetypes.guess_type(str(target))
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", mime_type or "application/octet-stream")
            self.send_header("Content-Length", str(len(content)))
            self._write_security_headers()
            self.end_headers()
            self.wfile.write(content)

        def _write_security_headers(self, *, retry_after: int | None = None) -> None:
            for header, value in build_security_headers(retry_after=retry_after).items():
                self.send_header(header, value)

        def _write_json(
            self,
            status: int,
            payload: dict[str, Any],
            *,
            retry_after: int | None = None,
        ) -> None:
            content = json.dumps(payload, ensure_ascii=True, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self._write_security_headers(retry_after=retry_after)
            self.end_headers()
            self.wfile.write(content)

    server = ThreadingHTTPServer((host, port), Handler)
    server.app = app  # type: ignore[attr-defined]
    # Start the backend collection scheduler (independent of the frontend).
    from .scheduler import CollectionScheduler
    scheduler = CollectionScheduler(app)
    server.scheduler = scheduler  # type: ignore[attr-defined]
    scheduler.start()
    return server

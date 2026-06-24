"""Local authentication, session handling, and RBAC enforcement."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from http import HTTPStatus
from typing import Any

from .errors import ApiError, AuthError, ConflictError, ForbiddenError, NotFoundError, ValidationError
from .mock_data import isoformat, utc_now


ROLE_LEVELS = {"viewer": 1, "auditor": 2, "operator": 3, "admin": 4}
PERMISSION_SETS = {
    "viewer": {"devices:read", "groups:read", "alerts:read", "collections:read", "dashboard:read", "retention:read", "metrics:read"},
    "auditor": {"devices:read", "groups:read", "alerts:read", "collections:read", "dashboard:read", "retention:read", "metrics:read", "audit:read", "users:read"},
    "operator": {"devices:*", "groups:*", "alerts:*", "collections:*", "dashboard:read", "retention:read", "metrics:read", "audit:read"},
    "admin": {"*:*"},
}
PASSWORD_ITERATIONS = 240_000
PASSWORD_MIN_LENGTH = 8
SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_SESSIONS = 500
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]{3,64}$")
FAILED_LOGIN_WINDOW_SECONDS = 5 * 60
FAILED_LOGIN_LIMIT = 5
FAILED_LOGIN_COOLDOWN_SECONDS = 5 * 60


@dataclass(frozen=True)
class Principal:
    user_id: str
    username: str
    role: str
    subject: str
    auth_scheme: str
    session_id: str
    session_expires_at: str


def _next_numbered_id(prefix: str, items: list[dict[str, Any]]) -> str:
    highest = 0
    for item in items:
        item_id = str(item.get("id", ""))
        if not item_id.startswith(prefix + "-"):
            continue
        try:
            highest = max(highest, int(item_id.rsplit("-", 1)[1]))
        except ValueError:
            continue
    return f"{prefix}-{highest + 1:05d}"


def _parse_timestamp(raw: str | None):
    if not raw:
        return None
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


class AuthService:
    def __init__(self, store) -> None:
        self.store = store
        self._failed_login_lock = threading.Lock()
        self._failed_login_state: dict[tuple[str, str], dict[str, Any]] = {}

    def bootstrap_status(self) -> dict[str, Any]:
        users = self.store.read("users")
        return {
            "required": len(users) == 0,
            "user_count": len(users),
        }

    def bootstrap_admin(self, payload: dict[str, Any]) -> dict[str, Any]:
        username = self._normalize_username(payload.get("username"))
        password = self._normalize_password(payload.get("password"))
        token = self._generate_token()
        return self.store.update(
            lambda state: self._bootstrap_admin_mutate(
                state,
                username=username,
                password=password,
                token=token,
            )
        )

    def login(self, payload: dict[str, Any], *, client_ip: str | None = None) -> dict[str, Any]:
        username = self._normalize_username(payload.get("username"))
        rate_limit_key = self._rate_limit_key(client_ip, username)
        self._ensure_login_not_rate_limited(rate_limit_key)
        password = self._normalize_password(payload.get("password"))
        token = self._generate_token()
        try:
            result = self.store.update(
                lambda state: self._login_mutate(
                    state,
                    username=username,
                    password=password,
                    token=token,
                )
            )
        except AuthError:
            self._record_failed_login(rate_limit_key)
            raise
        self._clear_failed_login(rate_limit_key)
        return result

    def logout(self, session_id: str) -> dict[str, Any]:
        return self.store.update(lambda state: self._logout_mutate(state, session_id=session_id))

    def resolve_principal(self, headers: dict[str, str]) -> Principal:
        token = self.extract_bearer_token(headers)
        if not token:
            if self.bootstrap_status()["required"]:
                raise AuthError("系统尚未初始化，请先创建管理员账户")
            raise AuthError()
        return self.store.update(lambda state: self._resolve_principal_mutate(state, token=token))

    def list_users(self) -> dict[str, Any]:
        users = self.store.read("users")
        users.sort(key=lambda item: item["username"].casefold())
        return {"users": [self._public_user(user) for user in users]}

    def create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        username = self._normalize_username(payload.get("username"))
        password = self._normalize_password(payload.get("password"))
        role = self._normalize_role(payload.get("role"))
        enabled = payload.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValidationError("enabled 必须是布尔值")
        return self.store.update(
            lambda state: self._create_user_mutate(
                state,
                username=username,
                password=password,
                role=role,
                enabled=enabled,
            )
        )

    def update_user(self, user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValidationError("用户更新请求体必须是对象")
        updates: dict[str, Any] = {}
        if "role" in payload:
            updates["role"] = self._normalize_role(payload.get("role"))
        if "enabled" in payload:
            if not isinstance(payload.get("enabled"), bool):
                raise ValidationError("enabled 必须是布尔值")
            updates["enabled"] = payload["enabled"]
        if not updates:
            raise ValidationError("用户更新至少需要 enabled 或 role")
        return self.store.update(
            lambda state: self._update_user_mutate(state, user_id=user_id, updates=updates)
        )

    def reset_password(self, user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        password = self._normalize_password(payload.get("password"))
        return self.store.update(
            lambda state: self._reset_password_mutate(state, user_id=user_id, password=password)
        )

    def build_me(self, principal: Principal) -> dict[str, Any]:
        return {
            "id": principal.user_id,
            "username": principal.username,
            "role": principal.role,
            "subject": principal.subject,
            "auth_scheme": principal.auth_scheme,
            "session_id": principal.session_id,
            "session_expires_at": principal.session_expires_at,
        }

    def extract_bearer_token(self, headers: dict[str, str]) -> str | None:
        authorization = headers.get("authorization") or ""
        if not authorization.lower().startswith("bearer "):
            return None
        token = authorization.split(" ", 1)[1].strip()
        return token or None

    def _bootstrap_admin_mutate(self, state, *, username: str, password: str, token: str) -> dict[str, Any]:
        if state["users"]:
            raise ConflictError("系统已经完成初始化，不能重复创建初始管理员")
        user = self._build_user(state, username=username, password=password, role="admin", enabled=True)
        state["users"].append(user)
        session = self._issue_session(state, user=user, token=token)
        return {
            "bootstrap_required": False,
            "user": self._public_user(user),
            "token": token,
            "session": self._public_session(session),
        }

    def _login_mutate(self, state, *, username: str, password: str, token: str) -> dict[str, Any]:
        self._cleanup_expired_sessions(state)
        if not state["users"]:
            raise ConflictError("系统尚未初始化，请先创建管理员账户")
        user = self._find_user_by_username(state, username)
        if not user.get("enabled", True):
            raise AuthError("账户已被禁用")
        if not self._verify_password(password, user):
            raise AuthError("用户名或密码错误")
        now = isoformat(utc_now())
        user["last_login_at"] = now
        session = self._issue_session(state, user=user, token=token)
        return {
            "user": self._public_user(user),
            "token": token,
            "session": self._public_session(session),
        }

    def _logout_mutate(self, state, *, session_id: str) -> dict[str, Any]:
        before = len(state["sessions"])
        state["sessions"] = [session for session in state["sessions"] if session["id"] != session_id]
        return {"logged_out": before != len(state["sessions"])}

    def _resolve_principal_mutate(self, state, *, token: str) -> Principal:
        self._cleanup_expired_sessions(state)
        if not state["users"]:
            raise AuthError("系统尚未初始化，请先创建管理员账户")
        token_hash = self._hash_token(token)
        for session in state["sessions"]:
            if not hmac.compare_digest(session["token_hash"], token_hash):
                continue
            user = self._find_user_by_id(state, session["user_id"])
            if not user.get("enabled", True):
                state["sessions"] = [item for item in state["sessions"] if item["id"] != session["id"]]
                raise AuthError("账户已被禁用")
            now = isoformat(utc_now())
            session["last_seen_at"] = now
            return Principal(
                user_id=user["id"],
                username=user["username"],
                role=user["role"],
                subject=f"user:{user['username']}",
                auth_scheme="bearer",
                session_id=session["id"],
                session_expires_at=session["expires_at"],
            )
        raise AuthError("会话无效或已过期")

    def _create_user_mutate(
        self,
        state,
        *,
        username: str,
        password: str,
        role: str,
        enabled: bool,
    ) -> dict[str, Any]:
        if not state["users"]:
            raise ConflictError("系统尚未初始化，请先创建管理员账户")
        self._ensure_username_available(state, username)
        user = self._build_user(
            state,
            username=username,
            password=password,
            role=role,
            enabled=enabled,
        )
        state["users"].append(user)
        state["users"].sort(key=lambda item: item["username"].casefold())
        return self._public_user(user)

    def _update_user_mutate(self, state, *, user_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        user = self._find_user_by_id(state, user_id)
        next_role = updates.get("role", user["role"])
        next_enabled = updates.get("enabled", user.get("enabled", True))
        if user["role"] == "admin" and (next_role != "admin" or not next_enabled):
            enabled_admins = [
                candidate
                for candidate in state["users"]
                if candidate.get("enabled", True) and candidate["role"] == "admin"
            ]
            if len(enabled_admins) <= 1:
                raise ConflictError("至少需要保留一个启用中的管理员账户")
        user.update(updates)
        user["updated_at"] = isoformat(utc_now())
        if not user.get("enabled", True):
            self._revoke_user_sessions(state, user["id"])
        return self._public_user(user)

    def _reset_password_mutate(self, state, *, user_id: str, password: str) -> dict[str, Any]:
        user = self._find_user_by_id(state, user_id)
        password_hash, password_salt = self._hash_password(password)
        now = isoformat(utc_now())
        user["password_hash"] = password_hash
        user["password_salt"] = password_salt
        user["password_iterations"] = PASSWORD_ITERATIONS
        user["password_updated_at"] = now
        user["updated_at"] = now
        self._revoke_user_sessions(state, user["id"])
        return self._public_user(user)

    def _issue_session(self, state, *, user: dict[str, Any], token: str) -> dict[str, Any]:
        now = utc_now()
        created_at = isoformat(now)
        expires_at = isoformat(now + timedelta(seconds=SESSION_TTL_SECONDS))
        session = {
            "id": _next_numbered_id("sess", state["sessions"]),
            "user_id": user["id"],
            "token_hash": self._hash_token(token),
            "created_at": created_at,
            "last_seen_at": created_at,
            "expires_at": expires_at,
        }
        state["sessions"].insert(0, session)
        state["sessions"] = state["sessions"][:MAX_SESSIONS]
        return session

    def _cleanup_expired_sessions(self, state) -> None:
        now = utc_now()
        state["sessions"] = [
            session
            for session in state["sessions"]
            if (_parse_timestamp(session.get("expires_at")) or now) > now
        ]

    def _revoke_user_sessions(self, state, user_id: str) -> None:
        state["sessions"] = [session for session in state["sessions"] if session["user_id"] != user_id]

    def _build_user(
        self,
        state,
        *,
        username: str,
        password: str,
        role: str,
        enabled: bool,
    ) -> dict[str, Any]:
        self._ensure_username_available(state, username)
        password_hash, password_salt = self._hash_password(password)
        now = isoformat(utc_now())
        return {
            "id": _next_numbered_id("user", state["users"]),
            "username": username,
            "role": role,
            "enabled": enabled,
            "password_hash": password_hash,
            "password_salt": password_salt,
            "password_iterations": PASSWORD_ITERATIONS,
            "created_at": now,
            "updated_at": now,
            "last_login_at": None,
            "password_updated_at": now,
        }

    def _ensure_username_available(self, state, username: str) -> None:
        normalized = username.casefold()
        if any(candidate["username"].casefold() == normalized for candidate in state["users"]):
            raise ConflictError("用户名已存在", {"username": username})

    def _find_user_by_username(self, state, username: str) -> dict[str, Any]:
        normalized = username.casefold()
        for user in state["users"]:
            if user["username"].casefold() == normalized:
                return user
        raise AuthError("用户名或密码错误")

    def _find_user_by_id(self, state, user_id: str) -> dict[str, Any]:
        for user in state["users"]:
            if user["id"] == user_id:
                return user
        raise NotFoundError("user", user_id)

    def _public_user(self, user: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "enabled": user.get("enabled", True),
            "created_at": user.get("created_at"),
            "updated_at": user.get("updated_at"),
            "last_login_at": user.get("last_login_at"),
            "password_updated_at": user.get("password_updated_at"),
        }

    def _public_session(self, session: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": session["id"],
            "created_at": session["created_at"],
            "last_seen_at": session["last_seen_at"],
            "expires_at": session["expires_at"],
        }

    def _normalize_username(self, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError("username 必须是非空字符串")
        username = value.strip()
        if not USERNAME_PATTERN.match(username):
            raise ValidationError("username 仅支持 3-64 位字母、数字、点、下划线、@、-")
        return username

    def _normalize_password(self, value: Any) -> str:
        if not isinstance(value, str) or not value:
            raise ValidationError("密码必须是非空字符串")
        if len(value) < PASSWORD_MIN_LENGTH:
            raise ValidationError(f"密码长度至少需要 {PASSWORD_MIN_LENGTH} 位")
        return value

    def _normalize_role(self, value: Any) -> str:
        if not isinstance(value, str):
            raise ValidationError("role 必须是字符串")
        role = value.strip().lower()
        if role not in ROLE_LEVELS:
            raise ValidationError("role 不受支持", {"allowed": sorted(ROLE_LEVELS)})
        return role

    def has_permission(self, principal: Principal, resource: str, action: str) -> bool:
        result = can_access(
            actor={"role": principal.role, "permissions": list(PERMISSION_SETS.get(principal.role, set()))},
            resource=resource,
            action=action,
        )
        return result.get("allowed", False)

    def _hash_password(self, password: str, salt_hex: str | None = None) -> tuple[str, str]:
        salt = os.urandom(16) if salt_hex is None else bytes.fromhex(salt_hex)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
        return digest.hex(), salt.hex()

    def _verify_password(self, password: str, user: dict[str, Any]) -> bool:
        password_hash, _ = self._hash_password(password, user["password_salt"])
        return hmac.compare_digest(password_hash, user["password_hash"])

    def _hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _generate_token(self) -> str:
        return secrets.token_urlsafe(32)

    def _rate_limit_key(self, client_ip: str | None, username: str) -> tuple[str, str]:
        return ((client_ip or "unknown").strip() or "unknown", username.casefold())

    def _ensure_login_not_rate_limited(self, key: tuple[str, str]) -> None:
        now = utc_now()
        with self._failed_login_lock:
            self._prune_failed_login_state(now)
            state = self._failed_login_state.get(key)
            cooldown_until = state.get("cooldown_until") if state else None
            if cooldown_until and cooldown_until > now:
                retry_after = max(1, int((cooldown_until - now).total_seconds()))
                raise ApiError(
                    "rate_limited",
                    "登录失败次数过多，请 5 分钟后再试",
                    HTTPStatus.TOO_MANY_REQUESTS,
                    {"retry_after_seconds": retry_after},
                )

    def _record_failed_login(self, key: tuple[str, str]) -> None:
        now = utc_now()
        with self._failed_login_lock:
            self._prune_failed_login_state(now)
            state = self._failed_login_state.setdefault(key, {"failures": [], "cooldown_until": None})
            failures = [
                failure_at
                for failure_at in state.get("failures", [])
                if (now - failure_at).total_seconds() <= FAILED_LOGIN_WINDOW_SECONDS
            ]
            failures.append(now)
            state["failures"] = failures
            if len(failures) >= FAILED_LOGIN_LIMIT:
                state["cooldown_until"] = now + timedelta(seconds=FAILED_LOGIN_COOLDOWN_SECONDS)

    def _clear_failed_login(self, key: tuple[str, str]) -> None:
        with self._failed_login_lock:
            self._failed_login_state.pop(key, None)

    def _prune_failed_login_state(self, now: datetime) -> None:
        for key in list(self._failed_login_state):
            state = self._failed_login_state[key]
            failures = [
                failure_at
                for failure_at in state.get("failures", [])
                if (now - failure_at).total_seconds() <= FAILED_LOGIN_WINDOW_SECONDS
            ]
            cooldown_until = state.get("cooldown_until")
            if cooldown_until and cooldown_until <= now:
                cooldown_until = None
            if failures or cooldown_until:
                state["failures"] = failures
                state["cooldown_until"] = cooldown_until
            else:
                self._failed_login_state.pop(key, None)


def require_role(principal: Principal | None, minimum_role: str) -> None:
    if principal is None:
        raise AuthError()
    if ROLE_LEVELS[principal.role] < ROLE_LEVELS[minimum_role]:
        raise ForbiddenError(f"{principal.role} 无法访问该接口，需要 {minimum_role} 权限")


def require_permission(
    principal: Principal | None,
    resource: str,
    action: str,
    *,
    resource_id: str | None = None,
    allowed_groups: set[str] | None = None,
) -> None:
    """Action-based permission check with optional resource-level filtering."""
    if principal is None:
        raise AuthError()
    result = can_access(
        actor={"role": principal.role, "permissions": list(PERMISSION_SETS.get(principal.role, set()))},
        resource=resource,
        action=action,
        resource_id=resource_id,
        allowed_groups=allowed_groups,
    )
    if not result["allowed"]:
        raise ForbiddenError(result.get("reason", "权限不足"))


def can_access(
    actor=None,
    resource: str | None = None,
    action: str | None = None,
    permission: str | None = None,
    resource_id: str | None = None,
    allowed_groups: set[str] | None = None,
):
    """Public permission decision helper with action-based policy."""
    if actor is None:
        return {"allowed": False, "reason": "missing_actor"}
    if isinstance(actor, dict) and "actor" in actor:
        payload = actor
        actor = payload.get("actor")
        resource = payload.get("resource", resource)
        action = payload.get("action", action)
        permission = payload.get("permission", permission)
        resource_id = payload.get("resource_id", resource_id)
        allowed_groups = payload.get("allowed_groups", allowed_groups)

    role = (actor or {}).get("role", "viewer") if isinstance(actor, dict) else "viewer"
    explicit_permissions = set((actor or {}).get("permissions", [])) if isinstance(actor, dict) else set()

    # Admin has full access
    if role == "admin":
        return {"allowed": True, "reason": "admin"}

    # Resolve the requested permission string
    requested_permission = permission or (f"{resource}:{action}" if resource and action else "")
    if not requested_permission:
        return {"allowed": False, "reason": "no_permission_specified"}

    # Exact match or wildcard match
    role_perms = PERMISSION_SETS.get(role, set())
    if requested_permission in explicit_permissions:
        return {"allowed": True, "reason": "explicit_permission"}
    if requested_permission in role_perms:
        return {"allowed": True, "reason": "role_permission"}

    # Check wildcard permissions (e.g. "devices:*" matches "devices:read")
    prefix, _, _ = requested_permission.rpartition(":")
    wildcard = f"{prefix}:*"
    if wildcard in role_perms or wildcard in explicit_permissions:
        return {"allowed": True, "reason": "wildcard_permission"}

    # Check global wildcard
    if "*:*" in role_perms or "*:*" in explicit_permissions:
        return {"allowed": True, "reason": "global_wildcard"}

    # Resource-level group access (for cross-cutting access control)
    if resource_id is not None and allowed_groups is not None:
        if resource_id in allowed_groups:
            return {"allowed": True, "reason": "resource_group_match"}

    # Default deny
    return {"allowed": False, "reason": f"default_deny:{role}"}

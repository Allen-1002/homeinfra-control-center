"""SQLite-backed state store for HomeInfra with normalized relational tables."""

from __future__ import annotations

import json
import sqlite3
from copy import deepcopy
from pathlib import Path
from threading import RLock
from typing import Any, Callable
from uuid import uuid4

from .mock_data import build_empty_state, build_initial_state

STATE_KEYS = (
    "started_at",
    "audit_logs",
    "users",
    "sessions",
    "retention_settings",
    "collection_settings",
    "metrics",
    "device_groups",
    "devices",
    "collection_records",
    "alerts",
)

DDL_STATEMENTS = [
    # Device groups
    """
    CREATE TABLE IF NOT EXISTS device_groups (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        color TEXT NOT NULL DEFAULT '#7da38f',
        icon TEXT NOT NULL DEFAULT 'server',
        sort_order INTEGER NOT NULL DEFAULT 100,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    # Devices
    """
    CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL DEFAULT 22,
        username TEXT NOT NULL DEFAULT 'monitor',
        auth_type TEXT NOT NULL DEFAULT 'none',
        password TEXT,
        private_key_path TEXT,
        encrypted_private_key TEXT,
        device_type TEXT NOT NULL DEFAULT 'other',
        group_id TEXT NOT NULL,
        tags TEXT NOT NULL DEFAULT '[]',
        enabled INTEGER NOT NULL DEFAULT 1,
        poll_interval INTEGER NOT NULL DEFAULT 60,
        verified INTEGER NOT NULL DEFAULT 0,
        last_seen TEXT,
        status TEXT NOT NULL DEFAULT 'unknown',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (group_id) REFERENCES device_groups(id)
    )
    """,
    # Collection records
    """
    CREATE TABLE IF NOT EXISTS collection_records (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        group_id TEXT,
        device_name TEXT,
        collector TEXT NOT NULL DEFAULT '',
        command TEXT NOT NULL DEFAULT '',
        collected_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'healthy',
        summary TEXT NOT NULL DEFAULT '',
        payload TEXT NOT NULL DEFAULT '{}',
        error_message TEXT,
        purpose TEXT,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    )
    """,
    # Alerts
    """
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        group_id TEXT,
        severity TEXT NOT NULL DEFAULT 'warning',
        status TEXT NOT NULL DEFAULT 'active',
        type TEXT NOT NULL DEFAULT '',
        code TEXT NOT NULL DEFAULT '',
        title TEXT NOT NULL DEFAULT '',
        message TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        resolved_at TEXT,
        resolved_by TEXT,
        last_record_id TEXT,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
    )
    """,
    # Users
    """
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL DEFAULT 'viewer',
        enabled INTEGER NOT NULL DEFAULT 1,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        password_iterations INTEGER NOT NULL DEFAULT 240000,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_login_at TEXT,
        password_updated_at TEXT
    )
    """,
    # Sessions
    """
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """,
    # Audit logs
    """
    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        actor TEXT NOT NULL,
        role TEXT NOT NULL,
        action TEXT NOT NULL,
        resource TEXT NOT NULL,
        outcome TEXT NOT NULL,
        request_id TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT '{}'
    )
    """,
    # Key-value store (retention, metrics, collection settings, etc.)
    """
    CREATE TABLE IF NOT EXISTS app_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    # Indexes
    "CREATE INDEX IF NOT EXISTS idx_devices_group_id ON devices(group_id)",
    "CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status)",
    "CREATE INDEX IF NOT EXISTS idx_devices_device_type ON devices(device_type)",
    "CREATE INDEX IF NOT EXISTS idx_collections_device_id ON collection_records(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_collections_collected_at ON collection_records(collected_at)",
    "CREATE INDEX IF NOT EXISTS idx_collections_status ON collection_records(status)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_device_id ON alerts(device_id)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor)",
    "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash)",
]


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return dict(row)


def rows_to_list(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


class SQLiteStore:
    """Normalized SQLite store with relational tables and query optimisation."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._uri = False
        self._keepalive: sqlite3.Connection | None = None
        if db_path is None:
            self.db_path = f"file:homeinfra_mem_{uuid4().hex}?mode=memory&cache=shared"
            self._uri = True
            self._keepalive = sqlite3.connect(
                self.db_path,
                uri=True,
                timeout=5.0,
                check_same_thread=False,
            )
            self._keepalive.row_factory = sqlite3.Row
        else:
            self.db_path = str(db_path)
        if not self._uri:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.db_path,
            timeout=5.0,
            check_same_thread=False,
            uri=self._uri,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                for statement in DDL_STATEMENTS:
                    conn.execute(statement)
                conn.commit()

                # Check if legacy app_state table exists (Phase 1 format)
                legacy = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='app_state'"
                ).fetchone()
                if legacy:
                    self._migrate_from_legacy(conn)
                else:
                    # Seed empty config if not present
                    self._seed_config(conn)
                self._ensure_devices_schema(conn)
                conn.commit()
            finally:
                conn.close()

    def _ensure_devices_schema(self, conn: sqlite3.Connection) -> None:
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(devices)").fetchall()
        }
        if "verified" not in columns:
            conn.execute("ALTER TABLE devices ADD COLUMN verified INTEGER NOT NULL DEFAULT 0")

    def _migrate_from_legacy(self, conn: sqlite3.Connection) -> None:
        """Migrate from Phase 1 single app_state JSON table to normalized tables."""
        rows = conn.execute("SELECT key, value FROM app_state").fetchall()
        state = build_empty_state()
        for row in rows:
            key = row["key"]
            try:
                state[key] = json.loads(row["value"])
            except (json.JSONDecodeError, TypeError):
                state[key] = {}

        # Write config values
        config_keys = {
            "started_at",
            "retention_settings", "collection_settings", "metrics",
        }
        for key in config_keys:
            conn.execute(
                "INSERT OR REPLACE INTO app_config(key, value) VALUES(?, ?)",
                (key, json.dumps(state.get(key, {}), ensure_ascii=True)),
            )

        # Write device_groups
        for group in state.get("device_groups", []):
            conn.execute(
                """INSERT OR REPLACE INTO device_groups(id, name, description, color, icon, sort_order, created_at, updated_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    group["id"], group["name"], group.get("description", ""),
                    group.get("color", "#7da38f"), group.get("icon", "server"),
                    group.get("sort_order", 100), group.get("created_at", ""),
                    group.get("updated_at", ""),
                ),
            )

        # Write devices
        for device in state.get("devices", []):
            conn.execute(
                """INSERT OR REPLACE INTO devices(id, name, host, port, username, auth_type, password,
                   private_key_path, encrypted_private_key, device_type, group_id, tags, enabled,
                   poll_interval, verified, last_seen, status, created_at, updated_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    device["id"], device["name"], device.get("host", ""),
                    device.get("port", 22), device.get("username", "monitor"),
                    device.get("auth_type", "none"), device.get("password"),
                    device.get("private_key_path"), device.get("encrypted_private_key"),
                    device.get("device_type", "other"), device.get("group_id", ""),
                    json.dumps(device.get("tags", []), ensure_ascii=True),
                    1 if device.get("enabled", True) else 0,
                    device.get("collection_interval", device.get("poll_interval", 60)),
                    1 if device.get("verified", False) else 0,
                    device.get("last_seen"),
                    device.get("status", "unknown"), device.get("created_at", ""),
                    device.get("updated_at", ""),
                ),
            )

        # Write collection_records
        for record in state.get("collection_records", []):
            conn.execute(
                """INSERT OR REPLACE INTO collection_records(id, device_id, group_id, device_name,
                   collector, command, collected_at, status, summary, payload, error_message, purpose)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record["id"], record.get("device_id", ""), record.get("group_id"),
                    record.get("device_name"), record.get("collector", ""),
                    record.get("command", ""), record.get("collected_at", ""),
                    record.get("status", "healthy"), record.get("summary", ""),
                    json.dumps(record.get("payload", {}), ensure_ascii=True),
                    record.get("error_message"), record.get("purpose"),
                ),
            )

        # Write alerts
        for alert in state.get("alerts", []):
            conn.execute(
                """INSERT OR REPLACE INTO alerts(id, device_id, group_id, severity, status, type, code,
                   title, message, created_at, updated_at, resolved_at, resolved_by, last_record_id)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert["id"], alert.get("device_id", ""), alert.get("group_id"),
                    alert.get("severity", "warning"), alert.get("status", "active"),
                    alert.get("type", ""), alert.get("code", ""),
                    alert.get("title", ""), alert.get("message", ""),
                    alert.get("created_at", ""), alert.get("updated_at", ""),
                    alert.get("resolved_at"), alert.get("resolved_by"),
                    alert.get("last_record_id"),
                ),
            )

        # Write users
        for user in state.get("users", []):
            conn.execute(
                """INSERT OR REPLACE INTO users(id, username, role, enabled, password_hash,
                   password_salt, password_iterations, created_at, updated_at,
                   last_login_at, password_updated_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    user["id"], user["username"], user.get("role", "viewer"),
                    1 if user.get("enabled", True) else 0,
                    user.get("password_hash", ""), user.get("password_salt", ""),
                    user.get("password_iterations", 240000),
                    user.get("created_at", ""), user.get("updated_at", ""),
                    user.get("last_login_at"), user.get("password_updated_at", ""),
                ),
            )

        # Write sessions
        for session in state.get("sessions", []):
            conn.execute(
                """INSERT OR REPLACE INTO sessions(id, user_id, token_hash, created_at, last_seen_at, expires_at)
                   VALUES(?, ?, ?, ?, ?, ?)""",
                (
                    session["id"], session.get("user_id", ""), session.get("token_hash", ""),
                    session.get("created_at", ""), session.get("last_seen_at", ""),
                    session.get("expires_at", ""),
                ),
            )

        # Write audit_logs
        for entry in state.get("audit_logs", []):
            conn.execute(
                """INSERT OR REPLACE INTO audit_logs(id, timestamp, actor, role, action, resource,
                   outcome, request_id, details)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    entry.get("id", ""), entry.get("timestamp", ""), entry.get("actor", ""),
                    entry.get("role", ""), entry.get("action", ""), entry.get("resource", ""),
                    entry.get("outcome", ""), entry.get("request_id", ""),
                    json.dumps(entry.get("details", {}), ensure_ascii=True),
                ),
            )

        # Drop legacy table after migration
        conn.execute("DROP TABLE IF EXISTS app_state")

    def _seed_config(self, conn: sqlite3.Connection) -> None:
        existing = {
            row["key"] for row in conn.execute("SELECT key FROM app_config").fetchall()
        }
        seed = build_empty_state()
        config_keys = {
            "started_at",
            "retention_settings", "collection_settings", "metrics",
        }
        for key in config_keys:
            if key not in existing:
                conn.execute(
                    "INSERT INTO app_config(key, value) VALUES(?, ?)",
                    (key, json.dumps(seed.get(key, {}), ensure_ascii=True)),
                )

        # Ensure ungrouped group exists
        existing_groups = conn.execute("SELECT id FROM device_groups WHERE id = ?", ("grp-ungrouped",)).fetchone()
        if not existing_groups:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            conn.execute(
                """INSERT OR IGNORE INTO device_groups(id, name, description, color, icon, sort_order, created_at, updated_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?)""",
                ("grp-ungrouped", "未分组", "尚未归类的设备", "#94a3b8", "folder", 999, now, now),
            )

    # ── Legacy-compatible snapshot (for code that still uses snapshot()) ──

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            conn = self._connect()
            try:
                state = build_empty_state()

                config_rows = conn.execute("SELECT key, value FROM app_config").fetchall()
                for row in config_rows:
                    key = row["key"]
                    try:
                        state[key] = json.loads(row["value"])
                    except (json.JSONDecodeError, TypeError):
                        state[key] = {}

                state["device_groups"] = rows_to_list(
                    conn.execute("SELECT * FROM device_groups ORDER BY sort_order, name").fetchall()
                )

                device_rows = conn.execute("SELECT * FROM devices ORDER BY name").fetchall()
                converted_devices = []
                for d in device_rows:
                    d = dict(d)
                    d["tags"] = json.loads(d.get("tags", "[]"))
                    d["enabled"] = bool(d.get("enabled", 1))
                    d["verified"] = bool(d.get("verified", 0))
                    d["collection_interval"] = d.get("collection_interval", d.get("poll_interval", 60))
                    converted_devices.append(d)
                state["devices"] = converted_devices

                collection_rows = conn.execute(
                    "SELECT * FROM collection_records ORDER BY collected_at DESC, id DESC LIMIT 5000"
                ).fetchall()
                converted_collections = []
                for r in collection_rows:
                    r = dict(r)
                    try:
                        r["payload"] = json.loads(r.get("payload", "{}"))
                    except (json.JSONDecodeError, TypeError):
                        r["payload"] = {}
                    converted_collections.append(r)
                state["collection_records"] = converted_collections

                alert_rows = conn.execute(
                    "SELECT * FROM alerts ORDER BY created_at DESC"
                ).fetchall()
                state["alerts"] = [dict(row) for row in alert_rows]

                state["users"] = rows_to_list(
                    conn.execute("SELECT * FROM users ORDER BY username").fetchall()
                )

                state["sessions"] = rows_to_list(
                    conn.execute("SELECT * FROM sessions").fetchall()
                )

                state["audit_logs"] = rows_to_list(
                    conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 5000").fetchall()
                )
                for entry in state["audit_logs"]:
                    details = entry.get("details", "{}")
                    try:
                        entry["details"] = json.loads(details) if isinstance(details, str) else details
                    except (json.JSONDecodeError, TypeError):
                        entry["details"] = {}

                return deepcopy(state)
            finally:
                conn.close()

    # ── Single-key read ──

    def read(self, key: str) -> Any:
        with self._lock:
            conn = self._connect()
            try:
                if key in {"retention_settings", "collection_settings", "metrics", "started_at"}:
                    row = conn.execute(
                        "SELECT value FROM app_config WHERE key = ?", (key,)
                    ).fetchone()
                    if row is None:
                        raise KeyError(key)
                    return deepcopy(json.loads(row["value"]))
                if key == "device_groups":
                    return rows_to_list(
                        conn.execute("SELECT * FROM device_groups ORDER BY sort_order, name").fetchall()
                    )
                if key == "devices":
                    rows = rows_to_list(
                        conn.execute("SELECT * FROM devices ORDER BY name").fetchall()
                    )
                    for d in rows:
                        d["tags"] = json.loads(d.get("tags", "[]"))
                        d["enabled"] = bool(d.get("enabled", 1))
                        d["verified"] = bool(d.get("verified", 0))
                        d["collection_interval"] = d.get("collection_interval", d.get("poll_interval", 60))
                    return rows
                if key == "collection_records":
                    rows = rows_to_list(
                        conn.execute(
                            "SELECT * FROM collection_records ORDER BY collected_at DESC, id DESC LIMIT 5000"
                        ).fetchall()
                    )
                    for r in rows:
                        try:
                            r["payload"] = json.loads(r.get("payload", "{}"))
                        except (json.JSONDecodeError, TypeError):
                            r["payload"] = {}
                    return rows
                if key == "alerts":
                    return rows_to_list(
                        conn.execute("SELECT * FROM alerts ORDER BY created_at DESC").fetchall()
                    )
                if key == "users":
                    return rows_to_list(
                        conn.execute("SELECT * FROM users ORDER BY username").fetchall()
                    )
                if key == "sessions":
                    return rows_to_list(
                        conn.execute("SELECT * FROM sessions").fetchall()
                    )
                if key == "audit_logs":
                    rows = rows_to_list(
                        conn.execute(
                            "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 5000"
                        ).fetchall()
                    )
                    for entry in rows:
                        details = entry.get("details", "{}")
                        try:
                            entry["details"] = json.loads(details) if isinstance(details, str) else details
                        except (json.JSONDecodeError, TypeError):
                            entry["details"] = {}
                    return rows
                raise KeyError(key)
            finally:
                conn.close()

    # ── Transactional update ──

    def update(self, mutator: Callable[[dict[str, Any]], Any]) -> Any:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                state = self._build_state_from_tables(conn)
                result = mutator(state)
                self._persist_state_to_tables(conn, state)
                conn.commit()
                return deepcopy(result)
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def _build_state_from_tables(self, conn: sqlite3.Connection) -> dict[str, Any]:
        state = build_empty_state()

        config_rows = conn.execute("SELECT key, value FROM app_config").fetchall()
        for row in config_rows:
            try:
                state[row["key"]] = json.loads(row["value"])
            except (json.JSONDecodeError, TypeError):
                state[row["key"]] = {}

        state["device_groups"] = rows_to_list(
            conn.execute("SELECT * FROM device_groups ORDER BY sort_order, name").fetchall()
        )

        device_rows = rows_to_list(
            conn.execute("SELECT * FROM devices ORDER BY name").fetchall()
        )
        for d in device_rows:
            d["tags"] = json.loads(d.get("tags", "[]"))
            d["enabled"] = bool(d.get("enabled", 1))
            d["verified"] = bool(d.get("verified", 0))
            d["collection_interval"] = d.get("collection_interval", d.get("poll_interval", 60))
        state["devices"] = device_rows

        collection_rows = rows_to_list(
            conn.execute(
                "SELECT * FROM collection_records ORDER BY collected_at DESC, id DESC LIMIT 5000"
            ).fetchall()
        )
        for r in collection_rows:
            try:
                r["payload"] = json.loads(r.get("payload", "{}"))
            except (json.JSONDecodeError, TypeError):
                r["payload"] = {}
        state["collection_records"] = collection_rows

        state["alerts"] = rows_to_list(
            conn.execute("SELECT * FROM alerts ORDER BY created_at DESC").fetchall()
        )

        state["users"] = rows_to_list(
            conn.execute("SELECT * FROM users ORDER BY username").fetchall()
        )

        state["sessions"] = rows_to_list(
            conn.execute("SELECT * FROM sessions").fetchall()
        )

        state["audit_logs"] = rows_to_list(
            conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 5000").fetchall()
        )
        for entry in state["audit_logs"]:
            details = entry.get("details", "{}")
            try:
                entry["details"] = json.loads(details) if isinstance(details, str) else details
            except (json.JSONDecodeError, TypeError):
                entry["details"] = {}

        return state

    def _persist_state_to_tables(self, conn: sqlite3.Connection, state: dict[str, Any]) -> None:
        # Delete all tables (child before parent for FK constraints)
        conn.execute("DELETE FROM collection_records")
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM audit_logs")
        conn.execute("DELETE FROM devices")
        conn.execute("DELETE FROM device_groups")
        conn.execute("DELETE FROM users")

        # Config key-values
        config_keys = {
            "started_at",
            "retention_settings", "collection_settings", "metrics",
        }
        for key in config_keys:
            value = state.get(key, {})
            conn.execute(
                "INSERT OR REPLACE INTO app_config(key, value) VALUES(?, ?)",
                (key, json.dumps(value, ensure_ascii=True)),
            )

        # Device groups (parent of devices — insert first)
        for g in state.get("device_groups", []):
            conn.execute(
                """INSERT OR REPLACE INTO device_groups(id, name, description, color, icon, sort_order, created_at, updated_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?)""",
                (g["id"], g["name"], g.get("description", ""), g.get("color", "#7da38f"),
                 g.get("icon", "server"), g.get("sort_order", 100), g.get("created_at", ""),
                 g.get("updated_at", "")),
            )

        # Devices (child of device_groups)
        for d in state.get("devices", []):
            conn.execute(
                """INSERT OR REPLACE INTO devices(id, name, host, port, username, auth_type, password,
                   private_key_path, encrypted_private_key, device_type, group_id, tags, enabled,
                   poll_interval, verified, last_seen, status, created_at, updated_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (d["id"], d["name"], d.get("host", ""), d.get("port", 22),
                 d.get("username", "monitor"), d.get("auth_type", "none"),
                 d.get("password"), d.get("private_key_path"), d.get("encrypted_private_key"),
                 d.get("device_type", "other"), d.get("group_id", ""),
                 json.dumps(d.get("tags", []), ensure_ascii=True),
                 1 if d.get("enabled", True) else 0,
                 d.get("collection_interval", d.get("poll_interval", 60)),
                 1 if d.get("verified", False) else 0,
                 d.get("last_seen"), d.get("status", "unknown"),
                 d.get("created_at", ""), d.get("updated_at", "")),
            )

        # Users (parent of sessions)
        for u in state.get("users", []):
            conn.execute(
                """INSERT OR REPLACE INTO users(id, username, role, enabled, password_hash,
                   password_salt, password_iterations, created_at, updated_at,
                   last_login_at, password_updated_at)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (u["id"], u["username"], u.get("role", "viewer"),
                 1 if u.get("enabled", True) else 0,
                 u.get("password_hash", ""), u.get("password_salt", ""),
                 u.get("password_iterations", 240000),
                 u.get("created_at", ""), u.get("updated_at", ""),
                 u.get("last_login_at"), u.get("password_updated_at", "")),
            )

        # Re-insert collection records, alerts, sessions, audit logs
        for r in state.get("collection_records", []):
            conn.execute(
                """INSERT OR REPLACE INTO collection_records(id, device_id, group_id, device_name,
                   collector, command, collected_at, status, summary, payload, error_message, purpose)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (r["id"], r.get("device_id", ""), r.get("group_id"), r.get("device_name"),
                 r.get("collector", ""), r.get("command", ""), r.get("collected_at", ""),
                 r.get("status", "healthy"), r.get("summary", ""),
                 json.dumps(r.get("payload", {}), ensure_ascii=True),
                 r.get("error_message"), r.get("purpose")),
            )

        for a in state.get("alerts", []):
            conn.execute(
                """INSERT OR REPLACE INTO alerts(id, device_id, group_id, severity, status, type, code,
                   title, message, created_at, updated_at, resolved_at, resolved_by, last_record_id)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (a["id"], a.get("device_id", ""), a.get("group_id"),
                 a.get("severity", "warning"), a.get("status", "active"),
                 a.get("type", ""), a.get("code", ""),
                 a.get("title", ""), a.get("message", ""),
                 a.get("created_at", ""), a.get("updated_at", ""),
                 a.get("resolved_at"), a.get("resolved_by"),
                 a.get("last_record_id")),
            )

        for s in state.get("sessions", []):
            conn.execute(
                """INSERT OR REPLACE INTO sessions(id, user_id, token_hash, created_at, last_seen_at, expires_at)
                   VALUES(?, ?, ?, ?, ?, ?)""",
                (s["id"], s.get("user_id", ""), s.get("token_hash", ""),
                 s.get("created_at", ""), s.get("last_seen_at", ""),
                 s.get("expires_at", "")),
            )

        for entry in state.get("audit_logs", []):
            conn.execute(
                """INSERT OR REPLACE INTO audit_logs(id, timestamp, actor, role, action, resource,
                   outcome, request_id, details)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (entry.get("id", ""), entry.get("timestamp", ""), entry.get("actor", ""),
                 entry.get("role", ""), entry.get("action", ""), entry.get("resource", ""),
                 entry.get("outcome", ""), entry.get("request_id", ""),
                 json.dumps(entry.get("details", {}), ensure_ascii=True)),
            )

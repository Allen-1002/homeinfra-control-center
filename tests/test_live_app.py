import http.client
import json
import threading
import unittest
from http import HTTPStatus

from homeinfra.app import HomeInfraApp, build_security_headers, create_server
from homeinfra.collector_service import CollectorService
from homeinfra.collectors import MockCommandCollector
from homeinfra.errors import ApiError


EXPECTED_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "base-uri 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)


class LiveAppRouteTests(unittest.TestCase):
    def setUp(self):
        self.app = HomeInfraApp(
            static_dir="static",
            collector_mode="ssh",
            collector_service_override=CollectorService(
                MockCommandCollector(),
                sample_interval=0.0,
                data_source="ssh",
                is_real_data=True,
            ),
        )

    def auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def request(self, method: str, path: str, *, headers=None, body=None, query=None, client_ip=None):
        return self.app.handle_api_request(
            method=method,
            path=path,
            headers=headers or {},
            body=body or {},
            query=query or {},
            client_ip=client_ip,
        )

    def bootstrap(self) -> str:
        result, _request_id = self.request(
            "POST",
            "/api/v1/auth/bootstrap",
            headers={},
            body={"username": "admin", "password": "ExampleAdminPass123"},
        )
        return result["token"]

    def test_first_startup_requires_bootstrap(self):
        status, _request_id = self.request("GET", "/api/v1/auth/bootstrap", headers={})
        self.assertTrue(status["required"])

        with self.assertRaises(ApiError) as ctx:
            self.request("GET", "/api/v1/dashboard", headers={})
        self.assertEqual(ctx.exception.code, "auth_required")

    def test_bootstrap_then_login_and_me(self):
        bootstrap_token = self.bootstrap()
        me, _request_id = self.request("GET", "/api/v1/auth/me", headers=self.auth_headers(bootstrap_token))
        self.assertEqual(me["username"], "admin")
        self.assertEqual(me["role"], "admin")

        self.request("POST", "/api/v1/auth/logout", headers=self.auth_headers(bootstrap_token), body={})
        login, _request_id = self.request(
            "POST",
            "/api/v1/auth/login",
            headers={},
            body={"username": "admin", "password": "ExampleAdminPass123"},
        )
        self.assertIn("token", login)
        self.assertEqual(login["user"]["username"], "admin")

    def test_disabling_user_invalidates_existing_session(self):
        admin_token = self.bootstrap()
        created, _request_id = self.request(
            "POST",
            "/api/v1/users",
            headers=self.auth_headers(admin_token),
            body={"username": "operator", "password": "ExampleOperatorPass123", "role": "operator"},
        )
        login, _request_id = self.request(
            "POST",
            "/api/v1/auth/login",
            headers={},
            body={"username": "operator", "password": "ExampleOperatorPass123"},
        )

        self.request("PATCH", f"/api/v1/users/{created['id']}", headers=self.auth_headers(admin_token), body={"enabled": False})

        with self.assertRaises(ApiError) as ctx:
            self.request("GET", "/api/v1/auth/me", headers=self.auth_headers(login["token"]))
        self.assertEqual(ctx.exception.code, "auth_required")

    def test_login_rate_limit_returns_429_during_cooldown(self):
        self.bootstrap()
        client_ip = "198.51.100.10"
        for _ in range(5):
            with self.assertRaises(ApiError) as ctx:
                self.request(
                    "POST",
                    "/api/v1/auth/login",
                    headers={},
                    body={"username": "admin", "password": "WrongPassword123"},
                    client_ip=client_ip,
                )
            self.assertEqual(ctx.exception.code, "auth_required")

        with self.assertRaises(ApiError) as ctx:
            self.request(
                "POST",
                "/api/v1/auth/login",
                headers={},
                body={"username": "admin", "password": "ExampleAdminPass123"},
                client_ip=client_ip,
            )
        self.assertEqual(ctx.exception.code, "rate_limited")
        self.assertEqual(ctx.exception.status, 429)
        self.assertGreaterEqual(ctx.exception.details.get("retry_after_seconds", 0), 1)

    def test_successful_login_clears_failed_rate_limit_state(self):
        self.bootstrap()
        client_ip = "198.51.100.11"
        for _ in range(4):
            with self.assertRaises(ApiError) as ctx:
                self.request(
                    "POST",
                    "/api/v1/auth/login",
                    headers={},
                    body={"username": "admin", "password": "WrongPassword123"},
                    client_ip=client_ip,
                )
            self.assertEqual(ctx.exception.code, "auth_required")

        login, _request_id = self.request(
            "POST",
            "/api/v1/auth/login",
            headers={},
            body={"username": "admin", "password": "ExampleAdminPass123"},
            client_ip=client_ip,
        )
        self.assertEqual(login["user"]["username"], "admin")

        for _ in range(5):
            with self.assertRaises(ApiError) as ctx:
                self.request(
                    "POST",
                    "/api/v1/auth/login",
                    headers={},
                    body={"username": "admin", "password": "WrongPassword123"},
                    client_ip=client_ip,
                )
            self.assertEqual(ctx.exception.code, "auth_required")

        with self.assertRaises(ApiError) as ctx:
            self.request(
                "POST",
                "/api/v1/auth/login",
                headers={},
                body={"username": "admin", "password": "ExampleAdminPass123"},
                client_ip=client_ip,
            )
        self.assertEqual(ctx.exception.code, "rate_limited")

    def test_cleanup_preserves_active_alerts_and_writes_audit_log(self):
        admin_token = self.bootstrap()
        self.request("POST", "/api/v1/device-groups", headers=self.auth_headers(admin_token), body={"name": "NAS", "id": "grp-nas"})
        self.request(
            "POST",
            "/api/v1/devices",
            headers=self.auth_headers(admin_token),
            body={
                "id": "dev-nas-01",
                "name": "Test NAS",
                "host": "192.0.2.20",
                "device_type": "nas",
                "group_id": "grp-nas",
            },
        )
        self.request("POST", "/api/v1/devices/dev-nas-01/refresh", headers=self.auth_headers(admin_token), body={"timeout": 5})
        self.request(
            "PATCH",
            "/api/v1/settings/retention",
            headers=self.auth_headers(admin_token),
            body={
                "collection_history_days": 1,
                "audit_log_days": 1,
                "resolved_alert_days": 1,
            },
        )
        result, _request_id = self.request(
            "POST",
            "/api/v1/settings/retention/cleanup",
            headers=self.auth_headers(admin_token),
            body={},
        )
        self.assertGreaterEqual(result["active_alerts_preserved"], 0)

        audit, _request_id = self.request("GET", "/api/v1/audit", headers=self.auth_headers(admin_token), query={"limit": ["20"]})
        self.assertTrue(any(entry["action"] == "retention.cleanup" for entry in audit["entries"]))


class ResponseSecurityHeaderTests(unittest.TestCase):
    def setUp(self):
        self.app = HomeInfraApp(
            static_dir="static",
            collector_mode="ssh",
            collector_service_override=CollectorService(
                MockCommandCollector(),
                sample_interval=0.0,
                data_source="ssh",
                is_real_data=True,
            ),
        )

    def bootstrap(self) -> str:
        result, _request_id = self.app.handle_api_request(
            method="POST",
            path="/api/v1/auth/bootstrap",
            headers={},
            body={"username": "admin", "password": "ExampleAdminPass123"},
            query={},
        )
        return result["token"]

    def assert_security_headers(self, headers):
        self.assertEqual(
            headers["Content-Security-Policy"],
            (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "base-uri 'self'; "
                "frame-ancestors 'none'; "
                "object-src 'none'"
            ),
        )
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["Cache-Control"], "no-store, max-age=0")

    def test_security_headers_builder_covers_json_and_static_responses(self):
        self.assert_security_headers(build_security_headers())

    def test_429_response_includes_retry_after_header(self):
        self.bootstrap()
        client_ip = "198.51.100.99"
        for _ in range(5):
            with self.assertRaises(ApiError):
                self.app.handle_api_request(
                    method="POST",
                    path="/api/v1/auth/login",
                    headers={},
                    body={"username": "admin", "password": "WrongPassword123"},
                    query={},
                    client_ip=client_ip,
                )

        with self.assertRaises(ApiError) as ctx:
            self.app.handle_api_request(
                method="POST",
                path="/api/v1/auth/login",
                headers={},
                body={"username": "admin", "password": "ExampleAdminPass123"},
                query={},
                client_ip=client_ip,
            )
        self.assertEqual(ctx.exception.code, "rate_limited")
        headers = build_security_headers(retry_after=ctx.exception.details["retry_after_seconds"])
        self.assertGreaterEqual(int(headers["Retry-After"]), 1)
        self.assert_security_headers(headers)

    def test_http_request_metrics_increment_once_per_request(self):
        before = self.app.store.read("metrics")["requests_total"]
        self.app.handle_api_request(
            method="GET",
            path="/api/v1/health/live",
            headers={},
            query={},
        )
        after = self.app.store.read("metrics")["requests_total"]
        self.assertEqual(after - before, 1)

    def test_audit_payload_strips_all_sensitive_keys_including_token_hash(self):
        payload = {
            "username": "admin",
            "password": "ssh-secret",
            "new_password": "rotated-secret",
            "password_hash": "deadbeef",
            "password_salt": "salty",
            "authorization": "Bearer abc",
            "token": "raw-token",
            "token_hash": "tokhash-123",
            "private_key_path": "/keys/id",
            "key_path": "/keys/id",
            "inline_private_key": "INLINE",
            "encrypted_private_key": "LEGACY",
            "device": {
                "id": "dev-1",
                "token_hash": "nested-tokhash",
                "password": "nested-secret",
            },
            "tags": ["keep", "this"],
        }
        sanitized = self.app.safe_audit_payload(payload)
        for key in (
            "password",
            "new_password",
            "password_hash",
            "password_salt",
            "authorization",
            "token",
            "token_hash",
            "private_key_path",
            "key_path",
            "inline_private_key",
            "encrypted_private_key",
        ):
            self.assertNotIn(key, sanitized, f"leaked top-level key: {key}")
        self.assertEqual(sanitized["username"], "admin")
        self.assertEqual(sanitized["tags"], ["keep", "this"])
        nested = sanitized["device"]
        self.assertEqual(nested["id"], "dev-1")
        self.assertNotIn("token_hash", nested)
        self.assertNotIn("password", nested)


class RealHttpSecurityHeaderTests(unittest.TestCase):
    """Verify security headers are emitted on real HTTP responses, not just by
    the in-process builder. Exercises the live ``create_server`` socket layer
    for JSON, static and 429 responses."""

    @classmethod
    def setUpClass(cls):
        cls.server = create_server(
            "127.0.0.1",
            0,
            static_dir="static",
            collector_mode="ssh",
            collector_service_override=CollectorService(
                MockCommandCollector(),
                sample_interval=0.0,
                data_source="ssh",
                is_real_data=True,
            ),
        )
        cls.port = cls.server.server_address[1]
        cls._serve_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls._serve_thread.start()
        # Bootstrap an admin once so the 429 login test can target a real user.
        resp, body = cls._request_raw(
            "POST",
            "/api/v1/auth/bootstrap",
            body=json.dumps({"username": "admin", "password": "ExampleAdminPass123"}),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status == HTTPStatus.OK, body

    @classmethod
    def tearDownClass(cls):
        cls.server.scheduler.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls._serve_thread.join(timeout=5)

    @classmethod
    def _request_raw(cls, method, path, *, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return resp, data
        finally:
            conn.close()

    def _assert_security_headers(self, resp):
        self.assertEqual(resp.getheader("Content-Security-Policy"), EXPECTED_CSP)
        self.assertEqual(resp.getheader("X-Frame-Options"), "DENY")
        self.assertEqual(resp.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.getheader("Referrer-Policy"), "no-referrer")
        self.assertEqual(resp.getheader("Cache-Control"), "no-store, max-age=0")

    def test_json_api_response_has_security_headers(self):
        resp, data = self._request_raw("GET", "/api/v1/health/live")
        self.assertEqual(resp.status, HTTPStatus.OK)
        self.assertEqual(resp.getheader("Content-Type"), "application/json; charset=utf-8")
        self._assert_security_headers(resp)
        self.assertIn("data", json.loads(data))

    def test_static_file_response_has_security_headers(self):
        resp, _data = self._request_raw("GET", "/")
        self.assertEqual(resp.status, HTTPStatus.OK)
        self.assertEqual(resp.getheader("Content-Type"), "text/html")
        self._assert_security_headers(resp)

    def test_429_response_has_retry_after_and_security_headers(self):
        headers = {"Content-Type": "application/json"}
        bad = json.dumps({"username": "admin", "password": "WrongPassword123"})
        for _ in range(5):
            resp, _body = self._request_raw("POST", "/api/v1/auth/login", body=bad, headers=headers)
            self.assertEqual(resp.status, HTTPStatus.UNAUTHORIZED)

        resp, body = self._request_raw("POST", "/api/v1/auth/login", body=bad, headers=headers)
        self.assertEqual(resp.status, HTTPStatus.TOO_MANY_REQUESTS)
        retry_after = resp.getheader("Retry-After")
        self.assertIsNotNone(retry_after)
        self.assertGreaterEqual(int(retry_after), 1)
        self._assert_security_headers(resp)
        envelope = json.loads(body)
        self.assertEqual(envelope["error"]["code"], "rate_limited")

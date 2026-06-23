import unittest

from homeinfra.app import HomeInfraApp
from homeinfra.collector_service import CollectorService
from homeinfra.collectors import MockCommandCollector
from homeinfra.errors import ApiError


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

    def bootstrap(self) -> str:
        result, _request_id = self.app.handle_api_request(
            method="POST",
            path="/api/v1/auth/bootstrap",
            headers={},
            body={"username": "admin", "password": "ExampleAdminPass123"},
        )
        return result["token"]

    def test_first_startup_requires_bootstrap(self):
        status, _request_id = self.app.handle_api_request(
            method="GET",
            path="/api/v1/auth/bootstrap",
            headers={},
        )
        self.assertTrue(status["required"])

        with self.assertRaises(ApiError) as ctx:
            self.app.handle_api_request(
                method="GET",
                path="/api/v1/dashboard",
                headers={},
            )
        self.assertEqual(ctx.exception.code, "auth_required")

    def test_bootstrap_then_login_and_me(self):
        bootstrap_token = self.bootstrap()
        me, _request_id = self.app.handle_api_request(
            method="GET",
            path="/api/v1/auth/me",
            headers=self.auth_headers(bootstrap_token),
        )
        self.assertEqual(me["username"], "admin")
        self.assertEqual(me["role"], "admin")

        self.app.handle_api_request(
            method="POST",
            path="/api/v1/auth/logout",
            headers=self.auth_headers(bootstrap_token),
            body={},
        )
        login, _request_id = self.app.handle_api_request(
            method="POST",
            path="/api/v1/auth/login",
            headers={},
            body={"username": "admin", "password": "ExampleAdminPass123"},
        )
        self.assertIn("token", login)
        self.assertEqual(login["user"]["username"], "admin")

    def test_disabling_user_invalidates_existing_session(self):
        admin_token = self.bootstrap()
        created, _request_id = self.app.handle_api_request(
            method="POST",
            path="/api/v1/users",
            headers=self.auth_headers(admin_token),
            body={"username": "operator", "password": "ExampleOperatorPass123", "role": "operator"},
        )
        login, _request_id = self.app.handle_api_request(
            method="POST",
            path="/api/v1/auth/login",
            headers={},
            body={"username": "operator", "password": "ExampleOperatorPass123"},
        )

        self.app.handle_api_request(
            method="PATCH",
            path=f"/api/v1/users/{created['id']}",
            headers=self.auth_headers(admin_token),
            body={"enabled": False},
        )

        with self.assertRaises(ApiError) as ctx:
            self.app.handle_api_request(
                method="GET",
                path="/api/v1/auth/me",
                headers=self.auth_headers(login["token"]),
            )
        self.assertEqual(ctx.exception.code, "auth_required")

    def test_cleanup_preserves_active_alerts_and_writes_audit_log(self):
        admin_token = self.bootstrap()
        self.app.handle_api_request(
            method="POST",
            path="/api/v1/device-groups",
            headers=self.auth_headers(admin_token),
            body={"name": "NAS", "id": "grp-nas"},
        )
        self.app.handle_api_request(
            method="POST",
            path="/api/v1/devices",
            headers=self.auth_headers(admin_token),
            body={
                "id": "dev-nas-01",
                "name": "Test NAS",
                "host": "192.0.2.20",
                "device_type": "nas",
                "group_id": "grp-nas",
            },
        )
        self.app.handle_api_request(
            method="POST",
            path="/api/v1/devices/dev-nas-01/refresh",
            headers=self.auth_headers(admin_token),
            body={"timeout": 5},
        )
        self.app.handle_api_request(
            method="PATCH",
            path="/api/v1/settings/retention",
            headers=self.auth_headers(admin_token),
            body={
                "collection_history_days": 1,
                "audit_log_days": 1,
                "resolved_alert_days": 1,
            },
        )
        result, _request_id = self.app.handle_api_request(
            method="POST",
            path="/api/v1/settings/retention/cleanup",
            headers=self.auth_headers(admin_token),
            body={},
        )
        self.assertGreaterEqual(result["active_alerts_preserved"], 0)

        audit, _request_id = self.app.handle_api_request(
            method="GET",
            path="/api/v1/audit",
            headers=self.auth_headers(admin_token),
            query={"limit": ["20"]},
        )
        self.assertTrue(any(entry["action"] == "retention.cleanup" for entry in audit["entries"]))

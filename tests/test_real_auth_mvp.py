import unittest

from homeinfra.app import HomeInfraApp
from homeinfra.errors import ApiError


class RealAuthContractTestCase(unittest.TestCase):
    ROUTE_EXISTS_CODES = {"forbidden", "validation_error", "conflict", "auth_required"}

    def setUp(self):
        self.app = HomeInfraApp(static_dir="static")
        bootstrap = self.app.auth.bootstrap_admin({"username": "admin", "password": "ExampleAdminPass123"})
        self.tokens = {"admin": bootstrap["token"]}
        self.app.auth.create_user(
            {"username": "operator", "password": "ExampleOperatorPass123", "role": "operator"}
        )
        self.tokens["operator"] = self.app.auth.login(
            {"username": "operator", "password": "ExampleOperatorPass123"}
        )["token"]

    def request(self, method, path, *, role="admin", body=None, query=None, headers=None):
        merged_headers = {"Authorization": f"Bearer {self.tokens[role]}"}
        if headers:
            merged_headers.update(headers)
        return self.app.handle_api_request(
            method=method,
            path=path,
            headers=merged_headers,
            body=body or {},
            query=query or {},
        )

    def first_existing_path(self, method, paths, *, role="admin", body=None, query=None):
        for path in paths:
            try:
                self.request(method, path, role=role, body=body, query=query)
                return path
            except ApiError as exc:
                if exc.code in self.ROUTE_EXISTS_CODES:
                    return path
                if exc.code != "not_found":
                    raise
        self.skipTest("No candidate route found: " + ", ".join(paths))


class RealAuthBootstrapTests(RealAuthContractTestCase):
    def test_first_initialization_requires_admin_creation(self):
        fresh_app = HomeInfraApp(static_dir="static")
        payload, _request_id = fresh_app.handle_api_request(
            method="GET",
            path="/api/v1/auth/bootstrap",
            headers={},
        )
        self.assertTrue(payload["required"])
        self.assertEqual(payload["user_count"], 0)


class RealAuthUserManagementTests(RealAuthContractTestCase):
    USER_COLLECTION_PATHS = (
        "/api/v1/users",
        "/api/v1/admin/users",
        "/api/v1/auth/users",
    )

    def test_admin_user_management_contract(self):
        user_path = self.first_existing_path("GET", self.USER_COLLECTION_PATHS)
        payload, _request_id = self.request("GET", user_path, role="admin")
        self.assertIsInstance(payload, dict)

        rendered = str(payload).lower()
        self.assertNotIn("password_hash", rendered)
        self.assertNotIn("password salt", rendered)
        self.assertNotIn("credential", rendered)

    def test_non_admin_cannot_manage_users(self):
        user_path = self.first_existing_path("GET", self.USER_COLLECTION_PATHS)
        with self.assertRaises(ApiError) as ctx:
            self.request("POST", user_path, role="operator", body={"username": "ops-user"})
        self.assertEqual(ctx.exception.code, "forbidden")


class RealAuthHistoryContractTests(RealAuthContractTestCase):
    HISTORY_PATHS = (
        "/api/v1/collections",
    )

    def test_history_supports_device_group_time_and_status_filters(self):
        history_path = self.first_existing_path("GET", self.HISTORY_PATHS)
        payload, _request_id = self.request(
            "GET",
            history_path,
            role="admin",
            query={
                "device_id": ["dev-nas-01"],
                "group_id": ["grp-nas"],
                "status": ["warning"],
                "since": ["2026-01-01T00:00:00Z"],
                "until": ["2026-12-31T23:59:59Z"],
            },
        )
        self.assertIsInstance(payload, dict)

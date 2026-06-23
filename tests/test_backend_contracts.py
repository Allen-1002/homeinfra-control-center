import importlib
import json
import unittest


class ContractTestCase(unittest.TestCase):
    def import_first(self, *module_names):
        errors = []
        for module_name in module_names:
            try:
                return importlib.import_module(module_name)
            except ModuleNotFoundError as exc:
                top_level = module_name.split(".", 1)[0]
                if (
                    exc.name == top_level
                    or exc.name == module_name
                    or exc.name.startswith(module_name + ".")
                ):
                    errors.append(module_name)
                    continue
                raise
        self.skipTest("No candidate module found: " + ", ".join(errors))

    def find_attr(self, module, *names):
        for name in names:
            if hasattr(module, name):
                return getattr(module, name)
        self.fail(
            f"{module.__name__} must expose one of: {', '.join(names)}"
        )

    def call_any(self, func, *patterns):
        type_errors = []
        for args, kwargs in patterns:
            try:
                return func(*args, **kwargs)
            except TypeError as exc:
                type_errors.append(str(exc))
        self.fail(
            f"{getattr(func, '__name__', func)!r} did not accept any expected "
            f"contract call shape. Last TypeErrors: {type_errors[-3:]}"
        )

    def allowed_value(self, decision):
        if isinstance(decision, bool):
            return decision
        if isinstance(decision, dict):
            for key in ("allowed", "allow", "granted", "permitted"):
                if key in decision:
                    return bool(decision[key])
        for key in ("allowed", "allow", "granted", "permitted"):
            if hasattr(decision, key):
                return bool(getattr(decision, key))
        self.fail(f"Permission decision is not a recognized envelope: {decision!r}")

    def severity_value(self, result):
        if isinstance(result, str):
            return result.lower()
        if isinstance(result, dict):
            for key in ("severity", "risk", "level", "status"):
                if key in result:
                    return str(result[key]).lower()
            if "score" in result:
                return "high" if result["score"] >= 0.7 else "low"
        for key in ("severity", "risk", "level", "status"):
            if hasattr(result, key):
                return str(getattr(result, key)).lower()
        self.fail(f"Risk result is not a recognized envelope: {result!r}")

    def reasons_text(self, result):
        if isinstance(result, dict):
            values = []
            for key in ("reasons", "findings", "messages", "issues"):
                value = result.get(key)
                if isinstance(value, (list, tuple)):
                    values.extend(map(str, value))
                elif value:
                    values.append(str(value))
            return " ".join(values).lower()
        return str(result).lower()


class PermissionDecisionTests(ContractTestCase):
    def setUp(self):
        module = self.import_first(
            "homeinfra.permissions",
            "homeinfra.authz",
            "homeinfra.security.permissions",
        )
        self.decide = self.find_attr(
            module,
            "can_access",
            "is_allowed",
            "has_permission",
            "decide_permission",
            "authorize",
        )

    def test_admin_write_permission_is_allowed(self):
        actor = {
            "id": "u-admin",
            "role": "admin",
            "permissions": ["devices:write", "groups:read"],
        }
        permission = "devices:write"

        decision = self.call_any(
            self.decide,
            ((), {"actor": actor, "resource": "devices", "action": "write"}),
            ((actor, "devices", "write"), {}),
            ((actor, permission), {}),
            ((), {"actor": actor, "permission": permission}),
            (({"actor": actor, "resource": "devices", "action": "write"},), {}),
        )

        self.assertTrue(self.allowed_value(decision))

    def test_viewer_write_permission_is_denied(self):
        actor = {
            "id": "u-viewer",
            "role": "viewer",
            "permissions": ["devices:read"],
        }
        permission = "devices:write"

        decision = self.call_any(
            self.decide,
            ((), {"actor": actor, "resource": "devices", "action": "write"}),
            ((actor, "devices", "write"), {}),
            ((actor, permission), {}),
            ((), {"actor": actor, "permission": permission}),
            (({"actor": actor, "resource": "devices", "action": "write"},), {}),
        )

        self.assertFalse(self.allowed_value(decision))


class AlertGenerationTests(ContractTestCase):
    def setUp(self):
        module = self.import_first("homeinfra.alerts", "homeinfra.monitoring.alerts")
        self.generate = self.find_attr(
            module,
            "generate_alerts",
            "evaluate_alerts",
            "build_alerts",
        )

    def test_generates_high_signal_alerts_for_infrastructure_risks(self):
        snapshot = {
            "nas": {
                "capacity_percent": 94,
                "raid_status": "degraded",
                "backup_age_days": 10,
            },
        }

        alerts = self.call_any(
            self.generate,
            ((snapshot,), {}),
            ((), {"snapshot": snapshot}),
        )

        self.assertIsInstance(alerts, list)
        self.assertGreaterEqual(len(alerts), 1)
        rendered = json.dumps(alerts, ensure_ascii=False).lower()
        self.assertRegex(rendered, r"capacity|raid|backup")
        self.assertRegex(rendered, r"warning|high|critical|error")

    def test_healthy_snapshot_does_not_create_warning_alerts(self):
        snapshot = {
            "nas": {
                "capacity_percent": 40,
                "raid_status": "healthy",
                "backup_age_days": 0,
            },
        }

        alerts = self.call_any(
            self.generate,
            ((snapshot,), {}),
            ((), {"snapshot": snapshot}),
        )

        rendered = json.dumps(alerts, ensure_ascii=False).lower()
        self.assertNotRegex(rendered, r"critical|error|high")


class NasRiskTests(ContractTestCase):
    def setUp(self):
        module = self.import_first(
            "homeinfra.nas",
            "homeinfra.risk.nas",
            "homeinfra.risk",
        )
        self.assess = self.find_attr(
            module,
            "assess_nas_risk",
            "evaluate_nas_risk",
            "nas_risk",
        )

    def test_capacity_raid_and_backup_risks_are_reported(self):
        nas = {
            "capacity_percent": 94,
            "raid_status": "degraded",
            "last_backup_age_days": 9,
        }

        result = self.call_any(self.assess, ((nas,), {}), ((), {"nas": nas}))

        self.assertIn(self.severity_value(result), {"high", "critical", "error"})
        reasons = self.reasons_text(result)
        self.assertIn("raid", reasons)
        self.assertRegex(reasons, r"capacity|storage|disk")
        self.assertIn("backup", reasons)

    def test_healthy_nas_is_low_risk(self):
        nas = {
            "capacity_percent": 35,
            "raid_status": "healthy",
            "last_backup_age_days": 0,
        }

        result = self.call_any(self.assess, ((nas,), {}), ((), {"nas": nas}))

        self.assertIn(self.severity_value(result), {"ok", "low", "healthy", "none"})


class MockDataContractTests(ContractTestCase):
    def setUp(self):
        module = self.import_first(
            "homeinfra.mock_data",
            "homeinfra.fixtures.mock_data",
            "homeinfra.data.mock",
        )
        provider = getattr(module, "MOCK_DATA", None)
        if provider is None:
            provider = self.find_attr(
                module,
                "get_mock_data",
                "load_mock_data",
                "build_mock_data",
            )
        self.provider = provider

    def get_data(self):
        if callable(self.provider):
            return self.call_any(self.provider, ((), {}))
        return self.provider

    def test_mock_data_has_dashboard_contract_keys(self):
        data = self.get_data()

        self.assertIsInstance(data, dict)
        for key in ("summary", "device_groups", "devices", "collection_records", "alerts", "audit_logs"):
            self.assertIn(key, data)
        self.assertIsInstance(data["summary"], dict)
        self.assertIsInstance(data["alerts"], list)

    def test_mock_data_is_json_serializable(self):
        data = self.get_data()

        json.dumps(data, ensure_ascii=False, sort_keys=True)


class ApiErrorEnvelopeTests(ContractTestCase):
    def setUp(self):
        module = self.import_first(
            "homeinfra.api",
            "homeinfra.api.errors",
            "homeinfra.web.errors",
        )
        self.build = self.find_attr(
            module,
            "error_response",
            "build_error_response",
            "api_error",
        )

    def test_error_response_uses_stable_public_envelope(self):
        response = self.call_any(
            self.build,
            (("VALIDATION_ERROR", "Name is required"), {"status": 400}),
            ((), {"code": "VALIDATION_ERROR", "message": "Name is required", "status": 400}),
            ((400, "VALIDATION_ERROR", "Name is required"), {}),
        )

        if isinstance(response, tuple):
            body, status = response[0], response[1]
        else:
            body, status = response, None

        self.assertIsInstance(body, dict)
        self.assertIn("error", body)
        self.assertIsInstance(body["error"], dict)
        self.assertEqual(body["error"].get("code"), "VALIDATION_ERROR")
        self.assertEqual(body["error"].get("message"), "Name is required")
        self.assertNotIn("traceback", json.dumps(body).lower())
        self.assertNotIn("exception", json.dumps(body).lower())
        if status is not None:
            self.assertEqual(status, 400)
        else:
            self.assertIn(body.get("status") or body.get("status_code"), (400, None))

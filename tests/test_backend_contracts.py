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
            "permissions": ["automation:write", "nas:read"],
        }
        permission = "automation:write"

        decision = self.call_any(
            self.decide,
            ((), {"actor": actor, "resource": "automation", "action": "write"}),
            ((actor, "automation", "write"), {}),
            ((actor, permission), {}),
            ((), {"actor": actor, "permission": permission}),
            (({"actor": actor, "resource": "automation", "action": "write"},), {}),
        )

        self.assertTrue(self.allowed_value(decision))

    def test_viewer_write_permission_is_denied(self):
        actor = {
            "id": "u-viewer",
            "role": "viewer",
            "permissions": ["automation:read"],
        }
        permission = "automation:write"

        decision = self.call_any(
            self.decide,
            ((), {"actor": actor, "resource": "automation", "action": "write"}),
            ((actor, "automation", "write"), {}),
            ((actor, permission), {}),
            ((), {"actor": actor, "permission": permission}),
            (({"actor": actor, "resource": "automation", "action": "write"},), {}),
        )

        self.assertFalse(self.allowed_value(decision))


class AutomationTaskStateMachineTests(ContractTestCase):
    def setUp(self):
        self.module = self.import_first(
            "homeinfra.automation",
            "homeinfra.automation_tasks",
            "homeinfra.tasks",
        )

    def test_task_can_progress_from_pending_to_running_to_success(self):
        transition = getattr(self.module, "transition_task_state", None)
        if transition is None:
            transition = getattr(self.module, "next_task_state", None)

        if transition is not None:
            running = self.call_any(
                transition,
                (("pending", "start"), {}),
                ((), {"state": "pending", "event": "start"}),
            )
            self.assertIn(str(running).lower(), {"running", "in_progress"})

            success = self.call_any(
                transition,
                ((str(running), "succeed"), {}),
                ((), {"state": str(running), "event": "succeed"}),
            )
            self.assertIn(str(success).lower(), {"succeeded", "success", "completed"})
            return

        task_cls = self.find_attr(
            self.module,
            "AutomationTask",
            "AutomationTaskStateMachine",
            "TaskStateMachine",
        )
        task = self.call_any(
            task_cls,
            ((), {"task_id": "task-1", "name": "backup"}),
            (("task-1", "backup"), {}),
            ((), {}),
        )

        start = self.find_attr(task, "start", "run", "mark_running")
        self.call_any(start, ((), {}))
        self.assertIn(
            str(getattr(task, "state")).lower(),
            {"running", "in_progress"},
        )

        succeed = self.find_attr(task, "succeed", "complete", "mark_succeeded")
        self.call_any(succeed, ((), {}))
        self.assertIn(
            str(getattr(task, "state")).lower(),
            {"succeeded", "success", "completed"},
        )

    def test_terminal_success_state_cannot_restart(self):
        transition = getattr(self.module, "transition_task_state", None)
        if transition is None:
            transition = getattr(self.module, "next_task_state", None)
        if transition is None:
            self.skipTest("State function not available for terminal contract check")

        try:
            result = self.call_any(
                transition,
                (("succeeded", "start"), {}),
                ((), {"state": "succeeded", "event": "start"}),
            )
        except Exception:
            return

        self.assertIn(
            str(result).lower(),
            {"succeeded", "success", "completed"},
            "Terminal success state must not transition back to running.",
        )


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
            "vpn_clients": [
                {"name": "phone", "enabled": True, "last_handshake_age_days": 45}
            ],
        }

        alerts = self.call_any(
            self.generate,
            ((snapshot,), {}),
            ((), {"snapshot": snapshot}),
        )

        self.assertIsInstance(alerts, list)
        self.assertGreaterEqual(len(alerts), 1)
        rendered = json.dumps(alerts, ensure_ascii=False).lower()
        self.assertRegex(rendered, r"capacity|raid|backup|vpn|handshake")
        self.assertRegex(rendered, r"warning|high|critical|error")

    def test_healthy_snapshot_does_not_create_warning_alerts(self):
        snapshot = {
            "nas": {
                "capacity_percent": 40,
                "raid_status": "healthy",
                "backup_age_days": 0,
            },
            "vpn_clients": [
                {"name": "laptop", "enabled": True, "last_handshake_age_days": 1}
            ],
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


class VpnClientRiskTests(ContractTestCase):
    def setUp(self):
        module = self.import_first(
            "homeinfra.vpn",
            "homeinfra.risk.vpn",
            "homeinfra.risk",
        )
        self.assess = self.find_attr(
            module,
            "assess_vpn_client_risk",
            "evaluate_vpn_client_risk",
            "vpn_client_risk",
        )

    def test_stale_enabled_client_with_wide_route_is_risky(self):
        client = {
            "name": "old-phone",
            "enabled": True,
            "last_handshake_age_days": 45,
            "allowed_ips": ["0.0.0.0/0"],
        }

        result = self.call_any(
            self.assess,
            ((client,), {}),
            ((), {"client": client}),
        )

        self.assertIn(self.severity_value(result), {"medium", "high", "critical"})
        self.assertRegex(self.reasons_text(result), r"handshake|stale|route|wide")

    def test_recent_limited_client_is_low_risk(self):
        client = {
            "name": "laptop",
            "enabled": True,
            "last_handshake_age_days": 1,
            "allowed_ips": ["192.0.2.21/32"],
        }

        result = self.call_any(
            self.assess,
            ((client,), {}),
            ((), {"client": client}),
        )

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
        for key in ("nas", "vpn_clients", "automation_tasks", "alerts"):
            self.assertIn(key, data)
        self.assertIsInstance(data["vpn_clients"], list)
        self.assertIsInstance(data["automation_tasks"], list)
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

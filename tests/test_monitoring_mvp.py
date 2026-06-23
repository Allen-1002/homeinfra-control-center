import importlib
import os
import tempfile
import unittest

from homeinfra.app import HomeInfraApp
from homeinfra.collectors import MockCommandCollector, BaseSSHCollector, MOCK_FIXTURES
from homeinfra.collector_service import CollectorService
from homeinfra.errors import ApiError
from homeinfra.monitoring import MonitoringService
from homeinfra.persistence import SQLiteStore
from homeinfra.scheduler import CollectionScheduler


class MonitoringContractTestCase(unittest.TestCase):
    MODULE_CANDIDATES = (
        "homeinfra.monitoring",
        "homeinfra.monitoring.service",
        "homeinfra.monitoring.devices",
        "homeinfra.monitoring.collector",
        "homeinfra.monitoring.sqlite_store",
        "homeinfra.monitoring.storage",
    )

    DEVICE_COLLECTION_PATHS = (
        "/api/v1/monitoring/devices",
        "/api/v1/devices",
    )
    GROUP_COLLECTION_PATHS = (
        "/api/v1/monitoring/device-groups",
        "/api/v1/monitoring/groups",
        "/api/v1/device-groups",
        "/api/v1/groups",
    )
    ALERT_COLLECTION_PATHS = (
        "/api/v1/monitoring/alerts",
        "/api/v1/alerts",
    )

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
                    or module_name.startswith(exc.name + ".")
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
        self.skipTest(
            f"{module.__name__} does not expose any of: {', '.join(names)}"
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
        bootstrap = self.app.auth.bootstrap_admin({"username": "admin", "password": "ExampleAdminPass123"})
        self.tokens = {"admin": bootstrap["token"]}
        self.app.auth.create_user(
            {"username": "operator", "password": "ExampleOperatorPass123", "role": "operator"}
        )
        self.app.auth.create_user(
            {"username": "viewer", "password": "ExampleViewerPass123", "role": "viewer"}
        )
        self.tokens["operator"] = self.app.auth.login(
            {"username": "operator", "password": "ExampleOperatorPass123"}
        )["token"]
        self.tokens["viewer"] = self.app.auth.login(
            {"username": "viewer", "password": "ExampleViewerPass123"}
        )["token"]

    def request(
        self,
        method,
        path,
        *,
        role="admin",
        body=None,
        query=None,
        headers=None,
    ):
        token = self.tokens.get(role, self.tokens["viewer"])
        default_headers = {"Authorization": f"Bearer {token}"}
        if headers:
            default_headers.update(headers)
        return self.app.handle_api_request(
            method=method,
            path=path,
            headers=default_headers,
            body=body or {},
            query=query or {},
        )

    def first_existing_path(self, method, paths, *, role="viewer", body=None, query=None):
        for path in paths:
            try:
                self.request(method, path, role=role, body=body, query=query)
                return path
            except ApiError as exc:
                if exc.code != "not_found":
                    return path
        self.skipTest("No candidate route found: " + ", ".join(paths))

    def collection_item_path(self, collection_path, item_id):
        return collection_path.rstrip("/") + "/" + item_id


class MonitoringAuthorizationTests(MonitoringContractTestCase):
    def test_viewer_cannot_add_or_delete_devices_or_groups(self):
        device_path = self.first_existing_path("GET", self.DEVICE_COLLECTION_PATHS)
        group_path = self.first_existing_path("GET", self.GROUP_COLLECTION_PATHS)

        with self.assertRaises(ApiError) as device_create:
            self.request(
                "POST",
                device_path,
                role="viewer",
                body={"name": "viewer-test-device", "host": "192.0.2.50"},
            )
        self.assertEqual(device_create.exception.code, "forbidden")

        with self.assertRaises(ApiError) as group_create:
            self.request(
                "POST",
                group_path,
                role="viewer",
                body={"name": "viewer-test-group"},
            )
        self.assertEqual(group_create.exception.code, "forbidden")

        for target in (
            self.collection_item_path(device_path, "viewer-test-device"),
            self.collection_item_path(group_path, "viewer-test-group"),
        ):
            with self.assertRaises(ApiError) as delete_ctx:
                self.request("DELETE", target, role="viewer")
            self.assertEqual(delete_ctx.exception.code, "forbidden")

    def test_operator_cannot_modify_ssh_credentials(self):
        device_path = self.first_existing_path("GET", self.DEVICE_COLLECTION_PATHS)
        target_path = self.collection_item_path(device_path, "dev-server-01")

        with self.assertRaises(ApiError) as ctx:
            self.request(
                "PATCH",
                target_path,
                role="operator",
                body={
                    "username": "root",
                    "auth_type": "password",
                    "password": "not-a-real-secret",
                    "port": 2222,
                },
            )
        self.assertEqual(ctx.exception.code, "forbidden")

    def test_admin_can_manage_devices_and_groups(self):
        device_path = self.first_existing_path("GET", self.DEVICE_COLLECTION_PATHS)
        group_path = self.first_existing_path("GET", self.GROUP_COLLECTION_PATHS)

        group_response, _ = self.request(
            "POST",
            group_path,
            role="admin",
            body={"name": "lab-group"},
        )
        self.assertIsInstance(group_response, dict)

        device_response, _ = self.request(
            "POST",
            device_path,
            role="admin",
            body={"name": "lab-device", "host": "192.0.2.72", "group": "lab-group"},
        )
        self.assertIsInstance(device_response, dict)


class MonitoringCrudAndFilteringTests(MonitoringContractTestCase):
    def test_device_and_group_crud_contracts_exist(self):
        device_path = self.first_existing_path("GET", self.DEVICE_COLLECTION_PATHS)
        group_path = self.first_existing_path("GET", self.GROUP_COLLECTION_PATHS)

        devices, _ = self.request("GET", device_path, role="viewer")
        groups, _ = self.request("GET", group_path, role="viewer")

        self.assertIsInstance(devices, dict)
        self.assertIsInstance(groups, dict)

    def test_deleting_a_group_moves_devices_to_ungrouped(self):
        group_path = self.first_existing_path("GET", self.GROUP_COLLECTION_PATHS)
        device_path = self.first_existing_path("GET", self.DEVICE_COLLECTION_PATHS)

        group, _ = self.request(
            "POST",
            group_path,
            role="admin",
            body={"name": "temporary-group"},
        )
        group_id = group.get("id") or group.get("group", {}).get("id") or "temporary-group"

        device, _ = self.request(
            "POST",
            device_path,
            role="admin",
            body={"name": "grouped-device", "host": "192.0.2.80", "group_id": group_id},
        )
        device_id = device.get("id") or device.get("device", {}).get("id") or "grouped-device"

        self.request("DELETE", self.collection_item_path(group_path, group_id), role="admin")
        device_after, _ = self.request(
            "GET",
            self.collection_item_path(device_path, device_id),
            role="viewer",
        )
        rendered = str(device_after).lower()
        self.assertRegex(rendered, r"ungroup|none|null|default")

    def test_filtering_devices_by_group(self):
        device_path = self.first_existing_path("GET", self.DEVICE_COLLECTION_PATHS)
        response, _ = self.request(
            "GET",
            device_path,
            role="viewer",
            query={"group": ["ungrouped"]},
        )
        self.assertIsInstance(response, dict)

    def test_filtering_alerts_by_group(self):
        alert_path = self.first_existing_path("GET", self.ALERT_COLLECTION_PATHS)
        response, _ = self.request(
            "GET",
            alert_path,
            role="viewer",
            query={"group": ["ungrouped"]},
        )
        self.assertIsInstance(response, dict)

    def test_alert_history_filters_by_device_group_and_status(self):
        self.request(
            "POST",
            "/api/v1/device-groups",
            role="admin",
            body={"name": "NAS", "id": "grp-nas"},
        )
        self.request(
            "POST",
            "/api/v1/devices",
            role="admin",
            body={
                "id": "dev-nas-01",
                "name": "Test NAS",
                "host": "192.0.2.20",
                "device_type": "nas",
                "group_id": "grp-nas",
            },
        )
        self.request(
            "POST",
            "/api/v1/devices/dev-nas-01/refresh",
            role="operator",
            body={"timeout": 5},
        )
        response, _ = self.request(
            "GET",
            "/api/v1/alerts",
            role="viewer",
            query={
                "device_id": ["dev-nas-01"],
                "group_id": ["grp-nas"],
                "status": ["active"],
            },
        )
        alerts = response.get("alerts", [])
        self.assertIsInstance(alerts, list)
        if alerts:
            self.assertTrue(
                all(
                    alert["device_id"] == "dev-nas-01"
                    and alert["group_id"] == "grp-nas"
                    and alert["status"] == "active"
                    for alert in alerts
                )
            )

    def test_collection_history_filters_by_device_and_tolerates_time_window_params(self):
        self.request(
            "POST",
            "/api/v1/device-groups",
            role="admin",
            body={"name": "NAS", "id": "grp-nas"},
        )
        self.request(
            "POST",
            "/api/v1/devices",
            role="admin",
            body={
                "id": "dev-nas-01",
                "name": "Test NAS",
                "host": "192.0.2.20",
                "device_type": "nas",
                "group_id": "grp-nas",
            },
        )
        self.request(
            "POST",
            "/api/v1/devices/dev-nas-01/refresh",
            role="operator",
            body={"timeout": 5},
        )
        response, _ = self.request(
            "GET",
            "/api/v1/collections",
            role="viewer",
            query={
                "device_id": ["dev-nas-01"],
                "limit": ["10"],
                "start_at": ["2026-01-01T00:00:00Z"],
                "end_at": ["2026-12-31T23:59:59Z"],
            },
        )
        records = response["records"]
        self.assertTrue(records)
        self.assertTrue(all(record["device_id"] == "dev-nas-01" for record in records))

    def test_invalid_monitoring_api_parameters_do_not_produce_500(self):
        for path in self.DEVICE_COLLECTION_PATHS + self.GROUP_COLLECTION_PATHS + self.ALERT_COLLECTION_PATHS:
            try:
                with self.assertRaises(ApiError) as ctx:
                    self.request(
                        "GET",
                        path,
                        role="viewer",
                        query={"limit": ["bad-int"], "group": ["%%%"]},
                    )
                self.assertNotEqual(ctx.exception.status, 500)
                return
            except AssertionError:
                raise
            except Exception:
                continue
        self.skipTest("No monitoring list endpoint found for invalid-parameter contract")


class MonitoringCollectorAndAlertTests(MonitoringContractTestCase):
    def setUp(self):
        super().setUp()
        self.module = self.import_first(*self.MODULE_CANDIDATES)

    def test_ssh_whitelist_blocks_dangerous_commands(self):
        checker = self.find_attr(
            self.module,
            "is_ssh_command_allowed",
            "check_ssh_command_whitelist",
            "validate_ssh_command",
        )
        result = self.call_any(
            checker,
            (("rm -rf /",), {}),
            ((), {"command": "rm -rf /"}),
        )
        self.assertIn(str(result).lower(), {"false", "denied", "blocked", "forbidden"})

    def test_mock_collector_returns_normal_metrics(self):
        collector = self.find_attr(
            self.module,
            "collect_mock_metrics",
            "mock_collect_metrics",
            "collect_metrics_mock",
        )
        metrics = self.call_any(collector, ((), {}))
        rendered = str(metrics).lower()
        self.assertRegex(rendered, r"cpu|memory|disk|pool|smart")

    def test_collection_failure_generates_alert(self):
        generator = self.find_attr(
            self.module,
            "generate_collection_failure_alert",
            "build_collection_failure_alert",
            "alert_for_collection_failure",
        )
        alert = self.call_any(
            generator,
            (("device-1", "ssh timeout"), {}),
            ((), {"device_id": "device-1", "error": "ssh timeout"}),
        )
        rendered = str(alert).lower()
        self.assertRegex(rendered, r"alert|warning|critical|error")
        self.assertIn("device", rendered)

    def test_disk_pool_thresholds_create_warning(self):
        evaluator = self.find_attr(
            self.module,
            "evaluate_threshold_alerts",
            "generate_threshold_alerts",
            "build_threshold_alerts",
        )
        alerts = self.call_any(
            evaluator,
            (({"disk_percent": 91, "pool_percent": 88},), {}),
            ((), {"metrics": {"disk_percent": 91, "pool_percent": 88}}),
        )
        rendered = str(alerts).lower()
        self.assertRegex(rendered, r"warning|warn")

    def test_smart_abnormal_creates_critical(self):
        evaluator = self.find_attr(
            self.module,
            "evaluate_smart_alert",
            "generate_smart_alert",
            "build_smart_alert",
        )
        alert = self.call_any(
            evaluator,
            (({"smart_status": "abnormal"},), {}),
            ((), {"metrics": {"smart_status": "abnormal"}}),
        )
        self.assertRegex(str(alert).lower(), r"critical|error")


class MonitoringSqliteAndAuditTests(MonitoringContractTestCase):
    def test_sqlite_init_and_basic_read_write(self):
        module = self.import_first(*self.MODULE_CANDIDATES)
        initializer = self.find_attr(
            module,
            "init_sqlite",
            "initialize_sqlite",
            "init_db",
        )
        writer = self.find_attr(
            module,
            "save_device",
            "create_device",
            "insert_device",
        )
        reader = self.find_attr(
            module,
            "get_device",
            "read_device",
            "fetch_device",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "monitoring.sqlite3")
            self.call_any(
                initializer,
                ((db_path,), {}),
                ((), {"path": db_path}),
            )
            self.call_any(
                writer,
                ((db_path, {"id": "dev-1", "name": "device-1", "host": "127.0.0.1"}), {}),
                ((), {"path": db_path, "device": {"id": "dev-1", "name": "device-1", "host": "127.0.0.1"}}),
            )
            device = self.call_any(
                reader,
                ((db_path, "dev-1"), {}),
                ((), {"path": db_path, "device_id": "dev-1"}),
            )
            self.assertIn("dev-1", str(device))

    def test_audit_logs_record_sensitive_operations(self):
        device_path = self.first_existing_path("GET", self.DEVICE_COLLECTION_PATHS, role="viewer")

        try:
            with self.assertRaises(ApiError):
                self.request(
                    "POST",
                    device_path,
                    role="viewer",
                    body={"name": "forbidden-device", "host": "192.0.2.99"},
                )
        except AssertionError:
            raise
        except Exception:
            self.skipTest("Sensitive monitoring mutation route unavailable")

        audit, _ = self.request(
            "GET",
            "/api/v1/audit",
            role="operator",
            query={"limit": ["20"]},
        )
        rendered = str(audit).lower()
        self.assertRegex(rendered, r"forbidden|validation|device|group|ssh")

    def test_sensitive_credentials_are_redacted_from_device_responses_and_audit_logs(self):
        device_path = self.first_existing_path("GET", self.DEVICE_COLLECTION_PATHS)
        created, _request_id = self.request(
            "POST",
            device_path,
            role="admin",
            body={
                "id": "dev-secret-01",
                "name": "Secret Device",
                "host": "192.0.2.91",
                "username": "root",
                "auth_type": "private_key",
                "private_key_path": "/tmp/id_secret",
                "encrypted_private_key": "ENCRYPTED-SECRET",
                "group_id": "grp-ungrouped",
                "device_type": "other",
                "tags": ["secret"],
                "enabled": True,
                "poll_interval": 60,
            },
        )
        self.assertNotIn("password", created)
        self.assertEqual(created["private_key_path"], "***configured***")
        self.assertEqual(created["encrypted_private_key"], "***configured***")

        fetched, _request_id = self.request(
            "GET",
            self.collection_item_path(device_path, "dev-secret-01"),
            role="viewer",
        )
        self.assertNotIn("password", fetched)
        self.assertEqual(fetched["private_key_path"], "***configured***")
        self.assertEqual(fetched["encrypted_private_key"], "***configured***")

        audit, _request_id = self.request(
            "GET",
            "/api/v1/audit",
            role="operator",
            query={"limit": ["10"]},
        )
        matching = [
            entry
            for entry in audit["entries"]
            if entry.get("resource") == "devices/dev-secret-01"
        ]
        self.assertTrue(matching)
        audit_details = matching[0]["details"]
        self.assertEqual(audit_details["private_key_path"], "***configured***")
        self.assertEqual(audit_details["encrypted_private_key"], "***configured***")

    def test_collection_history_keeps_refresh_records(self):
        store = SQLiteStore()
        service = MonitoringService(store, collector_service=CollectorService(
            MockCommandCollector(), sample_interval=0.0, data_source="mock", is_real_data=False
        ))
        service.create_group({"id": "grp-servers", "name": "服务器"})
        service.create_device(
            {
                "id": "dev-server-01",
                "name": "Server",
                "host": "192.0.2.30",
                "device_type": "linux_server",
                "group_id": "grp-servers",
            }
        )

        for _ in range(50):
            service.refresh_device("dev-server-01", timeout=5)

        snapshot = store.snapshot()
        records = snapshot["collection_records"]
        server_records = [record for record in records if record["device_id"] == "dev-server-01"]
        self.assertEqual(len(records), 50)
        self.assertEqual(len(server_records), 50)
        self.assertEqual(records[0]["device_id"], "dev-server-01")
        self.assertEqual(records[0]["id"], "col-00050")
        self.assertEqual(records[-1]["id"], "col-00001")


class MonitoringPhase1ContractTests(MonitoringContractTestCase):
    """Baseline collection contract — test stubs may exercise the SSH pipeline."""

    def test_stub_device_detail_returns_phase1_fields_and_truthiness(self):
        store = SQLiteStore()
        service = MonitoringService(store, collector_service=CollectorService(
            MockCommandCollector(), sample_interval=0.0, data_source="ssh", is_real_data=True
        ))
        service.create_group({"name": "Servers", "id": "grp-servers"})
        service.create_device({
            "name": "web-01", "host": "192.0.2.10", "device_type": "linux_server",
            "group_id": "grp-servers", "verified": True,
        })
        service.refresh_device("dev-web-01", timeout=5)
        device = service.get_device("dev-web-01")

        self.assertIsNotNone(device.get("hostname"))
        self.assertIsNotNone(device.get("uname"))
        self.assertIsNotNone(device.get("cpu_percent"))
        self.assertIsNotNone(device.get("cpu_cores"))
        self.assertIsNotNone(device.get("memory_percent"))
        self.assertIsNotNone(device.get("memory_total_mb"))
        self.assertIsNotNone(device.get("memory_used_mb"))
        self.assertIsNotNone(device.get("load_average"))
        self.assertIsNotNone(device.get("uptime"))
        self.assertIsInstance(device.get("partitions"), list)
        self.assertTrue(len(device.get("partitions", [])) > 0)
        self.assertIsInstance(device.get("network_interfaces"), list)
        self.assertTrue(len(device.get("network_interfaces", [])) > 0)

        self.assertEqual(device.get("data_source"), "ssh")
        self.assertEqual(device.get("is_real_data"), True)
        self.assertEqual(device.get("verified"), True)
        self.assertIsInstance(device.get("collector_errors"), list)
        self.assertIsInstance(device.get("unavailable_metrics"), list)

    def test_stub_refresh_can_surface_nas_raid_alerts(self):
        store = SQLiteStore()
        service = MonitoringService(store, collector_service=CollectorService(
            MockCommandCollector(), sample_interval=0.0, data_source="ssh", is_real_data=True
        ))
        service.create_group({"name": "Servers", "id": "grp-servers"})
        service.create_device({
            "name": "nas-01", "host": "192.0.2.20", "device_type": "nas",
            "group_id": "grp-servers", "verified": True,
        })
        result = service.refresh_device("dev-nas-01", timeout=5)
        alerts = result.get("alerts", [])
        active_alerts = [a for a in alerts if a.get("status") == "active"]
        alert_types = {alert.get("type") for alert in active_alerts}
        self.assertIn("nas_raid_degraded", alert_types)
        self.assertIn("nas_raid_abnormal", alert_types)

    def test_unavailable_metrics_do_not_trigger_critical(self):
        store = SQLiteStore()
        service = MonitoringService(store, collector_service=CollectorService(
            FaultInjectingCollector(fail_keys={"zfs_list"}), sample_interval=0.0, data_source="ssh", is_real_data=True
        ))
        service.create_group({"name": "Servers", "id": "grp-servers"})
        service.create_device({
            "name": "srv-01", "host": "192.0.2.30", "device_type": "nas",
            "group_id": "grp-servers", "verified": True,
        })
        result = service.refresh_device("dev-srv-01", timeout=5)
        device = result.get("device", {})

        unavailable = device.get("unavailable_metrics", [])
        alerts = result.get("alerts", [])
        active_alerts = [a for a in alerts if a.get("status") == "active"]

        # An optional NAS metric failing (zfs_list) must surface as unavailable
        # but must NOT raise any critical alert.
        self.assertIn("zfs_list", unavailable)
        for alert in active_alerts:
            self.assertNotEqual(alert.get("severity"), "critical")
        # Optional failures must not enter critical_errors.
        for err in device.get("critical_errors", []):
            self.assertNotEqual(err.get("command_id"), "zfs_list")


class FaultInjectingCollector(BaseSSHCollector):
    """A collector that can simulate failures for specific probe keys."""

    name = "fault-inject"

    def __init__(self, fail_keys=None, fail_all=False,
                 error_type="non_zero_exit", data=None):
        super().__init__()
        self.fail_keys = fail_keys or set()
        self.fail_all = fail_all
        self.error_type = error_type
        self._data = data or dict(MOCK_FIXTURES)
        self.calls: list[list[tuple[str, str]]] = []

    def execute_commands(
        self, device, probes, *, timeout
    ):
        self.calls.append(list(probes))
        results: dict[str, str] = {}
        errors: list[dict] = []
        for key, cmd in probes:
            if self.fail_all or key in self.fail_keys:
                errors.append({
                    "command_id": key,
                    "command": cmd,
                    "exit_code": 1 if self.error_type == "non_zero_exit" else None,
                    "stderr": f"{key}: simulated {self.error_type}",
                    "stdout": "",
                    "error_type": self.error_type,
                    "error_message": f"{key}: simulated {self.error_type} for {cmd}",
                })
                results[key] = ""
            else:
                results[key] = self._data.get(key, "")
        return results, errors


class DfFallbackMockCollector(BaseSSHCollector):
    """Fails df -P -B1 on first call, succeeds df -P on fallback call.

    The fallback returns 1K-block output (as real ``df -P`` would), so the
    service must parse it with block_size=1024 to get correct GiB values.
    """

    name = "df-fallback-test"

    # Same disk as MOCK_FIXTURES["df"] but expressed in 1K-blocks (df -P).
    DF_1K_BLOCKS = (
        "Filesystem     1024-blocks      Used  Available Capacity Mounted on\n"
        "/dev/sda1        102400000  43999176   58359808      43% /\n"
        "/dev/sdb1       1024000000 629439545  394850494      62% /data\n"
        "tmpfs              8144000         0    8144000       0% /dev/shm\n"
    )

    def __init__(self):
        super().__init__()
        self._call_seq = 0

    def execute_commands(
        self, device, probes, *, timeout
    ):
        results: dict[str, str] = {}
        errors: list[dict] = []
        for key, cmd in probes:
            if key == "df":
                self._call_seq += 1
                if self._call_seq == 1:
                    # Primary df -P -B1 fails (e.g. BusyBox rejects -B1)
                    errors.append({
                        "command_id": "df",
                        "command": cmd,
                        "exit_code": 1,
                        "stderr": "df: invalid option -- B",
                        "stdout": "",
                        "error_type": "non_zero_exit",
                        "error_message": "df: invalid option -- B",
                    })
                    results[key] = ""
                else:
                    # Fallback (df -P) succeeds with 1K-block output
                    results[key] = self.DF_1K_BLOCKS
            elif key in MOCK_FIXTURES:
                results[key] = MOCK_FIXTURES[key]
            else:
                results[key] = ""
        return results, errors


class RecordingCollector(BaseSSHCollector):
    """Records every probe sent; returns fixture data with optional per-key
    failure injection (exit_code/stderr/error_type configurable)."""

    name = "probe-record"

    def __init__(self, fail_keys=None, exit_code=1, stderr_tmpl=None,
                 error_type="non_zero_exit", data=None):
        super().__init__()
        self.fail_keys = fail_keys or set()
        self.exit_code = exit_code
        self.stderr_tmpl = stderr_tmpl
        self.error_type = error_type
        self._data = data if data is not None else dict(MOCK_FIXTURES)
        self.calls: list[list[tuple[str, str]]] = []
        self.keys_seen: set[str] = set()

    def execute_commands(self, device, probes, *, timeout):
        self.calls.append(list(probes))
        results: dict[str, str] = {}
        errors: list[dict] = []
        for key, cmd in probes:
            self.keys_seen.add(key)
            if key in self.fail_keys:
                stderr = (self.stderr_tmpl or f"{key}: simulated {self.error_type}")
                stderr = stderr.format(key=key, cmd=cmd)
                errors.append({
                    "command_id": key,
                    "command": cmd,
                    "exit_code": self.exit_code,
                    "stderr": stderr,
                    "stdout": "",
                    "error_type": self.error_type,
                    "error_message": stderr,
                })
                results[key] = ""
            else:
                results[key] = self._data.get(key, "")
        return results, errors


class RobustCollectionTests(MonitoringContractTestCase):
    """Phase 1 robustness: individual command failures must not crash collection."""

    def test_df_failure_preserves_cpu_memory_network(self):
        store = SQLiteStore()
        collector = FaultInjectingCollector(fail_keys={"df"})
        service = MonitoringService(store, collector_service=CollectorService(
            collector, sample_interval=0.0, data_source="ssh", is_real_data=True
        ))
        service.create_group({"name": "Servers", "id": "grp-srv"})
        service.create_device({
            "name": "test-srv", "host": "192.0.2.10",
            "device_type": "linux_server", "group_id": "grp-srv",
        })
        result = service.refresh_device("dev-test-srv", timeout=5)
        device = result.get("device", {})

        self.assertIsNotNone(device.get("cpu_percent"), "CPU must be collected despite df failure")
        self.assertIsNotNone(device.get("cpu_cores"))
        self.assertGreater(device.get("cpu_cores", 0), 0)
        self.assertIsNotNone(device.get("memory_percent"))
        self.assertIsNotNone(device.get("memory_total_mb"))
        self.assertIsNotNone(device.get("hostname"))
        self.assertIsNotNone(device.get("uname"))
        self.assertIsInstance(device.get("network_interfaces"), list)
        self.assertTrue(len(device.get("network_interfaces", [])) > 0)

        self.assertEqual(len(device.get("partitions", [])), 0,
                         "partitions should be empty when df fails and no fallback data")
        self.assertIn("disk_partitions", device.get("unavailable_metrics", []))

    def test_collector_errors_contain_structured_fields(self):
        store = SQLiteStore()
        collector = FaultInjectingCollector(fail_keys={"df", "meminfo"})
        service = MonitoringService(store, collector_service=CollectorService(
            collector, sample_interval=0.0, data_source="ssh", is_real_data=True
        ))
        service.create_group({"name": "S", "id": "g"})
        service.create_device({
            "name": "s", "host": "198.51.100.1",
            "device_type": "linux_server", "group_id": "g",
        })
        result = service.refresh_device("dev-s", timeout=5)
        device = result.get("device", {})
        errors = device.get("collector_errors", [])

        self.assertGreaterEqual(len(errors), 2,
                                "should have at least 2 errors for df and meminfo failure")
        required_keys = {"command_id", "command", "exit_code", "stderr", "stdout", "error_type"}
        for e in errors:
            for k in required_keys:
                self.assertIn(k, e, f"error dict missing key: {k}")

        err_ids = {e["command_id"] for e in errors}
        self.assertIn("df", err_ids)
        self.assertIn("meminfo", err_ids)

    def test_timeout_error_identifies_specific_command(self):
        store = SQLiteStore()
        collector = FaultInjectingCollector(
            fail_keys={"stat_1"}, error_type="timeout",
        )
        service = MonitoringService(store, collector_service=CollectorService(
            collector, sample_interval=0.0, data_source="ssh", is_real_data=True
        ))
        service.create_group({"name": "G", "id": "g-tmo"})
        service.create_device({
            "name": "tmo", "host": "198.51.100.2",
            "device_type": "linux_server", "group_id": "g-tmo",
        })
        result = service.refresh_device("dev-tmo", timeout=5)
        device = result.get("device", {})
        errors = device.get("collector_errors", [])

        stat_errors = [e for e in errors if e.get("command_id") == "stat_1"]
        self.assertEqual(len(stat_errors), 1,
                         "should have exactly one error for stat_1 timeout")
        self.assertEqual(stat_errors[0]["error_type"], "timeout")
        self.assertEqual(stat_errors[0]["command_id"], "stat_1")

        # Other metrics should still be collected
        self.assertIsNotNone(device.get("hostname"))
        self.assertIsNotNone(device.get("uname"))

    def test_command_failure_preserves_data_source_flag(self):
        store = SQLiteStore()
        collector = FaultInjectingCollector(fail_keys={"df", "uptime"})
        service = MonitoringService(store, collector_service=CollectorService(
            collector, sample_interval=0.0, data_source="ssh", is_real_data=True
        ))
        service.create_group({"name": "G", "id": "g-ds"})
        service.create_device({
            "name": "ds-test", "host": "192.0.2.77",
            "device_type": "linux_server", "group_id": "g-ds",
        })
        result = service.refresh_device("dev-ds-test", timeout=5)
        device = result.get("device", {})

        self.assertEqual(device.get("data_source"), "ssh",
                         "data_source must stay 'ssh' after command failures")
        self.assertEqual(device.get("is_real_data"), True,
                         "is_real_data must stay True after command failures")
        errors = device.get("collector_errors", [])
        self.assertGreaterEqual(len(errors), 1,
                                "should have at least one collector error")

    def test_df_fallback_tries_alternatives(self):
        store = SQLiteStore()
        collector = DfFallbackMockCollector()
        service = MonitoringService(store, collector_service=CollectorService(
            collector, sample_interval=0.0, data_source="ssh", is_real_data=True
        ))
        service.create_group({"name": "G", "id": "g-fb"})
        service.create_device({
            "name": "fb-test", "host": "198.51.100.3",
            "device_type": "linux_server", "group_id": "g-fb",
        })
        result = service.refresh_device("dev-fb-test", timeout=5)
        device = result.get("device", {})

        partitions = device.get("partitions", [])
        self.assertTrue(len(partitions) > 0,
                        f"df fallback should produce partitions, got {len(partitions)}")
        self.assertNotIn("disk_partitions", device.get("unavailable_metrics", []),
                         "df fallback succeeded, disk_partitions should NOT be unavailable")

        # Unit fix: fallback df -P reports 1K-blocks and must be parsed with
        # block_size=1024. Root disk is ~97.66 GiB, not ~0.1 GiB (bytes) nor
        # ~99942 GiB (1K-blocks misread as bytes->GiB without scaling).
        root_part = next((p for p in partitions if p.get("mount") == "/"), None)
        self.assertIsNotNone(root_part, "root partition must be present after fallback")
        self.assertAlmostEqual(root_part["total_gb"], 97.66, delta=1.0,
                               msg=f"fallback 1K-block unit wrong: got {root_part['total_gb']} GiB")
        self.assertGreater(root_part["total_gb"], 1.0,
                           "total_gb must be a realistic disk size, not a 1024x undersized value")

    def test_all_commands_fail_still_reports_data_source(self):
        store = SQLiteStore()
        collector = FaultInjectingCollector(fail_all=True)
        service = MonitoringService(store, collector_service=CollectorService(
            collector, sample_interval=0.0, data_source="ssh", is_real_data=True
        ))
        service.create_group({"name": "G", "id": "g-all"})
        service.create_device({
            "name": "all-fail", "host": "198.51.100.4",
            "device_type": "linux_server", "group_id": "g-all",
        })
        result = service.refresh_device("dev-all-fail", timeout=5)
        device = result.get("device", {})

        self.assertEqual(device.get("data_source"), "ssh")
        self.assertEqual(device.get("is_real_data"), True)
        errors = device.get("collector_errors", [])
        self.assertGreater(len(errors), 3)
        # All metrics should be unavailable
        unav = device.get("unavailable_metrics", [])
        self.assertGreater(len(unav), 3, "most metrics should be unavailable")


# ── device_type scoping & error bucketing tests ────────────────────

NAS_PROBE_KEYS = {
    "lsblk", "smartctl_scan", "mdstat", "zpool_list", "zpool_status",
    "zfs_list", "btrfs_show", "btrfs_device_stats", "btrfs_usage",
    "smartctl_sda", "smartctl_sdb",
}

PVE_LIGHT_DETECT_KEYS = {
    "detect_pveversion", "detect_pvesm", "detect_pve_dir",
}


def _make_service(collector):
    store = SQLiteStore()
    return MonitoringService(store, collector_service=CollectorService(
        collector, sample_interval=0.0, data_source="ssh", is_real_data=True
    ))


class DeviceTypeScopingTests(MonitoringContractTestCase):
    """device_type must control which probes are issued."""

    def _refresh(self, collector, device_type):
        service = _make_service(collector)
        service.create_group({"name": "G", "id": "g-scope"})
        service.create_device({
            "name": "dev-scope", "host": "192.0.2.50",
            "device_type": device_type, "group_id": "g-scope",
        })
        result = service.refresh_device("dev-dev-scope", timeout=5)
        return result, collector

    def test_linux_server_skips_nas_probes(self):
        collector = RecordingCollector()
        result, collector = self._refresh(collector, "linux_server")
        device = result["device"]

        # No NAS probe keys were ever sent to the collector
        sent_nas = NAS_PROBE_KEYS & collector.keys_seen
        self.assertEqual(sent_nas, set(), f"linux_server must not run NAS probes: {sent_nas}")
        # No capability probes either (NAS phase skipped entirely)
        self.assertFalse(any(k.startswith("cap_") for k in collector.keys_seen))

        # NAS metrics recorded as not_applicable (internal), not as errors
        not_applicable = device.get("not_applicable_indicators", [])
        self.assertIn("smartctl_scan", not_applicable)
        self.assertIn("zpool_list", not_applicable)
        self.assertIn("btrfs_show", not_applicable)
        # not_applicable must NOT leak into the compat unavailable_metrics
        self.assertNotIn("smartctl_scan", device.get("unavailable_metrics", []))
        # No critical errors, host stays healthy + verified
        self.assertEqual(device.get("critical_errors"), [])
        self.assertEqual(device.get("health_status"), "normal")
        self.assertEqual(device.get("verified"), True)

    def test_docker_host_skips_nas_but_runs_docker_probe(self):
        collector = RecordingCollector()
        result, collector = self._refresh(collector, "docker_host")
        device = result["device"]

        sent_nas = NAS_PROBE_KEYS & collector.keys_seen
        self.assertEqual(sent_nas, set(), f"docker_host must not run NAS probes: {sent_nas}")
        # docker capability + docker_info probe were issued
        self.assertIn("cap_docker", collector.keys_seen)
        self.assertIn("docker_info", collector.keys_seen)
        self.assertEqual(device.get("docker_info"), MOCK_FIXTURES["docker_info"])
        self.assertEqual(device.get("health_status"), "normal")
        self.assertEqual(device.get("verified"), True)

    def test_router_skips_nas_probes(self):
        for device_type in ("router", "openwrt", "other"):
            collector = RecordingCollector()
            result, collector = self._refresh(collector, device_type)
            device = result["device"]
            sent_nas = NAS_PROBE_KEYS & collector.keys_seen
            self.assertEqual(sent_nas, set(),
                             f"{device_type} must not run NAS probes: {sent_nas}")
            self.assertEqual(device.get("health_status"), "normal")

    def test_nas_runs_nas_probes(self):
        collector = RecordingCollector()
        result, collector = self._refresh(collector, "nas")
        device = result["device"]

        # NAS probes ARE issued for nas hosts
        self.assertIn("lsblk", collector.keys_seen)
        self.assertIn("smartctl_scan", collector.keys_seen)
        self.assertIn("mdstat", collector.keys_seen)
        # capability probes were sent
        self.assertTrue(any(k.startswith("cap_") for k in collector.keys_seen))
        # NAS data surfaces on the device
        self.assertIsInstance(device.get("nas_raid"), list)
        self.assertGreater(len(device.get("nas_raid", [])), 0)
        self.assertEqual(device.get("health_status"), "normal")
        self.assertEqual(device.get("verified"), True)


class ErrorBucketingTests(MonitoringContractTestCase):
    """command-not-found / optional failures must not become critical."""

    def test_command_not_found_is_not_critical(self):
        # zpool_list returns exit 127 / "command not found" -> not_applicable
        collector = RecordingCollector(
            fail_keys={"zpool_list"}, exit_code=127,
            stderr_tmpl="zpool: command not found",
        )
        service = _make_service(collector)
        service.create_group({"name": "G", "id": "g-cnf"})
        service.create_device({
            "name": "cnf", "host": "192.0.2.51", "device_type": "nas", "group_id": "g-cnf",
        })
        result = service.refresh_device("dev-cnf", timeout=5)
        device = result["device"]

        # The command-not-found must not appear in critical_errors
        crit_ids = {e.get("command_id") for e in device.get("critical_errors", [])}
        self.assertNotIn("zpool_list", crit_ids)
        # It is classified as not_applicable
        self.assertIn("zpool_list", device.get("not_applicable_indicators", []))
        # Host stays verified and non-critical
        self.assertEqual(device.get("verified"), True)
        self.assertNotEqual(device.get("health_status"), "critical")

    def test_non_btrfs_filesystem_skips_btrfs_probes(self):
        # Mock lsblk reports ext4 (no btrfs) -> btrfs commands must not run.
        collector = RecordingCollector()
        service = _make_service(collector)
        service.create_group({"name": "G", "id": "g-btr"})
        service.create_device({
            "name": "btr", "host": "192.0.2.52", "device_type": "nas", "group_id": "g-btr",
        })
        service.refresh_device("dev-btr", timeout=5)

        for btrfs_key in ("btrfs_show", "btrfs_device_stats", "btrfs_usage"):
            self.assertNotIn(btrfs_key, collector.keys_seen,
                             f"{btrfs_key} must not run on non-btrfs filesystem")
        # btrfs metrics marked not_applicable (not critical, not unavailable noise)

    def test_zpool_status_json_fallback_to_text(self):
        # zpool_status returns invalid JSON; zpool_status_text returns real text.
        zpool_text = (
            "  pool: tank\n"
            " state: ONLINE\n"
            " scan: scrub repaired 0B in 02:30:00\n"
            "errors: No known data errors\n"
        )
        data = dict(MOCK_FIXTURES)
        data["zpool_status"] = "zpool: unable to open //bad"  # non-JSON
        data["zpool_status_text"] = zpool_text
        collector = RecordingCollector(data=data)
        service = _make_service(collector)
        service.create_group({"name": "G", "id": "g-zp"})
        service.create_device({
            "name": "zp", "host": "192.0.2.53", "device_type": "nas", "group_id": "g-zp",
        })
        result = service.refresh_device("dev-zp", timeout=5)
        device = result["device"]

        pools = device.get("nas_pools", [])
        self.assertTrue(len(pools) > 0, "zpool text fallback should still produce pools")
        tank = next((p for p in pools if p.get("name") == "tank"), None)
        self.assertIsNotNone(tank, "tank pool must be parsed from text fallback")
        self.assertEqual(tank.get("health_state"), "ONLINE")

    def test_smartctl_no_phantom_device_names(self):
        # smartctl --scan-open returns a phantom entry /dev/bus/0 plus loop0
        # and a bare "0"; none should produce smartctl_0 / smartctl_loop0.
        phantom_scan = (
            '{"devices":['
            '{"name":"/dev/sda"},'
            '{"name":"/dev/bus/0"},'
            '{"name":"/dev/loop0"},'
            '{"name":"0"},'
            '{"name":"/dev/nvme0n1"}'
            ']}'
        )
        data = dict(MOCK_FIXTURES)
        data["smartctl_scan"] = phantom_scan
        collector = RecordingCollector(data=data)
        service = _make_service(collector)
        service.create_group({"name": "G", "id": "g-sm"})
        service.create_device({
            "name": "sm", "host": "192.0.2.54", "device_type": "nas", "group_id": "g-sm",
        })
        service.refresh_device("dev-sm", timeout=5)

        # No phantom smartctl probes
        self.assertNotIn("smartctl_0", collector.keys_seen)
        self.assertNotIn("smartctl_loop0", collector.keys_seen)
        self.assertNotIn("smartctl_bus", collector.keys_seen)
        # Real disks are probed
        self.assertIn("smartctl_sda", collector.keys_seen)
        self.assertIn("smartctl_nvme0n1", collector.keys_seen)


class DiskPercentSelectionTests(MonitoringContractTestCase):
    """disk_percent must prefer mount='/' over pseudo mounts."""

    def test_disk_percent_prefers_root_over_tmpfs_first(self):
        # tmpfs listed FIRST (would be df_partitions[0]); root listed second.
        df_tmpfs_first = (
            "Filesystem     1024-blocks      Used  Available Capacity Mounted on\n"
            "tmpfs              8144000         0    8144000       0% /dev/shm\n"
            "/dev/sda1        102400000  43999176   58359808      43% /\n"
        )
        data = dict(MOCK_FIXTURES)
        data["df"] = df_tmpfs_first
        collector = RecordingCollector(data=data)
        service = _make_service(collector)
        service.create_group({"name": "G", "id": "g-dp"})
        service.create_device({
            "name": "dp", "host": "192.0.2.55", "device_type": "linux_server", "group_id": "g-dp",
        })
        result = service.refresh_device("dev-dp", timeout=5)
        device = result["device"]

        # disk_percent must reflect root (43%), not tmpfs (0%)
        self.assertEqual(device.get("disk_percent"), 43.0,
                         f"disk_percent must use root partition, got {device.get('disk_percent')}")


class LinuxServerAcceptanceTests(MonitoringContractTestCase):
    """Acceptance: a plain linux_server with no NAS tools stays healthy."""

    def test_linux_server_clean_collection_is_normal(self):
        # A collector that returns no NAS fixtures at all (simulating a host
        # without smartctl/zpool/zfs/btrfs). linux_server never asks for them.
        collector = RecordingCollector()
        service = _make_service(collector)
        service.create_group({"name": "G", "id": "g-acc"})
        service.create_device({
            "name": "srv", "host": "192.0.2.60", "device_type": "linux_server", "group_id": "g-acc",
        })
        result = service.refresh_device("dev-srv", timeout=5)
        device = result["device"]

        # Core baseline metrics collected
        self.assertIsNotNone(device.get("hostname"))
        self.assertIsNotNone(device.get("cpu_percent"))
        self.assertIsNotNone(device.get("memory_percent"))
        self.assertIsInstance(device.get("partitions"), list)
        self.assertGreater(len(device.get("partitions", [])), 0)

        # No red collection errors; verified and healthy
        self.assertEqual(device.get("critical_errors"), [])
        self.assertEqual(device.get("collector_errors"), [])
        self.assertEqual(device.get("verified"), True)
        self.assertEqual(device.get("health_status"), "normal")
        self.assertEqual(device.get("online_status"), "online")
        # No active alerts at all
        active_alerts = [a for a in result.get("alerts", []) if a.get("status") == "active"]
        self.assertEqual(active_alerts, [])


class ProxmoxHostTests(MonitoringContractTestCase):
    """device_type=proxmox_host runs the PVE phase, not the NAS phase."""

    def test_proxmox_host_collects_pve_metrics(self):
        collector = RecordingCollector()
        service = _make_service(collector)
        service.create_group({"name": "G", "id": "g-pve"})
        service.create_device({
            "name": "pve", "host": "192.0.2.70", "device_type": "proxmox_host", "group_id": "g-pve",
        })
        result = service.refresh_device("dev-pve", timeout=5)
        device = result["device"]

        # PVE probes were issued
        self.assertIn("pveversion", collector.keys_seen)
        self.assertIn("pvesm", collector.keys_seen)
        self.assertIn("qm_list", collector.keys_seen)
        self.assertIn("pct_list", collector.keys_seen)
        self.assertIn("ip_br_addr", collector.keys_seen)

        # PVE fields surfaced
        self.assertEqual(device.get("pve_version"), "8.2.2")
        self.assertIsInstance(device.get("pve_storage"), list)
        self.assertGreater(len(device.get("pve_storage", [])), 0)
        self.assertEqual(device.get("pve_vm_total"), 3)
        self.assertEqual(device.get("pve_vm_running"), 2)
        self.assertEqual(device.get("pve_vm_stopped"), 1)
        self.assertEqual(device.get("pve_lxc_total"), 2)
        self.assertIsInstance(device.get("pve_interfaces"), list)

        # Core metrics + verified + healthy (optional PVE failures don't break it)
        self.assertIsNotNone(device.get("hostname"))
        self.assertEqual(device.get("verified"), True)
        self.assertNotEqual(device.get("health_status"), "critical")

    def test_proxmox_host_does_not_run_btrfs_by_default(self):
        collector = RecordingCollector()
        service = _make_service(collector)
        service.create_group({"name": "G", "id": "g-pve2"})
        service.create_device({
            "name": "pve2", "host": "192.0.2.71", "device_type": "proxmox_host", "group_id": "g-pve2",
        })
        service.refresh_device("dev-pve2", timeout=5)

        # Mock findmnt returns ext4 (not btrfs) -> btrfs commands never run
        for btrfs_key in ("btrfs_show", "btrfs_device_stats", "btrfs_usage"):
            self.assertNotIn(btrfs_key, collector.keys_seen)
        # btrfs recorded as not_applicable (not critical)
        # (not_applicable_indicators present on the device via latest_record payload)

    def test_proxmox_optional_failure_keeps_verified(self):
        # pvesm absent (cap_pvesm empty) -> pvesm not_applicable, not critical.
        data = dict(MOCK_FIXTURES)
        data["cap_pvesm"] = ""   # pvesm not installed
        data["cap_qm"] = ""
        data["cap_pct"] = ""
        collector = RecordingCollector(data=data)
        service = _make_service(collector)
        service.create_group({"name": "G", "id": "g-pve3"})
        service.create_device({
            "name": "pve3", "host": "192.0.2.72", "device_type": "proxmox_host", "group_id": "g-pve3",
        })
        result = service.refresh_device("dev-pve3", timeout=5)
        device = result["device"]

        # Optional PVE tools missing -> not_applicable, verified stays true
        self.assertEqual(device.get("verified"), True)
        self.assertNotEqual(device.get("health_status"), "critical")
        na = device.get("not_applicable_indicators", [])
        self.assertIn("pvesm", na)

    def test_non_proxmox_host_uses_only_lightweight_detection_when_not_pve(self):
        collector = RecordingCollector()
        service = _make_service(collector)
        service.create_group({"name": "G", "id": "g-pve-lite"})
        service.create_device({
            "name": "srv-lite", "host": "192.0.2.73", "device_type": "linux_server", "group_id": "g-pve-lite",
        })
        service.refresh_device("dev-srv-lite", timeout=5)

        self.assertTrue(PVE_LIGHT_DETECT_KEYS.issubset(collector.keys_seen))
        self.assertNotIn("pveversion", collector.keys_seen)
        self.assertNotIn("pvesm", collector.keys_seen)
        self.assertNotIn("qm_list", collector.keys_seen)
        self.assertNotIn("pct_list", collector.keys_seen)

    def test_non_proxmox_host_auto_detects_pve_from_any_lightweight_signal(self):
        detectors = {
            "detect_pveversion": "/usr/bin/pveversion\n",
            "detect_pvesm": "/usr/sbin/pvesm\n",
            "detect_pve_dir": "1\n",
        }
        for idx, (detector_key, detector_value) in enumerate(detectors.items(), start=1):
            with self.subTest(detector_key=detector_key):
                data = dict(MOCK_FIXTURES)
                data[detector_key] = detector_value
                collector = RecordingCollector(data=data)
                service = _make_service(collector)
                group_id = f"g-pve-auto-{idx}"
                device_id = f"dev-pve-auto-{idx}"
                service.create_group({"name": "G", "id": group_id})
                service.create_device({
                    "id": device_id,
                    "name": f"pve-auto-{idx}",
                    "host": f"192.0.2.8{idx}",
                    "device_type": "other",
                    "group_id": group_id,
                })
                result = service.refresh_device(device_id, timeout=5)
                device = result["device"]

                self.assertEqual(device.get("device_type"), "other")
                self.assertIn("pveversion", collector.keys_seen)
                self.assertIn("pvesm", collector.keys_seen)
                self.assertIn("qm_list", collector.keys_seen)
                self.assertNotIn("mdstat", collector.keys_seen)
                self.assertEqual(device.get("pve_version"), "8.2.2")
                self.assertGreater(device.get("pve_vm_total", 0), 0)


class CollectionIntervalTests(MonitoringContractTestCase):
    """collection_interval default/min/inheritance and settings."""

    def test_default_collection_interval_is_30(self):
        service = _make_service(RecordingCollector())
        service.create_group({"name": "G", "id": "g-ci"})
        dev = service.create_device({
            "name": "ci", "host": "198.51.100.9", "device_type": "linux_server", "group_id": "g-ci",
        })
        self.assertEqual(dev.get("collection_interval"), 30)

    def test_collection_interval_min_30(self):
        service = _make_service(RecordingCollector())
        service.create_group({"name": "G", "id": "g-ci2"})
        with self.assertRaises(Exception):
            service.create_device({
                "name": "ci2", "host": "198.51.100.8", "device_type": "linux_server",
                "group_id": "g-ci2", "collection_interval": 10,
            })

    def test_collection_settings_endpoint(self):
        from homeinfra.app import HomeInfraApp
        app = HomeInfraApp(
            static_dir="static", collector_mode="ssh",
            collector_service_override=CollectorService(
                RecordingCollector(), sample_interval=0.0, data_source="ssh", is_real_data=True),
        )
        app.auth.bootstrap_admin({"username": "admin", "password": "ExampleAdminPass123"})
        login = app.handle_api_request(
            method="POST", path="/api/v1/auth/login",
            headers={}, body={"username": "admin", "password": "ExampleAdminPass123"},
        )
        tok = (login[0].get("data", {}).get("token")) or (login[0].get("token"))
        res, _ = app.handle_api_request(
            method="GET", path="/api/v1/settings/collection",
            headers={"Authorization": "Bearer " + tok}, body=None,
        )
        self.assertEqual(res.get("default_collection_interval"), 30)
        res, _ = app.handle_api_request(
            method="PATCH", path="/api/v1/settings/collection",
            headers={"Authorization": "Bearer " + tok},
            body={"default_collection_interval": 60},
        )
        self.assertEqual(res.get("default_collection_interval"), 60)

    def test_run_scheduled_collection_runs_for_due_devices(self):
        collector = RecordingCollector()
        service = _make_service(collector)
        service.create_group({"name": "G", "id": "g-sch"})
        service.create_device({
            "name": "sch", "host": "198.51.100.7", "device_type": "linux_server", "group_id": "g-sch",
        })
        # Device has no last_seen -> immediately due
        n = service.run_scheduled_collection(timeout=5)
        self.assertGreaterEqual(n, 1)
        # After collection last_seen is set -> not due again immediately
        n2 = service.run_scheduled_collection(timeout=5)
        self.assertEqual(n2, 0)

    def test_scheduler_uses_service_monitoring_for_background_collection(self):
        class _FakeStop:
            def __init__(self):
                self._wait_calls = 0
                self._stopped = False

            def wait(self, _timeout):
                self._wait_calls += 1
                if self._wait_calls == 1:
                    return False
                self._stopped = True
                return True

            def is_set(self):
                return self._stopped

            def set(self):
                self._stopped = True

        collector = RecordingCollector()
        app = HomeInfraApp(
            static_dir="static",
            collector_mode="ssh",
            collector_service_override=CollectorService(
                collector, sample_interval=0.0, data_source="ssh", is_real_data=True
            ),
        )
        app.service.monitoring.create_group({"name": "G", "id": "g-sch-bg"})
        device = app.service.monitoring.create_device({
            "name": "sch-bg",
            "host": "198.51.100.8",
            "device_type": "linux_server",
            "group_id": "g-sch-bg",
        })
        scheduler = CollectionScheduler(app, tick_interval=1, timeout=5)
        scheduler._stop = _FakeStop()

        scheduler._loop()

        history = app.service.monitoring.list_collection_records(device_id=device["id"])
        self.assertGreaterEqual(len(history["records"]), 1)

import unittest
from pathlib import Path

from homeinfra.app import HomeInfraApp, MAX_JSON_BODY_BYTES, parse_json_object_body
from homeinfra.errors import ApiError


ROOT = Path(__file__).resolve().parent.parent


class RepoContractTests(unittest.TestCase):
    def test_docker_compose_uses_host_bind_in_ports(self):
        compose_text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn('${HOST_BIND:-127.0.0.1}:${HOST_PORT:-8010}:${APP_PORT:-8000}', compose_text)

    def test_dockerfile_uses_runtime_env_for_app_host_and_port(self):
        dockerfile_text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn('CMD ["python", "/app/run.py", "--static-dir", "/app/static"]', dockerfile_text)
        self.assertNotIn('--host", "0.0.0.0"', dockerfile_text)

    def test_env_example_documents_container_and_host_bind_separately(self):
        env_text = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn("APP_HOST=0.0.0.0", env_text)
        self.assertIn("HOST_BIND=127.0.0.1", env_text)
        self.assertIn("Container listen address", env_text)
        self.assertIn("Host-side bind address", env_text)

    def test_github_actions_ci_file_exists(self):
        workflow_path = ROOT / ".github" / "workflows" / "ci.yml"
        self.assertTrue(workflow_path.exists())
        workflow_text = workflow_path.read_text(encoding="utf-8")
        self.assertIn("python3 -m unittest -v", workflow_text)
        self.assertIn("node --check static/app.js", workflow_text)
        self.assertIn("python3 -m compileall homeinfra run.py tests", workflow_text)

    def test_frontend_vendors_chart_js_locally(self):
        index_text = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        chart_vendor = ROOT / "static" / "vendor" / "chart.umd.min.js"
        self.assertTrue(chart_vendor.exists())
        self.assertIn('./vendor/chart.umd.min.js', index_text)
        self.assertNotIn("https://cdn.jsdelivr.net", index_text)

    def test_oversized_json_body_returns_413(self):
        oversized_length = MAX_JSON_BODY_BYTES + 1
        with self.assertRaises(ApiError) as ctx:
            parse_json_object_body(b'{"username":"admin"}', content_length=oversized_length)
        self.assertEqual(ctx.exception.code, "payload_too_large")
        self.assertEqual(ctx.exception.status, 413)
        self.assertEqual(ctx.exception.details["max_bytes"], MAX_JSON_BODY_BYTES)
        self.assertEqual(ctx.exception.details["received_bytes"], oversized_length)

    def test_client_ip_extraction_ignores_untrusted_proxy_headers(self):
        app = HomeInfraApp(static_dir="static")
        client_ip = app.extract_client_ip(
            {"x-forwarded-for": "203.0.113.55", "x-real-ip": "203.0.113.56"},
            fallback="127.0.0.1",
        )
        self.assertEqual(client_ip, "127.0.0.1")

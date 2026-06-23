from pathlib import Path
import re
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = PROJECT_ROOT / "static"


class FrontendSmokeTests(unittest.TestCase):
    def read_static(self, filename):
        path = STATIC_DIR / filename
        self.assertTrue(path.exists(), f"Missing static asset: {path}")
        text = path.read_text(encoding="utf-8")
        self.assertNotEqual(text.strip(), "", f"{filename} must not be empty")
        self.assertNotIn("<<<<<<<", text, f"{filename} contains merge conflict markers")
        self.assertNotIn(">>>>>>>", text, f"{filename} contains merge conflict markers")
        return text

    def test_index_references_app_and_styles(self):
        html = self.read_static("index.html")

        self.assertRegex(html, r"<html\b", "index.html should be a full HTML document")
        self.assertRegex(html, r"<title>[^<]+</title>", "index.html needs a title")
        self.assertIn("styles.css", html)
        self.assertIn("app.js", html)
        self.assertRegex(
            html,
            r'id=["\'](?:app|root)["\']',
            "index.html should expose a stable frontend mount point",
        )

    def test_app_js_mounts_without_document_write(self):
        script = self.read_static("app.js")

        self.assertNotIn("document.write", script)
        self.assertRegex(
            script,
            r"DOMContentLoaded|getElementById|querySelector",
            "app.js should attach to the existing DOM instead of relying on load order",
        )
        self.assertRegex(
            script,
            r"nas|vpn|automation|alert",
            "app.js should render infrastructure dashboard concepts",
        )

    def test_styles_define_responsive_dashboard_basics(self):
        css = self.read_static("styles.css")

        self.assertRegex(css, r":root|body\s*{", "styles.css should define base styles")
        self.assertRegex(
            css,
            r"grid|flex",
            "styles.css should provide dashboard layout primitives",
        )
        self.assertRegex(
            css,
            r"@media|max-width|min-width",
            "styles.css should include at least one responsive rule",
        )
        self.assertIsNone(
            re.search(r"font-size\s*:\s*\d+(?:\.\d+)?vw\b", css),
            "Avoid viewport-width font scaling because it causes unstable text fitting",
        )

    def test_app_js_references_phase1_contract_fields(self):
        script = self.read_static("app.js")

        self.assertRegex(script, r"hostname", "app.js must render hostname from device")
        self.assertRegex(script, r"uname", "app.js must render uname from device")
        self.assertRegex(script, r"data_source", "app.js must show data_source indicator")
        self.assertRegex(script, r"collector_errors", "app.js must display collector_errors")
        self.assertRegex(script, r"unavailable_metrics", "app.js must display unavailable_metrics")

    def test_app_js_data_source_truthiness_labels(self):
        script = self.read_static("app.js")

        self.assertIn("真实 SSH 数据", script)
        self.assertIn("采集已禁用 / 无可用数据", script)
        self.assertIn("未验证", script)
        self.assertIn("采集错误", script)
        self.assertIn("指标不可用", script)

    def test_app_js_references_health_and_bucket_fields(self):
        """New backend compatibility fields must be consumed by the UI."""
        script = self.read_static("app.js")

        # Health display
        self.assertIn("health_status", script)
        self.assertIn("online_status", script)
        self.assertIn("正常", script)
        self.assertIn("警告", script)
        self.assertIn("异常", script)

        # Error bucketing
        self.assertIn("critical_errors", script)
        self.assertIn("permission_warnings", script)
        self.assertIn("optional_warnings", script)
        self.assertIn("unavailable_indicators", script)
        self.assertIn("not_applicable_indicators", script)
        self.assertIn("probe_summary", script)

        # not_applicable must be collapsed (details/summary), not a red error
        self.assertIn("<details", script)
        self.assertIn("严重错误", script)
        self.assertIn("权限警告", script)
        self.assertIn("可选功能警告", script)

    def test_app_js_probe_applicability_label_and_filter(self):
        """Probe applicability chips + split status filters."""
        script = self.read_static("app.js")

        # No misleading "能力探测" wording; chips use ✔/✗ applicability.
        self.assertNotIn("能力探测", script)
        self.assertNotIn("探测适用性：", script)

        # Health / online / enabled are three INDEPENDENT filter dimensions
        self.assertIn("devHealth", script)
        self.assertIn("devOnline", script)
        self.assertIn('value="normal"', script)
        self.assertIn('value="critical"', script)
        self.assertIn('value="offline"', script)
        self.assertIn("d.health_status", script)
        self.assertIn("d.online_status", script)

    def test_app_js_pve_detail_and_form(self):
        """PVE device type + PVE detail sections must be implemented."""
        script = self.read_static("app.js")
        # device_type dropdown includes proxmox_host
        self.assertIn('value="proxmox_host"', script)
        # PVE detail sections
        self.assertIn("pveDetailHtml", script)
        self.assertIn("PVE 版本", script)
        self.assertIn("VM / LXC", script)
        self.assertIn("PVE 存储", script)
        self.assertIn("网络桥接", script)
        self.assertIn("ZFS 池", script)
        self.assertIn("SMART 摘要", script)

    def test_app_js_collection_interval_advanced_settings(self):
        """collection_interval hidden on add, in advanced settings on edit."""
        script = self.read_static("app.js")
        # Advanced settings collapsed section on edit
        self.assertIn("高级设置", script)
        self.assertIn("后端采集周期", script)
        self.assertIn('min="30"', script)
        # collection_interval only sent on edit (id present)
        self.assertIn("if (id && form.collection_interval)", script)

    def test_app_js_settings_page_collection_setting(self):
        """Settings page exposes the backend collection interval setting."""
        script = self.read_static("app.js")
        self.assertIn("loadCollectionSettings", script)
        self.assertIn("saveCollectionSettings", script)
        self.assertIn("/settings/collection", script)
        self.assertIn("default_collection_interval", script)

    def test_app_js_auto_refresh_defaults_and_label(self):
        """Auto-refresh defaults to 10s / on, min 5s, labeled 页面自动刷新."""
        script = self.read_static("app.js")
        self.assertIn("页面自动刷新", script)
        # default period 10, on by default first visit
        self.assertIn("'hinfra_ar') === null ? true", script)
        self.assertIn("|| 10", script)

    def test_app_js_no_helper_text_or_placeholders_or_tooltips(self):
        """No helper text, placeholder examples, or tooltip explanations."""
        script = self.read_static("app.js")
        # No tooltip explanations in title attributes on capability chips
        self.assertNotIn('title="适用于当前设备类型"', script)
        self.assertNotIn('title="当前设备类型不适用', script)
        # No legend hint text
        self.assertNotIn("✔ 适用于本设备类型", script)
        self.assertNotIn("不适用已跳过", script)
        # Device form / search have no placeholder examples
        self.assertNotIn('placeholder="留空不修改"', script)
        self.assertNotIn('placeholder="用逗号分隔"', script)
        self.assertNotIn('placeholder="🔍 搜索', script)
        self.assertNotIn("auth-subtitle", script)
        self.assertNotIn('placeholder="3-64位字母数字"', script)
        self.assertNotIn('placeholder="至少8位"', script)
        self.assertNotIn('placeholder="再次输入密码"', script)

    def test_app_js_device_list_three_status_columns(self):
        """Device list must render health / online / enabled as separate columns."""
        script = self.read_static("app.js")
        self.assertIn("健康状态", script)
        self.assertIn("在线状态", script)
        self.assertIn("启用状态", script)
        self.assertIn("healthBadge", script)
        self.assertIn("onlineBadge", script)
        self.assertIn("enabledBadge", script)

    def test_app_js_auto_refresh_and_loading(self):
        """Auto-refresh + operation loading + timeout must be implemented."""
        script = self.read_static("app.js")
        # Auto-refresh controls
        self.assertIn("setAutoRefresh", script)
        self.assertIn("setRefreshPeriod", script)
        self.assertIn("startRefreshTimer", script)
        self.assertIn("stopRefreshTimer", script)
        self.assertIn("refresh-countdown", script)
        self.assertIn("refresh-last", script)
        # Single timer guard (no duplicate setInterval)
        self.assertIn("clearInterval(_refreshTimer)", script)
        # Operation loading + long-op progress + 30s timeout
        self.assertIn("S.busy", script)
        self.assertIn("runLongOp", script)
        self.assertIn("已等待", script)
        self.assertIn("最多等待 ", script)
        self.assertIn("操作超时", script)
        # Loading button labels
        self.assertIn("刷新中…", script)
        self.assertIn("测试中…", script)
        self.assertIn("保存中…", script)
        self.assertIn("删除中…", script)
        # Success/failure toasts with reasons
        self.assertIn("SSH 测试成功", script)
        self.assertIn("SSH 测试失败", script)
        self.assertIn("刷新完成", script)
        self.assertIn("刷新失败", script)
        self.assertIn("保存成功", script)
        self.assertIn("保存失败", script)

    def test_app_js_keeps_legacy_fields_for_backward_compat(self):
        """Old collector_errors / unavailable_metrics must still render for old data."""
        script = self.read_static("app.js")
        self.assertIn("collector_errors", script)
        self.assertIn("unavailable_metrics", script)

    def test_app_js_search_input_preserves_focus_and_value(self):
        """Search input must stay focused and keep its value across renders."""
        script = self.read_static("app.js")

        # Search input has a stable id + value bound to devSearch (so a full
        # render restores what the user typed instead of clearing it).
        self.assertIn('id="dev-search-input"', script)
        self.assertRegex(script, r'value="\' \+ esc\(devSearch\)')

        # Filter changes swap only #dev-table-wrap, NOT the whole page — so the
        # search input is never rebuilt (and never loses focus) while typing.
        self.assertIn("renderDevTable", script)
        self.assertIn('oninput="devSearch=this.value;renderDevTable()"', script)
        self.assertIn("dev-table-wrap", script)

        # render() restores focus + cursor if an input was focused.
        self.assertIn("document.activeElement", script)
        self.assertIn("setSelectionRange", script)

    def test_app_js_auto_refresh_does_not_clear_search(self):
        """Auto-refresh on the devices page must not rebuild the filter bar."""
        script = self.read_static("app.js")
        # doAutoRefresh swaps only the table on the devices page.
        self.assertIn("if (S.page === 'devices') renderDevTable()", script)

    def test_app_js_long_op_aborts_and_no_double_callback(self):
        """Long ops must AbortController-abort fetch on timeout and not double-fire."""
        script = self.read_static("app.js")

        # AbortController is created and wired into the fetch signal.
        self.assertIn("new AbortController()", script)
        self.assertIn("ac.abort()", script)
        self.assertIn("asyncFn(ac.signal)", script)
        # API client forwards signal to fetch.
        self.assertIn("if (signal) init.signal = signal", script)
        # The `done` guard prevents onDone/onFail being called twice (the abort
        # rejection that follows a timeout must be a no-op).
        self.assertIn("if (done) return", script)
        # Timeout restores button state (setBusy false) and shows a message.
        self.assertIn("操作超时：", script)

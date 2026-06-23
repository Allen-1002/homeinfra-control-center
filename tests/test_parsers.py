"""Unit tests for homeinfra.parsers using static fixture files."""

import os
import unittest
from pathlib import Path

from homeinfra.parsers import (
    compute_cpu_percent,
    compute_network_rates,
    parse_df_P_B1,
    parse_hostname,
    parse_ip_br_addr,
    parse_loadavg,
    parse_meminfo,
    parse_pct_list,
    parse_proc_net_dev,
    parse_proc_stat,
    parse_pveversion,
    parse_pvesm_status,
    parse_qm_list,
    parse_uname,
    parse_uptime,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


class ParserUnitTests(unittest.TestCase):
    def test_parse_hostname(self):
        text = _read_fixture("hostname.txt")
        result = parse_hostname(text)
        self.assertEqual(result, "test-host")

    def test_parse_hostname_empty(self):
        self.assertIsNone(parse_hostname(""))
        self.assertIsNone(parse_hostname(None))

    def test_parse_uname(self):
        text = _read_fixture("uname.txt")
        result = parse_uname(text)
        self.assertTrue(result.startswith("Linux"))

    def test_parse_uname_empty(self):
        self.assertIsNone(parse_uname(""))
        self.assertIsNone(parse_uname(None))

    def test_parse_uptime(self):
        text = _read_fixture("proc_uptime.txt")
        result = parse_uptime(text)
        self.assertAlmostEqual(result, 630576.28, places=1)

    def test_parse_uptime_empty(self):
        self.assertIsNone(parse_uptime(""))
        self.assertIsNone(parse_uptime(None))

    def test_parse_loadavg(self):
        text = _read_fixture("proc_loadavg.txt")
        result = parse_loadavg(text)
        self.assertIsNotNone(result)
        self.assertAlmostEqual(result["load_1m"], 0.32)
        self.assertAlmostEqual(result["load_5m"], 0.28)
        self.assertAlmostEqual(result["load_15m"], 0.21)

    def test_parse_loadavg_empty(self):
        self.assertIsNone(parse_loadavg(""))
        self.assertIsNone(parse_loadavg(None))

    def test_parse_meminfo_full(self):
        text = _read_fixture("proc_meminfo.txt")
        result = parse_meminfo(text)
        self.assertIsNotNone(result)
        total = 16284996 / 1024  # kB to MB
        self.assertAlmostEqual(result["memory_total_mb"], total, places=0)
        self.assertGreater(result["memory_total_mb"], 0)
        self.assertGreater(result["memory_used_mb"], 0)
        self.assertLessEqual(result["memory_used_mb"], result["memory_total_mb"])
        self.assertAlmostEqual(result["memory_used_mb"], total - (8220460 / 1024.0), places=0)
        self.assertAlmostEqual(result["memory_percent"], result["memory_used_mb"] / result["memory_total_mb"] * 100, places=0)
        self.assertGreater(result["memory_swap_total_mb"], 0)

    def test_parse_meminfo_empty(self):
        self.assertIsNone(parse_meminfo(""))
        self.assertIsNone(parse_meminfo(None))

    def test_parse_df_P_B1(self):
        text = _read_fixture("df_P_B1.txt")
        result = parse_df_P_B1(text)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(len(result), 2)

        root_part = next(p for p in result if p["mount"] == "/")
        self.assertGreater(root_part["size_gb"], 0)
        self.assertGreater(root_part["used_gb"], 0)
        self.assertAlmostEqual(root_part["usage_percent"], 43.0, places=0)

        data_part = next(p for p in result if p["mount"] == "/data")
        self.assertAlmostEqual(data_part["usage_percent"], 62.0, places=0)

    def test_parse_df_P_B1_empty(self):
        self.assertIsNone(parse_df_P_B1(""))
        self.assertIsNone(parse_df_P_B1(None))

    def test_parse_df_bytes_block_size_1(self):
        # df -P -B1 reports sizes in bytes; block_size=1 (default) is correct.
        result = parse_df_P_B1(_read_fixture("df_P_B1.txt"))
        self.assertIsNotNone(result)
        root_part = next(p for p in result if p["mount"] == "/")
        # 104857600000 bytes ~= 97.66 GiB
        self.assertAlmostEqual(root_part["size_gb"], 97.66, places=1)
        self.assertGreater(root_part["used_gb"], 0)

    def test_parse_df_1k_blocks_block_size_1024(self):
        # df -P / df report sizes in 1K-blocks; must pass block_size=1024.
        result = parse_df_P_B1(_read_fixture("df_P.txt"), block_size=1024)
        self.assertIsNotNone(result)
        root_part = next(p for p in result if p["mount"] == "/")
        # 102400000 * 1024 bytes ~= 97.66 GiB (same disk as byte fixture)
        self.assertAlmostEqual(root_part["size_gb"], 97.66, places=1)
        self.assertAlmostEqual(root_part["usage_percent"], 43.0, places=0)

    def test_parse_df_1k_blocks_wrong_unit_shrinks_1024x(self):
        # Demonstrates the bug: parsing 1K-block output with default block_size=1
        # yields a value ~1024x too small.
        result = parse_df_P_B1(_read_fixture("df_P.txt"))
        self.assertIsNotNone(result)
        root_part = next(p for p in result if p["mount"] == "/")
        self.assertLess(root_part["size_gb"], 1.0,
                        "1K-block values parsed as bytes must be ~1024x too small")

    def test_parse_proc_stat(self):
        text = _read_fixture("proc_stat.txt")
        result = parse_proc_stat(text)
        self.assertIsNotNone(result)
        self.assertIn("cpu", result)
        self.assertEqual(len(result["cpu"]), 10)
        self.assertIn("cpu_cores", result)
        self.assertEqual(len(result["cpu_cores"]), 4)

    def test_parse_proc_stat_empty(self):
        self.assertIsNone(parse_proc_stat(""))
        self.assertIsNone(parse_proc_stat(None))

    def test_compute_cpu_percent(self):
        stat1 = parse_proc_stat(_read_fixture("proc_stat.txt"))
        stat2 = parse_proc_stat(_read_fixture("proc_stat_2.txt"))
        result = compute_cpu_percent(stat1, stat2, elapsed_seconds=1.0)
        self.assertIsNotNone(result)
        self.assertGreater(result["cpu_percent"], 0)
        self.assertLessEqual(result["cpu_percent"], 100)
        self.assertEqual(result["cpu_cores"], 4)
        self.assertEqual(len(result["per_core_cpu"]), 4)
        for core in result["per_core_cpu"]:
            self.assertIn("core", core)
            self.assertIn("percent", core)
            self.assertGreaterEqual(core["percent"], 0)
            self.assertLessEqual(core["percent"], 100)

    def test_compute_cpu_percent_none_input(self):
        stat = parse_proc_stat(_read_fixture("proc_stat.txt"))
        self.assertIsNone(compute_cpu_percent(None, stat, 1.0))
        self.assertIsNone(compute_cpu_percent(stat, None, 1.0))
        self.assertIsNone(compute_cpu_percent(stat, stat, 0.0))
        self.assertIsNone(compute_cpu_percent(stat, stat, -1.0))

    def test_parse_proc_net_dev(self):
        text = _read_fixture("proc_net_dev.txt")
        result = parse_proc_net_dev(text)
        self.assertIsNotNone(result)
        interfaces = result["interfaces"]
        self.assertEqual(len(interfaces), 2)
        names = [iface["name"] for iface in interfaces]
        self.assertIn("eth0", names)
        self.assertIn("eth1", names)
        self.assertNotIn("lo", names)

    def test_parse_proc_net_dev_empty(self):
        self.assertIsNone(parse_proc_net_dev(""))
        self.assertIsNone(parse_proc_net_dev(None))

    def test_compute_network_rates(self):
        net1 = parse_proc_net_dev(_read_fixture("proc_net_dev.txt"))
        net2 = parse_proc_net_dev(_read_fixture("proc_net_dev_2.txt"))
        result = compute_network_rates(net1, net2, elapsed_seconds=1.0)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2)
        for iface in result:
            self.assertIn("name", iface)
            self.assertIn("rx_mbps", iface)
            self.assertIn("tx_mbps", iface)
            self.assertIn("rx_bytes_total", iface)
            self.assertIn("tx_bytes_total", iface)

    def test_compute_network_rates_none_input(self):
        net = parse_proc_net_dev(_read_fixture("proc_net_dev.txt"))
        self.assertIsNone(compute_network_rates(None, net, 1.0))
        self.assertIsNone(compute_network_rates(net, None, 1.0))
        self.assertIsNone(compute_network_rates(net, net, 0.0))
        self.assertIsNone(compute_network_rates(net, net, -1.0))


class PveParserTests(unittest.TestCase):
    def test_parse_pveversion(self):
        self.assertEqual(parse_pveversion("pve-manager/8.2.2/9a2c43f0 (running kernel: 6.8.4-2-pve)\n"), "8.2.2")

    def test_parse_pveversion_empty(self):
        self.assertIsNone(parse_pveversion(""))
        self.assertIsNone(parse_pveversion(None))

    def test_parse_pvesm_status(self):
        text = "Name             Type     Status           Total         Used    Available percent\n" \
               "local             dir     active    104857600000  45097156608  59760443392       43\n" \
               "local-lvm         lvm     active    214748364800  64424509440 150323855360       30\n"
        result = parse_pvesm_status(text)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["storage"], "local")
        self.assertEqual(result[0]["type"], "dir")
        self.assertEqual(result[0]["status"], "active")
        self.assertEqual(result[0]["percent"], 43.0)
        self.assertEqual(result[1]["storage"], "local-lvm")

    def test_parse_pvesm_status_empty(self):
        self.assertIsNone(parse_pvesm_status(""))

    def test_parse_qm_list(self):
        text = "  VMID Name                 Status      Mem(MB)    Bootdisk(GB) \n" \
               "   100 vm-100               running    4096       32\n" \
               "   101 vm-101               stopped    2048       20\n"
        result = parse_qm_list(text)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["id"], "100")
        self.assertEqual(result[0]["name"], "vm-100")
        self.assertEqual(result[0]["status"], "running")
        self.assertEqual(result[1]["status"], "stopped")

    def test_parse_pct_list(self):
        text = "  CTID Name                 Status      Mem(MB)    \n" \
               "   200 ct-200               running    1024       \n"
        result = parse_pct_list(text)
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["id"], "200")
        self.assertEqual(result[0]["status"], "running")

    def test_parse_ip_br_addr(self):
        text = "vmbr0   UP             192.0.2.10/24  \neno1   UP             198.51.100.5/24  \n"
        result = parse_ip_br_addr(text)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2)
        self.assertTrue(result[0]["is_bridge"])
        self.assertTrue(result[1]["is_physical"])
        self.assertIn("192.0.2.10/24", result[0]["ip_addresses"])

    def test_parse_ip_br_addr_empty(self):
        self.assertIsNone(parse_ip_br_addr(""))


if __name__ == "__main__":
    unittest.main()

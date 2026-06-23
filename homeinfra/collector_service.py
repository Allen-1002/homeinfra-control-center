"""Collector service orchestrator - defines probes, executes via collector,
parses raw outputs, and assembles contract payloads.

Supports two-phase sampling (CPU and network rates) with real elapsed time.

Probe selection is driven by ``device_type`` and runtime capability checks
(``command -v``) so that non-NAS hosts (linux_server, docker_host, router, ...)
are not issued NAS-only commands (smartctl/zpool/zfs/btrfs/mdadm). Optional
tool failures are bucketed (critical/permission/optional/unavailable/
not_applicable) so they do not pollute critical collection errors."""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any

from .collectors import BaseSSHCollector, CollectorError
from .contracts import CollectionResult, LinuxHostMetrics
from .parsers import (
    compute_cpu_percent,
    compute_network_rates,
    parse_btrfs_device_stats,
    parse_btrfs_filesystem_show,
    parse_btrfs_filesystem_usage,
    parse_df_P_B1,
    parse_hostname,
    parse_ip_br_addr,
    parse_ip_s_link,
    parse_loadavg,
    parse_lsblk_json,
    parse_mdstat,
    parse_meminfo,
    parse_pct_list,
    parse_proc_net_dev,
    parse_proc_stat,
    parse_pveversion,
    parse_pvesm_status,
    parse_qm_list,
    parse_smartctl_health_json,
    parse_smartctl_scan_json,
    parse_uname,
    parse_uptime,
    parse_zfs_list,
    parse_zpool_list,
    parse_zpool_status_json,
    parse_zpool_status_text,
)

# ── Phase 1 baseline probe definitions (all device types) ──────

ONE_SHOT_PROBES: list[tuple[str, str]] = [
    ("hostname", "hostname"),
    ("uname", "uname -a"),
    ("uptime", "cat /proc/uptime"),
    ("loadavg", "cat /proc/loadavg"),
    ("meminfo", "cat /proc/meminfo"),
]

DF_PRIMARY: tuple[str, str] = ("df", "df -P -B1")
DF_FALLBACKS: list[tuple[str, str]] = [
    ("df", "df -P"),
    ("df", "df"),
]

BATCH1_EXTRAS: list[tuple[str, str]] = [
    ("stat_1", "cat /proc/stat"),
    ("net_1", "cat /proc/net/dev"),
]

BATCH2_PROBES: list[tuple[str, str]] = [
    ("stat_2", "cat /proc/stat"),
    ("net_2", "cat /proc/net/dev"),
]

# ── Phase 2 NAS probe commands (issued only for NAS-capable hosts) ──

LSBLK_CMD = "lsblk -J -b -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL,SERIAL,ROTA,TRAN"
SMARTCTL_SCAN_OPEN_CMD = "smartctl --scan-open -j"
SMARTCTL_SCAN_CMD = "smartctl --scan -j"
ZPOOL_LIST_CMD = "zpool list -H -p"
ZPOOL_STATUS_JSON_CMD = "zpool status -j"
ZPOOL_STATUS_CMD = "zpool status"
ZFS_LIST_CMD = "zfs list -H -p -o name,type,used,available,referenced,mountpoint,creation"
BTRFS_SHOW_CMD = "btrfs filesystem show --raw"
BTRFS_DEV_STATS_CMD = "btrfs device stats /"
BTRFS_USAGE_CMD = "btrfs filesystem usage -b /"
MDSTAT_CMD = "cat /proc/mdstat"
FINDMNT_ROOT_CMD = "findmnt -no FSTYPE /"
DOCKER_INFO_CMD = "docker info"

# ── Proxmox VE (PVE) probe commands ──
PVEVERSION_CMD = "pveversion"
PVESM_STATUS_CMD = "pvesm status"
QM_LIST_CMD = "qm list"
PCT_LIST_CMD = "pct list"
IP_BR_ADDR_CMD = "ip -br addr"
IP_S_LINK_CMD = "ip -s link"

PVE_CAPABILITY_PROBES: list[tuple[str, str]] = [
    ("cap_pveversion", "command -v pveversion"),
    ("cap_pvesm", "command -v pvesm"),
    ("cap_qm", "command -v qm"),
    ("cap_pct", "command -v pct"),
    ("cap_zpool", "command -v zpool"),
    ("cap_zfs", "command -v zfs"),
    ("cap_smartctl", "command -v smartctl"),
    ("cap_btrfs", "command -v btrfs"),
    ("cap_findmnt", "command -v findmnt"),
    ("cap_ip", "command -v ip"),
]

PVE_DETECTION_PROBES: list[tuple[str, str]] = [
    ("detect_pveversion", "command -v pveversion"),
    ("detect_pvesm", "command -v pvesm"),
    ("detect_pve_dir", "test -d /etc/pve && echo 1"),
]

# command -v probes determine which optional tools exist before running them.
CAPABILITY_PROBES: list[tuple[str, str]] = [
    ("cap_lsblk", "command -v lsblk"),
    ("cap_smartctl", "command -v smartctl"),
    ("cap_zpool", "command -v zpool"),
    ("cap_zfs", "command -v zfs"),
    ("cap_btrfs", "command -v btrfs"),
    ("cap_findmnt", "command -v findmnt"),
    ("cap_docker", "command -v docker"),
    ("cap_pveversion", "command -v pveversion"),
    ("cap_pvesm", "command -v pvesm"),
]

# Baseline command ids whose failure is considered critical (core metrics).
BASELINE_KEYS: set[str] = {
    "hostname", "uname", "uptime", "loadavg", "meminfo",
    "stat_1", "net_1", "stat_2", "net_2", "df",
}

# device_type -> allowed probe scope.
NAS_CAPABLE_TYPES: set[str] = {"nas"}
DOCKER_CAPABLE_TYPES: set[str] = {"docker_host"}
PROXMOX_TYPE: str = "proxmox_host"

# NAS metric names recorded as not_applicable when the host type skips NAS.
NAS_METRIC_NAMES: list[str] = [
    "lsblk", "smartctl_scan", "smart_attributes", "mdstat",
    "zpool_list", "zpool_status", "zfs_list",
    "btrfs_show", "btrfs_device_stats", "btrfs_usage",
]

# PVE metric names recorded as not_applicable when the host is not PVE.
PVE_METRIC_NAMES: list[str] = [
    "pveversion", "pvesm", "qm_list", "pct_list",
    "ip_br_addr", "ip_s_link",
]

# Mounts/devices that do not represent the system primary disk.
_PSEUDO_DEVICES: set[str] = {
    "tmpfs", "devtmpfs", "overlay", "squashfs", "9p", "none", "cgroup", "mqueue", "shm",
}
_PSEUDO_MOUNT_PREFIXES: tuple[str, ...] = (
    "/dev/shm", "/run", "/boot", "/var/lib/docker", "/var/lib/containerd", "/snap",
)

# Non-physical disk name prefixes filtered from smartctl enumeration.
_NON_PHYSICAL_DISK_PREFIXES: tuple[str, ...] = ("loop", "zram", "ram", "dm-", "md", "sr", "rom")


# ── Error classification helpers ───────────────────────────────

def _is_command_not_found(err: dict[str, Any]) -> bool:
    if err.get("exit_code") == 127:
        return True
    stderr = (err.get("stderr") or "").lower()
    return any(tok in stderr for tok in ("not found", "command not found", "no such file or directory"))


def _is_permission_denied(err: dict[str, Any]) -> bool:
    if err.get("exit_code") == 126:
        return True
    stderr = (err.get("stderr") or "").lower()
    return "permission denied" in stderr


def _normalize_smart_device(name: str) -> str | None:
    """Normalize a smartctl scan device path to a physical disk name.

    ``/dev/sda`` -> ``sda``; ``/dev/nvme0n1`` -> ``nvme0n1``;
    ``/dev/sdb -d sat`` -> ``sdb``. Returns None for non-physical or phantom
    names (loop/zram/dm/md/sr/rom, pure digits, partitions) so that no
    ``smartctl_0`` style phantom probe is ever generated.
    """
    if not name:
        return None
    base = str(name).split()[0]
    dev = base.split("/")[-1]
    if not dev:
        return None
    lower = dev.lower()
    if lower.isdigit():
        return None
    if any(lower.startswith(pref) for pref in _NON_PHYSICAL_DISK_PREFIXES):
        return None
    if re.match(r"^(sd|hd|vd)[a-z]+\d+$", lower):
        return None
    if re.match(r"^nvme\d+n\d+p\d+$", lower):
        return None
    return dev


def _is_pseudo_partition(part: dict[str, Any]) -> bool:
    dev = (part.get("device") or "").lower()
    mount = part.get("mount") or ""
    if dev in _PSEUDO_DEVICES:
        return True
    for pref in _PSEUDO_MOUNT_PREFIXES:
        if mount == pref or mount.startswith(pref + "/"):
            return True
    return False


def _select_disk_percent(partitions: list[dict[str, Any]]) -> float | None:
    """Pick the system disk usage percent: prefer mount=='/', else the first
    real (non-pseudo) partition, else the first partition."""
    if not partitions:
        return None
    for p in partitions:
        if p.get("mount") == "/":
            return p.get("percent")
    for p in partitions:
        if not _is_pseudo_partition(p):
            return p.get("percent")
    return partitions[0].get("percent")


class ErrorBuckets:
    """Five-bucket classification of collection outcomes.

    ``critical``/``permission``/``optional`` hold structured error dicts;
    ``unavailable``/``not_applicable`` hold metric-name strings.
    """

    def __init__(self) -> None:
        self.critical: list[dict[str, Any]] = []
        self.permission: list[dict[str, Any]] = []
        self.optional: list[dict[str, Any]] = []
        self.unavailable: list[str] = []
        self.not_applicable: list[str] = []

    def classify(self, err: dict[str, Any]) -> None:
        cid = str(err.get("command_id", ""))
        if cid.startswith("cap_"):
            return  # capability probe outcomes are not collection errors
        if _is_command_not_found(err):
            self.not_applicable.append(cid)
            return
        if _is_permission_denied(err):
            self.permission.append(err)
            return
        if cid in BASELINE_KEYS:
            self.critical.append(err)
            return
        self.optional.append(err)

    @property
    def all_command_errors(self) -> list[dict[str, Any]]:
        return self.critical + self.permission + self.optional

    @property
    def has_blocking_errors(self) -> bool:
        return bool(self.critical or self.permission or self.optional)

    def summary(self) -> dict[str, Any]:
        return {
            "critical_error_count": len(self.critical),
            "permission_warning_count": len(self.permission),
            "optional_error_count": len(self.optional),
            "unavailable_count": len(self.unavailable),
            "not_applicable_count": len(self.not_applicable),
        }


class CollectorService:
    """Orchestrates collection: defines probes, executes, parses, assembles."""

    def __init__(
        self,
        collector: BaseSSHCollector,
        *,
        sample_interval: float = 1.0,
        data_source: str = "unknown",
        is_real_data: bool = False,
    ) -> None:
        self.collector = collector
        self.sample_interval = max(0.0, sample_interval)
        self._data_source = data_source
        self._is_real_data = is_real_data

    def collect(
        self, device: dict[str, Any], *, timeout: int, purpose: str
    ) -> CollectionResult:
        """Execute collection for a device, scoped by device_type and capabilities.

        Individual command failures are isolated — they do not crash the
        entire collection. Only SSH connect/auth failures raise CollectorError.
        """
        if timeout <= 0:
            raise CollectorError("timeout must be positive", status="warning")

        t_start = time.monotonic()
        buckets = ErrorBuckets()
        device_type = device.get("device_type", "other")

        # ── Batch 1: baseline one-shot probes + first stat/net samples ──
        # NAS probes are NOT issued unconditionally; they run only for
        # NAS-capable hosts via _run_nas_phase after capability checks.
        batch1 = list(ONE_SHOT_PROBES) + BATCH1_EXTRAS
        results_1, errs_1 = self.collector.execute_commands(device, batch1, timeout=timeout)
        for err in errs_1:
            buckets.classify(err)

        # ── df: primary -B1 (bytes), then fallbacks (1K-blocks) ──
        # DF_PRIMARY ``df -P -B1`` reports sizes in bytes (block_size=1).
        # When -B1 is unsupported (BusyBox/older df), fall back to ``df -P`` /
        # ``df`` which report 1K-blocks (block_size=1024). The block_size is
        # passed to the parser so GiB conversion is correct for either unit.
        df_block_size = 1
        df_resolved = False
        df_errors: list[dict[str, Any]] = []
        try:
            df_prim_results, df_prim_errs = self.collector.execute_commands(
                device, [DF_PRIMARY], timeout=timeout
            )
            if df_prim_results.get("df"):
                results_1["df"] = df_prim_results["df"]
                df_resolved = True
            else:
                df_errors.extend(df_prim_errs)
        except CollectorError:
            pass

        if not df_resolved:
            for fb_key, fb_cmd in DF_FALLBACKS:
                try:
                    fb_results, fb_errs = self.collector.execute_commands(
                        device, [(fb_key, fb_cmd)], timeout=timeout
                    )
                    if fb_results.get(fb_key):
                        results_1["df"] = fb_results[fb_key]
                        df_block_size = 1024
                        df_resolved = True
                        df_errors.clear()
                        break
                    df_errors.extend(fb_errs)
                except CollectorError:
                    continue
            if not df_resolved:
                buckets.unavailable.append("disk_partitions")
        # Classify at most one df error (avoid triple-counting primary+fallbacks)
        for err in df_errors[:1]:
            buckets.classify(err)

        raw: dict[str, str] = dict(results_1)

        # ── Phase 2: type-specific probes ──
        is_pve = device_type == PROXMOX_TYPE or self._detect_pve_host(device, timeout)
        if is_pve:
            self._run_pve_phase(device, raw, buckets, timeout)
        elif device_type in NAS_CAPABLE_TYPES:
            self._run_nas_phase(device, raw, buckets, timeout)
        else:
            buckets.not_applicable.extend(NAS_METRIC_NAMES)
            buckets.not_applicable.extend(PVE_METRIC_NAMES)

        # ── Docker probes (only for docker_host) ──
        if device_type in DOCKER_CAPABLE_TYPES:
            self._run_docker_phase(device, raw, buckets, timeout)

        # ── Sleep for two-phase sampling ──
        t1 = time.monotonic()
        if self.sample_interval > 0:
            time.sleep(self.sample_interval)
        t2 = time.monotonic()
        elapsed = t2 - t1

        # ── Batch 2: second stat/net samples ──
        results_2, errs_2 = self.collector.execute_commands(device, BATCH2_PROBES, timeout=timeout)
        for err in errs_2:
            buckets.classify(err)
        raw.update(results_2)

        # ── Parse and assemble ──
        payload = self._assemble_payload(raw, elapsed, buckets, df_block_size, device_type, is_pve)

        # Determine overall status: optional/permission failures degrade to
        # warning but never critical (critical is reserved for SSH-level
        # failures handled by CollectorError). unavailable/not_applicable do
        # not affect status, so a linux_server skipping NAS stays healthy.
        status = "warning" if buckets.has_blocking_errors else "healthy"
        if status == "healthy":
            summary = "SSH 只读探测完成"
        else:
            summary = "SSH 探测完成（部分命令失败）"

        elapsed_ms = (time.monotonic() - t_start) * 1000

        return CollectionResult(
            collector=self.collector.name,
            command="ssh probe (multi-exec per connection)",
            status=status,
            summary=summary,
            payload=payload,
            data_source=self._data_source,
            is_real_data=self._is_real_data,
            connection_duration_ms=round(elapsed_ms, 1),
        )

    # ── Phase 2 orchestration ──────────────────────────────────

    def _detect_pve_host(self, device: dict[str, Any], timeout: int) -> bool:
        """Cheap PVE detection for non-proxmox_host devices.

        This runs at most three lightweight checks so we can route obvious PVE
        boxes into the PVE phase without issuing the full PVE capability matrix
        to every host.
        """
        detect_res, _ = self._safe_execute(device, PVE_DETECTION_PROBES, timeout)
        return bool(
            (detect_res.get("detect_pveversion") or "").strip()
            or (detect_res.get("detect_pvesm") or "").strip()
            or (detect_res.get("detect_pve_dir") or "").strip()
        )

    def _run_nas_phase(
        self, device: dict[str, Any], raw: dict[str, str], buckets: ErrorBuckets, timeout: int
    ) -> None:
        """Run NAS probes for NAS-capable hosts, gated by capability + fstype."""
        cap_res, _ = self.collector.execute_commands(device, CAPABILITY_PROBES, timeout=timeout)
        # capability probe (command -v) errors are dropped by classify; an empty
        # result means the tool is absent -> capability False.
        tools = ("lsblk", "smartctl", "zpool", "zfs", "btrfs", "findmnt", "docker", "pveversion", "pvesm")
        caps = {t: bool(cap_res.get(f"cap_{t}")) for t in tools}

        # lsblk first (needed for block devices + btrfs fstype detection)
        if caps["lsblk"]:
            r, e = self._safe_execute(device, [("lsblk", LSBLK_CMD)], timeout)
            raw["lsblk"] = r.get("lsblk", "")
            for err in e:
                buckets.classify(err)
        else:
            buckets.not_applicable.append("lsblk")

        # btrfs fstype pre-check: only run btrfs commands on btrfs filesystems
        has_btrfs = False
        if raw.get("lsblk"):
            block_devices = parse_lsblk_json(raw["lsblk"])
            if block_devices:
                has_btrfs = any(b.get("fstype") == "btrfs" for b in block_devices)
        if not has_btrfs and caps["findmnt"]:
            r, e = self._safe_execute(device, [("findmnt_root", FINDMNT_ROOT_CMD)], timeout)
            if (r.get("findmnt_root", "") or "").strip() == "btrfs":
                has_btrfs = True
            for err in e:
                buckets.classify(err)

        # Build the NAS probe list based on capabilities and fstype
        probes: list[tuple[str, str]] = [("mdstat", MDSTAT_CMD)]
        if caps["smartctl"]:
            probes.append(("smartctl_scan", SMARTCTL_SCAN_OPEN_CMD))
        else:
            buckets.not_applicable.extend(["smartctl_scan", "smart_attributes"])
        if caps["zpool"]:
            probes.append(("zpool_list", ZPOOL_LIST_CMD))
            probes.append(("zpool_status", ZPOOL_STATUS_JSON_CMD))
        else:
            buckets.not_applicable.extend(["zpool_list", "zpool_status"])
        if caps["zfs"]:
            probes.append(("zfs_list", ZFS_LIST_CMD))
        else:
            buckets.not_applicable.append("zfs_list")
        if caps["btrfs"] and has_btrfs:
            probes.append(("btrfs_show", BTRFS_SHOW_CMD))
            probes.append(("btrfs_device_stats", BTRFS_DEV_STATS_CMD))
            probes.append(("btrfs_usage", BTRFS_USAGE_CMD))
        else:
            buckets.not_applicable.extend(["btrfs_show", "btrfs_device_stats", "btrfs_usage"])
        if caps["pvesm"]:
            probes.append(("pvesm", "pvesm status"))

        r, e = self._safe_execute(device, probes, timeout)
        raw.update(r)
        for err in e:
            buckets.classify(err)

        # smartctl --scan-open fallback + per-drive (normalized names)
        self._run_smartctl_drives(device, raw, buckets, caps, timeout)
        # zpool status -j fallback to text
        self._run_zpool_status_fallback(device, raw, buckets, caps, timeout)

    def _run_pve_phase(
        self, device: dict[str, Any], raw: dict[str, str], buckets: ErrorBuckets, timeout: int
    ) -> None:
        """Run Proxmox VE probes for proxmox_host devices.

        PVE is NOT treated as NAS: it does not run mdstat/btrfs by default and
        adds pveversion/pvesm/qm/pct/network probes. ZFS and SMART are reused
        (capability-gated). btrfs only runs if a btrfs filesystem is detected.
        """
        cap_res, _ = self._safe_execute(device, PVE_CAPABILITY_PROBES, timeout)
        tools = ("pveversion", "pvesm", "qm", "pct", "zpool", "zfs", "smartctl", "btrfs", "findmnt", "ip")
        caps = {t: bool(cap_res.get(f"cap_{t}")) for t in tools}

        # btrfs fstype pre-check (PVE does not run btrfs unless fs is btrfs)
        has_btrfs = False
        if caps["findmnt"]:
            r, e = self._safe_execute(device, [("findmnt_root", FINDMNT_ROOT_CMD)], timeout)
            if (r.get("findmnt_root", "") or "").strip() == "btrfs":
                has_btrfs = True
            for err in e:
                buckets.classify(err)

        probes: list[tuple[str, str]] = []
        # PVE core
        if caps["pveversion"]:
            probes.append(("pveversion", PVEVERSION_CMD))
        else:
            buckets.not_applicable.append("pveversion")
        if caps["pvesm"]:
            probes.append(("pvesm", PVESM_STATUS_CMD))
        else:
            buckets.not_applicable.append("pvesm")
        if caps["qm"]:
            probes.append(("qm_list", QM_LIST_CMD))
        else:
            buckets.not_applicable.append("qm_list")
        if caps["pct"]:
            probes.append(("pct_list", PCT_LIST_CMD))
        else:
            buckets.not_applicable.append("pct_list")
        # ZFS
        if caps["zpool"]:
            probes.append(("zpool_list", ZPOOL_LIST_CMD))
            probes.append(("zpool_status", ZPOOL_STATUS_JSON_CMD))
        else:
            buckets.not_applicable.extend(["zpool_list", "zpool_status"])
        if caps["zfs"]:
            probes.append(("zfs_list", ZFS_LIST_CMD))
        else:
            buckets.not_applicable.append("zfs_list")
        # SMART
        if caps["smartctl"]:
            probes.append(("smartctl_scan", SMARTCTL_SCAN_OPEN_CMD))
        else:
            buckets.not_applicable.extend(["smartctl_scan", "smart_attributes"])
        # Network
        if caps["ip"]:
            probes.append(("ip_br_addr", IP_BR_ADDR_CMD))
            probes.append(("ip_s_link", IP_S_LINK_CMD))
        else:
            buckets.not_applicable.extend(["ip_br_addr", "ip_s_link"])
        # btrfs (only on btrfs filesystems)
        if caps["btrfs"] and has_btrfs:
            probes.append(("btrfs_show", BTRFS_SHOW_CMD))
            probes.append(("btrfs_device_stats", BTRFS_DEV_STATS_CMD))
            probes.append(("btrfs_usage", BTRFS_USAGE_CMD))
        else:
            buckets.not_applicable.extend(["btrfs_show", "btrfs_device_stats", "btrfs_usage"])

        r, e = self._safe_execute(device, probes, timeout)
        raw.update(r)
        for err in e:
            buckets.classify(err)

        self._run_smartctl_drives(device, raw, buckets, caps, timeout)
        self._run_zpool_status_fallback(device, raw, buckets, caps, timeout)

    def _run_docker_phase(
        self, device: dict[str, Any], raw: dict[str, str], buckets: ErrorBuckets, timeout: int
    ) -> None:
        """Run a lightweight docker probe for docker_host devices."""
        cap_res, _ = self._safe_execute(device, [("cap_docker", "command -v docker")], timeout)
        if cap_res.get("cap_docker"):
            r, e = self._safe_execute(device, [("docker_info", DOCKER_INFO_CMD)], timeout)
            raw["docker_info"] = r.get("docker_info", "")
            for err in e:
                buckets.classify(err)
        else:
            buckets.not_applicable.append("docker_info")

    def _run_smartctl_drives(
        self, device: dict[str, Any], raw: dict[str, str], buckets: ErrorBuckets,
        caps: dict[str, bool], timeout: int,
    ) -> None:
        if not caps.get("smartctl"):
            return
        scan_raw = raw.get("smartctl_scan", "")
        drives = parse_smartctl_scan_json(scan_raw) if scan_raw else None
        if not drives:
            # --scan-open unsupported / permission / empty -> fallback to --scan
            r, e = self._safe_execute(device, [("smartctl_scan", SMARTCTL_SCAN_CMD)], timeout)
            scan_raw = r.get("smartctl_scan", "")
            if scan_raw:
                raw["smartctl_scan"] = scan_raw
            drives = parse_smartctl_scan_json(scan_raw) if scan_raw else None
            for err in e:
                buckets.classify(err)
        if not drives:
            return
        smart_probes: list[tuple[str, str]] = []
        seen: set[str] = set()
        for drive in drives:
            dev = _normalize_smart_device(drive)
            if not dev or dev in seen:
                continue
            seen.add(dev)
            smart_probes.append((f"smartctl_{dev}", f"smartctl -a -j /dev/{dev}"))
        if not smart_probes:
            return
        r, e = self._safe_execute(device, smart_probes, timeout)
        raw.update(r)
        for err in e:
            buckets.classify(err)

    def _run_zpool_status_fallback(
        self, device: dict[str, Any], raw: dict[str, str], buckets: ErrorBuckets,
        caps: dict[str, bool], timeout: int,
    ) -> None:
        if not caps.get("zpool"):
            return
        if parse_zpool_status_json(raw.get("zpool_status", "")) is not None:
            return  # JSON path succeeded
        r, e = self._safe_execute(device, [("zpool_status_text", ZPOOL_STATUS_CMD)], timeout)
        if r.get("zpool_status_text"):
            raw["zpool_status_text"] = r["zpool_status_text"]
        for err in e:
            buckets.classify(err)

    def _safe_execute(
        self, device: dict[str, Any], probes: list[tuple[str, str]], timeout: int
    ) -> tuple[dict[str, str], list[dict[str, Any]]]:
        """execute_commands wrapper that swallows CollectorError (SSH already up)."""
        try:
            return self.collector.execute_commands(device, probes, timeout=timeout)
        except CollectorError:
            return {}, []

    def _assemble_payload(
        self,
        raw: dict[str, str],
        elapsed: float,
        buckets: ErrorBuckets,
        df_block_size: int,
        device_type: str,
        is_pve: bool = False,
    ) -> dict[str, Any]:
        """Parse all raw outputs and assemble the LinuxHostMetrics contract payload."""
        hostname = parse_hostname(raw.get("hostname", ""))
        if hostname is None:
            buckets.unavailable.append("hostname")

        uname_val = parse_uname(raw.get("uname", ""))
        if uname_val is None:
            buckets.unavailable.append("uname")

        uptime_sec = parse_uptime(raw.get("uptime", ""))
        if uptime_sec is None:
            buckets.unavailable.append("uptime")

        loadavg = parse_loadavg(raw.get("loadavg", ""))
        if loadavg is None:
            buckets.unavailable.append("loadavg")

        meminfo = parse_meminfo(raw.get("meminfo", ""))
        if meminfo is None:
            buckets.unavailable.append("meminfo")

        df_partitions = parse_df_P_B1(raw.get("df", ""), block_size=df_block_size)
        if df_partitions is None:
            buckets.unavailable.append("df")

        proc_stat1 = parse_proc_stat(raw.get("stat_1", ""))
        proc_stat2 = parse_proc_stat(raw.get("stat_2", ""))
        cpu_data = compute_cpu_percent(proc_stat1, proc_stat2, elapsed)
        if cpu_data is None:
            buckets.unavailable.append("cpu")

        net_dev1 = parse_proc_net_dev(raw.get("net_1", ""))
        net_dev2 = parse_proc_net_dev(raw.get("net_2", ""))
        net_rates = compute_network_rates(net_dev1, net_dev2, elapsed)
        if net_rates is None:
            buckets.unavailable.append("network")

        load_1m = loadavg["load_1m"] if loadavg else None
        load_5m = loadavg["load_5m"] if loadavg else None
        load_15m = loadavg["load_15m"] if loadavg else None
        load_str = f"{load_1m} {load_5m} {load_15m}" if loadavg else None

        payload: dict[str, Any] = {}
        if hostname:
            payload["hostname"] = hostname
        if uname_val:
            payload["uname"] = uname_val
        if uptime_sec is not None:
            payload["uptime"] = _format_uptime(uptime_sec)
        if load_str:
            payload["load_average"] = load_str
        if cpu_data:
            payload["cpu_percent"] = cpu_data["cpu_percent"]
            payload["cpu_cores"] = cpu_data["cpu_cores"]
            payload["per_core_cpu"] = cpu_data["per_core_cpu"]
        if meminfo:
            payload["memory_percent"] = round(meminfo["memory_percent"], 1)
            payload["memory_total_mb"] = round(meminfo["memory_total_mb"], 1)
            payload["memory_used_mb"] = round(meminfo["memory_used_mb"], 1)
            payload["memory_buffers_mb"] = round(meminfo["memory_buffers_mb"], 1)
            payload["memory_cached_mb"] = round(meminfo["memory_cached_mb"], 1)
            payload["memory_swap_total_mb"] = round(meminfo["memory_swap_total_mb"], 1)
            payload["memory_swap_used_mb"] = round(meminfo["memory_swap_used_mb"], 1)
        if df_partitions:
            for p in df_partitions:
                p["total_gb"] = p.pop("size_gb", 0)
                p["percent"] = p.pop("usage_percent", 0)
            payload["disk_percent"] = _select_disk_percent(df_partitions)
            payload["partitions"] = df_partitions
        if net_rates:
            total_rx = sum(i["rx_mbps"] for i in net_rates)
            total_tx = sum(i["tx_mbps"] for i in net_rates)
            payload["network_rx_mbps"] = round(total_rx, 1)
            payload["network_tx_mbps"] = round(total_tx, 1)
            payload["network_interfaces"] = net_rates

        # ── Phase 2: type-specific parsing ──
        if is_pve or device_type == PROXMOX_TYPE:
            self._parse_pve_metrics(raw, payload, buckets)
        elif device_type in NAS_CAPABLE_TYPES:
            self._parse_nas_metrics(raw, payload, buckets)

        # ── Docker parsing (only for docker_host) ──
        if device_type in DOCKER_CAPABLE_TYPES and raw.get("docker_info"):
            payload["docker_info"] = raw["docker_info"]

        # ── Error buckets + backward-compatible aliases ──
        payload["critical_errors"] = list(buckets.critical)
        payload["permission_warnings"] = list(buckets.permission)
        payload["optional_warnings"] = list(buckets.optional)
        payload["unavailable_indicators"] = list(buckets.unavailable)
        payload["not_applicable_indicators"] = list(buckets.not_applicable)
        # Backward compatibility: collector_errors aggregates the structured
        # command errors; unavailable_metrics aggregates parse-unavailable names
        # only (not_applicable is kept separate to avoid noisy "not applicable"
        # entries on non-NAS hosts).
        payload["errors"] = list(buckets.all_command_errors)
        payload["unavailable_metrics"] = list(buckets.unavailable)
        payload["probe_summary"] = buckets.summary()

        return payload

    def _parse_nas_metrics(
        self, raw: dict[str, str], payload: dict[str, Any], buckets: ErrorBuckets
    ) -> None:
        """Parse NAS-specific raw outputs into the payload."""
        block_devices = parse_lsblk_json(raw.get("lsblk", ""))
        if block_devices is None:
            buckets.unavailable.append("lsblk")
        else:
            payload["block_devices"] = block_devices

        smart_attributes_all: list[dict[str, Any]] = []
        for k, v in raw.items():
            if k.startswith("smartctl_") and k != "smartctl_scan":
                drive_smart = parse_smartctl_health_json(v)
                if drive_smart:
                    drive_name = k.replace("smartctl_", "")
                    for attr in drive_smart:
                        if "drive" not in attr:
                            attr["drive"] = drive_name
                    smart_attributes_all.extend(drive_smart)
        if not smart_attributes_all:
            buckets.unavailable.append("smart_attributes")
        else:
            smart_attributes_all.sort(key=lambda a: (a.get("drive", ""), a.get("attr_name", "")))
            payload["smart_attributes"] = smart_attributes_all

        md = parse_mdstat(raw.get("mdstat", ""))
        if md is None:
            buckets.unavailable.append("mdstat")
        else:
            payload["nas_raid"] = md

        zpool = parse_zpool_list(raw.get("zpool_list", ""))
        # prefer zpool status JSON, fall back to text parser
        zpool_status = parse_zpool_status_json(raw.get("zpool_status", ""))
        if zpool_status is None:
            zpool_status = parse_zpool_status_text(raw.get("zpool_status_text", ""))
        if zpool is not None and zpool_status is not None:
            health_map = {s["name"]: s for s in zpool_status}
            for pool in zpool:
                hs = health_map.get(pool["name"], {})
                pool["health_state"] = hs.get("health_state") or pool.get("health_state", "UNKNOWN")
        if zpool is None:
            buckets.unavailable.append("zpool_list")
        else:
            payload["nas_pools"] = zpool

        zfs = parse_zfs_list(raw.get("zfs_list", ""))
        if zfs is None:
            buckets.unavailable.append("zfs_list")
        else:
            if zfs.get("volumes"):
                payload["nas_volumes"] = zfs["volumes"]
            if zfs.get("snapshots"):
                payload["nas_snapshots"] = zfs["snapshots"]

        btrfs_show = parse_btrfs_filesystem_show(raw.get("btrfs_show", ""))
        if btrfs_show is None:
            buckets.unavailable.append("btrfs_show")
        else:
            payload["btrfs_filesystems"] = btrfs_show

        btrfs_dev_stats = parse_btrfs_device_stats(raw.get("btrfs_device_stats", ""))
        if btrfs_dev_stats is None:
            buckets.unavailable.append("btrfs_device_stats")
        else:
            payload["btrfs_device_stats"] = btrfs_dev_stats

        btrfs_usage = parse_btrfs_filesystem_usage(raw.get("btrfs_usage", ""))
        if btrfs_usage is None:
            buckets.unavailable.append("btrfs_usage")
        else:
            payload["btrfs_usage"] = btrfs_usage

        return payload

    def _parse_pve_metrics(
        self, raw: dict[str, str], payload: dict[str, Any], buckets: ErrorBuckets
    ) -> None:
        """Parse PVE-specific raw outputs into the payload."""
        # PVE version
        pve_ver = parse_pveversion(raw.get("pveversion", ""))
        if pve_ver is None:
            buckets.unavailable.append("pveversion")
        else:
            payload["pve_version"] = pve_ver

        # PVE storage (pvesm status)
        pve_storage = parse_pvesm_status(raw.get("pvesm", ""))
        if pve_storage is None:
            buckets.unavailable.append("pvesm")
        else:
            payload["pve_storage"] = pve_storage

        # VM list (qm list)
        vms = parse_qm_list(raw.get("qm_list", ""))
        if vms is None:
            buckets.unavailable.append("qm_list")
        else:
            payload["pve_vms"] = vms
            payload["pve_vm_total"] = len(vms)
            payload["pve_vm_running"] = sum(1 for v in vms if str(v.get("status", "")).lower() == "running")
            payload["pve_vm_stopped"] = sum(1 for v in vms if str(v.get("status", "")).lower() == "stopped")

        # LXC list (pct list)
        lxcs = parse_pct_list(raw.get("pct_list", ""))
        if lxcs is None:
            buckets.unavailable.append("pct_list")
        else:
            payload["pve_lxcs"] = lxcs
            payload["pve_lxc_total"] = len(lxcs)
            payload["pve_lxc_running"] = sum(1 for c in lxcs if str(c.get("status", "")).lower() == "running")
            payload["pve_lxc_stopped"] = sum(1 for c in lxcs if str(c.get("status", "")).lower() == "stopped")

        # ZFS pools (reused from NAS parsing)
        zpool = parse_zpool_list(raw.get("zpool_list", ""))
        zpool_status = parse_zpool_status_json(raw.get("zpool_status", ""))
        if zpool_status is None:
            zpool_status = parse_zpool_status_text(raw.get("zpool_status_text", ""))
        if zpool is not None and zpool_status is not None:
            health_map = {s["name"]: s for s in zpool_status}
            for pool in zpool:
                hs = health_map.get(pool["name"], {})
                pool["health_state"] = hs.get("health_state") or pool.get("health_state", "UNKNOWN")
        if zpool is None:
            buckets.unavailable.append("zpool_list")
        else:
            payload["nas_pools"] = zpool

        zfs = parse_zfs_list(raw.get("zfs_list", ""))
        if zfs is None:
            buckets.unavailable.append("zfs_list")
        else:
            if zfs.get("volumes"):
                payload["nas_volumes"] = zfs["volumes"]
            if zfs.get("snapshots"):
                payload["nas_snapshots"] = zfs["snapshots"]

        # SMART attributes (reused)
        smart_attributes_all: list[dict[str, Any]] = []
        for k, v in raw.items():
            if k.startswith("smartctl_") and k != "smartctl_scan":
                drive_smart = parse_smartctl_health_json(v)
                if drive_smart:
                    drive_name = k.replace("smartctl_", "")
                    for attr in drive_smart:
                        if "drive" not in attr:
                            attr["drive"] = drive_name
                    smart_attributes_all.extend(drive_smart)
        if not smart_attributes_all:
            buckets.unavailable.append("smart_attributes")
        else:
            smart_attributes_all.sort(key=lambda a: (a.get("drive", ""), a.get("attr_name", "")))
            payload["smart_attributes"] = smart_attributes_all

        # Network (ip -br addr + ip -s link)
        ip_br = parse_ip_br_addr(raw.get("ip_br_addr", ""))
        ip_link = parse_ip_s_link(raw.get("ip_s_link", ""))
        if ip_br is None and ip_link is None:
            buckets.unavailable.extend(["ip_br_addr", "ip_s_link"])
        else:
            interfaces = ip_br or []
            link_map = {i["name"]: i for i in (ip_link or [])}
            for iface in interfaces:
                lk = link_map.get(iface["name"])
                if lk:
                    iface["rx_bytes"] = lk.get("rx_bytes", 0)
                    iface["tx_bytes"] = lk.get("tx_bytes", 0)
            payload["pve_interfaces"] = interfaces

        # btrfs (only present if btrfs fs was detected)
        btrfs_show = parse_btrfs_filesystem_show(raw.get("btrfs_show", ""))
        if btrfs_show is not None:
            payload["btrfs_filesystems"] = btrfs_show

        return


def _format_uptime(total_seconds: float) -> str:
    remaining = int(total_seconds)
    days = remaining // 86400
    hours = (remaining % 86400) // 3600
    minutes = (remaining % 3600) // 60
    seconds = remaining % 60
    parts = []
    if days > 0:
        parts.append(f"{days} day{'s' if days > 1 else ''}")
    parts.append(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
    return " ".join(parts)

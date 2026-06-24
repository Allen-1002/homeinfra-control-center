"""Device collection abstractions with safe SSH, host-key management, and retry.

Collectors execute individual commands and return raw outputs keyed by probe name.
The CollectorService orchestrates probes, parsing, and two-phase sampling."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("homeinfra.collectors")
EXTERNAL_SECRET_SENTINEL = "__external_secret__"


# ── Command whitelist (read-only, expanded per device type) ──────

BANNED_COMMAND_TOKENS = (
    "rm ", "dd ", "mkfs", "reboot", "shutdown", "iptables ", "poweroff",
    "systemctl stop", "systemctl restart", "systemctl kill", "halt",
    "init 0", "init 6", "kill ", "pkill ", "killall ",
    "chmod ", "chown ", "mount ", "umount ", "fdisk", "parted",
    "> ", ">>", "| sh", "$(", "`",
)

COMMAND_VALIDATION_PATTERN = re.compile(r"^[a-zA-Z0-9\s/_.\-%;:=,&\'\"\[\]\*?><|$]+$")


def command_allowed(command: str) -> bool:
    """Check that command is read-only and contains no dangerous tokens."""
    normalized = (command or "").strip()
    if not normalized:
        return False
    if not COMMAND_VALIDATION_PATTERN.match(normalized):
        return False
    lower = normalized.lower()
    for token in BANNED_COMMAND_TOKENS:
        if token in lower:
            return False
    return True


# ── Host key management ────────────────────────────────────────

@dataclass
class HostKeyEntry:
    hostname: str
    key_type: str
    key_base64: str

    @property
    def fingerprint_sha256(self) -> str:
        raw = self.key_base64.encode()
        return hashlib.sha256(raw).hexdigest()[:32]

    def to_known_hosts_line(self) -> str:
        return f"{self.hostname} {self.key_type} {self.key_base64}"


class HostKeyStore:
    """Manage known_hosts entries for SSH host key verification."""

    def __init__(self, known_hosts_path: str | None = None) -> None:
        self._path = known_hosts_path
        self._entries: dict[str, HostKeyEntry] = {}
        if self._path and Path(self._path).exists():
            self._load()

    def _load(self) -> None:
        if not self._path:
            return
        try:
            content = Path(self._path).read_text()
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    entry = HostKeyEntry(
                        hostname=parts[0],
                        key_type=parts[1],
                        key_base64=parts[2],
                    )
                    self._entries[entry.hostname] = entry
        except OSError:
            pass

    def lookup(self, hostname: str) -> HostKeyEntry | None:
        return self._entries.get(hostname)

    def add(self, hostname: str, key_type: str, key_base64: str) -> None:
        entry = HostKeyEntry(hostname=hostname, key_type=key_type, key_base64=key_base64)
        self._entries[hostname] = entry
        if self._path:
            try:
                Path(self._path).parent.mkdir(parents=True, exist_ok=True)
                lines = [e.to_known_hosts_line() for e in self._entries.values()]
                Path(self._path).write_text("\n".join(lines) + "\n")
            except OSError:
                pass

    def remove(self, hostname: str) -> None:
        self._entries.pop(hostname, None)
        if self._path:
            try:
                lines = [e.to_known_hosts_line() for e in self._entries.values()]
                Path(self._path).write_text("\n".join(lines) + "\n")
            except OSError:
                pass


# ── Retry strategy ─────────────────────────────────────────────

class RetryStrategy:
    """Configurable retry with exponential backoff."""

    def __init__(
        self,
        max_retries: int = 3,
        base_delay_seconds: float = 1.0,
        max_delay_seconds: float = 30.0,
        backoff_multiplier: float = 2.0,
    ) -> None:
        self.max_retries = max(0, max_retries)
        self.base_delay = max(0.1, base_delay_seconds)
        self.max_delay = max(self.base_delay, max_delay_seconds)
        self.multiplier = max(1.0, backoff_multiplier)

    def delay_for(self, attempt: int) -> float:
        delay = self.base_delay * (self.multiplier ** attempt)
        return min(delay, self.max_delay)


# ── Collector error ────────────────────────────────────────────

class CollectorError(Exception):
    def __init__(self, message: str, *, status: str = "critical") -> None:
        super().__init__(message)
        self.message = message
        self.status = status


# ── Base collector ─────────────────────────────────────────────

class BaseSSHCollector:
    name = "base"

    def __init__(self, retry: RetryStrategy | None = None) -> None:
        self.retry = retry or RetryStrategy()

    def execute_commands(
        self, device: dict[str, Any], probes: list[tuple[str, str]], *, timeout: int
    ) -> tuple[dict[str, str], list[dict[str, Any]]]:
        """Execute probe commands on device. Returns (results, command_errors) tuple.
        results: dict mapping probe key to raw output (successful commands only).
        command_errors: list of structured error dicts for failed commands."""
        raise NotImplementedError


class DisabledCollector(BaseSSHCollector):
    """Explicitly disables collection without falling back to fixture data."""

    name = "disabled"

    def execute_commands(
        self, device: dict[str, Any], probes: list[tuple[str, str]], *, timeout: int
    ) -> tuple[dict[str, str], list[dict[str, Any]]]:
        raise CollectorError("采集已禁用", status="disabled")


# ── Mock command collector ─────────────────────────────────────

MOCK_FIXTURES: dict[str, str] = {
    "hostname": "test-host\n",
    "uname": "Linux test-host 6.2.0-39-generic #40-Ubuntu SMP PREEMPT_DYNAMIC Tue Nov 28 10:16:28 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n",
    "uptime": "630576.28 2420528.15\n",
    "loadavg": "0.32 0.28 0.21 3/1024 12345\n",
    "meminfo": """MemTotal:       16284996 kB
MemFree:         4313728 kB
MemAvailable:    8220460 kB
Buffers:          518456 kB
Cached:          3994084 kB
SwapCached:            0 kB
Active:          8265316 kB
Inactive:        4456892 kB
Active(anon):    5235680 kB
Inactive(anon):  1088100 kB
Active(file):    3029636 kB
Inactive(file):  3368792 kB
Unevictable:           0 kB
Mlocked:               0 kB
SwapTotal:       8388604 kB
SwapFree:        8255288 kB
Dirty:               128 kB
Writeback:             0 kB
AnonPages:       5235456 kB
Mapped:          1024456 kB
Shmem:           1088356 kB
KReclaimable:     256896 kB
Slab:             348160 kB
SReclaimable:     256896 kB
SUnreclaim:        91264 kB
KernelStack:       14272 kB
PageTables:        25472 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:    16531140 kB
Committed_AS:    9425380 kB
VmallocTotal:   34359738367 kB
VmallocUsed:       63744 kB
VmallocChunk:          0 kB
Percpu:             5600 kB
HardwareCorrupted:     0 kB
AnonHugePages:         0 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
FileHugePages:         0 kB
FilePmdMapped:         0 kB
HugePages_Total:       0
HugePages_Free:        0
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB
Hugetlb:               0 kB
DirectMap4k:      181184 kB
DirectMap2M:     9213952 kB
DirectMap1G:     8388608 kB
""",
    "df": """Filesystem     1024-blocks         Used     Available Capacity Mounted on
/dev/sda1       104857600000    45097156608    59760443392      43% /
/dev/sdb1      1048576000000   644245094400   404330905600      62% /data
tmpfs             8342528000            0     8342528000       0% /dev/shm
""",
    "stat_1": """cpu  753450 2345 189234 45678902 12567 234 8976 0 0 0
cpu0 189234 567 45678 11420800 3456 56 2345 0 0 0
cpu1 181234 432 43210 11435600 2987 45 2123 0 0 0
cpu2 201345 678 43210 11418900 3345 67 2010 0 0 0
cpu3 181637 668 47136 11403602 2779 66 2498 0 0 0
intr 89456732 234 56789 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
ctxt 189234567
btime 1715432400
processes 45678
procs_running 3
procs_blocked 0
softirq 12345678 234 56789 0 1234 5678 0 12 34567 0 12345
""",
    "stat_2": """cpu  753600 2346 189345 45679300 12570 235 8986 0 0 0
cpu0 189300 567 45689 11420900 3459 56 2348 0 0 0
cpu1 181300 432 43222 11435600 2990 45 2127 0 0 0
cpu2 201500 678 43234 11419100 3348 67 2015 0 0 0
cpu3 181700 669 47200 11403700 2782 67 2506 0 0 0
intr 89456800 234 56789 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
ctxt 189236000
btime 1715432400
processes 45679
procs_running 2
procs_blocked 0
softirq 12345700 234 56789 0 1234 5678 0 12 34567 0 12345
""",
    "net_1": """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 12884901888 15678901    0    0    0     0          0         0 6442450944 8987654    0    0    0     0       0          0
  eth1: 1073741824  2156789    0    0    0     0          0         0  536870912  987654    0    0    0     0       0          0
    lo: 2147483648  3456789    0    0    0     0          0         0 2147483648 3456789    0    0    0     0       0          0
""",
    "net_2": """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: 12884912184 15679001    0    0    0     0          0         0 6442492160 8987700    0    0    0     0       0          0
  eth1: 1073782784  2156800    0    0    0     0          0         0  536879104  987660    0    0    0     0       0          0
    lo: 2147500032  3456800    0    0    0     0          0         0 2147500032 3456800    0    0    0     0       0          0
""",
    # ── Phase 2 NAS fixtures ──
    "lsblk": """{
   "blockdevices": [
      {"name":"sda","size":1000204886016,"type":"disk","mountpoint":null,
       "fstype":null,"model":"WDC WD1003FBYX","serial":"WD-WCAW12345678","rota":true,"tran":"sata"},
      {"name":"sda1","size":999000000000,"type":"part","mountpoint":"/",
       "fstype":"ext4","model":null,"serial":null,"rota":true,"tran":null},
      {"name":"sdb","size":2000398934016,"type":"disk","mountpoint":null,
       "fstype":null,"model":"ST2000DM008","serial":"ST-Z9A12345","rota":true,"tran":"sata"},
      {"name":"sdb1","size":1999000000000,"type":"part","mountpoint":"/data",
       "fstype":"ext4","model":null,"serial":null,"rota":true,"tran":null}
   ]
}""",
    "smartctl_scan": """{
   "json_format_version": [1,0],
   "smartctl": {"version": [7,2]},
   "devices": [
      {"name": "/dev/sda", "info_name": "/dev/sda", "type": "scsi", "protocol": "ATA"},
      {"name": "/dev/sdb", "info_name": "/dev/sdb", "type": "scsi", "protocol": "ATA"}
   ]
}""",
    "smartctl_sda": """{
   "ata_smart_attributes": {
      "table": [
         {"name": "Raw_Read_Error_Rate", "value": 100, "thresh": 16, "when_failed": "", "raw": {"string": "0"}},
         {"name": "Spin_Up_Time", "value": 95, "thresh": 21, "when_failed": "", "raw": {"string": "0"}},
         {"name": "Reallocated_Sector_Ct", "value": 100, "thresh": 36, "when_failed": "", "raw": {"string": "0"}},
         {"name": "Seek_Error_Rate", "value": 87, "thresh": 30, "when_failed": "", "raw": {"string": "65345145"}},
         {"name": "Temperature_Celsius", "value": 64, "thresh": 0, "when_failed": "", "raw": {"string": "36"}}
      ]
   }
}""",
    "smartctl_sdb": """{
   "ata_smart_attributes": {
      "table": [
         {"name": "Raw_Read_Error_Rate", "value": 100, "thresh": 6, "when_failed": "", "raw": {"string": "0"}},
         {"name": "Reallocated_Sector_Ct", "value": 90, "thresh": 10, "when_failed": "-", "raw": {"string": "120"}},
         {"name": "Temperature_Celsius", "value": 60, "thresh": 0, "when_failed": "", "raw": {"string": "40"}}
      ]
   }
}""",
    "mdstat": """Personalities : [raid1]
md0 : active raid1 sda1[0] sdb1[1]
      976629760 blocks super 1.2 [2/2] [UU]

md1 : active raid5 sdc1[0] sdd1[1] sde1[2] sdf1[3](F)
      1953262592 blocks super 1.2 level 5, 512k chunk, algorithm 2 [4/3] [_UUU]

unused devices: <none>
""",
    "zpool_list": "tank\t19998258227200\t10485760000000\t9512498227200\t0\t0\t10\t46\t1.00x\tONLINE\t-\n",
    "zpool_status": '{"pools":{"tank":{"health":"ONLINE","scan":"scrub repaired 0B in 02:30:00 on Sun May 12 03:00:00 2025"}}}',
    "zfs_list": "tank/media\tfilesystem\t524288000000\t200038205440\t524288000000\t/mnt/tank/media\t1715432400\n" +
                "tank/media@snap-2025-05-12\tsnapshot\t104857600\t0\t524288000000\t-\t1715518800\n" +
                "tank/backups\tfilesystem\t2097152000000\t1900685492224\t2097152000000\t/mnt/tank/backups\t1715432400\n",
    "btrfs_show": "Label: 'data'  uuid: 12345678-abcd-4e5f-890a-bcdef1234567\n" +
                 "\tTotal devices 2 FS bytes used 500.00GiB\n" +
                 "\tdevid    1 size 1.00TiB used 600.00GiB path /dev/sdc\n" +
                 "\tdevid    2 size 1.00TiB used 500.00GiB path /dev/sdd\n",
    "btrfs_device_stats": "[/dev/sdc].write_io_errs   0\n[/dev/sdc].read_io_errs     0\n[/dev/sdc].flush_io_errs    0\n[/dev/sdc].corruption_errs  0\n[/dev/sdc].generation_errs  0\n" +
                         "[/dev/sdd].write_io_errs   0\n[/dev/sdd].read_io_errs     2\n[/dev/sdd].flush_io_errs    0\n[/dev/sdd].corruption_errs  0\n[/dev/sdd].generation_errs  0\n",
    "btrfs_usage": "Overall:\n    Device size:\t\t1099511627776\n    Device allocated:\t\t549755813888\n    Device unallocated:\t\t549755813888\n    Device missing:\t\t  0\n    Used:\t\t\t536870912000\n    Free (estimated):\t\t536870912000\n    Data ratio:\t\t\t1.00\n    Metadata ratio:\t\t1.50\n    System ratio:\t\t  -\n",
    # ── Capability probe fixtures (command -v <tool> prints the path) ──
    "cap_lsblk": "/usr/bin/lsblk\n",
    "cap_smartctl": "/usr/sbin/smartctl\n",
    "cap_zpool": "/usr/sbin/zpool\n",
    "cap_zfs": "/usr/sbin/zfs\n",
    "cap_btrfs": "/usr/sbin/btrfs\n",
    "cap_findmnt": "/usr/bin/findmnt\n",
    "cap_docker": "/usr/bin/docker\n",
    # ── Docker probe fixture ──
    "docker_info": "Server Version: 20.10.12\nStorage Driver: overlay2\nContainers: 12\n Running: 5\n",
    # ── PVE capability + probe fixtures ──
    "cap_pveversion": "/usr/bin/pveversion\n",
    "cap_pvesm": "/usr/sbin/pvesm\n",
    "cap_qm": "/usr/sbin/qm\n",
    "cap_pct": "/usr/sbin/pct\n",
    "cap_ip": "/usr/sbin/ip\n",
    "pveversion": "pve-manager/8.2.2/9a2c43f0 (running kernel: 6.8.4-2-pve)\n",
    "pvesm": "Name             Type     Status           Total         Used    Available percent\nlocal             dir     active    104857600000  45097156608  59760443392       43\nlocal-lvm         lvm     active    214748364800  64424509440 150323855360       30\nnfs-share         nfs     active    1099511627776 0            1099511627776 0\n",
    "qm_list": "  VMID Name                 Status      Mem(MB)    Bootdisk(GB) \n   100 vm-100               running    4096       32\n   101 vm-101               stopped    2048       20\n   102 vm-102               running    8192       50\n",
    "pct_list": "  CTID Name                 Status      Mem(MB)    \n   200 ct-200               running    1024       \n   201 ct-201               stopped    512        \n",
    "ip_br_addr": "vmbr0   UP             192.0.2.10/24  \neno1   UP             198.51.100.5/24  \nlo     UNKNOWN        \n",
    "ip_s_link": "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n    RX: bytes 1234 packets 12 errors 0\n    TX: bytes 5678 packets 34 errors 0\n2: eno1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000\n    RX: bytes 999999 packets 999 errors 0\n    TX: bytes 888888 packets 888 errors 0\n3: vmbr0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000\n    RX: bytes 111111 packets 111 errors 0\n    TX: bytes 222222 packets 222 errors 0\n",
}


class MockCommandCollector(BaseSSHCollector):
    """Returns fixture raw command outputs. Used for mock mode (clear labeling)."""

    name = "mock"

    def execute_commands(
        self, device: dict[str, Any], probes: list[tuple[str, str]], *, timeout: int
    ) -> tuple[dict[str, str], list[dict[str, Any]]]:
        if timeout <= 0:
            raise CollectorError("timeout must be positive", status="warning")
        if not device.get("enabled", True):
            raise CollectorError("device is disabled", status="warning")

        host = device.get("host", "")
        status = str(device.get("status", "unknown")).lower()
        if status == "offline" or host.endswith(".250") or "offline" in host:
            raise CollectorError("ssh timeout contacting host", status="critical")

        results: dict[str, str] = {}
        for key, cmd in probes:
            if not command_allowed(cmd):
                raise CollectorError("collector command is not allowed", status="critical")
            if key in MOCK_FIXTURES:
                results[key] = MOCK_FIXTURES[key]
            else:
                results[key] = ""
        return results, []


# ── Real Paramiko SSH collector ────────────────────────────────

class ParamikoSSHCollector(BaseSSHCollector):
    name = "paramiko"

    def __init__(
        self,
        *,
        retry: RetryStrategy | None = None,
        known_hosts_path: str | None = None,
        auto_accept_host_key: bool = False,
    ) -> None:
        super().__init__(retry=retry)
        self._known_hosts_path = known_hosts_path
        self._host_key_store = HostKeyStore(known_hosts_path)
        self._auto_accept_host_key = auto_accept_host_key

    def execute_commands(
        self, device: dict[str, Any], probes: list[tuple[str, str]], *, timeout: int
    ) -> tuple[dict[str, str], list[dict[str, Any]]]:
        if timeout <= 0:
            raise CollectorError("timeout must be positive", status="warning")
        if device.get("auth_type") not in {"private_key", "password"}:
            raise CollectorError("unsupported auth_type for SSH collector", status="warning")

        for _, cmd in probes:
            if not command_allowed(cmd):
                raise CollectorError("collector command is not allowed", status="critical")

        try:
            import paramiko  # type: ignore
        except Exception as exc:
            raise CollectorError("paramiko is not installed", status="warning") from exc

        last_error: Exception | None = None
        for attempt in range(self.retry.max_retries + 1):
            if attempt > 0:
                delay = self.retry.delay_for(attempt - 1)
                time.sleep(delay)
            try:
                return self._connect_and_execute(
                    paramiko, device=device, probes=probes, timeout=timeout, attempt=attempt,
                )
            except CollectorError:
                raise
            except Exception as exc:
                last_error = exc
                continue

        raise CollectorError(
            f"SSH 采集失败（重试 {self.retry.max_retries} 次后仍失败）",
            status="critical",
        ) from last_error

    @staticmethod
    def _build_connect_kwargs(device: dict[str, Any], connect_timeout: int) -> dict[str, Any]:
        connect_kwargs: dict[str, Any] = {
            "hostname": device["host"],
            "port": int(device.get("port", 22)),
            "username": device["username"],
            "timeout": connect_timeout,
            "banner_timeout": min(15, connect_timeout),
            "auth_timeout": min(15, connect_timeout),
            "look_for_keys": False,
            "allow_agent": False,
        }
        if device.get("auth_type") == "private_key":
            private_key_path = device.get("private_key_path")
            if not private_key_path:
                raise CollectorError(
                    "使用私钥认证时必须提供 SSH 私钥路径",
                    status="warning",
                )
            expanded = os.path.expanduser(private_key_path)
            if not os.path.exists(expanded):
                raise CollectorError(
                    "SSH 私钥文件不存在或不可访问", status="warning"
                )
            connect_kwargs["key_filename"] = expanded
        else:
            password = device.get("password")
            if password == EXTERNAL_SECRET_SENTINEL:
                raise CollectorError(
                    "密码认证需要通过外部凭据源提供 SSH 凭据",
                    status="warning",
                )
            if not password:
                raise CollectorError(
                    "密码认证需要提供 SSH 凭据", status="warning"
                )
            connect_kwargs["password"] = password
        return connect_kwargs

    def _connect_client(self, paramiko, device: dict[str, Any], connect_timeout: int):
        client = paramiko.SSHClient()

        if self._auto_accept_host_key:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        elif self._known_hosts_path:
            client.load_system_host_keys()
            try:
                client.load_host_keys(os.path.expanduser(self._known_hosts_path))
            except OSError:
                pass
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        connect_kwargs = self._build_connect_kwargs(device, connect_timeout)
        client.connect(**connect_kwargs)
        return client

    def _connect_and_execute(
        self,
        paramiko,
        *,
        device: dict[str, Any],
        probes: list[tuple[str, str]],
        timeout: int,
        attempt: int,
    ) -> tuple[dict[str, str], list[dict[str, Any]]]:
        connect_timeout = max(3, timeout // 2)
        channel_timeout = max(3, timeout - connect_timeout)

        client = self._connect_client(paramiko, device, connect_timeout)

        try:
            results: dict[str, str] = {}
            command_errors: list[dict[str, Any]] = []

            for key, cmd in probes:
                err = None
                exit_code = None
                stdout_raw = ""
                stderr_raw = ""
                stdout = None
                t0 = time.monotonic()

                try:
                    _stdin, stdout, stderr = client.exec_command(cmd, timeout=channel_timeout)
                    stdout_raw = stdout.read().decode("utf-8", errors="replace")
                    stderr_raw = stderr.read().decode("utf-8", errors="replace")
                    exit_code = stdout.channel.recv_exit_status()
                except Exception as exc:
                    err_msg = str(exc)
                    error_type = "timeout" if "timeout" in err_msg.lower() else "channel_error"
                    err = {
                        "command_id": key,
                        "command": cmd,
                        "exit_code": None,
                        "stderr": stderr_raw[:500],
                        "stdout": stdout_raw[:500],
                        "error_type": error_type,
                        "error_message": err_msg,
                    }
                finally:
                    if stdout is not None:
                        try:
                            stdout.channel.close()
                        except Exception:
                            pass

                duration_ms = (time.monotonic() - t0) * 1000

                if err is not None:
                    logger.info(
                        "cmd=%s exit=N/A duration=%.0fms stdout=%d stderr=%d status=ERROR",
                        key, duration_ms, len(stdout_raw), len(stderr_raw),
                    )
                    command_errors.append(err)
                    results[key] = ""
                    continue

                if exit_code is not None and exit_code != 0:
                    err = {
                        "command_id": key,
                        "command": cmd,
                        "exit_code": exit_code,
                        "stderr": stderr_raw[:500],
                        "stdout": stdout_raw[:500],
                        "error_type": "non_zero_exit",
                        "error_message": stderr_raw.strip()[:200] or f"exit code {exit_code}",
                    }
                    logger.info(
                        "cmd=%s exit=%d duration=%.0fms stdout=%d stderr=%d status=NONZERO",
                        key, exit_code, duration_ms, len(stdout_raw), len(stderr_raw),
                    )
                    command_errors.append(err)
                    results[key] = stdout_raw.strip()
                    continue

                logger.info(
                    "cmd=%s exit=0 duration=%.0fms stdout=%d stderr=%d",
                    key, duration_ms, len(stdout_raw), len(stderr_raw),
                )
                results[key] = stdout_raw.strip()

            return results, command_errors

        except CollectorError:
            raise
        except Exception as exc:
            raise CollectorError(
                f"SSH 连接或命令执行失败: {exc}", status="critical"
            ) from exc
        finally:
            try:
                client.close()
            except Exception:
                pass

    def quick_verify(self, device: dict[str, Any], *, timeout: int) -> dict[str, str]:
        """Verify SSH connectivity and basic system identity (hostname + uname).

        Used during device creation when COLLECTOR_MODE=ssh to validate
        the new device before saving.
        """
        results, _errors = self.execute_commands(
            device,
            [("hostname", "hostname"), ("uname", "uname -a")],
            timeout=timeout,
        )
        return results

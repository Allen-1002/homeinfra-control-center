"""Pure parsing functions for Linux command outputs.

All functions are stateless. They accept raw text and return structured
data, or None on failure (no exceptions raised)."""

from __future__ import annotations

import re
from typing import Any


def parse_hostname(text: str) -> str | None:
    """Parse hostname output. Returns the hostname string or None."""
    if not text:
        return None
    lines = text.strip().splitlines()
    return lines[0].strip() or None


def parse_uname(text: str) -> str | None:
    """Parse uname -a output. Returns the full uname string or None."""
    if not text:
        return None
    content = text.strip()
    return content or None


def parse_uptime(text: str) -> float | None:
    """Parse /proc/uptime. Returns total uptime in seconds as float."""
    if not text:
        return None
    parts = text.strip().split()
    if not parts:
        return None
    try:
        return float(parts[0])
    except (ValueError, IndexError):
        return None


def parse_loadavg(text: str) -> dict[str, float] | None:
    """Parse /proc/loadavg. Returns dict with keys 'load_1m', 'load_5m', 'load_15m'."""
    if not text:
        return None
    parts = text.strip().split()
    if len(parts) < 3:
        return None
    try:
        return {
            "load_1m": float(parts[0]),
            "load_5m": float(parts[1]),
            "load_15m": float(parts[2]),
        }
    except (ValueError, IndexError):
        return None


def parse_meminfo(text: str) -> dict[str, float] | None:
    """Parse /proc/meminfo. Returns dict with memory values in MB.

    memory_used_mb = MemTotal - MemAvailable (not MemFree).
    """
    if not text:
        return None
    values: dict[str, float] = {}
    for line in text.strip().splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        key = parts[0].strip()
        val_str = parts[1].strip().split()[0]
        try:
            val_kb = float(val_str)
        except (ValueError, IndexError):
            continue
        if key in {"MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached"}:
            values[key.lower()] = val_kb / 1024.0
        elif key == "SwapTotal":
            values["swaptotal"] = val_kb / 1024.0
        elif key == "SwapFree":
            values["swapfree"] = val_kb / 1024.0

    if "memtotal" not in values:
        return None

    mem_total = values.get("memtotal", 0.0)
    mem_avail = values.get("memavailable", values.get("memfree", 0.0))
    mem_used = max(0.0, mem_total - mem_avail)
    mem_percent = (mem_used / mem_total * 100.0) if mem_total > 0 else 0.0

    swap_total = values.get("swaptotal", 0.0)
    swap_free = values.get("swapfree", 0.0)
    swap_used = max(0.0, swap_total - swap_free)

    return {
        "memory_total_mb": mem_total,
        "memory_used_mb": mem_used,
        "memory_percent": mem_percent,
        "memory_buffers_mb": values.get("buffers", 0.0),
        "memory_cached_mb": values.get("cached", 0.0),
        "memory_swap_total_mb": swap_total,
        "memory_swap_used_mb": swap_used,
    }


def parse_df_P_B1(text: str, *, block_size: int = 1) -> list[dict[str, Any]] | None:
    """Parse ``df -P`` style output. Returns list of partition dicts by column position.

    Columns: Filesystem 1024-blocks Used Available Capacity Mounted on

    ``block_size`` is the unit (in bytes) of the size/used/available columns:
      * ``1``  for ``df -P -B1``  (values are bytes)
      * ``1024`` for ``df -P`` / ``df`` (values are 1K-blocks)
    """
    if not text:
        return None
    lines = text.strip().splitlines()
    if len(lines) < 2:
        return None

    partitions: list[dict[str, Any]] = []
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            fs_name = parts[0]
            total_bytes = float(parts[1]) * block_size
            used_bytes = float(parts[2]) * block_size
            avail_bytes = float(parts[3]) * block_size
            capacity_str = parts[4].rstrip("%")
            mount = parts[5]
            capacity_pct = float(capacity_str) if capacity_str else 0.0

            if total_bytes <= 0:
                continue

            partitions.append({
                "device": fs_name,
                "mount": mount,
                "size_gb": round(total_bytes / (1024.0 ** 3), 2),
                "used_gb": round(used_bytes / (1024.0 ** 3), 2),
                "usage_percent": round(capacity_pct, 1),
            })
        except (ValueError, IndexError):
            continue

    return partitions if partitions else None


def parse_proc_stat(text: str) -> dict[str, Any] | None:
    """Parse /proc/stat. Returns raw CPU counters for delta computation.

    Returns dict with:
      - 'cpu': list of 10 int counter values (user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice)
      - 'cpu_cores': list of per-core dicts with 'core' and raw counter list
    """
    if not text:
        return None
    lines = text.strip().splitlines()
    cpu_aggregate: list[int] | None = None
    cpu_cores: list[dict[str, Any]] = []

    for line in lines:
        parts = line.split()
        if not parts:
            continue
        label = parts[0]
        if label == "cpu":
            try:
                cpu_aggregate = [int(v) for v in parts[1:11]]
            except (ValueError, IndexError):
                continue
        elif label.startswith("cpu") and len(label) > 3:
            try:
                core_num = int(label[3:])
                counters = [int(v) for v in parts[1:11]]
                cpu_cores.append({"core": core_num, "counters": counters})
            except (ValueError, IndexError):
                continue

    if cpu_aggregate is None:
        return None

    cpu_cores.sort(key=lambda c: c["core"])
    return {
        "cpu": cpu_aggregate,
        "cpu_cores": cpu_cores,
    }


def compute_cpu_percent(stat1: dict[str, Any] | None, stat2: dict[str, Any] | None, elapsed_seconds: float) -> dict[str, Any] | None:
    """Compute CPU usage percent from two /proc/stat samples with real elapsed time.

    Returns dict with 'cpu_percent', 'cpu_cores', and 'per_core_cpu' list.
    """
    if stat1 is None or stat2 is None or elapsed_seconds <= 0:
        return None

    try:
        cpu1 = stat1["cpu"]
        cpu2 = stat2["cpu"]
    except (KeyError, IndexError):
        return None

    if len(cpu1) < 4 or len(cpu2) < 4:
        return None

    def _cpu_busy(counters: list[int]) -> int:
        return sum(counters[:3])  # user + nice + system

    def _cpu_total(counters: list[int]) -> int:
        return sum(counters[:8])  # user...steal

    total_delta = _cpu_total(cpu2) - _cpu_total(cpu1)
    busy_delta = _cpu_busy(cpu2) - _cpu_busy(cpu1)
    cpu_percent = (busy_delta / total_delta * 100.0) if total_delta > 0 else 0.0

    cores1 = {c["core"]: c["counters"] for c in stat1.get("cpu_cores", [])}
    cores2 = {c["core"]: c["counters"] for c in stat2.get("cpu_cores", [])}

    per_core_cpu: list[dict[str, Any]] = []
    for core_id in sorted(set(cores1.keys()) & set(cores2.keys())):
        c1 = cores1[core_id]
        c2 = cores2[core_id]
        core_total = _cpu_total(c2) - _cpu_total(c1)
        core_busy = _cpu_busy(c2) - _cpu_busy(c1)
        core_pct = (core_busy / core_total * 100.0) if core_total > 0 else 0.0
        per_core_cpu.append({"core": core_id, "percent": round(core_pct, 1)})

    return {
        "cpu_percent": round(cpu_percent, 1),
        "cpu_cores": len(per_core_cpu),
        "per_core_cpu": per_core_cpu,
    }


def parse_proc_net_dev(text: str) -> dict[str, list[dict[str, Any]]] | None:
    """Parse /proc/net/dev. Returns dict with 'interfaces' list.

    Each interface has: name, rx_bytes, tx_bytes.
    Excludes 'lo' only (per Phase 1 spec).
    """
    if not text:
        return None
    lines = text.strip().splitlines()
    if len(lines) < 3:
        return None

    interfaces: list[dict[str, Any]] = []
    for line in lines[2:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 10:
            continue
        name = parts[0].rstrip(":")
        if name == "lo":
            continue
        try:
            rx_bytes = int(parts[1])
            tx_bytes = int(parts[9])
            interfaces.append({
                "name": name,
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
            })
        except (ValueError, IndexError):
            continue

    return {"interfaces": interfaces} if interfaces else None


def compute_network_rates(
    net1: dict[str, Any] | None,
    net2: dict[str, Any] | None,
    elapsed_seconds: float,
) -> list[dict[str, Any]] | None:
    """Compute network rates from two /proc/net/dev samples.

    Returns list of interface dicts with rx_mbps, tx_mbps.
    Uses same elapsed_seconds as CPU sampling interval.
    """
    if net1 is None or net2 is None or elapsed_seconds <= 0:
        return None

    ifaces1 = {iface["name"]: iface for iface in net1.get("interfaces", [])}
    ifaces2 = {iface["name"]: iface for iface in net2.get("interfaces", [])}

    result: list[dict[str, Any]] = []
    common = set(ifaces1.keys()) & set(ifaces2.keys())
    for name in sorted(common):
        rx_delta = ifaces2[name]["rx_bytes"] - ifaces1[name]["rx_bytes"]
        tx_delta = ifaces2[name]["tx_bytes"] - ifaces1[name]["tx_bytes"]
        rx_mbps = round((rx_delta * 8) / (elapsed_seconds * 1_000_000), 2)
        tx_mbps = round((tx_delta * 8) / (elapsed_seconds * 1_000_000), 2)
        result.append({
            "name": name,
            "rx_mbps": rx_mbps,
            "tx_mbps": tx_mbps,
            "rx_bytes_total": ifaces2[name]["rx_bytes"],
            "tx_bytes_total": ifaces2[name]["tx_bytes"],
        })

    return result if result else None


# ═══════════════════════════════════════════════════════════════════
#  Phase 2: NAS baseline parsers — lsblk, SMART, mdstat, ZFS, btrfs
#  Each returns None on failure; callers handle unavailable_metrics.
# ═══════════════════════════════════════════════════════════════════

import json


def parse_lsblk_json(text: str) -> list[dict[str, Any]] | None:
    """Parse ``lsblk -J -b`` JSON output.

    Returns a list of block device dicts with keys:
      name, size_gb, type, mountpoint, fstype, model, serial,
      rotational, transport

    Returns None when text is empty or parsing fails.
    """
    if not text:
        return None
    try:
        root = json.loads(text)
        devices: list[dict[str, Any]] = root.get("blockdevices", [])
    except (json.JSONDecodeError, KeyError, TypeError):
        return None
    result: list[dict[str, Any]] = []
    for dev in devices:
        size_bytes = dev.get("size") or 0
        result.append({
            "name": dev.get("name", ""),
            "size_gb": round(size_bytes / (1024 ** 3), 2),
            "type": dev.get("type", ""),
            "mountpoint": dev.get("mountpoint") or "",
            "fstype": dev.get("fstype") or "",
            "model": dev.get("model") or "",
            "serial": dev.get("serial") or "",
            "rotational": bool(dev.get("rota")),
            "transport": dev.get("tran") or "",
        })
    return result if result else None


def parse_smartctl_scan_json(text: str) -> list[str] | None:
    """Parse ``smartctl --scan -j`` JSON output.

    Returns a list of device paths (e.g. ``["/dev/sda", "/dev/sdb"]``)
    or None on failure.
    """
    if not text:
        return None
    try:
        root = json.loads(text)
        dev_list: list[dict[str, Any]] = root.get("devices", [])
    except (json.JSONDecodeError, KeyError, TypeError):
        return None
    paths = [d.get("name", "") for d in dev_list if d.get("name")]
    return paths if paths else None


def parse_smartctl_health_json(text: str) -> list[dict[str, Any]] | None:
    """Parse ``smartctl -a -j`` JSON output.

    Returns a list of SMART attribute dicts (ATA drives only) with keys:
      attr_name, value, threshold, raw, status
    """
    if not text:
        return None
    try:
        root = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None

    table: list[dict[str, Any]] | None = None
    try:
        table = root["ata_smart_attributes"]["table"]
    except (KeyError, TypeError):
        pass

    if not table:
        try:
            entries = root.get("ata_smart_attributes", {}).get("table", [])
        except Exception:
            return None
        if not entries:
            return None
        table = entries

    result: list[dict[str, Any]] = []
    for attr in table:
        raw_val = attr.get("raw", {})
        if isinstance(raw_val, dict):
            raw_str = str(raw_val.get("string", raw_val.get("value", "")))
        else:
            raw_str = str(raw_val)
        status = attr.get("when_failed", "")
        result.append({
            "attr_name": attr.get("name", ""),
            "value": attr.get("value"),
            "threshold": attr.get("thresh"),
            "raw": raw_str[:120],
            "status": "FAILED" if (status and status != "" and status != "-") else "PASSED",
        })
    return result if result else None


def parse_mdstat(text: str) -> list[dict[str, Any]] | None:
    """Parse ``/proc/mdstat``.

    Returns a list of RAID array dicts with keys:
      name, type, state, drives, degraded_drives
    """
    if not text:
        return None
    arrays: list[dict[str, Any]] = []
    lines = text.strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line or ":" not in line or "Personalities" in line or "unused" in line:
            continue
        name_part, _, info = line.partition(":")
        name = name_part.strip()
        if not name:
            continue
        info = info.strip()
        state = "active"
        if "inactive" in info.lower():
            state = "inactive"
        parts = info.split()
        drives = sum(1 for p in parts if p.startswith(("sd", "hd", "nvme", "vd")))
        degraded = 0
        if "(F)" in info:
            degraded = info.count("(F)")
        raid_type = "unknown"
        for p in parts:
            if p.startswith("raid") or p in ("linear", "multipath"):
                raid_type = p
                break
        arrays.append({
            "name": name,
            "type": raid_type,
            "state": state.upper(),
            "drives": drives,
            "degraded_drives": degraded,
        })
    return arrays if arrays else None


def parse_zpool_list(text: str) -> list[dict[str, Any]] | None:
    """Parse ``zpool list -H -p`` tab-separated output.

    Columns: name  size  allocated  free  checkpoint  expandsize
             fragmentation  capacity  dedupratio  health  altroot

    Returns list of pool dicts with keys:
      name, size_gb, used_gb, free_gb, usage_percent, health, dedup_ratio
    """
    if not text:
        return None
    pools: list[dict[str, Any]] = []
    for line in text.strip().splitlines():
        fields = line.split("\t")
        if len(fields) < 10:
            continue
        try:
            name = fields[0]
            size_bytes = int(fields[1])
            allocated_bytes = int(fields[2])
            free_bytes = int(fields[3])
            capacity_pct = float(fields[7]) if fields[7] else 0.0
            health = fields[9] if len(fields) > 9 else ""
            pools.append({
                "name": name,
                "size_gb": round(size_bytes / (1024 ** 3), 2),
                "used_gb": round(allocated_bytes / (1024 ** 3), 2),
                "free_gb": round(free_bytes / (1024 ** 3), 2),
                "usage_percent": round(capacity_pct, 1),
                "health_state": health if health else "UNKNOWN",
                "compression_ratio": 1.0,
            })
        except (ValueError, IndexError):
            continue
    return pools if pools else None


def parse_zpool_status_json(text: str) -> list[dict[str, Any]] | None:
    """Parse ``zpool status -j`` JSON output.

    Returns list of pool status dicts with keys:
      name, health_state, scan_status

    Use this to annotate pools from parse_zpool_list with health_state.
    """
    if not text:
        return None
    try:
        root = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
    pools_status = root.get("pools", root) if isinstance(root, dict) else {}
    result: list[dict[str, Any]] = []
    if isinstance(pools_status, dict):
        for pool_name, pool_data in pools_status.items():
            result.append({
                "name": pool_name,
                "health_state": pool_data.get("health", "UNKNOWN"),
                "scan_status": pool_data.get("scan", "") or "",
            })
    return result if result else None


def parse_zpool_status_text(text: str) -> list[dict[str, Any]] | None:
    """Parse plain ``zpool status`` text output (fallback when ``-j`` unsupported).

    Returns list of pool status dicts with keys: name, health_state, scan_status.
    """
    if not text:
        return None
    result: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("pool:"):
            if current is not None:
                result.append(current)
            current = {"name": line.split(":", 1)[1].strip(), "health_state": "UNKNOWN", "scan_status": ""}
        elif line.startswith("state:") and current is not None:
            current["health_state"] = line.split(":", 1)[1].strip() or "UNKNOWN"
        elif line.startswith("scan:") and current is not None:
            current["scan_status"] = line.split(":", 1)[1].strip()
    if current is not None:
        result.append(current)
    return result if result else None


def parse_zfs_list(text: str) -> dict[str, list[dict[str, Any]]] | None:
    """Parse ``zfs list -H -p -o name,type,used,available,referenced,mountpoint,creation``.

    Returns dict with keys ``volumes`` and ``snapshots``, each a list of
    dicts with: name, pool, used_gb, available_gb, creation.
    """
    if not text:
        return None
    volumes: list[dict[str, Any]] = []
    snapshots: list[dict[str, Any]] = []
    for line in text.strip().splitlines():
        fields = line.split("\t")
        if len(fields) < 7:
            continue
        try:
            name = fields[0]
            ds_type = fields[1]
            used_bytes = int(fields[2])
            avail_bytes = int(fields[3])
            creation = fields[6] if len(fields) > 6 else ""
            pool = name.split("/", 1)[0] if "/" in name else name
            entry = {
                "name": name,
                "pool": pool,
                "used_gb": round(used_bytes / (1024 ** 3), 2),
                "available_gb": round(avail_bytes / (1024 ** 3), 2),
                "creation": creation,
            }
            if ds_type == "snapshot":
                snapshots.append(entry)
            elif ds_type in ("filesystem", "volume"):
                volumes.append(entry)
        except (ValueError, IndexError):
            continue
    if not volumes and not snapshots:
        return None
    return {"volumes": volumes, "snapshots": snapshots}


def _parse_size_bytes(value_str: str) -> float:
    """Convert human-readable size like '500.00GiB' or '1.00TiB' to bytes."""
    value_str = value_str.strip().upper()
    multipliers = {
        "B": 1, "KB": 1024, "KIB": 1024,
        "MB": 1024**2, "MIB": 1024**2,
        "GB": 1024**3, "GIB": 1024**3,
        "TB": 1024**4, "TIB": 1024**4,
    }
    for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
        if value_str.endswith(suffix):
            try:
                return float(value_str[: -len(suffix)]) * mult
            except ValueError:
                return 0
    return 0


def parse_btrfs_filesystem_show(text: str) -> list[dict[str, Any]] | None:
    """Parse ``btrfs filesystem show --raw`` output.

    Returns list of filesystem dicts with keys:
      label, uuid, total_devices, total_size_gb, used_gb
    """
    if not text:
        return None
    fs_list: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith("label:"):
            if current:
                fs_list.append(current)
            current = {"label": "", "uuid": "", "total_devices": 0, "total_size_gb": 0.0, "used_gb": 0.0}
            # Label: 'mylabel'  uuid: xxxx
            if "'" in line:
                parts = line.split("'")
                if len(parts) > 1:
                    current["label"] = parts[1]
            if "uuid:" in line:
                uuid_part = line.split("uuid:")[-1].strip()
                uuid_part = uuid_part.rstrip(")")
                current["uuid"] = uuid_part
        elif current is not None:
            if "Total devices" in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p.isdigit() and i > 0:
                        current["total_devices"] = int(p)
                        break
                if "FS bytes used" in line:
                    idx = line.find("FS bytes used")
                    if idx >= 0:
                        rest = line[idx + len("FS bytes used"):].strip()
                        used_bytes = _parse_size_bytes(rest.split()[0])
                        current["used_gb"] = round(used_bytes / (1024**3), 2)
            elif "devid" in line and "size" in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "size" and i + 1 < len(parts):
                        size_bytes = _parse_size_bytes(parts[i + 1])
                        current["total_size_gb"] += round(size_bytes / (1024**3), 2)
                        break
    if current:
        fs_list.append(current)
    return fs_list if fs_list else None


def parse_btrfs_device_stats(text: str) -> list[dict[str, Any]] | None:
    """Parse ``btrfs device stats /`` output.

    Returns list of device stats dicts with keys:
      device, write_errs, read_errs, flush_errs, corruption_errs, generation_errs
    """
    if not text:
        return None
    stats: list[dict[str, Any]] = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or not line.startswith("["):
            continue
        try:
            dev_end = line.index("]")
            device = line[1:dev_end]
            fields_str = line[dev_end + 1:].strip()
            field_pairs = fields_str.split(".")
            entry: dict[str, Any] = {"device": device}
            for pair in field_pairs:
                pair = pair.strip()
                if not pair:
                    continue
                key_val = pair.split()
                if len(key_val) >= 2:
                    entry[key_val[0]] = int(key_val[1])
            entry_out = {
                "device": device,
                "write_errs": entry.get("write_io_errs", 0),
                "read_errs": entry.get("read_io_errs", 0),
                "flush_errs": entry.get("flush_io_errs", 0),
                "corruption_errs": entry.get("corruption_errs", 0),
                "generation_errs": entry.get("generation_errs", 0),
            }
            stats.append(entry_out)
        except (ValueError, IndexError):
            continue
    return stats if stats else None


def parse_btrfs_filesystem_usage(text: str) -> list[dict[str, Any]] | None:
    """Parse ``btrfs filesystem usage -b /`` output.

    Returns list of usage dicts per device/section with keys:
      device, size_gb, used_gb, free_gb, usage_percent
    """
    if not text:
        return None
    result: list[dict[str, Any]] = []
    section: dict[str, Any] | None = None
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            if section:
                result.append(section)
                section = None
            continue
        if ":" in line and line.startswith(("Overall", "Device", "Unallocated")):
            continue
        if "Device size:" in line:
            if section:
                result.append(section)
            section = {}
            try:
                size_bytes = float(line.split(":")[1].strip().split()[0])
                section["size_gb"] = round(size_bytes / (1024 ** 3), 2)
            except (ValueError, IndexError):
                section["size_gb"] = 0
        elif section is not None:
            if "Used" in line or "used" in line:
                try:
                    section["used_gb"] = round(float(line.split(":")[-1].strip().split()[0]) / (1024 ** 3), 2)
                except (ValueError, IndexError):
                    pass
            elif "Free" in line or "free" in line:
                try:
                    section["free_gb"] = round(float(line.split(":")[-1].strip().split()[0]) / (1024 ** 3), 2)
                except (ValueError, IndexError):
                    pass
    if section:
        result.append(section)
    for s in result:
        if "used_gb" in s and "size_gb" in s and s["size_gb"] > 0:
            s["usage_percent"] = round(s["used_gb"] / s["size_gb"] * 100, 1)
        else:
            s["usage_percent"] = 0
    return result if result else None


# ── Proxmox VE (PVE) parsers ─────────────────────────────────

def parse_pveversion(text: str) -> str | None:
    """Parse ``pveversion`` output, e.g. 'pve-manager/8.2.2/...'. Returns the
    version string (manager version) or None."""
    if not text:
        return None
    line = text.strip().splitlines()[0].strip()
    if not line:
        return None
    # 'pve-manager/8.2.2/9a2c43f0 (running kernel: 6.8.4-2-pve)'
    if "pve-manager/" in line:
        try:
            return line.split("pve-manager/")[1].split("/")[0]
        except (IndexError, ValueError):
            pass
    return line


def parse_pvesm_status(text: str) -> list[dict[str, Any]] | None:
    """Parse ``pvesm status`` output.

    Columns: Name Type Status Total Used Available percent (sizes in bytes).
    Returns list of {storage, type, status, total, used, available, percent}.
    """
    if not text:
        return None
    result: list[dict[str, Any]] = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.lower().startswith("name"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            entry: dict[str, Any] = {
                "storage": parts[0],
                "type": parts[1],
                "status": parts[2],
                "total": 0,
                "used": 0,
                "available": 0,
                "percent": 0,
            }
            if len(parts) >= 4:
                entry["total"] = int(parts[3])
            if len(parts) >= 5:
                entry["used"] = int(parts[4])
            if len(parts) >= 6:
                entry["available"] = int(parts[5])
            if len(parts) >= 7:
                entry["percent"] = float(str(parts[6]).rstrip("%"))
            elif entry["total"] > 0:
                entry["percent"] = round(entry["used"] / entry["total"] * 100, 1)
            result.append(entry)
        except (ValueError, IndexError):
            continue
    return result if result else None


def parse_qm_list(text: str) -> list[dict[str, Any]] | None:
    """Parse ``qm list`` (VM list) output.

    Columns: VMID Name Status Memory(GB) Disk(GB) ... Returns list of
    {id, name, status, memory, disk}.
    """
    return _parse_guest_list(text)


def parse_pct_list(text: str) -> list[dict[str, Any]] | None:
    """Parse ``pct list`` (LXC container list) output."""
    return _parse_guest_list(text)


def _parse_guest_list(text: str) -> list[dict[str, Any]] | None:
    if not text:
        return None
    result: list[dict[str, Any]] = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.lower().startswith("vmid") or line.lower().startswith("ctid"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            entry: dict[str, Any] = {
                "id": parts[0],
                "name": parts[1],
                "status": parts[2] if len(parts) > 2 else "unknown",
                "memory": 0,
                "disk": 0,
            }
            if len(parts) > 3:
                try:
                    entry["memory"] = float(parts[3])
                except ValueError:
                    pass
            if len(parts) > 4:
                try:
                    entry["disk"] = float(parts[4])
                except ValueError:
                    pass
            result.append(entry)
        except (ValueError, IndexError):
            continue
    return result if result else None


def parse_ip_br_addr(text: str) -> list[dict[str, Any]] | None:
    """Parse ``ip -br addr`` output.

    Lines: 'vmbr0   UP             192.0.2.10/24  fe80::...'
    Returns list of {name, state, ip_addresses (list), is_bridge, is_physical}.
    """
    if not text:
        return None
    result: list[dict[str, Any]] = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[0]
        state = parts[1]
        ips = [p for p in parts[2:] if "/" in p]
        result.append({
            "name": name,
            "state": state,
            "ip_addresses": ips,
            "is_bridge": name.startswith("vmbr"),
            "is_physical": bool(name) and not name.startswith(("vmbr", "lo", "docker", "br-")),
        })
    return result if result else None


def parse_ip_s_link(text: str) -> list[dict[str, Any]] | None:
    """Parse ``ip -s link`` output for per-interface RX/TX byte counters.

    Returns list of {name, rx_bytes, tx_bytes, rx_mbps, tx_mbps}. Rates are
    not computed here (no delta); rx_bytes/tx_bytes are cumulative counters.
    """
    if not text:
        return None
    result: list[dict[str, Any]] = []
    blocks = re.split(r"\n(?=\d+: )", text)
    for block in blocks:
        lines = block.strip().splitlines()
        if not lines:
            continue
        m = re.match(r"\d+:\s+([^\s@:]+)", lines[0])
        if not m:
            continue
        name = m.group(1)
        rx_bytes = 0
        tx_bytes = 0
        # stats block: "    RX: bytes packets errors ..." then "    TX: ..."
        for ln in lines:
            mm = re.match(r"\s+(RX|TX):\s+bytes\s+(\d+)", ln)
            if mm:
                if mm.group(1) == "RX":
                    rx_bytes = int(mm.group(2))
                else:
                    tx_bytes = int(mm.group(2))
        result.append({"name": name, "rx_bytes": rx_bytes, "tx_bytes": tx_bytes})
    return result if result else None

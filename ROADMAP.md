# Roadmap

## Phase 1 ✅ 完成

- [x] 设备 CRUD + 分组管理
- [x] SQLite 持久化
- [x] Mock 采集器（演示模式）
- [x] 真实 SSH 采集器（COLLECTOR_MODE=ssh）
- [x] 告警（离线、资源阈值、采集失败）
- [x] 用户与权限（admin / operator / viewer）
- [x] 审计日志 + 保留策略
- [x] 中文界面 + 数据源真伪标识

## Phase 2: NAS Baseline（仅基础，不大而全）

采集前先检查命令是否存在，不存在的指标放入 `unavailable_metrics`，不影响 Phase 1 指标。

### 2a. 存储池与挂载点
- 磁盘设备列表（`lsblk -J`）
- 挂载点基础信息（`df -B1` 已有）
- NAS 存储池基础信息（`zpool list` / `btrfs filesystem show`，如命令存在）

### 2b. SMART 健康
- `smartctl --scan` 发现磁盘
- `smartctl -a /dev/sdX` 解析健康状态、温度、关键属性
- 命令不存在 → `unavailable_metrics: ["smart"]`

### 2c. RAID 状态
- `/proc/mdstat` 解析 mdadm RAID 状态
- 文件不存在 → 跳过，不影响基线

### 2d. Btrfs / ZFS（按需）
- `zpool status` / `zfs list`（存在时解析）
- `btrfs device stats` / `btrfs filesystem usage`（存在时解析）
- 命令不存在 → `unavailable_metrics: ["zfs", "btrfs"]`

### 核心原则
- **高级指标失败不影响 Phase 1 baseline**
- 每个采集项独立 try/except，失败不影响其他指标
- 缺失的命令记录到 `unavailable_metrics`，不触发告警
- 前端对 `unavailable_metrics` 仅显示黄条提示，不显示为错误

## Phase 3: 告警增强（后续）
- 多级阈值告警
- 告警静默期
- Webhook 通知（飞书/钉钉/企业微信）

## Phase 4: 灰度与权限（后续）
- Action-based policy
- 资源级权限
- 独立 auditor 角色

## 不在当前计划
- VPN 隧道管理
- 文件同步任务
- 高危远程控制
- 公网自动扫描
- 任意命令执行

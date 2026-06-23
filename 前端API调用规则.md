# HomeInfra 前端 API 调用规则

这份文档按当前后端行为整理，供前端开发和联调用。

## 1. 总体规则

- API 前缀：`/api/v1`
- 所有响应统一为：

```json
{
  "data": {},
  "error": null,
  "meta": {
    "request_id": "req-000001"
  }
}
```

- 失败时读取：
  - `error.code`
  - `error.message`
  - `error.details`
- 前端不要自己拼权限逻辑，按钮显隐只能作为体验优化，最终以后端返回为准。
- 除初始化和登录外，默认都要带：

```http
Authorization: Bearer <token>
```

## 2. 认证流

### 2.1 首次初始化检查

请求：

```http
GET /api/v1/auth/bootstrap
```

返回：

```json
{
  "required": true,
  "user_count": 0
}
```

前端规则：
- `required=true`：显示“创建首位管理员”页
- `required=false`：显示登录页

### 2.2 创建首位管理员

请求：

```http
POST /api/v1/auth/bootstrap
Content-Type: application/json
```

请求体：

```json
{
  "username": "admin",
  "password": "ExampleAdminPass123"
}
```

返回重点：

```json
{
  "user": {
    "id": "user-00001",
    "username": "admin",
    "role": "admin",
    "enabled": true
  },
  "token": "..."
}
```

前端规则：
- 成功后立刻保存 `token`
- 再请求 `GET /auth/me`
- 进入主界面

### 2.3 登录

请求：

```http
POST /api/v1/auth/login
Content-Type: application/json
```

请求体：

```json
{
  "username": "admin",
  "password": "ExampleAdminPass123"
}
```

返回重点：

```json
{
  "user": {
    "id": "user-00001",
    "username": "admin",
    "role": "admin",
    "enabled": true
  },
  "token": "..."
}
```

前端规则：
- 只支持用户名/密码登录
- 请求头不支持 `X-Role`
- 令牌存在 `sessionStorage`

### 2.4 当前身份

请求：

```http
GET /api/v1/auth/me
Authorization: Bearer <token>
```

返回重点：

```json
{
  "id": "user-00001",
  "username": "admin",
  "role": "admin",
  "subject": "user:admin",
  "auth_scheme": "bearer",
  "session_id": "sess-00001",
  "session_expires_at": "2026-06-29T00:00:00Z"
}
```

前端规则：
- 用它决定当前角色
- `role` 仅用于页面展示和按钮显隐

### 2.5 注销

请求：

```http
POST /api/v1/auth/logout
Authorization: Bearer <token>
```

前端规则：
- 成功后删除本地 token
- 回到登录页

## 3. 页面与接口映射

### 3.1 Dashboard

请求：

```http
GET /api/v1/dashboard
```

返回重点：

```json
{
  "summary": {
    "total_devices": 5,
    "online_devices": 2,
    "warning_devices": 1,
    "offline_devices": 2,
    "active_alerts": 3,
    "groups": 6,
    "average_cpu_percent": 18.0,
    "average_memory_percent": 37.0,
    "storage_pool_risks": 1,
    "latest_collection_at": "2026-06-22T08:00:00Z",
    "health_score": 55
  },
  "monitoring": {},
  "recent_audit": []
}
```

前端只建议使用：
- `summary`
- `monitoring`
- `recent_audit`

主页面应以 `summary`、`monitoring`、`recent_audit` 为主。

### 3.2 设备分组页

列表：

```http
GET /api/v1/device-groups
```

返回：

```json
{
  "groups": [
    {
      "id": "grp-nas",
      "name": "NAS",
      "description": "家庭 NAS 与存储设备",
      "color": "#2f855a",
      "icon": "hard-drive",
      "sort_order": 10,
      "device_count": 3,
      "online_count": 1,
      "offline_count": 1,
      "warning_count": 1,
      "active_alert_count": 2
    }
  ]
}
```

详情：

```http
GET /api/v1/device-groups/{id}
```

创建：

```http
POST /api/v1/device-groups
```

请求体：

```json
{
  "name": "NAS",
  "description": "家庭 NAS 与存储设备",
  "color": "#2f855a",
  "icon": "hard-drive",
  "sort_order": 10
}
```

编辑：

```http
PATCH /api/v1/device-groups/{id}
```

删除：

```http
DELETE /api/v1/device-groups/{id}
```

前端规则：
- 删除成功后，设备自动移到“未分组”
- `grp-ungrouped` 不应展示删除按钮

### 3.3 设备列表页

列表：

```http
GET /api/v1/devices
```

支持查询参数：

- `group_id`
- `group`
- `device_type`
- `status`
- `enabled`

示例：

```http
GET /api/v1/devices?group_id=grp-nas&enabled=true
```

返回：

```json
{
  "devices": [
    {
      "id": "dev-nas-01",
      "name": "群晖 NAS",
      "host": "192.0.2.20",
      "port": 22,
      "username": "monitor",
      "auth_type": "private_key",
      "private_key_path": "***configured***",
      "encrypted_private_key": null,
      "device_type": "nas",
      "group_id": "grp-nas",
      "group": {
        "id": "grp-nas",
        "name": "NAS"
      },
      "tags": ["存储", "关键设备"],
      "enabled": true,
      "poll_interval": 60,
      "last_seen": "2026-06-22T08:00:00Z",
      "status": "warning"
    }
  ]
}
```

详情：

```http
GET /api/v1/devices/{id}
```

返回重点：

- 基础字段
- `group`
- `recent_collections`
- `alerts`

创建：

```http
POST /api/v1/devices
```

最低请求体：

```json
{
  "name": "家庭服务器",
  "host": "192.0.2.30",
  "group_id": "grp-ungrouped"
}
```

推荐完整体：

```json
{
  "name": "家庭服务器",
  "host": "192.0.2.30",
  "port": 22,
  "username": "monitor",
  "auth_type": "private_key",
  "private_key_path": "/keys/server",
  "device_type": "linux_server",
  "group_id": "grp-servers",
  "tags": ["家庭", "服务"],
  "enabled": true,
  "poll_interval": 60,
  "status": "unknown"
}
```

编辑：

```http
PATCH /api/v1/devices/{id}
```

删除：

```http
DELETE /api/v1/devices/{id}
```

前端规则：
- `admin` 可编辑所有字段
- `operator` 只能编辑普通字段，不能改：
  - `username`
  - `password`
  - `private_key_path`
  - `encrypted_private_key`
  - `auth_type`
- 保存成功后建议立刻调用一次：

```http
POST /api/v1/devices/{id}/refresh
```

让详情页立即出现第一条采集记录。

### 3.4 设备测试连接

```http
POST /api/v1/devices/{id}/test
```

请求体：

```json
{
  "timeout": 5
}
```

返回重点：

```json
{
  "device": {},
  "record": {
    "status": "healthy",
    "summary": "SSH 只读探测完成"
  },
  "alerts": [],
  "purpose": "test"
}
```

### 3.5 手动刷新设备

```http
POST /api/v1/devices/{id}/refresh
```

请求体：

```json
{
  "timeout": 5
}
```

返回重点：

```json
{
  "device": {},
  "record": {
    "status": "warning",
    "summary": "NAS 在线，但存储池与磁盘状态存在风险",
    "payload": {}
  },
  "alerts": [],
  "purpose": "refresh"
}
```

前端规则：
- 设备新增成功后应自动刷新一次
- 刷新完成后再重拉设备详情和 Dashboard

### 3.6 历史记录页

全局历史：

```http
GET /api/v1/collections
```

支持查询参数：

- `device_id`
- `group_id`
- `group`
- `status`
- `since`
- `until`
- `start_at`
- `end_at`
- `limit`

示例：

```http
GET /api/v1/collections?device_id=dev-nas-01&status=warning&since=2026-06-01T00:00:00Z&until=2026-06-30T23:59:59Z&limit=100
```

返回：

```json
{
  "records": [
    {
      "id": "col-00001",
      "device_id": "dev-nas-01",
      "group_id": "grp-nas",
      "device_name": "群晖 NAS",
      "purpose": "refresh",
      "collector": "mock",
      "command": "cat /proc/stat && free -m && df -h && lsblk",
      "collected_at": "2026-06-22T08:00:00Z",
      "status": "warning",
      "summary": "存储池使用率 92%，RAID 状态降级",
      "payload": {},
      "error_message": null
    }
  ]
}
```

设备详情里的历史：

```http
GET /api/v1/devices/{id}/collections?limit=20
```

前端规则：
- 历史页以 `/collections` 为主
- 设备详情页优先用 `/devices/{id}` 返回的 `recent_collections`
- 不要在前端保存历史副本

### 3.7 告警页

```http
GET /api/v1/alerts
```

支持查询参数：

- `device_id`
- `group_id`
- `group`
- `status`

处理告警：

```http
POST /api/v1/alerts/{id}/resolve
```

前端规则：
- `operator` / `admin` 可处理
- `viewer` 不显示处理按钮
- 处理成功后刷新：
  - 告警列表
  - 设备详情
  - Dashboard

### 3.8 用户管理页

列表：

```http
GET /api/v1/users
```

返回：

```json
{
  "users": [
    {
      "id": "user-00001",
      "username": "admin",
      "role": "admin",
      "enabled": true,
      "created_at": "...",
      "updated_at": "...",
      "last_login_at": "..."
    }
  ]
}
```

创建：

```http
POST /api/v1/users
```

请求体：

```json
{
  "username": "operator1",
  "password": "ExampleOperatorPass123",
  "role": "operator",
  "enabled": true
}
```

编辑角色/启用状态：

```http
PATCH /api/v1/users/{id}
```

请求体：

```json
{
  "role": "viewer",
  "enabled": false
}
```

重置密码：

```http
POST /api/v1/users/{id}/reset-password
```

请求体：

```json
{
  "password": "NewPassword123"
}
```

前端规则：
- 这一页只对 `admin` 可见
- 前端不要假设存在 `display_name`
- 用户列表中不要展示任何 hash/salt

### 3.9 设置页 / 保留策略

读取：

```http
GET /api/v1/settings/retention
```

返回：

```json
{
  "collection_history_days": 90,
  "audit_log_days": 180,
  "resolved_alert_days": 180
}
```

更新：

```http
PATCH /api/v1/settings/retention
```

请求体：

```json
{
  "collection_history_days": 90,
  "audit_log_days": 180,
  "resolved_alert_days": 180
}
```

手动清理：

```http
POST /api/v1/settings/retention/cleanup
```

返回：

```json
{
  "retention_settings": {},
  "deleted": {
    "collection_records": 12,
    "audit_logs": 3,
    "resolved_alerts": 4
  },
  "active_alerts_preserved": 2
}
```

前端规则：
- 这一页只对 `admin` 可见
- 不再使用 `auto_cleanup`
- 页面上应有“立即清理”按钮

## 4. 前端必须避免的做法

- 不要再发送 `X-Role`
- 权限判断应完全以后端返回结果为准
- 不要在前端保存密码、私钥、token 到业务数据结构里
- 不要把本地 `localStorage` 当设备/分组主存储
- 不要依赖未在当前接口文档中定义的额外字段

## 5. 推荐前端状态流

1. 页面启动
   - `GET /auth/bootstrap`
   - `required=true` -> 初始化页
   - 否则尝试从 `sessionStorage` 恢复 token
2. token 存在
   - `GET /auth/me`
   - 成功 -> 主界面
   - 失败 -> 登录页
3. 登录后
   - 并发拉：
     - `/dashboard`
     - `/device-groups`
     - `/devices`
     - `/alerts`
     - `/metrics`
   - 按页面再补拉：
     - `/collections`
     - `/users`
     - `/settings/retention`
     - `/audit`

## 6. 推荐前端主流程依赖

如果你要重构前端，建议直接围绕：

- `auth`
- `users`
- `device-groups`
- `devices`
- `collections`
- `alerts`
- `settings/retention`
- `dashboard`

来重做。  

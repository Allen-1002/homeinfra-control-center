# API

前缀：

```text
/api/v1
```

## 初始化与认证

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/auth/bootstrap` | 公开 | 查看是否需要创建首位管理员 |
| POST | `/auth/bootstrap` | 公开 | 创建首位管理员 |
| POST | `/auth/login` | 公开 | 用户名密码登录 |
| POST | `/auth/logout` | viewer+ | 注销当前会话 |
| GET | `/auth/me` | viewer+ | 当前登录用户 |

## 用户管理

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/users` | admin | 查看用户列表 |
| POST | `/users` | admin | 创建用户 |
| PATCH | `/users/{id}` | admin | 修改角色或启用状态 |
| POST | `/users/{id}/reset-password` | admin | 重置密码 |

## 设备分组

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/device-groups` | viewer | 查看分组列表 |
| POST | `/device-groups` | admin | 创建分组 |
| GET | `/device-groups/{id}` | viewer | 查看分组详情 |
| PATCH | `/device-groups/{id}` | admin | 编辑分组 |
| DELETE | `/device-groups/{id}` | admin | 删除分组，设备移到未分组 |

## 设备

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/devices` | viewer | 查看设备列表 |
| POST | `/devices` | admin | 创建设备 |
| GET | `/devices/{id}` | viewer | 查看设备详情 |
| PATCH | `/devices/{id}` | admin / operator | 更新设备；operator 不能改 SSH 凭据 |
| DELETE | `/devices/{id}` | admin | 删除设备 |
| POST | `/devices/{id}/test` | operator | 测试连接 |
| POST | `/devices/{id}/refresh` | operator | 刷新设备 |
| GET | `/devices/{id}/collections` | viewer | 查看设备采集历史 |

## 历史记录

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/collections` | viewer | 查看采集历史 |

支持参数：

- `device_id`
- `group_id`
- `group`
- `status`
- `since`
- `until`
- `start_at`
- `end_at`
- `limit`

## 告警

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/alerts` | viewer | 查看告警列表 |
| POST | `/alerts/{id}/resolve` | operator | 处理告警 |

支持参数：

- `device_id`
- `group_id`
- `group`
- `status`

## 保留策略

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/settings/retention` | admin | 查看保留策略 |
| PATCH | `/settings/retention` | admin | 更新保留策略 |
| POST | `/settings/retention/cleanup` | admin | 手动清理过期数据 |

字段：

- `collection_history_days`
- `audit_log_days`
- `resolved_alert_days`

## 健康与指标

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| GET | `/health/live` | viewer | 存活检查 |
| GET | `/health/ready` | viewer | 就绪检查 |
| GET | `/ready` | viewer | 就绪别名 |
| GET | `/metrics` | viewer | 指标与库存概要 |
| GET | `/dashboard` | viewer | 仪表盘汇总 |
| GET | `/audit` | operator | 审计日志 |

## 统一返回

成功：

```json
{
  "data": {},
  "error": null,
  "meta": {
    "request_id": "req-000001"
  }
}
```

失败：

```json
{
  "data": null,
  "error": {
    "code": "forbidden",
    "message": "权限不足"
  },
  "meta": {
    "request_id": "req-000002"
  }
}
```

## 错误码

- `auth_required`
- `forbidden`
- `not_found`
- `conflict`
- `validation_error`
- `confirmation_required`
- `internal_error`

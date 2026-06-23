# Security

## 当前安全边界

项目当前是本地优先的家庭设备监控面板。

默认边界：

- 首次启动必须创建管理员
- 后续通过真实用户名/密码登录换取 Bearer Token 会话
- 默认不连接真实 SSH
- 默认不执行任何危险命令

## 认证与会话

当前实现：

- 密码使用 `hashlib.pbkdf2_hmac` + 随机 salt
- 每个用户独立保存 `password_hash`、`password_salt`、`password_iterations`
- 登录后签发高熵 Bearer Token，并在登录/初始化响应里返回给客户端一次
- 会话在 SQLite 中只持久化 `token_hash`
- 内置 HTTP 服务按直连客户端 IP + 用户名限速：5 分钟内失败 5 次后，会进入 5 分钟冷却
- 禁用用户或重置密码时会撤销已有会话

注意：

- 当前是 Bearer Token，不是 cookie session
- 当前没有 CSRF 机制，因为不是 cookie 模式
- 当前不适合直接暴露到公网
- 当前内置限速默认使用直连 socket IP，不信任客户端自行提交的代理头

## 权限

- `viewer`：只读
- `operator`：刷新设备、测试连接、处理告警、修改普通字段
- `admin`：用户管理、设备管理、分组管理、敏感凭据和保留策略

后端会真实校验权限，不依赖前端按钮隐藏。

## SSH 安全原则

真实 SSH 采集只有在显式启用 `COLLECTOR_MODE=ssh` 或 `--collector-mode=ssh` 时启用。

安全要求：

- 强制 timeout
- 只允许白名单只读命令
- 默认拒绝未知 host key
- 不允许任意命令执行
- 不记录密码、私钥、token

禁止命令包括但不限于：

- `rm`
- `dd`
- `mkfs`
- `reboot`
- `shutdown`
- `iptables`
- `poweroff`

## 敏感字段

以下字段不会通过 API 明文返回：

- `password`
- `password_hash`
- `password_salt`
- `private_key_path`
- `encrypted_private_key`
- `token_hash`

审计日志也会对敏感字段做脱敏。

存储语义需要额外区分：

- 用户登录密码不会明文持久化，只保存 `password_hash`、`password_salt`、`password_iterations`
- Bearer Token 只在签发时返回给客户端，SQLite 中只保存 `token_hash`
- 设备 SSH 凭据目前仍会落 SQLite：`password` 为应用可读明文，`private_key_path` 与 `encrypted_private_key` 按传入值持久化
- 因此 API 脱敏不等于底层数据库不保存，数据库文件和备份仍应按敏感数据处理

## 历史记录与清理

- 每次设备刷新/采集都会产生历史记录
- 历史记录不保存密码、密钥、token
- cleanup 只删除过期历史、过期审计和已处理告警
- cleanup 不会删除活跃告警
- cleanup 会写审计日志

## SQLite 限制

当前 SQLite 是轻量持久化方案，适合单机场景。

限制：

- 不适合高并发多实例写入
- 当前仍是 JSON 状态存储，不是细粒度关系模型

## Docker 安全

Compose 默认：

- 使用默认 `HOST_BIND=127.0.0.1` 时，只绑定到本机回环地址
- `read_only: true`
- `cap_drop: ALL`
- `no-new-privileges: true`
- 非 root 运行

## 人工检查建议

- 不要把真实 `.env`、SSH 私钥或密码提交进仓库
- 启用真实 SSH 前，先核对 host key 和监控账号权限
- 如果未来要暴露到共享环境，应先补真实认证前置层或反向代理策略

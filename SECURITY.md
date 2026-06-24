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
- 登录限流是轻量级进程内状态：5 分钟内失败 5 次后进入 5 分钟冷却；进程重启会清零，多实例之间不共享。如果未来暴露到共享环境，应迁移到 SQLite/Redis 持久化限流，或交给反向代理/WAF 统一做限流
- 当前 `extract_client_ip` 不信任客户端提交的 `X-Forwarded-For` 等代理头，默认使用直连 socket 来源 IP，避免 header 伪造。代价是：部署在反向代理后面时，多个用户可能被视为同一个代理 IP，导致限流粒度变粗。未来可增加 `TRUSTED_PROXY_CIDRS` 配置，或由反代/WAF 负责真实 IP 透传与限流

## 权限

- `viewer`：只读
- `operator`：刷新设备、测试连接、处理告警、查看审计、修改非连接类普通字段
- `admin`：用户管理、设备管理、分组管理、敏感凭据和保留策略

后端会真实校验权限，不依赖前端按钮隐藏。

## SSH 安全原则

真实 SSH 采集只有在显式启用 `COLLECTOR_MODE=ssh` 或 `--collector-mode=ssh` 时启用。

安全要求：

- 强制 timeout
- 采集只执行应用内置的只读 probe 命令（按设备类型固定，不可由用户配置）
- 每条命令在执行前经过命令安全校验：字符白名单 + 危险 token denylist
- 默认拒绝未知 host key
- 不允许任意命令执行
- 不在审计日志、错误响应或普通设备 API 中返回密码、私钥路径、token 或授权头

当前并未实现用户可配置的命令 allowlist；命令集合由应用内置 probe 决定。Phase-2 可考虑改为 probe-id allowlist，由管理员显式启用/禁用某些 probe。

危险 token denylist 包括但不限于：

- `rm`
- `dd`
- `mkfs`
- `reboot`
- `shutdown`
- `iptables`
- `poweroff`

## 敏感字段

以下字段不会通过普通设备 API、审计日志和错误响应明文返回：

- `password`
- `password_hash`
- `password_salt`
- `authorization`
- `private_key_path`
- `inline_private_key`
- `token_hash`
- `token`

审计日志会直接移除这些敏感字段，而不是回显占位值。

存储语义需要额外区分：

- 用户登录密码不会明文持久化，只保存 `password_hash`、`password_salt`、`password_iterations`
- Bearer Token 只在签发时返回给客户端，SQLite 中只保存 `token_hash`
- 设备 SSH 首选外部私钥文件路径：`private_key_path`
- 密码认证不会把提交的明文 SSH 密码原样持久化；应用只保留“需要外部凭据源”的占位信息
- 当前实现不接受内联私钥内容，也不依赖误导性的“已加密私钥字符串”字段
- 在真实 SSH 采集模式（`COLLECTOR_MODE=ssh`）下，password 认证设备不会再使用落库明文密码采集；如果没有外部凭据源注入，这类设备的采集会失败，推荐改用只读低权限 `key_path`
- 数据库文件和备份仍应按敏感资产处理，因为其中仍包含主机地址、用户名、会话 hash 和外部私钥路径引用

## 升级与凭据轮换

- 升级到本版本后，旧的明文 SSH 密码（`devices.password`）会在首次加载时被非破坏性清理：password 认证设备改写为外部凭据占位符，其他认证类型置空；历史 `encrypted_private_key` 内联密钥也会被清空。该迁移不删除任何列
- 旧明文凭据应视为已暴露：升级后请立即轮换受影响设备的 SSH 密码或改用 `key_path`
- password 认证设备在真实 SSH 采集模式下需要外部凭据源，否则采集会失败；如不具备外部凭据源，请改用只读低权限 SSH 私钥路径

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
- `APP_HOST` 只控制容器内监听；真正的宿主机暴露面由 `HOST_BIND` 控制
- `read_only: true`
- `cap_drop: ALL`
- `no-new-privileges: true`
- 非 root 运行

## 前端资源

- 浏览器端静态资源默认全部从本地 `static/` 提供
- `Chart.js` 已固定版本并 vendor 到 `static/vendor/`
- 默认策略不依赖外部 CDN
- `Content-Security-Policy` 当前仍保留 `script-src 'unsafe-inline'` 与 `style-src 'unsafe-inline'`：`index.html` 本身没有内联 `<script>` 块，但 `app.js` 动态生成的 HTML 大量使用内联事件处理器（`onclick`/`onsubmit`/`onchange` 等）和内联 `style` 属性，移除 `unsafe-inline` 会导致 UI 失效。Phase-2 计划将内联事件处理器重构为 `addEventListener` + `data-*` 属性、内联样式抽取到外部样式表，再逐步收紧 CSP

## 人工检查建议

- 不要把真实 `.env`、SSH 私钥或密码提交进仓库
- 启用真实 SSH 前，先核对 host key 和监控账号权限
- 如果未来要暴露到共享环境，应先补真实认证前置层或反向代理策略

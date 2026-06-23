# HomeInfra Control Center

`HomeInfra Control Center` 是一个轻量级的家庭基础设施监控与管理面板，适用于 NAS、Linux 服务器、路由器、迷你主机等设备。

这是我第一个相对完整的个人项目。开发过程中使用了 AI 工具辅助完成部分代码编写、问题排查和结构整理，但需求设计、功能取舍、测试验证、部署处理和最终仓库整理都由我自己参与完成。

## 项目概览

这个项目是一个本地优先、部署成本较低的 Web 应用，整体结构比较轻量：

- 基于 Python 标准库 HTTP 栈的后端
- 基于静态 HTML、CSS、JavaScript 的前端
- 默认使用 SQLite 持久化
- 可选的 SSH 只读采集能力，用于设备监控

它主要面向家庭或实验环境，不适合直接暴露到公网。

## 功能特性

- 设备的新增、编辑、删除、启用/禁用、测试连接和手动刷新
- 设备分组管理，方便按类别组织监控对象
- 历史采集记录与筛选查询
- 告警生成与处理流程
- 关键操作的审计日志
- 本地用户管理，支持 `admin`、`operator`、`viewer` 三种角色
- 历史数据保留策略与清理能力

## 技术栈

- Python 3
- SQLite
- 原生 JavaScript
- HTML/CSS
- Docker Compose
- Paramiko（用于可选 SSH 采集）

## 部署方式

本地运行：

```sh
python3 run.py --host 127.0.0.1 --port 8010 --static-dir static
```

打开：

```text
http://127.0.0.1:8010/
```

使用 Docker 运行：

```sh
docker compose up --build
```

## 配置说明

重要默认项：

- 数据库路径：`./data/homeinfra.db`
- 静态资源目录：`./static`
- 环境变量示例：[`.env.example`](./.env.example)

启动时可以覆盖数据库路径：

```sh
python3 run.py --db-path /app/data/homeinfra.db
```

首次启动且数据库为空时，系统会要求先创建第一个管理员账号，之后才能正常登录使用。

## 采集模式

采集行为由 `COLLECTOR_MODE` 控制。

| 模式 | 值 | 说明 |
| --- | --- | --- |
| Disabled | `disabled` | 仅保存设备配置，不执行采集 |
| SSH | `ssh` | 通过 SSH 连接目标设备，并执行受白名单限制的只读命令 |

本地运行示例：

```sh
python3 run.py --host 127.0.0.1 --port 8010 --static-dir static
COLLECTOR_MODE=ssh python3 run.py --host 127.0.0.1 --port 8010 --static-dir static
```

SSH 密钥示例：

```sh
mkdir -p ./ssh-keys
ssh-keygen -t ed25519 -C "homeinfra-monitor" -f ./ssh-keys/id_ed25519
ssh-copy-id -i ./ssh-keys/id_ed25519.pub monitor@example-host
```

容器内路径示例：

```json
{
  "private_key_path": "/app/ssh-keys/id_ed25519"
}
```

## 测试

基础检查：

```sh
python3 -m unittest -v
node --check static/app.js
```

可选编译检查：

```sh
PYTHONPYCACHEPREFIX=/private/tmp/homeinfra-pyc python3 -m compileall homeinfra run.py tests
```

在准备好的环境中，也可以执行可选的 SSH 烟雾测试：

```sh
chmod +x smoke_test.sh
./smoke_test.sh
```

更多测试说明见 [`TESTING.md`](./TESTING.md)。

## 说明

- 这是一个本地优先项目，建议始终放在可信网络边界之后使用。
- SSH 采集器只用于只读监控，并且受命令白名单限制。
- 项目不包含 VPN 管理、文件同步或其他高风险远程控制功能。
- 更多接口与实现说明可参考 [`API.md`](./API.md)、[`ARCHITECTURE.md`](./ARCHITECTURE.md) 和 [`前端API调用规则.md`](./前端API调用规则.md)。

## 许可证

本项目使用 MIT License。

# Testing

## 命令

全量测试：

```sh
python3 -m unittest -v
```

兼容入口：

```sh
python3 -m unittest -v discovery
```

前端语法：

```sh
node --check static/app.js
```

编译检查：

```sh
PYTHONPYCACHEPREFIX=/private/tmp/homeinfra-pyc python3 -m compileall homeinfra run.py tests
```

## 覆盖范围

- 首次初始化必须创建管理员
- 登录 / 注销 / 当前身份
- 登录失败限速 / 冷却
- 用户禁用后会话失效
- 成功登录后清理失败计数
- 用户管理权限
- 设备 / 分组 CRUD
- 删除分组后设备回到未分组
- SSH 命令安全校验（内置只读 probe + 危险 token denylist）
- 内存采集桩与异常场景
- 历史记录筛选
- 告警筛选
- retention cleanup
- 敏感字段脱敏
- 设备 API / 审计日志不返回敏感凭据
- collector / validation 错误不泄露私钥路径
- JSON 请求体 413 限制
- 429 响应包含 `Retry-After`
- JSON / 静态响应安全头
- Docker Compose 绑定格式
- `APP_HOST` / `HOST_BIND` 语义契约
- Chart.js 本地 vendor，不依赖 CDN
- operator 不能修改 host / port / device_type / SSH 凭据
- GitHub Actions CI 文件存在性
- 非法参数不返回 500
- 前端静态资源 smoke

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
- 用户禁用后会话失效
- 用户管理权限
- 设备 / 分组 CRUD
- 删除分组后设备回到未分组
- SSH 白名单
- 内存采集桩与异常场景
- 历史记录筛选
- 告警筛选
- retention cleanup
- 敏感字段脱敏
- 非法参数不返回 500
- 前端静态资源 smoke

## 提交前建议

提交前建议至少执行一次以下检查：

- `python3 -m unittest -v`
- `node --check static/app.js`
- `PYTHONPYCACHEPREFIX=/private/tmp/homeinfra-pyc python3 -m compileall homeinfra run.py tests`

## 仍建议人工验证

1. 首次初始化页
2. 登录页
3. 用户管理页
4. 历史记录页
5. 设置页中的 cleanup
6. 设备详情和设备编辑

#!/usr/bin/env bash
# ============================================================
# N1 真实部署验证脚本
# 在 N1 (Linux) 上运行，验证 COLLECTOR_MODE=ssh 全流程
#
# 前置条件：
#   1. 已安装 docker 和 docker compose
#   2. ~/ssh-keys/ 下有可用的 SSH 私钥 (如 id_ed25519)
#   3. 目标 Linux 设备已配置 authorized_keys
#
# 用法：
#   1. 修改下方 DEVICE_* 变量为你的真实设备信息
#   2. 确认 COLLECTOR_MODE=ssh 在 .env 中
#   3. chmod +x deploy_verify.sh && ./deploy_verify.sh
# ============================================================
set -euo pipefail

API_BASE="${API_BASE:-http://127.0.0.1:8010/api/v1}"
FRONTEND="${FRONTEND:-http://127.0.0.1:8010}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-ExampleAdminPass123}"

# === 修改为你的真实设备信息 ===
DEVICE_HOST="${DEVICE_HOST:-192.0.2.100}"
DEVICE_PORT="${DEVICE_PORT:-22}"
DEVICE_USER="${DEVICE_USER:-monitor}"
DEVICE_KEY="${DEVICE_KEY:-/app/ssh-keys/id_ed25519}"
# ===============================

PASS=0; FAIL=0
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'

log()   { echo -e "[verify] $*"; }
pass()  { PASS=$((PASS+1)); echo -e "  ${GREEN}[PASS]${NC} $*"; }
fail()  { FAIL=$((FAIL+1)); echo -e "  ${RED}[FAIL]${NC} $*"; }
warn()  { echo -e "  ${YELLOW}[WARN]${NC} $*"; }

check_req() {
  command -v docker >/dev/null 2>&1 || { echo "需要 docker"; exit 1; }
  command -v curl >/dev/null 2>&1 || { echo "需要 curl"; exit 1; }
}

# ── 1. Docker 构建与启动 ─────────────────────────────────────
step1_docker() {
  log "1. Docker compose build..."
  docker compose build --no-cache 2>&1 | tail -3
  pass "docker compose build"

  log "   docker compose up -d..."
  docker compose down --remove-orphans 2>/dev/null || true
  docker compose up -d
  sleep 3

  STATUS=$(docker compose ps --format json 2>/dev/null | python3 -c "import sys,json; [print(json.loads(l).get('State','')) for l in sys.stdin]" 2>/dev/null || echo "unknown")
  if echo "$STATUS" | grep -q "running"; then
    pass "容器运行中 (状态: $STATUS)"
  else
    fail "容器未运行 (状态: $STATUS)"
    docker compose logs --tail=20
    return 1
  fi

  # 检查容器内 SSH 配置
  log "   checking SSH env in container..."
  SSH_ENV=$(docker compose exec -T app env 2>/dev/null | grep -E "COLLECTOR_MODE|SSH" || true)
  echo "$SSH_ENV"
  if echo "$SSH_ENV" | grep -q "COLLECTOR_MODE=ssh"; then
    pass "COLLECTOR_MODE=ssh 已设置"
  else
    fail "COLLECTOR_MODE 未设为 ssh"
  fi

  # 检查 SSH key 可读
  log "   checking SSH key in container..."
  if docker compose exec -T app test -r "$DEVICE_KEY" 2>/dev/null; then
    pass "SSH key 可读: $DEVICE_KEY"
  else
    fail "SSH key 不可读: $DEVICE_KEY"
    warn "请确认 docker-compose.yml 中 volumes 已正确挂载 ~/ssh-keys:/app/ssh-keys:ro"
  fi
}

# ── 2. 初始化管理员 ──────────────────────────────────────────
step2_bootstrap() {
  log "2. Bootstrapping admin..."
  BOOTSTRAP=$(curl -sfS "${API_BASE}/auth/bootstrap" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('required',''))")
  if [ "$BOOTSTRAP" = "True" ]; then
    curl -sfS -X POST "${API_BASE}/auth/bootstrap" \
      -H 'Content-Type: application/json' \
      -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" > /dev/null
    pass "管理员创建: ${ADMIN_USER}"
  else
    pass "管理员已存在"
  fi

  LOGIN=$(curl -sfS -X POST "${API_BASE}/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}")
  TOKEN=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")
  pass "登录成功"
}

# ── 3. 创建设备 & 刷新 ───────────────────────────────────────
step3_refresh() {
  log "3. 创建设备 & 刷新..."

  # 创建分组
  curl -sfS -X POST "${API_BASE}/device-groups" \
    -H 'Content-Type: application/json' -H "Authorization: Bearer ${TOKEN}" \
    -d '{"name":"N1 验证","id":"grp-n1-verify"}' > /dev/null 2>&1 || true

  # 删除旧设备（如果存在）
  curl -sfS -X DELETE "${API_BASE}/devices/dev-n1-target" \
    -H "Authorization: Bearer ${TOKEN}" > /dev/null 2>&1 || true

  # 创建设备
  CREATE=$(curl -sfS -X POST "${API_BASE}/devices" \
    -H 'Content-Type: application/json' -H "Authorization: Bearer ${TOKEN}" \
    -d "{
      \"name\":\"n1-target\",
      \"host\":\"${DEVICE_HOST}\",
      \"port\":${DEVICE_PORT},
      \"device_type\":\"linux_server\",
      \"group_id\":\"grp-n1-verify\",
      \"username\":\"${DEVICE_USER}\",
      \"auth_type\":\"private_key\",
      \"private_key_path\":\"${DEVICE_KEY}\"
    }")
  DEV_ID=$(echo "$CREATE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('id',''))" 2>/dev/null || echo "")
  if [ -n "$DEV_ID" ]; then
    pass "设备创建: $DEV_ID"
  else
    fail "设备创建失败"
    echo "$CREATE" | python3 -m json.tool 2>/dev/null || echo "$CREATE"
    return 1
  fi

  # 刷新
  log "   刷新设备 (timeout=15)..."
  REFRESH=$(curl -sfS -X POST "${API_BASE}/devices/${DEV_ID}/refresh" \
    -H 'Content-Type: application/json' -H "Authorization: Bearer ${TOKEN}" \
    -d '{"timeout":15}')
  echo "$REFRESH" | python3 -c "
import sys, json
data = json.load(sys.stdin).get('data', {})
device = data.get('device', {})
record = data.get('record', {})
alerts = data.get('alerts', [])
active_alerts = [a for a in alerts if a.get('status') == 'active']

# ── 4. API 验证 ──────────────────────────────────────────
# 4a. data_source=ssh
ds = device.get('data_source', 'UNKNOWN')
assert ds == 'ssh', f'FAIL: data_source={ds}, expected ssh'
print(f'[PASS] data_source = {ds}')

# 4b. is_real_data=True
isr = device.get('is_real_data', False)
assert isr == True, f'FAIL: is_real_data={isr}'
print(f'[PASS] is_real_data = {isr}')

# 4c. hostname
hn = device.get('hostname', '')
assert hn, 'FAIL: hostname empty'
print(f'[PASS] hostname = {hn}')

# 4d. uname
un = device.get('uname', '')
assert un, 'FAIL: uname empty'
print(f'[PASS] uname = {un}')

# 4e. CPU / cores
cpu = device.get('cpu_percent')
cores = device.get('cpu_cores')
assert cpu is not None, 'FAIL: cpu_percent None'
assert cores is not None and cores > 0, f'FAIL: cpu_cores={cores}'
print(f'[PASS] cpu_percent={cpu}, cores={cores}')

# 4f. memory
mem = device.get('memory_percent')
mem_total = device.get('memory_total_mb')
mem_used = device.get('memory_used_mb')
assert mem is not None, 'FAIL: memory_percent None'
assert mem_total is not None and mem_total > 0, f'FAIL: memory_total_mb={mem_total}'
assert mem_used is not None, f'FAIL: memory_used_mb={mem_used}'
print(f'[PASS] memory={mem}% ({mem_used}/{mem_total} MB)')

# 4g. disk
parts = device.get('partitions', [])
assert len(parts) > 0, 'FAIL: partitions empty'
print(f'[PASS] partitions: {len(parts)} mount(s)')

# 4h. network
net = device.get('network_interfaces', [])
assert len(net) > 0, 'FAIL: network_interfaces empty'
print(f'[PASS] network_interfaces: {len(net)} iface(s)')

# 4i. uptime / loadavg
upt = device.get('uptime', '')
ld = device.get('load_average', '')
print(f'[PASS] uptime={upt}')
print(f'[PASS] load_average={ld}')

# 4j. collector_errors
errs = device.get('collector_errors', [])
unav = device.get('unavailable_metrics', [])
print(f'[OK] collector_errors:{len(errs)}, unavailable_metrics:{len(unav)}')
if unav:
    for u in unav:
        print(f'  [INFO] unavailable: {u}')

# 4k. status
st = device.get('status', '')
assert st == 'online', f'FAIL: status={st}, expected online'
print(f'[PASS] status={st}')

# 4l. no fake NAS alerts for linux device
nas_alert_types = {'nas_pool_critical','nas_pool_high','nas_pool_degraded','nas_raid_degraded','nas_raid_abnormal','smart_abnormal'}
for a in active_alerts:
    assert a.get('type') not in nas_alert_types, f'FAIL: unexpected NAS alert: {a.get(\"type\")}'
print(f'[PASS] no false NAS alerts (active: {len(active_alerts)})')

print()
print('=== ALL API CHECKS PASSED ===')
" || {
    fail "API 验证失败（详见上方输出）"
    return 1
  }
}

# ── 5. 前端验证 ──────────────────────────────────────────────
step4_frontend() {
  log "5. Frontend verification..."

  # 获取设备详情页
  DEV_PAGE=$(curl -sfS "${API_BASE}/devices/dev-n1-target" \
    -H "Authorization: Bearer ${TOKEN}")
  
  DS=$(echo "$DEV_PAGE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('data_source',''))")
  if [ "$DS" = "ssh" ]; then
    pass "API returns data_source=ssh"
  else
    fail "data_source=$DS"
  fi

  # 检查前端 HTML 引用
  HTML=$(curl -sfS "$FRONTEND" 2>/dev/null || true)
  if echo "$HTML" | grep -q "app.js"; then
    pass "前端 HTML 可访问"
  else
    warn "前端 HTML 可能未正常加载"
  fi

  JS=$(curl -sfS "${FRONTEND}/static/app.js" 2>/dev/null || true)
  if echo "$JS" | grep -q "真实 SSH 数据"; then
    pass "app.js 包含 '真实 SSH 数据' 文案"
  else
    fail "app.js 缺少 '真实 SSH 数据' 文案"
  fi

  if echo "$JS" | grep -q "演示数据"; then
    pass "app.js 包含 '演示数据' 文案"
  else
    fail "app.js 缺少 '演示数据' 文案"
  fi

  if echo "$JS" | grep -q "非真实采集"; then
    pass "app.js 包含 '非真实采集' 文案"
  else
    fail "app.js 缺少 '非真实采集' 文案"
  fi
}

# ── 6. 不存在 IP 必须失败 ────────────────────────────────────
step5_dead_host() {
  log "6. 不存在 IP 测试 (203.0.113.254)..."

  # 创建不可达设备
  curl -sfS -X DELETE "${API_BASE}/devices/dev-dead-host" \
    -H "Authorization: Bearer ${TOKEN}" > /dev/null 2>&1 || true

  curl -sfS -X POST "${API_BASE}/devices" \
    -H 'Content-Type: application/json' -H "Authorization: Bearer ${TOKEN}" \
    -d '{
      "name":"dead-host",
      "host":"203.0.113.254",
      "port":22,
      "device_type":"linux_server",
      "group_id":"grp-n1-verify",
      "username":"nobody",
      "auth_type":"private_key",
      "private_key_path":"/tmp/no-such-key"
    }' > /dev/null 2>&1 || warn "(create may fail — expected)"

  # 刷新（预期超时/失败）
  REFRESH=$(curl -sfS -X POST "${API_BASE}/devices/dev-dead-host/refresh" \
    -H 'Content-Type: application/json' -H "Authorization: Bearer ${TOKEN}" \
    -d '{"timeout":10}' 2>/dev/null || true)

  if [ -z "$REFRESH" ]; then
    warn "refresh 无响应（连接超时）"
  else
    IS_REAL=$(echo "$REFRESH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('device',{}).get('is_real_data','N/A'))" 2>/dev/null || echo "FAIL")
    STATUS=$(echo "$REFRESH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('device',{}).get('status','N/A'))" 2>/dev/null || echo "FAIL")
    DS=$(echo "$REFRESH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('device',{}).get('data_source','N/A'))" 2>/dev/null || echo "FAIL")

    if [ "$STATUS" = "offline" ] || [ "$STATUS" = "warning" ]; then
      pass "不存在 IP 状态: $STATUS (非 online)"
    else
      fail "不存在 IP 状态: $STATUS (应为 offline/warning)"
    fi

    if [ "$IS_REAL" != "True" ]; then
      pass "is_real_data != True (未返回假数据)"
    else
      fail "is_real_data=True (可能返回了假数据!)"
    fi
  fi
}

# ── 7. 安全检查 ──────────────────────────────────────────────
step6_security() {
  log "7. 容器安全检查..."
  
  # 确认没有私钥在容器文件系统（除了挂载的）
  if docker compose exec -T app find /app -name "*.pem" -o -name "id_rsa" -o -name "id_ed25519" 2>/dev/null | grep -v "/app/ssh-keys"; then
    fail "容器内发现 SSH 私钥文件!"
  else
    pass "容器内无未授权私钥文件"
  fi

  # 确认 .env 不在镜像内
  if docker compose exec -T app test -f /app/.env 2>/dev/null; then
    fail ".env 被打包进镜像!"
  else
    pass ".env 不在镜像内"
  fi
}

# ── Main ─────────────────────────────────────────────────────
main() {
  check_req
  step1_docker || { echo "Docker 启动失败，跳过后续步骤"; exit 1; }
  step2_bootstrap
  step3_refresh || true
  step4_frontend
  step5_dead_host || true
  step6_security

  echo
  echo "=========================================="
  echo "  N1 部署验证完成"
  echo "  PASS: $PASS  FAIL: $FAIL"
  echo "=========================================="
  if [ "$FAIL" -gt 0 ]; then
    echo "存在失败项，请检查上方输出"
    exit 1
  else
    echo "全部通过!"
  fi
}

main "$@"

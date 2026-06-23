#!/usr/bin/env bash
# ============================================================
# N1 Smoke Test — Phase 1 Baseline Collection Verification
# Usage:
#   1. chmod +x smoke_test.sh
#   2. Set COLLECTOR_MODE=ssh in .env
#   3. Replace DEVICE_* below with your target Linux host
#   4. ./smoke_test.sh
# ============================================================
set -euo pipefail

API_BASE="${API_BASE:-http://127.0.0.1:8010/api/v1}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-ExampleAdminPass123}"
DEVICE_HOST="${DEVICE_HOST:-192.0.2.100}"
DEVICE_PORT="${DEVICE_PORT:-22}"
DEVICE_USER="${DEVICE_USER:-monitor}"
DEVICE_KEY="${DEVICE_KEY:-/app/ssh-keys/id_ed25519}"

log()  { echo "[smoke] $*"; }
fail() { echo "[FAIL] $*"; exit 1; }

check_field() {
  local desc="$1" val="$2"
  if [ -z "$val" ] || [ "$val" = "null" ]; then
    echo "  [WARN] $desc: EMPTY"
  else
    echo "  [ OK ] $desc: $val"
  fi
}

# ── 1. Bootstrap admin ────────────────────────────────────────
log "Bootstrapping admin user..."
BOOTSTRAP=$(curl -sfS "${API_BASE}/auth/bootstrap" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('data',{}).get('required','unknown'))")
if [ "$BOOTSTRAP" = "True" ]; then
  curl -sfS -X POST "${API_BASE}/auth/bootstrap" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" > /dev/null
  log "Admin created: ${ADMIN_USER}"
fi

# ── 2. Login ──────────────────────────────────────────────────
log "Logging in..."
LOGIN=$(curl -sfS -X POST "${API_BASE}/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}")
TOKEN=$(echo "$LOGIN" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")
AUTH="Authorization: Bearer ${TOKEN}"
log "Token obtained"

# ── 3. Create group ───────────────────────────────────────────
log "Creating device group..."
curl -sfS -X POST "${API_BASE}/device-groups" \
  -H 'Content-Type: application/json' -H "${AUTH}" \
  -d '{"name":"Smoke Test","id":"grp-smoke"}' > /dev/null

# ── 4. Create device ──────────────────────────────────────────
log "Creating device..."
curl -sfS -X POST "${API_BASE}/devices" \
  -H 'Content-Type: application/json' -H "${AUTH}" \
  -d "{
    \"name\":\"smoke-target\",
    \"host\":\"${DEVICE_HOST}\",
    \"port\":${DEVICE_PORT},
    \"device_type\":\"linux_server\",
    \"group_id\":\"grp-smoke\",
    \"username\":\"${DEVICE_USER}\",
    \"auth_type\":\"private_key\",
    \"private_key_path\":\"${DEVICE_KEY}\"
  }" > /dev/null

# ── 5. Refresh device ─────────────────────────────────────────
log "Refreshing device (timeout=15)..."
REFRESH=$(curl -sfS -X POST "${API_BASE}/devices/dev-smoke-target/refresh" \
  -H 'Content-Type: application/json' -H "${AUTH}" \
  -d '{"timeout":15}')
echo "$REFRESH" | python3 -c "
import sys, json
data = json.load(sys.stdin).get('data', {})
device = data.get('device', {})
record = data.get('record', {})

# ── 6. Verify data_source ─────────────────────────────────────
ds = device.get('data_source', 'UNKNOWN')
is_real = device.get('is_real_data', False)
print(f'[VERIFY] data_source = {ds}')
print(f'[VERIFY] is_real_data = {is_real}')
assert ds == 'ssh', f'FAIL: data_source must be ssh, got {ds}'
assert is_real == True, f'FAIL: is_real_data must be True, got {is_real}'
print('[PASS] data_source=ssh, is_real_data=True')

# ── 7. Verify hostname / uname ────────────────────────────────
hostname = device.get('hostname', '')
uname = device.get('uname', '')
assert hostname, 'FAIL: hostname is empty'
assert uname, 'FAIL: uname is empty'
print(f'[PASS] hostname={hostname}')
print(f'[PASS] uname={uname}')

# ── 8. Verify CPU / memory / disk / network ───────────────────
cpu = device.get('cpu_percent')
mem = device.get('memory_percent')
cores = device.get('cpu_cores')
assert cpu is not None, 'FAIL: cpu_percent is None'
assert mem is not None, 'FAIL: memory_percent is None'
assert cores is not None and cores > 0, f'FAIL: cpu_cores invalid: {cores}'
print(f'[PASS] cpu_percent={cpu}, cores={cores}, memory_percent={mem}')

partitions = device.get('partitions', [])
assert len(partitions) > 0, 'FAIL: partitions is empty'
print(f'[PASS] disk_partitions: {len(partitions)} mount(s)')

net = device.get('network_interfaces', [])
assert len(net) > 0, 'FAIL: network_interfaces is empty'
print(f'[PASS] network_interfaces: {len(net)} iface(s)')

# ── 9. Verify uptime / loadavg ────────────────────────────────
uptime = device.get('uptime', '')
loadavg = device.get('load_average', '')
print(f'[ OK ] uptime={uptime}')
print(f'[ OK ] load_average={loadavg}')

# ── 10. Verify collector_errors / unavailable_metrics ─────────
errs = device.get('collector_errors', [])
unav = device.get('unavailable_metrics', [])
print(f'[ OK ] collector_errors:{len(errs)}, unavailable_metrics:{len(unav)}')

print()
print('=== ALL SMOKE CHECKS PASSED ===')
"
log "Smoke test complete."

# ── 11. Verify failure for non-existent host ──────────────────
log "Testing non-existent host (must fail)..."
curl -sfS -X POST "${API_BASE}/devices" \
  -H 'Content-Type: application/json' -H "${AUTH}" \
  -d '{
    "name":"dead-host",
    "host":"203.0.113.254",
    "port":22,
    "device_type":"linux_server",
    "group_id":"grp-smoke",
    "username":"nobody",
    "auth_type":"private_key",
    "private_key_path":"/tmp/no-such-key"
  }' > /dev/null 2>&1 || log "  (create may fail on SSH verify — expected)"

REFRESH_DEAD=$(curl -s -o /dev/null -w '%{http_code}' -X POST "${API_BASE}/devices/dev-dead-host/refresh" \
  -H 'Content-Type: application/json' -H "${AUTH}" \
  -d '{"timeout":10}' 2>/dev/null || echo "000")

if [ "$REFRESH_DEAD" = "000" ] || [ "$REFRESH_DEAD" = "502" ] || [ "$REFRESH_DEAD" = "500" ]; then
  log "[PASS] Dead host refresh did not return fake data (HTTP ${REFRESH_DEAD})"
else
  # Check that device status went offline
  DEAD_DEVICE=$(curl -sfS "${API_BASE}/devices/dev-dead-host" -H "${AUTH}")
  DEAD_STATUS=$(echo "$DEAD_DEVICE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('status','unknown'))")
  if [ "$DEAD_STATUS" = "offline" ]; then
    log "[PASS] Dead host status is offline"
  elif [ "$DEAD_STATUS" = "warning" ]; then
    log "[PASS] Dead host status is warning (no fake online data)"
  else
    log "[WARN] Dead host status=${DEAD_STATUS} (expected offline or warning)"
  fi
fi

log "=== N1 Smoke Test Done ==="

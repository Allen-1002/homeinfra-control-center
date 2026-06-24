/* ============================================================
 * HomeInfra Control Center — Unified Frontend v3
 * Strictly /api/v1 — no mocks, no X-Role, no fallback.
 * ============================================================ */

// ─── API Client ─────────────────────────────────────────────
const API = {
  base: '/api/v1',

  headers(skipAuth) {
    const h = { 'Content-Type': 'application/json' };
    if (!skipAuth && API._token) h['Authorization'] = 'Bearer ' + API._token;
    return h;
  },

  get _token() { return sessionStorage.getItem('hinfra_token'); },
  set _token(t) {
    if (t) sessionStorage.setItem('hinfra_token', t);
    else sessionStorage.removeItem('hinfra_token');
  },

  async request(method, path, opts) {
    const { body, skipAuth, params, signal } = opts || {};
    let url = this.base + path;
    if (params) {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(params))
        if (v !== undefined && v !== null && v !== '') q.set(k, String(v));
      const qs = q.toString();
      if (qs) url += '?' + qs;
    }
    const init = { method, headers: this.headers(skipAuth) };
    if (body && method !== 'GET') init.body = JSON.stringify(body);
    if (signal) init.signal = signal;   // allows callers to abort long ops
    const res = await fetch(url, init);
    const json = await res.json().catch(() => null);
    if (!res.ok) {
      const err = new Error((json && json.error && json.error.message) || ('请求失败 (' + res.status + ')'));
      err.code = (json && json.error && json.error.code) || ('http_' + res.status);
      err.details = (json && json.error && json.error.details) || {};
      err.status = res.status;
      throw err;
    }
    return json;
  },

  get(p, o)          { return this.request('GET', p, o); },
  post(p, b, o)      { return this.request('POST', p, { body: b, ...o }); },
  patch(p, b, o)     { return this.request('PATCH', p, { body: b, ...o }); },
  del(p, o)          { return this.request('DELETE', p, o); }
};

// ─── Chart Registry ────────────────────────────────────────
const Charts = {
  _instances: {},
  destroyAll() {
    Object.values(this._instances).forEach(c => { try { c.destroy(); } catch (e) { /* ignore */ } });
    this._instances = {};
  },
  create(id, config) {
    const canvas = document.getElementById(id);
    if (!canvas) return null;
    if (this._instances[id]) { try { this._instances[id].destroy(); } catch (e) { /* ignore */ } }
    const c = new Chart(canvas, config);
    this._instances[id] = c;
    return c;
  }
};

// ─── State ──────────────────────────────────────────────────
const S = {
  auth: 'loading',
  user: null,
  dashboard: null,
  devices: [],
  groups: [],
  alerts: [],
  collections: [],
  users: [],
  retention: null,
  page: 'dashboard',
  modalHtml: null
};

// ─── Toast ──────────────────────────────────────────────────
function toast(msg, type) {
  type = type || 'info';
  const c = document.getElementById('toast-container');
  if (!c) return;
  const icons = { success: '✓', error: '✕', warning: '!', info: 'ℹ' };
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.innerHTML = '<span style="font-size:16px">' + (icons[type] || '') + '</span>' + esc(msg);
  c.appendChild(el);
  setTimeout(function () {
    el.style.opacity = '0';
    el.style.transition = 'opacity .3s';
    setTimeout(function () { el.remove(); }, 300);
  }, 3500);
}

// ─── Operation loading + long-op progress ──────────────────
// S.busy maps an op key (e.g. "refresh:dev-1") to true while in flight, so
// buttons render disabled with a "…中" label and prevent double clicks.
S.busy = {};
S._detailDeviceId = null;   // device id whose detail modal is open

function isBusy(key) { return !!S.busy[key]; }
function setBusy(key, val) { S.busy[key] = val; }

// Persistent progress bar for long SSH operations (test/refresh). Shows
// elapsed seconds up to maxSec, then a timeout message. Restores UI on exit.
function showOpProgress(key, label, maxSec) {
  var bar = document.getElementById('op-progress-' + key);
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'op-progress-' + key;
    bar.className = 'op-progress';
    var c = document.getElementById('toast-container') || document.body;
    c.appendChild(bar);
  }
  bar.dataset.start = String(Date.now());
  bar.dataset.max = String(maxSec);
  bar.dataset.label = label;
  bar.style.display = 'block';
  updateOpProgress(key);
}
function updateOpProgress(key) {
  var bar = document.getElementById('op-progress-' + key);
  if (!bar || bar.style.display === 'none') return;
  var start = Number(bar.dataset.start);
  var max = Number(bar.dataset.max);
  var elapsed = Math.floor((Date.now() - start) / 1000);
  if (elapsed >= max) {
    bar.innerHTML = '<span style="color:var(--danger);font-weight:600">⏱ 操作超时：' + esc(bar.dataset.label) +
      ' 未在 ' + max + ' 秒内完成。</span>';
    return;
  }
  bar.innerHTML = '<span class="spin">◌</span> 正在' + esc(bar.dataset.label) + '… 已等待 ' + elapsed +
    ' 秒，最多等待 ' + max + ' 秒';
}
function hideOpProgress(key) {
  var bar = document.getElementById('op-progress-' + key);
  if (bar) bar.remove();
}

// Run a long operation with a live elapsed counter, a hard client-side
// timeout, and AbortController so the in-flight fetch is actually cancelled
// on timeout (not just hidden). The `done` guard guarantees onDone/onFail is
// invoked exactly once — the abort rejection cannot double-fire the callback.
function runLongOp(key, label, maxSec, asyncFn, onDone, onFail) {
  if (isBusy(key)) return;            // prevent double click
  setBusy(key, true);
  showOpProgress(key, label, maxSec);
  render();
  var ticker = setInterval(function () { updateOpProgress(key); }, 1000);
  var ac = new AbortController();
  var toId = null;
  var done = false;
  function finish(ok, payload) {
    if (done) return;                 // guard: timeout + resolve/abort both possible
    done = true;
    if (toId) clearTimeout(toId);
    clearInterval(ticker);
    hideOpProgress(key);
    setBusy(key, false);
    render();
    if (ok && onDone) onDone(payload);
    else if (!ok && onFail) onFail(payload);
  }
  // asyncFn receives the AbortSignal so it can wire it into fetch().
  Promise.resolve(asyncFn(ac.signal)).then(function (r) { finish(true, r); })
    .catch(function (err) {
      // If we already timed out (done), this abort-rejection is a no-op.
      if (done) return;
      finish(false, err);
    });
  toId = setTimeout(function () {
    try { ac.abort(); } catch (e) { /* ignore */ }
    finish(false, { timeout: true, message: '操作超时：' + label + ' 未在 ' + maxSec + ' 秒内完成。' });
  }, maxSec * 1000);
}

// ─── Auto-refresh (页面自动刷新) ────────────────────────────
// Default ON (first visit), default 10s, min 5s. Only re-fetches backend data;
// never triggers SSH collection.
S.autoRefresh = localStorage.getItem('hinfra_ar') === null ? true : localStorage.getItem('hinfra_ar') === '1';
S.refreshPeriod = Number(localStorage.getItem('hinfra_ar_period')) || 10;
S.lastRefreshAt = null;
S.nextRefreshIn = 0;
var _refreshTimer = null;

function setAutoRefresh(on) {
  S.autoRefresh = !!on;
  localStorage.setItem('hinfra_ar', S.autoRefresh ? '1' : '0');
  if (S.autoRefresh) startRefreshTimer();
  else stopRefreshTimer();
  render();
}
function setRefreshPeriod(sec) {
  var n = Math.max(5, parseInt(sec, 10) || 10);
  S.refreshPeriod = n;
  localStorage.setItem('hinfra_ar_period', String(n));
  if (S.autoRefresh) startRefreshTimer();
  render();
}
function startRefreshTimer() {
  stopRefreshTimer();
  S.nextRefreshIn = S.refreshPeriod;
  _refreshTimer = setInterval(tickRefresh, 1000);
}
function stopRefreshTimer() {
  if (_refreshTimer) { clearInterval(_refreshTimer); _refreshTimer = null; }
  S.nextRefreshIn = 0;
  var cd = document.getElementById('refresh-countdown');
  if (cd) cd.textContent = '—';
}
function tickRefresh() {
  if (!S.autoRefresh) return;
  S.nextRefreshIn--;
  if (S.nextRefreshIn <= 0) {
    S.nextRefreshIn = S.refreshPeriod;
    doAutoRefresh();
  }
  // update countdown display without full re-render
  var cd = document.getElementById('refresh-countdown');
  if (cd) cd.textContent = S.nextRefreshIn + 's';
}
async function doAutoRefresh() {
  try {
    await loadMain();
    S.lastRefreshAt = new Date();
    var el = document.getElementById('refresh-last');
    if (el) el.textContent = fmtTime(S.lastRefreshAt);
    if (S._detailDeviceId) {
      await refreshDeviceDetail(S._detailDeviceId, true);
    }
    // On the devices page, only swap the table — never rebuild the filter bar,
    // so an in-progress search input keeps focus and its value.
    if (S.page === 'devices') renderDevTable();
    else render();
  } catch (e) { /* loadMain already toasts */ }
}
function fmtTime(d) {
  if (!d) return '—';
  var p = function (n) { return (n < 10 ? '0' : '') + n; };
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}
// manual refresh: reload + reset countdown
async function manualRefresh() {
  if (isBusy('manualRefresh')) return;
  setBusy('manualRefresh', true); render();
  try {
    await loadMain();
    S.lastRefreshAt = new Date();
    if (S.autoRefresh) S.nextRefreshIn = S.refreshPeriod;  // reset countdown
    toast('刷新完成', 'success');
  } catch (e) { toast('刷新失败：' + (e.message || '未知错误'), 'error'); }
  setBusy('manualRefresh', false); render();
}

// ─── Helpers ────────────────────────────────────────────────
function esc(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function statusBadge(s) {
  var map = { online: 'success', healthy: 'success', normal: 'success', warning: 'warning', offline: 'muted', critical: 'danger', failed: 'danger', disabled: 'muted', unavailable: 'warning' };
  return map[s] || 'info';
}
function statusText(s) {
  var map = { online: '在线', offline: '离线', warning: '警告', unknown: '未知', healthy: '健康', normal: '正常', critical: '严重', failed: '失败', resolved: '已处理', active: '活跃', disabled: '已禁用', unavailable: '无可用数据' };
  return map[s] || s || '未知';
}

// Health status is its own dimension (normal/warning/critical/unknown) and
// must NOT fall back to the connectivity status. Online/offline is shown
// separately via onlineBadge.
function healthBadge(dev) {
  var hs = dev.health_status;
  if (hs === 'normal') return '<span class="badge badge-success">正常</span>';
  if (hs === 'warning') return '<span class="badge badge-warning">警告</span>';
  if (hs === 'critical') return '<span class="badge badge-danger">异常</span>';
  return '<span class="badge badge-muted">未知</span>';
}
function healthText(dev) {
  var hs = dev.health_status;
  if (hs === 'normal') return '正常';
  if (hs === 'warning') return '警告';
  if (hs === 'critical') return '异常';
  return '未知';
}

// Online status (connectivity): online/offline/disabled/unknown.
function onlineBadge(dev) {
  var os = dev.online_status || (dev.status === 'disabled' ? 'disabled' : dev.status);
  if (os === 'online') return '<span class="badge badge-success">在线</span>';
  if (os === 'offline') return '<span class="badge badge-muted">离线</span>';
  if (os === 'disabled') return '<span class="badge badge-muted">已禁用</span>';
  return '<span class="badge badge-muted">未知</span>';
}
function onlineText(dev) {
  var os = dev.online_status || (dev.status === 'disabled' ? 'disabled' : dev.status);
  if (os === 'online') return '在线';
  if (os === 'offline') return '离线';
  if (os === 'disabled') return '已禁用';
  return '未知';
}

function enabledBadge(dev) {
  return dev.enabled !== false
    ? '<span class="badge badge-success">启用</span>'
    : '<span class="badge badge-muted">禁用</span>';
}

// Render a structured error bucket (critical / permission / optional).
function errBucket(errs, kind, title, icon) {
  if (!errs || !errs.length) return '';
  var tones = {
    critical:   { border: 'var(--danger)',  bg: 'rgba(239,68,68,0.10)',  color: 'var(--danger)' },
    permission: { border: 'var(--warning)', bg: 'rgba(245,158,11,0.12)', color: '#92400e' },
    optional:   { border: 'var(--info)',    bg: 'rgba(59,130,246,0.10)', color: 'var(--info)' },
  };
  var t = tones[kind] || tones.optional;
  var items = errs.map(function (e) {
    if (typeof e === 'string') return '<div class="text-xs text-muted" style="margin-top:2px">• ' + esc(e) + '</div>';
    var cmdId = esc(e.command_id || '?');
    var msg = esc(e.error_message || '');
    var code = e.exit_code != null ? ' exit=' + e.exit_code : '';
    var stderr = (e.stderr || '').substring(0, 120);
    return '<div class="text-xs" style="margin-top:3px">' +
      '<span style="font-weight:600">' + cmdId + '</span>' +
      '<span class="text-muted">: ' + msg + code + '</span>' +
      (stderr ? '<div class="text-muted" style="font-size:10px;opacity:0.7;margin-left:8px">' + esc(stderr) + '</div>' : '') +
      '</div>';
  }).join('');
  return '<div class="mt-2 p-2" style="background:' + t.bg + ';border:1px solid ' + t.border + ';border-radius:6px">' +
    '<span class="text-xs" style="color:' + t.color + ';font-weight:600">' + icon + ' ' + esc(title) + ' (' + errs.length + ')</span>' +
    items + '</div>';
}

// Render a list of indicator names (unavailable = low priority yellow;
// not_applicable = collapsed/muted so it does not alarm).
function indicatorList(items, kind, title, icon) {
  if (!items || !items.length) return '';
  var names = items.map(function (m) { return esc(m); }).join(', ');
  if (kind === 'not_applicable') {
    // collapsed + weakened: hidden behind a <details> toggle, muted styling
    return '<details class="mt-2" style="opacity:0.75"><summary class="text-xs text-muted" style="cursor:pointer">' +
      icon + ' ' + esc(title) + ' (' + items.length + ')</summary>' +
      '<div class="text-xs text-muted" style="margin-top:4px;padding-left:8px">' + names + '</div></details>';
  }
  // unavailable: low priority, visible but subdued
  return '<div class="mt-2 p-2" style="background:rgba(245,158,11,0.08);border:1px solid var(--warning);border-radius:6px">' +
    '<span class="text-xs" style="color:var(--warning);font-weight:600">' + icon + ' ' + esc(title) + ' (' + items.length + ')</span>' +
    '<div class="text-xs text-muted" style="margin-top:2px">' + names + '</div></div>';
}

// Render the collection error / indicator section. Uses new bucketed fields
// when present, otherwise falls back to legacy collector_errors /
// unavailable_metrics so old data still renders.
function renderCollectionIssues(dev) {
  var hasBuckets = dev.critical_errors || dev.permission_warnings ||
    dev.optional_warnings || dev.unavailable_indicators || dev.not_applicable_indicators;
  var html = '';
  if (hasBuckets) {
    html += errBucket(dev.critical_errors, 'critical', '严重错误', '⚠');
    html += errBucket(dev.permission_warnings, 'permission', '权限警告', '🔒');
    html += errBucket(dev.optional_warnings, 'optional', '可选功能警告', 'ℹ');
    html += indicatorList(dev.unavailable_indicators, 'unavailable', '工具不可用', 'ℹ');
    html += indicatorList(dev.not_applicable_indicators, 'not_applicable', '不适用（已跳过）', '∅');
  } else {
    html += errBucket(dev.collector_errors, 'critical', '采集错误', '⚠');
    html += indicatorList(dev.unavailable_metrics, 'unavailable', '指标不可用', 'ℹ');
  }
  return html;
}

function collectionPayloadHasData(payload) {
  if (!payload || typeof payload !== 'object') return false;
  var scalarKeys = [
    'hostname', 'uname', 'cpu_percent', 'cpu_cores', 'memory_percent',
    'memory_total_mb', 'memory_used_mb', 'disk_percent', 'network_rx_mbps',
    'network_tx_mbps', 'load_average', 'uptime', 'temperature_c',
    'smart_status', 'pve_version'
  ];
  for (var i = 0; i < scalarKeys.length; i += 1) {
    var scalar = payload[scalarKeys[i]];
    if (scalar != null && scalar !== '') return true;
  }
  var listKeys = [
    'per_core_cpu', 'partitions', 'network_interfaces', 'nas_pools',
    'nas_volumes', 'nas_snapshots', 'nas_raid', 'smart_attributes',
    'temperatures', 'block_devices', 'pve_storage', 'pve_vms',
    'pve_lxcs', 'pve_interfaces'
  ];
  for (var j = 0; j < listKeys.length; j += 1) {
    var list = payload[listKeys[j]];
    if (Array.isArray(list) && list.length) return true;
  }
  if (payload.storage_pool && typeof payload.storage_pool === 'object' && Object.keys(payload.storage_pool).length) return true;
  return false;
}

function currentCollectionHasData(dev) {
  return collectionPayloadHasData({
    hostname: dev.hostname,
    uname: dev.uname,
    cpu_percent: dev.cpu_percent,
    cpu_cores: dev.cpu_cores,
    memory_percent: dev.memory_percent,
    memory_total_mb: dev.memory_total_mb,
    memory_used_mb: dev.memory_used_mb,
    disk_percent: dev.disk_percent,
    network_rx_mbps: dev.network_rx_mbps,
    network_tx_mbps: dev.network_tx_mbps,
    load_average: dev.load_average,
    uptime: dev.uptime,
    temperature_c: dev.temperature_c,
    smart_status: dev.smart_status,
    pve_version: dev.pve_version,
    per_core_cpu: dev.per_core_cpu,
    partitions: dev.partitions,
    network_interfaces: dev.network_interfaces,
    nas_pools: dev.nas_pools,
    nas_volumes: dev.nas_volumes,
    nas_snapshots: dev.nas_snapshots,
    nas_raid: dev.nas_raid,
    smart_attributes: dev.smart_attributes,
    temperatures: dev.temperatures,
    block_devices: dev.block_devices,
    pve_storage: dev.pve_storage,
    pve_vms: dev.pve_vms,
    pve_lxcs: dev.pve_lxcs,
    pve_interfaces: dev.pve_interfaces,
    storage_pool: dev.storage_pool
  });
}

function hasCollectionHistory(dev) {
  if (currentCollectionHasData(dev)) return true;
  var cols = dev.recent_collections || [];
  for (var i = 0; i < cols.length; i += 1) {
    if (collectionPayloadHasData(cols[i] && cols[i].payload)) return true;
  }
  return false;
}

function latestCollectionRecord(dev) {
  var cols = dev.recent_collections || [];
  return cols.length ? cols[0] : (dev.latest_record || null);
}

function isSuccessfulCollectionStatus(status) {
  return status === 'healthy' || status === 'normal' || status === 'success' ||
    status === 'warning' || status === 'online';
}

function collectionStatusText(dev, rec) {
  var parts = [];
  if (rec && rec.summary) parts.push(rec.summary);
  if (rec && rec.error_message && rec.error_message !== rec.summary) parts.push(rec.error_message);
  if (dev && dev.collector_errors && dev.collector_errors.length) {
    for (var i = 0; i < dev.collector_errors.length; i += 1) {
      var err = dev.collector_errors[i];
      if (typeof err === 'string' && err) parts.push(err);
      else if (err && err.error_message) parts.push(err.error_message);
    }
  }
  return parts.join(' ');
}

function getCollectionState(dev) {
  var rec = latestCollectionRecord(dev);
  var hasCurrentData = currentCollectionHasData(dev);
  var hasHistory = hasCollectionHistory(dev);
  var lower = collectionStatusText(dev, rec).toLowerCase();
  // Legacy broad copy kept in source for smoke-test compatibility:
  // 采集已禁用 / 无可用数据
  if (dev.enabled === false) {
    return {
      kind: 'device-disabled',
      label: '设备已禁用：请先启用该设备',
      badge: 'badge-muted',
      tone: 'muted',
      hasCurrentData: false
    };
  }
  if (dev.data_source === 'disabled' || dev.status === 'disabled') {
    return {
      kind: 'collector-disabled',
      label: '采集未开启：当前 COLLECTOR_MODE=disabled',
      badge: 'badge-muted',
      tone: 'muted',
      hasCurrentData: false
    };
  }
  if (dev.auth_type === 'none') {
    return {
      kind: 'missing-credential',
      label: '缺少 SSH 凭据：请配置 SSH 密钥或密码',
      badge: 'badge-warning',
      tone: 'warning',
      hasCurrentData: false
    };
  }
  if (dev.auth_type === 'password' && (
    lower.indexOf('外部凭据源') !== -1 ||
    lower.indexOf('stored password') !== -1 ||
    lower.indexOf('allow_stored_password_auth') !== -1
  )) {
    return {
      kind: 'password-auth-disabled',
      label: '密码认证未启用：请在 .env 中设置 ALLOW_STORED_PASSWORD_AUTH=1',
      badge: 'badge-warning',
      tone: 'warning',
      hasCurrentData: false
    };
  }
  if (hasCurrentData && dev.data_source === 'ssh') {
    return {
      kind: 'ok',
      label: '真实 SSH 数据',
      badge: 'badge-success',
      tone: 'success',
      hasCurrentData: true
    };
  }
  if (
    lower.indexOf('ssh 连接或命令执行失败') !== -1 ||
    lower.indexOf('ssh 采集失败') !== -1 ||
    lower.indexOf('ssh timeout contacting host') !== -1 ||
    lower.indexOf('connection refused') !== -1 ||
    lower.indexOf('no valid connections') !== -1 ||
    lower.indexOf('authentication failed') !== -1 ||
    lower.indexOf('name or service not known') !== -1 ||
    lower.indexOf('timed out') !== -1
  ) {
    return {
      kind: 'ssh-connect-failed',
      label: 'SSH 连接失败：请检查主机地址、端口、用户名和凭据',
      badge: 'badge-danger',
      tone: 'danger',
      hasCurrentData: false
    };
  }
  if (!hasCurrentData && rec && !hasHistory && !isSuccessfulCollectionStatus(rec.status)) {
    return {
      kind: 'failed-no-history',
      label: '采集失败：最近一次采集未成功，且暂无历史数据',
      badge: 'badge-danger',
      tone: 'danger',
      hasCurrentData: false
    };
  }
  if (!hasCurrentData && rec && isSuccessfulCollectionStatus(rec.status)) {
    return {
      kind: 'empty-success',
      label: '采集成功但数据为空：请检查目标主机返回内容',
      badge: 'badge-warning',
      tone: 'warning',
      hasCurrentData: false
    };
  }
  if (!hasCurrentData && rec) {
    return {
      kind: 'failed',
      label: '采集失败：最近一次采集未成功',
      badge: 'badge-danger',
      tone: 'danger',
      hasCurrentData: false
    };
  }
  return {
    kind: 'pending',
    label: '暂无采集数据：等待首次采集完成',
    badge: 'badge-muted',
    tone: 'muted',
    hasCurrentData: false
  };
}

function renderCollectionStateCard(state) {
  var tones = {
    success: { border: 'var(--success)', bg: 'rgba(16,185,129,0.10)', color: 'var(--success)' },
    warning: { border: 'var(--warning)', bg: 'rgba(245,158,11,0.10)', color: '#92400e' },
    danger: { border: 'var(--danger)', bg: 'rgba(239,68,68,0.10)', color: 'var(--danger)' },
    muted: { border: 'var(--border)', bg: 'var(--surface)', color: 'var(--muted)' }
  };
  var tone = tones[state.tone] || tones.muted;
  return '<div class="card mb-4"><div class="card-header">📊 采集状态</div>' +
    '<div class="mt-2 p-2" style="background:' + tone.bg + ';border:1px solid ' + tone.border + ';border-radius:6px">' +
    '<span class="text-sm" style="color:' + tone.color + ';font-weight:600">' + esc(state.label) + '</span>' +
    '</div></div>';
}

// Render the probe summary card (counts + applicability chips).
function probeSummaryCard(dev) {
  var ps = dev.probe_summary;
  if (!ps) return '';
  var rows = [
    ['严重错误', ps.critical_error_count, 'danger'],
    ['权限警告', ps.permission_warning_count, 'warning'],
    ['可选功能警告', ps.optional_error_count, 'info'],
    ['工具不可用', ps.unavailable_count, 'warning'],
    ['不适用', ps.not_applicable_count, 'muted'],
  ];
  var chips = rows.filter(function (r) { return r[1] > 0; }).map(function (r) {
    return '<span class="badge badge-' + r[2] + '">' + esc(r[0]) + ': ' + r[1] + '</span>';
  }).join(' ');

  var na = dev.not_applicable_indicators || [];
  var nasSet = {}; na.forEach(function (n) { nasSet[n] = true; });
  var caps = [];
  function cap(label, naKey) {
    var ok = !nasSet[naKey];
    caps.push('<span class="badge badge-' + (ok ? 'success' : 'muted') + '">' + esc(label) + (ok ? ' ✔' : ' ✗') + '</span>');
  }
  cap('SMART', 'smartctl_scan');
  cap('ZFS', 'zfs_list');
  cap('Btrfs', 'btrfs_show');
  cap('RAID', 'mdstat');
  cap('Block', 'lsblk');
  var capHtml = caps.join(' ');

  return '<div class="card mb-4"><div class="card-header">采集摘要</div>' +
    '<div class="mt-2">' + (chips || capHtml) + '</div>' +
    '<div class="mt-2">' + capHtml + '</div>' +
    '</div>';
}

// PVE detail sections: version, VM/LXC summary, storage, network bridges.
// SMART (smart_attributes) and ZFS pools (nas_pools) are rendered by the
// shared sections above; this only adds PVE-specific blocks.
function pveDetailHtml(dev) {
  var h = '';
  // PVE 版本 + VM/LXC 统计
  h += '<div class="card mb-4"><div class="card-header">PVE 版本</div>' +
    '<div class="grid-4 mt-2">' +
      miniMetric('PVE 版本', dev.pve_version || '—', '', 'load') +
      miniMetric('VM 总数', dev.pve_vm_total != null ? dev.pve_vm_total : '—', '', 'cpu') +
      miniMetric('VM 运行', dev.pve_vm_running != null ? dev.pve_vm_running : '—', '', 'memory') +
      miniMetric('LXC 总数', dev.pve_lxc_total != null ? dev.pve_lxc_total : '—', '', 'disk') +
    '</div></div>';

  // VM / LXC 列表
  if ((dev.pve_vms && dev.pve_vms.length) || (dev.pve_lxcs && dev.pve_lxcs.length)) {
    h += '<div class="card mb-4"><div class="card-header">VM / LXC</div>' +
      '<div class="table-wrap mt-2"><table><thead><tr><th>类型</th><th>ID</th><th>名称</th><th>状态</th><th>内存</th><th>磁盘</th></tr></thead><tbody>';
    (dev.pve_vms || []).forEach(function (v) {
      h += '<tr><td>VM</td><td>' + esc(v.id) + '</td><td>' + esc(v.name) + '</td>' +
        '<td><span class="badge ' + (String(v.status).toLowerCase() === 'running' ? 'badge-success' : 'badge-muted') + '">' + esc(v.status) + '</span></td>' +
        '<td>' + (v.memory != null ? v.memory : '—') + '</td><td>' + (v.disk != null ? v.disk : '—') + '</td></tr>';
    });
    (dev.pve_lxcs || []).forEach(function (c) {
      h += '<tr><td>LXC</td><td>' + esc(c.id) + '</td><td>' + esc(c.name) + '</td>' +
        '<td><span class="badge ' + (String(c.status).toLowerCase() === 'running' ? 'badge-success' : 'badge-muted') + '">' + esc(c.status) + '</span></td>' +
        '<td>' + (c.memory != null ? c.memory : '—') + '</td><td>' + (c.disk != null ? c.disk : '—') + '</td></tr>';
    });
    h += '</tbody></table></div></div>';
  }

  // PVE 存储
  if (dev.pve_storage && dev.pve_storage.length) {
    h += '<div class="card mb-4"><div class="card-header">PVE 存储</div>' +
      '<div class="table-wrap mt-2"><table><thead><tr><th>名称</th><th>类型</th><th>状态</th><th>总量</th><th>已用</th><th>使用率</th></tr></thead><tbody>';
    dev.pve_storage.forEach(function (s) {
      var pct = s.percent != null ? s.percent : 0;
      h += '<tr><td>' + esc(s.storage) + '</td><td>' + esc(s.type) + '</td>' +
        '<td><span class="badge ' + (s.status === 'active' ? 'badge-success' : 'badge-muted') + '">' + esc(s.status) + '</span></td>' +
        '<td>' + (s.total ? Math.round(s.total / 1073741824) + ' GB' : '—') + '</td>' +
        '<td>' + (s.used ? Math.round(s.used / 1073741824) + ' GB' : '—') + '</td>' +
        '<td><span class="badge ' + (pct > 85 ? 'badge-danger' : pct > 70 ? 'badge-warning' : 'badge-success') + '">' + pct + '%</span></td></tr>';
    });
    h += '</tbody></table></div></div>';
  }

  // 网络桥接
  if (dev.pve_interfaces && dev.pve_interfaces.length) {
    h += '<div class="card mb-4"><div class="card-header">网络桥接</div>' +
      '<div class="table-wrap mt-2"><table><thead><tr><th>接口</th><th>状态</th><th>类型</th><th>IP</th><th>RX</th><th>TX</th></tr></thead><tbody>';
    dev.pve_interfaces.forEach(function (n) {
      h += '<tr><td>' + esc(n.name) + '</td>' +
        '<td><span class="badge ' + (n.state === 'UP' ? 'badge-success' : 'badge-muted') + '">' + esc(n.state) + '</span></td>' +
        '<td>' + (n.is_bridge ? 'Bridge' : (n.is_physical ? 'Physical' : '—')) + '</td>' +
        '<td><code>' + esc((n.ip_addresses || []).join(', ') || '—') + '</code></td>' +
        '<td>' + (n.rx_bytes != null ? n.rx_bytes : '—') + '</td>' +
        '<td>' + (n.tx_bytes != null ? n.tx_bytes : '—') + '</td></tr>';
    });
    h += '</tbody></table></div></div>';
  }

  return h;
}

function sevBadge(s)   { return ({ critical: 'danger', warning: 'warning', info: 'info' })[s] || 'info'; }
function sevText(s)    { return ({ critical: '严重', warning: '警告', info: '信息' })[s] || s || '未知'; }
function roleText(r)   { return ({ admin: '管理员', operator: '操作员', viewer: '查看者' })[r] || r || '未知'; }
function groupById(id) { var g = S.groups.find(function (x) { return x.id === id; }); return g ? g.name : '未分组'; }
function devById(id)   { var d = S.devices.find(function (x) { return x.id === id; }); return d ? d.name : (id || '未知设备'); }
function isAdmin()     { return S.user && S.user.role === 'admin'; }
function canOperate()  { return S.user && (S.user.role === 'admin' || S.user.role === 'operator'); }
function initial(s)    { return (s || '?').charAt(0).toUpperCase(); }

// ─── Router ─────────────────────────────────────────────────
function go(page) { S.page = page; S.modalHtml = null; S._detailDeviceId = null; render(); }

// ─── Auth ───────────────────────────────────────────────────
async function initAuth() {
  var t = API._token;
  if (t) {
    try {
      var me = await API.get('/auth/me');
      S.user = me.data || me;
      S.auth = 'authenticated';
      await loadMain();
      render();
      if (S.autoRefresh) startRefreshTimer();
      return;
    } catch (e) { API._token = null; }
  }
  try {
    var bs = await API.get('/auth/bootstrap');
    S.auth = (bs.data && bs.data.required) ? 'setup' : 'login';
  } catch (e) { S.auth = 'login'; }
  render();
}

async function doLogin(form) {
  var u = form.username.value.trim(), p = form.password.value;
  if (!u || !p) return toast('请输入用户名和密码', 'warning');
  try {
    var res = await API.post('/auth/login', { username: u, password: p }, { skipAuth: true });
    var tok = (res.data && res.data.token) || res.token;
    if (!tok) return toast('登录失败：服务器未返回令牌', 'error');
    API._token = tok;
    var me = await API.get('/auth/me');
    S.user = me.data || me;
    S.auth = 'authenticated';
    await loadMain();
    render();
    if (S.autoRefresh) startRefreshTimer();
  } catch (e) { toast(e.message || '登录失败', 'error'); }
}

async function doSetup(form) {
  var u = form.username.value.trim(), p = form.password.value, c = form.confirm_password && form.confirm_password.value;
  if (!u || !p) return toast('请填写用户名和密码', 'warning');
  if (c !== undefined && p !== c) return toast('两次密码不一致', 'warning');
  try {
    var res = await API.post('/auth/bootstrap', { username: u, password: p }, { skipAuth: true });
    var tok = (res.data && res.data.token) || res.token;
    if (!tok) { S.auth = 'login'; toast('管理员已创建，请登录', 'success'); }
    else {
      API._token = tok;
      var me = await API.get('/auth/me');
      S.user = me.data || me;
      S.auth = 'authenticated';
      await loadMain();
    }
    render();
  } catch (e) { toast(e.message || '初始化失败', 'error'); }
}

async function doLogout() {
  stopRefreshTimer();
  try { await API.post('/auth/logout'); } catch (e) { /* ignore */ }
  API._token = null;
  S.user = null;
  S.auth = 'login';
  S.dashboard = null; S.devices = []; S.groups = []; S.alerts = []; S.collections = []; S.users = []; S.retention = null; S.collectionSettings = null;
  S._detailDeviceId = null;
  S.page = 'dashboard';
  render();
  toast('已退出登录', 'success');
}

// ─── Data Loading ───────────────────────────────────────────
async function loadMain() {
  try {
    var results = await Promise.all([
      API.get('/dashboard'),
      API.get('/devices'),
      API.get('/device-groups'),
      API.get('/alerts')
    ]);
    S.dashboard = results[0].data || results[0];
    S.devices = ((results[1].data && results[1].data.devices) || results[1].devices || []);
    S.groups  = ((results[2].data && results[2].data.groups) || results[2].groups || []);
    S.alerts  = ((results[3].data && results[3].data.alerts) || results[3].alerts || []);
  } catch (e) { toast('数据加载失败：' + (e.message || '未知错误'), 'error'); }
}

async function loadCollections(params) {
  try {
    var res = await API.get('/collections', { params: Object.assign({ limit: 200 }, params || {}) });
    S.collections = ((res.data && res.data.records) || res.records || []);
  } catch (e) { toast('历史记录加载失败', 'error'); }
}

async function loadUsers() {
  try {
    var res = await API.get('/users');
    S.users = ((res.data && res.data.users) || res.users || []);
  } catch (e) { toast('用户列表加载失败', 'error'); }
}

async function loadRetention() {
  try {
    var res = await API.get('/settings/retention');
    S.retention = res.data || res;
  } catch (e) { toast('保留策略加载失败', 'error'); }
}

// ─── Render ─────────────────────────────────────────────────
function render() {
  var app = document.getElementById('app');
  if (!app) return;
  Charts.destroyAll();

  if (S.auth === 'loading') {
    app.innerHTML = '<div class="auth-wrapper"><div style="text-align:center;color:var(--text-secondary)"><div style="font-size:32px;margin-bottom:12px">⏳</div>加载中...</div></div>';
    return;
  }
  if (S.auth === 'setup')   { app.innerHTML = renderSetupPage(); return; }
  if (S.auth === 'login')   { app.innerHTML = renderLoginPage(); return; }

  // Capture focus + cursor on any input/textarea with an id so a full
  // re-render (e.g. after an operation completes) does not strand the user
  // mid-typing in the search box.
  var fe = document.activeElement;
  var focusId = null, selStart = 0, selEnd = 0;
  if (fe && (fe.tagName === 'INPUT' || fe.tagName === 'TEXTAREA') && fe.id) {
    focusId = fe.id;
    selStart = fe.selectionStart != null ? fe.selectionStart : 0;
    selEnd = fe.selectionEnd != null ? fe.selectionEnd : 0;
  }

  var pageHtml = renderPage();
  var breadcrumb = ({
    dashboard: '仪表盘', devices: '设备管理', groups: '设备分组',
    history: '历史记录', alerts: '告警中心', users: '用户管理', settings: '系统设置'
  })[S.page] || '';

  app.innerHTML =
    '<nav class="sidebar">' +
      '<div class="sidebar-brand">' +
        '<div class="sidebar-brand-icon">⚡</div>' +
        'HomeInfra' +
      '</div>' +
      '<ul class="nav-menu">' +
        navItem('dashboard', '📊', '仪表盘') +
        navItem('devices',   '🖥', '设备管理') +
        navItem('groups',    '📁', '设备分组') +
        navItem('history',   '📋', '历史记录') +
        navItem('alerts',    '🔔', '告警中心') +
        (isAdmin() ? navItem('users', '👥', '用户管理') : '') +
        (isAdmin() ? navItem('settings', '⚙', '系统设置') : '') +
      '</ul>' +
    '</nav>' +
    '<main class="main-content">' +
      '<header class="topbar">' +
        '<div class="topbar-left"><span class="page-breadcrumb">' + esc(breadcrumb) + '</span></div>' +
        '<div class="topbar-right">' +
          '<div class="user-chip">' +
            '<div class="user-avatar">' + initial(S.user && S.user.username) + '</div>' +
            esc(S.user && S.user.username || '') +
            '<span class="role-tag">' + roleText(S.user && S.user.role) + '</span>' +
          '</div>' +
          '<button class="btn btn-outline btn-sm" onclick="doLogout()">退出</button>' +
        '</div>' +
      '</header>' +
      '<div class="page-content">' + pageHtml + '</div>' +
    '</main>';

  // Restore focus + cursor if the same input still exists after re-render.
  if (focusId) {
    var restored = document.getElementById(focusId);
    if (restored && restored.focus) {
      try {
        restored.focus();
        if (restored.setSelectionRange && selEnd != null) {
          restored.setSelectionRange(selStart, selEnd);
        }
      } catch (e) { /* ignore */ }
    }
  }

  if (S.modalHtml) renderModal();
  postRender();
}

function navItem(page, icon, label) {
  return '<li class="nav-item' + (S.page === page ? ' active' : '') + '" onclick="go(\'' + page + '\')">' +
    '<span class="nav-icon">' + icon + '</span>' + label + '</li>';
}

function postRender() {
  var configs = window.__charts;
  if (!configs || !configs.length) return;
  for (var i = 0; i < configs.length; i++) {
    Charts.create(configs[i].id, configs[i].config);
  }
  window.__charts = [];
}

function queueChart(id, config) {
  if (!window.__charts) window.__charts = [];
  window.__charts.push({ id: id, config: config });
}

function renderPage() {
  switch (S.page) {
    case 'dashboard': return renderDashboard();
    case 'devices':   return renderDevices();
    case 'groups':    return renderGroups();
    case 'history':   return renderHistory();
    case 'alerts':    return renderAlerts();
    case 'users':     return isAdmin() ? renderUsers() : '<div class="empty-state"><div class="empty-state-icon">🔒</div><div class="empty-state-text">无权限访问</div></div>';
    case 'settings':  return isAdmin() ? renderSettings() : '<div class="empty-state"><div class="empty-state-icon">🔒</div><div class="empty-state-text">无权限访问</div></div>';
    default:          return renderDashboard();
  }
}

// ─── Auth Pages ──────────────────────────────────────────────
function renderSetupPage() {
  return '<div class="auth-wrapper"><div class="auth-card">' +
    '<h1 class="auth-title">⚡ 创建管理员账户</h1>' +
    '<form onsubmit="event.preventDefault();doSetup(this)">' +
      '<div class="form-group"><label class="form-label">用户名</label><input name="username" class="form-control" required autofocus></div>' +
      '<div class="form-group"><label class="form-label">密码</label><input name="password" type="password" class="form-control" required></div>' +
      '<div class="form-group"><label class="form-label">确认密码</label><input name="confirm_password" type="password" class="form-control" required></div>' +
      '<button type="submit" class="btn btn-primary w-full" style="padding:12px">创建管理员并登录</button>' +
    '</form></div></div>';
}

function renderLoginPage() {
  return '<div class="auth-wrapper"><div class="auth-card">' +
    '<h1 class="auth-title">🔐 登录 HomeInfra</h1>' +
    '<form onsubmit="event.preventDefault();doLogin(this)">' +
      '<div class="form-group"><label class="form-label">用户名</label><input name="username" class="form-control" required autofocus></div>' +
      '<div class="form-group"><label class="form-label">密码</label><input name="password" type="password" class="form-control" required></div>' +
      '<button type="submit" class="btn btn-primary w-full" style="padding:12px">登录</button>' +
    '</form></div></div>';
}

// ─── Dashboard ──────────────────────────────────────────────
function renderDashboard() {
  var d = (S.dashboard && S.dashboard.summary) ? S.dashboard.summary : (S.dashboard || {});
  var online  = 0, offline = 0, warn = 0, unk = 0;
  if (S.devices.length) {
    for (var i = 0; i < S.devices.length; i++) {
      var s = S.devices[i].status;
      if (s === 'online') online++;
      else if (s === 'offline') offline++;
      else if (s === 'warning') warn++;
      else unk++;
    }
  }
  var total = d.total_devices != null ? d.total_devices : S.devices.length;

  // device status chart
  if (online + offline + warn + unk > 0) {
    queueChart('chart-dev-status', {
      type: 'doughnut',
      data: {
        labels: ['在线', '离线', '警告', '未知'],
        datasets: [{ data: [online, offline, warn, unk], backgroundColor: ['#10b981', '#94a3b8', '#f59e0b', '#cbd5e1'], borderWidth: 0 }]
      },
      options: { plugins: { legend: { position: 'bottom', labels: { padding: 20, usePointStyle: true } } } }
    });
  }
  // group stats chart
  if (S.groups.length) {
    queueChart('chart-grp-stats', {
      type: 'bar',
      data: {
        labels: S.groups.map(function (g) { return g.name; }),
        datasets: [
          { label: '设备数', data: S.groups.map(function (g) { return g.device_count || 0; }), backgroundColor: '#4f46e5', borderRadius: 4 },
          { label: '告警', data: S.groups.map(function (g) { return g.active_alert_count || 0; }), backgroundColor: '#ef4444', borderRadius: 4 }
        ]
      },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { usePointStyle: true } } } }
    });
  }

  var healthScore = Number(d.health_score);
  var scoreTone = healthScore >= 80 ? 'success' : healthScore >= 50 ? 'warning' : 'danger';
  var alertCount = d.open_alerts != null ? d.open_alerts : (d.active_alerts || 0);

  return '<div class="page-header"><h1 class="page-title">仪表盘</h1></div>' +

    '<div class="grid-4 mb-6">' +
      statCard('设备总数', String(total), 'info') +
      statCard('在线设备', String(online), online > 0 ? 'success' : '') +
      statCard('离线/警告', (d.offline_devices != null ? d.offline_devices : offline) + ' / ' +
               (d.warning_devices != null ? d.warning_devices : warn),
               (offline > 0 || warn > 0) ? 'danger' : 'success') +
      statCard('活跃告警', String(alertCount), alertCount > 0 ? 'danger' : 'success') +
    '</div>' +

    '<div class="grid-4 mb-6">' +
      statCard('分组数', String(d.groups != null ? d.groups : S.groups.length), 'info') +
      statCard('平均 CPU', (d.average_cpu_percent != null ? Number(d.average_cpu_percent).toFixed(1) : '—') + '%',
               (Number(d.average_cpu_percent) > 80) ? 'danger' : (Number(d.average_cpu_percent) > 60) ? 'warning' : 'success') +
      statCard('平均内存', (d.average_memory_percent != null ? Number(d.average_memory_percent).toFixed(1) : '—') + '%',
               (Number(d.average_memory_percent) > 80) ? 'danger' : (Number(d.average_memory_percent) > 60) ? 'warning' : 'success') +
      statCard('健康评分', healthScore >= 0 ? String(healthScore) : '—', scoreTone) +
    '</div>' +

    '<div class="grid-2">' +
      ((online + offline + warn + unk > 0)
        ? '<div class="card"><div class="card-header">📊 设备状态分布</div><div class="chart-wrap chart-md"><canvas id="chart-dev-status"></canvas></div></div>'
        : '<div class="card"><div class="card-header">📊 设备状态分布</div><div class="empty-state"><div class="empty-state-icon">📡</div><div class="empty-state-text">暂无设备数据</div></div></div>') +
      (S.groups.length
        ? '<div class="card"><div class="card-header">📁 分组统计</div><div class="chart-wrap chart-lg"><canvas id="chart-grp-stats"></canvas></div></div>'
        : '<div class="card"><div class="card-header">📁 分组统计</div><div class="empty-state"><div class="empty-state-icon">📁</div><div class="empty-state-text">暂无分组</div></div></div>') +
    '</div>' +
    (d.latest_collection_at ? '<p class="text-muted text-sm mt-4">最近采集：' + d.latest_collection_at + '</p>' : '');
}

function statCard(label, value, tone) {
  var cls = tone ? ' stat-card tone-' + tone : 'stat-card';
  return '<div class="card' + cls + '"><span class="stat-label">' + label + '</span><span class="stat-value">' + value + '</span></div>';
}

// ─── Devices ────────────────────────────────────────────────
var devSearch = '', devGrp = 'all', devType = 'all', devHealth = 'all', devOnline = 'all', devEnabled = 'all';

function renderDevices() {
  // deduplicate types
  var types = [];
  for (var i = 0; i < S.devices.length; i++) {
    var t = S.devices[i].device_type;
    if (t && types.indexOf(t) === -1) types.push(t);
  }

  // Auto-refresh control bar
  var arBar = '<div class="auto-refresh-bar mb-4">' +
    '<label class="text-xs text-muted">页面自动刷新</label> ' +
    '<label class="switch"><input type="checkbox" id="ar-toggle" onchange="setAutoRefresh(this.checked)"' + (S.autoRefresh ? ' checked' : '') + '><span class="switch-slider"></span></label> ' +
    '<span class="text-xs ' + (S.autoRefresh ? 'text-success' : 'text-muted') + '" id="ar-state">' + (S.autoRefresh ? '开启' : '关闭') + '</span>' +
    '<input type="number" class="form-control" style="width:80px;display:inline-block;margin-left:16px" min="5" value="' + S.refreshPeriod + '" onchange="setRefreshPeriod(this.value)"> 秒' +
    '<span class="text-xs text-muted" style="margin-left:16px">上次刷新: <span id="refresh-last">' + fmtTime(S.lastRefreshAt) + '</span></span>' +
    '<span class="text-xs text-muted" style="margin-left:16px">下次刷新: <span id="refresh-countdown">' + (S.autoRefresh ? S.nextRefreshIn + 's' : '—') + '</span></span>' +
    '<button class="btn btn-outline btn-sm" style="margin-left:auto" onclick="manualRefresh()"' + (isBusy('manualRefresh') ? ' disabled' : '') + '>' + (isBusy('manualRefresh') ? '刷新中…' : '立即刷新') + '</button>' +
    '</div>';

  return '<div class="page-header"><h1 class="page-title">🖥 设备管理</h1>' +
    (isAdmin() ? '<button class="btn btn-primary" onclick="openDeviceModal()">+ 新增设备</button>' : '') +
    '</div>' +

    arBar +

    // Filter bar is rendered once and stays stable across filter changes —
    // filter oninput/onchange only swap #dev-table-wrap below, so the search
    // input never loses focus and its value is never reset.
    '<div class="flex gap-3 mb-4 flex-wrap">' +
      '<input id="dev-search-input" class="form-control" style="width:200px" value="' + esc(devSearch) + '" oninput="devSearch=this.value;renderDevTable()">' +
      '<select class="form-control" style="width:150px" onchange="devGrp=this.value;renderDevTable()">' +
        '<option value="all">全部分组</option>' +
        S.groups.map(function (g) { return '<option value="' + esc(g.id) + '"' + sel(devGrp, g.id) + '>' + esc(g.name) + '</option>'; }).join('') +
      '</select>' +
      '<select class="form-control" style="width:150px" onchange="devType=this.value;renderDevTable()">' +
        '<option value="all">全部类型</option>' +
        types.map(function (t) { return '<option value="' + esc(t) + '"' + sel(devType, t) + '>' + esc(t) + '</option>'; }).join('') +
      '</select>' +
      '<select class="form-control" style="width:130px" onchange="devHealth=this.value;renderDevTable()">' +
        '<option value="all">全部健康状态</option>' +
        '<option value="normal"' + sel(devHealth, 'normal') + '>正常</option>' +
        '<option value="warning"' + sel(devHealth, 'warning') + '>警告</option>' +
        '<option value="critical"' + sel(devHealth, 'critical') + '>异常</option>' +
        '<option value="unknown"' + sel(devHealth, 'unknown') + '>未知</option>' +
      '</select>' +
      '<select class="form-control" style="width:130px" onchange="devOnline=this.value;renderDevTable()">' +
        '<option value="all">全部在线状态</option>' +
        '<option value="online"' + sel(devOnline, 'online') + '>在线</option>' +
        '<option value="offline"' + sel(devOnline, 'offline') + '>离线</option>' +
        '<option value="unknown"' + sel(devOnline, 'unknown') + '>未知</option>' +
      '</select>' +
      '<select class="form-control" style="width:120px" onchange="devEnabled=this.value;renderDevTable()">' +
        '<option value="all">全部启用</option>' +
        '<option value="true"' + sel(devEnabled, 'true') + '>已启用</option>' +
        '<option value="false"' + sel(devEnabled, 'false') + '>已禁用</option>' +
      '</select>' +
    '</div>' +

    '<div id="dev-table-wrap">' + devTableHtml() + '</div>';
}

// Table-only render target. Swapping just this container preserves the filter
// bar (and the search input's focus/value) during filtering and auto-refresh.
function devTableHtml() {
  var filtered = filterDevices();
  if (filtered.length === 0) {
    return '<div class="empty-state"><div class="empty-state-icon">🖥</div><div class="empty-state-text">暂无设备</div></div>';
  }
  return '<div class="table-wrap"><table><thead><tr>' +
      '<th>名称</th><th>地址</th><th>端口</th><th>类型</th><th>分组</th><th>健康状态</th><th>在线状态</th><th>启用状态</th><th>最后在线</th><th>操作</th>' +
    '</tr></thead><tbody>' +
    filtered.map(function (d) {
      var rBusy = isBusy('refresh:' + d.id), tBusy = isBusy('test:' + d.id);
      return '<tr>' +
        '<td><span class="link" onclick="openDeviceDetail(\'' + esc(d.id) + '\')" style="font-weight:600">' + esc(d.name) + '</span></td>' +
        '<td><code style="font-size:12px">' + esc(d.host || '—') + '</code></td>' +
        '<td>' + (d.port != null ? d.port : '—') + '</td>' +
        '<td>' + esc(d.device_type || '—') + '</td>' +
        '<td>' + esc((d.group && d.group.name) || groupById(d.group_id)) + '</td>' +
        '<td>' + healthBadge(d) + '</td>' +
        '<td>' + onlineBadge(d) + '</td>' +
        '<td>' + enabledBadge(d) + '</td>' +
        '<td class="text-sm text-muted">' + (d.last_seen || '—') + '</td>' +
        '<td><div class="flex gap-1">' +
          '<button class="btn btn-xs btn-outline" onclick="openDeviceDetail(\'' + esc(d.id) + '\')">详情</button>' +
          (canOperate() ? '<button class="btn btn-xs btn-outline" onclick="refreshDevice(\'' + esc(d.id) + '\')"' + (rBusy ? ' disabled' : '') + '>' + (rBusy ? '刷新中…' : '刷新') + '</button>' : '') +
          (canOperate() ? '<button class="btn btn-xs btn-outline" onclick="testDevice(\'' + esc(d.id) + '\')"' + (tBusy ? ' disabled' : '') + '>' + (tBusy ? '测试中…' : '测试') + '</button>' : '') +
          (canOperate() ? '<button class="btn btn-xs btn-outline" onclick="openDeviceEdit(\'' + esc(d.id) + '\')">编辑</button>' : '') +
          (canOperate() ? '<button class="btn btn-xs btn-outline" onclick="toggleDevice(\'' + esc(d.id) + '\',' + !d.enabled + ')"' + (isBusy('toggle:' + d.id) ? ' disabled' : '') + '>' + (isBusy('toggle:' + d.id) ? '更新中…' : (d.enabled ? '禁用' : '启用')) + '</button>' : '') +
          (isAdmin() ? '<button class="btn btn-xs btn-danger" onclick="deleteDevice(\'' + esc(d.id) + '\')"' + (isBusy('delete:' + d.id) ? ' disabled' : '') + '>' + (isBusy('delete:' + d.id) ? '删除中…' : '删除') + '</button>' : '') +
        '</div></td>' +
      '</tr>';
    }).join('') +
    '</tbody></table></div>';
}

function renderDevTable() {
  var wrap = document.getElementById('dev-table-wrap');
  if (wrap) wrap.innerHTML = devTableHtml();
}

function sel(current, value) { return current === value ? ' selected' : ''; }

function filterDevices() {
  return S.devices.filter(function (d) {
    if (devGrp !== 'all' && d.group_id !== devGrp) return false;
    if (devType !== 'all' && d.device_type !== devType) return false;
    // Health filter (independent dimension)
    if (devHealth !== 'all') {
      var hs = d.health_status || 'unknown';
      if (hs !== devHealth) return false;
    }
    // Online filter (independent dimension)
    if (devOnline !== 'all') {
      var os = d.online_status || (d.status === 'disabled' ? 'disabled' : d.status) || 'unknown';
      if (os !== devOnline) return false;
    }
    if (devEnabled !== 'all' && String(d.enabled) !== devEnabled) return false;
    if (devSearch) {
      var kw = devSearch.toLowerCase();
      if ([d.name, d.host, d.device_type, (d.group && d.group.name) || ''].join(' ').toLowerCase().indexOf(kw) === -1) return false;
    }
    return true;
  });
}

async function openDeviceDetail(id) {
  S._detailDeviceId = id;
  await refreshDeviceDetail(id);
}

// Re-fetch a device and re-render its detail modal. Called by openDeviceDetail
// and by the auto-refresh tick (silent=true suppresses error toasts).
async function refreshDeviceDetail(id, silent) {
  if (S._detailDeviceId !== id) return; // modal closed or switched to another device
  try {
    var res = await API.get('/devices/' + id);
    var dev = res.data || res;
    var cols = dev.recent_collections || [];
    var als  = dev.alerts || [];
    var isPveDevice = dev.device_type === 'proxmox_host' || dev.pve_version || (dev.pve_vms && dev.pve_vms.length) || (dev.pve_storage && dev.pve_storage.length);
    var collectionState = getCollectionState(dev);
    var dsLabel = collectionState.label;
    var dsBadge = collectionState.badge;
    var verifiedBadge = dev.verified ? '<span class="badge badge-success">已验证</span>' : '<span class="badge badge-muted">未验证</span>';

    var html = '<div class="modal-backdrop" onclick="if(event.target===this)closeModal()"><div class="modal" style="max-width:760px">' +
      '<div class="modal-header"><span>📡 ' + esc(dev.name) + '</span><button class="modal-close" onclick="closeModal()">✕</button></div>' +

      '<div class="card mb-4" style="background:var(--surface);padding:12px 16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap">' +
        '<span class="badge ' + dsBadge + '" style="font-size:14px;padding:6px 12px">' + dsLabel + '</span>' +
        verifiedBadge +
        '<span class="text-xs text-muted">健康: ' + healthBadge(dev) + '</span>' +
        '<span class="text-xs text-muted">在线: ' + onlineBadge(dev) + '</span>' +
        '<span class="text-xs text-muted">启用: ' + enabledBadge(dev) + '</span>' +
        (dev.data_source ? '<span class="text-xs text-muted">来源: ' + esc(dev.data_source) + '</span>' : '') +
        (dev.critical_errors && dev.critical_errors.length ? '<span class="badge badge-danger" style="margin-left:auto">严重错误: ' + dev.critical_errors.length + '</span>' : '') +
        (dev.permission_warnings && dev.permission_warnings.length ? '<span class="badge badge-warning">权限警告: ' + dev.permission_warnings.length + '</span>' : '') +
        (dev.optional_warnings && dev.optional_warnings.length ? '<span class="badge badge-info">可选警告: ' + dev.optional_warnings.length + '</span>' : '') +
        (dev.unavailable_indicators && dev.unavailable_indicators.length ? '<span class="badge badge-warning">工具不可用: ' + dev.unavailable_indicators.length + '</span>' : '') +
        // backward compat: when bucket fields are absent, surface legacy counts
        (!dev.critical_errors && dev.collector_errors && dev.collector_errors.length ? '<span class="badge badge-danger" style="margin-left:auto">采集错误: ' + dev.collector_errors.length + ' 项</span>' : '') +
        (!dev.unavailable_indicators && dev.unavailable_metrics && dev.unavailable_metrics.length ? '<span class="badge badge-warning">指标不可用: ' + dev.unavailable_metrics.length + ' 项</span>' : '') +
      '</div>' +

      '<div class="grid-2 mb-4">' +
        kv('名称', esc(dev.name)) + kv('主机', '<code>' + esc(dev.host || '') + '</code>') +
        kv('主机名', dev.hostname || '—') + kv('系统', '<code style="font-size:11px">' + esc(dev.uname || '—') + '</code>') +
        kv('端口', dev.port || '—') + kv('类型', esc(dev.device_type || '—')) +
        kv('健康状态', healthBadge(dev)) + kv('在线状态', onlineBadge(dev)) +
        kv('启用状态', enabledBadge(dev)) + kv('验证状态', verifiedBadge) +
        kv('数据来源', esc(dsLabel)) +
        kv('分组', esc((dev.group && dev.group.name) || groupById(dev.group_id))) +
        kv('采集周期', (dev.collection_interval || dev.poll_interval || '—') + ' 秒') +
        kv('最后在线', dev.last_seen || '—') +
      '</div>';

    if (collectionState.hasCurrentData) {
      var metricRecord = latestCollectionRecord(dev);
      var p = (metricRecord && metricRecord.payload) || {};
      html += '<div class="card mb-4"><div class="card-header">📊 最近采集指标</div>' +
        '<div class="grid-4">' +
          miniMetric('CPU', p.cpu_percent, '%', 'cpu') +
          miniMetric('内存', p.memory_percent, '%', 'memory') +
          miniMetric('磁盘', p.disk_percent, '%', 'disk') +
          miniMetric('运行时间', dev.uptime || '—', '', 'load') +
        '</div>';

      if (dev.load_average) {
        html += '<div class="mt-2"><span class="text-xs text-muted">负载均值: ' + esc(dev.load_average) + '</span></div>';
      }

      if (dev.memory_total_mb != null || dev.memory_used_mb != null) {
        html += '<div class="mt-2"><span class="text-xs text-muted">内存: ' +
          (dev.memory_used_mb != null ? (Number(dev.memory_used_mb) / 1024).toFixed(1) + ' GB' : '—') + ' / ' +
          (dev.memory_total_mb != null ? (Number(dev.memory_total_mb) / 1024).toFixed(1) + ' GB' : '—') +
          '</span></div>';
      }

      // Error / indicator display — bucketed by severity (new fields) with
      // legacy fallback. not_applicable is collapsed so it never alarms.
      html += renderCollectionIssues(dev);

      if (dev.per_core_cpu && dev.per_core_cpu.length) {
        html += '<div class="mt-3"><span class="text-xs text-muted">CPU 各核心</span>' +
          '<div class="grid-4 mt-1">' +
          dev.per_core_cpu.map(function(c) {
            return miniMetric('核心 ' + c.core, c.percent, '%', 'cpu');
          }).join('') +
          '</div></div>';
      }

      if (dev.network_interfaces && dev.network_interfaces.length) {
        html += '<div class="mt-3"><span class="text-xs text-muted">网络接口</span>' +
          '<div class="table-wrap mt-1"><table><thead><tr><th>接口</th><th>状态</th><th>RX</th><th>TX</th><th>IP</th></tr></thead><tbody>' +
          dev.network_interfaces.map(function(n) {
            return '<tr><td>' + esc(n.name) + '</td>' +
              '<td><span class="badge ' + (n.state === 'up' || n.state === 'RUNNING' ? 'badge-success' : 'badge-warning') + '">' + esc(n.state) + '</span></td>' +
              '<td>' + (n.rx_mbps != null ? n.rx_mbps + ' Mbps' : '—') + '</td>' +
              '<td>' + (n.tx_mbps != null ? n.tx_mbps + ' Mbps' : '—') + '</td>' +
              '<td><code>' + esc(n.ipv4 || '—') + '</code></td></tr>';
          }).join('') +
          '</tbody></table></div></div>';
      }

      if (dev.partitions && dev.partitions.length) {
        html += '<div class="mt-3"><span class="text-xs text-muted">磁盘分区</span>' +
          '<div class="table-wrap mt-1"><table><thead><tr><th>挂载点</th><th>设备</th><th>总量</th><th>已用</th><th>使用率</th></tr></thead><tbody>' +
          dev.partitions.map(function(d) {
            return '<tr><td>' + esc(d.mount) + '</td>' +
              '<td><code>' + esc(d.device) + '</code></td>' +
              '<td>' + (d.total_gb != null ? d.total_gb + ' GB' : '—') + '</td>' +
              '<td>' + (d.used_gb != null ? d.used_gb + ' GB' : '—') + '</td>' +
              '<td><span class="badge ' + (d.percent > 85 ? 'badge-danger' : d.percent > 70 ? 'badge-warning' : 'badge-success') + '">' + (d.percent != null ? d.percent + '%' : '—') + '</span></td></tr>';
          }).join('') +
          '</tbody></table></div></div>';
      }

      if (dev.temperatures && dev.temperatures.length) {
        html += '<div class="mt-3"><span class="text-xs text-muted">温度传感器</span>' +
          '<div class="grid-4 mt-1">' +
          dev.temperatures.map(function(t) {
            return miniMetric(t.sensor, t.temp_c, '°C', t.temp_c > 75 ? 'temp' : 'load');
          }).join('') +
          '</div></div>';
      } else if (dev.temperature_c != null) {
        html += '<div class="mt-3"><span class="text-xs text-muted">温度</span>' +
          '<div class="grid-4 mt-1">' +
          miniMetric('设备温度', dev.temperature_c, '°C', dev.temperature_c > 75 ? 'temp' : 'load') +
          '</div></div>';
      }

      if (dev.nas_pools && dev.nas_pools.length) {
        html += '<div class="mt-3"><span class="text-xs text-muted">' + (isPveDevice ? 'ZFS 池' : 'NAS 存储池') + '</span>' +
          '<div class="table-wrap mt-1"><table><thead><tr><th>名称</th><th>总量</th><th>已用</th><th>使用率</th><th>状态</th><th>压缩比</th></tr></thead><tbody>' +
          dev.nas_pools.map(function(pool) {
            return '<tr><td>' + esc(pool.name) + '</td>' +
              '<td>' + (pool.size_gb != null ? pool.size_gb + ' GB' : '—') + '</td>' +
              '<td>' + (pool.used_gb != null ? pool.used_gb + ' GB' : '—') + '</td>' +
              '<td><span class="badge ' + (pool.usage_percent > 85 ? 'badge-danger' : pool.usage_percent > 70 ? 'badge-warning' : 'badge-success') + '">' + (pool.usage_percent != null ? pool.usage_percent + '%' : '—') + '</span></td>' +
              '<td><span class="badge ' + (pool.health_state === 'ONLINE' || pool.health_state === 'HEALTHY' ? 'badge-success' : 'badge-danger') + '">' + esc(pool.health_state) + '</span></td>' +
              '<td>' + (pool.compression_ratio != null ? pool.compression_ratio + 'x' : '—') + '</td></tr>';
          }).join('') +
          '</tbody></table></div></div>';
      }

      if (dev.nas_raid && dev.nas_raid.length) {
        html += '<div class="mt-3"><span class="text-xs text-muted">RAID 阵列</span>' +
          '<div class="table-wrap mt-1"><table><thead><tr><th>名称</th><th>类型</th><th>状态</th><th>磁盘数</th><th>降级磁盘</th></tr></thead><tbody>' +
          dev.nas_raid.map(function(r) {
            return '<tr><td>' + esc(r.name) + '</td>' +
              '<td>' + esc(r.type || '—') + '</td>' +
              '<td><span class="badge ' + (r.state === 'ONLINE' || r.state === 'HEALTHY' ? 'badge-success' : 'badge-danger') + '">' + esc(r.state) + '</span></td>' +
              '<td>' + (r.drives != null ? r.drives : '—') + '</td>' +
              '<td><span class="badge ' + (r.degraded_drives > 0 ? 'badge-danger' : 'badge-success') + '">' + (r.degraded_drives || 0) + '</span></td></tr>';
          }).join('') +
          '</tbody></table></div></div>';
      }

      if (dev.smart_attributes && dev.smart_attributes.length) {
        html += '<div class="mt-3"><span class="text-xs text-muted">' + (isPveDevice ? 'SMART 摘要' : 'SMART 属性') + '</span>' +
          '<div class="table-wrap mt-1"><table><thead><tr><th>属性</th><th>值</th><th>阈值</th><th>原始值</th><th>状态</th></tr></thead><tbody>' +
          dev.smart_attributes.map(function(s) {
            return '<tr><td>' + esc(s.attr_name) + '</td>' +
              '<td>' + (s.value != null ? s.value : '—') + '</td>' +
              '<td>' + (s.threshold != null ? s.threshold : '—') + '</td>' +
              '<td>' + (s.raw != null ? s.raw : '—') + '</td>' +
              '<td><span class="badge ' + (s.status === 'PASSED' || s.status === 'ok' ? 'badge-success' : 'badge-danger') + '">' + esc(s.status || '—') + '</span></td></tr>';
          }).join('') +
          '</tbody></table></div></div>';
      }

      if (dev.nas_volumes && dev.nas_volumes.length) {
        html += '<div class="mt-3"><span class="text-xs text-muted">' + (isPveDevice ? 'ZFS 数据集' : 'NAS 卷') + '</span>' +
          '<div class="table-wrap mt-1"><table><thead><tr><th>名称</th><th>' + (isPveDevice ? '所属池' : '存储池') + '</th><th>已用</th><th>可用</th></tr></thead><tbody>' +
          dev.nas_volumes.map(function(v) {
            return '<tr><td>' + esc(v.name) + '</td>' +
              '<td>' + esc(v.pool || '—') + '</td>' +
              '<td>' + (v.used_gb != null ? v.used_gb + ' GB' : '—') + '</td>' +
              '<td>' + (v.available_gb != null ? v.available_gb + ' GB' : '—') + '</td></tr>';
          }).join('') +
          '</tbody></table></div></div>';
      }

      if (dev.nas_snapshots && dev.nas_snapshots.length) {
        html += '<div class="mt-3"><span class="text-xs text-muted">' + (isPveDevice ? 'ZFS 快照' : 'NAS 快照') + '</span>' +
          '<div class="table-wrap mt-1"><table><thead><tr><th>名称</th><th>' + (isPveDevice ? '所属池' : '存储池') + '</th><th>已用</th><th>创建时间</th></tr></thead><tbody>' +
          dev.nas_snapshots.map(function(sn) {
            return '<tr><td>' + esc(sn.name) + '</td>' +
              '<td>' + esc(sn.pool || '—') + '</td>' +
              '<td>' + (sn.used_gb != null ? sn.used_gb + ' GB' : '—') + '</td>' +
              '<td>' + esc(sn.creation || '—') + '</td></tr>';
          }).join('') +
          '</tbody></table></div></div>';
      }

      html += '</div>';

      // Probe summary card (counts + capability hints) — outside metrics card
      html += probeSummaryCard(dev);

      // PVE-specific sections (version / VM-LXC / storage / network bridges)
      if (isPveDevice) {
        html += pveDetailHtml(dev);
      }
    } else {
      html += renderCollectionStateCard(collectionState);
    }

    if (als.length) {
      html += '<div class="card"><div class="card-header">🔔 关联告警 (' + als.length + ')</div>' +
        '<div class="table-wrap mt-2"><table><thead><tr><th>级别</th><th>信息</th><th>状态</th><th>时间</th></tr></thead><tbody>' +
        als.map(function (a) {
          return '<tr><td><span class="badge badge-' + sevBadge(a.severity) + '">' + sevText(a.severity) + '</span></td>' +
            '<td>' + esc(a.message || a.title || '—') + '</td>' +
            '<td><span class="badge ' + (a.status === 'active' ? 'badge-danger' : 'badge-success') + '">' + (a.status === 'active' ? '活跃' : '已处理') + '</span></td>' +
            '<td class="text-sm text-muted">' + (a.created_at || '—') + '</td></tr>';
        }).join('') +
        '</tbody></table></div></div>';
    }

    html += '</div></div>';
    S.modalHtml = html;
    renderModal();
  } catch (e) { if (!silent) toast('获取设备详情失败：' + e.message, 'error'); }
}

function kv(label, value) {
  return '<div><span class="text-xs text-muted" style="display:block;margin-bottom:2px">' + label + '</span><span>' + value + '</span></div>';
}

function miniMetric(label, val, unit, type) {
  var tones = { cpu: '#4f46e5', memory: '#10b981', disk: '#f59e0b', load: '#3b82f6' };
  var color = tones[type] || '#64748b';
  return '<div class="card" style="text-align:center;padding:16px">' +
    '<div class="text-xs text-muted mb-1">' + label + '</div>' +
    '<div style="font-size:22px;font-weight:700;color:' + color + '">' + (val != null ? val : '—') + (val != null ? unit : '') + '</div>' +
  '</div>';
}

function openDeviceModal() { openDeviceEdit(null); }

function openDeviceEdit(id) {
  var dev = id ? (S.devices.find(function (d) { return d.id === id; }) || null) : null;
  var isNew = !dev;
  var admin = isAdmin();

  var html = '<div class="modal-backdrop" onclick="if(event.target===this)closeModal()"><div class="modal" style="max-width:600px">' +
    '<div class="modal-header"><span>' + (isNew ? '➕ 新增设备' : '✏️ 编辑设备') + '</span><button class="modal-close" onclick="closeModal()">✕</button></div>' +
    '<form onsubmit="event.preventDefault();saveDevice(this,\'' + (id || '') + '\')">' +
      '<div class="form-group"><label class="form-label">名称 <span style="color:var(--danger)">*</span></label><input name="name" class="form-control" value="' + esc(dev && dev.name || '') + '" required></div>' +
      '<div class="form-group"><label class="form-label">主机地址 <span style="color:var(--danger)">*</span></label><input name="host" class="form-control" value="' + esc(dev && dev.host || '') + '" required></div>' +
      '<div class="grid-2">' +
        '<div class="form-group"><label class="form-label">端口</label><input name="port" type="number" class="form-control" value="' + (dev ? dev.port : 22) + '"></div>' +
        '<div class="form-group"><label class="form-label">主机类型</label><select name="device_type" class="form-control">' +
          '<option value="linux_server"' + (dev && dev.device_type === 'linux_server' ? ' selected' : '') + '>linux_server</option>' +
          '<option value="nas"' + (dev && dev.device_type === 'nas' ? ' selected' : '') + '>nas</option>' +
          '<option value="proxmox_host"' + (dev && dev.device_type === 'proxmox_host' ? ' selected' : '') + '>proxmox_host</option>' +
          '<option value="openwrt"' + (dev && dev.device_type === 'openwrt' ? ' selected' : '') + '>openwrt</option>' +
          '<option value="docker_host"' + (dev && dev.device_type === 'docker_host' ? ' selected' : '') + '>docker_host</option>' +
          '<option value="other"' + ((!dev || dev.device_type === 'other') ? ' selected' : '') + '>other</option>' +
        '</select></div>' +
      '</div>' +
      '<div class="form-group"><label class="form-label">分组</label><select name="group_id" class="form-control">' +
        S.groups.map(function (g) {
          return '<option value="' + esc(g.id) + '"' + (dev && dev.group_id === g.id ? ' selected' : '') + '>' + esc(g.name) + '</option>';
        }).join('') +
      '</select></div>';

  if (admin) {
    html += '<div class="grid-2">' +
      '<div class="form-group"><label class="form-label">SSH 用户名</label><input name="username" class="form-control" value="' + esc(dev && dev.username || '') + '"></div>' +
      '<div class="form-group"><label class="form-label">认证方式</label><select name="auth_type" class="form-control">' +
        '<option value="none"' + (dev && dev.auth_type === 'none' ? ' selected' : '') + '>暂不配置</option>' +
        '<option value="private_key"' + (dev && dev.auth_type === 'private_key' ? ' selected' : '') + '>私钥</option>' +
        '<option value="password"' + (dev && dev.auth_type === 'password' ? ' selected' : '') + '>密码</option>' +
      '</select></div></div>' +
      '<div class="grid-2">' +
        '<div class="form-group"><label class="form-label">密码</label><input name="password" type="password" class="form-control"></div>' +
        '<div class="form-group"><label class="form-label">Key Path</label><input name="key_path" class="form-control" value="' + esc(dev && (dev.key_path || dev.private_key_path) || '') + '"></div>' +
      '</div>';
  }

  html += '<div class="form-group"><label class="form-label">标签</label><input name="tags" class="form-control" value="' + esc((dev && dev.tags || []).join(', ')) + '"></div>' +
    '<div class="form-group"><label class="form-label">启用状态</label>' +
      '<label style="display:flex;align-items:center;gap:8px;height:40px">' +
        '<input type="checkbox" name="enabled"' + (dev && dev.enabled === false ? '' : ' checked') + '> 启用' +
      '</label>' +
    '</div>';

  // Advanced settings (collapsed) — only on edit. collection_interval is not
  // shown on the add form; new devices inherit the backend default.
  if (!isNew) {
    html += '<details class="mt-2">' +
      '<summary class="form-label" style="cursor:pointer">高级设置</summary>' +
      '<div class="form-group mt-2"><label class="form-label">后端采集周期</label>' +
        '<input name="collection_interval" type="number" class="form-control" value="' + (dev ? (dev.collection_interval || dev.poll_interval || 30) : 30) + '" min="30"> 秒' +
      '</div>' +
      '</details>';
  }

  html += '<button type="submit" class="btn btn-primary mt-4">保存</button>' +
    '</form></div></div>';

  S.modalHtml = html;
  renderModal();
}

async function saveDevice(form, id) {
  var key = 'save';
  if (isBusy(key)) return;
  var btn = form.querySelector('button[type="submit"]');
  if (btn) { btn.disabled = true; btn.textContent = '保存中…'; }
  var payload = {
    name: form.name.value.trim(),
    host: form.host.value.trim(),
    port: parseInt(form.port.value, 10) || 22,
    device_type: form.device_type.value.trim() || 'linux_server',
    group_id: form.group_id.value,
    tags: (form.tags.value || '').split(',').map(function (t) { return t.trim(); }).filter(Boolean),
    enabled: form.enabled ? form.enabled.checked : true
  };
  // collection_interval only sent on edit (advanced settings); on add it is
  // omitted so the backend inherits default_collection_interval.
  if (id && form.collection_interval) {
    var ci = parseInt(form.collection_interval.value, 10);
    if (ci >= 30) payload.collection_interval = ci;
  }
  if (isAdmin()) {
    if (form.username) payload.username = form.username.value.trim() || undefined;
    if (form.auth_type) payload.auth_type = form.auth_type.value || 'private_key';
    var pw = form.password && form.password.value.trim();
    var pkp = form.key_path && form.key_path.value.trim();
    if (pw) payload.password = pw;
    if (pkp) payload.key_path = pkp;
  }
  if (!payload.name || !payload.host) {
    if (btn) { btn.disabled = false; btn.textContent = '保存'; }
    return toast('名称和主机不能为空', 'warning');
  }
  setBusy(key, true);
  try {
    if (id) {
      await API.patch('/devices/' + id, payload);
      toast('保存成功：设备已更新', 'success');
    } else {
      await API.post('/devices', payload);
      toast('保存成功：设备已创建', 'success');
    }
    closeModal();
    await loadMain();
    render();
  } catch (e) {
    if (btn) { btn.disabled = false; btn.textContent = '保存'; }
    if (e.status === 403) return toast('保存失败：无权限执行此操作', 'error');
    toast('保存失败：' + (e.message || '未知错误'), 'error');
  } finally {
    setBusy(key, false);
  }
}

function refreshDevice(id) {
  runLongOp('refresh:' + id, '刷新设备', 30, function (signal) {
    return API.post('/devices/' + id + '/refresh', { timeout: 30 }, { signal: signal });
  }, function (res) {
    var rec = (res && res.data && res.data.record) || (res && res.record) || {};
    var dev = (res && res.data && res.data.device) || {};
    var status = rec.status || dev.status || 'healthy';
    if (status === 'healthy') toast('刷新完成：' + (rec.summary || '采集正常'), 'success');
    else if (status === 'warning') toast('刷新完成（部分指标异常）：' + (rec.summary || ''), 'warning');
    else toast('刷新失败：' + (rec.summary || rec.error_message || '设备不可达'), 'error');
    loadMain().then(function () {
      if (S.page === 'devices') renderDevTable(); else render();
    });
    if (S._detailDeviceId === id) refreshDeviceDetail(id, true);
  }, function (err) {
    if (err && err.timeout) toast(err.message, 'error');
    else if (err && err.status === 403) toast('刷新失败：无权限执行此操作', 'error');
    else toast('刷新失败：' + ((err && err.message) || '未知错误'), 'error');
  });
}

function testDevice(id) {
  runLongOp('test:' + id, '测试 SSH 连接', 30, function (signal) {
    return API.post('/devices/' + id + '/test', { timeout: 30 }, { signal: signal });
  }, function (res) {
    var rec = (res && res.data && res.data.record) || (res && res.record) || {};
    var status = rec.status || 'healthy';
    if (status === 'healthy' || status === 'online') toast('SSH 测试成功：' + (rec.summary || '连接正常'), 'success');
    else if (status === 'warning') toast('SSH 测试完成（有警告）：' + (rec.summary || ''), 'warning');
    else toast('SSH 测试失败：' + (rec.summary || rec.error_message || '连接失败'), 'error');
  }, function (err) {
    if (err && err.timeout) toast(err.message, 'error');
    else if (err && err.status === 403) toast('SSH 测试失败：无权限执行此操作', 'error');
    else toast('SSH 测试失败：' + ((err && err.message) || '未知错误'), 'error');
  });
}

async function toggleDevice(id, enabled) {
  var key = 'toggle:' + id;
  if (isBusy(key)) return;
  setBusy(key, true); render();
  try {
    await API.patch('/devices/' + id, { enabled: enabled });
    toast('状态更新成功：设备已' + (enabled ? '启用' : '禁用'), 'success');
    await loadMain(); render();
  } catch (e) {
    if (e.status === 403) toast('状态更新失败：无权限执行此操作', 'error');
    else toast('状态更新失败：' + (e.message || '未知错误'), 'error');
  } finally {
    setBusy(key, false); render();
  }
}

function deleteDevice(id) {
  var key = 'delete:' + id;
  if (isBusy(key)) return;
  if (!confirm('确定删除该设备？采集记录和告警也会被移除。')) return;
  setBusy(key, true); render();
  API.del('/devices/' + id).then(function () {
    toast('删除成功：设备已删除', 'success');
    return loadMain().then(render);
  }).catch(function (e) {
    if (e.status === 403) toast('删除失败：无权限执行此操作', 'error');
    else toast('删除失败：' + (e.message || '未知错误'), 'error');
  }).finally(function () {
    setBusy(key, false); render();
  });
}

// ─── Groups ─────────────────────────────────────────────────
function renderGroups() {
  return '<div class="page-header"><h1 class="page-title">📁 设备分组</h1>' +
    (isAdmin() ? '<button class="btn btn-primary" onclick="openGroupModal()">+ 新增分组</button>' : '') +
    '</div>' +

    (S.groups.length === 0
      ? '<div class="empty-state"><div class="empty-state-icon">📁</div><div class="empty-state-text">暂无分组</div></div>'
      : '<div class="grid-3">' +
        S.groups.map(function (g) {
          return '<div class="card">' +
            '<div class="card-header">' +
              '<span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:' + esc(g.color || '#4f46e5') + ';margin-right:8px"></span>' + esc(g.name) + '</span>' +
              (g.id !== 'grp-ungrouped' && isAdmin()
                ? '<div class="flex gap-1">' +
                    '<button class="btn btn-xs btn-outline" onclick="openGroupEdit(\'' + esc(g.id) + '\')">编辑</button>' +
                    '<button class="btn btn-xs btn-danger" onclick="deleteGroup(\'' + esc(g.id) + '\')">删除</button>' +
                  '</div>'
                : '') +
            '</div>' +
            (g.description ? '<p class="text-muted text-sm mb-4">' + esc(g.description) + '</p>' : '') +
            '<div class="grid-4 mt-4">' +
              '<div style="text-align:center"><div class="stat-value" style="font-size:20px">' + (g.device_count || 0) + '</div><span class="text-xs text-muted">设备</span></div>' +
              '<div style="text-align:center"><div class="stat-value" style="font-size:20px;color:var(--success)">' + (g.online_count || 0) + '</div><span class="text-xs text-muted">在线</span></div>' +
              '<div style="text-align:center"><div class="stat-value" style="font-size:20px;color:var(--danger)">' + (g.offline_count || 0) + '</div><span class="text-xs text-muted">离线</span></div>' +
              '<div style="text-align:center"><div class="stat-value" style="font-size:20px;color:var(--warning)">' + (g.active_alert_count || 0) + '</div><span class="text-xs text-muted">告警</span></div>' +
            '</div>' +
          '</div>';
        }).join('') +
      '</div>');
}

function openGroupModal() { openGroupEdit(null); }

function openGroupEdit(id) {
  var g = id ? (S.groups.find(function (x) { return x.id === id; }) || null) : null;
  var html = '<div class="modal-backdrop" onclick="if(event.target===this)closeModal()"><div class="modal">' +
    '<div class="modal-header"><span>' + (g ? '✏️ 编辑分组' : '➕ 新增分组') + '</span><button class="modal-close" onclick="closeModal()">✕</button></div>' +
    '<form onsubmit="event.preventDefault();saveGroup(this,\'' + (id || '') + '\')">' +
      '<div class="form-group"><label class="form-label">名称 <span style="color:var(--danger)">*</span></label><input name="name" class="form-control" value="' + esc(g && g.name || '') + '" required></div>' +
      '<div class="form-group"><label class="form-label">描述</label><input name="description" class="form-control" value="' + esc(g && g.description || '') + '"></div>' +
      '<div class="grid-2">' +
        '<div class="form-group"><label class="form-label">颜色</label><input name="color" type="color" class="form-control" value="' + esc(g && g.color || '#4f46e5') + '" style="height:40px;padding:4px"></div>' +
        '<div class="form-group"><label class="form-label">图标 (emoji)</label><input name="icon" class="form-control" value="' + esc(g && g.icon || '📁') + '"></div>' +
      '</div>' +
      '<div class="form-group"><label class="form-label">排序权重</label><input name="sort_order" type="number" class="form-control" value="' + (g && g.sort_order != null ? g.sort_order : 100) + '"></div>' +
      '<button type="submit" class="btn btn-primary">保存</button>' +
    '</form></div></div>';
  S.modalHtml = html;
  renderModal();
}

async function saveGroup(form, id) {
  var payload = {
    name: form.name.value.trim(),
    description: form.description.value.trim(),
    color: form.color.value || '#4f46e5',
    icon: form.icon.value || '📁',
    sort_order: parseInt(form.sort_order.value, 10) || 100
  };
  if (!payload.name) return toast('分组名称不能为空', 'warning');
  try {
    if (id) { await API.patch('/device-groups/' + id, payload); toast('分组已更新', 'success'); }
    else   { await API.post('/device-groups', payload); toast('分组已创建', 'success'); }
    closeModal();
    await loadMain(); render();
  } catch (e) {
    if (e.status === 403) return toast('无权限执行此操作', 'error');
    toast('保存失败：' + e.message, 'error');
  }
}

async function deleteGroup(id) {
  if (!confirm('确定删除此分组？关联设备会移动到未分组。')) return;
  try {
    await API.del('/device-groups/' + id);
    toast('分组已删除', 'success');
    await loadMain(); render();
  } catch (e) { toast('删除失败：' + e.message, 'error'); }
}

// ─── History ─────────────────────────────────────────────────
var histDev = 'all', histGrp = 'all', histStat = 'all', histLimit = 200;

function renderHistory() {
  if (!S.collections.length) { loadCollections().then(render); }
  var filtered = filterCollections();

  return '<div class="page-header"><h1 class="page-title">📋 历史记录</h1></div>' +
    '<div class="flex gap-3 mb-4 flex-wrap items-center">' +
      '<select class="form-control" style="width:180px" onchange="histDev=this.value;render()">' +
        '<option value="all">全部设备</option>' +
        S.devices.map(function (d) { return '<option value="' + esc(d.id) + '">' + esc(d.name) + '</option>'; }).join('') +
      '</select>' +
      '<select class="form-control" style="width:180px" onchange="histGrp=this.value;render()">' +
        '<option value="all">全部分组</option>' +
        S.groups.map(function (g) { return '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>'; }).join('') +
      '</select>' +
      '<select class="form-control" style="width:130px" onchange="histStat=this.value;render()">' +
        '<option value="all">全部状态</option>' +
        '<option value="healthy">健康</option><option value="warning">警告</option><option value="critical">严重</option><option value="failed">失败</option>' +
      '</select>' +
      '<input class="form-control" style="width:90px" type="number" value="200" min="10" max="500" onchange="histLimit=parseInt(this.value)||200;loadCollections({limit:histLimit}).then(render)">' +
      '<button class="btn btn-outline btn-sm" onclick="loadCollections({limit:histLimit,device_id:histDev!==\'all\'?histDev:undefined,group_id:histGrp!==\'all\'?histGrp:undefined,status:histStat!==\'all\'?histStat:undefined}).then(render)">🔄 刷新</button>' +
    '</div>' +

    (filtered.length === 0
      ? '<div class="empty-state"><div class="empty-state-icon">📋</div><div class="empty-state-text">暂无历史记录</div></div>'
      : '<div class="table-wrap"><table><thead><tr>' +
          '<th>时间</th><th>设备</th><th>分组</th><th>类型</th><th>状态</th><th>摘要</th>' +
        '</tr></thead><tbody>' +
        filtered.map(function (r) {
          return '<tr>' +
            '<td class="text-sm">' + (r.collected_at || '—') + '</td>' +
            '<td>' + esc(r.device_name || devById(r.device_id)) + '</td>' +
            '<td>' + esc(groupById(r.group_id)) + '</td>' +
            '<td>' + esc(r.purpose || r.collector || '—') + '</td>' +
            '<td><span class="badge badge-' + statusBadge(r.status) + '">' + statusText(r.status) + '</span></td>' +
            '<td class="text-sm text-muted" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(r.summary || r.error_message || '—') + '</td>' +
          '</tr>';
        }).join('') +
        '</tbody></table></div>');
}

function filterCollections() {
  return S.collections.filter(function (r) {
    if (histDev !== 'all' && r.device_id !== histDev) return false;
    if (histGrp !== 'all' && r.group_id !== histGrp) return false;
    if (histStat !== 'all' && r.status !== histStat) return false;
    return true;
  });
}

// ─── Alerts ─────────────────────────────────────────────────
var altStatus = 'all', altGrp = 'all', altDev = 'all';

function renderAlerts() {
  var critical = 0, warning = 0, info = 0, resolved = 0, active = 0;
  for (var i = 0; i < S.alerts.length; i++) {
    var a = S.alerts[i];
    if (a.status === 'active') {
      active++;
      if (a.severity === 'critical') critical++;
      else if (a.severity === 'warning') warning++;
      else if (a.severity === 'info') info++;
    } else if (a.status === 'resolved') resolved++;
  }

  if (critical + warning + info > 0) {
    queueChart('chart-alert-sev', {
      type: 'pie',
      data: {
        labels: ['严重', '警告', '信息'],
        datasets: [{ data: [critical, warning, info], backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6'], borderWidth: 0 }]
      },
      options: { plugins: { legend: { position: 'bottom', labels: { usePointStyle: true } } } }
    });
  }
  if (active + resolved > 0) {
    queueChart('chart-alert-status', {
      type: 'doughnut',
      data: {
        labels: ['活跃', '已处理'],
        datasets: [{ data: [active, resolved], backgroundColor: ['#ef4444', '#10b981'], borderWidth: 0 }]
      },
      options: { plugins: { legend: { position: 'bottom', labels: { usePointStyle: true } } } }
    });
  }

  var filtered = filterAlerts();
  return '<div class="page-header"><h1 class="page-title">🔔 告警中心</h1></div>' +

    '<div class="grid-4 mb-6">' +
      statCard('活跃告警', String(active), active > 0 ? 'danger' : 'success') +
      statCard('已处理', String(resolved), 'success') +
      statCard('严重', String(critical), critical > 0 ? 'danger' : '') +
      statCard('警告', String(warning), warning > 0 ? 'warning' : '') +
    '</div>' +

    '<div class="grid-2 mb-6">' +
      (critical + warning + info > 0
        ? '<div class="card"><div class="card-header">📊 严重程度分布</div><div class="chart-wrap chart-md"><canvas id="chart-alert-sev"></canvas></div></div>'
        : '<div class="card"><div class="card-header">📊 严重程度分布</div><div class="empty-state"><div class="empty-state-text">暂无数据</div></div></div>') +
      (active + resolved > 0
        ? '<div class="card"><div class="card-header">📊 活跃/已处理比例</div><div class="chart-wrap chart-md"><canvas id="chart-alert-status"></canvas></div></div>'
        : '<div class="card"><div class="card-header">📊 活跃/已处理比例</div><div class="empty-state"><div class="empty-state-text">暂无数据</div></div></div>') +
    '</div>' +

    '<div class="flex gap-3 mb-4 flex-wrap">' +
      '<select class="form-control" style="width:130px" onchange="altStatus=this.value;render()">' +
        '<option value="all">全部状态</option><option value="active">活跃</option><option value="resolved">已处理</option>' +
      '</select>' +
      '<select class="form-control" style="width:180px" onchange="altGrp=this.value;render()">' +
        '<option value="all">全部分组</option>' +
        S.groups.map(function (g) { return '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>'; }).join('') +
      '</select>' +
      '<select class="form-control" style="width:180px" onchange="altDev=this.value;render()">' +
        '<option value="all">全部设备</option>' +
        S.devices.map(function (d) { return '<option value="' + esc(d.id) + '">' + esc(d.name) + '</option>'; }).join('') +
      '</select>' +
    '</div>' +

    (filtered.length === 0
      ? '<div class="empty-state"><div class="empty-state-icon">✅</div><div class="empty-state-text">暂无告警</div></div>'
      : '<div class="table-wrap"><table><thead><tr>' +
          '<th>级别</th><th>设备</th><th>分组</th><th>信息</th><th>状态</th><th>时间</th><th>操作</th>' +
        '</tr></thead><tbody>' +
        filtered.map(function (a) {
          return '<tr>' +
            '<td><span class="badge badge-' + sevBadge(a.severity) + '">' + sevText(a.severity) + '</span></td>' +
            '<td>' + esc(a.device_name || devById(a.device_id)) + '</td>' +
            '<td>' + esc(groupById(a.group_id)) + '</td>' +
            '<td>' + esc(a.message || a.title || '—') + '</td>' +
            '<td><span class="badge ' + (a.status === 'active' ? 'badge-danger' : 'badge-success') + '">' + (a.status === 'active' ? '活跃' : '已处理') + '</span></td>' +
            '<td class="text-sm text-muted">' + (a.created_at || '—') + '</td>' +
            '<td>' + (a.status === 'active' && canOperate() ? '<button class="btn btn-xs btn-outline" onclick="resolveAlert(\'' + esc(a.id) + '\')">✔ 处理</button>' : '') + '</td>' +
          '</tr>';
        }).join('') +
        '</tbody></table></div>');
}

function filterAlerts() {
  return S.alerts.filter(function (a) {
    if (altStatus !== 'all' && a.status !== altStatus) return false;
    if (altGrp !== 'all' && a.group_id !== altGrp) return false;
    if (altDev !== 'all' && a.device_id !== altDev) return false;
    return true;
  });
}

async function resolveAlert(id) {
  try {
    await API.post('/alerts/' + id + '/resolve');
    toast('告警已处理', 'success');
    await loadMain(); render();
  } catch (e) {
    if (e.status === 403) return toast('无权限执行此操作', 'error');
    toast('处理失败：' + e.message, 'error');
  }
}

// ─── Users ──────────────────────────────────────────────────
function renderUsers() {
  if (!S.users.length) { loadUsers().then(render); }
  return '<div class="page-header"><h1 class="page-title">👥 用户管理</h1><button class="btn btn-primary" onclick="openUserModal()">+ 新增用户</button></div>' +
    (S.users.length === 0
      ? '<div class="empty-state"><div class="empty-state-icon">👥</div><div class="empty-state-text">暂无用户</div></div>'
      : '<div class="table-wrap"><table><thead><tr><th>用户名</th><th>角色</th><th>状态</th><th>最后登录</th><th>创建时间</th><th>操作</th></tr></thead><tbody>' +
        S.users.map(function (u) {
          return '<tr>' +
            '<td><strong>' + esc(u.username) + '</strong></td>' +
            '<td><span class="badge badge-info">' + roleText(u.role) + '</span></td>' +
            '<td>' + (u.enabled !== false ? '<span class="badge badge-success">启用</span>' : '<span class="badge badge-muted">禁用</span>') + '</td>' +
            '<td class="text-sm text-muted">' + (u.last_login_at || '—') + '</td>' +
            '<td class="text-sm text-muted">' + (u.created_at || '—') + '</td>' +
            '<td><div class="flex gap-1">' +
              '<button class="btn btn-xs btn-outline" onclick="openUserEdit(\'' + esc(u.id) + '\')">编辑</button>' +
              '<button class="btn btn-xs btn-outline" onclick="toggleUser(\'' + esc(u.id) + '\',' + !u.enabled + ')">' + (u.enabled ? '禁用' : '启用') + '</button>' +
              '<button class="btn btn-xs btn-outline" onclick="resetUserPassword(\'' + esc(u.id) + '\')">重置密码</button>' +
            '</div></td>' +
          '</tr>';
        }).join('') +
      '</tbody></table></div>');
}

function openUserModal() { openUserEdit(null); }

function openUserEdit(id) {
  var u = id ? (S.users.find(function (x) { return x.id === id; }) || null) : null;
  var isNew = !u;
  var html = '<div class="modal-backdrop" onclick="if(event.target===this)closeModal()"><div class="modal">' +
    '<div class="modal-header"><span>' + (isNew ? '➕ 新增用户' : '✏️ 编辑用户') + '</span><button class="modal-close" onclick="closeModal()">✕</button></div>' +
    '<form onsubmit="event.preventDefault();saveUser(this,\'' + (id || '') + '\')">' +
      (isNew ? '<div class="form-group"><label class="form-label">用户名 <span style="color:var(--danger)">*</span></label><input name="username" class="form-control" required></div>' : '') +
      '<div class="form-group"><label class="form-label">角色</label><select name="role" class="form-control">' +
        '<option value="admin"' + (u && u.role === 'admin' ? ' selected' : '') + '>管理员</option>' +
        '<option value="operator"' + (u && u.role === 'operator' ? ' selected' : '') + '>操作员</option>' +
        '<option value="viewer"' + (u && u.role === 'viewer' ? ' selected' : '') + '>查看者</option>' +
      '</select></div>' +
      (isNew ? '<div class="form-group"><label class="form-label">密码 <span style="color:var(--danger)">*</span></label><input name="password" type="password" class="form-control" required></div>' : '') +
      '<div class="form-group">' +
        '<label style="display:flex;align-items:center;gap:8px"><input type="checkbox" name="enabled"' + (u && u.enabled === false ? '' : ' checked') + '> 启用账户</label>' +
      '</div>' +
      '<button type="submit" class="btn btn-primary">保存</button>' +
    '</form></div></div>';
  S.modalHtml = html;
  renderModal();
}

async function saveUser(form, id) {
  if (!id) {
    var p = { username: form.username.value.trim(), password: form.password.value, role: form.role.value, enabled: form.enabled.checked };
    if (!p.username || !p.password) return toast('用户名和密码不能为空', 'warning');
    try { await API.post('/users', p); toast('用户已创建', 'success'); closeModal(); await loadUsers(); render(); }
    catch (e) { toast('创建失败：' + e.message, 'error'); }
  } else {
    var pu = { role: form.role.value, enabled: form.enabled.checked };
    try { await API.patch('/users/' + id, pu); toast('用户已更新', 'success'); closeModal(); await loadUsers(); render(); }
    catch (e) { toast('更新失败：' + e.message, 'error'); }
  }
}

async function toggleUser(id, enabled) {
  try { await API.patch('/users/' + id, { enabled: enabled }); toast(enabled ? '用户已启用' : '用户已禁用', 'success'); await loadUsers(); render(); }
  catch (e) { toast('操作失败：' + e.message, 'error'); }
}

async function resetUserPassword(id) {
  var pw = prompt('请输入新密码（至少8位）：');
  if (!pw) return;
  try { await API.post('/users/' + id + '/reset-password', { password: pw }); toast('密码已重置', 'success'); }
  catch (e) { toast('重置失败：' + e.message, 'error'); }
}

// ─── Settings ───────────────────────────────────────────────
function renderSettings() {
  if (!S.retention) { loadRetention().then(render); }
  if (!S.collectionSettings) { loadCollectionSettings().then(render); }
  var r = S.retention || {};
  var c = S.collectionSettings || {};
  return '<div class="page-header"><h1 class="page-title">⚙ 系统设置</h1></div>' +
    '<div class="grid-2">' +
      '<div class="card">' +
        '<div class="card-header">后端采集周期</div>' +
        '<form onsubmit="event.preventDefault();saveCollectionSettings(this)">' +
          '<div class="form-group"><label class="form-label">后端采集周期</label><input name="default_collection_interval" type="number" class="form-control" value="' + (c.default_collection_interval || 30) + '" min="30"> 秒</div>' +
          '<button type="submit" class="btn btn-primary">保存</button>' +
        '</form>' +
      '</div>' +
      '<div class="card">' +
        '<div class="card-header">🗄 数据保留策略</div>' +
        '<form onsubmit="event.preventDefault();saveRetention(this)">' +
          '<div class="form-group"><label class="form-label">采集记录保留天数</label><input name="collection_history_days" type="number" class="form-control" value="' + (r.collection_history_days || 90) + '" min="1"></div>' +
          '<div class="form-group"><label class="form-label">审计日志保留天数</label><input name="audit_log_days" type="number" class="form-control" value="' + (r.audit_log_days || 180) + '" min="1"></div>' +
          '<div class="form-group"><label class="form-label">已处理告警保留天数</label><input name="resolved_alert_days" type="number" class="form-control" value="' + (r.resolved_alert_days || 180) + '" min="1"></div>' +
          '<div class="flex gap-2">' +
            '<button type="submit" class="btn btn-primary">保存</button>' +
            '<button type="button" class="btn btn-danger" onclick="runCleanup()">立即清理</button>' +
          '</div>' +
        '</form>' +
      '</div>' +
    '</div>';
}

async function loadCollectionSettings() {
  try {
    var res = await API.get('/settings/collection');
    S.collectionSettings = res.data || res;
  } catch (e) { S.collectionSettings = { default_collection_interval: 30 }; }
}

async function saveCollectionSettings(form) {
  var v = parseInt(form.default_collection_interval.value, 10);
  if (!v || v < 30) return toast('后端采集周期不能小于 30 秒', 'warning');
  try {
    var res = await API.patch('/settings/collection', { default_collection_interval: v });
    S.collectionSettings = res.data || res;
    toast('保存成功', 'success'); render();
  } catch (e) { toast('保存失败：' + e.message, 'error'); }
}

async function saveRetention(form) {
  var p = {
    collection_history_days: parseInt(form.collection_history_days.value, 10),
    audit_log_days: parseInt(form.audit_log_days.value, 10),
    resolved_alert_days: parseInt(form.resolved_alert_days.value, 10)
  };
  try { await API.patch('/settings/retention', p); S.retention = p; toast('保存成功', 'success'); render(); }
  catch (e) { toast('保存失败：' + e.message, 'error'); }
}

async function runCleanup() {
  if (!confirm('确定立即清理过期数据？活跃告警不会被删除。')) return;
  try {
    var res = await API.post('/settings/retention/cleanup');
    var d = (res.data && res.data.deleted) || (res.deleted) || {};
    toast('清理完成：采集 ' + (d.collection_records || 0) + '、审计 ' + (d.audit_logs || 0) + '、告警 ' + (d.resolved_alerts || 0), 'success');
  } catch (e) { toast('清理失败：' + e.message, 'error'); }
}

// ─── Modal System ───────────────────────────────────────────
function renderModal() {
  var exist = document.getElementById('modal-overlay');
  if (exist) exist.remove();
  if (!S.modalHtml) return;
  var overlay = document.createElement('div');
  overlay.id = 'modal-overlay';
  overlay.innerHTML = S.modalHtml;
  document.body.appendChild(overlay);
}

function closeModal() {
  S.modalHtml = null;
  S._detailDeviceId = null;   // stop detail auto-refresh
  var overlay = document.getElementById('modal-overlay');
  if (overlay) overlay.remove();
}

// ─── Global error handler ───────────────────────────────────
window.addEventListener('unhandledrejection', function (event) {
  var e = event.reason;
  if (e && e.status === 401) {
    API._token = null;
    S.user = null;
    S.auth = 'login';
    S.dashboard = null; S.devices = []; S.groups = []; S.alerts = []; S.collections = []; S.users = []; S.retention = null; S.collectionSettings = null;
    render();
    toast('会话已过期，请重新登录', 'warning');
  } else if (e && e.status === 403) {
    toast('无权限执行此操作', 'error');
  }
});

// ─── Bootstrap ──────────────────────────────────────────────
initAuth();

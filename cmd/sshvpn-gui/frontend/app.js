const MASKED_TEXT = '••••••••';

const state = {
  servers: [],
  processes: [],
  savingProcesses: false,
  pendingProcessSave: false,
  processFeedbackTimer: null,
  selectedName: '',
  mode: 'process',
  formEditing: false,
  status: { state: 'stopped', mode: 'process', endpoint: 'SOCKS5 127.0.0.1:1080', upload: 0, download: 0 },
  logs: [],
  runningProcesses: [],
  runningSelected: new Set(),
  manageSelectedName: '',
  editingOriginalName: '',
  confirmResolver: null,
};

const api = () => window.go.main.App;

document.addEventListener('DOMContentLoaded', async () => {
  bindEvents();
  subscribeBackendEvents();
  await loadBootstrap();
});

function bindEvents() {
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });
  document.getElementById('gotoProcessBtn').addEventListener('click', () => switchTab('process'));

  document.querySelectorAll('input[name="proxyMode"]').forEach((radio) => {
    radio.addEventListener('change', () => {
      state.mode = radio.value;
      updateEndpointPreview();
      api().SetSelection(state.selectedName, state.mode);
    });
  });

  document.getElementById('showPasswordCheck').addEventListener('change', (e) => {
    document.getElementById('passwordInput').type = e.target.checked ? 'text' : 'password';
  });

  document.getElementById('editBtn').addEventListener('click', () => {
    const profile = findSelectedProfile();
    if (profile) {
      loadProfileToEditor(profile);
    }
  });

  document.getElementById('saveBtn').addEventListener('click', saveInlineForm);
  document.getElementById('connectBtn').addEventListener('click', toggleConnection);
  document.getElementById('manageServersBtn').addEventListener('click', openServerManager);
  document.getElementById('pickRunningBtn').addEventListener('click', openRunningPicker);
  document.getElementById('browseExeBtn').addEventListener('click', browseAndAddExe);
  document.getElementById('browseDirBtn').addEventListener('click', browseAndAddDir);
  document.getElementById('addManualBtn').addEventListener('click', addManualRule);
  document.getElementById('manualProcInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') addManualRule();
  });

  document.getElementById('copyLogsBtn').addEventListener('click', copyLogs);
  document.getElementById('clearLogsBtn').addEventListener('click', clearLogs);
  document.getElementById('openDirBtn').addEventListener('click', () => api().OpenDataDirectory());
  document.getElementById('resetTrafficBtn').addEventListener('click', resetTraffic);

  document.querySelectorAll('[data-close]').forEach((btn) => {
    btn.addEventListener('click', () => closeModal(btn.dataset.close));
  });

  document.getElementById('modalAddServerBtn').addEventListener('click', () => openServerEditModal(null));
  document.getElementById('modalEditServerBtn').addEventListener('click', () => {
    const target = state.servers.find((s) => s.name === state.manageSelectedName);
    if (target) openServerEditModal(target);
  });
  document.getElementById('modalDeleteServerBtn').addEventListener('click', deleteManagedServer);
  document.getElementById('editModalSaveBtn').addEventListener('click', saveServerEditModal);

  document.getElementById('refreshRunningBtn').addEventListener('click', refreshRunningList);
  document.getElementById('runningSearchInput').addEventListener('input', renderRunningList);
  document.getElementById('confirmRunningBtn').addEventListener('click', addSelectedRunningProcesses);

  document.getElementById('confirmCancelBtn').addEventListener('click', () => resolveConfirm(false));
  document.getElementById('confirmOkBtn').addEventListener('click', () => resolveConfirm(true));
}

function subscribeBackendEvents() {
  if (!window.runtime || !window.runtime.EventsOn) return;
  window.runtime.EventsOn('log', (line) => {
    appendLogLine(line);
  });
  window.runtime.EventsOn('state', (snapshot) => {
    applyStatus(snapshot);
  });
  window.runtime.EventsOn('traffic', (data) => {
    if (data) {
      updateTrafficText(data.upload || 0, data.download || 0);
    }
  });
  window.runtime.EventsOn('sync', async () => {
    try {
      const snap = await api().GetLiveSnapshot();
      replaceAllLogs(snap.logs || []);
      applyStatus(snap.status);
    } catch (_) {
      // 忽略窗口恢复时的瞬时同步异常
    }
  });
}

async function loadBootstrap() {
  try {
    const boot = await api().GetBootstrapState();
    state.servers = boot.servers || [];
    state.processes = boot.processes || [];
    state.selectedName = boot.selected_name || (state.servers[0]?.name || '');
    state.mode = boot.selected_mode || 'process';

    document.getElementById('dataDirText').textContent = boot.base_directory || '';
    document.querySelectorAll('input[name="proxyMode"]').forEach((r) => {
      r.checked = r.value === state.mode;
    });

    (boot.logs || []).forEach((line) => appendLogLine(line, true));
    scrollLogsToBottom();

    renderServerList();
    syncFormAfterSelection();
    renderProcessRules();
    applyStatus(boot.status);
  } catch (err) {
    showValidation(err.message || String(err));
  }
}

function switchTab(name) {
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.tab === name);
  });
  document.querySelectorAll('.tab-pane').forEach((pane) => {
    pane.classList.toggle('active', pane.id === `tab-${name}`);
  });
}

function findSelectedProfile() {
  return state.servers.find((s) => s.name === state.selectedName) || null;
}

function renderServerList() {
  const ul = document.getElementById('serverList');
  ul.innerHTML = '';
  state.servers.forEach((srv) => {
    const li = document.createElement('li');
    li.textContent = srv.name;
    li.title = srv.name;
    if (srv.name === state.selectedName) li.classList.add('selected');
    li.addEventListener('click', () => {
      if (isRunning()) return;
      state.selectedName = srv.name;
      api().SetSelection(state.selectedName, state.mode);
      renderServerList();
      syncFormAfterSelection();
    });
    ul.appendChild(li);
  });
}

function syncFormAfterSelection() {
  const profile = findSelectedProfile();
  if (profile) {
    lockForm(profile.proxy_port || 1080);
  } else {
    clearFormForNewEntry();
  }
}

function lockForm(port) {
  document.getElementById('serverAddressInput').value = MASKED_TEXT;
  document.getElementById('usernameInput').value = MASKED_TEXT;
  document.getElementById('passwordInput').value = MASKED_TEXT;
  document.getElementById('passwordInput').type = 'password';
  document.getElementById('showPasswordCheck').checked = false;
  document.getElementById('proxyPortInput').value = MASKED_TEXT;
  document.getElementById('dnsServerInput').value = MASKED_TEXT;
  state.formEditing = false;
  updateEndpointPreview(port);
  refreshControlsEnabled();
}

function loadProfileToEditor(profile) {
  document.getElementById('serverAddressInput').value = profile.server_address || '';
  document.getElementById('usernameInput').value = profile.username || '';
  document.getElementById('passwordInput').value = profile.password || '';
  document.getElementById('passwordInput').type = 'password';
  document.getElementById('showPasswordCheck').checked = false;
  document.getElementById('proxyPortInput').value = String(profile.proxy_port || 1080);
  document.getElementById('dnsServerInput').value = profile.dns_server || '';
  state.formEditing = true;
  updateEndpointPreview(profile.proxy_port || 1080);
  refreshControlsEnabled();
}

function clearFormForNewEntry() {
  document.getElementById('serverAddressInput').value = '';
  document.getElementById('usernameInput').value = '';
  document.getElementById('passwordInput').value = '';
  document.getElementById('passwordInput').type = 'password';
  document.getElementById('showPasswordCheck').checked = false;
  document.getElementById('proxyPortInput').value = '1080';
  document.getElementById('dnsServerInput').value = '';
  state.formEditing = true;
  updateEndpointPreview(1080);
  refreshControlsEnabled();
}

function isRunning() {
  return ['starting', 'connected', 'stopping'].includes(state.status.state);
}

function refreshControlsEnabled() {
  const running = isRunning();
  const canEditFields = !running && state.formEditing;
  ['serverAddressInput', 'usernameInput', 'passwordInput', 'proxyPortInput', 'dnsServerInput', 'showPasswordCheck'].forEach((id) => {
    document.getElementById(id).disabled = !canEditFields;
  });
  document.getElementById('saveBtn').disabled = !canEditFields;
  document.getElementById('editBtn').disabled = running || state.formEditing || !findSelectedProfile();
  document.getElementById('manageServersBtn').disabled = running;
  document.querySelectorAll('input[name="proxyMode"]').forEach((r) => {
    r.disabled = running;
  });
  document.getElementById('connectBtn').disabled = state.status.state === 'stopping';
}

function updateEndpointPreview(portOverride) {
  if (state.status.state === 'connected' && state.status.endpoint) {
    document.getElementById('endpointText').textContent = state.status.endpoint;
    return;
  }
  const profile = findSelectedProfile();
  const port = portOverride || (profile ? profile.proxy_port : 1080) || 1080;
  const prefix = state.mode === 'process'
    ? '按进程分流 · SOCKS5 '
    : state.mode === 'global'
      ? '全局 TCP · SOCKS5 '
      : 'SOCKS5 ';
  document.getElementById('endpointText').textContent = `${prefix}127.0.0.1:${port}`;
}

function applyStatus(snapshot) {
  if (!snapshot) return;
  state.status = snapshot;

  const dot = document.getElementById('statusDot');
  dot.className = `status-dot dot-${snapshot.state || 'stopped'}`;

  let text = '未连接';
  if (snapshot.state === 'starting') text = '正在连接';
  else if (snapshot.state === 'stopping') text = '正在断开';
  else if (snapshot.state === 'faulted') text = '连接失败';
  else if (snapshot.state === 'connected') {
    if (snapshot.mode === 'process') text = '已连接（按进程分流）';
    else if (snapshot.mode === 'socks5') text = '已连接（SOCKS5）';
    else text = '已连接（全局 TCP）';
  }
  document.getElementById('statusText').textContent = text;

  const canDisconnect = snapshot.state === 'starting' || snapshot.state === 'connected';
  document.getElementById('connectBtn').textContent = canDisconnect ? '断开' : '连接';

  updateTrafficText(snapshot.upload || 0, snapshot.download || 0);
  updateEndpointPreview();
  refreshControlsEnabled();

  if (snapshot.state === 'faulted') {
    showValidation(snapshot.error ? `连接失败：${snapshot.error}` : '连接失败，详细原因请查看日志页');
  }
}

async function saveInlineForm() {
  hideValidation();
  if (!state.formEditing) return true;

  const addr = document.getElementById('serverAddressInput').value.trim();
  const user = document.getElementById('usernameInput').value.trim();
  const pass = document.getElementById('passwordInput').value;
  const port = parseInt(document.getElementById('proxyPortInput').value.trim(), 10);
  const dns = document.getElementById('dnsServerInput').value.trim();

  if (!addr) return showValidation('请填写服务器地址'), false;
  if (!user) return showValidation('请填写用户名'), false;
  if (!pass) return showValidation('请填写密码'), false;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return showValidation('代理端口必须在 1 到 65535 之间'), false;
  }

  const current = findSelectedProfile();
  const payload = {
    name: current ? current.name : addr,
    server_address: addr,
    username: user,
    password: pass,
    proxy_port: port,
    dns_server: dns,
  };

  try {
    state.servers = await api().SaveServer(current ? current.name : '', payload);
    state.selectedName = payload.name;
    renderServerList();
    syncFormAfterSelection();
    return true;
  } catch (err) {
    showValidation(err.message || String(err));
    return false;
  }
}

async function toggleConnection() {
  hideValidation();
  if (state.status.state === 'starting' || state.status.state === 'connected') {
    try {
      await api().Disconnect();
    } catch (err) {
      showValidation(err.message || String(err));
    }
    return;
  }
  if (state.status.state === 'stopping') return;

  if (!(await saveInlineForm())) return;
  if (!state.selectedName) {
    showValidation('请先添加并保存服务器配置');
    return;
  }
  try {
    await api().Connect(state.selectedName, state.mode);
  } catch (err) {
    showValidation(err.message || String(err));
  }
}

function showValidation(msg) {
  const box = document.getElementById('validationBox');
  box.textContent = msg;
  box.classList.remove('hidden');
}

function hideValidation() {
  document.getElementById('validationBox').classList.add('hidden');
}

/* 进程分流规则 */
function updateProcessBadge() {
  const enabledCount = state.processes.filter((r) => r.enabled !== false).length;
  document.getElementById('ruleBadge').textContent = String(enabledCount);
}

function showProcessFeedback(msg, isError = false) {
  const box = document.getElementById('processFeedback');
  if (state.processFeedbackTimer) {
    clearTimeout(state.processFeedbackTimer);
    state.processFeedbackTimer = null;
  }
  box.textContent = msg;
  box.className = `process-feedback ${isError ? 'error' : 'ok'}`;
  if (!isError) {
    state.processFeedbackTimer = setTimeout(() => {
      box.classList.add('hidden');
      state.processFeedbackTimer = null;
    }, 4000);
  }
}

function showProcessSaveSuccess(res) {
  if (res.applied_live) {
    if (res.closed_connections > 0) {
      showProcessFeedback(
        `已实时生效：当前启用 ${res.enabled_count} 条规则，已断开 ${res.closed_connections} 条受影响连接以立即切换`,
        false,
      );
      return;
    }
    showProcessFeedback(`已实时生效：当前启用 ${res.enabled_count} 条规则`, false);
    return;
  }
  if (state.status.state === 'connected') {
    showProcessFeedback('规则已保存（当前非「按进程分流」模式，切换模式重连后生效）', false);
    return;
  }
  if (state.status.state === 'starting') {
    showProcessFeedback('规则已保存（正在建立连接，完成后自动生效）', false);
    return;
  }
  showProcessFeedback(`规则已保存（当前启用 ${res.enabled_count} 条，连接后生效）`, false);
}

function normalizeRuleTarget(rule) {
  const rawPath = (rule.path || '').trim();
  if (rawPath) {
    const slashes = rawPath.replace(/\//g, '\\');
    if (slashes.endsWith('\\')) {
      return slashes.replace(/\\+$/, '\\').toLowerCase();
    }
    return slashes.toLowerCase();
  }
  return (rule.name || '').trim().toLowerCase();
}

function upsertProcessRule(rule) {
  const key = normalizeRuleTarget(rule);
  if (!key) return;
  const normalizedRule = {
    ...rule,
    enabled: rule.enabled !== false,
  };
  const existingIdx = state.processes.findIndex((item) => normalizeRuleTarget(item) === key);
  if (existingIdx >= 0) {
    state.processes[existingIdx] = {
      ...state.processes[existingIdx],
      ...normalizedRule,
    };
    return;
  }
  state.processes.push(normalizedRule);
}

function renderProcessRules() {
  const ul = document.getElementById('processRuleList');
  const empty = document.getElementById('processEmptyState');
  ul.innerHTML = '';

  updateProcessBadge();

  if (state.processes.length === 0) {
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');

  state.processes.forEach((rule, idx) => {
    const li = document.createElement('li');
    li.className = 'process-item';

    const chk = document.createElement('input');
    chk.type = 'checkbox';
    chk.checked = rule.enabled !== false;
    chk.addEventListener('change', async () => {
      state.processes[idx].enabled = chk.checked;
      updateProcessBadge();
      await persistProcessRules();
    });

    const meta = document.createElement('div');
    meta.className = 'process-meta';
    const nameEl = document.createElement('div');
    nameEl.className = 'process-name';
    nameEl.textContent = rule.name || rule.path;
    const pathEl = document.createElement('div');
    pathEl.className = 'process-path';
    if (rule.path && /[\\/]$/.test(rule.path)) {
      pathEl.textContent = `目录规则：${rule.path}（目录下全部程序及子进程走代理）`;
    } else if (rule.path) {
      pathEl.textContent = `${rule.path}（含派生的全部子进程）`;
    } else {
      pathEl.textContent = '按进程名匹配（所有目录同名程序及其子进程生效）';
    }
    pathEl.title = pathEl.textContent;
    meta.append(nameEl, pathEl);

    const delBtn = document.createElement('button');
    delBtn.className = 'btn btn-danger btn-xs';
    delBtn.type = 'button';
    delBtn.textContent = '移除';
    delBtn.addEventListener('click', async () => {
      state.processes.splice(idx, 1);
      renderProcessRules();
      await persistProcessRules();
    });

    li.append(chk, meta, delBtn);
    ul.appendChild(li);
  });
}

async function persistProcessRules() {
  if (state.savingProcesses) {
    state.pendingProcessSave = true;
    return;
  }
  state.savingProcesses = true;
  try {
    do {
      state.pendingProcessSave = false;
      const snapshot = state.processes.map((rule) => ({ ...rule }));
      const res = await api().SaveProcessRules(snapshot);
      if (!state.pendingProcessSave) {
        state.processes = res.processes || [];
        renderProcessRules();
        showProcessSaveSuccess(res);
      }
    } while (state.pendingProcessSave);
  } catch (err) {
    showProcessFeedback(err.message || String(err), true);
    try {
      const boot = await api().GetBootstrapState();
      state.processes = boot.processes || [];
      renderProcessRules();
    } catch (_) {
      // 忽略恢复读取失败，保留错误提示
    }
  } finally {
    state.savingProcesses = false;
  }
}

async function browseAndAddExe() {
  try {
    const selectedPath = await api().PickExecutable();
    if (!selectedPath) return;
    const base = selectedPath.split(/[/\\]/).pop() || selectedPath;
    const name = base.replace(/\.exe$/i, '') || base;
    upsertProcessRule({ name, path: selectedPath, enabled: true });
    renderProcessRules();
    await persistProcessRules();
  } catch (err) {
    showProcessFeedback(err.message || String(err), true);
  }
}

async function browseAndAddDir() {
  try {
    const selectedDir = await api().PickDirectory();
    if (!selectedDir) return;
    const trimmed = selectedDir.replace(/[\\/]+$/, '');
    const name = trimmed.split(/[/\\]/).pop() || selectedDir;
    upsertProcessRule({ name, path: selectedDir, enabled: true });
    renderProcessRules();
    await persistProcessRules();
  } catch (err) {
    showProcessFeedback(err.message || String(err), true);
  }
}

async function addManualRule() {
  const input = document.getElementById('manualProcInput');
  const value = input.value.trim();
  if (!value) return;
  const hasSep = /[\\/]/.test(value);
  let rule;
  if (hasSep) {
    const trimmed = value.replace(/[\\/]+$/, '');
    const base = trimmed.split(/[/\\]/).pop() || value;
    const name = /[\\/]$/.test(value) ? base : (base.replace(/\.exe$/i, '') || base);
    rule = { name, path: value, enabled: true };
  } else {
    rule = { name: value, enabled: true };
  }
  upsertProcessRule(rule);
  input.value = '';
  renderProcessRules();
  await persistProcessRules();
}

/* 运行中程序选择器 */
async function openRunningPicker() {
  state.runningSelected.clear();
  document.getElementById('runningSearchInput').value = '';
  document.getElementById('runningSelectedHint').textContent = '选择要加入分流的程序';
  openModal('runningProcModal');
  await refreshRunningList();
}

async function refreshRunningList() {
  const listEl = document.getElementById('runningProcList');
  listEl.innerHTML = '<li class="empty-state">正在读取进程列表...</li>';
  try {
    state.runningProcesses = await api().ListRunningProcesses();
    renderRunningList();
  } catch (err) {
    listEl.innerHTML = `<li class="empty-state">读取失败：${err.message || err}</li>`;
  }
}

function renderRunningList() {
  const kw = document.getElementById('runningSearchInput').value.trim().toLowerCase();
  const listEl = document.getElementById('runningProcList');
  listEl.innerHTML = '';

  const filtered = state.runningProcesses.filter((p) => {
    if (!kw) return true;
    return p.name.toLowerCase().includes(kw) || p.path.toLowerCase().includes(kw);
  });

  if (filtered.length === 0) {
    listEl.innerHTML = '<li class="empty-state">没有匹配的进程</li>';
    return;
  }

  filtered.forEach((proc) => {
    const li = document.createElement('li');
    li.className = 'running-item';
    const chk = document.createElement('input');
    chk.type = 'checkbox';
    chk.checked = state.runningSelected.has(proc.path);
    chk.addEventListener('change', () => {
      if (chk.checked) state.runningSelected.add(proc.path);
      else state.runningSelected.delete(proc.path);
      document.getElementById('runningSelectedHint').textContent =
        state.runningSelected.size > 0 ? `已选择 ${state.runningSelected.size} 个程序` : '选择要加入分流的程序';
    });

    const meta = document.createElement('div');
    meta.className = 'process-meta';
    const n = document.createElement('div');
    n.className = 'process-name';
    n.textContent = proc.name;
    const p = document.createElement('div');
    p.className = 'process-path';
    p.textContent = proc.path;
    meta.append(n, p);

    li.addEventListener('click', (e) => {
      if (e.target !== chk) {
        chk.checked = !chk.checked;
        chk.dispatchEvent(new Event('change'));
      }
    });

    li.append(chk, meta);
    listEl.appendChild(li);
  });
}

async function addSelectedRunningProcesses() {
  if (state.runningSelected.size === 0) {
    closeModal('runningProcModal');
    return;
  }
  state.runningSelected.forEach((path) => {
    const found = state.runningProcesses.find((p) => p.path === path);
    upsertProcessRule({
      name: found ? found.name : path,
      path,
      enabled: true,
    });
  });
  closeModal('runningProcModal');
  renderProcessRules();
  await persistProcessRules();
}

/* 服务器管理弹窗 */
function openServerManager() {
  state.manageSelectedName = state.selectedName || (state.servers[0]?.name || '');
  renderManageServerList();
  openModal('serverModal');
}

function renderManageServerList() {
  const ul = document.getElementById('manageServerList');
  const empty = document.getElementById('manageServerEmpty');
  ul.innerHTML = '';

  if (state.servers.length === 0) {
    empty.classList.remove('hidden');
    ul.classList.add('hidden');
  } else {
    empty.classList.add('hidden');
    ul.classList.remove('hidden');
  }

  state.servers.forEach((srv) => {
    const li = document.createElement('li');
    li.textContent = `${srv.name} (${srv.server_address})`;
    if (srv.name === state.manageSelectedName) li.classList.add('selected');
    li.addEventListener('click', () => {
      state.manageSelectedName = srv.name;
      renderManageServerList();
    });
    ul.appendChild(li);
  });
}

function openServerEditModal(profile) {
  document.getElementById('editModalError').classList.add('hidden');
  if (profile) {
    state.editingOriginalName = profile.name;
    document.getElementById('serverEditTitle').textContent = '编辑服务器';
    document.getElementById('editNameInput').value = profile.name;
    document.getElementById('editAddrInput').value = profile.server_address;
    document.getElementById('editUserInput').value = profile.username;
    document.getElementById('editPassInput').value = profile.password;
    document.getElementById('editPortInput').value = String(profile.proxy_port || 1080);
    document.getElementById('editDnsInput').value = profile.dns_server || '';
  } else {
    state.editingOriginalName = '';
    document.getElementById('serverEditTitle').textContent = '新增服务器';
    document.getElementById('editNameInput').value = '新服务器';
    document.getElementById('editAddrInput').value = '';
    document.getElementById('editUserInput').value = '';
    document.getElementById('editPassInput').value = '';
    document.getElementById('editPortInput').value = '1080';
    document.getElementById('editDnsInput').value = '';
  }
  openModal('serverEditModal');
}

async function saveServerEditModal() {
  const errBox = document.getElementById('editModalError');
  errBox.classList.add('hidden');

  const name = document.getElementById('editNameInput').value.trim();
  const addr = document.getElementById('editAddrInput').value.trim();
  const user = document.getElementById('editUserInput').value.trim();
  const pass = document.getElementById('editPassInput').value;
  const port = parseInt(document.getElementById('editPortInput').value.trim(), 10);
  const dns = document.getElementById('editDnsInput').value.trim();

  if (!name || !addr || !user || !pass || !Number.isInteger(port) || port < 1 || port > 65535) {
    errBox.textContent = '请完整填写名称、地址、用户名、密码及有效端口 (1-65535)';
    errBox.classList.remove('hidden');
    return;
  }

  try {
    state.servers = await api().SaveServer(state.editingOriginalName, {
      name,
      server_address: addr,
      username: user,
      password: pass,
      proxy_port: port,
      dns_server: dns,
    });
    state.manageSelectedName = name;
    state.selectedName = name;
    closeModal('serverEditModal');
    renderManageServerList();
    renderServerList();
    syncFormAfterSelection();
  } catch (err) {
    errBox.textContent = err.message || String(err);
    errBox.classList.remove('hidden');
  }
}

async function deleteManagedServer() {
  if (!state.manageSelectedName) return;
  const ok = await askConfirm('删除服务器', `确定删除服务器“${state.manageSelectedName}”吗？`);
  if (!ok) return;

  try {
    state.servers = await api().DeleteServer(state.manageSelectedName);
    if (!state.servers.some((s) => s.name === state.selectedName)) {
      state.selectedName = state.servers[0]?.name || '';
    }
    state.manageSelectedName = state.servers[0]?.name || '';
    renderManageServerList();
    renderServerList();
    syncFormAfterSelection();
  } catch (err) {
    showValidation(err.message || String(err));
  }
}

/* 日志与流量 */
function appendLogLine(line, skipScroll = false) {
  state.logs.push(line);
  const container = document.getElementById('logContainer');
  const div = document.createElement('div');
  div.className = 'log-line';
  div.textContent = line;
  container.appendChild(div);
  while (state.logs.length > 1000) {
    state.logs.shift();
    if (container.firstChild) container.removeChild(container.firstChild);
  }
  if (!skipScroll) scrollLogsToBottom();
}

function replaceAllLogs(lines) {
  state.logs = [];
  const container = document.getElementById('logContainer');
  container.innerHTML = '';
  const frag = document.createDocumentFragment();
  lines.slice(-1000).forEach((line) => {
    state.logs.push(line);
    const div = document.createElement('div');
    div.className = 'log-line';
    div.textContent = line;
    frag.appendChild(div);
  });
  container.appendChild(frag);
  scrollLogsToBottom();
}

function scrollLogsToBottom() {
  const container = document.getElementById('logContainer');
  container.scrollTop = container.scrollHeight;
}

async function copyLogs() {
  if (state.logs.length === 0) return;
  try {
    await navigator.clipboard.writeText(state.logs.join('\n'));
  } catch (_) {
    // 忽略剪切板权限异常
  }
}

function clearLogs() {
  state.logs = [];
  document.getElementById('logContainer').innerHTML = '';
  api().ClearLogs();
}

async function resetTraffic() {
  const ok = await askConfirm('重置流量', '确定清零累计流量统计吗？（运行中无需断开即可立即清零）');
  if (!ok) return;
  try {
    await api().ResetTraffic();
  } catch (err) {
    showValidation(err.message || String(err));
  }
}

function updateTrafficText(upload, download) {
  document.getElementById('trafficText').textContent =
    `上行 ${formatBytes(upload)} · 下行 ${formatBytes(download)}`;
}

function formatBytes(bytes) {
  const kb = 1024;
  const mb = kb * 1024;
  const gb = mb * 1024;
  if (bytes >= gb) return `${(bytes / gb).toFixed(2)} GB`;
  if (bytes >= mb) return `${(bytes / mb).toFixed(2)} MB`;
  if (bytes >= kb) return `${(bytes / kb).toFixed(2)} KB`;
  return `${bytes} B`;
}

function openModal(id) {
  document.getElementById(id).classList.remove('hidden');
}

function closeModal(id) {
  document.getElementById(id).classList.add('hidden');
}

function askConfirm(title, message) {
  document.getElementById('confirmTitle').textContent = title;
  document.getElementById('confirmMessage').textContent = message;
  openModal('confirmModal');
  return new Promise((resolve) => {
    state.confirmResolver = resolve;
  });
}

function resolveConfirm(result) {
  closeModal('confirmModal');
  if (state.confirmResolver) {
    const fn = state.confirmResolver;
    state.confirmResolver = null;
    fn(result);
  }
}

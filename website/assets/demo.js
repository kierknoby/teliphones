(function () {
  'use strict';
  const stateApi = window.TeliphonesDemoState;
  let storage = null;
  try { storage = window.localStorage; } catch (_) {}
  let state = stateApi.safeLoad(storage);
  if (!storage) state.notice = 'Browser storage is unavailable; demonstration changes will last only until this page closes.';
  let activeTab = 'pbx';
  const pbxPanel = document.querySelector('[data-panel="pbx"]');
  const windowsPanel = document.querySelector('[data-panel="windows"]');
  const notice = (text) => `<p class="demo-notice" role="status" aria-live="polite" tabindex="-1">${escapeHtml(text)}</p>`;
  const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
  const status = (connected) => `<span class="demo-status ${connected ? 'is-on' : 'is-off'}">${connected ? 'Connected · admitted' : 'Disconnected'}</span>`;

  function persistAndRender() {
    const previousFocus = document.activeElement;
    try {
      if (!storage) throw new Error('Browser storage is unavailable.');
      stateApi.save(storage, state);
    } catch (_) {
      state.notice = 'Browser storage is unavailable; demonstration changes will last only until this page closes.';
    }
    render();
    if (previousFocus && previousFocus !== document.body) {
      const previousData = previousFocus.dataset || {};
      const actions = Array.from(document.querySelectorAll(`[data-panel="${activeTab}"] [data-action]`));
      const target = actions.find((element) =>
        previousData.action && element.dataset.action === previousData.action &&
        element.dataset.id === previousData.id && element.dataset.tab === previousData.tab) ||
        (previousData.id && actions.find((element) => element.dataset.id === previousData.id)) ||
        document.querySelector(`[data-panel="${activeTab}"] .demo-notice`);
      target?.focus();
    }
  }

  function focusTab(name) {
    Array.from(document.querySelectorAll('[data-tab]'))
      .find((tab) => tab.dataset.tab === name)?.focus();
  }

  function renderPbx() {
    const rows = state.workstations.map((workstation) => `<tr>
      <th scope="row">${escapeHtml(workstation.name)}<small>${escapeHtml(workstation.id)}</small></th>
      <td>${escapeHtml(workstation.ssh ? 'Web + SSH' : 'Web only')}<small>${workstation.ssh ? `SSH: approved · ${escapeHtml(workstation.sshUser)}` : 'SSH: not authorised'}</small></td>
      <td>${status(workstation.connected)}</td>
      <td>${workstation.locked ? 'Locked' : 'Unlocked'}<small>${escapeHtml(workstation.sources || 'No source restriction')}</small></td>
      <td class="demo-row-actions">${workstation.connected
        ? `<button data-action="disconnect" data-id="${escapeHtml(workstation.id)}">Disconnect</button>`
        : `<button data-action="connect" data-id="${escapeHtml(workstation.id)}">Connect test session</button>`}
        <button data-action="lock-current" data-id="${escapeHtml(workstation.id)}">Lock to Current IP</button>
        <button data-action="edit-sources" data-id="${escapeHtml(workstation.id)}">Edit Allowed List</button>
        <button class="danger" data-action="revoke" data-id="${escapeHtml(workstation.id)}">Revoke</button></td>
    </tr>`).join('');
    pbxPanel.innerHTML = `<div class="demo-app-header"><div><p class="micro">FreePBX · Connectivity</p><h2>Windows workstations</h2><p>Review policy, pairing requests, admitted sessions and per-workstation restrictions.</p></div><span class="demo-chip">${escapeHtml(state.policy.toUpperCase())}</span></div>
      <div class="demo-summary"><div><span>Connection state</span><strong>${escapeHtml(state.policy[0].toUpperCase() + state.policy.slice(1))}</strong></div><div><span>Admitted sessions</span><strong>${stateApi.occupancy(state)} / ${state.maximum}</strong></div><div><span>Pending pairing</span><strong>${state.pending ? '1 request' : 'None'}</strong></div></div>
      <div class="demo-grid"><section class="demo-card"><h3>Connection policy</h3><p>Closed disconnects sample workstations. Frozen retains approved access but pauses new pairing. Open permits approved workstations to connect subject to their restrictions and session capacity.</p><label>Policy<select data-action="policy"><option value="open"${state.policy === 'open' ? ' selected' : ''}>Open</option><option value="closed"${state.policy === 'closed' ? ' selected' : ''}>Closed</option><option value="frozen"${state.policy === 'frozen' ? ' selected' : ''}>Frozen</option></select></label><label>Maximum simultaneous sessions<select data-action="maximum">${[1,2,3,4,5].map((n) => `<option value="${n}"${state.maximum === n ? ' selected' : ''}>${n}</option>`).join('')}</select></label></section>
      <section class="demo-card"><h3>Pairing request</h3>${state.pending ? `<p><strong>${escapeHtml(state.pending.name)}</strong> requests ${escapeHtml(state.pending.access === 'ssh' ? 'Web + SSH' : 'Web-only')} access.${state.pending.locked ? ' Initial source lock requested.' : ''}</p><p class="micro">PBX-observed sample source: 203.0.113.24</p>${state.pending.access === 'ssh' ? `<label>Existing Linux account<select data-pair-account><option value="">Select an account…</option><option value="pbxadmin">pbxadmin</option><option value="operator">operator</option><option value="maint">maint</option></select></label>` : ''}<div class="demo-actions"><button class="button small" data-action="approve-pair">Approve pairing</button><button class="button secondary small" data-action="reject-pair">Reject</button></div>` : '<p>No pending pairing request. Create one from the Windows demonstration.</p>'}</section></div>
      ${state.sshRequest ? `<section class="demo-card demo-approval"><h3>SSH elevation request</h3><p>${escapeHtml(state.workstations.find((item) => item.id === state.sshRequest.id)?.name || 'Workstation')} requests SSH access. Select an existing sample Linux account; no account is created.</p><label>Existing Linux account<select data-action="ssh-account"><option value=""${state.sshRequest.account ? '' : ' selected'}>Select an account…</option>${['pbxadmin', 'operator', 'maint'].map((account) => `<option value="${account}"${state.sshRequest.account === account ? ' selected' : ''}>${account}</option>`).join('')}</select></label><div class="demo-actions"><button class="button small" data-action="approve-ssh">Approve SSH</button><button class="button secondary small" data-action="reject-ssh">Reject SSH</button></div></section>` : ''}
      ${state.sourceRequest ? `<section class="demo-card demo-approval"><h3>Allowed List change</h3><p>${escapeHtml(state.workstations.find((item) => item.id === state.sourceRequest.id)?.name || 'Workstation')} requests <code>${escapeHtml(state.sourceRequest.sources)}</code>. Existing restrictions stay active until approval.</p><div class="demo-actions"><button class="button small" data-action="approve-sources">Approve sources</button><button class="button secondary small" data-action="reject-sources">Reject sources</button></div></section>` : ''}
      ${state.unlockRequest ? `<section class="demo-card demo-approval"><h3>Unlock request</h3><p>${escapeHtml(state.workstations.find((item) => item.id === state.unlockRequest.id)?.name || 'Workstation')} requests removal of its source restriction. Current restrictions remain active pending your decision.</p><div class="demo-actions"><button class="button small" data-action="approve-unlock">Approve unlock</button><button class="button secondary small" data-action="reject-unlock">Reject unlock</button></div></section>` : ''}
      <section class="demo-card demo-table-card"><h3>Approved workstations</h3><div class="demo-table-scroll"><table class="demo-table"><thead><tr><th>Workstation</th><th>Access</th><th>Session</th><th>Sources</th><th>Actions</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No approved workstations. Create a request in the Windows demonstration.</td></tr>'}</tbody></table></div></section>
      <div class="demo-grid"><section class="demo-card"><h3>Manually managed Banned List</h3><p>Demonstration only: sample bans apply to the TELIPHONES WireGuard listener, not other PBX services.</p><form data-form="ban-add"><label>IPv4 / IPv6 / CIDR<input name="source" placeholder="198.51.100.8/32" required></label><button class="button secondary small">Add sample ban</button></form><ul class="demo-list">${state.bans.map((source) => `<li><code>${escapeHtml(source)}</code><button data-action="ban-remove" data-value="${escapeHtml(source)}">Remove</button></li>`).join('')}</ul></section><section class="demo-card"><h3>Allowed List and DNS</h3><p>Lock to Current IP uses the sample PBX-observed public source. Source changes are validated in the browser demo; this does not resolve real DNS.</p><p class="fine">Synthetic public source: 203.0.113.24 · DNS: example.invalid (illustrative only)</p></section></div>${notice(state.notice)}`;
  }

  function renderWindows() {
    const workstation = state.workstations.find((item) => item.id === state.selectedId) || state.workstations[0];
    const pairingForm = `<form data-form="request-pair"><label>PBX name<input name="name" value="Desk workstation ${state.nextId}" maxlength="40" required></label><label>Requested access<select name="access"><option value="web">Web Access</option><option value="ssh">Web + SSH Access</option></select></label><label class="demo-check"><input name="locked" type="checkbox"> Lock to current PBX-verified IP</label><label>Allowed sources (optional)<input name="sources" value="203.0.113.24"></label><button class="button small">Request Approval</button></form>`;
    const workstationNav = state.workstations.map((item) => `<button type="button" class="${workstation && item.id === workstation.id ? 'selected' : ''}" data-action="select-workstation" data-id="${escapeHtml(item.id)}">${escapeHtml(item.name)}</button>`).join('');
    windowsPanel.innerHTML = `<div class="windows-demo-window"><div class="windows-demo-top"><span class="app-mark">T</span><strong>TELIPHONES</strong><span class="micro">Interactive demo</span><button class="quiet-button" data-action="reset" aria-label="Reset demonstration">Reset Demo</button></div><div class="windows-demo-layout"><nav class="windows-demo-nav" aria-label="Application sections"><strong>My PBXs</strong>${workstationNav || '<button class="selected" type="button">PBX · Demo Lab</button>'}<button type="button" disabled>Remote Support</button><button type="button" disabled>Settings</button><p class="fine">Sample profile only</p></nav><div class="windows-demo-content"><div class="windows-demo-title"><div><p class="micro">SAVED CONNECTION</p><h2>${escapeHtml(workstation ? workstation.name : 'Demo Lab')}</h2><p>FreePBX 17 · synthetic PBX</p></div>${workstation ? status(workstation.connected) : '<span class="demo-status is-off">Not paired</span>'}</div>
      <div class="windows-policy-strip"><span>PBX policy <strong>${escapeHtml(state.policy.toUpperCase())}</strong></span><span>Admission <strong>${stateApi.occupancy(state)} / ${state.maximum}</strong></span><span>Source <strong>${workstation && workstation.locked ? 'Locked' : 'Unlocked'}</strong></span></div>
      <section class="windows-demo-card"><h3>Pair a workstation</h3>${state.pending ? `<p>Request for <strong>${escapeHtml(state.pending.name)}</strong> is <b>Pending Approval</b>.</p><p>Access requested: ${escapeHtml(state.pending.access === 'ssh' ? 'Web + SSH' : 'Web only')}. ${state.pending.locked ? 'Source restriction requested.' : ''}</p>` : state.workstations.length && !state.newPairing ? `<p>Pairing identity <code>${escapeHtml(workstation ? workstation.id : '')}</code> is preserved.</p><button class="button secondary small" data-action="new-pairing">Add another workstation</button>` : pairingForm}</section>
      ${workstation ? `      <section class="windows-demo-card"><h3>Connection</h3><div class="demo-actions">${workstation.connected ? `<button class="button secondary small" data-action="disconnect" data-id="${escapeHtml(workstation.id)}">Disconnect</button><button class="button small" data-action="connect" data-id="${escapeHtml(workstation.id)}">Reconnect</button>` : `<button class="button small" data-action="connect" data-id="${escapeHtml(workstation.id)}">Connect</button>`}<button class="button secondary small" data-action="lock-current" data-id="${escapeHtml(workstation.id)}">Lock to Current IP</button></div><p>${workstation.connected && state.policy === 'open' ? 'Connected; PBX session admission granted.' : state.policy === 'closed' ? 'Unavailable: PBX policy is Closed.' : state.policy === 'frozen' ? 'Policy Frozen; approved profiles may connect, pairing changes are paused.' : 'Disconnected; connect to request session admission.'}</p><p class="fine">Connection Health: <strong>${workstation.connected ? 'Healthy · simulated' : 'Unavailable · disconnected'}</strong>. No tunnel or real health probes are performed.</p></section>
      <section class="windows-demo-card"><h3>Security</h3><label class="demo-check"><input type="checkbox" data-action="password"${state.passwordProtected ? ' checked' : ''}> Password Protection ${state.passwordProtected ? '<span>Enabled (simulated state)</span>' : '<span>Disabled</span>'}</label><p class="fine">No password is requested or stored by this demo. Real Password Protection uses the Windows application's credential flow.</p></section>
      ${workstation.ssh && workstation.connected ? `<section class="windows-demo-card"><h3>Integrated SSH Console</h3><p>Authorised sample account: <strong>${escapeHtml(workstation.sshUser || 'approved account')}</strong> @ <strong>demo-pbx</strong></p><div class="demo-terminal" aria-label="Simulated terminal output"><pre data-terminal-output>Simulated TELIPHONES console · no SSH connection\nType help to see safe demo commands.</pre></div><form data-form="terminal"><label class="sr-only" for="demo-terminal-command">Simulated command</label><div class="demo-terminal-input"><input id="demo-terminal-command" name="command" autocomplete="off" placeholder="help"><button class="button small">Run demo command</button></div></form><p class="fine">Only help, whoami, hostname, pwd, ls, uptime and clear are simulated. No shell is invoked.</p></section>` : `<section class="windows-demo-card"><h3>SSH Access</h3><p>${workstation.ssh ? 'SSH is approved for the selected account. Connect and obtain PBX session admission to open the simulated console.' : state.sshRequest && state.sshRequest.id === workstation.id ? 'Pending Approval by the FreePBX administrator.' : 'SSH is not authorised for this workstation.'}</p>${workstation.ssh ? '' : `<button class="button secondary small" data-action="request-ssh" data-id="${escapeHtml(workstation.id)}"${state.sshRequest ? ' disabled' : ''}>Request SSH Access</button>`}<p class="fine">Web access remains available if SSH is rejected.</p></section>`}
      <section class="windows-demo-card"><h3>Workstation policy</h3><p>${workstation.locked ? `Locked · Allowed List: ${escapeHtml(workstation.sources)}` : 'Unlocked · no public-source lock'}</p><p class="fine">${state.sourceRequest && state.sourceRequest.id === workstation.id ? 'Allowed List change: Pending Approval · current restriction still enforced.' : state.unlockRequest && state.unlockRequest.id === workstation.id ? 'Unlock: Pending Approval · current restriction still enforced.' : 'Policy request status: Applied.'}</p>${workstation.locked ? `<button class="button secondary small" data-action="request-unlock" data-id="${escapeHtml(workstation.id)}"${state.unlockRequest ? ' disabled' : ''}>Request Unlock</button>` : ''}<form data-form="sources" data-id="${escapeHtml(workstation.id)}"><label>Edit Allowed List<input name="sources" value="${escapeHtml(workstation.sources)}" required></label><button class="button secondary small"${state.sourceRequest ? ' disabled' : ''}>Request source change</button></form></section>` : '<section class="windows-demo-card"><h3>Waiting for pairing</h3><p>Create a request and approve it in the FreePBX module demonstration.</p></section>'}
      <p class="demo-inline-notice" role="status" aria-live="polite">${escapeHtml(state.notice)}</p></div></div></div>`;
  }

  function render() {
    document.querySelectorAll('[data-tab]').forEach((tab) => {
      const selected = tab.dataset.tab === activeTab;
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
    });
    document.querySelectorAll('[data-panel]').forEach((panel) => { panel.hidden = panel.dataset.panel !== activeTab; });
    renderPbx();
    renderWindows();
  }

  document.addEventListener('keydown', (event) => {
    const current = event.target.closest('[data-tab]');
    if (!current || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    const tabs = Array.from(document.querySelectorAll('[data-tab]'));
    const index = tabs.indexOf(current);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1
      : (index + (event.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length;
    activeTab = tabs[next].dataset.tab;
    render();
    focusTab(activeTab);
    event.preventDefault();
  });

  document.addEventListener('click', (event) => {
    const button = event.target.closest('[data-action]');
    if (!button) return;
    const action = button.dataset.action;
    if (action === 'tab') {
      activeTab = button.dataset.tab;
      render();
      focusTab(activeTab);
      return;
    }
    if (action === 'edit-sources') {
      const item = state.workstations.find((workstation) => workstation.id === button.dataset.id);
      const value = window.prompt('Edit comma-separated allowed sources (IPv4, IPv6, CIDR or DNS):', item && item.sources);
      if (value !== null) state = stateApi.apply(state, 'sources', { id: button.dataset.id, value });
    } else if (action === 'reset') {
      if (!window.confirm('Reset all browser-local TELIPHONES demonstration data?')) return;
      state = stateApi.apply(state, 'reset');
      activeTab = 'pbx';
    } else {
      const payload = { id: button.dataset.id, value: button.dataset.value };
      if (action === 'approve-pair') {
        const account = pbxPanel.querySelector('[data-pair-account]');
        if (account) payload.account = account.value;
      }
      state = stateApi.apply(state, action, payload);
    }
    persistAndRender();
  });

  document.addEventListener('change', (event) => {
    if (event.target.dataset.action === 'policy') state = stateApi.apply(state, 'policy', { value: event.target.value });
    else if (event.target.dataset.action === 'maximum') state = stateApi.apply(state, 'maximum', { value: event.target.value });
    else if (event.target.dataset.action === 'password') state.passwordProtected = event.target.checked;
    else if (event.target.dataset.action === 'ssh-account') state = stateApi.apply(state, 'ssh-account', { value: event.target.value });
    else return;
    persistAndRender();
  });

  document.addEventListener('submit', (event) => {
    const form = event.target;
    event.preventDefault();
    const data = new FormData(form);
    if (form.dataset.form === 'request-pair') {
      state = stateApi.apply(state, 'request-pair', { name: data.get('name'), access: data.get('access'), locked: data.has('locked'), sources: data.get('sources') });
      activeTab = 'pbx';
    } else if (form.dataset.form === 'ban-add') {
      state = stateApi.apply(state, 'ban-add', { value: data.get('source') });
    } else if (form.dataset.form === 'sources') {
      state = stateApi.apply(state, 'request-sources', { id: form.dataset.id, value: data.get('sources') });
    } else if (form.dataset.form === 'terminal') {
      const command = String(data.get('command') || '').trim();
      const output = form.parentElement.querySelector('[data-terminal-output]');
      const selectedWorkstation = state.workstations.find((item) => item.id === state.selectedId) || state.workstations[0];
      const response = stateApi.terminalResponse(command, selectedWorkstation?.sshUser);
      if (command === 'clear') output.textContent = 'Simulated TELIPHONES console · no SSH connection';
      else output.textContent += `\n$ ${command}\n${response}`;
      form.reset();
      return;
    }
    persistAndRender();
  });

  window.addEventListener('storage', (event) => {
    if (event.key === stateApi.KEY || event.key === null) {
      state = stateApi.safeLoad(storage);
      render();
    }
  });
  render();
})();

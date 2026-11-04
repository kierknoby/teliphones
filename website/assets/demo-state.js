(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.TeliphonesDemoState = api;
})(typeof globalThis === 'object' ? globalThis : this, function () {
  'use strict';
  const KEY = 'teliphones-demo-v1';

  function initialState() {
    return {
      policy: 'open',
      maximum: 1,
      workstations: [],
      pending: null,
      sshRequest: null,
      sourceRequest: null,
      unlockRequest: null,
      bans: ['198.51.100.44'],
      notice: 'Choose a demonstration action to begin.',
      nextId: 1,
      selectedId: null,
      newPairing: false,
      passwordProtected: false
    };
  }

  function validDemoState(state) {
    if (!['open', 'closed', 'frozen'].includes(state.policy) ||
        !Number.isInteger(state.maximum) || state.maximum < 1 || state.maximum > 5 ||
        !Number.isInteger(state.nextId) || state.nextId < 1 ||
        !Array.isArray(state.workstations) || state.workstations.length > 100 ||
        !Array.isArray(state.bans) || state.bans.length > 100 ||
        typeof state.notice !== 'string' || state.notice.length > 500 ||
        typeof state.newPairing !== 'boolean' || typeof state.passwordProtected !== 'boolean') return false;

    const ids = new Set();
    for (const workstation of state.workstations) {
      if (!workstation || typeof workstation.id !== 'string' || !/^WS-\d{3,}$/.test(workstation.id) ||
          ids.has(workstation.id) || typeof workstation.name !== 'string' || !workstation.name ||
          workstation.name.length > 40 || !['web', 'ssh'].includes(workstation.access) ||
          typeof workstation.locked !== 'boolean' || typeof workstation.connected !== 'boolean' ||
          workstation.authorized !== true || typeof workstation.ssh !== 'boolean' ||
          typeof workstation.sshUser !== 'string' || typeof workstation.sources !== 'string' ||
          !validSourceList(workstation.sources) || typeof workstation.currentSource !== 'string' ||
          !parseIp(workstation.currentSource) ||
          (workstation.ssh && !['pbxadmin', 'operator', 'maint'].includes(workstation.sshUser)) ||
          (workstation.access === 'ssh' && !workstation.ssh)) return false;
      ids.add(workstation.id);
      if (workstation.connected &&
          (state.policy === 'closed' ||
           state.bans.some((source) => sourceMatches(source, workstation.currentSource)) ||
           (workstation.locked && !workstation.sources.split(',').map((source) => source.trim())
             .some((source) => sourceMatches(source, workstation.currentSource))))) return false;
    }

    if (state.workstations.some((item) => Number(item.id.slice(3)) >= state.nextId) ||
        state.workstations.filter((item) => item.connected).length > state.maximum ||
        (state.selectedId !== null && (!ids.has(state.selectedId) || typeof state.selectedId !== 'string'))) return false;
    if (!Array.isArray(state.bans) || state.bans.some((source) =>
      typeof source !== 'string' || !validSource(source) || !parseIp(source.split('/')[0]))) return false;

    if (state.pending !== null &&
        (!state.pending || typeof state.pending.name !== 'string' || !state.pending.name ||
         state.pending.name.length > 40 || !['web', 'ssh'].includes(state.pending.access) ||
         typeof state.pending.locked !== 'boolean' || typeof state.pending.sources !== 'string' ||
         !validSourceList(state.pending.sources) || !Number.isFinite(state.pending.requestedAt))) return false;
    if (state.sshRequest !== null &&
        (!state.sshRequest || !ids.has(state.sshRequest.id) ||
         !['', 'pbxadmin', 'operator', 'maint'].includes(state.sshRequest.account))) return false;
    if (state.sourceRequest !== null &&
        (!state.sourceRequest || !ids.has(state.sourceRequest.id) ||
         typeof state.sourceRequest.sources !== 'string' || !validSourceList(state.sourceRequest.sources))) return false;
    if (state.unlockRequest !== null &&
        (!state.unlockRequest || !ids.has(state.unlockRequest.id))) return false;
    return true;
  }

  function safeLoad(storage) {
    try {
      const saved = storage.getItem(KEY);
      if (!saved) return initialState();
      const parsed = JSON.parse(saved);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return initialState();
      const state = { ...initialState(), ...parsed };
      if (validDemoState(state)) return state;
      const reset = initialState();
      reset.notice = 'Invalid saved demonstration data was reset.';
      return reset;
    } catch (_) {
      const state = initialState();
      state.notice = 'Browser storage could not be read; the demonstration is using temporary state.';
      return state;
    }
  }

  function save(storage, state) {
    storage.setItem(KEY, JSON.stringify(state));
  }

  function occupancy(state) {
    return state.workstations.filter((workstation) => workstation.connected).length;
  }

  function parseIp(value) {
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
      const octets = value.split('.').map(Number);
      if (octets.some((octet) => octet > 255)) return null;
      return { bits: 32, value: octets.reduce((result, octet) => (result << 8n) | BigInt(octet), 0n) };
    }
    if (!value.includes(':') || value.includes('.')) return null;
    const halves = value.toLowerCase().split('::');
    if (halves.length > 2) return null;
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    const missing = 8 - left.length - right.length;
    if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
    const groups = halves.length === 1 ? left : left.concat(Array(missing).fill('0'), right);
    if (groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;
    return { bits: 128, value: groups.reduce((result, group) => (result << 16n) | BigInt(`0x${group}`), 0n) };
  }

  function validSource(value) {
    const pieces = value.split('/');
    if (pieces.length > 2 || !pieces[0]) return false;
    const ip = parseIp(pieces[0]);
    if (ip) return pieces.length === 1 || (/^\d+$/.test(pieces[1]) && Number(pieces[1]) <= ip.bits);
    if (pieces.length !== 1 || value.length > 253) return false;
    return value.split('.').length > 1 && value.split('.').every((label) =>
      label.length <= 63 && /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label));
  }

  function sourceMatches(entry, currentSource) {
    if (entry === 'office.example.test') return currentSource === '203.0.113.24';
    const [address, prefixText] = entry.split('/');
    const source = parseIp(currentSource);
    const restriction = parseIp(address);
    if (!source || !restriction || source.bits !== restriction.bits) return false;
    const prefix = prefixText === undefined ? source.bits : Number(prefixText);
    return (source.value >> BigInt(source.bits - prefix)) ===
      (restriction.value >> BigInt(restriction.bits - prefix));
  }

  function validSourceList(value) {
    const entries = value.split(',').map((item) => item.trim()).filter(Boolean);
    return entries.length > 0 && entries.length <= 8 && entries.every(validSource);
  }

  function terminalResponse(command, user) {
    const responses = {
      help: 'Safe demo commands: help, whoami, hostname, pwd, ls, uptime, clear',
      whoami: String(user || 'approved account'),
      hostname: 'demo-pbx',
      pwd: `/home/${String(user || 'operator')}`,
      ls: 'admin/  recordings/  backups/  (synthetic names)',
      uptime: 'up 12 days, 4 hours (simulated)'
    };
    if (command === 'clear') return '';
    return Object.prototype.hasOwnProperty.call(responses, command)
      ? responses[command] : 'Command not available in the safe demonstration. Try help.';
  }

  function apply(state, action, payload) {
    const data = payload || {};
    let message = '';
    switch (action) {
      case 'policy':
        if (!['open', 'closed', 'frozen'].includes(data.value)) return state;
        state.policy = data.value;
        if (state.policy === 'closed') state.workstations.forEach((workstation) => { workstation.connected = false; });
        message = state.policy === 'closed' ? 'Policy Closed: sample sessions disconnected.' : `Policy ${state.policy[0].toUpperCase()}${state.policy.slice(1)} applied.`;
        break;
      case 'maximum': {
        const maximum = Number(data.value);
        if (!Number.isInteger(maximum) || maximum < 1 || maximum > 5 || occupancy(state) > maximum) {
          message = 'Limit not changed: disconnect sessions before lowering capacity below current occupancy.';
          break;
        }
        state.maximum = maximum;
        message = `Maximum simultaneous sessions set to ${maximum}.`;
        break;
      }
      case 'request-pair':
        if (state.policy !== 'open') message = `Pairing unavailable while policy is ${state.policy}.`;
        else if (state.pending) message = 'A sample pairing request is already awaiting review.';
        else if (data.locked && !validSourceList(String(data.sources || '203.0.113.24'))) message = 'Enter one to eight valid IPv4, IPv6, CIDR or DNS sources before requesting a locked pairing.';
        else {
          state.pending = { name: String(data.name || 'Desk workstation').slice(0, 40), access: data.access === 'ssh' ? 'ssh' : 'web', locked: Boolean(data.locked), sources: String(data.sources || '203.0.113.24').slice(0, 160), requestedAt: Date.now() };
          state.newPairing = false;
          message = 'Pairing request sent to the sample FreePBX module.';
        }
        break;
      case 'approve-pair':
        if (!state.pending || state.policy !== 'open') message = 'No approvable request; Open policy is required.';
        else if (state.pending.access === 'ssh' && !['pbxadmin', 'operator', 'maint'].includes(data.account)) message = 'Select an existing Linux account before approving SSH access.';
        else {
          const workstation = { id: `WS-${String(state.nextId++).padStart(3, '0')}`, name: state.pending.name, access: state.pending.access, locked: state.pending.locked, sources: state.pending.sources, connected: false, authorized: true, ssh: state.pending.access === 'ssh', sshUser: state.pending.access === 'ssh' ? data.account : '', currentSource: '203.0.113.24' };
          state.workstations.push(workstation);
          state.selectedId = workstation.id;
          state.pending = null;
          message = 'Pairing approved. The workstation retains its identity and is available to connect.';
        }
        break;
      case 'reject-pair':
        state.pending = null;
        message = 'Pairing request rejected; no workstation access was added.';
        break;
      case 'connect': {
        const workstation = state.workstations.find((item) => item.id === data.id);
        if (!workstation) message = 'No approved workstation is selected.';
        else if (state.policy === 'closed') message = 'Connection rejected: PBX policy is Closed.';
        else if (state.bans.some((source) => sourceMatches(source, workstation.currentSource))) message = 'Connection rejected: the PBX Banned List blocks this public source.';
        else if (workstation.locked && !workstation.sources.split(',').map((item) => item.trim()).some((source) => sourceMatches(source, workstation.currentSource))) message = 'Connection rejected: this public source is not on the workstation Allowed List.';
        else if (!workstation.connected && occupancy(state) >= state.maximum) message = `Connection rejected: all ${state.maximum} session slot(s) are occupied.`;
        else {
          workstation.connected = true;
          message = `${workstation.name} connected and admitted (${occupancy(state)}/${state.maximum}).`;
        }
        break;
      }
      case 'disconnect': {
        const workstation = state.workstations.find((item) => item.id === data.id);
        if (workstation) workstation.connected = false;
        message = 'Sample session disconnected; its capacity slot is released.';
        break;
      }
      case 'revoke':
        state.workstations = state.workstations.filter((item) => item.id !== data.id);
        if (state.selectedId === data.id) state.selectedId = state.workstations[0]?.id || null;
        if (state.sshRequest && state.sshRequest.id === data.id) state.sshRequest = null;
        if (state.sourceRequest && state.sourceRequest.id === data.id) state.sourceRequest = null;
        if (state.unlockRequest && state.unlockRequest.id === data.id) state.unlockRequest = null;
        message = 'Workstation revoked. Its sample session and permissions are removed.';
        break;
      case 'select-workstation':
        if (state.workstations.some((item) => item.id === data.id)) state.selectedId = data.id;
        break;
      case 'new-pairing':
        state.newPairing = true;
        message = 'Create another synthetic workstation request.';
        break;
      case 'lock-current': {
        const workstation = state.workstations.find((item) => item.id === data.id);
        if (workstation && !workstation.connected) message = 'Connect and obtain PBX admission before locking to the verified current source.';
        else if (workstation) {
          workstation.locked = true;
          workstation.sources = workstation.currentSource;
          message = 'Locked to the PBX-verified current public source.';
        }
        break;
      }
      case 'sources': {
        const workstation = state.workstations.find((item) => item.id === data.id);
        const sources = String(data.value || '').split(',').map((item) => item.trim()).filter(Boolean);
        if (workstation && validSourceList(sources.join(','))) {
          workstation.sources = sources.join(', ');
          workstation.locked = true;
          if (workstation.connected && !sources.some((source) => sourceMatches(source, workstation.currentSource))) workstation.connected = false;
          message = 'Allowed List updated in the demonstration.';
        } else message = 'Enter one to eight comma-separated IPv4, IPv6, CIDR or DNS entries.';
        break;
      }
      case 'request-sources': {
        const workstation = state.workstations.find((item) => item.id === data.id);
        const sources = String(data.value || '').split(',').map((item) => item.trim()).filter(Boolean);
        if (!workstation || !workstation.connected) message = 'Connect and obtain PBX admission before requesting a source change.';
        else if (state.sourceRequest) message = 'A source-list change is already Pending Approval.';
        else if (validSourceList(sources.join(','))) {
          state.sourceRequest = { id: workstation.id, sources: sources.join(', ') };
          message = 'Allowed List change is Pending Approval; current restrictions remain applied.';
        } else message = 'Enter one to eight comma-separated IPv4, IPv6, CIDR or DNS entries.';
        break;
      }
      case 'approve-sources':
        if (state.sourceRequest) {
          const workstation = state.workstations.find((item) => item.id === state.sourceRequest.id);
          if (workstation) {
            workstation.sources = state.sourceRequest.sources;
            workstation.locked = true;
            if (workstation.connected && !workstation.sources.split(',').some((source) => sourceMatches(source, workstation.currentSource))) workstation.connected = false;
          }
          state.sourceRequest = null;
          message = 'Allowed List change approved and applied.';
        }
        break;
      case 'reject-sources':
        state.sourceRequest = null;
        message = 'Allowed List change rejected; the existing restrictions remain applied.';
        break;
      case 'request-unlock': {
        const workstation = state.workstations.find((item) => item.id === data.id);
        if (!workstation || !workstation.connected) message = 'Connect and obtain PBX admission before requesting an unlock.';
        else if (state.unlockRequest) message = 'An unlock request is already Pending Approval.';
        else if (workstation.locked) {
          state.unlockRequest = { id: workstation.id };
          message = 'Unlock request is Pending Approval; current restrictions remain applied.';
        }
        break;
      }
      case 'approve-unlock':
        if (state.unlockRequest) {
          const workstation = state.workstations.find((item) => item.id === state.unlockRequest.id);
          if (workstation) workstation.locked = false;
          state.unlockRequest = null;
          message = 'Unlock approved. The administrator-controlled restrictions were relaxed.';
        }
        break;
      case 'reject-unlock':
        state.unlockRequest = null;
        message = 'Unlock request rejected; the existing source restrictions remain applied.';
        break;
      case 'request-ssh': {
        const workstation = state.workstations.find((item) => item.id === data.id);
        if (workstation && workstation.connected && !workstation.ssh) {
          state.sshRequest = { id: workstation.id, account: '' };
          message = 'SSH access requested; it is Pending Approval.';
        } else message = 'Connect to an admitted session before requesting SSH, or SSH is already authorised.';
        break;
      }
      case 'approve-ssh':
        if (state.sshRequest && !['pbxadmin', 'operator', 'maint'].includes(data.account || state.sshRequest.account)) {
          message = 'Select an existing Linux account before approving SSH access.';
        } else if (state.sshRequest) {
          const workstation = state.workstations.find((item) => item.id === state.sshRequest.id);
          if (workstation) {
            workstation.ssh = true;
            workstation.sshUser = String(data.account || state.sshRequest.account);
          }
          state.sshRequest = null;
          message = 'SSH elevation approved for the selected existing Linux account.';
        }
        break;
      case 'reject-ssh':
        state.sshRequest = null;
        message = 'SSH elevation rejected; existing web access is unchanged.';
        break;
      case 'ssh-account':
        if (state.sshRequest && ['pbxadmin', 'operator', 'maint'].includes(data.value)) {
          state.sshRequest.account = data.value;
          message = `Existing Linux account ${data.value} selected for administrator review.`;
        }
        break;
      case 'ban-add': {
        const source = String(data.value || '').trim();
        if (validSource(source) && parseIp(source.split('/')[0]) && !state.bans.includes(source)) {
          state.bans.push(source);
          state.workstations.forEach((workstation) => {
            if (sourceMatches(source, workstation.currentSource)) workstation.connected = false;
          });
          message = 'Sample listener ban applied; matching sample sessions were disconnected.';
        } else message = 'Enter a valid IPv4, IPv6 or CIDR address for the Banned List.';
        break;
      }
      case 'ban-remove':
        state.bans = state.bans.filter((source) => source !== data.value);
        message = 'Sample listener ban removed.';
        break;
      case 'reset':
        return initialState();
      default:
        return state;
    }
    state.notice = message || state.notice;
    return state;
  }

  return { KEY, initialState, safeLoad, save, occupancy, terminalResponse, apply };
});

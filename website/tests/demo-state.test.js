'use strict';

const assert = require('node:assert/strict');
const demo = require('../assets/demo-state.js');

const storage = {
  value: null,
  getItem(key) { assert.equal(key, demo.KEY); return this.value; },
  setItem(key, value) { assert.equal(key, demo.KEY); this.value = value; }
};

let state = demo.safeLoad(storage);
assert.equal(state.policy, 'open');
assert.equal(state.maximum, 1);
state = demo.apply(state, 'policy', { value: 'closed' });
state = demo.apply(state, 'request-pair', { name: 'Blocked pair', access: 'web' });
assert.equal(state.pending, null, 'Closed policy does not create a pairing request');
state = demo.apply(state, 'request-pair', { name: 'Desk 1', access: 'web', locked: true });
assert.equal(state.pending, null, 'Closed policy rejects pairing');
state = demo.apply(state, 'policy', { value: 'open' });
state = demo.apply(state, 'request-pair', { name: 'Desk 1', access: 'web', locked: true });
assert.ok(state.pending);
state = demo.apply(state, 'approve-pair');
const first = state.workstations[0];
assert.equal(first.ssh, false);
assert.equal(state.pending, null);
state = demo.apply(state, 'connect', { id: first.id });
assert.equal(demo.occupancy(state), 1);
state = demo.apply(state, 'request-pair', { name: 'Desk 2', access: 'ssh' });
state = demo.apply(state, 'approve-pair', { account: 'operator' });
const second = state.workstations[1];
state = demo.apply(state, 'connect', { id: second.id });
assert.equal(demo.occupancy(state), 1);
assert.match(state.notice, /all 1 session slot/);
state = demo.apply(state, 'maximum', { value: 0 });
assert.equal(state.maximum, 1, 'invalid session limits do not change capacity');
state = demo.apply(state, 'maximum', { value: 6 });
assert.equal(state.maximum, 1, 'capacity cannot exceed the controls shown in the demo');
state = demo.apply(state, 'disconnect', { id: first.id });
state = demo.apply(state, 'connect', { id: first.id });
state = demo.apply(state, 'request-ssh', { id: first.id });
assert.equal(state.sshRequest.id, first.id);
assert.equal(state.sshRequest.account, '', 'the administrator must explicitly select an existing account');
state = demo.apply(state, 'reject-ssh');
assert.equal(state.workstations[0].authorized, true);
assert.equal(state.workstations[0].ssh, false);
state = demo.apply(state, 'request-ssh', { id: first.id });
state = demo.apply(state, 'approve-ssh');
assert.equal(state.sshRequest.id, first.id, 'SSH approval without an account remains pending');
state = demo.apply(state, 'ssh-account', { value: 'operator' });
state = demo.apply(state, 'approve-ssh');
assert.equal(state.workstations[0].sshUser, 'operator');
assert.equal(state.workstations[0].ssh, true);
state = demo.apply(state, 'disconnect', { id: first.id });
state = demo.apply(state, 'connect', { id: second.id });
state = demo.apply(state, 'policy', { value: 'frozen' });
state = demo.apply(state, 'request-pair', { name: 'Frozen pairing', access: 'web' });
assert.equal(state.pending, null, 'Frozen policy pauses pairing');
state = demo.apply(state, 'connect', { id: second.id });
assert.ok(state.workstations[1].connected, 'Frozen policy preserves existing approved workstations');
state = demo.apply(state, 'policy', { value: 'closed' });
assert.equal(demo.occupancy(state), 0);
state = demo.apply(state, 'policy', { value: 'open' });
state = demo.apply(state, 'connect', { id: first.id });
state = demo.apply(state, 'lock-current', { id: first.id });
assert.equal(state.workstations[0].sources, '203.0.113.24');
state = demo.apply(state, 'request-unlock', { id: first.id });
assert.equal(state.unlockRequest.id, first.id);
state = demo.apply(state, 'reject-unlock');
assert.equal(state.workstations[0].locked, true, 'rejected unlock retains source enforcement');
state = demo.apply(state, 'request-unlock', { id: first.id });
state = demo.apply(state, 'approve-unlock');
assert.equal(state.workstations[0].locked, false);
state = demo.apply(state, 'lock-current', { id: first.id });
state = demo.apply(state, 'request-sources', { id: first.id, value: '198.51.100.10' });
assert.equal(state.workstations[0].sources, '203.0.113.24', 'source relaxation remains pending approval');
state = demo.apply(state, 'approve-sources');
assert.equal(state.workstations[0].sources, '198.51.100.10');
assert.equal(state.workstations[0].connected, false, 'a restriction change that excludes the current source drops that session');
state = demo.apply(state, 'disconnect', { id: first.id });
state = demo.apply(state, 'connect', { id: first.id });
assert.match(state.notice, /not on the workstation Allowed List/);
state = demo.apply(state, 'sources', { id: first.id, value: '203.0.113.0/24' });
state = demo.apply(state, 'connect', { id: first.id });
assert.equal(state.workstations[0].connected, true, 'an IPv4 CIDR containing the verified source is permitted');
state = demo.apply(state, 'sources', { id: first.id, value: 'office.example.test' });
assert.equal(state.workstations[0].connected, true, 'the documented synthetic DNS record resolves to the sample source');
state = demo.apply(state, 'sources', { id: first.id, value: '2001:db8::/32' });
assert.equal(state.workstations[0].connected, false, 'a valid IPv6 restriction that excludes the source disconnects');
state = demo.apply(state, 'connect', { id: first.id });
assert.match(state.notice, /not on the workstation Allowed List/);
state = demo.apply(state, 'sources', { id: second.id, value: '203.0.113.24' });
state = demo.apply(state, 'ban-add', { value: '203.0.113.0/24' });
state = demo.apply(state, 'connect', { id: second.id });
assert.match(state.notice, /Banned List blocks/);
assert.equal(state.workstations[0].connected, false, 'adding an applicable ban disconnects any active matching session');
assert.equal(state.workstations[1].connected, false, 'adding an applicable ban disconnects every matching session');
state = demo.apply(state, 'ban-remove', { value: '203.0.113.0/24' });
assert.equal(state.bans.includes('203.0.113.0/24'), false);
state = demo.apply(state, 'revoke', { id: first.id });
assert.equal(state.workstations.some((item) => item.id === first.id), false);
demo.save(storage, state);
assert.equal(demo.safeLoad(storage).workstations.length, 1);
assert.equal(demo.apply(state, 'reset').workstations.length, 0);
assert.equal(demo.terminalResponse('whoami', 'operator'), 'operator');
assert.equal(demo.terminalResponse('hostname'), 'demo-pbx');
assert.match(demo.terminalResponse('cat /etc/shadow'), /not available/);
assert.equal(demo.terminalResponse('clear'), '');
assert.match(demo.terminalResponse('`whoami`'), /not available/, 'command text is not interpreted');
assert.match(demo.terminalResponse('constructor'), /not available/, 'inherited object properties are not commands');
storage.value = '{"policy":"unexpected","maximum":999,"workstations":[]}';
assert.equal(demo.safeLoad(storage).policy, 'open', 'invalid persisted demo state resets safely');
assert.match(demo.safeLoad(storage).notice, /Invalid saved demonstration data was reset/);
assert.match(demo.safeLoad({ getItem() { throw new Error('storage disabled'); } }).notice,
  /Browser storage could not be read/, 'unavailable browser storage is surfaced');
storage.value = JSON.stringify({ ...demo.initialState(), workstations: [null] });
assert.equal(demo.safeLoad(storage).workstations.length, 0, 'malformed workstation records reset safely');
storage.value = JSON.stringify({
  ...demo.initialState(),
  workstations: ['WS-001', 'WS-002'].map((id) => ({
    id, name: 'Forged', access: 'web', locked: false, sources: '203.0.113.24',
    connected: true, authorized: true, ssh: false, sshUser: '', currentSource: '203.0.113.24'
  })),
  selectedId: 'WS-001',
  nextId: 3,
  maximum: 1
});
assert.equal(demo.safeLoad(storage).workstations.length, 0, 'forged saved sessions do not bypass admission capacity');

console.log('Interactive demo state tests passed.');

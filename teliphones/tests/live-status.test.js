'use strict';
// Behavioural tests for assets/js/teliphones.js (polling state machine). Run: node tests/live-status.test.js
const assert = require('assert');
const path = require('path');
const live = require(path.join(__dirname, '..', 'assets', 'js', 'teliphones.js'));

const tick = () => new Promise((resolve) => setImmediate(resolve));

function status(overrides) {
    return Object.assign({
        available: true, condition: 'operational', phase: 'Missing dependency', enabled: true, can_authorise: false,
        readiness: { 'WireGuard wg': false, 'Gateway enrollment': true }, session: [], access_verified: false,
        engineer: null, challenge: null, operation: null, server_time: 1000, error: null, broker_current: true
    }, overrides || {});
}

function operation(overrides) {
    return Object.assign({ id: 'op1', action: 'dependencies', label: 'Approve installation of WireGuard tools', state: 'running',
        stage: 'Installing WireGuard tools', message: '', started_at: 1000, finished_at: null }, overrides || {});
}

function harness(initial) {
    const h = { now: 0, timers: [], fetches: [], posts: [], events: [], renders: [] };
    h.view = {
        render: (s, controls) => h.renders.push({ status: s, controls }),
        result: (r) => h.events.push(['result', r]),
        started: (action, message) => h.events.push(['started', action, message]),
        slow: (v) => h.events.push(['slow', v]),
        temporary: (n) => h.events.push(['temporary', n]),
        paused: (v) => h.events.push(['paused', v]),
        unsupported: (a) => h.events.push(['unsupported', a]),
        authError: (m) => h.events.push(['auth', m])
    };
    const deferred = () => { let resolve; let reject; const promise = new Promise((r, j) => { resolve = r; reject = j; }); return { promise, resolve, reject }; };
    h.monitor = live.createMonitor({
        initial, labels: { dependencies: 'Approve installation of WireGuard tools', authorise: 'Authorise Remote Support' }, view: h.view,
        now: () => h.now,
        setTimer: (fn, ms) => { const t = { fn, ms, id: h.timers.length + 1, active: true }; h.timers.push(t); return t.id; },
        clearTimer: (id) => { const t = h.timers.find((x) => x.id === id); if (t) t.active = false; },
        fetchStatus: () => { const d = deferred(); h.fetches.push(d); return d.promise; },
        postAction: (action, payload) => { const d = deferred(); h.posts.push({ action, payload, d }); return d.promise; }
    });
    h.pending = () => h.timers.filter((t) => t.active);
    h.fire = () => {
        const active = h.pending();
        assert.strictEqual(active.length, 1, 'exactly one poll timer may be pending');
        active[0].active = false;
        h.now += active[0].ms;
        active[0].fn();
    };
    h.results = () => h.events.filter((e) => e[0] === 'result').map((e) => e[1]);
    h.last = () => h.renders[h.renders.length - 1];
    return h;
}

const tests = {
    async 'idle page does not poll'() {
        const h = harness(status());
        assert.strictEqual(h.pending().length, 0);
        assert.strictEqual(h.monitor.state().monitoring, false);
    },

    async 'unavailable broker never polls or submits'() {
        const h = harness({ available: false, condition: 'not_installed', operation: null, readiness: {} });
        assert.strictEqual(h.monitor.submit('dependencies', {}), false);
        assert.strictEqual(h.posts.length, 0);
        assert.strictEqual(h.pending().length, 0);
    },

    async 'queued operation is monitored every two seconds until verified success'() {
        const h = harness(status());
        assert.strictEqual(h.last().controls.dependencies.enabled, true);
        assert.strictEqual(h.monitor.submit('dependencies', { token: 't' }), true);
        assert.strictEqual(h.last().controls.dependencies.enabled, false, 'button disabled while submitting');
        assert.strictEqual(live.progress('dependencies', h.monitor.state().status, { dependencies: true }).text, 'Starting…');
        h.posts[0].d.resolve({ kind: 'ok', body: { notice: { ok: true, operation_id: 'op1' }, status: status({ operation: operation() }) } });
        await tick();
        assert.deepStrictEqual(h.events.find((e) => e[0] === 'started'), ['started', 'dependencies', live.STARTED_MESSAGE]);
        assert.strictEqual(live.STARTED_MESSAGE, 'TELIPHONES operation started. Monitoring progress automatically…');
        const cell = live.readinessCell('WireGuard wg', false, h.monitor.state().status);
        assert.deepStrictEqual(cell, { kind: 'busy', text: 'Installing WireGuard tools…' });
        assert.strictEqual(live.readinessCell('Gateway enrollment', true, h.monitor.state().status).kind, 'ok', 'other rows unaffected');
        assert.strictEqual(h.pending()[0].ms, 2000);
        h.fire();
        assert.strictEqual(h.fetches.length, 1);
        assert.strictEqual(h.pending().length, 0, 'no overlapping request while one is in flight');
        h.monitor.pollNow();
        assert.strictEqual(h.fetches.length, 1);
        h.fetches[0].resolve({ kind: 'ok', status: status({ server_time: 1002, operation: operation({ stage: 'Checking WireGuard tools' }) }) });
        await tick();
        assert.strictEqual(h.results().length, 0);
        h.fire();
        const done = status({ server_time: 1004, readiness: { 'WireGuard wg': true, 'Gateway enrollment': true },
            operation: operation({ state: 'succeeded', message: 'WireGuard tools installed and verified.', finished_at: 1004 }) });
        h.fetches[1].resolve({ kind: 'ok', status: done });
        await tick();
        assert.deepStrictEqual(h.results().map((r) => [r.id, r.state]), [['op1', 'succeeded']]);
        assert.deepStrictEqual(live.readinessCell('WireGuard wg', true, done), { kind: 'ok', text: '✓ Installed / configured (operation not yet verified)' });
        assert.strictEqual(h.monitor.state().monitoring, false, 'polling stops when finished');
        assert.strictEqual(h.pending().length, 0);
        assert.deepStrictEqual(h.last().controls.dependencies, { enabled: false, reason: 'installed' }, 'installed dependency cannot be reinstalled');
    },

    async 'success is not reported unless wg is verified'() {
        const h = harness(status({ operation: operation() }));
        h.fire();
        h.fetches[0].resolve({ kind: 'ok', status: status({ operation: operation({ state: 'succeeded', message: 'ok' }) }) });
        await tick();
        assert.strictEqual(h.results()[0].state, 'failed');
        assert.match(h.results()[0].message, /could not be verified/);
    },

    async 'failed operation is reported once and the action can be retried'() {
        const h = harness(status({ operation: operation() }));
        h.fire();
        const failed = status({ operation: operation({ state: 'failed', message: 'apt-get failed' }) });
        h.fetches[0].resolve({ kind: 'ok', status: failed });
        await tick();
        assert.deepStrictEqual(h.results().map((r) => [r.state, r.message, r.label]), [['failed', 'apt-get failed', 'Approve installation of WireGuard tools']]);
        assert.deepStrictEqual(live.readinessCell('WireGuard wg', false, failed), { kind: 'fail', text: '✕ Installation failed' });
        assert.strictEqual(h.last().controls.dependencies.enabled, true, 'retry is safe after failure');
        assert.strictEqual(h.pending().length, 0);
    },

    async 'duplicate submissions are prevented'() {
        const h = harness(status({ can_authorise: true, readiness: { 'WireGuard wg': true } }));
        assert.strictEqual(h.monitor.submit('authorise', {}), true);
        assert.strictEqual(h.monitor.submit('authorise', {}), false);
        assert.strictEqual(h.posts.length, 1);
        h.posts[0].d.resolve({ kind: 'ok', body: { notice: { ok: true, operation_id: 'op2' },
            status: status({ can_authorise: true, operation: operation({ id: 'op2', action: 'authorise', stage: 'Provisioning WireGuard connection' }) }) } });
        await tick();
        for (const action of ['authorise', 'dependencies', 'evidence', 'configure']) {
            assert.strictEqual(h.monitor.submit(action, {}), false, action + ' blocked while an operation runs');
        }
        assert.strictEqual(h.last().controls.revoke.enabled, true, 'revocation stays available during authorisation');
        assert.strictEqual(live.sessionPhase(h.monitor.state().status).kind, 'busy');
        assert.strictEqual(h.monitor.submit('revoke', {}), true);
        assert.strictEqual(h.monitor.submit('revoke', {}), false);
        assert.strictEqual(h.posts.length, 2);
        assert.strictEqual(h.monitor.submit('exec', {}), false);
    },

    async 'action response during an in-flight poll does not overlap requests'() {
        const h = harness(status({ operation: operation({ action: 'authorise', label: 'Authorise Remote Support' }) }));
        h.fire();
        assert.strictEqual(h.monitor.state().inflight, true);
        h.monitor.submit('revoke', {});
        h.posts[0].d.resolve({ kind: 'ok', body: { notice: { ok: true, operation_id: 'r1' }, status: status({ operation: operation({ id: 'r1', action: 'revoke' }) }) } });
        await tick();
        assert.strictEqual(h.pending().length, 0, 'no timer while a status request is in flight');
        h.fetches[0].resolve({ kind: 'ok', status: status({ operation: operation({ id: 'r1', action: 'revoke' }) }) });
        await tick();
        assert.strictEqual(h.pending().length, 1);
        assert.strictEqual(h.fetches.length, 1);
    },

    async 'refused action is shown as a failure without monitoring'() {
        const h = harness(status());
        h.monitor.submit('dependencies', {});
        h.posts[0].d.resolve({ kind: 'ok', body: { notice: { ok: false, operation: 'Approve installation of WireGuard tools', error: 'Another TELIPHONES operation is running.' }, status: status() } });
        await tick();
        assert.strictEqual(h.results()[0].state, 'failed');
        assert.strictEqual(h.results()[0].message, 'Another TELIPHONES operation is running.');
        assert.strictEqual(h.last().controls.dependencies.enabled, true, 'button restored');
        assert.strictEqual(h.pending().length, 0);
    },

    async 'accepted request without an operation id is not reported as refused'() {
        const h = harness(status());
        h.monitor.submit('dependencies', {});
        h.posts[0].d.resolve({ kind: 'ok', body: { notice: { ok: true, message: 'TELIPHONES operation queued. Refresh to monitor the result.' }, status: status() } });
        await tick();
        assert.strictEqual(h.results().length, 0);
        assert.deepStrictEqual(h.events.find((e) => e[0] === 'started'), ['started', 'dependencies', 'TELIPHONES operation queued. Refresh to monitor the result.']);
    },

    async 'outdated broker keeps ordinary form submission'() {
        const listeners = [];
        const element = (text) => ({ textContent: text, getAttribute: () => null, querySelector: () => null, querySelectorAll: () => [] });
        const documentStub = {
            getElementById: (id) => (id === 'teliphones-root' ? element('') : id === 'teliphones-initial-status'
                ? element(JSON.stringify(status({ broker_current: false }))) : null),
            addEventListener: (name) => listeners.push(name)
        };
        const windowStub = { fetch: () => { throw new Error('must not fetch'); }, addEventListener: (name) => listeners.push(name),
            setInterval: () => { throw new Error('must not start timers'); } };
        assert.strictEqual(live.bindDocument(documentStub, windowStub), null);
        assert.deepStrictEqual(listeners, []);
    },

    async 'slow operations show the continuing message'() {
        assert.strictEqual(live.SLOW_MESSAGE, 'This operation is taking longer than expected. TELIPHONES is continuing to check its status.');
        const h = harness(status({ operation: operation() }));
        assert.deepStrictEqual(h.events.filter((e) => e[0] === 'slow').pop(), ['slow', false]);
        h.fire();
        h.fetches[0].resolve({ kind: 'ok', status: status({ server_time: 1000 + live.SLOW_AFTER.dependencies + 1, operation: operation() }) });
        await tick();
        assert.deepStrictEqual(h.events.filter((e) => e[0] === 'slow').pop(), ['slow', true]);
        assert.strictEqual(h.monitor.state().monitoring, true, 'slow operations keep being checked');
        assert.strictEqual(h.results().length, 0, 'slow is not failure');
    },

    async 'temporary status failures back off and are not reported as operation failures'() {
        const h = harness(status({ operation: operation() }));
        const delays = [];
        for (let i = 0; i < 5; i += 1) {
            h.fire();
            h.fetches[i].resolve(i % 2 ? { kind: 'temporary' } : { kind: 'ok', status: { available: false } });
            await tick();
            delays.push(h.pending()[0].ms);
        }
        assert.deepStrictEqual(delays, [2000, 4000, 8000, 10000, 10000]);
        assert.deepStrictEqual(h.events.filter((e) => e[0] === 'temporary').pop(), ['temporary', 5]);
        assert.strictEqual(h.results().length, 0);
        h.fire();
        h.fetches[5].resolve({ kind: 'ok', status: status({ operation: operation() }) });
        await tick();
        assert.deepStrictEqual(h.events.filter((e) => e[0] === 'temporary').pop(), ['temporary', 0]);
        assert.strictEqual(h.pending()[0].ms, 2000);
    },

    async 'rejected status request is treated as temporary'() {
        const h = harness(status({ operation: operation() }));
        h.fire();
        h.fetches[0].reject(new Error('network'));
        await tick();
        assert.strictEqual(h.monitor.state().failures, 1);
        assert.strictEqual(h.monitor.state().inflight, false);
        assert.strictEqual(h.results().length, 0);
        assert.strictEqual(h.pending().length, 1, 'retry scheduled');
    },

    async 'authorisation failure stops polling'() {
        const h = harness(status({ operation: operation() }));
        h.fire();
        h.fetches[0].resolve({ kind: 'auth', error: 'TELIPHONES permission denied' });
        await tick();
        assert.deepStrictEqual(h.events.pop(), ['auth', 'TELIPHONES permission denied']);
        assert.strictEqual(h.monitor.state().stopped, true);
        assert.strictEqual(h.pending().length, 0);
        assert.strictEqual(h.monitor.submit('revoke', {}), false);
    },

    async 'missing endpoint falls back without polling forever'() {
        const h = harness(status({ operation: operation() }));
        h.fire();
        h.fetches[0].resolve({ kind: 'unsupported' });
        await tick();
        assert.strictEqual(h.monitor.state().monitoring, false);
        assert.strictEqual(h.pending().length, 0);
        const h2 = harness(status());
        h2.monitor.submit('dependencies', {});
        h2.posts[0].d.resolve({ kind: 'unsupported' });
        await tick();
        assert.deepStrictEqual(h2.events.pop(), ['unsupported', 'dependencies'], 'action falls back to the ordinary form POST');
    },

    async 'lost action response is resolved by status, not assumed failed'() {
        const h = harness(status());
        h.monitor.submit('dependencies', {});
        h.posts[0].d.resolve({ kind: 'temporary' });
        await tick();
        assert.strictEqual(h.results().length, 0);
        assert.strictEqual(h.monitor.state().monitoring, true);
        h.fire();
        h.fetches[0].resolve({ kind: 'ok', status: status({ operation: operation({ id: 'op9' }) }) });
        await tick();
        assert.deepStrictEqual(h.monitor.state().watching, ['op9'], 'operation discovered from status');
    },

    async 'monitoring resumes after navigation and stops on unload'() {
        const h = harness(status({ operation: operation({ action: 'configure', label: 'Save secure gateway enrollment', stage: 'Validating gateway enrollment' }) }));
        assert.strictEqual(h.monitor.state().monitoring, true, 'running operation detected on load');
        assert.strictEqual(live.readinessCell('Gateway enrollment', true, h.monitor.state().status).kind, 'busy');
        assert.strictEqual(h.pending().length, 1);
        h.monitor.stop();
        assert.strictEqual(h.pending().length, 0);
        assert.strictEqual(h.monitor.state().stopped, true);
        h.monitor.resume();
        assert.strictEqual(h.pending().length, 0, 'stopped monitor stays stopped');
    },

    async 'background cleanup after expiry is monitored and confirmed'() {
        const h = harness(status({ phase: 'Revoking expired session', session: { session_id: 's1', state: 'revoking' } }));
        assert.strictEqual(h.monitor.state().monitoring, true);
        assert.strictEqual(live.sessionPhase(h.monitor.state().status).kind, 'busy');
        assert.strictEqual(h.last().controls.revoke.enabled, true, 'revocation remains available during cleanup');
        h.fire();
        h.fetches[0].resolve({ kind: 'ok', status: status({ phase: 'Not configured' }) });
        await tick();
        assert.deepStrictEqual(h.results().map((r) => [r.action, r.state]), [['cleanup', 'succeeded']]);
        assert.strictEqual(h.monitor.state().monitoring, false);
    },

    async 'quarantined cleanup is reported as failed'() {
        const h = harness(status({ phase: 'Revoking expired session' }));
        h.fire();
        h.fetches[0].resolve({ kind: 'ok', status: status({ phase: 'Cleanup failed; quarantined' }) });
        await tick();
        assert.strictEqual(h.results()[0].state, 'failed');
    },

    async 'revocation supersedes a running operation'() {
        const h = harness(status({ operation: operation({ id: 'a1', action: 'authorise', label: 'Authorise Remote Support' }) }));
        h.monitor.submit('revoke', {});
        h.posts[0].d.resolve({ kind: 'ok', body: { notice: { ok: true, operation_id: 'r1' },
            status: status({ operation: operation({ id: 'r1', action: 'revoke', label: 'Revoke Remote Support', stage: 'Cancelling the running operation' }) }) } });
        await tick();
        assert.deepStrictEqual(h.results().map((r) => [r.id, r.state]), [['a1', 'cancelled']]);
        h.fire();
        h.fetches[0].resolve({ kind: 'ok', status: status({ operation: operation({ id: 'r1', action: 'revoke', label: 'Revoke Remote Support', state: 'failed', message: 'Cleanup failed; quarantined.' }) }) });
        await tick();
        assert.deepStrictEqual(h.results().map((r) => [r.id, r.state]), [['a1', 'cancelled'], ['r1', 'failed']], 'failed revocation never reported as success');
    },

    async 'monitoring pauses after the cap and can be resumed'() {
        const h = harness(status({ operation: operation() }));
        h.now = live.MAX_MONITOR_MS + 1;
        h.fire();
        h.fetches[0].resolve({ kind: 'ok', status: status({ operation: operation() }) });
        await tick();
        assert.deepStrictEqual(h.events.filter((e) => e[0] === 'paused').pop(), ['paused', true]);
        assert.strictEqual(h.pending().length, 0);
        h.monitor.resume();
        assert.deepStrictEqual(h.events.filter((e) => e[0] === 'paused').pop(), ['paused', false]);
        assert.strictEqual(h.pending().length, 1);
    },

    async 'hidden page suspends timers and resumes immediately when visible'() {
        const h = harness(status({ operation: operation() }));
        h.monitor.setHidden(true);
        assert.strictEqual(h.pending().length, 0);
        h.monitor.setHidden(false);
        assert.strictEqual(h.pending()[0].ms, 0);
    },

    async 'response classification'() {
        assert.strictEqual(live.classify(403, '{}').kind, 'auth');
        assert.strictEqual(live.classify(200, JSON.stringify({ teliphones_api: 1, auth_error: true, error: 'x' })).kind, 'auth');
        assert.strictEqual(live.classify(200, '<html>login</html>').kind, 'unsupported');
        assert.strictEqual(live.classify(404, '').kind, 'unsupported');
        assert.strictEqual(live.classify(502, '').kind, 'temporary');
        assert.strictEqual(live.classify(200, JSON.stringify({ teliphones_api: 1, ok: true, status: { available: true } })).kind, 'ok');
        assert.strictEqual(live.classify(200, JSON.stringify({ result: { teliphones_api: 1, ok: true, status: {} } })).kind, 'ok', 'framework wrapper tolerated');
    }
};

(async () => {
    let failures = 0;
    for (const [name, test] of Object.entries(tests)) {
        try {
            await test();
        } catch (error) {
            failures += 1;
            console.error('FAIL: ' + name + '\n' + (error && error.stack));
        }
    }
    if (failures) {
        process.exit(1);
    }
    console.log('Live status JavaScript tests: PASS (' + Object.keys(tests).length + ' monitor scenarios: polling, completion, failure, duplicates, slow, temporary errors, cleanup, button state)');
})();

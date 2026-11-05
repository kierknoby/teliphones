'use strict';
const assert = require('assert');
const { execFileSync } = require('child_process');
const path = require('path');
const vm = require('vm');

function page(post = {}) {
    return JSON.parse(execFileSync(process.env.PHP_BINARY || 'php',
        [path.join(__dirname, 'pairing-page.php'), '', JSON.stringify(post)],
        { encoding: 'utf8', env: { ...process.env, XDEBUG_MODE: 'off' } }));
}

function form(javascript = true) {
    const rendered = page();
    const elements = new Map(rendered.elements.map(field => [field.id, {
        ...field, listeners: {},
        addEventListener(event, listener) { this.listeners[event] = listener; }
    }]));
    assert(rendered.script.includes('function updateRequest()'), 'Execute the actual template script');
    if (javascript) vm.runInNewContext(rendered.script, {
        document: { getElementById: id => elements.get(id) || null },
        window: { atob: value => Buffer.from(value, 'base64').toString('binary') }
    });
    return {
        elements,
        set(id, value, event = 'input') {
            const field = elements.get(id);
            field.value = value;
            if (javascript && field.listeners[event]) field.listeners[event]();
        },
        post() {
            const post = { action: 'pair', token: 'pair-test-token' };
            for (const field of elements.values()) {
                if (!field.name || field.disabled || field.fieldsetDisabled) continue;
                assert(!(field.name in post), `Multiple successful fields named ${field.name}`);
                post[field.name] = field.value;
            }
            return post;
        }
    };
}

const payload = { schema: 'teliphones-pair-request/1', workstation: 'ADMIN-PC',
    public_key: Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1)).toString('base64'),
    nonce: 'abcdefghijklmnopqrstuv' };
const encode = (value, version) => `TELIPHONES-PAIR-REQUEST-${version}:` +
    Buffer.from(JSON.stringify(value)).toString('base64url');
const request = encode(payload, 1);
const web = form();
web.set('teliphones-pair-request', request);
web.set('teliphones-pair-host', 'pbx.example.net');
web.set('teliphones-pair-mode', 'persistent');
web.set('teliphones-pair-minutes', '240');
const complete = web.post();
assert.strictEqual(web.elements.get('teliphones-pair-ssh').disabled, true);
assert.strictEqual(complete.ssh, '0', 'Disabled SSH approval must still submit explicit web-only access');
assert.strictEqual(complete.request, request, 'The Windows request must not be modified or cleared');
for (const name of ['request', 'endpoint_host', 'listen_port', 'mode', 'minutes', 'ssh', 'web', 'sources']) {
    assert.strictEqual(typeof complete[name], 'string', `${name} must be a successful form control`);
}

if (process.argv.includes('--post')) {
    process.stdout.write(JSON.stringify(complete));
} else {
    const response = page(complete);
    assert.strictEqual(response.calls, 3, 'Actual page path must probe status, dispatch pairing once, then refresh');
    assert.deepStrictEqual(response.sent[1],
        Object.fromEntries(Object.entries({ ...complete, progress: true }).filter(([key]) => key !== 'token')));
    assert.strictEqual(response.notice.ok, false, 'Modelled broker rejection must remain a failure');
    assert(!response.html.includes(request), 'Never redisplay pairing material');
    assert(!response.html.includes(payload.public_key));
    const retained = Object.fromEntries(response.elements.map(field => [field.name, field.value]));
    for (const name of ['endpoint_host', 'listen_port', 'mode', 'minutes', 'web', 'sources']) {
        assert.strictEqual(retained[name], complete[name], `${name} should survive a failed POST`);
    }
    assert(response.html.includes('paste the request again'));

    for (const [field, label] of Object.entries({ request: 'Windows pairing request',
        endpoint_host: 'PBX hostname', listen_port: 'WireGuard UDP port', mode: 'duration mode', ssh: 'SSH access choice' })) {
        for (const invalid of [undefined, '', ['not-text']]) {
            const post = { ...complete, [field]: invalid };
            const rejected = page(post);
            assert.strictEqual(rejected.calls, 1, `${field} must be rejected before pairing dispatch`);
            assert.strictEqual(rejected.notice.ok, false);
            assert(rejected.notice.error.includes(label));
            assert(!rejected.html.includes(request));
        }
    }
    for (const post of [{ ...complete, ssh: 'yes' }, { ...complete, mode: 'forever' }]) {
        assert.strictEqual(page(post).calls, 1, 'Invalid access/duration choices must not be dispatched');
    }
    const escaped = page({ ...complete, endpoint_host: '"><script>unsafe</script>', token: 'pair-test-token' });
    assert(!escaped.html.includes('value=""><script>unsafe</script>'));
    assert(escaped.html.includes('&quot;&gt;&lt;script&gt;unsafe&lt;/script&gt;'));
    const csrf = page({ ...complete, token: 'wrong-token', endpoint_host: 'untrusted.example.net' });
    assert.strictEqual(csrf.calls, 1);
    assert(!csrf.html.includes('untrusted.example.net'), 'Untrusted submissions must not be retained');

    const noScript = form(false);
    noScript.set('teliphones-pair-request', request);
    assert.strictEqual(noScript.post().ssh, '0', 'No-JavaScript submission remains explicitly web-only');
    const managed = form();
    managed.set('teliphones-pair-request', encode({ ...payload, schema: 'teliphones-pair-request/2',
        ssh_public_key: 'ssh-ed25519 ' + Buffer.concat([Buffer.from([0, 0, 0, 11]),
            Buffer.from('ssh-ed25519'), Buffer.from([0, 0, 0, 32]), Buffer.alloc(32, 1)]).toString('base64') }, 2));
    assert.strictEqual(managed.elements.get('teliphones-pair-web-only').disabled, true);
    assert.strictEqual(managed.post().ssh, '0', 'SSH-capable request does not grant SSH automatically');
    managed.set('teliphones-pair-ssh', '1', 'change');
    managed.set('teliphones-pair-ssh-user', 'administrator');
    assert.strictEqual(managed.post().ssh, '1');
    assert.strictEqual(managed.post().ssh_user, 'administrator');
    managed.set('teliphones-pair-request', 'malformed');
    assert.strictEqual(managed.post().ssh, '0');
    assert(!('ssh_user' in managed.post()), 'Losing SSH capability must remove account approval');
    console.log('Pairing form tests: PASS (actual page/template/JavaScript POST, explicit access, retained safe values, missing fields, CSRF)');
}

/* TELIPHONES live status monitor for Connectivity > TELIPHONES. No external dependencies. */
(function (root, factory) {
    'use strict';
    var api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined' && typeof document !== 'undefined') {
        // FreePBX may auto-load module assets in addition to the page's explicit tag.
        if (window.TeliphonesLive) {
            return;
        }
        window.TeliphonesLive = api;
        var boot = function () { api.bindDocument(document, window); };
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', boot);
        } else {
            boot();
        }
    }
}(this, function () {
    'use strict';

    var POLL_MS = 2000;
    var MAX_BACKOFF_MS = 10000;
    var MAX_MONITOR_MS = 15 * 60 * 1000;
    var REQUEST_TIMEOUT_MS = 10000;
    // Seconds after which an operation is reported as slow; no percentage is ever estimated.
    var SLOW_AFTER = { dependencies: 120, configure: 30, authorise: 120, evidence: 60, revoke: 45, cleanup: 90 };
    var SLOW_MESSAGE = 'This operation is taking longer than expected. TELIPHONES is continuing to check its status.';
    var STARTED_MESSAGE = 'TELIPHONES operation started. Monitoring progress automatically…';
    var ACTIONS = ['dependencies', 'authorise', 'revoke', 'evidence', 'configure'];
    var REASONS = {
        running: 'Another TELIPHONES operation is in progress.',
        installed: 'WireGuard tools are installed (wg executable detected by the broker).',
        session: 'Not available while a support session exists. Revoke it first.',
        'not-ready': 'Authorisation becomes available when every required component is ready and no session is active.',
        'no-challenge': '',
        broker: ''
    };
    var ENROLLMENT_COMPONENTS = ['Gateway enrollment', 'Checker trusted public key'];

    function isRunning(status) {
        return !!(status && status.operation && status.operation.state === 'running');
    }

    function isBackgroundCleanup(status) {
        return !!(status && status.available && !isRunning(status) && typeof status.phase === 'string' && status.phase.indexOf('Revoking') === 0);
    }

    function needsMonitoring(status) {
        return isRunning(status) || isBackgroundCleanup(status);
    }

    function hasSession(status) {
        return !!(status && status.session && typeof status.session === 'object' && Object.keys(status.session).length > 0);
    }

    function wireguardInstalled(status) {
        return !!(status && status.readiness && status.readiness['WireGuard wg'] === true);
    }

    function controls(status, submitting) {
        submitting = submitting || {};
        var available = !!(status && status.available);
        var busy = isRunning(status);
        var operation = busy ? status.operation : null;
        var installed = wireguardInstalled(status);
        var session = hasSession(status);
        var state = function (enabled, reason) { return { enabled: !!enabled, reason: enabled ? '' : reason }; };
        return {
            dependencies: state(available && !busy && !installed && !session && !submitting.dependencies,
                !available ? 'broker' : installed ? 'installed' : (busy || submitting.dependencies) ? 'running' : 'session'),
            authorise: state(available && !busy && status.can_authorise === true && !submitting.authorise,
                !available ? 'broker' : (busy || submitting.authorise) ? 'running' : 'not-ready'),
            revoke: state(available && !submitting.revoke && !(operation && operation.action === 'revoke'),
                !available ? 'broker' : 'running'),
            evidence: state(available && !busy && !!status.challenge && !submitting.evidence,
                !available ? 'broker' : (busy || submitting.evidence) ? 'running' : 'no-challenge'),
            configure: state(available && !busy && !session && !submitting.configure,
                !available ? 'broker' : (busy || submitting.configure) ? 'running' : 'session')
        };
    }

    function readinessCell(component, value, status) {
        var operation = status && status.operation;
        if (isRunning(status)) {
            if (operation.action === 'dependencies' && component === 'WireGuard wg') {
                return { kind: 'busy', text: (operation.stage || 'Installing WireGuard tools') + '…' };
            }
            if (operation.action === 'configure' && ENROLLMENT_COMPONENTS.indexOf(component) !== -1) {
                return { kind: 'busy', text: (operation.stage || 'Validating gateway enrollment') + '…' };
            }
        }
        if (value === true) {
            return { kind: 'ok', text: '✓ Installed / configured (operation not yet verified)' };
        }
        if (operation && operation.state === 'failed' && operation.action === 'dependencies' && component === 'WireGuard wg') {
            return { kind: 'fail', text: '✕ Installation failed' };
        }
        if (operation && operation.state === 'failed' && operation.action === 'configure' && ENROLLMENT_COMPONENTS.indexOf(component) !== -1) {
            return { kind: 'fail', text: '✕ Enrollment failed' };
        }
        return { kind: 'plain', text: 'Missing or unavailable' };
    }

    function sessionPhase(status) {
        if (!status || !status.available) {
            return { kind: 'plain', text: 'Not verified (broker unavailable)' };
        }
        var operation = status.operation;
        var phase = status.phase || 'Not configured';
        if (isRunning(status) && ['authorise', 'evidence', 'revoke'].indexOf(operation.action) !== -1) {
            return { kind: 'busy', text: phase + ': ' + (operation.stage || operation.label) + '…' };
        }
        if (isBackgroundCleanup(status)) {
            return { kind: 'busy', text: phase + ' — background cleanup in progress…' };
        }
        if (status.access_verified === true && phase === 'Connected') {
            return { kind: 'ok', text: '✓ ' + phase };
        }
        return { kind: /failed|quarantined/i.test(phase) ? 'fail' : 'plain', text: phase };
    }

    function progress(action, status, submitting) {
        if (submitting && submitting[action]) {
            return { kind: 'busy', text: 'Starting…' };
        }
        if (isRunning(status) && status.operation.action === action) {
            return { kind: 'busy', text: (status.operation.stage || status.operation.label) + '…' };
        }
        return { kind: 'hidden', text: '' };
    }

    /**
     * Polling state machine. deps: initial, labels, fetchStatus(), postAction(action, payload),
     * now(), setTimer(fn, ms), clearTimer(id), view (render, result, started, slow, temporary,
     * paused, unsupported, authError). Never overlaps status requests.
     */
    function createMonitor(deps) {
        var status = deps.initial;
        var labels = deps.labels || {};
        var timer = null;
        var inflight = false;
        var stopped = false;
        var hidden = false;
        var monitoring = false;
        var monitorSince = 0;
        var failures = 0;
        var cleanupSince = null;
        var watching = {};
        var submitting = {};
        var announced = {};

        function render() {
            deps.view.render(status, controls(status, submitting), submitting);
        }

        function clear() {
            if (timer !== null) {
                deps.clearTimer(timer);
                timer = null;
            }
        }

        function schedule(delay) {
            if (stopped || hidden || inflight || timer !== null || !monitoring) {
                return;
            }
            timer = deps.setTimer(function () {
                timer = null;
                poll();
            }, delay);
        }

        function startMonitoring() {
            if (stopped) {
                return;
            }
            if (!monitoring) {
                monitoring = true;
                monitorSince = deps.now();
                deps.view.paused(false);
            }
            schedule(POLL_MS);
        }

        function stopMonitoring() {
            monitoring = false;
            clear();
            deps.view.slow(false);
            deps.view.temporary(0);
        }

        function announce(result) {
            if (announced[result.id]) {
                return;
            }
            announced[result.id] = true;
            deps.view.result(result);
        }

        function observe() {
            var operation = status.operation;
            if (operation && operation.state === 'running') {
                watching[operation.id] = operation.action;
            }
            Object.keys(watching).forEach(function (id) {
                if (operation && operation.id === id && operation.state === 'running') {
                    return;
                }
                var action = watching[id];
                delete watching[id];
                if (operation && operation.id === id) {
                    var ok = operation.state === 'succeeded';
                    var message = operation.message;
                    if (ok && action === 'dependencies' && !wireguardInstalled(status)) {
                        ok = false;
                        message = 'The installation finished, but WireGuard tools could not be verified as available.';
                    }
                    announce({ id: id, action: action, label: operation.label, state: ok ? 'succeeded' : 'failed', message: message });
                } else if (operation && operation.action === 'revoke' && action !== 'revoke') {
                    announce({ id: id, action: action, label: labels[action] || action, state: 'cancelled', message: 'Cancelled by revocation.' });
                } else {
                    announce({ id: id, action: action, label: labels[action] || action, state: 'unknown',
                        message: 'The outcome could not be confirmed (the broker may have restarted). Review the current status before retrying.' });
                }
            });
            if (isBackgroundCleanup(status)) {
                if (cleanupSince === null) {
                    cleanupSince = deps.now();
                }
            } else if (cleanupSince !== null) {
                cleanupSince = null;
                var failed = /failed|quarantined/i.test(status.phase || '');
                announce({ id: 'cleanup-' + deps.now(), action: 'cleanup', label: 'Background cleanup', state: failed ? 'failed' : 'succeeded',
                    message: failed ? 'Cleanup did not complete; TELIPHONES is quarantined. Revocation may be retried.' : 'Session cleanup confirmed.' });
            }
        }

        function slowNow() {
            if (isRunning(status)) {
                var elapsed = (status.server_time || 0) - (status.operation.started_at || 0);
                return elapsed > (SLOW_AFTER[status.operation.action] || 60);
            }
            return cleanupSince !== null && deps.now() - cleanupSince > SLOW_AFTER.cleanup * 1000;
        }

        function apply(next) {
            status = next;
            observe();
            render();
            if (needsMonitoring(status)) {
                deps.view.slow(slowNow());
                startMonitoring();
            } else {
                stopMonitoring();
            }
        }

        function onPoll(result) {
            inflight = false;
            if (stopped) {
                return;
            }
            if (result.kind === 'auth') {
                stop();
                deps.view.authError(result.error);
                return;
            }
            if (result.kind === 'unsupported') {
                stopMonitoring();
                deps.view.unsupported();
                return;
            }
            if (result.kind === 'ok' && result.status && result.status.available) {
                failures = 0;
                deps.view.temporary(0);
                apply(result.status);
            } else {
                // A temporary inability to read status is never reported as an operation failure.
                failures += 1;
                deps.view.temporary(failures);
            }
            if (!monitoring) {
                return;
            }
            if (deps.now() - monitorSince > MAX_MONITOR_MS) {
                monitoring = false;
                clear();
                deps.view.paused(true);
                return;
            }
            schedule(failures ? Math.min(POLL_MS * Math.pow(2, failures - 1), MAX_BACKOFF_MS) : POLL_MS);
        }

        function poll() {
            if (inflight || stopped) {
                return;
            }
            inflight = true;
            deps.fetchStatus().then(onPoll, function () { onPoll({ kind: 'temporary' }); });
        }

        function submit(action, payload) {
            if (stopped || ACTIONS.indexOf(action) === -1 || submitting[action] || !controls(status, submitting)[action].enabled) {
                return false;
            }
            submitting[action] = true;
            render();
            deps.postAction(action, payload).then(function (result) {
                submitting[action] = false;
                if (result.kind === 'auth') {
                    render();
                    stop();
                    deps.view.authError(result.error);
                    return;
                }
                if (result.kind === 'unsupported') {
                    render();
                    deps.view.unsupported(action);
                    return;
                }
                if (result.kind !== 'ok') {
                    // The request may or may not have reached the broker: discover the outcome from status.
                    deps.view.temporary(1);
                    render();
                    startMonitoring();
                    return;
                }
                var body = result.body;
                var notice = body.notice || {};
                if (notice.ok && notice.operation_id) {
                    watching[notice.operation_id] = action;
                    deps.view.started(action, STARTED_MESSAGE);
                } else if (notice.ok) {
                    // Accepted by a broker that does not report operation ids; progress cannot be tracked.
                    deps.view.started(action, notice.message || 'Request submitted. Use Refresh session status to check the result.');
                } else {
                    announce({ id: 'refused-' + action + '-' + deps.now(), action: action, label: notice.operation || labels[action] || action,
                        state: 'failed', message: notice.error || 'The request was refused.' });
                }
                if (body.status && body.status.available) {
                    apply(body.status);
                } else {
                    render();
                }
                if (notice.ok && notice.operation_id) {
                    startMonitoring();
                }
            }, function () {
                submitting[action] = false;
                deps.view.temporary(1);
                render();
                startMonitoring();
            });
            return true;
        }

        function stop() {
            stopped = true;
            monitoring = false;
            clear();
        }

        function setHidden(value) {
            hidden = !!value;
            if (hidden) {
                clear();
            } else if (monitoring) {
                schedule(0);
            }
        }

        function resume() {
            if (stopped) {
                return;
            }
            monitoring = false;
            failures = 0;
            startMonitoring();
        }

        render();
        if (status && status.available && needsMonitoring(status)) {
            observe();
            deps.view.slow(slowNow());
            startMonitoring();
        }

        return {
            submit: submit,
            stop: stop,
            resume: resume,
            setHidden: setHidden,
            pollNow: function () { if (!monitoring) { startMonitoring(); } },
            state: function () {
                return { status: status, monitoring: monitoring, inflight: inflight, stopped: stopped, timer: timer !== null,
                    failures: failures, submitting: Object.assign({}, submitting), watching: Object.keys(watching) };
            }
        };
    }

    function unwrap(value) {
        if (value && typeof value === 'object') {
            if (value.teliphones_api === 1) {
                return value;
            }
            var keys = Object.keys(value);
            for (var index = 0; index < keys.length; index += 1) {
                var nested = value[keys[index]];
                if (nested && typeof nested === 'object' && nested.teliphones_api === 1) {
                    return nested;
                }
            }
        }
        return null;
    }

    function classify(httpStatus, text) {
        var body = null;
        try {
            body = unwrap(JSON.parse(text));
        } catch (error) {
            body = null;
        }
        if (httpStatus === 401 || httpStatus === 403 || (body && body.auth_error)) {
            return { kind: 'auth', error: body && typeof body.error === 'string' ? body.error : 'Your FreePBX session is no longer authorised.' };
        }
        if (!body) {
            return httpStatus >= 500 || httpStatus === 0 ? { kind: 'temporary' } : { kind: 'unsupported' };
        }
        return { kind: 'ok', body: body, status: body.status };
    }

    function bindDocument(document, window) {
        var rootElement = document.getElementById('teliphones-root');
        var initialElement = document.getElementById('teliphones-initial-status');
        if (!rootElement || !initialElement || typeof window.fetch !== 'function') {
            return null;
        }
        var initial;
        try {
            initial = JSON.parse(initialElement.textContent);
        } catch (error) {
            return null;
        }
        if (initial.available && initial.broker_current !== true) {
            // An older root broker cannot report operation progress; keep ordinary form submission.
            return null;
        }
        var endpoint = rootElement.getAttribute('data-teliphones-ajax') || 'ajax.php?module=teliphones';
        var controllers = [];
        var offset = 0;
        var find = function (selector) { return rootElement.querySelector(selector); };
        var findAll = function (selector) { return Array.prototype.slice.call(rootElement.querySelectorAll(selector)); };

        function request(url, options) {
            var controller = typeof window.AbortController === 'function' ? new window.AbortController() : null;
            if (controller) {
                controllers.push(controller);
                options.signal = controller.signal;
            }
            var timeout = window.setTimeout(function () { if (controller) { controller.abort(); } }, REQUEST_TIMEOUT_MS);
            options.credentials = 'same-origin';
            options.headers = { Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest' };
            var done = function () {
                window.clearTimeout(timeout);
                controllers = controllers.filter(function (item) { return item !== controller; });
            };
            return window.fetch(url, options).then(function (response) {
                return response.text().then(function (text) {
                    done();
                    return classify(response.status, text);
                });
            }, function () {
                done();
                return { kind: 'temporary' };
            });
        }

        function setCell(element, state) {
            if (!element) {
                return;
            }
            var spinner = element.querySelector('.teliphones-spinner');
            var text = element.querySelector('.teliphones-cell-text');
            var className = 'teliphones-cell-text teliphones-' + state.kind;
            if (spinner) {
                spinner.hidden = state.kind !== 'busy';
            }
            if (text && text.textContent !== state.text) {
                text.textContent = state.text;
            }
            if (text && text.className !== className) {
                text.className = className;
            }
            if (element.hasAttribute('data-teliphones-progress')) {
                element.hidden = state.kind === 'hidden';
            }
        }

        function setText(selector, value) {
            var element = find(selector);
            if (element && element.textContent !== value) {
                element.textContent = value;
            }
        }

        function remaining(status) {
            if (!status.session || typeof status.session.expires_at !== 'number') {
                return '';
            }
            return String(Math.max(0, Math.round(status.session.expires_at - (Date.now() / 1000 + offset))));
        }

        var current = initial;
        var view = {
            render: function (status, state, submitting) {
                current = status;
                if (typeof status.server_time === 'number') {
                    offset = status.server_time - Date.now() / 1000;
                }
                if (!status.available) {
                    return;
                }
                setText('[data-teliphones="phase"]', status.phase || 'Not configured');
                findAll('[data-teliphones-component]').forEach(function (cell) {
                    var name = cell.getAttribute('data-teliphones-component');
                    setCell(cell, readinessCell(name, status.readiness ? status.readiness[name] : undefined, status));
                });
                setCell(find('[data-teliphones="session-phase"]'), sessionPhase(status));
                ACTIONS.forEach(function (action) {
                    var button = find('button[value="' + action + '"]');
                    if (button) {
                        button.disabled = !state[action].enabled;
                        button.setAttribute('aria-disabled', state[action].enabled ? 'false' : 'true');
                        button.setAttribute('aria-busy', progress(action, status, submitting).kind === 'busy' ? 'true' : 'false');
                    }
                    var reason = find('[data-teliphones-reason="' + action + '"]');
                    if (reason) {
                        var text = REASONS[state[action].reason] || '';
                        reason.hidden = text === '';
                        if (reason.textContent !== text) {
                            reason.textContent = text;
                        }
                    }
                    setCell(find('[data-teliphones-progress="' + action + '"]'), progress(action, status, submitting));
                });
                var dependencyButton = find('button[value="dependencies"]');
                if (dependencyButton) {
                    var label = wireguardInstalled(status) ? 'WireGuard tools installed' : 'Approve installation of WireGuard tools';
                    if (dependencyButton.textContent !== label) {
                        dependencyButton.textContent = label;
                    }
                }
                var minutes = find('#teliphones-minutes');
                if (minutes) {
                    minutes.disabled = !state.authorise.enabled;
                }
                var session = find('#teliphones-session-details');
                if (session) {
                    session.hidden = !hasSession(status);
                    setText('[data-teliphones="session-id"]', (status.session && status.session.session_id) || '');
                    setText('[data-teliphones="engineer"]', status.engineer || 'Not yet established');
                    setText('[data-teliphones="remaining"]', remaining(status));
                    setText('[data-teliphones="access"]', status.access_verified
                        ? 'WireGuard-scoped web access and temporary source-restricted, public-key-only root SSH.'
                        : 'No current engineer SSH access has been confirmed.');
                }
                var evidence = find('#teliphones-evidence-section');
                if (evidence) {
                    evidence.hidden = !status.challenge;
                    setText('[data-teliphones="challenge"]', status.challenge ? JSON.stringify(status.challenge, null, 4) : '');
                }
                var fieldset = find('#teliphones-enrollment-fields');
                if (fieldset) {
                    fieldset.disabled = !state.configure.enabled;
                }
            },
            result: function (result) {
                var container = find('#teliphones-results');
                if (!container) {
                    return;
                }
                var box = document.createElement('div');
                var heading = document.createElement('strong');
                var success = result.state === 'succeeded';
                box.setAttribute('role', success ? 'status' : 'alert');
                if (success) {
                    box.className = 'alert alert-success teliphones-operation-result';
                    heading.textContent = '✓ ' + result.label + ' completed';
                } else if (result.state === 'cancelled' || result.state === 'unknown') {
                    box.className = 'alert alert-warning teliphones-operation-result';
                    heading.textContent = result.label + ': ' + (result.state === 'cancelled' ? 'cancelled' : 'outcome not confirmed');
                } else {
                    box.className = 'alert alert-danger teliphones-operation-result teliphones-operation-failure';
                    heading.textContent = '✕ Operation failed: ' + result.label;
                }
                box.appendChild(heading);
                box.appendChild(document.createElement('br'));
                box.appendChild(document.createTextNode(result.message || ''));
                container.insertBefore(box, container.firstChild);
                while (container.children.length > 3) {
                    container.removeChild(container.lastChild);
                }
                var started = find('#teliphones-started');
                if (started) {
                    started.hidden = true;
                }
                if (result.action === 'configure' && success) {
                    findAll('#teliphones-enrollment-fields textarea[name="private_key"]').forEach(function (field) { field.value = ''; });
                }
            },
            started: function (action, message) {
                var notice = find('#teliphones-started');
                if (notice) {
                    notice.textContent = message;
                    notice.hidden = false;
                }
            },
            slow: function (isSlow) {
                var element = find('#teliphones-slow');
                if (element && element.hidden === isSlow) {
                    element.hidden = !isSlow;
                }
            },
            temporary: function (count) {
                var element = find('#teliphones-poll-warning');
                if (!element) {
                    return;
                }
                element.hidden = count === 0;
                if (count) {
                    element.textContent = 'TELIPHONES could not retrieve the current status (attempt ' + count + '). This is not an operation failure; retrying automatically…';
                }
            },
            paused: function (isPaused) {
                var element = find('#teliphones-paused');
                if (element) {
                    element.hidden = !isPaused;
                }
            },
            unsupported: function (action) {
                if (action) {
                    var button = find('button[value="' + action + '"]');
                    if (button && button.form && typeof button.form.teliphonesFallback === 'function') {
                        button.form.teliphonesFallback();
                        return;
                    }
                }
                var element = find('#teliphones-poll-warning');
                if (element) {
                    element.hidden = false;
                    element.textContent = 'Automatic status updates are not available on this system. Use Refresh session status.';
                }
            },
            authError: function (message) {
                var element = find('#teliphones-poll-warning');
                if (element) {
                    element.hidden = false;
                    element.className = 'alert alert-danger';
                    element.textContent = (message || 'Your FreePBX session is no longer authorised.') + ' Automatic updates stopped; sign in again and refresh.';
                }
            }
        };

        var monitor = createMonitor({
            initial: initial,
            labels: initial.labels || {},
            now: function () { return Date.now(); },
            setTimer: function (callback, delay) { return window.setTimeout(callback, delay); },
            clearTimer: function (id) { window.clearTimeout(id); },
            fetchStatus: function () {
                return request(endpoint + '&command=status', { method: 'GET' });
            },
            postAction: function (action, payload) {
                return request(endpoint + '&command=action', { method: 'POST', body: payload });
            },
            view: view
        });

        findAll('form[data-teliphones-form]').forEach(function (form) {
            var nativeSubmit = window.HTMLFormElement && window.HTMLFormElement.prototype.submit;
            form.addEventListener('submit', function (event) {
                var submitter = event.submitter;
                if (!submitter || submitter.name !== 'action' || ACTIONS.indexOf(submitter.value) === -1) {
                    return;
                }
                event.preventDefault();
                var payload = new window.FormData(form);
                payload.set('action', submitter.value);
                form.teliphonesFallback = function () {
                    // ajax.php did not reach TELIPHONES; use the ordinary page POST, which enforces the same checks.
                    var field = document.createElement('input');
                    field.type = 'hidden';
                    field.name = 'action';
                    field.value = submitter.value;
                    form.appendChild(field);
                    (nativeSubmit || form.submit).call(form);
                };
                monitor.submit(submitter.value, payload);
            });
        });

        var resume = find('#teliphones-resume');
        if (resume) {
            resume.addEventListener('click', function () { monitor.resume(); });
        }
        var expiryChecked = null;
        var countdown = window.setInterval(function () {
            if (!current || !current.available || !hasSession(current) || typeof current.session.expires_at !== 'number') {
                return;
            }
            var left = remaining(current);
            setText('[data-teliphones="remaining"]', left);
            if (left === '0' && expiryChecked !== current.session.expires_at) {
                expiryChecked = current.session.expires_at;
                // Expiry is enforced by PBX timers; observe the resulting background cleanup.
                monitor.pollNow();
            }
        }, 1000);
        document.addEventListener('visibilitychange', function () { monitor.setHidden(document.hidden); });
        window.addEventListener('pagehide', function (event) {
            controllers.forEach(function (controller) { controller.abort(); });
            if (event && event.persisted) {
                // Page kept in the back/forward cache: suspend, and re-check status on return.
                monitor.setHidden(true);
                return;
            }
            monitor.stop();
            window.clearInterval(countdown);
        });
        window.addEventListener('pageshow', function (event) {
            if (event && event.persisted) {
                monitor.setHidden(false);
                monitor.pollNow();
            }
        });
        return monitor;
    }

    return {
        POLL_MS: POLL_MS,
        MAX_MONITOR_MS: MAX_MONITOR_MS,
        MAX_BACKOFF_MS: MAX_BACKOFF_MS,
        SLOW_AFTER: SLOW_AFTER,
        SLOW_MESSAGE: SLOW_MESSAGE,
        STARTED_MESSAGE: STARTED_MESSAGE,
        controls: controls,
        readinessCell: readinessCell,
        sessionPhase: sessionPhase,
        progress: progress,
        needsMonitoring: needsMonitoring,
        classify: classify,
        createMonitor: createMonitor,
        bindDocument: bindDocument
    };
}));

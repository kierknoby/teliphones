'use strict';
const assert = require('assert');
const live = require('../assets/js/teliphones.js');

function element(tagName, parentElement) {
    const listeners = {};
    const attributes = {};
    return {
        tagName, parentElement, open: false, listeners, attributes,
        setAttribute: (name, value) => { attributes[name] = value; },
        getAttribute: (name) => attributes[name],
        addEventListener: (name, callback, capture) => { listeners[name] = { callback, capture }; },
        querySelector: () => null,
        querySelectorAll: () => []
    };
}

const root = element('DIV', null);
const panel = element('DETAILS', root);
const summary = element('SUMMARY', panel);
const nested = element('DETAILS', panel);
const nestedSummary = element('SUMMARY', nested);
const field = element('INPUT', nested);
const link = element('A', root);
link.attributes['data-teliphones-open'] = 'pair';
panel.querySelector = () => summary;
nested.querySelector = () => nestedSummary;
root.querySelectorAll = (selector) => selector === 'details' ? [panel, nested] : [link];
root.querySelector = (selector) => selector === '#pair' ? panel : null;

live.bindPanels(root);
assert.strictEqual(summary.attributes['aria-expanded'], 'false');
assert.strictEqual(root.listeners.invalid.capture, true, 'invalid does not bubble');
root.listeners.invalid.callback({ target: field });
assert.strictEqual(panel.open, true, 'invalid field reveals outer panel');
assert.strictEqual(nested.open, true, 'invalid field reveals all nested help panels');
assert.strictEqual(summary.attributes['aria-expanded'], 'true');
assert.strictEqual(nestedSummary.attributes['aria-expanded'], 'true');
panel.open = false;
panel.listeners.toggle.callback();
assert.strictEqual(summary.attributes['aria-expanded'], 'false', 'native keyboard/mouse toggle updates accessible state');
link.listeners.click.callback();
assert.strictEqual(panel.open, true, 'empty-state pairing link opens the form');

const documentStub = {
    getElementById: (id) => id === 'teliphones-root' ? root : null
};
assert.strictEqual(live.bindDocument(documentStub, {}), null);
panel.open = false;
root.listeners.invalid.callback({ target: field });
assert.strictEqual(panel.open, true, 'panel validation works without fetch or a current broker');
assert.strictEqual(live.readinessWarning({ readiness: { 'WireGuard wg': false } }), '',
    'WireGuard has a separate actionable warning');
const configurationWarning = live.readinessWarning({ readiness: { 'Checker trusted public key': false, 'Temporary SSH server': true } });
assert(configurationWarning.includes('Checker trusted public key'));
assert(!configurationWarning.includes('platform administrator'), 'configuration gaps must not imply platform dependencies are missing');
assert(live.readinessWarning({ readiness: { iproute2: false } }).includes('platform administrator'));
assert.strictEqual(live.readinessWarning({ readiness: { 'Checker trusted public key': true } }), '',
    'configured components clear their warning after a live update');
console.log('Administration panel JavaScript tests: PASS (nested validation, accessible toggle, pairing link, no-fetch fallback)');

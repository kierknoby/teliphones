'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const site = path.resolve(__dirname, '..');
const root = path.resolve(site, '..');
const pages = fs.readdirSync(site, { recursive: true })
  .filter((name) => name.endsWith('.html'))
  .map((name) => path.join(site, name));
const contents = new Map(pages.map((file) => [file, fs.readFileSync(file, 'utf8')]));
const windows = fs.readFileSync(path.join(root, 'desktop/windows/src/app/Version.h'), 'utf8');
const version = ['MAJOR', 'MINOR', 'PATCH'].map((part) => {
  const match = windows.match(new RegExp(`^#define TELIPHONES_VERSION_${part}\\s+(\\d+)$`, 'm'));
  assert.ok(match, `Missing Windows ${part} version`);
  return match[1];
}).join('.');
const moduleVersion = fs.readFileSync(path.join(root, 'teliphones/module.xml'), 'utf8')
  .match(/<version>([^<]+)<\/version>/)[1];
const brokerVersion = fs.readFileSync(path.join(root, 'teliphones/support_broker.py'), 'utf8')
  .match(/^VERSION = "([^"]+)"/m)[1];

test('all site pages have valid local links, assets and unique fragment targets', () => {
  const ids = new Map();
  for (const [file, html] of contents) {
    assert.match(html, /<html lang="en-GB">/, file);
    const anchors = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
    assert.equal(new Set(anchors).size, anchors.length, `Duplicate id in ${file}`);
    ids.set(file, new Set(anchors));
  }
  for (const [file, html] of contents) {
    for (const match of html.matchAll(/\b(?:href|src)="([^"]+)"/g)) {
      const target = match[1];
      const url = new URL(target, `https://local.test/${path.relative(site, file).replaceAll(path.sep, '/')}`);
      if (url.origin !== 'https://local.test') continue;
      let resolved = path.resolve(site, '.' + decodeURIComponent(url.pathname));
      assert.ok(resolved === site || resolved.startsWith(site + path.sep), `Link escapes site: ${target}`);
      assert.ok(fs.existsSync(resolved), `${file}: missing ${target}`);
      if (fs.statSync(resolved).isDirectory()) resolved = path.join(resolved, 'index.html');
      assert.ok(fs.existsSync(resolved), `${file}: missing index for ${target}`);
      if (url.hash && contents.has(resolved)) {
        assert.ok(ids.get(resolved).has(decodeURIComponent(url.hash.slice(1))),
          `${file}: missing fragment ${target}`);
      }
    }
  }
});

test('current product and installation copy matches independent source versions', () => {
  for (const name of ['index.html', 'windows/index.html', 'downloads/index.html',
    'freepbx/index.html', 'faq/index.html', 'about/index.html', 'roadmap/index.html']) {
    const html = contents.get(path.join(site, name));
    assert.ok(html.includes(version), `${name}: missing Windows ${version}`);
    assert.ok(html.includes(moduleVersion), `${name}: missing module ${moduleVersion}`);
  }
  for (const name of ['downloads/index.html', 'freepbx/index.html', 'docs/getting-started/index.html',
    'docs/troubleshooting/index.html', 'faq/index.html']) {
    const html = contents.get(path.join(site, name));
    assert.ok(html.includes(brokerVersion), `${name}: missing broker ${brokerVersion}`);
    assert.match(html, /protocol (?:<strong>)?12/, name);
  }
  for (const [file, html] of contents) {
    assert.doesNotMatch(html, /0\.8\.0|0\.6\.0|protocol 7|broker 0\.6\.3/, file);
  }
});

test('pairing guide distinguishes request, approval, validation and unshipped module correction', () => {
  const html = contents.get(path.join(site, 'windows/index.html'));
  const pairing = html.slice(html.indexOf('<section id="pair">'), html.indexOf('<section id="connect">'));
  assert.equal((pairing.match(/<li>/g) || []).length, 8);
  for (const phrase of ['Request access', 'Complete pairing', 'Generate request', 'Copy request',
    'Save connection', 'Changing name/access', 'read-only', 'not independently signed',
    'predates', 'web-only form correction']) {
    assert.ok(pairing.includes(phrase), `Missing pairing guidance: ${phrase}`);
  }
  assert.match(contents.get(path.join(site, 'downloads/index.html')), /has not been rebuilt/);
  assert.match(contents.get(path.join(site, 'about/index.html')), /localStorage/);
});

test('existing Windows CI runs offline website checks and propagates failure', () => {
  const workflow = fs.readFileSync(path.join(root, '.github/workflows/windows-build.yml'), 'utf8');
  assert.ok(workflow.includes("'website/**'"));
  assert.ok(workflow.includes('python teliphones/tests/documentation-links.py'));
  assert.ok(workflow.includes('node --test @tests'));
  assert.ok(workflow.includes("if ($LASTEXITCODE -ne 0) { throw 'Offline website content and demonstration tests failed.' }"));
});

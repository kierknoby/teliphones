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
const currentModuleVersion = '0.8.3.15';
const currentBrokerVersion = '0.8.3.15';

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
  assert.equal(moduleVersion, brokerVersion, 'Module and broker source versions must match');
  assert.equal(moduleVersion, currentModuleVersion,
    'The website module version must match the currently tested installation');
  assert.equal(version, '0.10.0');
  for (const name of ['index.html', 'windows/index.html', 'downloads/index.html',
    'freepbx/index.html', 'faq/index.html', 'about/index.html', 'roadmap/index.html']) {
    const html = contents.get(path.join(site, name));
    assert.ok(html.includes(version), `${name}: missing Windows ${version}`);
    assert.ok(html.includes(currentModuleVersion), `${name}: missing module ${currentModuleVersion}`);
  }
  for (const name of ['index.html', 'about/index.html', 'downloads/index.html', 'freepbx/index.html',
    'roadmap/index.html', 'security/index.html', 'docs/index.html', 'docs/getting-started/index.html',
    'docs/troubleshooting/index.html', 'faq/index.html']) {
    assert.ok(contents.get(path.join(site, name)).includes(currentModuleVersion),
      `${name}: missing FreePBX version ${currentModuleVersion}`);
  }
  for (const [file, html] of contents) {
    assert.doesNotMatch(html, /0\.7\.0|0\.6\.0|protocol 7|broker 0\.6\.[45]|0\.9\.0/, file);
    assert.doesNotMatch(html, /TELIPHONES-0\.8\.2\.tgz|TELIPHONES-0\.6\.7\.tgz|historical 0\.6\.7/, file);
  }
  for (const name of ['index.html', 'features/index.html', 'downloads/index.html',
    'freepbx/index.html', 'faq/index.html', 'about/index.html', 'roadmap/index.html',
    'docs/index.html', 'docs/getting-started/index.html', 'docs/troubleshooting/index.html']) {
    assert.doesNotMatch(contents.get(path.join(site, name)), /0\.8\.2/, `${name}: stale module version`);
  }
  for (const name of ['index.html', 'windows/index.html', 'downloads/index.html',
    'freepbx/index.html', 'faq/index.html', 'about/index.html', 'roadmap/index.html',
    'security/index.html', 'docs/index.html', 'docs/getting-started/index.html',
    'docs/troubleshooting/index.html']) {
    const html = contents.get(path.join(site, name));
    assert.match(html, /0\.10\.0/, `${name}: missing Windows development target`);
    assert.match(html, /0\.8\.3\.15/, `${name}: missing current module version`);
  }
  const windowsPage = contents.get(path.join(site, 'windows/index.html'));
  for (const phrase of ['certificate-validated', 'HTTPS as the primary management service',
    'Microsoft Edge', 'private WireGuard address', 'No engineer public-IP trust',
    'permanent Windows DNS/hosts-file change', 'universal browser network isolation',
    'HTTPS Hostname...', 'disconnected', 'regardless of the general browser preference',
    'Normal TLS certificate validation remains enabled',
    'independently of saved PBX profiles', 'unrelated WireGuard/VPN connections',
    '1168 remains unconfirmed']) {
    assert.ok(windowsPage.includes(phrase), `Windows page missing 0.10.0 guidance: ${phrase}`);
  }
  for (const name of ['index.html', 'windows/index.html', 'features/index.html',
    'roadmap/index.html', 'faq/index.html', 'docs/getting-started/index.html',
    'security/index.html']) {
    const html = contents.get(path.join(site, name));
    assert.match(html, /selected external OpenSSH-backed terminal|selected external OpenSSH terminal|external managed SSH terminal|external-terminal path/i,
      `${name}: must identify the active external managed SSH path`);
  }
  const troubleshooting = contents.get(path.join(site, 'docs/troubleshooting/index.html'));
  assert.match(troubleshooting, /Open SSH[\s\S]*selected external terminal/);
  for (const name of ['windows/index.html', 'features/index.html', 'roadmap/index.html',
    'faq/index.html', 'security/index.html']) {
    const html = contents.get(path.join(site, name));
    assert.match(html, /disabled on (?:the )?(?:current|this) (?:managed SSH|Open SSH) path|disabled on the current Open SSH path/i,
      `${name}: must identify the experimental built-in console as disabled`);
  }
  assert.match(contents.get(path.join(site, 'windows/index.html')), /While the workstation is disconnected[\s\S]*HTTPS Hostname\.\.\./i);
  assert.match(contents.get(path.join(site, 'windows/index.html')), /Secure HTTPS administration always launches Microsoft Edge[\s\S]*regardless of the general browser preference/i);
  assert.match(contents.get(path.join(site, 'windows/index.html')), /never bypass certificate errors/i);
  const windowsConnect = contents.get(path.join(site, 'windows/index.html'))
    .slice(contents.get(path.join(site, 'windows/index.html')).indexOf('<section id="connect">'),
      contents.get(path.join(site, 'windows/index.html')).indexOf('<section id="ssh">'));
  assert.match(windowsConnect, /configure certificate-validated <strong>HTTPS as the primary management service<\/strong>/i);
  assert.match(windowsConnect, /While the workstation is disconnected[\s\S]*HTTPS Hostname\.\.\./i);
  for (const name of ['docs/getting-started/index.html', 'docs/troubleshooting/index.html',
    'features/index.html', 'faq/index.html', 'freepbx/index.html']) {
    const html = contents.get(path.join(site, name));
    assert.ok(html.includes('HTTPS Hostname...'), `${name}: missing hostname setup control`);
    assert.match(html, /Microsoft Edge[\s\S]*browser preference|browser preference[\s\S]*Microsoft Edge/i,
      `${name}: must distinguish the secure Edge launch from browser preference`);
  }
  assert.doesNotMatch(windowsPage, /0\.10\.0 (?:is )?(?:released|signed|production-ready|publicly downloadable)/i);
});

test('download guidance distinguishes package, CI artifact and acceptance', () => {
  const downloads = contents.get(path.join(site, 'downloads/index.html'));
  assert.match(downloads, /No 0\.10\.0 build is available/);
  assert.match(downloads, /preserve existing published download links and version information/i);
  assert.doesNotMatch(downloads, /TELIPHONES-Windows-x64|43980149884|14281389786/);
  assert.match(downloads, /does not announce a new public release or provide an approved 0\.10\.0 download/);
  const security = contents.get(path.join(site, 'security/index.html'));
  assert.match(security, /No 0\.10\.0 build is available/);
  assert.match(security, /crash report for the experimental built-in console remains unresolved/i);
  assert.match(security, /does not describe the selected external-terminal path/i);
});

test('site describes deployment evidence without claiming publication', () => {
  const about = contents.get(path.join(site, 'about/index.html'));
  assert.match(about, /no local evidence establishes the deployment target, deployed revision/);
  assert.match(about, /deployment has not been performed/);
  assert.match(about, /separate static-site ZIP snapshot differ/);
});

test('pairing guide distinguishes approval and independent product versions', () => {
  const html = contents.get(path.join(site, 'windows/index.html'));
  const pairing = html.slice(html.indexOf('<section id="pair">'), html.indexOf('<section id="connect">'));
  assert.equal((pairing.match(/<li>/g) || []).length, 8);
  for (const phrase of ['Request access', 'Complete pairing', 'Generate request', 'Copy request',
    'Save connection', 'Changing name/access', 'read-only', 'not independently signed',
    'currently tested FreePBX module installation', '0.8.3.15']) {
    assert.ok(pairing.includes(phrase), `Missing pairing guidance: ${phrase}`);
  }
  assert.match(contents.get(path.join(site, 'downloads/index.html')), /currently tested FreePBX module package is <strong>0\.8\.3\.15/);
  assert.match(contents.get(path.join(site, 'downloads/index.html')), /No 0\.10\.0 build is available/);
  assert.match(contents.get(path.join(site, 'about/index.html')), /localStorage/);
});

test('existing Windows CI runs offline website checks and propagates failure', () => {
  const workflow = fs.readFileSync(path.join(root, '.github/workflows/windows-build.yml'), 'utf8');
  assert.ok(workflow.includes("'website/**'"));
  assert.ok(workflow.includes('python teliphones/tests/documentation-links.py'));
  assert.ok(workflow.includes('node --test @tests'));
  assert.ok(workflow.includes("if ($LASTEXITCODE -ne 0) { throw 'Offline website content and demonstration tests failed.' }"));
});

'use strict';
// E7 (docs/endpoints.md, docs/branding.md): the third-party notices. One text (src/endpoints/notices.js) is served by the route, shown by the portal tab and printed by both
// installers. Here: the module, the real route file (with the sign-in chain replaced), the installer templates, and the REAL bash and (when installed) the REAL PowerShell printing the
// notices. The portal tab is in portal-endpoints.test.js; the rule that the product name appears nowhere else is in branding.test.js.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const notices = require('../src/endpoints/notices');
const installer = require('../src/endpoints/agent-installer');
const OPTS = { host: '192.168.68.54', group: 'default', managerVersion: 'v4.14.9' };

describe('notices module', () => {
  it('names the component, its licence (with a link), its source and its copyright line', () => {
    assert.ok(notices.COMPONENTS.length >= 1);
    for (const c of notices.COMPONENTS) {
      for (const k of ['id', 'name', 'licence', 'licence_url', 'source', 'copyright']) assert.ok(typeof c[k] === 'string' && c[k].length > 3, k);
      assert.match(c.licence_url, /^https:\/\//); assert.match(c.source, /^https:\/\//);
    }
    const t = notices.text(); assert.match(t, /GNU General Public License, version 2/); assert.match(t, /github\.com\/wazuh\/wazuh/); assert.match(t, /Copyright Wazuh, Inc\./); assert.match(t, /trademark/);
  });
  it('is a draft until REVIEWED is true, and says so in the text and in the API answer', () => {
    assert.strictEqual(notices.REVIEWED, false, 'flip REVIEWED only after the lawyer read (docs/branding.md)');
    assert.match(notices.text(false), /DRAFT/); assert.ok(!/DRAFT/.test(notices.text(true)));
    const a = notices.forApi(); assert.strictEqual(a.draft, true); assert.strictEqual(a.reviewed, false); assert.strictEqual(a.text, notices.text());
  });
  it('is safe to paste into a shell or PowerShell script, in both forms', () => {
    for (const t of [notices.text(false), notices.text(true)]) {
      assert.ok(!/[^\x20-\x7e\n]/.test(t), 'plain ASCII'); assert.ok(!/['"`@$\\]/.test(t), 'no quote, @, $, backtick or backslash');
      assert.ok(t.endsWith('\n') && !t.endsWith('\n\n')); assert.ok(!t.split('\n').some((l) => /^[']@|^ASIX_NOTICES/.test(l)));
    }
  });
  it('a statement that breaks the paste rule stops the module loading', () => {
    const src = fs.readFileSync(path.join(root, 'src/endpoints/notices.js'), 'utf8').replace("'Wazuh is a trademark of its owner.", "'Wazuh is a trademark of its owner\\u2019s.");
    assert.throws(() => new Function('require', 'module', '__dirname', src)(require, { exports: {} }, __dirname), /plain ASCII/);
  });
  it('the API answer is a copy: changing it does not change the module', () => {
    const a = notices.forApi(); a.components[0].name = 'x'; a.statements.length = 0; assert.notStrictEqual(notices.forApi().components[0].name, 'x'); assert.ok(notices.forApi().statements.length >= 1);
  });
});

describe('route GET /v1/endpoints/notices', () => {
  const express = require('express');
  const sharedPath = require.resolve('../src/gateway/shared');
  const perms = []; let server, base;
  before(async () => {
    require.cache[sharedPath] = { id: sharedPath, filename: sharedPath, loaded: true, exports: { guarded: (perm) => { perms.push(perm); return [(req, res, next) => next()]; }, apiError: () => {} } };
    const app = express(); app.use(require('../src/gateway/routes/endpoint-notices'));
    await new Promise((res) => { server = app.listen(0, '127.0.0.1', res); }); base = 'http://127.0.0.1:' + server.address().port;
  });
  after(() => { server.close(); delete require.cache[require.resolve('../src/gateway/routes/endpoint-notices')]; delete require.cache[sharedPath]; });

  it('is one GET guarded by capacity:read, with no database and no manager call', () => {
    assert.deepStrictEqual(perms, ['capacity:read']);
    const src = fs.readFileSync(path.join(root, 'src/gateway/routes/endpoint-notices.js'), 'utf8'); assert.ok(!/router\.(post|put|patch|delete)\(/.test(src)); assert.ok(!/db\.|wazuh-api|manager-store/.test(src.replace(/\/\/.*$/gm, '')));
  });
  it('answers with the module text, and nothing in the request changes it', async () => {
    const a = await (await fetch(base + '/v1/endpoints/notices')).json(); const b = await (await fetch(base + '/v1/endpoints/notices?draft=0&text=x&reviewed=true')).json();
    assert.strictEqual(a.success, true); assert.deepStrictEqual(a, b); assert.deepStrictEqual({ ...a, success: undefined }, { ...notices.forApi(), success: undefined }); assert.strictEqual(a.draft, true);
  });
  it('has no write route', async () => { assert.strictEqual((await fetch(base + '/v1/endpoints/notices', { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } })).status, 404); });
  it('is mounted in the gateway, before the readiness route', () => {
    const g = fs.readFileSync(path.join(root, 'src/gateway/index.js'), 'utf8'); const m = g.indexOf("require('./routes/endpoint-notices')"); assert.ok(m > 0); assert.ok(m < g.indexOf("app.get('/v1/health/ready'"));
  });
});

describe('installer templates carry the notices', () => {
  const linux = installer.render(OPTS).script, win = installer.renderWindows(OPTS).script;
  it('each template has exactly one notices field and none is left after filling', () => {
    for (const f of ['agent-install-linux.sh', 'agent-install-windows.ps1']) assert.strictEqual((fs.readFileSync(path.join(root, 'src/endpoints/templates', f), 'utf8').match(/@NOTICES@/g) || []).length, 1, f);
    assert.ok(!/@NOTICES@/.test(linux) && !/@NOTICES@/.test(win));
    assert.ok(linux.includes(notices.text())); assert.ok(win.includes(notices.text()));
  });
  it('the Windows script stays plain ASCII and the Linux heredoc ends where it should', () => {
    assert.ok(!/[^\x00-\x7f]/.test(win)); assert.strictEqual(linux.split('\n').filter((l) => l === 'ASIX_NOTICES_TEXT').length, 1); assert.strictEqual(win.split('\n').filter((l) => l === "'@").length, 1);
  });
  it('a template that lost its field is refused (the check list names the field)', () => {
    assert.match(fs.readFileSync(path.join(root, 'src/endpoints/agent-installer.js'), 'utf8'), /@\(MANAGER\|GROUP\|VERSION\|NOTICES\)@/);
  });
});

describe('the REAL bash script prints the notices', () => {
  let tmp, script, bin;
  before(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'notices-')); script = path.join(tmp, 'i.sh'); fs.writeFileSync(script, installer.render(OPTS).script, { mode: 0o755 });
    bin = path.join(tmp, 'bin'); fs.mkdirSync(bin); fs.writeFileSync(path.join(bin, 'id'), '#!/bin/sh\necho 1000\n', { mode: 0o755 });   // not root
  });
  after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const run = (args) => spawnSync('bash', [script, ...args], { encoding: 'utf8', env: { PATH: bin + ':/usr/bin:/bin', HOME: tmp } });
  it('--notices prints exactly the module text and exits 0, without root and before any check', () => {
    const r = run(['--notices']); assert.strictEqual(r.status, 0, r.stderr); assert.strictEqual(r.stdout, notices.text()); assert.strictEqual(r.stderr, '');
  });
  it('--notices wins over the other options and changes nothing', () => {
    const r = run(['--check', '--notices', '--name', 'x']); assert.strictEqual(r.status, 0); assert.strictEqual(r.stdout, notices.text()); assert.deepStrictEqual(fs.readdirSync(tmp).sort(), ['bin', 'i.sh']);
  });
  it('a normal start points to the notices before it does anything else (here it then stops: not root)', () => {
    const r = run(['--check']); assert.strictEqual(r.status, 1); assert.match(r.stdout, /Third-party notices for this software: run this script with --notices\./); assert.match(r.stderr, /Run as root/);
  });
});

const hasPwsh = spawnSync('pwsh', ['-NoProfile', '-Command', '1'], { encoding: 'utf8' }).status === 0;
describe('the REAL PowerShell script prints the notices', { skip: hasPwsh ? false : 'PowerShell 7 (pwsh) is not installed' }, () => {
  let tmp, script;
  before(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'noticesw-')); script = path.join(tmp, 'i.ps1'); fs.writeFileSync(script, installer.renderWindows(OPTS).script); });
  after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const run = (args) => spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-File', script, ...args], { encoding: 'utf8', env: { ...process.env, DOTNET_SYSTEM_GLOBALIZATION_INVARIANT: '1' } });
  it('-Notices prints exactly the module text and exits 0 (no administrator needed)', () => {
    const r = run(['-Notices']); assert.strictEqual(r.status, 0, r.stderr); assert.strictEqual(r.stdout.replace(/\r\n/g, '\n').replace(/\n$/, '') + '\n', notices.text());
  });
  it('an unknown word is still refused with exit 2, notices or not', () => {
    const r = run(['-Notices', 'extra']); assert.strictEqual(r.status, 2); assert.match(r.stderr, /Unknown argument/);
  });
});

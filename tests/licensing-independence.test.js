'use strict';
// Licensing is a module of its own that other modules never depend on (agreed 2026-11-08): it can be OFF, and while it is off the platform behaves as if it did not exist, so other modules are
// built and tested without it. These tests keep it that way: the few places the rest of the code touches it are listed here, and a new one fails a test until someone decides it is fine.
const { describe, it, beforeEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const walk = (dir) => fs.readdirSync(path.join(root, dir), { withFileTypes: true }).flatMap((d) => (d.isDirectory() ? (d.name === 'node_modules' ? [] : walk(path.join(dir, d.name))) : [path.join(dir, d.name)]));

describe('where the rest of the platform touches licensing', () => {
  it('only the listed files outside src/licensing refer to it, and nothing refers to its inside by another route', () => {
    const allowed = ['src/detection/ioc-matcher.js', 'src/detection/rule-runner.js', 'src/gateway/index.js', 'src/modules/index.js', 'src/server.js'];
    const hits = walk('src').filter((f) => f.endsWith('.js') && !f.startsWith('src/licensing/') && !f.startsWith('src/portal/modules/licensing/')).filter((f) => /require\([^)]*licensing/.test(read(f))).sort();
    assert.deepStrictEqual(hits, allowed);
    assert.deepStrictEqual([...read('src/modules/index.js').matchAll(/require\('([^']*licensing[^']*)'\)/g)].map((m) => m[1]), ['../licensing']);
    assert.deepStrictEqual([...read('src/gateway/index.js').matchAll(/require\('([^']*licensing[^']*)'\)/g)].map((m) => m[1]), ['../licensing/gate', '../licensing/routes']);
    assert.deepStrictEqual([...read('src/server.js').matchAll(/require\('([^']*licensing[^']*)'\)/g)].map((m) => m[1]), ['./licensing/notices']);
    for (const f of ['src/detection/rule-runner.js', 'src/detection/ioc-matcher.js']) assert.deepStrictEqual([...read(f).matchAll(/require\('([^']*licensing[^']*)'\)/g)].map((m) => m[1]), ['../licensing/worker-gate'], f);
  });
  it('the licensing folder reaches into the rest of the platform only through a short, known list', () => {
    const known = new Set(['../modules', '../db', '../gateway/shared', '../notifications/secret-box', '../notifications/senders']);
    const used = new Set(walk('src/licensing').flatMap((f) => [...read(f).matchAll(/require\('(\.\.[^']*)'\)/g)].map((m) => m[1])));
    for (const u of used) assert.ok(known.has(u), 'licensing now requires ' + u + ': add it here on purpose, or remove it');
  });
  it('the module manifests do not know about licensing: no home-tier module names a license feature, and no other module file mentions it', () => {
    const manifests = require('../src/modules/registry').loadDir();
    for (const m of manifests.filter((x) => x.tier === 'home')) assert.strictEqual(m.entitlement, null, m.id);
    for (const f of fs.readdirSync(path.join(root, 'src/modules/manifests')).filter((x) => !['licensing.js', 'endpoints.js'].includes(x))) assert.ok(!/licens/i.test(read('src/modules/manifests/' + f).replace(/license feature that unlocks it;[^\n]*/g, '').replace(/entitlement[^\n]*/g, '')), f);
  });
  it('no test of another module sets up licensing: only the licensing tests mention it', () => {
    const mine = new Set(['tests/licensing.test.js', 'tests/license-page.test.js', 'tests/licensing-page.test.js', 'tests/licensing-independence.test.js']);
    const others = fs.readdirSync(path.join(root, 'tests')).filter((f) => f.endsWith('.test.js') && !mine.has('tests/' + f)).filter((f) => /src\/licensing|ASIX_LICENSE_MODE|build-channel|license-store|vendor-keys/.test(read('tests/' + f)));
    assert.deepStrictEqual(others, []);
  });
});

describe('licensing off (the default on a development build)', () => {
  const modules = require('../src/modules'); const buildChannel = require('../src/licensing/build-channel'); const installation = require('../src/licensing/installation');
  const down = { async query() { throw new Error('database not reachable'); } };
  beforeEach(() => { modules.resetCache(); installation.reset(); buildChannel.override({ channel: 'dev', version: null }); });
  it('with nothing set up at all (no database, no license) every module of the edition is on, exactly as before licensing existed', async () => {
    for (const profile of ['home', 'enterprise']) {
      const s = await modules.snapshot({ ASIX_PROFILE: profile, ASIX_LICENSE_FILE: '/nonexistent' }, down); assert.strictEqual(s.license.mode, 'off'); assert.strictEqual(s.license.status, 'off');
      const locked = s.modules.filter((m) => m.state === 'locked'); assert.deepStrictEqual(locked.filter((m) => m.reason !== 'profile').map((m) => m.id), [], 'nothing is locked for want of a license'); modules.resetCache();
    }
  });
  it('the module states are the same as the platform had before licensing: a licensed feature never locks a module while off, even on the smaller edition', async () => {
    const s = await modules.snapshot({ ASIX_PROFILE: 'home' }, down); const on = s.modules.filter((m) => m.state === 'enabled').map((m) => m.id);
    for (const id of ['search', 'detections', 'alerts', 'cases', 'actions', 'content-packs', 'dashboards', 'notifications', 'threat-intel']) assert.ok(on.includes(id), id);
  });
  it('a database that has never heard of licensing (the schema job has not run) is also just off', async () => {
    const noTable = { async query() { const e = new Error('relation "installation" does not exist'); e.code = '42P01'; throw e; } };
    const s = await modules.snapshot({ ASIX_PROFILE: 'home' }, noTable); assert.strictEqual(s.license.mode, 'off'); assert.strictEqual(s.modules.find((m) => m.id === 'alerts').state, 'enabled');
  });
  it('a release build with the same broken database is on and locked (the customer build never opens by accident)', async () => {
    buildChannel.override({ channel: 'release', version: '26.4.0' }); const s = await modules.snapshot({ ASIX_PROFILE: 'home', ASIX_LICENSE_FILE: '/nonexistent' }, down); assert.strictEqual(s.license.mode, 'on'); assert.strictEqual(s.modules.find((m) => m.id === 'alerts').state, 'locked'); assert.strictEqual(s.modules.find((m) => m.id === 'ingestion').state, 'enabled');
  });
  it('the real gateway refuses nothing for want of a license while off, on either edition, and the workers are not paused', async () => {
    const get = (port, p) => new Promise((resolve, reject) => http.get({ port, path: p }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); }).on('error', reject));
    const db = require('../src/db'); const orig = db.query; db.query = async () => { throw new Error('no database'); };
    for (const profile of ['home', 'enterprise']) {
      process.env.ASIX_PROFILE = profile; modules.resetCache(); const server = require('../src/gateway').listen(0);
      try { const port = server.address().port; for (const p of ['/v1/search/fields', '/v1/alerts', '/v1/cases', '/v1/actions', '/v1/detections', '/v1/notifications', '/v1/threat-intel', '/v1/packs', '/v1/endpoints/agents']) assert.notStrictEqual(await get(port, p), 403, profile + ' ' + p); } finally { server.close(); }
    }
    db.query = orig; assert.strictEqual(await require('../src/licensing/worker-gate').enabled('detections', 'alerts'), true);
  });
  it('the notices do nothing while off, and a healthy or absent license sends nothing', async () => {
    const n = require('../src/licensing/notices'); for (const status of ['off', 'none', 'valid']) assert.strictEqual(n.stageOf({ status, expiring: false, expires_at: '2027-01-01T00:00:00Z' }), null, status);
  });
});

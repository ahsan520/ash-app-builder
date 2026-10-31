'use strict';
// E4q: what ONE machine is configured to monitor, from the manager (src/endpoints/wazuh-api.js agentConfig / shapeConfig, route GET /v1/endpoints/agents/:id/config/:section)
// against the stand-in manager API over real HTTPS (tests/fixtures/fake-wazuh-api.js, the documented Wazuh 4.x shape, NOT a real manager).
process.env.ASIX_WAZUH_API_TIMEOUT_MS = '600';
process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true';
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const express = require('express');
const fake = require('./fixtures/fake-wazuh-api');
const api = require('../src/endpoints/wazuh-api');

const mk = (srv, extra = {}) => ({ tenant_id: 'T-' + srv.port, api_url: srv.url, api_user: srv.user, api_password: srv.password, ca_pem: srv.cert, cert_sha256: 'x', api_secret_enc_hash: 'h', ...extra });
const rejects = async (p, code) => { try { await p; } catch (e) { assert.ok(e instanceof api.WazuhApiError, 'a WazuhApiError, got ' + e); assert.strictEqual(e.code, code, e.message); return e; } assert.fail('expected ' + code); };

describe('agentConfig against the stand-in manager', () => {
  let srv, m;
  before(async () => { srv = await fake.start(); m = mk(srv); });
  after(async () => { await srv.stop(); });
  const cfgCalls = () => srv.state.requests.filter((r) => /\/config\//.test(r.path));
  it('syscheck: the monitored folders with their options, the ignore list and the frequency; extra fields are not passed on', async () => {
    const c = await api.agentConfig(m, '001', 'syscheck');
    assert.deepStrictEqual(c.items, ['/etc (check_all, realtime)', '/usr/bin (check_all)', 'C:\\Windows\\System32']); assert.deepStrictEqual(c.ignored, ['/etc/mtab', '.log$']); assert.strictEqual(c.frequency_seconds, 43200);
    assert.ok(!JSON.stringify(c).includes('private.key') && !JSON.stringify(c).includes('skip_nfs'));
    assert.deepStrictEqual(cfgCalls().map((r) => r.path), ['/agents/001/config/syscheck/syscheck']);
  });
  it('logcollector: files, channels and commands with their format; junk entries are skipped; the channel query is not passed on', async () => {
    const c = await api.agentConfig(m, '002', 'logcollector');
    assert.deepStrictEqual(c.items, ['/var/log/syslog (syslog)', 'Security (eventchannel)', 'df -P (command)']); assert.ok(!JSON.stringify(c).includes('EventID'));
    assert.strictEqual(cfgCalls().pop().path, '/agents/002/config/logcollector/localfile');
  });
  it('a bad agent id or section sends nothing; an unknown section name such as __proto__ is refused', async () => {
    const n = srv.state.requests.length;
    for (const id of ['1', '12345678a', '../x', '']) await rejects(api.agentConfig(m, id, 'syscheck'), 'BAD_ID');
    for (const sec of ['syscheck/syscheck', 'client', '__proto__', 'toString', '', undefined, null, ['syscheck']]) await rejects(api.agentConfig(m, '001', sec), 'BAD_SECTION');
    assert.strictEqual(srv.state.requests.length, n);
  });
  it('an agent that is not active (the manager answers 400) is the proxy\'s bad response, not an empty list', async () => { await rejects(api.agentConfig(m, '999', 'syscheck'), 'BAD_RESPONSE'); });
  it('shapeConfig survives odd shapes and cuts lists and text', () => {
    assert.throws(() => api.shapeConfig('syscheck', null)); assert.throws(() => api.shapeConfig('syscheck', { data: 5 }));
    assert.deepStrictEqual(api.shapeConfig('syscheck', { data: {} }), { section: 'syscheck', items: [], ignored: [], frequency_seconds: null, realtime_note: null });
    assert.deepStrictEqual(api.shapeConfig('logcollector', { data: { localfile: 'x' } }).items, []);
    const many = api.shapeConfig('logcollector', { data: { localfile: Array.from({ length: 500 }, (_, i) => ({ file: 'f' + i + 'x'.repeat(500), logformat: 'syslog' })) } });
    assert.strictEqual(many.items.length, 200); assert.ok(many.items.every((x) => x.length <= 320));
    assert.strictEqual(api.shapeConfig('syscheck', { data: { syscheck: { frequency: -5 } } }).frequency_seconds, null);
  });
});

describe('route GET /v1/endpoints/agents/:id/config/:section', () => {
  const sharedPath = require.resolve('../src/gateway/shared'), storePath = require.resolve('../src/endpoints/wazuh-manager-store');
  const routeFiles = ['wazuh-manager', 'endpoint-checks'].map((n) => require.resolve('../src/gateway/routes/' + n));
  const perms = []; let srv, server, base;
  const put = (p, exports) => { require.cache[p] = { id: p, filename: p, loaded: true, exports }; };
  before(async () => {
    srv = await fake.start({ cn: 'cfgroute' });
    put(sharedPath, { db: { withTenant: async (t, fn) => fn({}) }, apiError: (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } }),
      guarded: (perm) => { perms.push(perm); return [(req, res, next) => { req.tenant_id = 'T1'; next(); }]; } });
    put(storePath, { readRow: async () => ({ tenant_id: 'T1' }), credentials: () => mk(srv, { tenant_id: 'T1' }), isMissingTable: () => false, view: () => ({}) });
    for (const f of routeFiles) delete require.cache[f];
    const app = express(); app.use(require('../src/gateway/routes/endpoint-checks'));
    await new Promise((res) => { server = app.listen(0, '127.0.0.1', res); }); base = 'http://127.0.0.1:' + server.address().port;
  });
  after(async () => { server.close(); await srv.stop(); for (const p of [...routeFiles, sharedPath, storePath]) delete require.cache[p]; });
  const get = async (p, method = 'GET') => { const r = await fetch(base + p, { method }); return { status: r.status, body: await r.json().catch(() => null) }; };
  it('uses search:events:read, is GET only and is mounted through the existing router', () => {
    assert.strictEqual(perms[perms.length - 1], 'search:events:read');
    const src = fs.readFileSync(path.join(__dirname, '..', 'src/gateway/routes/endpoint-checks.js'), 'utf8'); assert.match(src, /router\.get\('\/v1\/endpoints\/agents\/:id\/config\/:section', \.\.\.guarded\('search:events:read'\)/);
  });
  it('200 for both sections with the shaped answer', async () => {
    const a = await get('/v1/endpoints/agents/001/config/syscheck'); assert.strictEqual(a.status, 200, JSON.stringify(a.body)); assert.strictEqual(a.body.config.items[0], '/etc (check_all, realtime)'); assert.strictEqual(a.body.agent, '001');
    const b = await get('/v1/endpoints/agents/001/config/logcollector'); assert.strictEqual(b.status, 200); assert.strictEqual(b.body.config.items.length, 3);
  });
  it('a bad agent id or section is a 400 and the manager is not asked; a POST is not answered', async () => {
    const n = srv.state.requests.length;
    assert.strictEqual((await get('/v1/endpoints/agents/1/config/syscheck')).status, 400);
    for (const sec of ['client', '__proto__', 'syscheck%2Fsyscheck', 'constructor']) { const r = await get('/v1/endpoints/agents/001/config/' + sec); assert.strictEqual(r.status, 400, sec); assert.strictEqual(r.body.error.code, 'INVALID_CONFIG_SECTION'); }
    assert.strictEqual(srv.state.requests.length, n); assert.notStrictEqual((await get('/v1/endpoints/agents/001/config/syscheck', 'POST')).status, 200);
  });
  it('an agent that is not connected gives the proxy\'s error, with no detail from the manager', async () => {
    const r = await get('/v1/endpoints/agents/999/config/syscheck'); assert.ok(r.status >= 500 || r.status === 502, String(r.status)); assert.ok(!/not active/.test(JSON.stringify(r.body)));
  });
});

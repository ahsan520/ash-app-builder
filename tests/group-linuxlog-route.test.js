'use strict';
// E13: the routes of the Linux logs block (src/gateway/routes/group-linuxlog.js): the REAL route file and service, with the database, the manager client and the stores stood in; plus wiring.
const { describe, it, beforeEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const express = require('express');
const gc = require('../src/endpoints/group-config');
const ll = require('../src/endpoints/group-linuxlog');

const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');
const TENANT = '11111111-1111-4111-8111-111111111111';
const BASE = '<agent_config>\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/messages</location>\n  </localfile>\n</agent_config>\n';
let files, hist, env, app;
function load() {
  const base = path.join(__dirname, '..', 'src');
  const stub = (rel, exports) => { const f = require.resolve(path.join(base, rel)); delete require.cache[f]; require.cache[f] = { id: f, filename: f, loaded: true, exports }; };
  class WazuhApiError extends Error { constructor(code, m) { super(m); this.code = code; } }
  stub('gateway/shared.js', { db: { withTenant: async (t, fn) => fn({}) }, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'u1'; next(); }], apiError: (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } }) });
  stub('endpoints/wazuh-manager-store.js', { readRow: async () => (env.manager ? { id: 'm' } : null), isMissingTable: () => false, credentials: () => ({ tenant_id: TENANT }) });
  stub('endpoints/group-config-store.js', { readWriter: async () => (env.writer ? { id: 'w' } : null), isMissingTable: () => false, writerCredentials: () => ({}) });
  stub('endpoints/wazuh-api.js', { WazuhApiError, groupAgentConf: async (m, w, g) => { if (!files.has(g)) throw new WazuhApiError('BAD_RESPONSE', 'no such group'); return files.get(g); }, putGroupAgentConf: async (m, w, g, xml) => { env.puts.push({ g, xml }); files.set(g, xml); } });
  stub('endpoints/group-linuxlog-store.js', { isMissingTable: () => false,
    record: async (c, t, g, h) => { const row = { id: '00000000-0000-4000-8000-00000000000' + (hist.length + 1), group_name: g, created_at: new Date(0), actor_name: 'ann', ...h }; hist.push(row); return { id: row.id }; },
    settle: async (c, t, id, result, after, note) => { Object.assign(hist.find((x) => x.id === id), { result, after_sha256: after, note }); return 1; },
    list: async (c, t, g) => hist.filter((x) => x.group_name === g).slice().reverse(), get: async (c, t, g, id) => hist.find((x) => x.group_name === g && x.id === id) || null });
  const rf = require.resolve(path.join(base, 'gateway/routes/group-linuxlog.js')); delete require.cache[rf];
  const a = express(); a.use(express.json()); a.use(require(rf)); return a;
}
const call = (method, p, body) => new Promise((resolve, reject) => { const s = app.listen(0, () => {
  const data = body === undefined ? null : JSON.stringify(body);
  const r = http.request({ port: s.address().port, path: p, method, headers: data ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) } : {} }, (res) => { let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => { s.close(); resolve({ status: res.statusCode, body: JSON.parse(b) }); }); });
  r.on('error', reject); if (data) r.write(data); r.end(); }); });
const U = '/v1/endpoints/group-linuxlog/default';
const E = [{ type: 'journald' }, { type: 'file', path: '/var/log/app/*.log' }];
beforeEach(() => { files = new Map([['default', BASE]]); hist = []; env = { manager: true, writer: true, puts: [] }; process.env.ASIX_ENDPOINT_CONFIG_WRITE = 'true'; app = load(); });

describe('routes', () => {
  it('read: state, entries, hash, switch; history without the old file', async () => {
    let r = await call('GET', U); assert.strictEqual(r.status, 200); assert.strictEqual(r.body.state, 'none'); assert.strictEqual(r.body.sha256, gc.sha256(BASE)); assert.strictEqual(r.body.write_enabled, true);
    await call('PUT', U, { entries: E, base_sha256: gc.sha256(BASE) }); r = await call('GET', U); assert.deepStrictEqual(r.body.entries, E); assert.strictEqual(r.body.history.length, 1); assert.ok(!JSON.stringify(r.body.history).includes('/var/log/messages')); assert.strictEqual(r.body.history[0].by, 'ann');
  });
  it('preview reads only; apply writes and records; an empty list removes; stale is a 409; missing hash a 400', async () => {
    let r = await call('POST', U + '/preview', { entries: E }); assert.strictEqual(r.status, 200); assert.strictEqual(r.body.diff.added.length, 2); assert.strictEqual(env.puts.length, 0);
    r = await call('PUT', U, { entries: E, base_sha256: gc.sha256(BASE) }); assert.strictEqual(r.status, 200); assert.strictEqual(ll.find(files.get('default')).state, 'ok'); assert.strictEqual(hist[0].action, 'apply');
    r = await call('PUT', U, { entries: [], base_sha256: gc.sha256(files.get('default')) }); assert.strictEqual(r.status, 200); assert.strictEqual(files.get('default'), BASE); assert.strictEqual(hist[1].action, 'remove');
    r = await call('PUT', U, { entries: E, base_sha256: 'b'.repeat(64) }); assert.strictEqual(r.status, 409); assert.strictEqual(r.body.error.code, 'GROUP_LINUXLOG_STALE'); r = await call('PUT', U, { entries: E }); assert.strictEqual(r.status, 400);
  });
  it('refuses secret and system paths with a 400 and writes nothing', async () => {
    for (const p of ['/etc/shadow', '/proc/self/environ', '/home/a/.ssh/id_rsa', '/var/log/../etc/passwd']) { const r = await call('PUT', U, { entries: [{ type: 'file', path: p }], base_sha256: gc.sha256(BASE) }); assert.strictEqual(r.status, 400, p); assert.strictEqual(r.body.error.code, 'GROUP_LINUXLOG_INVALID'); }
    assert.strictEqual(env.puts.length, 0);
  });
  it('a request carries entries and a hash only', async () => {
    for (const extra of [{ xml: '<a/>' }, { path: '/var/log/x' }, { url: 'https://x' }]) { assert.strictEqual((await call('PUT', U, { entries: E, base_sha256: gc.sha256(BASE), ...extra })).status, 400); assert.strictEqual((await call('POST', U + '/preview', { entries: E, ...extra })).status, 400); }
    for (const b of [{ entries: 'x', base_sha256: gc.sha256(BASE) }, ['x']]) assert.strictEqual((await call('PUT', U, b)).status, 400); assert.strictEqual(env.puts.length, 0);
  });
  it('the switch is read on every request: off is a 403 and nothing written', async () => {
    process.env.ASIX_ENDPOINT_CONFIG_WRITE = 'false'; let r = await call('PUT', U, { entries: E, base_sha256: gc.sha256(BASE) }); assert.strictEqual(r.status, 403); assert.strictEqual(r.body.error.code, 'GROUP_LINUXLOG_WRITE_OFF');
    assert.strictEqual((await call('POST', U + '/undo', { history_id: '00000000-0000-4000-8000-000000000001', base_sha256: gc.sha256(BASE) })).status, 403); assert.strictEqual((await call('POST', U + '/preview', { entries: E })).status, 200); assert.strictEqual(env.puts.length, 0);
  });
  it('no manager and no writer are 404s; a bad group is a 400', async () => {
    env.manager = false; assert.strictEqual((await call('GET', U)).body.error.code, 'GROUP_LINUXLOG_NO_MANAGER'); env.manager = true; env.writer = false; assert.strictEqual((await call('GET', U)).body.error.code, 'GROUP_LINUXLOG_NO_WRITER');
    env.writer = true; assert.strictEqual((await call('GET', '/v1/endpoints/group-linuxlog/' + 'x'.repeat(65))).body.error.code, 'GROUP_LINUXLOG_BAD_GROUP');
  });
  it('undo restores the list from before that change and keeps other edits; only an applied change; unknown 404; bad id 400', async () => {
    await call('PUT', U, { entries: [{ type: 'journald' }], base_sha256: gc.sha256(BASE) }); await call('PUT', U, { entries: E, base_sha256: gc.sha256(files.get('default')) }); files.set('default', files.get('default') + '<!-- other -->\n');
    let r = await call('POST', U + '/undo', { history_id: hist[1].id, base_sha256: gc.sha256(files.get('default')) }); assert.strictEqual(r.status, 200); assert.deepStrictEqual(ll.find(files.get('default')).entries, [{ type: 'journald' }]); assert.ok(files.get('default').includes('<!-- other -->'));
    hist[0].result = 'failed'; const h = gc.sha256(files.get('default'));
    assert.strictEqual((await call('POST', U + '/undo', { history_id: hist[0].id, base_sha256: h })).status, 409); assert.strictEqual((await call('POST', U + '/undo', { history_id: '99999999-9999-4999-8999-999999999999', base_sha256: h })).status, 404); assert.strictEqual((await call('POST', U + '/undo', { history_id: 'nope', base_sha256: h })).status, 400);
  });
});

describe('wiring', () => {
  const src = read('src/gateway/routes/group-linuxlog.js');
  it('exact routes and permissions', () => {
    const routes = [...src.matchAll(/router\.(get|post|put|patch|delete)\('([^']+)', \.\.\.guarded\('([^']+)'\)/g)].map((m) => m[1].toUpperCase() + ' ' + m[2] + ' ' + m[3]);
    assert.deepStrictEqual(routes, ['GET /v1/endpoints/group-linuxlog/:group capacity:read', 'POST /v1/endpoints/group-linuxlog/:group/preview capacity:read', 'PUT /v1/endpoints/group-linuxlog/:group endpoints:config:write', 'POST /v1/endpoints/group-linuxlog/:group/undo endpoints:config:write']);
    assert.strictEqual((src.match(/writeGate\(req, res\)/g) || []).length, 2); assert.ok(/module\.exports = router;/.test(src)); assert.ok(!/module\.exports\.[A-Za-z]+\s*=/.test(src));
  });
  it('nothing in a request chooses an address, credential or file; no secret in a log line', () => {
    assert.ok(!/req\.(body|query|params)\.(url|address|host|user|password|path|xml)/.test(src)); assert.ok(!/api_url|ca_pem|api_password|api_secret_enc/.test(src.replace(/\/\/.*$/gm, '')));
    for (const l of src.split('\n').filter((x) => /console\.(error|log|warn)/.test(x))) assert.ok(!/password|secret|creds|ctx/.test(l), l);
  });
  it('is mounted after the Windows block and before readiness; shares the lock key of the folders block; own history table with row security', () => {
    const g = read('src/gateway/index.js'), m = g.indexOf("require('./routes/group-linuxlog')"); assert.ok(m > g.indexOf("require('./routes/group-winlog')") && m < g.indexOf("app.get('/v1/health/ready'"));
    assert.match(read('src/endpoints/group-linuxlog-service.js'), /withLock\(\(ctx\.m\.tenant_id \|\| ''\) \+ '\|' \+ group,/);
    const s = read('k8s/12-schema-init.yaml'), t = 'endpoint_group_linuxlog_history'; for (const re of ['CREATE TABLE IF NOT EXISTS ' + t, 'ALTER TABLE ' + t + ' ENABLE ROW LEVEL SECURITY', 'CREATE POLICY ' + t + '_tenant_isolation ON ' + t, 'GRANT SELECT, INSERT, UPDATE, DELETE ON ' + t + ' TO asix_admin']) assert.ok(s.includes(re), re);
    for (const f of ['group-config-store', 'group-winlog-store']) assert.ok(!/endpoint_group_linuxlog_history/.test(read('src/endpoints/' + f + '.js')));
  });
  it('the product name is not shown to a person: no Wazuh in any message of the route or the card', () => {
    for (const m of [...src.matchAll(/'([^'\n]{12,})'/g)].map((x) => x[1]).filter((x) => /\s/.test(x))) assert.ok(!/wazuh/i.test(m), m);
    const card = read('src/portal/index.html'), i = card.indexOf('function groupLinuxlogCard()'); for (const l of card.slice(i, i + 9000).split('\n').filter((x) => /textContent|say\(/.test(x))) assert.ok(!/wazuh/i.test(l), l.slice(0, 80));
  });
});

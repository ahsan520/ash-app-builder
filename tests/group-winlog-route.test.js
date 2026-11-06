'use strict';
// E11: the routes of the Windows events block (src/gateway/routes/group-winlog.js): the REAL route file and the REAL service, with the database, the manager client and the
// stores stood in (an in-memory group file and history); plus the wiring no behaviour test would notice if it were forgotten (permissions, mount order, schema, CI list).
const { describe, it, beforeEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const express = require('express');
const wf = require('../src/endpoints/win-filter');
const gc = require('../src/endpoints/group-config');
const wl = require('../src/endpoints/group-winlog');

const read = (p) => fs.readFileSync(path.join(__dirname, '..', p), 'utf8');
const TENANT = '11111111-1111-4111-8111-111111111111';
const BASE = '<agent_config>\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/messages</location>\n  </localfile>\n</agent_config>\n';
const NOISY_ROW = { policy: wf.toInput(wf.validate(wf.presetNoisySecurity()).policy), revision: 4 };

let files, hist, env;   // the group files, the history rows, and what the stores answer
function load() {
  const base = path.join(__dirname, '..', 'src');
  const stub = (rel, exports) => { const f = require.resolve(path.join(base, rel)); delete require.cache[f]; require.cache[f] = { id: f, filename: f, loaded: true, exports }; };
  class WazuhApiError extends Error { constructor(code, m) { super(m); this.code = code; } }
  stub('gateway/shared.js', {
    db: { withTenant: async (t, fn) => fn({}) },
    guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'u1'; next(); }], apiError: (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } }),
  });
  stub('endpoints/wazuh-manager-store.js', { readRow: async () => (env.manager ? { id: 'm' } : null), isMissingTable: () => false, credentials: () => ({ tenant_id: TENANT }) });
  stub('endpoints/group-config-store.js', { readWriter: async () => (env.writer ? { id: 'w' } : null), isMissingTable: () => false, writerCredentials: () => ({}) });
  stub('endpoints/wazuh-api.js', { WazuhApiError,
    groupAgentConf: async (m, w, g) => { if (!files.has(g)) throw new WazuhApiError('BAD_RESPONSE', 'no such group'); return files.get(g); },
    putGroupAgentConf: async (m, w, g, xml) => { env.puts.push({ g, xml }); files.set(g, xml); } });
  stub('endpoints/group-winlog-store.js', { isMissingTable: () => false,
    record: async (c, t, g, h) => { const row = { id: '00000000-0000-4000-8000-00000000000' + (hist.length + 1), group_name: g, created_at: new Date(0), actor_name: 'ann', ...h }; hist.push(row); return { id: row.id }; },
    settle: async (c, t, id, result, after, note) => { Object.assign(hist.find((x) => x.id === id), { result, after_sha256: after, note }); return 1; },
    list: async (c, t, g) => hist.filter((x) => x.group_name === g).slice().reverse(), get: async (c, t, g, id) => hist.find((x) => x.group_name === g && x.id === id) || null });
  const wsf = require.resolve(path.join(base, 'endpoints/win-filter-store.js')); delete require.cache[wsf];
  const ws = require(wsf); ws.readRow = async () => env.policyRow; ws.isMissingTable = () => false;
  const rf = require.resolve(path.join(base, 'gateway/routes/group-winlog.js')); delete require.cache[rf];
  const app = express(); app.use(express.json()); app.use(require(rf)); return app;
}
const call = (app, method, p, body) => new Promise((resolve, reject) => { const s = app.listen(0, () => {
  const data = body === undefined ? null : JSON.stringify(body);
  const r = http.request({ port: s.address().port, path: p, method, headers: data ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) } : {} }, (res) => { let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => { s.close(); resolve({ status: res.statusCode, body: JSON.parse(b) }); }); });
  r.on('error', reject); if (data) r.write(data); r.end(); }); });
const U = '/v1/endpoints/group-winlog/default';
let app;
beforeEach(() => { files = new Map([['default', BASE], ['linux', '']]); hist = []; env = { manager: true, writer: true, policyRow: NOISY_ROW, puts: [] }; process.env.ASIX_ENDPOINT_CONFIG_WRITE = 'true'; app = load(); });

describe('reading a group', () => {
  it('a group with no block: state none, the channels worth offering from the policy, what the policy gives for them, the hash and the revision', async () => {
    const r = await call(app, 'GET', U); assert.strictEqual(r.status, 200); const b = r.body;
    assert.strictEqual(b.state, 'none'); assert.deepStrictEqual(b.channels, []); assert.strictEqual(b.sha256, gc.sha256(BASE)); assert.strictEqual(b.policy_revision, 4); assert.strictEqual(b.write_enabled, true);
    assert.deepStrictEqual(b.offered, ['Security', 'System', 'Application']); assert.match(b.pushes.find((x) => x.channel === 'Security').query, /EventID != 4656/); assert.deepStrictEqual(b.history, []);
  });
  it('no policy saved: revision 0 and no query for any channel', async () => {
    env.policyRow = null; const b = (await call(app, 'GET', U)).body; assert.strictEqual(b.policy_revision, 0); assert.ok(b.pushes.every((x) => x.query === null));
  });
  it('a group with a block says whether it is in step with the policy', async () => {
    files.set('default', BASE + wl.blockText(wf.validate({}).policy, ['Security']) + '\n');
    const b = (await call(app, 'GET', U)).body; assert.strictEqual(b.state, 'ok'); assert.deepStrictEqual(b.channels, ['Security']); assert.strictEqual(b.in_step, false); assert.strictEqual(b.rows[0].same, false);
  });
  it('the history is shaped for the page: names and times, never the old file', async () => {
    await call(app, 'PUT', U, { channels: ['Security'], base_sha256: gc.sha256(BASE) });
    const h = (await call(app, 'GET', U)).body.history; assert.strictEqual(h.length, 1); assert.deepStrictEqual(Object.keys(h[0]).sort(), ['action', 'after_sha256', 'at', 'before_sha256', 'by', 'channels_after', 'channels_before', 'id', 'note', 'policy_revision', 'result']);
    assert.strictEqual(h[0].by, 'ann'); assert.ok(!JSON.stringify(h).includes('syslog'));
  });
  it('answers for no manager, no writer and an invalid saved policy without guessing', async () => {
    env.manager = false; let r = await call(app, 'GET', U); assert.strictEqual(r.status, 404); assert.strictEqual(r.body.error.code, 'GROUP_WINLOG_NO_MANAGER');
    env.manager = true; env.writer = false; r = await call(app, 'GET', U); assert.strictEqual(r.status, 404); assert.strictEqual(r.body.error.code, 'GROUP_WINLOG_NO_WRITER');
    env.writer = true; env.policyRow = { policy: { version: 1, default: 'maybe' }, revision: 2 };
    for (const [m, body] of [['GET'], ['POST', { channels: [] }], ['PUT', { channels: ['Security'], base_sha256: 'a'.repeat(64) }]]) { r = await call(app, m, m === 'POST' ? U + '/preview' : U, body); assert.strictEqual(r.status, 409, m); assert.strictEqual(r.body.error.code, 'GROUP_WINLOG_POLICY_INVALID'); }
    assert.strictEqual(env.puts.length, 0);
  });
  it('a bad group name is refused', async () => { for (const g of ['a%20b', 'x'.repeat(65), '..']) { const r = await call(app, 'GET', '/v1/endpoints/group-winlog/' + g); assert.ok([400, 404].includes(r.status), g); } assert.strictEqual((await call(app, 'GET', '/v1/endpoints/group-winlog/' + 'x'.repeat(65))).body.error.code, 'GROUP_WINLOG_BAD_GROUP'); });
});

describe('preview and apply', () => {
  it('preview reads only', async () => {
    const r = await call(app, 'POST', U + '/preview', { channels: ['Security', 'System'] }); assert.strictEqual(r.status, 200); assert.strictEqual(r.body.changed, true); assert.strictEqual(r.body.diff.added.length, 2); assert.strictEqual(env.puts.length, 0);
  });
  it('preview of bad channels is a 400 with the list of problems', async () => { const r = await call(app, 'POST', U + '/preview', { channels: ['a<b'] }); assert.strictEqual(r.status, 400); assert.strictEqual(r.body.error.code, 'GROUP_WINLOG_INVALID'); assert.ok(r.body.errors.length); });
  it('apply writes the block made from the STORED policy and records the revision', async () => {
    const r = await call(app, 'PUT', U, { channels: ['Security'], base_sha256: gc.sha256(BASE) }); assert.strictEqual(r.status, 200); assert.strictEqual(r.body.changed, true);
    assert.match(files.get('default'), /<query>Event\/System\[EventID != 4656/); assert.strictEqual(hist[0].policy_revision, 4); assert.strictEqual(hist[0].action, 'apply'); assert.strictEqual(hist[0].result, 'applied');
  });
  it('an empty list removes the block and is recorded as a removal', async () => {
    await call(app, 'PUT', U, { channels: ['Security'], base_sha256: gc.sha256(BASE) });
    const r = await call(app, 'PUT', U, { channels: [], base_sha256: gc.sha256(files.get('default')) }); assert.strictEqual(r.status, 200); assert.strictEqual(files.get('default'), BASE); assert.strictEqual(hist[1].action, 'remove');
  });
  it('a stale hash is a 409 and nothing is written; a missing one is a 400', async () => {
    let r = await call(app, 'PUT', U, { channels: ['Security'], base_sha256: 'b'.repeat(64) }); assert.strictEqual(r.status, 409); assert.strictEqual(r.body.error.code, 'GROUP_WINLOG_STALE'); assert.strictEqual(r.body.current_sha256, gc.sha256(BASE));
    r = await call(app, 'PUT', U, { channels: ['Security'] }); assert.strictEqual(r.status, 400); assert.strictEqual(env.puts.length, 0);
  });
  it('a damaged or hand-edited block is a 409 with the way out', async () => {
    files.set('default', BASE + wl.blockText(wf.validate({}).policy, ['Security']).replace('eventchannel', 'syslog') + '\n');
    const r = await call(app, 'PUT', U, { channels: ['System'], base_sha256: gc.sha256(files.get('default')) }); assert.strictEqual(r.status, 409); assert.strictEqual(r.body.error.code, 'GROUP_WINLOG_BLOCK_EDITED'); assert.match(r.body.error.message, /remove the block/);
  });
  it('the switch is read on every request: off means 403 and nothing written, on again means it works', async () => {
    process.env.ASIX_ENDPOINT_CONFIG_WRITE = 'false';
    let r = await call(app, 'PUT', U, { channels: ['Security'], base_sha256: gc.sha256(BASE) }); assert.strictEqual(r.status, 403); assert.strictEqual(r.body.error.code, 'GROUP_WINLOG_WRITE_OFF'); assert.strictEqual(env.puts.length, 0);
    r = await call(app, 'POST', U + '/undo', { history_id: '00000000-0000-4000-8000-000000000001', base_sha256: gc.sha256(BASE) }); assert.strictEqual(r.status, 403);
    assert.strictEqual((await call(app, 'GET', U)).body.write_enabled, false); assert.strictEqual((await call(app, 'POST', U + '/preview', { channels: ['Security'] })).status, 200);
    process.env.ASIX_ENDPOINT_CONFIG_WRITE = 'true'; assert.strictEqual((await call(app, 'PUT', U, { channels: ['Security'], base_sha256: gc.sha256(BASE) })).status, 200);
  });
  it('a request cannot bring a policy, a query, an address or anything else: only channels and the hash', async () => {
    for (const extra of [{ policy: {} }, { query: 'Event/System[EventID=1]' }, { url: 'https://x' }, { xml: '<a/>' }]) {
      const r = await call(app, 'PUT', U, { channels: ['Security'], base_sha256: gc.sha256(BASE), ...extra }); assert.strictEqual(r.status, 400, Object.keys(extra)[0]); assert.strictEqual(r.body.error.code, 'GROUP_WINLOG_BAD_BODY');
      assert.strictEqual((await call(app, 'POST', U + '/preview', { channels: ['Security'], ...extra })).status, 400);
    }
    assert.strictEqual((await call(app, 'PUT', U, { channels: 'Security', base_sha256: gc.sha256(BASE) })).status, 400); assert.strictEqual((await call(app, 'PUT', U, ['x'])).status, 400); assert.strictEqual(env.puts.length, 0);
  });
});

describe('undo', () => {
  it('puts the channels back as they were before that change, leaving the rest of the file', async () => {
    await call(app, 'PUT', U, { channels: ['Security'], base_sha256: gc.sha256(BASE) });
    await call(app, 'PUT', U, { channels: ['Security', 'System'], base_sha256: gc.sha256(files.get('default')) });
    files.set('default', files.get('default') + '<!-- other -->\n');
    const r = await call(app, 'POST', U + '/undo', { history_id: hist[1].id, base_sha256: gc.sha256(files.get('default')) }); assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(wl.find(files.get('default')).channels, ['Security']); assert.ok(files.get('default').includes('<!-- other -->')); assert.strictEqual(hist[2].action, 'undo');
  });
  it('only an applied change can be undone, an unknown one is a 404, a malformed id a 400', async () => {
    await call(app, 'PUT', U, { channels: ['Security'], base_sha256: gc.sha256(BASE) }); hist[0].result = 'failed'; const h = gc.sha256(files.get('default'));
    assert.strictEqual((await call(app, 'POST', U + '/undo', { history_id: hist[0].id, base_sha256: h })).status, 409);
    assert.strictEqual((await call(app, 'POST', U + '/undo', { history_id: '99999999-9999-4999-8999-999999999999', base_sha256: h })).status, 404);
    assert.strictEqual((await call(app, 'POST', U + '/undo', { history_id: 'nope', base_sha256: h })).status, 400);
  });
});

describe('wiring', () => {
  const src = read('src/gateway/routes/group-winlog.js');
  it('has exactly the routes and permissions it should: reading and preview need capacity:read, a change and an undo need endpoints:config:write', () => {
    const routes = [...src.matchAll(/router\.(get|post|put|patch|delete)\('([^']+)', \.\.\.guarded\('([^']+)'\)/g)].map((m) => m[1].toUpperCase() + ' ' + m[2] + ' ' + m[3]);
    assert.deepStrictEqual(routes, ['GET /v1/endpoints/group-winlog/:group capacity:read', 'POST /v1/endpoints/group-winlog/:group/preview capacity:read', 'PUT /v1/endpoints/group-winlog/:group endpoints:config:write', 'POST /v1/endpoints/group-winlog/:group/undo endpoints:config:write']);
    assert.ok(!/router\.(patch|delete)\(/.test(src)); assert.strictEqual((src.match(/writeGate\(req, res\)/g) || []).length, 2);
  });
  it('no property of the exported router is replaced (the E6f outage)', () => { assert.ok(!/module\.exports\.[A-Za-z]+\s*=/.test(src)); assert.ok(/module\.exports = router;/.test(src)); });
  it('nothing in a request chooses an address, a credential, a path or a query', () => { assert.ok(!/req\.(body|query|params)\.(url|address|host|user|password|path|policy|query|xml)/.test(src)); assert.ok(!/api_url|ca_pem|api_password|api_secret_enc/.test(src.replace(/\/\/.*$/gm, ''))); });
  it('no password reaches a log line', () => { for (const l of src.split('\n').filter((x) => /console\.(error|log|warn)/.test(x))) assert.ok(!/password|secret|creds|ctx/.test(l), l); });
  it('is mounted before the readiness route, next to group-config, and the shared lock key is the same as the folders block', () => {
    const g = read('src/gateway/index.js'); const m = g.indexOf("require('./routes/group-winlog')"); assert.ok(m > g.indexOf("require('./routes/group-config')") && m < g.indexOf("app.get('/v1/health/ready'"));
    assert.match(read('src/endpoints/group-winlog-service.js'), /withLock\(\(ctx\.m\.tenant_id \|\| ''\) \+ '\|' \+ group,/); assert.match(read('src/endpoints/group-config-service.js'), /withLock\(\(ctx\.m\.tenant_id \|\| ''\) \+ '\|' \+ group,/);
  });
  it('the schema has the history table with row security, a policy per tenant, a grant, and only the three actions and results', () => {
    const s = read('k8s/12-schema-init.yaml'), t = 'endpoint_group_winlog_history';
    assert.match(s, new RegExp('CREATE TABLE IF NOT EXISTS ' + t)); assert.match(s, new RegExp('ALTER TABLE ' + t + ' ENABLE ROW LEVEL SECURITY')); assert.match(s, new RegExp('CREATE POLICY ' + t + '_tenant_isolation ON ' + t)); assert.match(s, new RegExp('GRANT SELECT, INSERT, UPDATE, DELETE ON ' + t + ' TO asix_admin'));
    const body = s.slice(s.indexOf('CREATE TABLE IF NOT EXISTS ' + t), s.indexOf('GRANT SELECT, INSERT, UPDATE, DELETE ON ' + t));
    assert.match(body, /action IN \('apply', 'remove', 'undo'\)/); assert.match(body, /result IN \('applied', 'rolled_back', 'failed'\)/);
  });
  it('the folder undo cannot read one of these rows, and this undo cannot read a folder row: separate tables', () => {
    assert.ok(!/endpoint_group_config_history/.test(read('src/endpoints/group-winlog-store.js'))); assert.ok(!/endpoint_group_winlog_history/.test(read('src/endpoints/group-config-store.js')));
  });
  it('the product name is not shown to a person (docs/branding.md): no Wazuh in any message of the route or the card', () => {
    const msgs = [...src.matchAll(/'([^'\n]{12,})'/g)].map((m) => m[1]).filter((x) => /\s/.test(x)); for (const m of msgs) assert.ok(!/wazuh/i.test(m), m);
    const card = read('src/portal/index.html'); const c = card.slice(card.indexOf('function groupWinlogCard()'), card.indexOf('function groupWinlogCard()') + 9000); for (const l of c.split('\n').filter((x) => /textContent|say\(/.test(x))) assert.ok(!/wazuh/i.test(l), l.slice(0, 80));
  });
});

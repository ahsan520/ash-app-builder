'use strict';
// The License page (docs/licensing.md): the routes (real route file, stored licenses in an in-memory stand-in for the database), the notices sent as a license runs out, the guard the detection
// workers ask, and the portal page cut out of index.html.
const { describe, it, before, beforeEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const { generateKeyPair, exportSPKI, SignJWT } = require('jose');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const IID = '11111111-2222-4333-8444-555555555555', OTHER = '99999999-2222-4333-8444-555555555555';
let pair, pem, other;
before(async () => { pair = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true }); pem = await exportSPKI(pair.publicKey); other = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true }); });
const sign = async (claims = {}, { exp = '30d', key } = {}) => { const now = Math.floor(Date.now() / 1000); return new SignJWT({ features: ['search', 'alerts', 'detections'], limits: {}, iid: IID, kind: 'residential', ...claims }).setProtectedHeader({ alg: 'EdDSA', kid: 'k1' }).setIssuer('asix').setSubject('Acme').setIssuedAt(now).setExpirationTime(now + parseInt(exp, 10) * 86400).sign(key || pair.privateKey); };
const sha = (t) => crypto.createHash('sha256').update(t).digest('hex');

// ---- an in-memory database for the few statements the License code runs ----
function makeDb() {
  const st = { files: [], enforce: false, seen: null, notices: new Map(), n: 0 };
  return { st, async query(sql, p = []) {
    if (/^SELECT id::text AS id, last_seen_at FROM installation/.test(sql)) return { rows: [{ id: IID, last_seen_at: st.seen }] };
    if (/^UPDATE installation SET last_seen_at/.test(sql)) { st.seen = new Date().toISOString(); return { rows: [] }; }
    if (/enforce FROM installation/.test(sql)) return { rows: [{ enforce: st.enforce }] };
    if (/^UPDATE installation SET enforce/.test(sql)) { st.enforce = p[0]; return { rows: [] }; }
    if (/SELECT token FROM license_files WHERE active/.test(sql)) { const a = st.files.find((f) => f.active); return { rows: a ? [{ token: a.token }] : [] }; }
    if (/SELECT token FROM license_files WHERE id/.test(sql)) { const f = st.files.find((x) => x.id === p[0]); return { rows: f ? [{ token: f.token }] : [] }; }
    if (/^SELECT id, label, customer/.test(sql)) return { rows: st.files.map((f) => ({ ...f, uploaded_at: 'now', uploaded_by: null })) };
    if (/SELECT count/.test(sql)) return { rows: [{ n: st.files.length }] };
    if (/^INSERT INTO license_files/.test(sql)) { if (st.files.some((f) => f.sha256 === p[2])) { const e = new Error('dup'); e.code = '23505'; throw e; } const id = '00000000-0000-4000-8000-00000000000' + (++st.n); st.files.push({ id, label: p[0], token: p[1], sha256: p[2], customer: p[3], kind: p[4], expires_at: p[5], active: false }); return { rows: [{ id }] }; }
    if (/^UPDATE license_files SET active = \(id =/.test(sql)) { st.files.forEach((f) => { f.active = f.id === p[0]; }); return { rows: st.files.filter((f) => f.id === p[0]).map((f) => ({ id: f.id, active: true })) }; }
    if (/^UPDATE license_files SET active = FALSE/.test(sql)) { st.files.forEach((f) => { f.active = false; }); return { rows: [] }; }
    if (/^DELETE FROM license_files/.test(sql)) { const i = st.files.findIndex((f) => f.id === p[0] && !f.active); if (i >= 0) st.files.splice(i, 1); return { rowCount: i >= 0 ? 1 : 0, rows: [] }; }
    if (/FROM license_notices/.test(sql)) return { rows: st.notices.has(p[0]) ? [{}] : [] };
    if (/^INSERT INTO license_notices/.test(sql)) { st.notices.set(p[0], p[1]); return { rows: [] }; }
    if (/FROM tenants/.test(sql)) return { rows: [{ id: 't1', name: 'Default Tenant' }] };
    throw new Error('unexpected statement: ' + sql.slice(0, 80));
  } };
}

describe('the License routes', () => {
  let db, app;
  const loadApp = () => {
    const base = path.join(root, 'src'); const f = (rel) => require.resolve(path.join(base, rel));
    delete require.cache[f('gateway/shared.js')]; require.cache[f('gateway/shared.js')] = { id: f('gateway/shared.js'), filename: f('gateway/shared.js'), loaded: true, exports: { guarded: () => [(req, res, next) => { req.user_id = 'u1'; next(); }], apiError: (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } }) } };
    const realDb = require('../src/db'); realDb.query = (sql, p) => db.query(sql, p);
    for (const m of ['modules/index.js', 'licensing/state.js', 'licensing/license-store.js', 'licensing/installation.js', 'licensing/routes.js']) delete require.cache[f(m)];
    const vendor = require('../src/licensing/vendor-keys'); vendor.KEYS.length = 0; vendor.KEYS.push({ kid: 'k1', pem });
    const a = express(); a.use(express.json()); a.use(require(f('licensing/routes.js'))); return a;
  };
  const call = (method, p, body) => new Promise((resolve, reject) => { const s = app.listen(0, () => {
    const data = body === undefined ? null : JSON.stringify(body);
    const r = http.request({ port: s.address().port, path: p, method, headers: data ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) } : {} }, (res) => { let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => { s.close(); resolve({ status: res.statusCode, body: JSON.parse(b) }); }); }); r.on('error', reject); if (data) r.write(data); r.end(); }); });
  beforeEach(() => { db = makeDb(); require('../src/licensing/build-channel').override({ channel: 'dev', version: null }); app = loadApp(); });

  it('shows the state, the build, the stored licenses without their text, and whether the switch exists', async () => {
    const r = await call('GET', '/v1/license'); assert.strictEqual(r.status, 200); assert.strictEqual(r.body.license.installation_id, IID); assert.strictEqual(r.body.license.enforce, false); assert.strictEqual(r.body.can_switch_enforcement, true); assert.deepStrictEqual(r.body.files, []); assert.ok(r.body.features.residential.includes('search')); assert.ok(r.body.features.enterprise.includes('endpoints'));
    const t = await sign(); await call('POST', '/v1/license', { license: t }); const g = await call('GET', '/v1/license'); assert.strictEqual(g.body.files.length, 1); assert.ok(!JSON.stringify(g.body).includes(t), 'the license text is never sent back'); assert.ok(!('token' in g.body.files[0]));
    require('../src/licensing/build-channel').override({ channel: 'release', version: '26.4.0' }); require('../src/modules').resetCache(); const rel = await call('GET', '/v1/license'); assert.strictEqual(rel.body.can_switch_enforcement, false); assert.strictEqual(rel.body.license.enforce, true);
  });
  it('storing checks the license first and does not activate it', async () => {
    const r = await call('POST', '/v1/license', { license: await sign(), label: 'Acme 2027' }); assert.strictEqual(r.status, 201); assert.strictEqual(r.body.active, false); assert.strictEqual(db.st.files[0].active, false); assert.strictEqual(db.st.files[0].label, 'Acme 2027'); assert.strictEqual(db.st.files[0].customer, 'Acme'); assert.strictEqual(db.st.files[0].kind, 'residential');
    assert.strictEqual((await call('GET', '/v1/license')).body.license.source, null);
  });
  it('refuses a forged license, one for another installation, one past its grace, bad text and extra fields; a duplicate is a 409', async () => {
    let r = await call('POST', '/v1/license', { license: await sign({}, { key: other.privateKey }) }); assert.strictEqual(r.status, 422); assert.match(r.body.error.message, /not a valid license/);
    r = await call('POST', '/v1/license', { license: await sign({ iid: OTHER }) }); assert.strictEqual(r.status, 422); assert.match(r.body.error.message, /different installation/);
    r = await call('POST', '/v1/license', { license: await sign({}, { exp: '-40d' }) }); assert.strictEqual(r.status, 422); assert.match(r.body.error.message, /expired/);
    for (const bad of ['', 'not a license', 'a.b', 'a.b.c.d', 'x'.repeat(9000)]) assert.strictEqual((await call('POST', '/v1/license', { license: bad })).status, 400, bad.slice(0, 10));
    assert.strictEqual((await call('POST', '/v1/license', { license: await sign(), extra: 1 })).status, 400); assert.strictEqual((await call('POST', '/v1/license', ['x'])).status, 400);
    const t = await sign(); assert.strictEqual((await call('POST', '/v1/license', { license: t })).status, 201); assert.strictEqual((await call('POST', '/v1/license', { license: t })).status, 409); assert.strictEqual(db.st.files.length, 1);
  });
  it('a license in its grace period can be stored; activating makes it the only active one and the platform uses it', async () => {
    const a = await call('POST', '/v1/license', { license: await sign({}, { exp: '-3d' }) }); assert.strictEqual(a.status, 201);
    const b = await call('POST', '/v1/license', { license: await sign({ features: ['search'] }) }); assert.strictEqual(b.status, 201);
    let r = await call('POST', '/v1/license/' + a.body.id + '/activate', {}); assert.strictEqual(r.status, 200); assert.strictEqual((await call('GET', '/v1/license')).body.license.status, 'off');   // dev build, not enforcing
    await call('PUT', '/v1/license/enforcement', { enforce: true }); let g = await call('GET', '/v1/license'); assert.strictEqual(g.body.license.status, 'grace'); assert.strictEqual(g.body.license.source, 'stored');
    r = await call('POST', '/v1/license/' + b.body.id + '/activate', {}); assert.strictEqual(r.status, 200); assert.strictEqual(db.st.files.filter((f) => f.active).length, 1); g = await call('GET', '/v1/license'); assert.strictEqual(g.body.license.status, 'valid'); assert.deepStrictEqual(g.body.license.features, ['search']);
  });
  it('activate refuses unknown and bad ids and a license that no longer checks out; deactivate switches the active one off', async () => {
    assert.strictEqual((await call('POST', '/v1/license/00000000-0000-4000-8000-0000000000ff/activate', {})).status, 404); assert.strictEqual((await call('POST', '/v1/license/nope/activate', {})).status, 400);
    const a = await call('POST', '/v1/license', { license: await sign() }); db.st.files[0].token = await sign({}, { exp: '-40d' }); assert.strictEqual((await call('POST', '/v1/license/' + a.body.id + '/activate', {})).status, 422);
    db.st.files[0].token = await sign(); await call('POST', '/v1/license/' + a.body.id + '/activate', {}); assert.strictEqual(db.st.files[0].active, true); assert.strictEqual((await call('POST', '/v1/license/deactivate', {})).status, 200); assert.strictEqual(db.st.files[0].active, false);
  });
  it('remove: only a stored license that is not active', async () => {
    const a = await call('POST', '/v1/license', { license: await sign() }); await call('POST', '/v1/license/' + a.body.id + '/activate', {});
    let r = await call('DELETE', '/v1/license/' + a.body.id); assert.strictEqual(r.status, 409); await call('POST', '/v1/license/deactivate', {}); r = await call('DELETE', '/v1/license/' + a.body.id); assert.strictEqual(r.status, 200); assert.strictEqual(db.st.files.length, 0); assert.strictEqual((await call('DELETE', '/v1/license/nope')).status, 400);
  });
  it('the enforcement switch works on a development build only, and takes a boolean', async () => {
    let r = await call('PUT', '/v1/license/enforcement', { enforce: true }); assert.strictEqual(r.status, 200); assert.strictEqual(db.st.enforce, true); for (const bad of [{ enforce: 'yes' }, {}, { enforce: 1 }, { enforce: true, x: 1 }]) assert.strictEqual((await call('PUT', '/v1/license/enforcement', bad)).status, 400);
    require('../src/licensing/build-channel').override({ channel: 'release', version: null }); r = await call('PUT', '/v1/license/enforcement', { enforce: false }); assert.strictEqual(r.status, 409); assert.strictEqual(r.body.error.code, 'LICENSE_ALWAYS_ENFORCED'); assert.strictEqual(db.st.enforce, true);
  });
  it('wiring: reading needs license:read, every change needs license:write, the routes are mounted and never gated, the role gets both permissions', () => {
    const src = read('src/licensing/routes.js');
    const routes = [...src.matchAll(/router\.(get|post|put|patch|delete)\('([^']+)', \.\.\.guarded\('([^']+)'\)/g)].map((m) => m[1].toUpperCase() + ' ' + m[2] + ' ' + m[3]);
    assert.deepStrictEqual(routes, ['GET /v1/license license:read', 'POST /v1/license license:write', 'POST /v1/license/deactivate license:write', 'POST /v1/license/:id/activate license:write', 'DELETE /v1/license/:id license:write', 'PUT /v1/license/enforcement license:write']);
    const g = read('src/gateway/index.js'); assert.ok(g.indexOf("require('../licensing/routes')") > g.indexOf("require('../licensing/gate')") && g.indexOf("require('../licensing/routes')") < g.indexOf("app.get('/v1/health/ready'"));
    assert.strictEqual(require('../src/licensing/gate').moduleOf('/v1/license'), null); assert.ok(/module\.exports = router;/.test(src)); assert.ok(!/console\.(error|log)\([^)]*token/i.test(src));
    const b = read('scripts/deploy/bootstrap-portal.sh'); assert.strictEqual((b.match(/'license:read', 'license:write', 'capacity:read'/g) || []).length, 2);
    const s = read('k8s/12-schema-init.yaml'); for (const re of [/CREATE TABLE IF NOT EXISTS license_files/, /CREATE UNIQUE INDEX IF NOT EXISTS license_files_one_active ON license_files \(active\) WHERE active/, /ADD COLUMN IF NOT EXISTS enforce BOOLEAN NOT NULL DEFAULT FALSE/, /CREATE TABLE IF NOT EXISTS license_notices/]) assert.match(s, re);
  });
});

describe('license notices', () => {
  const notices = require('../src/licensing/notices');
  it('say the right thing at each stage, once per stage and expiry date', () => {
    const base = { customer: 'Acme', expires_at: '2026-12-01T00:00:00.000Z', grace_days: 30 };
    const k = (o) => (notices.stageOf({ ...base, ...o }) || {}).key;
    assert.strictEqual(k({ status: 'valid', expiring: false, days_left: 90 }), undefined); assert.strictEqual(k({ status: 'valid', expiring: true, days_left: 14 }), 'expiring-14|2026-12-01'); assert.strictEqual(k({ status: 'valid', expiring: true, days_left: 8 }), 'expiring-14|2026-12-01'); assert.strictEqual(k({ status: 'valid', expiring: true, days_left: 7 }), 'expiring-7|2026-12-01'); assert.strictEqual(k({ status: 'valid', expiring: true, days_left: 1 }), 'expiring-1|2026-12-01'); assert.strictEqual(k({ status: 'valid', expiring: true, days_left: 0 }), 'expiring-1|2026-12-01');
    assert.strictEqual(k({ status: 'grace', grace_days_left: 30 }), 'grace-w0|2026-12-01'); assert.strictEqual(k({ status: 'grace', grace_days_left: 24 }), 'grace-w0|2026-12-01'); assert.strictEqual(k({ status: 'grace', grace_days_left: 23 }), 'grace-w1|2026-12-01'); assert.strictEqual(k({ status: 'grace', grace_days_left: 1 }), 'grace-last|2026-12-01'); assert.strictEqual(k({ status: 'expired' }), 'lapsed|2026-12-01');
    for (const status of ['none', 'off', 'invalid', 'wrong_install', 'clock_error']) assert.strictEqual(k({ status }), undefined, status);
    assert.strictEqual(notices.stageOf({ status: 'valid' }), null);
    const lapsed = notices.stageOf({ ...base, status: 'expired' }); assert.strictEqual(lapsed.severity, 'critical'); assert.match(lapsed.summary, /not being alerted to attacks/); assert.match(lapsed.summary, /nothing is deleted/);
    assert.match(notices.stageOf({ ...base, status: 'grace', grace_days_left: 5 }).summary, /5 more days/); assert.match(notices.stageOf({ ...base, status: 'valid', expiring: true, days_left: 3 }).title, /3 days/);
  });
  describe('sending', () => {
    let db; const realDb = require('../src/db'); const ch = (n) => ({ tenant: 'T' + n, type: 'slack', config_enc: 'cfg' + n });
    const snap = (license) => async () => ({ license });
    const lapsed = { status: 'expired', customer: 'Acme', expires_at: '2026-12-01T00:00:00.000Z' };
    beforeEach(() => { db = makeDb(); realDb.query = (s, p) => db.query(s, p); });
    it('sends one message to every channel of every tenant, records the stage, and does not send it again', async () => {
      const sent = []; const deps = { snapshot: snap(lapsed), channels: async () => [ch(1), ch(2)], plain: true, send: async (type, cfg, msg) => { sent.push({ type, cfg, msg }); } };
      let r = await notices.runOnce(deps); assert.strictEqual(r.sent, 2); assert.deepStrictEqual(sent.map((x) => x.cfg), ['cfg1', 'cfg2']); assert.strictEqual(sent[0].msg.severity, 'critical'); assert.match(sent[0].msg.title, /lapsed/); assert.strictEqual(sent[0].msg.tenant, 'T1'); assert.ok(db.st.notices.has('lapsed|2026-12-01'));
      r = await notices.runOnce(deps); assert.strictEqual(r.skipped, 'already sent'); assert.strictEqual(sent.length, 2);
    });
    it('if every send fails nothing is recorded and the next cycle tries again; one working channel is enough to record it', async () => {
      let ok = false; const deps = { snapshot: snap(lapsed), channels: async () => [ch(1)], plain: true, send: async () => { if (!ok) throw new Error('slack down'); } };
      let r = await notices.runOnce(deps); assert.strictEqual(r.sent, 0); assert.strictEqual(r.failed, 1); assert.strictEqual(db.st.notices.size, 0);
      ok = true; r = await notices.runOnce(deps); assert.strictEqual(r.sent, 1); assert.strictEqual(db.st.notices.size, 1);
      db.st.notices.clear(); let n = 0; r = await notices.runOnce({ ...deps, channels: async () => [ch(1), ch(2)], send: async () => { if (n++ === 0) throw new Error('first fails'); } }); assert.strictEqual(r.sent, 1); assert.strictEqual(r.failed, 1); assert.strictEqual(db.st.notices.size, 1);
    });
    it('with no channels set up the stage is recorded (the page banner is all there is); a renewal with a new expiry date starts the series again', async () => {
      let r = await notices.runOnce({ snapshot: snap(lapsed), channels: async () => [] }); assert.strictEqual(r.sent, 0); assert.strictEqual(db.st.notices.size, 1);
      const sent = []; r = await notices.runOnce({ snapshot: snap({ ...lapsed, expires_at: '2027-12-01T00:00:00.000Z' }), channels: async () => [ch(1)], plain: true, send: async (t, c, m) => { sent.push(m); } }); assert.strictEqual(r.sent, 1);
    });
    it('a healthy license or a missing one sends nothing', async () => { for (const license of [{ status: 'valid', expiring: false, expires_at: '2027-01-01T00:00:00Z', days_left: 200 }, { status: 'none' }, { status: 'off' }]) { const r = await notices.runOnce({ snapshot: snap(license), channels: async () => { throw new Error('should not be asked'); } }); assert.strictEqual(r.stage, null); } });
    it('goes through the channels directly, not the alert queue, so it still goes out when notifications are locked', () => {
      const src = read('src/licensing/notices.js').replace(/\/\/.*$/gm, ''); assert.ok(!/notification_deliveries/.test(src)); assert.ok(/sendToChannel/.test(src)); assert.ok(!/isEnabled|state === 'enabled'/.test(src)); assert.match(read('src/server.js'), /licensing\/notices'\)\.start\(\)/);
    });
  });
});

describe('the guard the detection workers ask', () => {
  const modules = require('../src/modules'); const gate = require('../src/licensing/worker-gate'); const orig = modules.snapshot;
  const mods = (o) => async () => ({ modules: Object.entries(o).map(([id, state]) => ({ id, state })) });
  it('is true only when every module asked about is enabled; a locked module or an unknown one stops the worker', async () => {
    modules.snapshot = mods({ detections: 'enabled', alerts: 'enabled' }); assert.strictEqual(await gate.enabled('detections', 'alerts'), true);
    modules.snapshot = mods({ detections: 'enabled', alerts: 'locked' }); assert.strictEqual(await gate.enabled('detections', 'alerts'), false);
    modules.snapshot = mods({ detections: 'enabled' }); assert.strictEqual(await gate.enabled('detections', 'alerts'), false); modules.snapshot = orig;
  });
  it('an error reading the module state keeps the worker running (protection is never switched off by a fault) and says so once', async () => {
    const errs = []; const e = console.error; console.error = (m) => errs.push(m); modules.snapshot = async () => { throw new Error('boom'); };
    try { assert.strictEqual(await gate.enabled('detections'), true); assert.strictEqual(await gate.enabled('detections'), true); } finally { console.error = e; modules.snapshot = orig; } assert.strictEqual(errs.length, 1);
  });
  it('the rule runner and the IOC matcher ask before every cycle, and ingestion, retention, capacity and backup workers never do', () => {
    assert.match(read('src/detection/rule-runner.js'), /workerGate\.enabled\('detections', 'alerts'\)/); assert.match(read('src/detection/ioc-matcher.js'), /workerGate\.enabled\('threat-intel', 'alerts'\)/);
    for (const f of ['src/ingest/http-ingest.js', 'src/ingestion/syslog-listener.js', 'src/ingestion/syslog-server.js', 'src/storage/retention.js', 'src/capacity/capacity.js', 'src/ingest/heartbeat.js']) assert.ok(!/worker-gate/.test(read(f)), f);
    assert.ok(fs.readdirSync(path.join(root, 'src/backup')).every((f) => !/worker-gate/.test(read('src/backup/' + f))));
  });
});

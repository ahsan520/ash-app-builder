'use strict';
// Licensing (docs/licensing.md): the license check, the installation id, what runs with no license, the server gate, the vendor tool and the files that wire it in.
const { describe, it, before, beforeEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { spawnSync } = require('child_process');
const { generateKeyPair, exportSPKI, SignJWT } = require('jose');
const license = require('../src/licensing/license');
const modules = require('../src/modules');
const vendor = require('../src/licensing/vendor-keys');
const bundles = require('../src/licensing/bundles');
const installation = require('../src/licensing/installation');
const buildChannel = require('../src/licensing/build-channel');
const gate = require('../src/licensing/gate');
const registry = require('../src/modules/registry');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const IID = '11111111-2222-4333-8444-555555555555', OTHER = '99999999-2222-4333-8444-555555555555';
const NOW = new Date('2026-11-07T12:00:00Z');
let pair, pem, other, otherPem;
before(async () => {
  pair = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true }); pem = await exportSPKI(pair.publicKey);
  other = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true }); otherPem = await exportSPKI(other.publicKey);
});
const KEYS = () => [{ kid: 'k1', pem }];
async function sign(claims = {}, { key, kid = 'k1', exp = '30d', iss = 'asix', sub = 'Acme' } = {}) {
  return new SignJWT({ features: ['alerts'], limits: {}, iid: IID, ...claims }).setProtectedHeader({ alg: 'EdDSA', kid }).setIssuer(iss).setSubject(sub).setIssuedAt(Math.floor(NOW.getTime() / 1000)).setExpirationTime(exp === 'past' ? Math.floor(NOW.getTime() / 1000) - 10 : Math.floor(NOW.getTime() / 1000) + parseInt(exp, 10) * 86400).sign((key || pair.privateKey));
}
const load = (token, opts = {}, env = {}) => license.load({ ASIX_LICENSE: token, ...env }, NOW, { keys: KEYS(), iid: IID, ...opts });

describe('the license check', () => {
  it('accepts a license for this installation and reports who, until when and what', async () => {
    const r = await load(await sign({ features: ['alerts', 'detections'], limits: { tenants: 3, retention_days_max: null }, kind: 'residential' }));
    assert.strictEqual(r.status, 'valid'); assert.strictEqual(r.customer, 'Acme'); assert.strictEqual(r.kind, 'residential'); assert.deepStrictEqual(r.features, ['alerts', 'detections']); assert.deepStrictEqual(r.limits, { tenants: 3, retention_days_max: null }); assert.strictEqual(r.days_left, 30); assert.strictEqual(r.expiring, false);
  });
  it('warns in the last 14 days', async () => { const r = await load(await sign({}, { exp: '10d' })); assert.strictEqual(r.status, 'valid'); assert.strictEqual(r.days_left, 10); assert.strictEqual(r.expiring, true); assert.strictEqual((await load(await sign({}, { exp: '14d' }))).expiring, true); assert.strictEqual((await load(await sign({}, { exp: '15d' }))).expiring, false); });
  it('after expiry there is a 30 day grace: everything still works with status grace; after it the license unlocks nothing', async () => {
    let r = await load(await sign({ features: ['alerts', 'search'] }, { exp: '-1d' })); assert.strictEqual(r.status, 'grace'); assert.deepStrictEqual(r.features, ['alerts', 'search']); assert.strictEqual(r.grace_days, 30); assert.strictEqual(r.grace_days_left, 29); assert.strictEqual(r.expiring, false);
    r = await load(await sign({}, { exp: '-29d' })); assert.strictEqual(r.status, 'grace'); assert.strictEqual(r.grace_days_left, 1);
    r = await load(await sign({}, { exp: '-31d' })); assert.strictEqual(r.status, 'expired'); assert.deepStrictEqual(r.features, []); assert.deepStrictEqual(r.limits, {});
    r = await load(await sign({}, { exp: 'past' })); assert.strictEqual(r.status, 'grace');
  });
  it('the grace period is a signed claim: 0 for a trial ends it on the day, a longer one is honoured, and a changed value breaks the signature', async () => {
    assert.strictEqual((await load(await sign({ grace_days: 0 }, { exp: '-1d' }))).status, 'expired'); assert.strictEqual((await load(await sign({ grace_days: 0 }, { exp: '5d' }))).status, 'valid');
    assert.strictEqual((await load(await sign({ grace_days: 60 }, { exp: '-50d' }))).status, 'grace'); assert.strictEqual((await load(await sign({ grace_days: 60 }, { exp: '-61d' }))).status, 'expired');
    assert.strictEqual((await load(await sign({ grace_days: 500 }, { exp: '-31d' }))).status, 'expired', 'an out-of-range value falls back to 30');
    const t = await sign({ grace_days: 0 }, { exp: '-5d' }); const [h, p, sg] = t.split('.'); const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url').toString()), grace_days: 90 })).toString('base64url');
    assert.strictEqual((await load([h, forged, sg].join('.'))).status, 'invalid');
  });
  it('a stored license (from the database) is used before the environment or a file', async () => { const r = await license.load({ ASIX_LICENSE: 'garbage' }, NOW, { keys: KEYS(), iid: IID, token: await sign({ features: ['alerts'] }) }); assert.strictEqual(r.status, 'valid'); });
  it('refuses a license signed with another key, an unknown key id, a tampered one and one from another issuer', async () => {
    assert.strictEqual((await load(await sign({}, { key: other.privateKey }))).status, 'invalid');
    assert.strictEqual((await load(await sign({}, { kid: 'nope' }))).status, 'invalid');
    const t = await sign({}); const [h, p, s] = t.split('.'); const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url').toString()), features: ['alerts', 'xdr', 'soar'] })).toString('base64url');
    assert.strictEqual((await load([h, forged, s].join('.'))).status, 'invalid');
    assert.strictEqual((await load(await sign({}, { iss: 'someone-else' }))).status, 'invalid');
    for (const bad of ['garbage', 'a.b.c', '....']) assert.strictEqual((await load(bad)).status, 'invalid', bad);
  });
  it('is bound to the installation: another installation, none known, or no id in the license is refused; * works anywhere', async () => {
    assert.strictEqual((await load(await sign({ iid: OTHER }))).status, 'wrong_install');
    assert.strictEqual((await load(await sign({}), { iid: null })).status, 'invalid');
    assert.strictEqual((await load(await sign({ iid: undefined }))).status, 'invalid');
    assert.strictEqual((await load(await sign({ iid: '*' }), { iid: OTHER })).status, 'valid');
  });
  it('a clock set back is noticed and unlocks nothing', async () => { const r = await load(await sign({}), { clockBack: true }); assert.strictEqual(r.status, 'clock_error'); assert.deepStrictEqual(r.features, []); });
  it('with no vendor key built in nothing can be verified', async () => { const r = await load(await sign({}), { keys: [] }); assert.strictEqual(r.status, 'invalid'); assert.match(r.reason, /no vendor key/); });
  it('a key from the environment or a file on the server is NOT trusted: the only keys are the built-in ones', async () => {
    const mine = await sign({ features: ['xdr', 'soar'] }, { key: other.privateKey });
    const r = await license.load({ ASIX_LICENSE: mine, ASIX_LICENSE_PUBKEY: otherPem, ASIX_LICENSE_PUBKEY_FILE: '/etc/asix/license.pub' }, NOW, { keys: KEYS(), iid: IID }); assert.strictEqual(r.status, 'invalid');
    assert.ok(!/ASIX_LICENSE_PUBKEY/.test(read('src/licensing/license.js').replace(/\/\/.*$/gm, '')), 'no code reads a key from the environment');
  });
  it('none, an unreadable file and the default path', async () => {
    assert.strictEqual((await license.load({ ASIX_LICENSE_FILE: '/nonexistent/license.jwt' }, NOW, { keys: KEYS(), iid: IID })).status, 'none');
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'lic-')); fs.writeFileSync(path.join(d, 'l.jwt'), await sign({})); assert.strictEqual((await license.load({ ASIX_LICENSE_FILE: path.join(d, 'l.jwt') }, NOW, { keys: KEYS(), iid: IID })).status, 'valid');
    fs.writeFileSync(path.join(d, 'e.jwt'), ''); assert.strictEqual((await license.load({ ASIX_LICENSE_FILE: path.join(d, 'e.jwt') }, NOW, { keys: KEYS(), iid: IID })).status, 'unreadable');
  });
});

describe('what runs with and without a license', () => {
  const manifests = registry.loadDir();
  const state = (profile, lic) => Object.fromEntries(modules.resolve(manifests, profile, lic).map((m) => [m.id, m.state]));
  const HOME = require('../src/modules/profiles').PROFILES.home, ENT = require('../src/modules/profiles').PROFILES.enterprise;
  it('with no license only the baseline runs: core, ingestion, retention, capacity and the licensing module itself (search is licensed)', () => {
    for (const p of [HOME, ENT]) { const s = state(p, { status: 'none', features: [] }); assert.deepStrictEqual(Object.keys(s).filter((k) => s[k] === 'enabled').sort(), ['capacity', 'core', 'ingestion', 'licensing', 'retention']); }
  });
  it('every license feature is named by a module, and every module feature is in a bundle', () => {
    const used = new Set(manifests.map(bundles.featureFor).filter(Boolean)); for (const f of used) assert.ok(bundles.ALL.includes(f), f); for (const f of bundles.ALL) assert.ok(used.has(f), 'no module uses the feature ' + f);
    assert.deepStrictEqual(bundles.BUNDLES['@enterprise'], [...bundles.RESIDENTIAL, ...bundles.ENTERPRISE_ONLY]); assert.ok(bundles.RESIDENTIAL.every((f) => manifests.find((m) => bundles.featureFor(m) === f).tier === 'home')); assert.ok(bundles.ENTERPRISE_ONLY.every((f) => manifests.find((m) => bundles.featureFor(m) === f).tier === 'enterprise'));
  });
  it('a residential license unlocks the residential modules on the home profile and not the enterprise ones', () => {
    const s = state(HOME, { status: 'valid', features: bundles.BUNDLES['@residential'] });
    for (const id of ['search', 'detections', 'alerts', 'cases', 'actions', 'lists', 'integrations', 'ioc-feeds', 'content-packs', 'dashboards', 'notifications', 'threat-intel']) assert.strictEqual(s[id], 'enabled', id);
    for (const id of ['endpoints', 'compliance', 'mssp', 'posture']) assert.notStrictEqual(s[id], 'enabled', id);
  });
  it('an enterprise license on the enterprise profile unlocks the built enterprise modules; planned ones stay planned; the home profile still locks them', () => {
    const s = state(ENT, { status: 'valid', features: bundles.BUNDLES['@enterprise'] }); assert.strictEqual(s.endpoints, 'enabled'); assert.strictEqual(s.xdr, 'planned');
    assert.notStrictEqual(state(HOME, { status: 'valid', features: bundles.BUNDLES['@enterprise'] }).endpoints, 'enabled');
  });
  it('a feature alone is not enough when what it needs is missing (alerts without detections)', () => { const s = state(HOME, { status: 'valid', features: ['alerts'] }); assert.strictEqual(s.alerts, 'locked'); assert.strictEqual(s.detections, 'locked'); });
  it('an expired (past grace), wrong-installation or clock-error license is the same as none', () => { for (const status of ['expired', 'wrong_install', 'clock_error', 'invalid']) assert.strictEqual(state(HOME, { status, features: [] }).alerts, 'locked', status); });
  it('licensing off turns every module of the edition on, whatever the license says', () => { const s = modules.resolve(manifests, HOME, { status: 'off', mode: 'off', features: [] }); assert.strictEqual(s.find((m) => m.id === 'alerts').state, 'enabled'); assert.strictEqual(s.find((m) => m.id === 'endpoints').state, 'locked'); });
});

describe('the snapshot, with the installation id from the database', () => {
  const fakeDb = (row, fail, o = {}) => ({ queries: [], async query(sql) { this.queries.push(sql); if (fail) throw new Error('db down'); if (/enforce FROM installation/.test(sql)) return { rows: [{ enforce: o.enforce !== false }] }; if (/FROM license_files/.test(sql)) return { rows: o.token ? [{ token: o.token }] : [] }; if (/^SELECT/.test(sql)) return { rows: row ? [row] : [] }; return { rows: [] }; } });
  beforeEach(() => { modules.resetCache(); installation.reset(); vendor.KEYS.length = 0; buildChannel.reset(); });
  const env = (token) => ({ ASIX_PROFILE: 'home', ASIX_LICENSE: token });
  it('a license for this installation unlocks its features; the same license on another installation does not', async () => {
    vendor.KEYS.push(...KEYS()); const token = await sign({ features: bundles.BUNDLES['@residential'], iid: IID });
    let s = await modules.snapshot(env(token), fakeDb({ id: IID, last_seen_at: null })); assert.strictEqual(s.license.status, 'valid'); assert.strictEqual(s.license.installation_id, IID); assert.ok(s.modules.find((m) => m.id === 'alerts').state === 'enabled');
    modules.resetCache(); s = await modules.snapshot(env(token), fakeDb({ id: OTHER, last_seen_at: null })); assert.strictEqual(s.license.status, 'wrong_install'); assert.strictEqual(s.modules.find((m) => m.id === 'alerts').state, 'locked');
  });
  it('shows the installation id even with no license, so a customer can ask for one', async () => { const s = await modules.snapshot({ ASIX_PROFILE: 'home', ASIX_LICENSE_FILE: '/nonexistent' }, fakeDb({ id: IID, last_seen_at: null })); assert.strictEqual(s.license.status, 'none'); assert.strictEqual(s.license.installation_id, IID); });
  it('a clock more than a day behind the last time seen locks the license; a small step back does not', async () => {
    vendor.KEYS.push(...KEYS()); const token = await sign({ iid: IID, features: ['alerts', 'detections'] });
    let s = await modules.snapshot(env(token), fakeDb({ id: IID, last_seen_at: new Date(Date.now() + 3 * 86400000).toISOString() })); assert.strictEqual(s.license.status, 'valid' === s.license.status ? 'clock_error' : s.license.status);
    modules.resetCache(); installation.reset(); s = await modules.snapshot(env(token), fakeDb({ id: IID, last_seen_at: new Date(Date.now() + 3600000).toISOString() })); assert.notStrictEqual(s.license.status, 'clock_error');
  });
  it('the database being down keeps the last answer; with none, the installation counts as unlicensed (not a crash)', async () => {
    buildChannel.override({ channel: 'release', version: null });   // a release build stays on when the database cannot be read (a development build stays off)
    vendor.KEYS.push(...KEYS()); const token = await sign({ iid: IID, features: ['alerts', 'detections'] });
    let s = await modules.snapshot(env(token), fakeDb(null, true)); assert.notStrictEqual(s.license.status, 'valid'); assert.strictEqual(s.modules.find((m) => m.id === 'ingestion').state, 'enabled');
    modules.resetCache(); await modules.snapshot(env(token), fakeDb({ id: IID, last_seen_at: null })); modules.resetCache();
    s = await modules.snapshot(env(token), fakeDb(null, true)); assert.strictEqual(s.license.status, 'valid');
  });
  it('the table row is read as text and the last-seen time only moves forward', async () => {
    const db = fakeDb({ id: IID, last_seen_at: null }); await installation.read(db, NOW); assert.ok(db.queries.some((q) => /GREATEST\(COALESCE\(last_seen_at/.test(q)));
    const bad = await installation.read(fakeDb({ id: 'not-a-uuid', last_seen_at: null })); assert.strictEqual(bad.id, null); assert.strictEqual((await installation.read(fakeDb(null))).id, null);
  });
});

describe('build channel, the enforcement switch and stored licenses', () => {
  const fakeDb = (o = {}) => ({ async query(sql) { if (/enforce FROM installation/.test(sql)) return { rows: [{ enforce: o.enforce === true }] }; if (/FROM license_files/.test(sql)) return { rows: o.token ? [{ token: o.token }] : [] }; if (/^SELECT/.test(sql)) return { rows: [{ id: IID, last_seen_at: null }] }; return { rows: [] }; } });
  beforeEach(() => { modules.resetCache(); installation.reset(); vendor.KEYS.length = 0; buildChannel.reset(); });
  const env = { ASIX_PROFILE: 'enterprise', ASIX_LICENSE_FILE: '/nonexistent' };
  it('a development build with licensing off (the default): every module of the edition is on, and it says so', async () => {
    buildChannel.override({ channel: 'dev', version: null }); const s = await modules.snapshot(env, fakeDb({ enforce: false })); assert.strictEqual(s.license.status, 'off'); assert.strictEqual(s.license.mode, 'off'); assert.strictEqual(s.license.enforce, false); assert.strictEqual(s.license.channel, 'dev'); assert.strictEqual(s.modules.find((m) => m.id === 'search').state, 'enabled'); assert.strictEqual(s.modules.find((m) => m.id === 'endpoints').state, 'enabled');
  });
  it('a development build with enforcement switched on behaves like a customer build', async () => {
    buildChannel.override({ channel: 'dev', version: null }); const s = await modules.snapshot(env, fakeDb({ enforce: true })); assert.strictEqual(s.license.status, 'none'); assert.strictEqual(s.license.enforce, true); assert.strictEqual(s.modules.find((m) => m.id === 'search').state, 'locked');
  });
  it('a release build always enforces, whatever the database says, and ASIX_LICENSE_MODE=open does nothing', async () => {
    buildChannel.override({ channel: 'release', version: '26.4.0' }); const s = await modules.snapshot({ ...env, ASIX_LICENSE_MODE: 'open' }, fakeDb({ enforce: false })); assert.strictEqual(s.license.status, 'none'); assert.strictEqual(s.license.channel, 'release'); assert.strictEqual(s.license.enforce, true); assert.strictEqual(s.modules.find((m) => m.id === 'alerts').state, 'locked'); assert.strictEqual(s.build.version, '26.4.0');
  });
  it('the channel comes from a file in the image, never from the environment', () => {
    const src = read('src/licensing/build-channel.js').replace(/\/\/.*$/gm, ''); assert.ok(!/process\.env/.test(src)); assert.match(read('Dockerfile'), /ARG ASIX_BUILD_CHANNEL=dev/); assert.match(read('Dockerfile'), /build-channel\.json/);
    buildChannel.reset(); assert.strictEqual(buildChannel.get().channel, 'dev');
  });
  it('reads the channel and version from the file the image build writes; anything else (no file, broken file, another word) is a development build', () => {
    const f = buildChannel.FILE, had = fs.existsSync(f) ? fs.readFileSync(f) : null;
    try {
      fs.writeFileSync(f, '{"channel":"release","version":"26.4.1"}\n'); buildChannel.reset(); assert.deepStrictEqual(buildChannel.get(), { channel: 'release', version: '26.4.1' });
      for (const bad of ['{"channel":"RELEASE"}', '{"channel":"prod"}', 'not json', '', '[]', '{"channel":1}']) { fs.writeFileSync(f, bad); buildChannel.reset(); assert.strictEqual(buildChannel.get().channel, 'dev', bad); }
      fs.rmSync(f); buildChannel.reset(); assert.strictEqual(buildChannel.get().channel, 'dev');
    } finally { if (had) fs.writeFileSync(f, had); else fs.rmSync(f, { force: true }); buildChannel.reset(); }
  });
  it('a stored active license is used, and the same license stored but not active is not', async () => {
    buildChannel.override({ channel: 'release', version: null }); vendor.KEYS.push(...KEYS()); const token = await sign({ features: bundles.BUNDLES['@residential'] });
    let s = await modules.snapshot({ ...env, ASIX_PROFILE: 'home' }, fakeDb({ token })); assert.strictEqual(s.license.status, 'valid'); assert.strictEqual(s.license.source, 'stored'); assert.strictEqual(s.modules.find((m) => m.id === 'search').state, 'enabled');
    modules.resetCache(); installation.reset(); s = await modules.snapshot({ ...env, ASIX_PROFILE: 'home' }, fakeDb({})); assert.strictEqual(s.license.status, 'none'); assert.strictEqual(s.modules.find((m) => m.id === 'search').state, 'locked');
  });
  it('in grace everything still works; after grace the licensed modules lock but ingestion, retention and capacity stay', async () => {
    buildChannel.override({ channel: 'release', version: null }); vendor.KEYS.push(...KEYS());
    let s = await modules.snapshot({ ...env, ASIX_PROFILE: 'home' }, fakeDb({ token: await sign({ features: bundles.BUNDLES['@residential'] }, { exp: '-5d' }) })); assert.strictEqual(s.license.status, 'grace'); assert.ok(s.license.grace_days_left >= 22 && s.license.grace_days_left <= 25, 'about 25 days of grace left (the snapshot uses the real clock; tokens are signed against a fixed date)'); assert.strictEqual(s.modules.find((m) => m.id === 'alerts').state, 'enabled');
    modules.resetCache(); installation.reset(); s = await modules.snapshot({ ...env, ASIX_PROFILE: 'home' }, fakeDb({ token: await sign({ features: bundles.BUNDLES['@residential'] }, { exp: '-40d' }) })); assert.strictEqual(s.license.status, 'expired');
    const on = s.modules.filter((m) => m.state === 'enabled').map((m) => m.id).sort(); assert.deepStrictEqual(on, ['capacity', 'core', 'ingestion', 'licensing', 'retention']);
  });
  it('the license store: add, activate (one active at a time), remove (never the active one), enforce switch', async () => {
    const store = require('../src/licensing/license-store'); const rows = []; let enforce = false;
    const db = { async query(sql, p = []) {
      if (/SELECT count/.test(sql)) return { rows: [{ n: rows.length }] };
      if (/^INSERT INTO license_files/.test(sql)) { if (rows.some((r) => r.sha256 === p[2])) { const e = new Error('dup'); e.code = '23505'; throw e; } rows.push({ id: 'id' + rows.length, label: p[0], token: p[1], sha256: p[2], active: false }); return { rows: [{ id: 'id' + (rows.length - 1) }] }; }
      if (/^UPDATE license_files SET active = \(id =/.test(sql)) { const hit = rows.find((r) => r.id === p[0]); rows.forEach((r) => { r.active = r.id === p[0]; }); return { rows: hit ? rows.filter((r) => r.id === p[0] || false).map((r) => ({ id: r.id, active: r.active })) : [] }; }
      if (/^DELETE FROM license_files/.test(sql)) { const i = rows.findIndex((r) => r.id === p[0] && !r.active); if (i >= 0) rows.splice(i, 1); return { rowCount: i >= 0 ? 1 : 0, rows: [] }; }
      if (/^UPDATE installation SET enforce/.test(sql)) { enforce = p[0]; return { rows: [] }; }
      return { rows: [] };
    } };
    const a = await store.add(db, { label: 'trial', token: 't1', sha256: 'h1' }); assert.ok(a.ok); assert.strictEqual((await store.add(db, { label: 'dup', token: 't1', sha256: 'h1' })).code, 'DUPLICATE');
    assert.ok(await store.activate(db, a.id)); assert.strictEqual(await store.remove(db, a.id), false); await store.setEnforce(db, true); assert.strictEqual(enforce, true);
    const b = await store.add(db, { label: 'res', token: 't2', sha256: 'h2' }); assert.ok(await store.activate(db, b.id)); assert.strictEqual(rows.filter((r) => r.active).length, 1); assert.strictEqual(await store.remove(db, a.id), true);
  });
});

describe('the server gate', () => {
  it('maps the locked features to their modules and leaves everything else alone', () => {
    for (const [p, id] of [['/v1/search/xql', 'search'], ['/v1/search/fields', 'search'], ['/v1/detections', 'detections'], ['/v1/detections/rules/1', 'detections'], ['/v1/alerts', 'alerts'], ['/v1/cases', 'cases'], ['/v1/cases/1', 'cases'], ['/v1/actions', 'actions'], ['/v1/lists', 'lists'], ['/v1/lists/1/entries', 'lists'], ['/v1/integrations', 'integrations'], ['/v1/ioc-feeds', 'ioc-feeds'], ['/v1/ioc-feeds/1/run', 'ioc-feeds'], ['/v1/integrations/1/credentials', 'integrations'], ['/v1/my-alerts', 'alerts'], ['/v1/alert-duplicates', 'alerts'], ['/v1/notifications/channels', 'notifications'], ['/v1/threat-intel/feeds', 'threat-intel'], ['/v1/packs', 'content-packs'], ['/v1/endpoints/agents', 'endpoints']]) assert.strictEqual(gate.moduleOf(p), id, p);
    for (const p of ['/v1/storage/retention', '/v1/capacity', '/v1/brokers', '/v1/collectors', '/v1/parsing-rules', '/v1/ingest', '/v1/ingest/http', '/v1/health/ready', '/v1/modules', '/v1/alertsmith', '/v1/detectionsX', '/', '/v1/ingestion-keys', '/v1/list-feed/x', '/v1/listsX']) assert.strictEqual(gate.moduleOf(p), null, p);
    for (const [, id] of gate.MAP) assert.ok(registry.loadDir().some((m) => m.id === id), id);
  });
  it('every route prefix of a licensed module is in the map (a new route file for a locked module cannot be forgotten)', () => {
    const files = fs.readdirSync(path.join(root, 'src/gateway/routes')); const prefixes = new Set();
    for (const f of files) for (const m of read('src/gateway/routes/' + f).matchAll(/router\.(?:get|post|put|patch|delete)\('(\/v1\/[a-z-]+)/g)) prefixes.add(m[1]);
    const baseline = new Set(['/v1/storage', '/v1/capacity', '/v1/brokers', '/v1/broker-settings', '/v1/broker-config', '/v1/collectors', '/v1/collector-watch-defaults', '/v1/ingestion-keys', '/v1/parsing-rules', '/v1/parser', '/v1/data-model-rules', '/v1/modules', '/v1/health', '/v1/ingest', '/v1/license', '/v1/me', '/v1/users', '/v1/roles', '/v1/audit', '/v1/tenants', '/v1/auth']);
    const unknown = [...prefixes].filter((p) => !gate.moduleOf(p) && !baseline.has(p)); assert.deepStrictEqual(unknown, [], 'route prefixes that are neither gated nor listed as baseline: ' + unknown.join(', '));
  });
  const get = (port, p) => new Promise((resolve, reject) => http.get({ port, path: p }, (res) => { let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => resolve({ status: res.statusCode, body: b })); }).on('error', reject));
  it('the real gateway refuses a locked feature with MODULE_LOCKED and never refuses the data plane or baseline routes', async () => {
    delete process.env.ASIX_LICENSE_MODE; process.env.ASIX_PROFILE = 'home'; process.env.ASIX_LICENSE_FILE = '/nonexistent/license.jwt'; delete process.env.ASIX_LICENSE; modules.resetCache(); installation.reset();
    const db = require('../src/db'); const orig = db.query; db.query = async (sql) => (/enforce FROM installation/.test(sql) ? { rows: [{ enforce: true }] } : /FROM license_files/.test(sql) ? { rows: [] } : /^SELECT/.test(sql) ? { rows: [{ id: IID, last_seen_at: null }] } : { rows: [] });
    const server = require('../src/gateway').listen(0);
    try {
      const port = server.address().port;
      for (const p of ['/v1/search/xql', '/v1/alerts', '/v1/cases', '/v1/actions', '/v1/detections', '/v1/notifications', '/v1/threat-intel', '/v1/packs', '/v1/endpoints/agents']) { const r = await get(port, p); assert.strictEqual(r.status, 403, p); const e = JSON.parse(r.body).error; assert.strictEqual(e.code, 'MODULE_LOCKED'); assert.match(e.message, /needs a license/); assert.strictEqual(e.license_status, 'none'); }
      for (const p of ['/', '/v1/modules', '/v1/capacity']) assert.notStrictEqual((await get(port, p)).status, 403, p);
    } finally { server.close(); db.query = orig; modules.resetCache(); }
  });
});

describe('the vendor tool and the files that wire licensing in', () => {
  const tool = (...a) => spawnSync('node', [path.join(root, 'scripts/license-tool.js'), ...a], { encoding: 'utf8' });
  it('keygen, sign and inspect work together, and what it signs verifies against the key it printed', async () => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'lt-')); const k = tool('keygen', d, 'asix-test'); assert.strictEqual(k.status, 0, k.stderr); assert.match(k.stdout, /kid: 'asix-test'/); assert.strictEqual(fs.statSync(path.join(d, 'license-private.pem')).mode & 0o777, 0o600);
    const s = tool('sign', path.join(d, 'license-private.pem'), 'asix-test', 'Smith Home', '30', IID, '@residential', '1', '365'); assert.strictEqual(s.status, 0, s.stderr);
    const r = await license.load({ ASIX_LICENSE: s.stdout.trim() }, new Date(), { keys: [{ kid: 'asix-test', pem: fs.readFileSync(path.join(d, 'license-public.pem'), 'utf8') }], iid: IID });
    assert.strictEqual(r.status, 'valid'); assert.strictEqual(r.kind, 'residential'); assert.deepStrictEqual(r.features, bundles.RESIDENTIAL); assert.deepStrictEqual(r.limits, { tenants: 1, retention_days_max: 365 });
    const e = tool('sign', path.join(d, 'license-private.pem'), 'asix-test', 'Acme', '30', IID, '@enterprise', 'unlimited'); const re = await license.load({ ASIX_LICENSE: e.stdout.trim() }, new Date(), { keys: [{ kid: 'asix-test', pem: fs.readFileSync(path.join(d, 'license-public.pem'), 'utf8') }], iid: IID }); assert.strictEqual(re.kind, 'enterprise'); assert.strictEqual(re.limits.tenants, null);
    assert.match(tool('inspect', s.stdout.trim()).stdout, /"installation": "11111111/);
  });
  it('the tool signs a grace period (0 to 90, default 30 when left out) and refuses one outside it', async () => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'lt-')); tool('keygen', d, 'g1'); const key = path.join(d, 'license-private.pem'); const keys = [{ kid: 'g1', pem: fs.readFileSync(path.join(d, 'license-public.pem'), 'utf8') }];
    const t0 = tool('sign', key, 'g1', 'Trial', '30', IID, '@residential', '1', '30', '0'); assert.strictEqual(t0.status, 0, t0.stderr); assert.match(tool('inspect', t0.stdout.trim()).stdout, /"grace_days": 0/);
    const r0 = await license.load({ ASIX_LICENSE: t0.stdout.trim() }, new Date(Date.now() + 31 * 86400000), { keys, iid: IID }); assert.strictEqual(r0.status, 'expired');
    const t1 = tool('sign', key, 'g1', 'Acme', '30', IID, '@residential'); assert.match(tool('inspect', t1.stdout.trim()).stdout, /default \(30\)/); assert.strictEqual((await license.load({ ASIX_LICENSE: t1.stdout.trim() }, new Date(Date.now() + 31 * 86400000), { keys, iid: IID })).status, 'grace');
    for (const bad of ['-1', '91', 'x']) assert.notStrictEqual(tool('sign', key, 'g1', 'A', '30', IID, '@residential', '1', '30', bad).status, 0, bad);
  });
  it('refuses a bad installation id, an unknown feature and too few arguments', () => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'lt-')); tool('keygen', d); const key = path.join(d, 'license-private.pem');
    assert.notStrictEqual(tool('sign', key, 'k', 'Acme', '30', 'not-a-uuid', '@residential').status, 0); assert.notStrictEqual(tool('sign', key, 'k', 'Acme', '30', IID, 'alerts,nonsense').status, 0); assert.notStrictEqual(tool('sign', key, 'k', 'Acme', '0', IID, '@residential').status, 0); assert.strictEqual(tool('sign', key).status, 2);
  });
  it('the built-in key list is where it should be: a list, empty until the vendor pastes their key', () => { assert.ok(Array.isArray(require('../src/licensing/vendor-keys').KEYS)); assert.match(read('src/licensing/vendor-keys.js'), /fail closed/); });
  it('install-license.sh is valid shell, is executable and refuses what is not a license', () => {
    const f = path.join(root, 'scripts/deploy/install-license.sh'); assert.strictEqual(spawnSync('bash', ['-n', f]).status, 0); assert.ok(fs.statSync(f).mode & 0o111);
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'il-')); fs.writeFileSync(path.join(d, 'bad'), 'not a license\n'); let r = spawnSync('bash', [f, path.join(d, 'bad')], { encoding: 'utf8', env: { ...process.env, KUBECTL: 'false' } }); assert.strictEqual(r.status, 2); assert.match(r.stderr, /does not look like a license/);
    r = spawnSync('bash', [f, path.join(d, 'missing')], { encoding: 'utf8', env: { ...process.env, KUBECTL: 'false' } }); assert.strictEqual(r.status, 2);
  });
  it('the deployment sets the profile and mounts the optional license secret read-only; the schema makes the installation table with one row', () => {
    const y = read('k8s/30-asix-api.yaml'); assert.match(y, /name: ASIX_PROFILE\n\s+value: "home"/); assert.match(y, /mountPath: \/etc\/asix\n\s+readOnly: true/); assert.match(y, /secretName: asix-license\n\s+optional: true/);
    const s = read('k8s/12-schema-init.yaml'); assert.match(s, /CREATE TABLE IF NOT EXISTS installation \(/); assert.match(s, /singleton BOOLEAN NOT NULL DEFAULT TRUE UNIQUE CHECK \(singleton\)/); assert.match(s, /INSERT INTO installation \(singleton\) VALUES \(TRUE\) ON CONFLICT DO NOTHING/);
  });
});

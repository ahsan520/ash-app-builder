'use strict';
// Broker upgrades, first slice (src/brokers/upgrade.js, src/gateway/routes/broker-settings.js, the target in GET /v1/brokers):
// the pure rules, then the real routes with the sign-in chain and the database replaced.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const up = require('../src/brokers/upgrade');
const view = require('../src/brokers/broker-view');

const NOW = Date.UTC(2026, 9, 18, 12, 0, 0);
const row = (o = {}) => ({ id: 'id-1', name: 'broker-1', alias: null, os: 'Vector broker VM', version: 'vector-0.59.0', last_ip: '10.0.0.5', first_seen: new Date(NOW - 1e8), last_seen: new Date(NOW - 60000),
  events_total: '10', connected_within_min: null, key_id: 'k1', installer_name: 'k', key_status: 'active', key_prefix: 'asix_ik_x', key_last_used_at: null, ...o });

describe('versions', () => {
  it('parses plain x.y.z only', () => {
    assert.deepStrictEqual(up.parseVersion('0.59.0'), [0, 59, 0]); assert.deepStrictEqual(up.parseVersion(' 1.2.3 '), [1, 2, 3]);
    for (const v of ['0.59', '0.59.0-rc1', 'v0.59.0', '0.59.0.1', '', null, undefined, 'unknown', '1.2.x', '1e3.0.0']) assert.strictEqual(up.parseVersion(v), null, String(v));
  });
  it('compares numerically, not as text', () => {
    assert.strictEqual(up.compareVersions('0.9.0', '0.59.0'), -1); assert.strictEqual(up.compareVersions('0.60.0', '0.59.9'), 1); assert.strictEqual(up.compareVersions('1.0.0', '1.0.0'), 0);
    assert.strictEqual(up.compareVersions('0.10.0', '0.9.0'), 1); assert.strictEqual(up.compareVersions('unknown', '0.9.0'), null);
  });
  it('checkTarget accepts a version, clears on empty, refuses anything else', () => {
    assert.deepStrictEqual(up.checkTarget('0.60.0'), { value: '0.60.0' }); assert.deepStrictEqual(up.checkTarget(' 0.60.0 '), { value: '0.60.0' });
    for (const v of [null, undefined, '', '   ']) assert.deepStrictEqual(up.checkTarget(v), { value: null });
    for (const v of ['0.60', 'latest', '0.60.0-rc1', 600, true, {}, [], '0.60.0; rm -rf /', '1000.0.0']) assert.ok(up.checkTarget(v).error, JSON.stringify(v));
  });
  it('upgradeState', () => {
    assert.strictEqual(up.upgradeState('0.59.0', null), 'none'); assert.strictEqual(up.upgradeState('0.59.0', '0.60.0'), 'behind');
    assert.strictEqual(up.upgradeState('0.60.0', '0.60.0'), 'current'); assert.strictEqual(up.upgradeState('0.61.0', '0.60.0'), 'ahead');
    assert.strictEqual(up.upgradeState(null, '0.60.0'), 'unknown'); assert.strictEqual(up.upgradeState('unknown', '0.60.0'), 'unknown');
  });
  it('the command names the version, or the newest when there is no target', () => {
    assert.strictEqual(up.upgradeCommand('0.60.0'), 'sudo ./scripts/deploy/upgrade-broker.sh --version 0.60.0'); assert.match(up.upgradeCommand(null), /^sudo \.\/scripts\/deploy\/upgrade-broker\.sh {3}#/);
  });
});

describe('broker view with a target', () => {
  it('flags a broker behind the target without calling it a problem', () => {
    const b = view.shape(row(), { now: NOW, target: '0.60.0' });
    assert.strictEqual(b.upgrade, 'behind'); assert.deepStrictEqual(b.problems, []);
  });
  it('no target: none; same: current; newer: ahead', () => {
    assert.strictEqual(view.shape(row(), { now: NOW }).upgrade, 'none');
    assert.strictEqual(view.shape(row(), { now: NOW, target: '0.59.0' }).upgrade, 'current');
    assert.strictEqual(view.shape(row(), { now: NOW, target: '0.58.0' }).upgrade, 'ahead');
  });
  it('the summary counts the brokers behind', () => {
    const bs = [row({ name: 'a' }), row({ name: 'b', version: 'vector-0.60.0' }), row({ name: 'c', version: 'vector-0.58.1' })].map((r) => view.shape(r, { now: NOW, target: '0.60.0' }));
    assert.strictEqual(view.summarize(bs).behind_target, 2); assert.strictEqual(view.summarize([]).behind_target, 0);
  });
});

describe('routes', () => {
  const TENANT = '11111111-1111-4111-8111-111111111111';
  let stored; let failTarget = false; let writes; let brokerRows;
  const fakeDb = { withTenant: async (t, fn) => fn({ query: async (sql, args) => {
    if (/FROM broker_settings/.test(sql)) { if (failTarget) throw new Error('relation "broker_settings" does not exist'); return { rows: stored === undefined ? [] : [{ vector_target: stored }] }; }
    if (/INSERT INTO broker_settings/.test(sql)) { writes.push(args); stored = args[1]; return { rows: [] }; }
    return { rows: brokerRows };
  } }), query: async () => ({ rows: [] }) };
  const shared = require('../src/gateway/shared');
  const savedShared = require.cache[require.resolve('../src/gateway/shared')].exports;
  let srv; let base;
  before(() => {
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: fakeDb, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'u1'; next(); }] };
    for (const f of ['brokers', 'broker-settings']) delete require.cache[require.resolve('../src/gateway/routes/' + f)];
    require('../src/events').setEventStore({ groupCounts: async () => [] });
    const app = express(); app.use(express.json());
    app.use(require('../src/gateway/routes/brokers')); app.use(require('../src/gateway/routes/broker-settings'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); require.cache[require.resolve('../src/gateway/shared')].exports = savedShared; });
  const call = async (method, p, body) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };

  it('GET with nothing stored: no target, the newest-version command', async () => {
    stored = undefined; writes = [];
    const r = await call('GET', '/v1/broker-settings'); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.settings.vector_target, null); assert.match(r.json.settings.upgrade_command, /upgrade-broker\.sh {3}#/);
  });
  it('PUT stores a valid target for this tenant, and GET returns it', async () => {
    const r = await call('PUT', '/v1/broker-settings', { vector_target: '0.60.0' });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.settings.vector_target, '0.60.0'); assert.match(r.json.settings.upgrade_command, /--version 0\.60\.0$/);
    assert.deepStrictEqual(writes, [[TENANT, '0.60.0', 'u1']]);
    assert.strictEqual((await call('GET', '/v1/broker-settings')).json.settings.vector_target, '0.60.0');
  });
  it('PUT null or empty clears it', async () => {
    for (const v of [null, '']) { stored = '0.60.0'; const r = await call('PUT', '/v1/broker-settings', { vector_target: v }); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.settings.vector_target, null); assert.strictEqual(stored, null); }
  });
  it('PUT refuses a bad body or version and stores nothing', async () => {
    writes = [];
    for (const b of [{}, { other: 1 }, { vector_target: 'latest' }, { vector_target: '0.60' }, { vector_target: 7 }, { vector_target: '0.60.0-rc1' }]) {
      const r = await call('PUT', '/v1/broker-settings', b); assert.strictEqual(r.status, 400, JSON.stringify(b));
    }
    assert.deepStrictEqual(writes, []);
  });
  it('GET /v1/brokers carries the target, the command and each broker\'s upgrade state', async () => {
    stored = '0.60.0'; brokerRows = [row(), row({ name: 'new', version: 'vector-0.60.0' })];
    const r = await call('GET', '/v1/brokers'); assert.strictEqual(r.status, 200);
    assert.strictEqual(r.json.vector_target, '0.60.0'); assert.match(r.json.upgrade_command, /--version 0\.60\.0$/);
    const by = Object.fromEntries(r.json.brokers.map((b) => [b.name, b.upgrade])); assert.deepStrictEqual(by, { 'broker-1': 'behind', new: 'current' }); assert.strictEqual(r.json.summary.behind_target, 1);
  });
  it('the Brokers page still loads when the setting cannot be read', async () => {
    failTarget = true; brokerRows = [row()];
    const r = await call('GET', '/v1/brokers'); failTarget = false;
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.vector_target, null); assert.strictEqual(r.json.brokers[0].upgrade, 'none');
  });
});

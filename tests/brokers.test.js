'use strict';
// Brokers page (src/brokers/broker-view.js and GET /v1/brokers): the pure shaping, then the real route with the
// sign-in chain, the database and the event store replaced.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const view = require('../src/brokers/broker-view');

const NOW = Date.UTC(2026, 9, 17, 12, 0, 0);
const ago = (m) => new Date(NOW - m * 60000);
const row = (o = {}) => ({ id: 'id-' + (o.name || 'b'), name: 'broker-1', alias: null, os: 'Vector broker VM (Ubuntu 24.04)', version: 'vector-0.47.0', last_ip: '10.0.0.5',
  first_seen: ago(5000), last_seen: ago(1), events_total: '1200', connected_within_min: null, key_id: 'k1', installer_name: 'home-broker', key_status: 'active', key_prefix: 'asix_ik_abcd', key_last_used_at: ago(1), ...o });

describe('isBroker', () => {
  it('recognises the heartbeat script\'s version string only', () => {
    assert.strictEqual(view.isBroker(row()), true);
    assert.strictEqual(view.isBroker(row({ version: 'Vector-0.47.0' })), true);
    for (const v of [null, undefined, '', '1.0', 'vector', 'my-vector-1', 'syslog-collector-1']) assert.strictEqual(view.isBroker(row({ version: v })), false, String(v));
    assert.strictEqual(view.isBroker(null), false);
  });
});

describe('shape and problems', () => {
  it('a healthy broker has no problems', () => {
    const b = view.shape(row(), { now: NOW, events24h: 40 });
    assert.strictEqual(b.status, 'connected'); assert.deepStrictEqual(b.problems, []);
    assert.strictEqual(b.vector_version, '0.47.0'); assert.strictEqual(b.events_total, 1200); assert.strictEqual(b.events_24h, 40);
    assert.strictEqual(b.installer.name, 'home-broker'); assert.strictEqual(b.connected_within_min, 15);
  });
  it('uses the collector\'s own connected threshold', () => {
    assert.strictEqual(view.shape(row({ last_seen: ago(40) }), { now: NOW }).status, 'disconnected');
    assert.strictEqual(view.shape(row({ last_seen: ago(40), connected_within_min: 60 }), { now: NOW }).status, 'connected');
  });
  it('says why a disconnected broker is disconnected, with the minutes', () => {
    const b = view.shape(row({ last_seen: ago(90) }), { now: NOW });
    assert.strictEqual(b.problems.length, 1); assert.match(b.problems[0], /Not seen for 90 minutes/); assert.match(b.problems[0], /Vector/);
  });
  it('flags a revoked key, a deleted key, and both reasons together', () => {
    assert.match(view.shape(row({ key_status: 'revoked' }), { now: NOW }).problems[0], /revoked/);
    const gone = view.shape(row({ key_id: null, installer_name: null, key_status: null }), { now: NOW });
    assert.strictEqual(gone.installer, null); assert.match(gone.problems[0], /deleted/);
    assert.strictEqual(view.shape(row({ key_status: 'revoked', last_seen: ago(500) }), { now: NOW }).problems.length, 2);
  });
  it('an unreadable last-seen is reported, not thrown', () => {
    const b = view.shape(row({ last_seen: null }), { now: NOW });
    assert.strictEqual(b.status, 'disconnected'); assert.deepStrictEqual(b.problems, ['Never seen.']);
  });
});

describe('summarize', () => {
  it('counts, sums events and spots mixed Vector versions', () => {
    const list = [view.shape(row({ name: 'a' }), { now: NOW, events24h: 5 }), view.shape(row({ name: 'b', version: 'vector-0.46.1', last_seen: ago(99) }), { now: NOW, events24h: 7 })];
    const s = view.summarize(list);
    assert.deepStrictEqual({ t: s.total, c: s.connected, d: s.disconnected, p: s.with_problems, e: s.events_24h, m: s.mixed_versions }, { t: 2, c: 1, d: 1, p: 1, e: 12, m: true });
    assert.deepStrictEqual(s.versions, { '0.47.0': 1, '0.46.1': 1 });
    assert.strictEqual(view.summarize([]).total, 0); assert.strictEqual(view.summarize([]).mixed_versions, false);
  });
  it('the install command never contains a key', () => assert.ok(!/asix_ik_[A-Za-z0-9]{8}/.test(view.installCommand())));
});

describe('GET /v1/brokers', () => {
  const TENANT = '11111111-1111-4111-8111-111111111111';
  let rows; let seen; let failStore = false;
  const fakeDb = { withTenant: async (t, fn) => fn({ query: async (sql, args) => { seen = { sql, args }; return { rows }; } }), query: async () => ({ rows: [] }) };
  const shared = require('../src/gateway/shared');
  const savedShared = require.cache[require.resolve('../src/gateway/shared')].exports;
  let srv; let base;
  before(async () => {
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: fakeDb, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }] };
    delete require.cache[require.resolve('../src/gateway/routes/brokers')];
    const { setEventStore } = require('../src/events');
    setEventStore({ groupCounts: async () => { if (failStore) throw new Error('store down'); return [{ key: 'broker-1', events: 33 }]; } });
    const app = express(); app.use(require('../src/gateway/routes/brokers'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); require.cache[require.resolve('../src/gateway/shared')].exports = savedShared; });
  const get = async () => { const r = await fetch(base + '/v1/brokers'); return { status: r.status, json: await r.json() }; };

  it('lists brokers with event counts, a summary and the install command; asks only for this tenant\'s vector collectors', async () => {
    rows = [row({ last_seen: new Date(Date.now() - 60000), first_seen: new Date(Date.now() - 1e8) })];
    const r = await get();
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.brokers.length, 1);
    assert.strictEqual(r.json.brokers[0].events_24h, 33); assert.strictEqual(r.json.brokers[0].status, 'connected');
    assert.strictEqual(r.json.summary.total, 1); assert.match(r.json.install_command, /bootstrap-broker\.sh/);
    assert.deepStrictEqual(seen.args, [TENANT, 'vector-%']);
  });
  it('drops rows that are not brokers even if the query returned them', async () => {
    rows = [row({ version: '1.0', name: 'laptop' })];
    assert.strictEqual((await get()).json.brokers.length, 0);
  });
  it('still answers when the event store fails, and says counts are unavailable', async () => {
    failStore = true; rows = [row({ last_seen: new Date() })];
    const r = await get(); failStore = false;
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.brokers[0].events_24h, 0); assert.ok(r.json.counts_error);
  });
});

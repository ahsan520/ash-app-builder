'use strict';
// Collector watchdog (src/collectors/watchdog.js): the pure planning rules, the SQL it sends (database replaced by a
// recorder), and PUT /v1/collectors/:id/watch with the sign-in chain and database replaced.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const wd = require('../src/collectors/watchdog');

const NOW = Date.UTC(2026, 9, 17, 12, 0, 0);
const ago = (m) => new Date(NOW - m * 60000);
const col = (o = {}) => ({ id: 'c1', name: 'broker-1', last_seen: ago(1), connected_within_min: null, ...o });
const iso = (m) => ago(m).toISOString();

describe('plan: raising', () => {
  it('raises nothing for a collector that is connected', () => {
    assert.deepStrictEqual(wd.plan({ collectors: [col()], active: [], latest: [] }, { now: NOW }), { raise: [], close: [] });
  });
  it('raises one alert when a watched collector is past its threshold, with the minutes and the last_seen it was raised for', () => {
    const p = wd.plan({ collectors: [col({ last_seen: ago(40) })], active: [], latest: [] }, { now: NOW });
    assert.strictEqual(p.raise.length, 1); assert.strictEqual(p.close.length, 0);
    assert.deepStrictEqual(p.raise[0], { collector_id: 'c1', name: 'broker-1', group_key: 'collector:c1', last_seen: iso(40), minutes: 40, threshold: 15 });
  });
  it('judges each collector by its own threshold', () => {
    const p = wd.plan({ collectors: [col({ last_seen: ago(40), connected_within_min: 120 }), col({ id: 'c2', name: 'quiet', last_seen: ago(40), connected_within_min: 30 })], active: [], latest: [] }, { now: NOW });
    assert.deepStrictEqual(p.raise.map((r) => r.name), ['quiet']);
    assert.strictEqual(p.raise[0].threshold, 30);
  });
  it('skips a collector that was never seen (no last_seen), instead of throwing', () => {
    assert.deepStrictEqual(wd.plan({ collectors: [col({ last_seen: null })], active: [], latest: [] }, { now: NOW }), { raise: [], close: [] });
  });
  it('does not raise a second alert while one is open or acknowledged', () => {
    for (const status of ['open', 'acknowledged']) {
      const p = wd.plan({ collectors: [col({ last_seen: ago(90) })], active: [{ id: 'a1', group_key: 'collector:c1' }], latest: [{ group_key: 'collector:c1', status, last_seen: iso(90) }] }, { now: NOW });
      assert.deepStrictEqual(p, { raise: [], close: [] }, status);
    }
  });
  it('does not raise again for the same outage after an analyst closed the alert', () => {
    const p = wd.plan({ collectors: [col({ last_seen: ago(90) })], active: [], latest: [{ group_key: 'collector:c1', status: 'closed', last_seen: iso(90) }] }, { now: NOW });
    assert.deepStrictEqual(p, { raise: [], close: [] });
  });
  it('raises again for a new outage (the collector came back, then went quiet again)', () => {
    const p = wd.plan({ collectors: [col({ last_seen: ago(30) })], active: [], latest: [{ group_key: 'collector:c1', status: 'closed', last_seen: iso(600) }] }, { now: NOW });
    assert.strictEqual(p.raise.length, 1); assert.strictEqual(p.raise[0].last_seen, iso(30));
  });
  it('raises nothing during the start-up grace, but still closes', () => {
    const p = wd.plan({ collectors: [col({ last_seen: ago(40) }), col({ id: 'c2', name: 'b2', last_seen: ago(1) })], active: [{ id: 'a2', group_key: 'collector:c2' }], latest: [] }, { now: NOW, raiseAllowed: false });
    assert.strictEqual(p.raise.length, 0); assert.deepStrictEqual(p.close.map((c) => c.alert_id), ['a2']);
  });
});

describe('plan: closing', () => {
  it('closes the alert when the collector is connected again', () => {
    const p = wd.plan({ collectors: [col()], active: [{ id: 'a1', group_key: 'collector:c1' }], latest: [{ group_key: 'collector:c1', status: 'open', last_seen: iso(90) }] }, { now: NOW });
    assert.deepStrictEqual(p.close, [{ alert_id: 'a1', reason: 'The collector is connected again.' }]);
  });
  it('closes the alert when the collector is no longer watched or was deleted (it is not in the watched list)', () => {
    const p = wd.plan({ collectors: [], active: [{ id: 'a1', group_key: 'collector:gone' }], latest: [] }, { now: NOW });
    assert.strictEqual(p.close.length, 1); assert.match(p.close[0].reason, /no longer watched or was removed/);
  });
  it('keeps the alert of a collector that is still down', () => {
    const p = wd.plan({ collectors: [col({ last_seen: ago(90) })], active: [{ id: 'a1', group_key: 'collector:c1' }], latest: [] }, { now: NOW });
    assert.deepStrictEqual(p.close, []);
  });
});

describe('text, severity and settings', () => {
  it('names the collector, the minutes and the threshold', () => {
    const t = wd.raiseText({ name: 'broker-1', minutes: 40, threshold: 15 });
    assert.strictEqual(t.title, 'Collector disconnected: broker-1'); assert.match(t.summary, /40 minutes/); assert.match(t.summary, /within 15/);
  });
  it('defaults to high (a notification channel\'s default minimum) and accepts only the known severities', () => {
    assert.strictEqual(wd.severity({}), 'high'); assert.strictEqual(wd.severity({ ASIX_WATCHDOG_SEVERITY: 'Medium' }), 'medium');
    assert.strictEqual(wd.severity({ ASIX_WATCHDOG_SEVERITY: 'urgent' }), 'high');
  });
});

describe('runTenant writes what plan says (database replaced by a recorder)', () => {
  const db = require('../src/db');
  const saved = db.withTenant;
  after(() => { db.withTenant = saved; });
  it('inserts the alert with a NULL rule, then closes with a note', async () => {
    const calls = [];
    db.withTenant = async (t, fn) => fn({ query: async (sql, args) => {
      calls.push({ sql, args });
      if (/FROM collectors/.test(sql)) return { rows: [{ id: 'c1', name: 'broker-1', last_seen: ago(40), connected_within_min: null }] };
      if (/DISTINCT ON/.test(sql)) return { rows: [] };
      if (/status IN \('open','acknowledged'\)/.test(sql)) return { rows: [{ id: 'old', group_key: 'collector:other' }] };
      return { rows: [] };
    } });
    const r = await wd.runTenant('t1', { now: NOW, sev: 'high' });
    assert.deepStrictEqual(r, { raised: 1, closed: 1 });
    const ins = calls.find((c) => /INSERT INTO alerts/.test(c.sql));
    assert.match(ins.sql, /VALUES \(\$1, NULL, \$2/); assert.strictEqual(ins.args[1], 'Collector disconnected'); assert.strictEqual(ins.args[2], 'high'); assert.strictEqual(ins.args[5], 'collector:c1');
    assert.strictEqual(JSON.parse(ins.args[7]).collector_id, 'c1');
    assert.ok(calls.some((c) => /SET status = 'closed'/.test(c.sql) && c.args[0] === 'old'));
    assert.ok(calls.some((c) => /INSERT INTO alert_notes/.test(c.sql) && c.args[1] === 'old'));
  });
});

describe('PUT /v1/collectors/:id/watch', () => {
  const TENANT = '11111111-1111-4111-8111-111111111111';
  const ID = '22222222-2222-4222-8222-222222222222';
  let rows; let seen;
  const fakeDb = { withTenant: async (t, fn) => fn({ query: async (sql, args) => { seen = { sql, args }; return { rows }; } }), query: async () => ({ rows: [] }) };
  const shared = require('../src/gateway/shared');
  const savedShared = require.cache[require.resolve('../src/gateway/shared')].exports;
  let srv; let base;
  before(() => {
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: fakeDb, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }] };
    delete require.cache[require.resolve('../src/gateway/routes/collector-watch')];
    const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/collector-watch'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); require.cache[require.resolve('../src/gateway/shared')].exports = savedShared; });
  const put = async (id, body) => { const r = await fetch(base + '/v1/collectors/' + id + '/watch', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };

  it('turns it on and off for this tenant\'s collector only', async () => {
    rows = [{ id: ID, name: 'broker-1', watch_disconnect: true }];
    let r = await put(ID, { watch: true });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.collector.watch_disconnect, true);
    assert.deepStrictEqual(seen.args, [ID, true, TENANT]);
    await put(ID, { watch: false }); assert.deepStrictEqual(seen.args, [ID, false, TENANT]);
  });
  it('refuses a bad id, a missing or non-boolean watch, and an unknown collector', async () => {
    assert.strictEqual((await put('nope', { watch: true })).status, 400);
    for (const b of [{}, { watch: 'yes' }, { watch: 1 }, { watch: null }]) assert.strictEqual((await put(ID, b)).status, 400, JSON.stringify(b));
    rows = []; assert.strictEqual((await put(ID, { watch: true })).status, 404);
  });
});

'use strict';
// "Leave out of all" (collectors.watch_exclude): the rules in src/collectors/watch-all.js, then PUT /v1/collectors/:id/watch-exclude
// with the sign-in chain and the database replaced.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const wa = require('../src/collectors/watch-all');

const NOW = Date.UTC(2026, 9, 18, 12, 0, 0);
const c = (o = {}) => ({ watch_disconnect: false, watch_silent_min: null, watch_exclude: false, last_seen: new Date(NOW - 60000), ...o });
const ON = { disconnect: true, silent_min: 60 };

describe('the rules', () => {
  it('a collector left out is not covered by the switch, for either alert', () => {
    assert.strictEqual(wa.watchesDisconnect(c(), ON, NOW), true); assert.strictEqual(wa.watchesDisconnect(c({ watch_exclude: true }), ON, NOW), false);
    assert.strictEqual(wa.silentMinutes(c(), ON, NOW), 60); assert.strictEqual(wa.silentMinutes(c({ watch_exclude: true }), ON, NOW), null);
  });
  it('what was switched on by hand on that collector still applies', () => {
    assert.strictEqual(wa.watchesDisconnect(c({ watch_exclude: true, watch_disconnect: true }), ON, NOW), true);
    assert.strictEqual(wa.silentMinutes(c({ watch_exclude: true, watch_silent_min: 30 }), ON, NOW), 30);
  });
  it('the Collectors page does not say "(all)" for a collector left out', () => {
    assert.strictEqual(wa.disconnectByDefault(c({ watch_exclude: true }), ON, NOW), false); assert.strictEqual(wa.silentByDefault(c({ watch_exclude: true }), ON, NOW), false);
    assert.strictEqual(wa.disconnectByDefault(c(), ON, NOW), true); assert.strictEqual(wa.silentByDefault(c(), ON, NOW), true);
  });
  it('a row with no watch_exclude value (an old query) counts as not left out', () => {
    const { watch_exclude, ...old } = c(); assert.strictEqual(watch_exclude, false);
    assert.strictEqual(wa.watchesDisconnect(old, ON, NOW), true); assert.strictEqual(wa.silentMinutes(old, ON, NOW), 60);
  });
  it('the SQL says the same thing', () => {
    assert.match(wa.WHERE_DISCONNECT, /NOT watch_exclude/); assert.match(wa.SILENT_MIN_SQL, /NOT watch_exclude/);
  });
});

describe('PUT /v1/collectors/:id/watch-exclude', () => {
  const TENANT = '11111111-1111-4111-8111-111111111111'; const ID = '22222222-2222-4222-8222-222222222222';
  let calls; let found = true;
  const fakeDb = { withTenant: async (t, fn) => fn({ query: async (sql, args) => { calls.push({ sql, args }); return { rows: found ? [{ id: args[0], name: 'c1', watch_exclude: args[1] }] : [] }; } }) };
  const shared = require('../src/gateway/shared');
  const saved = require.cache[require.resolve('../src/gateway/shared')].exports;
  let srv; let base;
  before(() => {
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: fakeDb, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }] };
    delete require.cache[require.resolve('../src/gateway/routes/collector-watch-exclude')];
    const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/collector-watch-exclude'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); require.cache[require.resolve('../src/gateway/shared')].exports = saved; });
  const put = async (id, body) => { const r = await fetch(base + '/v1/collectors/' + id + '/watch-exclude', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };

  it('sets and clears the flag, scoped to this tenant', async () => {
    calls = []; let r = await put(ID, { exclude: true }); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.collector.watch_exclude, true);
    assert.deepStrictEqual(calls[0].args, [ID, true, TENANT]); assert.match(calls[0].sql, /tenant_id = \$3/);
    r = await put(ID, { exclude: false }); assert.strictEqual(r.json.collector.watch_exclude, false);
  });
  it('refuses a bad id or body and touches nothing', async () => {
    calls = [];
    assert.strictEqual((await put('not-a-uuid', { exclude: true })).status, 400);
    for (const b of [{}, { exclude: 'yes' }, { exclude: 1 }, { exclude: null }, [true]]) assert.strictEqual((await put(ID, b)).status, 400, JSON.stringify(b));
    assert.deepStrictEqual(calls, []);
  });
  it('another tenant\'s or unknown collector is a 404', async () => {
    found = false; assert.strictEqual((await put(ID, { exclude: true })).status, 404); found = true;
  });
});

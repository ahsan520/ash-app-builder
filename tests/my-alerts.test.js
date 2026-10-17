'use strict';
// "My open alerts": the shaping rules, and the real route with the sign-in chain and database stubbed.
// The SQL itself is covered by tests/my-alerts-db.test.js (needs ASIX_TEST_DB=1).
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const mine = require('../src/alerts/mine');

describe('summarise', () => {
  it('counts by severity and status, and finds the oldest open alert', () => {
    const s = mine.summarise([
      { severity: 'high', status: 'open', n: 2, oldest: '2026-10-10T08:00:00Z' },
      { severity: 'high', status: 'acknowledged', n: 1, oldest: '2026-10-01T08:00:00Z' },   // acknowledged never counts as "unhandled"
      { severity: 'low', status: 'open', n: 4, oldest: new Date('2026-10-05T08:00:00Z') },
    ]);
    assert.deepStrictEqual(s.active, { critical: 0, high: 3, medium: 0, low: 4 });
    assert.strictEqual(s.active_total, 7); assert.strictEqual(s.open, 6); assert.strictEqual(s.acknowledged, 1);
    assert.strictEqual(s.oldest_open_at, '2026-10-05T08:00:00.000Z');
  });
  it('is all zeros and null for nothing, and ignores unknown values', () => {
    for (const rows of [[], undefined, null]) {
      const s = mine.summarise(rows);
      assert.strictEqual(s.active_total, 0); assert.strictEqual(s.open, 0); assert.strictEqual(s.oldest_open_at, null);
    }
    const s = mine.summarise([{ severity: 'weird', status: 'closed', n: 9, oldest: '2026-10-01T00:00:00Z' }]);
    assert.strictEqual(s.active_total, 0); assert.strictEqual(s.open, 0);
  });
});

describe('GET /v1/my-alerts', () => {
  const TENANT = '11111111-1111-4111-8111-111111111111'; const USER = '22222222-2222-4222-8222-222222222222';
  let user = USER; let calls = []; let fail = false;
  const shared = require('../src/gateway/shared');
  const saved = require.cache[require.resolve('../src/gateway/shared')].exports;
  let srv; let base;
  before(() => {
    const fakeDb = { withTenant: async (t, fn) => {
      if (fail) throw new Error('db down');
      return fn({ query: async (sql, params) => {
        calls.push({ sql, params });
        if (/GROUP BY/.test(sql)) return { rows: [{ severity: 'critical', status: 'open', n: 1, oldest: '2026-10-12T00:00:00Z' }] };
        return { rows: [{ id: 'a1', severity: 'critical', status: 'open', title: 'T', event_count: 3, last_event_at: '2026-10-12T00:01:00Z' }] };
      } });
    } };
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: fakeDb, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = user; next(); }] };
    delete require.cache[require.resolve('../src/gateway/routes/my-alerts')];
    const app = express(); app.use(require('../src/gateway/routes/my-alerts'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); require.cache[require.resolve('../src/gateway/shared')].exports = saved; });
  const get = async () => { const r = await fetch(base + '/v1/my-alerts'); return { status: r.status, body: await r.json() }; };

  it('returns the signed-in user\'s counts and top alerts, scoped by tenant and user', async () => {
    calls = [];
    const r = await get();
    assert.strictEqual(r.status, 200); assert.strictEqual(r.body.applicable, true);
    assert.strictEqual(r.body.active.critical, 1); assert.strictEqual(r.body.active_total, 1); assert.strictEqual(r.body.alerts.length, 1);
    assert.strictEqual(calls.length, 2);
    for (const c of calls) { assert.deepStrictEqual(c.params, [TENANT, USER]); assert.match(c.sql, /assignee_id = \$2/); assert.match(c.sql, /status IN \('open', 'acknowledged'\)/); }
  });
  it('a service account (no user) is not applicable and runs no query', async () => {
    calls = []; user = null;
    const r = await get(); user = USER;
    assert.deepStrictEqual(r.body, { success: true, applicable: false }); assert.strictEqual(calls.length, 0);
  });
  it('a database failure is a 500 with a plain message', async () => {
    fail = true; const r = await get(); fail = false;
    assert.strictEqual(r.status, 500); assert.strictEqual(r.body.error.code, 'MY_ALERTS_ERROR');
  });
});

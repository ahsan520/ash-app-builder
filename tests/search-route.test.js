'use strict';
// POST /v1/search/xql end to end through the real route and the event store. Runs in CI on the in-memory store;
// with ASIX_TEST_DB=1 (and DB_HOST / DB_PASSWORD) it also runs on the real Postgres events table.
// Only the sign-in chain is replaced (via require.cache); the route, parser, store and engine are real.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const express = require('express');

let TENANT = crypto.randomUUID();
const shared = require('../src/gateway/shared');
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }],
};
const searchRoutes = require('../src/gateway/routes/search');
const { setEventStore } = require('../src/events');
const { MemoryEventStore } = require('../src/events/memory-store');
const { buildDataset } = require('./fixtures/xql-dataset');

function suite(label, makeStore) {
  describe(`POST /v1/search/xql (${label})`, () => {
    let srv; let base; let cleanup; let ds;
    const post = async (body) => { const r = await fetch(base + '/v1/search/xql', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status, body: await r.json() }; };
    before(async () => {
      ({ cleanup } = await makeStore((t) => { TENANT = t; }));
      ds = buildDataset();
      await require('../src/events').getEventStore().insertBatch(TENANT, ds.events);
      const app = express(); app.use(express.json()); app.use(searchRoutes);
      srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
    });
    after(async () => { if (srv) srv.close(); if (cleanup) await cleanup(); });

    it('raw rows: columns, parsed fields as text, newest first', async () => {
      const { status, body } = await post({ query: 'dataset = syslog | filter host = "web01"' });
      assert.strictEqual(status, 200); assert.strictEqual(body.mode, 'raw'); assert.strictEqual(body.truncated, false);
      assert.strictEqual(body.count, 4);
      assert.deepStrictEqual(body.rows.map((r) => r._raw), ['dup host', 'unicode \u00fcn\u00efc\u00f6d\u00e9 \u65e5\u672c\u8a9e', 'Accepted publickey for ash', 'Failed password for invalid user admin from 203.0.113.9']);
      assert.strictEqual(body.columns[0], '_time'); assert.strictEqual(body.columns[body.columns.length - 1], '_raw');
      assert.ok(body.columns.includes('app_name') && body.columns.includes('host'));
      assert.strictEqual(body.rows[3]._time, '2026-10-01 00:07:00'); assert.strictEqual(body.rows[3].host, 'web01'); assert.strictEqual(body.rows[3].bytes, '100');
      assert.ok(String(body.rows[3].xdm).includes('203.0.113.9'));   // nested objects arrive as JSON text
    });

    it('comp: aggregate columns are text like before', async () => {
      const { body } = await post({ query: 'comp count() as hits, count_distinct(host) as hosts by app_name | sort hits desc, app_name asc' });
      assert.deepStrictEqual(body.columns, ['app_name', 'hits', 'hosts']);
      assert.deepStrictEqual(body.rows[0], { app_name: 'sshd', hits: '3', hosts: '1' });
      assert.ok(body.rows.some((r) => r.app_name === null && r.hits === '2'));
    });

    it('fields mode, limit and truncation', async () => {
      const { body } = await post({ query: 'dataset = syslog | fields host, app_name as app | sort asc _time | limit 3' });
      assert.deepStrictEqual(body.columns, ['host', 'app']);
      assert.deepStrictEqual(body.rows, [{ host: 'web01', app: 'sshd' }, { host: 'web01', app: 'sshd' }, { host: 'web02', app: 'sudo' }]);
      const t = await post({ query: 'dataset = syslog', limit: 2 });
      assert.strictEqual(t.body.count, 2); assert.strictEqual(t.body.truncated, true);
    });

    it('time range: minutes, from and to', async () => {
      assert.strictEqual((await post({ query: 'dataset = syslog', minutes: 5 })).body.count, 0);   // the data is from 2026-10-01
      assert.strictEqual((await post({ query: 'dataset = syslog', from: '2026-10-01T01:07:00Z', to: '2026-10-01T01:30:00Z' })).body.count, 2);
      assert.strictEqual((await post({ query: 'dataset = syslog', from: 'yesterday' })).body.error.code, 'INVALID_TIME');
    });

    it('errors keep their codes', async () => {
      let r = await post({ query: 'filter host =' });
      assert.strictEqual(r.status, 400); assert.strictEqual(r.body.error.code, 'XQL_SYNTAX');
      r = await post({ query: '' }); assert.strictEqual(r.body.error.code, 'XQL_SYNTAX');
      r = await post({ query: 'filter _raw ~= "' + 'a'.repeat(501) + '"' }); assert.strictEqual(r.body.error.code, 'XQL_SYNTAX');
      r = await post({ query: 'sort host | comp count()' });   // compiles in the old compiler, but no engine can run it
      assert.strictEqual(r.status, 400); assert.strictEqual(r.body.error.code, 'XQL_ERROR');
    });
  });
}

suite('memory store', async (setTenant) => {
  setEventStore(new MemoryEventStore());
  setTenant(crypto.randomUUID());
  return { cleanup: async () => setEventStore(null) };
});

if (process.env.ASIX_TEST_DB) {
  const db = require('../src/db');
  const { PostgresEventStore } = require('../src/events/postgres-store');
  suite('postgres store', async (setTenant) => {
    const t = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['search-route-' + Date.now()])).rows[0].id;
    setTenant(t);
    const store = new PostgresEventStore({ db });
    setEventStore(store);
    return { cleanup: async () => { await store.deleteBefore(t, '2999-01-01T00:00:00Z'); await db.query('DELETE FROM tenants WHERE id = $1', [t]); setEventStore(null); } };
  });
  after(() => db.close());
}

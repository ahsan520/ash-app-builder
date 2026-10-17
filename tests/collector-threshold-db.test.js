'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/collector-threshold-db.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected. Real queries; only the sign-in chain
// and the event store are replaced (the counts come from an in-memory store).
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }],
};
const { setEventStore } = require('../src/events'); const { MemoryEventStore } = require('../src/events/memory-store');
setEventStore(new MemoryEventStore());

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['thr-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['thr-b-' + stamp])).rows[0].id;
  const addCollector = async (tenant, name, minutesAgo) => (await db.query(
    "INSERT INTO collectors (tenant_id, name, platform, last_seen) VALUES ($1,$2,'linux', localtimestamp - ($3 || ' minutes')::interval) RETURNING id",
    [tenant, name, String(minutesAgo)])).rows[0].id;
  const slow = await addCollector(TENANT, 'slow-' + stamp, 40);
  const quiet = await addCollector(TENANT, 'quiet-' + stamp, 40);
  const foreign = await addCollector(OTHER, 'foreign-' + stamp, 1);

  const app = express(); app.use(express.json());
  app.use(require('../src/gateway/routes/collectors')); app.use(require('../src/gateway/routes/collector-threshold'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const put = async (id, body) => { const r = await fetch(base + '/v1/collectors/' + id + '/threshold', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const get = async () => Object.fromEntries((await (await fetch(base + '/v1/collectors?limit=500')).json()).collectors.map((c) => [c.name, c]));

  try {
    let by = await get();
    assert.strictEqual(by['slow-' + stamp].status, 'disconnected', '40 minutes ago is past the 15 minute default');
    assert.strictEqual(by['slow-' + stamp].connected_custom, false);

    let r = await put(slow, { minutes: 120 });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.collector.connected_within_min, 120);
    by = await get();
    assert.strictEqual(by['slow-' + stamp].status, 'connected'); assert.strictEqual(by['slow-' + stamp].connected_custom, true);
    assert.strictEqual(by['quiet-' + stamp].status, 'disconnected', 'only the collector that was changed');

    // the value is really in the table, as an integer
    assert.strictEqual((await db.query('SELECT connected_within_min FROM collectors WHERE id = $1', [slow])).rows[0].connected_within_min, 120);

    // another tenant's collector cannot be changed (row-level security and the tenant filter): 404, row untouched
    r = await put(foreign, { minutes: 5 });
    assert.strictEqual(r.status, 404);
    assert.strictEqual((await db.query('SELECT connected_within_min FROM collectors WHERE id = $1', [foreign])).rows[0].connected_within_min, null);

    // back to the default
    r = await put(slow, { minutes: null });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.collector.connected_custom, false);
    assert.strictEqual((await get())['slow-' + stamp].status, 'disconnected');
    assert.strictEqual((await db.query('SELECT connected_within_min FROM collectors WHERE id = $1', [slow])).rows[0].connected_within_min, null);

    // a heartbeat refreshes last_seen and must leave the threshold alone
    await put(quiet, { minutes: 90 });
    await db.withTenant(TENANT, (c) => c.query('UPDATE collectors SET last_seen = localtimestamp WHERE id = $1', [quiet]));
    assert.strictEqual((await get())['quiet-' + stamp].connected_within_min, 90);
    console.log('collector-threshold-db: all checks passed');
  } finally {
    srv.close();
    await db.query('DELETE FROM collectors WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

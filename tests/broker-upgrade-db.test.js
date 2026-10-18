'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-upgrade-db.test.js
// Skips itself otherwise. Real queries and real row-level security; only the sign-in chain and the event store are replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'tester'; next(); }] };
const { setEventStore } = require('../src/events'); const { MemoryEventStore } = require('../src/events/memory-store');
setEventStore(new MemoryEventStore());

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['bup-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['bup-b-' + stamp])).rows[0].id;
  const col = (tenant, name, version) => db.query(
    "INSERT INTO collectors (tenant_id, name, platform, os, version, last_seen) VALUES ($1,$2,'linux','Vector broker VM',$3, localtimestamp)", [tenant, name, version]);
  await col(TENANT, 'old-' + stamp, 'vector-0.47.0'); await col(TENANT, 'new-' + stamp, 'vector-0.60.0'); await col(TENANT, 'odd-' + stamp, 'vector-nightly');

  const app = express(); app.use(express.json());
  app.use(require('../src/gateway/routes/brokers')); app.use(require('../src/gateway/routes/broker-settings'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  try {
    assert.strictEqual((await call('GET', '/v1/broker-settings')).json.settings.vector_target, null, 'no row = no target');
    let r = await call('GET', '/v1/brokers'); assert.ok(r.json.brokers.every((b) => b.upgrade === 'none'));

    assert.strictEqual((await call('PUT', '/v1/broker-settings', { vector_target: '0.60.0' })).status, 200);
    assert.strictEqual((await call('PUT', '/v1/broker-settings', { vector_target: '0.60.1' })).json.settings.vector_target, '0.60.1', 'second save updates the same row');
    assert.strictEqual((await call('PUT', '/v1/broker-settings', { vector_target: '0.60.0' })).json.settings.vector_target, '0.60.0');
    assert.strictEqual((await db.query('SELECT count(*)::int AS n FROM broker_settings WHERE tenant_id = $1', [TENANT])).rows[0].n, 1);
    assert.strictEqual((await db.query('SELECT updated_by FROM broker_settings WHERE tenant_id = $1', [TENANT])).rows[0].updated_by, 'tester');

    r = await call('GET', '/v1/brokers'); const by = Object.fromEntries(r.json.brokers.map((b) => [b.name, b.upgrade]));
    assert.deepStrictEqual(by, { ['old-' + stamp]: 'behind', ['new-' + stamp]: 'current', ['odd-' + stamp]: 'unknown' });
    assert.strictEqual(r.json.vector_target, '0.60.0'); assert.strictEqual(r.json.summary.behind_target, 1);

    // another tenant does not see it, and the database itself refuses a malformed value
    const saved = TENANT; TENANT = OTHER;
    assert.strictEqual((await call('GET', '/v1/broker-settings')).json.settings.vector_target, null, 'another tenant does not see it');
    TENANT = saved;
    await assert.rejects(() => db.withTenant(TENANT, (c) => c.query("UPDATE broker_settings SET vector_target = 'latest' WHERE tenant_id = $1", [TENANT])), /broker_settings_vector_target_check|violates check/);

    assert.strictEqual((await call('PUT', '/v1/broker-settings', { vector_target: null })).status, 200);
    assert.strictEqual((await call('GET', '/v1/broker-settings')).json.settings.vector_target, null, 'cleared');
    console.log('broker-upgrade-db: all checks passed');
  } finally {
    srv.close();
    await db.query('DELETE FROM broker_settings WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM collectors WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

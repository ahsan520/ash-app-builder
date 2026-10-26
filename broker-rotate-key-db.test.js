'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-rotate-key-db.test.js
// Skips itself otherwise. Real queries and the real heartbeat lane; only the sign-in chain is replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
process.env.BROKER_INGEST_TOKEN = 'test-broker-token';
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const { generateKey, hashKey } = require('../src/ingest/http-ingest');
const { setEventStore } = require('../src/events'); const { MemoryEventStore } = require('../src/events/memory-store');
setEventStore(new MemoryEventStore());

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }],
};

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['rot-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['rot-b-' + stamp])).rows[0].id;
  const oldKey = generateKey();
  const oldId = (await db.query("INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,$2,'linux',$3,$4) RETURNING id",
    [TENANT, 'old-' + stamp, oldKey.slice(0, 12), hashKey(oldKey)])).rows[0].id;
  const broker = 'broker-' + stamp;
  const brokerId = (await db.query("INSERT INTO collectors (tenant_id, key_id, name, platform, version) VALUES ($1,$2,$3,'linux','vector-0.47.0') RETURNING id", [TENANT, oldId, broker])).rows[0].id;
  const plainId = (await db.query("INSERT INTO collectors (tenant_id, name, platform, version) VALUES ($1,$2,'linux','1.0') RETURNING id", [TENANT, 'plain-' + stamp])).rows[0].id;
  const foreignId = (await db.query("INSERT INTO collectors (tenant_id, name, platform, version) VALUES ($1,$2,'linux','vector-0.47.0') RETURNING id", [OTHER, 'foreign-' + stamp])).rows[0].id;

  const app = express(); app.use(require('../src/ingest/heartbeat').router); app.use(express.json());
  app.use(require('../src/gateway/routes/brokers')); app.use(require('../src/gateway/routes/collectors'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const post = (p, headers = {}) => fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: '{}' });
  try {
    // another tenant's broker and a non-broker are 404, nothing is created
    assert.strictEqual((await post('/v1/brokers/' + foreignId + '/rotate-key')).status, 404);
    assert.strictEqual((await post('/v1/brokers/' + plainId + '/rotate-key')).status, 404);
    assert.strictEqual((await db.query('SELECT count(*)::int AS n FROM ingestion_keys WHERE tenant_id = $1', [TENANT])).rows[0].n, 1);

    const r = await post('/v1/brokers/' + brokerId + '/rotate-key'); assert.strictEqual(r.status, 201);
    const j = await r.json(); assert.strictEqual(j.old_installer_id, oldId);
    const row = (await db.query('SELECT status, key_hash, key_prefix FROM ingestion_keys WHERE id = $1', [j.installer.id])).rows[0];
    assert.strictEqual(row.status, 'active'); assert.strictEqual(row.key_hash, hashKey(j.key)); assert.notStrictEqual(row.key_hash, j.key);
    assert.strictEqual((await db.query('SELECT status FROM ingestion_keys WHERE id = $1', [oldId])).rows[0].status, 'active', 'the old key still works');
    assert.strictEqual((await post('/v1/brokers/' + brokerId + '/rotate-key')).status, 409, 'same minute, same name');

    // both keys accept a heartbeat; the new one moves the broker onto it, which leaves the old key with no collectors
    assert.strictEqual((await post('/v1/ingest/heartbeat', { authorization: 'Bearer ' + oldKey, 'x-asix-collector': broker })).status, 200);
    assert.strictEqual((await post('/v1/ingest/heartbeat', { authorization: 'Bearer ' + j.key, 'x-asix-collector': broker })).status, 200);
    assert.strictEqual((await db.query('SELECT key_id FROM collectors WHERE id = $1', [brokerId])).rows[0].key_id, j.installer.id);
    const keys = (await (await fetch(base + '/v1/ingestion-keys')).json()).keys;
    assert.strictEqual(keys.find((k) => k.id === oldId).collectors, 0); assert.strictEqual(keys.find((k) => k.id === j.installer.id).collectors, 1);
    const list = (await (await fetch(base + '/v1/brokers')).json()).brokers.find((b) => b.id === brokerId);
    assert.strictEqual(list.installer.id, j.installer.id);

    // revoking the old key (the portal's second button) cuts off the old key only
    assert.strictEqual((await post('/v1/ingestion-keys/' + oldId + '/revoke')).status, 200);
    assert.strictEqual((await post('/v1/ingest/heartbeat', { authorization: 'Bearer ' + oldKey, 'x-asix-collector': broker })).status, 401);
    assert.strictEqual((await post('/v1/ingest/heartbeat', { authorization: 'Bearer ' + j.key, 'x-asix-collector': broker })).status, 200);
    console.log('broker-rotate-key-db: all checks passed');
  } finally {
    srv.close();
    await db.query('DELETE FROM collectors WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM ingestion_keys WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

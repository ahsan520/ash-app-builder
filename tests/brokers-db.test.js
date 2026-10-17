'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/brokers-db.test.js
// Skips itself otherwise. Real queries; only the sign-in chain and the event store are replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }] };
const { setEventStore } = require('../src/events'); const { MemoryEventStore } = require('../src/events/memory-store');
setEventStore(new MemoryEventStore());

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['brk-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['brk-b-' + stamp])).rows[0].id;
  const key = async (tenant, name, status) => (await db.query(
    "INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash, status) VALUES ($1,$2,'linux','asix_ik_test',$3,$4) RETURNING id",
    [tenant, name, require('crypto').randomBytes(32).toString('hex'), status])).rows[0].id;
  const col = (tenant, keyId, name, version, minutesAgo, custom) => db.query(
    "INSERT INTO collectors (tenant_id, key_id, name, platform, os, version, last_seen, connected_within_min) VALUES ($1,$2,$3,'linux','Vector broker VM',$4, localtimestamp - ($5 || ' minutes')::interval, $6)",
    [tenant, keyId, name, version, String(minutesAgo), custom || null]);
  const kOk = await key(TENANT, 'ok-' + stamp, 'active'); const kRev = await key(TENANT, 'rev-' + stamp, 'revoked'); const kOther = await key(OTHER, 'other-' + stamp, 'active');
  await col(TENANT, kOk, 'b-ok-' + stamp, 'vector-0.47.0', 1);
  await col(TENANT, kRev, 'b-rev-' + stamp, 'vector-0.46.1', 1);
  await col(TENANT, null, 'b-nokey-' + stamp, 'vector-0.47.0', 1);
  await col(TENANT, kOk, 'b-slow-' + stamp, 'vector-0.47.0', 40, 120);
  await col(TENANT, kOk, 'laptop-' + stamp, '1.2.3', 1);          // not a broker
  await col(OTHER, kOther, 'b-foreign-' + stamp, 'vector-0.47.0', 1);   // another tenant's broker

  const app = express(); app.use(require('../src/gateway/routes/brokers'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  try {
    const r = await (await fetch(base + '/v1/brokers')).json();
    const by = Object.fromEntries(r.brokers.map((b) => [b.name, b]));
    assert.deepStrictEqual(Object.keys(by).sort(), ['b-nokey-', 'b-ok-', 'b-rev-', 'b-slow-'].map((n) => n + stamp), 'only this tenant\'s vector collectors');
    assert.deepStrictEqual(by['b-ok-' + stamp].problems, []); assert.strictEqual(by['b-ok-' + stamp].installer.name, 'ok-' + stamp);
    assert.match(by['b-rev-' + stamp].problems[0], /revoked/);
    assert.strictEqual(by['b-nokey-' + stamp].installer, null); assert.match(by['b-nokey-' + stamp].problems[0], /deleted/);
    assert.strictEqual(by['b-slow-' + stamp].status, 'connected', '40 minutes ago is inside its own 120 minute threshold');
    assert.strictEqual(r.summary.total, 4); assert.strictEqual(r.summary.mixed_versions, true); assert.strictEqual(r.summary.with_problems, 2);
    console.log('brokers-db: all checks passed');
  } finally {
    srv.close();
    await db.query('DELETE FROM collectors WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM ingestion_keys WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

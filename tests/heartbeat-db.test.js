'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/heartbeat-db.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
process.env.BROKER_INGEST_TOKEN = 'test-broker-token';

const db = require('../src/db');
const shared = require('../src/gateway/shared');
const { generateKey, hashKey } = require('../src/ingest/http-ingest');

let TENANT;
// The Collectors page is behind Keycloak auth; replace only the auth chain, keep every query real.
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }],
};
const heartbeat = require('../src/ingest/heartbeat').router;
const collectorsRoutes = require('../src/gateway/routes/collectors');

async function main() {
  const t = await db.query("INSERT INTO tenants (name) VALUES ($1) RETURNING id", ['hb-test-' + Date.now()]);
  TENANT = t.rows[0].id;
  const key = generateKey();
  const k = await db.withTenant(TENANT, (c) => c.query(
    "INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,'broker-key','linux',$2,$3) RETURNING id",
    [TENANT, key.slice(0, 12), hashKey(key)]));
  const app = express(); app.use(heartbeat); app.use(collectorsRoutes);
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const post = (p, body, headers = {}) => fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
  const list = async () => (await (await fetch(base + '/v1/collectors')).json()).collectors;
  const row = async (name) => (await db.withTenant(TENANT, (c) => c.query('SELECT * FROM collectors WHERE name = $1', [name]))).rows[0];

  try {
    // --- key lane
    assert.strictEqual((await post('/v1/ingest/heartbeat', {}, { authorization: 'Bearer asix_ik_nope' })).status, 401);
    assert.strictEqual((await post('/v1/ingest/heartbeat', {})).status, 401);
    let r = await post('/v1/ingest/heartbeat', { collector: { name: 'broker-1', os: 'Vector broker VM (Ubuntu 24.04)', version: 'vector-0.49.0' } }, { authorization: 'Bearer ' + key });
    assert.strictEqual(r.status, 200); assert.strictEqual((await r.json()).interval_seconds, 60);
    let c = await row('broker-1');
    assert.strictEqual(c.key_id, k.rows[0].id); assert.strictEqual(Number(c.events_total), 0);
    assert.strictEqual(c.os, 'Vector broker VM (Ubuntu 24.04)'); assert.strictEqual(c.platform, 'linux');
    r = await post('/v1/ingest/heartbeat', { collector: { name: 'bad name!' } }, { authorization: 'Bearer ' + key });
    assert.strictEqual(r.status, 400);
    // header-only heartbeat, name falls back to the key's name
    r = await post('/v1/ingest/heartbeat', undefined, { authorization: 'Bearer ' + key });
    assert.strictEqual(r.status, 200); assert.ok(await row('broker-key'));

    // an idle broker whose last_seen is old reads Disconnected, and one heartbeat brings it back
    await db.withTenant(TENANT, (cl) => cl.query("UPDATE collectors SET last_seen = localtimestamp - interval '2 hours' WHERE name = 'broker-1'"));
    assert.strictEqual((await list()).find((x) => x.name === 'broker-1').status, 'disconnected');
    assert.strictEqual((await post('/v1/ingest/heartbeat', {}, { authorization: 'Bearer ' + key, 'x-asix-collector': 'broker-1' })).status, 200);
    let l = (await list()).find((x) => x.name === 'broker-1');
    assert.strictEqual(l.status, 'connected'); assert.strictEqual(l.origin, 'registered'); assert.strictEqual(l.installer, 'broker-key');

    // revoked key stops working
    await db.withTenant(TENANT, (cl) => cl.query("UPDATE ingestion_keys SET status='revoked' WHERE id=$1", [k.rows[0].id]));
    assert.strictEqual((await post('/v1/ingest/heartbeat', {}, { authorization: 'Bearer ' + key })).status, 401);

    // --- built-in lane (shared broker token)
    assert.strictEqual((await post('/v1/ingest/heartbeat/broker', { tenant_id: TENANT, collector_id: 'k8s-syslog-1' })).status, 401);
    const tok = { authorization: 'Bearer test-broker-token' };
    assert.strictEqual((await post('/v1/ingest/heartbeat/broker', { tenant_id: 'not-a-uuid', collector_id: 'k8s-syslog-1' }, tok)).status, 400);
    assert.strictEqual((await post('/v1/ingest/heartbeat/broker', { tenant_id: TENANT, collector_id: 'bad id' }, tok)).status, 400);
    assert.strictEqual((await post('/v1/ingest/heartbeat/broker', { tenant_id: TENANT, collector_id: 'k8s-syslog-1', version: 'syslog-listener' }, tok)).status, 200);
    c = await row('k8s-syslog-1'); assert.strictEqual(c.key_id, null);
    // idle built-in source: no events at all, still Connected, labelled built-in
    l = (await list()).find((x) => x.name === 'k8s-syslog-1');
    assert.strictEqual(l.status, 'connected'); assert.strictEqual(l.origin, 'built-in'); assert.strictEqual(l.events_total, 0);
    // once it has events, the event-derived counts are merged into the same row (no duplicate)
    await db.withTenant(TENANT, (cl) => cl.query(
      "INSERT INTO events (tenant_id, source_type, collector_id, raw) SELECT $1, 'syslog', 'k8s-syslog-1', 'x' FROM generate_series(1,3)", [TENANT]));
    const all = (await list()).filter((x) => x.name === 'k8s-syslog-1');
    assert.strictEqual(all.length, 1); assert.strictEqual(all[0].events_total, 3); assert.strictEqual(all[0].events_24h, 3);
    // event-only source (never sent a heartbeat) still appears as before
    await db.withTenant(TENANT, (cl) => cl.query("INSERT INTO events (tenant_id, source_type, collector_id, raw) VALUES ($1,'syslog','legacy-col','y')", [TENANT]));
    l = (await list()).find((x) => x.name === 'legacy-col');
    assert.strictEqual(l.origin, 'built-in'); assert.strictEqual(l.status, 'connected');
    console.log('heartbeat-db: all checks passed');
  } finally {
    srv.close();
    await db.withTenant(TENANT, async (cl) => {
      await cl.query('DELETE FROM events WHERE tenant_id = $1', [TENANT]);
      await cl.query('DELETE FROM collectors WHERE tenant_id = $1', [TENANT]);
      await cl.query('DELETE FROM ingestion_keys WHERE tenant_id = $1', [TENANT]);
    });
    await db.query('DELETE FROM tenants WHERE id = $1', [TENANT]);
    await db.close();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-config-db.test.js
// Skips itself otherwise. Real queries, real row-level security and the real ingestion-key lookup; only the sign-in chain is replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const { generateKey, hashKey } = require('../src/ingest/http-ingest');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'tester'; next(); }] };

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['bcfg-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['bcfg-b-' + stamp])).rows[0].id;
  const mkKey = async (tenant, name) => { const key = generateKey(); await db.withTenant(tenant, (c) => c.query(
    "INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,$2,'linux',$3,$4)", [tenant, name, key.slice(0, 12), hashKey(key)])); return key; };
  const keyA = await mkKey(TENANT, 'broker-a'), keyB = await mkKey(OTHER, 'broker-b');

  const app = express(); app.use(require('../src/ingest/broker-config').router); app.use(express.json());
  app.use(require('../src/gateway/routes/broker-config')); app.use(require('../src/gateway/routes/broker-settings'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body, headers = {}) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const pull = (key) => call('GET', '/v1/ingest/broker-config', undefined, key ? { authorization: 'Bearer ' + key } : {});
  try {
    // no row yet: no opinion
    assert.strictEqual((await call('GET', '/v1/broker-config')).json.config.syslog_port, null);
    let r = await pull(keyA); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.config.syslog_port, null);

    // set it: the portal route and the broker lane agree
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: 1514 })).status, 200);
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: '1515' })).json.config.syslog_port, 1515, 'second save updates the same row');
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: 1514 })).json.config.syslog_port, 1514);
    assert.strictEqual((await db.query('SELECT count(*)::int AS n FROM broker_settings WHERE tenant_id = $1', [TENANT])).rows[0].n, 1);
    assert.strictEqual((await db.query('SELECT updated_by FROM broker_settings WHERE tenant_id = $1', [TENANT])).rows[0].updated_by, 'tester');
    r = await pull(keyA); assert.deepStrictEqual(r.json.config, { syslog_port: 1514 }); assert.strictEqual(r.json.interval_seconds, 300);

    // the Vector target on the same row is not disturbed by either setting, in either order
    assert.strictEqual((await call('PUT', '/v1/broker-settings', { vector_target: '0.60.0' })).status, 200);
    assert.strictEqual((await call('GET', '/v1/broker-config')).json.config.syslog_port, 1514, 'setting the target keeps the port');
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: 2514 })).status, 200);
    assert.strictEqual((await call('GET', '/v1/broker-settings')).json.settings.vector_target, '0.60.0', 'setting the port keeps the target');

    // refused values change nothing
    for (const bad of [{ syslog_port: 22 }, { syslog_port: 8686 }, { syslog_port: 0 }, { syslog_port: 65536 }, { syslog_port: 'abc' }, {}]) assert.strictEqual((await call('PUT', '/v1/broker-config', bad)).status, 400, JSON.stringify(bad));
    assert.strictEqual((await call('GET', '/v1/broker-config')).json.config.syslog_port, 2514);
    // and the database refuses a bad value even if the application did not
    await assert.rejects(() => db.withTenant(TENANT, (c) => c.query('UPDATE broker_settings SET syslog_port = 70000 WHERE tenant_id = $1', [TENANT])), /broker_settings_syslog_port_check|violates check/);

    // another tenant's broker sees only its own tenant's value
    assert.strictEqual((await pull(keyB)).json.config.syslog_port, null, 'another tenant does not see it');
    const saved = TENANT; TENANT = OTHER; assert.strictEqual((await call('GET', '/v1/broker-config')).json.config.syslog_port, null); TENANT = saved;

    // keys: none, unknown and revoked are refused; a revoked key stops getting config
    assert.strictEqual((await pull()).status, 401); assert.strictEqual((await pull('asix_ik_' + 'z'.repeat(40))).status, 401);
    await db.withTenant(TENANT, (c) => c.query("UPDATE ingestion_keys SET status = 'revoked' WHERE name = 'broker-a'"));
    assert.strictEqual((await pull(keyA)).status, 401);

    // cleared: brokers keep what they have
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: null })).status, 200);
    assert.strictEqual((await pull(keyB)).json.config.syslog_port, null);
    assert.strictEqual((await call('GET', '/v1/broker-config')).json.config.syslog_port, null);
    console.log('broker-config-db: all checks passed');
  } finally {
    srv.close();
    await db.query('DELETE FROM broker_settings WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM ingestion_keys WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

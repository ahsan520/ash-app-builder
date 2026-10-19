'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-port-exclude-db.test.js
// Skips itself otherwise. Leaving ONE broker out of the tenant-wide syslog port: the real routes, real queries, real row-level security and the
// real ingestion-key lookup; only the sign-in chain is replaced.
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
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['bexcl-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['bexcl-b-' + stamp])).rows[0].id;
  const mkKey = async (tenant, name) => { const key = generateKey(); await db.withTenant(tenant, (c) => c.query(
    "INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,$2,'linux',$3,$4)", [tenant, name, key.slice(0, 12), hashKey(key)])); return key; };
  const keyA = await mkKey(TENANT, 'broker-a-key'), keyC = await mkKey(TENANT, 'broker-c-key'), keyB = await mkKey(OTHER, 'broker-b-key');

  const app = express(); app.use(require('../src/ingest/heartbeat').router); app.use(require('../src/ingest/broker-config').router); app.use(express.json());
  app.use(require('../src/gateway/routes/broker-config')); app.use(require('../src/gateway/routes/brokers')); app.use(require('../src/gateway/routes/broker-port')); app.use(require('../src/gateway/routes/broker-port-exclude'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body, headers = {}) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const bearer = (k) => ({ authorization: 'Bearer ' + k });
  const beat = (key, name, version = 'vector-0.59.0') => call('POST', '/v1/ingest/heartbeat', { collector: { name, platform: 'linux', version } }, bearer(key));
  const pull = (key, name) => call('GET', '/v1/ingest/broker-config' + (name ? '?collector=' + encodeURIComponent(name) : ''), undefined, key ? bearer(key) : {});
  const report = (key, body) => call('POST', '/v1/ingest/broker-config/report', body, bearer(key));
  const idOf = async (tenant, name) => (await db.query('SELECT id FROM collectors WHERE tenant_id = $1 AND name = $2', [tenant, name])).rows[0].id;
  const colOf = async (tenant, name) => (await db.query('SELECT syslog_port_exclude FROM collectors WHERE tenant_id = $1 AND name = $2', [tenant, name])).rows[0].syslog_port_exclude;
  const listed = async () => (await call('GET', '/v1/brokers')).json;
  const mine = (l, name) => l.brokers.find((b) => b.name === name);
  try {
    assert.strictEqual((await beat(keyA, 'broker-a')).status, 200); assert.strictEqual((await beat(keyC, 'broker-c')).status, 200); assert.strictEqual((await beat(keyB, 'broker-b')).status, 200);
    await db.withTenant(TENANT, (c) => c.query("INSERT INTO collectors (tenant_id, name, platform, version, events_total) VALUES ($1, 'not-a-broker', 'linux', 'syslog-1.0', 0)", [TENANT]));
    const A = await idOf(TENANT, 'broker-a'), C = await idOf(TENANT, 'broker-c'), B = await idOf(OTHER, 'broker-b'), N = await idOf(TENANT, 'not-a-broker');
    const excl = (id, exclude) => call('PUT', '/v1/brokers/' + id + '/syslog-port-exclude', { exclude });
    const own = (id, port) => call('PUT', '/v1/brokers/' + id + '/syslog-port', { syslog_port: port });

    // a new row is not left out, and the column is a real boolean that cannot be NULL
    assert.strictEqual(await colOf(TENANT, 'broker-a'), false);
    await assert.rejects(() => db.query('UPDATE collectors SET syslog_port_exclude = NULL WHERE tenant_id = $1', [TENANT]), /null value|violates not-null/);
    let l = await listed(); assert.strictEqual(mine(l, 'broker-a').config.excluded, false); assert.strictEqual(l.summary.port_excluded, 0);

    // with a tenant-wide port both brokers are told it; leaving broker-a out stops that for broker-a alone
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: 1514 })).status, 200);
    assert.deepStrictEqual((await pull(keyA, 'broker-a')).json.config, { syslog_port: 1514, tls_port: null });
    let r = await excl(A, true); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json, { success: true, broker: { id: A, name: 'broker-a', syslog_port_exclude: true } });
    assert.strictEqual(await colOf(TENANT, 'broker-a'), true);
    assert.deepStrictEqual((await pull(keyA, 'broker-a')).json.config, { syslog_port: null, tls_port: null }, 'left out: no opinion, it keeps what it has');
    assert.deepStrictEqual((await pull(keyC, 'broker-c')).json.config, { syslog_port: 1514, tls_port: null }, 'another broker still follows the tenant-wide port');
    assert.deepStrictEqual((await pull(keyA)).json.config, { syslog_port: 1514, tls_port: null }, 'an older script that sends no name is told the tenant-wide port');

    // a key reads only its own broker's flag: broker-a's key naming broker-c, broker-c's key naming broker-a, another tenant's key naming broker-a
    assert.strictEqual((await excl(C, true)).status, 200); assert.strictEqual((await excl(C, false)).status, 200);
    assert.deepStrictEqual((await pull(keyC, 'broker-a')).json.config, { syslog_port: 1514, tls_port: null }, 'broker-c\'s key does not see broker-a\'s flag');
    assert.deepStrictEqual((await pull(keyB, 'broker-a')).json.config, { syslog_port: null, tls_port: null }, 'another tenant sees nothing of it');
    assert.deepStrictEqual((await pull(keyA, 'no-such-broker')).json.config, { syslog_port: 1514, tls_port: null }, 'a name with no row is not left out');

    // the Brokers page: nothing asked, state none, what it listens on is still shown, and the summary counts it
    l = await listed(); let a = mine(l, 'broker-a').config;
    assert.strictEqual(a.excluded, true); assert.strictEqual(a.source, 'excluded'); assert.strictEqual(a.state, 'none'); assert.strictEqual(a.configured_port, null); assert.strictEqual(l.summary.port_excluded, 1);
    assert.strictEqual((await report(keyA, { collector: 'broker-a', syslog_port: 514, rejected_port: null })).json.recorded, true);
    l = await listed(); a = mine(l, 'broker-a').config; assert.strictEqual(a.state, 'none'); assert.strictEqual(a.reported_port, 514);
    assert.strictEqual(l.summary.config_applied, 0); assert.strictEqual(l.summary.config_not_applied, 1, 'broker-c is asked for 1514 and has not reported; broker-a is neither');

    // an own port wins over being left out; clearing the own port returns to being left out
    assert.strictEqual((await own(A, 2514)).status, 200);
    assert.deepStrictEqual((await pull(keyA, 'broker-a')).json.config, { syslog_port: 2514, tls_port: null });
    l = await listed(); a = mine(l, 'broker-a').config; assert.strictEqual(a.source, 'broker'); assert.strictEqual(a.excluded, true); assert.strictEqual(a.state, 'pending'); assert.strictEqual(l.summary.port_excluded, 0, 'it has its own port, so it is not counted as left out');
    assert.strictEqual((await own(A, null)).status, 200);
    assert.deepStrictEqual((await pull(keyA, 'broker-a')).json.config, { syslog_port: null, tls_port: null }); assert.strictEqual(mine(await listed(), 'broker-a').config.source, 'excluded');

    // a heartbeat, a report and a tenant-wide save leave the flag alone, and so does changing the tenant-wide port
    assert.strictEqual((await beat(keyA, 'broker-a')).status, 200); assert.strictEqual(await colOf(TENANT, 'broker-a'), true);
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: 4514 })).status, 200); assert.strictEqual(await colOf(TENANT, 'broker-a'), true);
    assert.deepStrictEqual((await pull(keyA, 'broker-a')).json.config, { syslog_port: null, tls_port: null }); assert.deepStrictEqual((await pull(keyC, 'broker-c')).json.config, { syslog_port: 4514, tls_port: null });

    // with no tenant-wide port the flag is kept but there is nothing to be left out of
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: null })).status, 200);
    assert.deepStrictEqual((await pull(keyA, 'broker-a')).json.config, { syslog_port: null, tls_port: null });
    a = mine(await listed(), 'broker-a').config; assert.strictEqual(a.excluded, true); assert.strictEqual(a.source, 'none');
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: 1514 })).status, 200);

    // putting it back: asked for the tenant-wide port again
    r = await excl(A, false); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.broker.syslog_port_exclude, false); assert.strictEqual(await colOf(TENANT, 'broker-a'), false);
    assert.deepStrictEqual((await pull(keyA, 'broker-a')).json.config, { syslog_port: 1514, tls_port: null }); assert.strictEqual(mine(await listed(), 'broker-a').config.source, 'tenant');

    // refused: bad body, a bad id, another tenant's broker, a collector that is not a broker. None of it writes anything.
    for (const bad of [{}, { exclude: 'true' }, { exclude: 1 }, { exclude: null }]) assert.strictEqual((await call('PUT', '/v1/brokers/' + C + '/syslog-port-exclude', bad)).status, 400, JSON.stringify(bad));
    assert.strictEqual((await excl('not-a-uuid', true)).status, 400);
    assert.strictEqual((await excl(B, true)).status, 404, 'another tenant\'s broker'); assert.strictEqual(await colOf(OTHER, 'broker-b'), false);
    assert.strictEqual((await excl(N, true)).status, 404, 'not a broker'); assert.strictEqual(await colOf(TENANT, 'not-a-broker'), false);
    assert.strictEqual((await excl('22222222-2222-4222-8222-222222222222', true)).status, 404);
    assert.strictEqual(await colOf(TENANT, 'broker-c'), false, 'refused requests change nothing');
    { const saved = TENANT; TENANT = OTHER; assert.strictEqual((await excl(C, true)).status, 404, 'broker-c is not the other tenant\'s'); assert.strictEqual((await listed()).summary.port_excluded, 0); TENANT = saved; }

    // a revoked key gets no config at all, named or not
    assert.strictEqual((await excl(C, true)).status, 200);
    await db.withTenant(TENANT, (c) => c.query("UPDATE ingestion_keys SET status = 'revoked' WHERE name = 'broker-c-key'"));
    assert.strictEqual((await pull(keyC, 'broker-c')).status, 401); assert.strictEqual((await pull(keyC)).status, 401);
    console.log('broker-port-exclude-db: all checks passed');
  } finally {
    srv.close();
    await db.query('DELETE FROM broker_settings WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM collectors WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM ingestion_keys WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

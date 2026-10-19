'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-tls-override-db.test.js
// Skips itself otherwise. A syslog-over-TLS port for ONE broker: the real routes, real queries, real row-level security and the real ingestion-key
// lookup; only the sign-in chain is replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const { generateKey, hashKey } = require('../src/ingest/http-ingest');
const config = require('../src/brokers/config');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'tester'; next(); }] };

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['btls-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['btls-b-' + stamp])).rows[0].id;
  const mkKey = async (tenant, name) => { const key = generateKey(); await db.withTenant(tenant, (c) => c.query(
    "INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,$2,'linux',$3,$4)", [tenant, name, key.slice(0, 12), hashKey(key)])); return key; };
  const keyA = await mkKey(TENANT, 'broker-a-key'), keyC = await mkKey(TENANT, 'broker-c-key'), keyB = await mkKey(OTHER, 'broker-b-key');

  const app = express(); app.use(require('../src/ingest/heartbeat').router); app.use(require('../src/ingest/broker-config').router); app.use(express.json());
  app.use(require('../src/gateway/routes/broker-config')); app.use(require('../src/gateway/routes/brokers')); app.use(require('../src/gateway/routes/broker-port'));
  app.use(require('../src/gateway/routes/broker-port-exclude')); app.use(require('../src/gateway/routes/broker-tls-port'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body, headers = {}) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const bearer = (k) => ({ authorization: 'Bearer ' + k });
  const beat = (key, name, version = 'vector-0.59.0') => call('POST', '/v1/ingest/heartbeat', { collector: { name, platform: 'linux', version } }, bearer(key));
  const pull = (key, name) => call('GET', '/v1/ingest/broker-config' + (name ? '?collector=' + encodeURIComponent(name) : ''), undefined, key ? bearer(key) : {});
  const report = (key, body) => call('POST', '/v1/ingest/broker-config/report', body, bearer(key));
  const idOf = async (tenant, name) => (await db.query('SELECT id FROM collectors WHERE tenant_id = $1 AND name = $2', [tenant, name])).rows[0].id;
  const colOf = async (tenant, name) => (await db.query('SELECT tls_port_override FROM collectors WHERE tenant_id = $1 AND name = $2', [tenant, name])).rows[0].tls_port_override;
  const listed = async () => (await call('GET', '/v1/brokers')).json;
  const mine = (l, name) => l.brokers.find((b) => b.name === name);
  try {
    assert.strictEqual((await beat(keyA, 'broker-a')).status, 200); assert.strictEqual((await beat(keyC, 'broker-c')).status, 200); assert.strictEqual((await beat(keyB, 'broker-b')).status, 200);
    await db.withTenant(TENANT, (c) => c.query("INSERT INTO collectors (tenant_id, name, platform, version, events_total) VALUES ($1, 'not-a-broker', 'linux', 'syslog-1.0', 0)", [TENANT]));
    const A = await idOf(TENANT, 'broker-a'), C = await idOf(TENANT, 'broker-c'), B = await idOf(OTHER, 'broker-b'), N = await idOf(TENANT, 'not-a-broker');
    const put = (id, body) => call('PUT', '/v1/brokers/' + id + '/tls-port', body);

    // nothing set anywhere: no opinion, with or without a name
    assert.deepStrictEqual((await pull(keyA, 'broker-a')).json.config, { syslog_port: null, tls_port: null });
    let l = await listed(); assert.strictEqual(mine(l, 'broker-a').tls.source, 'none'); assert.strictEqual(mine(l, 'broker-a').tls.override_port, null); assert.strictEqual(l.summary.tls_port_overrides, 0);

    // an own TLS port for broker-a: only broker-a is told, and only when it names itself
    let r = await put(A, { tls_port: 6515 }); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json, { success: true, broker: { id: A, name: 'broker-a' }, tls_port: 6515 });
    assert.strictEqual(await colOf(TENANT, 'broker-a'), 6515);
    assert.deepStrictEqual((await pull(keyA, 'broker-a')).json.config, { syslog_port: null, tls_port: 6515 }, 'an own TLS port needs no tenant-wide one');
    assert.deepStrictEqual((await pull(keyA)).json.config, { syslog_port: null, tls_port: null }, 'an older script that sends no name gets the tenant-wide answer');
    assert.deepStrictEqual((await pull(keyC, 'broker-c')).json.config, { syslog_port: null, tls_port: null }, 'another broker is not affected');
    r = await put(A, { tls_port: '6516' }); assert.strictEqual(r.json.tls_port, 6516, 'a second save updates the same broker');

    // with a tenant-wide TLS port: the broker with its own keeps it, the others follow the tenant
    assert.strictEqual((await call('PUT', '/v1/broker-config', { tls_port: 6514 })).status, 200);
    assert.deepStrictEqual((await pull(keyA, 'broker-a')).json.config, { syslog_port: null, tls_port: 6516 });
    assert.deepStrictEqual((await pull(keyC, 'broker-c')).json.config, { syslog_port: null, tls_port: 6514 });
    assert.deepStrictEqual((await pull(keyA)).json.config, { syslog_port: null, tls_port: 6514 });
    assert.deepStrictEqual((await pull(keyA, 'no-such-broker')).json.config, { syslog_port: null, tls_port: 6514 }, 'a name with no row falls back to the tenant-wide TLS port');

    // a key reads only its own broker's TLS port: broker-a's key naming broker-c, and another tenant's key naming broker-a
    assert.strictEqual((await put(C, { tls_port: 6517 })).status, 200);
    assert.deepStrictEqual((await pull(keyA, 'broker-c')).json.config, { syslog_port: null, tls_port: 6514 }, 'not broker-c\'s 6517');
    assert.deepStrictEqual((await pull(keyB, 'broker-a')).json.config, { syslog_port: null, tls_port: null }, 'another tenant sees nothing of it');
    assert.deepStrictEqual((await pull(keyC, 'broker-c')).json.config, { syslog_port: null, tls_port: 6517 });

    // the Brokers page: source, own port, and the state is judged against the TLS port THIS broker is asked for
    l = await listed(); assert.strictEqual(l.summary.tls_port_overrides, 2); assert.strictEqual(l.tls_port, 6514);
    assert.strictEqual(mine(l, 'broker-a').tls.state, 'unknown'); assert.strictEqual(mine(l, 'broker-a').tls.configured_port, 6516); assert.strictEqual(mine(l, 'broker-a').tls.source, 'broker');
    assert.strictEqual((await report(keyA, { collector: 'broker-a', syslog_port: 514, rejected_port: null, tls_port: 6516, rejected_tls_port: null })).json.recorded, true);
    assert.strictEqual((await report(keyC, { collector: 'broker-c', syslog_port: 514, rejected_port: null, tls_port: 6514, rejected_tls_port: null })).json.recorded, true);
    l = await listed(); assert.strictEqual(mine(l, 'broker-a').tls.state, 'applied'); assert.strictEqual(mine(l, 'broker-a').tls.override_port, 6516);
    assert.strictEqual(mine(l, 'broker-c').tls.state, 'pending', 'it reports the tenant-wide TLS port but is asked for its own');
    assert.strictEqual(l.summary.tls_applied, 1); assert.strictEqual(l.summary.tls_not_applied, 1);
    assert.strictEqual((await report(keyC, { collector: 'broker-c', syslog_port: 514, rejected_port: null, tls_port: 6514, rejected_tls_port: 6517 })).status, 200);
    assert.strictEqual(mine(await listed(), 'broker-c').tls.state, 'rejected');

    // a heartbeat and a report leave the own TLS port alone, and so does the tenant-wide setting
    assert.strictEqual((await beat(keyA, 'broker-a')).status, 200); assert.strictEqual(await colOf(TENANT, 'broker-a'), 6516);
    assert.strictEqual((await call('PUT', '/v1/broker-config', { tls_port: 6520 })).status, 200); assert.strictEqual(await colOf(TENANT, 'broker-a'), 6516);
    assert.strictEqual((await call('PUT', '/v1/broker-config', { tls_port: 6514 })).status, 200);

    // left out of the tenant-wide ports: told no tenant-wide TLS port, but its OWN TLS port still applies; the syslog-port override of the same broker is separate
    assert.strictEqual((await call('PUT', '/v1/brokers/' + C + '/syslog-port-exclude', { exclude: true })).status, 200);
    assert.strictEqual((await put(C, { tls_port: null })).status, 200);
    assert.deepStrictEqual((await pull(keyC, 'broker-c')).json.config, { syslog_port: null, tls_port: null }, 'left out and no own TLS port: no opinion');
    l = await listed(); assert.strictEqual(mine(l, 'broker-c').tls.state, 'none'); assert.strictEqual(mine(l, 'broker-c').tls.source, 'excluded');
    assert.strictEqual((await put(C, { tls_port: 6518 })).status, 200);
    assert.deepStrictEqual((await pull(keyC, 'broker-c')).json.config, { syslog_port: null, tls_port: 6518 }, 'an own TLS port wins over being left out');
    assert.strictEqual(mine(await listed(), 'broker-c').tls.source, 'broker');
    assert.strictEqual((await call('PUT', '/v1/brokers/' + C + '/syslog-port-exclude', { exclude: false })).status, 200);
    assert.strictEqual((await put(C, { tls_port: 6517 })).status, 200);

    // it must differ from the syslog port THIS broker is asked for (own, else tenant-wide); nothing is written when refused
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: 1514 })).status, 200);
    r = await put(A, { tls_port: 1514 }); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INVALID_TLS_PORT'); assert.strictEqual(await colOf(TENANT, 'broker-a'), 6516);
    assert.strictEqual((await call('PUT', '/v1/brokers/' + A + '/syslog-port', { syslog_port: 2514 })).status, 200);
    assert.strictEqual((await put(A, { tls_port: 2514 })).status, 400, 'its own syslog port wins over the tenant-wide one');
    assert.strictEqual((await put(A, { tls_port: 1514 })).status, 200, 'the tenant-wide syslog port is not broker-a\'s while it has its own');
    assert.deepStrictEqual((await pull(keyA, 'broker-a')).json.config, { syslog_port: 2514, tls_port: 1514 });
    assert.strictEqual((await put(A, { tls_port: 6516 })).status, 200);
    assert.strictEqual((await call('PUT', '/v1/brokers/' + A + '/syslog-port', { syslog_port: null })).status, 200);
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: null })).status, 200);

    // clearing goes back to following the tenant-wide TLS port
    for (const clear of [{ tls_port: null }, { tls_port: '' }]) { assert.strictEqual((await put(A, { tls_port: 6516 })).status, 200); r = await put(A, clear); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.tls_port, null); assert.strictEqual(await colOf(TENANT, 'broker-a'), null); }
    assert.deepStrictEqual((await pull(keyA, 'broker-a')).json.config, { syslog_port: null, tls_port: 6514 });
    assert.strictEqual(mine(await listed(), 'broker-a').tls.source, 'tenant');

    // refused: bad values, a bad id, another tenant's broker, a collector that is not a broker. None of it writes anything.
    for (const bad of [{}, { tls_port: 22 }, { tls_port: 443 }, { tls_port: 8686 }, { tls_port: 30443 }, { tls_port: 0 }, { tls_port: 65536 }, { tls_port: 'abc' }]) assert.strictEqual((await put(C, bad)).status, 400, JSON.stringify(bad));
    assert.strictEqual((await put('not-a-uuid', { tls_port: 6515 })).status, 400);
    assert.strictEqual((await put(B, { tls_port: 6515 })).status, 404, 'another tenant\'s broker'); assert.strictEqual(await colOf(OTHER, 'broker-b'), null);
    assert.strictEqual((await put(N, { tls_port: 6515 })).status, 404, 'not a broker'); assert.strictEqual(await colOf(TENANT, 'not-a-broker'), null);
    assert.strictEqual((await put('22222222-2222-4222-8222-222222222222', { tls_port: 6515 })).status, 404);
    // the write itself also refuses a non-broker and another tenant's broker (a second layer behind the route's own check)
    assert.strictEqual(await db.withTenant(TENANT, (c) => config.writeTlsOverride(c, TENANT, N, 6515)), null); assert.strictEqual(await colOf(TENANT, 'not-a-broker'), null);
    assert.strictEqual(await db.withTenant(TENANT, (c) => config.writeTlsOverride(c, TENANT, B, 6515)), null); assert.strictEqual(await colOf(OTHER, 'broker-b'), null);
    assert.strictEqual(await colOf(TENANT, 'broker-c'), 6517, 'refused values change nothing');
    { const saved = TENANT; TENANT = OTHER; assert.strictEqual((await put(C, { tls_port: 6515 })).status, 404, 'broker-a/c are not this tenant\'s'); assert.strictEqual((await listed()).summary.tls_port_overrides, 0); TENANT = saved; }
    // and the database refuses a bad port even if the application did not
    await assert.rejects(() => db.query('UPDATE collectors SET tls_port_override = 70000 WHERE tenant_id = $1', [TENANT]), /violates check/);
    await assert.rejects(() => db.query('UPDATE collectors SET tls_port_override = 0 WHERE tenant_id = $1', [TENANT]), /violates check/);

    // clashes from the other direction and for the tenant-wide saves (state here: broker-c has its own TLS port 6517, the tenant-wide TLS port is 6514)
    const syslogOwn = (id, v) => call('PUT', '/v1/brokers/' + id + '/syslog-port', { syslog_port: v });
    r = await syslogOwn(C, 6517); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INVALID_SYSLOG_PORT'); assert.match(r.json.error.message, /TLS port/);
    assert.strictEqual((await syslogOwn(A, 6514)).status, 400, 'broker-a follows the tenant-wide TLS port 6514');
    assert.strictEqual((await syslogOwn(C, 6514)).status, 200, 'broker-c has its own TLS port, so 6514 is not its TLS port'); assert.strictEqual((await syslogOwn(C, null)).status, 200);
    r = await call('PUT', '/v1/broker-config', { syslog_port: 6517 }); assert.strictEqual(r.status, 400); assert.match(r.json.error.message, /broker-c/);
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: 6519 })).status, 200);
    assert.strictEqual((await syslogOwn(A, 2599)).status, 200);
    r = await call('PUT', '/v1/broker-config', { tls_port: 2599 }); assert.strictEqual(r.status, 400); assert.strictEqual(r.json.error.code, 'INVALID_TLS_PORT'); assert.match(r.json.error.message, /broker-a/);
    assert.strictEqual((await call('GET', '/v1/broker-config')).json.config.tls_port, 6514, 'a refused save changes nothing');
    assert.strictEqual((await put(A, { tls_port: 2599 })).status, 400, 'and the own-port route refuses it too');
    assert.strictEqual((await call('PUT', '/v1/brokers/' + C + '/syslog-port-exclude', { exclude: true })).status, 200);
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: 6517 })).status, 200, 'a broker that is left out does not follow it, so no clash');
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: null })).status, 200); assert.strictEqual((await syslogOwn(A, null)).status, 200);
    assert.strictEqual((await call('PUT', '/v1/brokers/' + C + '/syslog-port-exclude', { exclude: false })).status, 200);

    // a revoked key gets no config at all, named or not
    await db.withTenant(TENANT, (c) => c.query("UPDATE ingestion_keys SET status = 'revoked' WHERE name = 'broker-c-key'"));
    assert.strictEqual((await pull(keyC, 'broker-c')).status, 401); assert.strictEqual((await pull(keyC)).status, 401);
    console.log('broker-tls-override-db: all checks passed');
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

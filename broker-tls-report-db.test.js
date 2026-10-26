'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-tls-report-db.test.js
// Skips itself otherwise. Whether each broker applied the syslog-over-TLS port, end to end: the real heartbeat creates the rows, the real report route stores
// what a broker says (config_tls_port, config_rejected_tls_port), the real PUT /v1/broker-config sets the tenant-wide TLS port, the real GET /v1/brokers
// shows the state; real row-level security, the real ingestion-key lookup and the real CHECK constraints.
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
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['btls-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['btls-b-' + stamp])).rows[0].id;
  const mkKey = async (tenant, name) => { const key = generateKey(); await db.withTenant(tenant, (c) => c.query(
    "INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,$2,'linux',$3,$4)", [tenant, name, key.slice(0, 12), hashKey(key)])); return key; };
  const keyA = await mkKey(TENANT, 'broker-a'), keyC = await mkKey(TENANT, 'broker-c-key'), keyD = await mkKey(TENANT, 'broker-d-key'), keyB = await mkKey(OTHER, 'broker-b');

  const app = express(); app.use(require('../src/ingest/heartbeat').router); app.use(require('../src/ingest/broker-config').router); app.use(express.json());
  app.use(require('../src/gateway/routes/broker-config')); app.use(require('../src/gateway/routes/brokers')); app.use(require('../src/gateway/routes/broker-port-exclude'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body, headers = {}) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const beat = (key, name) => call('POST', '/v1/ingest/heartbeat', { collector: { name, platform: 'linux', version: 'vector-0.59.0' } }, { authorization: 'Bearer ' + key });
  const report = (key, body) => call('POST', '/v1/ingest/broker-config/report', body, key ? { authorization: 'Bearer ' + key } : {});
  const listed = async () => (await call('GET', '/v1/brokers')).json;
  const bro = async (name) => (await listed()).brokers.find((b) => b.name === name);
  const raw = async (tenant, name) => (await db.query('SELECT config_tls_port, config_rejected_tls_port, config_syslog_port FROM collectors WHERE tenant_id = $1 AND name = $2', [tenant, name])).rows[0];
  const setTls = (v) => call('PUT', '/v1/broker-config', { tls_port: v });
  const base514 = (extra) => ({ syslog_port: 514, rejected_port: null, ...extra });
  try {
    for (const [k, n] of [[keyA, 'broker-a'], [keyC, 'broker-c'], [keyD, 'broker-d'], [keyB, 'broker-b']]) assert.strictEqual((await beat(k, n)).status, 200);

    // a new row: nothing reported, nothing asked
    assert.deepStrictEqual(await raw(TENANT, 'broker-a'), { config_tls_port: null, config_rejected_tls_port: null, config_syslog_port: null });
    let l = await listed(); assert.strictEqual(l.tls_port, null); assert.strictEqual((await bro('broker-a')).tls.state, 'none');

    // a TLS port is asked for but the broker has not said anything about TLS (an older script, or it did not opt in)
    assert.strictEqual((await setTls(6515)).status, 200);
    l = await listed(); assert.strictEqual(l.tls_port, 6515); assert.strictEqual((await bro('broker-a')).tls.state, 'unknown');
    assert.strictEqual(l.summary.tls_not_applied, 4 - 1, 'broker-b belongs to another tenant: three brokers here, none applied');

    // refused bodies write nothing, not even the syslog port
    for (const bad of [0, -1, 70000, 1.5, '65x14', true, {}]) {
      const r = await report(keyA, base514({ collector: 'broker-a', tls_port: bad })); assert.strictEqual(r.status, 400, JSON.stringify(bad)); assert.strictEqual(r.json.error.code, 'BROKER_REPORT_INVALID');
      const r2 = await report(keyA, base514({ collector: 'broker-a', tls_port: 6514, rejected_tls_port: bad })); assert.strictEqual(r2.status, 400, 'rejected ' + JSON.stringify(bad));
    }
    assert.deepStrictEqual(await raw(TENANT, 'broker-a'), { config_tls_port: null, config_rejected_tls_port: null, config_syslog_port: null });
    assert.strictEqual((await report(null, base514({ collector: 'broker-a', tls_port: 6515 }))).status, 401);
    assert.strictEqual((await report('asix_ik_' + 'z'.repeat(40), base514({ collector: 'broker-a', tls_port: 6515 }))).status, 401);
    assert.strictEqual((await raw(TENANT, 'broker-a')).config_tls_port, null);

    // pending: the listener is on the old port
    let r = await report(keyA, base514({ collector: 'broker-a', tls_port: 6514 })); assert.deepStrictEqual(r.json, { success: true, recorded: true });
    assert.deepStrictEqual(await raw(TENANT, 'broker-a'), { config_tls_port: 6514, config_rejected_tls_port: null, config_syslog_port: 514 });
    let b = await bro('broker-a'); assert.strictEqual(b.tls.state, 'pending'); assert.strictEqual(b.tls.reported_port, 6514); assert.strictEqual(b.tls.configured_port, 6515);
    // applied
    await report(keyA, base514({ collector: 'broker-a', tls_port: 6515 })); b = await bro('broker-a'); assert.strictEqual(b.tls.state, 'applied');
    // rejected: it tried 6516, put the old port back
    assert.strictEqual((await setTls(6516)).status, 200);
    await report(keyA, base514({ collector: 'broker-a', tls_port: 6515, rejected_tls_port: 6516 })); b = await bro('broker-a'); assert.strictEqual(b.tls.state, 'rejected'); assert.strictEqual(b.tls.rejected_port, 6516);
    assert.strictEqual((await setTls(6517)).status, 200); assert.strictEqual((await bro('broker-a')).tls.state, 'pending', 'ASIX moved on to another port: no longer rejected');
    assert.strictEqual((await setTls(6515)).status, 200); await report(keyA, base514({ collector: 'broker-a', tls_port: 6515 }));

    // a broker with no TLS listener says so: stored as 0, shown as no_listener, never as a failure
    r = await report(keyC, base514({ collector: 'broker-c', tls_port: null })); assert.strictEqual(r.json.recorded, true);
    assert.strictEqual((await raw(TENANT, 'broker-c')).config_tls_port, 0);
    b = await bro('broker-c'); assert.strictEqual(b.tls.state, 'no_listener'); assert.strictEqual(b.tls.has_listener, false); assert.strictEqual(b.tls.reported_port, null);
    // a broker on an older script reports no TLS fields at all: NULL (never said), not 0
    await report(keyD, base514({ collector: 'broker-d' })); assert.strictEqual((await raw(TENANT, 'broker-d')).config_tls_port, null); assert.strictEqual((await bro('broker-d')).tls.state, 'unknown');

    // the summary
    l = await listed(); assert.deepStrictEqual([l.summary.tls_applied, l.summary.tls_not_applied, l.summary.tls_no_listener], [1, 1, 1]);
    assert.deepStrictEqual((await listed()).brokers.flatMap((x) => x.problems), [], 'information, never a problem');
    assert.strictEqual(l.summary.with_problems, 0);

    // a report from an older script (no TLS fields) clears the old TLS claim; the syslog port part is unaffected
    await report(keyA, base514({ collector: 'broker-a', syslog_port: 1514 })); assert.deepStrictEqual(await raw(TENANT, 'broker-a'), { config_tls_port: null, config_rejected_tls_port: null, config_syslog_port: 1514 });
    await report(keyA, base514({ collector: 'broker-a', tls_port: 6515 }));

    // the next heartbeat does not wipe it
    assert.strictEqual((await beat(keyA, 'broker-a')).status, 200); assert.strictEqual((await raw(TENANT, 'broker-a')).config_tls_port, 6515);

    // a broker left out of the tenant-wide ports is asked for no TLS port: none (and it still says what it listens on)
    assert.strictEqual((await call('PUT', '/v1/brokers/' + (await bro('broker-a')).id + '/syslog-port-exclude', { exclude: true })).status, 200);
    b = await bro('broker-a'); assert.strictEqual(b.tls.state, 'none'); assert.strictEqual(b.tls.reported_port, 6515); assert.strictEqual(b.tls.configured_port, null);
    assert.strictEqual((await call('PUT', '/v1/brokers/' + b.id + '/syslog-port-exclude', { exclude: false })).status, 200); assert.strictEqual((await bro('broker-a')).tls.state, 'applied');

    // clearing the TLS port: nobody is asked
    assert.strictEqual((await setTls(null)).status, 200); l = await listed(); assert.strictEqual(l.tls_port, null);
    assert.deepStrictEqual(l.brokers.map((x) => x.tls.state), ['none', 'none', 'none']);
    assert.strictEqual((await setTls(6515)).status, 200);

    // a key writes only its own broker's row: another key in the same tenant, another tenant's key, a name with no row
    r = await report(keyA, base514({ collector: 'broker-c', tls_port: 6515 })); assert.strictEqual(r.json.recorded, false);
    r = await report(keyB, base514({ collector: 'broker-a', tls_port: 1234 })); assert.strictEqual(r.json.recorded, false);
    r = await report(keyA, base514({ collector: 'ghost', tls_port: 6515 })); assert.strictEqual(r.json.recorded, false);
    assert.strictEqual((await raw(TENANT, 'broker-c')).config_tls_port, 0, 'broker-c\'s claim is its own key\'s to change');
    assert.strictEqual((await raw(TENANT, 'broker-a')).config_tls_port, 6515); assert.strictEqual((await raw(OTHER, 'broker-b')).config_tls_port, null); assert.strictEqual(await raw(TENANT, 'ghost'), undefined);

    // another tenant's page sees only its own broker and no TLS port of ours
    { const saved = TENANT; TENANT = OTHER; const o = await listed(); TENANT = saved; assert.deepStrictEqual(o.brokers.map((x) => x.name), ['broker-b']); assert.strictEqual(o.tls_port, null); assert.strictEqual(o.brokers[0].tls.state, 'none'); }

    // an old report goes stale (a pending one); an applied one stays applied
    await report(keyA, base514({ collector: 'broker-a', tls_port: 6514 }));
    await db.query("UPDATE collectors SET config_reported_at = localtimestamp - interval '1 hour' WHERE tenant_id = $1 AND name = 'broker-a'", [TENANT]);
    assert.strictEqual((await bro('broker-a')).tls.state, 'stale'); assert.strictEqual((await listed()).summary.tls_not_applied >= 1, true);
    await report(keyA, base514({ collector: 'broker-a', tls_port: 6515 }));
    await db.query("UPDATE collectors SET config_reported_at = localtimestamp - interval '1 hour' WHERE tenant_id = $1 AND name = 'broker-a'", [TENANT]);
    assert.strictEqual((await bro('broker-a')).tls.state, 'applied');

    // the database refuses a port out of range even if the application did not
    await assert.rejects(() => db.query('UPDATE collectors SET config_tls_port = 70000 WHERE tenant_id = $1', [TENANT]), /violates check/);
    await assert.rejects(() => db.query('UPDATE collectors SET config_tls_port = -1 WHERE tenant_id = $1', [TENANT]), /violates check/);
    await assert.rejects(() => db.query('UPDATE collectors SET config_rejected_tls_port = 0 WHERE tenant_id = $1', [TENANT]), /violates check/);
    await db.query('UPDATE collectors SET config_tls_port = 0 WHERE tenant_id = $1 AND name = $2', [TENANT, 'broker-c']);   // 0 = no listener is allowed
    console.log('broker-tls-report-db: all checks passed');
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

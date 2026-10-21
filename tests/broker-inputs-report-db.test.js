'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-inputs-report-db.test.js
// Skips itself otherwise. The REAL heartbeat route writes the row and the REAL GET /v1/brokers reads it; only the sign-in chain and the event store are replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const { generateKey, hashKey } = require('../src/ingest/http-ingest');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }] };
const { setEventStore } = require('../src/events'); const { MemoryEventStore } = require('../src/events/memory-store');
setEventStore(new MemoryEventStore());

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['inp-a-' + stamp])).rows[0].id;
  const key = generateKey();
  await db.withTenant(TENANT, (c) => c.query("INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,'inp-key','linux',$2,$3)", [TENANT, key.slice(0, 12), hashKey(key)]));
  const app = express(); app.use(require('../src/ingest/heartbeat').router); app.use(require('../src/gateway/routes/brokers'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const name = 'b-inputs-' + stamp;
  const beat = (collector) => fetch(base + '/v1/ingest/heartbeat', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + key }, body: JSON.stringify({ collector: { name, os: 'Vector broker VM', version: 'vector-0.59.0', ...collector } }) });
  const broker = async () => (await (await fetch(base + '/v1/brokers')).json()).brokers.find((b) => b.name === name);
  const stored = async () => (await db.withTenant(TENANT, (c) => c.query('SELECT inputs FROM collectors WHERE name = $1', [name]))).rows[0].inputs;
  try {
    // an older script sends no inputs: the broker shows, with null
    assert.strictEqual((await beat({})).status, 200);
    assert.strictEqual((await broker()).inputs, null, 'never reported');

    // the first report
    assert.strictEqual((await beat({ inputs: 'syslog:514' })).status, 200);
    assert.deepStrictEqual((await broker()).inputs, [{ kind: 'syslog', port: 514 }]);

    // it changes: more inputs, a moved port
    assert.strictEqual((await beat({ inputs: 'syslog:1514,syslog-tls:6514,file,http:8088' })).status, 200);
    assert.deepStrictEqual((await broker()).inputs, [{ kind: 'syslog', port: 1514 }, { kind: 'syslog-tls', port: 6514 }, { kind: 'file', port: null }, { kind: 'http', port: 8088 }]);
    assert.strictEqual(await stored(), 'syslog:1514,syslog-tls:6514,file,http:8088');

    // an input taken away (re-run of the bootstrap without the flag) disappears
    assert.strictEqual((await beat({ inputs: 'syslog:1514' })).status, 200);
    assert.deepStrictEqual((await broker()).inputs, [{ kind: 'syslog', port: 1514 }]);

    // garbage and unknown names never reach the table, and never refuse the heartbeat; an unusable report keeps what is stored
    assert.strictEqual((await beat({ inputs: "x'; DROP TABLE collectors;--" })).status, 200);
    assert.strictEqual(await stored(), 'syslog:1514', 'nothing usable: the stored value is left alone');
    assert.strictEqual((await beat({ inputs: 'syslog:1514,kafka:9092,file' })).status, 200);
    assert.strictEqual(await stored(), 'syslog:1514,file', 'the unknown name is dropped, the rest kept');
    assert.strictEqual((await beat({ inputs: { a: 1 } })).status, 200);
    assert.strictEqual(await stored(), 'syslog:1514,file');

    // an older script's heartbeat later does not wipe what was reported
    assert.strictEqual((await beat({})).status, 200);
    assert.strictEqual(await stored(), 'syslog:1514,file', 'no inputs sent: kept');

    // the column's own limit holds even if something bypasses the parser
    await assert.rejects(db.withTenant(TENANT, (c) => c.query("UPDATE collectors SET inputs = $1 WHERE name = $2", ['x'.repeat(201), name])));

    // the broker is still a broker and its other fields are unchanged by the report
    const b = await broker(); assert.strictEqual(b.vector_version, '0.59.0'); assert.strictEqual(b.status, 'connected'); assert.deepStrictEqual(b.problems, []);
    console.log('broker-inputs-report-db: all checks passed');
  } finally {
    srv.close();
    await db.query('DELETE FROM collectors WHERE tenant_id = $1', [TENANT]).catch(() => {});
    await db.query('DELETE FROM ingestion_keys WHERE tenant_id = $1', [TENANT]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = $1', [TENANT]).catch(() => {});
    await db.pool.end().catch(() => {});
  }
}
main().then(() => process.exit(0), (e) => { console.error(e); process.exit(1); });

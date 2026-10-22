'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-paused-db.test.js
// Skips itself otherwise. Pausing optional inputs on ONE broker: the real routes, real queries, real row-level security and the real ingestion-key lookup;
// only the sign-in chain is replaced.
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
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['bpz-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['bpz-b-' + stamp])).rows[0].id;
  const mkKey = async (tenant, name) => { const key = generateKey(); await db.withTenant(tenant, (c) => c.query(
    "INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,$2,'linux',$3,$4)", [tenant, name, key.slice(0, 12), hashKey(key)])); return key; };
  const keyA = await mkKey(TENANT, 'bpz-a-key'), keyC = await mkKey(TENANT, 'bpz-c-key'), keyB = await mkKey(OTHER, 'bpz-b-key');

  const app = express(); app.use(require('../src/ingest/heartbeat').router); app.use(require('../src/ingest/broker-config').router); app.use(express.json());
  app.use(require('../src/gateway/routes/brokers')); app.use(require('../src/gateway/routes/broker-inputs'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body, headers = {}) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json().catch(() => null) }; };
  const bearer = (k) => ({ authorization: 'Bearer ' + k });
  const beat = (key, name, version = 'vector-0.59.0') => call('POST', '/v1/ingest/heartbeat', { collector: { name, platform: 'linux', version } }, bearer(key));
  const pull = (key, name) => call('GET', '/v1/ingest/broker-config' + (name ? '?collector=' + encodeURIComponent(name) : ''), undefined, key ? bearer(key) : {});
  const report = (key, body) => call('POST', '/v1/ingest/broker-config/report', body, bearer(key));
  const idOf = async (tenant, name) => (await db.query('SELECT id FROM collectors WHERE tenant_id = $1 AND name = $2', [tenant, name])).rows[0].id;
  const cols = async (tenant, name) => (await db.query('SELECT inputs_paused, config_paused_inputs, config_rejected_paused, config_syslog_port FROM collectors WHERE tenant_id = $1 AND name = $2', [tenant, name])).rows[0];
  const listed = async () => (await call('GET', '/v1/brokers')).json;
  const mine = (l, name) => l.brokers.find((b) => b.name === name);
  const rep = (o = {}) => ({ collector: 'broker-a', syslog_port: 514, rejected_port: null, ...o });
  try {
    assert.strictEqual((await beat(keyA, 'broker-a')).status, 200); assert.strictEqual((await beat(keyC, 'broker-c')).status, 200); assert.strictEqual((await beat(keyB, 'broker-b')).status, 200);
    await db.withTenant(TENANT, (c) => c.query("INSERT INTO collectors (tenant_id, name, platform, version, events_total) VALUES ($1, 'not-a-broker', 'linux', 'syslog-1.0', 0)", [TENANT]));
    const A = await idOf(TENANT, 'broker-a'), B = await idOf(OTHER, 'broker-b'), N = await idOf(TENANT, 'not-a-broker');
    const put = (id, body) => call('PUT', '/v1/brokers/' + id + '/inputs-paused', body);

    // nothing asked: the answer is what it always was
    assert.deepStrictEqual((await pull(keyA, 'broker-a')).json.config, { syslog_port: null, tls_port: null });
    let l = await listed(); assert.strictEqual(mine(l, 'broker-a').inputs_paused.state, 'none'); assert.strictEqual(l.summary.paused_asked, 0);

    // pause two inputs on broker-a: only broker-a, only when it names itself and uses its own key
    let r = await put(A, { paused: ['journald', 'file'] }); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json, { success: true, broker: { id: A, name: 'broker-a' }, paused: ['file', 'journald'] });
    assert.strictEqual((await cols(TENANT, 'broker-a')).inputs_paused, 'file,journald');
    assert.strictEqual((await pull(keyA, 'broker-a')).json.config.paused_inputs, 'file,journald');
    assert.strictEqual((await pull(keyA)).json.config.paused_inputs, undefined, 'no name: told nothing');
    assert.strictEqual((await pull(keyC, 'broker-a')).json.config.paused_inputs, undefined, 'another key in the same tenant naming broker-a reads nothing');
    assert.strictEqual((await pull(keyB, 'broker-a')).json.config.paused_inputs, undefined, 'another tenant\'s key reads nothing');
    assert.strictEqual((await pull(keyC, 'broker-c')).json.config.paused_inputs, undefined, 'another broker is not told');
    l = await listed(); assert.strictEqual(mine(l, 'broker-a').inputs_paused.state, 'unknown'); assert.deepStrictEqual(mine(l, 'broker-a').inputs_paused.asked, ['file', 'journald']); assert.strictEqual(l.summary.paused_asked, 1); assert.strictEqual(l.summary.paused_not_applied, 1);
    assert.deepStrictEqual(mine(l, 'broker-a').problems, [], 'never a problem');

    // the broker reports: applied. Another key, another tenant's key and a name with no row write nothing
    assert.deepStrictEqual((await report(keyA, rep({ paused_inputs: 'file,journald', rejected_paused_inputs: '' }))).json, { success: true, recorded: true });
    assert.deepStrictEqual({ ...(await cols(TENANT, 'broker-a')) }, { inputs_paused: 'file,journald', config_paused_inputs: 'file,journald', config_rejected_paused: null, config_syslog_port: 514 });
    l = await listed(); assert.strictEqual(mine(l, 'broker-a').inputs_paused.state, 'applied'); assert.strictEqual(l.summary.paused_not_applied, 0);
    assert.strictEqual((await report(keyC, rep({ paused_inputs: '' }))).json.recorded, false); assert.strictEqual((await report(keyB, rep({ paused_inputs: '' }))).json.recorded, false);
    assert.strictEqual((await cols(TENANT, 'broker-a')).config_paused_inputs, 'file,journald');

    // a heartbeat, and a report from an older script (no paused fields), leave the stored values alone
    assert.strictEqual((await beat(keyA, 'broker-a')).status, 200); assert.strictEqual((await report(keyA, rep({ syslog_port: 1514 }))).json.recorded, true);
    let c = await cols(TENANT, 'broker-a'); assert.strictEqual(c.inputs_paused, 'file,journald'); assert.strictEqual(c.config_paused_inputs, 'file,journald'); assert.strictEqual(c.config_syslog_port, 1514);

    // resume: the broker is told "" because it still reports something paused; once it reports none, nothing more is said
    r = await put(A, { paused: [] }); assert.strictEqual(r.status, 200); assert.strictEqual((await cols(TENANT, 'broker-a')).inputs_paused, null);
    assert.strictEqual((await pull(keyA, 'broker-a')).json.config.paused_inputs, '');
    assert.strictEqual(mine(await listed(), 'broker-a').inputs_paused.state, 'pending');
    assert.strictEqual((await report(keyA, rep({ paused_inputs: '', rejected_paused_inputs: '' }))).json.recorded, true);
    assert.strictEqual((await cols(TENANT, 'broker-a')).config_paused_inputs, '');
    assert.strictEqual((await pull(keyA, 'broker-a')).json.config.paused_inputs, undefined); assert.strictEqual(mine(await listed(), 'broker-a').inputs_paused.state, 'none');

    // a rejected list is shown as rejected, and a different list asked later is just pending
    await put(A, { paused: ['http'] }); await report(keyA, rep({ paused_inputs: '', rejected_paused_inputs: 'http' }));
    assert.strictEqual(mine(await listed(), 'broker-a').inputs_paused.state, 'rejected'); assert.deepStrictEqual(mine(await listed(), 'broker-a').inputs_paused.rejected, ['http']);
    await put(A, { paused: ['journald'] }); assert.strictEqual(mine(await listed(), 'broker-a').inputs_paused.state, 'pending');
    await put(A, { paused: null });

    // refusals write nothing: syslog, unknown, no body field, a bad id; another tenant's broker and a non-broker are 404
    const before = (await cols(TENANT, 'broker-a')).inputs_paused;
    for (const bad of [{ paused: ['syslog'] }, { paused: ['file', 'syslog-tls'] }, { paused: 'nope' }, {}, { paused: [5] }]) assert.strictEqual((await put(A, bad)).status, 400, JSON.stringify(bad));
    assert.strictEqual((await put('not-a-uuid', { paused: ['file'] })).status, 400); assert.strictEqual((await cols(TENANT, 'broker-a')).inputs_paused, before);
    assert.strictEqual((await put(B, { paused: ['file'] })).status, 404); assert.strictEqual((await put(N, { paused: ['file'] })).status, 404);
    assert.strictEqual((await cols(OTHER, 'broker-b')).inputs_paused, null); assert.strictEqual((await cols(TENANT, 'not-a-broker')).inputs_paused, null);

    // a bad report is a 400 and writes nothing, not even the port; the database CHECKs refuse a value outside the list
    assert.strictEqual((await report(keyA, rep({ syslog_port: 2514, paused_inputs: 'syslog' }))).status, 400); assert.strictEqual((await cols(TENANT, 'broker-a')).config_syslog_port, 514, 'the last good report stands');
    for (const sql of ["UPDATE collectors SET inputs_paused = 'file;x' WHERE name = 'broker-a'", "UPDATE collectors SET config_paused_inputs = 'FILE' WHERE name = 'broker-a'", "UPDATE collectors SET inputs_paused = '' WHERE name = 'broker-a'", "UPDATE collectors SET config_rejected_paused = 'Http' WHERE name = 'broker-a'"]) {
      await assert.rejects(db.withTenant(TENANT, (cl) => cl.query(sql)), /check constraint/, sql);
    }
    console.log('broker-paused-db: ok');
  } finally {
    srv.close();
    for (const t of [TENANT, OTHER]) { await db.query('DELETE FROM collectors WHERE tenant_id = $1', [t]); await db.query('DELETE FROM ingestion_keys WHERE tenant_id = $1', [t]); await db.query('DELETE FROM tenants WHERE id = $1', [t]); }
    await db.pool.end().catch(() => {});
  }
}
main().then(() => process.exit(0), (e) => { console.error(e); process.exit(1); });

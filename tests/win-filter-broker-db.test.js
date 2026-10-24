'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/win-filter-broker-db.test.js
// Skips itself otherwise. The Windows event filter on a broker (docs/endpoints.md, E3): the REAL policy routes save a policy, the REAL broker-config routes announce its hash and serve
// its program, the REAL report stores what a broker has, the REAL Brokers list shows the state; real queries, real row-level security, real ingestion-key lookup. Only the sign-in chain is replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const crypto = require('crypto');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const { generateKey, hashKey } = require('../src/ingest/http-ingest');
const wf = require('../src/endpoints/win-filter');
const wb = require('../src/endpoints/win-filter-broker');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'tester'; next(); }] };
const sha = (t) => crypto.createHash('sha256').update(t).digest('hex');

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['wfb-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['wfb-b-' + stamp])).rows[0].id;
  const mkKey = async (tenant, name) => { const key = generateKey(); await db.withTenant(tenant, (c) => c.query(
    "INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,$2,'linux',$3,$4)", [tenant, name, key.slice(0, 12), hashKey(key)])); return key; };
  const keyA = await mkKey(TENANT, 'wfb-a-key'), keyC = await mkKey(TENANT, 'wfb-c-key'), keyB = await mkKey(OTHER, 'wfb-b-key');

  const app = express(); app.use(require('../src/ingest/heartbeat').router); app.use(require('../src/ingest/broker-config').router); app.use(express.json());
  app.use(require('../src/gateway/routes/brokers')); app.use(require('../src/gateway/routes/win-filter'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body, headers = {}) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }); const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch (e) { /* text */ } return { status: r.status, json, text, headers: r.headers }; };
  const bearer = (k) => ({ authorization: 'Bearer ' + k });
  const beat = (key, name) => call('POST', '/v1/ingest/heartbeat', { collector: { name, platform: 'linux', version: 'vector-0.59.0' } }, bearer(key));
  const pull = (key, name) => call('GET', '/v1/ingest/broker-config' + (name ? '?collector=' + encodeURIComponent(name) : ''), undefined, bearer(key));
  const download = (key) => call('GET', '/v1/ingest/broker-config/win-filter', undefined, bearer(key));
  const report = (key, body) => call('POST', '/v1/ingest/broker-config/report', body, bearer(key));
  const rep = (o = {}) => ({ collector: 'broker-a', syslog_port: 514, rejected_port: null, ...o });
  const cols = async (tenant, name) => (await db.query('SELECT config_win_filter, config_rejected_win_filter, config_syslog_port FROM collectors WHERE tenant_id = $1 AND name = $2', [tenant, name])).rows[0];
  const state = async (name) => ((await call('GET', '/v1/brokers')).json.brokers.find((b) => b.name === name) || {}).win_filter;
  const save = (policy, if_revision) => call('PUT', '/v1/endpoints/win-filter', { policy, if_revision });
  try {
    assert.strictEqual((await beat(keyA, 'broker-a')).status, 200); assert.strictEqual((await beat(keyC, 'broker-c')).status, 200); assert.strictEqual((await beat(keyB, 'broker-b')).status, 200);

    // no policy: the answer has the shape it always had, the download is the keep-everything program
    assert.deepStrictEqual((await pull(keyA, 'broker-a')).json.config, { syslog_port: null, tls_port: null });
    let d = await download(keyA); assert.strictEqual(d.status, 200); assert.strictEqual(d.text, wb.IDENTITY_TEXT); assert.strictEqual(d.headers.get('x-asix-win-filter-revision'), '0');
    assert.strictEqual((await state('broker-a')).state, 'none');

    // save a policy with the real route: the hash announced is the hash of the program served, for every broker of the tenant
    let r = await save(wf.presetNoisySecurity(), 0); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.settings.revision, 1);
    const want = wb.program(wf.toInput(wf.validate(wf.presetNoisySecurity()).policy));
    const a = (await pull(keyA, 'broker-a')).json.config; assert.strictEqual(a.win_filter, want.sha256);
    assert.strictEqual((await pull(keyC, 'broker-c')).json.config.win_filter, want.sha256); assert.strictEqual((await pull(keyA)).json.config.win_filter, want.sha256, 'a script that sends no name is told too');
    d = await download(keyA); assert.strictEqual(d.text, want.text); assert.strictEqual(sha(d.text), a.win_filter); assert.strictEqual(d.headers.get('x-asix-win-filter-sha256'), a.win_filter); assert.strictEqual(d.headers.get('x-asix-win-filter-revision'), '1');
    assert.strictEqual((await state('broker-a')).state, 'unknown'); assert.strictEqual((await state('broker-a')).revision, 1);

    // tenant separation: the other tenant has no policy, is told nothing and downloads only the keep-everything program
    assert.strictEqual((await pull(keyB, 'broker-b')).json.config.win_filter, undefined); assert.strictEqual((await download(keyB)).text, wb.IDENTITY_TEXT);

    // the report lands on the broker's own row only (key AND name); a bad one is a 400 and writes nothing, not even the port
    assert.deepStrictEqual((await report(keyA, rep({ win_filter: '', rejected_win_filter: '' }))).json, { success: true, recorded: true });
    let l = await state('broker-a'); assert.strictEqual(l.state, 'pending', 'it has no file yet');
    assert.deepStrictEqual({ ...(await cols(TENANT, 'broker-a')) }, { config_win_filter: '', config_rejected_win_filter: null, config_syslog_port: 514 });
    assert.strictEqual((await report(keyC, rep({ win_filter: want.sha256 }))).json.recorded, false, 'another key naming broker-a writes nothing');
    assert.strictEqual((await report(keyB, rep({ win_filter: want.sha256 }))).json.recorded, false, 'another tenant writes nothing');
    assert.strictEqual((await cols(TENANT, 'broker-a')).config_win_filter, '');
    // the SQL itself, called directly (the route above already stops a foreign key one step earlier): wrong key or wrong name updates nothing
    const idC = (await db.query('SELECT id FROM ingestion_keys WHERE tenant_id = $1 AND name = $2', [TENANT, 'wfb-c-key'])).rows[0].id, idA = (await db.query('SELECT id FROM ingestion_keys WHERE tenant_id = $1 AND name = $2', [TENANT, 'wfb-a-key'])).rows[0].id;
    assert.strictEqual(await db.withTenant(TENANT, (c) => wb.recordReport(c, TENANT, idC, 'broker-a', 'e'.repeat(64), '')), false);
    assert.strictEqual(await db.withTenant(TENANT, (c) => wb.recordReport(c, TENANT, idA, 'broker-zzz', 'e'.repeat(64), '')), false);
    assert.strictEqual((await cols(TENANT, 'broker-a')).config_win_filter, '', 'unchanged');
    assert.strictEqual((await report(keyA, rep({ syslog_port: 2514, win_filter: 'XYZ' }))).status, 400); assert.strictEqual((await cols(TENANT, 'broker-a')).config_syslog_port, 514);

    // applied; then a heartbeat and a report from a script that sends no filter fields leave it alone
    assert.strictEqual((await report(keyA, rep({ win_filter: want.sha256, rejected_win_filter: '' }))).json.recorded, true); assert.strictEqual((await state('broker-a')).state, 'applied');
    await beat(keyA, 'broker-a'); await report(keyA, rep({ syslog_port: 1514 })); assert.strictEqual((await cols(TENANT, 'broker-a')).config_win_filter, want.sha256); assert.strictEqual((await state('broker-a')).state, 'applied');
    assert.strictEqual((await call('GET', '/v1/brokers')).json.summary.win_filter_applied, 1);

    // a changed policy: a new hash, the broker is Pending until it reports the new program; a rejection shows only for the program asked now
    r = await save({ ...wf.presetNoisySecurity(), strip_message: false }, 1); assert.strictEqual(r.json.settings.revision, 2);
    const want2 = wb.program(wf.toInput(wf.validate({ ...wf.presetNoisySecurity(), strip_message: false }).policy));
    assert.notStrictEqual(want2.sha256, want.sha256); assert.strictEqual((await pull(keyA, 'broker-a')).json.config.win_filter, want2.sha256); assert.strictEqual((await state('broker-a')).state, 'pending');
    await report(keyA, rep({ win_filter: want.sha256, rejected_win_filter: want2.sha256 })); assert.strictEqual((await state('broker-a')).state, 'rejected');
    await save({ ...wf.presetNoisySecurity(), strip_message: true, rules: [{ id: 'x', action: 'drop', channel: 'System', event_ids: [7036] }] }, 2); assert.strictEqual((await state('broker-a')).state, 'pending', 'the old rejection is about another program');

    // removed policy: a broker that still has a program is told the keep-everything hash; one that has none (or already has it) is told nothing
    assert.strictEqual((await call('PUT', '/v1/endpoints/win-filter', { clear: true })).status, 200);
    assert.strictEqual((await pull(keyA, 'broker-a')).json.config.win_filter, wb.IDENTITY_SHA); l = await state('broker-a'); assert.strictEqual(l.state, 'pending'); assert.strictEqual(l.removing, true);
    assert.strictEqual((await pull(keyC, 'broker-c')).json.config.win_filter, undefined, 'a broker that never reported has nothing to take away');
    assert.strictEqual((await pull(keyA, 'someone-else')).json.config.win_filter, undefined, 'the broker is found by key AND name: another name is not told what broker-a has');
    assert.strictEqual((await pull(keyC, 'broker-a')).json.config.win_filter, undefined, 'another key naming broker-a is not told either');
    await report(keyA, rep({ win_filter: wb.IDENTITY_SHA })); assert.strictEqual((await pull(keyA, 'broker-a')).json.config.win_filter, undefined); assert.strictEqual((await state('broker-a')).state, 'none');

    // clear and save again: the revision starts at 1 again, but the program (and so the hash) is what identifies it
    await save(wf.presetNoisySecurity(), 0); const again = await pull(keyA, 'broker-a'); assert.strictEqual(again.json.config.win_filter, want.sha256);
    assert.strictEqual((await download(keyA)).headers.get('x-asix-win-filter-revision'), '1');

    // the database CHECKs refuse anything that is not a lower-case hash
    for (const sql of ["UPDATE collectors SET config_win_filter = 'ABC' WHERE name = 'broker-a'", "UPDATE collectors SET config_win_filter = '" + 'A'.repeat(64) + "' WHERE name = 'broker-a'", "UPDATE collectors SET config_rejected_win_filter = '' WHERE name = 'broker-a'", "UPDATE collectors SET config_rejected_win_filter = 'abc' WHERE name = 'broker-a'"]) {
      await assert.rejects(db.withTenant(TENANT, (cl) => cl.query(sql)), /check constraint/, sql);
    }
    console.log('win-filter-broker-db: ok');
  } finally {
    srv.close();
    for (const t of [TENANT, OTHER]) { await db.query('DELETE FROM collectors WHERE tenant_id = $1', [t]); await db.query('DELETE FROM ingestion_keys WHERE tenant_id = $1', [t]); await db.query('DELETE FROM win_filter_policy WHERE tenant_id = $1', [t]); await db.query('DELETE FROM tenants WHERE id = $1', [t]); }
    await db.pool.end().catch(() => {});
  }
}
main().then(() => process.exit(0), (e) => { console.error(e); process.exit(1); });

'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-signature-report-db.test.js
// Skips itself otherwise. Which brokers check ASIX's signature, end to end: the real heartbeat creates the rows, the real report route stores what a
// broker says (config_signature), the real GET /v1/brokers shows it; real row-level security, the real ingestion-key lookup and the real CHECK constraint.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const crypto = require('crypto');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const signing = require('../src/brokers/config-signing');
const config = require('../src/brokers/config');
const { generateKey, hashKey } = require('../src/ingest/http-ingest');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'tester'; next(); }] };

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['bsig-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['bsig-b-' + stamp])).rows[0].id;
  const mkKey = async (tenant, name) => { const key = generateKey(); await db.withTenant(tenant, (c) => c.query(
    "INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,$2,'linux',$3,$4)", [tenant, name, key.slice(0, 12), hashKey(key)])); return key; };
  const keyA = await mkKey(TENANT, 'broker-a'), keyA2 = await mkKey(TENANT, 'broker-c-key'), keyB = await mkKey(OTHER, 'broker-b');

  const app = express(); app.use(require('../src/ingest/heartbeat').router); app.use(require('../src/ingest/broker-config').router); app.use(express.json());
  app.use(require('../src/gateway/routes/broker-config')); app.use(require('../src/gateway/routes/brokers'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body, headers = {}) => { const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const beat = (key, name) => call('POST', '/v1/ingest/heartbeat', { collector: { name, platform: 'linux', version: 'vector-0.59.0' } }, { authorization: 'Bearer ' + key });
  const report = (key, body) => call('POST', '/v1/ingest/broker-config/report', body, key ? { authorization: 'Bearer ' + key } : {});
  const listed = async () => (await call('GET', '/v1/brokers')).json;
  const sigOf = async (tenant, name) => (await db.query('SELECT config_signature, config_syslog_port FROM collectors WHERE tenant_id = $1 AND name = $2', [tenant, name])).rows[0];
  const bro = async (name) => (await listed()).brokers.find((b) => b.name === name);
  const savedEnv = process.env.ASIX_CONFIG_SIGNING_KEY;
  try {
    delete process.env.ASIX_CONFIG_SIGNING_KEY; signing.reset();
    for (const [k, n] of [[keyA, 'broker-a'], [keyA2, 'broker-c'], [keyB, 'broker-b']]) assert.strictEqual((await beat(k, n)).status, 200);

    // a new row: never reported, so unknown, and the column exists and is NULL
    assert.deepStrictEqual(await sigOf(TENANT, 'broker-a'), { config_signature: null, config_syslog_port: null });
    let b = await bro('broker-a'); assert.strictEqual(b.signature.state, 'unknown'); assert.strictEqual(b.signature.signing_on, false);

    // refused bodies write nothing and say why
    for (const bad of ['maybe', 5, '', 'OK', ['ok'], "ok'; DROP TABLE collectors;--"]) {
      const r = await report(keyA, { collector: 'broker-a', syslog_port: 514, signature: bad }); assert.strictEqual(r.status, 400, JSON.stringify(bad)); assert.strictEqual(r.json.error.code, 'BROKER_REPORT_INVALID');
    }
    assert.strictEqual((await sigOf(TENANT, 'broker-a')).config_syslog_port, null, 'a refused report writes nothing, not even the port');
    assert.strictEqual((await report(null, { collector: 'broker-a', syslog_port: 514, signature: 'ok' })).status, 401);
    assert.strictEqual((await report('asix_ik_' + 'z'.repeat(40), { collector: 'broker-a', syslog_port: 514, signature: 'ok' })).status, 401);
    assert.strictEqual((await sigOf(TENANT, 'broker-a')).config_signature, null);

    // every value the script can send is stored and read back as the right state
    const expect = { off: 'not_verifying', unchecked: 'waiting', ok: 'verifying' };
    for (const p of config.SIGNATURE_PROBLEMS) expect[p] = 'refused';
    for (const [sig, state] of Object.entries(expect)) {
      const r = await report(keyA, { collector: 'broker-a', syslog_port: 514, rejected_port: null, signature: sig }); assert.deepStrictEqual(r.json, { success: true, recorded: true }, sig);
      assert.strictEqual((await sigOf(TENANT, 'broker-a')).config_signature, sig);
      b = await bro('broker-a'); assert.strictEqual(b.signature.state, state, sig); assert.strictEqual(b.signature.problem, state === 'refused' ? sig : null);
      assert.deepStrictEqual(b.problems, [], sig + ': information, never a problem'); assert.strictEqual((await listed()).summary.with_problems, 0);
      if (state === 'refused') assert.ok(b.signature.help && b.signature.help.length > 20, sig);
    }

    // the summary
    await report(keyA, { collector: 'broker-a', syslog_port: 514, signature: 'ok' });
    await report(keyA2, { collector: 'broker-c', syslog_port: 514, signature: 'bad_signature' });
    let l = await listed(); assert.deepStrictEqual([l.summary.signature_verifying, l.summary.signature_not_verifying, l.summary.signature_refused], [1, 0, 1]);

    // a report from an older script (no signature) clears the old value instead of leaving a claim it can no longer make; the port part is unaffected
    await report(keyA, { collector: 'broker-a', syslog_port: 1514 });
    assert.deepStrictEqual(await sigOf(TENANT, 'broker-a'), { config_signature: null, config_syslog_port: 1514 });
    assert.strictEqual((await bro('broker-a')).signature.state, 'unknown');
    await report(keyA, { collector: 'broker-a', syslog_port: 1514, signature: 'ok' });

    // it does not disturb the port state, and the signature state does not depend on a port being set
    assert.strictEqual((await bro('broker-a')).config.state, 'none');
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: 1514 })).status, 200);
    b = await bro('broker-a'); assert.strictEqual(b.config.state, 'applied'); assert.strictEqual(b.signature.state, 'verifying');
    assert.strictEqual((await call('PUT', '/v1/broker-config', { syslog_port: null })).status, 200);

    // the next heartbeat does not wipe it
    assert.strictEqual((await beat(keyA, 'broker-a')).status, 200); assert.strictEqual((await sigOf(TENANT, 'broker-a')).config_signature, 'ok');

    // a key writes only its own broker's row: another key in the same tenant, another tenant's key, a name with no row
    let r = await report(keyA, { collector: 'broker-c', syslog_port: 514, signature: 'ok' }); assert.strictEqual(r.json.recorded, false, 'same tenant, not this key\'s broker');
    r = await report(keyB, { collector: 'broker-a', syslog_port: 514, signature: 'ok' }); assert.strictEqual(r.json.recorded, false, 'another tenant\'s key');
    r = await report(keyA, { collector: 'ghost', syslog_port: 514, signature: 'ok' }); assert.strictEqual(r.json.recorded, false);
    assert.strictEqual((await sigOf(TENANT, 'broker-c')).config_signature, 'bad_signature', 'broker-c\'s claim is its own key\'s to change');
    assert.strictEqual((await sigOf(OTHER, 'broker-b')).config_signature, null); assert.strictEqual((await sigOf(TENANT, 'ghost')), undefined);

    // another tenant's page sees only its own broker
    { const saved = TENANT; TENANT = OTHER; const o = await listed(); TENANT = saved; assert.deepStrictEqual(o.brokers.map((x) => x.name), ['broker-b']); assert.strictEqual(o.brokers[0].signature.state, 'unknown'); assert.strictEqual(o.summary.signature_verifying, 0); }

    // an old report goes stale (and a refusal keeps its reason); a broker with no key to check with ('off') has nothing to go stale
    await db.query("UPDATE collectors SET config_reported_at = localtimestamp - interval '1 hour' WHERE tenant_id = $1 AND name IN ('broker-a','broker-c')", [TENANT]);
    b = await bro('broker-a'); assert.strictEqual(b.signature.state, 'stale'); assert.strictEqual((await bro('broker-c')).signature.problem, 'bad_signature');
    l = await listed(); assert.strictEqual(l.summary.signature_verifying, 0, 'a stale report is not counted as verifying'); assert.strictEqual(l.summary.signature_refused, 0);
    await report(keyA, { collector: 'broker-a', syslog_port: 514, signature: 'off' });
    await db.query("UPDATE collectors SET config_reported_at = localtimestamp - interval '1 hour' WHERE tenant_id = $1 AND name = 'broker-a'", [TENANT]);
    assert.strictEqual((await bro('broker-a')).signature.state, 'not_verifying');

    // whether ASIX signs is shown next to it
    assert.strictEqual((await bro('broker-a')).signature.signing_on, false);
    process.env.ASIX_CONFIG_SIGNING_KEY = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'pem' }); signing.reset();
    assert.strictEqual((await bro('broker-a')).signature.signing_on, true, 'ASIX signs but this broker does not check: the page can say so');

    // and the database refuses a value outside the list even if the application did not
    await assert.rejects(() => db.query("UPDATE collectors SET config_signature = 'verified' WHERE tenant_id = $1", [TENANT]), /violates check/);
    await assert.rejects(() => db.query("UPDATE collectors SET config_signature = '' WHERE tenant_id = $1", [TENANT]), /violates check/);
    console.log('broker-signature-report-db: all checks passed');
  } finally {
    if (savedEnv === undefined) delete process.env.ASIX_CONFIG_SIGNING_KEY; else process.env.ASIX_CONFIG_SIGNING_KEY = savedEnv; signing.reset();
    srv.close();
    await db.query('DELETE FROM broker_settings WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM collectors WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM ingestion_keys WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

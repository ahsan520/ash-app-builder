'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-signature-watch-db.test.js
// Skips itself otherwise. Real queries, the real heartbeat lane, the real broker report route (what a broker says about the signature), a real
// signing key and the real notification dispatcher; only the sign-in chain is replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

process.env.NOTIFY_ENCRYPTION_KEY = process.env.NOTIFY_ENCRYPTION_KEY || Buffer.alloc(32, 7).toString('base64');
const assert = require('assert');
const crypto = require('crypto');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const signing = require('../src/brokers/config-signing');
const { generateKey, hashKey } = require('../src/ingest/http-ingest');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }] };
const sw = require('../src/collectors/signature-watch');
const wd = require('../src/collectors/watchdog');
const dispatcher = require('../src/notifications/dispatcher');
const box = require('../src/notifications/secret-box');

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['sw-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['sw-b-' + stamp])).rows[0].id;
  const mkKey = async (tenant, name) => { const key = generateKey(); await db.query("INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,$2,'linux',$3,$4)", [tenant, name + '-' + stamp, key.slice(0, 12), hashKey(key)]); return key; };
  const names = { off: 'off-' + stamp, ok: 'ok-' + stamp, ref: 'ref-' + stamp, unw: 'unw-' + stamp, unk: 'unk-' + stamp, oth: 'oth-' + stamp };
  const keys = {};
  for (const k of Object.keys(names)) keys[k] = await mkKey(k === 'oth' ? OTHER : TENANT, k);

  const app = express(); app.use(require('../src/ingest/heartbeat').router); app.use(require('../src/ingest/broker-config').router); app.use(express.json());
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = (p, body, key) => fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + key }, body: JSON.stringify(body) });
  const beat = (k) => call('/v1/ingest/heartbeat', { collector: { name: names[k], platform: 'linux', version: 'vector-0.59.0' } }, keys[k]);
  const say = async (k, sig) => { const r = await call('/v1/ingest/broker-config/report', { collector: names[k], syslog_port: 514, rejected_port: null, signature: sig }, keys[k]); assert.strictEqual((await r.json()).recorded, true, k + ' ' + sig); };
  const id = async (k) => (await db.query('SELECT id FROM collectors WHERE name = $1', [names[k]])).rows[0].id;

  const savedEnv = process.env.ASIX_CONFIG_SIGNING_KEY;
  const pem = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  const signOn = () => { process.env.ASIX_CONFIG_SIGNING_KEY = pem; signing.reset(); };
  const signOff = () => { delete process.env.ASIX_CONFIG_SIGNING_KEY; signing.reset(); };
  const alerts = async (tenant = TENANT) => (await db.query('SELECT id, status, severity, title, group_key, rule_id, details FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY created_at, id', [tenant, sw.RULE_NAME])).rows;
  const notes = async (aid) => (await db.query('SELECT author_name, body FROM alert_notes WHERE alert_id = $1', [aid])).rows;
  const cycle = (o) => sw.runTenant(TENANT, o);
  try {
    for (const k of Object.keys(names)) assert.strictEqual((await beat(k)).status, 200);
    await say('off', 'off'); await say('ok', 'ok'); await say('ref', 'bad_signature'); await say('unw', 'off'); await say('oth', 'off');   // unk never reports
    const oid = { off: await id('off'), ok: await id('ok'), ref: await id('ref'), unw: await id('unw'), unk: await id('unk'), oth: await id('oth') };
    await db.query('UPDATE collectors SET watch_disconnect = true WHERE id = ANY($1)', [[oid.off, oid.ok, oid.ref, oid.unk, oid.oth]]);   // unw is NOT watched
    // a collector that is not a broker, saying the same thing
    await db.query("INSERT INTO collectors (tenant_id, name, platform, version, last_seen, watch_disconnect, config_signature, config_reported_at) VALUES ($1,$2,'linux','1.2.3',localtimestamp,true,'off',localtimestamp)", [TENANT, 'plain-' + stamp]);
    await db.query("INSERT INTO notification_channels (tenant_id, name, type, enabled, min_severity, config_enc) VALUES ($1,'sw-hook','webhook',true,'high',$2)", [TENANT, box.encrypt({ url: 'https://example.com/hook', format: 'json', headers: {}, signing_secret: '', routing_key: '' })]);

    // ASIX does not sign: nothing is raised however the brokers answer
    signOff();
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    signOn();
    // start-up grace: nothing raised
    assert.deepStrictEqual(await cycle({ raiseAllowed: false }), { raised: 0, closed: 0 });
    // exactly the watched broker with no public key and the watched broker that refuses (not ok, unwatched, never reported, non-broker, other tenant)
    assert.deepStrictEqual(await cycle(), { raised: 2, closed: 0 });
    let al = await alerts(); assert.strictEqual(al.length, 2);
    const aOff = al.find((a) => a.group_key === 'brokersig:' + oid.off), aRef = al.find((a) => a.group_key === 'brokersig:' + oid.ref);
    assert.ok(aOff && aRef);
    assert.strictEqual(aOff.status, 'open'); assert.strictEqual(aOff.severity, 'high'); assert.strictEqual(aOff.rule_id, null);
    assert.strictEqual(aOff.title, 'Broker not checking config signature: ' + names.off); assert.strictEqual(aOff.details.sig_ref, 'not_verifying');
    assert.strictEqual(aRef.details.sig_ref, 'refused:bad_signature');
    assert.strictEqual((await alerts(OTHER)).length, 0);

    // the existing dispatcher sends each once
    const sent = [];
    assert.strictEqual((await dispatcher.runTenant(TENANT, { send: async (t, c, m) => { sent.push(m); } })).queued, 2);
    assert.ok(sent.every((m) => m.rule === 'Broker not checking config signature'));
    assert.strictEqual((await dispatcher.runTenant(TENANT, { send: async () => { throw new Error('must not send again'); } })).queued, 0);

    // repeat, acknowledged, closed by hand on the same problem: nothing more
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    await db.query("UPDATE alerts SET status = 'acknowledged' WHERE id = $1", [aOff.id]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    await db.query("UPDATE alerts SET status = 'closed' WHERE id = $1", [aOff.id]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    assert.strictEqual((await alerts()).length, 2);

    // the refusing broker changes its reason: still the same open alert
    await say('ref', 'clock_skew');
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    // the fix: the broker is given the public key and reports ok -> the alert closes with a note
    await say('ref', 'ok');
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });
    const n = await notes(aRef.id); assert.strictEqual(n.length, 1); assert.strictEqual(n[0].author_name, 'ASIX'); assert.match(n[0].body, /checks ASIX's signature again/);
    // an old report is not a problem any more (the broker stopped asking)
    await say('ref', 'bad_signature'); assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 }, 'closed by ASIX with the same problem: not raised again');
    await db.query("UPDATE alerts SET status = 'open' WHERE id = $1", [aRef.id]);
    await db.query("UPDATE collectors SET config_reported_at = localtimestamp - interval '1 hour' WHERE id = $1", [oid.ref]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });

    // a different problem than the one closed raises a new alert
    await db.query("UPDATE collectors SET config_reported_at = localtimestamp WHERE id = $1", [oid.ref]);
    await say('ref', 'off');
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
    al = await alerts(); assert.strictEqual(al.length, 3); assert.strictEqual(al[2].details.sig_ref, 'not_verifying');

    // ASIX stops signing: open alerts close with their own note
    signOff();
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });
    assert.match((await notes(al[2].id))[0].body, /does not sign/);
    signOn();
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 }, 'same problems were closed: not raised again');

    // the tenant-wide "watch everything" switch covers the unwatched broker (and not a left-out one)
    await db.query('INSERT INTO collector_watch_defaults (tenant_id, watch_disconnect) VALUES ($1, true)', [TENANT]);
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
    assert.ok((await alerts()).some((a) => a.group_key === 'brokersig:' + oid.unw));
    // stopping the watch closes; deleting the broker closes
    await db.query('UPDATE collector_watch_defaults SET watch_disconnect = false WHERE tenant_id = $1', [TENANT]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });
    await db.query("UPDATE alerts SET status = 'open' WHERE id = $1", [aOff.id]);
    await db.query('DELETE FROM collectors WHERE id = $1', [oid.off]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });

    // the watchdog's real cycle runs it too, without error
    const total = await wd.runOnce({ raiseAllowed: true });
    assert.strictEqual(total.errors, 0);
    console.log('broker-signature-watch-db: all checks passed');
  } finally {
    if (savedEnv === undefined) delete process.env.ASIX_CONFIG_SIGNING_KEY; else process.env.ASIX_CONFIG_SIGNING_KEY = savedEnv;
    signing.reset(); srv.close();
    for (const t of ['notification_deliveries', 'notification_channels', 'alert_notes', 'alerts', 'collector_watch_defaults', 'collectors', 'ingestion_keys']) await db.query(`DELETE FROM ${t} WHERE tenant_id = ANY($1)`, [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-key-watch-db.test.js
// Skips itself otherwise. Real queries, the real heartbeat lane, the real rotate-key and revoke routes, and the real notification
// dispatcher; only the sign-in chain is replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

process.env.NOTIFY_ENCRYPTION_KEY = process.env.NOTIFY_ENCRYPTION_KEY || Buffer.alloc(32, 7).toString('base64');
process.env.BROKER_INGEST_TOKEN = 'test-broker-token';
const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const { generateKey, hashKey } = require('../src/ingest/http-ingest');
const { setEventStore } = require('../src/events'); const { MemoryEventStore } = require('../src/events/memory-store');
setEventStore(new MemoryEventStore());

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }],
};
const kw = require('../src/collectors/key-watch');
const wd = require('../src/collectors/watchdog');
const dispatcher = require('../src/notifications/dispatcher');
const box = require('../src/notifications/secret-box');

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['kw-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['kw-b-' + stamp])).rows[0].id;
  const addKey = async (tenant, name) => { const key = generateKey(); const id = (await db.query("INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,$2,'linux',$3,$4) RETURNING id", [tenant, name, key.slice(0, 12), hashKey(key)])).rows[0].id; return { key, id }; };
  const addCollector = async (tenant, name, keyId, version = 'vector-0.59.0') => (await db.query("INSERT INTO collectors (tenant_id, key_id, name, platform, version, last_seen) VALUES ($1,$2,$3,'linux',$4, localtimestamp) RETURNING id", [tenant, keyId, name, version])).rows[0].id;

  const nA = 'rev-' + stamp, nB = 'ok-' + stamp, nC = 'unwatched-' + stamp, nD = 'plain-' + stamp, nE = 'foreign-' + stamp;
  const kA = await addKey(TENANT, 'kA-' + stamp), kB = await addKey(TENANT, 'kB-' + stamp), kC = await addKey(TENANT, 'kC-' + stamp), kD = await addKey(TENANT, 'kD-' + stamp), kE = await addKey(OTHER, 'kE-' + stamp);
  const a = await addCollector(TENANT, nA, kA.id);                 // watched broker, key will be revoked
  const b = await addCollector(TENANT, nB, kB.id);                 // watched broker, healthy
  const c = await addCollector(TENANT, nC, kC.id);                 // broker, key revoked, NOT watched
  const d = await addCollector(TENANT, nD, kD.id, '1.2.3');        // not a broker, key revoked
  const e = await addCollector(OTHER, nE, kE.id);                  // another tenant's broker
  await db.query("UPDATE ingestion_keys SET status='revoked', revoked_at=localtimestamp WHERE id = ANY($1)", [[kC.id, kD.id, kE.id]]);
  await db.query('UPDATE collectors SET watch_disconnect = true WHERE id = ANY($1)', [[a, b, d, e]]);

  await db.query("INSERT INTO notification_channels (tenant_id, name, type, enabled, min_severity, config_enc) VALUES ($1,'kw-hook','webhook',true,'high',$2)", [TENANT, box.encrypt({ url: 'https://example.com/hook', format: 'json', headers: {}, signing_secret: '', routing_key: '' })]);
  const alerts = async (tenant = TENANT) => (await db.query('SELECT id, status, severity, title, group_key, rule_id, details FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY created_at', [tenant, kw.RULE_NAME])).rows;
  const notes = async (id) => (await db.query('SELECT author_name, body FROM alert_notes WHERE alert_id = $1', [id])).rows;
  const cycle = (o) => kw.runTenant(TENANT, o);

  const app = express(); app.use(require('../src/ingest/heartbeat').router); app.use(express.json());
  app.use(require('../src/gateway/routes/brokers')); app.use(require('../src/gateway/routes/collectors'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const post = (p, headers = {}) => fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: '{}' });
  try {
    // start-up grace: nothing raised
    assert.deepStrictEqual(await cycle({ raiseAllowed: false }), { raised: 0, closed: 0 });
    // nothing wrong yet for the watched ones (key A is still active): nothing raised
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });

    // revoking key A while broker A is still on it: exactly one alert (not healthy B, unwatched C, non-broker D or the other tenant's E)
    assert.strictEqual((await post('/v1/ingestion-keys/' + kA.id + '/revoke')).status, 200);
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
    let al = await alerts(); assert.strictEqual(al.length, 1);
    assert.strictEqual(al[0].status, 'open'); assert.strictEqual(al[0].severity, 'high'); assert.strictEqual(al[0].rule_id, null);
    assert.strictEqual(al[0].group_key, 'brokerkey:' + a); assert.strictEqual(al[0].title, 'Broker installer key unusable: ' + nA);
    assert.strictEqual(al[0].details.key_ref, 'revoked:' + kA.id);
    assert.strictEqual((await alerts(OTHER)).length, 0);

    // the existing dispatcher sends it once
    const sent = [];
    assert.strictEqual((await dispatcher.runTenant(TENANT, { send: async (type, cfg, msg) => { sent.push(msg); } })).queued, 1);
    assert.strictEqual(sent[0].rule, 'Broker installer key unusable');
    assert.strictEqual((await dispatcher.runTenant(TENANT, { send: async () => { throw new Error('must not send again'); } })).queued, 0);

    // repeat cycles, and an acknowledged alert: nothing more; closed by hand on the same key: not raised again
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    await db.query("UPDATE alerts SET status = 'acknowledged' WHERE id = $1", [al[0].id]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    await db.query("UPDATE alerts SET status = 'closed' WHERE id = $1", [al[0].id]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    assert.strictEqual((await alerts()).length, 1);

    // the real fix: Rotate key, then the heartbeat with the new key moves the broker onto it; the alert (reopened) closes with a note
    await db.query("UPDATE alerts SET status = 'open' WHERE id = $1", [al[0].id]);
    const rot = await post('/v1/brokers/' + a + '/rotate-key'); assert.strictEqual(rot.status, 201);
    const rj = await rot.json();
    assert.strictEqual((await post('/v1/ingest/heartbeat', { authorization: 'Bearer ' + rj.key, 'x-asix-collector': nA })).status, 200);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });
    al = await alerts(); assert.strictEqual(al[0].status, 'closed');
    const n = await notes(al[0].id); assert.strictEqual(n.length, 1); assert.strictEqual(n[0].author_name, 'ASIX'); assert.match(n[0].body, /active installer key again/);

    // the normal rotation order raises nothing: new key in use on B, THEN the old key revoked
    const rotB = await (await post('/v1/brokers/' + b + '/rotate-key')).json();
    assert.strictEqual((await post('/v1/ingest/heartbeat', { authorization: 'Bearer ' + rotB.key, 'x-asix-collector': nB })).status, 200);
    assert.strictEqual((await post('/v1/ingestion-keys/' + kB.id + '/revoke')).status, 200);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });

    // a deleted key (key_id becomes NULL) raises a new alert for that broker, since it is a different problem
    assert.strictEqual((await fetch(base + '/v1/ingestion-keys/' + rj.installer.id, { method: 'DELETE' })).status, 200);
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
    al = await alerts(); assert.strictEqual(al.length, 2); assert.strictEqual(al[1].details.key_ref, 'deleted');

    // stopping the watch closes it; so does deleting the broker
    await db.query('UPDATE collectors SET watch_disconnect = false WHERE id = $1', [a]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });
    await db.query('UPDATE collectors SET watch_disconnect = true WHERE id = $1', [a]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 }, 'same deleted-key problem was closed: not raised again');
    await db.query("UPDATE alerts SET status = 'open' WHERE id = (SELECT id FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY created_at DESC LIMIT 1)", [TENANT, kw.RULE_NAME]);
    await db.query('DELETE FROM collectors WHERE id = $1', [a]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });

    // the watchdog's real cycle runs it as well (and the other checks) without error for this tenant
    const total = await wd.runOnce({ raiseAllowed: true });
    assert.strictEqual(total.errors, 0);
    assert.ok(c && d && e, 'ids used above');
    console.log('broker-key-watch-db: all checks passed');
  } finally {
    srv.close();
    await db.query('DELETE FROM notification_deliveries WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM notification_channels WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM alerts WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM collectors WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM ingestion_keys WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

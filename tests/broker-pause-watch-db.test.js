'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-pause-watch-db.test.js
// Skips itself otherwise. Real queries, the real heartbeat lane, the real pause route, the real broker report route (what a broker says about the list it
// paused or rejected) and the real notification dispatcher; only the sign-in chain is replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

process.env.NOTIFY_ENCRYPTION_KEY = process.env.NOTIFY_ENCRYPTION_KEY || Buffer.alloc(32, 7).toString('base64');
const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const { generateKey, hashKey } = require('../src/ingest/http-ingest');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'tester'; next(); }] };
const pw = require('../src/collectors/pause-watch');
const wd = require('../src/collectors/watchdog');
const dispatcher = require('../src/notifications/dispatcher');
const box = require('../src/notifications/secret-box');

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['pw-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['pw-b-' + stamp])).rows[0].id;
  const mkKey = async (tenant, name) => { const key = generateKey(); await db.query("INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,$2,'linux',$3,$4)", [tenant, name + '-' + stamp, key.slice(0, 12), hashKey(key)]); return key; };
  const names = { rej: 'rej-' + stamp, ok: 'ok-' + stamp, pend: 'pend-' + stamp, unw: 'unw-' + stamp, unk: 'unk-' + stamp, oth: 'oth-' + stamp };
  const keys = {};
  for (const k of Object.keys(names)) keys[k] = await mkKey(k === 'oth' ? OTHER : TENANT, k);

  const app = express(); app.use(require('../src/ingest/heartbeat').router); app.use(require('../src/ingest/broker-config').router); app.use(express.json());
  app.use(require('../src/gateway/routes/broker-inputs'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = (method, p, body, key) => fetch(base + p, { method, headers: { 'content-type': 'application/json', ...(key ? { authorization: 'Bearer ' + key } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const beat = (k) => call('POST', '/v1/ingest/heartbeat', { collector: { name: names[k], platform: 'linux', version: 'vector-0.59.0' } }, keys[k]);
  // What a broker says after a pull: the list it has paused now and, when it put its old settings back, the list it rejected.
  const say = async (k, paused, rejected) => { const r = await call('POST', '/v1/ingest/broker-config/report', { collector: names[k], syslog_port: 514, rejected_port: null, paused_inputs: paused, ...(rejected === undefined ? {} : { rejected_paused_inputs: rejected }) }, keys[k]); assert.strictEqual((await r.json()).recorded, true, k); };
  const id = async (k) => (await db.query('SELECT id FROM collectors WHERE name = $1', [names[k]])).rows[0].id;
  const ask = async (k, list) => { const r = await call('PUT', '/v1/brokers/' + (await id(k)) + '/inputs-paused', { paused: list }); assert.strictEqual(r.status, 200, k); };
  const alerts = async (tenant = TENANT) => (await db.query('SELECT id, status, severity, title, summary, group_key, rule_id, details FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY created_at, id', [tenant, pw.RULE_NAME])).rows;
  const notes = async (aid) => (await db.query('SELECT author_name, body FROM alert_notes WHERE alert_id = $1', [aid])).rows;
  const cycle = (o) => pw.runTenant(TENANT, o);
  try {
    for (const k of Object.keys(names)) assert.strictEqual((await beat(k)).status, 200);
    const oid = { rej: await id('rej'), ok: await id('ok'), pend: await id('pend'), unw: await id('unw'), unk: await id('unk'), oth: await id('oth') };
    // rej asked to pause the journal and rejected it; ok applied it; pend was asked and has not applied it yet; unw rejected but is NOT watched; unk was asked and never reported
    await ask('rej', ['journald']); await say('rej', '', 'journald');
    await ask('ok', ['journald']); await say('ok', 'journald');
    await ask('pend', ['file']); await say('pend', '');
    await ask('unw', ['http']); await say('unw', '', 'http');
    await ask('unk', ['file']);
    await db.query('UPDATE collectors SET inputs_paused = $2, config_paused_inputs = $3, config_rejected_paused = $4, config_reported_at = localtimestamp WHERE id = $1', [oid.oth, 'file', '', 'file']);   // other tenant, same trouble
    await db.query('UPDATE collectors SET watch_disconnect = true WHERE id = ANY($1)', [[oid.rej, oid.ok, oid.pend, oid.unk, oid.oth]]);   // unw is NOT watched
    // a collector that is not a broker, with the same columns
    await db.query("INSERT INTO collectors (tenant_id, name, platform, version, last_seen, watch_disconnect, inputs_paused, config_paused_inputs, config_rejected_paused, config_reported_at) VALUES ($1,$2,'linux','1.2.3',localtimestamp,true,'file','','file',localtimestamp)", [TENANT, 'plain-' + stamp]);
    await db.query("INSERT INTO notification_channels (tenant_id, name, type, enabled, min_severity, config_enc) VALUES ($1,'pw-hook','webhook',true,'high',$2)", [TENANT, box.encrypt({ url: 'https://example.com/hook', format: 'json', headers: {}, signing_secret: '', routing_key: '' })]);

    // start-up grace: nothing raised
    assert.deepStrictEqual(await cycle({ raiseAllowed: false }), { raised: 0, closed: 0 });
    // exactly the watched broker that rejected its list (not applied, pending, never reported, unwatched, non-broker, other tenant)
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
    let al = await alerts(); assert.strictEqual(al.length, 1);
    const a1 = al[0];
    assert.strictEqual(a1.group_key, 'brokerpause:' + oid.rej); assert.strictEqual(a1.status, 'open'); assert.strictEqual(a1.severity, 'high'); assert.strictEqual(a1.rule_id, null);
    assert.strictEqual(a1.title, 'Broker input pause not applied: ' + names.rej); assert.match(a1.summary, /asked to pause journald and rejected it/);
    assert.deepStrictEqual(a1.details, { broker_id: oid.rej, broker: names.rej, kind: 'rejected', pause_ref: 'rejected:journald', asked: ['journald'] });
    assert.strictEqual((await alerts(OTHER)).length, 0);

    // the existing dispatcher sends it once
    const sent = [];
    assert.strictEqual((await dispatcher.runTenant(TENANT, { send: async (t, c, m) => { sent.push(m); } })).queued, 1);
    assert.strictEqual(sent[0].rule, 'Broker input pause not applied');
    assert.strictEqual((await dispatcher.runTenant(TENANT, { send: async () => { throw new Error('must not send again'); } })).queued, 0);

    // repeat, acknowledged, closed by hand on the same list: nothing more
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    await db.query("UPDATE alerts SET status = 'acknowledged' WHERE id = $1", [a1.id]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    await db.query("UPDATE alerts SET status = 'closed' WHERE id = $1", [a1.id]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    assert.strictEqual((await alerts()).length, 1);

    // the operator asks for another list and the broker rejects that one too: a new alert (the first one was closed by hand for another list)
    await ask('rej', ['file', 'journald']); await say('rej', '', 'file,journald');
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
    al = await alerts(); assert.strictEqual(al.length, 2); const a2 = al[1];
    assert.strictEqual(a2.details.pause_ref, 'rejected:file,journald'); assert.match(a2.summary, /pause file, journald/);

    // while that alert is open the ask moves to a third rejected list: the open one is closed with a note, the next cycle raises the new one
    await ask('rej', ['http']); await say('rej', '', 'http');
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });
    assert.match((await notes(a2.id))[0].body, /different list/);
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
    al = await alerts(); assert.strictEqual(al.length, 3); const a3 = al[2]; assert.strictEqual(a3.details.pause_ref, 'rejected:http');

    // the operator asks to resume everything (nothing is rejected for an empty list): the alert closes with a note
    await ask('rej', []);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });
    const n = await notes(a3.id); assert.strictEqual(n.length, 1); assert.strictEqual(n[0].author_name, 'ASIX'); assert.match(n[0].body, /applied the list|no longer asks/);

    // ask for the journal again, the broker rejects it again: the same list as the first alert, which was closed by hand a while ago, but a newer alert
    // exists for another list, so this is a new problem and is raised
    await ask('rej', ['journald']); await say('rej', '', 'journald');
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
    al = await alerts(); const a4 = al[al.length - 1]; assert.strictEqual(a4.details.pause_ref, 'rejected:journald');
    // the fix: the broker applies it -> the alert closes with a note
    await say('rej', 'journald', null);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });
    assert.match((await notes(a4.id))[0].body, /applied the list/);

    // the tenant-wide "watch everything" switch covers the unwatched broker that rejected its list
    await db.query('INSERT INTO collector_watch_defaults (tenant_id, watch_disconnect) VALUES ($1, true)', [TENANT]);
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
    assert.ok((await alerts()).some((a) => a.group_key === 'brokerpause:' + oid.unw));
    // stopping the watch closes; deleting the broker closes
    await db.query('UPDATE collector_watch_defaults SET watch_disconnect = false WHERE tenant_id = $1', [TENANT]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });
    await db.query("UPDATE alerts SET status = 'open' WHERE group_key = $1 AND rule_name = $2", ['brokerpause:' + oid.unw, pw.RULE_NAME]);
    await db.query('DELETE FROM collectors WHERE id = $1', [oid.unw]);
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });

    // the watchdog's real cycle runs it too, without error
    const total = await wd.runOnce({ raiseAllowed: true });
    assert.strictEqual(total.errors, 0);
    console.log('broker-pause-watch-db: all checks passed');
  } finally {
    srv.close();
    for (const t of ['notification_deliveries', 'notification_channels', 'alert_notes', 'alerts', 'collector_watch_defaults', 'collectors', 'ingestion_keys']) await db.query(`DELETE FROM ${t} WHERE tenant_id = ANY($1)`, [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

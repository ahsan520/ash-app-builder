'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-pause-overdue-db.test.js
// Skips itself otherwise. Real queries, the real heartbeat lane, the real pause route (which stamps collectors.inputs_paused_at), the real broker report route and
// the real Brokers page route; the pause watch is run with the real watchdog query. Only the sign-in chain is replaced.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');
const { generateKey, hashKey } = require('../src/ingest/http-ingest');
const { setEventStore } = require('../src/events'); const { MemoryEventStore } = require('../src/events/memory-store');
setEventStore(new MemoryEventStore());

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = 'tester'; next(); }] };
const pw = require('../src/collectors/pause-watch');
const wd = require('../src/collectors/watchdog');

async function main() {
  delete process.env.ASIX_PAUSE_OVERDUE_MIN;   // the default, 30 minutes
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['po-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['po-b-' + stamp])).rows[0].id;
  const mkKey = async (tenant, name) => { const key = generateKey(); await db.query("INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1,$2,'linux',$3,$4)", [tenant, name + '-' + stamp, key.slice(0, 12), hashKey(key)]); return key; };
  // late: asked long ago, pending. soon: asked a few minutes ago. nev: asked long ago, never reported. app: asked long ago, applied. rej: asked long ago, rejected.
  // stl: asked long ago, last report old. unw: late but not watched. oth: late, other tenant.
  const names = {}; const keys = {};
  for (const k of ['late', 'soon', 'nev', 'app', 'rej', 'stl', 'unw', 'oth']) { names[k] = k + '-' + stamp; keys[k] = await mkKey(k === 'oth' ? OTHER : TENANT, k); }

  const app = express(); app.use(require('../src/ingest/heartbeat').router); app.use(require('../src/ingest/broker-config').router); app.use(express.json());
  app.use(require('../src/gateway/routes/broker-inputs')); app.use(require('../src/gateway/routes/brokers'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = (method, p, body, key) => fetch(base + p, { method, headers: { 'content-type': 'application/json', ...(key ? { authorization: 'Bearer ' + key } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  const beat = (k) => call('POST', '/v1/ingest/heartbeat', { collector: { name: names[k], platform: 'linux', version: 'vector-0.59.0' } }, keys[k]);
  const say = async (k, paused, rejected) => { const r = await call('POST', '/v1/ingest/broker-config/report', { collector: names[k], syslog_port: 514, rejected_port: null, paused_inputs: paused, ...(rejected === undefined ? {} : { rejected_paused_inputs: rejected }) }, keys[k]); assert.strictEqual((await r.json()).recorded, true, k); };
  const id = async (k) => (await db.query('SELECT id FROM collectors WHERE name = $1', [names[k]])).rows[0].id;
  const ask = async (k, list) => { const r = await call('PUT', '/v1/brokers/' + (await id(k)) + '/inputs-paused', { paused: list }); assert.strictEqual(r.status, 200, k); };
  const askedAt = async (k) => (await db.query('SELECT inputs_paused_at AS t FROM collectors WHERE name = $1', [names[k]])).rows[0].t;
  const backdate = (k, min) => db.query("UPDATE collectors SET inputs_paused_at = localtimestamp - ($2 || ' minutes')::interval WHERE name = $1", [names[k], String(min)]);
  const alerts = async () => (await db.query('SELECT id, status, title, summary, group_key, details FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY created_at, id', [TENANT, pw.RULE_NAME])).rows;
  const notes = async (aid) => (await db.query('SELECT author_name, body FROM alert_notes WHERE alert_id = $1', [aid])).rows;
  const cycle = (o) => pw.runTenant(TENANT, o);
  const page = async () => (await (await fetch(base + '/v1/brokers')).json());
  try {
    for (const k of Object.keys(names)) assert.strictEqual((await beat(k)).status, 200);
    const oid = {}; for (const k of Object.keys(names)) oid[k] = await id(k);

    // --- the pause route stamps the time the ask CHANGED
    assert.strictEqual(await askedAt('late'), null, 'nothing asked yet, no time');
    await ask('late', []); assert.strictEqual(await askedAt('late'), null, 'clearing a list that was never set stays NULL');
    await ask('late', ['file']); const t1 = await askedAt('late'); assert.ok(t1, 'the ask is stamped');
    await backdate('late', 40); const t2 = await askedAt('late');
    await ask('late', ['file']); assert.strictEqual((await askedAt('late')).getTime(), t2.getTime(), 'saving the same list again keeps the time (Save twice cannot reset the clock)');
    await ask('late', ['journald', 'file']); const t3 = await askedAt('late'); assert.ok(t3.getTime() > t2.getTime(), 'a different list moves the time');
    await ask('late', ['file']); await backdate('late', 40);   // back to the list used below, asked 40 minutes ago
    await ask('late', []); const t4 = await askedAt('late'); assert.ok(Date.now() - t4.getTime() < 60000, 'a resume is a change and moves the time');
    await ask('late', ['file']); await backdate('late', 40);

    // --- set the scene
    await say('late', ''); await ask('soon', ['http']); await say('soon', '');
    await ask('nev', ['journald']);                                    // never reported (did not opt in, or its timer is not running)
    await ask('app', ['file']); await say('app', 'file');
    await ask('rej', ['http']); await say('rej', '', 'http');
    await ask('stl', ['file']); await say('stl', '');
    await ask('unw', ['file']); await say('unw', '');
    await db.query("UPDATE collectors SET inputs_paused = 'file', config_paused_inputs = '', config_reported_at = localtimestamp, watch_disconnect = true WHERE id = $1", [oid.oth]);   // another tenant's broker, same trouble (the route is tenant-scoped, so set directly)
    await backdate('soon', 5);
    for (const k of ['nev', 'app', 'rej', 'stl', 'unw', 'oth']) await backdate(k, 120);   // (oth has no ask time yet from the route: backdate stamps it)
    await db.query("UPDATE collectors SET config_reported_at = localtimestamp - interval '3 hours' WHERE name = $1", [names.stl]);
    await db.query('UPDATE collectors SET watch_disconnect = true WHERE id = ANY($1)', [[oid.late, oid.soon, oid.nev, oid.app, oid.rej, oid.stl]]);   // unw is NOT watched
    await db.query("INSERT INTO collectors (tenant_id, name, platform, version, last_seen, watch_disconnect, inputs_paused, inputs_paused_at, config_paused_inputs, config_reported_at) VALUES ($1,$2,'linux','1.2.3',localtimestamp,true,'file',localtimestamp - interval '3 hours','',localtimestamp)", [TENANT, 'plain-' + stamp]);   // not a broker

    // --- start-up grace raises nothing; then exactly: late (pending too long), nev (never reported), rej (the rejection). Not soon, app, stl, unw, plain, oth.
    assert.deepStrictEqual(await cycle({ raiseAllowed: false }), { raised: 0, closed: 0 });
    assert.deepStrictEqual(await cycle(), { raised: 3, closed: 0 });
    let al = await alerts(); const by = Object.fromEntries(al.map((a) => [a.group_key, a]));
    assert.deepStrictEqual(Object.keys(by).sort(), ['brokerpause:' + oid.late, 'brokerpause:' + oid.nev, 'brokerpause:' + oid.rej].sort());
    const aLate = by['brokerpause:' + oid.late], aNev = by['brokerpause:' + oid.nev], aRej = by['brokerpause:' + oid.rej];
    assert.strictEqual(aLate.details.kind, 'overdue'); assert.match(aLate.details.pause_ref, /^overdue:file@\d+$/); assert.strictEqual(aLate.title, 'Broker input pause not applied: ' + names.late);
    assert.match(aLate.summary, /asked to pause file about 4\d minutes ago and has not applied it, so those inputs are still running/); assert.match(aLate.summary, /reports a different list/);
    assert.strictEqual(aNev.details.kind, 'overdue'); assert.match(aNev.summary, /never reported on this setting/); assert.match(aNev.summary, /about 12\d minutes ago/);
    assert.strictEqual(aRej.details.kind, 'rejected'); assert.strictEqual(aRej.details.pause_ref, 'rejected:http');
    assert.strictEqual((await db.query('SELECT count(*)::int AS n FROM alerts WHERE tenant_id = $1 AND rule_name = $2', [OTHER, pw.RULE_NAME])).rows[0].n, 0);

    // --- the Brokers page says the same thing the alert does (both ask paused.pausedState), and counts it
    const pg = await page(); const bn = Object.fromEntries(pg.brokers.map((b) => [b.name, b.inputs_paused]));
    assert.strictEqual(bn[names.late].overdue, true); assert.strictEqual(bn[names.nev].overdue, true);
    assert.strictEqual(bn[names.unw].overdue, true, 'the page shows it for an unwatched broker too (watching only decides whether an alert is raised)');
    for (const k of ['soon', 'app', 'rej', 'stl']) assert.strictEqual(bn[names[k]].overdue, false, k);
    assert.strictEqual(bn[names.late].state, 'pending'); assert.strictEqual(bn[names.nev].state, 'unknown'); assert.ok(bn[names.late].asked_at);
    assert.strictEqual(pg.summary.paused_overdue, 3);   // late, nev and the unwatched unw

    // --- no repeat while open or acknowledged, nor after a hand close of the same ask
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    await db.query("UPDATE alerts SET status = 'acknowledged' WHERE id = $1", [aLate.id]); assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    await db.query("UPDATE alerts SET status = 'closed' WHERE id = $1", [aLate.id]); assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    await ask('late', ['file']); assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 }, 'saving the same list again is not a new ask');

    // --- a different list asked later is a new problem
    await ask('late', ['file', 'http']); await backdate('late', 40);
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
    al = await alerts(); const aLate2 = al.filter((a) => a.group_key === 'brokerpause:' + oid.late).pop(); assert.match(aLate2.summary, /pause file, http/);

    // --- the broker applies it: closed with a note; so does nev when it finally reports it
    await say('late', 'file,http'); await say('nev', 'journald');
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 2 });
    assert.match((await notes(aLate2.id))[0].body, /applied the list/); assert.strictEqual((await notes(aLate2.id))[0].author_name, 'ASIX');
    assert.strictEqual((await page()).summary.paused_overdue, 1);   // only the unwatched unw is left

    // --- a rejection wins over an overdue ask: late asks for something new, is overdue, and then rejects it -> the overdue alert closes and the rejection is raised next
    await ask('late', ['journald']); await say('late', 'file,http'); await backdate('late', 50);
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
    const aOver = (await alerts()).filter((a) => a.group_key === 'brokerpause:' + oid.late).pop(); assert.strictEqual(aOver.details.kind, 'overdue');
    await say('late', 'file,http', 'journald');
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 }); assert.match((await notes(aOver.id))[0].body, /different list/);
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
    assert.strictEqual((await alerts()).filter((a) => a.group_key === 'brokerpause:' + oid.late).pop().details.kind, 'rejected');

    // --- ASIX_PAUSE_OVERDUE_MIN = 0 turns the overdue side off (page and alert), and leaves the rejection alone
    process.env.ASIX_PAUSE_OVERDUE_MIN = '0';
    await ask('soon', ['http', 'file']); await backdate('soon', 200); await say('soon', 'http');
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    assert.strictEqual((await page()).summary.paused_overdue, 0);
    process.env.ASIX_PAUSE_OVERDUE_MIN = '60';
    assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 }, 'a 60 minute limit: soon (200 minutes) is overdue');
    assert.strictEqual((await page()).summary.paused_overdue, 2);   // soon (200 min) and unw (120 min)
    delete process.env.ASIX_PAUSE_OVERDUE_MIN;

    // --- resume closes it; the watchdog's real cycle runs the pause watch without error
    await ask('soon', []); await say('soon', '');
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });
    // a watched broker asked before the column existed (no time) is never called overdue
    await db.query('UPDATE collectors SET inputs_paused_at = NULL WHERE id = $1', [oid.nev]); await say('nev', ''); await ask('nev', ['journald']); await db.query('UPDATE collectors SET inputs_paused_at = NULL WHERE id = $1', [oid.nev]);
    assert.strictEqual((await page()).brokers.find((b) => b.name === names.nev).inputs_paused.overdue, false);
    const total = await wd.runOnce({ raiseAllowed: true }); assert.strictEqual(total.errors, 0);
    console.log('broker-pause-overdue-db: all checks passed');
  } finally {
    delete process.env.ASIX_PAUSE_OVERDUE_MIN;
    srv.close();
    for (const t of ['notification_deliveries', 'notification_channels', 'alert_notes', 'alerts', 'collector_watch_defaults', 'collectors', 'ingestion_keys']) await db.query(`DELETE FROM ${t} WHERE tenant_id = ANY($1)`, [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/collector-silence-db.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected. Real queries and the real event store (PostgreSQL); only the
// sign-in chain is replaced. Checks the collector list route too, because it now returns the setting.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

process.env.NOTIFY_ENCRYPTION_KEY = process.env.NOTIFY_ENCRYPTION_KEY || Buffer.alloc(32, 7).toString('base64');   // only for the notification check below
const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }],
};
const sl = require('../src/collectors/silence');
const wd = require('../src/collectors/watchdog');
const dispatcher = require('../src/notifications/dispatcher');
const box = require('../src/notifications/secret-box');
const { getEventStore } = require('../src/events');

const MIN = 60000;
const ago = (m) => new Date(Date.now() - m * MIN).toISOString();

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['sl-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['sl-b-' + stamp])).rows[0].id;
  const store = getEventStore();
  // heartbeat age (minutes) is what keeps a collector "Connected"; events are separate rows in the event store
  const addCollector = async (tenant, name, hbMinutesAgo) => (await db.query(
    "INSERT INTO collectors (tenant_id, name, platform, last_seen) VALUES ($1,$2,'linux', localtimestamp - ($3 || ' minutes')::interval) RETURNING id",
    [tenant, name, String(hbMinutesAgo)])).rows[0].id;
  const addEvent = (tenant, collector, minutesAgo) => store.insertBatch(tenant, [{ source_type: 'syslog', collector_id: collector, raw: 'line', parsed: {}, received_at: ago(minutesAgo) }]);

  const nSilent = 'silent-' + stamp, nFine = 'fine-' + stamp, nUnwatched = 'unwatched-' + stamp, nDown = 'down-' + stamp, nForeign = 'foreign-' + stamp, nNoEvents = 'noevents-' + stamp;
  const silent = await addCollector(TENANT, nSilent, 1);        // alive, but its newest event is 90 minutes old
  const fine = await addCollector(TENANT, nFine, 1);            // alive, events flowing
  const unwatched = await addCollector(TENANT, nUnwatched, 1);  // alive and silent, but not watched
  const down = await addCollector(TENANT, nDown, 120);          // silent AND Disconnected: the other alert's business
  const noEvents = await addCollector(TENANT, nNoEvents, 1);    // watched, never sent an event
  const foreign = await addCollector(OTHER, nForeign, 1);
  await addEvent(TENANT, nSilent, 90); await addEvent(TENANT, nSilent, 300);
  await addEvent(TENANT, nFine, 2);
  await addEvent(TENANT, nUnwatched, 90);
  await addEvent(TENANT, nDown, 90);
  await addEvent(OTHER, nForeign, 90);

  await db.query("INSERT INTO notification_channels (tenant_id, name, type, enabled, min_severity, config_enc) VALUES ($1,'sl-hook','webhook',true,'high',$2)", [TENANT, box.encrypt({ url: 'https://example.com/hook', format: 'json', headers: {}, signing_secret: '', routing_key: '' })]);
  const alerts = async (tenant = TENANT) => (await db.query('SELECT id, status, severity, title, group_key, rule_id, details FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY created_at', [tenant, sl.RULE_NAME])).rows;
  const notes = async (id) => (await db.query('SELECT author_name, body FROM alert_notes WHERE alert_id = $1', [id])).rows;
  const cycle = (o) => sl.runTenant(TENANT, o);

  try {
    // nothing is watched yet: nothing is raised (deploying this changes nothing by itself)
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    assert.strictEqual((await alerts()).length, 0);

    // the column is NULL by default and takes the route's update, tenant-scoped
    assert.strictEqual((await db.query('SELECT watch_silent_min FROM collectors WHERE id = $1', [silent])).rows[0].watch_silent_min, null);
    const srv = express(); srv.use(express.json()); srv.use(require('../src/gateway/routes/collector-silent')); srv.use(require('../src/gateway/routes/collectors'));
    const http = srv.listen(0); const base = 'http://127.0.0.1:' + http.address().port;
    const put = async (id, minutes) => (await fetch(base + '/v1/collectors/' + id + '/silent-watch', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ minutes }) })).status;
    try {
      for (const id of [silent, fine, down, noEvents]) assert.strictEqual(await put(id, 60), 200);
      assert.strictEqual(await put(foreign, 60), 404);
      assert.strictEqual(await put(silent, 1), 400);
      assert.strictEqual((await db.query('SELECT watch_silent_min FROM collectors WHERE id = $1', [foreign])).rows[0].watch_silent_min, null, 'other tenant untouched');

      // the collector list returns the setting (and null where it is off)
      const list = await (await fetch(base + '/v1/collectors?limit=200')).json();
      const by = Object.fromEntries(list.collectors.map((c) => [c.name, c]));
      assert.strictEqual(by[nSilent].watch_silent_min, 60); assert.strictEqual(by[nUnwatched].watch_silent_min, null);

      // start-up grace: no new alert
      assert.deepStrictEqual(await cycle({ raiseAllowed: false }), { raised: 0, closed: 0 });
      // exactly one alert: the silent one. Not the flowing one, the unwatched one, the Disconnected one, the one with no events, or another tenant's
      assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
      let a = await alerts(); assert.strictEqual(a.length, 1);
      assert.strictEqual(a[0].status, 'open'); assert.strictEqual(a[0].severity, 'high'); assert.strictEqual(a[0].rule_id, null);
      assert.strictEqual(a[0].group_key, 'silent:' + silent); assert.strictEqual(a[0].title, 'Collector sending no events: ' + nSilent);
      assert.strictEqual(a[0].details.collector_id, silent); assert.strictEqual(a[0].details.silent_after_min, 60);
      assert.ok(Math.abs(Date.parse(a[0].details.last_event) - (Date.now() - 90 * MIN)) < 2 * MIN, 'raised for the NEWEST event (90 min ago, not 300)');
      assert.strictEqual((await alerts(OTHER)).length, 0);

      // the existing dispatcher sends it like any other alert, once
      const sent = [];
      const d1 = await dispatcher.runTenant(TENANT, { send: async (type, cfg, msg) => { sent.push({ type, msg }); } });
      assert.strictEqual(d1.queued, 1); assert.strictEqual(sent.length, 1);
      assert.strictEqual(sent[0].msg.rule, 'Collector sending no events'); assert.strictEqual(sent[0].msg.title, 'Collector sending no events: ' + nSilent);
      assert.strictEqual((await dispatcher.runTenant(TENANT, { send: async () => { throw new Error('must not send again'); } })).queued, 0);

      // a second cycle, and an acknowledged alert, raise nothing more
      assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
      await db.query("UPDATE alerts SET status = 'acknowledged' WHERE id = $1", [a[0].id]);
      assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });

      // closed by hand while still silent: the same silence does not raise again
      await db.query("UPDATE alerts SET status = 'closed' WHERE id = $1", [a[0].id]);
      assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
      assert.strictEqual((await alerts()).length, 1);

      // reopen it, then events arrive again: closed with an ASIX note
      await db.query("UPDATE alerts SET status = 'open' WHERE id = $1", [a[0].id]);
      await addEvent(TENANT, nSilent, 1);
      assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });
      a = await alerts(); assert.strictEqual(a[0].status, 'closed');
      const n = await notes(a[0].id); assert.strictEqual(n.length, 1); assert.strictEqual(n[0].author_name, 'ASIX'); assert.match(n[0].body, /arriving from the collector again/);

      // a new silence raises a new alert: move the clock 100 minutes on (and the heartbeat with it, so the collector still counts as Connected)
      const later = Date.now() + 100 * MIN;
      await db.query("UPDATE collectors SET last_seen = localtimestamp + interval '99 minutes' WHERE id = $1", [silent]);
      assert.deepStrictEqual(await cycle({ now: later }), { raised: 1, closed: 0 });
      a = await alerts(); assert.strictEqual(a.length, 2); assert.strictEqual(a[1].status, 'open');
      assert.notStrictEqual(a[1].details.last_event, a[0].details.last_event, 'the second alert is for the newer silence');

      // a limit longer than the gap closes the open alert (the collector is not silent by that measure any more)
      await db.query('UPDATE collectors SET watch_silent_min = 240 WHERE id = $1', [silent]);
      assert.deepStrictEqual(await cycle({ now: later }), { raised: 0, closed: 1 });
      await db.query('UPDATE collectors SET watch_silent_min = 60 WHERE id = $1', [silent]);
      assert.deepStrictEqual(await cycle({ now: later }), { raised: 0, closed: 0 }, 'the same silence was closed: not raised again');

      // a Disconnected collector is left to the other alert until it counts as Connected (a longer connected threshold)
      await db.query('UPDATE collectors SET connected_within_min = 300 WHERE id = $1', [down]);
      assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
      assert.strictEqual((await alerts()).filter((x) => x.group_key === 'silent:' + down).length, 1);
      await db.query('UPDATE collectors SET connected_within_min = NULL WHERE id = $1', [down]);

      // switching the watch off closes the open alert; deleting the collector does too
      assert.strictEqual(await put(down, null), 200);
      assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });
      assert.strictEqual(await put(noEvents, 60), 200);
      await db.query("UPDATE alerts SET status = 'open' WHERE id = (SELECT id FROM alerts WHERE tenant_id = $1 AND group_key = $2 ORDER BY created_at DESC LIMIT 1)", [TENANT, 'silent:' + silent]);
      await db.query('DELETE FROM collectors WHERE id = $1', [silent]);
      assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });

      // the watched collector that never sent an event was never raised for, and the unwatched and flowing ones neither
      assert.deepStrictEqual((await alerts()).filter((x) => [nNoEvents, nUnwatched, nFine].some((nm) => x.title.endsWith(nm))), []);
      assert.ok(unwatched && fine && noEvents, 'ids used above');
    } finally { http.close(); }
    console.log('collector-silence-db: all checks passed');
  } finally {
    await db.query('DELETE FROM notification_deliveries WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM notification_channels WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM alerts WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM collectors WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await store.deleteBefore(TENANT, '2999-01-01T00:00:00Z').catch(() => {});
    await store.deleteBefore(OTHER, '2999-01-01T00:00:00Z').catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

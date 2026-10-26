'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/collector-watch-db.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected. Real queries; only the sign-in chain is replaced.
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
const wd = require('../src/collectors/watchdog');
const dispatcher = require('../src/notifications/dispatcher');
const box = require('../src/notifications/secret-box');

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['wd-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['wd-b-' + stamp])).rows[0].id;
  const addCollector = async (tenant, name, minutesAgo) => (await db.query(
    "INSERT INTO collectors (tenant_id, name, platform, last_seen) VALUES ($1,$2,'linux', localtimestamp - ($3 || ' minutes')::interval) RETURNING id",
    [tenant, name, String(minutesAgo)])).rows[0].id;
  const down = await addCollector(TENANT, 'down-' + stamp, 60);
  const fine = await addCollector(TENANT, 'fine-' + stamp, 1);
  const unwatched = await addCollector(TENANT, 'unwatched-' + stamp, 60);
  const foreign = await addCollector(OTHER, 'foreign-' + stamp, 60);

  // a webhook channel at the default minimum severity ('high'), made before any alert exists (a channel never back-fills)
  await db.query("INSERT INTO notification_channels (tenant_id, name, type, enabled, min_severity, config_enc) VALUES ($1,'wd-hook','webhook',true,'high',$2)", [TENANT, box.encrypt({ url: 'https://example.com/hook', format: 'json', headers: {}, signing_secret: '', routing_key: '' })]);
  const alerts = async (tenant = TENANT) => (await db.query("SELECT id, status, severity, title, group_key, rule_id, details FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY created_at", [tenant, wd.RULE_NAME])).rows;
  const notes = async (id) => (await db.query('SELECT author_name, body FROM alert_notes WHERE alert_id = $1', [id])).rows;
  const cycle = (o) => wd.runTenant(TENANT, o);

  try {
    // nothing is watched yet: nothing is raised (deploying this changes nothing by itself)
    assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
    assert.strictEqual((await alerts()).length, 0);

    // the column defaults to false and accepts the route's update, tenant-scoped
    assert.strictEqual((await db.query('SELECT watch_disconnect FROM collectors WHERE id = $1', [down])).rows[0].watch_disconnect, false);
    const srv = express(); srv.use(express.json()); srv.use(require('../src/gateway/routes/collector-watch'));
    const http = srv.listen(0); const base = 'http://127.0.0.1:' + http.address().port;
    const put = async (id, watch) => { const r = await fetch(base + '/v1/collectors/' + id + '/watch', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ watch }) }); return r.status; };
    try {
      assert.strictEqual(await put(down, true), 200); assert.strictEqual(await put(fine, true), 200);
      assert.strictEqual(await put(foreign, true), 404);
      assert.strictEqual((await db.query('SELECT watch_disconnect FROM collectors WHERE id = $1', [foreign])).rows[0].watch_disconnect, false, 'other tenant untouched');

      // start-up grace: no new alert
      assert.deepStrictEqual(await cycle({ raiseAllowed: false }), { raised: 0, closed: 0 });
      // the down one raises exactly one alert; the connected and the unwatched ones none
      assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
      let a = await alerts(); assert.strictEqual(a.length, 1);
      assert.strictEqual(a[0].status, 'open'); assert.strictEqual(a[0].severity, 'high'); assert.strictEqual(a[0].rule_id, null);
      assert.strictEqual(a[0].group_key, 'collector:' + down); assert.strictEqual(a[0].title, 'Collector disconnected: down-' + stamp);
      assert.strictEqual(a[0].details.collector_id, down);
      assert.strictEqual((await alerts(OTHER)).length, 0);

      // the notification dispatcher sends it like any other alert, once
      const sent = [];
      const d1 = await dispatcher.runTenant(TENANT, { send: async (type, cfg, msg) => { sent.push({ type, msg }); } });
      assert.strictEqual(d1.queued, 1); assert.strictEqual(sent.length, 1);
      assert.strictEqual(sent[0].msg.title, 'Collector disconnected: down-' + stamp); assert.strictEqual(sent[0].msg.severity, 'high'); assert.strictEqual(sent[0].msg.rule, 'Collector disconnected');
      assert.strictEqual((await dispatcher.runTenant(TENANT, { send: async () => { throw new Error('must not send again'); } })).queued, 0);

      // a second cycle, and an acknowledged alert, raise nothing more
      assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
      await db.query("UPDATE alerts SET status = 'acknowledged' WHERE id = $1", [a[0].id]);
      assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });

      // closed by hand while the collector is still down: same outage, no new alert
      await db.query("UPDATE alerts SET status = 'closed' WHERE id = $1", [a[0].id]);
      assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 });
      assert.strictEqual((await alerts()).length, 1);

      // reopen it, then the collector comes back: closed with an ASIX note
      await db.query("UPDATE alerts SET status = 'open' WHERE id = $1", [a[0].id]);
      await db.query('UPDATE collectors SET last_seen = localtimestamp WHERE id = $1', [down]);
      assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });
      a = await alerts(); assert.strictEqual(a[0].status, 'closed');
      const n = await notes(a[0].id); assert.strictEqual(n.length, 1); assert.strictEqual(n[0].author_name, 'ASIX'); assert.match(n[0].body, /connected again/);

      // a new outage raises a new alert
      await db.query("UPDATE collectors SET last_seen = localtimestamp - interval '45 minutes' WHERE id = $1", [down]);
      assert.deepStrictEqual(await cycle(), { raised: 1, closed: 0 });
      assert.strictEqual((await alerts()).length, 2);

      // a custom threshold longer than the gap keeps it quiet and closes the open alert (it counts as Connected again)
      await db.query('UPDATE collectors SET connected_within_min = 120 WHERE id = $1', [down]);
      assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });
      await db.query('UPDATE collectors SET connected_within_min = NULL WHERE id = $1', [down]);

      // switching watching off closes the open alert; deleting the collector does too
      assert.deepStrictEqual(await cycle(), { raised: 0, closed: 0 }, 'the second outage is the same last_seen: not raised again once closed');
      await db.query("UPDATE alerts SET status = 'open' WHERE id = (SELECT id FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY created_at DESC LIMIT 1)", [TENANT, wd.RULE_NAME]);
      assert.strictEqual(await put(down, false), 200);
      assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });
      assert.strictEqual(await put(down, true), 200);
      await db.query("UPDATE alerts SET status = 'open' WHERE tenant_id = $1 AND rule_name = $2 AND status = 'closed' AND created_at = (SELECT max(created_at) FROM alerts WHERE tenant_id = $1 AND rule_name = $2)", [TENANT, wd.RULE_NAME]);
      await db.query('DELETE FROM collectors WHERE id = $1', [down]);
      assert.deepStrictEqual(await cycle(), { raised: 0, closed: 1 });

      assert.ok(unwatched, 'the unwatched collector never raised anything (checked by the single raise above)');
    } finally { http.close(); }
    console.log('collector-watch-db: all checks passed');
  } finally {
    await db.query('DELETE FROM notification_deliveries WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM notification_channels WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM alerts WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM collectors WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

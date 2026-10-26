'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/collector-watch-exclude-db.test.js
// Skips itself otherwise. Real queries, the real PostgreSQL event store and the real watchdog, silence and broker-key checks;
// only the sign-in chain is replaced. Checks "Leave out of all" (collectors.watch_exclude) end to end.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = null; next(); }],
};
const wa = require('../src/collectors/watch-all');
const wd = require('../src/collectors/watchdog');
const sl = require('../src/collectors/silence');
const kw = require('../src/collectors/key-watch');
const { generateKey, hashKey } = require('../src/ingest/http-ingest');
const { getEventStore } = require('../src/events');

const ago = (m) => new Date(Date.now() - m * 60000).toISOString();

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['wx-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['wx-b-' + stamp])).rows[0].id;
  const store = getEventStore();
  const n = (s) => s + '-' + stamp;
  const add = async (tenant, name, hbMinutesAgo, o = {}) => (await db.query(
    `INSERT INTO collectors (tenant_id, name, platform, version, key_id, last_seen, watch_disconnect, watch_silent_min, watch_exclude)
     VALUES ($1,$2,'linux',$3,$4, localtimestamp - ($5 || ' minutes')::interval, $6, $7, $8) RETURNING id`,
    [tenant, name, o.version || null, o.key_id || null, String(hbMinutesAgo), o.watch === true, o.silent || null, o.exclude === true])).rows[0].id;
  const event = (collector, minutesAgo) => store.insertBatch(TENANT, [{ source_type: 'syslog', collector_id: collector, raw: 'line', parsed: {}, received_at: ago(minutesAgo) }]);
  const key = generateKey();
  const keyId = (await db.query("INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash, status) VALUES ($1,$2,'linux',$3,$4,'revoked') RETURNING id", [TENANT, 'k-' + stamp, key.slice(0, 12), hashKey(key)])).rows[0].id;

  const down = await add(TENANT, n('down'), 120);                                            // covered by the switch
  const downX = await add(TENANT, n('downX'), 120, { exclude: true });                       // left out: nothing raised
  const manualX = await add(TENANT, n('manualX'), 120, { exclude: true, watch: true });      // left out, but "Alert if down" by hand: still alerts
  const silent = await add(TENANT, n('silent'), 1);                                          // covered: silent
  const silentX = await add(TENANT, n('silentX'), 1, { exclude: true });                     // left out: silent, nothing raised
  const ownX = await add(TENANT, n('ownX'), 1, { exclude: true, silent: 30 });               // left out, own limit 30: still alerts
  const brokerX = await add(TENANT, n('brokerX'), 1, { exclude: true, version: 'vector-0.59.0', key_id: keyId });   // broker on a revoked key, left out
  const broker = await add(TENANT, n('broker'), 1, { version: 'vector-0.59.0', key_id: keyId });                    // same, not left out
  const foreign = await add(OTHER, n('foreign'), 120);
  for (const name of ['silent', 'silentX', 'ownX']) await event(n(name), 90);

  const alerts = async (rule) => (await db.query('SELECT id, status, group_key FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY created_at', [TENANT, rule])).rows;
  const open = async (rule) => (await alerts(rule)).filter((a) => a.status !== 'closed').map((a) => a.group_key).sort();
  const srv = express(); srv.use(express.json()); srv.use(require('../src/gateway/routes/collector-watch-all')); srv.use(require('../src/gateway/routes/collector-watch-exclude')); srv.use(require('../src/gateway/routes/collectors'));
  const http = srv.listen(0); const base = 'http://127.0.0.1:' + http.address().port;
  const call = async (method, path, body) => { const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const list = async () => new Map((await call('GET', '/v1/collectors?limit=500')).json.collectors.map((c) => [c.name, c]));
  try {
    // 1. Switch on for everything: only the collectors not left out are covered, plus those with their own setting.
    assert.strictEqual((await call('PUT', '/v1/collector-watch-defaults', { disconnect: true, silent_min: 60 })).status, 200);
    await wd.runTenant(TENANT); await sl.runTenant(TENANT); await kw.runTenant(TENANT);
    assert.deepStrictEqual(await open(wd.RULE_NAME), ['collector:' + down, 'collector:' + manualX].sort(), 'left out raises nothing, a hand-set one still does');
    assert.deepStrictEqual(await open(sl.RULE_NAME), ['silent:' + silent, 'silent:' + ownX].sort(), 'left out raises nothing, its own limit still does');
    assert.deepStrictEqual(await open(kw.RULE_NAME), ['brokerkey:' + broker], 'a broker left out raises no key alert');

    // 2. The Collectors list says so, and the plain-code rules agree with the SQL the watchdogs ran.
    const L = await list(); const row = (s) => L.get(n(s));
    assert.deepStrictEqual([row('down'), row('downX'), row('manualX')].map((c) => [c.watch_exclude, c.watch_disconnect_by_default]), [[false, true], [true, false], [true, false]]);
    assert.deepStrictEqual([row('silent'), row('silentX'), row('ownX')].map((c) => c.watch_silent_by_default), [true, false, false]);
    const rows = (await db.query('SELECT id, last_seen, watch_disconnect, watch_silent_min, watch_exclude FROM collectors WHERE tenant_id = $1', [TENANT])).rows;
    const sql = (await db.query(`SELECT id FROM collectors WHERE tenant_id = $1 AND ${wa.WHERE_DISCONNECT}`, [TENANT, true, wa.cutoffOf(Date.now())])).rows.map((r) => r.id).sort();
    assert.deepStrictEqual(rows.filter((c) => wa.watchesDisconnect(c, { disconnect: true, silent_min: 60 })).map((c) => c.id).sort(), sql);
    const sm = new Map((await db.query(`SELECT id, ${wa.SILENT_MIN_SQL} AS m FROM collectors WHERE tenant_id = $1`, [TENANT, 60, wa.cutoffOf(Date.now())])).rows.map((r) => [r.id, r.m]));
    for (const c of rows) assert.strictEqual(wa.silentMinutes(c, { disconnect: true, silent_min: 60 }), sm.get(c.id), String(c.id));

    // 3. Leaving out a collector that already has an alert (held only by the switch) closes it, with a note.
    assert.strictEqual((await call('PUT', `/v1/collectors/${down}/watch-exclude`, { exclude: true })).status, 200);
    assert.deepStrictEqual(await wd.runTenant(TENANT), { raised: 0, closed: 1 });
    const closed = (await alerts(wd.RULE_NAME)).find((a) => a.group_key === 'collector:' + down);
    assert.strictEqual(closed.status, 'closed');
    const note = (await db.query('SELECT author_name, body FROM alert_notes WHERE alert_id = $1', [closed.id])).rows;
    assert.strictEqual(note.length, 1); assert.strictEqual(note[0].author_name, 'ASIX'); assert.match(note[0].body, /no longer watched/);
    assert.deepStrictEqual(await open(wd.RULE_NAME), ['collector:' + manualX], 'the hand-set collector keeps its alert');
    assert.strictEqual((await call('PUT', `/v1/collectors/${silent}/watch-exclude`, { exclude: true })).status, 200);
    assert.deepStrictEqual(await sl.runTenant(TENANT), { raised: 0, closed: 1 });
    assert.deepStrictEqual(await open(sl.RULE_NAME), ['silent:' + ownX]);
    assert.strictEqual((await call('PUT', `/v1/collectors/${broker}/watch-exclude`, { exclude: true })).status, 200);
    assert.deepStrictEqual(await kw.runTenant(TENANT), { raised: 0, closed: 1 });

    // 4. Putting one back covers it again: a new collector of the same kind is raised straight away.
    assert.strictEqual((await call('PUT', `/v1/collectors/${downX}/watch-exclude`, { exclude: false })).status, 200);
    assert.deepStrictEqual(await wd.runTenant(TENANT), { raised: 1, closed: 0 });
    assert.deepStrictEqual(await open(wd.RULE_NAME), ['collector:' + downX, 'collector:' + manualX].sort());
    assert.strictEqual((await list()).get(n('downX')).watch_disconnect_by_default, true);

    // 5. Another tenant's collector cannot be changed from here, and nothing changed on it.
    assert.strictEqual((await call('PUT', `/v1/collectors/${foreign}/watch-exclude`, { exclude: true })).status, 404);
    assert.strictEqual((await db.query('SELECT watch_exclude FROM collectors WHERE id = $1', [foreign])).rows[0].watch_exclude, false);
    assert.ok(brokerX && silentX);
    console.log('collector-watch-exclude-db: all checks passed');
  } finally {
    http.close();
    for (const t of ['alert_notes', 'alerts']) await db.query(`DELETE FROM ${t} WHERE ${t === 'alert_notes' ? 'alert_id IN (SELECT id FROM alerts WHERE tenant_id = ANY($1))' : 'tenant_id = ANY($1)'}`, [[TENANT, OTHER]]).catch(() => {});
    for (const t of ['collector_watch_defaults', 'collectors', 'ingestion_keys']) await db.query(`DELETE FROM ${t} WHERE tenant_id = ANY($1)`, [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/collector-watch-all-db.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected. Real queries, the real PostgreSQL event store and the real
// watchdog, silence and broker-key checks; only the sign-in chain is replaced. Checks that the SQL the watchdogs send and the
// plain-code rules in src/collectors/watch-all.js agree on the same rows.
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

const MIN = 60000;
const ago = (m) => new Date(Date.now() - m * MIN).toISOString();

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['wa-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['wa-b-' + stamp])).rows[0].id;
  const store = getEventStore();
  const addCollector = async (tenant, name, hbMinutesAgo, extra = {}) => (await db.query(
    `INSERT INTO collectors (tenant_id, name, platform, version, key_id, last_seen, watch_disconnect, watch_silent_min)
     VALUES ($1,$2,'linux',$3,$4, localtimestamp - ($5 || ' minutes')::interval, $6, $7) RETURNING id`,
    [tenant, name, extra.version || null, extra.key_id || null, String(hbMinutesAgo), extra.watch === true, extra.silent || null])).rows[0].id;
  const addEvent = (tenant, collector, minutesAgo) => store.insertBatch(tenant, [{ source_type: 'syslog', collector_id: collector, raw: 'line', parsed: {}, received_at: ago(minutesAgo) }]);
  const key = generateKey();
  const keyId = (await db.query("INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash, status) VALUES ($1,$2,'linux',$3,$4,'revoked') RETURNING id", [TENANT, 'k-' + stamp, key.slice(0, 12), hashKey(key)])).rows[0].id;

  const n = (s) => s + '-' + stamp;
  const down = await addCollector(TENANT, n('down'), 120);                       // Disconnected, nothing set by hand
  const ok = await addCollector(TENANT, n('ok'), 1);                             // connected
  const retired = await addCollector(TENANT, n('retired'), 10 * 24 * 60);        // gone for 10 days: left out of the switch
  const manual = await addCollector(TENANT, n('manual'), 10 * 24 * 60, { watch: true });   // same age, but switched on by hand: kept
  const brokerBad = await addCollector(TENANT, n('broker'), 1, { version: 'vector-0.59.0', key_id: keyId });   // broker on a revoked key
  const silent = await addCollector(TENANT, n('silent'), 1);                     // alive, newest event 90 min old
  const flowing = await addCollector(TENANT, n('flowing'), 1);                   // alive, events flowing
  const own = await addCollector(TENANT, n('own'), 1, { silent: 200 });          // own limit of 200 min wins over the switch
  const foreign = await addCollector(OTHER, n('foreign'), 120);                  // another tenant, Disconnected
  await addEvent(TENANT, n('silent'), 90); await addEvent(TENANT, n('flowing'), 2); await addEvent(TENANT, n('own'), 90);
  await addEvent(TENANT, n('retired'), 90);

  const alerts = async (rule, tenant = TENANT) => (await db.query('SELECT id, status, group_key FROM alerts WHERE tenant_id = $1 AND rule_name = $2 ORDER BY created_at', [tenant, rule])).rows;
  const keys = (rows) => rows.map((r) => r.group_key).sort();
  const dis = (o) => wd.runTenant(TENANT, o), sil = (o) => sl.runTenant(TENANT, o), brk = (o) => kw.runTenant(TENANT, o);

  const srv = express(); srv.use(express.json()); srv.use(require('../src/gateway/routes/collector-watch-all')); srv.use(require('../src/gateway/routes/collectors'));
  const http = srv.listen(0); const base = 'http://127.0.0.1:' + http.address().port;
  const call = async (method, path, body) => { const r = await fetch(base + path, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };
  const defaults = async () => (await call('GET', '/v1/collector-watch-defaults')).json.defaults;
  const list = async () => new Map((await call('GET', '/v1/collectors?limit=500')).json.collectors.map((c) => [c.name, c]));

  try {
    // 1. Nothing set: off, and the three checks raise nothing for the collector that is only Disconnected (deploying this changes nothing by itself).
    const d0 = await defaults();
    assert.deepStrictEqual([d0.disconnect, d0.silent_min, d0.max_age_days], [false, null, 7]);
    assert.deepStrictEqual(keys(await alerts(wd.RULE_NAME)), []);
    assert.deepStrictEqual(await dis(), { raised: 1, closed: 0 }, 'only the collector switched on by hand (manual) is watched');
    assert.deepStrictEqual(keys(await alerts(wd.RULE_NAME)), ['collector:' + manual]);
    assert.deepStrictEqual(await sil(), { raised: 0, closed: 0 });
    assert.deepStrictEqual(await brk(), { raised: 0, closed: 0 });

    // 2. Validation: nothing is stored for a bad request.
    for (const body of [{}, { disconnect: 'yes' }, { disconnect: 1 }, { silent_min: 4 }, { silent_min: 4321 }, { silent_min: 60.5 }, { silent_min: '60' }, [1]]) {
      assert.strictEqual((await call('PUT', '/v1/collector-watch-defaults', body)).status, 400, JSON.stringify(body));
    }
    assert.strictEqual((await db.query('SELECT count(*)::int AS n FROM collector_watch_defaults WHERE tenant_id = $1', [TENANT])).rows[0].n, 0);

    // 3. Switch the disconnect alert on for everything: the Disconnected collector is covered, the connected one and the retired one are not,
    //    the hand-switched one keeps its alert, and the broker on a revoked key raises the key alert.
    const put1 = await call('PUT', '/v1/collector-watch-defaults', { disconnect: true });
    assert.strictEqual(put1.status, 200); assert.strictEqual(put1.json.defaults.disconnect, true); assert.strictEqual(put1.json.defaults.silent_min, null);
    assert.strictEqual(put1.json.defaults.left_out_as_retired, 2, 'retired and manual are older than 7 days');
    assert.deepStrictEqual(await dis(), { raised: 1, closed: 0 });
    assert.deepStrictEqual(keys(await alerts(wd.RULE_NAME)), ['collector:' + down, 'collector:' + manual].sort());
    assert.deepStrictEqual(await dis(), { raised: 0, closed: 0 }, 'no duplicate on the next cycle');
    assert.deepStrictEqual(await brk(), { raised: 1, closed: 0 });
    assert.deepStrictEqual(keys(await alerts(kw.RULE_NAME)), ['brokerkey:' + brokerBad]);

    // 4. Silent limit for everything: the silent one is raised; the flowing one, the one with its own longer limit and the retired one are not.
    const put2 = await call('PUT', '/v1/collector-watch-defaults', { silent_min: 60 });
    assert.strictEqual(put2.status, 200); assert.strictEqual(put2.json.defaults.silent_min, 60); assert.strictEqual(put2.json.defaults.disconnect, true, 'what the request leaves out is kept');
    assert.deepStrictEqual(await sil(), { raised: 1, closed: 0 });
    assert.deepStrictEqual(keys(await alerts(sl.RULE_NAME)), ['silent:' + silent]);
    assert.strictEqual((await alerts(sl.RULE_NAME))[0].status, 'open');

    // 5. The Collectors list says what covers each row, and the plain-code rules agree with the SQL that was just run.
    const L = await list(); const lst = (name) => L.get(n(name));
    assert.deepStrictEqual(L.size >= 8, true);
    assert.deepStrictEqual([lst('down').watch_disconnect_by_default, lst('ok').watch_disconnect_by_default, lst('retired').watch_disconnect_by_default, lst('manual').watch_disconnect_by_default], [true, true, false, false]);
    assert.deepStrictEqual([lst('silent').watch_silent_by_default, lst('own').watch_silent_by_default, lst('retired').watch_silent_by_default], [true, false, false]);
    assert.deepStrictEqual([lst('own').watch_silent_min, lst('silent').watch_silent_min], [200, null], 'the list still shows only what was set on the collector');
    assert.deepStrictEqual((await call('GET', '/v1/collectors')).json.watch_defaults, { disconnect: true, silent_min: 60, max_age_days: 7 });
    const rows = (await db.query('SELECT id, name, last_seen, watch_disconnect, watch_silent_min FROM collectors WHERE tenant_id = $1', [TENANT])).rows;
    const sql = (await db.query(`SELECT id FROM collectors WHERE tenant_id = $1 AND ${wa.WHERE_DISCONNECT}`, [TENANT, true, wa.cutoffOf(Date.now())])).rows.map((r) => r.id).sort();
    assert.deepStrictEqual(rows.filter((c) => wa.watchesDisconnect(c, { disconnect: true, silent_min: 60 })).map((c) => c.id).sort(), sql);
    const sm = new Map((await db.query(`SELECT id, ${wa.SILENT_MIN_SQL} AS m FROM collectors WHERE tenant_id = $1`, [TENANT, 60, wa.cutoffOf(Date.now())])).rows.map((r) => [r.id, r.m]));
    for (const c of rows) assert.strictEqual(wa.silentMinutes(c, { disconnect: true, silent_min: 60 }), sm.get(c.id), c.name);

    // 6. Another tenant is not affected by this tenant's switch, and cannot see it.
    assert.deepStrictEqual(await wd.runTenant(OTHER), { raised: 0, closed: 0 });
    assert.deepStrictEqual(await sl.runTenant(OTHER), { raised: 0, closed: 0 });
    assert.strictEqual((await db.query('SELECT count(*)::int AS n FROM collector_watch_defaults WHERE tenant_id = $1', [OTHER])).rows[0].n, 0);
    assert.ok(foreign);

    // 7. A collector that was covered and then stops being covered: switch off closes only the alerts the switch was holding up.
    assert.strictEqual((await call('PUT', '/v1/collector-watch-defaults', { disconnect: false })).status, 200);
    assert.deepStrictEqual(await dis(), { raised: 0, closed: 1 });
    const left = await alerts(wd.RULE_NAME);
    assert.deepStrictEqual(left.filter((a) => a.status !== 'closed').map((a) => a.group_key), ['collector:' + manual], 'the hand-switched collector keeps its alert');
    const note = (await db.query("SELECT author_name, body FROM alert_notes WHERE alert_id = $1", [left.find((a) => a.group_key === 'collector:' + down).id])).rows;
    assert.strictEqual(note.length, 1); assert.strictEqual(note[0].author_name, 'ASIX'); assert.match(note[0].body, /no longer watched/);
    assert.deepStrictEqual(await brk(), { raised: 0, closed: 1 }, 'the broker key alert was only held by the switch');
    assert.deepStrictEqual((await defaults()).silent_min, 60, 'turning one off leaves the other');

    // 8. Silent limit off: its alert closes. A flowing collector never raised anything.
    assert.strictEqual((await call('PUT', '/v1/collector-watch-defaults', { silent_min: null })).status, 200);
    assert.deepStrictEqual(await sil(), { raised: 0, closed: 1 });
    assert.deepStrictEqual((await call('PUT', '/v1/collector-watch-defaults', { disconnect: false, silent_min: null })).json.defaults.silent_min, null);

    // 9. A collector coming back after the switch raised an alert closes it ("connected again"), like a hand-switched one.
    assert.strictEqual((await call('PUT', '/v1/collector-watch-defaults', { disconnect: true })).status, 200);
    assert.deepStrictEqual(await dis(), { raised: 0, closed: 0 }, 'the same outage that was closed when the switch went off is not raised again (same rule as a hand-switched collector)');
    await db.query("UPDATE collectors SET last_seen = localtimestamp - interval '130 minutes' WHERE id = $1", [down]);   // a new outage
    assert.deepStrictEqual(await dis(), { raised: 1, closed: 0 });
    await db.query('UPDATE collectors SET last_seen = localtimestamp WHERE id = $1', [down]);
    assert.deepStrictEqual(await dis(), { raised: 0, closed: 1 });
    assert.ok(ok && retired && flowing && own);
    console.log('collector-watch-all-db: all checks passed');
  } finally {
    http.close();
    await db.query('DELETE FROM alerts WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM collector_watch_defaults WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM collectors WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM ingestion_keys WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await store.deleteBefore(TENANT, '2999-01-01T00:00:00Z').catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

'use strict';
// Needs a real Postgres with the platform schema applied (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node tests/broker-watch-state-db.test.js
// Skips itself otherwise. The REAL GET /v1/brokers with real rows and the real "Watch everything" settings; only the sign-in chain
// and the event store are replaced. Proves the Brokers page's "Alert if down" column can say On (own button), On (all), Left out or Off,
// by the same rules as the Collectors page and the watchdog (src/collectors/watch-all.js).
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT;
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }] };
const { setEventStore } = require('../src/events'); const { MemoryEventStore } = require('../src/events/memory-store');
setEventStore(new MemoryEventStore());
const watchAll = require('../src/collectors/watch-all');

async function main() {
  const stamp = Date.now();
  TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['bws-a-' + stamp])).rows[0].id;
  const OTHER = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['bws-b-' + stamp])).rows[0].id;
  const add = (tenant, name, { minutesAgo = 1, watch = false, exclude = false } = {}) => db.query(
    "INSERT INTO collectors (tenant_id, name, platform, os, version, last_seen, watch_disconnect, watch_exclude) VALUES ($1,$2,'linux','Vector broker VM','vector-0.59.0', localtimestamp - ($3 || ' minutes')::interval, $4, $5)",
    [tenant, name, String(minutesAgo), watch, exclude]);
  const names = { own: 'own-' + stamp, plain: 'plain-' + stamp, left: 'left-' + stamp, leftOwn: 'leftown-' + stamp, retired: 'retired-' + stamp };
  await add(TENANT, names.own, { watch: true });
  await add(TENANT, names.plain);
  await add(TENANT, names.left, { exclude: true });
  await add(TENANT, names.leftOwn, { exclude: true, watch: true });
  await add(TENANT, names.retired, { minutesAgo: 60 * 24 * 30 });   // not seen for 30 days: the switch leaves it out
  await add(OTHER, 'foreign-' + stamp);

  const app = express(); app.use(require('../src/gateway/routes/brokers'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const get = async () => { const r = await (await fetch(base + '/v1/brokers')).json(); assert.strictEqual(r.success, true); return Object.fromEntries(r.brokers.map((b) => [b.name, b])); };
  const state = (b) => (b.watch_disconnect ? 'own' : b.watch_disconnect_by_default ? 'all' : b.watch_exclude ? 'left' : 'off');   // the portal's pill logic
  try {
    // ---- switch off (no row): only the broker's own button counts; nothing is "all"
    let by = await get();
    assert.deepStrictEqual(Object.fromEntries(Object.entries(names).map(([k, n]) => [k, state(by[n])])),
      { own: 'own', plain: 'off', left: 'left', leftOwn: 'own', retired: 'off' });
    assert.ok(!by['foreign-' + stamp], 'another tenant\'s broker is not listed');

    // ---- switch on: covered brokers say "all"; the left-out and the retired one do not; an own button still says own
    await db.withTenant(TENANT, (client) => watchAll.write(client, TENANT, { disconnect: true }));
    by = await get();
    assert.deepStrictEqual(Object.fromEntries(Object.entries(names).map(([k, n]) => [k, state(by[n])])),
      { own: 'own', plain: 'all', left: 'left', leftOwn: 'own', retired: 'off' });
    // the page and the watchdog's own SQL agree on who is covered
    const covered = (await db.withTenant(TENANT, (client) => client.query(
      `SELECT name FROM collectors WHERE tenant_id = $1 AND version ILIKE 'vector-%' AND ${watchAll.WHERE_DISCONNECT.replace('$2', '$2').replace('$3', '$3')}`,
      [TENANT, true, watchAll.cutoffOf(Date.now())]))).rows.map((r) => r.name).sort();
    const shown = Object.values(by).filter((b) => b.watch_disconnect || b.watch_disconnect_by_default).map((b) => b.name).sort();
    assert.deepStrictEqual(shown, covered);

    // ---- switch off again: back to the own buttons only
    await db.withTenant(TENANT, (client) => watchAll.write(client, TENANT, { disconnect: false }));
    by = await get();
    assert.strictEqual(state(by[names.plain]), 'off');

    // ---- another tenant's switch does not leak: turning it on for OTHER changes nothing here
    await db.withTenant(OTHER, (client) => watchAll.write(client, OTHER, { disconnect: true }));
    by = await get();
    assert.strictEqual(state(by[names.plain]), 'off');
    console.log('broker-watch-state-db: all checks passed');
  } finally {
    srv.close();
    await db.query('DELETE FROM collector_watch_defaults WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM collectors WHERE tenant_id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.query('DELETE FROM tenants WHERE id = ANY($1)', [[TENANT, OTHER]]).catch(() => {});
    await db.pool.end();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });

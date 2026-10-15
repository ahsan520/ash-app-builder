'use strict';
// Needs a real Postgres with the platform schema (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node --test tests/read-counts-db.test.js
// Skips itself otherwise. It holds everything that moved behind the event store (collector counts, the search fields
// panel, the storage page's range and daily chart, the retention page's source list, capacity's ingest rate) to the
// SQL it replaced: the old queries are written out below and must agree with what the store returns now.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const express = require('express');
const db = require('../src/db');

let TENANT;
const shared = require('../src/gateway/shared');
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }] };
const collectorRoutes = require('../src/gateway/routes/collectors');
const searchRoutes = require('../src/gateway/routes/search');
const storageRoutes = require('../src/gateway/routes/storage');
const storage = require('../src/storage/retention');
const capacity = require('../src/capacity/capacity');
const { getEventStore } = require('../src/events');

const MIN = 60000; const HOUR = 3600000; const DAY = 86400000;
const ago = (ms) => new Date(Date.now() - ms).toISOString();
const ev = (collector, source, age, parsed = {}) => ({ source_type: source, collector_id: collector, raw: 'line', parsed, received_at: ago(age) });
const norm = (rows) => JSON.parse(JSON.stringify(rows));

describe('reads moved behind the event store agree with the SQL they replaced (Postgres)', () => {
  let srv; let base; let keyId;
  const get = async (p) => { const r = await fetch(base + p); return { status: r.status, body: await r.json() }; };
  const q = async (sql, params) => (await db.query(sql, params)).rows;

  before(async () => {
    TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['read-counts-' + Date.now()])).rows[0].id;
    const events = [];
    for (let i = 0; i < 40; i++) events.push(ev('c-' + (i % 4), i % 3 ? 'syslog' : 'cloud', (i + 1) * 5 * MIN + i * HOUR, i % 2 ? { host: 'h' + i, app_name: 'sshd', xdm: { source: { ipv4: '10.0.0.' + i }, event: { type: 'authentication' } } } : { host: 'h' + i, n: i }));
    events.push(ev('c-old', 'syslog', 9 * DAY), ev('c-old', 'syslog', 20 * DAY), ev(null, 'syslog', 2 * HOUR), ev('c-9', 'wineventlog', 25 * DAY, { winlog: { id: 4625 } }));
    await getEventStore().insertBatch(TENANT, events);
    keyId = (await db.query("INSERT INTO ingestion_keys (tenant_id, name, platform, key_prefix, key_hash) VALUES ($1, 'k1', 'linux', 'asix_ik_test', $2) RETURNING id", [TENANT, crypto.randomBytes(32).toString('hex')])).rows[0].id;
    await db.query("INSERT INTO collectors (tenant_id, key_id, name, platform, events_total) VALUES ($1, $2, 'c-1', 'linux', 777)", [TENANT, keyId]);
    await db.query("INSERT INTO collectors (tenant_id, key_id, name, platform, events_total, last_seen) VALUES ($1, NULL, 'c-2', 'linux', 0, localtimestamp - interval '2 days')", [TENANT]);
    const app = express(); app.use(express.json()); app.use(collectorRoutes); app.use(searchRoutes); app.use(storageRoutes);
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(async () => {
    if (srv) srv.close();
    await db.query('DELETE FROM collectors WHERE tenant_id = $1', [TENANT]);
    await db.query('DELETE FROM ingestion_keys WHERE tenant_id = $1', [TENANT]);
    await getEventStore().deleteBefore(TENANT, '2999-01-01T00:00:00Z');
    await db.query('DELETE FROM tenants WHERE id = $1', [TENANT]);
    await db.close();
  });

  it('collectors page: totals, first/last seen and 24 hour counts equal the old queries', async () => {
    const oldBuilt = await q(`SELECT e.collector_id AS name, MIN(e.received_at) AS first_seen, MAX(e.received_at) AS last_seen, COUNT(*)::bigint AS events_total
      FROM events e WHERE e.tenant_id = $1 AND e.collector_id IS NOT NULL AND e.received_at > localtimestamp - interval '7 days'
        AND e.collector_id NOT IN (SELECT name FROM collectors WHERE tenant_id = $1 AND key_id IS NOT NULL) GROUP BY e.collector_id`, [TENANT]);
    const oldDay = await q(`SELECT collector_id, COUNT(*)::int AS n FROM events WHERE tenant_id = $1 AND collector_id IS NOT NULL AND received_at > localtimestamp - interval '24 hours' GROUP BY collector_id`, [TENANT]);
    const { status, body } = await get('/v1/collectors?limit=500');
    assert.strictEqual(status, 200);
    const by = Object.fromEntries(body.collectors.map((c) => [c.name, c]));
    for (const o of oldBuilt) {
      const c = by[o.name]; assert.ok(c, o.name + ' is listed');
      if (o.name === 'c-2') continue;                                                       // the key-less row merges (checked below)
      assert.strictEqual(c.events_total, Number(o.events_total), o.name + ' total');
      assert.strictEqual(Date.parse(c.first_seen), o.first_seen.getTime(), o.name + ' first_seen');
      assert.strictEqual(Date.parse(c.last_seen), o.last_seen.getTime(), o.name + ' last_seen');
    }
    for (const c of body.collectors) assert.strictEqual(c.events_24h, (oldDay.find((r) => r.collector_id === c.name) || { n: 0 }).n, c.name + ' 24h');
    assert.strictEqual(by['c-1'].events_total, 777, 'a keyed sender keeps the table counter');
    assert.ok(!by['c-old'] || by['c-old'].events_total === 1, 'only the event inside 7 days counts');           // c-old: one event 9d old and one 20d old: outside the window
    assert.ok(!by['c-9'], 'events 25 days old are not listed');
    const c2 = by['c-2']; const old2 = oldBuilt.find((o) => o.name === 'c-2');
    assert.strictEqual(c2.events_total, Number(old2.events_total));
    assert.strictEqual(Date.parse(c2.last_seen), old2.last_seen.getTime(), 'the key-less row takes its last_seen from the events, not its own 2 day old value');
    assert.strictEqual(c2.status, 'disconnected', 'its newest event is over 15 minutes old');
  });

  it('search fields: names, counts and datasets equal the old queries', async () => {
    const oldFields = await q(`SELECT k AS name, COUNT(*)::int AS events FROM (SELECT jsonb_object_keys(parsed) AS k FROM (SELECT parsed FROM events WHERE tenant_id = $1 ORDER BY received_at DESC LIMIT 2000) s) t GROUP BY k ORDER BY events DESC, k LIMIT 200`, [TENANT]);
    // the old route walked each event's xdm object once and counted every leaf path once per event
    const oldXdm = new Map();
    for (const r of await q(`SELECT parsed->'xdm' AS x FROM events WHERE tenant_id = $1 AND parsed ? 'xdm' ORDER BY received_at DESC LIMIT 500`, [TENANT])) {
      const paths = new Set();
      const walk = (o, p) => Object.entries(o || {}).forEach(([k, v]) => (v && typeof v === 'object' && !Array.isArray(v) ? walk(v, p + k + '.') : paths.add(p + k)));
      walk(r.x, 'xdm.');
      for (const k of paths) oldXdm.set(k, (oldXdm.get(k) || 0) + 1);
    }
    const oldDatasets = await q(`SELECT source_type AS name, COUNT(*)::int AS events, MAX(received_at) AS last_seen FROM events WHERE tenant_id = $1 AND received_at > localtimestamp - interval '7 days' GROUP BY 1 ORDER BY 2 DESC`, [TENANT]);
    const { status, body } = await get('/v1/search/fields');
    assert.strictEqual(status, 200);
    const top = body.fields.filter((f) => !f.name.startsWith('xdm.'));
    assert.deepStrictEqual(top, oldFields);
    assert.deepStrictEqual(Object.fromEntries(body.fields.filter((f) => f.name.startsWith('xdm.')).map((f) => [f.name, f.events])), Object.fromEntries(oldXdm));
    assert.deepStrictEqual(body.datasets.map((d) => [d.name, d.events]).sort(), oldDatasets.map((d) => [d.name, d.events]).sort());
    for (const d of body.datasets) assert.strictEqual(Date.parse(d.last_seen), oldDatasets.find((o) => o.name === d.name).last_seen.getTime());
  });

  it('storage page: oldest, newest and the 14 day chart equal the old queries', async () => {
    const range = (await q('SELECT MIN(received_at) AS oldest, MAX(received_at) AS newest FROM events WHERE tenant_id = $1', [TENANT]))[0];
    const daily = await q(`SELECT to_char(d.day, 'YYYY-MM-DD') AS day, COALESCE(c.n, 0)::int AS n FROM (SELECT CURRENT_DATE - g AS day FROM generate_series(13, 0, -1) g) d
      LEFT JOIN (SELECT received_at::date AS day, COUNT(*) AS n FROM events WHERE tenant_id = $1 AND received_at >= CURRENT_DATE - 13 GROUP BY 1) c ON c.day = d.day ORDER BY d.day`, [TENANT]);
    const s = await storage.summary(TENANT);
    assert.strictEqual(Date.parse(s.oldest), range.oldest.getTime()); assert.strictEqual(Date.parse(s.newest), range.newest.getTime());
    assert.deepStrictEqual(norm(s.daily), norm(daily));
    assert.ok(s.daily.reduce((a, d) => a + d.n, 0) > 0 && s.daily.length === 14);
  });

  it('retention page: the known sources are the last 30 days of source types', async () => {
    const old = (await q(`SELECT DISTINCT source_type FROM events WHERE tenant_id = $1 AND received_at > localtimestamp - interval '30 days' ORDER BY 1 LIMIT 100`, [TENANT])).map((r) => r.source_type);
    const { status, body } = await get('/v1/storage/retention');
    assert.strictEqual(status, 200); assert.deepStrictEqual(body.known_sources, old);
    assert.ok(body.known_sources.includes('wineventlog'), 'an event 25 days old is inside 30 days');
  });

  it('capacity: ingest per minute counts the last 5 minutes of every active tenant', async () => {
    await getEventStore().insertBatch(TENANT, Array.from({ length: 10 }, () => ev('c-0', 'syslog', MIN)));
    const old = Number((await q(`SELECT COUNT(*)::bigint AS n FROM events WHERE received_at > localtimestamp - interval '5 minutes' AND tenant_id IN (SELECT id FROM tenants WHERE status = 'active')`))[0].n);
    const r = await capacity.collectLive({ cpuSampleMs: 10, tenantId: TENANT });
    assert.ok(old >= 10);
    assert.ok(Math.abs(r.ingest_per_min - Math.round((old / 5) * 10) / 10) <= 0.2 + old * 0, `ingest_per_min ${r.ingest_per_min} vs ${old / 5}`);
  });
});

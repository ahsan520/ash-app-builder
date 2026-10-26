'use strict';
// Needs a real Postgres with the platform schema (k8s/12-schema-init.yaml's schema.sql):
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_PASSWORD=... node --test tests/core-reads-db.test.js
// Skips itself otherwise. It holds the events list (GET /v1/search/events), GET /v1/data-sources and GET /v1/dashboard/ingestion
// to the SQL they ran before they moved behind the event store: the old queries are written out below and must agree with
// what the routes return now. (One deliberate difference, tested at the end: q is a plain substring now, not an ILIKE pattern.)
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const express = require('express');
const db = require('../src/db');

let TENANT;
const pass = (req, res, next) => { req.tenant_id = TENANT; next(); };
const shared = require('../src/gateway/shared');
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared, authMiddleware: pass, tenantMiddleware: (req, res, next) => next(), rbacMiddleware: (req, res, next) => next(), auditMiddleware: (req, res, next) => next(),
};
const coreRoutes = require('../src/gateway/routes/core');
const { getEventStore } = require('../src/events');

const MIN = 60000; const HOUR = 3600000;
const ago = (ms) => new Date(Date.now() - ms).toISOString();
const iso = (d) => (d === null ? null : new Date(d).toISOString());

describe('events list, data sources and Command Center agree with the SQL they replaced (Postgres)', () => {
  let srv; let base;
  const get = async (p) => { const r = await fetch(base + p); return { status: r.status, body: await r.json() }; };
  const q = async (sql, params) => (await db.query(sql, params)).rows;

  before(async () => {
    TENANT = (await db.query('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['core-reads-' + Date.now()])).rows[0].id;
    const events = []; const types = ['syslog', 'cloud', 'wineventlog']; const raws = ['Failed password for root from 203.0.113.9', 'Accepted publickey for ash', 'api call \u00fcn\u00efc\u00f6d\u00e9', 'sudo: bob : COMMAND=/bin/ls', 'x'];
    for (let i = 0; i < 70; i++) {
      const age = (3 + i * 37) * MIN + i * 1234;                                         // 3 minutes to about 46 hours, every event at its own time
      events.push({
        source_type: types[i % 3], collector_id: i % 4 === 3 ? null : 'c' + (i % 3), raw: raws[i % 5] + ' #' + i, parsed: i % 2 ? { host: 'h' + (i % 5), n: i } : {},
        received_at: ago(age), event_time: i % 5 === 0 ? null : ago(age + (i % 7) * MIN + 777),
      });
    }
    await getEventStore().insertBatch(TENANT, events);
    const app = express(); app.use(express.json()); app.use(coreRoutes);
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(async () => {
    if (srv) srv.close();
    await getEventStore().deleteBefore(TENANT, '2999-01-01T00:00:00Z');
    await db.query('DELETE FROM tenants WHERE id = $1', [TENANT]);
    await db.close();
  });

  // the old route's query builder, as it was
  async function oldList(query) {
    const limit = Math.min(Number(query.limit) || 50, 500); const offset = Math.max(Number(query.offset) || 0, 0);
    const conditions = ['tenant_id = $1']; const params = [TENANT];
    if (query.source_type) { params.push(query.source_type); conditions.push(`source_type = $${params.length}`); }
    if (query.collector_id) { params.push(query.collector_id); conditions.push(`collector_id = $${params.length}`); }
    if (query.from) { params.push(query.from); conditions.push(`COALESCE(event_time, received_at) >= $${params.length}`); }
    if (query.to) { params.push(query.to); conditions.push(`COALESCE(event_time, received_at) <= $${params.length}`); }
    if (query.q) { params.push(`%${query.q}%`); conditions.push(`raw ILIKE $${params.length}`); }
    params.push(limit); const lp = params.length; params.push(offset); const op = params.length;
    return q(`SELECT id, source_type, collector_id, received_at, event_time, raw, parsed FROM events WHERE ${conditions.join(' AND ')}
              ORDER BY COALESCE(event_time, received_at) DESC LIMIT $${lp} OFFSET $${op}`, params);
  }

  it('events list: same events in the same order, same fields, for every filter combination', async () => {
    const cases = [
      {}, { limit: 10 }, { limit: 10, offset: 10 }, { limit: 500 }, { source_type: 'cloud' }, { collector_id: 'c1' }, { collector_id: 'nope' },
      { source_type: 'syslog', collector_id: 'c0', limit: 5 }, { q: 'password' }, { q: 'PASSWORD' }, { q: '\u00fcn\u00ef' }, { q: 'COMMAND=/bin' },
      { from: ago(10 * HOUR) }, { to: ago(10 * HOUR) }, { from: ago(30 * HOUR), to: ago(5 * HOUR) }, { from: ago(30 * HOUR), to: ago(5 * HOUR), source_type: 'wineventlog', q: 'e', limit: 7, offset: 2 },
      { from: '2020-01-01' }, { to: '2020-01-01 00:00:00' },
    ];
    for (const c of cases) {
      const want = await oldList(c);
      const url = '/v1/search/events?' + new URLSearchParams(Object.fromEntries(Object.entries(c).map(([k, v]) => [k, String(v)]))).toString();
      const { status, body } = await get(url);
      assert.strictEqual(status, 200, JSON.stringify(c));
      assert.deepStrictEqual(body.events.map((e) => e.id), want.map((r) => r.id), 'order and content: ' + JSON.stringify(c));
      assert.strictEqual(body.count, want.length);
      body.events.forEach((e, i) => {
        const w = want[i];
        assert.deepStrictEqual([e.source_type, e.collector_id, e.raw, e.parsed], [w.source_type, w.collector_id, w.raw, w.parsed]);
        assert.strictEqual(e.received_at, iso(w.received_at)); assert.strictEqual(e.event_time, iso(w.event_time));
      });
    }
    assert.ok((await oldList({})).length === 50 && (await oldList({ limit: 500 })).length === 70, 'the data set is big enough to page');
  });

  it('data sources: same rows, counts and order', async () => {
    const want = await q(`SELECT source_type, collector_id, COUNT(*)::int AS events_total,
        COUNT(*) FILTER (WHERE COALESCE(event_time, received_at) > now() - interval '24 hours')::int AS events_24h, MAX(received_at) AS last_received
      FROM events WHERE tenant_id = $1 GROUP BY source_type, collector_id ORDER BY MAX(received_at) DESC`, [TENANT]);
    const { status, body } = await get('/v1/data-sources');
    assert.strictEqual(status, 200);
    assert.deepStrictEqual(body.sources, want.map((r) => ({ source_type: r.source_type, collector_id: r.collector_id, events_total: r.events_total, events_24h: r.events_24h, last_received: iso(r.last_received) })));
    assert.ok(want.length >= 6 && want.some((r) => r.collector_id === null), 'the data set has several groups, some without a collector');
  });

  async function oldDashboard(col) {
    const totals = (await q(`SELECT COUNT(*)::int AS events_24h, COALESCE(SUM(octet_length(raw)), 0)::bigint AS bytes_24h,
        COUNT(*) FILTER (WHERE received_at > localtimestamp - interval '1 hour')::int AS events_1h, COUNT(DISTINCT source_type)::int AS source_types,
        COUNT(DISTINCT collector_id)::int AS collectors, MAX(received_at) AS last_received
      FROM events WHERE tenant_id = $1 AND COALESCE(event_time, received_at) > localtimestamp - interval '24 hours'`, [TENANT]))[0];
    const hourly = await q(`SELECT g.h AS hour, COALESCE(c.n, 0)::int AS n FROM generate_series(date_trunc('hour', localtimestamp) - interval '23 hours', date_trunc('hour', localtimestamp), interval '1 hour') AS g(h)
      LEFT JOIN (SELECT date_trunc('hour', COALESCE(event_time, received_at)) AS h, COUNT(*) AS n FROM events WHERE tenant_id = $1
        AND COALESCE(event_time, received_at) >= date_trunc('hour', localtimestamp) - interval '23 hours' GROUP BY 1) c ON c.h = g.h ORDER BY g.h`, [TENANT]);
    const groups = await q(`SELECT COALESCE(${col}, '(none)') AS key, COUNT(*)::int AS events_24h, COALESCE(SUM(octet_length(raw)), 0)::bigint AS bytes_24h
      FROM events WHERE tenant_id = $1 AND COALESCE(event_time, received_at) > localtimestamp - interval '24 hours' GROUP BY 1 ORDER BY 2 DESC LIMIT 12`, [TENANT]);
    return { totals, hourly, groups };
  }

  for (const [by, col] of [['source', 'source_type'], ['collector', 'collector_id']]) {
    it(`Command Center (by ${by}): totals, hourly chart and groups equal the old queries`, async () => {
      const want = await oldDashboard(col);
      const { status, body } = await get('/v1/dashboard/ingestion?by=' + by);
      assert.strictEqual(status, 200); assert.strictEqual(body.by, col);
      const t = want.totals;
      assert.deepStrictEqual(body.totals, { events_24h: t.events_24h, bytes_24h: Number(t.bytes_24h), events_1h: t.events_1h, source_types: t.source_types, collectors: t.collectors, last_received: iso(t.last_received) });
      assert.deepStrictEqual(body.hourly, want.hourly.map((h) => ({ hour: iso(h.hour), n: h.n })));
      assert.deepStrictEqual(body.groups.map((g) => [g.key, g.events_24h, g.bytes_24h]), want.groups.map((g) => [g.key, g.events_24h, Number(g.bytes_24h)]));
      assert.ok(t.events_24h > 10 && want.hourly.some((h) => h.n > 0) && want.groups.length >= 3, 'the data set exercises every part');
    });
  }

  it('the one deliberate difference: q is a plain substring, not an ILIKE pattern', async () => {
    await getEventStore().insertBatch(TENANT, [{ source_type: 'syslog', collector_id: 'cq', raw: 'disk is 100%_full', parsed: {}, received_at: ago(MIN) }, { source_type: 'syslog', collector_id: 'cq', raw: 'disk is 100 and full', parsed: {}, received_at: ago(2 * MIN) }]);
    const old = await oldList({ q: '100%_full' });                      // as an ILIKE pattern, % and _ are wildcards: both lines match
    const now = (await get('/v1/search/events?q=' + encodeURIComponent('100%_full'))).body.events;
    assert.strictEqual(old.length, 2); assert.strictEqual(now.length, 1); assert.strictEqual(now[0].raw, 'disk is 100%_full');
  });
});

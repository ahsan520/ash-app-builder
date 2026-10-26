'use strict';
// The events list (GET /v1/search/events), the data sources page and the Command Center numbers read through the event
// store. This runs the real routes on the in-memory store (no database), with only the sign-in chain replaced.
// tests/core-reads-db.test.js (ASIX_TEST_DB=1) holds the same routes to the SQL they replaced, on real Postgres.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const express = require('express');

const TENANT = crypto.randomUUID();
const pass = (req, res, next) => { req.tenant_id = TENANT; next(); };
const shared = require('../src/gateway/shared');
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared, authMiddleware: pass, tenantMiddleware: (req, res, next) => next(), rbacMiddleware: (req, res, next) => next(), auditMiddleware: (req, res, next) => next(),
};
const coreRoutes = require('../src/gateway/routes/core');
const { setEventStore, getEventStore } = require('../src/events');
const { MemoryEventStore } = require('../src/events/memory-store');

const MIN = 60000; const HOUR = 3600000;
const ago = (ms) => new Date(Date.now() - ms).toISOString();
const ev = (over) => ({ source_type: 'syslog', collector_id: 'c1', raw: 'line', parsed: {}, ...over });

describe('events list, data sources and Command Center read through the event store', () => {
  let srv; let base; const id = {};
  const get = async (path) => { const r = await fetch(base + path); return { status: r.status, body: await r.json() }; };
  before(async () => {
    setEventStore(new MemoryEventStore());
    const rows = [
      ['a', ev({ raw: 'Failed password for root', parsed: { host: 'h1' }, received_at: ago(20 * MIN), event_time: ago(21 * MIN) })],
      ['b', ev({ raw: 'Accepted publickey', received_at: ago(5 * HOUR), event_time: ago(5 * HOUR + MIN) })],
      ['c', ev({ source_type: 'cloud', collector_id: null, raw: 'api call 100%', received_at: ago(2 * HOUR), event_time: null })],
      ['d', ev({ source_type: 'cloud', collector_id: 'c2', raw: 'tiny', received_at: ago(30 * HOUR), event_time: ago(30 * HOUR) })],     // older than 24 hours
    ].map(([n, e]) => { e.id = crypto.randomUUID(); id[n] = e.id; return e; });
    await getEventStore().insertBatch(TENANT, rows);
    const app = express(); app.use(express.json()); app.use(coreRoutes);
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { if (srv) srv.close(); setEventStore(null); });
  const ids = (r) => r.body.events.map((e) => Object.keys(id).find((k) => id[k] === e.id));

  it('GET /v1/search/events: newest event time first, with the response shape the console expects', async () => {
    const r = await get('/v1/search/events');
    assert.strictEqual(r.status, 200); assert.strictEqual(r.body.success, true);
    assert.deepStrictEqual([r.body.count, r.body.limit, r.body.offset], [4, 50, 0]);
    assert.deepStrictEqual(ids(r), ['a', 'c', 'b', 'd']);                      // c has no event time: its received time (2 hours ago) counts
    assert.deepStrictEqual(Object.keys(r.body.events[0]).sort(), ['collector_id', 'event_time', 'id', 'parsed', 'raw', 'received_at', 'source_type']);
    assert.strictEqual(r.body.events.find((e) => e.id === id.c).event_time, null);
    assert.deepStrictEqual(r.body.events[0].parsed, { host: 'h1' });
  });

  it('filters, paging and the literal q', async () => {
    assert.deepStrictEqual(ids(await get('/v1/search/events?source_type=cloud')), ['c', 'd']);
    assert.deepStrictEqual(ids(await get('/v1/search/events?collector_id=c1')), ['a', 'b']);
    assert.deepStrictEqual(ids(await get('/v1/search/events?limit=2&offset=1')), ['c', 'b']);
    assert.deepStrictEqual(ids(await get('/v1/search/events?q=PASSWORD')), ['a']);
    assert.deepStrictEqual(ids(await get('/v1/search/events?q=100%25')), ['c']);                 // 100% as text, not a wildcard
    assert.deepStrictEqual(ids(await get('/v1/search/events?q=a%25')), []);                      // "a%" is not "a followed by anything"
    assert.deepStrictEqual(ids(await get('/v1/search/events?from=' + encodeURIComponent(ago(3 * HOUR)))), ['a', 'c']);
    assert.deepStrictEqual(ids(await get('/v1/search/events?to=' + encodeURIComponent(ago(3 * HOUR)))), ['b', 'd']);
    assert.deepStrictEqual((await get('/v1/search/events?limit=9999')).body.limit, 500);
    assert.deepStrictEqual((await get('/v1/search/events?limit=abc&offset=-5')).body.limit, 50);
  });

  it('from and to accept the date forms the database used to accept, read as UTC', async () => {
    const day = new Date().toISOString().slice(0, 10);
    for (const f of [day, `${day} 00:00:00`, `${day}T00:00:00`, `${day}T00:00:00Z`, `${day}T00:00:00+00:00`]) {
      assert.strictEqual((await get('/v1/search/events?to=' + encodeURIComponent(f))).status, 200, f);
    }
    for (const bad of ['soon', '2026-13-45', '']) if (bad) assert.strictEqual((await get('/v1/search/events?from=' + encodeURIComponent(bad))).status, 400, bad);
    const r = await get('/v1/search/events?from=a&from=b');
    assert.strictEqual(r.status, 400); assert.strictEqual(r.body.error.code, 'INVALID_QUERY');
    assert.strictEqual((await get('/v1/search/events?offset=100001')).status, 400);
  });

  it('GET /v1/data-sources: one row per source type and collector, most recently received first', async () => {
    const r = await get('/v1/data-sources');
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(r.body.sources.map((s) => [s.source_type, s.collector_id, s.events_total, s.events_24h]), [['syslog', 'c1', 2, 2], ['cloud', null, 1, 1], ['cloud', 'c2', 1, 0]]);
    assert.deepStrictEqual(Object.keys(r.body.sources[0]).sort(), ['collector_id', 'events_24h', 'events_total', 'last_received', 'source_type']);
    assert.match(r.body.sources[0].last_received, /^\d{4}-\d{2}-\d{2}T.*Z$/);
  });

  it('GET /v1/dashboard/ingestion: totals, 24 hourly buckets and the top groups', async () => {
    const r = await get('/v1/dashboard/ingestion');
    assert.strictEqual(r.status, 200); assert.strictEqual(r.body.by, 'source_type');
    const t = r.body.totals;
    assert.deepStrictEqual([t.events_24h, t.bytes_24h, t.events_1h, t.source_types, t.collectors], [3, 'Failed password for root'.length + 'Accepted publickey'.length + 'api call 100%'.length, 1, 2, 1]);
    assert.ok(Date.parse(t.last_received) > Date.now() - 25 * MIN);
    assert.strictEqual(r.body.hourly.length, 24); assert.ok(r.body.hourly.every((h) => /^\d{4}-\d{2}-\d{2}T\d{2}:00:00\.000Z$/.test(h.hour) && Number.isInteger(h.n)));
    assert.strictEqual(r.body.hourly.reduce((n, h) => n + h.n, 0), 3);
    assert.deepStrictEqual(r.body.groups, [{ key: 'syslog', events_24h: 2, bytes_24h: 'Failed password for root'.length + 'Accepted publickey'.length }, { key: 'cloud', events_24h: 1, bytes_24h: 'api call 100%'.length }]);
    const c = await get('/v1/dashboard/ingestion?by=collector');
    assert.strictEqual(c.body.by, 'collector_id');
    assert.deepStrictEqual(c.body.groups.map((g) => [g.key, g.events_24h]), [['c1', 2], ['(none)', 1]]);
  });

  it('a store failure is a 500 with the old error codes', async () => {
    const real = getEventStore(); const broken = new MemoryEventStore();
    for (const m of ['_listEvents', '_dataSources', '_ingestionStats']) broken[m] = async () => { throw new Error('boom'); };
    setEventStore(broken);
    const codes = [(await get('/v1/search/events')), (await get('/v1/data-sources')), (await get('/v1/dashboard/ingestion'))].map((r) => [r.status, r.body.error.code]);
    setEventStore(real);
    assert.deepStrictEqual(codes, [[500, 'SEARCH_ERROR'], [500, 'DATA_SOURCES_ERROR'], [500, 'INGESTION_SUMMARY_ERROR']]);
  });
});

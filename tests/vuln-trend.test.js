'use strict';
// E6k: GET /v1/endpoints/vulnerabilities/trend through the real route file and the in-memory event store (only the sign-in chain is replaced, as in search-route.test.js).
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const express = require('express');

const TENANT = crypto.randomUUID(), OTHER = crypto.randomUUID();
let who = TENANT;
const shared = require('../src/gateway/shared');
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = who; next(); }] };
const route = require('../src/gateway/routes/vuln-trend');
const { setEventStore } = require('../src/events');
const { MemoryEventStore } = require('../src/events/memory-store');
const summary = require('../src/endpoints/findings-summary');

const dayAgo = (d) => new Date(Date.now() - d * 86400000 + 3600000);
const mk = (tenant, d, over = {}, extra = {}) => {
  const when = dayAgo(d), day = when.toISOString().slice(0, 10);
  const e = summary.buildEvent(tenant, { total: 100 + d, machines: 3, distinct_cves: 50, severity: { critical: 4, high: 10, medium: 5, low: 1 } }, { total: 2, critical: over.nc === undefined ? 1 : over.nc, high: 1 }, { findings_total: 90, critical: 3 }, 's', when.getTime());
  e.id = crypto.randomUUID(); e.received_at = when.toISOString(); e.event_time = e.received_at; Object.assign(e.parsed, extra);
  return e;
};

describe('GET /v1/endpoints/vulnerabilities/trend', () => {
  let srv, base, store;
  before(async () => {
    store = new MemoryEventStore(); setEventStore(store);
    await store.insertBatch(TENANT, [mk(TENANT, 1), mk(TENANT, 3), mk(TENANT, 2), mk(TENANT, 40)]);
    await store.insertBatch(OTHER, [mk(OTHER, 1, {}, { findings_total: 999 })]);
    const app = express(); app.use(route); srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => srv.close());
  const get = async (q = '') => { const r = await fetch(base + '/v1/endpoints/vulnerabilities/trend' + q); return { status: r.status, body: await r.json() }; };

  it('lists one point per day, oldest first, with the numbers of the summary and the latest', async () => {
    const { status, body } = await get('?days=30');
    assert.strictEqual(status, 200); assert.strictEqual(body.points.length, 3, 'the 40-day-old summary is outside 30 days');
    assert.deepStrictEqual(body.points.map((p) => p.findings_total), [103, 102, 101]);
    assert.ok(body.points[0].day < body.points[1].day && body.points[1].day < body.points[2].day);
    assert.deepStrictEqual(body.latest, body.points[2]);
    const p = body.points[2]; assert.deepStrictEqual([p.critical, p.high, p.new_critical, p.machines, p.total_change, p.critical_change], [4, 10, 1, 3, 11, 1]);
  });
  it('days defaults to 30, keeps the newest N points, and a long range reaches older summaries', async () => {
    assert.strictEqual((await get()).body.days, 30);
    assert.deepStrictEqual((await get('?days=2')).body.points.map((p) => p.findings_total), [102, 101]);
    assert.strictEqual((await get('?days=90')).body.points.length, 4);
  });
  it('only this tenant\'s summaries are read', async () => {
    who = OTHER; try { const b = (await get('?days=7')).body; assert.deepStrictEqual(b.points.map((p) => p.findings_total), [999]); } finally { who = TENANT; }
  });
  it('two summaries for one day give one point: the newest wins', async () => {
    const t = crypto.randomUUID(); who = t;
    const a = mk(t, 1, {}, { findings_total: 111 }), b = mk(t, 1, {}, { findings_total: 222 }); b.received_at = b.event_time = new Date(Date.parse(a.received_at) + 60000).toISOString();
    await store.insertBatch(t, [a, b]);
    try { const { body } = await get('?days=7'); assert.deepStrictEqual(body.points.map((p) => p.findings_total), [222]); } finally { who = TENANT; }
  });
  it('an empty history is an empty list and latest null, not an error', async () => {
    who = crypto.randomUUID(); try { const r = await get(); assert.strictEqual(r.status, 200); assert.deepStrictEqual([r.body.points, r.body.latest], [[], null]); } finally { who = TENANT; }
  });
  it('passes on numbers only: other fields of the event, odd values and a bad day are dropped', async () => {
    const t = crypto.randomUUID(); who = t;
    await store.insertBatch(t, [mk(t, 1, {}, { secret: 'x', critical: '4; DROP', findings_total: -5, high: 7 }), mk(t, 2, {}, { summary_day: '<script>' })]);
    try {
      const { body } = await get('?days=7'); assert.strictEqual(body.points.length, 1, 'the point with a bad day is left out');
      const p = body.points[0]; assert.ok(!('secret' in p) && !('new_since' in p));
      assert.deepStrictEqual([p.critical, p.findings_total, p.high], [null, null, 7]);
    } finally { who = TENANT; }
  });
  it('refuses unknown parameters and bad day counts before reading anything', async () => {
    for (const q of ['?days=0', '?days=366', '?days=-1', '?days=abc', '?days=1.5', '?days=1&days=2', '?limit=5', '?source_type=syslog']) { const r = await get(q); assert.strictEqual(r.status, 400, q); assert.strictEqual(r.body.error.code || r.body.code, 'INVALID_VULN_TREND', q); }
  });
});

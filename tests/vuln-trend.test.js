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
  describe('machines that got worse', () => {
    const list = (rows) => JSON.stringify(rows);
    const seed = async (older, newer, extraNewer = {}, olderDaysAgo = 2) => { const t = crypto.randomUUID(); who = t; await store.insertBatch(t, [mk(t, olderDaysAgo, {}, { machines_json: older }), mk(t, 1, {}, { machines_json: newer, ...extraNewer })]); return t; };
    const m = async (q = '?days=7') => { try { return (await get(q)).body.machines; } finally { who = TENANT; } };
    it('lists the machines whose critical or high count rose, worst first, with the change, and new machines as new', async () => {
      await seed(list([['001', 'a', 10, 1, 5], ['002', 'b', 10, 2, 2], ['003', 'c', 10, 4, 4]]), list([['001', 'a', 12, 1, 8], ['002', 'b', 9, 4, 1], ['003', 'c', 8, 3, 3], ['004', 'd', 3, 1, 0]]));
      const r = await m();
      assert.deepStrictEqual(r.worse.map((x) => [x.agent_id, x.critical_change, x.high_change, x.is_new]), [['002', 2, -1, false], ['004', 1, 0, true], ['001', 0, 3, false]]);
      assert.deepStrictEqual([r.since_day < r.day, r.complete, r.worse_count], [true, true, 3]);
    });
    it('a machine that improved or stayed the same is not listed; nobody worse is an empty list, not null', async () => {
      await seed(list([['001', 'a', 10, 3, 5]]), list([['001', 'a', 5, 1, 2]])); const r = await m(); assert.deepStrictEqual([r.worse, r.worse_count], [[], 0]);
    });
    it('when the earlier list was cut at 50, a machine missing from it is not called new', async () => {
      const big = Array.from({ length: 50 }, (_, i) => [String(100 + i), 'm' + i, 5, 0, 1]);
      await seed(list(big), list(big.concat([['900', 'late', 9, 5, 5]]))); const r = await m(); assert.strictEqual(r.complete, false); assert.deepStrictEqual(r.worse, []);
    });
    it('is null with one summary, with no machine list, or with a list that is not JSON of the expected shape', async () => {
      const t = crypto.randomUUID(); who = t; await store.insertBatch(t, [mk(t, 1, {}, { machines_json: list([['001', 'a', 1, 1, 1]]) })]); assert.strictEqual(await m(), null);
      await seed(list([['001', 'a', 1, 1, 1]]), 'not json'); assert.strictEqual(await m(), null);
      await seed(list([['001', 'a', 1, 1, 1]]), '{"a":1}'); assert.strictEqual(await m(), null);
      await seed(list([['001', 'a', 1, 1, 1]]), 'x'.repeat(30000)); assert.strictEqual(await m(), null);
      await seed(list([['001', 'a', 1, 1, 1]]), list(Array.from({ length: 1500 }, () => ['001', 'a', 1, 1, 1]))); assert.strictEqual(await m(), null, 'valid JSON, but far longer than 50 machines can be');
    });
    it('works with days=1, and passes on only the allow-listed numbers and the name cut to 60', async () => {
      await seed(list([['001', 'a', 1, 0, 0]]), list([['001', 'n'.repeat(200), 'x', 7, 'drop']]), {}, 3); const r = await m('?days=1');   // the earlier summary is 3 days back, outside the 1 day shown, but still the one to compare with
      assert.strictEqual(r.worse[0].name.length, 60); assert.deepStrictEqual([r.worse[0].total, r.worse[0].critical, r.worse[0].high], [null, 7, null]);
    });
  });
  it('refuses unknown parameters and bad day counts before reading anything', async () => {
    for (const q of ['?days=0', '?days=366', '?days=-1', '?days=abc', '?days=1.5', '?days=1&days=2', '?limit=5', '?source_type=syslog']) { const r = await get(q); assert.strictEqual(r.status, 400, q); assert.strictEqual(r.body.error.code || r.body.code, 'INVALID_VULN_TREND', q); }
  });
});

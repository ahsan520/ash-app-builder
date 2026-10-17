'use strict';
// The parser pool status: the shaping, the unparsed count on the in-memory store, and the real route with the
// sign-in chain stubbed. No database. (Counts on PostgreSQL and ClickHouse use store.search(), which the search
// conformance suites already hold to the same results.)
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const express = require('express');
const ps = require('../src/ingestion/parser-status');
const { MemoryEventStore } = require('../src/events/memory-store');
const { ParserPool } = require('../src/ingestion/parser-pool');

const T1 = crypto.randomUUID(), T2 = crypto.randomUUID();
const ev = (tenant, minsAgo, parsed) => ({ id: crypto.randomUUID(), tenant_id: tenant, source_type: 'syslog', collector_id: null,
  received_at: new Date(Date.now() - minsAgo * 60000).toISOString(), event_time: null, raw: 'x', parsed });

async function seeded() {
  const store = new MemoryEventStore();
  await store.insertBatch(T1, [
    ev(T1, 5, { _parse_error: 'PARSE_TIMEOUT' }), ev(T1, 6, { _parse_error: 'PARSE_TIMEOUT' }), ev(T1, 7, { _parse_error: 'PARSE_WORKER_CRASH' }),
    ev(T1, 8, { host: 'ok' }), ev(T1, 9, {}),
    ev(T1, 60 * 30, { _parse_error: 'PARSE_FAILED' }),          // older than 24 h
    ev(T1, 10, { _parse_error: 'SOMETHING_NEW' }),
  ]);
  await store.insertBatch(T2, [ev(T2, 5, { _parse_error: 'PARSE_QUARANTINED' })]);
  return store;
}

describe('clampHours', () => {
  it('defaults, and keeps the value between 1 and 168', () => {
    assert.strictEqual(ps.clampHours(undefined), 24); assert.strictEqual(ps.clampHours('abc'), 24);
    assert.strictEqual(ps.clampHours('0'), 1); assert.strictEqual(ps.clampHours('-5'), 1);
    assert.strictEqual(ps.clampHours('500'), 168); assert.strictEqual(ps.clampHours('72'), 72);
  });
});

describe('settings and counters', () => {
  it('inline mode has no pool counters', () => {
    assert.deepStrictEqual(ps.settings(null), { mode: 'inline', workers: 0, timeout_ms: null, queue: null });
    assert.strictEqual(ps.counters(null), null);
  });
  it('workers mode reports the pool\'s own settings and counters, as numbers', () => {
    const fake = { size: 2, timeoutMs: 5000, maxQueue: 100, stats: () => ({ workers: 2, busy: 1, queued: 3, completed: 10, failed: 1, timeouts: 1, crashes: 0, rejected: 2, quarantined: 0, rules_resent: '4', extra: 9 }) };
    assert.deepStrictEqual(ps.settings(fake), { mode: 'workers', workers: 2, timeout_ms: 5000, queue: 100 });
    const c = ps.counters(fake);
    assert.strictEqual(c.rules_resent, 4); assert.strictEqual(c.queued, 3); assert.ok(!('extra' in c));
  });
  it('reads a real pool', async () => {
    const pool = new ParserPool({ size: 1, timeoutMs: 1234, maxQueue: 7 });
    try { assert.deepStrictEqual(ps.settings(pool), { mode: 'workers', workers: 1, timeout_ms: 1234, queue: 7 }); assert.strictEqual(ps.counters(pool).completed, 0); }
    finally { await pool.close(); }
  });
});

describe('unparsedCounts', () => {
  it('counts the last window by reason, for one tenant, and keeps unknown reasons', async () => {
    const store = await seeded();
    const r = await ps.unparsedCounts(store, T1, 24);
    assert.strictEqual(r.total, 4);
    assert.deepStrictEqual(r.by_reason, { PARSE_TIMEOUT: 2, PARSE_WORKER_CRASH: 1, SOMETHING_NEW: 1, PARSE_FAILED: 0, PARSE_QUARANTINED: 0 });
    const wide = await ps.unparsedCounts(store, T1, 72);
    assert.strictEqual(wide.total, 5); assert.strictEqual(wide.by_reason.PARSE_FAILED, 1);
    const other = await ps.unparsedCounts(store, T2, 24);
    assert.strictEqual(other.total, 1); assert.strictEqual(other.by_reason.PARSE_QUARANTINED, 1);
  });
  it('is zero when nothing was stored unparsed', async () => {
    const r = await ps.unparsedCounts(new MemoryEventStore(), T1, 24);
    assert.strictEqual(r.total, 0); assert.ok(ps.REASONS.every((k) => r.by_reason[k] === 0));
  });
});

describe('build', () => {
  it('survives a failing store: the settings still come back and the error is named, with no detail leaked', async () => {
    const boom = { search: async () => { throw new Error('secret connection string'); } };
    const out = await ps.build({ pool: null, store: boom, tenantId: T1, hours: 24 });
    assert.strictEqual(out.settings.mode, 'inline'); assert.strictEqual(out.unparsed.total, null);
    assert.strictEqual(out.unparsed_error, 'Could not count unparsed events'); assert.ok(!JSON.stringify(out).includes('secret'));
  });
});

describe('GET /v1/parser/status', () => {
  const shared = require('../src/gateway/shared');
  const saved = require.cache[require.resolve('../src/gateway/shared')].exports;
  const poolMod = require('../src/ingestion/parser-pool');
  const events = require('../src/events');
  let srv, base, perm, tenant = T1;
  before(async () => {
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: (p) => { perm = p; return [(req, res, next) => { req.tenant_id = tenant; next(); }]; } };
    delete require.cache[require.resolve('../src/gateway/routes/parser-status')];
    events.setEventStore(await seeded());
    poolMod.setParserPool(null);
    const app = express(); app.use(require('../src/gateway/routes/parser-status'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); require.cache[require.resolve('../src/gateway/shared')].exports = saved; events.setEventStore(null); poolMod.setParserPool(null); });
  const get = async (q = '') => { const r = await fetch(base + '/v1/parser/status' + q); return { status: r.status, body: await r.json() }; };

  it('needs capacity:read and answers for the signed-in tenant only', async () => {
    const r = await get();
    assert.strictEqual(perm, 'capacity:read');
    assert.strictEqual(r.status, 200); assert.strictEqual(r.body.success, true);
    assert.strictEqual(r.body.settings.mode, 'inline'); assert.strictEqual(r.body.pool, null);
    assert.strictEqual(r.body.unparsed.total, 4);
    tenant = T2; assert.strictEqual((await get()).body.unparsed.total, 1); tenant = T1;
  });
  it('takes a window in hours and bounds it', async () => {
    assert.strictEqual((await get('?hours=72')).body.unparsed.total, 5);
    assert.strictEqual((await get('?hours=99999')).body.unparsed.hours, 168);
  });
  it('reports a live pool', async () => {
    const pool = new ParserPool({ size: 1, timeoutMs: 2000, maxQueue: 5 });
    poolMod.setParserPool(pool);
    try { const r = await get(); assert.strictEqual(r.body.settings.mode, 'workers'); assert.strictEqual(r.body.pool.workers, 1); }
    finally { poolMod.setParserPool(null); await pool.close(); }
  });
});

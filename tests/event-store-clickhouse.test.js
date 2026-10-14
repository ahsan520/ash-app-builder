'use strict';
// Runs the event-store contract (tests/event-store-conformance.js) plus ClickHouse-specific checks
// against a real ClickHouse server. Needs one with the target database created:
//   ASIX_TEST_DB=1 ASIX_CLICKHOUSE_URL=http://default:pass@127.0.0.1:8123/asix node tests/event-store-clickhouse.test.js
// Skips itself otherwise, so `npm test` is unaffected on machines without a server. CI runs it against
// a ClickHouse service container (.github/workflows/ci.yml, job "clickhouse").
//
// Every run uses its own throwaway table (events_test_<random>) and drops only that table, so it is
// safe to point at a database that also holds a real `events` table.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 and ASIX_CLICKHOUSE_URL to run against ClickHouse)'); process.exit(0); }
if (!process.env.ASIX_CLICKHOUSE_URL) { console.error('ASIX_TEST_DB=1 needs ASIX_CLICKHOUSE_URL, e.g. http://default:pass@127.0.0.1:8123/asix'); process.exit(1); }

const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { runConformance } = require('./event-store-conformance');
const { ClickHouseEventStore } = require('../src/events/clickhouse-store');

async function setup() {
  const table = `events_test_${crypto.randomBytes(6).toString('hex')}`;
  const store = new ClickHouseEventStore({ table });
  await store.ensureSchema();
  return {
    store,
    tenants: [crypto.randomUUID(), crypto.randomUUID()],
    cleanup: async () => { await store._exec(`DROP TABLE IF EXISTS ${table}`); await store.close(); },
  };
}

runConformance('clickhouse', setup);

describe('clickhouse adapter specifics', () => {
  let store; let A; let B; let cleanup;
  before(async () => { ({ store, tenants: [A, B], cleanup } = await setup()); });
  after(async () => { if (cleanup) await cleanup(); });

  it('keeps millisecond precision and pages correctly between events in the same second', async () => {
    const base = Date.parse('2026-10-02T00:00:00.000Z');
    const batch = [0, 1, 2, 3, 4].map((ms) => ({ id: crypto.randomUUID(), received_at: new Date(base + ms * 100).toISOString(), source_type: 'x-ms', raw: `ms ${ms}` }));
    await store.insertBatch(A, batch);
    const got = await store.getByIds(A, batch.map((b) => b.id));
    assert.deepStrictEqual(got.map((g) => g.received_at), batch.map((b) => b.received_at));
    const seen = []; let after = null;
    do { const r = await store.scan(A, { source_type: 'x-ms', limit: 2, after }); seen.push(...r.events.map((e) => e.raw)); after = r.next; } while (after);
    assert.deepStrictEqual(seen, ['ms 0', 'ms 1', 'ms 2', 'ms 3', 'ms 4']);
  });

  it('never shows two copies of a re-sent event, even before ClickHouse merges parts', async () => {
    const e = { id: crypto.randomUUID(), received_at: '2026-10-02T01:00:00.000Z', source_type: 'x-dup', raw: 'resent' };
    assert.strictEqual((await store.insertBatch(A, [e])).inserted, 1);
    assert.strictEqual((await store.insertBatch(A, [e])).inserted, 0);
    assert.strictEqual((await store.insertBatch(A, [e, e])).skipped, 2);
    const twice = { id: crypto.randomUUID(), received_at: '2026-10-02T01:00:01.000Z', source_type: 'x-dup', raw: 'twice in one batch' };
    assert.deepStrictEqual((await store.insertBatch(A, [twice, twice])).inserted, 1);
    assert.strictEqual(await store.count(A, { source_type: 'x-dup' }), 2);
    // the table really holds one physical row per event: no merge has been needed to get that
    const phys = await store._rows(`SELECT count() AS n FROM ${store.table} WHERE source_type = 'x-dup'`);
    assert.strictEqual(Number(phys[0].n), 2);
  });

  it('treats quotes, backslashes and SQL text in filters as plain values', async () => {
    const nasty = ["x' OR 1=1 --", 'back\\slash', "tab\there", "a'; DROP TABLE x; --"];
    for (const s of nasty) await store.insertBatch(A, [{ source_type: s.replace(/\t/g, ' '), raw: 'nasty', collector_id: s.replace(/\t/g, ' ') }]);
    for (const s of nasty.map((n) => n.replace(/\t/g, ' '))) {
      assert.strictEqual(await store.count(A, { source_type: s }), 1, JSON.stringify(s));
      assert.strictEqual((await store.scan(A, { collector_id: s, source_type: s })).events.length, 1);
    }
    assert.strictEqual(await store.count(A, { source_type: "x' OR '1'='1" }), 0);
    assert.strictEqual(await store.count(B, { source_type: "x' OR 1=1 --" }), 0, 'another tenant still sees nothing');
  });

  it('round-trips unicode, newlines and a large parsed object', async () => {
    const big = {}; for (let i = 0; i < 2000; i++) big[`k${i}`] = `value ${i} ✓`;
    const e = { source_type: 'x-text', raw: 'line one\nline two\ttabbed — 日本語 🚀', parsed: { big, nested: { a: [1, 2, { b: null }] } } };
    const { ids } = await store.insertBatch(A, [e]);
    const [got] = await store.getByIds(A, ids);
    assert.strictEqual(got.raw, e.raw);
    assert.deepStrictEqual(got.parsed, e.parsed);
  });

  it('reports backend errors with a code and without leaking credentials', async () => {
    const broken = new ClickHouseEventStore({ table: 'no_such_table_here' });
    await assert.rejects(broken.count(A), (err) => err.code === 'BACKEND_ERROR' && !/password|Basic /i.test(err.message));
    const down = new ClickHouseEventStore({ url: 'http://user:secret@127.0.0.1:1/asix', timeoutMs: 2000 });
    await assert.rejects(down.count(A), (err) => err.code === 'BACKEND_UNAVAILABLE' && !/secret/.test(err.message));
  });

  it('refuses queries it cannot run yet instead of returning wrong data', async () => {
    await assert.rejects(store.querySQL(A, 'SELECT 1', []), (err) => err.code === 'NOT_IMPLEMENTED');
    await assert.rejects(store.queryAggregated(A, {}), (err) => err.code === 'NOT_IMPLEMENTED');
  });

  it('rejects an unsafe table name', () => {
    assert.throws(() => new ClickHouseEventStore({ table: 'events; DROP TABLE x' }), /table name/);
  });
});

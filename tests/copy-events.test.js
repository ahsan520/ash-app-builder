'use strict';
// The event copy tool (src/events/copy-events.js) between two in-memory stores. No database.
const test = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { MemoryEventStore } = require('../src/events/memory-store');
const { copyTenant, copyAll, differences, parseArgs } = require('../src/events/copy-events');

const T1 = crypto.randomUUID(), T2 = crypto.randomUUID();
const iso = (i) => new Date(Date.UTC(2026, 9, 1, 0, 0, 0) + i * 60000).toISOString();   // one event a minute from 2026-10-01
async function fill(store, tenant, n, tag = 'a') {
  const events = Array.from({ length: n }, (_, i) => ({ id: crypto.randomUUID(), received_at: iso(i), event_time: i % 2 ? iso(i - 1) : null, source_type: i % 3 ? 'syslog' : 'json',
    collector_id: i % 4 ? 'c1' : null, raw: `${tag} event ${i}`, parsed: { n: i, nested: { k: [1, 2, i] }, host: 'h' + (i % 5) } }));
  for (let i = 0; i < n; i += 1000) await store.insertBatch(tenant, events.slice(i, i + 1000));
  return events;
}
const all = async (store, tenant) => { const out = []; let after = null; for (;;) { const p = await store.scan(tenant, { limit: 1000, after }); out.push(...p.events); if (!p.next) break; after = p.next; } return out; };

test('copies everything for a tenant, in batches, and verifies it', async () => {
  const a = new MemoryEventStore(), b = new MemoryEventStore();
  const src = await fill(a, T1, 2350);
  const r = await copyTenant(a, b, T1, { batch: 500 });
  assert.strictEqual(r.read, 2350); assert.strictEqual(r.copied, 2350); assert.strictEqual(r.already_there, 0);
  assert.strictEqual(r.verified, 2350); assert.strictEqual(r.missing + r.mismatches, 0);
  const copy = await all(b, T1);
  assert.deepStrictEqual(copy.map((e) => e.id), src.map((e) => e.id));     // same ids, same order
  assert.deepStrictEqual(copy.map((e) => e.received_at), src.map((e) => e.received_at));
  assert.strictEqual(r.first_received, iso(0)); assert.strictEqual(r.last_received, iso(2349));
});

test('running it again copies nothing; events added to the source since are the only ones copied', async () => {
  const a = new MemoryEventStore(), b = new MemoryEventStore();
  await fill(a, T1, 700);
  await copyTenant(a, b, T1, { batch: 300 });
  let r = await copyTenant(a, b, T1, { batch: 300 });
  assert.strictEqual(r.copied, 0); assert.strictEqual(r.already_there, 700); assert.strictEqual(r.verified, 700);
  await a.insertBatch(T1, [{ source_type: 'syslog', raw: 'late one', received_at: iso(5000) }, { source_type: 'syslog', raw: 'late two', received_at: iso(5001) }]);
  r = await copyTenant(a, b, T1, { batch: 300 });
  assert.strictEqual(r.copied, 2); assert.strictEqual((await all(b, T1)).length, 702);
});

test('an event is "already there" by id even if the destination stored a different received_at (ms vs microsecond stores)', async () => {
  const a = new MemoryEventStore(), b = new MemoryEventStore();
  const src = await fill(a, T1, 10);
  // the destination holds the same ids, with received_at off by a fraction: the stores' own (id, received_at) key would not match
  await b.insertBatch(T1, src.map((e) => ({ ...e, received_at: new Date(Date.parse(e.received_at) + 1).toISOString() })));
  const r = await copyTenant(a, b, T1, { verify: false });
  assert.strictEqual(r.copied, 0); assert.strictEqual(r.already_there, 10);
  assert.strictEqual((await all(b, T1)).length, 10, 'no duplicates');
});

test('tenants are separate: copying one never touches another', async () => {
  const a = new MemoryEventStore(), b = new MemoryEventStore();
  await fill(a, T1, 30, 'one'); await fill(a, T2, 20, 'two');
  const res = await copyAll(a, b, [{ id: T1, name: 'one' }]);
  assert.strictEqual(res.ok, true); assert.strictEqual(res.totals.copied, 30);
  assert.strictEqual((await all(b, T2)).length, 0);
  const res2 = await copyAll(a, b, [{ id: T1 }, { id: T2 }]);
  assert.strictEqual(res2.totals.copied, 20); assert.strictEqual(res2.totals.already_there, 30);
});

test('--since / --until copy only that window (since inclusive, until exclusive)', async () => {
  const a = new MemoryEventStore(), b = new MemoryEventStore();
  await fill(a, T1, 100);
  const r = await copyTenant(a, b, T1, { since: iso(10), until: iso(20) });
  assert.strictEqual(r.read, 10); assert.strictEqual(r.copied, 10);
  const got = await all(b, T1); assert.strictEqual(got[0].received_at, iso(10)); assert.strictEqual(got[got.length - 1].received_at, iso(19));
});

test('a dry run reads and counts but writes nothing, and says what it would copy', async () => {
  const a = new MemoryEventStore(), b = new MemoryEventStore();
  const src = await fill(a, T1, 50);
  await b.insertBatch(T1, src.slice(0, 20));
  const r = await copyTenant(a, b, T1, { dryRun: true, batch: 15 });
  assert.strictEqual(r.read, 50); assert.strictEqual(r.would_copy, 30); assert.strictEqual(r.already_there, 20); assert.strictEqual(r.copied, 0);
  assert.strictEqual((await all(b, T1)).length, 20);
});

test('verification catches a copy that is missing or different, and does not overwrite what is there', async () => {
  const a = new MemoryEventStore(), b = new MemoryEventStore();
  const src = await fill(a, T1, 20);
  // 1) a destination that loses events silently
  const lossy = new MemoryEventStore(); const realInsert = lossy._insert.bind(lossy);
  lossy._insert = async (t, envs, o) => realInsert(t, envs.slice(0, -1), o);
  let r = await copyTenant(a, lossy, T1, { batch: 10 });
  assert.strictEqual(r.missing, 2); assert.match(r.examples[0].problem, /not in the destination/);
  // 2) a destination that already holds a DIFFERENT event under the same id
  await b.insertBatch(T1, [{ ...src[3], raw: 'something else entirely' }]);
  r = await copyTenant(a, b, T1);
  assert.strictEqual(r.mismatches, 1); assert.match(r.examples[0].problem, /differs in raw/);
  assert.strictEqual((await b.getByIds(T1, [src[3].id]))[0].raw, 'something else entirely', 'the existing event was left alone');
  const res = await copyAll(a, b, [{ id: T1 }]); assert.strictEqual(res.ok, false);
});

test('a failing destination is reported for that tenant and the others still run', async () => {
  const a = new MemoryEventStore(), b = new MemoryEventStore();
  await fill(a, T1, 5); await fill(a, T2, 5);
  const real = b.insertBatch.bind(b);
  b.insertBatch = async (t, ev, o) => { if (t === T1) throw Object.assign(new Error('disk full'), { code: 'BACKEND_ERROR' }); return real(t, ev, o); };
  const res = await copyAll(a, b, [{ id: T1 }, { id: T2 }]);
  assert.strictEqual(res.ok, false); assert.strictEqual(res.totals.failed_tenants, 1);
  assert.match(res.tenants[0].error, /BACKEND_ERROR: disk full/); assert.strictEqual(res.tenants[1].copied, 5);
});

test('differences compares times to the millisecond and parsed deeply, ignoring key order', () => {
  const base = { source_type: 's', collector_id: null, raw: 'r', parsed: { a: 1, b: { c: 2 } }, event_time: '2026-10-01T00:00:00.123Z', received_at: '2026-10-01T00:00:01.000Z' };
  assert.deepStrictEqual(differences(base, { ...base, parsed: { b: { c: 2 }, a: 1 }, event_time: '2026-10-01T00:00:00.123000Z' }), []);
  assert.deepStrictEqual(differences(base, { ...base, parsed: { a: 1, b: { c: 3 } }, collector_id: 'x' }).sort(), ['collector_id', 'parsed']);
});

test('command line: options are validated', () => {
  assert.deepStrictEqual(parseArgs(['--from', 'postgres', '--to', 'clickhouse', '--dry-run', '--batch', '250']).batch, 250);
  for (const bad of [[], ['--from', 'postgres', '--to', 'postgres'], ['--from', 'memory', '--to', 'postgres'], ['--from', 'postgres', '--to', 'clickhouse', '--batch', '0'],
    ['--from', 'postgres', '--to', 'clickhouse', '--tenant', 'nope'], ['--from', 'postgres', '--to', 'clickhouse', '--since', 'yesterday-ish'], ['--from', 'postgres', '--to', 'clickhouse', '--wat']]) {
    assert.throws(() => parseArgs(bad), Error, JSON.stringify(bad));
  }
});

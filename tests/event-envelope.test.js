'use strict';
// Unit tests (no database): envelope validation and cleaning, the registry, and the ingest wiring.
const test = require('node:test');
const assert = require('assert');
const { makeEnvelope, normalizeTime, cleanJson, EnvelopeError, LIMITS } = require('../src/events/envelope');
const { getEventStore, setEventStore, FACTORIES } = require('../src/events');
const { MemoryEventStore } = require('../src/events/memory-store');

const T = '3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b';
const base = { tenant_id: T, source_type: 'syslog', raw: 'hello' };

test('makeEnvelope: minimal event gets defaults', () => {
  assert.deepStrictEqual(makeEnvelope(base), {
    v: 1, id: null, tenant_id: T, source_type: 'syslog', collector_id: null, received_at: null, event_time: null, raw: 'hello', parsed: {},
  });
});

test('makeEnvelope: normalises times to UTC ISO strings', () => {
  assert.strictEqual(normalizeTime('2026-10-13T10:00:01+02:00', 't'), '2026-10-13T08:00:01.000Z');
  assert.strictEqual(normalizeTime('2026-10-13 10:00:01', 't'), '2026-10-13T10:00:01.000Z', 'no zone = UTC');
  assert.strictEqual(normalizeTime('2026-10-13T10:00:01+0000', 't'), '2026-10-13T10:00:01.000Z');
  assert.strictEqual(normalizeTime(new Date(0), 't'), '1970-01-01T00:00:00.000Z');
  assert.strictEqual(normalizeTime(1760349601000, 't'), '2025-10-13T10:00:01.000Z');
  assert.strictEqual(normalizeTime(undefined, 't'), null);
  assert.strictEqual(normalizeTime('', 't'), null);
  for (const bad of ['yesterday', 'Oct  1 10:00:00', '2026-13-45T00:00:00Z', {}, true]) assert.throws(() => normalizeTime(bad, 't'), EnvelopeError, String(bad));
});

test('makeEnvelope: rejects bad fields with the field name', () => {
  const fails = (over, field) => assert.throws(() => makeEnvelope({ ...base, ...over }), (e) => e instanceof EnvelopeError && e.code === 'INVALID_ENVELOPE' && e.field === field, JSON.stringify(over).slice(0, 60));
  fails({ tenant_id: 'x' }, 'tenant_id');
  fails({ tenant_id: undefined }, 'tenant_id');
  fails({ source_type: '' }, 'source_type');
  fails({ source_type: 'a'.repeat(LIMITS.SOURCE_TYPE + 1) }, 'source_type');
  fails({ source_type: 'sys\nlog' }, 'source_type');
  fails({ source_type: 5 }, 'source_type');
  fails({ collector_id: 'c'.repeat(LIMITS.COLLECTOR_ID + 1) }, 'collector_id');
  fails({ raw: undefined }, 'raw');
  fails({ raw: '' }, 'raw');
  fails({ raw: '\u0000' }, 'raw');
  fails({ raw: 'r'.repeat(LIMITS.RAW + 1) }, 'raw');
  fails({ parsed: 'x' }, 'parsed');
  fails({ parsed: [] }, 'parsed');
  fails({ parsed: { big: 'x'.repeat(LIMITS.PARSED_BYTES) } }, 'parsed');
  fails({ id: 'nope', received_at: '2026-10-13T10:00:00Z' }, 'id');
  fails({ id: T }, 'received_at');           // an id needs received_at: the pair is the idempotency key
  fails({ event_time: 'soon' }, 'event_time');
  for (const x of [null, undefined, 'str', 7, [], new Date()]) assert.throws(() => makeEnvelope(x), EnvelopeError);
});

test('makeEnvelope: an id with received_at is kept (lower-cased), source_type is trimmed', () => {
  const e = makeEnvelope({ ...base, id: T.toUpperCase(), received_at: '2026-10-13T10:00:00Z', source_type: ' syslog ', collector_id: '' });
  assert.strictEqual(e.id, T);
  assert.strictEqual(e.received_at, '2026-10-13T10:00:00.000Z');
  assert.strictEqual(e.source_type, 'syslog');
  assert.strictEqual(e.collector_id, null);
});

test('cleanJson: strips NULs, drops unusable values, never mutates the input', () => {
  const input = { a: 'x\u0000y', 'k\u0000': 1, n: NaN, big: 10n, d: new Date(0), f() {}, u: undefined, arr: [undefined, 'a\u0000', { z: 'q\u0000' }], nested: { deep: { ok: true } } };
  const snapshot = JSON.stringify(input, (k, v) => (typeof v === 'bigint' ? String(v) : v));
  const out = cleanJson(input);
  assert.deepStrictEqual(out, { a: 'xy', k: 1, n: null, big: '10', d: '1970-01-01T00:00:00.000Z', arr: [null, 'a', { z: 'q' }], nested: { deep: { ok: true } } });
  assert.strictEqual(JSON.stringify(input, (k, v) => (typeof v === 'bigint' ? String(v) : v)), snapshot);
});

test('cleanJson: __proto__ keys cannot change prototypes; absurd nesting is refused', () => {
  const evil = JSON.parse('{"__proto__": {"polluted": true}, "ok": 1}');
  const out = cleanJson(evil);
  assert.deepStrictEqual(out, { ok: 1 });
  assert.strictEqual(Object.getPrototypeOf(out), Object.prototype);
  assert.strictEqual({}.polluted, undefined);
  let deep = {}; const root = deep;
  for (let i = 0; i < LIMITS.JSON_DEPTH + 5; i++) { deep.n = {}; deep = deep.n; }
  assert.throws(() => cleanJson(root), EnvelopeError);
  const cyc = {}; cyc.self = cyc;
  assert.throws(() => cleanJson(cyc), EnvelopeError, 'cycles hit the depth limit instead of looping');
});

test('registry: default is postgres, memory is blocked in production, unknown names fail', () => {
  const saved = { s: process.env.ASIX_EVENT_STORE, n: process.env.NODE_ENV };
  try {
    setEventStore(null);
    process.env.ASIX_EVENT_STORE = 'memory'; process.env.NODE_ENV = 'test';
    assert.ok(getEventStore() instanceof MemoryEventStore);
    assert.strictEqual(getEventStore(), getEventStore(), 'one instance per process');
    setEventStore(null);
    process.env.NODE_ENV = 'production';
    assert.throws(() => getEventStore(), /not allowed in production/);
    setEventStore(null);
    process.env.ASIX_EVENT_STORE = 'cassandra';
    assert.throws(() => getEventStore(), /Unknown ASIX_EVENT_STORE/);
    setEventStore(null);
    delete process.env.ASIX_EVENT_STORE; process.env.NODE_ENV = 'test';
    assert.strictEqual(getEventStore().name, 'postgres');
    assert.deepStrictEqual(Object.keys(FACTORIES), ['postgres', 'memory']);
  } finally {
    setEventStore(null);
    if (saved.s === undefined) delete process.env.ASIX_EVENT_STORE; else process.env.ASIX_EVENT_STORE = saved.s;
    if (saved.n === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = saved.n;
  }
});

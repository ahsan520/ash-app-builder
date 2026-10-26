'use strict';
// Per-collector "Connected" threshold: the pure rules (src/collectors/status.js), then the real
// collectors routes with the sign-in chain, the database and the event store replaced.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const st = require('../src/collectors/status');

describe('checkMinutes', () => {
  it('accepts whole minutes in range and null (back to the default)', () => {
    assert.deepStrictEqual(st.checkMinutes(1), { value: 1 });
    assert.deepStrictEqual(st.checkMinutes(10080), { value: 10080 });
    assert.deepStrictEqual(st.checkMinutes(null), { value: null });
    assert.deepStrictEqual(st.checkMinutes(undefined), { value: null });
  });
  it('refuses zero, negatives, too large, fractions, strings and NaN', () => {
    for (const v of [0, -5, 10081, 1.5, '30', '', NaN, Infinity, true, [], {}]) assert.ok(st.checkMinutes(v).error, 'should refuse ' + JSON.stringify(v));
  });
});

describe('effectiveMinutes and isCustom', () => {
  it('uses the stored value, else the default', () => {
    assert.strictEqual(st.effectiveMinutes(60), 60);
    assert.strictEqual(st.effectiveMinutes('60'), 60);   // a driver may hand back text
    for (const v of [null, undefined, 0, -1, 99999, 'x']) assert.strictEqual(st.effectiveMinutes(v), st.DEFAULT_MINUTES);
  });
  it('custom means a usable stored value', () => {
    assert.strictEqual(st.isCustom(60), true);
    assert.strictEqual(st.isCustom(15), true);   // set on purpose, even if it equals the default
    for (const v of [null, undefined, 0, 99999]) assert.strictEqual(st.isCustom(v), false);
  });
});

describe('statusOf', () => {
  const now = Date.UTC(2026, 9, 17, 12, 0, 0);
  const ago = (min) => new Date(now - min * 60000);
  it('is connected up to and including the threshold, disconnected after', () => {
    assert.strictEqual(st.statusOf(ago(15), null, now), 'connected');
    assert.strictEqual(st.statusOf(ago(15.1), null, now), 'disconnected');
    assert.strictEqual(st.statusOf(ago(59), 60, now), 'connected');
    assert.strictEqual(st.statusOf(ago(61), 60, now), 'disconnected');
    assert.strictEqual(st.statusOf(ago(3), 2, now), 'disconnected');
  });
  it('reads Date objects and timestamp strings with or without a Z', () => {
    assert.strictEqual(st.statusOf('2026-10-17T11:50:00', null, now), 'connected');
    assert.strictEqual(st.statusOf('2026-10-17T11:50:00Z', null, now), 'connected');
    assert.strictEqual(st.statusOf('2026-10-17T11:50:00+00:00', null, now), 'connected');
    assert.strictEqual(st.statusOf('2026-10-17T10:00:00', null, now), 'disconnected');
  });
  it('treats a missing or unreadable last-seen as disconnected', () => {
    for (const v of [null, undefined, 'garbage']) assert.strictEqual(st.statusOf(v, 60, now), 'disconnected');
  });
});

describe('collectors routes', () => {
  const TENANT = '11111111-1111-4111-8111-111111111111';
  const ID_A = '22222222-2222-4222-8222-222222222222';
  const ID_B = '33333333-3333-4333-8333-333333333333';
  const mins = (m) => new Date(Date.now() - m * 60000);
  let rows; let updates;
  const fakeClient = {
    query: async (sql, args) => {
      if (/^UPDATE collectors SET connected_within_min/.test(sql)) {
        updates.push(args);
        const row = rows.find((r) => r.id === args[0] && args[2] === TENANT);
        if (!row) return { rows: [] };
        row.connected_within_min = args[1];
        return { rows: [{ id: row.id, name: row.name, connected_within_min: row.connected_within_min }] };
      }
      if (/FROM collectors c/.test(sql)) return { rows: rows.map((r) => ({ ...r })) };
      return { rows: [] };
    },
  };
  const fakeDb = { withTenant: async (t, fn) => fn(fakeClient), query: async () => ({ rows: [] }) };
  const shared = require('../src/gateway/shared');
  const savedShared = require.cache[require.resolve('../src/gateway/shared')].exports;
  let srv; let base;
  before(async () => {
    require.cache[require.resolve('../src/gateway/shared')].exports = {
      ...shared, db: fakeDb, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }],
    };
    for (const m of ['collectors', 'collector-threshold']) delete require.cache[require.resolve('../src/gateway/routes/' + m)];
    const { setEventStore } = require('../src/events'); const { MemoryEventStore } = require('../src/events/memory-store');
    setEventStore(new MemoryEventStore());
    const app = express(); app.use(express.json());
    app.use(require('../src/gateway/routes/collectors')); app.use(require('../src/gateway/routes/collector-threshold'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); require.cache[require.resolve('../src/gateway/shared')].exports = savedShared; });
  const fresh = () => {
    updates = [];
    rows = [
      { id: ID_A, name: 'nightly-job', alias: null, platform: 'linux', os: null, version: null, last_ip: null, first_seen: mins(9000), last_seen: mins(40), events_total: 5, connected_within_min: null, installer: 'k', origin: 'registered' },
      { id: ID_B, name: 'chatty', alias: null, platform: 'linux', os: null, version: null, last_ip: null, first_seen: mins(9000), last_seen: mins(5), events_total: 5, connected_within_min: null, installer: 'k', origin: 'registered' },
    ];
  };
  const put = async (id, body) => { const r = await fetch(base + '/v1/collectors/' + id + '/threshold', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status, body: await r.json() }; };
  const list = async (q = '') => (await fetch(base + '/v1/collectors' + q)).json();

  it('judges every collector against the default until it has its own threshold', async () => {
    fresh();
    const r = await list();
    assert.strictEqual(r.connected_within_minutes, 15);
    const by = Object.fromEntries(r.collectors.map((c) => [c.name, c]));
    assert.strictEqual(by['nightly-job'].status, 'disconnected'); assert.strictEqual(by['nightly-job'].connected_within_min, 15); assert.strictEqual(by['nightly-job'].connected_custom, false);
    assert.strictEqual(by.chatty.status, 'connected');
  });
  it('a longer threshold turns a slow sender connected, a shorter one turns a chatty sender disconnected', async () => {
    fresh();
    let r = await put(ID_A, { minutes: 120 });
    assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.body.collector, { id: ID_A, name: 'nightly-job', connected_within_min: 120, connected_custom: true, default_minutes: 15 });
    r = await put(ID_B, { minutes: 2 });
    assert.strictEqual(r.status, 200);
    const by = Object.fromEntries((await list()).collectors.map((c) => [c.name, c]));
    assert.strictEqual(by['nightly-job'].status, 'connected'); assert.strictEqual(by['nightly-job'].connected_custom, true);
    assert.strictEqual(by.chatty.status, 'disconnected'); assert.strictEqual(by.chatty.connected_within_min, 2);
  });
  it('the status filter uses each collector\'s own threshold', async () => {
    fresh(); await put(ID_A, { minutes: 120 });
    assert.deepStrictEqual((await list('?status=connected')).collectors.map((c) => c.name).sort(), ['chatty', 'nightly-job']);
    assert.deepStrictEqual((await list('?status=disconnected')).collectors, []);
  });
  it('null goes back to the default', async () => {
    fresh(); await put(ID_A, { minutes: 120 });
    const r = await put(ID_A, { minutes: null });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.body.collector.connected_custom, false); assert.strictEqual(r.body.collector.connected_within_min, 15);
    assert.strictEqual(rows[0].connected_within_min, null);
  });
  it('refuses bad values with 400 and writes nothing', async () => {
    fresh();
    for (const body of [{ minutes: 0 }, { minutes: 10081 }, { minutes: 1.5 }, { minutes: '30' }, {}, { other: 1 }]) {
      const r = await put(ID_A, body);
      assert.strictEqual(r.status, 400, JSON.stringify(body));
    }
    assert.strictEqual((await put('not-a-uuid', { minutes: 5 })).status, 400);
    assert.strictEqual(updates.length, 0);
  });
  it('404 for an unknown collector', async () => {
    fresh();
    assert.strictEqual((await put('44444444-4444-4444-8444-444444444444', { minutes: 5 })).status, 404);
  });
  it('sources that only appear in events use the default', async () => {
    fresh(); rows = [];
    const { getEventStore } = require('../src/events');
    await getEventStore().insertBatch(TENANT, [{ id: require('crypto').randomUUID(), tenant_id: TENANT, source_type: 'syslog', collector_id: 'syslog-built-in', received_at: new Date().toISOString(), event_time: null, raw: 'x', parsed: {} }]);
    const r = await list();
    assert.strictEqual(r.collectors.length, 1);
    assert.strictEqual(r.collectors[0].status, 'connected'); assert.strictEqual(r.collectors[0].connected_within_min, 15); assert.strictEqual(r.collectors[0].connected_custom, false);
  });
});

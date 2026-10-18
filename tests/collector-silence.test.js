'use strict';
// Silent-collector watch (src/collectors/silence.js): the pure planning rules, the SQL it sends (database and event store replaced
// by recorders), and PUT /v1/collectors/:id/silent-watch with the sign-in chain and database replaced.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const sl = require('../src/collectors/silence');

const NOW = Date.UTC(2026, 9, 18, 12, 0, 0);
const ago = (m) => new Date(NOW - m * 60000);
const iso = (m) => ago(m).toISOString();
const col = (o = {}) => ({ id: 'c1', name: 'broker-1', last_seen: ago(1), connected_within_min: null, watch_silent_min: 60, ...o });
const ev = (o) => new Map(Object.entries(o).map(([k, m]) => [k, iso(m)]));
const P = (o, opts = { now: NOW }) => sl.plan({ collectors: [col()], newestEvent: ev({ 'broker-1': 90 }), active: [], latest: [], ...o }, opts);

describe('checkMinutes', () => {
  it('accepts null (off) and whole minutes from 5 to 4320', () => {
    assert.deepStrictEqual(sl.checkMinutes(null), { value: null });
    assert.deepStrictEqual(sl.checkMinutes(undefined), { value: null });
    assert.deepStrictEqual(sl.checkMinutes(5), { value: 5 });
    assert.deepStrictEqual(sl.checkMinutes(4320), { value: 4320 });
  });
  it('refuses everything else', () => {
    for (const v of [0, 4, 4321, 1.5, '60', true, NaN, -1, {}]) assert.ok(sl.checkMinutes(v).error, String(v));
  });
});

describe('plan: raising', () => {
  it('raises nothing while events are flowing', () => {
    assert.deepStrictEqual(P({ newestEvent: ev({ 'broker-1': 10 }) }), { raise: [], close: [] });
  });
  it('raises one alert when the newest event is older than the limit and the collector still reports in', () => {
    const p = P();
    assert.strictEqual(p.raise.length, 1); assert.strictEqual(p.close.length, 0);
    assert.deepStrictEqual(p.raise[0], { collector_id: 'c1', name: 'broker-1', group_key: 'silent:c1', last_event: iso(90), minutes: 90, threshold: 60 });
  });
  it('is exactly at the limit: not yet silent', () => {
    assert.deepStrictEqual(P({ newestEvent: ev({ 'broker-1': 60 }) }), { raise: [], close: [] });
  });
  it('judges each collector by its own limit and its own events (matched by name)', () => {
    const p = P({ collectors: [col(), col({ id: 'c2', name: 'quiet', watch_silent_min: 240 })], newestEvent: ev({ 'broker-1': 90, quiet: 90 }) });
    assert.deepStrictEqual(p.raise.map((r) => r.name), ['broker-1']);
  });
  it('skips a collector with no event in the window, instead of guessing', () => {
    assert.deepStrictEqual(P({ newestEvent: new Map() }), { raise: [], close: [] });
  });
  it('leaves a collector that is itself Disconnected to the "Collector disconnected" alert', () => {
    assert.deepStrictEqual(P({ collectors: [col({ last_seen: ago(60) })] }), { raise: [], close: [] });
  });
  it('uses the collector\'s own connected threshold when judging that', () => {
    assert.strictEqual(P({ collectors: [col({ last_seen: ago(60), connected_within_min: 120 })] }).raise.length, 1);
  });
  it('ignores a stored limit that is not a positive number', () => {
    for (const v of [null, 0, 'x']) assert.deepStrictEqual(P({ collectors: [col({ watch_silent_min: v })] }), { raise: [], close: [] }, String(v));
  });
  it('does not raise a second alert while one is open or acknowledged', () => {
    for (const status of ['open', 'acknowledged']) {
      const p = P({ active: [{ id: 'a1', group_key: 'silent:c1' }], latest: [{ group_key: 'silent:c1', status, last_event: iso(90) }] });
      assert.deepStrictEqual(p, { raise: [], close: [] }, status);
    }
  });
  it('does not raise again for the same silence after an analyst closed the alert', () => {
    assert.deepStrictEqual(P({ latest: [{ group_key: 'silent:c1', status: 'closed', last_event: iso(90) }] }), { raise: [], close: [] });
  });
  it('raises again for a new silence (events came back, then stopped again)', () => {
    const p = P({ newestEvent: ev({ 'broker-1': 70 }), latest: [{ group_key: 'silent:c1', status: 'closed', last_event: iso(600) }] });
    assert.strictEqual(p.raise.length, 1); assert.strictEqual(p.raise[0].last_event, iso(70));
  });
  it('raises nothing during the start-up grace, but still closes', () => {
    const p = P({ collectors: [col(), col({ id: 'c2', name: 'b2' })], newestEvent: ev({ 'broker-1': 90, b2: 5 }), active: [{ id: 'a2', group_key: 'silent:c2' }] }, { now: NOW, raiseAllowed: false });
    assert.strictEqual(p.raise.length, 0); assert.deepStrictEqual(p.close.map((c) => c.alert_id), ['a2']);
  });
});

describe('plan: closing', () => {
  it('closes the alert when events arrive again', () => {
    const p = P({ newestEvent: ev({ 'broker-1': 2 }), active: [{ id: 'a1', group_key: 'silent:c1' }], latest: [{ group_key: 'silent:c1', status: 'open', last_event: iso(90) }] });
    assert.deepStrictEqual(p.close, [{ alert_id: 'a1', reason: 'Events are arriving from the collector again.' }]);
  });
  it('closes the alert when the collector is no longer watched or was deleted (it is not in the watched list)', () => {
    const p = P({ collectors: [], active: [{ id: 'a1', group_key: 'silent:gone' }] });
    assert.strictEqual(p.close.length, 1); assert.match(p.close[0].reason, /no longer watched for silence or was removed/);
  });
  it('keeps the alert of a collector that is still silent', () => {
    const p = P({ active: [{ id: 'a1', group_key: 'silent:c1' }], latest: [{ group_key: 'silent:c1', status: 'open', last_event: iso(90) }] });
    assert.deepStrictEqual(p, { raise: [], close: [] });
  });
  it('keeps the alert when the silence is so long that no event is left in the window', () => {
    const p = P({ newestEvent: new Map(), active: [{ id: 'a1', group_key: 'silent:c1' }] });
    assert.deepStrictEqual(p, { raise: [], close: [] });
  });
  it('keeps the alert of a silent collector that has also gone Disconnected (it is still silent)', () => {
    const p = P({ collectors: [col({ last_seen: ago(500) })], active: [{ id: 'a1', group_key: 'silent:c1' }], latest: [{ group_key: 'silent:c1', status: 'open', last_event: iso(90) }] });
    assert.deepStrictEqual(p, { raise: [], close: [] });
  });
});

describe('runTenant (database and event store replaced)', () => {
  const dbPath = require.resolve('../src/db');
  const saved = require.cache[dbPath].exports;
  let calls, rows;
  before(() => {
    require.cache[dbPath].exports = { ...saved, withTenant: async (t, fn) => fn({ query: async (sql, args) => {
      calls.push({ sql, args });
      if (/FROM collectors/.test(sql)) return { rows: rows.collectors };
      if (/status IN \('open','acknowledged'\)/.test(sql)) return { rows: rows.active };
      if (/DISTINCT ON/.test(sql)) return { rows: rows.latest };
      return { rows: [] };
    } }) };
    delete require.cache[require.resolve('../src/collectors/silence')];
  });
  after(() => { require.cache[dbPath].exports = saved; delete require.cache[require.resolve('../src/collectors/silence')]; });
  const run = (o) => require('../src/collectors/silence').runTenant('t1', o);

  it('asks the store for per-collector counts over the 7 day window, then raises and closes what plan() says', async () => {
    calls = []; rows = { collectors: [col()], active: [{ id: 'old', group_key: 'silent:gone' }], latest: [] };
    const asked = [];
    const store = { groupCounts: async (t, q) => { asked.push({ t, q }); return [{ key: 'broker-1', events: 3, first_seen: iso(500), last_seen: iso(90) }]; } };
    const r = await run({ now: NOW, sev: 'high', store });
    assert.deepStrictEqual(r, { raised: 1, closed: 1 });
    assert.deepStrictEqual(asked, [{ t: 't1', q: { by: 'collector_id', since: new Date(NOW - 7 * 86400000).toISOString() } }]);
    const ins = calls.find((c) => /INSERT INTO alerts/.test(c.sql));
    assert.match(ins.sql, /VALUES \(\$1, NULL, \$2/); assert.strictEqual(ins.args[1], 'Collector sending no events'); assert.strictEqual(ins.args[2], 'high'); assert.strictEqual(ins.args[5], 'silent:c1');
    assert.deepStrictEqual(JSON.parse(ins.args[7]), { collector_id: 'c1', collector: 'broker-1', last_event: iso(90), silent_after_min: 60 });
    assert.ok(calls.some((c) => /SET status = 'closed'/.test(c.sql) && c.args[0] === 'old'));
    assert.ok(calls.some((c) => /INSERT INTO alert_notes/.test(c.sql) && c.args[1] === 'old'));
  });
  it('does not touch the event store when nothing is watched and nothing is open', async () => {
    calls = []; rows = { collectors: [], active: [], latest: [] };
    const store = { groupCounts: async () => { throw new Error('must not be called'); } };
    assert.deepStrictEqual(await run({ now: NOW, store }), { raised: 0, closed: 0 });
  });
  it('lets an event-store failure through (the watchdog logs it and carries on with other tenants)', async () => {
    calls = []; rows = { collectors: [col()], active: [], latest: [] };
    await assert.rejects(run({ now: NOW, store: { groupCounts: async () => { throw new Error('store down'); } } }), /store down/);
  });
});

describe('PUT /v1/collectors/:id/silent-watch', () => {
  const TENANT = '11111111-1111-4111-8111-111111111111';
  const ID = '22222222-2222-4222-8222-222222222222';
  let rows; let seen;
  const fakeDb = { withTenant: async (t, fn) => fn({ query: async (sql, args) => { seen = { sql, args }; return { rows }; } }), query: async () => ({ rows: [] }) };
  const sharedPath = require.resolve('../src/gateway/shared');
  const shared = require('../src/gateway/shared');
  const savedShared = require.cache[sharedPath].exports;
  let srv; let base;
  before(() => {
    require.cache[sharedPath].exports = { ...shared, db: fakeDb, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }] };
    delete require.cache[require.resolve('../src/gateway/routes/collector-silent')];
    const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/collector-silent'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); require.cache[sharedPath].exports = savedShared; });
  const put = async (id, body) => { const r = await fetch(base + '/v1/collectors/' + id + '/silent-watch', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };

  it('turns it on and off for this tenant\'s collector only', async () => {
    rows = [{ id: ID, name: 'broker-1', watch_silent_min: 60 }];
    let r = await put(ID, { minutes: 60 });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.collector.watch_silent_min, 60);
    assert.deepStrictEqual(seen.args, [ID, 60, TENANT]);
    await put(ID, { minutes: null }); assert.deepStrictEqual(seen.args, [ID, null, TENANT]);
  });
  it('refuses a bad id, a missing or out-of-range minutes, and an unknown collector', async () => {
    assert.strictEqual((await put('nope', { minutes: 60 })).status, 400);
    assert.strictEqual((await put(ID, {})).status, 400);
    for (const b of [{ minutes: 4 }, { minutes: 5000 }, { minutes: '60' }, { minutes: 2.5 }, { minutes: true }]) assert.strictEqual((await put(ID, b)).status, 400, JSON.stringify(b));
    rows = []; assert.strictEqual((await put(ID, { minutes: 60 })).status, 404);
  });
});

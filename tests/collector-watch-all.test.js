'use strict';
// "Watch everything" (src/collectors/watch-all.js): the rules in plain code, the SQL arguments the watchdogs send, and
// GET/PUT /v1/collector-watch-defaults with the sign-in chain and database replaced. The real database is in collector-watch-all-db.test.js.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const wa = require('../src/collectors/watch-all');

const NOW = Date.UTC(2026, 9, 18, 12, 0, 0);
const DAY = 86400000;
const ago = (ms) => new Date(NOW - ms);
const ON = { disconnect: true, silent_min: 60 }, OFF = { disconnect: false, silent_min: null };
const col = (o = {}) => ({ watch_disconnect: false, watch_silent_min: null, last_seen: ago(60000), ...o });

describe('settings', () => {
  it('no row, or anything unusable, means off', () => {
    assert.deepStrictEqual(wa.fromRow(undefined), OFF);
    assert.deepStrictEqual(wa.fromRow({ watch_disconnect: 'true', watch_silent_min: '60' }), OFF);
    assert.deepStrictEqual(wa.fromRow({ watch_disconnect: true, watch_silent_min: 90 }), { disconnect: true, silent_min: 90 });
  });
  it('the age limit is 7 days unless ASIX_WATCH_ALL_MAX_AGE_DAYS is a whole number of days from 1 to 90', () => {
    assert.strictEqual(wa.maxAgeDays({}), 7);
    assert.strictEqual(wa.maxAgeDays({ ASIX_WATCH_ALL_MAX_AGE_DAYS: '30' }), 30);
    for (const v of ['0', '91', '1.5', 'abc', '-3', '']) assert.strictEqual(wa.maxAgeDays({ ASIX_WATCH_ALL_MAX_AGE_DAYS: v }), 7, v);
  });
  it('the cutoff is a UTC timestamp without a zone, the age limit before now', () => {
    assert.strictEqual(wa.cutoffOf(NOW, 7), '2026-10-11T12:00:00.000');
  });
});

describe('the rules', () => {
  it('switch off: only what was switched on by hand is watched, as before', () => {
    assert.strictEqual(wa.watchesDisconnect(col(), OFF, NOW), false);
    assert.strictEqual(wa.watchesDisconnect(col({ watch_disconnect: true }), OFF, NOW), true);
    assert.strictEqual(wa.silentMinutes(col(), OFF, NOW), null);
    assert.strictEqual(wa.silentMinutes(col({ watch_silent_min: 30 }), OFF, NOW), 30);
  });
  it('switch on: every collector seen within the age limit is watched, a Disconnected one too', () => {
    assert.strictEqual(wa.watchesDisconnect(col(), ON, NOW), true);
    assert.strictEqual(wa.watchesDisconnect(col({ last_seen: ago(3 * DAY) }), ON, NOW), true);
    assert.strictEqual(wa.silentMinutes(col(), ON, NOW), 60);
  });
  it('a collector not seen for longer than the age limit, or never, is left out; one switched on by hand is not', () => {
    const old = col({ last_seen: ago(8 * DAY) });
    assert.strictEqual(wa.watchesDisconnect(old, ON, NOW), false);
    assert.strictEqual(wa.silentMinutes(old, ON, NOW), null);
    assert.strictEqual(wa.watchesDisconnect(col({ last_seen: null }), ON, NOW), false);
    assert.strictEqual(wa.watchesDisconnect({ ...old, watch_disconnect: true }, ON, NOW), true);
    assert.strictEqual(wa.silentMinutes({ ...old, watch_silent_min: 15 }, ON, NOW), 15);
    assert.strictEqual(wa.watchesDisconnect(col({ last_seen: ago(7 * DAY) }), ON, NOW), true, 'exactly at the limit is still in');
  });
  it("a collector's own silent limit wins over the switch, longer or shorter", () => {
    assert.strictEqual(wa.silentMinutes(col({ watch_silent_min: 200 }), ON, NOW), 200);
    assert.strictEqual(wa.silentMinutes(col({ watch_silent_min: 10 }), ON, NOW), 10);
  });
  it('says when the switch, not the collector, is what covers it', () => {
    assert.strictEqual(wa.disconnectByDefault(col(), ON, NOW), true);
    assert.strictEqual(wa.disconnectByDefault(col({ watch_disconnect: true }), ON, NOW), false);
    assert.strictEqual(wa.disconnectByDefault(col(), OFF, NOW), false);
    assert.strictEqual(wa.silentByDefault(col(), ON, NOW), true);
    assert.strictEqual(wa.silentByDefault(col({ watch_silent_min: 200 }), ON, NOW), false);
    assert.strictEqual(wa.silentByDefault(col({ last_seen: ago(9 * DAY) }), ON, NOW), false);
  });
});

describe('the watchdogs send the switch to the database (database replaced by a recorder)', () => {
  const dbPath = require.resolve('../src/db');
  const saved = require.cache[dbPath].exports;
  let calls, defaults;
  before(() => {
    require.cache[dbPath].exports = { ...saved, withTenant: async (t, fn) => fn({ query: async (sql, args) => {
      calls.push({ sql, args });
      if (/FROM collector_watch_defaults/.test(sql)) return { rows: defaults ? [defaults] : [] };
      return { rows: [] };
    } }) };
    for (const m of ['watchdog', 'silence', 'key-watch']) delete require.cache[require.resolve('../src/collectors/' + m)];
  });
  after(() => { require.cache[dbPath].exports = saved; for (const m of ['watchdog', 'silence', 'key-watch']) delete require.cache[require.resolve('../src/collectors/' + m)]; });
  const sel = () => calls.find((c) => /FROM collectors/.test(c.sql));
  const cutoff = '2026-10-11T12:00:00.000';

  it('disconnect check: switch off sends false, switch on sends true, with the age cutoff', async () => {
    const wd = require('../src/collectors/watchdog');
    calls = []; defaults = null; await wd.runTenant('t1', { now: NOW });
    assert.deepStrictEqual(sel().args, ['t1', false, cutoff]); assert.match(sel().sql, /watch_disconnect OR \(\$2::boolean AND last_seen >= \$3::timestamp\)/);
    calls = []; defaults = { watch_disconnect: true, watch_silent_min: null }; await wd.runTenant('t1', { now: NOW });
    assert.deepStrictEqual(sel().args, ['t1', true, cutoff]);
  });
  it('silent check: the limit goes in as a number or null, and the collector\'s own limit is tried first', async () => {
    const sl = require('../src/collectors/silence');
    const store = { groupCounts: async () => [] };
    calls = []; defaults = { watch_disconnect: false, watch_silent_min: 45 }; await sl.runTenant('t1', { now: NOW, store });
    assert.deepStrictEqual(sel().args, ['t1', 45, cutoff]); assert.match(sel().sql, /COALESCE\(watch_silent_min, CASE WHEN last_seen >= \$3::timestamp THEN \$2::integer END\)/);
    calls = []; defaults = null; await sl.runTenant('t1', { now: NOW, store });
    assert.deepStrictEqual(sel().args, ['t1', null, cutoff]);
  });
  it('broker key check: follows the disconnect switch', async () => {
    const kw = require('../src/collectors/key-watch');
    calls = []; defaults = { watch_disconnect: true, watch_silent_min: null }; await kw.runTenant('t1', { now: NOW });
    assert.deepStrictEqual(sel().args, ['t1', 'vector-%', true, cutoff]);
  });
});

describe('GET/PUT /v1/collector-watch-defaults (sign-in chain and database replaced)', () => {
  const shPath = require.resolve('../src/gateway/shared');
  require('../src/gateway/shared');
  const savedSh = require.cache[shPath].exports;
  let stored, queries, http, base;
  const fakeDb = { withTenant: async (t, fn) => fn({ query: async (sql, args) => {
    queries.push({ sql, args });
    if (/FROM collector_watch_defaults/.test(sql)) return { rows: stored ? [stored] : [] };
    if (/INSERT INTO collector_watch_defaults/.test(sql)) { stored = { watch_disconnect: args[1], watch_silent_min: args[2] }; return { rows: [] }; }
    if (/count\(\*\)/.test(sql)) return { rows: [{ total: 9, retired: 2 }] };
    return { rows: [] };
  } }) };
  before(async () => {
    require.cache[shPath].exports = { ...savedSh, db: fakeDb, guarded: () => [(req, res, next) => { req.tenant_id = 't1'; req.user_id = 'u1'; next(); }] };
    delete require.cache[require.resolve('../src/gateway/routes/collector-watch-all')];
    const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/collector-watch-all'));
    http = app.listen(0); base = 'http://127.0.0.1:' + http.address().port;
  });
  after(() => { http.close(); require.cache[shPath].exports = savedSh; delete require.cache[require.resolve('../src/gateway/routes/collector-watch-all')]; });
  const call = async (method, body) => { const r = await fetch(base + '/v1/collector-watch-defaults', { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }); return { status: r.status, json: await r.json() }; };

  it('GET answers off when nothing is stored, with the age limit and how many collectors are left out', async () => {
    stored = null; queries = [];
    const r = await call('GET');
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(r.json.defaults, { disconnect: false, silent_min: null, max_age_days: 7, collectors: 9, left_out_as_retired: 2, silent_limits: { min: 5, max: 4320 } });
  });
  it('PUT stores what it is given and keeps what it leaves out', async () => {
    stored = null; queries = [];
    let r = await call('PUT', { disconnect: true });
    assert.strictEqual(r.status, 200); assert.deepStrictEqual([r.json.defaults.disconnect, r.json.defaults.silent_min], [true, null]);
    r = await call('PUT', { silent_min: 120 });
    assert.deepStrictEqual([r.json.defaults.disconnect, r.json.defaults.silent_min], [true, 120]);
    const ins = queries.filter((q) => /INSERT INTO collector_watch_defaults/.test(q.sql));
    assert.deepStrictEqual(ins[1].args, ['t1', true, 120, 'u1']);
    r = await call('PUT', { disconnect: false, silent_min: null });
    assert.deepStrictEqual([r.json.defaults.disconnect, r.json.defaults.silent_min], [false, null]);
  });
  it('PUT refuses a bad body and stores nothing', async () => {
    stored = null; queries = [];
    for (const body of [{}, { other: 1 }, { disconnect: 'true' }, { disconnect: null }, { silent_min: 1 }, { silent_min: 5000 }, { silent_min: 'x' }, [true]]) {
      const r = await call('PUT', body);
      assert.strictEqual(r.status, 400, JSON.stringify(body)); assert.ok(r.json.error || r.json.code || r.json.message, 'error body');
    }
    assert.ok(!queries.some((q) => /INSERT INTO collector_watch_defaults/.test(q.sql)));
  });
});

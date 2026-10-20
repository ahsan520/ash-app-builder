'use strict';
// Unparsed-events alert (src/ingestion/parse-watch.js): settings, the pure planning rules, and the SQL (database replaced by a recorder).
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const pw = require('../src/ingestion/parse-watch');

const cfg = { threshold: 10, windowMin: 15 };
const P = (o, c = cfg, opts) => pw.plan({ total: 0, byReason: {}, active: [], latest: null, ...o }, c, opts);

describe('config', () => {
  it('is off unless a whole number of events is set', () => {
    for (const v of [undefined, '', '0', '-3', '1.5', 'abc', '1000001']) assert.strictEqual(pw.config({ ASIX_PARSE_ALERT_MIN_EVENTS: v }).threshold, 0, String(v));
    assert.strictEqual(pw.config({ ASIX_PARSE_ALERT_MIN_EVENTS: '25' }).threshold, 25);
  });
  it('window defaults to 15 and accepts 5 to 1440 only', () => {
    assert.strictEqual(pw.config({}).windowMin, 15);
    for (const v of ['4', '1441', 'x', '7.5']) assert.strictEqual(pw.config({ ASIX_PARSE_ALERT_WINDOW_MIN: v }).windowMin, 15, v);
    assert.strictEqual(pw.config({ ASIX_PARSE_ALERT_WINDOW_MIN: '60' }).windowMin, 60);
  });
});

describe('plan', () => {
  it('raises nothing below the limit and one alert at the limit', () => {
    assert.deepStrictEqual(P({ total: 9 }), { raise: [], close: [] });
    const p = P({ total: 10, byReason: { PARSE_TIMEOUT: 10 } });
    assert.strictEqual(p.raise.length, 1); assert.deepStrictEqual(p.raise[0], { total: 10, window_min: 15, threshold: 10, by_reason: { PARSE_TIMEOUT: 10 } });
  });
  it('does nothing while off, and closes what is open', () => {
    assert.deepStrictEqual(P({ total: 999 }, { threshold: 0, windowMin: 15 }), { raise: [], close: [] });
    const p = P({ active: [{ id: 'a1' }] }, { threshold: 0, windowMin: 15 });
    assert.deepStrictEqual(p.close, [{ alert_id: 'a1', reason: 'The unparsed-events alert is turned off.' }]);
  });
  it('does not raise a second alert while one is open or acknowledged', () => {
    assert.deepStrictEqual(P({ total: 50, active: [{ id: 'a1' }], latest: { status: 'open', closed_by: null, age_s: 5 } }), { raise: [], close: [] });
  });
  it('closes when the count drops below the limit', () => {
    const p = P({ total: 3, active: [{ id: 'a1' }] });
    assert.strictEqual(p.close.length, 1); assert.match(p.close[0].reason, /below the limit/);
  });
  it('does not raise again for 60 minutes after an analyst closed it, then does', () => {
    const closed = (age_s) => ({ status: 'closed', closed_by: null, age_s });
    assert.strictEqual(P({ total: 50, latest: closed(59 * 60) }).raise.length, 0);
    assert.strictEqual(P({ total: 50, latest: closed(61 * 60) }).raise.length, 1);
  });
  it('raises again at once after an alert ASIX closed itself', () => {
    assert.strictEqual(P({ total: 50, latest: { status: 'closed', closed_by: 'asix', age_s: 10 } }).raise.length, 1);
  });
  it('raises nothing during the start-up grace, but still closes', () => {
    assert.strictEqual(P({ total: 50 }, cfg, { raiseAllowed: false }).raise.length, 0);
    assert.strictEqual(P({ total: 0, active: [{ id: 'a1' }] }, cfg, { raiseAllowed: false }).close.length, 1);
  });
  it('a count that is not a number raises nothing and closes nothing', () => {
    assert.deepStrictEqual(P({ total: null, active: [{ id: 'a1' }] }), { raise: [], close: [{ alert_id: 'a1', reason: 'The number of unparsed events is back below the limit.' }] });
  });
});

describe('raiseText', () => {
  it('names the count, the window, the limit and the reasons, worst first', () => {
    const t = pw.raiseText({ total: 12, window_min: 15, threshold: 10, by_reason: { PARSE_FAILED: 2, PARSE_TIMEOUT: 10, PARSE_WORKER_CRASH: 0 } });
    assert.strictEqual(t.title, 'Events stored unparsed: 12 in 15 minutes');
    assert.match(t.summary, /limit 10\), PARSE_TIMEOUT: 10, PARSE_FAILED: 2\./); assert.ok(!/PARSE_WORKER_CRASH/.test(t.summary));
  });
});

describe('countRecent (store replaced)', () => {
  const NOW = Date.parse('2026-10-19T22:48:45Z');
  const mk = (rows) => { const asked = []; return { asked, store: { search: async (t, plan) => { asked.push({ t, plan }); return { rows }; } } }; };
  const row = (minAgo, reason, fmt = 'pg') => { const d = new Date(NOW - minAgo * 60000); return { _insert_time: fmt === 'pg' ? d.toISOString().slice(0, 19).replace('T', ' ') : d.toISOString(), _parse_error: reason }; };

  it('counts what was RECEIVED in the window, whatever time the events say, in both time formats', async () => {
    const { store, asked } = mk([row(1, 'PARSE_TIMEOUT'), row(5, 'PARSE_TIMEOUT', 'iso'), row(14, 'PARSE_FAILED'), row(16, 'PARSE_TIMEOUT'), row(300, 'PARSE_TIMEOUT')]);
    const c = await pw.countRecent(store, 't1', cfg, NOW);
    assert.strictEqual(c.total, 3); assert.deepStrictEqual(c.by_reason, { PARSE_TIMEOUT: 2, PARSE_FAILED: 1, PARSE_WORKER_CRASH: 0, PARSE_QUARANTINED: 0 }); assert.strictEqual(c.at_least, false);
    // the query: newest received first, bounded on event time by the window plus 12 hours (every zone behind UTC), no time filter in the text
    const plan = asked[0].plan;
    assert.strictEqual(plan.from, new Date(NOW - 15 * 60000 - 12 * 3600000).toISOString());
    assert.deepStrictEqual(plan.stages.map((x) => x.op), ['filter', 'fields', 'sort', 'limit']); assert.strictEqual(plan.limit, 100);
  });
  it('reads at most the limit (at least 100, at most 5000) and says "at least" when every row read is inside the window', async () => {
    const rows = Array.from({ length: 100 }, (_, i) => row(i % 10, 'PARSE_TIMEOUT'));
    const { store, asked } = mk(rows);
    const c = await pw.countRecent(store, 't1', { threshold: 5, windowMin: 15 }, NOW);
    assert.strictEqual(c.total, 100); assert.strictEqual(c.at_least, true);
    assert.strictEqual(asked[0].plan.limit, 100);
    await pw.countRecent(mk([]).store, 't1', { threshold: 3000, windowMin: 15 }, NOW);
    const m = mk([]); await pw.countRecent(m.store, 't1', { threshold: 3000, windowMin: 15 }, NOW); assert.strictEqual(m.asked[0].plan.limit, 3000);
  });
  it('a limit above 5000 cannot be read newest-first, so it counts by event time as before', async () => {
    const m = mk([{ _parse_error: 'PARSE_TIMEOUT', n: 7000 }]);
    const c = await pw.countRecent(m.store, 't1', { threshold: 6000, windowMin: 15 }, NOW);
    assert.strictEqual(c.total, 7000); assert.strictEqual(c.at_least, false); assert.strictEqual(m.asked[0].plan.stages.some((x) => x.op === 'comp'), true);
  });
  it('an empty answer is zero with every known reason listed', async () => {
    const c = await pw.countRecent(mk([]).store, 't1', cfg, NOW);
    assert.deepStrictEqual(c, { total: 0, by_reason: { PARSE_TIMEOUT: 0, PARSE_WORKER_CRASH: 0, PARSE_FAILED: 0, PARSE_QUARANTINED: 0 }, at_least: false });
  });
});

describe('runTenant (database and store replaced)', () => {
  const dbPath = require.resolve('../src/db');
  const saved = require.cache[dbPath].exports;
  let calls, rows, asked;
  const NOW = Date.parse('2026-10-19T12:00:00Z');
  const store = { search: async (t, plan) => { asked.push({ t, plan }); return { rows: Array.from({ length: 12 }, (_, i) => ({ _insert_time: new Date(NOW - (i + 1) * 30000).toISOString(), _parse_error: 'PARSE_TIMEOUT' })) }; } };
  before(() => {
    require.cache[dbPath].exports = { ...saved, withTenant: async (t, fn) => fn({ query: async (sql, args) => {
      calls.push({ sql, args });
      if (/status IN \('open','acknowledged'\)/.test(sql)) return { rows: rows.active };
      if (/ORDER BY created_at DESC/.test(sql)) return { rows: rows.latest };
      return { rows: [] };
    } }) };
    delete require.cache[require.resolve('../src/ingestion/parse-watch')];
  });
  after(() => { require.cache[dbPath].exports = saved; delete require.cache[require.resolve('../src/ingestion/parse-watch')]; });

  it('counts in the window through the store, then raises', async () => {
    calls = []; asked = []; rows = { active: [], latest: [] };
    const r = await require('../src/ingestion/parse-watch').runTenant('t1', { cfg, store, sev: 'high', now: NOW });
    assert.deepStrictEqual(r, { raised: 1, closed: 0 });
    assert.strictEqual(asked.length, 1); assert.strictEqual(asked[0].t, 't1');
    const ins = calls.find((c) => /INSERT INTO alerts/.test(c.sql));
    assert.strictEqual(ins.args[1], 'Events stored unparsed'); assert.strictEqual(ins.args[2], 'high'); assert.strictEqual(ins.args[5], 'parser:unparsed'); assert.strictEqual(ins.args[6], 12);
    assert.strictEqual(JSON.parse(ins.args[7]).window_min, 15);
  });
  it('does not touch the store when off, and closes the open alert marked as closed by ASIX', async () => {
    calls = []; asked = []; rows = { active: [{ id: 'old' }], latest: [] };
    const r = await require('../src/ingestion/parse-watch').runTenant('t1', { cfg: { threshold: 0, windowMin: 15 }, store });
    assert.deepStrictEqual(r, { raised: 0, closed: 1 }); assert.strictEqual(asked.length, 0);
    const up = calls.find((c) => /SET status = 'closed'/.test(c.sql)); assert.match(up.sql, /closed_by/); assert.strictEqual(up.args[0], 'old');
  });
  it('lets a failing store count throw (the watchdog logs it) and writes nothing', async () => {
    calls = []; rows = { active: [], latest: [] };
    await assert.rejects(require('../src/ingestion/parse-watch').runTenant('t1', { cfg, store: { search: async () => { throw new Error('down'); } } }), /down/);
    assert.strictEqual(calls.length, 0);
  });
});

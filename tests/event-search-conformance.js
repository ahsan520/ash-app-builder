'use strict';
// The XQL search contract as a test suite: every event-store adapter that implements search() must pass it
// unchanged, so one query means one thing on every engine.
//
//   const { runSearchConformance } = require('./event-search-conformance');
//   runSearchConformance('my-adapter', async () => ({ store, tenants: [uuidA, uuidB], cleanup: async () => {} }));
//
// Two parts: (1) hand-written checks of each rule of the language (the rules are listed in
// src/search/xql-plan.js), (2) a large frozen set: every query in tests/fixtures/xql-golden.json run over
// tests/fixtures/xql-dataset.js, compared with tests/fixtures/xql-search-expected.json (made on real PostgreSQL,
// see tests/fixtures/gen-xql-search-expected.js). Not named *.test.js: it is a library.

const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const { parse } = require('../src/search/xql');
const { buildDataset } = require('./fixtures/xql-dataset');

// time windows every fixture query is run with: none, and one whose edges sit exactly on events
// (from is inclusive: event 7 is at 01:07:00; to is inclusive: event 9 is at 01:30:00)
const WINDOWS = [{}, { from: '2026-10-01T01:07:00.000Z', to: '2026-10-01T01:30:00.000Z' }];

const canon = (v) => JSON.stringify(v, (k, x) => (x && typeof x === 'object' && !Array.isArray(x) && !(x instanceof Date) ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : 1))) : x));
const isTotalOrder = (plan) => {
  const sorts = plan.stages.filter((s) => s.op === 'sort');
  if (plan.mode === 'comp') return false;
  return !sorts.length || sorts[sorts.length - 1].keys.every((k) => k.name === '_time' || k.name === '_insert_time');
};

// A result in a form that does not depend on the engine: event ids become n<k>, numbers are rounded, row order is
// kept only where the query fixes it completely (ties have no defined order).
function normalizeResult(plan, res, nOf) {
  const aggAliases = plan.mode === 'comp' ? new Set(plan.stages.find((s) => s.op === 'comp').aggs.map((a) => a.alias)) : new Set();
  const cell = (k, v) => {
    if (v instanceof Date) return v.toISOString();
    if (typeof v === 'string' && nOf.has(v)) return 'n' + nOf.get(v);
    if (aggAliases.has(k) && v !== null && v !== undefined) return Math.round(Number(v) * 1e6) / 1e6;
    return v === undefined ? null : v;
  };
  let rows = res.rows.map((r) => {
    if (plan.mode === 'raw') return 'n' + nOf.get(r._id);
    return canon(Object.fromEntries(Object.entries(r).map(([k, v]) => [k, cell(k, v)])));
  });
  if (!isTotalOrder(plan)) rows = rows.sort();
  return { truncated: res.truncated, rows };
}

function runSearchConformance(label, setup) {
  describe(`event search conformance: ${label}`, () => {
    let store; let A; let B; let cleanup; let ds;
    const run = async (q, o = {}) => store.search(A, parse(q, { limit: 50, ...o }));
    const ns = async (q, o) => { const r = await run(q, o); return r.rows.map((x) => ds.nOf.get(x._id)); };
    const set = async (q, o) => (await ns(q, o)).sort((a, b) => a - b);

    before(async () => {
      ({ store, tenants: [A, B], cleanup } = await setup());
      ds = buildDataset();
      await store.insertBatch(A, ds.events);
      await store.insertBatch(B, [ds.other]);
    });
    after(async () => { if (cleanup) await cleanup(); });

    it('only ever sees the tenant it is asked about', async () => {
      assert.deepStrictEqual(await set('filter host = "web01"'), [1, 2, 8, 10]);
      assert.strictEqual((await store.search(B, parse('dataset = syslog', { limit: 50 }))).rows.length, 1);
      assert.deepStrictEqual((await store.search(A, parse('comp count() as c'))).rows.map((r) => Number(r.c)), [10]);
    });

    it('raw rows carry every column and the parsed object', async () => {
      const r = await run('filter _raw contains "Failed password"');
      assert.strictEqual(r.mode, 'raw'); assert.strictEqual(r.columns, null); assert.strictEqual(r.rows.length, 1);
      const [row] = r.rows, spec = ds.events[0];
      assert.strictEqual(row._id, spec.id); assert.strictEqual(row.source_type, 'syslog'); assert.strictEqual(row.collector_id, 'c1');
      assert.strictEqual(row._raw, spec.raw); assert.deepStrictEqual(row.parsed, spec.parsed);
      assert.ok(row._time instanceof Date); assert.strictEqual(row._time.toISOString(), spec.event_time);
    });

    it('_time is the event time, or the received time when the source gave none; text looks like a timestamp', async () => {
      let r = await run('filter _raw contains "Failed password" | fields _time, _insert_time');
      assert.deepStrictEqual(r.rows, [{ _time: '2026-10-01 00:07:00', _insert_time: '2026-10-01 00:10:00' }]);
      r = await run('filter _raw = "no event time" | fields _time as t');
      assert.deepStrictEqual(r.rows, [{ t: '2026-10-01 01:30:00' }]);
    });

    it('time bounds are inclusive on both ends and use the event time', async () => {
      assert.deepStrictEqual(await set('dataset = syslog', { from: '2026-10-01T01:07:00.000Z', to: '2026-10-01T01:30:00.000Z' }), [8, 9]);
      assert.deepStrictEqual(await set('dataset in (syslog, router, mac)', { from: '2026-10-01T01:07:00.000Z', to: '2026-10-01T01:30:00.000Z' }), [7, 8, 9]);
    });

    it('eq is null for a missing field, so not/!= differ; ne treats missing as different', async () => {
      assert.deepStrictEqual(await set('filter not host = "web01"'), [3, 5, 6, 7, 9]);   // event 4 has no host: dropped
      assert.deepStrictEqual(await set('filter host != "web01"'), [3, 4, 5, 6, 7, 9]);   // event 4 is "different"
      assert.deepStrictEqual(await set('filter host = null'), [4]);
      assert.deepStrictEqual(await set('filter host != null'), [1, 2, 3, 5, 6, 7, 8, 9, 10]);
    });

    it('contains, in and ~= ignore case; = does not', async () => {
      assert.deepStrictEqual(await set('filter _raw contains "upper AND lower"'), [6]);
      assert.deepStrictEqual(await set('filter host ~= "^mbp$"'), [5, 6]);
      assert.deepStrictEqual(await set('filter host = "mbp"'), [5]);
      assert.deepStrictEqual(await set('filter app_name in ("SSHD", "sudo")'), [3]);
      assert.deepStrictEqual(await set('filter host not contains "WEB"'), [4, 5, 6, 7]);   // missing counts as not containing
    });

    it('contains treats % _ and backslash as plain characters', async () => {
      assert.deepStrictEqual(await set('filter _raw contains "100%_done"'), [7]);
      assert.deepStrictEqual(await set('filter _raw contains "100_" '), []);
      assert.deepStrictEqual(await set('filter _raw contains "\\\\ back"'), [7]);
    });

    it('numeric comparison only matches values that look like numbers (numbers or numeric text)', async () => {
      assert.deepStrictEqual(await set('filter bytes > 10'), [1, 2, 3, 8]);        // 100, "2500", 12.5, 1000; not "abc", "7", 5, 0, -3
      assert.deepStrictEqual(await set('filter bytes <= 0'), [6, 7]);             // -3, 0
      assert.deepStrictEqual(await set('filter bytes >= 12.5 and bytes < 1000'), [1, 3]);
    });

    it('paths walk objects and arrays; dots in a path are always separators', async () => {
      assert.deepStrictEqual(await set('filter xdm.source.ipv4 = "203.0.113.9"'), [1]);
      assert.deepStrictEqual(await set('filter nested.list.1.k = "v1"'), [6]);
      assert.deepStrictEqual(await set('filter ok = "true"'), [5]);
      assert.deepStrictEqual(await set('filter none != null'), []);               // a JSON null is the same as missing
    });

    it('count, count(f), count_distinct and numeric aggregates', async () => {
      let r = (await run('comp count() as c, count(host) as h, count_distinct(host) as d')).rows[0];
      assert.deepStrictEqual([Number(r.c), Number(r.h), Number(r.d)], [10, 9, 6]);   // mbp and MBP are different values
      r = (await run('comp sum(bytes) as s, min(bytes) as lo, max(bytes) as hi, avg(bytes) as a')).rows[0];
      // numeric values: 100, 2500, 12.5, -3, 0, 1000, 7, 5  ("abc" and the missing ones are ignored)
      assert.ok(Math.abs(Number(r.s) - 3621.5) < 1e-9); assert.strictEqual(Number(r.lo), -3); assert.strictEqual(Number(r.hi), 2500);
      assert.ok(Math.abs(Number(r.a) - 3621.5 / 8) < 1e-9);
      r = (await run('filter host = "mbp" | comp sum(bytes) as s, avg(bytes) as a')).rows[0];
      assert.deepStrictEqual([r.s, r.a], [null, null]);                              // no numeric value at all
    });

    it('a missing value is its own group, and sort puts missing values last either way', async () => {
      const q = (dir) => run(`comp max(bytes) as m by host | sort ${dir} m`);
      for (const dir of ['desc', 'asc']) {
        const rows = (await q(dir)).rows;
        assert.strictEqual(rows.length, 7);                                          // web01, web02, web03, mbp, MBP, rtr, (missing)
        const nulls = rows.filter((r) => r.m === null);
        assert.strictEqual(nulls.length, 2);                                         // mbp (only "abc") and the missing host
        assert.ok(rows.slice(-2).every((r) => r.m === null), `nulls last (${dir})`);
        const nums = rows.slice(0, 5).map((r) => Number(r.m));
        assert.deepStrictEqual(nums, dir === 'desc' ? [2500, 12.5, 7, 0, -3] : [-3, 0, 7, 12.5, 2500]);
      }
      assert.ok((await run('comp count() as c by host')).rows.some((r) => r.host === null));
    });

    it('sorting by an event field that is not selected, and by _time', async () => {
      assert.deepStrictEqual(await ns('dataset = syslog | sort asc _time'), [1, 2, 3, 4, 8, 9, 10]);
      assert.deepStrictEqual(await ns('dataset = syslog | sort desc _insert_time'), [10, 9, 8, 4, 3, 2, 1]);
      assert.deepStrictEqual((await run('dataset = syslog | fields host | sort asc _time | limit 3')).rows, [{ host: 'web01' }, { host: 'web01' }, { host: 'web02' }]);
    });

    it('limit trims the result and reports truncation', async () => {
      let r = await run('dataset = syslog | limit 2');
      assert.strictEqual(r.rows.length, 2); assert.strictEqual(r.truncated, true);
      r = await run('dataset = syslog | limit 7'); assert.strictEqual(r.rows.length, 7); assert.strictEqual(r.truncated, false);
      r = await run('dataset = syslog | limit 8'); assert.strictEqual(r.truncated, false);
    });

    it('field names that are also JavaScript object properties are plain event fields', async () => {
      for (const f of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
        assert.deepStrictEqual(await set(`filter ${f} = "x"`), [], f);
        assert.deepStrictEqual(await set(`filter ${f} = null`), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], f);
        assert.deepStrictEqual((await run(`comp count() as c by ${f}`)).rows.map((r) => [r[f], Number(r.c)]), [[null, 10]], f);
      }
    });

    it('hostile text in values is just text', async () => {
      for (const evil of ["'; DROP TABLE events; --", '"', "\\", '%', '\u0001', '${x}', "a' OR '1'='1", '\u65e5\u672c\u8a9e']) {
        const q = 'filter host = ' + JSON.stringify(evil) + ' or _raw contains ' + JSON.stringify(evil);
        let plan; try { plan = parse(q, { limit: 5 }); } catch (e) { continue; }   // some are not valid XQL strings; the parser decides
        const r = await store.search(A, plan);
        assert.ok(Array.isArray(r.rows));
      }
      assert.deepStrictEqual(await set('dataset = syslog'), [1, 2, 3, 4, 8, 9, 10]);   // and the data is still there
    });

    it('rejects a plan that is malformed or unsafe, before touching the engine', async () => {
      const good = parse('filter host = "a"', { limit: 5 });
      const bad = (mut) => { const p = JSON.parse(JSON.stringify(good)); mut(p); return p; };
      const cases = [
        bad((p) => { p.stages[0].expr.field = 'host"; DROP TABLE events; --'; }),
        bad((p) => { p.stages[0].expr.field = 'a b'; }),
        bad((p) => { p.stages[0].expr.t = 'sql'; }),
        bad((p) => { p.stages.push({ op: 'raw', sql: 'select 1' }); }),
        bad((p) => { p.limit = 0; }), bad((p) => { p.limit = 5001; }), bad((p) => { p.limit = 1.5; }),
        bad((p) => { p.v = 2; }), bad((p) => { p.mode = 'sql'; }), bad((p) => { p.from = 'yesterday'; }),
        bad((p) => { p.stages = new Array(13).fill(p.stages[0]); }),
        bad((p) => { p.stages = [{ op: 'fields', items: [{ field: 'host', alias: 'a"b' }] }]; p.mode = 'fields'; }),
        bad((p) => { p.stages = [{ op: 'comp', aggs: [{ fn: 'sum', field: null, alias: 'x' }], by: [] }]; p.mode = 'comp'; }),
        bad((p) => { p.stages = [{ op: 'sort', keys: [{ name: 'host', alias: false, dir: 'asc' }] }, { op: 'comp', aggs: [{ fn: 'count', field: null, alias: 'c' }], by: [] }]; p.mode = 'comp'; }),
        null, 'filter host = "a"', { v: 1 },
      ];
      for (const p of cases) await assert.rejects(store.search(A, p), (e) => e.code === 'INVALID_QUERY', JSON.stringify(p).slice(0, 120));
      let deep = { t: 'eq', field: 'host', value: 'a' };
      for (let i = 0; i < 70; i++) deep = { t: 'not', e: deep };
      await assert.rejects(store.search(A, bad((p) => { p.stages[0].expr = deep; })), (e) => e.code === 'INVALID_QUERY');
      await assert.rejects(store.search('not-a-uuid', good), (e) => e.code === 'INVALID_TENANT');
    });

    it('every query in the frozen set returns exactly what PostgreSQL returned', async () => {
      const G = require('./fixtures/xql-search-expected.json');
      assert.ok(G.cases.length > 100);
      const bad = [];
      for (const c of G.cases) {
        const plan = parse(c.query, { ...WINDOWS[c.window], limit: 50 });
        let got;
        try { got = normalizeResult(plan, await store.search(A, plan), ds.nOf); } catch (e) { got = { error: e.code || e.name }; }
        if (canon(got) !== canon(c.expect)) bad.push(`${JSON.stringify(c.query)} window ${c.window}\n   got      ${canon(got).slice(0, 300)}\n   expected ${canon(c.expect).slice(0, 300)}`);
      }
      assert.strictEqual(bad.length, 0, `${bad.length} of ${G.cases.length} differ:\n` + bad.slice(0, 8).join('\n'));
    });
  });
}

module.exports = { runSearchConformance, normalizeResult, WINDOWS };

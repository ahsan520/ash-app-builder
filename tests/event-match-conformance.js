'use strict';
// The rule-match contract as a test suite: every event-store adapter that implements matchGroups() must pass it
// unchanged, so one detection rule means one thing on every engine (spec: src/search/match-spec.js).
//
//   const { runMatchConformance } = require('./event-match-conformance');
//   runMatchConformance('my-adapter', async () => ({ store, tenants: [uuidA, uuidB], cleanup: async () => {} }));
//
// Runs over tests/fixtures/xql-dataset.js (10 events for tenant A, event time = 3 minutes before received time,
// except event 9 which has none) plus two extra events in tenant B. Not named *.test.js: it is a library.

const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { buildDataset, iso } = require('./fixtures/xql-dataset');
const { SOURCE_IP_PATTERN, buildRuleMatch } = require('../src/detection/rule-query');

const T = (m) => iso(m);                       // minutes after T0, as an ISO time
const eq = (field, value) => ({ t: 'eq', field, value });
const none = { by: 'none' };
const byField = (field) => ({ by: 'field', field });

function runMatchConformance(label, setup) {
  describe(`rule match conformance: ${label}`, () => {
    let store; let A; let B; let cleanup; let ds; let extra;
    const n = (id) => ds.nOf.get(id);
    // event times in the dataset (minutes): n1=7 n2=17 n3=27 n4=37 n5=47 n6=57 n7=67 n8=77 n9=90 (no event time: received) n10=97
    const run = (spec, tenant = A) => store.matchGroups(tenant, { after: T(0), group: none, ...spec });
    const byKey = (rows) => Object.fromEntries(rows.map((r) => [r.key, r.n]));

    before(async () => {
      ({ store, tenants: [A, B], cleanup } = await setup());
      ds = buildDataset();
      await store.insertBatch(A, ds.events);
      extra = {
        id: crypto.randomUUID(), received_at: T(120), event_time: T(118), source_type: 'weird', collector_id: null,
        raw: 'odd names', parsed: { 'user-agent': 'curl/8', '2fa': 'yes', dataset: 'parsed-dataset', _time: 'parsed-time' },
      };
      await store.insertBatch(B, [ds.other, extra]);
    });
    after(async () => { if (cleanup) await cleanup(); });

    it('one group for everything: counts, first and last event time, newest samples first', async () => {
      const [g, ...rest] = await run({});
      assert.strictEqual(rest.length, 0);
      assert.strictEqual(g.key, 'all');
      assert.strictEqual(g.n, 10);
      assert.strictEqual(Date.parse(g.first_at), Date.parse(T(7)));
      assert.strictEqual(Date.parse(g.last_at), Date.parse(T(97)));
      assert.deepStrictEqual(g.sample_ids.map(n), [10, 9, 8, 7, 6], 'five newest by event time (event 9 has none: its received time)');
      assert.strictEqual(g.sample_raw, 'dup host');
    });

    it('the time frame starts strictly after `after`, on event time (received time when there is none)', async () => {
      assert.strictEqual((await run({ after: T(7) }))[0].n, 9, 'event 1 is exactly at the bound and is left out');
      assert.strictEqual((await run({ after: T(6) }))[0].n, 10);
      const r = await run({ after: T(89) });
      assert.strictEqual(r[0].n, 2, 'event 9 counts by its received time (minute 90)');
      assert.deepStrictEqual(await run({ after: T(97) }), []);
    });

    it('groups by a field: a missing value is the group "unknown"; threshold and limit', async () => {
      const rows = await run({ group: byField('@host') });
      assert.deepStrictEqual(byKey(rows), { web01: 4, web02: 1, web03: 1, mbp: 1, MBP: 1, rtr: 1, unknown: 1 });
      assert.strictEqual(rows[0].key, 'web01', 'biggest group first');
      assert.deepStrictEqual(rows[0].sample_ids.map(n), [10, 8, 2, 1]);
      assert.deepStrictEqual(Object.keys(byKey(await run({ group: byField('@host'), threshold: 2 }))), ['web01']);
      assert.strictEqual((await run({ group: byField('@host'), limit: 2 })).length, 2);
      assert.strictEqual((await run({ group: byField('@host'), limit: 1 }))[0].key, 'web01');
      assert.deepStrictEqual(await run({ group: byField('@host'), threshold: 5 }), []);
      assert.deepStrictEqual(byKey(await run({ group: byField('@xdm.source.ipv4') })), { '203.0.113.9': 1, '10.0.0.5': 1, unknown: 8 });
      assert.deepStrictEqual(byKey(await run({ group: byField('collector_id') })), { c1: 5, c2: 1, c3: 2, c4: 1, unknown: 1 }, 'column fields work without @');
    });

    it('groups by the first capture group of a pattern on raw', async () => {
      const rows = await run({ group: { by: 'capture', pattern: SOURCE_IP_PATTERN } });
      assert.deepStrictEqual(byKey(rows), { '203.0.113.9': 1, unknown: 9 });
      assert.deepStrictEqual(byKey(await run({ group: { by: 'capture', pattern: 'for (\\w+)' } })), { invalid: 1, ash: 1, unknown: 8 }, 'the first match in the text decides');
    });

    it('filters: regex (any case), equality, inequality, contains, and combinations', async () => {
      const c = async (filter) => (await run({ filter }))[0];
      assert.deepStrictEqual((await c({ t: 'regex', field: 'raw', pattern: 'failed' })).sample_ids.map(n).sort((a, b) => a - b), [1, 5]);
      assert.strictEqual((await c({ t: 'and', args: [eq('source_type', 'syslog'), eq('@app_name', 'sshd')] })).n, 3);
      assert.strictEqual((await c({ t: 'ne', field: '@app_name', value: 'sshd' })).n, 7, 'a missing value is "not equal" (events 3-9 without sshd, including those with no app_name)');
      assert.strictEqual((await c({ t: 'contains', field: '@host', value: 'WEB0', neg: false })).n, 6);
      assert.strictEqual((await c({ t: 'contains', field: 'raw', value: '100%_', neg: false })).n, 1, '% and _ are not wildcards');
      assert.strictEqual((await c({ t: 'or', args: [eq('collector_id', 'c4'), eq('collector_id', 'c2')] })).n, 2);
      assert.deepStrictEqual(await run({ filter: eq('@host', 'nobody') }), []);
    });

    it('"@name" is always a parsed path; a bare name keeps its column meaning (so rule fields cannot be confused with columns)', async () => {
      assert.strictEqual((await run({ filter: eq('@user-agent', 'curl/8') }, B))[0].n, 1, 'hyphens are fine');
      assert.strictEqual((await run({ filter: eq('@2fa', 'yes') }, B))[0].n, 1, 'may start with a digit');
      assert.strictEqual((await run({ filter: eq('@dataset', 'parsed-dataset') }, B))[0].n, 1, 'the parsed field called dataset');
      assert.deepStrictEqual(await run({ filter: eq('dataset', 'parsed-dataset') }, B), [], 'the column called dataset is the source type');
      assert.strictEqual((await run({ filter: eq('dataset', 'weird') }, B))[0].n, 1);
      assert.strictEqual((await run({ filter: eq('@_time', 'parsed-time') }, B))[0].n, 1);
    });

    it('runs a real rule definition: an XQL "or" is only one of the rule\'s conditions (AND-ed with the rest)', async () => {
      const now = new Date(Date.parse(T(0)) + 1000 * 60000);               // window 1000 minutes: starts exactly at T0
      const rule = (over) => buildRuleMatch({ window_minutes: 1000, threshold: 1, group_by: 'none', xql: 'xdm.source.ipv4 = "203.0.113.9" or host = "rtr"', ...over }, { now });
      assert.deepStrictEqual((await store.matchGroups(A, rule({})))[0].sample_ids.map(n).sort((a, b) => a - b), [1, 7]);
      const only = await store.matchGroups(A, rule({ filters: [{ field: 'collector_id', op: 'equals', value: 'c4' }] }));
      assert.deepStrictEqual(only[0].sample_ids.map(n), [7], 'event 1 matches the "or" but not the collector filter');
      assert.deepStrictEqual(byKey(await store.matchGroups(A, rule({ group_by: 'source_ip', regex: 'dhcp|Failed' }))), { '203.0.113.9': 1, unknown: 1 });
      assert.deepStrictEqual(await store.matchGroups(A, rule({ threshold: 3 })), []);
    });

    it('only ever sees the tenant it is asked about', async () => {
      assert.strictEqual((await run({}, A))[0].n, 10);
      const b = await run({}, B);
      assert.strictEqual(b[0].n, 2);
      assert.ok(b[0].sample_ids.includes(ds.other.id) && !b[0].sample_ids.some((id) => ds.nOf.has(id) && ds.nOf.get(id) !== 99));
      assert.deepStrictEqual(await run({ filter: eq('@host', 'web02') }, B), []);
    });

    it('rejects specs it cannot run safely, with INVALID_QUERY', async () => {
      const bad = [
        { after: undefined }, { after: 'yesterday' }, { threshold: 0 }, { threshold: 1.5 }, { threshold: 100001 }, { limit: 0 },
        { group: { by: 'sql' } }, { group: { by: 'field', field: 'a b' } }, { group: { by: 'field', field: "x'; DROP TABLE events; --" } },
        { group: { by: 'capture', pattern: '' } }, { group: { by: 'capture', pattern: '\\1(a)' } },
        { filter: { t: 'nope' } }, { filter: eq('@bad;name', 'x') }, { filter: { t: 'regex', field: 'raw', pattern: '(a)\\1' } },
        { filter: { t: 'eq', field: 'raw', value: 5 } },
      ];
      for (const b of bad) await assert.rejects(store.matchGroups(A, { after: T(0), ...b }), (e) => e.code === 'INVALID_QUERY', JSON.stringify(b).slice(0, 100));
      await assert.rejects(store.matchGroups(A, null), (e) => e.code === 'INVALID_QUERY');
      await assert.rejects(store.matchGroups('not-a-uuid', { after: T(0) }), (e) => e.code === 'INVALID_TENANT');
    });
  });
}

module.exports = { runMatchConformance };

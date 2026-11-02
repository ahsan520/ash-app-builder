'use strict';
// E6i: the four built-in rules "Endpoint findings store ..." (docs/endpoints.md, "E6i as built"). Events are made the way the reporter sends them (a JSON array element with
// message, host and fields, through the real ingest lane's jsonEvent), parsed by the REAL default parsing rules, and each rule is run the way the rule runner runs it
// (buildRuleMatch + the event store's matchGroups, here the in-memory store). NOT covered: PostgreSQL and ClickHouse (the same plan expressions the conformance suites cover),
// a real indexer VM sending real reports.
const { describe, it } = require('node:test');
const assert = require('assert');
const { compile, apply } = require('../src/ingestion/parsing-rules');
const { jsonEvent } = require('../src/ingest/http-ingest');
const { MemoryEventStore } = require('../src/events/memory-store');
const { BUILTIN_RULES } = require('../src/detection/rule-runner');
const { normalizeDefinition, buildRuleMatch } = require('../src/detection/rule-query');

const defaults = compile(require('../src/ingestion/default-parsing-rules'));
const TENANT = '11111111-1111-4111-8111-111111111111';
const NOW = new Date('2026-11-01T12:00:00.000Z');
const KEYS = ['indexer-disk-filling', 'indexer-disk-nearly-full', 'indexer-writes-refused', 'indexer-unhealthy'];
const rule = (k) => BUILTIN_RULES.find((r) => r.key === k);

let seq = 0;
// a report: pct = the disk number (null = not measured), status, blocked (null = not known)
function report({ pct = 50, status = 'green', blocked = 0, host = 'idx1', minsAgo = 1, sourceType = 'indexer-health', extra = {} } = {}) {
  const f = { disk_path: '/var/lib/wazuh-indexer', cluster_status: status, ...(pct === null ? {} : { disk_used_pct: pct, disk_free_gb: 20.5, disk_total_gb: 100 }), ...(blocked === null ? {} : { write_blocked_indices: blocked }), ...extra };
  const at = new Date(NOW - minsAgo * 60000).toISOString();
  const x = jsonEvent({ message: `Findings indexer ${host}: test`, host, fields: f, time: at }, 'indexer-vm');
  const out = apply([defaults.rules], { source_type: sourceType, raw: x.raw, time: x.time, parsed: x.parsed });
  seq += 1;
  return { id: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`, source_type: sourceType, collector_id: 'indexer-vm', received_at: at, event_time: at, raw: x.raw, parsed: out.parsed };
}
async function run(key, events) {
  const r = rule(key); const store = new MemoryEventStore();
  if (events.length) await store.insertBatch(TENANT, events);
  const rows = await store.matchGroups(TENANT, buildRuleMatch(r.definition, { now: NOW }));
  const th = r.definition.threshold;
  return Object.fromEntries(rows.filter((g) => g.n >= th).map((g) => [g.key, g.n]));   // what the runner raises: groups at or over the threshold
}
const fired = async (events) => { const o = {}; for (const k of KEYS) { const r = await run(k, events); if (Object.keys(r).length) o[k] = r; } return o; };

describe('the four rules as shipped', () => {
  it('exist once each, valid, in the endpoint category, grouped by host, on source type indexer-health, real time', () => {
    for (const k of KEYS) {
      const r = rule(k); assert.ok(r, k); const n = normalizeDefinition(r.definition); assert.ok(!n.error, k + ': ' + JSON.stringify(n));
      assert.deepStrictEqual([r.kind, r.category, r.definition.source_type, r.definition.group_by, r.definition.mode, r.definition.suppression.enabled], ['bioc', 'Endpoint Security', 'indexer-health', 'host', 'realtime', true], k);
      assert.strictEqual(BUILTIN_RULES.filter((b) => b.key === k).length, 1, k);
    }
    assert.deepStrictEqual(KEYS.map((k) => rule(k).severity), ['medium', 'high', 'critical', 'high']);
  });
  it('the names and descriptions do not name the open source product behind the indexer', () => {
    for (const k of KEYS) assert.ok(!/wazuh|ossec|opensearch/i.test(rule(k).name + ' ' + rule(k).description), k);
  });
  it('the unhealthy rule needs two reports; the three disk rules need one', () => {
    assert.deepStrictEqual(KEYS.map((k) => rule(k).definition.threshold), [1, 1, 1, 2]);
  });
});

describe('the disk bands', () => {
  it('the boundaries: 79.9 nothing, 80 filling, 89.9 filling, 90 nearly full, 100 nearly full; never two disk bands for one number', async () => {
    assert.deepStrictEqual(await fired([report({ pct: 79.9 })]), {});
    assert.deepStrictEqual(await fired([report({ pct: 80 })]), { 'indexer-disk-filling': { idx1: 1 } });
    assert.deepStrictEqual(await fired([report({ pct: 89.9 })]), { 'indexer-disk-filling': { idx1: 1 } });
    assert.deepStrictEqual(await fired([report({ pct: 90 })]), { 'indexer-disk-nearly-full': { idx1: 1 } });
    assert.deepStrictEqual(await fired([report({ pct: 100 })]), { 'indexer-disk-nearly-full': { idx1: 1 } });
  });
  it('a report with no disk number (not measured) fires no disk rule', async () => {
    assert.deepStrictEqual(await fired([report({ pct: null })]), {});
  });
  it('two machines are two groups; a quiet machine does not hide a full one', async () => {
    assert.deepStrictEqual(await run('indexer-disk-nearly-full', [report({ pct: 93, host: 'idx1' }), report({ pct: 40, host: 'idx2' }), report({ pct: 95, host: 'idx3' })]), { idx1: 1, idx3: 1 });
  });
  it('only reports from the last 15 minutes count, and only source type indexer-health', async () => {
    assert.deepStrictEqual(await run('indexer-disk-nearly-full', [report({ pct: 95, minsAgo: 16 })]), {});
    assert.deepStrictEqual(await run('indexer-disk-nearly-full', [report({ pct: 95, sourceType: 'syslog' })]), {});
    assert.deepStrictEqual(await run('indexer-disk-nearly-full', [report({ pct: 95, minsAgo: 14 })]), { idx1: 1 });
  });
  it('a disk number that arrives as numeric text still counts as that number; text that is not a number fires nothing', async () => {
    assert.deepStrictEqual(await fired([report({ pct: '95' })]), { 'indexer-disk-nearly-full': { idx1: 1 } });
    assert.deepStrictEqual(await fired([report({ pct: 'full' })]), {});
  });
});

describe('writes refused', () => {
  it('fires on one or more blocked indices, not on zero, not when unknown', async () => {
    assert.deepStrictEqual(await run('indexer-writes-refused', [report({ blocked: 1 })]), { idx1: 1 });
    assert.deepStrictEqual(await run('indexer-writes-refused', [report({ blocked: 7, host: 'idx2' })]), { idx2: 1 });
    assert.deepStrictEqual(await run('indexer-writes-refused', [report({ blocked: 0 })]), {});
    assert.deepStrictEqual(await run('indexer-writes-refused', [report({ blocked: null })]), {});
  });
  it('at 96% with blocked indices both the disk rule and this one fire: two different facts, two alerts', async () => {
    assert.deepStrictEqual(await fired([report({ pct: 96, blocked: 2 })]), { 'indexer-disk-nearly-full': { idx1: 1 }, 'indexer-writes-refused': { idx1: 1 } });
  });
});

describe('unhealthy', () => {
  it('red or unreachable, twice within 15 minutes, fires; once does not (a restart of a minute or two)', async () => {
    assert.deepStrictEqual(await run('indexer-unhealthy', [report({ status: 'red' })]), {});
    assert.deepStrictEqual(await run('indexer-unhealthy', [report({ status: 'red' }), report({ status: 'red', minsAgo: 6 })]), { idx1: 2 });
    assert.deepStrictEqual(await run('indexer-unhealthy', [report({ status: 'unreachable' }), report({ status: 'unreachable', minsAgo: 6 })]), { idx1: 2 });
    assert.deepStrictEqual(await run('indexer-unhealthy', [report({ status: 'red' }), report({ status: 'unreachable', minsAgo: 6 })]), { idx1: 2 });
  });
  it('green, yellow and unknown never fire it; two reports on two machines are not two on one', async () => {
    for (const s of ['green', 'yellow', 'unknown']) assert.deepStrictEqual(await run('indexer-unhealthy', [report({ status: s }), report({ status: s, minsAgo: 6 })]), {}, s);
    assert.deepStrictEqual(await run('indexer-unhealthy', [report({ status: 'red', host: 'a' }), report({ status: 'red', host: 'b', minsAgo: 6 })]), {});
  });
  it('a healthy report between two bad ones does not hide them (it counts bad reports in the window)', async () => {
    assert.deepStrictEqual(await run('indexer-unhealthy', [report({ status: 'red', minsAgo: 12 }), report({ status: 'green', minsAgo: 6 }), report({ status: 'red', minsAgo: 1 })]), { idx1: 2 });
  });
});

describe('a normal report fires nothing, and the other endpoint rules ignore these reports', () => {
  it('50% used, green, nothing blocked', async () => { assert.deepStrictEqual(await fired([report()]), {}); });
  it('the other built-in rules do not fire on a worst-case report', async () => {
    const bad = report({ pct: 99, status: 'red', blocked: 3 });
    for (const r of BUILTIN_RULES.filter((b) => !KEYS.includes(b.key))) {
      const store = new MemoryEventStore(); await store.insertBatch(TENANT, [bad, report({ pct: 99, status: 'red', blocked: 3, minsAgo: 5 })]);
      const rows = await store.matchGroups(TENANT, buildRuleMatch(r.definition, { now: NOW }));
      assert.deepStrictEqual(rows.filter((g) => g.n >= r.definition.threshold), [], r.key);
    }
  });
});

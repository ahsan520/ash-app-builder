'use strict';
// E6k: the daily vulnerability findings summary (src/endpoints/findings-summary.js, docs/endpoints.md "E6k as built").
// The indexer is the stand-in over real HTTPS (tests/fixtures/fake-wazuh-indexer.js, written from the documented shape, NOT a real indexer), the event store is the in-memory one,
// the registry row is a stub (the real registry has its own tests). Checks: when a summary is due, what is written, that it is written once a day, what happens when the
// indexer fails, and that the built-in rule reads the event the way the rule runner does.
process.env.ASIX_WAZUH_INDEXER_TIMEOUT_MS = '800';
process.env.ASIX_WAZUH_ALLOW_LOOPBACK = 'true';
const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('assert');
const fake = require('./fixtures/fake-wazuh-indexer');
const ix = require('../src/endpoints/wazuh-indexer');
const fs = require('../src/endpoints/findings-summary');
const db = require('../src/db');
const { makeEnvelope } = require('../src/events/envelope');
const { MemoryEventStore } = require('../src/events/memory-store');
const { BUILTIN_RULES } = require('../src/detection/rule-runner');
const { normalizeDefinition, buildRuleMatch } = require('../src/detection/rule-query');

const T = '22222222-2222-4222-8222-222222222222';
const at = (iso) => Date.parse(iso);
const ON = { enabled: true, hour: 3 };

describe('config and plan', () => {
  it('is on by default at 03 UTC; the hour must be 0 to 23; ASIX_VULN_SUMMARY=false turns it off', () => {
    assert.deepStrictEqual(fs.config({}), { enabled: true, hour: 3 });
    assert.strictEqual(fs.config({ ASIX_VULN_SUMMARY_HOUR: '0' }).hour, 0);
    assert.strictEqual(fs.config({ ASIX_VULN_SUMMARY_HOUR: '23' }).hour, 23);
    for (const bad of ['24', '-1', 'x', '1.5']) assert.strictEqual(fs.config({ ASIX_VULN_SUMMARY_HOUR: bad }).hour, 3, bad);
    assert.strictEqual(fs.config({ ASIX_VULN_SUMMARY: 'false' }).enabled, false);
    assert.strictEqual(fs.config({ ASIX_VULN_SUMMARY: 'FALSE' }).enabled, false);
  });
  it('is due only with an indexer, from the chosen hour, when today has no summary yet', () => {
    const now = at('2026-11-03T05:00:00Z');
    assert.deepStrictEqual(fs.plan({ registered: true, haveDay: '2026-11-02' }, ON, now), { record: true, reason: 'due' });
    assert.strictEqual(fs.plan({ registered: true, haveDay: null }, ON, now).record, true);
    assert.strictEqual(fs.plan({ registered: false, haveDay: null }, ON, now).record, false);
    assert.strictEqual(fs.plan({ registered: true, haveDay: '2026-11-03' }, ON, now).record, false);
    assert.strictEqual(fs.plan({ registered: true, haveDay: null }, ON, at('2026-11-03T02:59:59Z')).record, false);
    assert.strictEqual(fs.plan({ registered: true, haveDay: null }, ON, at('2026-11-03T03:00:00Z')).record, true);
    assert.strictEqual(fs.plan({ registered: true, haveDay: null }, { enabled: false, hour: 3 }, now).record, false);
  });
  it('the "new since" time is the previous summary, kept between 1 hour and 8 days back', () => {
    const now = at('2026-11-03T05:00:00Z');
    assert.strictEqual(fs.sinceFor(at('2026-11-02T05:00:00Z'), now), '2026-11-02T05:00:00Z');
    assert.strictEqual(fs.sinceFor(NaN, now), '2026-11-02T05:00:00Z', 'no previous summary: 24 hours');
    assert.strictEqual(fs.sinceFor(at('2026-10-01T00:00:00Z'), now), '2026-10-26T05:00:00Z', 'a very old one: 8 days');
    assert.strictEqual(fs.sinceFor(at('2026-11-03T04:50:00Z'), now), '2026-11-03T04:00:00Z', 'a very recent one: 1 hour');
  });
});

describe('the event', () => {
  const S = { total: 100, machines: 4, distinct_cves: 60, severity: { critical: 5, high: 20, medium: 50, low: 25, unknown: 0 } };
  const N = { total: 7, critical: 2, high: 3, medium: 1, low: 1, unknown: 0 };
  it('carries the totals, the new counts and the change against the previous summary, and passes the envelope check', () => {
    const e = fs.buildEvent(T, S, N, { findings_total: 90, critical: 6 }, '2026-11-02T03:00:00Z', at('2026-11-03T03:05:00Z'));
    makeEnvelope(e);
    assert.strictEqual(e.source_type, 'vuln-summary');
    const p = e.parsed;
    assert.deepStrictEqual([p.summary_day, p.findings_total, p.machines, p.critical, p.high, p.new_total, p.new_critical, p.new_high, p.total_change, p.critical_change], ['2026-11-03', 100, 4, 5, 20, 7, 2, 3, 10, -1]);
    assert.match(e.raw, /2026-11-03: 100 on 4 machines/);
  });
  it('without a previous summary there is no change figure (never a made-up zero)', () => {
    const p = fs.buildEvent(T, S, N, null, '2026-11-02T03:00:00Z', at('2026-11-03T03:05:00Z')).parsed;
    assert.ok(!('total_change' in p) && !('critical_change' in p));
  });
  it('a missing or odd number is 0, never NaN or text', () => {
    const p = fs.buildEvent(T, { total: 'x', severity: {} }, {}, null, '2026-11-02T03:00:00Z', at('2026-11-03T03:05:00Z')).parsed;
    assert.deepStrictEqual([p.findings_total, p.critical, p.new_critical], [0, 0, 0]);
  });
  it('the id is a valid UUID, the same for one tenant and day, different for another day or tenant', () => {
    const a = fs.buildEvent(T, S, N, null, 's', at('2026-11-03T03:05:00Z')), b = fs.buildEvent(T, S, N, null, 's', at('2026-11-03T20:00:00Z'));
    const c = fs.buildEvent(T, S, N, null, 's', at('2026-11-04T03:05:00Z')), d = fs.buildEvent('33333333-3333-4333-8333-333333333333', S, N, null, 's', at('2026-11-03T03:05:00Z'));
    assert.strictEqual(a.id, b.id); assert.notStrictEqual(a.id, c.id); assert.notStrictEqual(a.id, d.id);
    assert.match(a.id, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });
});

describe('the indexer call for "new since" (against the stand-in)', () => {
  let srv;
  before(async () => { srv = await fake.start(); });
  after(async () => { await srv.stop(); });
  const m = () => ({ tenant_id: 'T-' + srv.port, index_url: srv.url, index_user: srv.user, index_password: srv.password, ca_pem: srv.cert, cert_sha256: 'x', index_name: srv.index });
  it('counts the findings first detected at or after the time, by severity', async () => {
    const r = await ix.detectedSince(m(), '2026-10-30T00:00:00Z');
    assert.deepStrictEqual(r, { total: 3, critical: 2, high: 1, medium: 0, low: 0, unknown: 0 });
    const last = srv.state.requests[srv.state.requests.length - 1];
    assert.deepStrictEqual(last.body.query, { bool: { filter: [{ range: { 'vulnerability.detected_at': { gte: '2026-10-30T00:00:00Z' } } }] } });
    assert.strictEqual(last.body.size, 0);
    assert.deepStrictEqual((await ix.detectedSince(m(), '2026-12-01T00:00:00Z')).total, 0);
  });
  it('lists the findings per machine and severity, the biggest first, with the name', async () => {
    const r = await ix.machineSeverities(m());
    assert.deepStrictEqual(r.map((x) => x.agent_id).sort(), ['001', '002']);
    const a = r.find((x) => x.agent_id === '001'), b = r.find((x) => x.agent_id === '002');
    assert.deepStrictEqual([a.name, a.total, a.critical, a.high, a.medium, a.low], ['WIN-DC01', 3, 1, 1, 1, 0]);
    assert.deepStrictEqual([b.name, b.total, b.critical, b.high, b.medium, b.low], ['web1', 3, 1, 1, 0, 1]);
    const last = srv.state.requests[srv.state.requests.length - 1];
    assert.strictEqual(last.body.size, 0); assert.strictEqual(last.body.aggs.agents.terms.field, 'agent.id'); assert.strictEqual(last.body.aggs.agents.terms.size, 200);
  });
  it('the machine limit is a whole number from 1 to 500, else 200 (nothing a caller sends goes further)', async () => {
    for (const [lim, want] of [[5, 5], [500, 500], [0, 200], [501, 200], ['5', 200], [1.5, 200], [undefined, 200]]) {
      await ix.machineSeverities(m(), lim); assert.strictEqual(srv.state.requests[srv.state.requests.length - 1].body.aggs.agents.terms.size, want, String(lim));
    }
  });
  it('refuses a time that is not a plain ISO UTC time before any request is made', async () => {
    const before = srv.state.requests.length;
    for (const bad of ['2026-10-30', 'yesterday', '2026-10-30T00:00:00+02:00', '2026-13-45T00:00:00Z', '2026-10-30T00:00:00Z"} , "x', '', null, 5]) {
      await assert.rejects(ix.detectedSince(m(), bad), (e) => e.code === 'BAD_REQUEST', String(bad));
    }
    assert.strictEqual(srv.state.requests.length, before);
  });
});

describe('the machine list in the event', () => {
  const S = { total: 1, machines: 1, severity: {} }, N = {};
  const mach = (i, c, h, t = 10) => ({ agent_id: String(i).padStart(3, '0'), name: 'pc' + i, total: t, critical: c, high: h, medium: 0, low: 0, unknown: 0 });
  it('keeps the worst 50, critical first, then high, then findings, as [id, name, total, critical, high]', () => {
    const list = [mach(1, 0, 5), mach(2, 3, 0), mach(3, 3, 2), mach(4, 0, 5, 99)]; for (let i = 5; i < 70; i++) list.push(mach(i, 0, 0, 1));
    const p = fs.buildEvent(T, S, N, null, 's', at('2026-11-03T03:05:00Z'), list).parsed;
    const out = JSON.parse(p.machines_json); assert.strictEqual(out.length, 50); assert.strictEqual(p.machines_listed, 50);
    assert.deepStrictEqual(out.slice(0, 4), [['003', 'pc3', 10, 3, 2], ['002', 'pc2', 10, 3, 0], ['004', 'pc4', 99, 0, 5], ['001', 'pc1', 10, 0, 5]]);
  });
  it('no list (the call failed or the index is empty) leaves the field out', () => {
    for (const m of [null, [], undefined]) assert.ok(!('machines_json' in fs.buildEvent(T, S, N, null, 's', at('2026-11-03T03:05:00Z'), m).parsed));
  });
  it('a long name is cut, and the event still passes the envelope check', () => {
    const e = fs.buildEvent(T, S, N, null, 's', at('2026-11-03T03:05:00Z'), [{ ...mach(1, 1, 1), name: 'x'.repeat(500) }]); makeEnvelope(e);
    assert.strictEqual(JSON.parse(e.parsed.machines_json)[0][1].length, 60);
  });
});

describe('runTenant: one summary a day, and nothing changed when the indexer fails', () => {
  let srv, store, origWith;
  before(async () => { srv = await fake.start(); origWith = db.withTenant; db.withTenant = async (t, fn) => fn({}); });
  after(async () => { db.withTenant = origWith; await srv.stop(); });
  beforeEach(() => { store = new MemoryEventStore(); srv.state.requests.length = 0; srv.state.mode = null; });
  let n = 0;
  const tenant = () => `44444444-4444-4444-8444-${String(++n).padStart(12, '0')}`;       // a fresh tenant per test: the retry gate is per tenant
  const reg = (row = true) => ({ readRow: async () => (row ? { tenant_id: 'x' } : null), isMissingTable: (e) => e && e.code === '42P01',
    credentials: () => ({ tenant_id: 'T-' + srv.port, index_url: srv.url, index_user: srv.user, index_password: srv.password, ca_pem: srv.cert, cert_sha256: 'x', index_name: srv.index }) });
  const run = (t, now, o = {}) => fs.runTenant(t, { now: at(now), cfg: ON, store, registry: reg(), ...o });
  const stored = (t) => store.listEvents(t, { source_type: 'vuln-summary', limit: 50 });

  it('records one event with the real totals of the stand-in index', async () => {
    const t = tenant();
    assert.strictEqual((await run(t, '2026-11-03T03:10:00Z')).recorded, 1);
    const [e] = await stored(t);
    assert.deepStrictEqual([e.parsed.summary_day, e.parsed.findings_total, e.parsed.machines, e.parsed.critical, e.parsed.high, e.parsed.medium, e.parsed.low], ['2026-11-03', 6, 2, 2, 2, 1, 1]);
    assert.strictEqual(e.parsed.new_since, '2026-11-02T03:10:00Z');
    assert.strictEqual(e.parsed.new_total, 0, 'every finding of the stand-in was detected before that day');
  });
  it('the event carries the machines of the stand-in index', async () => {
    const t = tenant(); await run(t, '2026-11-03T03:10:00Z');
    const [e] = await stored(t); assert.deepStrictEqual(JSON.parse(e.parsed.machines_json).map((x) => x[0]).sort(), ['001', '002']); assert.strictEqual(e.parsed.machines_listed, 2);
  });
  it('if only the machine call fails the summary is still written, without the list', async () => {
    const t = tenant(); const idx = { ...ix, machineSeverities: async () => { throw new Error('boom'); } };
    assert.strictEqual((await run(t, '2026-11-03T03:10:00Z', { idx })).recorded, 1);
    const [e] = await stored(t); assert.strictEqual(e.parsed.findings_total, 6); assert.ok(!('machines_json' in e.parsed));
  });
  it('a second cycle the same day does not read the indexer or write again', async () => {
    const t = tenant();
    await run(t, '2026-11-03T03:10:00Z'); const calls = srv.state.requests.length;
    assert.strictEqual((await run(t, '2026-11-03T03:11:00Z')).recorded, 0); assert.strictEqual((await run(t, '2026-11-03T22:00:00Z')).recorded, 0);
    assert.strictEqual(srv.state.requests.length, calls); assert.strictEqual((await stored(t)).length, 1);
  });
  it('the next day records again, with the change and the new findings since the previous summary', async () => {
    const t = tenant();
    await run(t, '2026-10-30T03:00:00Z');                         // yesterday: the first summary
    srv.state.indexes[srv.index] = srv.state.indexes[srv.index].concat(fake.DOCS_B.map((d) => ({ ...d, agent: { ...d.agent, id: '009' }, vulnerability: { ...d.vulnerability, id: 'CVE-2026-7777', severity: 'Critical', detected_at: '2026-10-30T12:00:00Z' } })));
    assert.strictEqual((await run(t, '2026-10-31T03:00:00Z')).recorded, 1);
    const [today, first] = await stored(t);
    assert.strictEqual(today.parsed.summary_day, '2026-10-31'); assert.strictEqual(first.parsed.summary_day, '2026-10-30');
    assert.deepStrictEqual([today.parsed.findings_total, today.parsed.total_change, today.parsed.critical_change, today.parsed.new_critical, today.parsed.new_total, today.parsed.new_since], [7, 1, 1, 3, 4, '2026-10-30T03:00:00Z']);
  });
  it('nothing is read or written when it is off, too early, in the start-up grace, or the tenant has no indexer', async () => {
    const t = tenant();
    assert.strictEqual((await run(t, '2026-11-03T03:10:00Z', { cfg: { enabled: false, hour: 3 } })).recorded, 0);
    assert.strictEqual((await run(t, '2026-11-03T02:10:00Z')).recorded, 0);
    assert.strictEqual((await run(t, '2026-11-03T03:10:00Z', { raiseAllowed: false })).recorded, 0);
    assert.strictEqual((await run(t, '2026-11-03T03:10:00Z', { registry: reg(false) })).recorded, 0);
    assert.strictEqual((await run(t, '2026-11-03T03:10:00Z', { registry: { ...reg(), readRow: async () => { const e = new Error('no table'); e.code = '42P01'; throw e; } } })).recorded, 0);
    assert.strictEqual(srv.state.requests.length, 0); assert.strictEqual((await stored(t)).length, 0);
  });
  it('an unreachable indexer writes nothing, is retried only after 15 minutes, and recovers', async () => {
    const t = tenant(); srv.state.mode = 'html';                  // answers 200 with a page that is not JSON: BAD_RESPONSE
    const warn = console.warn; const logged = []; console.warn = (...a) => logged.push(a.join(' '));
    try {
      assert.strictEqual((await run(t, '2026-11-03T03:10:00Z')).recorded, 0);
      const calls = srv.state.requests.length; assert.ok(calls > 0);
      await run(t, '2026-11-03T03:20:00Z'); assert.strictEqual(srv.state.requests.length, calls, 'not again within 15 minutes');
      srv.state.mode = null;
      assert.strictEqual((await run(t, '2026-11-03T03:26:00Z')).recorded, 1, 'after 15 minutes it tries again and works');
    } finally { console.warn = warn; }
    assert.strictEqual(logged.length, 1, 'one log line for the problem: ' + logged.join('|'));
    assert.strictEqual((await stored(t)).length, 1);
  });
});

describe('the built-in rule "New critical vulnerabilities on endpoints"', () => {
  const RULE = BUILTIN_RULES.find((r) => r.key === 'vuln-new-critical');
  const NOW = new Date('2026-11-03T12:00:00.000Z');
  const ev = (day, newCritical, minsAgo) => { const e = fs.buildEvent(T, { total: 10, machines: 1, severity: {} }, { total: newCritical, critical: newCritical }, null, 's', Date.parse(day + 'T03:00:00Z')); const a = new Date(NOW - minsAgo * 60000).toISOString(); return { ...e, id: undefined, received_at: a, event_time: a }; };
  const matches = async (events) => { const s = new MemoryEventStore(); if (events.length) await s.insertBatch(T, events.map((e, i) => ({ ...e, id: `00000000-0000-4000-8000-${String(i + 1).padStart(12, '0')}` }))); return Object.fromEntries((await s.matchGroups(T, buildRuleMatch(RULE.definition, { now: NOW }))).map((r) => [r.key, r.n])); };
  it('is a valid rule in the endpoint category: high, one alert a day', () => {
    assert.ok(RULE); assert.ok(!normalizeDefinition(RULE.definition).error, JSON.stringify(normalizeDefinition(RULE.definition)));
    assert.deepStrictEqual([RULE.severity, RULE.category, RULE.definition.source_type, RULE.definition.suppression.minutes], ['high', 'Endpoint Security', 'vuln-summary', 1440]);
  });
  it('fires for a summary with new critical findings, grouped by day', async () => { assert.deepStrictEqual(await matches([ev('2026-11-03', 2, 540)]), { '2026-11-03': 1 }); });
  it('stays quiet when nothing new is critical, when the summary is older than the window, and for other datasets', async () => {
    assert.deepStrictEqual(await matches([ev('2026-11-03', 0, 540)]), {});
    assert.deepStrictEqual(await matches([ev('2026-11-02', 5, 1700)]), {});
    assert.deepStrictEqual(await matches([{ ...ev('2026-11-03', 5, 540), source_type: 'syslog' }]), {});
  });
});

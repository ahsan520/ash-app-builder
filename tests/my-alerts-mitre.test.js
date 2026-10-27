'use strict';
// E4i: ATT&CK on the "My open alerts" tile (docs/endpoints.md, "E4i as built").
//   1. GET /v1/my-alerts with a stand-in database that records the SQL and parameters: the ATT&CK keys are selected, stored ATT&CK wins, an alert with none takes it from its
//      sample events (one batched read), a failing store gives none and never a failed tile, raw columns are never returned, the counts are untouched;
//   2. the tile in the portal (functions cut out of src/portal/index.html and run with small stand-ins, no DOM, no network).
// The SQL itself runs against a real PostgreSQL only in tests/my-alerts-db.test.js (not re-run for this change).
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const express = require('express');
const shared = require('../src/gateway/shared');
const { MemoryEventStore } = require('../src/events/memory-store');
const { setEventStore } = require('../src/events');

const TENANT = '11111111-1111-4111-8111-111111111111'; const USER = '22222222-2222-4222-8222-222222222222';
const EV = '44444444-4444-4444-8444-444444444444';
let user = USER; let queries = []; let topRows = [];

describe('GET /v1/my-alerts, ATT&CK', () => {
  const saved = require.cache[require.resolve('../src/gateway/shared')].exports;
  let srv; let base;
  before(() => {
    const fakeDb = { withTenant: async (t, fn) => fn({ query: async (sql, params) => {
      queries.push({ sql, params });
      if (/GROUP BY/.test(sql)) return { rows: [{ severity: 'high', status: 'open', n: 3, oldest: '2026-10-12T00:00:00Z' }] };
      return { rows: topRows };
    } }) };
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, db: fakeDb, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = user; next(); }] };
    delete require.cache[require.resolve('../src/gateway/routes/my-alerts')];
    const app = express(); app.use(require('../src/gateway/routes/my-alerts'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); require.cache[require.resolve('../src/gateway/shared')].exports = saved; });
  const get = async () => { queries = []; const r = await fetch(base + '/v1/my-alerts'); return { status: r.status, json: await r.json() }; };
  const row = (o) => ({ id: '33333333-3333-4333-8333-333333333333', severity: 'high', status: 'open', title: 't', event_count: 1, last_event_at: '2026-10-12T00:01:00Z', mitre_stored: null, sample_ids: [], ...o });

  it('selects only the two ATT&CK keys of details for the top alerts, scoped to the tenant and user as before', async () => {
    topRows = []; await get();
    const top = queries.find((q) => !/GROUP BY/.test(q.sql));
    assert.ok(/details->'mitre' AS mitre_stored/.test(top.sql)); assert.ok(/details->'sample_event_ids' AS sample_ids/.test(top.sql));
    assert.ok(!/SELECT[^;]*\bdetails\b\s*,/.test(top.sql.replace(/details->'mitre'/g, '').replace(/details->'sample_event_ids'/g, '')));
    assert.deepStrictEqual(top.params, [TENANT, USER]); assert.match(top.sql, /assignee_id = \$2/);
  });
  it('returns the stored ATT&CK through the safe view, links only for well-formed ids, and never the raw columns', async () => {
    topRows = [row({ mitre_stored: { techniques: [{ id: 'T1110', name: 'Brute Force' }, { id: 'javascript:alert(1)', name: 'x' }, 5], tactics: ['Credential Access', 7] }, sample_ids: [EV] }), row({ mitre_stored: 'oops' })];
    const r = await get();
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.applicable, true); assert.strictEqual(r.json.alerts.length, 2);
    assert.ok(r.json.alerts.every((a) => !('mitre_stored' in a) && !('sample_ids' in a)));
    assert.deepStrictEqual(r.json.alerts[0].mitre.techniques.map((t) => [t.id, t.url]), [['T1110', 'https://attack.mitre.org/techniques/T1110/'], ['javascript:alert(1)', null]]);
    assert.deepStrictEqual(r.json.alerts[0].mitre.tactics, ['Credential Access']);
    assert.deepStrictEqual(r.json.alerts[1].mitre, { techniques: [], tactics: [] });
  });
  it('leaves the counts and the other fields as they were', async () => {
    topRows = [row({ title: 'Endpoint security alert, x' })];
    const r = await get();
    assert.strictEqual(r.json.active_total, 3); assert.strictEqual(r.json.active.high, 3); assert.strictEqual(r.json.open, 3);
    assert.strictEqual(r.json.alerts[0].title, 'Endpoint security alert, x'); assert.strictEqual(r.json.alerts[0].event_count, 1);
  });
  it('an alert with no stored ATT&CK takes it from its sample events (one batched read; a stored one never reads), and a failing store gives none, not an error', async () => {
    const store = new MemoryEventStore();
    await store.insertBatch(TENANT, [{ id: EV, source_type: 'endpoint-alert', raw: 'x', parsed: { mitre_ids: 'T1548.003', mitre_techniques: 'Sudo', mitre_tactics: 'Privilege Escalation' }, received_at: new Date().toISOString() }]);
    setEventStore(store); let reads = 0; const orig = store.getByIds.bind(store); store.getByIds = async (t, ids) => { reads += 1; return orig(t, ids); };
    topRows = [row({ title: 'old', sample_ids: [EV, 'not-an-id', 9] }), row({ title: 'stored', mitre_stored: { techniques: [{ id: 'T1110', name: 'x' }], tactics: [] }, sample_ids: [EV] }), row({ title: 'plain', sample_ids: [] })];
    let r = await get();
    assert.strictEqual(reads, 1);
    assert.deepStrictEqual(Object.fromEntries(r.json.alerts.map((a) => [a.title, a.mitre.techniques.map((t) => t.id)])), { old: ['T1548.003'], stored: ['T1110'], plain: [] });
    store.getByIds = async () => { throw new Error('store down'); };
    r = await get(); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.active_total, 3);
    assert.deepStrictEqual(r.json.alerts.map((a) => a.mitre.techniques.length), [0, 1, 0]);
  });
  it('a service account is still not applicable and runs no query', async () => {
    user = null; const r = await get(); user = USER;
    assert.deepStrictEqual(r.json, { success: true, applicable: false }); assert.strictEqual(queries.length, 0);
  });
});

describe('the My open alerts tile in the portal', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
  const mitreSrc = html.slice(html.indexOf('// ---- ATT&CK on the alert list (E4g) ----'), html.indexOf('async function pgAlerts'));
  const tileSrc = html.slice(html.indexOf('function myAlertsTile'), html.indexOf('// ---- boot ----'));
  assert.ok(mitreSrc.includes('function alertMitreCell') && tileSrc.includes('table('), 'sources found');
  const el = (tag, attrs, ...kids) => Object.assign({}, attrs || {}, { tag, attrs: attrs || {}, kids: kids.flat(Infinity) });
  const walk = (n) => (typeof n === 'string' ? [n] : n && typeof n === 'object' ? (Array.isArray(n) ? n.flatMap(walk) : [n, ...(n.kids || []).flatMap(walk)]) : []);
  const card = (title, ...kids) => el('div', { className: 'card' }, ...kids);
  const table = (cols, rs) => el('table', { cols }, rs.map((r) => el('tr', {}, cols.map((c) => { const v = c.f(r); return typeof v === 'object' && v ? el('td', {}, v) : el('td', { textContent: String(v ?? '-') }); }))));
  const build = (m) => {
    const loc = { hash: null };
    const fn = new Function('el', 'card', 'table', 'menuModule', 'ago', 'sevPill', 'pill', 'SEV', 'location', mitreSrc + '\n' + tileSrc + '\nreturn myAlertsTile;')(
      el, card, table, () => false, () => 'now', (s) => el('span', { textContent: s }), (t) => el('span', { textContent: t }), ['critical', 'high', 'medium', 'low'], loc);
    return { tree: fn(m), loc };
  };
  const M = (alerts) => ({ applicable: true, active_total: alerts.length, open: alerts.length, acknowledged: 0, oldest_open_at: null, active: { critical: 0, high: alerts.length, medium: 0, low: 0 }, alerts });
  const A = (o) => ({ id: 'a', title: 'x', severity: 'high', status: 'open', last_event_at: '2026-10-27T10:00:00Z', mitre: { techniques: [], tactics: [] }, ...o });

  it('has an ATT&CK column with up to three techniques, "+N" for the rest and a dash for none', () => {
    const { tree } = build(M([A({ mitre: { techniques: ['T1110', 'T1078', 'T1565.001', 'T1059'].map((id) => ({ id, name: 'n' })), tactics: [] } }), A({})]));
    assert.deepStrictEqual(walk(tree).find((x) => x && x.tag === 'table').attrs.cols.map((c) => c.h), ['Severity', 'Alert', 'ATT&CK', 'Status', 'Last seen'], 'column header');
    const cells = walk(tree).filter((x) => x && x.tag === 'td');
    const first = cells.find((c) => walk(c).some((x) => x && x.textContent === 'T1110'));
    assert.deepStrictEqual(walk(first).filter((x) => x && x.className === 'pill off').map((x) => x.textContent), ['T1110', 'T1078', 'T1565.001']);
    assert.ok(walk(first).some((x) => x && x.textContent === '+1'));
    assert.ok(cells.some((c) => walk(c).some((x) => x && x.textContent === '-' && x.className === 'mute')));
  });
  it('a click on a technique opens my alerts filtered by it; a malformed id goes nowhere', () => {
    const { tree, loc } = build(M([A({ mitre: { techniques: [{ id: 'T1110', name: 'Brute Force' }], tactics: [] } })]));
    const chip = walk(tree).find((x) => x && x.textContent === 'T1110' && typeof x.onclick === 'function');
    let stopped = false; chip.onclick({ stopPropagation: () => { stopped = true; } });
    assert.ok(stopped); assert.strictEqual(loc.hash, '#/incidents?assignee=me&mitre=T1110');
    const bad = build(M([A({ mitre: { techniques: [{ id: "T1110'><b>", name: 'x' }], tactics: [] } })]));
    const c2 = walk(bad.tree).find((x) => x && typeof x.onclick === 'function' && x.className === 'pill off'); c2.onclick({ stopPropagation() {} });
    assert.strictEqual(bad.loc.hash, null);
  });
  it('an old answer without the mitre field still draws (a dash) and the empty tile is unchanged', () => {
    const { tree } = build(M([{ id: 'a', title: 'x', severity: 'high', status: 'open', last_event_at: '2026-10-27T10:00:00Z' }]));
    assert.ok(walk(tree).some((x) => x && x.textContent === '-'));
    const empty = build({ applicable: true, active_total: 0 });
    assert.ok(walk(empty.tree).some((x) => x && x.textContent === 'Nothing is assigned to you.'));
    assert.strictEqual(build({ applicable: false }).tree, '');
  });
});

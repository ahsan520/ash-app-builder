'use strict';
// E4g: ATT&CK on the alert list and the technique filter (docs/endpoints.md, "E4g as built").
//   1. GET /v1/alerts with a stand-in database that records the SQL and parameters: input validation, what is bound, what comes back;
//   2. the portal list (the functions are cut out of src/portal/index.html and run with small stand-ins, no DOM, no network).
// The SQL itself runs against a real PostgreSQL in tests/alert-list-mitre-db.test.js.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const express = require('express');
const shared = require('../src/gateway/shared');

let TENANT = '11111111-1111-4111-8111-111111111111';
let queries = []; let rows = [];
const realWithTenant = shared.db.withTenant;
describe('GET /v1/alerts, ATT&CK', () => {
  let srv; let base;
  before(() => {
    shared.db.withTenant = async (_t, fn) => fn({ query: async (sql, params) => { queries.push({ sql, params }); return { rows }; } });
    require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = null; next(); }] };
    delete require.cache[require.resolve('../src/gateway/routes/alerts')];
    const app = express(); app.use(require('../src/gateway/routes/alerts'));
    srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => { srv.close(); shared.db.withTenant = realWithTenant; });
  const get = async (qs) => { queries = []; const r = await fetch(base + '/v1/alerts?' + qs); return { status: r.status, json: await r.json() }; };
  const row = (o) => ({ id: '22222222-2222-4222-8222-222222222222', title: 't', severity: 'high', status: 'open', mitre_stored: null, ...o });

  it('adds no technique condition and no extra parameter when mitre is not given', async () => {
    rows = [];
    await get('status=active');
    assert.strictEqual(queries.length, 1); assert.deepStrictEqual(queries[0].params, [TENANT]); assert.ok(!/jsonb_array_elements/.test(queries[0].sql));
  });
  it('binds the id as one upper-cased parameter, never into the SQL text', async () => {
    rows = [];
    await get('mitre=t1110.003');
    assert.deepStrictEqual(queries[0].params, [TENANT, 'T1110.003']); assert.ok(!/T1110/.test(queries[0].sql)); assert.ok(/\$2::text/.test(queries[0].sql));
  });
  it('the parameter number follows the other filters', async () => {
    rows = [];
    await get('status=open&severity=high&mitre=T1110');
    assert.deepStrictEqual(queries[0].params, [TENANT, 'open', 'high', 'T1110']); assert.ok(/\$4::text/.test(queries[0].sql));
  });
  it('refuses anything that is not a technique id, before any query', async () => {
    for (const bad of ['', 'T111', 'T11100', 'T1110.3', "T1110'; DROP TABLE alerts;--", 'T1110%25', 'x', 'T1110.003.001', '%20', 'T1110,T1078']) {
      const r = await get('mitre=' + encodeURIComponent(bad));
      assert.strictEqual(r.status, 400, JSON.stringify(bad)); assert.strictEqual(queries.length, 0, 'no query for ' + JSON.stringify(bad));
    }
    const r = await get('mitre=T1110&mitre=T1078'); assert.strictEqual(r.status, 400); assert.strictEqual(queries.length, 0);
  });
  it('returns the stored ATT&CK through the safe view and never the raw column', async () => {
    rows = [row({ mitre_stored: { techniques: [{ id: 'T1110', name: 'Brute Force' }, { id: 'javascript:alert(1)', name: 'x' }, 5, null], tactics: ['Credential Access', 7] } }),
      row({ mitre_stored: 'oops' }), row({ mitre_stored: null }), row({ mitre_stored: { techniques: 'T1110' } })];
    const r = await get('status=all');
    assert.strictEqual(r.status, 200); assert.strictEqual(r.json.count, 4);
    assert.ok(r.json.alerts.every((a) => !('mitre_stored' in a)));
    assert.deepStrictEqual(r.json.alerts[0].mitre.techniques.map((t) => [t.id, t.url]), [['T1110', 'https://attack.mitre.org/techniques/T1110/'], ['javascript:alert(1)', null]]);
    assert.deepStrictEqual(r.json.alerts[0].mitre.tactics, ['Credential Access']);
    for (const i of [1, 2, 3]) assert.deepStrictEqual(r.json.alerts[i].mitre, { techniques: [], tactics: [] });
  });
  it('selects only the ATT&CK key of details, not the whole column', async () => {
    rows = []; await get('status=all');
    assert.ok(/details->'mitre' AS mitre_stored/.test(queries[0].sql)); assert.ok(!/SELECT[^;]*\bdetails\b\s*,/.test(queries[0].sql.replace(/details->'mitre'/g, '')));
  });
});

describe('the alert list in the portal', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
  const source = html.slice(html.indexOf('// ---- ATT&CK on the alert list (E4g) ----'), html.indexOf('// ---- Collectors & installers'));
  assert.ok(source.includes('async function pgAlerts'), 'page function found');
  const el = (tag, attrs, ...kids) => Object.assign({}, attrs || {}, { tag, attrs: attrs || {}, kids: kids.flat(Infinity), querySelectorAll: () => [], replaceChildren(...k) { this.kids = k.flat(Infinity); } });
  const walk = (n) => (typeof n === 'string' ? [n] : n && typeof n === 'object' ? (Array.isArray(n) ? n.flatMap(walk) : [n, ...(n.kids || []).flatMap(walk)]) : []);
  const card = (title, ...kids) => el('div', { className: 'card' }, ...kids);
  const table = (cols, rs, empty) => (!rs.length ? el('div', { className: 'mute', textContent: empty }) : el('table', { cols, rows: rs }, rs.map((r) => el('tr', {}, cols.map((c) => { const v = c.f(r); return typeof v === 'object' && v ? el('td', {}, v) : el('td', { textContent: String(v ?? '-') }); })))));
  const A = (o) => ({ id: '33333333-3333-4333-8333-333333333333', title: 'x', severity: 'high', status: 'open', event_count: 1, merged_count: 0, assignee_name: null, last_event_at: '2026-10-27T10:00:00Z', mitre: { techniques: [], tactics: [] }, ...o });
  async function open(query, alerts = []) {
    const calls = []; const hash = { hash: null };
    const api = async (p) => { calls.push(p); return { alerts, count: alerts.length }; };
    const g = { routeQuery: new URLSearchParams(query), location: hash };
    const fn = new Function('el', 'card', 'table', 'api', 'head', 'sevPill', 'pill', 'when', 'openAlert', 'openDedupe', 'route', 'routeQuery', 'location', 'SEV', 'window', source + '\nreturn pgAlerts;')(
      el, card, table, api, (t) => [el('h1', { textContent: t })], (s) => el('span', { textContent: s }), (t) => el('span', { textContent: t }), (v) => String(v || '-'), () => {}, () => {}, () => {}, g.routeQuery, hash, ['critical', 'high', 'medium', 'low'], {});
    const tree = await fn();
    const find = (pred, what) => { const n = walk(tree).find((x) => typeof x === 'object' && x.attrs && pred(x.attrs)); assert.ok(n, what + ' not found'); return n; };
    return { calls, hash, tree, find };
  }

  it('sends no mitre parameter and shows no clear button without a technique', async () => {
    const p = await open('');
    assert.ok(!/mitre=/.test(p.calls[0])); assert.ok(!walk(p.tree).some((x) => x && x.attrs && x.attrs.textContent === 'Clear technique'));
  });
  it('asks the server for the technique in the address, upper-cased, and drops a malformed one before sending', async () => {
    assert.ok(/mitre=T1110\.003/.test((await open('mitre=t1110.003')).calls[0]));
    for (const bad of ['T11', "T1110'", '<b>', 'T1110,T1078']) assert.ok(!/mitre=/.test((await open('mitre=' + encodeURIComponent(bad))).calls[0]), bad);
  });
  it('shows up to three technique ids per row, "+N" for the rest and a dash for none', async () => {
    const p = await open('', [A({ mitre: { techniques: ['T1110', 'T1078', 'T1565.001', 'T1059', 'T1021'].map((id) => ({ id, name: 'n ' + id })), tactics: [] } }), A({})]);
    const cells = walk(p.tree).filter((x) => x && x.tag === 'td');
    const first = cells.find((c) => walk(c).some((x) => x && x.textContent === 'T1110'));
    const ids = walk(first).filter((x) => x && x.className === 'pill off').map((x) => x.textContent);
    assert.deepStrictEqual(ids, ['T1110', 'T1078', 'T1565.001']);
    const more = walk(first).find((x) => x && x.textContent === '+2'); assert.ok(more && /T1059/.test(more.title) && /T1021/.test(more.title));
    assert.ok(cells.some((c) => walk(c).some((x) => x && x.textContent === '-' && x.className === 'mute')), 'an alert with none shows a dash');
  });
  it('a click on a technique filters by it and does not open the alert', async () => {
    const p = await open('status=closed', [A({ mitre: { techniques: [{ id: 'T1110', name: 'Brute Force' }], tactics: [] } })]);
    const chip = p.find((a) => a.textContent === 'T1110' && typeof a.onclick === 'function', 'technique chip');
    let stopped = false; chip.attrs.onclick({ stopPropagation: () => { stopped = true; } });
    assert.ok(stopped, 'the click does not reach the row');
    assert.strictEqual(p.hash.hash, '#/incidents?status=closed&mitre=T1110', 'the address keeps the other filters and adds the technique');
  });
  it('the technique box is filled from the address and typing a bad id sends nothing', async () => {
    const p = await open('mitre=T1110');
    const box = p.find((a) => a.placeholder && /ATT&CK/.test(a.placeholder), 'technique box'); assert.strictEqual(box.value, 'T1110');
    assert.ok(walk(p.tree).some((x) => x && x.attrs && x.attrs.textContent === 'Clear technique'));
  });
  it('explains an empty result for a technique', async () => {
    const p = await open('mitre=T1110', []);
    assert.ok(walk(p.tree).some((x) => x && typeof x.textContent === 'string' && /after ATT&CK was stored/.test(x.textContent)));
  });
});

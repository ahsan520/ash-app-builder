'use strict';
// E4h: ATT&CK tactic filter on the alert list (docs/endpoints.md, "E4h as built").
//   1. GET /v1/alerts?tactic= with a stand-in database that records SQL and parameters;
//   2. the portal list (functions cut out of src/portal/index.html, small stand-ins, no DOM, no network).
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const express = require('express');
const shared = require('../src/gateway/shared');

const TENANT = '11111111-1111-4111-8111-111111111111';
let queries = []; let rows = [];
const realWithTenant = shared.db.withTenant;

describe('GET /v1/alerts, tactic filter', () => {
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
  const stored = (ids, tactics) => ({ techniques: ids.map((id) => ({ id, name: id })), tactics });
  const titles = async (q) => (await get(q)).json.alerts.map((a) => a.title);

  it('without tactic the page size is the caller\'s; with it the newest 1,000 are read and nothing from the request is in the SQL', async () => {
    rows = []; await get('status=active&limit=7&offset=3');
    assert.ok(/LIMIT 7 OFFSET 3/.test(queries[0].sql));
    await get('tactic=credential%20access&limit=7&offset=3&severity=high');
    assert.ok(/LIMIT 1000 OFFSET 0/.test(queries[0].sql)); assert.deepStrictEqual(queries[0].params, [TENANT, 'high']); assert.ok(!/credential/i.test(queries[0].sql));
  });
  it('matches the start of a tactic name, any case, hyphen or space, and slices after the filter', async () => {
    rows = [
      row({ title: 'a0', mitre_stored: stored(['T1110'], ['Credential Access']) }),
      row({ title: 'a1', mitre_stored: stored(['T1565.001'], ['Impact']) }),
      row({ title: 'a2', mitre_stored: stored(['T1548.003'], ['Privilege Escalation', 'Defense Evasion']) }),
      row({ title: 'a3', mitre_stored: stored(['T1078'], ['Defense Evasion', 'Credential Access']) }),
      row({ title: 'a4', mitre_stored: null }),
    ];
    assert.deepStrictEqual(await titles('tactic=Credential%20Access'), ['a0', 'a3']);
    assert.deepStrictEqual(await titles('tactic=credential'), ['a0', 'a3']);
    assert.deepStrictEqual(await titles('tactic=CREDENTIAL-ACCESS'), ['a0', 'a3']);
    assert.deepStrictEqual(await titles('tactic=defense%20%20evasion'), ['a2', 'a3']);
    assert.deepStrictEqual(await titles('tactic=impact'), ['a1']);
    assert.deepStrictEqual(await titles('tactic=imp'), ['a1']);
    assert.deepStrictEqual(await titles('tactic=access'), [], 'the start of a name, not any part of it');
    assert.deepStrictEqual(await titles('tactic=Impact&limit=1&offset=1'), []);
    assert.deepStrictEqual(await titles('tactic=Defense&limit=1&offset=1'), ['a3'], 'paging happens after filtering');
    assert.deepStrictEqual(await titles('tactic=Persistence'), []);
  });
  it('combines with the technique filter: both must match', async () => {
    rows = [
      row({ title: 'x0', mitre_stored: stored(['T1110'], ['Credential Access']) }),
      row({ title: 'x1', mitre_stored: stored(['T1110'], ['Impact']) }),
      row({ title: 'x2', mitre_stored: stored(['T1078'], ['Credential Access']) }),
    ];
    assert.deepStrictEqual(await titles('tactic=credential&mitre=T1110'), ['x0']);
    assert.deepStrictEqual(await titles('tactic=impact&mitre=T1078'), []);
    assert.deepStrictEqual(await titles('mitre=T1110'), ['x0', 'x1'], 'the technique alone is unchanged');
  });
  it('refuses anything that is not the start of a tactic name, before any query', async () => {
    for (const bad of ['', ' ', '1', 'x'.repeat(41), "impact'; DROP TABLE alerts;--", 'impact%', '<b>', 'a,b', 'ünï', 'credential_access', '-impact']) {
      const r = await get('tactic=' + encodeURIComponent(bad));
      assert.strictEqual(r.status, 400, JSON.stringify(bad)); assert.strictEqual(r.json.error && r.json.error.code, 'INVALID_TACTIC'); assert.strictEqual(queries.length, 0, 'no query for ' + JSON.stringify(bad));
    }
    const r = await get('tactic=impact&tactic=discovery'); assert.strictEqual(r.status, 400); assert.strictEqual(queries.length, 0);
  });
});

describe('the alert list in the portal, tactic', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
  const source = html.slice(html.indexOf('// ---- ATT&CK on the alert list (E4g) ----'), html.indexOf('// ---- Collectors & installers'));
  const el = (tag, attrs, ...kids) => Object.assign({}, attrs || {}, { tag, attrs: attrs || {}, kids: kids.flat(Infinity), querySelectorAll: () => [] });
  const walk = (n) => (typeof n === 'string' ? [n] : n && typeof n === 'object' ? (Array.isArray(n) ? n.flatMap(walk) : [n, ...(n.kids || []).flatMap(walk)]) : []);
  const card = (t, ...kids) => el('div', { className: 'card' }, ...kids);
  const table = (cols, rs, empty) => (!rs.length ? el('div', { className: 'mute', textContent: empty }) : el('table', {}));
  async function open(query) {
    const calls = []; const hash = { hash: null };
    const api = async (p) => { calls.push(p); return { alerts: [], count: 0 }; };
    const fn = new Function('el', 'card', 'table', 'api', 'head', 'sevPill', 'pill', 'when', 'openAlert', 'openDedupe', 'route', 'routeQuery', 'location', 'SEV', 'window', source + '\nreturn pgAlerts;')(
      el, card, table, api, (t) => [el('h1', { textContent: t })], (s) => s, (t) => t, (v) => String(v || '-'), () => {}, () => {}, () => {}, new URLSearchParams(query), hash, ['critical', 'high', 'medium', 'low'], {});
    const tree = await fn();
    const sel = walk(tree).find((x) => x && x.tag === 'select' && x.title === 'ATT&CK tactic');
    return { calls, hash, tree, sel };
  }
  it('sends no tactic by default and has a select with the 14 enterprise tactics', async () => {
    const p = await open('');
    assert.ok(!/tactic=/.test(p.calls[0])); assert.ok(p.sel, 'tactic select');
    const names = p.sel.kids.map((o) => o.textContent); assert.strictEqual(names[0], 'any tactic'); assert.strictEqual(names.length, 15);
    assert.ok(names.includes('Credential Access') && names.includes('Command and Control') && names.includes('Impact'));
  });
  it('asks the server for the tactic in the address (any case, hyphens) and drops anything that is not one of the 14', async () => {
    assert.ok(/tactic=Credential\+Access/.test((await open('tactic=credential-access')).calls[0]));
    assert.ok(/tactic=Command\+and\+Control/.test((await open('tactic=COMMAND%20AND%20CONTROL')).calls[0]));
    for (const bad of ['cred', 'x', '<b>', 'Impact; drop', 'Impact,Discovery']) assert.ok(!/tactic=/.test((await open('tactic=' + encodeURIComponent(bad))).calls[0]), bad);
  });
  it('the select shows the tactic of the address and a choice goes into the address with the other filters', async () => {
    const p = await open('status=closed&mitre=T1110&tactic=impact');
    assert.strictEqual(p.sel.value, 'Impact');
    p.sel.value = 'Discovery'; p.sel.onchange();
    assert.strictEqual(p.hash.hash, '#/incidents?status=closed&mitre=T1110&tactic=Discovery');
    p.sel.value = ''; p.sel.onchange();
    assert.strictEqual(p.hash.hash, '#/incidents?status=closed&mitre=T1110', 'any tactic removes it');
  });
});

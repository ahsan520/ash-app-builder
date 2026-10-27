'use strict';
// E4f: MITRE ATT&CK on the ASIX alerts raised from endpoint alerts (docs/endpoints.md, "E4f as built").
//   1. the helpers (src/endpoints/endpoint-alerts.js): the union of the events' techniques and tactics, the stored shape read back safely, the batched lookup;
//   2. the rule runner (evaluateRule) with the REAL default parsing rules, the in-memory event store and a stand-in database client that records what it is told to write;
//   3. GET /v1/alerts/:id with a stand-in database and the in-memory event store;
//   4. the portal's MITRE section of an alert (the function is cut out of the page and run with stand-ins).
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const express = require('express');
const ea = require('../src/endpoints/endpoint-alerts');
const { compile, apply } = require('../src/ingestion/parsing-rules');
const { jsonEvent } = require('../src/ingest/http-ingest');
const { MemoryEventStore } = require('../src/events/memory-store');
const { setEventStore } = require('../src/events');
const { BUILTIN_RULES, evaluateRule } = require('../src/detection/rule-runner');

const defaults = compile(require('../src/ingestion/default-parsing-rules'));
const TENANT = '11111111-1111-4111-8111-111111111111';
const HIGH = BUILTIN_RULES.find((r) => r.key === 'endpoint-alert-high');

const BF = { id: ['T1110'], technique: ['Brute Force'], tactic: ['Credential Access'] };
const FIM = { id: ['T1565.001'], technique: ['Stored Data Manipulation'], tactic: ['Impact'] };
let seq = 0;
// An endpoint alert as the broker sends it, parsed by the real rules, `minsAgo` minutes before now (the runner uses the real clock).
function alertEvent({ level = 10, ruleId = '5763', agent = 'web1', minsAgo = 1, mitre = {}, sourceType = 'endpoint-alert' } = {}) {
  const f = { asix_via: 'wazuh', rule_id: ruleId, rule_level: String(level), rule_description: 'd', agent_name: agent, mitre_ids: (mitre.id || []).join(','), mitre_techniques: (mitre.technique || []).join(','), mitre_tactics: (mitre.tactic || []).join(',') };
  const time = new Date(Date.now() - minsAgo * 60000).toISOString();
  const x = jsonEvent({ message: `[Endpoint alert] rule ${ruleId} level ${level}: d`, time, host: agent, fields: f }, 'broker-test');
  const out = apply([defaults.rules], { source_type: sourceType, raw: x.raw, time: x.time, parsed: x.parsed });
  seq += 1;
  return { id: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`, source_type: sourceType, collector_id: 'broker-test', received_at: time, event_time: time, raw: x.raw, parsed: out.parsed };
}

describe('mitreOfEvents', () => {
  const ev = (p) => ({ parsed: p });
  it('is the union of the techniques and tactics of the events, in the order first seen, without repeats', () => {
    const m = ea.mitreOfEvents([ev({ mitre_ids: 'T1110', mitre_techniques: 'Brute Force', mitre_tactics: 'Credential Access' }), ev({ mitre_ids: 'T1565.001,T1110', mitre_techniques: 'Stored Data Manipulation,Brute Force', mitre_tactics: 'Impact,Credential Access' })]);
    assert.deepStrictEqual(m, { techniques: [{ id: 'T1110', name: 'Brute Force' }, { id: 'T1565.001', name: 'Stored Data Manipulation' }], tactics: ['Credential Access', 'Impact'] });
  });
  it('a later event can supply a name the first one lacked', () => {
    const m = ea.mitreOfEvents([ev({ mitre_ids: 'T1059', mitre_techniques: 'a,b' }), ev({ mitre_ids: 'T1059', mitre_techniques: 'Command and Scripting Interpreter' })]);
    assert.deepStrictEqual(m.techniques, [{ id: 'T1059', name: 'Command and Scripting Interpreter' }]);
  });
  it('nothing in, nothing out; missing parsed, odd inputs and non-arrays are survived', () => {
    for (const x of [[], undefined, null, [ev(undefined)], [ev({})], [null], [{}]]) assert.deepStrictEqual(ea.mitreOfEvents(x), { techniques: [], tactics: [] });
  });
  it('is bounded', () => {
    const ids = Array.from({ length: 60 }, (_, i) => 'T' + String(1000 + i)).join(','), tac = Array.from({ length: 40 }, (_, i) => 'tac' + i).join(',');
    const m = ea.mitreOfEvents([ev({ mitre_ids: ids, mitre_tactics: tac })]);
    assert.strictEqual(m.techniques.length, ea.MAX_ALERT_TECHNIQUES); assert.strictEqual(m.tactics.length, ea.MAX_ALERT_TACTICS);
  });
});

describe('mitreView (what is stored on the alert, read back)', () => {
  it('adds a link only for a well-formed technique id', () => {
    const v = ea.mitreView({ techniques: [{ id: 'T1110', name: 'Brute Force' }, { id: 'T1565.001', name: null }, { id: 'javascript:alert(1)', name: 'x' }, { id: 'T1110/../x', name: 'y' }], tactics: ['Impact'] });
    assert.deepStrictEqual(v.techniques.map((t) => [t.id, t.name, t.url]), [['T1110', 'Brute Force', 'https://attack.mitre.org/techniques/T1110/'], ['T1565.001', null, 'https://attack.mitre.org/techniques/T1565/001/'], ['javascript:alert(1)', 'x', null], ['T1110/../x', 'y', null]]);
    assert.deepStrictEqual(v.tactics, ['Impact']);
  });
  it('anything of the wrong shape is ignored, not trusted', () => {
    for (const x of [undefined, null, 'T1110', 5, [], { techniques: 'T1110' }, { techniques: [null, 5, {}, { id: 7 }, { id: '' }], tactics: [null, 5, {}, ''] }, { techniques: {}, tactics: { a: 1 } }]) assert.deepStrictEqual(ea.mitreView(x), { techniques: [], tactics: [] }, JSON.stringify(x));
  });
  it('values are cut and put on one line; lists are bounded', () => {
    const v = ea.mitreView({ techniques: [{ id: 'T1110', name: ' a\n\tb ' + 'c'.repeat(500) }], tactics: ['x'.repeat(500)] });
    assert.ok(v.techniques[0].name.startsWith('a b c') && v.techniques[0].name.length === 200); assert.strictEqual(v.tactics[0].length, 100);
    assert.strictEqual(ea.mitreView({ techniques: Array.from({ length: 50 }, (_, i) => ({ id: 'T' + (1000 + i) })), tactics: Array.from({ length: 50 }, (_, i) => 't' + i) }).techniques.length, ea.MAX_ALERT_TECHNIQUES);
  });
});

describe('mitreForGroups', () => {
  it('reads the groups\' sample events in one batch and returns the union per group, only for groups that have any', async () => {
    const store = new MemoryEventStore(); const a = alertEvent({ mitre: BF }), b = alertEvent({ mitre: FIM }), c = alertEvent({ ruleId: '1' });
    await store.insertBatch(TENANT, [a, b, c]);
    let reads = 0; const real = store.getByIds.bind(store); store.getByIds = (...x) => { reads += 1; return real(...x); };
    const m = await ea.mitreForGroups(store, TENANT, [{ gkey: 'g1', sample_ids: [a.id, b.id] }, { gkey: 'g2', sample_ids: [c.id] }, { gkey: 'g3', sample_ids: [] }, { gkey: 'g4' }]);
    assert.strictEqual(reads, 1); assert.deepStrictEqual([...m.keys()], ['g1']);
    assert.deepStrictEqual(m.get('g1'), { techniques: [{ id: 'T1110', name: 'Brute Force' }, { id: 'T1565.001', name: 'Stored Data Manipulation' }], tactics: ['Credential Access', 'Impact'] });
  });
  it('an event that is gone is simply not counted; no rows is an empty answer; a failing store throws (the caller decides)', async () => {
    const store = new MemoryEventStore(); const a = alertEvent({ mitre: BF }); await store.insertBatch(TENANT, [a]);
    const m = await ea.mitreForGroups(store, TENANT, [{ gkey: 'g', sample_ids: [a.id, '99999999-9999-4999-8999-999999999999'] }]); assert.strictEqual(m.get('g').techniques.length, 1);
    assert.strictEqual((await ea.mitreForGroups(store, TENANT, [])).size, 0);
    store.getByIds = async () => { throw new Error('down'); }; await assert.rejects(() => ea.mitreForGroups(store, TENANT, [{ gkey: 'g', sample_ids: [a.id] }]), /down/);
  });
  it('reads in batches of at most 500 ids', async () => {
    const store = new MemoryEventStore(), sizes = []; store.getByIds = async (t, ids) => { sizes.push(ids.length); return []; };
    const rows = Array.from({ length: 260 }, (_, i) => ({ gkey: 'g' + i, sample_ids: [1, 2, 3, 4].map((k) => `00000000-0000-4000-8000-${String(i * 4 + k).padStart(12, '0')}`) }));
    await ea.mitreForGroups(store, TENANT, rows); assert.deepStrictEqual(sizes, [500, 500, 40]);
  });
});

// ---- the rule runner -----------------------------------------------------------------------------------------------------------------------------------
describe('evaluateRule: ASIX alerts from endpoint alerts carry MITRE details', () => {
  let store, quiet;
  before(() => { quiet = console.error; });
  after(() => { console.error = quiet; setEventStore(null); });
  // A database client that has no existing alerts (or one active alert) and records every write.
  const fakeClient = ({ existing = false } = {}) => { const w = { inserts: [], updates: [] }; return { w, query: async (sql, params) => {
    if (sql.includes('INSERT INTO alerts')) { w.inserts.push(params); return { rows: [] }; }
    if (sql.includes('UPDATE alerts')) { w.updates.push(params); return { rows: [] }; }
    if (sql.includes('SELECT id FROM alerts')) return { rows: existing ? [{ id: 'existing-alert' }] : [] };
    return { rows: [] };
  } }; };
  const rule = (o = {}) => ({ id: 'rule-1', name: HIGH.name, description: HIGH.description, severity: HIGH.severity, kind: HIGH.kind, category: HIGH.category, definition: { ...HIGH.definition, ...o } });
  const detailsOf = (params) => JSON.parse(params[10]);
  const fresh = async (events) => { store = new MemoryEventStore(); setEventStore(store); if (events.length) await store.insertBatch(TENANT, events); };

  it('the high rule: the alert details hold the techniques and tactics of the endpoint alert it was raised from', async () => {
    await fresh([alertEvent({ level: 10, mitre: BF })]); const c = fakeClient();
    const r = await evaluateRule(c, TENANT, rule()); assert.strictEqual(r.created, 1);
    const d = detailsOf(c.w.inserts[0]);
    assert.deepStrictEqual(d.mitre, { techniques: [{ id: 'T1110', name: 'Brute Force' }], tactics: ['Credential Access'] });
    assert.strictEqual(d.group_by, 'field:alert_key'); assert.ok(d.sample_event_ids.length === 1);   // the rest of the details are as before
  });
  it('several events in one group give the union; each group gets its own', async () => {
    await fresh([alertEvent({ level: 10, ruleId: '5763', mitre: BF }), alertEvent({ level: 10, ruleId: '5763', mitre: FIM }), alertEvent({ level: 9, ruleId: '5710', agent: 'db1', mitre: { id: ['T1078'], technique: ['Valid Accounts'], tactic: ['Initial Access'] } })]);
    const c = fakeClient(); await evaluateRule(c, TENANT, rule());
    const by = Object.fromEntries(c.w.inserts.map((p) => [p[6], detailsOf(p)]));
    assert.deepStrictEqual(Object.keys(by).sort(), ['5710 on db1', '5763 on web1']);
    assert.deepStrictEqual(by['5763 on web1'].mitre.techniques.map((t) => t.id).sort(), ['T1110', 'T1565.001']); assert.deepStrictEqual(by['5763 on web1'].mitre.tactics.sort(), ['Credential Access', 'Impact']);
    assert.deepStrictEqual(by['5710 on db1'].mitre.techniques.map((t) => t.id), ['T1078']);
  });
  it('an endpoint alert with no ATT&CK mapping gives an alert with no mitre key (the details are exactly as before)', async () => {
    await fresh([alertEvent({ level: 10 })]); const c = fakeClient(); await evaluateRule(c, TENANT, rule());
    assert.ok(!('mitre' in detailsOf(c.w.inserts[0])));
  });
  it('an alert that already exists is updated with the details, MITRE included', async () => {
    await fresh([alertEvent({ level: 10, mitre: FIM })]); const c = fakeClient({ existing: true }); const r = await evaluateRule(c, TENANT, rule());
    assert.deepStrictEqual([r.updated, r.created, c.w.inserts.length], [1, 0, 0]); assert.strictEqual(JSON.parse(c.w.updates[0][3]).mitre.techniques[0].id, 'T1565.001');
  });
  it('a rule on another source type never reads events for MITRE', async () => {
    await fresh([alertEvent({ level: 10, mitre: BF, sourceType: 'syslog' })]); let reads = 0; const real = store.getByIds.bind(store); store.getByIds = (...x) => { reads += 1; return real(...x); };
    const c = fakeClient(); const r = await evaluateRule(c, TENANT, rule({ source_type: 'syslog', xql: 'rule_id = "5763"' }));
    assert.strictEqual(r.created, 1); assert.strictEqual(reads, 0); assert.ok(!('mitre' in detailsOf(c.w.inserts[0])));
  });
  it('a failing MITRE lookup never stops the alert: it is raised without MITRE and the failure is logged', async () => {
    await fresh([alertEvent({ level: 10, mitre: BF })]); const real = store.getByIds.bind(store); store.getByIds = async () => { throw new Error('store down'); };
    const logged = []; console.error = (...a) => logged.push(a.join(' ')); const c = fakeClient();
    try { const r = await evaluateRule(c, TENANT, rule()); assert.strictEqual(r.created, 1); assert.ok(!('mitre' in detailsOf(c.w.inserts[0]))); assert.ok(logged.some((l) => /MITRE lookup failed: store down/.test(l))); } finally { console.error = quiet; store.getByIds = real; }
  });
  it('no matching events: no lookup, no alert', async () => {
    await fresh([]); let reads = 0; store.getByIds = async () => { reads += 1; return []; }; const c = fakeClient(); const r = await evaluateRule(c, TENANT, rule());
    assert.deepStrictEqual([r.created, reads], [0, 0]);
  });
});

// ---- GET /v1/alerts/:id ---------------------------------------------------------------------------------------------------------------------------------
describe('GET /v1/alerts/:id shows the alert\'s MITRE details', () => {
  const sharedPath = require.resolve('../src/gateway/shared'), routePath = require.resolve('../src/gateway/routes/alerts');
  let server, base, store, alertRow = null; const ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const noop = (req, res, next) => next();
  before(async () => {
    require.cache[sharedPath] = { id: sharedPath, filename: sharedPath, loaded: true, exports: { db: { withTenant: async (t, fn) => fn({ query: async () => ({ rows: alertRow ? [alertRow] : [] }) }) },
      authMiddleware: noop, tenantMiddleware: noop, rbacMiddleware: () => noop, auditMiddleware: () => noop, brokerAuthMiddleware: noop, guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }],
      UUID_RE: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, SEVERITIES: ['critical', 'high', 'medium', 'low'], ALERT_STATUSES: ['open', 'acknowledged', 'closed'],
      apiError: (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } }) } };
    delete require.cache[routePath];
    store = new MemoryEventStore(); setEventStore(store);
    const app = express(); app.use(require('../src/gateway/routes/alerts'));
    await new Promise((res) => { server = app.listen(0, '127.0.0.1', res); }); base = 'http://127.0.0.1:' + server.address().port;
  });
  after(() => { server.close(); setEventStore(null); delete require.cache[routePath]; delete require.cache[sharedPath]; });
  const row = (details) => ({ id: ID, tenant_id: TENANT, rule_name: 'Endpoint security alert, high', severity: 'high', status: 'open', title: 't', details });
  const get = async () => { const r = await fetch(base + '/v1/alerts/' + ID); return { status: r.status, body: await r.json() }; };

  it('the techniques stored on the alert are shown, with links to ATT&CK pages and the tactics', async () => {
    alertRow = row({ sample_event_ids: [], mitre: { techniques: [{ id: 'T1110', name: 'Brute Force' }, { id: 'T1565.001', name: 'Stored Data Manipulation' }], tactics: ['Credential Access', 'Impact'] } });
    const r = await get(); assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(r.body.mitre, { techniques: [{ id: 'T1110', name: 'Brute Force', url: 'https://attack.mitre.org/techniques/T1110/' }, { id: 'T1565.001', name: 'Stored Data Manipulation', url: 'https://attack.mitre.org/techniques/T1565/001/' }], tactics: ['Credential Access', 'Impact'] });
  });
  it('an alert raised before this existed takes them from its sample events as they are now', async () => {
    const a = alertEvent({ mitre: FIM }); await store.insertBatch(TENANT, [a]); alertRow = row({ sample_event_ids: [a.id] });
    const r = await get(); assert.deepStrictEqual(r.body.mitre.techniques.map((t) => [t.id, t.name]), [['T1565.001', 'Stored Data Manipulation']]); assert.deepStrictEqual(r.body.mitre.tactics, ['Impact']);
  });
  it('an alert with none (other rules, no sample events) answers with empty lists, and the rest of the answer is as before', async () => {
    const plain = alertEvent({}); await store.insertBatch(TENANT, [plain]); alertRow = row({ sample_event_ids: [plain.id] });
    const r = await get(); assert.deepStrictEqual(r.body.mitre, { techniques: [], tactics: [] });
    assert.deepStrictEqual(Object.keys(r.body).sort(), ['alert', 'events', 'mitre', 'success']); assert.deepStrictEqual(Object.keys(r.body.events[0]).sort(), ['collector_id', 'event_time', 'id', 'raw', 'received_at', 'source_type']);
    alertRow = row(null); assert.deepStrictEqual((await get()).body.mitre, { techniques: [], tactics: [] });
  });
  it('hostile or malformed stored values are not trusted: no link for a bad id, wrong shapes ignored', async () => {
    alertRow = row({ mitre: { techniques: [{ id: 'javascript:alert(1)', name: '<img src=x onerror=alert(1)>' }, { id: 'T1110', name: 'Brute Force' }], tactics: ['<b>x</b>'] } });
    const m = (await get()).body.mitre; assert.deepStrictEqual(m.techniques.map((t) => t.url), [null, 'https://attack.mitre.org/techniques/T1110/']);
    alertRow = row({ mitre: 'T1110' }); assert.deepStrictEqual((await get()).body.mitre, { techniques: [], tactics: [] });
  });
  it('an unknown alert is still a 404 and a bad id a 400', async () => {
    alertRow = null; assert.strictEqual((await get()).status, 404);
    assert.strictEqual((await fetch(base + '/v1/alerts/not-an-id')).status, 400);
  });
});

// ---- the portal -------------------------------------------------------------------------------------------------------------------------------------------
describe('portal: the MITRE section of an alert', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
  const line = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head); return html.slice(i, html.indexOf('\n', i)); };
  const cut = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head); return html.slice(i, html.indexOf('\n}\n', i) + 3); };
  const source = [line('const EP_MITRE_URL'), line('const epMitreLink'), cut('function alertMitre')].join('\n');
  const el = (tag, attrs, ...kids) => Object.assign({}, attrs || {}, { tag, attrs: attrs || {}, kids: kids.flat(Infinity) });
  const walk = (n) => (typeof n === 'string' ? [n] : n && typeof n === 'object' ? [n, ...(n.kids || []).flatMap(walk)] : []);
  const table = (cols, rows) => el('table', {}, rows.map((r) => el('tr', {}, cols.map((c) => { const v = c.f(r); return typeof v === 'object' && v ? el('td', {}, v) : el('td', { textContent: String(v) }); }))));
  const alertMitre = new Function('el', 'table', source + '\nreturn alertMitre;')(el, table);
  const text = (n) => walk(n).map((x) => (typeof x === 'string' ? x : x.textContent || '')).join(' | ');
  const links = (n) => walk(n).filter((x) => x.tag === 'a');

  it('draws nothing for an alert with no MITRE details (and for a missing or odd value)', () => {
    for (const m of [undefined, null, {}, { techniques: [], tactics: [] }, { techniques: null, tactics: null }]) assert.strictEqual(alertMitre(m), '');
  });
  it('shows the techniques with names and a link, and the tactics', () => {
    const n = alertMitre({ techniques: [{ id: 'T1110', name: 'Brute Force', url: 'https://attack.mitre.org/techniques/T1110/' }, { id: 'T1565.001', name: null, url: 'https://attack.mitre.org/techniques/T1565/001/' }], tactics: ['Credential Access', 'Impact'] });
    const t = text(n); assert.match(t, /MITRE ATT&CK/); assert.match(t, /Brute Force/); assert.match(t, /Credential Access/); assert.match(t, /Impact/);
    assert.deepStrictEqual(links(n).map((a) => [a.attrs.href, a.attrs.target, a.attrs.rel]), [['https://attack.mitre.org/techniques/T1110/', '_blank', 'noopener noreferrer'], ['https://attack.mitre.org/techniques/T1565/001/', '_blank', 'noopener noreferrer']]);
  });
  it('a link only for a real ATT&CK technique address; the id stays visible as text otherwise', () => {
    for (const url of ['javascript:alert(1)', 'https://attack.mitre.org.evil.example/techniques/T1110/', 'http://attack.mitre.org/techniques/T1110/', null, '']) {
      const n = alertMitre({ techniques: [{ id: 'T1110', name: 'x', url }], tactics: [] }); assert.strictEqual(links(n).length, 0, String(url)); assert.match(text(n), /T1110/);
    }
  });
  it('tactics alone are enough to draw the section; values stay text', () => {
    const n = alertMitre({ techniques: [], tactics: ['<img src=x onerror=alert(1)>'] }); assert.match(text(n), /<img src=x onerror=alert\(1\)>/); assert.ok(!walk(n).some((x) => x.tag === 'img')); assert.ok(!/Technique/.test(text(n)));
  });
  it('the alert page asks for it: openAlert reads mitre from the answer and puts the section in the card', () => {
    const open = cut('async function openAlert');
    assert.match(open, /const \{ alert: a, events, mitre \} = await api\('\/v1\/alerts\/' \+ id\)/); assert.match(open, /alertMitre\(mitre\)/);
  });
});

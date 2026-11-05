'use strict';
// E6t: alerts per machine. 1. the pure part (plan, counts); 2. GET /v1/endpoints/alerts/by-machine over the in-memory event store with the REAL default parsing rules, two tenants;
// 3. the Agents tab's "Alerts (n)" link (src/portal/index.html, pgEndpoints) cut out of the page and run with small stand-ins.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const express = require('express');
const alerts = require('../src/endpoints/endpoint-alerts');
const { validatePlan } = require('../src/search/xql-plan');
const { compile, apply } = require('../src/ingestion/parsing-rules');
const { jsonEvent } = require('../src/ingest/http-ingest');
const { MemoryEventStore } = require('../src/events/memory-store');
const { setEventStore } = require('../src/events');
const F = require('./fixtures/wazuh-alerts');

const root = path.join(__dirname, '..');
const T1 = '11111111-1111-4111-8111-111111111111', T2 = '22222222-2222-4222-8222-222222222222';
const defaults = compile(require('../src/ingestion/default-parsing-rules'));

describe('machinePlan and machineCounts', () => {
  it('the plan is valid, counts by the agent name, and has no filter but the window', () => {
    const f = alerts.parseQuery({ window: '7d' }); const plan = alerts.machinePlan(f);
    assert.doesNotThrow(() => validatePlan(plan)); assert.strictEqual(plan.mode, 'comp'); assert.deepStrictEqual(plan.stages[1].by, ['agent_name']); assert.strictEqual(plan.stages.length, 2);
    assert.strictEqual(plan.from, f.from); assert.strictEqual(plan.limit, alerts.MACHINE_ROWS);
  });
  it('counts most first with name order on ties, adds duplicate names, cuts names to 200, and skips nameless rows and bad counts', () => {
    const r = alerts.machineCounts([{ agent_name: 'b', n: '2' }, { agent_name: 'a', n: 2 }, { agent_name: 'c', n: 9 }, { agent_name: 'a', n: 1 }, { agent_name: '', n: 5 }, { agent_name: null, n: 5 }, { agent_name: 'x', n: 'many' }, { agent_name: 'y', n: -1 }, { agent_name: 'z', n: 1.5 }, { agent_name: 'q'.repeat(300), n: 1 }]);
    assert.deepStrictEqual(r.slice(0, 3), [{ name: 'c', count: 9 }, { name: 'a', count: 3 }, { name: 'b', count: 2 }]);
    assert.deepStrictEqual(r.map((x) => x.name.length), [1, 1, 1, 200]); assert.deepStrictEqual(alerts.machineCounts(undefined), []);
  });
});

const flat = (a) => { const m = a.rule.mitre || {};
  return { rule_id: a.rule.id, alert_level: a.rule.level, alert_name: a.rule.description, mitre_ids: (m.id || []).join(','), agent_id: a.agent.id, agent_name: a.agent.name, agent_ip: a.agent.ip, manager_name: a.manager.name, full_log: a.full_log || '' }; };
let seq = 0;
function eventOf(a, { minsAgo = 5, sourceType = 'endpoint-alert' } = {}) {
  const time = new Date(Date.now() - minsAgo * 60000).toISOString();
  const x = jsonEvent({ message: '[Endpoint alert] rule ' + a.rule.id, time, host: a.agent.name, fields: flat(a) }, 'broker-test');
  const out = apply([defaults.rules], { source_type: sourceType, raw: x.raw, time: x.time, parsed: x.parsed });
  seq += 1;
  return { id: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`, source_type: sourceType, collector_id: 'broker-test', received_at: time, event_time: time, raw: x.raw, parsed: out.parsed };
}
const mk = (level, agent) => F.base({ agent: { id: '002', name: agent, ip: '10.0.0.30' }, rule: { level, id: '5763', description: 'rule', groups: ['syslog'], mitre: {} }, id: 'ref' });

describe('GET /v1/endpoints/alerts/by-machine', () => {
  const sharedPath = require.resolve('../src/gateway/shared');
  const perms = []; let tenant = T1, server, base, store;
  const put = (p, exports) => { require.cache[p] = { id: p, filename: p, loaded: true, exports }; };
  before(async () => {
    put(sharedPath, { db: {}, UUID_RE: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, apiError: (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } }),
      guarded: (perm) => { perms.push(perm); return [(req, res, next) => { req.tenant_id = tenant; next(); }]; } });
    store = new MemoryEventStore(); setEventStore(store);
    const add = async (t, level, agent, o) => store.insertBatch(t, [eventOf(mk(level, agent), o)]);
    for (let i = 0; i < 3; i++) await add(T1, 10, 'web1', { minsAgo: 1 + i });
    await add(T1, 5, 'db1', { minsAgo: 2 }); await add(T1, 5, 'db1', { minsAgo: 60 * 24 * 3 });      // one in the window, one three days old
    await add(T1, 12, 'web1', { minsAgo: 3, sourceType: 'syslog' });                                  // same shape, not an endpoint alert
    await add(T2, 12, 'secret-host', { minsAgo: 1 });
    const app = express(); app.use(require('../src/gateway/routes/alert-machines')); app.use(require('../src/gateway/routes/endpoint-alerts'));
    await new Promise((res) => { server = app.listen(0, '127.0.0.1', res); }); base = 'http://127.0.0.1:' + server.address().port;
  });
  after(() => { server.close(); setEventStore(null); for (const m of ['alert-machines', 'endpoint-alerts']) delete require.cache[require.resolve('../src/gateway/routes/' + m)]; delete require.cache[sharedPath]; });
  const get = async (q = '') => { const r = await fetch(base + '/v1/endpoints/alerts/by-machine' + q); return { status: r.status, body: await r.json() }; };

  it('asks for search:events:read, is GET only, and is mounted before the /alerts/:id route', () => {
    assert.ok(perms.includes('search:events:read') && perms.every((p) => p === 'search:events:read'));
    const src = fs.readFileSync(path.join(root, 'src/gateway/routes/alert-machines.js'), 'utf8'); assert.ok(!/router\.(post|put|patch|delete|all|use)\(/.test(src)); assert.strictEqual((src.match(/router\.get\(/g) || []).length, 1);
    const g = fs.readFileSync(path.join(root, 'src/gateway/index.js'), 'utf8'); assert.ok(g.indexOf("routes/alert-machines") > 0 && g.indexOf("routes/alert-machines") < g.indexOf("routes/endpoint-alerts"));
  });
  it('exact counts per machine in the last 24 hours, most first; no syslog event, no old alert, no other tenant', async () => {
    const { status, body } = await get(); assert.strictEqual(status, 200);
    assert.deepStrictEqual(body.machines, [{ name: 'web1', count: 3 }, { name: 'db1', count: 1 }]); assert.strictEqual(body.window, '24h'); assert.strictEqual(body.truncated, false);
    assert.ok(!JSON.stringify(body).includes('secret-host'));
    tenant = T2; try { assert.deepStrictEqual((await get()).body.machines, [{ name: 'secret-host', count: 1 }]); } finally { tenant = T1; }
  });
  it('a wider window brings the old alert back; only `window` is accepted; a bad window is a 400', async () => {
    assert.deepStrictEqual((await get('?window=7d')).body.machines, [{ name: 'web1', count: 3 }, { name: 'db1', count: 2 }]);
    for (const q of ['?agent=web1', '?limit=5', '?window=2d', '?window=24h&window=7d']) assert.strictEqual((await get(q)).status, 400, q);
  });
  it('the other alert routes still answer (an id is not taken for "by-machine")', async () => {
    assert.strictEqual((await fetch(base + '/v1/endpoints/alerts')).status, 200); assert.strictEqual((await fetch(base + '/v1/endpoints/alerts/not-a-uuid')).status, 400);
  });
  it('a failing store gives a 500 without its message', async () => {
    const real = store.search.bind(store); store.search = async () => { throw new Error('secret db detail'); }; const log = console.error; console.error = () => {};
    try { const r = await get(); assert.strictEqual(r.status, 500); assert.ok(!JSON.stringify(r.body).includes('secret db detail')); } finally { console.error = log; store.search = real; }
  });
});

// ---- the Agents tab ----
const html = fs.readFileSync(path.join(root, 'src', 'portal', 'index.html'), 'utf8');
const i1 = html.indexOf('async function pgEndpoints'), j = html.indexOf('\n}\n', i1);
const pageSource = html.slice(html.indexOf('const EP_STATUS ='), i1) + html.slice(i1, j + 3);
const el = (tag, attrs, ...kids) => Object.assign({}, attrs || {}, { tag, attrs: attrs || {}, kids: kids.flat(Infinity), replaceChildren(...k) { this.kids = k.flat(Infinity); }, append(...k) { this.kids.push(...k.flat(Infinity)); } });
const walk = (n) => (typeof n === 'string' ? [n] : n && typeof n === 'object' ? (Array.isArray(n) ? n.flatMap(walk) : [n, ...(n.kids || []).flatMap(walk)]) : []);
const nodes = (t) => walk(t).filter((n) => n && typeof n === 'object' && n.attrs);
const card = (title, ...kids) => el('div', { className: 'card' }, title ? el('h3', { textContent: title }) : '', ...kids);
const pill = (t, c) => el('span', { className: 'pill ' + (c || 'off'), textContent: t });
const kv = (o) => el('div', {}, Object.entries(o).map(([k, v]) => el('div', {}, el('span', { textContent: k }), el('span', { textContent: String(v) }))));
const when = (v) => (v ? String(v) : '-');
const table = (cols, rows, empty) => (!rows.length ? el('div', { className: 'mute', textContent: empty || 'Nothing to show yet.' })
  : el('table', {}, el('tr', {}, cols.map((c) => el('th', { textContent: c.h }))), rows.map((r) => el('tr', {}, cols.map((c) => { const v = c.f(r); return typeof v === 'object' && v ? el('td', {}, v) : el('td', { textContent: String(v) }); })))));
const tick = async () => { for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r)); };
const agent = (id, name) => ({ id, name, ip: '10.0.0.' + Number(id), register_ip: 'any', status: 'active', version: 'v4.14.9', groups: ['default'], last_keep_alive: '2026-10-25T19:00:00Z', date_added: '2026-10-20T10:00:00Z', node: 'n', manager: 'm', os: { name: 'Ubuntu', version: '22.04', platform: 'ubuntu' } });
const LIST = { total: 3, limit: 50, offset: 0, agents: [agent('001', 'web01'), agent('002', 'db01'), agent('003', 'quiet01')] };
const MANAGER = { available: true, registered: true, label: 'lab', host: 'h', port: 55000, api_user: 'u', cert_sha256: 'x', updated_at: '2026-10-25T18:49:08Z', status: { reachable: true, version: 'v4.14.9', max_agents: 'unlimited', timezone: 'UTC' } };

async function open(counts) {
  const calls = [];
  const api = async (p) => {
    calls.push(p);
    if (p === '/v1/endpoints/manager') return { success: true, manager: MANAGER };
    if (p === '/v1/endpoints/agents/summary') return { success: true, summary: { active: 3, disconnected: 0, never_connected: 0, pending: 0, total: 3 } };
    if (p.startsWith('/v1/endpoints/agents?')) return { success: true, ...LIST };
    if (p.startsWith('/v1/endpoints/alerts/by-machine')) { if (counts instanceof Error) throw counts; return counts; }
    throw new Error('unexpected call ' + p);
  };
  const fn = new Function('el', 'card', 'pill', 'table', 'kv', 'when', 'api', 'route', 'copyBtn', pageSource + '\nreturn pgEndpoints;')(el, card, pill, table, kv, when, api, () => {}, () => el('button'));
  const tree = await fn(); await tick();
  const tab = nodes(tree).find((n) => /xtab/.test(n.attrs.className || '') && n.attrs.textContent === 'Agents'); if (tab) { await tab.attrs.onclick(); await tick(); }
  const links = () => nodes(tree).filter((n) => n.attrs.title === 'Open the alerts of this machine').map((n) => n.attrs.textContent);
  return { calls, links };
}

describe('the Agents tab \"Alerts (n)\" link', () => {
  it('shows the 24-hour count of each machine, 0 for a machine with no alerts, from one request for the window the link opens', async () => {
    const p = await open({ success: true, window: '24h', machines: [{ name: 'web01', count: 12 }, { name: 'db01', count: 1 }], truncated: false });
    assert.deepStrictEqual(p.links(), ['Alerts (12)', 'Alerts (1)', 'Alerts (0)']);
    assert.deepStrictEqual(p.calls.filter((c) => c.includes('by-machine')), ['/v1/endpoints/alerts/by-machine?window=24h']);
  });
  it('a refused or failing count (no permission, server error, an odd answer) leaves the plain links', async () => {
    assert.deepStrictEqual((await open(new Error('403'))).links(), ['Alerts', 'Alerts', 'Alerts']);
    assert.deepStrictEqual((await open({ success: true })).links(), ['Alerts', 'Alerts', 'Alerts']);
  });
  it('when the store held more machine names than were read, a machine not in the list gets the plain link, not a false 0', async () => {
    const p = await open({ success: true, machines: [{ name: 'web01', count: 4 }], truncated: true });
    assert.deepStrictEqual(p.links(), ['Alerts (4)', 'Alerts', 'Alerts']);
  });
  it('the count does not change what the link does: it still opens the Alerts tab on that machine name', async () => {
    const src = pageSource; assert.ok(/onclick: \(\) => openAlerts\(a\.name\)/.test(src));
  });
});

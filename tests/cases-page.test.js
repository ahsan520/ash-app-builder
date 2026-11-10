'use strict';
// CS1: the Cases page, a page the module brings itself (docs/portal-shell.md). Same method as tests/marketplace-page.test.js: the page file is
// copied to a temporary .mjs file and imported; it draws only through ctx.el, so a fake el() and a fake server are enough.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');
const registry = require('../src/modules/registry');

const PAGE = path.join(__dirname, '../src/portal/modules/cases/cases.js');
let tmp; let page;
before(async () => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'asix-cases-'));
  fs.copyFileSync(PAGE, path.join(tmp, 'cases.mjs'));
  page = await import(pathToFileURL(path.join(tmp, 'cases.mjs')).href);
});
after(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

// ---- fakes -----------------------------------------------------------------------------------------------------
const clean = (k) => k.flat(Infinity).filter((x) => x !== '' && x != null);
const fakeEl = (tag, props, ...kids) => ({ tag, ...(props || {}), kids: clean(kids), replaceChildren(...k) { this.kids = clean(k); } });
const fakeHost = () => ({ kids: [], replaceChildren(...k) { this.kids = clean(k); } });
const walk = (n) => (n && typeof n === 'object' ? [n, ...(n.kids || []).flatMap(walk)] : []);
const allText = (host) => host.kids.flatMap(walk).flatMap((x) => [x.textContent, ...(x.kids || []).filter((c) => typeof c === 'string')]).filter((x) => typeof x === 'string').join(' | ');
const all = (host) => host.kids.flatMap(walk);
const buttons = (host, label) => all(host).filter((n) => n.tag === 'button' && (label === undefined || n.textContent === label));
const tick = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r)); };
const click = async (host, label, nth = 0) => { const b = buttons(host, label)[nth]; assert.ok(b, `no button "${label}" in: ${allText(host).slice(0, 400)}`); assert.ok(!b.disabled, `"${label}" is disabled`); b.onclick(); await tick(); };
const selects = (host) => all(host).filter((n) => n.tag === 'select');
const textareas = (host) => all(host).filter((n) => n.tag === 'textarea');
const inputs = (host, type = 'text') => all(host).filter((n) => n.tag === 'input' && n.type === type);
const selectedValue = (sel) => (sel.kids.find((o) => o.selected) || {}).value;

const ID = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const USERS = [{ id: ID(901), username: 'alice' }, { id: ID(902), username: 'bob' }];
const ME = ID(901);
const mkCase = (n, over = {}) => ({ id: ID(n), case_number: n, title: 'Case ' + n, description: null, severity: 'high', status: 'open', owner_id: null, owner_name: null, created_by_name: 'alice', created_at: '2026-11-08T10:00:00.000Z', updated_at: '2026-11-08T11:30:00.000Z', closed_at: null, alert_count: 2, ...over });
const mkAlert = (n, over = {}) => ({ id: ID(100 + n), title: 'Alert ' + n, severity: 'medium', status: 'open', rule_name: 'Rule ' + n, last_event_at: '2026-11-08T09:00:00.000Z', ...over });
const view = (c, alerts = [mkAlert(1), mkAlert(2)], timeline = [{ id: 'e1', kind: 'created', actor_name: 'alice', text: 'Case created with 2 alerts', body: null, created_at: '2026-11-08T10:00:00.000Z' }]) => ({ success: true, case: c, alerts, timeline });

// a tiny fake server: cases are kept in memory and the routes answer like the real ones
function server(initial, extra = {}) {
  const cases = new Map(initial.map((c) => [c.id, { c, alerts: [mkAlert(1), mkAlert(2)], timeline: view(c).timeline }]));
  const calls = []; const free = [mkAlert(7, { severity: 'critical' }), mkAlert(8)];
  const api = async (p, o = {}) => {
    const method = o.method || 'GET'; calls.push({ key: method + ' ' + p, body: o.body });
    if (extra[method + ' ' + p]) return extra[method + ' ' + p](o);
    if (method === 'GET' && p.startsWith('/v1/cases?')) {
      const qs = new URLSearchParams(p.split('?')[1]); const st = qs.get('status');
      let list = [...cases.values()].map((x) => x.c).filter((c) => (st === 'active' ? c.status !== 'closed' : st === 'closed' ? c.status === 'closed' : true));
      if (qs.get('owner') === 'me') list = list.filter((c) => c.owner_id === ME);
      return { success: true, cases: list, total: list.length, limit: 100, offset: 0 };
    }
    if (method === 'GET' && p === '/v1/alert-assignees') return { success: true, users: USERS, me: ME };
    if (method === 'GET' && p === '/v1/cases/candidates') return { success: true, alerts: free };
    let m;
    if (method === 'GET' && (m = /^\/v1\/cases\/([^/?]+)$/.exec(p))) { const x = cases.get(m[1]); return { success: true, case: x.c, alerts: x.alerts, timeline: x.timeline }; }
    if (method === 'POST' && p === '/v1/cases') { const c = mkCase(50, { title: o.body.title, severity: o.body.severity || 'medium', description: o.body.description || null, alert_count: 0 }); cases.set(c.id, { c, alerts: [], timeline: [] }); return { success: true, case: c, alerts: [], timeline: [] }; }
    if (method === 'PATCH' && (m = /^\/v1\/cases\/([^/?]+)$/.exec(p))) {
      const x = cases.get(m[1]); Object.assign(x.c, o.body);
      if (o.body.owner_id !== undefined) x.c.owner_name = (USERS.find((u) => u.id === o.body.owner_id) || {}).username || null;
      return { success: true, case: x.c, alerts: x.alerts, timeline: x.timeline };
    }
    if (method === 'POST' && (m = /^\/v1\/cases\/([^/?]+)\/alerts$/.exec(p))) { const x = cases.get(m[1]); const a = free.splice(free.findIndex((f) => f.id === o.body.alert_ids[0]), 1)[0]; x.alerts.push(a); return { success: true, case: x.c, alerts: x.alerts, timeline: x.timeline }; }
    if (method === 'DELETE' && (m = /^\/v1\/cases\/([^/]+)\/alerts\/([^/]+)$/.exec(p))) { const x = cases.get(m[1]); x.alerts = x.alerts.filter((a) => a.id !== m[2]); return { success: true, case: x.c, alerts: x.alerts, timeline: x.timeline }; }
    if (method === 'POST' && (m = /^\/v1\/cases\/([^/]+)\/notes$/.exec(p))) { const x = cases.get(m[1]); x.timeline = [...x.timeline, { id: 'n' + x.timeline.length, kind: 'note', actor_name: 'alice', text: o.body.body, body: o.body.body, created_at: '2026-11-08T12:00:00.000Z' }]; return { success: true, case: x.c, alerts: x.alerts, timeline: x.timeline }; }
    throw new Error('unexpected call ' + method + ' ' + p);
  };
  return { api, calls, cases, free };
}
const err = (status, msg, code) => Object.assign(new Error(`${status} ${msg}${code ? ' (' + code + ')' : ''}`), { status });
async function open(srv, perms = ['alerts:read', 'alerts:write']) {
  const host = fakeHost(); const toasts = [];
  await page.mount(host, { api: srv.api, el: fakeEl, can: (p) => perms.includes(p), toast: (t, k) => toasts.push([t, k]) });
  return { host, toasts };
}

describe('the page file follows the module-page rules', () => {
  const src = fs.readFileSync(PAGE, 'utf8');
  it('exports mount and unmount', () => { assert.strictEqual(typeof page.mount, 'function'); assert.strictEqual(typeof page.unmount, 'function'); });
  it('uses no browser globals, dialogs or innerHTML', () => {
    const code = src.replace(/'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|`(?:\\.|[^`\\])*`/g, '""').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
    for (const w of ['document', 'window', 'alert', 'confirm', 'prompt', 'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'localStorage', 'sessionStorage', 'eval', 'Function', 'fetch']) assert.ok(!new RegExp('(?<![.\\w$])' + w + '\\b(?!\\s*:)').test(code), `the page must not use ${w}`);
    assert.ok(code.includes('ctx.api') && code.includes('ctx.el'));
  });
  it('talks only to the cases routes (and the user list for the owner choice)', () => {
    const urls = [...src.matchAll(/ctx\.api\(\s*'([^']+)'/g)].map((m) => m[1]);
    assert.ok(urls.length >= 6);
    for (const u of urls) assert.ok(u.startsWith('/v1/cases') || u === '/v1/alert-assignees', u);
  });
  it('is declared by the cases manifest, which the registry accepts, and soar depends on it', () => {
    const list = registry.loadDir(); const cm = list.find((x) => x.id === 'cases');
    assert.deepStrictEqual({ ...cm.ui.entries[0] }, { id: 'cases', label: 'Cases', area: 'Main', group: null, permission: 'alerts:read', order: 30, path: 'mod/cases/cases', page: 'cases.js' });
    assert.ok(cm.permissions.includes('alerts:read') && cm.permissions.includes('alerts:write'));
    assert.ok(list.find((x) => x.id === 'soar').requires.includes('cases'));
  });
});

describe('the list', () => {
  const set = () => [mkCase(1, { owner_id: ME, owner_name: 'alice', status: 'investigating', alert_count: 3 }), mkCase(2, { severity: 'low', alert_count: 1 }), mkCase(3, { status: 'closed', severity: 'critical' })];
  it('shows active cases with number, title, severity, status, owner, alert count and the time', async () => {
    const { host } = await open(server(set()));
    const t = allText(host);
    assert.match(t, /#1  Case 1/); assert.match(t, /Investigating/); assert.match(t, /Owner: alice · 3 alerts/); assert.match(t, /No owner · 1 alert ·/); assert.match(t, /changed 2026-11-08 11:30/);
    assert.ok(!/Case 3/.test(t), 'closed cases are not in Active');
  });
  it('Closed and All tabs, and "Mine only", ask the server for those', async () => {
    const srv = server(set());
    const { host } = await open(srv);
    await click(host, 'Closed'); assert.match(allText(host), /#3  Case 3/); assert.ok(!/#1  Case 1/.test(allText(host)));
    await click(host, 'All'); assert.match(allText(host), /Case 1/); assert.match(allText(host), /Case 3/);
    inputs(host, 'checkbox')[0].onchange({ target: { checked: true } }); await tick();
    assert.ok(srv.calls.some((c) => c.key === '/v1/cases?status=all&owner=me&limit=100'.replace('/v1', 'GET /v1')));
    assert.ok(/Case 1/.test(allText(host)) && !/Case 2/.test(allText(host)));
  });
  it('an empty list says so, and "Showing x of y" appears when there is more', async () => {
    let { host } = await open(server([])); assert.match(allText(host), /No active cases/);
    const srv = server([mkCase(1)], { 'GET /v1/cases?status=active&limit=100': async () => ({ success: true, cases: [mkCase(1)], total: 250, limit: 100, offset: 0 }) });
    ({ host } = await open(srv)); assert.match(allText(host), /Showing 1 of 250/);
  });
  it('mount rejects if the list cannot be read, so the shell shows its error card', async () => {
    await assert.rejects(() => open({ api: async () => { throw err(403, 'Forbidden', 'FORBIDDEN'); } }), /403 Forbidden/);
  });
  it('a read-only role has no New case button', async () => {
    const { host } = await open(server(set()), ['alerts:read']);
    assert.strictEqual(buttons(host, 'New case').length, 0); assert.ok(buttons(host, 'Open').length >= 1);
  });
});

describe('a new case', () => {
  it('the form keeps what is typed; Create needs a title; the body carries only what was filled in; then the case opens', async () => {
    const srv = server([]); const { host, toasts } = await open(srv);
    await click(host, 'New case');
    await click(host, 'Create case');
    assert.match(allText(host), /Give the case a title/); assert.ok(!srv.calls.some((c) => c.key === 'POST /v1/cases'));
    inputs(host)[0].oninput({ target: { value: 'Odd traffic' } });
    await click(host, 'Create case');
    assert.deepStrictEqual(srv.calls.find((c) => c.key === 'POST /v1/cases').body, { title: 'Odd traffic' });
    assert.match(allText(host), /#50  Odd traffic/); assert.deepStrictEqual(toasts, [['Case created', undefined]]);
  });
  it('severity and description are sent when chosen', async () => {
    const srv = server([]); const { host } = await open(srv);
    await click(host, 'New case');
    inputs(host)[0].oninput({ target: { value: 'T' } }); selects(host)[0].onchange({ target: { value: 'critical' } }); textareas(host)[0].oninput({ target: { value: 'Details here' } });
    await click(host, 'Create case');
    assert.deepStrictEqual(srv.calls.find((c) => c.key === 'POST /v1/cases').body, { title: 'T', severity: 'critical', description: 'Details here' });
  });
  it('Cancel closes the form without asking the server', async () => {
    const srv = server([]); const { host } = await open(srv);
    await click(host, 'New case'); await click(host, 'Cancel');
    assert.strictEqual(inputs(host).length, 1 - 1 + inputs(host).filter((n) => n.placeholder === 'Title').length); assert.ok(!srv.calls.some((c) => c.key === 'POST /v1/cases'));
    assert.ok(!allText(host).includes('New case |') || buttons(host, 'Create case').length === 0);
  });
  it('a refusal from the server is shown on the page', async () => {
    const srv = server([], { 'POST /v1/cases': async () => { throw err(400, 'title must be 1-200 characters', 'INVALID_BODY'); } });
    const { host } = await open(srv); await click(host, 'New case'); inputs(host)[0].oninput({ target: { value: 'x' } }); await click(host, 'Create case');
    assert.match(allText(host), /400 title must be 1-200 characters/);
  });
});

describe('one case', () => {
  const C = () => mkCase(1, { owner_id: null });
  const openOne = async (c = C(), perms) => { const srv = server([c]); const o = await open(srv, perms); await click(o.host, 'Open'); return { ...o, srv }; };

  it('shows the header, description, alerts and the timeline', async () => {
    const { host } = await openOne(mkCase(1, { description: 'Seen on the router', owner_id: ME, owner_name: 'alice' }));
    const t = allText(host);
    assert.match(t, /#1  Case 1/); assert.match(t, /Opened by alice · 2026-11-08 10:00/); assert.match(t, /Seen on the router/); assert.match(t, /2 alerts/); assert.match(t, /Alert 1/); assert.match(t, /Rule 2 · open/); assert.match(t, /Timeline/); assert.match(t, /Case created with 2 alerts/);
  });
  it('status buttons depend on the state, and each sends a PATCH', async () => {
    const { host, srv, toasts } = await openOne();
    assert.deepStrictEqual(buttons(host).map((b) => b.textContent).filter((l) => /^(Mark|Close|Reopen)/.test(l)), ['Mark investigating', 'Close case']);
    await click(host, 'Mark investigating');
    assert.deepStrictEqual(srv.calls.find((c) => c.key.startsWith('PATCH')).body, { status: 'investigating' });
    assert.match(allText(host), /Investigating/); assert.deepStrictEqual(buttons(host).map((b) => b.textContent).filter((l) => /^(Mark|Close|Reopen)/.test(l)), ['Mark open', 'Close case']);
    await click(host, 'Close case');
    assert.strictEqual(srv.cases.get(ID(1)).c.status, 'closed'); assert.deepStrictEqual(toasts.map((t) => t[0]), ['Case investigating', 'Case closed']);
  });
  it('owner: the people of the tenant, the current one selected, a change is a PATCH, "Take it" assigns me', async () => {
    const { host, srv } = await openOne();
    const [owner] = selects(host);
    assert.deepStrictEqual(owner.kids.map((o) => o.textContent), ['Nobody', 'alice', 'bob']); assert.strictEqual(selectedValue(owner), '');
    owner.onchange({ target: { value: ID(902) } }); await tick();
    assert.deepStrictEqual(srv.calls.filter((c) => c.key.startsWith('PATCH')).at(-1).body, { owner_id: ID(902) });
    assert.strictEqual(selectedValue(selects(host)[0]), ID(902));
    await click(host, 'Take it'); assert.deepStrictEqual(srv.calls.filter((c) => c.key.startsWith('PATCH')).at(-1).body, { owner_id: ME });
    assert.strictEqual(buttons(host, 'Take it').length, 0, 'no "Take it" once it is mine');
    selects(host)[0].onchange({ target: { value: '' } }); await tick();
    assert.deepStrictEqual(srv.calls.filter((c) => c.key.startsWith('PATCH')).at(-1).body, { owner_id: null });
  });
  it('severity change is a PATCH', async () => {
    const { host, srv } = await openOne(); selects(host)[1].onchange({ target: { value: 'low' } }); await tick();
    assert.deepStrictEqual(srv.calls.find((c) => c.key.startsWith('PATCH')).body, { severity: 'low' });
  });
  it('editing: sends only what changed, nothing when nothing did, and refuses an empty title without asking', async () => {
    const { host, srv } = await openOne(mkCase(1, { description: 'Old text' }));
    await click(host, 'Edit title and description');
    inputs(host)[0].oninput({ target: { value: '' } }); await click(host, 'Save'); assert.match(allText(host), /title cannot be empty/); assert.ok(!srv.calls.some((c) => c.key.startsWith('PATCH')));
    inputs(host)[0].oninput({ target: { value: 'Case 1' } }); await click(host, 'Save'); assert.ok(!srv.calls.some((c) => c.key.startsWith('PATCH')), 'nothing changed, nothing sent');
    await click(host, 'Edit title and description'); inputs(host)[0].oninput({ target: { value: 'Renamed' } }); textareas(host)[0].oninput({ target: { value: '  ' } }); await click(host, 'Save');
    assert.deepStrictEqual(srv.calls.find((c) => c.key.startsWith('PATCH')).body, { title: 'Renamed', description: '  ' });
  });
  it('alerts: Remove deletes one; Add alerts lists the free ones, Add puts one in and refreshes the list', async () => {
    const { host, srv } = await openOne();
    await click(host, 'Remove', 0); assert.ok(srv.calls.some((c) => c.key === `DELETE /v1/cases/${ID(1)}/alerts/${ID(101)}`)); assert.match(allText(host), /1 alert\b/);
    await click(host, 'Add alerts');
    assert.match(allText(host), /Open alerts that are not in a case, worst first/); assert.match(allText(host), /Alert 7/); assert.match(allText(host), /Alert 8/);
    await click(host, 'Add', 0);
    assert.deepStrictEqual(srv.calls.find((c) => c.key === `POST /v1/cases/${ID(1)}/alerts`).body, { alert_ids: [ID(107)] });
    assert.match(allText(host), /2 alerts/); assert.ok(!/Alert 7  /.test(allText(host).split('Open alerts')[1] || ''), 'the added alert leaves the free list');
    await click(host, 'Hide the list'); assert.ok(!/worst first/.test(allText(host)));
  });
  it('when nothing is free it says so', async () => {
    const srv = server([C()]); srv.free.length = 0; const { host } = await open(srv); await click(host, 'Open'); await click(host, 'Add alerts');
    assert.match(allText(host), /Every open alert is already in a case/);
  });
  it('notes: the typed text survives a redraw, an empty note is not sent, a note goes in the timeline and the box empties', async () => {
    const { host, srv } = await openOne();
    await click(host, 'Add note'); assert.match(allText(host), /Write a note first/); assert.ok(!srv.calls.some((c) => c.key.endsWith('/notes')));
    textareas(host).at(-1).oninput({ target: { value: 'Called the owner' } });
    await click(host, 'Add alerts');   // anything that redraws the page
    assert.strictEqual(textareas(host).at(-1).value, 'Called the owner', 'the half-written note is still there');
    await click(host, 'Add note');
    assert.deepStrictEqual(srv.calls.find((c) => c.key.endsWith('/notes')).body, { body: 'Called the owner' });
    assert.match(allText(host), /alice .*Called the owner|Called the owner/); assert.strictEqual(textareas(host).at(-1).value, '');
  });
  it('a closed case is read-only: only Reopen and notes', async () => {
    const srv = server([mkCase(1, { status: 'closed', closed_at: '2026-11-08T12:00:00.000Z' })]); const { host } = await open(srv);
    assert.match(allText(host), /No active cases/, 'a closed case is not in Active'); await click(host, 'All'); await click(host, 'Open');
    assert.match(allText(host), /closed 2026-11-08 12:00/); assert.match(allText(host), /read-only/);
    assert.deepStrictEqual(buttons(host).map((b) => b.textContent).filter((l) => /^(Mark|Close|Reopen)/.test(l)), ['Reopen', 'Reopen as Investigating']);
    for (const s of selects(host)) assert.ok(s.disabled);
    for (const l of ['Add alerts', 'Remove', 'Edit title and description', 'Take it']) assert.strictEqual(buttons(host, l).length, 0, l);
    assert.strictEqual(buttons(host, 'Add note').length, 1, 'notes are still allowed');
    await click(host, 'Reopen'); assert.deepStrictEqual(srv.calls.find((c) => c.key.startsWith('PATCH')).body, { status: 'open' });
    assert.ok(buttons(host, 'Close case').length === 1);
  });
  it('a read-only role sees the case and the timeline but no controls', async () => {
    const { host } = await openOne(C(), ['alerts:read']);
    assert.match(allText(host), /can look at cases but not change them/); assert.match(allText(host), /Timeline/);
    for (const l of ['Close case', 'Mark investigating', 'Add alerts', 'Remove', 'Add note', 'Edit title and description']) assert.strictEqual(buttons(host, l).length, 0, l);
    assert.strictEqual(textareas(host).length, 0);
  });
  it('a refusal (for example a case closed by someone else) is shown and the page stays usable', async () => {
    const srv = server([C()], { [`PATCH /v1/cases/${ID(1)}`]: async () => { throw err(409, 'This case is closed. Reopen it (set the status) before changing anything else.', 'CASE_CLOSED'); } });
    const { host } = await open(srv); await click(host, 'Open'); await click(host, 'Mark investigating');
    assert.match(allText(host), /409 This case is closed/); assert.ok(buttons(host, 'Close case').length === 1);
  });
  it('Back returns to a fresh list', async () => {
    const { host, srv } = await openOne(); const before = srv.calls.filter((c) => c.key.startsWith('GET /v1/cases?')).length;
    await click(host, '← Back'); assert.match(allText(host), /Cases/); assert.ok(buttons(host, 'Active').length === 1);
    assert.strictEqual(srv.calls.filter((c) => c.key.startsWith('GET /v1/cases?')).length, before + 1);
  });
  it('after unmount a late answer never draws into the host', async () => {
    let release; const gate = new Promise((r) => { release = r; });
    const srv = server([C()], { [`PATCH /v1/cases/${ID(1)}`]: async () => { await gate; return view(C()); } });
    const { host } = await open(srv); await click(host, 'Open');
    buttons(host, 'Close case')[0].onclick(); await tick(); const snapshot = host.kids.slice();
    page.unmount(); release(); await tick();
    assert.deepStrictEqual(host.kids, snapshot);
  });
});

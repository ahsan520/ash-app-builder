'use strict';
// E10c: what the Group settings tab says about a group's alert rule (E10b): the pure view and the read in src/endpoints/fim-watch.js, the `watch` field of GET /v1/endpoints/group-config/:group
// (real route file, the stores and the manager client stood in), and the line and the "Write the alert rule" button of the portal card (cut out of the page and run with stand-ins).
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const express = require('express');
const fw = require('../src/endpoints/fim-watch');

const TENANT = '11111111-1111-4111-8111-111111111111';
const WIN = [{ system: 'windows', path: 'C:\\ASIX-Test', realtime: true }];
const MIX = [{ system: 'linux', path: '/srv/data', realtime: false }, { system: 'windows', path: 'C:\\ASIX-Test', realtime: true }];
const row = (entries, extra = {}) => ({ id: 'r1', enabled: true, severity: 'medium', xql: fw.queryFor(entries), ...extra });

describe('the view of a group\'s rule', () => {
  it('no rule: none, and Apply is needed only when there are folders', () => {
    assert.deepStrictEqual(fw.view(null, WIN), { state: 'none', folders: 1, without_real_time: 0, rule_id: null, enabled: null, severity: null, needs_apply: true });
    assert.strictEqual(fw.view(null, []).needs_apply, false);
    assert.strictEqual(fw.view(undefined, undefined).state, 'none');
  });
  it('a rule whose query is the one these folders give is on, or off when an operator switched it off', () => {
    const on = fw.view(row(WIN), WIN); assert.strictEqual(on.state, 'on'); assert.strictEqual(on.needs_apply, false); assert.strictEqual(on.severity, 'medium'); assert.strictEqual(on.rule_id, 'r1');
    const off = fw.view(row(WIN, { enabled: false, severity: 'high' }), WIN); assert.strictEqual(off.state, 'off'); assert.strictEqual(off.enabled, false); assert.strictEqual(off.severity, 'high'); assert.strictEqual(off.needs_apply, false);
  });
  it('a rule whose query is not the one these folders give is out of step, whatever its switch says', () => {
    for (const r of [row(MIX), row(WIN, { xql: fw.queryFor(WIN) + ' and agent_name = "x"' }), row(WIN, { xql: null }), row(WIN, { enabled: false, xql: fw.NO_FOLDERS })]) {
      const v = fw.view(r, WIN); assert.strictEqual(v.state, 'out_of_step'); assert.strictEqual(v.needs_apply, true);
    }
  });
  it('no folders with a rule left over is idle (kept, matches nothing); an old query left after the list was emptied is out of step', () => {
    assert.strictEqual(fw.view(row([]), []).state, 'idle'); assert.strictEqual(fw.view(row([]), []).needs_apply, false);
    assert.strictEqual(fw.view(row(WIN), []).state, 'out_of_step');
  });
  it('counts the folders and the ones that are not in real time; junk entries are not folders', () => {
    const v = fw.view(row(MIX), MIX); assert.strictEqual(v.folders, 2); assert.strictEqual(v.without_real_time, 1);
    const j = fw.view(null, [null, {}, { system: 'linux', path: '' }, { system: 'linux', path: '/a' }]); assert.strictEqual(j.folders, 1);
  });
  it('agrees with what sync writes: the query a sync stores reads back as on, for Linux and Windows and regex characters', async () => {
    for (const e of [WIN, MIX, [{ system: 'linux', path: '/srv/a.b+c(1)', realtime: false }], []]) {
      const calls = []; await fw.sync({ query: async (sql, args) => { calls.push(args); return { rows: [] }; } }, TENANT, 'g', e);
      const v = fw.view({ id: 'x', enabled: true, severity: 'medium', xql: calls[0][5] }, e); assert.strictEqual(v.state, e.length ? 'on' : 'idle', JSON.stringify(e));
    }
  });
});

describe('reading the rule', () => {
  it('is one SELECT for this tenant and this group\'s key, and returns the view', async () => {
    const calls = []; const client = { query: async (sql, args) => { calls.push({ sql, args }); return { rows: [row(WIN)] }; } };
    const v = await fw.status(client, TENANT, 'default', WIN);
    assert.strictEqual(calls.length, 1); assert.match(calls[0].sql, /^\s*SELECT/i); assert.ok(!/\b(INSERT|UPDATE|DELETE)\b/i.test(calls[0].sql));
    assert.deepStrictEqual(calls[0].args, [TENANT, 'endpoint-fim-watched:default']); assert.match(calls[0].sql, /tenant_id = \$1 AND builtin_key = \$2/); assert.strictEqual(v.state, 'on');
  });
  it('no row is none', async () => { assert.strictEqual((await fw.status({ query: async () => ({ rows: [] }) }, TENANT, 'g', WIN)).state, 'none'); });
});

// ---- the route ----
function load(overrides = {}) {
  const base = path.join(__dirname, '..', 'src');
  const stub = (rel, exports) => { const f = require.resolve(path.join(base, rel)); delete require.cache[f]; require.cache[f] = { id: f, filename: f, loaded: true, exports }; };
  const calls = { status: [], withTenant: 0 };
  class WazuhApiError extends Error { constructor(code, m) { super(m); this.code = code; } }
  stub('gateway/shared.js', {
    db: { withTenant: async (t, fn) => { calls.withTenant += 1; return fn(overrides.client || { query: async () => ({ rows: [] }) }); } },
    guarded: () => [(req, res, next) => { req.tenant_id = TENANT; next(); }], apiError: (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } }),
  });
  stub('endpoints/wazuh-manager-store.js', { readRow: async () => ({ id: 'm' }), isMissingTable: () => false, credentials: () => ({ tenant_id: TENANT }) });
  stub('endpoints/group-config-store.js', { readWriter: async () => ({ id: 'w' }), isMissingTable: () => false, writerCredentials: () => ({}), list: async () => [], writerView: () => ({}) });
  stub('endpoints/wazuh-api.js', { WazuhApiError, groupList: async () => [] });
  stub('endpoints/group-config-service.js', { describe: async (ctx, g) => overrides.describe || ({ ok: true, group: g, sha256: 'a'.repeat(64), state: 'ok', state_text: 't', entries: WIN, bytes: 10 }) });
  const fwf = require.resolve(path.join(base, 'endpoints/fim-watch.js')); delete require.cache[fwf];
  const real = require(fwf); if (overrides.status) real.status = async (...a) => { calls.status.push(a); return overrides.status(...a); };
  const rf = require.resolve(path.join(base, 'gateway/routes/group-config.js')); delete require.cache[rf];
  const router = require(rf); const app = express(); app.use(express.json()); app.use(router);
  return { app, calls };
}
const get = (app, p) => new Promise((resolve, reject) => { const s = app.listen(0, () => { http.get({ port: s.address().port, path: p }, (r) => { let b = ''; r.on('data', (c) => { b += c; }); r.on('end', () => { s.close(); resolve({ status: r.statusCode, body: JSON.parse(b) }); }); }).on('error', reject); }); });

describe('the group route carries the rule state', () => {
  it('answers with watch read for this group and the folders the manager holds', async () => {
    const t = load({ client: { query: async () => ({ rows: [row(WIN)] }) } }); const r = await get(t.app, '/v1/endpoints/group-config/default');
    assert.strictEqual(r.status, 200); assert.strictEqual(r.body.watch.state, 'on'); assert.strictEqual(r.body.watch.folders, 1); assert.ok(Array.isArray(r.body.history));
  });
  it('an out of step rule and a missing rule are told apart', async () => {
    let r = await get(load({ client: { query: async () => ({ rows: [row(MIX)] }) } }).app, '/v1/endpoints/group-config/default'); assert.strictEqual(r.body.watch.state, 'out_of_step');
    r = await get(load({ client: { query: async () => ({ rows: [] }) } }).app, '/v1/endpoints/group-config/default'); assert.strictEqual(r.body.watch.state, 'none'); assert.strictEqual(r.body.watch.needs_apply, true);
  });
  it('a failed read of the rule leaves watch null and the group answer a 200', async () => {
    const t = load({ status: async () => { throw new Error('relation detection_rules does not exist'); } }); const r = await get(t.app, '/v1/endpoints/group-config/default');
    assert.strictEqual(r.status, 200); assert.strictEqual(r.body.watch, null); assert.strictEqual(r.body.state, 'ok');
  });
  it('a damaged or hand-edited block gives no comparison at all (its folders are unknown), and the rule is not even read', async () => {
    for (const state of ['broken', 'edited']) {
      const t = load({ describe: { ok: true, group: 'default', sha256: 'a'.repeat(64), state, state_text: 't', entries: [], bytes: 1 }, status: async () => ({ state: 'none' }) });
      const r = await get(t.app, '/v1/endpoints/group-config/default'); assert.strictEqual(r.body.watch, null, state); assert.strictEqual(t.calls.status.length, 0, state);
    }
  });
  it('the read uses the group in the address as the rule key', async () => {
    const t = load({ status: async () => ({ state: 'none' }) }); await get(t.app, '/v1/endpoints/group-config/linux'); assert.strictEqual(t.calls.status[0][2], 'linux'); assert.strictEqual(t.calls.status[0][1], TENANT);
  });
});

// ---- the portal card ----
const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (name) => { const i = html.indexOf('function ' + name + '('); assert.ok(i >= 0, name); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const el = (tag, props, ...kids) => { const n = Object.assign({ tag, kids: kids.flat(Infinity) }, props || {}); n.props = n; n.replaceChildren = (...k) => { n.kids = k.flat(Infinity); }; n.prepend = (k) => { n.kids = [k, ...n.kids]; }; if (tag === 'select' && n.value === undefined) { const o = n.kids.find((k) => k && k.tag === 'option'); if (o) n.value = o.value; } return n; };
const card = (title, ...kids) => el('div', { className: 'card' }, title ? el('h3', { textContent: title }) : '', ...kids);
const pill = (t, c) => el('span', { className: 'pill ' + (c || 'off'), textContent: t });
const all = (n) => (n && typeof n === 'object' ? [n, ...(n.kids || []).flatMap(all)] : []);
const texts = (n) => all(n).flatMap((x) => [x.props && x.props.textContent, ...(x.kids || []).filter((k) => typeof k === 'string')]).filter((x) => typeof x === 'string' && x);
const btn = (n, label) => all(n).find((x) => x.tag === 'button' && x.props.textContent === label);
const tick = () => new Promise((r) => setTimeout(r, 15));
const SHA = 'a'.repeat(64);
const STATUS = { success: true, write_enabled: true, manager_registered: true, writer_registered: true, writer: { registered: true }, groups: [{ name: 'default', agents: 3 }], limits: { max_entries: 50, max_realtime: 10 } };
const grp = (watch, extra = {}) => ({ success: true, group: 'default', sha256: SHA, state: 'ok', state_text: 'ASIX manages the folders below', entries: [{ system: 'windows', path: 'C:\\ASIX-Test', realtime: true }], history: [], watch, ...extra });
const W = (o) => ({ state: 'on', folders: 1, without_real_time: 0, rule_id: 'r1', enabled: true, severity: 'medium', needs_apply: false, ...o });
function build(group, { status = STATUS, put = undefined, confirmAnswer = true } = {}) {
  const calls = [], confirms = [];
  const api = async (p, o) => { const key = ((o && o.method) || 'GET') + ' ' + p; calls.push({ key, body: o && o.body }); if (key === 'GET /v1/endpoints/group-config') return status; if (key === 'GET /v1/endpoints/group-config/default') return typeof group === 'function' ? group() : group; if (key === 'PUT /v1/endpoints/group-config/default') { if (put instanceof Error) throw put; return put || { success: true, changed: false }; } throw new Error('no stand-in for ' + key); };
  const fn = new Function('el', 'api', 'card', 'pill', 'confirm', 'alert', cut('groupConfigCard') + '\nreturn groupConfigCard;')(el, api, card, pill, (m) => { confirms.push(m); return confirmAnswer; }, () => {});
  return { fn, calls, confirms };
}
const pills = (c) => all(c).filter((x) => x.tag === 'span' && /pill/.test(x.props.className || '')).map((x) => x.props.textContent);

describe('the rule line on the Group settings card', () => {
  it('on: says an alert is raised, with the severity and the rule name, and offers no button', async () => {
    const b = build(grp(W({}))); const c = b.fn(); await tick(); const t = texts(c).join(' | ');
    assert.ok(pills(c).includes('Alert rule on')); assert.match(t, /raises an ASIX alert \(severity medium; Detections, "Watched folder changed on an endpoint \(default\)"\)/); assert.strictEqual(btn(c, 'Write the alert rule'), undefined);
  });
  it('off and idle are said plainly and need no button', async () => {
    let c = build(grp(W({ state: 'off', enabled: false }))).fn(); await tick(); assert.ok(pills(c).includes('Alert rule off')); assert.match(texts(c).join(' '), /switched off on the Detections page/); assert.strictEqual(btn(c, 'Write the alert rule'), undefined);
    c = build(grp(W({ state: 'idle', folders: 0 }), { entries: [], state: 'none' })).fn(); await tick(); assert.ok(pills(c).includes('Alert rule idle')); assert.strictEqual(btn(c, 'Write the alert rule'), undefined);
  });
  it('no rule yet, with folders: says so and offers the button; out of date too', async () => {
    let c = build(grp(W({ state: 'none', needs_apply: true, rule_id: null, enabled: null, severity: null }))).fn(); await tick(); assert.ok(pills(c).includes('No alert rule yet')); assert.ok(btn(c, 'Write the alert rule'));
    c = build(grp(W({ state: 'out_of_step', needs_apply: true }))).fn(); await tick(); assert.ok(pills(c).includes('Alert rule out of date')); assert.ok(btn(c, 'Write the alert rule'));
  });
  it('no folders and no rule draws nothing about a rule', async () => {
    const c = build(grp(W({ state: 'none', folders: 0, needs_apply: false, rule_id: null }), { entries: [], state: 'none' })).fn(); await tick(); assert.ok(!pills(c).some((x) => /Alert rule/.test(x))); assert.ok(!texts(c).join(' ').includes('through a rule'));
  });
  it('an answer without watch (an older API, an unreadable rule) draws nothing and the card still works', async () => {
    for (const w of [undefined, null]) { const c = build(grp(w)).fn(); await tick(); assert.ok(!pills(c).some((x) => /Alert rule/.test(x))); assert.ok(btn(c, 'Preview')); }
  });
  it('a damaged or hand-edited block shows no rule line (the folders are unknown)', async () => {
    const c = build(grp(W({ state: 'out_of_step', needs_apply: true }), { state: 'edited', entries: [] })).fn(); await tick(); assert.ok(!pills(c).some((x) => /Alert rule/.test(x))); assert.strictEqual(btn(c, 'Write the alert rule'), undefined);
  });
  it('folders without real time get a plain warning with the counts; all in real time gets none', async () => {
    let c = build(grp(W({ folders: 3, without_real_time: 2 }))).fn(); await tick(); assert.match(texts(c).join(' '), /2 of 3 folders are not in real time: the agent compares them only at its scheduled scan/);
    c = build(grp(W({ folders: 3, without_real_time: 0 }))).fn(); await tick(); assert.ok(!/not in real time/.test(texts(c).join(' ')));
  });
  it('the button is not offered while changes are switched off on the server', async () => {
    const c = build(grp(W({ state: 'none', needs_apply: true })), { status: { ...STATUS, write_enabled: false } }).fn(); await tick(); assert.ok(pills(c).includes('No alert rule yet')); assert.strictEqual(btn(c, 'Write the alert rule'), undefined);
  });
});

describe('Write the alert rule', () => {
  const none = () => grp(W({ state: 'none', needs_apply: true }));
  it('asks first, then sends the folders the manager holds with the hash it read, and reads the group again', async () => {
    let n = 0; const b = build(() => (n++ ? grp(W({})) : none())); const c = b.fn(); await tick(); await btn(c, 'Write the alert rule').props.onclick();
    assert.strictEqual(b.confirms.length, 1); assert.match(b.confirms[0], /group "default"/); assert.match(b.confirms[0], /not changed/);
    const w = b.calls.find((x) => x.key.startsWith('PUT')); assert.deepStrictEqual(w.body, { entries: [{ system: 'windows', path: 'C:\\ASIX-Test', realtime: true }], base_sha256: SHA });
    assert.strictEqual(b.calls.filter((x) => x.key === 'GET /v1/endpoints/group-config/default').length, 2); assert.match(texts(c).join(' '), /Done\. The alert rule is written/); assert.ok(pills(c).includes('Alert rule on'));
  });
  it('a person who says no sends nothing', async () => {
    const b = build(none, { confirmAnswer: false }); const c = b.fn(); await tick(); await btn(c, 'Write the alert rule').props.onclick(); assert.ok(!b.calls.some((x) => x.key.startsWith('PUT')));
  });
  it('a refusal is shown as text and the card stays; a stale file reloads the group', async () => {
    let b = build(none, { put: new Error('You may not change group configuration') }); let c = b.fn(); await tick(); await btn(c, 'Write the alert rule').props.onclick(); assert.match(texts(c).join(' '), /may not change group configuration/); assert.strictEqual(b.calls.filter((x) => x.key === 'GET /v1/endpoints/group-config/default').length, 1);
    b = build(none, { put: new Error('The group configuration changed since you looked at it. Preview again.') }); c = b.fn(); await tick(); await btn(c, 'Write the alert rule').props.onclick(); assert.match(texts(c).join(' '), /changed since/); assert.strictEqual(b.calls.filter((x) => x.key === 'GET /v1/endpoints/group-config/default').length, 2);
  });
  it('shows only text: the card code never sets HTML', () => { assert.ok(!/innerHTML|insertAdjacentHTML/.test(cut('groupConfigCard'))); });
});

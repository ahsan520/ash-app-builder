'use strict';
// The Endpoints page (src/portal/index.html, pgEndpoints; docs/endpoints.md task E6): the function is cut out of the page and run with small stand-ins for
// el(), card(), pill(), table(), kv(), when(), api() and route(), as in portal-win-filter.test.js. No DOM, no network.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const consts = html.slice(html.indexOf('const EP_STATUS ='), html.indexOf('async function pgEndpoints'));
const source = consts + cut('async function pgEndpoints');

const el = (tag, attrs, ...kids) => Object.assign({}, attrs || {}, { tag, attrs: attrs || {}, kids: kids.flat(Infinity), replaceChildren(...k) { this.kids = k.flat(Infinity); }, append(...k) { this.kids.push(...k.flat(Infinity)); } });
const walk = (n) => (typeof n === 'string' ? [n] : n && typeof n === 'object' ? (Array.isArray(n) ? n.flatMap(walk) : [n, ...(n.kids || []).flatMap(walk)]) : []);
const texts = (n) => walk(n).map((x) => (typeof x === 'string' ? x : typeof x.textContent === 'string' ? x.textContent : '')).join(' | ');
const card = (title, ...kids) => el('div', { className: 'card' }, title ? el('h3', { textContent: title }) : '', ...kids);
const pill = (t, c) => el('span', { className: 'pill ' + (c || 'off'), textContent: t });
const kv = (o) => el('div', {}, Object.entries(o).map(([k, v]) => el('div', { className: 'kv' }, el('span', { textContent: k }), el('span', { textContent: v === null || v === undefined ? '-' : String(v) }))));
const when = (v) => (v ? String(v).replace('T', ' ').replace(/\.\d+Z?$/, '') : '-');
const table = (cols, rows, empty) => (!rows.length ? el('div', { className: 'mute', textContent: empty || 'Nothing to show yet.' })
  : el('table', {}, el('tr', {}, cols.map((c) => el('th', { textContent: c.h }))), rows.map((r) => el('tr', {}, cols.map((c) => { const v = c.f(r); return typeof v === 'object' && v ? el('td', {}, v) : el('td', { textContent: String(v ?? '-') }); })))));

const MANAGER = { available: true, registered: true, label: 'lab broker manager', host: '192.168.68.54', port: 55000, api_user: 'asix-readonly', cert_sha256: '8b3e2d85', updated_at: '2026-10-25T18:49:08.275Z',
  status: { reachable: true, version: 'v4.14.9', compilation_date: null, max_agents: 'unlimited', timezone: 'UTC' } };
const SUMMARY = { active: 2, disconnected: 1, never_connected: 0, pending: 1, total: 4 };
const agent = (id, name, status) => ({ id, name, ip: '10.0.0.' + Number(id), register_ip: 'any', status, version: 'v4.14.9', groups: ['default', 'linux'], last_keep_alive: '2026-10-25T19:00:00Z', date_added: '2026-10-20T10:00:00Z', node: 'node01', manager: 'mgr',
  os: { name: 'Ubuntu', platform: 'ubuntu', version: '24.04', arch: 'x86_64' } });
const LIST = { total: 3, limit: 50, offset: 0, agents: [agent('001', 'web01', 'active'), agent('002', 'db01', 'disconnected'), agent('003', 'new01', 'never_connected')] };

async function open(manager = MANAGER, answers = {}) {
  const calls = [], routes = [];
  const api = async (p, o = {}) => {
    calls.push({ p, method: o.method || 'GET' });
    const a = answers[p] !== undefined ? answers[p] : answers[p.split('?')[0]];
    if (a instanceof Error) throw a;
    if (a !== undefined) return a;
    if (p === '/v1/endpoints/manager') return { success: true, manager };
    if (p === '/v1/endpoints/agents/summary') return { success: true, summary: SUMMARY };
    if (p.startsWith('/v1/endpoints/agents?')) return { success: true, ...LIST };
    if (p.startsWith('/v1/endpoints/installer/linux?')) return { success: true, installer: { platform: 'linux', manager: '192.168.68.54', group: new URLSearchParams(p.split('?')[1]).get('group'), agent_version: '4.14.9-1', from_manager: true, filename: 'asix-endpoint-install.sh',
      password_token: '__ASIX_ENROLL_PASSWORD__', script: "#!/bin/bash\nEMBEDDED_PASSWORD='__ASIX_ENROLL_PASSWORD__'; PLACEHOLDER=\"__ASIX_ENROLL_\"\"PASSWORD__\"\necho hi\n" } };
    const one = /^\/v1\/endpoints\/agents\/(\d+)$/.exec(p);
    if (one) return { success: true, agent: LIST.agents.find((x) => x.id === one[1]) };
    throw new Error('unexpected call ' + p);
  };
  const copyBtn = (get, label) => el('button', { textContent: label, onclick: () => get() });
  const fn = new Function('el', 'card', 'pill', 'table', 'kv', 'when', 'api', 'route', 'copyBtn', source + '\nreturn pgEndpoints;')(el, card, pill, table, kv, when, api, () => routes.push(1), copyBtn);
  const tree = await fn();
  const click = async (label) => { const t = walk(tree).find((n) => typeof n === 'object' && n.attrs && n.attrs.textContent === label && typeof n.attrs.onclick === 'function'); assert.ok(t, label + ' not found'); await t.attrs.onclick(); await new Promise((r) => setImmediate(r)); };
  return { tree, calls, routes, click, text: () => texts(tree), all: () => walk(tree) };
}

describe('Endpoints page', () => {
  it('has a menu entry, is not tied to a planned module, and shows no product name outside the notices tab', async () => {
    assert.match(html, /\{ id: 'endpoints', label: 'Endpoints', ic: '[^']+', page: pgEndpoints/);
    assert.ok(!/'endpoints': '/.test(html) && !/endpoints: '/.test(html.slice(html.indexOf('const MENU_MODULE'), html.indexOf('let menuMods'))), 'not mapped to a module: the only candidate (xdr) is "planned" and would lock the page');
    const p = await open(); await p.click('Agents');
    assert.ok(!/wazuh/i.test(p.text()), 'overview and agents show no Wazuh name');
  });
  it('is read only: only GET calls to the E4c routes, and no HTML injection', async () => {
    assert.ok(!/innerHTML|insertAdjacentHTML|method:/.test(source));
    const p = await open(); await p.click('Agents');
    assert.ok(p.calls.length >= 3 && p.calls.every((c) => c.method === 'GET' && /^\/v1\/endpoints\/(manager|agents)/.test(c.p)));
  });
  it('database not ready: says so and calls nothing else', async () => {
    const p = await open({ available: false, registered: false, status: null });
    assert.match(p.text(), /Not ready/); assert.deepStrictEqual(p.calls.map((c) => c.p), ['/v1/endpoints/manager']);
  });
  it('no manager registered: shows how an operator registers one, and calls nothing else', async () => {
    const p = await open({ available: true, registered: false, status: null });
    assert.match(p.text(), /No endpoint manager registered/); assert.match(p.text(), /wazuh-manager-cli\.js register --tenant/); assert.deepStrictEqual(p.calls.map((c) => c.p), ['/v1/endpoints/manager']);
  });
  it('overview: manager details, version, pinned certificate and the five agent counts', async () => {
    const p = await open(); const t = p.text();
    assert.match(t, /Reachable/); assert.match(t, /192\.168\.68\.54:55000/); assert.match(t, /v4\.14\.9/); assert.match(t, /8b3e2d85/); assert.match(t, /asix-readonly/);
    for (const k of ['Total', 'Active', 'Disconnected', 'Never connected', 'Pending']) assert.ok(t.includes(k), k);
    const stats = p.all().filter((n) => typeof n === 'object' && n.attrs && n.attrs.className === 'stat').map((n) => n.kids[0]);
    assert.deepStrictEqual(stats, ['4', '2', '1', '0', '1']);
    assert.ok(p.calls.some((c) => c.p === '/v1/endpoints/agents/summary'));
  });
  it('an unreachable manager shows why and does not ask for the agent counts', async () => {
    const p = await open({ ...MANAGER, status: { reachable: false, code: 'TIMEOUT', message: 'The manager did not answer in time' } });
    assert.match(p.text(), /Not reachable/); assert.match(p.text(), /TIMEOUT: The manager did not answer in time/);
    assert.ok(!p.calls.some((c) => c.p === '/v1/endpoints/agents/summary'));
  });
  it('a failing summary is shown without hiding the manager card', async () => {
    const p = await open(MANAGER, { '/v1/endpoints/agents/summary': new Error('502 WAZUH_BAD_RESPONSE') });
    assert.match(p.text(), /502 WAZUH_BAD_RESPONSE/); assert.match(p.text(), /Endpoint manager/);
  });
  it('agents tab: first page, status pills, groups, OS, and the query the routes accept', async () => {
    const p = await open(); await p.click('Agents');
    const q = p.calls.map((c) => c.p).find((x) => x.startsWith('/v1/endpoints/agents?'));
    assert.strictEqual(q, '/v1/endpoints/agents?limit=50&offset=0&sort=%2Bname');
    const t = p.text(); for (const s of ['web01', 'db01', 'new01', 'Active', 'Disconnected', 'Never connected', 'default, linux', 'Ubuntu 24.04', '1 to 3 of 3']) assert.ok(t.includes(s), s);
  });
  it('search and status filters go into the query, encoded, and start again from the first page', async () => {
    const p = await open(); await p.click('Agents');
    const box = p.all().find((n) => n.tag === 'input'), sel = p.all().filter((n) => n.tag === 'select');
    box.value = 'web & 01'; sel[0].value = 'active'; sel[1].value = '-lastKeepAlive'; await p.click('Search');
    assert.strictEqual(p.calls.at(-1).p, '/v1/endpoints/agents?limit=50&offset=0&sort=-lastKeepAlive&search=web+%26+01&status=active');
  });
  it('paging: Next asks for the next 50, Previous is off on the first page, Next is off on the last', async () => {
    const answers = { '/v1/endpoints/agents': { success: true, total: 120, limit: 50, offset: 0, agents: LIST.agents } };
    const p = await open(MANAGER, answers); await p.click('Agents');
    const btn = (l) => p.all().find((n) => n.tag === 'button' && n.attrs.textContent === l);
    assert.strictEqual(btn('Previous').disabled, true); assert.strictEqual(btn('Next').disabled, false);
    await p.click('Next'); assert.match(p.calls.at(-1).p, /offset=50/);
    assert.strictEqual(btn('Previous').disabled, false);
  });
  it('an empty list says how a machine gets here; a failed list shows the error', async () => {
    const e = await open(MANAGER, { '/v1/endpoints/agents': { success: true, total: 0, limit: 50, offset: 0, agents: [] } }); await e.click('Agents');
    assert.match(e.text(), /No agents match/); assert.match(e.text(), /0 of 0/);
    const f = await open(MANAGER, { '/v1/endpoints/agents': new Error('503 WAZUH_BUSY') }); await f.click('Agents'); assert.match(f.text(), /503 WAZUH_BUSY/);
  });
  it('clicking an agent id loads that agent only', async () => {
    const p = await open(); await p.click('Agents'); await p.click('002');
    assert.strictEqual(p.calls.at(-1).p, '/v1/endpoints/agents/002'); assert.match(p.text(), /Agent 002/); assert.match(p.text(), /db01/); assert.match(p.text(), /node01/);
  });
  it('agent text from the manager is only ever placed as text', async () => {
    const evil = { ...agent('009', '<img src=x onerror=alert(1)>', 'active') };
    const p = await open(MANAGER, { '/v1/endpoints/agents': { success: true, total: 1, limit: 50, offset: 0, agents: [evil] } }); await p.click('Agents');
    assert.ok(p.text().includes('<img src=x onerror=alert(1)>')); assert.ok(!p.all().some((n) => n.tag === 'img'));
  });

  it('Add a machine: asks for the script by group only, and shows it without a password when none was typed', async () => {
    const p = await open(); await p.click('Add a machine');
    assert.match(p.text(), /Debian, Ubuntu, RHEL/); await p.click('Create script');
    assert.strictEqual(p.calls.at(-1).p, '/v1/endpoints/installer/linux?group=default'); assert.strictEqual(p.calls.at(-1).method, 'GET');
    const t = p.text(); assert.match(t, /Made for 192\.168\.68\.54, group default, agent package 4\.14\.9-1/); assert.match(t, /No password is in this script/); assert.ok(t.includes("EMBEDDED_PASSWORD='__ASIX_ENROLL_PASSWORD__'"));
  });
  it('a typed password goes into the script in the browser only: never in a request, quotes and $ kept, token gone', async () => {
    const p = await open(); await p.click('Add a machine');
    const [group, pw] = p.all().filter((n) => n.tag === 'input'); group.value = ' linux servers '; pw.value = "a'b$&c\\d"; await p.click('Create script');
    assert.strictEqual(p.calls.at(-1).p, '/v1/endpoints/installer/linux?group=linux+servers'); assert.ok(!p.calls.some((c) => c.p.includes('a%27b') || c.p.includes("a'b")));
    const script = p.all().find((n) => n.tag === 'pre').attrs.textContent;
    assert.ok(script.includes("EMBEDDED_PASSWORD='a'\\''b$&c\\d'"), script); assert.ok(!script.includes('__ASIX_ENROLL_PASSWORD__;') && !/EMBEDDED_PASSWORD='__ASIX/.test(script));
    assert.ok(script.includes('PLACEHOLDER="__ASIX_ENROLL_""PASSWORD__"'), 'the script\u2019s own comparison string is not touched'); assert.match(p.text(), /ASIX never received it/);
  });
  it('a password with a line break is refused before any request; a failing route shows its message', async () => {
    const p = await open(); await p.click('Add a machine'); const before = p.calls.length;
    p.all().filter((n) => n.tag === 'input')[1].value = 'a\nb'; await p.click('Create script'); assert.strictEqual(p.calls.length, before); assert.match(p.text(), /must be one line/);
    const f = await open(MANAGER, { '/v1/endpoints/installer/linux': new Error('400 INSTALLER_BAD_GROUP') }); await f.click('Add a machine'); await f.click('Create script'); assert.match(f.text(), /INSTALLER_BAD_GROUP/);
  });
  it('third-party notices: the open source component, its licence and source, with the version the manager reports', async () => {
    const p = await open(); await p.click('Third-party notices'); const t = p.text();
    assert.match(t, /Wazuh/); assert.match(t, /GNU General Public License, version 2/); assert.match(t, /github\.com\/wazuh\/wazuh/); assert.match(t, /v4\.14\.9/); assert.match(t, /lawyer/);
    const a = p.all().find((n) => n.tag === 'a'); assert.strictEqual(a.attrs.rel, 'noopener noreferrer'); assert.strictEqual(a.attrs.target, '_blank');
  });
  it('Refresh reloads the page', async () => { const p = await open(); await p.click('Refresh'); assert.strictEqual(p.routes.length, 1); });
});

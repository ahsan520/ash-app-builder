'use strict';
// E6c: the File integrity tab of the Endpoints page (src/portal/index.html, pgEndpoints > alertsView(true); docs/endpoints.md, "E6c as built"): the page function is cut out and run with small
// stand-ins, as tests/portal-endpoint-alerts.test.js does for the Alerts tab. No DOM, no network.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const source = html.slice(html.indexOf('const EP_STATUS ='), html.indexOf('async function pgEndpoints')) + cut('async function pgEndpoints');

const el = (tag, attrs, ...kids) => Object.assign({}, attrs || {}, { tag, attrs: attrs || {}, kids: kids.flat(Infinity), replaceChildren(...k) { this.kids = k.flat(Infinity); }, append(...k) { this.kids.push(...k.flat(Infinity)); } });
const walk = (n) => (typeof n === 'string' ? [n] : n && typeof n === 'object' ? (Array.isArray(n) ? n.flatMap(walk) : [n, ...(n.kids || []).flatMap(walk)]) : []);
const texts = (n) => walk(n).map((x) => (typeof x === 'string' ? x : typeof x.textContent === 'string' ? x.textContent : '')).join(' | ');
const card = (title, ...kids) => el('div', { className: 'card' }, title ? el('h3', { textContent: title }) : '', ...kids);
const pill = (t, c) => el('span', { className: 'pill ' + (c || 'off'), textContent: t });
const kv = (o) => el('div', {}, Object.entries(o).map(([k, v]) => el('div', { className: 'kv' }, el('span', { textContent: k }), el('span', { textContent: v === null || v === undefined ? '-' : String(v) }))));
const when = (v) => (v ? String(v).replace('T', ' ').replace(/\.\d+Z?$/, '') : '-');
const table = (cols, rows, empty) => (!rows.length ? el('div', { className: 'mute', textContent: empty || 'Nothing to show yet.' })
  : el('table', {}, el('tr', {}, cols.map((c) => el('th', { textContent: c.h }))), rows.map((r) => el('tr', {}, cols.map((c) => { const v = c.f(r); return typeof v === 'object' && v ? el('td', {}, v) : el('td', { textContent: String(v ?? '-') }); })))));

const MANAGER = { available: true, registered: true, label: 'lab', host: '10.0.0.5', port: 55000, api_user: 'asix-readonly', cert_sha256: 'ab12', updated_at: '2026-10-25T18:49:08Z', status: { reachable: true, version: 'v4.14.9', max_agents: 'unlimited', timezone: 'UTC' } };
const SUMMARY = { active: 1, disconnected: 0, never_connected: 0, pending: 0, total: 1 };
const A1 = '00000000-0000-4000-8000-000000000001', A2 = '00000000-0000-4000-8000-000000000002', A3 = '00000000-0000-4000-8000-000000000003';
const mitre = (techs, tactics) => ({ techniques: techs.map(([id, name, url]) => ({ id, name, url })), unpaired_names: [], tactics });
const alert = (id, o = {}) => ({ id, time: '2026-10-27T10:00:00.123Z', received_at: '2026-10-27T10:00:01Z', rule_id: '5763', level: 10, severity: 'high', description: 'sshd: brute force', agent: { id: '002', name: 'web1', ip: '10.0.0.30' },
  groups: ['syslog', 'sshd'], mitre: mitre([['T1110', 'Brute Force', 'https://attack.mitre.org/techniques/T1110/']], ['Credential Access']), file_path: null, file_event: null, user: 'admin', src_ip: '203.0.113.9', ...o });
const ALERTS = [alert(A1), alert(A2, { rule_id: '550', level: 7, severity: 'medium', description: 'Integrity checksum changed.', agent: { id: '003', name: 'db1', ip: '10.0.0.31' }, user: null, src_ip: null, file_path: '/etc/passwd',
  mitre: mitre([['T1565.001', 'Stored Data Manipulation', 'https://attack.mitre.org/techniques/T1565/001/']], ['Impact']) }), alert(A3, { rule_id: '5402', level: 3, severity: 'low', description: 'sudo', mitre: mitre([], []), user: null, src_ip: null })];
const SUM = { success: true, window: '24h', since: 'x', severity: { critical: 0, high: 1, medium: 1, low: 1, unknown: 0, total: 3 },
  top: { rules: [{ rule_id: '5763', description: 'sshd: brute force', level: 10, count: 1 }], agents: [{ name: 'web1', count: 2 }, { name: 'db1', count: 1 }],
    techniques: [{ id: 'T1110', name: 'Brute Force', url: 'https://attack.mitre.org/techniques/T1110/', count: 1 }], tactics: [{ name: 'Credential Access', count: 1 }] }, sampled: { events: 3, truncated: false } };
const DETAIL = { ...alert(A1), manager: 'mgr-lab', decoder: 'sshd', location: '/var/log/auth.log', alert_ref: '1761.1', full_log: 'Failed password for invalid user admin from 203.0.113.9', data: { srcip: '203.0.113.9', srcuser: 'admin' }, file_integrity: {} };

async function open(answers = {}, manager = MANAGER) {
  const calls = [];
  const api = async (p, o = {}) => {
    calls.push({ p, method: o.method || 'GET' });
    const a = answers[p] !== undefined ? answers[p] : answers[p.split('?')[0]];
    if (a instanceof Error) throw a;
    if (typeof a === 'function') return a(p);
    if (a !== undefined) return a;
    if (p === '/v1/endpoints/manager') return { success: true, manager };
    if (p === '/v1/endpoints/agents/summary') return { success: true, summary: SUMMARY };
    if (p.startsWith('/v1/endpoints/alerts/summary')) return SUM;
    if (p.startsWith('/v1/endpoints/alerts?')) return { success: true, alerts: ALERTS, count: ALERTS.length, offset: 0, limit: 50, more: false, window: '24h' };
    const one = /^\/v1\/endpoints\/alerts\/([0-9a-f-]+)$/.exec(p);
    if (one) return { success: true, alert: { ...DETAIL, id: one[1] } };
    throw new Error('unexpected call ' + p);
  };
  const copyBtn = (get, label) => el('button', { textContent: label, onclick: () => get() });
  const fn = new Function('el', 'card', 'pill', 'table', 'kv', 'when', 'api', 'route', 'copyBtn', source + '\nreturn pgEndpoints;')(el, card, pill, table, kv, when, api, () => {}, copyBtn);
  const tree = await fn();
  const settle = () => new Promise((r) => setImmediate(r));
  const find = (pred, what) => { const n = walk(tree).find((x) => typeof x === 'object' && x.attrs && pred(x.attrs)); assert.ok(n, what + ' not found'); return n; };
  const click = async (label) => { await find((a) => a.textContent === label && typeof a.onclick === 'function', label).attrs.onclick(); await settle(); };
  const clickStarting = async (label) => { await find((a) => typeof a.textContent === 'string' && a.textContent.startsWith(label) && typeof a.onclick === 'function', label).attrs.onclick(); await settle(); };
  const clickTitle = async (title) => { await find((a) => a.title === title && typeof a.onclick === 'function', title).attrs.onclick(); await settle(); };
  const typeInto = (placeholder, v) => { find((a) => a.placeholder === placeholder, placeholder).value = v; };
  const alertsTab = async () => { await click('Alerts'); await settle(); };
  return { tree, calls, click, clickStarting, clickTitle, typeInto, alertsTab, settle, find, text: () => texts(tree), all: () => walk(tree), listCalls: () => calls.filter((c) => c.p.startsWith('/v1/endpoints/alerts?')), sumCalls: () => calls.filter((c) => c.p.startsWith('/v1/endpoints/alerts/summary')) };
}
const qs = (p) => Object.fromEntries(new URLSearchParams(p.split('?')[1]));

const FA1 = '00000000-0000-4000-8000-0000000000a1', FA2 = '00000000-0000-4000-8000-0000000000a2';
const FIM = [alert(FA1, { rule_id: '550', level: 7, severity: 'medium', description: 'Integrity checksum changed.', file_path: '/etc/passwd', file_event: 'modified', user: null, src_ip: null, mitre: mitre([], []) }),
  alert(FA2, { rule_id: '553', level: 12, severity: 'critical', description: 'File deleted.', file_path: '/var/log/auth.log', file_event: 'deleted', agent: { id: '003', name: 'db1', ip: '10.0.0.31' }, user: null, src_ip: null, mitre: mitre([], []) })];
const FSUM = { success: true, window: '24h', since: 'x', severity: { critical: 1, high: 0, medium: 1, low: 0, unknown: 0, total: 2 },
  top: { rules: [{ rule_id: '550', description: 'Integrity checksum changed.', level: 7, count: 1 }], agents: [{ name: 'web1', count: 1 }, { name: 'db1', count: 1 }], techniques: [], tactics: [],
    files: [{ path: '/etc/passwd', count: 1 }, { path: '/var/log/auth.log', count: 1 }], file_events: [{ name: 'modified', count: 1 }, { name: 'deleted', count: 1 }] }, sampled: { events: 2, truncated: false } };
const fimAnswers = (over = {}) => ({ '/v1/endpoints/alerts/summary': () => FSUM, '/v1/endpoints/alerts': () => ({ success: true, alerts: FIM, count: 2, offset: 0, limit: 50, more: false, window: '24h' }), ...over });
const fimTab = async (answers) => { const p = await open(fimAnswers(answers)); await p.click('File integrity'); return p; };
const fim = (p, list = p.listCalls()) => list.filter((c) => qs(c.p).kind === 'file_integrity');

describe('Endpoints page, File integrity tab', () => {
  it('there is a File integrity tab after Alerts; nothing is loaded for it until it is opened, and the Alerts tab never asks for file integrity', async () => {
    const p = await open(fimAnswers()); const labels = p.all().filter((n) => typeof n === 'object' && n.attrs && n.attrs.className && String(n.attrs.className).startsWith('xtab')).map((n) => n.attrs.textContent);
    assert.deepStrictEqual(labels, ['Overview', 'Agents', 'Alerts', 'File integrity', 'Configuration checks', 'Add a machine', 'Third-party notices']);
    assert.ok(!p.calls.some((c) => c.p.includes('/alerts')), 'no alert call before a tab is opened');
    await p.alertsTab(); assert.ok(p.calls.filter((c) => c.p.includes('/alerts')).every((c) => !c.p.includes('kind=')), 'the Alerts tab sends no kind');
  });
  it('opening it asks for the cards and the list with kind=file_integrity, the 24 hour window and no file event', async () => {
    const p = await fimTab(); assert.strictEqual(p.sumCalls().length, 1); assert.strictEqual(p.listCalls().length, 1);
    for (const c of [p.sumCalls()[0], p.listCalls()[0]]) { const q = qs(c.p); assert.strictEqual(q.kind, 'file_integrity'); assert.strictEqual(q.window, '24h'); assert.ok(!('file_event' in q)); }
    assert.ok(p.calls.every((c) => c.method === 'GET'));
  });
  it('draws the file changes: the file, what happened, the machine and the cards with changed files and kinds of change', async () => {
    const p = await fimTab(); const t = p.text();
    assert.match(t, /File changes, last 24 hours/); assert.match(t, /\/etc\/passwd/); assert.match(t, /\/var\/log\/auth\.log/); assert.match(t, /modified/); assert.match(t, /deleted/); assert.match(t, /web1/);
    assert.deepStrictEqual(p.all().filter((n) => n.tag === 'th').map((n) => n.textContent), ['Time (UTC)', 'Change', 'File', 'Machine', 'Severity', 'Rule', 'ATT&CK']);
    assert.match(t, /Changes/); assert.match(t, /Files/); assert.match(t, /file change alerts/);
  });
  it('clicking a changed file searches for it (the box shows it); the list is asked again with kind kept and from the first page', async () => {
    const p = await fimTab(); await p.clickStarting('/etc/passwd');
    const q = qs(p.listCalls().at(-1).p); assert.deepStrictEqual([q.kind, q.q, q.offset], ['file_integrity', '/etc/passwd', '0']);
    assert.strictEqual(p.find((a) => a.placeholder === 'Search file path, machine, user or description', 'box').value, '/etc/passwd');
  });
  it('clicking a kind of change, or choosing one, filters the list (a chip) or the list and the cards (the choice) by it', async () => {
    const p = await fimTab(); await p.clickStarting('deleted');
    assert.strictEqual(qs(p.listCalls().at(-1).p).file_event, 'deleted'); assert.strictEqual(qs(p.listCalls().at(-1).p).kind, 'file_integrity'); assert.strictEqual(p.sumCalls().length, 1, 'a chip filters the list; the cards stay the breakdown (as on Alerts)');
    const sel = p.all().filter((n) => n.tag === 'select'); assert.strictEqual(sel.length, 3, 'window, severity, change'); assert.strictEqual(sel[2].value, 'deleted');
    sel[2].value = 'added'; await sel[2].onchange(); await p.settle(); assert.strictEqual(qs(p.listCalls().at(-1).p).file_event, 'added'); assert.strictEqual(qs(p.sumCalls().at(-1).p).file_event, 'added'); assert.strictEqual(qs(p.sumCalls().at(-1).p).kind, 'file_integrity');
    sel[2].value = ''; await sel[2].onchange(); await p.settle(); assert.ok(!('file_event' in qs(p.listCalls().at(-1).p)), 'cleared');
  });
  it('severity, machine and window still apply, together with kind', async () => {
    const p = await fimTab(); await p.clickStarting('web1');
    let q = qs(p.listCalls().at(-1).p); assert.deepStrictEqual([q.kind, q.agent], ['file_integrity', 'web1']);
    const sev = p.all().filter((n) => n.tag === 'select')[1]; sev.value = 'critical'; await sev.onchange(); await p.settle();
    q = qs(p.listCalls().at(-1).p); assert.deepStrictEqual([q.kind, q.agent, q.severity], ['file_integrity', 'web1', 'critical']); assert.ok(!('severity' in qs(p.sumCalls().at(-1).p)), 'the cards ignore severity');
  });
  it('the two tabs keep their own filters: a change filter here is not sent from Alerts, and is still set when coming back', async () => {
    const p = await fimTab(); await p.clickStarting('modified');
    await p.alertsTab(); const q = qs(p.listCalls().at(-1).p); assert.ok(!('kind' in q) && !('file_event' in q), JSON.stringify(q));
    assert.strictEqual(p.all().filter((n) => n.tag === 'select').length, 2, 'no change select on Alerts');
    await p.click('File integrity'); assert.deepStrictEqual([qs(p.listCalls().at(-1).p).kind, qs(p.listCalls().at(-1).p).file_event], ['file_integrity', 'modified']);
  });
  it('a filter set on the Alerts tab is not used on File integrity, and the other way round', async () => {
    const p = await open(fimAnswers()); await p.alertsTab(); await p.clickStarting('web1');   // Alerts tab: only machine web1
    assert.strictEqual(qs(p.listCalls().at(-1).p).agent, 'web1');
    await p.click('File integrity'); assert.ok(!('agent' in qs(p.listCalls().at(-1).p)), 'File integrity starts clean');
    await p.clickStarting('db1'); await p.alertsTab(); const q = qs(p.listCalls().at(-1).p); assert.strictEqual(q.agent, 'web1'); assert.ok(!('kind' in q));
  });
  it('opening a row loads that alert by id, and Next pages with kind kept', async () => {
    const p = await fimTab({ '/v1/endpoints/alerts': () => ({ success: true, alerts: FIM, count: 2, offset: 0, limit: 50, more: true, window: '24h' }) });
    await p.click('2026-10-27 10:00:00'); assert.strictEqual(p.calls.at(-1).p, '/v1/endpoints/alerts/' + FA1);
    await p.click('Next'); const q = qs(p.listCalls().at(-1).p); assert.deepStrictEqual([q.kind, q.offset], ['file_integrity', '50']);
  });
  it('shows its own empty text, shows a failure in place, and never draws file text as HTML', async () => {
    let p = await fimTab({ '/v1/endpoints/alerts': () => ({ success: true, alerts: [], count: 0, offset: 0, limit: 50, more: false, window: '24h' }), '/v1/endpoints/alerts/summary': () => ({ ...FSUM, severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0 }, top: { rules: [], agents: [], techniques: [], tactics: [], files: [], file_events: [] } }) });
    assert.match(p.text(), /No file changes match/); assert.ok(!/No alerts match/.test(p.text()));
    p = await fimTab({ '/v1/endpoints/alerts': () => { throw new Error('You do not have permission: search:events:read'); } }); assert.match(p.text(), /search:events:read/);
    const evil = '<img src=x onerror=alert(1)>';
    p = await fimTab({ '/v1/endpoints/alerts': () => ({ success: true, alerts: [{ ...FIM[0], file_path: evil }], count: 1, offset: 0, limit: 50, more: false, window: '24h' }), '/v1/endpoints/alerts/summary': () => ({ ...FSUM, top: { ...FSUM.top, files: [{ path: evil, count: 1 }] } }) });
    assert.ok(p.text().includes(evil)); assert.ok(!p.all().some((n) => n.tag === 'img')); assert.ok(!p.all().some((n) => typeof n === 'object' && n.attrs && 'innerHTML' in n.attrs));
  });
  it('an answer from an older API without files and change lists still draws', async () => {
    const old = { ...FSUM, top: { rules: [], agents: [], techniques: [], tactics: [] } };
    const p = await fimTab({ '/v1/endpoints/alerts/summary': () => old }); assert.match(p.text(), /Files/); assert.match(p.text(), /\/etc\/passwd/);
  });
});

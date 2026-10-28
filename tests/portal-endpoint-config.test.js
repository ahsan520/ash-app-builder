'use strict';
// E6d: the Configuration checks tab of the Endpoints page (src/portal/index.html, pgEndpoints > alertsView('config'); docs/endpoints.md, "E6d as built"): the page function is cut out and run with small
// stand-ins, as tests/portal-endpoint-fim.test.js does for the File integrity tab. No DOM, no network.
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
const DETAIL = { ...alert(A1), config: null, configuration: {}, manager: 'mgr-lab', decoder: 'sshd', location: '/var/log/auth.log', alert_ref: '1761.1', full_log: 'Failed password for invalid user admin from 203.0.113.9', data: { srcip: '203.0.113.9', srcuser: 'admin' }, file_integrity: {} };

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

const C1 = '00000000-0000-4000-8000-0000000000c1', C2 = '00000000-0000-4000-8000-0000000000c2', C3 = '00000000-0000-4000-8000-0000000000c3';
const CIS = 'CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0';
const cfgOf = (o) => ({ policy: CIS, policy_id: 'cis_ubuntu22-04', type: 'check', check_id: '28500', check_title: 'Ensure SSH root login is disabled', result: 'failed', previous_result: 'passed', score: null, passed: null, failed: null, invalid: null, total: null, ...o });
const CFG = [
  alert(C1, { rule_id: '19008', level: 7, severity: 'medium', description: CIS + ': Ensure SSH root login is disabled', user: null, src_ip: null, mitre: mitre([], []), config: cfgOf({}) }),
  alert(C2, { rule_id: '19008', level: 3, severity: 'low', description: 'x', agent: { id: '003', name: 'db1', ip: '10.0.0.31' }, user: null, src_ip: null, mitre: mitre([], []), config: cfgOf({ check_id: '28501', check_title: 'Ensure X11 forwarding is disabled', result: 'passed', previous_result: null }) }),
  alert(C3, { rule_id: '19004', level: 9, severity: 'high', description: 'SCA summary', user: null, src_ip: null, mitre: mitre([], []), config: cfgOf({ type: 'summary', check_id: null, check_title: null, result: null, previous_result: null, score: 72, passed: 120, failed: 45, invalid: 12, total: 177 }) }),
];
const CSUM = { success: true, window: '24h', since: 'x', severity: { critical: 0, high: 1, medium: 1, low: 1, unknown: 0, total: 3 },
  top: { rules: [{ rule_id: '19008', description: 'check', level: 7, count: 2 }], agents: [{ name: 'web1', count: 2 }, { name: 'db1', count: 1 }], techniques: [], tactics: [], files: [], file_events: [],
    policies: [{ name: CIS, count: 3 }], check_results: [{ name: 'failed', count: 1 }, { name: 'passed', count: 1 }, { name: 'not applicable', count: 1 }] }, sampled: { events: 3, truncated: false } };
const CDETAIL = { ...DETAIL, id: C1, rule_id: '19008', config: cfgOf({}), configuration: { policy: CIS, check_remediation: 'Set PermitRootLogin no.', check_rationale: 'Direct root login hides who did what.' }, data: {} };
const cfgAnswers = (over = {}) => ({ '/v1/endpoints/alerts/summary': () => CSUM, '/v1/endpoints/alerts': () => ({ success: true, alerts: CFG, count: 3, offset: 0, limit: 50, more: false, window: '24h' }), ...over });
const cfgTab = async (answers) => { const p = await open(cfgAnswers(answers)); await p.click('Configuration checks'); return p; };
const selects = (p) => p.all().filter((n) => n.tag === 'select');
const cfgCalls = (p) => p.listCalls().filter((c) => qs(c.p).kind === 'configuration');

describe('Endpoints page, Configuration checks tab', () => {
  it('there is a Configuration checks tab after File integrity; nothing is loaded for it until it is opened, and the other tabs never ask for it', async () => {
    const p = await open(cfgAnswers()); const labels = p.all().filter((n) => typeof n === 'object' && n.attrs && n.attrs.className && String(n.attrs.className).startsWith('xtab')).map((n) => n.attrs.textContent);
    assert.deepStrictEqual(labels, ['Overview', 'Agents', 'Alerts', 'File integrity', 'Configuration checks', 'Add a machine', 'Third-party notices']);
    assert.ok(!p.calls.some((c) => c.p.includes('/alerts')), 'no alert call before a tab is opened');
    await p.alertsTab(); await p.click('File integrity'); assert.ok(p.calls.filter((c) => c.p.includes('/alerts')).every((c) => !c.p.includes('configuration') && !c.p.includes('check_result') && !c.p.includes('policy=')));
  });
  it('opening it asks for the cards and the list with kind=configuration, the 24 hour window and no result or policy', async () => {
    const p = await cfgTab(); assert.strictEqual(p.sumCalls().length, 1); assert.strictEqual(p.listCalls().length, 1);
    for (const c of [p.sumCalls()[0], p.listCalls()[0]]) { const q = qs(c.p); assert.strictEqual(q.kind, 'configuration'); assert.strictEqual(q.window, '24h'); assert.ok(!('check_result' in q) && !('policy' in q) && !('file_event' in q)); }
    assert.ok(p.calls.every((c) => c.method === 'GET'));
  });
  it('draws the checks: result and what it was before, policy, check title or summary counts, machine; and the cards with results and policies', async () => {
    const p = await cfgTab(); const t = p.text();
    assert.deepStrictEqual(p.all().filter((n) => n.tag === 'th').map((n) => n.textContent), ['Time (UTC)', 'Result', 'Policy', 'Check', 'Machine', 'Severity']);
    assert.match(t, /Configuration checks, last 24 hours/); assert.match(t, /failed \(was passed\)/); assert.match(t, /Ensure SSH root login is disabled/); assert.match(t, /scan summary/); assert.match(t, /120 passed, 45 failed, score 72%/);
    assert.match(t, /Results/); assert.match(t, /Policies/); assert.match(t, /not applicable/); assert.match(t, /configuration check alerts/); assert.ok(!/ATT&CK techniques/.test(t), 'no ATT&CK cards on this tab');
  });
  it('clicking a result chip filters the list (the choice shows it, "not applicable" is sent with an underscore); the cards stay the breakdown', async () => {
    const p = await cfgTab(); await p.clickStarting('failed');
    let q = qs(p.listCalls().at(-1).p); assert.deepStrictEqual([q.kind, q.check_result, q.offset], ['configuration', 'failed', '0']); assert.strictEqual(p.sumCalls().length, 1); assert.strictEqual(selects(p)[2].value, 'failed');
    await p.clickStarting('not applicable'); q = qs(p.listCalls().at(-1).p); assert.strictEqual(q.check_result, 'not_applicable'); assert.strictEqual(selects(p)[2].value, 'not_applicable');
  });
  it('choosing a result, or a policy, reloads the list and the cards with kind kept; a policy chip fills the policy box', async () => {
    const p = await cfgTab(); const sel = selects(p); assert.strictEqual(sel.length, 3, 'window, severity, result');
    sel[2].value = 'passed'; await sel[2].onchange(); await p.settle(); assert.strictEqual(qs(p.listCalls().at(-1).p).check_result, 'passed'); assert.strictEqual(qs(p.sumCalls().at(-1).p).check_result, 'passed'); assert.strictEqual(qs(p.sumCalls().at(-1).p).kind, 'configuration');
    await p.clickStarting(CIS); const q = qs(p.listCalls().at(-1).p); assert.deepStrictEqual([q.kind, q.policy, q.check_result], ['configuration', CIS, 'passed']);
    assert.strictEqual(p.find((a) => a.placeholder === 'Policy name', 'box').value, CIS);
    sel[2].value = ''; await sel[2].onchange(); await p.settle(); assert.ok(!('check_result' in qs(p.listCalls().at(-1).p)), 'cleared');
  });
  it('typing a policy and pressing Search sends it, trimmed; text, machine and severity still apply with kind', async () => {
    const p = await cfgTab(); p.typeInto('Policy name', '  ' + CIS + ' '); p.typeInto('Search check title, policy, machine or description', 'ssh'); await p.click('Search');
    let q = qs(p.listCalls().at(-1).p); assert.deepStrictEqual([q.kind, q.policy, q.q], ['configuration', CIS, 'ssh']);
    await p.clickStarting('db1'); q = qs(p.listCalls().at(-1).p); assert.deepStrictEqual([q.kind, q.agent, q.policy], ['configuration', 'db1', CIS]);
    const sev = selects(p)[1]; sev.value = 'low'; await sev.onchange(); await p.settle(); q = qs(p.listCalls().at(-1).p); assert.strictEqual(q.severity, 'low'); assert.ok(!('severity' in qs(p.sumCalls().at(-1).p)), 'the cards ignore severity');
  });
  it('the three tabs keep their own filters, and the other two never send the result or the policy', async () => {
    const p = await cfgTab(); await p.clickStarting('failed'); await p.clickStarting(CIS);
    await p.alertsTab(); let q = qs(p.listCalls().at(-1).p); assert.ok(!('kind' in q) && !('check_result' in q) && !('policy' in q), JSON.stringify(q)); assert.strictEqual(selects(p).length, 2);
    await p.click('File integrity'); q = qs(p.listCalls().at(-1).p); assert.strictEqual(q.kind, 'file_integrity'); assert.ok(!('check_result' in q) && !('policy' in q));
    await p.click('Configuration checks'); q = qs(p.listCalls().at(-1).p); assert.deepStrictEqual([q.kind, q.check_result, q.policy], ['configuration', 'failed', CIS]);
  });
  it('a filter set on the Alerts tab is not used on Configuration checks, and the other way round', async () => {
    const p = await open(cfgAnswers()); await p.alertsTab(); await p.clickStarting('web1');   // Alerts tab: only machine web1
    assert.strictEqual(qs(p.listCalls().at(-1).p).agent, 'web1');
    await p.click('Configuration checks'); assert.ok(!('agent' in qs(p.listCalls().at(-1).p)), 'Configuration checks starts clean');
    await p.clickStarting('db1'); await p.alertsTab(); const q = qs(p.listCalls().at(-1).p); assert.strictEqual(q.agent, 'web1'); assert.ok(!('kind' in q));
  });
  it('opening a row loads that alert by id and draws the check card and the manager\'s check text; Next pages with kind kept', async () => {
    const p = await cfgTab({ '/v1/endpoints/alerts': () => ({ success: true, alerts: CFG, count: 3, offset: 0, limit: 50, more: true, window: '24h' }), ['/v1/endpoints/alerts/' + C1]: () => ({ success: true, alert: CDETAIL }) });
    await p.click('2026-10-27 10:00:00'); assert.strictEqual(p.calls.at(-1).p, '/v1/endpoints/alerts/' + C1);
    const t = p.text(); assert.match(t, /Configuration check/); assert.match(t, /Check details from the manager/); assert.match(t, /Set PermitRootLogin no\./); assert.match(t, /Result before/);
    await p.click('Next'); const q = qs(p.listCalls().at(-1).p); assert.deepStrictEqual([q.kind, q.offset], ['configuration', '50']);
  });
  it('a scan summary opens with its score and counts', async () => {
    const p = await cfgTab({ ['/v1/endpoints/alerts/' + C3]: () => ({ success: true, alert: { ...CDETAIL, id: C3, config: CFG[2].config, configuration: { type: 'summary' } } }) });
    const f = p.all().filter((n) => n.attrs && n.attrs.textContent === '2026-10-27 10:00:00' && typeof n.attrs.onclick === 'function'); await f[2].attrs.onclick(); await p.settle();
    assert.match(p.text(), /72%/); assert.match(p.text(), /Checks in the scan/); assert.match(p.text(), /177/);
  });
  it('shows its own empty text, shows a failure in place, and never draws check text as HTML', async () => {
    let p = await cfgTab({ '/v1/endpoints/alerts': () => ({ success: true, alerts: [], count: 0, offset: 0, limit: 50, more: false, window: '24h' }), '/v1/endpoints/alerts/summary': () => ({ ...CSUM, severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0 }, top: { rules: [], agents: [], techniques: [], tactics: [], files: [], file_events: [], policies: [], check_results: [] } }) });
    assert.match(p.text(), /No configuration check alerts match/); assert.ok(!/No alerts match/.test(p.text()) && !/No file changes match/.test(p.text()));
    p = await cfgTab({ '/v1/endpoints/alerts': () => { throw new Error('You do not have permission: search:events:read'); } }); assert.match(p.text(), /search:events:read/);
    const evil = '<img src=x onerror=alert(1)>';
    p = await cfgTab({ '/v1/endpoints/alerts': () => ({ success: true, alerts: [{ ...CFG[0], config: cfgOf({ check_title: evil, policy: evil }) }], count: 1, offset: 0, limit: 50, more: false, window: '24h' }), '/v1/endpoints/alerts/summary': () => ({ ...CSUM, top: { ...CSUM.top, policies: [{ name: evil, count: 1 }] } }) });
    assert.ok(p.text().includes(evil)); assert.ok(!p.all().some((n) => n.tag === 'img')); assert.ok(!p.all().some((n) => typeof n === 'object' && n.attrs && 'innerHTML' in n.attrs));
  });
  it('an answer from an older API without policies and results still draws', async () => {
    const old = { ...CSUM, top: { rules: [], agents: [], techniques: [], tactics: [] } };
    const p = await cfgTab({ '/v1/endpoints/alerts/summary': () => old }); assert.match(p.text(), /Results/); assert.match(p.text(), /Ensure SSH root login is disabled/);
  });
  it('an alert from an older API without a config part still draws as a row', async () => {
    const p = await cfgTab({ '/v1/endpoints/alerts': () => ({ success: true, alerts: [{ ...CFG[0], config: undefined }], count: 1, offset: 0, limit: 50, more: false, window: '24h' }) }); assert.match(p.text(), /Configuration checks, last 24 hours/);
  });
});

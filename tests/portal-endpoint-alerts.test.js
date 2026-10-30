'use strict';
// The Alerts tab of the Endpoints page (src/portal/index.html, pgEndpoints > alertsView; docs/endpoints.md, task E6b): the page function is cut out and run with small stand-ins
// for el(), card(), pill(), table(), kv(), when(), api() and route(), exactly as tests/portal-endpoints.test.js does. No DOM, no network.
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

describe('Endpoints page, Alerts tab', () => {
  it('there is an Alerts tab; nothing about alerts is loaded until it is opened', async () => {
    const p = await open(); assert.match(p.text(), /Overview/); p.find((a) => a.textContent === 'Alerts' && typeof a.onclick === 'function', 'Alerts tab');
    assert.ok(!p.calls.some((c) => c.p.includes('/alerts')), 'no alert call before the tab is opened');
  });
  it('is read only: only GET calls, on the three alert routes, and no HTML injection anywhere in the page code', async () => {
    // E4m: the two small functions of the disconnected-agent alert are the ONLY place that writes; everything else stays read only. They may only PUT to the one route.
    const e4m = ['agentAlertCard', 'agentSkipButton'].map((n) => { const i = source.indexOf('function ' + n + '('); assert.ok(i >= 0, n); return source.slice(i, source.indexOf('\n}\n', i) + 3); });
    const rest = e4m.reduce((s, f) => s.replace(f, ''), source);
    for (const f of e4m) { assert.ok(/method: 'PUT'/.test(f)); assert.ok((f.match(/method:/g) || []).length === (f.match(/method: 'PUT'/g) || []).length); assert.ok((f.match(/api\('([^']*)'/g) || []).every((x) => x === "api('/v1/endpoints/agent-alert'")); assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write/.test(f)); }
    assert.ok(!/innerHTML|insertAdjacentHTML|outerHTML|document\.write|method:/.test(rest));
    const p = await open(); await p.alertsTab(); await p.click('Search');
    const a = p.calls.filter((c) => c.p.includes('/alerts')); assert.ok(a.length >= 4);
    assert.ok(a.every((c) => c.method === 'GET' && /^\/v1\/endpoints\/alerts(\/summary)?\?/.test(c.p)));
  });
  it('first load: the summary and the list for the last 24 hours, 50 to a page, no filters', async () => {
    const p = await open(); await p.alertsTab();
    assert.strictEqual(p.sumCalls().length, 1); assert.strictEqual(p.listCalls().length, 1);
    assert.deepStrictEqual(qs(p.sumCalls()[0].p), { window: '24h' }); assert.deepStrictEqual(qs(p.listCalls()[0].p), { window: '24h', limit: '50', offset: '0' });
  });
  it('the cards show the exact severity counts, the top machines, techniques, tactics and rules, and say what is sampled', async () => {
    const p = await open(); await p.alertsTab(); const t = p.text();
    assert.match(t, /Alerts, last 24 hours/); assert.ok(p.all().some((n) => n.attrs && n.attrs.className === 'stat' && n.attrs.textContent === '3'));
    for (const s of ['high  1', 'medium  1', 'low  1', 'critical  0']) assert.ok(t.includes(s), s);
    assert.match(t, /web1  2/); assert.match(t, /T1110 Brute Force  1/); assert.match(t, /Credential Access  1/); assert.match(t, /5763 sshd: brute force  1/); assert.match(t, /counted over the newest 3 alerts/);
  });
  it('the list shows time, severity with level, rule, machine, ATT&CK ids and the detail', async () => {
    const p = await open(); await p.alertsTab(); const t = p.text();
    assert.match(t, /2026-10-27 10:00:00/); assert.match(t, /high {2}10/); assert.match(t, /5763: sshd: brute force/); assert.match(t, /web1/); assert.match(t, /T1565\.001/); assert.match(t, /\/etc\/passwd/); assert.match(t, /user admin; from 203\.0\.113\.9/);
  });
  it('clicking a severity pill filters the list but not the summary (the cards stay a breakdown)', async () => {
    const p = await open(); await p.alertsTab();
    await p.clickTitle('Show only high');
    assert.strictEqual(qs(p.listCalls().at(-1).p).severity, 'high'); assert.strictEqual(qs(p.listCalls().at(-1).p).offset, '0');
    assert.strictEqual(p.sumCalls().length, 1, 'the cards are not reloaded by a severity click'); assert.ok(!('severity' in qs(p.sumCalls()[0].p)));
  });
  it('clicking a machine or an ATT&CK technique filters both the list and the cards, and starts again from the first page', async () => {
    const p = await open(); await p.alertsTab();
    await p.clickStarting('web1  2');
    assert.strictEqual(qs(p.listCalls().at(-1).p).agent, 'web1');
    await p.clickStarting('T1110 Brute Force');
    const l = qs(p.listCalls().at(-1).p); assert.deepStrictEqual([l.agent, l.mitre, l.offset], ['web1', 'T1110', '0']);
  });
  it('Search sends the text boxes trimmed and the window and severity as chosen; empty boxes are left out; Enter does the same', async () => {
    const p = await open(); await p.alertsTab();
    p.typeInto('Search description, user, address or file', '  passwd  '); p.typeInto('Machine name', 'db1'); p.typeInto('ATT&CK id, e.g. T1110', '');
    await p.click('Search');
    assert.deepStrictEqual(qs(p.listCalls().at(-1).p), { window: '24h', q: 'passwd', agent: 'db1', limit: '50', offset: '0' });
    assert.deepStrictEqual(qs(p.sumCalls().at(-1).p), { window: '24h', q: 'passwd', agent: 'db1' });
    const box = p.find((a) => a.placeholder === 'Machine name', 'machine box'); box.value = 'web1'; await box.onkeydown({ key: 'Enter' }); await p.settle();
    assert.strictEqual(qs(p.listCalls().at(-1).p).agent, 'web1');
  });
  it('the window and severity selects apply at once', async () => {
    const p = await open(); await p.alertsTab();
    const sels = p.all().filter((n) => n.tag === 'select' && typeof n.onchange === 'function');
    assert.strictEqual(sels.length, 2);
    sels[0].value = '7d'; await sels[0].onchange(); await p.settle(); assert.strictEqual(qs(p.listCalls().at(-1).p).window, '7d'); assert.strictEqual(qs(p.sumCalls().at(-1).p).window, '7d');
    sels[1].value = 'critical'; await sels[1].onchange(); await p.settle(); assert.strictEqual(qs(p.listCalls().at(-1).p).severity, 'critical'); assert.ok(!('severity' in qs(p.sumCalls().at(-1).p)));
    assert.deepStrictEqual(Array.from(sels[0].kids, (o) => o.attrs.value), ['1h', '24h', '7d', '30d']); assert.deepStrictEqual(Array.from(sels[1].kids, (o) => o.attrs.value), ['', 'critical', 'high', 'medium', 'low']);
  });
  it('paging: Previous is off on the first page, Next follows the server\'s "more" and asks for the next 50', async () => {
    const more = { success: true, alerts: ALERTS, count: 3, offset: 0, limit: 50, more: true, window: '24h' };
    const p = await open({ '/v1/endpoints/alerts': (path) => ({ ...more, more: qs(path).offset === '0' }) }); await p.alertsTab();
    const btn = (label) => p.find((a) => a.textContent === label && typeof a.onclick === 'function', label);
    assert.strictEqual(btn('Previous').disabled, true); assert.strictEqual(btn('Next').disabled, false);
    await p.click('Next'); assert.strictEqual(qs(p.listCalls().at(-1).p).offset, '50');
    assert.strictEqual(btn('Previous').disabled, false); assert.strictEqual(btn('Next').disabled, true);
    await p.click('Previous'); assert.strictEqual(qs(p.listCalls().at(-1).p).offset, '0');
  });
  it('with no alerts it says how they get here; with no more pages Next is off', async () => {
    const p = await open({ '/v1/endpoints/alerts': { success: true, alerts: [], count: 0, offset: 0, limit: 50, more: false, window: '24h' } }); await p.alertsTab();
    assert.match(p.text(), /No alerts match\. Alerts appear here once a broker/);
    const p2 = await open(); await p2.alertsTab(); assert.strictEqual(p2.find((a) => a.textContent === 'Next' && typeof a.onclick === 'function', 'Next').disabled, true);
  });

  it('opening an alert loads it by id and shows the details, the log line and the MITRE techniques with names, links and tactics', async () => {
    const p = await open(); await p.alertsTab();
    await p.click('2026-10-27 10:00:00');   // the first row's time
    assert.strictEqual(p.calls.at(-1).p, '/v1/endpoints/alerts/' + A1); const t = p.text();
    assert.match(t, /rule level 10/); assert.match(t, /mgr-lab/); assert.match(t, /sshd/); assert.match(t, /\/var\/log\/auth\.log/); assert.match(t, /MITRE ATT&CK/); assert.match(t, /Brute Force/); assert.match(t, /Credential Access/);
    assert.match(t, /Failed password for invalid user admin/); assert.match(t, /Details from the event/); assert.match(t, /srcip/); assert.ok(!p.all().some((n) => n.tag === 'h3' && n.textContent === 'File integrity'), 'an empty section is not drawn');   // the tab of that name (E6c) is not a section
    const links = p.all().filter((n) => n.tag === 'a'); assert.deepStrictEqual(links.map((n) => [n.attrs.href, n.attrs.target, n.attrs.rel, n.attrs.textContent]), [['https://attack.mitre.org/techniques/T1110/', '_blank', 'noopener noreferrer', 'T1110']]);
  });
  it('a technique link is made only for a real ATT&CK technique address; anything else is plain text', async () => {
    const hostile = ['javascript:alert(1)', 'https://attack.mitre.org.evil.example/techniques/T1110/', 'http://attack.mitre.org/techniques/T1110/', 'https://attack.mitre.org/techniques/T1110/../../x/', 'https://attack.mitre.org/techniques/T1110/?a=1', null, ''];
    for (const url of hostile) {
      const d = { ...DETAIL, mitre: mitre([['T1110', 'x', url]], ['A']) };
      const p = await open({ ['/v1/endpoints/alerts/' + A1]: { success: true, alert: d } }); await p.alertsTab(); await p.click('2026-10-27 10:00:00');
      assert.strictEqual(p.all().filter((n) => n.tag === 'a').length, 0, String(url)); assert.match(p.text(), /T1110/);
    }
    const ok = ['https://attack.mitre.org/techniques/T1565/001/', 'https://attack.mitre.org/techniques/T1110/'];
    for (const url of ok) { const p = await open({ ['/v1/endpoints/alerts/' + A1]: { success: true, alert: { ...DETAIL, mitre: mitre([['T1110', 'x', url]], []) } } }); await p.alertsTab(); await p.click('2026-10-27 10:00:00'); assert.strictEqual(p.all().filter((n) => n.tag === 'a').length, 1, url); }
  });
  it('an alert with no ATT&CK mapping says so; names that could not be matched are listed apart', async () => {
    const none = await open({ ['/v1/endpoints/alerts/' + A1]: { success: true, alert: { ...DETAIL, mitre: mitre([], []) } } }); await none.alertsTab(); await none.click('2026-10-27 10:00:00');
    assert.match(none.text(), /carries no ATT&CK mapping/);
    const un = await open({ ['/v1/endpoints/alerts/' + A1]: { success: true, alert: { ...DETAIL, mitre: { techniques: [{ id: 'T1059', name: null, url: 'https://attack.mitre.org/techniques/T1059/' }], unpaired_names: ['Command and Scripting Interpreter', 'Other'], tactics: [] } } } });
    await un.alertsTab(); await un.click('2026-10-27 10:00:00'); assert.match(un.text(), /could not be matched to the ids\): Command and Scripting Interpreter, Other/);
  });
  it('file integrity fields get their own section', async () => {
    const p = await open({ ['/v1/endpoints/alerts/' + A1]: { success: true, alert: { ...DETAIL, data: {}, file_integrity: { path: '/etc/passwd', md5_after: 'bbbb' } } } }); await p.alertsTab(); await p.click('2026-10-27 10:00:00');
    assert.match(p.text(), /File integrity/); assert.match(p.text(), /md5_after/); assert.ok(!/Details from the event/.test(p.text()));
  });
  it('text from the alerts stays text: a hostile machine name, description, log line and detail value are never turned into elements', async () => {
    const evil = '<img src=x onerror=alert(1)>';
    const bad = { ...alert(A1, { description: evil, agent: { id: '1', name: evil, ip: evil }, user: evil, src_ip: evil }), manager: evil, decoder: evil, location: evil, alert_ref: evil, full_log: evil, data: { [evil]: evil }, file_integrity: {} };
    const p = await open({ '/v1/endpoints/alerts': { success: true, alerts: [bad], count: 1, offset: 0, limit: 50, more: false, window: '24h' }, ['/v1/endpoints/alerts/' + A1]: { success: true, alert: bad },
      '/v1/endpoints/alerts/summary': { ...SUM, top: { ...SUM.top, agents: [{ name: evil, count: 1 }] } } });
    await p.alertsTab(); await p.click('2026-10-27 10:00:00');
    assert.ok(!p.all().some((n) => n.tag === 'img' || n.tag === 'script'));
    assert.ok(p.text().includes(evil));
  });
  it('shows no product name on the Alerts tab (it is named on the Third-party notices tab only)', async () => {
    const p = await open(); await p.alertsTab(); await p.click('2026-10-27 10:00:00');
    assert.ok(!/wazuh/i.test(p.text()), 'no Wazuh in the alerts list, cards or detail');
  });

  it('a failing summary is shown without hiding the list; a failing list is shown without hiding the cards; a failing detail is shown under the list', async () => {
    const a = await open({ '/v1/endpoints/alerts/summary': new Error('502 broke') }); await a.alertsTab();
    assert.match(a.text(), /502 broke/); assert.match(a.text(), /5763: sshd: brute force/);
    const b = await open({ '/v1/endpoints/alerts': new Error('500 list broke') }); await b.alertsTab();
    assert.match(b.text(), /500 list broke/); assert.match(b.text(), /Alerts, last 24 hours/);
    const c = await open({ ['/v1/endpoints/alerts/' + A1]: new Error('404 gone') }); await c.alertsTab(); await c.click('2026-10-27 10:00:00');
    assert.match(c.text(), /404 gone/); assert.match(c.text(), /5763: sshd: brute force/);
  });
  it('a missing permission is shown as the server says it, on both parts', async () => {
    const denied = new Error('Forbidden: search:events:read is required'); denied.status = 403;
    const p = await open({ '/v1/endpoints/alerts/summary': denied, '/v1/endpoints/alerts': denied }); await p.alertsTab();
    assert.strictEqual((p.text().match(/search:events:read is required/g) || []).length, 2);
  });
  it('the other tabs and an unreachable manager are unchanged: no alert call is made for them', async () => {
    const p = await open({}, { ...MANAGER, status: { reachable: false, code: 'TIMEOUT', message: 'no answer' } }); assert.match(p.text(), /Not reachable/); await p.click('Agents');
    assert.ok(!p.calls.some((c) => c.p.includes('/alerts')));
  });
  it('the breadcrumb follows the open tab, and the pills and times do not wrap', async () => {
    const crumb = el('div', {}); global.document = { getElementById: (id) => (id === 'crumb' ? crumb : null) };
    try {
      const p = await open(); assert.match(texts(crumb), /Endpoints.*Overview/);
      await p.alertsTab(); assert.match(texts(crumb), /Endpoints.*Alerts/); assert.ok(!/Agents/.test(texts(crumb)));
      await p.click('Third-party notices'); assert.match(texts(crumb), /Third-party notices/);
    } finally { delete global.document; }
    const p = await open(); await p.alertsTab();
    assert.ok(p.all().some((n) => n.attrs && n.attrs.className === 'pill' && /nowrap/.test(n.attrs.style || '') && /^high/.test(n.attrs.textContent || '')));
    assert.ok(p.all().some((n) => n.attrs && /nowrap/.test(n.attrs.style || '') && n.attrs.textContent === '2026-10-27 10:00:00'));
  });
  it('rule chips: clicking a rule shows only that rule, "hide" hides it; both appear as removable filters and go to the list and the cards', async () => {
    const p = await open(); await p.alertsTab();
    await p.clickStarting('5763 sshd: brute force');
    assert.strictEqual(qs(p.listCalls().at(-1).p).rule, '5763'); assert.strictEqual(qs(p.sumCalls().at(-1).p).rule, '5763'); assert.match(p.text(), /Only rule 5763/);
    await p.clickStarting('Only rule 5763');
    assert.ok(!('rule' in qs(p.listCalls().at(-1).p))); assert.ok(!/Only rule/.test(p.text()));
    await p.clickTitle('Hide rule 5763');
    assert.strictEqual(qs(p.listCalls().at(-1).p).exclude_rule, '5763'); assert.strictEqual(qs(p.sumCalls().at(-1).p).exclude_rule, '5763'); assert.strictEqual(qs(p.listCalls().at(-1).p).offset, '0'); assert.match(p.text(), /Hiding rule 5763/);
    await p.clickStarting('Hiding rule 5763');
    assert.ok(!('exclude_rule' in qs(p.listCalls().at(-1).p))); assert.ok(!/Hiding rule/.test(p.text()));
  });
  it('hiding a rule that is shown "only" drops the "only" filter, and showing one "only" un-hides it', async () => {
    const p = await open(); await p.alertsTab();
    await p.clickStarting('5763 sshd: brute force'); await p.clickTitle('Hide rule 5763');
    let l = qs(p.listCalls().at(-1).p); assert.ok(!('rule' in l)); assert.strictEqual(l.exclude_rule, '5763');
    await p.clickStarting('5763 sshd: brute force');
    l = qs(p.listCalls().at(-1).p); assert.strictEqual(l.rule, '5763'); assert.ok(!('exclude_rule' in l));
  });
});


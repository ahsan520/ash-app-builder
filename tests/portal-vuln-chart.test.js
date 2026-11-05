'use strict';
// E6m: the severity chart on the Trend card of the Vulnerabilities tab and the links from a machine to its findings (src/portal/index.html: vulnChartModel, vulnChart,
// vulnerabilitiesView(focusAgent), the Agents tab of pgEndpoints). The functions are cut out of the page and run with small stand-ins, as in portal-vuln-trend.test.js and
// portal-endpoints.test.js. No DOM, no network.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const cut = (head) => { const i = html.indexOf(head); assert.ok(i >= 0, head + ' not found'); const j = html.indexOf('\n}\n', i); return html.slice(i, j + 3); };
const i0 = html.indexOf('const EP_VULN_COL ='), i1 = html.indexOf('async function pgEndpoints');
const vulnSource = html.slice(i0, i1);
const pageSource = html.slice(html.indexOf('const EP_STATUS ='), i1) + cut('async function pgEndpoints');

const el = (tag, attrs, ...kids) => Object.assign({}, attrs || {}, { tag, attrs: attrs || {}, kids: kids.flat(Infinity), replaceChildren(...k) { this.kids = k.flat(Infinity); }, append(...k) { this.kids.push(...k.flat(Infinity)); } });
const walk = (n) => (typeof n === 'string' ? [n] : n && typeof n === 'object' ? (Array.isArray(n) ? n.flatMap(walk) : [n, ...(n.kids || []).flatMap(walk)]) : []);
const texts = (n) => walk(n).map((x) => (typeof x === 'string' ? x : typeof x.textContent === 'string' ? x.textContent : '')).join(' | ');
const nodes = (t) => walk(t).filter((n) => n && typeof n === 'object' && n.attrs);
const card = (title, ...kids) => el('div', { className: 'card' }, title ? el('h3', { textContent: title }) : '', ...kids);
const pill = (t, c) => el('span', { className: 'pill ' + (c || 'off'), textContent: t });
const kv = (o) => el('div', {}, Object.entries(o).map(([k, v]) => el('div', { className: 'kv' }, el('span', { textContent: k }), el('span', { textContent: v === null || v === undefined ? '-' : String(v) }))));
const when = (v) => (v ? String(v).replace('T', ' ').replace(/\.\d+Z?$/, '') : '-');
const table = (cols, rows, empty) => (!rows.length ? el('div', { className: 'mute', textContent: empty || 'Nothing to show yet.' })
  : el('table', {}, el('tr', {}, cols.map((c) => el('th', { textContent: c.h }))), rows.map((r) => el('tr', {}, cols.map((c) => { const v = c.f(r); return typeof v === 'object' && v ? el('td', {}, v) : el('td', { textContent: String(v ?? '-') }); })))));
const tick = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r)); };

const SOURCE = { available: true, registered: true, label: 'Acme', host: 'idx', port: 9200, index: 'wazuh-states-vulnerabilities-acme', index_user: 'u', cert_sha256: 'a'.repeat(64), updated_at: '2026-11-01T00:00:00Z', status: { reachable: true, count: 5 } };
const SUMMARY = { total: 5, machines: 1, distinct_cves: 5, severity: { critical: 1, high: 1, medium: 1, low: 1, unknown: 0 }, top_packages: [], top_cves: [], top_agents: [] };
const pt = (day, o = {}) => ({ day, findings_total: 100, machines: 3, critical: 4, high: 10, medium: 30, low: 56, new_critical: 0, new_total: 2, total_change: 5, critical_change: -1, ...o });
const bars = (t) => nodes(t).filter((n) => /^\d{4}-\d{2}-\d{2}: /.test(n.attrs.title || ''));

const lib = new Function('el', 'card', 'pill', 'table', 'kv', 'when', 'api', vulnSource + '\nreturn { vulnerabilitiesView, vulnChartModel, vulnChart };');
const pure = lib(el, card, pill, table, kv, when, async () => { throw new Error('no api here'); });

async function openTab(trend, focus) {
  const calls = [];
  const api = async (p) => {
    calls.push(p);
    if (p === '/v1/endpoints/vulnerabilities/status') return { success: true, source: SOURCE };
    if (p.startsWith('/v1/endpoints/vulnerabilities/summary')) return { success: true, summary: SUMMARY };
    if (p.startsWith('/v1/endpoints/vulnerabilities/trend')) { if (trend instanceof Error) throw trend; return trend; }
    if (p.startsWith('/v1/endpoints/vulnerabilities?')) return { success: true, total: 0, limit: 50, offset: 0, findings: [] };
    throw new Error('unexpected call ' + p);
  };
  const fn = lib(el, card, pill, table, kv, when, api).vulnerabilitiesView;
  const tree = fn(focus); await tick();
  return { tree, calls, text: () => texts(tree) };
}

describe('the severity chart model', () => {
  it('stacks critical, high, medium, low and not rated in that order and finds the tallest day', () => {
    const m = pure.vulnChartModel([pt('2026-12-01', { critical: 1, high: 2, medium: 3, low: 4 }), pt('2026-12-02', { critical: 0, high: 0, medium: 0, low: 9 })], 'all');
    assert.deepStrictEqual(m.sevs, ['critical', 'high', 'medium', 'low', 'unknown']);
    assert.deepStrictEqual(m.cols[0].segs.map((s) => s.n), [1, 2, 3, 4, 0]); assert.strictEqual(m.cols[0].total, 10); assert.strictEqual(m.cols[1].total, 9); assert.strictEqual(m.max, 10);
  });
  it('"critical and high" leaves medium and low out of the bars and the scale', () => {
    const m = pure.vulnChartModel([pt('2026-12-01', { critical: 1, high: 2, medium: 300, low: 400 })], 'ch');
    assert.deepStrictEqual(m.sevs, ['critical', 'high']); assert.strictEqual(m.cols[0].total, 3); assert.strictEqual(m.max, 3);
  });
  it('an unknown mode falls back to all severities', () => assert.strictEqual(pure.vulnChartModel([pt('2026-12-01')], 'x').sevs.length, 5));
  it('a missing, negative or fractional number counts as 0; a day with none of them is marked as having no figures', () => {
    const m = pure.vulnChartModel([{ day: '2026-12-01', critical: null, high: -3, medium: 2.5, low: 7 }, { day: '2026-12-02' }], 'all');
    assert.deepStrictEqual(m.cols[0].segs.map((s) => s.n), [0, 0, 0, 7, 0]); assert.strictEqual(m.cols[0].known, true);
    assert.strictEqual(m.cols[1].total, 0); assert.strictEqual(m.cols[1].known, false); assert.strictEqual(m.max, 7);
  });
  it('anything that is not a list gives an empty model, and the input is not changed', () => {
    assert.deepStrictEqual(pure.vulnChartModel(null, 'all').cols, []); assert.strictEqual(pure.vulnChartModel(undefined, 'all').max, 0);
    const input = [pt('2026-12-01')], copy = JSON.stringify(input); pure.vulnChartModel(input, 'ch'); assert.strictEqual(JSON.stringify(input), copy);
  });
});

describe('the severity chart', () => {
  it('draws one bar a day, oldest first, with the day and the counts in its tooltip and the first and last day under it', () => {
    const c = pure.vulnChart([pt('2026-12-01', { critical: 1, high: 2, medium: 3, low: 4 }), pt('2026-12-02'), pt('2026-12-03')], 'all');
    const b = bars(c); assert.strictEqual(b.length, 3);
    assert.deepStrictEqual(b.map((x) => x.attrs.title.slice(0, 10)), ['2026-12-01', '2026-12-02', '2026-12-03']);
    assert.strictEqual(b[0].attrs.title, '2026-12-01: critical 1, high 2, medium 3, low 4 (10)');
    assert.match(texts(c), /2026-12-01 \| 2026-12-03/);
    const axis = nodes(c).find((n) => n.attrs.role === 'img'); assert.match(axis.attrs['aria-label'], /2026-12-01 to 2026-12-03/);
  });
  it('colours each segment by severity, sizes it by its count, and scales the bars to the tallest day', () => {
    const c = pure.vulnChart([pt('2026-12-01', { critical: 1, high: 2, medium: 3, low: 4 }), pt('2026-12-02', { critical: 0, high: 0, medium: 0, low: 5 })], 'all');
    const [first, second] = bars(c), inner = (b) => b.kids[0];
    assert.match(inner(first).attrs.style, /height:100%/); assert.match(inner(second).attrs.style, /height:50%/);
    assert.deepStrictEqual(inner(first).kids.map((s) => /^flex:(\d+) /.exec(s.attrs.style)[1]), ['1', '2', '3', '4'], 'critical at the bottom: the column runs bottom to top');
    assert.match(inner(first).attrs.style, /column-reverse/);
    assert.match(inner(first).kids[0].attrs.style, /#e5484d/); assert.match(inner(first).kids[1].attrs.style, /#f08a24/); assert.match(inner(first).kids[2].attrs.style, /#e6c229/); assert.match(inner(first).kids[3].attrs.style, /#6b7fa3/);
    assert.strictEqual(inner(second).kids.length, 1, 'a severity with no findings draws no segment');
  });
  it('a day with findings is never thinner than 2% and an empty day is height 0', () => {
    const c = pure.vulnChart([pt('2026-12-01', { critical: 1, high: 0, medium: 0, low: 0 }), pt('2026-12-02', { critical: 0, high: 0, medium: 0, low: 1000 }), { day: '2026-12-03' }], 'all');
    const h = bars(c).map((b) => b.kids[0].attrs.style.match(/height:(\d+)%/)[1]);
    assert.deepStrictEqual(h, ['2', '100', '0']); assert.match(bars(c)[2].attrs.title, /no figures/);
  });
  it('the legend names the severities of the mode, and "critical and high" has no medium or low in it', () => {
    const all = texts(pure.vulnChart([pt('2026-12-01')], 'all')), ch = texts(pure.vulnChart([pt('2026-12-01')], 'ch'));
    assert.match(all, /critical/); assert.match(all, /medium/); assert.match(all, /low/); assert.match(ch, /critical/); assert.match(ch, /high/); assert.ok(!/medium|low/.test(ch));
    assert.match(all, /tallest day: 100/); assert.match(ch, /tallest day: 14/);
  });
  it('findings with no severity (the lab\'s kernel images, 3240 of 8958) are drawn on top as \"not rated\" in their own colour, are in the tooltip only when there are some, and \"critical and high\" leaves them out', () => {
    const c = pure.vulnChart([pt('2026-12-01', { critical: 1, high: 2, medium: 3, low: 4, unknown: 6 }), pt('2026-12-02')], 'all'), b = bars(c);
    assert.strictEqual(b[0].attrs.title, '2026-12-01: critical 1, high 2, medium 3, low 4, not rated 6 (16)'); assert.ok(!/not rated/.test(b[1].attrs.title), 'no \"not rated 0\" noise');
    const segs = b[0].kids[0].kids; assert.strictEqual(segs.length, 5); assert.match(segs[4].attrs.style, /flex:6 /); assert.match(segs[4].attrs.style, /#4b5563/); assert.ok(!/#6b7fa3/.test(segs[4].attrs.style), 'not the colour of low');
    assert.match(texts(c), /not rated/); assert.ok(!/unknown/.test(texts(c)));
    const ch = pure.vulnChart([pt('2026-12-01', { unknown: 6 })], 'ch'); assert.ok(!/not rated/.test(texts(ch)) && !/not rated/.test(bars(ch)[0].attrs.title));
  });
  it('no summaries draws nothing, and the chart writes no HTML', () => {
    assert.strictEqual(pure.vulnChart([], 'all').kids.length, 0);
    const body = vulnSource.slice(vulnSource.indexOf('function vulnChartModel'), vulnSource.indexOf('function vulnerabilitiesView'));
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(body));
  });
});

describe('the chart on the Trend card', () => {
  const POINTS = { success: true, points: [pt('2026-12-01'), pt('2026-12-02', { critical: 6 }), pt('2026-12-03', { critical: 8, medium: 0 })] };
  it('sits above the table with two buttons, all severities first, and the table is still there', async () => {
    const p = await openTab(POINTS), t = p.text();
    assert.strictEqual(bars(p.tree).length, 3); assert.match(t, /All severities/); assert.match(t, /Critical and high/); assert.match(t, /Trend \(one summary a day\)/); assert.match(t, /Day \(UTC\)/);
    assert.match(bars(p.tree)[0].attrs.title, /medium 30/);
  });
  it('"Critical and high" redraws the chart without another request, and "All severities" brings the rest back', async () => {
    const p = await openTab(POINTS), before = p.calls.length;
    const btn = (label) => nodes(p.tree).find((n) => n.attrs.textContent === label && typeof n.attrs.onclick === 'function');
    btn('Critical and high').attrs.onclick(); assert.ok(!/medium/.test(bars(p.tree)[0].attrs.title)); assert.match(bars(p.tree)[0].attrs.title, /critical 4, high 10 \(14\)/);
    assert.match(btn('Critical and high').attrs.className, /pri/); assert.ok(!/pri/.test(btn('All severities').attrs.className));
    btn('All severities').attrs.onclick(); assert.match(bars(p.tree)[0].attrs.title, /medium 30/);
    assert.strictEqual(p.calls.length, before, 'switching the chart reads nothing');
  });
  it('the By severity card shows findings with no severity as a \"not rated\" pill with a plain explanation, not as \"no usable severity\" and not as low', async () => {
    SUMMARY.severity.unknown = 3240;
    try { const p = await openTab({ success: true, points: [] }), t = p.text(); assert.match(t, /not rated {2}3240/); assert.match(t, /Not rated: the vulnerability source gave these no severity/); assert.ok(!/no usable severity/.test(t));
      const pillNode = nodes(p.tree).find((n) => /^not rated/.test(n.attrs.textContent || '')); assert.match(pillNode.attrs.style, /#4b5563/); const click = nodes(p.tree).find((n) => typeof n.attrs.onclick === 'function' && /not rated/.test(texts(n))); assert.ok(click, 'the pill is a filter since E6q');
      const before = p.calls.length; click.attrs.onclick(); await tick(); const after = p.calls.slice(before);
      assert.ok(after.some((c) => c.startsWith('/v1/endpoints/vulnerabilities?') && /severity=unknown/.test(c)), 'the list is asked for severity=unknown'); assert.ok(after.some((c) => c.startsWith('/v1/endpoints/vulnerabilities/summary') && /severity=unknown/.test(c)));
      const sel = nodes(p.tree).find((n) => n.tag === 'select' && n.kids.some((o) => o.attrs && o.attrs.value === 'unknown')); assert.ok(sel && sel.value === 'unknown', 'the dropdown follows: Not rated'); } finally { SUMMARY.severity.unknown = 0; }
    const none = await openTab({ success: true, points: [] }); assert.ok(!/Not rated: the vulnerability source/.test(none.text()) && !nodes(none.tree).some((n) => /^not rated/.test(n.attrs.textContent || '')), 'no pill and no explanation when there are none (the dropdown still offers Not rated)');
  });
  it('no summary yet shows no chart and no buttons; a failed read shows the message and no chart', async () => {
    const none = await openTab({ success: true, points: [] }); assert.strictEqual(bars(none.tree).length, 0); assert.ok(!/All severities/.test(none.text())); assert.match(none.text(), /No summary yet/);
    const bad = await openTab(new Error('The database is busy')); assert.strictEqual(bars(bad.tree).length, 0); assert.match(bad.text(), /The database is busy/);
  });
});

describe('a machine opens its findings', () => {
  const W = { day: '2026-12-03', since_day: '2026-12-02', complete: true, worse_count: 1, worse: [{ agent_id: '002', name: 'web1', total: 9, critical: 4, high: 1, critical_change: 2, high_change: 0, is_new: false }] };
  it('clicking a machine under "Machines that got worse" filters the cards and the list to it', async () => {
    const p = await openTab({ success: true, points: [pt('2026-12-03')], machines: W }), n0 = p.calls.length;
    const link = nodes(p.tree).find((n) => n.attrs.textContent === 'web1 (002)'); assert.ok(link && typeof link.attrs.onclick === 'function');
    link.attrs.onclick(); await tick();
    const after = p.calls.slice(n0); assert.ok(after.some((c) => c.startsWith('/v1/endpoints/vulnerabilities/summary') && /agent=002/.test(c))); assert.ok(after.some((c) => c.startsWith('/v1/endpoints/vulnerabilities?') && /agent=002/.test(c)));
    assert.strictEqual(nodes(p.tree).find((n) => n.attrs.placeholder === 'Agent id').value, '002', 'the Agent id box shows the filter');
  });
  it('the tab opened for one machine asks for that machine only, from the first request', async () => {
    const p = await openTab({ success: true, points: [] }, '003');
    const sum = p.calls.find((c) => c.startsWith('/v1/endpoints/vulnerabilities/summary')), list = p.calls.find((c) => c.startsWith('/v1/endpoints/vulnerabilities?'));
    assert.match(sum, /agent=003/); assert.match(list, /agent=003/); assert.strictEqual(nodes(p.tree).find((n) => n.attrs.placeholder === 'Agent id').value, '003');
  });
  it('the tab opened without a machine sends no agent filter, and a long or odd id is cut and encoded', async () => {
    const a = await openTab({ success: true, points: [] }); assert.ok(a.calls.every((c) => !/agent=/.test(c)));
    const b = await openTab({ success: true, points: [] }, 'x&y=1 ' + 'z'.repeat(40)); const list = b.calls.find((c) => c.startsWith('/v1/endpoints/vulnerabilities?'));
    const q = new URLSearchParams(list.split('?')[1]); assert.ok(q.get('agent').length <= 20); assert.ok(!q.has('y'), 'an ampersand in the id does not add a parameter');
  });
});

describe('the Agents tab links to the findings and the alerts', () => {
  const agent = (id, name) => ({ id, name, ip: '10.0.0.' + Number(id), register_ip: 'any', status: 'active', version: 'v4.14.9', groups: ['default'], last_keep_alive: '2026-10-25T19:00:00Z', date_added: '2026-10-20T10:00:00Z', node: 'n', manager: 'm', os: { name: 'Ubuntu', version: '24.04', platform: 'ubuntu', arch: 'x86_64' } });
  const LIST = { total: 2, limit: 50, offset: 0, agents: [agent('001', 'web01'), agent('002', 'db01')] };
  const MANAGER = { available: true, registered: true, label: 'lab', host: '192.168.68.54', port: 55000, api_user: 'u', cert_sha256: 'x', updated_at: '2026-10-25T18:49:08Z', status: { reachable: true, version: 'v4.14.9', max_agents: 'unlimited', timezone: 'UTC' } };
  async function page() {
    const calls = [];
    const api = async (p) => {
      calls.push(p);
      if (p === '/v1/endpoints/manager') return { success: true, manager: MANAGER };
      if (p === '/v1/endpoints/agents/summary') return { success: true, summary: { active: 2, disconnected: 0, never_connected: 0, pending: 0, total: 2 } };
      if (p.startsWith('/v1/endpoints/agents?')) return { success: true, ...LIST };
      const one = /^\/v1\/endpoints\/agents\/(\d+)$/.exec(p); if (one) return { success: true, agent: LIST.agents.find((x) => x.id === one[1]) };
      if (p === '/v1/endpoints/vulnerabilities/status') return { success: true, source: SOURCE };
      if (p.startsWith('/v1/endpoints/vulnerabilities/summary')) return { success: true, summary: SUMMARY };
      if (p.startsWith('/v1/endpoints/vulnerabilities/trend')) return { success: true, points: [] };
      if (p.startsWith('/v1/endpoints/vulnerabilities?')) return { success: true, total: 0, limit: 50, offset: 0, findings: [] };
      if (p.startsWith('/v1/endpoints/alerts/summary')) return { success: true, window: '24h', since: 'x', severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0 }, top: { rules: [], agents: [], techniques: [], tactics: [] }, sampled: { events: 0, truncated: false } };
      if (p.startsWith('/v1/endpoints/alerts?')) return { success: true, alerts: [], count: 0, offset: 0, limit: 50, more: false, window: '24h', since: 'x' };
      throw new Error('unexpected call ' + p);
    };
    const fn = new Function('el', 'card', 'pill', 'table', 'kv', 'when', 'api', 'route', 'copyBtn', pageSource + '\nreturn pgEndpoints;')(el, card, pill, table, kv, when, api, () => {}, () => el('button'));
    const tree = await fn(); await tick();
    const tabBar = () => nodes(tree).find((n) => n.attrs.className === 'xtab' && n.attrs.textContent === 'Agents') && null;
    const click = async (pred) => { const t = nodes(tree).find(pred); assert.ok(t, 'not found'); await t.attrs.onclick(); await tick(); };
    return { tree, calls, click, tabBar };
  }
  const tabByLabel = (l) => (n) => /xtab/.test(n.attrs.className || '') && n.attrs.textContent === l;
  const vulnCalls = (p, from) => p.calls.slice(from).filter((c) => c.startsWith('/v1/endpoints/vulnerabilities'));

  it('each machine row has a link that opens the Vulnerabilities tab on that machine', async () => {
    const p = await page(); await p.click(tabByLabel('Agents'));
    const links = nodes(p.tree).filter((n) => n.attrs.title === 'Open the vulnerabilities of this machine'); assert.strictEqual(links.length, 2);
    const from = p.calls.length; await links[1].attrs.onclick(); await tick();
    const v = vulnCalls(p, from); assert.ok(v.length >= 3); assert.ok(v.filter((c) => /summary|\?/.test(c) && !/status|trend/.test(c)).every((c) => /agent=002/.test(c)), v.join('\n'));
    assert.ok(nodes(p.tree).some((n) => n.attrs.placeholder === 'Agent id' && n.value === '002'));
  });
  it('an agent\'s detail has a button that does the same', async () => {
    const p = await page(); await p.click(tabByLabel('Agents'));
    await p.click((n) => typeof n.attrs.onclick === 'function' && n.attrs.textContent === '001' && n.attrs.style && /underline/.test(n.attrs.style));
    const from = p.calls.length; await p.click((n) => n.attrs.textContent === 'Show its vulnerabilities');
    const v = vulnCalls(p, from).filter((c) => !/status|trend/.test(c)); assert.ok(v.length >= 2); assert.ok(v.every((c) => /agent=001/.test(c)));
  });
  it('opening the tab from the tab bar afterwards starts on every machine again', async () => {
    const p = await page(); await p.click(tabByLabel('Agents'));
    const link = nodes(p.tree).find((n) => n.attrs.title === 'Open the vulnerabilities of this machine'); await link.attrs.onclick(); await tick();
    await p.click(tabByLabel('Overview')); const from = p.calls.length; await p.click(tabByLabel('Vulnerabilities'));
    const v = vulnCalls(p, from).filter((c) => !/status|trend/.test(c)); assert.ok(v.length >= 2); assert.ok(v.every((c) => !/agent=/.test(c)), v.join('\n'));
  });
  it('the link and button only switch tabs: no request other than the Vulnerabilities reads, and the page writes no HTML', async () => {
    const p = await page(); await p.click(tabByLabel('Agents'));
    const from = p.calls.length; await (nodes(p.tree).find((n) => n.attrs.title === 'Open the vulnerabilities of this machine')).attrs.onclick(); await tick();
    assert.ok(p.calls.slice(from).every((c) => c.startsWith('/v1/endpoints/vulnerabilities')));
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(cut('async function pgEndpoints')));
  });
  // E6r: from a machine to its alerts (the Alerts tab filters by the machine's name).
  const alertCalls = (p, from) => p.calls.slice(from).filter((c) => c.startsWith('/v1/endpoints/alerts'));
  it('each machine row has an Alerts link that opens the Alerts tab on that machine, by name, with every other filter cleared', async () => {
    const p = await page(); await p.click(tabByLabel('Agents'));
    const links = nodes(p.tree).filter((n) => n.attrs.title === 'Open the alerts of this machine'); assert.strictEqual(links.length, 2);
    const from = p.calls.length; await links[1].attrs.onclick(); await tick();
    const a = alertCalls(p, from); assert.ok(a.length >= 2, a.join('\n')); assert.ok(a.every((c) => new URLSearchParams(c.split('?')[1]).get('agent') === 'db01'), a.join('\n'));
    assert.ok(a.every((c) => { const q = new URLSearchParams(c.split('?')[1]); return q.get('window') === '24h' && !q.has('mitre') && !q.has('q') && !q.has('rule') && !q.has('exclude_rule'); }), 'nothing else is filtered');
    assert.ok(nodes(p.tree).some((n) => n.attrs.placeholder === 'Machine name' && n.value === 'db01'), 'the Machine name box shows the filter');
    assert.ok(nodes(p.tree).some((n) => /xtab/.test(n.attrs.className || '') && /on/.test(n.attrs.className) && n.attrs.textContent === 'Alerts'));
  });
  it('earlier filters on the Alerts tab (ATT&CK id, severity, search text) are replaced, not added to', async () => {
    const p = await page(); await p.click(tabByLabel('Alerts'));
    const box = (ph) => nodes(p.tree).find((n) => n.attrs.placeholder === ph), sevSel = () => nodes(p.tree).find((n) => n.tag === 'select' && n.kids.some((o) => o.attrs && o.attrs.textContent === 'Any severity'));
    box('ATT&CK id, e.g. T1110').value = 'T1110'; sevSel().value = 'high'; box('Search description, user, address or file').value = 'sshd';
    await p.click((n) => n.attrs.textContent === 'Search' && typeof n.attrs.onclick === 'function');
    const typed = alertCalls(p, 0).pop(); assert.ok(/mitre=T1110/.test(typed) || alertCalls(p, 0).some((c) => /mitre=T1110/.test(c)), 'the filters were really committed first');
    await p.click(tabByLabel('Agents')); const from = p.calls.length; await (nodes(p.tree).filter((n) => n.attrs.title === 'Open the alerts of this machine')[0]).attrs.onclick(); await tick();
    const a = alertCalls(p, from); assert.ok(a.length >= 2); assert.ok(a.every((c) => { const q = new URLSearchParams(c.split('?')[1]); return !q.has('mitre') && !q.has('q') && !q.has('severity') && q.get('agent') === 'web01'; }), a.join('\n'));
    assert.strictEqual(box('ATT&CK id, e.g. T1110').value, ''); assert.strictEqual(sevSel().value, '');
  });
  it('an agent\'s detail has a Show its alerts button that does the same', async () => {
    const p = await page(); await p.click(tabByLabel('Agents'));
    await p.click((n) => typeof n.attrs.onclick === 'function' && n.attrs.textContent === '001' && n.attrs.style && /underline/.test(n.attrs.style));
    const from = p.calls.length; await p.click((n) => n.attrs.textContent === 'Show its alerts');
    const a = alertCalls(p, from); assert.ok(a.length >= 2); assert.ok(a.every((c) => new URLSearchParams(c.split('?')[1]).get('agent') === 'web01'));
  });
  it('a machine with no name has no Alerts link (a dash), and the name is cut to the 200 characters the server takes', async () => {
    const saved = LIST.agents[1].name; LIST.agents[1].name = '';
    try { const p = await page(); await p.click(tabByLabel('Agents')); assert.strictEqual(nodes(p.tree).filter((n) => n.attrs.title === 'Open the alerts of this machine').length, 1); } finally { LIST.agents[1].name = saved; }
    LIST.agents[0].name = 'n'.repeat(300);
    try { const p = await page(); await p.click(tabByLabel('Agents')); const from = p.calls.length; await (nodes(p.tree).find((n) => n.attrs.title === 'Open the alerts of this machine')).attrs.onclick(); await tick();
      assert.ok(alertCalls(p, from).every((c) => new URLSearchParams(c.split('?')[1]).get('agent').length === 200)); } finally { LIST.agents[0].name = 'web01'; }
  });
  it('the Alerts link only switches tabs and reads the two alert routes; the machine name is a query value, not markup', async () => {
    LIST.agents[0].name = 'x&agent=evil<img>'; 
    try { const p = await page(); await p.click(tabByLabel('Agents')); const from = p.calls.length; await (nodes(p.tree).find((n) => n.attrs.title === 'Open the alerts of this machine')).attrs.onclick(); await tick();
      const c = p.calls.slice(from); assert.ok(c.length >= 2 && c.every((x) => x.startsWith('/v1/endpoints/alerts')), c.join('\n'));
      const qv = new URLSearchParams(c[0].split('?')[1]); assert.strictEqual(qv.get('agent'), 'x&agent=evil<img>'); assert.strictEqual(qv.getAll('agent').length, 1); } finally { LIST.agents[0].name = 'web01'; }
  });
  it('is wired: the tab entry passes the focus and a tab click clears it', () => {
    assert.match(html, /\['vuln', 'Vulnerabilities', \(\) => vulnerabilitiesView\(vulnFocus\)\]/);
    assert.match(html, /if \(id === 'vuln'\) vulnFocus = ''; tab = id; draw\(\);/);
    assert.match(html, /const openFindings = \(id\) => \{ vulnFocus = String\(id\); tab = 'vuln'; draw\(\); \};/);
  });
});

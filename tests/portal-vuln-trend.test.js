'use strict';
// E6k: the Trend card of the Vulnerabilities tab (src/portal/index.html, vulnerabilitiesView, loadTrend). The function is cut out of the page and run with small stand-ins, as in
// portal-endpoint-vuln.test.js. No DOM, no network.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const i0 = html.indexOf('const EP_VULN_COL ='), i1 = html.indexOf('async function pgEndpoints');
const source = html.slice(i0, i1);

const el = (tag, attrs, ...kids) => Object.assign({}, attrs || {}, { tag, attrs: attrs || {}, kids: kids.flat(Infinity), replaceChildren(...k) { this.kids = k.flat(Infinity); } });
const walk = (n) => (typeof n === 'string' ? [n] : n && typeof n === 'object' ? (Array.isArray(n) ? n.flatMap(walk) : [n, ...(n.kids || []).flatMap(walk)]) : []);
const texts = (n) => walk(n).map((x) => (typeof x === 'string' ? x : typeof x.textContent === 'string' ? x.textContent : '')).join(' | ');
const card = (title, ...kids) => el('div', { className: 'card' }, title ? el('h3', { textContent: title }) : '', ...kids);
const pill = (t, c) => el('span', { className: 'pill ' + (c || 'off'), textContent: t });
const kv = (o) => el('div', {}, Object.entries(o).map(([k, v]) => el('div', {}, el('span', { textContent: k }), el('span', { textContent: String(v) }))));
const when = (v) => (v ? String(v) : '-');
const table = (cols, rows, empty) => (!rows.length ? el('div', { className: 'mute', textContent: empty || 'Nothing to show yet.' })
  : el('table', {}, el('tr', {}, cols.map((c) => el('th', { textContent: c.h }))), rows.map((r) => el('tr', {}, cols.map((c) => { const v = c.f(r); return typeof v === 'object' && v ? el('td', {}, v) : el('td', { textContent: String(v) }); })))));
const tick = async () => { for (let i = 0; i < 6; i++) await new Promise((r) => setImmediate(r)); };
const SOURCE = { available: true, registered: true, label: 'Acme', host: 'idx', port: 9200, index: 'wazuh-states-vulnerabilities-acme', index_user: 'u', cert_sha256: 'a'.repeat(64), updated_at: '2026-11-01T00:00:00Z', status: { reachable: true, count: 5 } };
const SUMMARY = { total: 5, machines: 1, distinct_cves: 5, severity: { critical: 1, high: 1, medium: 1, low: 1, unknown: 0 }, top_packages: [], top_cves: [], top_agents: [] };
const pt = (day, o = {}) => ({ day, findings_total: 100, machines: 3, critical: 4, high: 10, new_critical: 0, new_total: 2, total_change: 5, critical_change: -1, ...o });

async function open(trend) {
  const calls = [];
  const api = async (p) => {
    calls.push(p);
    if (p === '/v1/endpoints/vulnerabilities/status') return { success: true, source: SOURCE };
    if (p.startsWith('/v1/endpoints/vulnerabilities/summary')) return { success: true, summary: SUMMARY };
    if (p.startsWith('/v1/endpoints/vulnerabilities/trend')) { if (trend instanceof Error) throw trend; return trend; }
    if (p.startsWith('/v1/endpoints/vulnerabilities?')) return { success: true, total: 0, limit: 50, offset: 0, findings: [] };
    throw new Error('unexpected call ' + p);
  };
  const fn = new Function('el', 'card', 'pill', 'table', 'kv', 'when', 'api', source + '\nreturn vulnerabilitiesView;')(el, card, pill, table, kv, when, api);
  const tree = fn(); await tick();
  return { tree, calls, text: () => texts(tree) };
}

describe('the Trend card of the Vulnerabilities tab', () => {
  it('asks for 14 days and shows them newest first, with the changes signed', async () => {
    const p = await open({ success: true, points: [pt('2026-12-01', { total_change: null, critical_change: null }), pt('2026-12-02', { total_change: -3 }), pt('2026-12-03', { new_critical: 2, total_change: 5 })] });
    assert.ok(p.calls.includes('/v1/endpoints/vulnerabilities/trend?days=14'));
    const t = p.text(); assert.match(t, /Trend \(one summary a day\)/);
    assert.ok(t.indexOf('2026-12-03') < t.indexOf('2026-12-02') && t.indexOf('2026-12-02') < t.indexOf('2026-12-01'), 'newest first');
    assert.match(t, /\+5/); assert.match(t, /-3/); assert.match(t, /-1/);
    const rows = walk(p.tree).filter((n) => n && n.tag === 'tr' && texts(n).includes('2026-12-01'));
    assert.match(texts(rows[0]), /2026-12-01 \| 100 \| - \|/, 'no previous summary: a dash, not 0');
  });
  it('no summary yet is a note that says when the first one comes', async () => {
    const p = await open({ success: true, points: [] }); assert.match(p.text(), /No summary yet/); assert.match(p.text(), /03:00 UTC/);
  });
  it('a failed read shows its message in the card and leaves the rest of the tab working', async () => {
    const p = await open(new Error('The database is busy')); assert.match(p.text(), /The database is busy/); assert.match(p.text(), /Findings/);
  });
  it('a missing number shows a dash and the card writes no HTML', async () => {
    const p = await open({ success: true, points: [pt('2026-12-03', { critical: null, new_critical: null })] }); assert.match(p.text(), /2026-12-03 \| 100 \| \+5 \| - \|/);
    assert.ok(!/innerHTML/.test(source.slice(source.indexOf('const loadTrend'), source.indexOf('const showOne'))));
  });
});

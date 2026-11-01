'use strict';
// The Vulnerabilities tab of the Endpoints page (src/portal/index.html, vulnerabilitiesView; docs/endpoints.md task E6e): the function is cut out of the page and run with small
// stand-ins for el(), card(), pill(), table(), kv(), when() and api(), as in portal-endpoint-sca.test.js. No DOM, no network.
const { describe, it } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const i0 = html.indexOf('const EP_VULN_COL ='), i1 = html.indexOf('async function pgEndpoints');
assert.ok(i0 >= 0 && i1 > i0, 'the tab is placed before pgEndpoints');
const source = html.slice(i0, i1);

const el = (tag, attrs, ...kids) => Object.assign({}, attrs || {}, { tag, attrs: attrs || {}, kids: kids.flat(Infinity), replaceChildren(...k) { this.kids = k.flat(Infinity); } });
const walk = (n) => (typeof n === 'string' ? [n] : n && typeof n === 'object' ? (Array.isArray(n) ? n.flatMap(walk) : [n, ...(n.kids || []).flatMap(walk)]) : []);
const texts = (n) => walk(n).map((x) => (typeof x === 'string' ? x : typeof x.textContent === 'string' ? x.textContent : '')).join(' | ');
const card = (title, ...kids) => el('div', { className: 'card' }, title ? el('h3', { textContent: title }) : '', ...kids);
const pill = (t, c) => el('span', { className: 'pill ' + (c || 'off'), textContent: t });
const kv = (o) => el('div', {}, Object.entries(o).map(([k, v]) => el('div', { className: 'kv' }, el('span', { textContent: k }), el('span', { textContent: v === null || v === undefined ? '-' : String(v) }))));
const when = (v) => (v ? String(v).replace('T', ' ').replace(/\.\d+Z?$/, '') : '-');
const table = (cols, rows, empty) => (!rows.length ? el('div', { className: 'mute', textContent: empty || 'Nothing to show yet.' })
  : el('table', {}, el('tr', {}, cols.map((c) => el('th', { textContent: c.h }))), rows.map((r) => el('tr', {}, cols.map((c) => { const v = c.f(r); return typeof v === 'object' && v ? el('td', {}, v) : el('td', { textContent: v === null || v === undefined ? '-' : String(v) }); })))));

const SOURCE = { available: true, registered: true, label: 'Acme', host: 'idx.internal', port: 9200, index: 'wazuh-states-vulnerabilities-acme', index_user: 'asix-vuln-acme', cert_sha256: 'a'.repeat(64), updated_at: '2026-11-01T00:00:00Z', status: { reachable: true, count: 6 } };
const F = (cve, sev, score, extra = {}) => ({ cve, severity: sev, score, score_version: '3.1', agent_id: '001', agent_name: 'WIN-DC01', package: 'openssl', version: '3.0.13', package_type: 'deb', architecture: 'amd64', os: 'Ubuntu 24.04', description: 'About ' + cve,
  references: ['https://nvd.nist.gov/vuln/detail/' + cve], published_at: '2026-08-01T00:00:00Z', detected_at: '2026-10-30T10:00:00Z', under_evaluation: false, ...extra });
const SUMMARY = { total: 6, machines: 2, distinct_cves: 5, severity: { critical: 2, high: 2, medium: 1, low: 1, unknown: 0 }, top_packages: [{ key: 'openssl', count: 3 }], top_cves: [{ key: 'CVE-2026-1001', count: 2 }], top_agents: [{ agent_id: '001', name: 'WIN-DC01', count: 3 }] };
const tick = async () => { for (let i = 0; i < 6; i++) await new Promise((r) => setImmediate(r)); };

async function open(answers = {}) {
  const calls = [];
  const api = async (p) => {
    calls.push(p);
    const a = answers[p] !== undefined ? answers[p] : answers[p.split('?')[0]];
    if (a instanceof Error) throw a;
    if (a !== undefined) return typeof a === 'function' ? a(p) : a;
    if (p === '/v1/endpoints/vulnerabilities/status') return { success: true, source: SOURCE };
    if (p.startsWith('/v1/endpoints/vulnerabilities/summary')) return { success: true, summary: SUMMARY };
    if (p.startsWith('/v1/endpoints/vulnerabilities?')) { const q = new URLSearchParams(p.split('?')[1]); return { success: true, total: 120, limit: 50, offset: Number(q.get('offset')), findings: [F('CVE-2026-1001', 'critical', 9.8), F('CVE-2026-1002', 'high', 7.5, { references: ['https://example.org/a', 'javascript:alert(1)'] })] }; }
    throw new Error('unexpected call ' + p);
  };
  const fn = new Function('el', 'card', 'pill', 'table', 'kv', 'when', 'api', source + '\nreturn vulnerabilitiesView;')(el, card, pill, table, kv, when, api);
  const tree = fn(); await tick();
  const find = (label) => walk(tree).find((n) => typeof n === 'object' && n.attrs && n.attrs.textContent === label && typeof n.attrs.onclick === 'function');
  const click = async (label) => { const t = find(label); assert.ok(t, label + ' not found in: ' + texts(tree)); await t.attrs.onclick(); await tick(); };
  const byPlaceholder = (ph) => walk(tree).find((n) => n && n.tag === 'input' && n.attrs.placeholder === ph);
  const selects = () => walk(tree).filter((n) => n && n.tag === 'select');
  return { tree, calls, click, find, byPlaceholder, selects, text: () => texts(tree) };
}

describe('the Vulnerabilities tab', () => {
  it('asks for the source first and shows the findings: cards, severity counts, top lists and a table', async () => {
    const p = await open();
    assert.strictEqual(p.calls[0], '/v1/endpoints/vulnerabilities/status');
    assert.deepStrictEqual(p.calls.slice(1).sort(), ['/v1/endpoints/vulnerabilities/summary?', '/v1/endpoints/vulnerabilities?limit=50&offset=0&sort=-score'].sort());
    const t = p.text(); assert.match(t, /Reachable/); assert.match(t, /idx\.internal:9200/); assert.match(t, /wazuh-states-vulnerabilities-acme/); assert.match(t, /Findings stored \| 6/);
    assert.match(t, /5 different vulnerabilities on 2 machines/); assert.match(t, /critical {2}2/); assert.match(t, /Most affected machines/); assert.match(t, /WIN-DC01 \(001\)/); assert.match(t, /Most common packages/); assert.match(t, /openssl/);
    assert.match(t, /CVE-2026-1001/); assert.match(t, /9\.8/); assert.match(t, /1 to 2 of 120/);
  });
  it('no source registered: says so, shows the operator command, and asks for nothing else', async () => {
    const p = await open({ '/v1/endpoints/vulnerabilities/status': { success: true, source: { available: true, registered: false } } });
    assert.deepStrictEqual(p.calls, ['/v1/endpoints/vulnerabilities/status']); assert.match(p.text(), /No vulnerability source registered/); assert.match(p.text(), /wazuh-indexer-cli\.js register --tenant/);
  });
  it('table missing: "Not ready" with the schema hint; a failed read shows the message', async () => {
    let p = await open({ '/v1/endpoints/vulnerabilities/status': { success: true, source: { available: false, registered: false } } }); assert.match(p.text(), /Not ready/); assert.match(p.text(), /schema job/);
    p = await open({ '/v1/endpoints/vulnerabilities/status': new Error('The call failed') }); assert.match(p.text(), /The call failed/); assert.strictEqual(p.calls.length, 1);
  });
  it('an unreachable source shows its code and message and loads no findings', async () => {
    const p = await open({ '/v1/endpoints/vulnerabilities/status': { success: true, source: { ...SOURCE, status: { reachable: false, code: 'TLS', message: 'The indexer\u2019s certificate is not the one registered' } } } });
    assert.match(p.text(), /Not reachable/); assert.match(p.text(), /TLS: /); assert.match(p.text(), /not the one registered/); assert.deepStrictEqual(p.calls, ['/v1/endpoints/vulnerabilities/status']);
  });
  it('a reachable source with no findings says when they appear, and loads none', async () => {
    const p = await open({ '/v1/endpoints/vulnerabilities/status': { success: true, source: { ...SOURCE, status: { reachable: true, count: 0 } } } });
    assert.match(p.text(), /holds no findings yet/); assert.deepStrictEqual(p.calls, ['/v1/endpoints/vulnerabilities/status']);
  });
  it('pressing a severity filters the cards and the list; the text and agent boxes and Search do the same', async () => {
    const p = await open(); p.calls.length = 0;
    const crit = walk(p.tree).find((n) => n && n.attrs && n.attrs.title === 'Show only critical'); assert.ok(crit); await crit.attrs.onclick(); await tick();
    assert.deepStrictEqual(p.calls.sort(), ['/v1/endpoints/vulnerabilities/summary?severity=critical', '/v1/endpoints/vulnerabilities?limit=50&offset=0&sort=-score&severity=critical'].sort());
    p.calls.length = 0; p.byPlaceholder('Package, vulnerability id or machine').value = ' openssl '; p.byPlaceholder('Agent id').value = '002'; await p.click('Search');
    assert.ok(p.calls.includes('/v1/endpoints/vulnerabilities?limit=50&offset=0&sort=-score&severity=critical&q=openssl&agent=002'), p.calls.join('\n'));   // the severity chosen a moment ago stays: filters combine
    assert.ok(p.calls.includes('/v1/endpoints/vulnerabilities/summary?severity=critical&q=openssl&agent=002'));
  });
  it('paging asks for the next 50 and Previous is off on the first page', async () => {
    const p = await open(); assert.strictEqual(p.find('Previous').attrs.textContent, 'Previous'); assert.strictEqual(walk(p.tree).find((n) => n && n.attrs && n.attrs.textContent === 'Previous').disabled, true);
    p.calls.length = 0; await p.click('Next'); assert.deepStrictEqual(p.calls, ['/v1/endpoints/vulnerabilities?limit=50&offset=50&sort=-score']);
  });
  it('a finding opens with its score, machine, package, dates and description; only http(s) references become links', async () => {
    const p = await open(); await p.click('CVE-2026-1002'); const t = p.text();
    assert.match(t, /Finding CVE-2026-1002/); assert.match(t, /7\.5 \(CVSS 3\.1\)/); assert.match(t, /WIN-DC01 \(001\)/); assert.match(t, /Installed version \| 3\.0\.13/); assert.match(t, /About CVE-2026-1002/);
    const links = walk(p.tree).filter((n) => n && n.tag === 'a'); assert.ok(links.length >= 1); for (const a of links) assert.match(a.href, /^https?:\/\//);
    assert.ok(!/javascript:/.test(JSON.stringify(walk(p.tree).filter((n) => n && n.tag === 'a').map((a) => a.href))), 'no javascript: link');
  });
  it('is wired as a tab after Configuration checks, and writes nothing into the page as HTML', () => {
    assert.match(html, /\['config', 'Configuration checks', \(\) => alertsView\('config'\)\], \['vuln', 'Vulnerabilities', vulnerabilitiesView\]/);
    assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(source), 'the tab uses textContent and el() only');
    assert.ok(html.indexOf('function vulnerabilitiesView') < html.indexOf('async function pgEndpoints'));
  });
});

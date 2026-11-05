'use strict';
// E6s: the "Findings indexer disk" card of the Vulnerabilities tab. Two parts: the route (GET /v1/endpoints/vulnerabilities/trend, field indexer_disk) through the real route file and the
// in-memory event store, and the portal function (src/portal/index.html, vulnerabilitiesView/loadTrend) cut out of the page and run with small stand-ins. No DOM, no network.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const path = require('path');

const TENANT = crypto.randomUUID(), OTHER = crypto.randomUUID();
let who = TENANT;
const shared = require('../src/gateway/shared');
require.cache[require.resolve('../src/gateway/shared')].exports = { ...shared, guarded: () => [(req, res, next) => { req.tenant_id = who; next(); }] };
const route = require('../src/gateway/routes/vuln-trend');
const { setEventStore } = require('../src/events');
const { MemoryEventStore } = require('../src/events/memory-store');

const minAgo = (m) => new Date(Date.now() - m * 60000).toISOString();
const rep = (host, m, fields = {}, parsedExtra = {}) => {
  const at = minAgo(m);
  return { id: crypto.randomUUID(), source_type: 'indexer-health', collector_id: null, received_at: at, event_time: at, raw: 'x',
    parsed: { host, message: 'Findings indexer ' + host, disk_used_pct: 42.5, disk_free_gb: 57.5, disk_total_gb: 100, cluster_status: 'green', write_blocked_indices: 0, ...fields, ...parsedExtra } };
};

describe('indexer_disk in GET /v1/endpoints/vulnerabilities/trend', () => {
  let srv, base, store;
  before(async () => {
    store = new MemoryEventStore(); setEventStore(store);
    await store.insertBatch(TENANT, [rep('idx1', 1, { disk_used_pct: 81 }), rep('idx1', 6, { disk_used_pct: 50 }), rep('idx2', 3, { cluster_status: 'red', write_blocked_indices: 2 }), rep('idx3', 400)]);
    await store.insertBatch(OTHER, [rep('other-idx', 1)]);
    const app = express(); app.use(route); srv = app.listen(0); base = 'http://127.0.0.1:' + srv.address().port;
  });
  after(() => srv.close());
  const get = async () => (await (await fetch(base + '/v1/endpoints/vulnerabilities/trend?days=7')).json());

  it('gives the newest report of each host, sorted by host, and leaves out a host silent for more than 6 hours', async () => {
    const d = (await get()).indexer_disk;
    assert.deepStrictEqual(d.map((h) => h.host), ['idx1', 'idx2']);
    assert.strictEqual(d[0].disk_used_pct, 81, 'the newer report of idx1 wins');
    assert.deepStrictEqual([d[0].disk_free_gb, d[0].disk_total_gb, d[0].cluster_status, d[0].write_blocked_indices], [57.5, 100, 'green', 0]);
    assert.deepStrictEqual([d[1].cluster_status, d[1].write_blocked_indices], ['red', 2]);
  });
  it('marks a report older than 15 minutes late and says how old it is', async () => {
    const d = (await get()).indexer_disk;
    assert.deepStrictEqual([d[0].stale, d[0].age_minutes], [false, 1]); assert.strictEqual(d[1].age_minutes, 3);
    const t = crypto.randomUUID(); who = t; await store.insertBatch(t, [rep('old', 40)]);
    try { const h = (await get()).indexer_disk[0]; assert.strictEqual(h.stale, true); assert.ok(h.age_minutes >= 39 && h.age_minutes <= 41); } finally { who = TENANT; }
  });
  it('is null when there is no report, and only this tenant\'s reports are read', async () => {
    who = crypto.randomUUID(); try { const r = await get(); assert.strictEqual(r.indexer_disk, null); assert.deepStrictEqual(r.points, []); } finally { who = TENANT; }
    who = OTHER; try { assert.deepStrictEqual((await get()).indexer_disk.map((h) => h.host), ['other-idx']); } finally { who = TENANT; }
  });
  it('keeps only allow-listed, in-range values: text, negative, over 100 per cent and unknown statuses become null or unknown', async () => {
    const t = crypto.randomUUID(); who = t;
    await store.insertBatch(t, [rep('bad1', 1, { disk_used_pct: '50', disk_free_gb: -3, disk_total_gb: 1e9, cluster_status: '<b>x</b>', write_blocked_indices: 1.5 }), rep('bad2', 1, { disk_used_pct: 140 }),
      rep('bad host!', 1), rep('', 1), rep('x'.repeat(101), 1), rep('nan', 1, { disk_used_pct: null, disk_free_gb: undefined })]);
    try {
      const d = (await get()).indexer_disk, by = Object.fromEntries(d.map((h) => [h.host, h]));
      assert.deepStrictEqual(Object.keys(by).sort(), ['bad1', 'bad2', 'nan']);
      assert.deepStrictEqual([by.bad1.disk_used_pct, by.bad1.disk_free_gb, by.bad1.disk_total_gb, by.bad1.cluster_status, by.bad1.write_blocked_indices], [null, null, null, 'unknown', null]);
      assert.strictEqual(by.bad2.disk_used_pct, null); assert.strictEqual(by.nan.disk_used_pct, null);
      assert.ok(!('message' in by.bad1) && !('raw' in by.bad1), 'nothing but the allow-listed fields');
    } finally { who = TENANT; }
  });
  it('shows at most 5 hosts', async () => {
    const t = crypto.randomUUID(); who = t; await store.insertBatch(t, ['a', 'b', 'c', 'd', 'e', 'f', 'g'].map((h, i) => rep('h-' + h, i + 1)));
    try { assert.deepStrictEqual((await get()).indexer_disk.map((h) => h.host), ['h-a', 'h-b', 'h-c', 'h-d', 'h-e']); } finally { who = TENANT; }
  });
  it('a failed read of the health events leaves the trend answering, with indexer_disk null', async () => {
    const t = crypto.randomUUID(); who = t; const real = store.listEvents.bind(store);
    store.listEvents = async (tn, q) => { if (q.source_type === 'indexer-health') throw new Error('boom'); return real(tn, q); };
    const log = console.error; console.error = () => {};
    try { const r = await get(); assert.strictEqual(r.success, true); assert.strictEqual(r.indexer_disk, null); } finally { console.error = log; store.listEvents = real; who = TENANT; }
  });
});

// ---- the portal part ----
const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'portal', 'index.html'), 'utf8');
const source = html.slice(html.indexOf('const EP_VULN_COL ='), html.indexOf('async function pgEndpoints'));
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
const SOURCE = { available: true, registered: true, label: 'Acme', host: 'idx', port: 9200, index: 'i', index_user: 'u', cert_sha256: 'a'.repeat(64), updated_at: '2026-11-01', status: { reachable: true, count: 5 } };
const SUMMARY = { total: 5, machines: 1, distinct_cves: 5, severity: { critical: 1, high: 1, medium: 1, low: 1, unknown: 0 }, top_packages: [], top_cves: [], top_agents: [] };
const H = (o = {}) => ({ host: 'idx1', disk_used_pct: 42.5, disk_free_gb: 57.5, disk_total_gb: 100, cluster_status: 'green', write_blocked_indices: 0, reported_at: '2026-11-04T10:00:00.000Z', age_minutes: 2, stale: false, ...o });

async function open(trend) {
  const api = async (p) => {
    if (p === '/v1/endpoints/vulnerabilities/status') return { success: true, source: SOURCE };
    if (p.startsWith('/v1/endpoints/vulnerabilities/summary')) return { success: true, summary: SUMMARY };
    if (p.startsWith('/v1/endpoints/vulnerabilities/trend')) return trend;
    if (p.startsWith('/v1/endpoints/vulnerabilities?')) return { success: true, total: 0, limit: 50, offset: 0, findings: [] };
    throw new Error('unexpected call ' + p);
  };
  const fn = new Function('el', 'card', 'pill', 'table', 'kv', 'when', 'api', source + '\nreturn vulnerabilitiesView;')(el, card, pill, table, kv, when, api);
  const tree = fn(); await tick();
  return { text: () => texts(tree), pills: () => walk(tree).filter((n) => n && n.className && String(n.className).startsWith('pill ')).map((n) => n.className.slice(5) + ':' + n.textContent) };
}
const base = { success: true, points: [], machines: null };

describe('the "Findings indexer disk" card', () => {
  it('shows a healthy VM: used per cent, free of total, indexer status, blocked indices and the report time', async () => {
    const p = await open({ ...base, indexer_disk: [H()] }), t = p.text();
    assert.match(t, /Findings indexer disk/); for (const piece of ['idx1', '42.5%', '57.5 GB of 100 GB', 'green', '2026-11-04T10:00:00.000Z']) assert.ok(t.includes(piece), 'missing: ' + piece);
    assert.ok(p.pills().includes('ok:42.5%') && p.pills().includes('ok:green'));
    assert.ok(!/late/.test(t), 'a fresh report is not late');
  });
  it('colours the disk by the same bands as the alert rules: under 80 ok, 80 to 89 getting full, 90 and over bad', async () => {
    const p = await open({ ...base, indexer_disk: [H({ host: 'a', disk_used_pct: 79.9 }), H({ host: 'b', disk_used_pct: 80 }), H({ host: 'c', disk_used_pct: 89.9 }), H({ host: 'd', disk_used_pct: 90 })] });
    assert.deepStrictEqual(p.pills().filter((x) => /%/.test(x)), ['ok:79.9%', 'off:80% getting full', 'off:89.9% getting full', 'bad:90% full']);
  });
  it('colours the indexer status: green ok, yellow and unknown grey, red and unreachable bad; shows a late report and missing numbers', async () => {
    const p = await open({ ...base, indexer_disk: [H({ host: 'a', cluster_status: 'yellow' }), H({ host: 'b', cluster_status: 'red', write_blocked_indices: 3 }), H({ host: 'c', cluster_status: 'unreachable' }), H({ host: 'd', cluster_status: 'unknown', disk_used_pct: null, disk_free_gb: null, disk_total_gb: null, write_blocked_indices: null, stale: true, age_minutes: 40 })] });
    assert.deepStrictEqual(p.pills().filter((x) => !/%|Not measured|Reachable/.test(x)), ['off:yellow', 'bad:red', 'bad:unreachable', 'off:unknown']);
    const t = p.text(); assert.match(t, /Not measured/); assert.ok(t.includes('- of -') && t.includes('2026-11-04T10:00:00.000Z (40 min ago: late)'));
  });
  it('no report in 6 hours says how to install the reporter; an older server (no field) shows no card at all', async () => {
    assert.match((await open({ ...base, indexer_disk: null })).text(), /No report from the indexer VM in the last 6 hours[^|]*install-indexer-health\.sh/);
    assert.ok(!/Findings indexer disk/.test((await open({ ...base })).text()));
  });
  it('the card does not hide the trend or the machines card', async () => {
    const t = (await open({ ...base, indexer_disk: [H()] })).text(); assert.match(t, /Trend \(one summary a day\)/); assert.match(t, /Machines that got worse/);
  });
});

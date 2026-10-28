'use strict';
// E6c: the File integrity tab's read side (docs/endpoints.md, "E6c as built"): `kind=file_integrity` and `file_event` on the endpoint alert routes, and the changed-files and
// change-kind lists in the summary. Events are parsed by the REAL default parsing rules (syscheck_path -> file_path, syscheck_event -> file_event); in-memory store; two tenants.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const express = require('express');
const alerts = require('../src/endpoints/endpoint-alerts');
const { validatePlan } = require('../src/search/xql-plan');
const { compile, apply } = require('../src/ingestion/parsing-rules');
const { jsonEvent } = require('../src/ingest/http-ingest');
const { MemoryEventStore } = require('../src/events/memory-store');
const { setEventStore } = require('../src/events');
const F = require('./fixtures/wazuh-alerts');

const NOW = Date.parse('2026-10-27T12:00:00.000Z');
const T1 = '11111111-1111-4111-8111-111111111111', T2 = '22222222-2222-4222-8222-222222222222';
const defaults = compile(require('../src/ingestion/default-parsing-rules'));

describe('parseQuery and plans', () => {
  const ok = (q) => { const r = alerts.parseQuery(q, { now: NOW }); assert.ok(!r.error, JSON.stringify(r)); return r; };
  const bad = (q, re) => { const r = alerts.parseQuery(q, { now: NOW }); assert.ok(r.error, 'should be refused: ' + JSON.stringify(q)); if (re) assert.match(r.error, re); };
  const conds = (plan) => { const f = plan.stages.find((s) => s.op === 'filter'); return f ? (f.expr.t === 'and' ? f.expr.args : [f.expr]) : []; };
  it('defaults have no kind and no file event; the two new values are checked', () => {
    const d = ok({}); assert.strictEqual(d.kind, null); assert.strictEqual(d.file_event, null);
    assert.strictEqual(ok({ kind: 'file_integrity' }).kind, 'file_integrity'); assert.strictEqual(ok({ kind: '' }).kind, null);
    for (const v of ['added', 'modified', 'deleted']) assert.strictEqual(ok({ file_event: v }).file_event, v);
    bad({ kind: 'alerts' }, /kind must be/); bad({ kind: ['file_integrity', 'x'] }); bad({ kind: 'FILE_INTEGRITY' });
    bad({ file_event: 'renamed' }, /file_event must be one of/); bad({ file_event: 'x' }); assert.deepStrictEqual(alerts.FILE_EVENTS, ['added', 'modified', 'deleted']); assert.deepStrictEqual(alerts.KINDS, ['file_integrity']); bad({ file_event: ['added', 'deleted'] }); bad({ file_event: "added' or 1=1" });
  });
  it('kind adds a "file path is present" condition and file_event an equality on the parsed field; both plans validate, and a plain request adds neither', () => {
    const f = ok({ kind: 'file_integrity', file_event: 'deleted' });
    for (const plan of [alerts.listPlan(f), alerts.severityPlan(f), alerts.samplePlan(f)]) {
      validatePlan(plan); const c = conds(plan);
      assert.ok(c.some((x) => x.t === 'isnull' && x.field === '@file_path' && x.neg === true)); assert.ok(c.some((x) => x.t === 'eq' && x.field === '@file_event' && x.value === 'deleted'));
    }
    const plain = alerts.listPlan(ok({})); assert.ok(!JSON.stringify(plain).includes('file_path') && !JSON.stringify(plain).includes('file_event'));
    assert.ok(!JSON.stringify(alerts.listPlan(ok({ kind: 'file_integrity' }))).includes('@file_event'));
  });
});

describe('topLists, files and changes', () => {
  const ev = (p) => ({ id: 'x', received_at: 'r', parsed: p });
  it('counts the files that changed most and what happened to them, only from alerts that name a file', () => {
    const t = alerts.topLists([ev({ file_path: '/etc/passwd', file_event: 'modified' }), ev({ file_path: '/etc/passwd', file_event: 'modified' }), ev({ file_path: '/tmp/a', file_event: 'added' }),
      ev({ rule_id: '5763', file_event: 'modified' }), ev({ file_path: '/b' }), ev(null)]);
    assert.deepStrictEqual(t.files, [{ path: '/etc/passwd', count: 2 }, { path: '/b', count: 1 }, { path: '/tmp/a', count: 1 }]);
    assert.deepStrictEqual(t.file_events, [{ name: 'modified', count: 2 }, { name: 'added', count: 1 }]);
    assert.deepStrictEqual(alerts.topLists([ev({ rule_id: '1' })]).files, []);
  });
  it('the other lists are unchanged and at most ten files are returned', () => {
    const many = Array.from({ length: 15 }, (_, i) => ev({ file_path: '/f' + i, file_event: 'added', agent_name: 'm', rule_id: '1' }));
    const t = alerts.topLists(many); assert.strictEqual(t.files.length, 10); assert.deepStrictEqual(t.agents, [{ name: 'm', count: 15 }]); assert.strictEqual(t.rules[0].count, 15);
  });
});

let seq = 0;
const flat = (a) => {
  const m = a.rule.mitre || {}, f = { asix_via: 'wazuh', rule_id: a.rule.id, rule_level: String(a.rule.level), rule_description: a.rule.description, rule_groups: (a.rule.groups || []).join(','),
    mitre_ids: (m.id || []).join(','), mitre_tactics: (m.tactic || []).join(','), mitre_techniques: (m.technique || []).join(','), alert_id: a.id || '', agent_id: a.agent.id, agent_name: a.agent.name, agent_ip: a.agent.ip,
    manager_name: a.manager.name, decoder_name: (a.decoder || {}).name || '', location: a.location || '', full_log: a.full_log || '' };
  for (const [k, v] of Object.entries(a.data || {})) if (v === null || typeof v !== 'object') f['data_' + k] = String(v);
  for (const [k, v] of Object.entries(a.syscheck || {})) if (v === null || typeof v !== 'object') f['syscheck_' + k] = Array.isArray(v) ? v.join(',') : String(v);
  return f;
};
function eventOf(a, { minsAgo = 5, sourceType = 'endpoint-alert' } = {}) {
  const time = new Date(Date.now() - minsAgo * 60000).toISOString();
  const x = jsonEvent({ message: '[Endpoint alert] rule ' + a.rule.id, time, host: a.agent.name, fields: flat(a) }, 'broker-test');
  const out = apply([defaults.rules], { source_type: sourceType, raw: x.raw, time: x.time, parsed: x.parsed });
  seq += 1;
  return { id: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`, source_type: sourceType, collector_id: 'broker-test', received_at: time, event_time: time, raw: x.raw, parsed: out.parsed };
}
const mk = (level, o = {}) => F.base({ agent: { id: '002', name: o.agent || 'web1', ip: '10.0.0.30' }, rule: { level, id: o.rule || '550', description: o.desc || 'Integrity checksum changed.', groups: ['syscheck'], mitre: o.mitre || {} },
  id: 'ref' + (++seq), full_log: 'log', data: o.data || {}, location: 'syscheck', ...(o.file ? { syscheck: { path: o.file, event: o.event } } : { syscheck: undefined }) });

describe('routes with real parsing rules', () => {
  const sharedPath = require.resolve('../src/gateway/shared');
  let server, base, store, ids = {};
  const put = (p, exports) => { require.cache[p] = { id: p, filename: p, loaded: true, exports }; };
  before(async () => {
    put(sharedPath, { db: {}, UUID_RE: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, apiError: (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } }),
      guarded: () => [(req, res, next) => { req.tenant_id = T1; next(); }] });
    store = new MemoryEventStore(); setEventStore(store);
    const put1 = async (t, a, o) => { const e = eventOf(a, o); await store.insertBatch(t, [e]); return e.id; };
    ids.passwd1 = await put1(T1, mk(7, { rule: '550', agent: 'web1', file: '/etc/passwd', event: 'modified', mitre: { id: ['T1565.001'], technique: ['Stored Data Manipulation'], tactic: ['Impact'] } }), { minsAgo: 1 });
    ids.passwd2 = await put1(T1, mk(7, { rule: '550', agent: 'db1', file: '/etc/passwd', event: 'modified' }), { minsAgo: 2 });
    ids.added = await put1(T1, mk(5, { rule: '554', desc: 'File added to the system.', agent: 'web1', file: '/tmp/new.sh', event: 'added' }), { minsAgo: 3 });
    ids.deleted = await put1(T1, mk(12, { rule: '553', desc: 'File deleted.', agent: 'web1', file: '/var/log/auth.log', event: 'deleted' }), { minsAgo: 4 });
    ids.ssh = await put1(T1, mk(10, { rule: '5763', desc: 'sshd: brute force', agent: 'web1' }), { minsAgo: 5 });              // an alert that names no file
    ids.old = await put1(T1, mk(7, { rule: '550', agent: 'web1', file: '/etc/old', event: 'modified' }), { minsAgo: 60 * 24 * 3 });  // outside the window
    ids.other = await put1(T2, mk(7, { rule: '550', agent: 'secret-host', file: '/etc/secret-file', event: 'modified' }), { minsAgo: 1 });   // another tenant
    ids.syslog = await put1(T1, mk(7, { rule: '550', agent: 'web1', file: '/etc/syslog-file', event: 'modified' }), { minsAgo: 1, sourceType: 'syslog' });  // not an endpoint alert
    const app = express(); app.use(require('../src/gateway/routes/endpoint-alerts'));
    await new Promise((res) => { server = app.listen(0, '127.0.0.1', res); }); base = 'http://127.0.0.1:' + server.address().port;
  });
  after(() => { server.close(); setEventStore(null); delete require.cache[require.resolve('../src/gateway/routes/endpoint-alerts')]; delete require.cache[sharedPath]; });
  const get = async (p) => { const r = await fetch(base + p); return { status: r.status, body: await r.json() }; };
  const list = async (q = '') => { const r = await get('/v1/endpoints/alerts' + q); assert.strictEqual(r.status, 200, JSON.stringify(r.body)); return r.body; };
  const files = (b) => b.alerts.map((a) => a.file_path);

  it('kind=file_integrity lists only the alerts that name a file, newest first, this tenant and window only; without it the list is as before', async () => {
    assert.deepStrictEqual(files(await list('?kind=file_integrity')), ['/etc/passwd', '/etc/passwd', '/tmp/new.sh', '/var/log/auth.log']);
    const all = await list(); assert.strictEqual(all.count, 5); assert.ok(all.alerts.some((a) => a.file_path === null));
    const b = JSON.stringify(await list('?kind=file_integrity&window=30d')); assert.ok(b.includes('/etc/old')); assert.ok(!b.includes('secret') && !b.includes('syslog-file'));
  });
  it('file_event filters by what happened to the file; a file event alone also works, and combines with the other filters', async () => {
    assert.deepStrictEqual(files(await list('?kind=file_integrity&file_event=added')), ['/tmp/new.sh']);
    assert.deepStrictEqual(files(await list('?kind=file_integrity&file_event=deleted')), ['/var/log/auth.log']);
    assert.strictEqual((await list('?kind=file_integrity&file_event=modified')).count, 2);
    assert.deepStrictEqual(files(await list('?kind=file_integrity&file_event=modified&agent=db1')), ['/etc/passwd']);
    assert.deepStrictEqual(files(await list('?kind=file_integrity&severity=critical')), ['/var/log/auth.log']);
    assert.deepStrictEqual(files(await list('?kind=file_integrity&q=new.sh')), ['/tmp/new.sh']);
    assert.deepStrictEqual(files(await list('?kind=file_integrity&mitre=T1565')), ['/etc/passwd']);
    assert.strictEqual((await list('?file_event=added')).count, 1);
  });
  it('each shaped alert carries the file and the change; the one-alert route still shows its file integrity fields', async () => {
    const b = await list('?kind=file_integrity&file_event=added'); assert.deepStrictEqual([b.alerts[0].file_path, b.alerts[0].file_event], ['/tmp/new.sh', 'added']);
    const d = await get('/v1/endpoints/alerts/' + ids.added); assert.strictEqual(d.status, 200); assert.strictEqual(d.body.alert.file_integrity.path, '/tmp/new.sh'); assert.strictEqual(d.body.alert.file_integrity.event, 'added');
  });
  it('the summary counts only file changes with kind=file_integrity, and lists the changed files and the kinds of change; severity counts stay exact', async () => {
    const r = await get('/v1/endpoints/alerts/summary?kind=file_integrity'); assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.severity.total, 4); assert.deepStrictEqual([r.body.severity.critical, r.body.severity.medium], [1, 3]);
    assert.deepStrictEqual(r.body.top.files[0], { path: '/etc/passwd', count: 2 }); assert.deepStrictEqual(r.body.top.files.map((x) => x.path).sort(), ['/etc/passwd', '/tmp/new.sh', '/var/log/auth.log']);
    assert.deepStrictEqual(r.body.top.file_events[0], { name: 'modified', count: 2 }); assert.strictEqual(r.body.sampled.events, 4);
    const plain = await get('/v1/endpoints/alerts/summary'); assert.strictEqual(plain.body.severity.total, 5);
    const f = await get('/v1/endpoints/alerts/summary?kind=file_integrity&file_event=added'); assert.strictEqual(f.body.severity.total, 1);
  });
  it('bad values are a 400 and the store is not asked', async () => {
    for (const q of ['?kind=other', '?kind=file_integrity&kind=file_integrity', '?file_event=moved', "?file_event=added'--"]) { const r = await get('/v1/endpoints/alerts' + q); assert.strictEqual(r.status, 400, q); assert.strictEqual(r.body.error.code, 'INVALID_ALERT_QUERY'); }
    assert.strictEqual((await get('/v1/endpoints/alerts/summary?kind=x')).status, 400);
  });
});

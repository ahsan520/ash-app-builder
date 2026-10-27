'use strict';
// E6b: the read side of the Endpoints "Alerts" tab (src/endpoints/endpoint-alerts.js and src/gateway/routes/endpoint-alerts.js; docs/endpoints.md, "E6b as built").
//   1. the query string -> a validated filter -> an XQL query plan (no SQL, validated by the event store);
//   2. shaping an alert, with its MITRE ATT&CK details split out;
//   3. the three routes over the in-memory event store, with events parsed by the REAL default parsing rules (so alert_level, alert_severity, user, src_ip,
//      file_path are the ones the real rule makes), two tenants, and a stand-in for the sign-in chain that records which permission each route asks for.
const { describe, it, before, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const express = require('express');
const alerts = require('../src/endpoints/endpoint-alerts');
const { validatePlan } = require('../src/search/xql-plan');
const { compile, apply } = require('../src/ingestion/parsing-rules');
const { jsonEvent } = require('../src/ingest/http-ingest');
const { MemoryEventStore } = require('../src/events/memory-store');
const { setEventStore } = require('../src/events');
const F = require('./fixtures/wazuh-alerts');

const root = path.join(__dirname, '..');
const NOW = Date.parse('2026-10-27T12:00:00.000Z');
const T1 = '11111111-1111-4111-8111-111111111111', T2 = '22222222-2222-4222-8222-222222222222';
const defaults = compile(require('../src/ingestion/default-parsing-rules'));

// ---- 1. the query string ---------------------------------------------------------------------------------------------------------------------------
describe('parseQuery', () => {
  const ok = (q) => { const r = alerts.parseQuery(q, { now: NOW }); assert.ok(!r.error, JSON.stringify(r)); return r; };
  const bad = (q, re) => { const r = alerts.parseQuery(q, { now: NOW }); assert.ok(r.error, 'should be refused: ' + JSON.stringify(q)); if (re) assert.match(r.error, re); };
  it('defaults: the last 24 hours, 50 alerts, no filters', () => {
    const r = ok({});
    assert.deepStrictEqual([r.window, r.limit, r.offset, r.severity, r.agent, r.rule, r.mitre, r.q], ['24h', 50, 0, null, null, null, null, null]);
    assert.strictEqual(r.from, '2026-10-26T12:00:00.000Z');
  });
  it('each window reaches back the right distance', () => {
    assert.strictEqual(ok({ window: '1h' }).from, '2026-10-27T11:00:00.000Z');
    assert.strictEqual(ok({ window: '7d' }).from, '2026-10-20T12:00:00.000Z');
    assert.strictEqual(ok({ window: '30d' }).from, '2026-09-27T12:00:00.000Z');
    bad({ window: '90d' }, /window/); bad({ window: 'toString' }, /window/); bad({ window: '__proto__' }, /window/);
  });
  it('severity, rule and mitre only accept their own alphabet', () => {
    for (const s of alerts.SEVERITIES) assert.strictEqual(ok({ severity: s }).severity, s);
    bad({ severity: 'urgent' }); bad({ rule: '5763; drop' }); bad({ rule: '' + '9'.repeat(11) }); bad({ mitre: 'T11' }); bad({ mitre: 't1110' }); bad({ mitre: 'T1110.03' }); bad({ mitre: "T1110' OR 1=1" });
    assert.strictEqual(ok({ rule: '5763' }).rule, '5763'); assert.strictEqual(ok({ mitre: 'T1110' }).mitre, 'T1110'); assert.strictEqual(ok({ mitre: 'T1565.001' }).mitre, 'T1565.001');
  });
  it('text filters must be one line of at most 200 characters', () => {
    assert.strictEqual(ok({ agent: 'web 1' }).agent, 'web 1'); assert.strictEqual(ok({ q: 'passwd' }).q, 'passwd');
    bad({ agent: 'a'.repeat(201) }); bad({ q: 'two\nlines' }); bad({ q: 'nul\u0000byte' }); bad({ agent: 'tab\there' });
    assert.strictEqual(ok({ agent: 'a'.repeat(200) }).agent.length, 200);
  });
  it('an empty value means "no filter" and a repeated parameter is refused', () => {
    const r = ok({ severity: '', agent: '', q: '', rule: '', mitre: '' }); assert.deepStrictEqual([r.severity, r.agent, r.q, r.rule, r.mitre], [null, null, null, null, null]);
    bad({ severity: ['high', 'low'] }); bad({ window: ['1h', '7d'] }); bad({ limit: ['5', '6'] });
  });
  it('limit is 1 to 100 and offset 0 to 900, whole numbers only', () => {
    assert.strictEqual(ok({ limit: '100' }).limit, 100); assert.strictEqual(ok({ limit: '1' }).limit, 1); assert.strictEqual(ok({ offset: '900' }).offset, 900); assert.strictEqual(ok({ offset: '0' }).offset, 0);
    for (const v of ['0', '101', '-1', '1.5', 'abc', '', '1e2', ' 5']) bad({ limit: v }, /limit/);
    for (const v of ['901', '-1', '2.5', 'x']) bad({ offset: v }, /offset/);
  });
  it('an unknown parameter is refused, so a typo is not silently ignored', () => {
    bad({ serverity: 'high' }, /unknown parameter "serverity"/); bad({ __proto__x: '1' }); bad({ source_type: 'syslog' }, /unknown parameter/);
  });
});

// ---- the plans ---------------------------------------------------------------------------------------------------------------------------------------
describe('the query plans', () => {
  const full = () => alerts.parseQuery({ window: '7d', severity: 'high', agent: "web1' OR '1'='1", rule: '5763', mitre: 'T1110', q: '100%_ \\ "quoted"', limit: '20', offset: '40' }, { now: NOW });
  it('every plan the module can build passes the event store\'s own plan validation, with and without every filter', () => {
    const combos = [{}, { severity: 'critical' }, { agent: 'a' }, { rule: '1' }, { mitre: 'T1110.003' }, { q: 'x' }, full()];
    for (const c of combos) {
      const f = c.from ? c : alerts.parseQuery(c, { now: NOW });
      for (const mk of [alerts.listPlan, alerts.severityPlan, alerts.samplePlan]) assert.doesNotThrow(() => validatePlan(mk(f)), JSON.stringify(c));
    }
  });
  it('the list reads only the endpoint-alert dataset, newest first from the window start, offset plus limit rows', () => {
    const f = full(), p = alerts.listPlan(f);
    assert.deepStrictEqual(p.stages[0], { op: 'dataset', names: ['endpoint-alert'], list: false });
    assert.strictEqual(p.mode, 'raw'); assert.strictEqual(p.limit, 60); assert.strictEqual(p.from, f.from); assert.strictEqual(p.to, null);
    assert.ok(!p.stages.some((s) => s.op === 'sort'), 'the store\'s own order (newest first)');
  });
  it('values are carried as plain text in the plan and cannot add stages or expressions', () => {
    const f = full(), p = alerts.listPlan(f), j = JSON.stringify(p);
    assert.strictEqual(p.stages.length, 2);
    const eq = JSON.stringify(p.stages[1]); assert.ok(eq.includes(JSON.stringify("web1' OR '1'='1")));
    assert.ok(!/"op":"(comp|fields|sort)"/.test(j));
  });
  it('the summary ignores the severity filter (so the cards stay a breakdown), the list does not', () => {
    const f = alerts.parseQuery({ severity: 'high' }, { now: NOW });
    assert.ok(JSON.stringify(alerts.listPlan(f)).includes('@alert_level')); assert.ok(!JSON.stringify(alerts.severityPlan(f)).includes('@alert_level')); assert.ok(!JSON.stringify(alerts.samplePlan(f)).includes('@alert_level'));
  });
  it('severity bands are the manager\'s level bands', () => {
    assert.deepStrictEqual(alerts.BANDS, { critical: [12, 15], high: [8, 11], medium: [5, 7], low: [0, 4] });
  });
});

// ---- 2. shaping -----------------------------------------------------------------------------------------------------------------------------------------
describe('mitreOf and shape', () => {
  it('pairs ids with their names in order and builds the ATT&CK page of a sub-technique', () => {
    const m = alerts.mitreOf({ mitre_ids: 'T1110,T1565.001', mitre_techniques: 'Brute Force,Stored Data Manipulation', mitre_tactics: 'Credential Access,Impact' });
    assert.deepStrictEqual(m.techniques, [{ id: 'T1110', name: 'Brute Force', url: 'https://attack.mitre.org/techniques/T1110/' }, { id: 'T1565.001', name: 'Stored Data Manipulation', url: 'https://attack.mitre.org/techniques/T1565/001/' }]);
    assert.deepStrictEqual(m.tactics, ['Credential Access', 'Impact']); assert.deepStrictEqual(m.unpaired_names, []);
  });
  it('names that do not line up with the ids are not paired (a name holding a comma, say) and are returned apart', () => {
    const m = alerts.mitreOf({ mitre_ids: 'T1059', mitre_techniques: 'Command and Scripting Interpreter,Extra' });
    assert.strictEqual(m.techniques[0].name, null); assert.deepStrictEqual(m.unpaired_names, ['Command and Scripting Interpreter', 'Extra']);
  });
  it('tactics are never paired with ids: one tactic list for several techniques stays a plain list', () => {
    const m = alerts.mitreOf({ mitre_ids: 'T1078', mitre_techniques: 'Valid Accounts', mitre_tactics: 'Defense Evasion,Persistence,Privilege Escalation,Initial Access' });
    assert.strictEqual(m.techniques.length, 1); assert.strictEqual(m.tactics.length, 4);
  });
  it('only a well-formed technique id gets a link; anything else is shown as text with no link', () => {
    for (const id of ['javascript:alert(1)', 'T11', 'T1110/../../x', 'https://evil.example/', 'T1110.3', ' T1110', 'T1110.0001']) assert.strictEqual(alerts.mitreUrl(id), null, id);
    const m = alerts.mitreOf({ mitre_ids: 'javascript:alert(1),T1110', mitre_techniques: 'a,b' });
    assert.deepStrictEqual(m.techniques.map((t) => t.url), [null, 'https://attack.mitre.org/techniques/T1110/']);
  });
  it('no MITRE fields (or empty ones) give empty lists, not an error', () => {
    for (const p of [undefined, {}, { mitre_ids: '', mitre_tactics: '', mitre_techniques: '' }, { mitre_ids: null }, { mitre_ids: 5 }]) assert.deepStrictEqual(alerts.mitreOf(p), { techniques: [], unpaired_names: [], tactics: [] });
  });
  it('shape: level as a number, the severity from the parsing rule else from the level, descriptions on one line, hostile text stays text', () => {
    const e = { id: 'x', received_at: '2026-10-27T10:00:00.000Z', event_time: '2026-10-27T09:59:00.000Z', parsed: { alert_level: 9, alert_severity: 'high', rule_id: '5763', alert_name: ' a\r\n b\t\tc ', agent_name: '<img src=x onerror=alert(1)>', agent_id: '002', rule_groups: 'a, b ,,c' } };
    const a = alerts.shape(e);
    assert.strictEqual(a.level, 9); assert.strictEqual(a.severity, 'high'); assert.strictEqual(a.description, 'a b c'); assert.strictEqual(a.agent.name, '<img src=x onerror=alert(1)>'); assert.deepStrictEqual(a.groups, ['a', 'b', 'c']);
    assert.strictEqual(a.time, '2026-10-27T09:59:00.000Z');
    assert.strictEqual(alerts.shape({ id: 'y', received_at: 'r', parsed: { rule_level: '12' } }).severity, 'critical');
    assert.strictEqual(alerts.shape({ id: 'y', received_at: 'r', parsed: { alert_level: 'banana', alert_severity: 'rm -rf' } }).severity, null);
    assert.strictEqual(alerts.shape({ id: 'y', received_at: 'r', parsed: {} }).level, null);
  });
  it('the list shape leaves out the long text and the detail fields; the detail shape adds them and hides the internal marker', () => {
    const e = { id: 'x', received_at: 'r', parsed: { rule_id: '1', asix_via: 'wazuh', full_log: 'line', data_srcip: '1.2.3.4', data_win_eventdata_x: 'v', syscheck_path: '/etc/passwd', alert_key: '1 on a', manager_name: 'm', location: 'syscheck', decoder_name: 'd', alert_id: 'ref' } };
    const l = alerts.shape(e), d = alerts.shape(e, { detail: true });
    for (const k of ['full_log', 'data', 'file_integrity', 'manager']) assert.ok(!(k in l), k);
    assert.strictEqual(d.full_log, 'line'); assert.deepStrictEqual(d.data, { srcip: '1.2.3.4', win_eventdata_x: 'v' }); assert.deepStrictEqual(d.file_integrity, { path: '/etc/passwd' });
    assert.ok(!JSON.stringify(d).includes('asix_via') && !JSON.stringify(d).includes('alert_key'));
    assert.deepStrictEqual([d.manager, d.location, d.decoder, d.alert_ref], ['m', 'syscheck', 'd', 'ref']);
  });
  it('values are cut to a sane length', () => {
    const d = alerts.shape({ id: 'x', received_at: 'r', parsed: { full_log: 'a'.repeat(5000), data_k: 'b'.repeat(5000), alert_name: 'c'.repeat(5000) } }, { detail: true });
    assert.strictEqual(d.full_log.length, 2000); assert.strictEqual(d.data.k.length, 500); assert.strictEqual(d.description.length, 500);
  });
});

describe('topLists and severityCounts', () => {
  const ev = (parsed) => ({ id: 'i', received_at: 'r', parsed });
  it('count rules, machines, techniques and tactics, most frequent first with stable ties', () => {
    const t = alerts.topLists([
      ev({ rule_id: '5763', alert_name: 'ssh', alert_level: 10, agent_name: 'web1', mitre_ids: 'T1110', mitre_techniques: 'Brute Force', mitre_tactics: 'Credential Access' }),
      ev({ rule_id: '5763', alert_name: 'ssh', alert_level: 10, agent_name: 'web2', mitre_ids: 'T1110', mitre_techniques: 'Brute Force', mitre_tactics: 'Credential Access' }),
      ev({ rule_id: '550', alert_name: 'fim', alert_level: 7, agent_name: 'web1', mitre_ids: 'T1565.001,T1110', mitre_techniques: 'x,Brute Force', mitre_tactics: 'Impact' }),
    ]);
    assert.deepStrictEqual(t.rules.map((r) => [r.rule_id, r.count]), [['5763', 2], ['550', 1]]);
    assert.deepStrictEqual(t.agents.map((r) => [r.name, r.count]), [['web1', 2], ['web2', 1]]);
    assert.deepStrictEqual(t.techniques.map((r) => [r.id, r.count]), [['T1110', 3], ['T1565.001', 1]]);
    assert.deepStrictEqual(t.tactics.map((r) => [r.name, r.count]), [['Credential Access', 2], ['Impact', 1]]);
  });
  it('is bounded and survives events with nothing in them', () => {
    const many = Array.from({ length: 50 }, (_, i) => ev({ rule_id: String(i), agent_name: 'm' + i }));
    assert.strictEqual(alerts.topLists(many).rules.length, 10); assert.deepStrictEqual(alerts.topLists([ev({}), ev(null)]).rules, []);
  });
  it('severityCounts: a row with no or an odd severity is "unknown", bad counts are skipped', () => {
    assert.deepStrictEqual(alerts.severityCounts([{ alert_severity: 'high', n: '3' }, { alert_severity: 'low', n: 2 }, { alert_severity: null, n: 1 }, { alert_severity: 'weird', n: 4 }, { alert_severity: 'high', n: 'x' }]),
      { critical: 0, high: 3, medium: 0, low: 2, unknown: 5, total: 10 });
    assert.strictEqual(alerts.severityCounts(undefined).total, 0);
  });
});

// ---- 3. the routes --------------------------------------------------------------------------------------------------------------------------------------
// The broker's flattening of a Wazuh alert into the fields the lane receives (docs/endpoints.md, "E4d as built"), so the rest is the real parsing rule.
const flat = (a) => {
  const m = a.rule.mitre || {}, f = { asix_via: 'wazuh', rule_id: a.rule.id, rule_level: String(a.rule.level), rule_description: a.rule.description, rule_groups: (a.rule.groups || []).join(','),
    mitre_ids: (m.id || []).join(','), mitre_tactics: (m.tactic || []).join(','), mitre_techniques: (m.technique || []).join(','), alert_id: a.id || '', agent_id: a.agent.id, agent_name: a.agent.name, agent_ip: a.agent.ip,
    manager_name: a.manager.name, decoder_name: (a.decoder || {}).name || '', location: a.location || '', full_log: a.full_log || '' };
  for (const [k, v] of Object.entries(a.data || {})) if (v === null || typeof v !== 'object') f['data_' + k] = String(v);
  for (const [k, v] of Object.entries(a.syscheck || {})) if (v === null || typeof v !== 'object') f['syscheck_' + k] = Array.isArray(v) ? v.join(',') : String(v);
  return f;
};
let seq = 0;
function eventOf(a, { minsAgo = 5, sourceType = 'endpoint-alert' } = {}) {
  const time = new Date(Date.now() - minsAgo * 60000).toISOString();   // the routes use the real clock, so these events are placed relative to it
  const x = jsonEvent({ message: '[Endpoint alert] rule ' + a.rule.id, time, host: a.agent.name, fields: flat(a) }, 'broker-test');
  const out = apply([defaults.rules], { source_type: sourceType, raw: x.raw, time: x.time, parsed: x.parsed });
  seq += 1;
  return { id: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`, source_type: sourceType, collector_id: 'broker-test', received_at: time, event_time: time, raw: x.raw, parsed: out.parsed };
}
const mk = (level, o = {}) => F.base({ agent: { id: o.agentId || '002', name: o.agent || 'web1', ip: '10.0.0.30' }, rule: { level, id: o.rule || '5763', description: o.desc || 'rule ' + (o.rule || '5763'), groups: ['syslog'], mitre: o.mitre || {} }, id: 'ref' + (++seq), full_log: o.log || 'log', data: o.data || {}, location: 'x' });

describe('routes', () => {
  const sharedPath = require.resolve('../src/gateway/shared');
  const perms = []; let tenant = T1, server, base, store, ids = {};
  const put = (p, exports) => { require.cache[p] = { id: p, filename: p, loaded: true, exports }; };
  before(async () => {
    put(sharedPath, { db: {}, UUID_RE: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, apiError: (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } }),
      guarded: (perm) => { perms.push(perm); return [(req, res, next) => { req.tenant_id = tenant; next(); }]; } });
    store = new MemoryEventStore(); setEventStore(store);
    const put1 = async (t, a, o) => { const e = eventOf(a, o); await store.insertBatch(t, [e]); return e.id; };
    // levels around every band edge, on three machines, with MITRE ids that overlap (T1110 and T1110.003, but not T1111)
    ids.l15 = await put1(T1, mk(15, { rule: '1001', agent: 'web1', mitre: { id: ['T1110.003'], technique: ['Password Spraying'], tactic: ['Credential Access'] } }), { minsAgo: 1 });
    ids.l12 = await put1(T1, mk(12, { rule: '1002', agent: 'web1' }), { minsAgo: 2 });
    ids.l11 = await put1(T1, mk(11, { rule: '1003', agent: 'db1' }), { minsAgo: 3 });
    ids.l8 = await put1(T1, mk(8, { rule: '1004', agent: 'db1', mitre: { id: ['T1110'], technique: ['Brute Force'], tactic: ['Credential Access'] } }), { minsAgo: 4 });
    ids.l7 = await put1(T1, mk(7, { rule: '1005', agent: 'web1', desc: 'Integrity checksum changed.', mitre: { id: ['T1565.001'], technique: ['Stored Data Manipulation'], tactic: ['Impact'] }, data: { srcuser: 'alice' } }), { minsAgo: 5 });
    ids.l5 = await put1(T1, mk(5, { rule: '1006', agent: 'app1', mitre: { id: ['T1111'], technique: ['Two-Factor Authentication Interception'], tactic: ['Credential Access'] } }), { minsAgo: 6 });
    ids.l4 = await put1(T1, mk(4, { rule: '1007', agent: 'app1' }), { minsAgo: 7 });
    ids.l0 = await put1(T1, mk(0, { rule: '1008', agent: 'app1' }), { minsAgo: 8 });
    ids.old = await put1(T1, mk(10, { rule: '1009', agent: 'web1' }), { minsAgo: 60 * 24 * 3 });          // three days ago: outside the 24 hour window
    ids.other = await put1(T2, mk(14, { rule: '2001', agent: 'secret-host' }), { minsAgo: 1 });              // another tenant's alert
    ids.syslog = await put1(T1, mk(14, { rule: '3001', agent: 'web1' }), { minsAgo: 1, sourceType: 'syslog' });  // same shape, not an endpoint alert
    const app = express(); app.use(require('../src/gateway/routes/endpoint-alerts'));
    await new Promise((res) => { server = app.listen(0, '127.0.0.1', res); }); base = 'http://127.0.0.1:' + server.address().port;
  });
  after(() => { server.close(); setEventStore(null); delete require.cache[require.resolve('../src/gateway/routes/endpoint-alerts')]; delete require.cache[sharedPath]; });
  const get = async (p) => { const r = await fetch(base + p); return { status: r.status, body: await r.json() }; };
  const list = async (q = '') => { const r = await get('/v1/endpoints/alerts' + q); assert.strictEqual(r.status, 200, JSON.stringify(r.body)); return r.body; };
  const rules = (b) => b.alerts.map((a) => a.rule_id);

  it('all three routes are GET only and ask for search:events:read (the permission that reads event contents), not capacity:read', () => {
    assert.strictEqual(perms.length, 3); assert.ok(perms.every((p) => p === 'search:events:read'), perms.join());
    const src = fs.readFileSync(path.join(root, 'src/gateway/routes/endpoint-alerts.js'), 'utf8');
    assert.ok(!/router\.(post|put|patch|delete|all|use)\(/.test(src)); assert.strictEqual((src.match(/router\.get\(/g) || []).length, 3);
  });
  it('lists the newest endpoint alerts of this tenant in the window, newest first, and nothing else', async () => {
    const b = await list();
    assert.deepStrictEqual(rules(b), ['1001', '1002', '1003', '1004', '1005', '1006', '1007', '1008']);   // not the 3-day-old one, not another tenant's, not the syslog event
    assert.deepStrictEqual([b.count, b.offset, b.limit, b.more, b.window], [8, 0, 50, false, '24h']);
    assert.ok(!JSON.stringify(b).includes('secret-host'));
  });
  it('a wider window brings the older alert back; a narrower one drops the rest', async () => {
    assert.ok(rules(await list('?window=7d')).includes('1009')); assert.deepStrictEqual(rules(await list('?window=1h')), ['1001', '1002', '1003', '1004', '1005', '1006', '1007', '1008']);
    const b = await list('?window=1h'); assert.ok(!rules(b).includes('1009'));
  });
  it('severity filters at the manager\'s band edges: 15 and 12 critical, 11 and 8 high, 7 and 5 medium, 4 and 0 low', async () => {
    assert.deepStrictEqual(rules(await list('?severity=critical')), ['1001', '1002']); assert.deepStrictEqual(rules(await list('?severity=high')), ['1003', '1004']);
    assert.deepStrictEqual(rules(await list('?severity=medium')), ['1005', '1006']); assert.deepStrictEqual(rules(await list('?severity=low')), ['1007', '1008']);
    const b = await list('?severity=high'); assert.ok(b.alerts.every((a) => a.severity === 'high' && a.level >= 8 && a.level <= 11));
  });
  it('filters by machine (exact), by rule id, and by text in the description, user or file', async () => {
    assert.deepStrictEqual(rules(await list('?agent=db1')), ['1003', '1004']); assert.deepStrictEqual(rules(await list('?agent=db')), []);
    assert.deepStrictEqual(rules(await list('?rule=1005')), ['1005']);
    assert.deepStrictEqual(rules(await list('?q=integrity')), ['1005']); assert.deepStrictEqual(rules(await list('?q=ALICE')), ['1005']);
  });
  it('a MITRE id finds its sub-techniques too, and never a different technique that shares digits', async () => {
    assert.deepStrictEqual(rules(await list('?mitre=T1110')), ['1001', '1004']);   // T1110.003 and T1110
    assert.deepStrictEqual(rules(await list('?mitre=T1110.003')), ['1001']); assert.deepStrictEqual(rules(await list('?mitre=T1111')), ['1006']); assert.deepStrictEqual(rules(await list('?mitre=T1565.001')), ['1005']);
  });
  it('filters combine (all must match)', async () => {
    assert.deepStrictEqual(rules(await list('?agent=db1&severity=high&mitre=T1110')), ['1004']); assert.deepStrictEqual(rules(await list('?agent=web1&severity=low')), []);
  });
  it('pages with limit and offset, says when there is more, and does not repeat or skip an alert', async () => {
    const p1 = await list('?limit=3'), p2 = await list('?limit=3&offset=3'), p3 = await list('?limit=3&offset=6');
    assert.deepStrictEqual([rules(p1), p1.more], [['1001', '1002', '1003'], true]); assert.deepStrictEqual([rules(p2), p2.more], [['1004', '1005', '1006'], true]); assert.deepStrictEqual([rules(p3), p3.more], [['1007', '1008'], false]);
    const exact = await list('?limit=8'); assert.strictEqual(exact.more, false); assert.strictEqual((await list('?limit=7')).more, true);
    assert.deepStrictEqual((await list('?limit=2&offset=7')).alerts.map((a) => a.rule_id), ['1008']);
  });
  it('the MITRE details of each alert come back split into techniques (with names and links) and tactics', async () => {
    const a = (await list('?rule=1001')).alerts[0];
    assert.deepStrictEqual(a.mitre, { techniques: [{ id: 'T1110.003', name: 'Password Spraying', url: 'https://attack.mitre.org/techniques/T1110/003/' }], unpaired_names: [], tactics: ['Credential Access'] });
    assert.deepStrictEqual((await list('?rule=1002')).alerts[0].mitre, { techniques: [], unpaired_names: [], tactics: [] });
  });
  it('severity and level come from the real parsing rule', async () => {
    const b = await list(); const by = Object.fromEntries(b.alerts.map((a) => [a.rule_id, [a.level, a.severity]]));
    assert.deepStrictEqual(by['1001'], [15, 'critical']); assert.deepStrictEqual(by['1004'], [8, 'high']); assert.deepStrictEqual(by['1008'], [0, 'low']);
  });
  it('bad queries are a 400 and read nothing', async () => {
    for (const q of ['?severity=urgent', '?window=1y', '?limit=0', '?limit=101', '?offset=901', '?mitre=T1', '?rule=abc', '?bogus=1', '?agent=' + 'a'.repeat(201)]) {
      const r = await get('/v1/endpoints/alerts' + q); assert.strictEqual(r.status, 400, q); assert.strictEqual(r.body.error.code, 'INVALID_ALERT_QUERY');
    }
    assert.strictEqual((await get('/v1/endpoints/alerts/summary?severity=urgent')).status, 400);
  });
  it('hostile filter text is only ever text: it matches nothing and breaks nothing', async () => {
    for (const v of ["x' OR '1'='1", '"; DROP TABLE events; --', '%', '_', '\\', '${jndi:ldap://x}', '<script>alert(1)</script>']) {
      const b = await list('?agent=' + encodeURIComponent(v)); assert.strictEqual(b.count, 0, v);
      const q = await list('?q=' + encodeURIComponent(v)); assert.strictEqual(q.count, 0, v);
    }
    assert.strictEqual((await list('?q=' + encodeURIComponent('%'))).count, 0, 'a % is not a wildcard');
  });

  it('summary: exact severity counts that ignore the severity filter, and the top machines, rules, techniques and tactics', async () => {
    const r = await get('/v1/endpoints/alerts/summary'); assert.strictEqual(r.status, 200); const b = r.body;
    assert.deepStrictEqual(b.severity, { critical: 2, high: 2, medium: 2, low: 2, unknown: 0, total: 8 });
    assert.deepStrictEqual(b.top.agents.map((x) => [x.name, x.count]), [['app1', 3], ['db1', 2], ['web1', 3]].sort((x, y) => y[1] - x[1] || (x[0] < y[0] ? -1 : 1)));
    assert.deepStrictEqual(b.top.techniques.map((x) => x.id).sort(), ['T1110', 'T1110.003', 'T1111', 'T1565.001']);
    assert.deepStrictEqual(b.top.tactics.map((x) => [x.name, x.count]), [['Credential Access', 3], ['Impact', 1]]);
    assert.deepStrictEqual(b.sampled, { events: 8, truncated: false });
    assert.deepStrictEqual((await get('/v1/endpoints/alerts/summary?severity=high')).body.severity, b.severity);
  });
  it('summary follows the other filters and the window, and never counts another tenant or another source', async () => {
    const m = (await get('/v1/endpoints/alerts/summary?mitre=T1110')).body; assert.strictEqual(m.severity.total, 2); assert.deepStrictEqual([m.severity.critical, m.severity.high], [1, 1]);
    assert.strictEqual((await get('/v1/endpoints/alerts/summary?window=7d')).body.severity.total, 9);
    assert.ok(!JSON.stringify((await get('/v1/endpoints/alerts/summary?window=30d')).body).includes('secret-host'));
    tenant = T2; try { const t2 = (await get('/v1/endpoints/alerts/summary')).body; assert.strictEqual(t2.severity.total, 1); assert.deepStrictEqual(t2.top.agents.map((x) => x.name), ['secret-host']); } finally { tenant = T1; }
  });

  it('detail: one alert with its long text, the event\'s details and file integrity fields, and no internal marker', async () => {
    const r = await get('/v1/endpoints/alerts/' + ids.l7); assert.strictEqual(r.status, 200); const a = r.body.alert;
    assert.strictEqual(a.rule_id, '1005'); assert.strictEqual(a.full_log, 'log'); assert.strictEqual(a.data.srcuser, 'alice'); assert.strictEqual(a.user, 'alice'); assert.strictEqual(a.mitre.techniques[0].id, 'T1565.001'); assert.strictEqual(a.location, 'x');
    assert.ok(!JSON.stringify(a).includes('asix_via'));
  });
  it('detail: 404 for an id that is not an endpoint alert of this tenant (another source, another tenant, unknown), 400 for something that is not an id', async () => {
    for (const id of [ids.syslog, ids.other, '99999999-9999-4999-8999-999999999999']) { const r = await get('/v1/endpoints/alerts/' + id); assert.strictEqual(r.status, 404, id); assert.strictEqual(r.body.error.code, 'ALERT_NOT_FOUND'); }
    for (const id of ['abc', '1', "x'--", '00000000-0000-4000-8000-00000000000g']) { const r = await get('/v1/endpoints/alerts/' + encodeURIComponent(id)); assert.strictEqual(r.status, 400, id); assert.strictEqual(r.body.error.code, 'INVALID_ALERT_ID'); }
    assert.strictEqual((await get('/v1/endpoints/alerts/' + ids.l7.toUpperCase())).status, 200);
  });
  it('a failing store is a 500 with a message that does not leak the cause; a store that refuses the query is a 400', async () => {
    const real = store.search; const quiet = console.error; console.error = () => {};
    try {
      store.search = async () => { throw new Error('connection to 10.1.2.3:5432 refused, password=hunter2'); };
      for (const p of ['/v1/endpoints/alerts', '/v1/endpoints/alerts/summary']) { const r = await get(p); assert.strictEqual(r.status, 500); assert.strictEqual(r.body.error.code, 'ENDPOINT_ALERTS_ERROR'); assert.ok(!/hunter2|10\.1\.2\.3/.test(JSON.stringify(r.body))); }
      store.search = async () => { const e = new Error('plan.limit must be a whole number'); e.code = 'INVALID_QUERY'; throw e; };
      assert.strictEqual((await get('/v1/endpoints/alerts')).status, 400);
    } finally { store.search = real; console.error = quiet; }
  });
});

'use strict';
// E6d: the Configuration checks tab's read side (docs/endpoints.md, "E6d as built"): `kind=configuration`, `check_result` and `policy` on the endpoint alert routes, the `config` part of
// a shaped alert, the `configuration` card of one alert, and the policy and check result lists in the summary. The alerts are the manager's configuration check (SCA) alerts: hand-made
// samples of the documented shape (data.sca.*), flattened the way the broker does it (data.sca.check.title -> data_sca_check_title), then parsed by the REAL default parsing rules.
// In-memory store; two tenants. No real manager has produced one of these yet.
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
const CIS = 'CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0', STIG = 'STIG Windows Server 2022';

describe('parseQuery and plans', () => {
  const ok = (q) => { const r = alerts.parseQuery(q, { now: NOW }); assert.ok(!r.error, JSON.stringify(r)); return r; };
  const bad = (q, re) => { const r = alerts.parseQuery(q, { now: NOW }); assert.ok(r.error, 'should be refused: ' + JSON.stringify(q)); if (re) assert.match(r.error, re); };
  const conds = (plan) => { const f = plan.stages.find((s) => s.op === 'filter'); return f ? (f.expr.t === 'and' ? f.expr.args : [f.expr]) : []; };
  it('kind accepts configuration; check_result accepts exactly three words; policy is one line of text; everything else is refused', () => {
    assert.strictEqual(ok({ kind: 'configuration' }).kind, 'configuration'); assert.deepStrictEqual(alerts.KINDS, ['file_integrity', 'configuration']);
    assert.deepStrictEqual(alerts.CHECK_RESULTS, { passed: 'passed', failed: 'failed', not_applicable: 'not applicable' });
    for (const v of ['passed', 'failed', 'not_applicable']) assert.strictEqual(ok({ check_result: v }).check_result, v);
    assert.strictEqual(ok({ check_result: '' }).check_result, null); assert.strictEqual(ok({}).check_result, null); assert.strictEqual(ok({}).policy, null);
    bad({ check_result: 'not applicable' }, /check_result must be one of/); bad({ check_result: 'FAILED' }); bad({ check_result: ['passed', 'failed'] }); bad({ check_result: "failed' or 1=1" }); bad({ kind: 'Configuration' });
    assert.strictEqual(ok({ policy: CIS }).policy, CIS); bad({ policy: 'a\nb' }, /policy must be/); bad({ policy: 'x'.repeat(201) }); bad({ policy: ['a', 'b'] });
    assert.ok(alerts.QUERY_KEYS.includes('check_result') && alerts.QUERY_KEYS.includes('policy'));
  });
  it('the plans hold a "policy is present" condition, an equality on the manager\'s own result text and one on the policy; all validate; a plain request adds none of them', () => {
    const f = ok({ kind: 'configuration', check_result: 'not_applicable', policy: CIS });
    for (const plan of [alerts.listPlan(f), alerts.severityPlan(f), alerts.samplePlan(f)]) {
      validatePlan(plan); const c = conds(plan);
      assert.ok(c.some((x) => x.t === 'isnull' && x.field === '@data_sca_policy' && x.neg === true));
      assert.ok(c.some((x) => x.t === 'eq' && x.field === '@data_sca_check_result' && x.value === 'not applicable'), 'the stored text has a space, the query word an underscore');
      assert.ok(c.some((x) => x.t === 'eq' && x.field === '@data_sca_policy' && x.value === CIS));
    }
    const plain = JSON.stringify(alerts.listPlan(ok({}))); assert.ok(!plain.includes('data_sca'));
    assert.ok(!JSON.stringify(alerts.listPlan(ok({ kind: 'configuration' }))).includes('data_sca_check_result'));
  });
  it('the text search also reads the check title and the policy, but only on the configuration tab', () => {
    const on = JSON.stringify(alerts.listPlan(ok({ kind: 'configuration', q: 'ssh' }))), off = JSON.stringify(alerts.listPlan(ok({ q: 'ssh' }))), fim = JSON.stringify(alerts.listPlan(ok({ kind: 'file_integrity', q: 'ssh' })));
    assert.ok(on.includes('@data_sca_check_title') && on.includes('@rule_description')); assert.ok(!off.includes('data_sca') && !fim.includes('data_sca'));
    validatePlan(alerts.listPlan(ok({ kind: 'configuration', q: 'ssh' })));
  });
});

describe('shaping and top lists', () => {
  const ev = (p) => ({ id: 'x', received_at: 'r', parsed: p });
  const check = { rule_id: '19008', rule_level: '7', alert_level: 7, alert_severity: 'medium', data_sca_type: 'check', data_sca_policy: CIS, data_sca_policy_id: 'cis_ubuntu22-04', data_sca_check_id: '28500', data_sca_check_title: '  Ensure   SSH root\n login is disabled ',
    data_sca_check_result: 'failed', data_sca_check_previous_result: 'passed', data_sca_check_rationale: 'Direct root login hides who did what.', data_sca_check_remediation: 'Set PermitRootLogin no.' };
  const summary = { rule_id: '19004', alert_level: 9, alert_severity: 'high', data_sca_type: 'summary', data_sca_policy: CIS, data_sca_passed: '120', data_sca_failed: '45', data_sca_invalid: '12', data_sca_total_checks: '177', data_sca_score: '72' };
  it('a check alert has its policy, check and results; a summary has its counts as numbers; another alert has no config', () => {
    const c = alerts.shape(ev(check)).config; assert.deepStrictEqual([c.policy, c.policy_id, c.type, c.check_id, c.check_title, c.result, c.previous_result], [CIS, 'cis_ubuntu22-04', 'check', '28500', 'Ensure SSH root login is disabled', 'failed', 'passed']);
    assert.deepStrictEqual([c.score, c.passed, c.failed, c.invalid, c.total], [null, null, null, null, null]);
    const s = alerts.shape(ev(summary)).config; assert.deepStrictEqual([s.type, s.score, s.passed, s.failed, s.invalid, s.total, s.result, s.check_title], ['summary', 72, 120, 45, 12, 177, null, null]);
    assert.strictEqual(alerts.shape(ev({ rule_id: '5763', alert_level: 10 })).config, null); assert.strictEqual(alerts.shape(ev(null)).config, null);
    assert.strictEqual(alerts.shape(ev({ ...summary, data_sca_score: 'seventy', data_sca_failed: '4.5' })).config.score, null);
  });
  it('one alert carries every data_sca_ field in `configuration` and keeps them out of the general details; hostile text stays text', () => {
    const d = alerts.shape(ev({ ...check, data_srcip: '1.2.3.4', data_sca_check_title: '<img src=x onerror=alert(1)>' }), { detail: true });
    assert.deepStrictEqual(d.data, { srcip: '1.2.3.4' }); assert.strictEqual(d.configuration.check_rationale, 'Direct root login hides who did what.'); assert.strictEqual(d.configuration.check_remediation, 'Set PermitRootLogin no.');
    assert.strictEqual(d.configuration.policy, CIS); assert.strictEqual(d.config.check_title, '<img src=x onerror=alert(1)>');
    assert.deepStrictEqual(alerts.shape(ev({ rule_id: '1', alert_level: 3 }), { detail: true }).configuration, {});
    assert.strictEqual(alerts.shape(ev({ ...check, data_sca_check_remediation: 'r'.repeat(3000) }), { detail: true }).configuration.check_remediation.length, 1000);
  });
  it('counts the policies and the results of single checks; a summary counts for its policy only; other alerts for neither', () => {
    const t = alerts.topLists([ev(check), ev(check), ev({ ...check, data_sca_check_result: 'passed', data_sca_policy: STIG }), ev(summary), ev({ rule_id: '5763' }), ev(null)]);
    assert.deepStrictEqual(t.policies, [{ name: CIS, count: 3 }, { name: STIG, count: 1 }]); assert.deepStrictEqual(t.check_results, [{ name: 'failed', count: 2 }, { name: 'passed', count: 1 }]);
    const none = alerts.topLists([ev({ rule_id: '1' })]); assert.deepStrictEqual([none.policies, none.check_results], [[], []]);
    assert.deepStrictEqual(alerts.topLists([ev({ rule_id: '1', agent_name: 'm' })]).agents, [{ name: 'm', count: 1 }]);
  });
});

let seq = 0;
// The broker's flattening (deploy/broker/vector-wazuhalerts.yaml): nested names joined with _, every value text, characters outside A-Za-z0-9_ replaced by _.
const flatten = (o, prefix, out = {}) => {
  for (const [k, v] of Object.entries(o || {})) {
    const key = prefix + '_' + k.replace(/[^A-Za-z0-9_]/g, '_');
    if (v !== null && typeof v === 'object') flatten(v, key, out); else if (v !== null && v !== undefined) out[key] = String(v);
  }
  return out;
};
const flat = (a) => {
  const m = a.rule.mitre || {}, f = { asix_via: 'wazuh', rule_id: a.rule.id, rule_level: String(a.rule.level), rule_description: a.rule.description, rule_groups: (a.rule.groups || []).join(','),
    mitre_ids: (m.id || []).join(','), mitre_tactics: (m.tactic || []).join(','), mitre_techniques: (m.technique || []).join(','), alert_id: a.id || '', agent_id: a.agent.id, agent_name: a.agent.name, agent_ip: a.agent.ip,
    manager_name: a.manager.name, decoder_name: (a.decoder || {}).name || '', location: a.location || '', full_log: a.full_log || '' };
  return { ...f, ...flatten(a.data, 'data') };
};
function eventOf(a, { minsAgo = 5, sourceType = 'endpoint-alert' } = {}) {
  const time = new Date(Date.now() - minsAgo * 60000).toISOString();
  const x = jsonEvent({ message: '[Endpoint alert] rule ' + a.rule.id, time, host: a.agent.name, fields: flat(a) }, 'broker-test');
  const out = apply([defaults.rules], { source_type: sourceType, raw: x.raw, time: x.time, parsed: x.parsed });
  seq += 1;
  return { id: `00000000-0000-4000-8000-${String(seq).padStart(12, '0')}`, source_type: sourceType, collector_id: 'broker-test', received_at: time, event_time: time, raw: x.raw, parsed: out.parsed };
}
const chk = (o) => F.base({ agent: { id: '002', name: o.agent || 'web1', ip: '10.0.0.30' }, rule: { level: o.level || 7, id: o.rule || '19008', description: o.desc || (o.policy || CIS) + ': ' + o.title, groups: ['sca'], mitre: {} }, id: 'ref' + (++seq), full_log: '', location: 'sca',
  data: { sca: { type: 'check', scan_id: '1', policy: o.policy || CIS, policy_id: 'pid', check: { id: o.id, title: o.title, rationale: 'Because.', remediation: 'Fix it.', compliance: { cis: '5.2.10' }, command: ['sshd -T'], result: o.result, ...(o.prev ? { previous_result: o.prev } : {}) } } } });
const summ = (o) => F.base({ agent: { id: '002', name: o.agent || 'web1', ip: '10.0.0.30' }, rule: { level: 9, id: '19004', description: 'SCA summary: ' + CIS + ': Score less than 80% (72)', groups: ['sca'], mitre: {} }, id: 'ref' + (++seq), full_log: '', location: 'sca',
  data: { sca: { type: 'summary', scan_id: '1', policy: CIS, policy_id: 'pid', passed: 120, failed: 45, invalid: 12, total_checks: 177, score: 72 } } });

describe('routes with real parsing rules', () => {
  const sharedPath = require.resolve('../src/gateway/shared');
  let server, base, store, ids = {};
  const put = (p, exports) => { require.cache[p] = { id: p, filename: p, loaded: true, exports }; };
  before(async () => {
    put(sharedPath, { db: {}, UUID_RE: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, apiError: (res, status, code, message) => res.status(status).json({ success: false, error: { code, message } }),
      guarded: () => [(req, res, next) => { req.tenant_id = T1; next(); }] });
    store = new MemoryEventStore(); setEventStore(store);
    const put1 = async (t, a, o) => { const e = eventOf(a, o); await store.insertBatch(t, [e]); return e.id; };
    ids.ssh = await put1(T1, chk({ id: '28500', title: 'Ensure SSH root login is disabled', result: 'failed', prev: 'passed', level: 7 }), { minsAgo: 1 });
    ids.pass = await put1(T1, chk({ id: '28501', title: 'Ensure SSH X11 forwarding is disabled', result: 'passed', prev: 'failed', level: 3, agent: 'db1' }), { minsAgo: 2 });
    ids.na = await put1(T1, chk({ id: '28502', title: 'Ensure IPv6 router advertisements are ignored', result: 'not applicable', level: 3, agent: 'db1' }), { minsAgo: 3 });
    ids.win = await put1(T1, chk({ id: '15001', title: 'Ensure password history is enforced', result: 'failed', policy: STIG, level: 12, agent: 'WIN-DC01' }), { minsAgo: 4 });
    ids.sum = await put1(T1, summ({}), { minsAgo: 5 });
    ids.fim = await put1(T1, F.alerts.fileChanged, { minsAgo: 6 });          // an alert that is not a configuration check
    ids.old = await put1(T1, chk({ id: '28599', title: 'An old check', result: 'failed' }), { minsAgo: 60 * 24 * 3 });   // outside the window
    ids.other = await put1(T2, chk({ id: '28500', title: 'Secret tenant check', result: 'failed', agent: 'secret-host' }), { minsAgo: 1 });   // another tenant
    ids.syslog = await put1(T1, chk({ id: '28500', title: 'Syslog impostor', result: 'failed' }), { minsAgo: 1, sourceType: 'syslog' });   // not an endpoint alert
    const app = express(); app.use(require('../src/gateway/routes/endpoint-alerts'));
    await new Promise((res) => { server = app.listen(0, '127.0.0.1', res); }); base = 'http://127.0.0.1:' + server.address().port;
  });
  after(() => { server.close(); setEventStore(null); delete require.cache[require.resolve('../src/gateway/routes/endpoint-alerts')]; delete require.cache[sharedPath]; });
  const get = async (p) => { const r = await fetch(base + p); return { status: r.status, body: await r.json() }; };
  const list = async (q = '') => { const r = await get('/v1/endpoints/alerts' + q); assert.strictEqual(r.status, 200, JSON.stringify(r.body)); return r.body; };
  const titles = (b) => b.alerts.map((a) => (a.config && (a.config.check_title || a.config.type)) || null);

  it('kind=configuration lists only configuration check alerts, newest first, this tenant and window only; without it the list also holds the other alerts', async () => {
    assert.deepStrictEqual(titles(await list('?kind=configuration')), ['Ensure SSH root login is disabled', 'Ensure SSH X11 forwarding is disabled', 'Ensure IPv6 router advertisements are ignored', 'Ensure password history is enforced', 'summary']);
    assert.strictEqual((await list()).count, 6); assert.ok((await list()).alerts.some((a) => a.config === null));
    const b = JSON.stringify(await list('?kind=configuration&window=30d')); assert.ok(b.includes('An old check')); assert.ok(!b.includes('Secret tenant') && !b.includes('impostor'));
  });
  it('the real parsing rules still make a severity and a machine for these alerts, and the check fields come through', async () => {
    const a = (await list('?kind=configuration')).alerts; assert.deepStrictEqual([a[0].severity, a[0].agent.name, a[0].rule_id, a[0].level], ['medium', 'web1', '19008', 7]); assert.strictEqual(a[3].severity, 'critical');
    assert.deepStrictEqual([a[0].config.policy, a[0].config.result, a[0].config.previous_result, a[0].config.check_id], [CIS, 'failed', 'passed', '28500']);
    assert.deepStrictEqual([a[4].config.type, a[4].config.score, a[4].config.passed, a[4].config.failed, a[4].config.invalid, a[4].config.total], ['summary', 72, 120, 45, 12, 177]);
  });
  it('check_result filters by what the manager reports, including "not applicable"; a summary has no result so no result filter keeps it', async () => {
    assert.deepStrictEqual((await list('?kind=configuration&check_result=failed')).alerts.map((a) => a.config.check_id), ['28500', '15001']);
    assert.deepStrictEqual((await list('?kind=configuration&check_result=passed')).alerts.map((a) => a.config.check_id), ['28501']);
    assert.deepStrictEqual((await list('?kind=configuration&check_result=not_applicable')).alerts.map((a) => a.config.check_id), ['28502']);
    assert.strictEqual((await list('?check_result=failed')).count, 2);
  });
  it('policy, machine, severity and text combine with kind', async () => {
    assert.deepStrictEqual((await list('?kind=configuration&policy=' + encodeURIComponent(STIG))).alerts.map((a) => a.config.check_id), ['15001']);
    assert.strictEqual((await list('?kind=configuration&policy=CIS')).count, 0, 'the policy name must match whole');
    assert.deepStrictEqual((await list('?kind=configuration&agent=db1')).alerts.map((a) => a.config.check_id), ['28501', '28502']);
    assert.deepStrictEqual((await list('?kind=configuration&severity=critical')).alerts.map((a) => a.config.check_id), ['15001']);
    assert.deepStrictEqual((await list('?kind=configuration&q=ipv6')).alerts.map((a) => a.config.check_id), ['28502']);
    assert.deepStrictEqual((await list('?kind=configuration&q=' + encodeURIComponent('STIG Windows'))).alerts.map((a) => a.config.check_id), ['15001']);
    assert.deepStrictEqual((await list('?kind=configuration&check_result=failed&agent=web1')).alerts.map((a) => a.config.check_id), ['28500']);
  });
  it('the one-alert route gives the check card and every check field, in `configuration`, not in the general details', async () => {
    const d = await get('/v1/endpoints/alerts/' + ids.ssh); assert.strictEqual(d.status, 200);
    const a = d.body.alert; assert.strictEqual(a.config.check_title, 'Ensure SSH root login is disabled'); assert.strictEqual(a.configuration.check_remediation, 'Fix it.'); assert.strictEqual(a.configuration.check_compliance_cis, '5.2.10'); assert.strictEqual(a.configuration.check_command_0, 'sshd -T');
    assert.ok(!Object.keys(a.data).some((k) => k.startsWith('sca_'))); assert.strictEqual((await get('/v1/endpoints/alerts/' + ids.other)).status, 404);
  });
  it('the summary counts only configuration check alerts with kind=configuration, and lists the policies and the results; severity counts stay exact', async () => {
    const r = await get('/v1/endpoints/alerts/summary?kind=configuration'); assert.strictEqual(r.status, 200);
    assert.strictEqual(r.body.severity.total, 5); assert.deepStrictEqual([r.body.severity.critical, r.body.severity.high, r.body.severity.medium, r.body.severity.low], [1, 1, 1, 2]);
    assert.deepStrictEqual(r.body.top.policies, [{ name: CIS, count: 4 }, { name: STIG, count: 1 }]); assert.deepStrictEqual(r.body.top.check_results, [{ name: 'failed', count: 2 }, { name: 'not applicable', count: 1 }, { name: 'passed', count: 1 }]);
    assert.strictEqual(r.body.sampled.events, 5);
    const f = await get('/v1/endpoints/alerts/summary?kind=configuration&check_result=failed'); assert.strictEqual(f.body.severity.total, 2);
    assert.strictEqual((await get('/v1/endpoints/alerts/summary')).body.severity.total, 6);
  });
  it('bad values are a 400 and the store is not asked', async () => {
    for (const q of ['?kind=config', '?check_result=not%20applicable', '?check_result=passed&check_result=failed', "?policy=x%0Ay", '?policy=' + 'x'.repeat(201)]) { const r = await get('/v1/endpoints/alerts' + q); assert.strictEqual(r.status, 400, q); assert.strictEqual(r.body.error.code, 'INVALID_ALERT_QUERY'); }
    assert.strictEqual((await get('/v1/endpoints/alerts/summary?check_result=maybe')).status, 400);
  });
});

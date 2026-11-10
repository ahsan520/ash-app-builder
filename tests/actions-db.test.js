'use strict';
// SR2 against a real PostgreSQL (platform schema applied): the real routes, the real SQL in src/actions/service.js, the real built-in actions on the
// real cases tables, and the real audit_events table. Only the sign-in chain is replaced (the same way as tests/cases-db.test.js).
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_USER=asix_admin DB_NAME=asix_platform DB_PASSWORD=... node tests/actions-db.test.js
// Skips itself otherwise, so `npm test` and CI are unaffected.
if (!process.env.ASIX_TEST_DB) { console.log('skipped (set ASIX_TEST_DB=1 to run against Postgres)'); process.exit(0); }
process.env.ASIX_PROFILE = process.env.ASIX_PROFILE || 'home';

const assert = require('assert');
const express = require('express');
const db = require('../src/db');
const shared = require('../src/gateway/shared');

let TENANT; let USER; const asked = [];
require.cache[require.resolve('../src/gateway/shared')].exports = {
  ...shared,
  guarded: (permission) => [(req, res, next) => { req.tenant_id = TENANT; req.user_id = USER; asked.push([req.method, req.route ? req.route.path : req.path, permission]); next(); }],
};
const modules = require('../src/modules');
const catalog = require('../src/actions/catalog');
const service = require('../src/actions/service');

async function main() {
  const stamp = Date.now();
  const q = (t, p) => db.query(t, p);
  const mkTenant = async (n) => (await q('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['actions-' + n + '-' + stamp])).rows[0].id;
  const mkUser = async (t, n) => (await q('INSERT INTO users (tenant_id, username, email) VALUES ($1, $2, $3) RETURNING id', [t, `${n}-${stamp}`, `${n}-${stamp}@example.test`])).rows[0].id;
  const mkAlert = async (t, title, severity) => (await q(`INSERT INTO alerts (tenant_id, rule_name, severity, status, title, last_event_at) VALUES ($1, 'test rule', $2, 'open', $3, localtimestamp) RETURNING id`, [t, severity, title])).rows[0].id;
  const A = await mkTenant('a'); const B = await mkTenant('b');
  const alice = await mkUser(A, 'alice'); const bob = await mkUser(A, 'bob'); const eve = await mkUser(B, 'eve');
  const a1 = await mkAlert(A, 'Brute force', 'high'); const a2 = await mkAlert(A, 'New device', 'low'); const a3 = await mkAlert(A, 'Odd login', 'medium');

  // test-only actions through the same register() that SR1 and SR5 will use
  const log = [];
  catalog.register({
    id: 'test.high', name: 'High-risk test', description: 'd', publisher: 'test', kind: 'builtin', source: 'test', risk: 'high', reversible: false, max_autonomy: 2, default_autonomy: 2, parameters: [],
    async execute() { log.push('high'); return { ok: true, result: { did: 'it' }, undo: null }; },
  });
  catalog.register({
    id: 'test.boom', name: 'Throws after writing', description: 'd', publisher: 'test', kind: 'builtin', source: 'test', risk: 'low', reversible: false, append_only: true, max_autonomy: 4, default_autonomy: 2, parameters: [],
    async execute({ client, tenantId }) {
      await client.query(`INSERT INTO cases (tenant_id, case_number, title, created_by_name) VALUES ($1, 999, 'half written', 'test')`, [tenantId]);
      throw new Error('boom: secret database detail');
    },
  });

  const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/actions')); app.use(require('../src/gateway/routes/cases'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body) => {
    const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    let json = null; try { json = await r.json(); } catch { /* no body */ }
    return { status: r.status, json };
  };
  const code = (r) => r.json && r.json.error && r.json.error.code;
  const as = (t, u) => { TENANT = t; USER = u; };
  const settingOf = (id, body) => call('PUT', `/v1/actions/${id}/setting`, body);
  const runAct = (id, parameters) => call('POST', `/v1/actions/${id}/run`, { parameters });
  const mkCase = async (title, extra) => (await call('POST', '/v1/cases', { title, ...(extra || {}) })).json.case.id;
  const caseOf = async (id) => (await call('GET', '/v1/cases/' + id)).json;
  const rows = async (t, sql, p) => (await q(sql, [t, ...(p || [])])).rows;
  const auditCount = async (t, action, result) => (await rows(t, 'SELECT COUNT(*)::int AS n FROM audit_events WHERE tenant_id = $1 AND action = $2' + (result ? ' AND result = $3' : ''), result ? [action, result] : [action]))[0].n;
  // a run recorded by automation (the playbook runner of SR3 will call this): through the service, never through a route
  const automate = (t, u, id, params) => db.withTenant(t, (c) => service.request(c, t, u, id, params, 'automation'));
  as(A, alice);

  try {
    // 1. the registry: everything is installed and nothing is enabled
    let r = await call('GET', '/v1/actions');
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(r.json.actions.filter((a) => a.id.startsWith('case.')).map((a) => a.id), ['case.add_alerts', 'case.add_note', 'case.create', 'case.remove_alerts', 'case.set_owner', 'case.set_severity', 'case.set_status']);
    assert.ok(r.json.actions.every((a) => a.enabled === false && a.configured === false && a.runs === 0), 'installed actions start disabled');
    assert.ok(r.json.actions.every((a) => !('execute' in a)), 'no code is sent');
    assert.strictEqual(r.json.actions.find((a) => a.id === 'case.add_note').autonomy, 2);
    assert.strictEqual(r.json.levels['3'], 'Run low-risk actions by itself');
    r = await call('GET', '/v1/actions/case.add_note'); assert.deepStrictEqual([r.status, r.json.action.name], [200, 'Add a note to a case']);
    r = await call('GET', '/v1/actions/no.such'); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND']);

    // 2. a disabled action is refused, and the refusal is recorded and audited; bad parameters are a 400 and record nothing
    const c1 = await mkCase('Router attack', { alert_ids: [a1] });
    r = await runAct('case.add_note', { case_id: c1, body: 'hello' });
    assert.deepStrictEqual([r.status, code(r)], [409, 'ACTION_DISABLED']);
    assert.strictEqual(r.json.run.status, 'refused'); assert.strictEqual(r.json.error.run_id, r.json.run.id);
    assert.strictEqual((await caseOf(c1)).timeline.length, 2, 'nothing was changed (created + alert added)');
    assert.strictEqual(await auditCount(A, 'soar:action:run', 'denied'), 1);
    r = await runAct('case.add_note', { case_id: 'nope', body: 'x' }); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_PARAMETER']);
    r = await runAct('case.add_note', { case_id: c1, body: 'x', origin: 'automation' }); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_PARAMETERS']);
    r = await call('POST', '/v1/actions/case.add_note/run', { parameters: { case_id: c1, body: 'x' }, origin: 'automation' }); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_BODY']);
    r = await runAct('no.such', {}); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND']);
    assert.strictEqual((await call('GET', '/v1/actions/runs')).json.total, 1, 'only the refused request was recorded');

    // 3. enabling: the audit row, the setting, and a person's run executes at the default level 2 and is recorded under their name
    r = await settingOf('case.add_note', { enabled: true });
    assert.deepStrictEqual([r.status, r.json.action.enabled, r.json.action.autonomy, r.json.action.updated_by_name], [200, true, 2, 'alice-' + stamp]);
    assert.strictEqual(await auditCount(A, 'soar:action:enable'), 1);
    await settingOf('case.add_note', { enabled: true });
    assert.strictEqual(await auditCount(A, 'soar:action:enable'), 1, 'setting what is already set writes nothing');
    r = await runAct('case.add_note', { case_id: c1, body: '  seen on the router  ' });
    assert.strictEqual(r.status, 201);
    const note = r.json.run;
    assert.deepStrictEqual([note.status, note.origin, note.risk_class, note.autonomy_level, note.requested_by_name, note.decided_by_name, note.undo], ['succeeded', 'user', 'low', 2, 'alice-' + stamp, 'alice-' + stamp, null]);
    assert.deepStrictEqual(note.params, { case_id: c1, body: 'seen on the router' });
    let cv = await caseOf(c1);
    assert.strictEqual(cv.timeline[cv.timeline.length - 1].text, 'seen on the router');
    assert.strictEqual(cv.timeline[cv.timeline.length - 1].actor_name, 'alice-' + stamp);
    assert.strictEqual(await auditCount(A, 'soar:action:run', 'success'), 1);
    assert.ok((await rows(A, 'SELECT resource FROM audit_events WHERE tenant_id = $1 AND action = $2 AND result = $3', ['soar:action:run', 'success']))[0].resource.includes(note.id), 'the audit row names the run');
    r = await runAct('case.add_note', { case_id: c1, body: 'x' }); assert.strictEqual(r.status, 201);
    r = await call('POST', '/v1/actions/runs/' + note.id + '/undo'); assert.deepStrictEqual([r.status, code(r)], [409, 'NOT_UNDOABLE']);

    // 4. the levels: 1 records a recommendation and changes nothing; 0 refuses; a level above the ceiling is refused
    await settingOf('case.add_note', { autonomy: 1 }); assert.strictEqual(await auditCount(A, 'soar:action:autonomy'), 1);
    const before = (await caseOf(c1)).timeline.length;
    r = await runAct('case.add_note', { case_id: c1, body: 'only a recommendation' });
    assert.deepStrictEqual([r.status, r.json.run.status], [201, 'recommended']);
    assert.strictEqual((await caseOf(c1)).timeline.length, before);
    await settingOf('case.add_note', { autonomy: 0 });
    r = await runAct('case.add_note', { case_id: c1, body: 'x' }); assert.deepStrictEqual([r.status, code(r), r.json.run.status], [409, 'OBSERVE_ONLY', 'refused']);
    r = await settingOf('case.set_status', { autonomy: 4 }); assert.deepStrictEqual([r.status, code(r)], [400, 'AUTONOMY_TOO_HIGH']);
    assert.strictEqual((await call('GET', '/v1/actions/case.set_status')).json.action.configured, false, 'a refused setting leaves no row');
    r = await settingOf('case.add_note', {}); assert.strictEqual(r.status, 400);
    r = await settingOf('no.such', { enabled: true }); assert.strictEqual(r.status, 404);
    await settingOf('case.add_note', { autonomy: 2 });

    // 5. a change that can be undone: close a case, then put it back; a second undo and an undo of an undo are refused
    r = await settingOf('case.set_status', { enabled: true }); assert.strictEqual(r.json.action.autonomy, 2);
    r = await runAct('case.set_status', { case_id: c1, status: 'closed' });
    assert.deepStrictEqual([r.status, r.json.run.status, r.json.run.risk_class], [201, 'succeeded', 'medium']);
    assert.deepStrictEqual(r.json.run.result, { case_id: c1, changed: true, from: 'open', to: 'closed' });
    assert.deepStrictEqual(r.json.run.undo, { action: 'case.set_status', params: { case_id: c1, status: 'open' } });
    const closing = r.json.run;
    assert.strictEqual((await caseOf(c1)).case.status, 'closed');
    r = await call('POST', '/v1/actions/runs/' + closing.id + '/undo');
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual([r.json.run.origin, r.json.run.status], ['undo', 'succeeded']);
    assert.strictEqual(r.json.run.undo_of_run_id, closing.id); assert.strictEqual(r.json.undone.undone_by_run_id, r.json.run.id);
    const undoRun = r.json.run;
    assert.strictEqual((await caseOf(c1)).case.status, 'open');
    r = await call('POST', '/v1/actions/runs/' + closing.id + '/undo'); assert.deepStrictEqual([r.status, code(r)], [409, 'ALREADY_UNDONE']);
    r = await call('POST', '/v1/actions/runs/' + undoRun.id + '/undo'); assert.deepStrictEqual([r.status, code(r)], [409, 'NOT_UNDOABLE']);
    assert.strictEqual(await auditCount(A, 'soar:action:run', 'success'), 4);
    // the same value again changes nothing, so there is nothing to undo
    r = await runAct('case.set_status', { case_id: c1, status: 'open' });
    assert.deepStrictEqual([r.json.run.status, r.json.run.result.changed, r.json.run.undo], ['succeeded', false, null]);
    r = await call('POST', '/v1/actions/runs/' + r.json.run.id + '/undo'); assert.strictEqual(code(r), 'NOT_UNDOABLE');

    // 6. every reversible built-in gives an undo that works: severity, owner (also back to nobody), alerts added and removed
    await settingOf('case.set_severity', { enabled: true }); await settingOf('case.set_owner', { enabled: true }); await settingOf('case.add_alerts', { enabled: true }); await settingOf('case.remove_alerts', { enabled: true });
    const c2 = await mkCase('Second', { severity: 'low' });
    r = await runAct('case.set_severity', { case_id: c2, severity: 'critical' }); assert.strictEqual((await caseOf(c2)).case.severity, 'critical');
    r = await call('POST', '/v1/actions/runs/' + r.json.run.id + '/undo'); assert.deepStrictEqual([r.status, (await caseOf(c2)).case.severity], [200, 'low']);
    r = await runAct('case.set_owner', { case_id: c2, owner_id: bob }); assert.strictEqual((await caseOf(c2)).case.owner_id, bob);
    const ownerRun = r.json.run;
    r = await call('POST', '/v1/actions/runs/' + ownerRun.id + '/undo'); assert.deepStrictEqual([r.status, (await caseOf(c2)).case.owner_id], [200, null]);
    r = await runAct('case.set_owner', { case_id: c2, owner_id: null }); assert.deepStrictEqual([r.json.run.status, r.json.run.result.changed], ['succeeded', false]);
    r = await runAct('case.set_owner', { case_id: c2 }); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_PARAMETERS']);
    r = await runAct('case.set_owner', { case_id: c2, owner_id: eve }); assert.deepStrictEqual([r.json.run.status, r.json.run.error_code], ['failed', 'OWNER_NOT_FOUND']);
    // add two alerts where one is already in: the undo takes out only the one that was added
    await runAct('case.add_alerts', { case_id: c2, alert_ids: [a2] });
    r = await runAct('case.add_alerts', { case_id: c2, alert_ids: [a2, a3] });
    assert.deepStrictEqual([r.json.run.status, r.json.run.result.added, r.json.run.result.already], ['succeeded', 1, 1]);
    assert.deepStrictEqual(r.json.run.undo, { action: 'case.remove_alerts', params: { case_id: c2, alert_ids: [a3] } });
    r = await call('POST', '/v1/actions/runs/' + r.json.run.id + '/undo'); assert.strictEqual(r.status, 200);
    assert.deepStrictEqual((await caseOf(c2)).alerts.map((a) => a.id), [a2]);
    r = await runAct('case.remove_alerts', { case_id: c2, alert_ids: [a2] }); assert.deepStrictEqual((await caseOf(c2)).alerts, []);
    r = await call('POST', '/v1/actions/runs/' + r.json.run.id + '/undo'); assert.deepStrictEqual([r.status, (await caseOf(c2)).alerts.map((a) => a.id)], [200, [a2]]);
    // an alert in another case refuses the whole request, and the failed run says why
    r = await runAct('case.add_alerts', { case_id: c2, alert_ids: [a1] }); assert.deepStrictEqual([r.json.run.status, r.json.run.error_code], ['failed', 'ALERTS_TAKEN']);
    // undo is allowed after the action was switched off, because it only reverses something that was allowed
    r = await runAct('case.set_severity', { case_id: c2, severity: 'high' }); const sev = r.json.run;
    await settingOf('case.set_severity', { enabled: false });
    r = await call('POST', '/v1/actions/runs/' + sev.id + '/undo'); assert.deepStrictEqual([r.status, (await caseOf(c2)).case.severity], [200, 'low']);
    r = await runAct('case.set_severity', { case_id: c2, severity: 'high' }); assert.deepStrictEqual([r.status, code(r)], [409, 'ACTION_DISABLED']);
    assert.strictEqual(await auditCount(A, 'soar:action:disable'), 1);

    // 7. a failure rolls back everything the action did and records the failure; a database error never reaches the caller in the database's words
    await settingOf('case.remove_alerts', { enabled: true });
    await runAct('case.add_alerts', { case_id: c2, alert_ids: [a3] });
    r = await runAct('case.remove_alerts', { case_id: c2, alert_ids: [a3, a1] });
    assert.deepStrictEqual([r.json.run.status, r.json.run.error_code], ['failed', 'NOT_ATTACHED']);
    assert.ok((await caseOf(c2)).alerts.some((a) => a.id === a3), 'the alert taken out before the failure came back');
    r = await runAct('case.add_note', { case_id: '00000000-0000-4000-8000-000000000000', body: 'x' }); assert.deepStrictEqual([r.json.run.status, r.json.run.error_code], ['failed', 'NOT_FOUND']);
    await settingOf('test.boom', { enabled: true });
    r = await runAct('test.boom', {});
    assert.deepStrictEqual([r.status, r.json.run.status, r.json.run.error_code, r.json.run.error_message], [201, 'failed', 'ACTION_ERROR', 'The action failed with an internal error']);
    assert.ok(!JSON.stringify(r.json).includes('secret database detail'));
    assert.strictEqual((await rows(A, "SELECT COUNT(*)::int AS n FROM cases WHERE tenant_id = $1 AND title = 'half written'"))[0].n, 0, 'what the action wrote before it threw is gone');
    assert.ok((await rows(A, "SELECT 1 FROM action_runs WHERE tenant_id = $1 AND id = $2", [r.json.run.id])).length === 1, 'but the run itself is kept');

    // 8. automation: level 2 waits, a person approves it and it runs as asked; the one who asked is not changed by the approval
    await settingOf('case.set_status', { enabled: true, autonomy: 2 });
    let out = await automate(A, null, 'case.set_status', { case_id: c2, status: 'investigating' });
    assert.deepStrictEqual([out.run.status, out.run.origin, out.run.requested_by_name, out.run.decided_by_name, out.run.autonomy_level], ['awaiting_approval', 'automation', 'service account', null, 2]);
    assert.strictEqual((await caseOf(c2)).case.status, 'open', 'nothing happened yet');
    const waiting = out.run.id;
    r = await call('GET', '/v1/actions/runs?status=awaiting_approval'); assert.deepStrictEqual(r.json.runs.map((x) => x.id), [waiting]);
    as(A, bob);
    r = await call('POST', `/v1/actions/runs/${waiting}/approve`);
    assert.deepStrictEqual([r.status, r.json.run.status, r.json.run.decided_by_name, r.json.run.requested_by_name], [200, 'succeeded', 'bob-' + stamp, 'service account']);
    assert.strictEqual((await caseOf(c2)).case.status, 'investigating');
    assert.strictEqual((await caseOf(c2)).timeline.pop().actor_name, 'service account', 'the change is the requester\'s; the approval is on the run');
    assert.strictEqual(await auditCount(A, 'soar:action:approve', 'success'), 1);
    r = await call('POST', `/v1/actions/runs/${waiting}/approve`); assert.deepStrictEqual([r.status, code(r)], [409, 'NOT_WAITING']);
    r = await call('POST', `/v1/actions/runs/${waiting}/reject`); assert.deepStrictEqual([r.status, code(r)], [409, 'NOT_WAITING']);
    r = await call('POST', `/v1/actions/runs/${waiting}/undo`); assert.strictEqual(r.status, 200);   // an approved run can be undone like any other
    assert.strictEqual((await caseOf(c2)).case.status, 'open');
    // rejecting: nothing runs and the note is kept
    out = await automate(A, null, 'case.set_status', { case_id: c2, status: 'closed' });
    r = await call('POST', `/v1/actions/runs/${out.run.id}/reject`, { note: 'not yet' });
    assert.deepStrictEqual([r.status, r.json.run.status, r.json.run.decided_by_name, r.json.run.decision_note], [200, 'rejected', 'bob-' + stamp, 'not yet']);
    assert.strictEqual((await caseOf(c2)).case.status, 'open');
    assert.strictEqual(await auditCount(A, 'soar:action:reject', 'rejected'), 1);
    // switching the action off stops what was already waiting: the approval is refused and recorded
    out = await automate(A, null, 'case.set_status', { case_id: c2, status: 'closed' });
    await settingOf('case.set_status', { enabled: false });
    r = await call('POST', `/v1/actions/runs/${out.run.id}/approve`);
    assert.deepStrictEqual([r.status, code(r), r.json.run.status], [409, 'ACTION_DISABLED', 'refused']);
    assert.strictEqual((await caseOf(c2)).case.status, 'open');
    await settingOf('case.set_status', { enabled: true });

    // 9. automation at level 3: a low-risk action runs by itself, a medium-risk one still waits; level 4 runs a low-risk class
    await settingOf('case.add_note', { autonomy: 3 }); await settingOf('case.set_status', { autonomy: 3 });
    out = await automate(A, null, 'case.add_note', { case_id: c2, body: 'by automation' });
    assert.deepStrictEqual([out.run.status, out.run.decided_by_name], ['succeeded', null]);
    out = await automate(A, null, 'case.set_status', { case_id: c2, status: 'closed' });
    assert.strictEqual(out.run.status, 'awaiting_approval'); assert.match(out.run.decision_note, /medium-risk/);
    await settingOf('case.add_note', { autonomy: 4 });
    out = await automate(A, null, 'case.add_note', { case_id: c2, body: 'level four' }); assert.strictEqual(out.run.status, 'succeeded');
    out = await automate(A, null, 'case.add_note', { case_id: c2 }); assert.deepStrictEqual([out.code], ['INVALID_PARAMETERS']);
    await assert.rejects(() => db.withTenant(A, (c) => service.request(c, A, null, 'case.add_note', { case_id: c2, body: 'x' }, 'undo')), /origin must be user or automation/);

    // 10. a high-risk action: automation always waits, the one who asked may not approve, somebody else may
    await settingOf('test.high', { enabled: true });
    r = await settingOf('test.high', { autonomy: 3 }); assert.deepStrictEqual([r.status, code(r)], [400, 'AUTONOMY_TOO_HIGH']);
    out = await automate(A, alice, 'test.high', {});
    assert.strictEqual(out.run.status, 'awaiting_approval');
    as(A, alice);
    r = await call('POST', `/v1/actions/runs/${out.run.id}/approve`); assert.deepStrictEqual([r.status, code(r)], [409, 'SELF_APPROVAL']);
    assert.deepStrictEqual(log, [], 'refused approval ran nothing');
    as(A, bob);
    r = await call('POST', `/v1/actions/runs/${out.run.id}/approve`); assert.deepStrictEqual([r.status, r.json.run.status], [200, 'succeeded']);
    assert.deepStrictEqual(log, ['high']);
    r = await call('POST', `/v1/actions/runs/${out.run.id}/undo`); assert.strictEqual(code(r), 'NOT_UNDOABLE');
    as(A, alice);

    // 11. two people approving at once: one runs it, the other is told it is no longer waiting. Two undos at once: one wins.
    await settingOf('case.add_note', { autonomy: 2 });
    out = await automate(A, null, 'case.add_note', { case_id: c2, body: 'once only' });
    const race = await Promise.all([call('POST', `/v1/actions/runs/${out.run.id}/approve`), call('POST', `/v1/actions/runs/${out.run.id}/approve`)]);
    assert.deepStrictEqual(race.map((x) => x.status).sort(), [200, 409]);
    assert.strictEqual((await caseOf(c2)).timeline.filter((e) => e.text === 'once only').length, 1, 'it ran once');
    r = await runAct('case.set_severity', { case_id: c2, severity: 'critical' }); // disabled above: refused, so use set_owner
    await settingOf('case.set_owner', { enabled: true });
    r = await runAct('case.set_owner', { case_id: c2, owner_id: bob });
    const two = await Promise.all([call('POST', `/v1/actions/runs/${r.json.run.id}/undo`), call('POST', `/v1/actions/runs/${r.json.run.id}/undo`)]);
    assert.deepStrictEqual(two.map((x) => x.status).sort(), [200, 409]);

    // 12. runs: list, filter, page, read one
    r = await call('GET', '/v1/actions/runs?limit=5'); assert.deepStrictEqual([r.status, r.json.runs.length, r.json.limit], [200, 5, 5]); assert.ok(r.json.total > 5);
    assert.ok(r.json.runs.every((x, i, a) => !i || new Date(a[i - 1].created_at) >= new Date(x.created_at)), 'newest first');
    r = await call('GET', '/v1/actions/runs?status=refused'); assert.ok(r.json.runs.length >= 3 && r.json.runs.every((x) => x.status === 'refused'));
    r = await call('GET', '/v1/actions/runs?action=case.add_note&status=recommended'); assert.strictEqual(r.json.total, 1);
    r = await call('GET', '/v1/actions/runs?status=weird'); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_STATUS']);
    r = await call('GET', '/v1/actions/runs/' + note.id); assert.deepStrictEqual([r.status, r.json.run.id], [200, note.id]);
    r = await call('GET', '/v1/actions/runs/not-an-id'); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_ID']);
    r = await call('GET', '/v1/actions'); const noteAction = r.json.actions.find((a) => a.id === 'case.add_note');
    assert.ok(noteAction.runs >= 6 && noteAction.last_run_at, 'the registry shows how often an action ran');

    // 13. every run has its audit row (a run that waited for a person has two: when it was asked and when it ran), and no audit row holds a parameter value
    const allRuns = await rows(A, 'SELECT id, status FROM action_runs WHERE tenant_id = $1');
    for (const run of allRuns) {
      const got = await rows(A, "SELECT result FROM audit_events WHERE tenant_id = $1 AND action = 'soar:action:run' AND resource LIKE $2", ['% run=' + run.id]);
      const waited = got.some((x) => x.result === 'pending'); const ran = run.status === 'succeeded' || run.status === 'failed';
      assert.strictEqual(got.length, waited && ran ? 2 : 1, `run ${run.id} (${run.status}) has ${got.length} audit rows`);
    }
    assert.ok(allRuns.length > 30, 'a good number of runs were checked');
    const bad = await rows(A, "SELECT resource FROM audit_events WHERE tenant_id = $1 AND action LIKE 'soar:action:%' AND (resource LIKE '%seen on the router%' OR resource LIKE '%once only%')");
    assert.deepStrictEqual(bad, []);
    assert.ok((await rows(A, "SELECT 1 FROM audit_events WHERE tenant_id = $1 AND action LIKE 'soar:action:%' AND user_id = $2", [alice])).length > 0, 'audit rows carry the user');

    // 14. tenant B is separate: nothing enabled, cannot see or touch A's runs, and A's settings do not carry over
    as(B, eve);
    r = await call('GET', '/v1/actions'); assert.ok(r.json.actions.every((x) => !x.enabled && x.runs === 0));
    r = await call('GET', '/v1/actions/runs'); assert.strictEqual(r.json.total, 0);
    r = await call('GET', '/v1/actions/runs/' + note.id); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND']);
    r = await call('POST', `/v1/actions/runs/${waiting}/undo`); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND']);
    out = await automate(A, null, 'case.set_status', { case_id: c2, status: 'closed' });
    r = await call('POST', `/v1/actions/runs/${out.run.id}/approve`); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND']);
    r = await call('POST', `/v1/actions/runs/${out.run.id}/reject`); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND']);
    r = await runAct('case.add_note', { case_id: c1, body: 'x' }); assert.strictEqual(code(r), 'ACTION_DISABLED');
    await settingOf('case.add_note', { enabled: true });
    r = await runAct('case.add_note', { case_id: c1, body: 'cross-tenant' }); assert.deepStrictEqual([r.json.run.status, r.json.run.error_code], ['failed', 'NOT_FOUND'], "another tenant's case is not found");
    as(A, alice);
    assert.ok((await caseOf(c1)).timeline.every((e) => e.text !== 'cross-tenant'));
    assert.strictEqual((await call('GET', '/v1/actions/case.add_note')).json.action.enabled, true);

    // 15. row-level security, with a role that does not own the tables (the API connects as the owner and filters by tenant itself; this checks the policies)
    try {
      await q('DROP ROLE IF EXISTS asix_actions_rls_test'); await q('CREATE ROLE asix_actions_rls_test NOLOGIN');
      await q('GRANT SELECT ON action_runs, action_settings TO asix_actions_rls_test');
      await q('GRANT asix_actions_rls_test TO CURRENT_USER');
      const seen = async (tenant) => db.withTenant(tenant, async (c) => { await c.query('SET LOCAL ROLE asix_actions_rls_test'); return (await c.query('SELECT (SELECT COUNT(*)::int FROM action_runs) AS runs, (SELECT COUNT(*)::int FROM action_settings) AS settings')).rows[0]; });
      const a = await seen(A); const b = await seen(B);
      assert.ok(a.runs > 10 && a.settings > 5, 'tenant A sees its rows');
      assert.deepStrictEqual(b, { runs: 2, settings: 1 }, 'tenant B sees only its own two runs (one refused, one on a case it cannot see) and its one setting');
      console.log('  row-level security checked with a non-owner role');
    } catch (e) { if (/permission denied|must be|CREATE ROLE|GRANT/i.test(e.message) && !(e instanceof assert.AssertionError)) console.log('  row-level security step skipped (this database user may not create roles):', e.message); else throw e; }
    finally { try { await q('DROP OWNED BY asix_actions_rls_test'); await q('DROP ROLE IF EXISTS asix_actions_rls_test'); } catch { /* best effort */ } }

    // 16. the constraints refuse what the service would never write
    await assert.rejects(() => q(`INSERT INTO action_runs (tenant_id, action_id, origin, status, risk_class, requested_by_name) VALUES ($1, 'x.y', 'user', 'maybe', 'low', 'x')`, [A]), /action_runs_status_chk/);
    await assert.rejects(() => q(`INSERT INTO action_settings (tenant_id, action_id, autonomy_level, updated_by_name) VALUES ($1, 'x.y', 5, 'x')`, [A]), /action_settings_level_chk/);
    await assert.rejects(() => q(`INSERT INTO action_runs (tenant_id, action_id, origin, status, risk_class, requested_by_name) VALUES ($1, 'x.y', 'user', 'failed', 'extreme', 'x')`, [A]), /action_runs_risk_chk/);

    // 17. which permission each route asks for
    const perm = (m, p) => [...new Set(asked.filter((x) => x[0] === m && x[1] === p).map((x) => x[2]))];
    for (const [m, p, want] of [['GET', '/v1/actions', 'soar:actions:read'], ['GET', '/v1/actions/:id', 'soar:actions:read'], ['GET', '/v1/actions/runs', 'soar:actions:read'], ['GET', '/v1/actions/runs/:id', 'soar:actions:read'],
      ['PUT', '/v1/actions/:id/setting', 'soar:actions:write'], ['POST', '/v1/actions/:id/run', 'soar:actions:write'], ['POST', '/v1/actions/runs/:id/approve', 'soar:actions:write'],
      ['POST', '/v1/actions/runs/:id/reject', 'soar:actions:write'], ['POST', '/v1/actions/runs/:id/undo', 'soar:actions:write']]) {
      assert.deepStrictEqual(perm(m, p), [want], `${m} ${p} asked for ${perm(m, p)}`);
    }

    // 18. a deployment with the module off answers 403 on every route
    const real = modules.isEnabled; modules.isEnabled = async () => false;
    for (const [m, p, body] of [['GET', '/v1/actions'], ['GET', '/v1/actions/runs'], ['PUT', '/v1/actions/case.add_note/setting', { enabled: true }], ['POST', '/v1/actions/case.add_note/run', {}], ['POST', `/v1/actions/runs/${waiting}/undo`]]) {
      r = await call(m, p, body); assert.deepStrictEqual([r.status, code(r)], [403, 'MODULE_DISABLED'], `${m} ${p}`);
    }
    modules.isEnabled = real;
    console.log('actions-db: all checks passed');
  } finally {
    srv.close();
    for (const t of [A, B]) {
      for (const tbl of ['action_runs', 'action_settings', 'audit_events', 'case_events', 'case_alerts', 'cases', 'alerts', 'users']) await q(`DELETE FROM ${tbl} WHERE tenant_id = $1`, [t]).catch((e) => console.error('cleanup', tbl, e.message));
      await q('DELETE FROM tenants WHERE id = $1', [t]).catch((e) => console.error('cleanup tenants', e.message));
    }
    await db.close();
  }
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });

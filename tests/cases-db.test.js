'use strict';
// CS1 against a real PostgreSQL (platform schema applied): the real routes, the real SQL in src/cases/service.js and the real tables.
// Only the sign-in chain is replaced (the same way as tests/score-alert-db.test.js).
//   ASIX_TEST_DB=1 DB_HOST=127.0.0.1 DB_USER=asix_admin DB_NAME=asix_platform DB_PASSWORD=... node tests/cases-db.test.js
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

async function main() {
  const stamp = Date.now();
  const q = (t, p) => db.query(t, p);
  const mkTenant = async (n) => (await q('INSERT INTO tenants (name) VALUES ($1) RETURNING id', ['cases-' + n + '-' + stamp])).rows[0].id;
  const mkUser = async (t, n) => (await q('INSERT INTO users (tenant_id, username, email) VALUES ($1, $2, $3) RETURNING id', [t, `${n}-${stamp}`, `${n}-${stamp}@example.test`])).rows[0].id;
  const mkAlert = async (t, title, severity, over = {}) => (await q(
    `INSERT INTO alerts (tenant_id, rule_name, severity, status, title, last_event_at, merged_into_id) VALUES ($1, 'test rule', $2, $3, $4, localtimestamp - ($5 || ' minutes')::interval, $6) RETURNING id`,
    [t, severity, over.status || 'open', title, String(over.minutesAgo || 0), over.mergedInto || null])).rows[0].id;
  const A = await mkTenant('a'); const B = await mkTenant('b');
  const alice = await mkUser(A, 'alice'); const bob = await mkUser(A, 'bob'); const eve = await mkUser(B, 'eve');
  const aHigh = await mkAlert(A, 'Brute force on router', 'high', { minutesAgo: 5 });
  const aLow = await mkAlert(A, 'New device on wifi', 'low', { minutesAgo: 9 });
  const aCrit = await mkAlert(A, 'Malware found', 'critical', { minutesAgo: 20 });
  const aMed = await mkAlert(A, 'Odd login hour', 'medium', { minutesAgo: 1 });
  const aClosed = await mkAlert(A, 'Old closed alert', 'high', { status: 'closed' });
  const aMerged = await mkAlert(A, 'Folded duplicate', 'high', { mergedInto: aHigh });
  const bAlert = await mkAlert(B, 'Other tenant alert', 'critical');

  const app = express(); app.use(express.json()); app.use(require('../src/gateway/routes/cases'));
  const srv = app.listen(0); const base = 'http://127.0.0.1:' + srv.address().port;
  const call = async (method, p, body) => {
    const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    let json = null; try { json = await r.json(); } catch { /* no body */ }
    return { status: r.status, json };
  };
  const code = (r) => r.json && r.json.error && r.json.error.code;
  const texts = (r) => r.json.timeline.map((e) => e.text);
  const as = (t, u) => { TENANT = t; USER = u; };
  as(A, alice);

  try {
    // 1. create a case from two alerts: number 1, severity = the worst alert, a timeline in order, the alerts listed worst first
    let r = await call('POST', '/v1/cases', { title: '  Router attack  ', description: 'Seen on the home router', alert_ids: [aLow, aHigh] });
    assert.strictEqual(r.status, 201); const c1 = r.json.case.id;
    assert.deepStrictEqual([r.json.case.case_number, r.json.case.title, r.json.case.severity, r.json.case.status, r.json.case.created_by_name], [1, 'Router attack', 'high', 'open', 'alice-' + stamp]);
    assert.deepStrictEqual(r.json.alerts.map((a) => a.title), ['Brute force on router', 'New device on wifi'], 'worst severity first');
    assert.deepStrictEqual(texts(r), ['Case created with 2 alerts', 'Alert added: New device on wifi', 'Alert added: Brute force on router']);
    assert.ok(r.json.timeline.every((e) => e.actor_name === 'alice-' + stamp));

    // 2. a case with an owner and an explicit severity, no alerts
    r = await call('POST', '/v1/cases', { title: 'Check the NAS', severity: 'low', owner_id: bob }); assert.strictEqual(r.status, 201);
    const c2 = r.json.case.id; assert.deepStrictEqual([r.json.case.case_number, r.json.case.severity, r.json.case.owner_name], [2, 'low', 'bob-' + stamp]);
    assert.deepStrictEqual(texts(r), ['Case created']);

    // 3. refusals leave nothing behind and do not use up a case number
    r = await call('POST', '/v1/cases', { title: 'Steal an alert', alert_ids: [aHigh] });
    assert.deepStrictEqual([r.status, code(r)], [409, 'ALERTS_TAKEN']); assert.match(r.json.error.message, /case #1/);
    r = await call('POST', '/v1/cases', { title: 'Alert from another tenant', alert_ids: [bAlert] }); assert.deepStrictEqual([r.status, code(r)], [404, 'ALERTS_NOT_FOUND']);
    r = await call('POST', '/v1/cases', { title: 'Owner from another tenant', owner_id: eve }); assert.deepStrictEqual([r.status, code(r)], [404, 'USER_NOT_FOUND']);
    r = await call('POST', '/v1/cases', { title: 'Third', alert_ids: [aCrit] }); assert.strictEqual(r.status, 201);
    assert.strictEqual(r.json.case.case_number, 3, 'the refused attempts did not consume numbers 3 and 4'); assert.strictEqual(r.json.case.severity, 'critical'); const c3 = r.json.case.id;
    assert.strictEqual((await q('SELECT COUNT(*)::int AS n FROM cases WHERE tenant_id = $1', [A])).rows[0].n, 3);

    // 4. input checks (400) and an unknown id (404)
    for (const b of [{}, { title: '' }, { title: 'x'.repeat(201) }, { title: 'ok', severity: 'urgent' }, { title: 'ok', alert_ids: 'x' }, { title: 'ok', alert_ids: ['nope'] }, { title: 'ok', extra: 1 }, { title: 'ok', owner_id: 'nope' }, { title: 'ok', alert_ids: Array.from({ length: 51 }, () => aMed) }]) {
      r = await call('POST', '/v1/cases', b); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_BODY'], JSON.stringify(b).slice(0, 60));
    }
    r = await call('GET', '/v1/cases/not-a-uuid'); assert.deepStrictEqual([r.status, code(r)], [400, 'INVALID_ID']);
    r = await call('GET', '/v1/cases/00000000-0000-4000-8000-000000000000'); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND']);

    // 5. candidates: active alerts in no case, not merged, worst first; and which case an alert is in
    r = await call('GET', '/v1/cases/candidates'); assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(r.json.alerts.map((a) => a.title), ['Odd login hour'], 'only the medium alert is still free (closed and merged alerts are not offered)');
    r = await call('GET', `/v1/alerts/${aHigh}/case`); assert.deepStrictEqual([r.status, r.json.case.case_number, r.json.case.title], [200, 1, 'Router attack']);
    r = await call('GET', `/v1/alerts/${aMed}/case`); assert.deepStrictEqual([r.status, r.json.case], [200, null]);

    // 6. attach: adds, skips what is already there, refuses an alert of another case, and says what is missing
    r = await call('POST', `/v1/cases/${c2}/alerts`, { alert_ids: [aMed, aClosed] }); assert.deepStrictEqual([r.status, r.json.added, r.json.already, r.json.alerts.length], [200, 2, 0, 2]);
    r = await call('POST', `/v1/cases/${c2}/alerts`, { alert_ids: [aMed.toUpperCase()] }); assert.deepStrictEqual([r.json.added, r.json.already], [0, 1], 'the same alert again is skipped, whatever the letter case');
    r = await call('POST', `/v1/cases/${c2}/alerts`, { alert_ids: [aHigh] }); assert.deepStrictEqual([r.status, code(r)], [409, 'ALERTS_TAKEN']);
    r = await call('POST', `/v1/cases/${c2}/alerts`, { alert_ids: [aMerged, bAlert] }); assert.deepStrictEqual([r.status, code(r)], [404, 'ALERTS_NOT_FOUND']); assert.ok(r.json.error.message.includes(bAlert));
    assert.strictEqual((await call('POST', `/v1/cases/${c2}/alerts`, { alert_ids: [] })).status, 400);
    r = await call('GET', `/v1/cases/${c2}`); assert.ok(texts(r).includes('Alert added: Odd login hour') && texts(r).includes('Alert added: Old closed alert'));
    r = await call('GET', '/v1/cases/candidates'); assert.deepStrictEqual(r.json.alerts, []);

    // 7. detach puts the alert back in the pool and writes the timeline; detaching what is not there is a 404
    r = await call('DELETE', `/v1/cases/${c2}/alerts/${aClosed}`); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.alerts.length, 1);
    assert.strictEqual(r.json.timeline.at(-1).text, 'Alert removed: Old closed alert');
    r = await call('DELETE', `/v1/cases/${c2}/alerts/${aClosed}`); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_ATTACHED']);
    assert.strictEqual((await call('DELETE', `/v1/cases/${c2}/alerts/nope`)).status, 400);

    // 8. edit: each real change is one timeline entry, in a fixed order; setting the same value again writes nothing
    r = await call('PATCH', `/v1/cases/${c2}`, { status: 'investigating', owner_id: alice, severity: 'high', title: 'Check the NAS and the router' });
    assert.strictEqual(r.status, 200); assert.deepStrictEqual([r.json.case.status, r.json.case.owner_name, r.json.case.severity, r.json.case.title], ['investigating', 'alice-' + stamp, 'high', 'Check the NAS and the router']);
    assert.deepStrictEqual(texts(r).slice(-4), ['Status: Open → Investigating', `Owner: bob-${stamp} → alice-${stamp}`, 'Severity: low → high', 'Title changed from "Check the NAS" to "Check the NAS and the router"']);
    const events = (await call('GET', `/v1/cases/${c2}`)).json.timeline.length;
    r = await call('PATCH', `/v1/cases/${c2}`, { status: 'investigating', owner_id: alice, severity: 'high' }); assert.strictEqual(r.status, 200);
    assert.strictEqual(r.json.timeline.length, events, 'no change, no new entries');
    r = await call('PATCH', `/v1/cases/${c2}`, { owner_id: null, description: 'Now with a description' }); assert.deepStrictEqual([r.json.case.owner_id, r.json.case.description], [null, 'Now with a description']);
    assert.deepStrictEqual(texts(r).slice(-2), [`Owner: alice-${stamp} → nobody`, 'Description edited']);
    for (const [b, c] of [[{}, 'INVALID_BODY'], [{ status: 'done' }, 'INVALID_BODY'], [{ severity: 'x' }, 'INVALID_BODY'], [{ title: '' }, 'INVALID_BODY'], [{ id: 'x' }, 'INVALID_BODY'], [{ owner_id: 'x' }, 'INVALID_BODY']]) {
      r = await call('PATCH', `/v1/cases/${c2}`, b); assert.deepStrictEqual([r.status, code(r)], [400, c], JSON.stringify(b));
    }
    r = await call('PATCH', `/v1/cases/${c2}`, { owner_id: eve }); assert.deepStrictEqual([r.status, code(r)], [404, 'USER_NOT_FOUND']);
    r = await call('PATCH', '/v1/cases/00000000-0000-4000-8000-000000000000', { status: 'closed' }); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND']);

    // 9. notes go in the timeline, with the author; the limit holds
    r = await call('POST', `/v1/cases/${c2}/notes`, { body: '  Called the owner of the NAS  ' }); assert.strictEqual(r.status, 201);
    assert.deepStrictEqual([r.json.timeline.at(-1).kind, r.json.timeline.at(-1).text, r.json.timeline.at(-1).actor_name], ['note', 'Called the owner of the NAS', 'alice-' + stamp]);
    for (const b of [{}, { body: '' }, { body: '   ' }, { body: 'x'.repeat(2001) }, { body: 5 }]) assert.strictEqual((await call('POST', `/v1/cases/${c2}/notes`, b)).status, 400);
    assert.strictEqual((await call('POST', '/v1/cases/00000000-0000-4000-8000-000000000000/notes', { body: 'x' })).status, 404);

    // 10. closing: closed_at is set, and only a note or a reopen is allowed afterwards
    r = await call('PATCH', `/v1/cases/${c2}`, { status: 'closed' }); assert.strictEqual(r.json.case.status, 'closed'); assert.ok(r.json.case.closed_at);
    for (const [m, p, b] of [['PATCH', `/v1/cases/${c2}`, { title: 'new' }], ['PATCH', `/v1/cases/${c2}`, { status: 'closed', severity: 'low' }], ['POST', `/v1/cases/${c2}/alerts`, { alert_ids: [aMed] }], ['DELETE', `/v1/cases/${c2}/alerts/${aMed}`]]) {
      r = await call(m, p, b); assert.deepStrictEqual([r.status, code(r)], [409, 'CASE_CLOSED'], m + ' ' + p);
    }
    r = await call('POST', `/v1/cases/${c2}/notes`, { body: 'Closed, but still a note' }); assert.strictEqual(r.status, 201);
    r = await call('PATCH', `/v1/cases/${c2}`, { status: 'open', title: 'Reopened with a new title' }); assert.deepStrictEqual([r.status, r.json.case.status, r.json.case.closed_at, r.json.case.title], [200, 'open', null, 'Reopened with a new title']);

    // 11. the list: filters, owner, paging, order (most recently changed first)
    r = await call('PATCH', `/v1/cases/${c3}`, { status: 'closed', owner_id: bob }); assert.strictEqual(r.status, 200);
    const nums = async (qs) => (await call('GET', '/v1/cases' + qs)).json.cases.map((c) => c.case_number);
    assert.deepStrictEqual(await nums(''), [2, 1], 'active = open and investigating, the one changed last first');
    assert.deepStrictEqual(await nums('?status=closed'), [3]); assert.deepStrictEqual((await nums('?status=all')).sort(), [1, 2, 3]);
    assert.deepStrictEqual(await nums('?status=open&owner=unassigned'), [2, 1], 'both open cases have no owner; the reopened one changed last');
    assert.deepStrictEqual(await nums('?status=all&owner=me'), [], 'alice owns none now'); assert.deepStrictEqual(await nums('?status=all&owner=' + bob), [3]);
    r = await call('GET', '/v1/cases?status=all&limit=2&offset=1'); assert.deepStrictEqual([r.json.cases.length, r.json.total, r.json.limit, r.json.offset], [2, 3, 2, 1]);
    r = await call('GET', '/v1/cases?status=all');
    const counts = Object.fromEntries(r.json.cases.map((c) => [c.case_number, c.alert_count])); assert.deepStrictEqual(counts, { 1: 2, 2: 1, 3: 1 });
    for (const qs of ['?status=nope', '?owner=x', '?limit=0', '?limit=201', '?limit=x', '?offset=-1']) { r = await call('GET', '/v1/cases' + qs); assert.strictEqual(r.status, 400, qs); }

    // 12. another tenant sees nothing of this one, and cannot change it; its numbers start at 1
    as(B, eve);
    assert.deepStrictEqual(await nums('?status=all'), []);
    for (const [m, p, b] of [['GET', `/v1/cases/${c1}`], ['PATCH', `/v1/cases/${c1}`, { title: 'hijack' }], ['POST', `/v1/cases/${c1}/notes`, { body: 'x' }], ['POST', `/v1/cases/${c1}/alerts`, { alert_ids: [bAlert] }], ['DELETE', `/v1/cases/${c1}/alerts/${aHigh}`]]) {
      r = await call(m, p, b); assert.deepStrictEqual([r.status, code(r)], [404, 'NOT_FOUND'], m + ' ' + p);
    }
    assert.strictEqual((await call('GET', `/v1/alerts/${aHigh}/case`)).json.case, null, 'not even which case an alert is in');
    assert.deepStrictEqual((await call('GET', '/v1/cases/candidates')).json.alerts.map((a) => a.title), ['Other tenant alert']);
    r = await call('POST', '/v1/cases', { title: 'Eve\'s first', alert_ids: [bAlert] }); assert.deepStrictEqual([r.status, r.json.case.case_number], [201, 1]);
    r = await call('POST', '/v1/cases', { title: 'Eve takes alice\'s alert', alert_ids: [aMed] }); assert.deepStrictEqual([r.status, code(r)], [404, 'ALERTS_NOT_FOUND']);
    as(A, alice);
    assert.strictEqual((await call('GET', `/v1/cases/${c1}`)).json.case.title, 'Router attack', 'untouched by the other tenant');

    // 13. concurrent creates get distinct, gapless numbers; two creates racing for one alert: exactly one wins
    as(B, eve);
    const many = await Promise.all(Array.from({ length: 12 }, (_, i) => call('POST', '/v1/cases', { title: 'parallel ' + i })));
    assert.ok(many.every((x) => x.status === 201), many.map((x) => x.status).join());
    assert.deepStrictEqual(many.map((x) => x.json.case.case_number).sort((a, b) => a - b), Array.from({ length: 12 }, (_, i) => i + 2));
    const bFree = await mkAlert(B, 'Race for me', 'low');
    const raceA = await Promise.all([call('POST', '/v1/cases', { title: 'racer 1', alert_ids: [bFree] }), call('POST', '/v1/cases', { title: 'racer 2', alert_ids: [bFree] })]);
    assert.deepStrictEqual(raceA.map((x) => x.status).sort(), [201, 409]);
    assert.strictEqual((await q('SELECT COUNT(*)::int AS n FROM case_alerts WHERE alert_id = $1', [bFree])).rows[0].n, 1);
    as(A, alice);

    // 14. the database itself refuses what the API would never send, and cleans up behind a deleted alert or case
    await assert.rejects(() => q(`INSERT INTO cases (tenant_id, case_number, title, status, created_by_name) VALUES ($1, 99, 't', 'done', 'x')`, [A]), /cases_status_chk/);
    await assert.rejects(() => q(`INSERT INTO cases (tenant_id, case_number, title, severity, created_by_name) VALUES ($1, 99, 't', 'urgent', 'x')`, [A]), /cases_severity_chk/);
    await assert.rejects(() => q(`INSERT INTO cases (tenant_id, case_number, title, created_by_name) VALUES ($1, 1, 't', 'x')`, [A]), /cases_tenant_number/);
    await assert.rejects(() => q('INSERT INTO case_alerts (tenant_id, case_id, alert_id, added_by_name) VALUES ($1, $2, $3, $4)', [A, c2, aHigh, 'x']), /case_alerts_one_case/);
    await q('DELETE FROM alerts WHERE id = $1', [aLow]);
    assert.strictEqual((await call('GET', `/v1/cases/${c1}`)).json.alerts.length, 1, 'a deleted alert leaves its case');
    const evBefore = (await q('SELECT COUNT(*)::int AS n FROM case_events WHERE case_id = $1', [c3])).rows[0].n; assert.ok(evBefore > 0);
    await q('DELETE FROM cases WHERE id = $1', [c3]);
    assert.strictEqual((await q('SELECT (SELECT COUNT(*)::int FROM case_events WHERE case_id = $1) + (SELECT COUNT(*)::int FROM case_alerts WHERE case_id = $1) AS n', [c3])).rows[0].n, 0, 'a deleted case takes its alerts links and timeline with it');
    assert.strictEqual((await q('SELECT status FROM alerts WHERE id = $1', [aCrit])).rows[0].status, 'open', 'and the alert itself is untouched');
    await q('DELETE FROM users WHERE id = $1', [bob]);
    assert.strictEqual((await q('SELECT owner_id FROM cases WHERE id = $1', [c2])).rows[0].owner_id, null, 'a deleted user only empties the owner');

    // 15. row-level security, with a role that does not own the tables (the API connects as the owner and filters by tenant itself; this checks the policies)
    try {
      await q('DROP ROLE IF EXISTS asix_cases_rls_test'); await q('CREATE ROLE asix_cases_rls_test NOLOGIN');
      await q('GRANT SELECT ON cases, case_alerts, case_events TO asix_cases_rls_test');
      await q('GRANT asix_cases_rls_test TO CURRENT_USER');
      const seen = async (tenant) => db.withTenant(tenant, async (c) => { await c.query('SET LOCAL ROLE asix_cases_rls_test'); return (await c.query('SELECT (SELECT COUNT(*)::int FROM cases) AS cases, (SELECT COUNT(*)::int FROM case_events) AS events, (SELECT COUNT(*)::int FROM case_alerts) AS links')).rows[0]; });
      const sa = await seen(A); const sb = await seen(B);
      const own = async (t) => (await q('SELECT (SELECT COUNT(*)::int FROM cases WHERE tenant_id = $1) AS cases, (SELECT COUNT(*)::int FROM case_events WHERE tenant_id = $1) AS events, (SELECT COUNT(*)::int FROM case_alerts WHERE tenant_id = $1) AS links', [t])).rows[0];
      assert.deepStrictEqual(sa, await own(A)); assert.deepStrictEqual(sb, await own(B)); assert.ok(sa.cases > 0 && sb.cases > 0 && sa.cases !== sb.cases);
      console.log('  row-level security checked with a non-owner role');
    } catch (e) { if (/permission denied|must be|CREATE ROLE|GRANT/i.test(e.message) && !(e instanceof assert.AssertionError)) console.log('  row-level security step skipped (this database user may not create roles):', e.message); else throw e; }
    finally { try { await q('DROP OWNED BY asix_cases_rls_test'); await q('DROP ROLE IF EXISTS asix_cases_rls_test'); } catch { /* best effort */ } }

    // 16. which permission each route asks for
    const perm = (m, p) => asked.filter((x) => x[0] === m && x[1] === p).map((x) => x[2]);
    for (const [m, p, want] of [['GET', '/v1/cases', 'alerts:read'], ['GET', '/v1/cases/:id', 'alerts:read'], ['GET', '/v1/cases/candidates', 'alerts:read'], ['GET', '/v1/alerts/:id/case', 'alerts:read'],
      ['POST', '/v1/cases', 'alerts:write'], ['PATCH', '/v1/cases/:id', 'alerts:write'], ['POST', '/v1/cases/:id/alerts', 'alerts:write'], ['DELETE', '/v1/cases/:id/alerts/:alertId', 'alerts:write'], ['POST', '/v1/cases/:id/notes', 'alerts:write']]) {
      const got = [...new Set(perm(m, p))]; assert.deepStrictEqual(got, [want], `${m} ${p} asked for ${got}`);
    }

    // 17. a deployment with the module off answers 403 on every route
    const real = modules.isEnabled; modules.isEnabled = async () => false;
    for (const [m, p] of [['GET', '/v1/cases'], ['POST', '/v1/cases', { title: 'x' }], ['GET', '/v1/cases/candidates']]) { r = await call(m, p, m === 'POST' ? { title: 'x' } : undefined); assert.deepStrictEqual([r.status, code(r)], [403, 'MODULE_DISABLED'], p); }
    modules.isEnabled = real;
    console.log('cases-db: all checks passed');
  } finally {
    srv.close();
    for (const t of [A, B]) {
      for (const tbl of ['case_events', 'case_alerts', 'cases', 'alerts', 'users']) await q(`DELETE FROM ${tbl} WHERE tenant_id = $1`, [t]).catch(() => {});
      await q('DELETE FROM tenants WHERE id = $1', [t]).catch(() => {});
    }
    await db.close();
  }
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
